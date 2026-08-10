"use strict";

// Proxy rotation helpers — cycle per account index.
// Source: file (proxies.txt, gitignored) or optional API rotator.
// Scope: Puppeteer launch (AWS Builder ID). 9router API direct.
//
// Line formats in proxies.txt (one per line):
//   protocol://user:pass@host:port     (auth uses puppeteer args + page.authenticate)
//   host:port:user:pass                 (legacy 4-field colon)
//   host:port                           (no auth)
//   user:pass@host:port                 (defaults to http)
//
// Empty lines / `#` are skipped. Per-line parse errors are treated as warnings
// and skipped — they do not abort the entire load.

const fs = require("fs");

// Parse a single line. Returns null if invalid.
/** @param {string} line */
function parseProxyLine(line) {
  const trimmed = String(line || "").trim();
  if (!trimmed || trimmed.startsWith("#")) return null;

  // Format 1: protocol://user:pass@host:port
  const m1 = trimmed.match(/^([a-z0-9]+):\/\/(?:([^:@]+):([^@]+)@)?([^:/]+):(\d+)\/?$/i);
  if (m1) {
    return {
      protocol: m1[1].toLowerCase(),
      host: m1[4],
      port: Number(m1[5]),
      username: m1[2] || null,
      password: m1[3] || null,
      raw: trimmed,
    };
  }

  // Format 2: host:port:user:pass
  const m2 = trimmed.match(/^([^:]+):(\d+):([^:]+):(.+)$/);
  if (m2) {
    return {
      protocol: "http",
      host: m2[1],
      port: Number(m2[2]),
      username: m2[3],
      password: m2[4],
      raw: trimmed,
    };
  }

  // Format 3: user:pass@host:port
  const m3 = trimmed.match(/^(?:([^:@]+):([^@]+)@)?([^:@]+):(\d+)\/?$/);
  if (m3) {
    return {
      protocol: "http",
      host: m3[3],
      port: Number(m3[4]),
      username: m3[1] || null,
      password: m3[2] || null,
      raw: trimmed,
    };
  }

  return null;
}

// Load proxies from file (gitignored). Returns array of parsed proxies.
// Invalid lines log a warning but do not throw — so one broken line does not
// fail the entire load.
/** @param {string} filePath */
function loadProxies(filePath) {
  if (!filePath || !fs.existsSync(filePath)) return [];
  const content = fs.readFileSync(filePath, "utf8");
  const lines = content.split(/\r?\n/);
  const out = [];
  lines.forEach((line, i) => {
    const p = parseProxyLine(line);
    if (p) out.push(p);
    else if (line.trim() && !line.trim().startsWith("#")) {
      console.warn(`[proxy] skip line ${i + 1}: ${String(line).slice(0, 60)}`);
    }
  });
  return out;
}

// Return proxy for account index (cycle). Returns null if pool is empty.
/** @param {Array<object>} proxies @param {number} accountIndex */
function getProxyForAccount(proxies, accountIndex) {
  if (!Array.isArray(proxies) || proxies.length === 0) return null;
  return proxies[((accountIndex % proxies.length) + proxies.length) % proxies.length];
}

// Pick the first LIVE proxy from the pool, else null (caller falls back to a
// DIRECT connection). Liveness is checked with a fast HEAD request. A dead
// proxy (all network errors / auth 407) would break the initial navigation
// (e.g. Google OAuth) — better to go direct than hang on a dead tunnel.
/** @param {Array<object>} proxies @returns {Promise<object|null>} */
async function pickLiveOrFirst(proxies) {
  if (!Array.isArray(proxies) || proxies.length === 0) return null;
  const checked = Math.min(proxies.length, 10); // don't scan all 100
  for (let i = 0; i < checked; i++) {
    if (await checkProxyAlive(proxies[i])) return proxies[i];
  }
  return null; // none alive → caller goes direct
}

/**
 * Fast liveness probe: HEAD https://accounts.google.com through the proxy.
 * Treats HTTP 200/30x/403 as alive (any HTTP response means the tunnel works);
 * network errors / 407 require a retry or direct fallback.
 * @param {object} proxy
 * @returns {Promise<boolean>}
 */
function checkProxyAlive(proxy) {
  return new Promise((resolve) => {
    const http = require("http");
    const auth =
      proxy.username && proxy.password
        ? `${proxy.username}:${proxy.password}@`
        : "";
    const url = `http://${auth}${proxy.host}:${proxy.port}`;
    const req = http.request(
      url,
      {
        method: "HEAD",
        path: "http://accounts.google.com/",
        timeout: 6000,
        // Send proxy auth directly if credentials exist (http.request handles
        // the Proxy-Authorization header via the URL userinfo).
        auth:
          proxy.username && proxy.password
            ? `${proxy.username}:${proxy.password}`
            : undefined,
      },
      (res) => {
        // 407/401 = proxy auth rejected (dead creds) → NOT alive.
        const code = res.statusCode;
        const ok = code !== undefined && code !== 407 && code !== 401 && code < 500;
        res.resume();
        resolve(ok);
      }
    );
    req.on("timeout", () => req.destroy());
    req.on("error", () => resolve(false));
    req.end();
  });
}

// Build Chromium launch args for proxy. No auth in args (username/password
// is attached via page.authenticate after launch — Puppeteer does not support
// authenticated proxies in args across all builds).
/** @param {{protocol: string, host: string, port: number}|null} proxy */
function chromiumArgsForProxy(proxy) {
  if (!proxy) return [];
  return [`--proxy-server=${proxy.protocol}://${proxy.host}:${proxy.port}`];
}

module.exports = {
  parseProxyLine,
  loadProxies,
  getProxyForAccount,
  pickLiveOrFirst,
  checkProxyAlive,
  chromiumArgsForProxy,
};
