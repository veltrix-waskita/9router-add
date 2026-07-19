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
  chromiumArgsForProxy,
};
