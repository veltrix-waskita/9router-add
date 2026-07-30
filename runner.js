#!/usr/bin/env node
"use strict";

/**
 * Interactive TUI runner for 9router-add.
 *
 * Flow:
 *   1. Mode: local | remote
 *   2. Provider: antigravity | kiro | grok-cli
 *   3. Run: single | batch (JSON file) | auto (generate email+password+name)
 *   4. Proxy: none | rotate from proxies.txt | single URL for all
 *
 * Provider capabilities (as implemented today):
 *   - antigravity → Google OAuth only (email + password for Google)
 *   - kiro        → email only (pure-HTTP worker; IMAP OTP or temp-mail; no Google OAuth)
 *   - grok-cli    → email signup + IMAP OTP only (pure-HTTP; no Google OAuth yet)
 *
 * Auto-credentials (email method only — grok-cli, kiro email):
 *   email  = random alias on providers.<name>.aliasDomain (CF Email Routing catch-all)
 *   password / name = random strong values; saved to generated-accounts-*.json
 *
 * Batch: ALL providers support sequential batch via Provider.add() one account
 * at a time (same path as `node src/index.js batch <provider> file.json`).
 *
 * Usage:  node runner.js
 *         npm run interactive
 */

const fs = require("fs");
const path = require("path");
const os = require("os");
const readline = require("readline");
const http = require("http");

const { loadConfig, isLocalHost } = require("./src/core/config");
const { resolveAuthHeaders } = require("./src/core/auth");
const { request } = require("./src/core/http-client");
const { loadProviders, loadServices } = require("./src/core/cli");
const captchaSolver = require("./src/services/captcha-solver");

// Solver lifecycle: start always on runner boot; stop only if we own the process.
const SOLVER_DIR = path.join(__dirname, "captcha-solver");
let solverOwned = false;

// ─── ANSI styling (zero-dependency) — MASS ACCOUNT aesthetic ───────────────
// Palette: gold/yellow borders · cyan labels · green ENABLED · numbered chips

const style = {
  reset: "\x1b[0m",
  bold: (s) => `\x1b[1m${s}\x1b[0m`,
  dim: (s) => `\x1b[2m${s}\x1b[0m`,
  italic: (s) => `\x1b[3m${s}\x1b[0m`,
  ul: (s) => `\x1b[4m${s}\x1b[0m`,
  // 16 foreground
  black: (s) => `\x1b[30m${s}\x1b[0m`,
  red: (s) => `\x1b[31m${s}\x1b[0m`,
  green: (s) => `\x1b[32m${s}\x1b[0m`,
  yellow: (s) => `\x1b[33m${s}\x1b[0m`,
  blue: (s) => `\x1b[34m${s}\x1b[0m`,
  magenta: (s) => `\x1b[35m${s}\x1b[0m`,
  cyan: (s) => `\x1b[36m${s}\x1b[0m`,
  white: (s) => `\x1b[37m${s}\x1b[0m`,
  // bright
  brightRed: (s) => `\x1b[91m${s}\x1b[0m`,
  brightGreen: (s) => `\x1b[92m${s}\x1b[0m`,
  brightYellow: (s) => `\x1b[93m${s}\x1b[0m`,
  brightBlue: (s) => `\x1b[94m${s}\x1b[0m`,
  brightMagenta: (s) => `\x1b[95m${s}\x1b[0m`,
  brightCyan: (s) => `\x1b[96m${s}\x1b[0m`,
  brightWhite: (s) => `\x1b[97m${s}\x1b[0m`,
  // background
  bgRed: (s) => `\x1b[41m${s}\x1b[0m`,
  bgGreen: (s) => `\x1b[42m${s}\x1b[0m`,
  bgYellow: (s) => `\x1b[43m${s}\x1b[0m`,
  bgBlue: (s) => `\x1b[44m${s}\x1b[0m`,
  bgMagenta: (s) => `\x1b[45m${s}\x1b[0m`,
  bgCyan: (s) => `\x1b[46m${s}\x1b[0m`,
  // gold = bright yellow (MASS ACCOUNT border color)
  gold: (s) => `\x1b[93m${s}\x1b[0m`,
};

// Visible width ignoring ANSI escapes (for box padding)
function stripAnsi(s) {
  return String(s).replace(/\x1b\[[0-9;]*m/g, "");
}
function visLen(s) {
  return stripAnsi(s).length;
}

// Composed helpers — MASS ACCOUNT style
function tag(label, value, color = "cyan") {
  // "  Status     : ENABLED" style — cyan label, colored value
  const pad = label.padEnd(14);
  const valColor = style[color] || style.cyan;
  return `  ${style.cyan(pad)}: ${valColor(String(value))}`;
}
function badge(text, bg) {
  return ` ${style[`bg${bg}`](` ${text} `)}${style.reset} `;
}
function dim(s) { return style.dim(s); }
function bold(s) { return style.bold(s); }
function hr(char = "─", width = 50) {
  return style.gold(char.repeat(width));
}
function bullet(text, color = "cyan") {
  return `  ${style[color]("◆")} ${text}`;
}
function okBadge() { return badge("OK", "Green"); }
function failBadge() { return badge("FAIL", "Red"); }
function warnBadge() { return badge("!", "Yellow"); }
function infoBadge() { return badge("i", "Blue"); }

// Numbered option chip: [1] green label  (n=0 → last color, MASS ACCOUNT exit key)
function optChip(n) {
  const colors = [
    style.brightYellow, style.brightCyan, style.brightGreen,
    style.brightMagenta, style.brightBlue, style.brightRed,
    style.yellow, style.cyan, style.green, style.magenta,
  ];
  const idx = n === 0 ? colors.length - 1 : Math.abs(n - 1) % colors.length;
  return colors[idx](`[${n}]`);
}

// Truncate ANSI-aware string to max visible width (keep SGR intact-ish)
function truncVis(s, max) {
  const str = String(s ?? "");
  if (visLen(str) <= max) return str;
  // strip and rebuild with ellipsis — simple path: plain truncate after strip
  const plain = stripAnsi(str);
  return plain.slice(0, Math.max(0, max - 1)) + "…";
}

// Gold bordered box — MASS ACCOUNT panel style
// title is centered in the top border; lines are content strings (may have ANSI)
function goldBox(title, lines, innerWidth = 56) {
  const W = innerWidth;
  const t = String(title || "").slice(0, Math.max(0, W - 4));
  const side = Math.max(0, Math.floor((W - t.length - 2) / 2));
  const right = Math.max(0, W - t.length - 2 - side);
  // bold+gold as one SGR so reset doesn't kill bold
  const top =
    `\x1b[93m╔${"═".repeat(side)} \x1b[0m` +
    `\x1b[1;93m${t}\x1b[0m` +
    `\x1b[93m ${"═".repeat(right)}╗\x1b[0m`;
  const bot = `\x1b[93m╚${"═".repeat(W)}╝\x1b[0m`;
  const out = [top];
  for (const raw of lines) {
    let line = String(raw ?? "");
    if (visLen(line) > W) line = truncVis(line, W);
    const pad = Math.max(0, W - visLen(line));
    out.push(`\x1b[93m║\x1b[0m${line}${" ".repeat(pad)}\x1b[93m║\x1b[0m`);
  }
  out.push(bot);
  return out.join("\n");
}

// Large pixel/block ASCII title — yellow/gold, centered feel
function printBanner() {
  // Combined bold+gold in one SGR sequence (avoids nested reset killing bold)
  const B = (s) => `\x1b[1;93m${s}\x1b[0m`;
  // "9ROUTER" in block letters (compact, fits ~70 cols)
  const art = [
    "  █████╗ ██████╗  ██████╗ ██╗   ██╗████████╗███████╗██████╗ ",
    " ██╔══██╗██╔══██╗██╔═══██╗██║   ██║╚══██╔══╝██╔════╝██╔══██╗",
    " ███████║██████╔╝██║   ██║██║   ██║   ██║   █████╗  ██████╔╝",
    " ██╔══██║██╔══██╗██║   ██║██║   ██║   ██║   ██╔══╝  ██╔══██╗",
    " ██║  ██║██║  ██║╚██████╔╝╚██████╔╝   ██║   ███████╗██║  ██║",
    " ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝╚═╝  ╚═╝",
  ];
  console.log();
  for (const line of art) console.log(B(line));
  console.log(
    style.gold("              ◆ ") +
      "\x1b[1;97mADD\x1b[0m" +
      style.gold(" ◆ ") +
      style.dim("interactive account automation") +
      style.gold(" ◆")
  );
  console.log(
    style.dim("         antigravity") +
      style.gold(" · ") +
      style.dim("kiro") +
      style.gold(" · ") +
      style.dim("grok-cli") +
      style.dim("  (sequential batch)")
  );
  console.log();
}

const {
  generateAccounts,
  resolveAliasDomain,
  randomPassword,
  randomName,
} = require("./src/services/credentials");
const {
  loadProxies,
  getProxyForAccount,
  parseProxyLine,
} = require("./src/services/proxy");

// ─── provider catalog (honest about what code actually supports) ────────────

const PROVIDER_INFO = {
  antigravity: {
    label: "Antigravity",
    methods: ["google"],
    notes: "Google OAuth only — credentials.email/password must be a Google account.",
    needsBrowser: true,
    needsImap: false,
    needsWorker: false,
    needsSolver: false,
    batch: true,
  },
  kiro: {
    label: "Kiro AI",
    methods: ["email"],
    notes:
      "Email signup only (pure-HTTP worker; bare @gmail.com not supported — Gmail plus-aliases like you+tag@gmail.com work). emailSource=imap (default) needs IMAP catch-all; emailSource=tempmail uses disposable inbox.",
    needsBrowser: false,
    needsImap: false, // imap optional since tempmail mode exists
    needsWorker: true,
    needsSolver: false,
    batch: true,
    autoCredentials: true,
    supportsTempmail: true,
  },
  "grok-cli": {
    label: "Grok CLI (xAI)",
    methods: ["email"],
    notes:
      "Email signup (password + IMAP OTP / temp-mail + Turnstile). emailSource=imap (default) needs IMAP catch-all; emailSource=tempmail uses disposable inbox.",
    needsBrowser: false,
    needsImap: false, // imap optional since tempmail mode exists
    needsWorker: true,
    needsSolver: true,
    batch: true,
    autoCredentials: true,
    supportsTempmail: true,
  },
};

// Providers that can invent email+password (need catch-all alias domain).
function supportsAutoCredentials(providerName) {
  return !!(PROVIDER_INFO[providerName] && PROVIDER_INFO[providerName].autoCredentials) ||
    providerName === "kiro"; // kiro email-method also works with aliases
}

// ─── readline helpers ───────────────────────────────────────────────────────
// When APP (session dashboard) is active, prompts redraw the frame first and
// panels go into the content area instead of dumping goldBox to the terminal.

function createRl() {
  return readline.createInterface({
    input: process.stdin,
    output: process.stdout,
  });
}

/** Low-level prompt (no dashboard redraw). Used by AppShell.ask. */
function askRaw(rl, question, { defaultValue } = {}) {
  const hint =
    defaultValue !== undefined && defaultValue !== ""
      ? ` ${dim(`[${defaultValue}]`)}`
      : "";
  return new Promise((resolve) => {
    rl.question(
      `  ${style.gold("▸")} ${style.brightWhite(question)}${hint} ${style.brightGreen("›")} `,
      (answer) => {
        const trimmed = String(answer || "").trim();
        resolve(trimmed === "" && defaultValue !== undefined ? defaultValue : trimmed);
      }
    );
  });
}

/** Low-level hidden prompt. Used by AppShell.askHidden. */
async function askHiddenRaw(rl, question) {
  return new Promise((resolve) => {
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;
    process.stdout.write(
      `  ${style.gold("▸")} ${style.brightWhite(question)} ${style.brightGreen("›")} `
    );
    let buf = "";
    const onData = (ch) => {
      const s = ch.toString("utf8");
      if (s === "\n" || s === "\r" || s === "") {
        stdin.removeListener("data", onData);
        if (stdin.setRawMode && wasRaw !== undefined) stdin.setRawMode(!!wasRaw);
        process.stdout.write("\n");
        resolve(buf);
        return;
      }
      if (s === "") {
        process.stdout.write("\n");
        process.exit(130);
      }
      if (s === "" || s === "\b") {
        buf = buf.slice(0, -1);
        return;
      }
      buf += s;
    };
    if (stdin.setRawMode) stdin.setRawMode(true);
    stdin.resume();
    stdin.on("data", onData);
  });
}

/** Dashboard-aware ask: redraw frame then prompt. */
async function ask(rl, question, opts) {
  if (APP && APP._active) return APP.ask(rl, question, opts || {});
  return askRaw(rl, question, opts || {});
}

async function askHidden(rl, question) {
  if (APP && APP._active) return APP.askHidden(rl, question);
  return askHiddenRaw(rl, question);
}

/**
 * Put a titled panel into the session dashboard content area, or goldBox fallback.
 */
function showPanel(title, lines) {
  if (APP && APP._active) {
    APP.setContent(title, lines);
    return;
  }
  console.log();
  console.log(goldBox(title, lines, 56));
}

/** Short status note into dashboard log (or console when shell inactive). */
function noteLine(msg, level = "info") {
  if (APP && APP._active) {
    APP.note(msg, level);
    return;
  }
  const badgeFn =
    level === "ok"
      ? okBadge
      : level === "warn"
        ? warnBadge
        : level === "fail"
          ? failBadge
          : infoBadge;
  console.log(`  ${badgeFn()}${dim(" " + msg)}`);
}

/**
 * MASS ACCOUNT style menu inside dashboard content panel (or goldBox fallback).
 */
async function choose(rl, title, options) {
  const lines = [""];
  options.forEach((opt, i) => {
    const n = i + 1;
    const chip = optChip(n);
    const label = `\x1b[1;92m${opt.label}\x1b[0m`;
    const hint = opt.hint ? style.dim(`  ${opt.hint}`) : "";
    lines.push(`  ${chip}  ${label}${hint ? "\n      " + hint : ""}`);
  });
  lines.push("");

  const boxLines = [];
  for (const row of lines) {
    if (row.includes("\n")) {
      for (const part of row.split("\n")) boxLines.push(part);
    } else {
      boxLines.push(row);
    }
  }

  showPanel(String(title || "").toUpperCase(), boxLines);
  if (APP && APP._active) APP.setWork(`pilih · ${title}`);

  for (;;) {
    const raw = await ask(rl, "Pilih opsi");
    const n = Number(raw);
    if (Number.isInteger(n) && n >= 1 && n <= options.length) {
      const chosen = options[n - 1];
      if (APP && APP._active) {
        APP.note(`pilih: ${chosen.label}`, "ok");
        APP.setWork(chosen.label);
      } else {
        console.log(`  ${okBadge()} \x1b[1;92m${chosen.label}\x1b[0m`);
      }
      return chosen.value;
    }
    if (APP && APP._active) {
      APP.note(`Masukkan 1–${options.length}`, "warn");
    } else {
      console.log(`  ${warnBadge()} ${style.yellow(`Masukkan 1–${options.length}`)}`);
    }
  }
}

function yn(value) {
  return /^(y|yes|ya)$/i.test(String(value || "").trim());
}

// ─── preflight ──────────────────────────────────────────────────────────────

function checkFile(p) {
  try {
    return fs.existsSync(p);
  } catch {
    return false;
  }
}

function probeSolver(port = 8877, timeoutMs = 1500) {
  return new Promise((resolve) => {
    const req = http.request(
      {
        hostname: "127.0.0.1",
        port,
        path: "/health",
        method: "GET",
        timeout: timeoutMs,
      },
      (res) => {
        res.resume();
        // Any HTTP response means the port is alive (even 404).
        resolve({ ok: true, status: res.statusCode });
      }
    );
    req.on("error", (e) => resolve({ ok: false, error: e.message }));
    req.on("timeout", () => {
      req.destroy();
      resolve({ ok: false, error: "timeout" });
    });
    req.end();
  });
}

/**
 * Ensure local Turnstile solver is up on :8877.
 * - If something already answers → reuse (do not own → will not stop).
 * - Else spawn captcha-solver/ via captchaSolver.start and mark owned.
 * Soft-fail: returns { ok, owned, error? } so non-grok providers can continue.
 */
async function ensureSolverStarted() {
  const existing = await probeSolver(8877);
  if (existing.ok) {
    return { ok: true, owned: false, reused: true, status: existing.status };
  }

  if (!checkFile(path.join(SOLVER_DIR, "server.py"))) {
    return {
      ok: false,
      owned: false,
      error: `missing ${path.join(SOLVER_DIR, "server.py")}`,
    };
  }
  const hasVenv =
    checkFile(path.join(SOLVER_DIR, "venv", "bin", "python3")) ||
    checkFile(path.join(SOLVER_DIR, ".venv", "bin", "python3"));
  if (!hasVenv) {
    return {
      ok: false,
      owned: false,
      error:
        `missing captcha-solver venv — run: cd captcha-solver && python3 -m venv venv && ` +
        `venv/bin/pip install -r requirements.txt`,
    };
  }

  try {
    await captchaSolver.start(SOLVER_DIR, {
      // Do NOT set SOLVER_ALLOW_PRIVATE=1 — it short-circuits check_ssrf()
      // entirely, and nothing here needs it: the only URL we hand the solver
      // is the public Turnstile page (accounts.x.ai).
      HOST: "127.0.0.1",
      SOLVER_MODE: process.env.SOLVER_MODE || "local",
      SOLVER_HEADLESS: process.env.SOLVER_HEADLESS || "1",
    });
    solverOwned = true;
    const after = await probeSolver(8877, 3000);
    if (!after.ok) {
      return {
        ok: false,
        owned: true,
        error: `started but health probe failed: ${after.error}`,
      };
    }
    return { ok: true, owned: true, reused: false, status: after.status };
  } catch (err) {
    return { ok: false, owned: false, error: err.message };
  }
}

async function stopOwnedSolver() {
  if (!solverOwned) return;
  solverOwned = false;
  try {
    await captchaSolver.stop();
  } catch {
    /* ignore */
  }
}

/**
 * Check a provider's Python pure-HTTP worker (signup.py + venv + curl_cffi).
 * Each worker-carrying provider keeps its own venv under
 * src/providers/<name>/worker/.venv (kiro and grok-cli today).
 *
 * @param {string} providerName
 * @returns {{workerDir: string, signup: boolean, venv: boolean, curlCffi: boolean}}
 */
function checkWorker(providerName) {
  const workerDir = path.join(__dirname, "src/providers", providerName, "worker");
  const venvPy = path.join(workerDir, ".venv/bin/python3");
  const signup = path.join(workerDir, "signup.py");
  const out = { workerDir, signup: checkFile(signup), venv: checkFile(venvPy), curlCffi: false };
  if (out.venv) {
    try {
      const { execFileSync } = require("child_process");
      execFileSync(venvPy, ["-c", "import curl_cffi"], { stdio: "ignore", timeout: 5000 });
      out.curlCffi = true;
    } catch {
      out.curlCffi = false;
    }
  }
  return out;
}

/**
 * Run preflight checks for the chosen mode + provider.
 * Returns { ok, warnings[], errors[] }.
 */
async function preflight(config, providerName) {
  const info = PROVIDER_INFO[providerName] || {};
  const errors = [];
  const warnings = [];
  const lines = [];

  lines.push(`mode=${config.mode}  ${config.proto}://${config.host}:${config.port}`);

  // Transport / auth shape
  if (config.mode === "remote") {
    if (config.proto !== "https" && !isLocalHost(config.host)) {
      errors.push("Remote non-localhost requires proto=https (password must not go over HTTP).");
    }
    if (!config.password) {
      errors.push("Remote mode needs dashboard password (config.password or 9R_ADD_PASSWORD).");
    }
  } else {
    const mid = path.join(os.homedir(), ".9router", "machine-id");
    if (!checkFile(mid)) {
      errors.push(`Local mode needs machine-id at ${mid}`);
    }
    if (!config.cliSecret) {
      errors.push("Local mode needs cliSecret in config.json (or 9R_ADD_CLI_SECRET).");
    }
    const dbPath =
      config.dbPath || path.join(os.homedir(), ".9router", "db", "data.sqlite");
    lines.push(`dbPath=${dbPath}`);
    if (!checkFile(dbPath)) {
      warnings.push(`dbPath not found yet (will be created by 9router if missing): ${dbPath}`);
    }
  }

  // IMAP (only required for imap emailSource — tempmail providers don't need it)
  if (info.supportsTempmail) {
    if (!config.imap || !config.imap.user || !config.imap.password) {
      warnings.push(
        "IMAP not configured — tempmail mode will be used (disposable inbox). " +
        "Set config.imap + --email-source=imap for catch-all alias flow."
      );
    } else {
      lines.push(`imap=${config.imap.user}@${config.imap.host || "imap.gmail.com"}`);
    }
  } else if (info.needsImap) {
    if (!config.imap || !config.imap.user || !config.imap.password) {
      errors.push("IMAP required (config.imap.user + imap.password) for this provider.");
    } else {
      lines.push(`imap=${config.imap.user}@${config.imap.host || "imap.gmail.com"}`);
    }
  }

  // Browser / chromium
  if (info.needsBrowser) {
    const chrom =
      config.chromiumPath ||
      process.env.CHROMIUM_PATH ||
      "/usr/bin/chromium";
    if (!checkFile(chrom)) {
      warnings.push(`chromiumPath not found: ${chrom} (browser providers may fail)`);
    } else {
      lines.push(`chromium=${chrom}`);
    }
  }

  // Python pure-HTTP worker (kiro, grok-cli)
  if (info.needsWorker) {
    const w = checkWorker(providerName);
    if (!w.signup) errors.push(`Missing worker: ${path.join(w.workerDir, "signup.py")}`);
    if (!w.venv) {
      errors.push(
        `Missing worker venv: ${path.join(w.workerDir, ".venv")} — run: cd src/providers/${providerName}/worker && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt`
      );
    } else if (!w.curlCffi) {
      errors.push("Worker venv missing curl_cffi — pip install -r requirements.txt inside .venv");
    } else {
      lines.push(`worker=${providerName} venv+curl_cffi ok`);
    }
  }

  // Turnstile solver — runner always tries ensureSolverStarted() before preflight.
  // Here we only re-probe; if still down, hard-error only when provider needs it.
  {
    const sol = await probeSolver(8877);
    if (sol.ok) {
      lines.push(
        `solver=:8877 http=${sol.status}${solverOwned ? " (owned)" : " (external)"}`
      );
    } else if (info.needsSolver) {
      errors.push(
        `Turnstile solver not reachable on 127.0.0.1:8877 (${sol.error}). ` +
          `Check captcha-solver/ venv + deps (camoufox).`
      );
    } else {
      warnings.push(
        `Turnstile solver not on :8877 (${sol.error}) — ok for this provider.`
      );
    }
  }

  // Proxy file (optional)
  if (config.proxyFile) {
    const pp = path.isAbsolute(config.proxyFile)
      ? config.proxyFile
      : path.join(process.cwd(), config.proxyFile);
    if (checkFile(pp)) {
      const n = fs
        .readFileSync(pp, "utf8")
        .split("\n")
        .filter((l) => l.trim() && !l.trim().startsWith("#")).length;
      lines.push(`proxyFile=${pp} (${n} lines)`);
    } else {
      warnings.push(`proxyFile set but missing: ${pp}`);
    }
  }

  // Live auth probe
  try {
    const api = { request };
    const headers = await resolveAuthHeaders(config, api);
    // Light request: list providers or device-code shape depends on provider.
    // Use a generic path that exists on 9router dashboards.
    const probePath =
      providerName === "antigravity"
        ? "/api/providers"
        : PROVIDER_INFO[providerName]
          ? `/api/oauth/${providerName === "grok-cli" ? "grok-cli" : providerName}/device-code`.replace(
              // antigravity uses authorize not device-code — already branched
              "antigravity/device-code",
              "antigravity/authorize"
            )
          : "/api/providers";

    // For auth probe only hit /api/providers — safer, no side effects.
    const res = await request(config, {
      method: "GET",
      path: "/api/providers",
      headers,
    });
    if (res.statusCode >= 400) {
      errors.push(`Auth probe GET /api/providers → HTTP ${res.statusCode}`);
    } else {
      lines.push(`auth=ok (GET /api/providers ${res.statusCode})`);
    }
    // silence unused
    void probePath;
  } catch (e) {
    errors.push(`Auth/API probe failed: ${e.message}`);
  }

  return { ok: errors.length === 0, errors, warnings, lines };
}

// ─── account input ──────────────────────────────────────────────────────────

async function promptSingleAccount(rl, providerName) {
  const info = PROVIDER_INFO[providerName];
  showPanel("SINGLE ACCOUNT", [
    tag("Provider", info.label, "brightYellow"),
    tag("Methods", info.methods.join(", "), "cyan"),
    tag("Proxy", "dipilih di langkah berikutnya", "dim"),
  ]);

  let emailSource = "imap";
  // Ask email source only for providers that support tempmail (non-google method).
  if (info.supportsTempmail) {
    const raw = await ask(rl, "Email source (imap / tempmail)", { defaultValue: "imap" });
    emailSource = raw.trim().toLowerCase() === "tempmail" ? "tempmail" : "imap";
    if (emailSource === "tempmail") {
      noteLine("using temp-mail: no IMAP config needed", "info");
    }
  }

  let email = "";
  let password = "";
  let name = "";

  if (emailSource === "tempmail") {
    noteLine("email will be auto-generated from temp-mail provider", "info");
    name = randomName();
    noteLine(`display name: ${name} (auto)`, "info");
  } else {
    email = await ask(rl, "Email");
    if (!email) throw new Error("Email required");
    password = await askHidden(rl, "Password (hidden)");
    if (!password) throw new Error("Password required");
    name = await ask(rl, "Display name (optional)", { defaultValue: "" });
  }

  // Method hint for kiro (email only — pure-HTTP; Google OAuth removed)
  if (providerName === "kiro") {
    const lowerEmail = email.trim().toLowerCase();
    const isGmail = lowerEmail.endsWith("@gmail.com");
    // Non-empty tag after "+" required: "user+@gmail.com" normalizes to bare
    // gmail (the unsupported google path), matching detectMethod/signup.py.
    const localPart = lowerEmail.split("@", 1)[0];
    const plusIdx = localPart.indexOf("+");
    const isPlusAlias = isGmail && plusIdx !== -1 && localPart.slice(plusIdx + 1).length > 0;
    if (isGmail && !isPlusAlias) {
      noteLine(
        "kiro no longer supports bare @gmail.com (pure-HTTP) — use a plus-alias (you+tag@gmail.com), a catch-all alias, or temp-mail",
        "warn"
      );
    } else if (isPlusAlias) {
      noteLine(
        "Gmail plus-alias: registers as a distinct account, OTP lands in the base inbox",
        "info"
      );
    } else if (emailSource === "tempmail") {
      noteLine("kiro uses email signup + temp-mail (no IMAP catch-all needed)", "info");
    } else {
      noteLine("kiro uses email signup + IMAP OTP — requires a catch-all that receives this alias", "warn");
    }
  }
  if (providerName === "antigravity") {
    noteLine("antigravity always uses Google OAuth with this email", "info");
  }
  if (providerName === "grok-cli") {
    const src = emailSource === "tempmail" ? "temp-mail" : "IMAP OTP";
    noteLine(`grok-cli uses email signup + ${src}`, "info");
  }

  const credentials = { email, password };
  if (name) credentials.name = name;
  const options = {};
  if (emailSource === "tempmail") {
    options.emailSource = "tempmail";
  }
  return { credentials, options };
}

/**
 * Auto-generate N accounts for email-method providers.
 * Supports IMAP mode (alias domain + catch-all) and tempmail mode
 * (disposable inbox, no alias domain needed).
 * Prints emails only (never passwords to the console — full set saved to file).
 */
async function promptAutoAccounts(rl, config, providerName) {
  const info = PROVIDER_INFO[providerName];
  showPanel("AUTO GENERATE", [
    tag("Provider", providerName, "brightYellow"),
    tag("Proxy", "dipilih di langkah berikutnya", "dim"),
  ]);

  // Ask email source only for providers that support tempmail.
  let emailSource = "imap";
  if (info && info.supportsTempmail) {
    const raw = await ask(rl, "Email source (imap / tempmail)", { defaultValue: "imap" });
    emailSource = raw.trim().toLowerCase() === "tempmail" ? "tempmail" : "imap";
  }

  if (emailSource === "tempmail") {
    showPanel("TEMP-MAIL MODE", [
      tag("Status", "ENABLED", "brightGreen"),
      tag("Alias", "not needed", "dim"),
      tag("IMAP", "not needed", "dim"),
      tag("Email", "auto per account", "cyan"),
    ]);
  } else {
    const domain = resolveAliasDomain(config, providerName);
    if (!domain) {
      throw new Error(
        `IMAP auto-credentials need providers.${providerName}.aliasDomain in config.json ` +
          `(e.g. "minom.my.id" with CF Email Routing catch-all → IMAP Gmail, ` +
          `or "you@gmail.com" for Gmail plus-aliases you+tag@gmail.com). ` +
          `Or use emailSource=tempmail to skip the alias domain requirement.`
      );
    }
    const plusMode = domain.includes("@");
    showPanel("IMAP ALIAS MODE", [
      tag("Status", "ENABLED", "brightGreen"),
      tag(plusMode ? "Base inbox" : "Domain", domain, "cyan"),
      tag("Email", plusMode ? "base+<random tag>@gmail.com" : "random alias@domain", "yellow"),
      tag("OTP", plusMode ? "IMAP (shared base inbox)" : "IMAP catch-all", "yellow"),
    ]);
  }

  const countRaw = await ask(rl, "Berapa akun?", { defaultValue: "1" });
  const count = Math.max(1, Math.min(Number(countRaw) || 1, 100));

  const stamp = new Date()
    .toISOString()
    .replace(/[:.]/g, "-")
    .replace("T", "_")
    .slice(0, 19);
  const defaultSave = path.join(
    process.cwd(),
    `generated-accounts-${providerName}-${stamp}.json`
  );
  const saveFile = await ask(rl, "Simpan credentials ke file", {
    defaultValue: defaultSave,
  });

  let accounts, aliasPath;
  if (emailSource === "tempmail") {
    // Temp-mail mode: no alias domain needed. Generate password + name only;
    // email is a placeholder — the provider replaces it with a real temp-mail address.
    const generated = [];
    for (let i = 0; i < count; i++) {
      generated.push({
        credentials: {
          email: "tempmail@pending.local",
          password: randomPassword(),
          name: randomName(),
        },
        options: { emailSource: "tempmail" },
      });
    }
    accounts = generated;
    aliasPath = null;
    if (saveFile) {
      const payload = {
        generatedAt: new Date().toISOString(),
        provider: providerName,
        mode: "tempmail",
        accounts,
      };
      fs.writeFileSync(saveFile, JSON.stringify(payload, null, 2) + "\n", {
        mode: 0o600,
      });
    }
  } else {
    const result = generateAccounts({
      config,
      providerName,
      count,
      saveFile,
    });
    accounts = result.accounts;
    aliasPath = result.aliasPath;
  }

  const resultLines = [
    tag("Generated", String(accounts.length), "brightGreen"),
    tag("Source", emailSource, "cyan"),
  ];
  if (emailSource === "tempmail") {
    resultLines.push(tag("Email", "tempmail@pending.local (runtime)", "dim"));
  } else {
    const dom = resolveAliasDomain(config, providerName);
    resultLines.push(tag(dom && dom.includes("@") ? "Base inbox" : "Domain", dom, "cyan"));
    for (const a of accounts) {
      // Email only — password stays in the save file (mode 0600).
      resultLines.push(`  ${style.cyan("·")} ${style.cyan(a.credentials.email)}  ${dim("(" + a.credentials.name + ")")}`);
    }
    if (aliasPath) resultLines.push(tag("Aliases", aliasPath, "dim"));
  }
  if (saveFile) resultLines.push(tag("Saved", saveFile, "yellow"));
  resultLines.push(tag("Passwords", "hidden (file only)", "brightYellow"));
  showPanel("GENERATED ACCOUNTS", resultLines);
  noteLine(`generated ${accounts.length} account(s)`, "ok");
  return accounts;
}

async function loadBatchFile(rl) {
  const defaultPath = path.join(process.cwd(), "accounts.json");
  const file = await ask(rl, "Path ke batch JSON", { defaultValue: defaultPath });
  if (!checkFile(file)) throw new Error(`File not found: ${file}`);
  const raw = JSON.parse(fs.readFileSync(file, "utf8"));
  const accounts = raw.accounts || raw;
  if (!Array.isArray(accounts) || accounts.length === 0) {
    throw new Error("Batch file must contain non-empty accounts[]");
  }
  // Normalize shapes: {credentials, options} or flat {email, password, ...}
  return accounts.map((a, i) => {
    if (a.credentials) {
      return {
        credentials: a.credentials,
        options: a.options || {},
      };
    }
    if (a.email) {
      const { email, password, name, proxy, ...rest } = a;
      return {
        credentials: { email, password, name, ...rest },
        options: proxy ? { proxy } : {},
      };
    }
    throw new Error(`Account #${i + 1}: need credentials.email or email field`);
  });
}

// ─── proxy plan ─────────────────────────────────────────────────────────────

/**
 * Convert a parsed proxy object (or URL string) to a URL string for options.proxy.
 * Grok worker expects a string; browser providers accept object or string.
 * Never log credentials — only host:port for display.
 */
function proxyToUrl(proxy) {
  if (!proxy) return null;
  if (typeof proxy === "string") {
    const p = parseProxyLine(proxy);
    if (!p) return proxy.trim() || null;
    proxy = p;
  }
  const auth =
    proxy.username && proxy.password
      ? `${proxy.username}:${proxy.password}@`
      : "";
  return `${proxy.protocol || "http"}://${auth}${proxy.host}:${proxy.port}`;
}

function proxyDisplay(proxy) {
  if (!proxy) return "none";
  if (typeof proxy === "string") {
    const p = parseProxyLine(proxy);
    if (!p) return "(custom url)";
    proxy = p;
  }
  return `${proxy.protocol || "http"}://${proxy.host}:${proxy.port}`;
}

function resolveProxyFile(config) {
  const raw = (config && config.proxyFile) || "proxies.txt";
  return path.isAbsolute(raw) ? raw : path.join(process.cwd(), raw);
}

/**
 * Interactive proxy mode picker.
 * @returns {Promise<{mode: 'none'|'rotate'|'single', proxies?: object[], singleUrl?: string, file?: string}>}
 */
async function pickProxyMode(rl, config) {
  const mode = await choose(rl, "Mode Proxy", [
    {
      value: "none",
      label: "non-proxy",
      hint: "langsung IP mesin (tanpa proxy)",
    },
    {
      value: "rotate",
      label: "proxy rotate",
      hint: "satu proxy per akun, cycle dari proxies.txt",
    },
    {
      value: "single",
      label: "proxy single",
      hint: "satu URL proxy dipakai semua akun",
    },
  ]);

  if (mode === "none") {
    noteLine("non-proxy: options.proxy dibersihkan", "info");
    return { mode: "none" };
  }

  if (mode === "single") {
    const url = await ask(rl, "Proxy URL (http://user:pass@host:port)");
    if (!url) throw new Error("Proxy URL required for single mode");
    const parsed = parseProxyLine(url);
    if (!parsed) throw new Error("Invalid proxy URL format");
    noteLine(`single proxy ${proxyDisplay(parsed)} for all accounts`, "ok");
    return { mode: "single", singleUrl: proxyToUrl(parsed) };
  }

  // rotate
  const defaultFile = resolveProxyFile(config);
  const file = await ask(rl, "Path proxies.txt", { defaultValue: defaultFile });
  const proxies = loadProxies(file);
  if (proxies.length === 0) {
    throw new Error(
      `No valid proxies in ${file}. Formats: protocol://user:pass@host:port | host:port:user:pass`
    );
  }
  showPanel("PROXY ROTATE", [
    tag("Status", "ENABLED", "brightGreen"),
    tag("Count", String(proxies.length), "brightYellow"),
    tag("File", file, "cyan"),
    tag("First", proxyDisplay(proxies[0]), "yellow"),
  ]);
  noteLine(`rotate · ${proxies.length} proxy`, "ok");
  return { mode: "rotate", proxies, file };
}

/**
 * Apply proxy plan onto account list (mutates options.proxy).
 * - none: strip any existing proxy
 * - single: same URL on every account
 * - rotate: cycle pool by account index (overwrites batch-file proxies)
 */
function applyProxyPlan(accounts, plan) {
  if (!plan || plan.mode === "none") {
    for (const a of accounts) {
      if (a.options) delete a.options.proxy;
      else a.options = {};
    }
    return { label: "non-proxy", detail: "no proxy" };
  }

  if (plan.mode === "single") {
    for (const a of accounts) {
      a.options = { ...(a.options || {}), proxy: plan.singleUrl };
    }
    return {
      label: "proxy-single",
      detail: proxyDisplay(plan.singleUrl),
    };
  }

  // rotate
  for (let i = 0; i < accounts.length; i++) {
    const p = getProxyForAccount(plan.proxies, i);
    accounts[i].options = {
      ...(accounts[i].options || {}),
      proxy: proxyToUrl(p),
    };
  }
  return {
    label: "proxy-rotate",
    detail: `${plan.proxies.length} proxies, cycle by index`,
  };
}

// ─── session dashboard (web-UI-ish TUI from boot → run) ───────────────────────
// Fixed frame for the whole interactive session:
//   header · wizard steps · content panel · working/progress · compact log
// Menus/preflight/confirm render in the content panel; runAccounts reuses the
// same shell (no second alt-screen). Secrets filtered; raw JSONL never shown.

const STEP_LABELS = {
  tempmail_init: "init temp-mail",
  tempmail_create: "buat email temp",
  bootstrap: "bootstrap CF",
  create_email_code: "kirim kode email",
  otp: "tunggu OTP",
  tempmail_otp: "tunggu OTP",
  verify_email_code: "verifikasi email",
  turnstile: "Turnstile",
  create_user: "buat akun",
  sso: "SSO cookies",
  device_consent: "device consent",
  self_test: "self-test",
  validate_password: "cek password",
};

const WIZARD_STEPS = [
  { key: "mode", label: "Mode" },
  { key: "provider", label: "Provider" },
  { key: "preflight", label: "Preflight" },
  { key: "accounts", label: "Accounts" },
  { key: "proxy", label: "Proxy" },
  { key: "confirm", label: "Confirm" },
  { key: "run", label: "Run" },
];

// Match lines that look like they *contain a secret value*, not just the word
// "password". xAI form errors ("password: Password too weak") are allow-listed
// in looksSecret() so the user still sees the reason for create_user failures.
const SECRET_RE = new RegExp(
  [
    String.raw`(?:clearTextPassword|password)\s*["']?\s*[:=]\s*["']?[^\s,"'}]{3,}`,
    String.raw`(?:device_code|codeVerifier|code_verifier)\s*["']?\s*[:=]\s*["']?\S+`,
    String.raw`authorization:\s*bearer\s+\S+`,
    String.raw`\botp(?:[_-\s]?code)?\s*(?:is|=|:)?\s*[0-9A-Z]{3}[- ]?[0-9A-Z]{3}\b`,
    String.raw`\b(?:otp|verification)\s*code\s*[:=]\s*\S+`,
  ].join("|"),
  "i"
);

const PASSWORD_POLICY_RE =
  /password\s+too\s+weak|choose a stronger password|form-invalid:password|WKE=form-invalid:password/i;

function looksSecret(line) {
  const s = String(line || "");
  if (!s) return false;
  if (PASSWORD_POLICY_RE.test(s)) return false;
  return SECRET_RE.test(s);
}

function shortError(msg) {
  const s = String(msg || "").replace(/\s+/g, " ").trim();
  const m = s.match(/password:\s*([^.]+)/i);
  if (m) return m[1].trim();
  return s.length > 72 ? s.slice(0, 71) + "…" : s;
}

/**
 * Compact a provider/worker console line or JSONL payload into a short status.
 * Returns { work?, log?, level? } or null to drop the line.
 */
function compactLogLine(raw) {
  const line = String(raw ?? "").replace(/\n+$/, "");
  if (!line.trim()) return null;
  if (looksSecret(line)) return null;

  const stripped = line.replace(/^\[[^\]]+\]\s*/, "").trim();

  let jsonStr = null;
  const workerM = stripped.match(/^\[worker(?::debug)?\]\s*(\{.*\})\s*$/);
  if (workerM) jsonStr = workerM[1];
  else if (stripped.startsWith("{") && stripped.endsWith("}")) jsonStr = stripped;

  if (jsonStr) {
    let obj;
    try {
      obj = JSON.parse(jsonStr);
    } catch {
      return { log: "worker: (unparsed)", level: "dim" };
    }
    const payload = obj.payload && typeof obj.payload === "object" ? obj.payload : obj;

    if (payload.kind === "result" || obj.kind === "result") {
      const ok = payload.ok !== false && obj.ok !== false;
      if (ok) return { work: "worker selesai", log: "hasil worker: OK", level: "ok" };
      const err = shortError(payload.error || obj.error || "failed");
      const step = payload.step || obj.step;
      const stepLbl = step ? (STEP_LABELS[step] || step) + " · " : "";
      return {
        work: `gagal · ${stepLbl}${err}`,
        log: `gagal: ${stepLbl}${err}`,
        level: "fail",
      };
    }

    if (payload.event === "debug" || obj.event === "debug") {
      const msg = payload.msg || obj.msg || "";
      if (/miss|retry|incomplete|soft_fail|error/i.test(msg)) {
        return { log: `debug: ${msg}`, level: "dim" };
      }
      return null;
    }

    const step = payload.step || obj.step;
    const status = payload.status || obj.status || "";
    if (step) {
      const base = STEP_LABELS[step] || step;
      let detail = "";
      if (payload.address) detail = ` · ${payload.address}`;
      else if (typeof payload.elapsed_s === "number") detail = ` · ${payload.elapsed_s}s`;
      else if (typeof payload.ms === "number") detail = ` · ${(payload.ms / 1000).toFixed(1)}s`;
      else if (payload.approved === true) detail = " · approved";
      else if (Array.isArray(payload.cookies)) detail = ` · ${payload.cookies.length} cookie`;
      else if (payload.principal_source) detail = ` · via ${payload.principal_source}`;
      const work =
        status === "ok" || status === ""
          ? `${base}${detail}`
          : `${base} (${status})${detail}`;
      const level = status === "fail" || status === "error" ? "fail" : "ok";
      return { work, log: work, level: status === "pending" ? "dim" : level };
    }
  }

  if (/Device code received/i.test(stripped)) {
    return { work: "device code", log: "device code diterima", level: "ok" };
  }
  if (/Spawning Python/i.test(stripped)) {
    return { work: "spawn worker", log: "spawn pure-HTTP worker", level: "dim" };
  }
  if (/Connection established/i.test(stripped)) {
    return { work: "koneksi OK", log: "connection established", level: "ok" };
  }
  if (/Poll attempt\s+(\d+).*pending/i.test(stripped)) {
    const n = stripped.match(/Poll attempt\s+(\d+)/i)[1];
    return { work: `poll #${n}`, log: `poll pending #${n}`, level: "dim" };
  }
  if (/Poll attempt/i.test(stripped)) {
    return { work: "polling 9router", log: truncVis(stripped, 70), level: "dim" };
  }
  if (/rename failed/i.test(stripped)) {
    return { log: "rename gagal (non-fatal)", level: "warn" };
  }
  if (/worker failed/i.test(stripped) || /grok-cli worker failed/i.test(line)) {
    return {
      work: "worker gagal",
      log: shortError(stripped.replace(/^grok-cli worker failed:\s*/i, "")),
      level: "fail",
    };
  }

  const plain = stripAnsi(stripped);
  if (plain.length < 4) return null;
  return { log: truncVis(plain, 70), level: "dim" };
}

/** Global session shell (set by main). Interactive helpers read this. */
let APP = null;

/**
 * Session-long web-like CLI shell.
 * Wizard steps + live run share one alt-screen frame.
 * LiveDashboard API (beginAccount/finishAccount/ingest) preserved for run + tests.
 */
class AppShell {
  /**
   * @param {{ provider?: string, mode?: string, total?: number, proxyLabel?: string }} [opts]
   */
  constructor(opts = {}) {
    this.provider = opts.provider || "—";
    this.mode = opts.mode || "—";
    this.total = opts.total || 0;
    this.proxyLabel = opts.proxyLabel || "—";
    this.phase = "wizard"; // wizard | run | summary
    this.stepKey = "mode";
    this.stepStatus = Object.fromEntries(WIZARD_STEPS.map((s) => [s.key, "pending"]));
    this.contentTitle = "BOOT";
    this.content = ["  Memulai dashboard…"];
    this.work = "siap";
    this.index = 0;
    this.email = "—";
    this.proxy = "—";
    this.ok = 0;
    this.fail = 0;
    this.skip = 0;
    this.logs = [];
    this.maxLogs = 8;
    this.maxContent = 14;
    this.startedAt = Date.now();
    this._active = false;
    this._tty = !!(process.stdout && process.stdout.isTTY);
    this._origLog = null;
    this._origErr = null;
    this._origWarn = null;
    this._renderTimer = null;
    this._dirty = false;
    this._width = Math.max(60, Math.min(100, process.stdout.columns || 80));
    this._hooksInstalled = false;
  }

  start() {
    if (this._active) return;
    this._active = true;
    this.startedAt = Date.now();
    if (this._tty) {
      process.stdout.write("\x1b[?1049h\x1b[?25l");
    }
    this._installConsoleHooks();
    this.render(true);
  }

  stop() {
    if (!this._active) return;
    this._active = false;
    if (this._renderTimer) {
      clearTimeout(this._renderTimer);
      this._renderTimer = null;
    }
    this._restoreConsoleHooks();
    if (this._tty) {
      this.render(true);
      process.stdout.write("\x1b[?25h\x1b[?1049l");
    }
  }

  /** Advance wizard step (marks previous done, current active). */
  setStep(key) {
    const keys = WIZARD_STEPS.map((s) => s.key);
    const idx = keys.indexOf(key);
    if (idx < 0) return;
    for (let i = 0; i < keys.length; i++) {
      if (i < idx) this.stepStatus[keys[i]] = "done";
      else if (i === idx) this.stepStatus[keys[i]] = "active";
      // leave later as-is (pending) unless already done
    }
    this.stepKey = key;
    if (key === "run") this.phase = "run";
    this._scheduleRender();
  }

  setMeta({ provider, mode, proxyLabel } = {}) {
    if (provider != null) this.provider = provider;
    if (mode != null) this.mode = mode;
    if (proxyLabel != null) this.proxyLabel = proxyLabel;
    this._scheduleRender();
  }

  /**
   * Put a panel into the content area (replaces goldBox console output).
   * @param {string} title
   * @param {string[]} lines
   */
  setContent(title, lines) {
    this.contentTitle = String(title || "");
    const arr = Array.isArray(lines) ? lines : [String(lines ?? "")];
    // Keep last maxContent lines so tall menus still fit.
    this.content = arr.length > this.maxContent
      ? arr.slice(arr.length - this.maxContent)
      : arr.slice();
    if (!this._tty || !this._active) {
      // Non-TTY / inactive: print as gold box for readability.
      (this._origLog || console.log)();
      (this._origLog || console.log)(goldBox(this.contentTitle, this.content, 56));
      return;
    }
    this._scheduleRender();
  }

  setWork(msg) {
    if (!msg) return;
    this.work = String(msg);
    this._scheduleRender();
  }

  log(msg, level = "dim") {
    if (!msg) return;
    this._pushLog(msg, level);
    this._scheduleRender();
  }

  note(msg, level = "info") {
    this.log(msg, level);
  }

  /** Switch into run phase (reuses same alt-screen). */
  enterRun({ total, proxyLabel } = {}) {
    this.phase = "run";
    this.setStep("run");
    this.total = total || this.total || 0;
    if (proxyLabel) this.proxyLabel = proxyLabel;
    this.ok = 0;
    this.fail = 0;
    this.skip = 0;
    this.index = 0;
    this.email = "—";
    this.proxy = "—";
    this.work = "menyiapkan…";
    this._pushLog(`mulai run · ${this.total} akun`, "info");
    this.setContent("LIVE RUN", [
      tag("Provider", this.provider, "brightYellow"),
      tag("Mode", this.mode, "cyan"),
      tag("Akun", String(this.total), "brightGreen"),
      tag("Proxy", this.proxyLabel, "yellow"),
      "",
      style.dim("  Worker log disingkat · secret disaring"),
    ]);
  }

  beginAccount(i, email, proxyDisp) {
    this.index = i;
    this.email = email || `#${i}`;
    this.proxy = proxyDisp || "direct";
    this.work = "mulai…";
    this._pushLog(`akun ${i}/${this.total} · ${this.email}`, "info");
    this._scheduleRender();
  }

  ingest(raw) {
    const c = compactLogLine(raw);
    if (!c) return;
    if (c.work) this.work = c.work;
    if (c.log) this._pushLog(c.log, c.level || "dim");
    this._scheduleRender();
  }

  finishAccount(status, detail) {
    if (status === "ok") this.ok += 1;
    else if (status === "skip") this.skip += 1;
    else this.fail += 1;
    const label =
      status === "ok" ? "OK" : status === "skip" ? "SKIP" : "FAIL";
    const level = status === "ok" ? "ok" : status === "skip" ? "warn" : "fail";
    this._pushLog(
      `${label} · ${this.email}${detail ? " · " + detail : ""}`,
      level
    );
    this.work =
      status === "ok"
        ? "selesai"
        : status === "skip"
          ? `skip · ${detail || ""}`
          : `gagal · ${detail || ""}`;
    this._scheduleRender();
  }

  /**
   * Ask a question under the frame (redraw first so prompt sits cleanly).
   */
  async ask(rl, question, opts) {
    if (this._tty && this._active) {
      this.render(true);
      // Show cursor while typing.
      process.stdout.write("\x1b[?25h");
    }
    try {
      return await askRaw(rl, question, opts);
    } finally {
      if (this._tty && this._active) {
        process.stdout.write("\x1b[?25l");
      }
    }
  }

  async askHidden(rl, question) {
    if (this._tty && this._active) {
      this.render(true);
      process.stdout.write("\x1b[?25h");
    }
    try {
      return await askHiddenRaw(rl, question);
    } finally {
      if (this._tty && this._active) {
        process.stdout.write("\x1b[?25l");
      }
    }
  }

  _pushLog(text, level) {
    const t = new Date();
    const hh = String(t.getHours()).padStart(2, "0");
    const mm = String(t.getMinutes()).padStart(2, "0");
    const ss = String(t.getSeconds()).padStart(2, "0");
    this.logs.push({
      t: `${hh}:${mm}:${ss}`,
      text: truncVis(String(text), this._width - 14),
      level: level || "dim",
    });
    while (this.logs.length > this.maxLogs) this.logs.shift();
  }

  _scheduleRender() {
    this._dirty = true;
    if (!this._tty) {
      const last = this.logs[this.logs.length - 1];
      if (last && this._active) {
        const color =
          last.level === "ok"
            ? style.brightGreen
            : last.level === "fail"
              ? style.brightRed
              : last.level === "warn"
                ? style.yellow
                : last.level === "info"
                  ? style.cyan
                  : style.dim;
        (this._origLog || console.log)(
          `${style.dim(last.t)} ${color(last.text)}`
        );
      }
      this._dirty = false;
      return;
    }
    if (this._renderTimer) return;
    this._renderTimer = setTimeout(() => {
      this._renderTimer = null;
      if (this._dirty && this._active) this.render(true);
    }, 80);
  }

  _bar(done, total, width) {
    const t = Math.max(1, total);
    const filled = Math.round((Math.min(done, t) / t) * width);
    const empty = Math.max(0, width - filled);
    return (
      style.brightGreen("█".repeat(filled)) + style.dim("░".repeat(empty))
    );
  }

  _elapsed() {
    const s = Math.floor((Date.now() - this.startedAt) / 1000);
    const m = Math.floor(s / 60);
    const r = s % 60;
    return m > 0 ? `${m}m${String(r).padStart(2, "0")}s` : `${r}s`;
  }

  _stepBar(inner) {
    // Compact step chips: · Mode · [Provider] · Preflight …
    const parts = [];
    for (const s of WIZARD_STEPS) {
      const st = this.stepStatus[s.key] || "pending";
      if (st === "done") parts.push(style.brightGreen(`✓${s.label}`));
      else if (st === "active") parts.push(style.brightYellow(`[${s.label}]`));
      else parts.push(style.dim(s.label));
    }
    let joined = parts.join(style.dim(" › "));
    if (visLen(joined) > inner - 4) {
      // Fallback shorter labels
      joined = parts
        .map((p, i) => {
          const s = WIZARD_STEPS[i];
          const st = this.stepStatus[s.key];
          if (st === "done") return style.brightGreen("✓");
          if (st === "active") return style.brightYellow(`[${s.label[0]}]`);
          return style.dim(s.label[0]);
        })
        .join(style.dim(" "));
    }
    return joined;
  }

  render(force) {
    if (!this._active && !force) return;
    this._dirty = false;
    if (!this._tty) return;

    const W = Math.max(60, Math.min(100, process.stdout.columns || this._width));
    this._width = W;
    const inner = W - 2;

    const pad = (s, w) => {
      const vis = visLen(s);
      if (vis >= w) return truncVis(s, w);
      return s + " ".repeat(w - vis);
    };
    const row = (content) =>
      `\x1b[93m║\x1b[0m${pad(content, inner)}\x1b[93m║\x1b[0m`;

    const title = " 9ROUTER-ADD · DASHBOARD ";
    const side = Math.max(0, Math.floor((inner - title.length) / 2));
    const right = Math.max(0, inner - title.length - side);
    const top =
      `\x1b[93m╔${"═".repeat(side)}\x1b[0m` +
      `\x1b[1;93m${title}\x1b[0m` +
      `\x1b[93m${"═".repeat(right)}╗\x1b[0m`;
    const mid = `\x1b[93m╠${"═".repeat(inner)}╣\x1b[0m`;
    const bot = `\x1b[93m╚${"═".repeat(inner)}╝\x1b[0m`;

    const lines = [top];

    // Header meta
    lines.push(
      row(
        `  ${style.cyan("Provider")} ${style.brightYellow(truncVis(this.provider, 14))}` +
          `  ${style.cyan("Mode")} ${style.brightCyan(String(this.mode))}` +
          `  ${style.cyan("Proxy")} ${style.yellow(truncVis(this.proxyLabel, 16))}` +
          `  ${style.dim(this._elapsed())}`
      )
    );

    // Wizard step bar
    lines.push(row(`  ${this._stepBar(inner)}`));
    lines.push(mid);

    // Content panel
    const cTitle = truncVis(this.contentTitle || "PANEL", inner - 4);
    lines.push(row(`  ${style.gold(cTitle)}`));
    const contentSlots = this.maxContent;
    const content = this.content || [];
    const cStart = Math.max(0, content.length - contentSlots);
    for (let i = 0; i < contentSlots; i++) {
      const line = content[cStart + i];
      if (line == null) {
        lines.push(row(`  ${style.dim(" ")}`));
        continue;
      }
      lines.push(row(truncVis(String(line), inner)));
    }

    lines.push(mid);

    // Working + progress
    if (this.phase === "run" || this.total > 0) {
      const done = this.ok + this.fail + this.skip;
      const progressLabel = this.index
        ? `${this.index}/${this.total}`
        : `0/${this.total || 0}`;
      const bar = this._bar(
        done,
        Math.max(1, this.total || 1),
        Math.min(20, Math.max(8, inner - 48))
      );
      lines.push(
        row(
          `  ${style.cyan("Progress")} ${style.brightWhite(progressLabel)} ${bar}` +
            ` ${style.brightGreen("OK:" + this.ok)}` +
            ` ${style.brightRed("FAIL:" + this.fail)}` +
            ` ${style.yellow("SKIP:" + this.skip)}`
        )
      );
      lines.push(
        row(
          `  ${style.cyan("Account ")} ${style.brightCyan(truncVis(this.email, Math.max(18, inner - 30)))}` +
            `  ${style.dim(this.proxy)}`
        )
      );
    }
    lines.push(
      row(
        `  ${style.cyan("Working ")} ${style.brightWhite(truncVis(this.work, inner - 14))}`
      )
    );

    lines.push(mid);
    lines.push(row(`  ${style.gold("LOG")}`));

    const logSlots = this.maxLogs;
    const start = Math.max(0, this.logs.length - logSlots);
    for (let i = 0; i < logSlots; i++) {
      const entry = this.logs[start + i];
      if (!entry) {
        lines.push(row(`  ${style.dim("·")}`));
        continue;
      }
      const color =
        entry.level === "ok"
          ? style.brightGreen
          : entry.level === "fail"
            ? style.brightRed
            : entry.level === "warn"
              ? style.yellow
              : entry.level === "info"
                ? style.cyan
                : style.dim;
      lines.push(
        row(`  ${style.dim(entry.t)} ${color(truncVis(entry.text, inner - 12))}`)
      );
    }
    lines.push(bot);

    process.stdout.write("\x1b[H\x1b[J" + lines.join("\n") + "\n");
  }

  _installConsoleHooks() {
    if (this._hooksInstalled) return;
    this._origLog = console.log;
    this._origErr = console.error;
    this._origWarn = console.warn;
    this._hooksInstalled = true;
    const self = this;
    const wrap =
      (orig) =>
      (...args) => {
        if (!self._active) return orig.apply(console, args);
        const joined = args
          .map((a) => {
            if (typeof a === "string") return a;
            try {
              return JSON.stringify(a);
            } catch {
              return String(a);
            }
          })
          .join(" ");
        // During wizard, goldBox multi-line dumps are noisy — drop pure-empty,
        // feed the rest through compactLogLine (or short note).
        if (!joined.trim()) return;
        // Box-drawing frames from legacy goldBox console.log → ignore
        if (/^[╔╚╠║]/.test(stripAnsi(joined).trim()) || /═{3,}/.test(joined)) {
          return;
        }
        self.ingest(joined);
      };
    console.log = wrap(this._origLog);
    console.error = wrap(this._origErr);
    console.warn = wrap(this._origWarn);
  }

  _restoreConsoleHooks() {
    if (!this._hooksInstalled) return;
    if (this._origLog) console.log = this._origLog;
    if (this._origErr) console.error = this._origErr;
    if (this._origWarn) console.warn = this._origWarn;
    this._origLog = this._origErr = this._origWarn = null;
    this._hooksInstalled = false;
  }
}

// Back-compat alias for smoke tests / older call sites.
const LiveDashboard = AppShell;

// ─── run ────────────────────────────────────────────────────────────────────

async function buildApi(config) {
  const api = { request };
  const authHeaders = await resolveAuthHeaders(config, api);
  const original = api.request;
  api.request = (cfg, opts) =>
    original(cfg, {
      ...opts,
      headers: { ...authHeaders, ...(opts.headers || {}) },
    });
  return api;
}

async function runAccounts(config, api, providerName, accounts) {
  const providers = loadProviders(config, api);
  const Provider = providers[providerName];
  if (!Provider) throw new Error(`Provider not loaded: ${providerName}`);

  const baseConfig = {
    ...config,
    _provider: providerName,
    providerConfig: (config.providers && config.providers[providerName]) || {},
  };

  const summary = { ok: 0, fail: 0, skip: 0, errors: [] };
  const total = accounts.length;

  // Infer proxy label from first account (plan already applied).
  let proxyLabel = "non-proxy";
  const firstPx = accounts[0] && accounts[0].options && accounts[0].options.proxy;
  if (firstPx) {
    const allSame = accounts.every(
      (a) => a.options && a.options.proxy === firstPx
    );
    proxyLabel = allSame ? "single" : "rotate";
  }

  // Reuse session shell when available (no second alt-screen).
  const ownsDash = !(APP && APP._active);
  const dash =
    APP && APP._active
      ? APP
      : new LiveDashboard({
          provider: providerName,
          mode: config.mode || "?",
          total,
          proxyLabel,
        });
  if (ownsDash) dash.start();
  else {
    dash.setMeta({
      provider: providerName,
      mode: config.mode || "?",
      proxyLabel,
    });
    dash.enterRun({ total, proxyLabel });
  }

  try {
    for (let i = 0; i < total; i++) {
      const { credentials, options } = accounts[i];
      const label = credentials.email || `#${i + 1}`;
      const px =
        options && options.proxy ? proxyDisplay(options.proxy) : "direct";
      dash.beginAccount(i + 1, label, px);
      dash.setWork("menyiapkan provider…");

      // Fresh provider + services per account (matches cli batch semantics).
      const provider = new Provider(baseConfig, api, loadServices(baseConfig));
      try {
        const result = await provider.add(credentials, options || {});
        if (result && result.skip) {
          summary.skip += 1;
          dash.finishAccount("skip", result.reason || "skipped");
        } else if (result && result.ok !== false) {
          summary.ok += 1;
          const id =
            (result.connection && result.connection.id) || result.id || "?";
          // Prefer real email if tempmail worker updated it on the provider.
          if (provider._accountEmail && provider._accountEmail !== label) {
            dash.email = provider._accountEmail;
          }
          dash.finishAccount("ok", `id=${id}`);
        } else {
          summary.fail += 1;
          const why =
            (result && (result.reason || result.error)) || "unknown";
          dash.finishAccount("fail", shortError(why));
        }
      } catch (e) {
        summary.fail += 1;
        summary.errors.push({ email: label, error: e.message });
        dash.finishAccount("fail", shortError(e.message));
      }
    }
  } finally {
    // Only stop if we own the shell (standalone run). Session main() stops APP.
    if (ownsDash) dash.stop();
  }

  const sumLines = [
    tag("OK", String(summary.ok), summary.ok > 0 ? "brightGreen" : "dim"),
    tag("Fail", String(summary.fail), summary.fail > 0 ? "brightRed" : "dim"),
    tag("Skip", String(summary.skip), summary.skip > 0 ? "brightYellow" : "dim"),
    tag("Total", String(total), "cyan"),
  ];
  if (summary.errors.length) {
    sumLines.push("");
    for (const e of summary.errors) {
      sumLines.push(
        `  ${style.red("•")} ${dim(e.email)}: ${style.red(shortError(e.error))}`
      );
    }
  }
  // Show summary in panel while shell still up; also goldBox after exit.
  if (APP && APP._active && !ownsDash) {
    APP.phase = "summary";
    APP.setContent("SUMMARY", sumLines);
    APP.setWork("selesai");
    APP.note(
      `done · OK ${summary.ok} · FAIL ${summary.fail} · SKIP ${summary.skip}`,
      summary.fail ? "warn" : "ok"
    );
  } else {
    console.log();
    console.log(goldBox("SUMMARY", sumLines, 56));
  }
  return summary;
}

// ─── mode config ────────────────────────────────────────────────────────────

async function pickModeConfig(rl) {
  const mode = await choose(rl, "Koneksi 9router", [
    {
      value: "local",
      label: "local",
      hint: "mesin yang sama · CLI token · SQLite langsung",
    },
    {
      value: "remote",
      label: "remote",
      hint: "VPS/domain · dashboard password · HTTPS wajib",
    },
  ]);

  // Base from config.json / env / defaults, then override mode.
  let config = loadConfig(process.argv.slice(2), { mode });

  if (mode === "local") {
    config.mode = "local";
    // Keep host/port/proto from file; force local defaults if missing.
    config.host = config.host || "localhost";
    config.port = config.port || 20128;
    config.proto = config.proto || "http";
    if (!config.dbPath) {
      config.dbPath = path.join(os.homedir(), ".9router", "db", "data.sqlite");
    }
    showPanel("LOCAL MODE", [
      tag("Status", "ENABLED", "brightGreen"),
      tag("Endpoint", `${config.proto}://${config.host}:${config.port}`, "cyan"),
      tag("DB Path", config.dbPath, "yellow"),
      tag("Auth", "CLI token (machine-id)", "dim"),
    ]);
    if (APP) {
      APP.setMeta({ mode: "local" });
      APP.note("mode local", "ok");
    }
  } else {
    config.mode = "remote";
    const host = await ask(rl, "Remote host", {
      defaultValue: config.host && !isLocalHost(config.host) ? config.host : "",
    });
    if (!host) throw new Error("Remote host required");
    const portRaw = await ask(rl, "Port", {
      defaultValue: String(config.port || 443),
    });
    const protoDefault =
      isLocalHost(host) ? config.proto || "http" : "https";
    const proto = await ask(rl, "Proto (https recommended)", {
      defaultValue: protoDefault,
    });
    config.host = host;
    config.port = Number(portRaw) || 443;
    config.proto = proto;

    if (config.proto === "http" && !isLocalHost(config.host)) {
      throw new Error("Security: remote non-localhost requires HTTPS. Set proto=https.");
    }

    let password = config.password || process.env["9R_ADD_PASSWORD"] || "";
    if (!password) {
      password = await askHidden(rl, "Dashboard password (hidden)");
    } else {
      if (APP) APP.note("password from config/env", "info");
      else console.log(`  ${infoBadge()} password from config/env`);
    }
    if (!password) throw new Error("Dashboard password required for remote");
    config.password = password;

    showPanel("REMOTE MODE", [
      tag("Status", "ENABLED", "brightGreen"),
      tag("Endpoint", `${config.proto}://${config.host}:${config.port}`, "cyan"),
      tag("Auth", "dashboard password", "yellow"),
      tag("TLS", config.proto === "https" ? "required" : "off", config.proto === "https" ? "brightGreen" : "red"),
    ]);
    if (APP) {
      APP.setMeta({ mode: "remote" });
      APP.note("mode remote", "ok");
    }
  }

  return config;
}

// ─── main ───────────────────────────────────────────────────────────────────

async function main() {
  const rl = createRl();

  // Session-wide dashboard from boot (wizard → run → summary).
  APP = new AppShell({});
  APP.start();
  APP.setStep("mode");
  APP.setContent("BOOT", [
    tag("App", "9router-add", "brightYellow"),
    tag("UI", "CLI dashboard", "cyan"),
    tag("Providers", "antigravity · kiro · grok-cli", "dim"),
    "",
    style.dim("  Header · steps · panel · working · log"),
    style.dim("  Secret disaring · log disingkat"),
  ]);
  APP.setWork("start captcha-solver…");
  APP.note("dashboard siap", "info");

  // Always try to bring up local Turnstile solver (whether provider needs it or not).
  // Ownership: only kill on exit if we spawned it; external :8877 is left alone.
  {
    APP.note("captcha-solver: ensuring :8877…", "info");
    const sol = await ensureSolverStarted();
    if (sol.ok && sol.reused) {
      APP.note("captcha-solver: reuse existing :8877", "ok");
    } else if (sol.ok && sol.owned) {
      APP.note("captcha-solver: started (owned)", "ok");
    } else {
      APP.note(
        `captcha-solver: not ready (${sol.error || "unknown"}) — grok-cli preflight will fail`,
        "warn"
      );
    }
  }
  APP.setWork("pilih mode koneksi");

  try {
    // 1) Mode
    APP.setStep("mode");
    const config = await pickModeConfig(rl);

    // 2) Provider
    APP.setStep("provider");
    APP.setWork("pilih provider");
    const providerName = await choose(rl, "Pilih Provider", [
      {
        value: "antigravity",
        label: "antigravity",
        hint: "Google OAuth only",
      },
      {
        value: "kiro",
        label: "kiro",
        hint: "email alias / Gmail plus-alias · IMAP · temp-mail",
      },
      {
        value: "grok-cli",
        label: "grok-cli",
        hint: "email + IMAP OTP / temp-mail (pure-HTTP)",
      },
    ]);
    const info = PROVIDER_INFO[providerName];
    APP.setMeta({ provider: providerName, mode: config.mode });
    showPanel("PROVIDER INFO", [
      tag("Name", info.label, "brightYellow"),
      tag("Methods", info.methods.join(", "), "yellow"),
      tag("Batch", info.batch ? "ENABLED" : "DISABLED", info.batch ? "brightGreen" : "red"),
      tag("Browser", info.needsBrowser ? "required" : "no", info.needsBrowser ? "yellow" : "dim"),
      tag("Worker", info.needsWorker ? "python pure-HTTP" : "no", info.needsWorker ? "cyan" : "dim"),
      tag("Solver", info.needsSolver ? ":8877 turnstile" : "no", info.needsSolver ? "cyan" : "dim"),
      "",
      ...(info.notes ? [style.dim("  " + info.notes)] : []),
    ]);
    APP.note(`provider ${providerName}`, "ok");

    // 3) Preflight
    APP.setStep("preflight");
    APP.setWork("preflight check…");
    const pf = await preflight(config, providerName);
    const pfLines = [];
    for (const line of pf.lines) {
      pfLines.push(`  ${style.cyan("◆")} ${line}`);
    }
    for (const w of pf.warnings) {
      pfLines.push(`  ${style.yellow("!")} ${style.yellow(w)}`);
    }
    for (const e of pf.errors) {
      pfLines.push(`  ${style.red("✗")} ${style.red(e)}`);
    }
    pfLines.push("");
    pfLines.push(
      pf.ok
        ? tag("Status", "ENABLED", "brightGreen")
        : tag("Status", "FAILED", "brightRed")
    );
    showPanel("PREFLIGHT CHECK", pfLines);
    if (!pf.ok) {
      APP.setWork("preflight gagal");
      APP.note("preflight failed", "fail");
      const cont = await ask(rl, "Preflight gagal. Lanjut tetap? (y/N)", {
        defaultValue: "n",
      });
      if (!yn(cont)) {
        APP.note("dibatalkan", "warn");
        APP.setWork("dibatalkan");
        return;
      }
    } else {
      APP.note("preflight OK", "ok");
    }

    // 4) Single / batch / auto
    APP.setStep("accounts");
    APP.setWork("mode eksekusi");
    const execOptions = [
      {
        value: "single",
        label: "single",
        hint: "satu akun, input email/password manual",
      },
      {
        value: "batch",
        label: "batch",
        hint: "file JSON, loop one-by-one",
      },
    ];
    if (supportsAutoCredentials(providerName)) {
      execOptions.push({
        value: "auto",
        label: "auto",
        hint: "generate email (alias or temp-mail) + password + name",
      });
    }
    const runMode = await choose(rl, "Mode Eksekusi", execOptions);

    let accounts;
    if (runMode === "single") {
      accounts = [await promptSingleAccount(rl, providerName)];
    } else if (runMode === "auto") {
      accounts = await promptAutoAccounts(rl, config, providerName);
    } else {
      showPanel("BATCH JSON FORMAT", [
        "  {",
        '    "accounts": [',
        "      {",
        '        "credentials": { "email": "...", "password": "..." },',
        '        "options": { "proxy": "...", "emailSource": "imap" }',
        "      }",
        "    ]",
        "  }",
        "",
        style.dim('  Note: tempmail → options.emailSource = "tempmail"'),
      ]);
      accounts = await loadBatchFile(rl);
      APP.note(`loaded ${accounts.length} account(s)`, "ok");
    }
    APP.note(`accounts: ${accounts.length}`, "info");

    // 5) Proxy mode
    APP.setStep("proxy");
    APP.setWork("mode proxy");
    const proxyPlan = await pickProxyMode(rl, config);
    const proxySummary = applyProxyPlan(accounts, proxyPlan);
    APP.setMeta({ proxyLabel: proxySummary.label });

    // Confirm
    APP.setStep("confirm");
    APP.setWork("konfirmasi");
    showPanel("KONFIRMASI RUN", [
      tag("Provider", providerName, "brightYellow"),
      tag("Mode", config.mode, "cyan"),
      tag("Akun", String(accounts.length), "brightGreen"),
      tag("Proxy", proxySummary.label, "yellow"),
      proxySummary.detail
        ? tag("Proxy URL", proxySummary.detail, "dim")
        : tag("Proxy URL", "—", "dim"),
      tag("Status", "READY", "brightGreen"),
    ]);
    const confirm = await ask(rl, "Jalankan? (y/N)", { defaultValue: "n" });
    if (!yn(confirm)) {
      APP.note("dibatalkan", "warn");
      APP.setWork("dibatalkan");
      return;
    }
    APP.note("menjalankan…", "ok");

    // 6) Execute (reuses same APP shell)
    APP.setStep("run");
    const api = await buildApi(config);
    await runAccounts(config, api, providerName, accounts);
  } finally {
    await stopOwnedSolver();
    if (APP) {
      // Brief final paint then leave alt screen.
      try {
        APP.render(true);
      } catch {
        /* ignore */
      }
      APP.stop();
      APP = null;
    }
    rl.close();
  }
}

// Stop owned solver on signals (finally may not run if we force-exit).
function _signalShutdown(sig) {
  stopOwnedSolver()
    .catch(() => {})
    .finally(() => {
      if (APP) {
        try {
          APP.stop();
        } catch {
          /* ignore */
        }
        APP = null;
      }
      process.exit(sig === "SIGINT" ? 130 : 143);
    });
}
process.on("SIGINT", () => _signalShutdown("SIGINT"));
process.on("SIGTERM", () => _signalShutdown("SIGTERM"));

main().catch(async (err) => {
  try {
    await stopOwnedSolver();
  } catch {
    /* ignore */
  }
  console.error(`\n ${failBadge()} ${style.red("Fatal: " + err.message)}`);
  process.exit(1);
});
