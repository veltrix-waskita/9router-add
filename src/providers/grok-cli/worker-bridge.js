"use strict";

// Node↔Python bridge for the grok-cli pure-HTTP worker. Pure helpers only —
// unit-testable without instantiating the provider.
//
// Security contract: buildWorkerEnv must NEVER copy device_code or
// codeVerifier from deviceData into the worker env. Only user_code crosses
// the boundary, embedded in GROK_SIGNIN_URL.

const { spawn } = require("child_process");
const path = require("path");
const { ProviderError } = require("../../base/errors");

const SIGNIN_BASE =
  "https://accounts.x.ai/sign-in?redirect=oauth2-provider&return_to=";

const FIRST_NAMES = [
  "Alex",
  "Jordan",
  "Taylor",
  "Morgan",
  "Casey",
  "Riley",
  "Sam",
  "Jamie",
  "Drew",
  "Quinn",
];
const LAST_NAMES = [
  "Rivera",
  "Bennett",
  "Carter",
  "Reyes",
  "Ellis",
  "Novak",
  "Frost",
  "Hale",
  "Brooks",
  "Lane",
];

/**
 * Build the accounts.x.ai sign-in URL that carries the device user_code.
 * @param {string} userCode
 * @returns {string}
 */
function buildSignInUrl(userCode) {
  const returnUrl = `/oauth2/device?user_code=${userCode}`;
  return SIGNIN_BASE + encodeURIComponent(returnUrl);
}

function pickName(name) {
  if (name && String(name).trim().includes(" ")) {
    const parts = String(name).trim().split(/\s+/);
    return { first: parts[0], last: parts[parts.length - 1] };
  }
  const first = FIRST_NAMES[Math.floor(Math.random() * FIRST_NAMES.length)];
  const last = LAST_NAMES[Math.floor(Math.random() * LAST_NAMES.length)];
  return { first, last };
}

/**
 * Build the env-var object passed to worker/signup.py.
 *
 * Pure-HTTP: no chromiumPath. Always sets PURE_HTTP=1.
 * Supports dual email source mode via options.emailSource.
 *
 * @param {object} p
 * @param {object} p.deviceData - 9router device-code response; only user_code is used.
 * @param {object} p.credentials - { email, password, name? }.
 * @param {object} p.config - resolved config (uses .imap and .providers['grok-cli']).
 * @param {object} [p.options={}] - run options (optional .proxy, .emailSource, .tempmailProviders).
 * @returns {object<string,string>} env map for the child process.
 */
function buildWorkerEnv({ deviceData, credentials, config, options = {} }) {
  const imap = (config && config.imap) || {};
  const providerCfg =
    (config && config.providers && config.providers["grok-cli"]) ||
    (config && config.providerConfig) ||
    {};
  const { first, last } = pickName(credentials && credentials.name);

  const emailSource = (options && options.emailSource) || "imap";

  const env = {
    GROK_EMAIL: credentials && credentials.email,
    GROK_PASSWORD: credentials && credentials.password,
    GROK_SIGNIN_URL: buildSignInUrl(deviceData && deviceData.user_code),
    GROK_FIRST: first,
    GROK_LAST: last,
    GROK_EMAIL_SOURCE: emailSource,
    PURE_HTTP: "1",
  };

  // Temp-mail provider preference (optional).
  const tempmailProviders = options && options.tempmailProviders;
  if (tempmailProviders) {
    env.GROK_TEMPMAIL_PROVIDERS = Array.isArray(tempmailProviders)
      ? tempmailProviders.join(",")
      : String(tempmailProviders);
  }

  // IMAP env vars only for imap mode.
  if (emailSource === "imap") {
    env.GROK_IMAP_HOST = String(imap.host || "imap.gmail.com");
    env.GROK_IMAP_PORT = String(imap.port || 993);
    env.GROK_IMAP_USER = imap.user || "";
    env.GROK_IMAP_PASSWORD = imap.password || "";
    env.GROK_IMAP_TLS = String(imap.tls !== false);
    env.GROK_IMAP_DELETE_AFTER_READ = String(imap.deleteAfterRead === true);
    env.GROK_OTP_SUBJECT = String(providerCfg.otpSubject || "");
    env.GROK_OTP_SENDER_DOMAIN = String(providerCfg.otpSenderDomain || "x.ai");
  }

  // Optional proxy: accept a ready URL string OR { host, port, username?, password?, protocol? }.
  const proxy = options && options.proxy;
  if (proxy) {
    if (typeof proxy === "string" && proxy) {
      env.GROK_PROXY = proxy;
    } else if (proxy.host) {
      const auth =
        proxy.username && proxy.password
          ? `${proxy.username}:${proxy.password}@`
          : "";
      env.GROK_PROXY = `${proxy.protocol || "http"}://${auth}${proxy.host}:${proxy.port}`;
    }
  }

  return env;
}

/**
 * Classify one stdout line from the worker.
 * @param {string} line
 * @returns {{kind:'skip'}|{kind:'debug',raw:string}|{kind:'event',event:string,payload:object}|{kind:'result',ok:boolean,error:string|null,step:string|null}}
 */
function parseWorkerLine(line) {
  const s = String(line).trim();
  if (!s) return { kind: "skip" };
  let obj;
  try {
    obj = JSON.parse(s);
  } catch {
    return { kind: "debug", raw: s };
  }
  if (obj && typeof obj === "object") {
    // Prefer explicit kind:result, also accept event:result (worker emits both).
    if (obj.kind === "result" || obj.event === "result") {
      return {
        kind: "result",
        ok: !!obj.ok,
        error: obj.error || null,
        step: obj.step || null,
      };
    }
    if (typeof obj.event === "string") {
      return { kind: "event", event: obj.event, payload: obj };
    }
  }
  return { kind: "debug", raw: s };
}

function errCodeFrom(error) {
  // turnstile-timeout -> TURNSTILE_TIMEOUT ; worker-exit-nonzero -> WORKER_EXIT_NONZERO
  return String(error || "worker-exit-nonzero")
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");
}

/**
 * Spawn a worker command, stream stdout JSONL, and resolve/reject on exit.
 *
 * @param {object} p
 * @param {string} p.command - executable to spawn (DI so tests can pass process.execPath).
 * @param {string[]} p.args - args for the command.
 * @param {object} p.env - worker env (already built by buildWorkerEnv).
 * @param {string} [p.cwd] - working directory.
 * @param {(parsed:object)=>void} [p.onEvent] - called for every non-skip parsed line.
 * @param {number} [p.timeoutMs] - optional kill timeout.
 * @returns {Promise<{ok:true}>}
 */
function runSignupWorker({ command, args, env, cwd, onEvent = () => {}, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      env: { ...process.env, ...env },
      cwd,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let buf = "";
    let stderrBuf = "";
    let lastResult = null;
    let settled = false;

    const finish = (fn) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      fn();
    };

    const timer = timeoutMs
      ? setTimeout(() => {
          try {
            child.kill("SIGKILL");
          } catch {
            /* ignore */
          }
          finish(() =>
            reject(
              new ProviderError(
                `grok-cli worker timed out after ${timeoutMs}ms`,
                { code: "WORKER_TIMEOUT", retryable: true }
              )
            )
          );
        }, timeoutMs)
      : null;

    child.stdout.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      buf += chunk;
      let idx;
      while ((idx = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, idx);
        buf = buf.slice(idx + 1);
        const parsed = parseWorkerLine(line);
        if (parsed.kind === "skip") continue;
        if (parsed.kind === "result") lastResult = parsed;
        try {
          onEvent(parsed);
        } catch {
          /* ignore listener errors */
        }
      }
    });
    child.stderr.setEncoding("utf8");
    child.stderr.on("data", (chunk) => {
      stderrBuf += chunk;
      if (stderrBuf.length > 4000) stderrBuf = stderrBuf.slice(-4000);
    });

    child.on("error", (e) =>
      finish(() =>
        reject(
          new ProviderError(`grok-cli worker spawn failed: ${e.message}`, {
            code: "WORKER_SPAWN",
          })
        )
      )
    );

    child.on("close", (code) => {
      if (code === 0) {
        if (lastResult && lastResult.ok) {
          return finish(() => resolve({ ok: true }));
        }
        return finish(() =>
          reject(
            new ProviderError(
              `grok-cli worker exited 0 without ok result${
                stderrBuf ? `; stderr: ${stderrBuf.slice(0, 500)}` : ""
              }`,
              { code: "WORKER_PROTOCOL" }
            )
          )
        );
      }
      const error = (lastResult && lastResult.error) || "worker-exit-nonzero";
      const step = (lastResult && lastResult.step) || null;
      const tail = stderrBuf ? `; stderr: ${stderrBuf.slice(0, 500)}` : "";
      return finish(() =>
        reject(
          new ProviderError(
            `grok-cli worker failed: ${error}${step ? ` (step ${step})` : ""}${tail}`,
            {
              code: errCodeFrom(error),
              retryable: /timeout|temp|transient/i.test(error),
            }
          )
        )
      );
    });
  });
}

function pythonBin(workerDir) {
  return path.join(workerDir, ".venv", "bin", "python3");
}

/**
 * Production wrapper: spawn worker/signup.py with the project venv python.
 * @param {string} workerDir
 * @param {object} env
 * @param {{onEvent?:Function, timeoutMs?:number}} [opts]
 * @returns {Promise<{ok:true}>}
 */
function spawnSignupWorker(workerDir, env, opts = {}) {
  return runSignupWorker({
    command: pythonBin(workerDir),
    args: [path.join(workerDir, "signup.py")],
    env,
    cwd: workerDir,
    onEvent: opts.onEvent,
    timeoutMs: opts.timeoutMs,
  });
}

module.exports = {
  buildSignInUrl,
  buildWorkerEnv,
  parseWorkerLine,
  runSignupWorker,
  spawnSignupWorker,
  pickName,
};
