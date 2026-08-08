"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { BaseProvider } = require("../../base/provider");
const { AuthError } = require("../../base/errors");
const {
  buildWorkerEnv,
  parseWorkerLine,
  spawnSignupWorker,
  pickName,
} = require("./worker-bridge");

/**
 * Security: strip secret-bearing keys before a worker line hits console.log.
 * Result lines carry the PAT (pat/token) + email; never serialize them.
 * @param {object} obj - full worker payload (already parsed).
 * @returns {object} same shape with secret values removed.
 */
function scrubForLog(obj) {
  if (!obj || typeof obj !== "object") return obj;
  const out = { ...obj };
  for (const key of ["pat", "token", "password", "apiKey", "authorization"]) {
    if (key in out) out[key] = "[redacted]";
  }
  return out;
}

/**
 * Security: strip secret values out of arbitrary untrusted text (raw worker
 * stdout lines, error strings) before it reaches console.log / error messages.
 * The worker already masks 6-digit OTP runs, but a stray debug/error echo may
 * still contain a PAT, password, apiKey, or authorization header.
 * @param {string} text
 * @returns {string} same text with every value of a secret key replaced.
 */
function redactSecrets(text) {
  const s = String(text == null ? "" : text);
  // Match `key: "value"`, `"key": "value"`, `key='value'` (JSON + Python repr),
  // and unquoted `key=value` / `key: value` shapes for every secret key. The
  // value is replaced wholesale; the leading `(?<![A-Za-z0-9_])` guard stops
  // mangling plain words that merely contain a key substring (e.g. "compat").
  const re =
    /(?<![A-Za-z0-9_])(?:["'])?(password|pat|token|apiKey|authorization)["']?\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^,;&}\]\n]+)/gi;
  return s.replace(re, (m, key) => `${key}:"[redacted]"`);
}

/**
 * Qoder provider — automates Qoder (qoder.com) AI coding account registration
 * + Personal Access Token (PAT) generation.
 *
 * Config: providers.qoder.solverUrl overrides the Aliyun solver endpoint
 * (default http://127.0.0.1:8877/solve); accountsDir relocates the PAT
 * sidecar files (default process.cwd()).
 *
 * Architecture: Node orchestrates; a Python pure-HTTP worker
 * (worker/signup.py, subprocess-per-run) drives register + OTP + PAT via
 * curl_cffi Chrome 131 impersonation. No browser, no nodriver, no puppeteer.
 *
 * Pure-HTTP direct flow (no 9router OAuth device-code bridge):
 *   - Node builds the worker env (credentials + options only) and spawns
 *     worker/signup.py.
 *   - Worker emits JSONL step events and a final `{kind:"result", ok, ...}`
 *     line carrying the account + PAT.
 *   - add() resolves the worker, parses the result payload, and returns
 *     `{ ok, connection }` with the PAT as an apikey auth.
 *
 * Supports dual email source:
 *   - tempmail (default): worker generates a disposable inbox (ncaori).
 *   - imap: OTP via Gmail or minom alias mailbox.
 *
 * Output: after each successful signup, afterAdd() persists two files next to
 * the generated-accounts JSON:
 *   - qoder-pats.txt — PAT only, one per line (for mass API-key consumption).
 *   - qoder-accounts.txt — full account data (email | name | PAT), one per
 *     line (import/backup). Both 0600, gitignored, appended per success.
 *
 * Security: never logs the password or the PAT.
 */
class QoderProvider extends BaseProvider {
  static get providerName() {
    return "qoder";
  }

  static get endpoints() {
    return {
      signup: "https://qoder.com/users/sign-up",
      register: "https://qoder.com/api/v1/users",
      me: "https://qoder.com/api/v1/me",
      pat: "https://qoder.com/api/v1/me/personal-access-tokens",
    };
  }

  /**
   * @param {object} config - resolved config (may include .providers['qoder']).
   * @param {object} api - API client with apiCall(url, opts).
   * @param {object} services - service container (quota, etc.).
   */
  constructor(config, api, services) {
    super(config, api, services);
  }

  /**
   * Run the full signup flow:
   * 1. Validate credentials/config (email+password; tempmail mode may
   *    auto-generate an email).
   * 2. Build the worker env (QODER_*) and spawn worker/signup.py.
   * 3. Parse the worker JSONL result; return {ok, connection}.
   *
   * @param {{email?: string, password?: string, name?: string}} [credentials={}] - Account credentials.
   * @param {{proxy?: object|string, emailSource?: string, signupUrl?: string, solverUrl?: string}} [options={}] - Run options.
   * @returns {Promise<{ok: boolean, connection?: object}>}
   */
  async add(credentials = {}, options = {}) {
    const emailSource = (options && options.emailSource) || "tempmail";

    if (emailSource === "tempmail") {
      // Tempmail mode: email can be empty (worker generates a disposable mailbox).
      // Password will be auto-generated below if empty.
      if (!credentials.email) {
        credentials.email = "tempmail@pending.local";
      }
    } else if (!credentials || !credentials.email || !credentials.password) {
      throw new Error("qoder requires email + password credentials");
    }

    // Auto-generate password if not provided.
    const password =
      credentials.password ||
      `Qoder${crypto.randomBytes(6).toString("base64").slice(0, 8)}!A1`;
    const name = pickName(credentials.name);

    this._accountEmail = credentials.email;
    this._accountPassword = password;
    this._accountName = name;

    const workerDir = path.join(__dirname, "worker");
    const env = buildWorkerEnv({
      credentials: {
        email: this._accountEmail,
        password: this._accountPassword,
        name: this._accountName,
      },
      config: this.config,
      options,
    });

    const label = this._accountEmail;
    console.log(`[${label}] Spawning Python pure-HTTP worker (qoder)...`);

    let lastPayload = null;
    // this._spawnSignupWorker is the DI seam (tests stub it to capture onEvent
    // without spawning a real subprocess); defaults to the worker-bridge spawn.
    const spawn = this._spawnSignupWorker || spawnSignupWorker;
    await spawn(workerDir, env, {
      onEvent: (parsed) => {
        // Capture the real temp-mail address when the worker creates one
        // (this._accountEmail starts as the "tempmail@pending.local" placeholder),
        // so the connection + generated-accounts file carry the live address.
        const payload = parsed.payload || parsed;
        if (payload.step === "tempmail_create" && payload.address) {
          this._accountEmail = payload.address;
        }
        if (parsed.kind === "result") {
          lastPayload = parsed.payload || parsed;
        }
        if (parsed.kind === "event" || parsed.kind === "result") {
          console.log(
            `[${label}]    [worker] ${JSON.stringify(scrubForLog(parsed.payload || parsed))}`
          );
        } else if (parsed.kind === "debug") {
          // Raw-line echo may carry a secret (e.g. an unparseable error line
          // echoing the request body) — redact before logging.
          console.log(`[${label}]    [worker:debug] ${redactSecrets(parsed.raw)}`);
        }
      },
      // Worker worst case: OTP poll 180s + ~120s register/PAT/me. Keep a
      // 420s cap so the worker's own verdict (e.g. otp-timeout) surfaces
      // instead of a SIGKILL mid-flow.
      timeoutMs: 420000,
    });

    return this._toConnectionResult(lastPayload, { email: this._accountEmail, password });
  }

  /**
   * Turn a worker result payload into an account connection object.
   * Worker emits {kind:"result", ok, step, email, pat, ...}.
   *
   * @param {object|null} payload
   * @param {{email:string, password:string}} creds
   * @returns {{ok:boolean, connection?:object}}
   */
  _toConnectionResult(payload, { email, password }) {
    const result = payload || {};
    const pat = result.pat || result.token || null;
    if (result.ok !== true || !pat) {
      // result.error may echo server text that contains a secret (e.g. a
      // register-step2 failure body with the password echoed back) — truncate
      // AND redact before embedding it in the error message.
      const reason = redactSecrets(String(result.error || "no-pat-result").slice(0, 200));
      throw new AuthError(`qoder signup did not yield a PAT: ${reason}`);
    }
    // Prefer the email the worker actually registered (temp-mail address), falling
    // back to the provider's bookkeeping email.
    const accountEmail =
      (typeof result.email === "string" && result.email && !result.email.includes("pending.local")
        ? result.email
        : email) || email;
    return {
      ok: true,
      connection: {
        provider: "qoder",
        email: accountEmail,
        password,
        authType: "apikey",
        data: {
          apiKey: pat,
          name: result.name || this._accountName,
        },
      },
      // Copy claim result fields (best-effort, from worker's emit_result) so
      // afterAdd / callers can read them for sidecar files + trial filtering.
      trial: result.trial,
      ultimate: result.ultimate,
      qwen800: result.qwen800,
      qwen2000: result.qwen2000,
      credits: result.credits,
    };
  }

  /**
   * Lifecycle: afterAdd — persist PAT-only + full-account sidecar files.
   *
   * Appends to three files (all gitignored, 0600):
   *   1. qoder-pats.txt           — one-line per PAT (for bulk API use)
   *   2. qoder-accounts.txt       — email | name | PAT (one per line)
   *   3. qoder-pat-trial.json     — JSON-lines: {email,pat,claims,timestamp}
   *                              - ONLY if worker.reported.trial === true (Pro Trial active)
   *
   * Never logs passwords. The trial file filters for accounts with Pro Trial.
   * Non-fatal: failures do not block signup.
   *
   * @param {{ok:boolean, connection?:object, trial?:boolean, ultimate?:boolean, qwen800?:boolean, qwen2000?:boolean, credits?:number}} result - add() result.
   *
   * Output (2-phase flow):
   *   1. generated-accounts-qoder-*.json — full credentials (runner/CLI writes)
   *   2. accounts/qoder/qoder-pats.txt    — ALL PATs (one per line) from signup.
   *      Trial claim happens SEPARATELY via `node . claim-qoder` (PATs need
   *      the account to age before qoder.com grants Pro Trial).
   */
  async afterAdd(result) {
    if (!result || result.ok !== true || !result.connection) return;
    const { connection } = result;
    const pat = connection.data && connection.data.apiKey;
    if (!pat) return;

    const dir = path.join(this.config.accountsDir || "accounts", "qoder");
    try {
      fs.mkdirSync(dir, { recursive: true });
      fs.appendFileSync(path.join(dir, "qoder-pats.txt"), `${pat}\n`, { mode: 0o600 });
    } catch (err) {
      console.warn(`[qoder] could not append PAT file: ${err.message}`);
    }
  }

  /**
   * Claim Pro Trial for all PATs in accounts/qoder/qoder-pats.txt.
   * Skips PATs that are already PRO_TRIAL (dual_claim reports ACTIVE).
   * Reads PATs, runs dual_claim --pool per PAT, writes claimed PATs to
   * accounts/qoder/qoder-pats-trial.txt.
   *
   * @param {{attempts?: number}} [opts]
   * @returns {Promise<{claimed: string[], failed: string[], already: string[]}>}
   */
  async claimAllPats(opts = {}) {
    const dir = path.join(this.config.accountsDir || "accounts", "qoder");
    const patsFile = path.join(dir, "qoder-pats.txt");
    if (!fs.existsSync(patsFile)) {
      throw new Error(`No PATs file: ${patsFile} — run 'node . add qoder' first`);
    }
    const pats = fs.readFileSync(patsFile, "utf8").split("\n").map(s => s.trim()).filter(Boolean);
    const attempts = opts.attempts || 3;

    const claimed = [];
    const failed = [];
    const already = [];

    for (const pat of pats) {
      const result = await claimTrialForPat(pat, attempts);
      if (result.trial) {
        claimed.push(pat);
        console.log(`✅ ${pat.slice(0, 24)}... trial ACTIVE`);
      } else if (result.already) {
        already.push(pat);
        console.log(`↷ ${pat.slice(0, 24)}... already PRO_TRIAL`);
      } else {
        failed.push(pat);
        console.log(`❌ ${pat.slice(0, 24)}... ${result.error || "PLAN_TIER_FREE"}`);
      }
    }

    // Write claimed PATs to trial file
    if (claimed.length) {
      fs.appendFileSync(
        path.join(dir, "qoder-pats-trial.txt"),
        claimed.map(p => p + "\n").join(""),
        { mode: 0o600 }
      );
    }

    return { claimed, failed, already };
  }

  /**
   * Lifecycle: beforeAdd -- quota check.
   */
  async beforeAdd(credentials, options) {
    const { quota } = this.services || {};
    if (quota && credentials && credentials.email) {
      const cap =
        (this.config.providerConfig && this.config.providerConfig.quotaCap) || 3;
      const { allowed } = quota.tryConsume(
        this.config.quotaFile || ".batch-stats.json",
        credentials.email,
        cap
      );
      if (!allowed) {
        return {
          skip: true,
          reason: `Quota cap (${cap}/day) reached for ${credentials.email}`,
        };
      }
    }
  }
}

/**
 * Claim Pro Trial for one PAT via the vendored dual_claim.py (--pool).
 *
 * Runs the claim tool up to `attempts` times. Fresh accounts usually show
 * PLAN_TIER_FREE until qoder.com grants the trial (needs the account to age).
 * Returns:
 *   {trial: true}           — Pro Trial ACTIVE
 *   {trial: false, already: true} — already PRO_TRIAL (skip)
 *   {trial: false, error}   — still FREE / claim failed
 *
 * @param {string} pat
 * @param {number} [attempts=3]
 * @returns {Promise<{trial: boolean, already?: boolean, error?: string}>}
 */
async function claimTrialForPat(pat, attempts = 3) {
  const { execFile } = require("child_process");
  const os = require("os");

  const repoRoot = path.join(__dirname, "..", "..", "..");
  const trialDir = path.join(repoRoot, "qoder-trial");
  const venvPython = path.join(__dirname, "worker", ".venv", "bin", "python3");
  const dualClaim = path.join(trialDir, "dual_claim.py");

  if (!fs.existsSync(dualClaim) || !fs.existsSync(venvPython)) {
    return { trial: false, error: "qoder-trial assets missing (dual_claim.py / venv)" };
  }

  const env = {
    ...process.env,
    QODER_IDENTITY_DIR: trialDir,
    QODER_RUNTIME_INFO: path.join(trialDir, "runtime-info-linux-x64"),
    QODER_SPOOF_SO: path.join(trialDir, "hooks", "spoof_hw.so"),
  };

  const runOnce = () => new Promise((resolve) => {
    execFile(
      venvPython,
      [dualClaim, "--pat", pat, "--pool", "--attempts", "1"],
      { cwd: trialDir, env, timeout: 120000, maxBuffer: 4 * 1024 * 1024 },
      (err, stdout, stderr) => {
        const out = `${stdout || ""}\n${stderr || ""}`;
        resolve({ out, err });
      }
    );
  });

  for (let i = 0; i < attempts; i++) {
    const { out, err } = await runOnce();
    // Already trial (from previous claim) — skip
    if (/ACTIVE! Plan: PLAN_TIER_PRO_TRIAL/.test(out)) {
      return { trial: true };
    }
    if (/Waiting 30 seconds/.test(out)) {
      return { trial: true };
    }
    if (/Already claimed|already claimed/i.test(out)) {
      return { trial: false, already: true };
    }
    if (i < attempts - 1) {
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
  return { trial: false, error: "PLAN_TIER_FREE (account may need to age)" };
}

module.exports = QoderProvider;