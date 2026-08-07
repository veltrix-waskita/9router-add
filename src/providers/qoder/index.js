"use strict";

const crypto = require("crypto");
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
 * Qoder provider — automates Qoder (qoder.com) AI coding account registration
 * + Personal Access Token (PAT) generation.
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
   * @param {{proxy?: object|string, emailSource?: string, signupUrl?: string}} [options={}] - Run options.
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
          console.log(`[${label}]    [worker:debug] ${parsed.raw}`);
        }
      },
      timeoutMs: 300000,
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
      throw new AuthError(
        `qoder signup did not yield a PAT: ${String(result.error || "no-pat-result").slice(0, 200)}`
      );
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
    };
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

module.exports = QoderProvider;