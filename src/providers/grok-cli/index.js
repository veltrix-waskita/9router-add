"use strict";

const fs = require("fs");
const path = require("path");
const { BaseProvider } = require("../../base/provider");
const { QuotaError } = require("../../base/errors");

/**
 * Grok CLI provider — automates xAI (accounts.x.ai) OAuth device signup
 * against the 9router OAuth bridge.
 *
 * Architecture: Node orchestrates; a Python pure-HTTP worker
 * (worker/signup.py, subprocess-per-run) drives signup + device-authorize
 * via curl_cffi Chrome 131 impersonation. No browser, no nodriver.
 *
 * Verified API contract (probed against live 9router):
 *   1. GET /api/oauth/grok-cli/device-code
 *      -> { device_code, user_code, verification_uri, verification_uri_complete,
 *           expires_in: 1800, interval: 5, codeVerifier }
 *   2. Spawn worker/signup.py (env contract in worker-bridge.buildWorkerEnv).
 *      device_code + codeVerifier stay in Node; only user_code crosses,
 *      embedded in GROK_SIGNIN_URL.
 *   3. POST /api/oauth/grok-cli/poll { deviceCode, codeVerifier } until
 *      result.success. codeVerifier comes from the device-code response and
 *      never leaves Node (worker never sees it). 9router stores the connection
 *      itself via the poll response — we must NOT injectToDb (doing so creates
 *      a duplicate row without the token).
 *
 * Supports dual email source: IMAP (default) and temp-mail.
 * - IMAP mode: requires imap config block for OTP delivery.
 * - Temp-mail mode: creates a disposable inbox via the Python EmailBox;
 *   no IMAP config needed.
 *
 * Security: never logs the password, OTP value, device_code, or codeVerifier.
 */
class GrokCliProvider extends BaseProvider {
  static providerName = "grok-cli";

  static endpoints = {
    deviceCode: "/api/oauth/grok-cli/device-code",
    poll: "/api/oauth/grok-cli/poll",
  };

  /**
   * @param {object} config - resolved config (may include .imap block, .providers['grok-cli']).
   * @param {object} api - API client with apiCall(url, opts).
   * @param {object} services - service container (quota, etc.).
   */
  constructor(config, api, services) {
    super(config, api, services);
  }

  /**
   * Run the full signup flow:
   * 1. Validate credentials.
   * 2. Validate IMAP config if emailSource is "imap" (default).
   * 3. GET device code from 9router.
   * 4. Spawn the Python pure-HTTP worker (signup + device authorize).
   * 5. Poll 9router until the connection is stored (9router stores it via
   *    the poll response — no injectToDb in local mode).
   *
   * @param {{email?: string, password?: string, name?: string}} credentials - Account credentials.
   * @param {{proxy?: object|string, emailSource?: string, tempmailProviders?: string|string[]}} [options={}] - Run options.
   * @returns {Promise<{ok: boolean, id?: string, connection?: object}>}
   */
  async add(credentials, options = {}) {
    const emailSource = (options && options.emailSource) || "imap";

    // Tempmail mode: email can be empty (worker generates a disposable mailbox).
    // IMAP mode: email + password are required.
    if (emailSource === "tempmail") {
      if (!credentials || !credentials.password) {
        throw new Error("grok-cli tempmail mode requires at least password credentials");
      }
      if (!credentials.email) {
        credentials.email = "tempmail@pending.local";
      }
    } else {
      if (!credentials || !credentials.email || !credentials.password) {
        throw new Error("grok-cli requires email + password credentials");
      }
    }

    // IMAP mode requires IMAP config for OTP delivery.
    if (emailSource === "imap") {
      if (
        !this.config.imap ||
        !this.config.imap.user ||
        !this.config.imap.password
      ) {
        throw new Error(
          "grok-cli (imap mode) requires IMAP config (imap.user + imap.password). " +
          "Set the 'imap' block in config.json, or use emailSource=tempmail."
        );
      }
    }

    // 1. Request device code (GET — no body).
    const deviceData = await this._apiCall(
      "GET",
      this.constructor.endpoints.deviceCode
    );
    // Track the account email for later use (e.g. renameConnection).
    this._accountEmail = credentials.email;

    console.log(
      `[${credentials.email}] Device code received (length ${String(deviceData.user_code || "").length})`
    );

    // 2. Spawn the Python pure-HTTP worker (signup + device authorize).
    await this._runSignupWorker(deviceData, credentials, options);

    // 3. Poll until 9router stores the connection.
    const pollResult = await this.pollUntilConnected(
      deviceData,
      credentials.email
    );

    return { ok: true, id: pollResult.connection?.id, ...pollResult };
  }

  /**
   * Spawn worker/signup.py and stream its JSONL progress. Rejects with a
   * ProviderError on non-zero exit or timeout. device_code/codeVerifier
   * never leave Node (buildWorkerEnv omits them).
   *
   * @param {object} deviceData - 9router device-code response (only user_code used).
   * @param {object} credentials - { email, password, name? }.
   * @param {object} options - run options (optional .proxy, .emailSource).
   * @returns {Promise<void>}
   */
  async _runSignupWorker(deviceData, credentials, options = {}) {
    const path = require("path");
    const { buildWorkerEnv, spawnSignupWorker } = require("./worker-bridge");
    const workerDir = path.join(__dirname, "worker");
    const env = buildWorkerEnv({
      deviceData,
      credentials,
      config: this.config,
      options,
    });
    const label = credentials.email;
    const expiresMs = (deviceData.expires_in ?? 1800) * 1000;
    // Reserve a 60s margin so poll still has time after the worker returns.
    const timeoutMs = Math.max(60000, expiresMs - 60000);
    console.log(
      `[${label}] Spawning Python pure-HTTP worker (timeout ${Math.round(timeoutMs / 1000)}s)...`
    );
    await spawnSignupWorker(workerDir, env, {
      onEvent: (parsed) => {
        // Capture the actual temp-mail address when the worker creates one
        // (this._accountEmail starts as "tempmail@pending.local").
        const payload = parsed.payload || parsed;
        if (payload.step === "tempmail_create" && payload.address) {
          this._accountEmail = payload.address;
        }
        if (parsed.kind === "event" || parsed.kind === "result") {
          console.log(
            `[${label}]    [worker] ${JSON.stringify(parsed.payload || parsed)}`
          );
        } else if (parsed.kind === "debug") {
          console.log(`[${label}]    [worker:debug] ${parsed.raw}`);
        }
      },
      timeoutMs,
    });
  }

  /**
   * Poll 9router's grok-cli poll endpoint until the user completes
   * the device-authorize flow. Matches kiro's poll pattern.
   *
   * 9router response fields:
   *   { success: true, connection: {...} }              → done
   *   { success: false, error: "authorization_pending",
   *     pending: true }                                  → still waiting
   *   { success: false, error: "expired_token", ... }   → terminal (throw)
   *   { success: false, error: "access_denied", ... }   → terminal (throw)
   *
   * @param {object} deviceData - device-code response (needs device_code, codeVerifier, interval).
   * @param {string} label - email for logging.
   * @returns {Promise<object>} resolved poll result.
   */
  async pollUntilConnected(deviceData, label) {
    if (!deviceData || !deviceData.device_code || !deviceData.codeVerifier) {
      throw new Error("pollUntilConnected: no device_code or codeVerifier in deviceData");
    }

    const deadline = Date.now() + (deviceData.expires_in ?? 1800) * 1000;
    const intervalMs = (deviceData.interval || 5) * 1000;
    const body = { deviceCode: deviceData.device_code, codeVerifier: deviceData.codeVerifier };

    let attempts = 0;
    while (Date.now() < deadline) {
      attempts++;
      try {
        const res = await this._apiCall("POST", this.constructor.endpoints.poll, body);

        // ——— Success + terminal states (from 9router response) ———
        if (res && res.success && res.connection) {
          console.log(`[${label}] Connection established after ${attempts} poll(s)`);
          return res;
        }

        if (res && res.pending) {
          // Still waiting for authorization — log and retry
          console.log(`[${label}] Poll attempt ${attempts}: pending (${res.error || "waiting"})`);
        } else if (res && res.error) {
          // Terminal error states
          if (res.error === "expired_token") {
            throw Object.assign(new Error(`Device code expired: ${res.errorDescription || ""}`), { code: "EXPIRED_TOKEN", retryable: false });
          }
          if (res.error === "access_denied") {
            throw Object.assign(new Error(`User denied authorization: ${res.errorDescription || ""}`), { code: "ACCESS_DENIED", retryable: false });
          }
          // Unknown error — non-terminal, log and retry
          console.log(`[${label}] Poll attempt ${attempts}: ${res.error} — ${res.errorDescription || ""}`);
        } else {
          console.log(`[${label}] Poll attempt ${attempts}: ${JSON.stringify(res)}`);
        }
      } catch (err) {
        if (err.code === "EXPIRED_TOKEN" || err.code === "ACCESS_DENIED") throw err;
        // Transient network/server error — log and retry
        console.log(`[${label}] Poll error (retry): ${err.message}`);
      }

      await new Promise((r) => setTimeout(r, intervalMs));
    }

    throw Object.assign(
      new Error(`Device authorization timed out for ${label} after ${Math.round((deviceData.expires_in ?? 1800) * 1000 / 1000)}s`),
      { code: "POLL_TIMEOUT", retryable: true }
    );
  }

  /**
   * Generic API call with JSON body support.
   *
   * @param {"GET"|"POST"|"PUT"} method
   * @param {string} path
   * @param {object} [body]
   * @returns {Promise<object>}
   */
  async _apiCall(method, path, body) {
    const bodyStr =
      body === undefined || body === null
        ? undefined
        : typeof body === "object"
          ? JSON.stringify(body)
          : String(body);
    const res = await this.apiCall(method, path, bodyStr, {
      headers: { "Content-Type": "application/json" },
    });
    if (!res || (res.statusCode && res.statusCode >= 400)) {
      const errBody = (res && res.body) ? (typeof res.body === "string" ? res.body.slice(0, 200) : JSON.stringify(res.body).slice(0, 200)) : "no body";
      throw new Error(`HTTP ${res ? res.statusCode : "??"} from ${path}: ${errBody}`);
    }
    return res.body || res;
  }

  /**
   * Rename a connection via PUT /api/providers/:id.
   *
   * @param {string} id
   * @returns {Promise<void>}
   */
  async renameConnection(id) {
    // Prefer the account email — it's the most meaningful display name.
    // Fall back to config name or provider name.
    const name =
      this._accountEmail ||
      this.config.providers?.["grok-cli"]?.name ||
      this.constructor.providerName;
    await this._apiCall("PUT", `/api/providers/${id}`, { name });
  }

  /**
   * Lifecycle: beforeAdd — quota check.
   * @param {object} credentials
   * @param {object} options
   */
  async beforeAdd(credentials, options) {
    const { quota } = this.services || {};
    if (quota && credentials && credentials.email) {
      const providerCfg = this.config.providers && this.config.providers["grok-cli"];
      const cap = (providerCfg && providerCfg.quotaCap) || 3;
      const { allowed } = quota.tryConsume(
        this.config.quotaFile || ".batch-stats.json",
        credentials.email,
        cap
      );
      if (!allowed) {
        throw new QuotaError((credentials.email || "").split("@")[1] || "unknown");
      }
    }
  }

  /**
   * Lifecycle: afterAdd — rename the connection + persist full account JSONL.
   *
   * Writes accounts/grok-cli/grok-accounts.jsonl with full connection data
   * (email, id, accessToken, refreshToken, expiresAt, scope, displayName).
   * Non-fatal: file write failure does not fail the signup.
   * @param {{id?: string, connection?: object}} result
   */
  async afterAdd(result) {
    // 1. Rename connection (existing behavior)
    if (result && result.id) {
      try {
        await this.renameConnection(result.id);
      } catch (e) {
        console.log(`[grok-cli] Warning: rename failed for ${result.id}: ${e.message}`);
      }
    }

    // 2. Persist full account JSONL to accounts/grok-cli/
    // The connection object from add() has {id, provider} but tokens are in
    // 9router DB — read from local SQLite directly (API strips tokens).
    if (!result || !result.connection) return;
    const conn = result.connection;
    let data = conn.data || {};

    // Fetch full connection data from local DB (tokens are stripped by API)
    if (!data.accessToken && conn.id) {
      try {
        const { findById } = require("../../core/db");
        const stored = await findById(this.config, conn.id);
        if (stored && stored.data) data = stored.data;
        if (!conn.email && stored && stored.email) conn.email = stored.email;
      } catch { /* non-fatal — DB read may fail on remote */ }
    }

    if (!data.accessToken) return;

    const dir = path.join(this.config.accountsDir || "accounts", "grok-cli");
    try {
      fs.mkdirSync(dir, { recursive: true });
      const entry = {
        email: conn.email || data.email || "",
        id: conn.id || result.id || "",
        displayName: data.displayName || "",
        accessToken: data.accessToken || "",
        refreshToken: data.refreshToken || "",
        expiresAt: data.expiresAt || "",
        scope: data.scope || "",
        createdAt: data.createdAt || new Date().toISOString(),
      };
      fs.appendFileSync(
        path.join(dir, "grok-accounts.jsonl"),
        JSON.stringify(entry) + "\n",
        { mode: 0o600 }
      );
    } catch (err) {
      console.warn(`[grok-cli] could not append account JSONL: ${err.message}`);
    }
  }

  /**
   * Inspect an existing connection.
   * Delegates to the base API call (local → SQLite, remote → 9router API).
   * @param {string} id
   * @returns {Promise<object>}
   */
  async inspect(id) {
    return this._apiCall("GET", `/api/providers/${id}`);
  }

  /**
   * Delete a connection.
   * @param {string} id
   * @returns {Promise<void>}
   */
  async delete(id) {
    await this._apiCall("DELETE", `/api/providers/${id}`);
  }
}

module.exports = GrokCliProvider;
