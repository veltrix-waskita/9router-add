"use strict";

const crypto = require("crypto");
const { BaseProvider } = require("../../base/provider");
const { AuthError } = require("../../base/errors");
const {
  buildWorkerEnv,
  parseWorkerLine,
  spawnSignupWorker,
  pickName,
} = require("./worker-bridge");

/**
 * Kiro provider — automates Kiro AI account registration against the
 * 9router OAuth bridge.
 *
 * Architecture: Node orchestrates; a Python pure-HTTP worker
 * (worker/signup.py, subprocess-per-run) drives signup + device-authorize
 * via curl_cffi Chrome 131 impersonation. No browser, no nodriver, no
 * puppeteer.
 *
 * Verified API contract (probed against live 9router):
 *   1. GET /api/oauth/kiro/device-code
 *      -> { device_code, user_code, verification_uri, verification_uri_complete,
 *           expires_in: 600, interval: 1, _clientId, _clientSecret,
 *           _region, _authMethod, _startUrl }
 *   2. Spawn worker/signup.py (env contract in worker-bridge.buildWorkerEnv).
 *      device_code never leaves Node; only verification_uri_complete crosses
 *      (embedded in KIRO_DEVICE_URL).
 *   3. POST /api/oauth/kiro/poll { deviceCode, extraData } until
 *      result.success. extraData contains the underscore-prefixed fields
 *      from the device-code response. 9router stores the connection itself
 *      via the poll response — we must NOT injectToDb (doing so creates a
 *      duplicate row without the token).
 *
 * Supports dual email source: IMAP (default) and temp-mail.
 * - IMAP mode: requires imap config block for OTP delivery.
 * - Temp-mail mode: creates a disposable inbox via the Python EmailBox;
 *   no IMAP config needed.
 *
 * Security: never logs the password, device_code, or extraData fields.
 * The underscore-prefixed fields never enter the worker environment.
 */
class KiroProvider extends BaseProvider {
  static get providerName() {
    return "kiro";
  }

  static get endpoints() {
    return {
      deviceCode: "/api/oauth/kiro/device-code",
      poll: "/api/oauth/kiro/poll",
      provider: "/api/providers",
    };
  }

  /**
   * @param {object} config - resolved config (may include .imap block, .providers['kiro']).
   * @param {object} api - API client with apiCall(url, opts).
   * @param {object} services - service container (quota, etc.).
   */
  constructor(config, api, services) {
    super(config, api, services);
  }

  /**
   * Choose the registration method based on the email domain.
   *
   * @param {string} [email] - Account email.
   * @returns {"google"|"email"} "google" for @gmail.com, otherwise "email".
   */
  detectMethod(email) {
    if (!email) return "email";
    return email.toLowerCase().endsWith("@gmail.com") ? "google" : "email";
  }

  /**
   * Run the full signup flow:
   * 1. Validate method (google is not supported in pure-HTTP v1).
   * 2. Validate credentials and config.
   * 3. GET device code from 9router.
   * 4. Spawn the Python pure-HTTP worker (signup + device authorize).
   * 5. Poll 9router until the connection is stored (9router stores it via
   *    the poll response — no injectToDb in local mode).
   *
   * @param {{email?: string, password?: string, name?: string}} [credentials={}] - Account credentials.
   * @param {{proxy?: object|string, emailSource?: string, tempmailProviders?: string|string[]}} [options={}] - Run options.
   * @returns {Promise<{ok: boolean, id?: string, connection?: object}>}
   */
  async add(credentials = {}, options = {}) {
    const method = this.detectMethod(credentials.email);

    // Google accounts are not supported in pure-HTTP v1.
    if (method === "google") {
      throw new AuthError("Google / @gmail.com accounts are not supported in pure-HTTP v1");
    }

    const emailSource = (options && options.emailSource) || "imap";

    // Tempmail mode: email can be empty (worker generates a disposable mailbox).
    // IMAP mode: email + password are required.
    if (emailSource === "tempmail") {
      if (!credentials.email) {
        credentials.email = "tempmail@pending.local";
      }
      // Password will be auto-generated below if empty.
    } else {
      if (!credentials || !credentials.email || !credentials.password) {
        throw new Error("kiro requires email + password credentials");
      }
      // IMAP mode requires IMAP config for OTP delivery.
      if (
        !this.config.imap ||
        !this.config.imap.user ||
        !this.config.imap.password
      ) {
        throw new Error(
          "kiro (imap mode) requires IMAP config (imap.user + imap.password). " +
          "Set the 'imap' block in config.json, or use emailSource=tempmail."
        );
      }
    }

    // Auto-generate password if not provided.
    const password =
      credentials.password ||
      `Kiro${crypto.randomBytes(6).toString("base64").slice(0, 8)}!A1`;
    const name = pickName(credentials.name);

    this._accountEmail = credentials.email;
    this._accountPassword = password;
    this._accountName = name;

    // 1. Request device code (GET — no body).
    const deviceData = await this._apiCall(
      "GET",
      this.constructor.endpoints.deviceCode
    );

    console.log(
      `[${credentials.email}] Device code received (length ${String(deviceData.user_code || "").length})`
    );

    // 2. Spawn the Python pure-HTTP worker (signup + device authorize).
    await this._runSignupWorker(deviceData, options);

    // 3. Poll until 9router stores the connection.
    const pollResult = await this.pollUntilConnected(deviceData);

    return { ok: true, id: pollResult.connection?.id, ...pollResult };
  }

  /**
   * Spawn worker/signup.py and stream its JSONL progress. Rejects with a
   * ProviderError on non-zero exit or timeout. device_code and extraData
   * fields never leave Node (buildWorkerEnv omits them).
   *
   * @param {object} deviceData - 9router device-code response (only verification_uri_complete used).
   * @param {object} options - run options (optional .proxy, .emailSource).
   * @returns {Promise<void>}
   */
  async _runSignupWorker(deviceData, options = {}) {
    const path = require("path");
    const { buildWorkerEnv, spawnSignupWorker } = require("./worker-bridge");
    const workerDir = path.join(__dirname, "worker");
    const env = buildWorkerEnv({
      deviceData,
      credentials: {
        email: this._accountEmail,
        password: this._accountPassword,
        name: this._accountName,
      },
      config: this.config,
      options,
    });
    const label = this._accountEmail;
    const expiresMs = (deviceData.expires_in ?? 600) * 1000;
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
   * Poll 9router's kiro poll endpoint until the user completes
   * the device-authorize flow.
   *
   * 9router response fields:
   *   { success: true, connection: {...} }              -> done
   *   { success: false, error: "authorization_pending",
   *     pending: true }                                  -> still waiting
   *   { success: false, error: "expired_token", ... }   -> terminal (throw)
   *   { success: false, error: "access_denied", ... }   -> terminal (throw)
   *
   * @param {object} deviceData - device-code response (needs device_code,
   *   expires_in, interval, plus underscore-prefixed extraData fields).
   * @returns {Promise<object>} resolved poll result.
   */
  async pollUntilConnected(deviceData) {
    if (!deviceData || !deviceData.device_code) {
      throw new Error("pollUntilConnected: no device_code in deviceData");
    }

    const extraData = {
      _clientId: deviceData._clientId,
      _clientSecret: deviceData._clientSecret,
      _region: deviceData._region,
      _authMethod: deviceData._authMethod,
      _startUrl: deviceData._startUrl,
    };

    const deadline = Date.now() + (deviceData.expires_in ?? 600) * 1000;
    const intervalMs = (deviceData.interval ?? 1) * 1000;
    const body = { deviceCode: deviceData.device_code, extraData };
    const label = this._accountEmail || "kiro";

    let attempts = 0;
    while (Date.now() < deadline) {
      attempts++;
      try {
        const res = await this._apiCall("POST", this.constructor.endpoints.poll, body);

        // --- Success + terminal states (from 9router response) ---
        if (res && res.success && res.connection) {
          console.log(`[${label}] Connection established after ${attempts} poll(s)`);
          return res;
        }

        if (res && res.pending) {
          // Still waiting for authorization -- log and retry
          console.log(`[${label}] Poll attempt ${attempts}: pending (${res.error || "waiting"})`);
        } else if (res && res.error) {
          // Terminal error states
          if (res.error === "expired_token") {
            throw Object.assign(
              new Error(`Device code expired: ${res.errorDescription || ""}`),
              { code: "EXPIRED_TOKEN", retryable: false }
            );
          }
          if (res.error === "access_denied") {
            throw Object.assign(
              new Error(`User denied authorization: ${res.errorDescription || ""}`),
              { code: "ACCESS_DENIED", retryable: false }
            );
          }
          // Unknown error -- non-terminal, log and retry
          console.log(`[${label}] Poll attempt ${attempts}: ${res.error} -- ${res.errorDescription || ""}`);
        } else {
          console.log(`[${label}] Poll attempt ${attempts}: ${JSON.stringify(res)}`);
        }
      } catch (err) {
        if (err.code === "EXPIRED_TOKEN" || err.code === "ACCESS_DENIED") throw err;
        // Transient network/server error -- log and retry
        console.log(`[${label}] Poll error (retry): ${err.message}`);
      }

      await new Promise((r) => setTimeout(r, intervalMs));
    }

    throw Object.assign(
      new Error(
        `Device authorization timed out for ${label} after ${Math.round(
          ((deviceData.expires_in || 600) * 1000) / 1000
        )}s`
      ),
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
      const errBody =
        res && res.body
          ? typeof res.body === "string"
            ? res.body.slice(0, 200)
            : JSON.stringify(res.body).slice(0, 200)
          : "no body";
      throw new Error(`HTTP ${res ? res.statusCode : "??"} from ${path}: ${errBody}`);
    }
    return res.body || res;
  }

  /**
   * Rename a connection via PUT /api/providers/:id.
   * Kiro uses encodeURIComponent on the id (divergence from grok-cli).
   *
   * @param {string} id - Connection ID.
   * @param {string} name - New display name.
   * @returns {Promise<void>}
   */
  async renameConnection(id, name) {
    await this._apiCall("PUT", `${this.constructor.endpoints.provider}/${encodeURIComponent(id)}`, { name });
  }

  /**
   * Lifecycle: beforeAdd -- quota check.
   * Kiro uses {skip: true, reason} return style (NOT throwing QuotaError).
   *
   * @param {object} credentials
   * @param {object} options
   * @returns {Promise<{skip?: boolean, reason?: string}|void>}
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

  /**
   * Lifecycle: afterAdd -- rename the connection.
   * @param {{id?: string}} result
   */
  async afterAdd(result) {
    if (result && result.id) {
      try {
        const name =
          this._accountEmail ||
          this.config.providers?.kiro?.name ||
          "kiro";
        await this.renameConnection(result.id, name);
      } catch (e) {
        // Non-fatal: connection was already established.
        console.log(`[kiro] Warning: rename failed for ${result.id}: ${e.message}`);
      }
    }
  }

  /**
   * Inspect an existing connection.
   * Local mode: delegates to findById from core/db.
   * Remote mode: GET via API.
   * @param {string} id
   * @returns {Promise<object>}
   */
  async inspect(id) {
    if (this.config.mode === "local") {
      const { findById } = require("../../core/db");
      return findById(this.config, id);
    }
    return this._apiCall("GET", `${this.constructor.endpoints.provider}/${encodeURIComponent(id)}`);
  }

  /**
   * Delete a connection.
   * Local mode: delegates to del from core/db.
   * Remote mode: DELETE via API.
   * @param {string} id
   * @returns {Promise<void>}
   */
  async delete(id) {
    if (this.config.mode === "local") {
      const { del } = require("../../core/db");
      await del(this.config, id);
      return;
    }
    await this._apiCall("DELETE", `${this.constructor.endpoints.provider}/${encodeURIComponent(id)}`);
  }
}

module.exports = KiroProvider;
