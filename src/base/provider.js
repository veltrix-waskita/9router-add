"use strict";

const { AuthError, QuotaError, ProviderError } = require("./errors");

/**
 * Abstract base class for all provider plugins.
 *
 * Subclasses must override the static `providerName` getter and the
 * `add()` method. Optional lifecycle hooks (`beforeAdd`, `afterAdd`,
 * `onError`) and helpers (`apiCall`, `injectToDb`, `launchBrowser`)
 * are provided with sensible defaults.
 *
 * The `add()` method is wrapped at construction time with the
 * beforeAdd / afterAdd / onError lifecycle so that subclass overrides
 * are captured by the wrapper.
 *
 * WARNING: Subclass overrides of `add()` MUST NOT call `super.add(...)` —
 * the lifecycle wrapper is installed on the instance at construction time,
 * and `super.add` resolves directly to `BaseProvider.prototype.add`,
 * bypassing the wrapper entirely. Use the `beforeAdd` / `afterAdd`
 * hooks if pre- or post-processing is needed.
 */
class BaseProvider {
  /**
   * @param {object} config - Resolved config for this provider.
   * @param {object} api - HTTP client wrapper (e.g. HttpClient).
   * @param {object} services - Shared services (proxy, IMAP, etc.).
   */
  constructor(config, api, services) {
    if (new.target === BaseProvider) {
      throw new Error("BaseProvider cannot be instantiated directly");
    }
    this.config = config;
    this.api = api;
    this.services = services;

    // Capture subclass's add() override (if any) and replace this.add
    // with a lifecycle wrapper. This ensures the wrapper actually
    // intercepts subclass overrides (which would otherwise shadow
    // BaseProvider.prototype.add on the prototype chain).
    const userAdd = this.add;
    this.add = async (credentials, options) => {
      try {
        const beforeResult = await this.beforeAdd(credentials, options);
        if (beforeResult && beforeResult.skip) {
          return { ok: false, skip: true, reason: beforeResult.reason };
        }
        const result = await userAdd.call(this, credentials, options);
        await this.afterAdd(result);
        return result;
      } catch (err) {
        await this.onError(err, { credentials, options });
        if (err instanceof QuotaError) {
          return { ok: false, skip: true, reason: err.message };
        }
        if (err instanceof AuthError) {
          return { ok: false, error: err.message };
        }
        throw err;
      }
    };
  }

  /** @returns {string|undefined} Provider identifier; subclasses MUST override. */
  static get providerName() {
    return undefined;
  }

  /** @returns {object} Map of named HTTP endpoint paths. */
  static get endpoints() {
    return {};
  }

  /** Execute the account creation flow. Subclasses MUST override. */
  async add(credentials, options) {
    throw new Error("add() must be implemented");
  }

  /** Optional pre-flow hook; return `{ skip: true, reason }` to skip add(). */
  async beforeAdd(credentials, options) {
    // optional hook
  }

  /** Optional post-flow hook invoked after a successful add(). */
  async afterAdd(result) {
    // optional hook
  }

  /** Optional error hook invoked when add() throws. */
  async onError(err, context) {
    // optional hook
  }

  /** Inspect an existing connection; subclasses MAY override. */
  async inspect(id) {
    throw new Error("inspect() not implemented");
  }

  /** Delete a connection; subclasses MAY override. */
  async delete(id) {
    throw new Error("delete() not implemented");
  }

  /** Convenience wrapper around `this.api.request`. */
  async apiCall(method, path, body, opts = {}) {
    return this.api.request(this.config, { method, path, body, ...opts });
  }

  /** Insert a connection into the local DB via the db wrapper. */
  async injectToDb(connection) {
    const { insert } = require("../core/db");
    return insert(this.config, connection);
  }

  /** Launch a stealth browser via the browser service. */
  async launchBrowser(options = {}) {
    const { launchStealthBrowser } = require("../services/browser");
    return launchStealthBrowser(this.config, this.services, options);
  }
}

module.exports = { BaseProvider };
