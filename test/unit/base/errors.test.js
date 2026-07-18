"use strict";
const { describe, it } = require("node:test");
const assert = require("node:assert");
const {
  ProviderError,
  AuthError,
  QuotaError,
  RetryableError,
  BrowserError,
} = require("../../../src/base/errors");

describe("ProviderError", () => {
  it("should set message, code, recoverable, retryable", () => {
    const err = new ProviderError("test", { code: "TEST", recoverable: true, retryable: false });
    assert.strictEqual(err.message, "test");
    assert.strictEqual(err.code, "TEST");
    assert.strictEqual(err.recoverable, true);
    assert.strictEqual(err.retryable, false);
    assert.strictEqual(err.name, "ProviderError");
  });
  it("should default to recoverable=false, retryable=false", () => {
    const err = new ProviderError("default");
    assert.strictEqual(err.recoverable, false);
    assert.strictEqual(err.retryable, false);
  });
});

describe("AuthError", () => {
  it("should set code=AUTH_FAILED, recoverable=true", () => {
    const err = new AuthError("login failed");
    assert.strictEqual(err.message, "login failed");
    assert.strictEqual(err.code, "AUTH_FAILED");
    assert.strictEqual(err.recoverable, true);
    assert.strictEqual(err.name, "AuthError");
  });
});

describe("QuotaError", () => {
  it("should set code=QUOTA_EXCEEDED, recoverable=true", () => {
    const err = new QuotaError("mozmail.com");
    assert.ok(err.message.includes("mozmail.com"));
    assert.strictEqual(err.code, "QUOTA_EXCEEDED");
    assert.strictEqual(err.recoverable, true);
    assert.strictEqual(err.name, "QuotaError");
  });
});

describe("RetryableError", () => {
  it("should set retryable=true", () => {
    const err = new RetryableError("timeout");
    assert.strictEqual(err.retryable, true);
    assert.strictEqual(err.name, "RetryableError");
  });
});

describe("BrowserError", () => {
  it("should set retryable=true, code=BROWSER_ERROR", () => {
    const err = new BrowserError("crash");
    assert.strictEqual(err.retryable, true);
    assert.strictEqual(err.code, "BROWSER_ERROR");
    assert.strictEqual(err.name, "BrowserError");
  });
});
