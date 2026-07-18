"use strict";

class ProviderError extends Error {
  constructor(message, { code, recoverable = false, retryable = false } = {}) {
    super(message);
    this.name = "ProviderError";
    this.code = code || null;
    this.recoverable = recoverable;
    this.retryable = retryable;
  }
}

class AuthError extends ProviderError {
  constructor(message, code = "AUTH_FAILED") {
    super(message, { code, recoverable: true });
    this.name = "AuthError";
  }
}

class QuotaError extends ProviderError {
  constructor(domain) {
    super(`Quota cap reached for domain: ${domain}`, {
      code: "QUOTA_EXCEEDED",
      recoverable: true,
    });
    this.name = "QuotaError";
  }
}

class RetryableError extends ProviderError {
  constructor(message, code = "RETRYABLE") {
    super(message, { code, retryable: true });
    this.name = "RetryableError";
  }
}

class BrowserError extends ProviderError {
  constructor(message, code = "BROWSER_ERROR") {
    super(message, { code, retryable: true });
    this.name = "BrowserError";
  }
}

module.exports = { ProviderError, AuthError, QuotaError, RetryableError, BrowserError };
