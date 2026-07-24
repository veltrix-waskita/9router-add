"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const {
  buildWorkerEnv,
  parseWorkerLine,
  runSignupWorker,
  pickName,
} = require("../../../src/providers/kiro/worker-bridge");
const { ProviderError } = require("../../../src/base/errors");

const FAKE_WORKER = path.join(__dirname, "../../fixtures/fake-worker.py");

describe("pickName", () => {
  it("returns full string when provided", () => {
    assert.strictEqual(pickName("Jane Doe"), "Jane Doe");
  });

  it("falls back to random when missing", () => {
    const n = pickName("");
    assert.ok(n.includes(" "));
    const parts = n.split(" ");
    assert.ok(parts.length >= 2);
  });
});

describe("buildWorkerEnv", () => {
  const deviceData = {
    device_code: "secret-dc",
    verification_uri_complete: "https://example.com/activate?user_code=ABC123",
    codeVerifier: "secret-verifier",
    extraData: { _clientId: "cid", _clientSecret: "cs" },
    expires_in: 1800,
  };
  const credentials = {
    email: "user@example.com",
    password: "s3cret-pass",
    name: "Alex Frost",
  };
  const config = {
    imap: {
      host: "imap.gmail.com",
      port: 993,
      user: "imap@example.com",
      password: "imap-pass",
      tls: true,
      deleteAfterRead: false,
    },
    providers: {
      kiro: {
        otpSubject: "confirmation code",
        otpSenderDomain: "signin.aws",
      },
    },
  };

  it("maps credentials + config to env vars", () => {
    const env = buildWorkerEnv({ deviceData, credentials, config });
    assert.strictEqual(env.KIRO_EMAIL, "user@example.com");
    assert.strictEqual(env.KIRO_PASSWORD, "s3cret-pass");
    assert.strictEqual(env.KIRO_NAME, "Alex Frost");
    assert.strictEqual(env.KIRO_IMAP_HOST, "imap.gmail.com");
    assert.strictEqual(env.KIRO_IMAP_PORT, "993");
    assert.strictEqual(env.KIRO_IMAP_USER, "imap@example.com");
    assert.strictEqual(env.KIRO_IMAP_PASSWORD, "imap-pass");
    assert.strictEqual(env.KIRO_IMAP_TLS, "true");
    assert.strictEqual(env.KIRO_IMAP_DELETE_AFTER_READ, "false");
    assert.strictEqual(env.KIRO_OTP_SUBJECT, "confirmation code");
    assert.strictEqual(env.KIRO_OTP_SENDER_DOMAIN, "signin.aws");
    assert.strictEqual(env.PURE_HTTP, "1");
    assert.strictEqual(env.KIRO_DEVICE_URL, "https://example.com/activate?user_code=ABC123");
  });

  it("must not leak secrets to worker env", () => {
    const env = buildWorkerEnv({ deviceData, credentials, config, options: {} });
    const envStr = JSON.stringify(env);
    assert(!envStr.includes("secret-dc"), "device_code leaked");
    assert(!envStr.includes("secret-verifier"), "codeVerifier leaked");
    assert(!envStr.includes("_clientSecret"), "clientSecret leaked");
    assert(!envStr.includes("_clientId"), "clientId leaked");
    assert.strictEqual(env.KIRO_DEVICE_URL, deviceData.verification_uri_complete);
    assert(!Object.keys(env).some((k) => k.includes("DEVICE_CODE")), "DEVICE_CODE key exists");
  });

  it("never includes device_code or codeVerifier (security)", () => {
    const env = buildWorkerEnv({ deviceData, credentials, config });
    const joined = JSON.stringify(env);
    assert.ok(!joined.includes("secret-dc"));
    assert.ok(!joined.includes("secret-verifier"));
    assert.ok(!("KIRO_DEVICE_CODE" in env));
    assert.ok(!("KIRO_CODE_VERIFIER" in env));
  });

  it("passes proxy string through", () => {
    const env = buildWorkerEnv({
      deviceData,
      credentials,
      config,
      options: { proxy: "http://user:pass@1.2.3.4:8080" },
    });
    assert.strictEqual(env.KIRO_PROXY, "http://user:pass@1.2.3.4:8080");
  });

  it("builds proxy URL from object form", () => {
    const env = buildWorkerEnv({
      deviceData,
      credentials,
      config,
      options: {
        proxy: {
          host: "9.9.9.9",
          port: 3128,
          username: "u",
          password: "p",
          protocol: "socks5",
        },
      },
    });
    assert.strictEqual(env.KIRO_PROXY, "socks5://u:p@9.9.9.9:3128");
  });
});

describe("parseWorkerLine", () => {
  it("skips empty lines", () => {
    assert.deepStrictEqual(parseWorkerLine("  \n"), { kind: "skip" });
  });

  it("marks non-JSON as debug", () => {
    assert.deepStrictEqual(parseWorkerLine("hello world"), {
      kind: "debug",
      raw: "hello world",
    });
  });

  it("parses step events", () => {
    const line = JSON.stringify({ event: "step", step: "bootstrap", status: "ok" });
    const p = parseWorkerLine(line);
    assert.strictEqual(p.kind, "event");
    assert.strictEqual(p.event, "step");
    assert.strictEqual(p.payload.step, "bootstrap");
  });

  it("parses result via kind or event", () => {
    const a = parseWorkerLine(JSON.stringify({ kind: "result", ok: true }));
    assert.strictEqual(a.kind, "result");
    assert.strictEqual(a.ok, true);

    const b = parseWorkerLine(
      JSON.stringify({ event: "result", ok: false, error: "boom", step: "otp" })
    );
    assert.strictEqual(b.kind, "result");
    assert.strictEqual(b.ok, false);
    assert.strictEqual(b.error, "boom");
    assert.strictEqual(b.step, "otp");
  });
});

describe("runSignupWorker", () => {
  it("resolves on ok result", async () => {
    const events = [];
    const result = await runSignupWorker({
      command: "python3",
      args: [FAKE_WORKER],
      env: { FAKE_WORKER_MODE: "ok" },
      onEvent: (e) => events.push(e),
      timeoutMs: 10000,
    });
    assert.deepStrictEqual(result, { ok: true });
    assert.ok(events.some((e) => e.kind === "event"));
    assert.ok(events.some((e) => e.kind === "result" && e.ok));
  });

  it("rejects on non-zero exit with ProviderError", async () => {
    await assert.rejects(
      () =>
        runSignupWorker({
          command: "python3",
          args: [FAKE_WORKER],
          env: { FAKE_WORKER_MODE: "fail" },
          timeoutMs: 10000,
        }),
      (err) => {
        assert.ok(err instanceof ProviderError);
        assert.ok(/turnstile-timeout/i.test(err.message));
        assert.strictEqual(err.code, "TURNSTILE_TIMEOUT");
        assert.strictEqual(err.retryable, true);
        return true;
      }
    );
  });

  it("rejects on timeout", async () => {
    await assert.rejects(
      () =>
        runSignupWorker({
          command: "python3",
          args: [FAKE_WORKER],
          env: { FAKE_WORKER_MODE: "hang" },
          timeoutMs: 300,
        }),
      (err) => {
        assert.ok(err instanceof ProviderError);
        assert.strictEqual(err.code, "WORKER_TIMEOUT");
        assert.strictEqual(err.retryable, true);
        return true;
      }
    );
  });

  it("rejects when exit 0 without ok result", async () => {
    await assert.rejects(
      () =>
        runSignupWorker({
          command: "python3",
          args: [FAKE_WORKER],
          env: { FAKE_WORKER_MODE: "noresult" },
          timeoutMs: 10000,
        }),
      (err) => {
        assert.ok(err instanceof ProviderError);
        assert.strictEqual(err.code, "WORKER_PROTOCOL");
        return true;
      }
    );
  });
});