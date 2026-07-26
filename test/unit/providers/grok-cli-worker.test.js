"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const {
  buildSignInUrl,
  buildWorkerEnv,
  parseWorkerLine,
  runSignupWorker,
  pickName,
} = require("../../../src/providers/grok-cli/worker-bridge");
const { ProviderError } = require("../../../src/base/errors");

const FAKE_WORKER = path.join(__dirname, "../../fixtures/fake-worker.py");

describe("buildSignInUrl", () => {
  it("embeds user_code in the return_to path", () => {
    const url = buildSignInUrl("ABCD-EFGH");
    assert.ok(url.startsWith("https://accounts.x.ai/sign-in?"));
    assert.ok(url.includes("redirect=oauth2-provider"));
    assert.ok(url.includes(encodeURIComponent("/oauth2/device?user_code=ABCD-EFGH")));
  });
});

describe("pickName", () => {
  it("splits a full name", () => {
    assert.deepStrictEqual(pickName("Jane Doe"), { first: "Jane", last: "Doe" });
  });

  it("falls back to random when missing", () => {
    const n = pickName("");
    assert.ok(n.first);
    assert.ok(n.last);
  });
});

describe("buildWorkerEnv", () => {
  const deviceData = {
    device_code: "SECRET_DEVICE_CODE",
    user_code: "WXYZ-1234",
    codeVerifier: "SECRET_VERIFIER",
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
      "grok-cli": {
        otpSubject: "confirmation code",
        otpSenderDomain: "x.ai",
      },
    },
  };

  it("maps credentials + config to env vars", () => {
    const env = buildWorkerEnv({ deviceData, credentials, config });
    assert.strictEqual(env.GROK_EMAIL, "user@example.com");
    assert.strictEqual(env.GROK_PASSWORD, "s3cret-pass");
    assert.strictEqual(env.GROK_FIRST, "Alex");
    assert.strictEqual(env.GROK_LAST, "Frost");
    assert.strictEqual(env.GROK_IMAP_HOST, "imap.gmail.com");
    assert.strictEqual(env.GROK_IMAP_PORT, "993");
    assert.strictEqual(env.GROK_IMAP_USER, "imap@example.com");
    assert.strictEqual(env.GROK_IMAP_PASSWORD, "imap-pass");
    assert.strictEqual(env.GROK_IMAP_TLS, "true");
    assert.strictEqual(env.GROK_IMAP_DELETE_AFTER_READ, "false");
    assert.strictEqual(env.GROK_OTP_SUBJECT, "confirmation code");
    assert.strictEqual(env.GROK_OTP_SENDER_DOMAIN, "x.ai");
    assert.strictEqual(env.PURE_HTTP, "1");
    assert.ok(env.GROK_SIGNIN_URL.includes("WXYZ-1234"));
  });

  it("never includes device_code or codeVerifier (security)", () => {
    const env = buildWorkerEnv({ deviceData, credentials, config });
    const joined = JSON.stringify(env);
    assert.ok(!joined.includes("SECRET_DEVICE_CODE"));
    assert.ok(!joined.includes("SECRET_VERIFIER"));
    assert.ok(!("GROK_DEVICE_CODE" in env));
    assert.ok(!("GROK_CODE_VERIFIER" in env));
    // Sign-in URL must only carry user_code.
    assert.ok(!env.GROK_SIGNIN_URL.includes("SECRET"));
  });

  it("passes proxy string through", () => {
    const env = buildWorkerEnv({
      deviceData,
      credentials,
      config,
      options: { proxy: "http://user:pass@1.2.3.4:8080" },
    });
    assert.strictEqual(env.GROK_PROXY, "http://user:pass@1.2.3.4:8080");
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
    assert.strictEqual(env.GROK_PROXY, "socks5://u:p@9.9.9.9:3128");
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
      command: process.execPath.includes("node")
        ? "python3"
        : "python3",
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
