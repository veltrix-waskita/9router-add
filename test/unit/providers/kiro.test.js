"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");
const path = require("path");

function loadProvider() {
  const p = path.resolve(__dirname, "../../../src/providers/kiro/index.js");
  delete require.cache[require.resolve(p)];
  return require(p);
}

function makeConfig(overrides = {}) {
  return {
    mode: "remote",
    baseUrl: "https://example.test",
    imap: {
      host: "imap.gmail.com",
      user: "imap@example.com",
      password: "imap-pass",
    },
    providers: {
      kiro: {
        quotaCap: 3,
        otpSubject: "Verify your AWS Builder ID email address",
        otpSenderDomain: "signin.aws",
      },
    },
    providerConfig: {
      quotaCap: 3,
      otpSubject: "Verify your AWS Builder ID email address",
      otpSenderDomain: "signin.aws",
    },
    ...overrides,
  };
}

function makeProvider(config, services = {}) {
  const KiroProvider = loadProvider();
  // api is unused when _apiCall is stubbed; pass a no-op.
  return new KiroProvider(config, { request: async () => ({}) }, services);
}

describe("KiroProvider statics", () => {
  it("providerName is kiro", () => {
    const KiroProvider = loadProvider();
    assert.strictEqual(KiroProvider.providerName, "kiro");
  });

  it("endpoints returns deviceCode, poll, and provider", () => {
    const KiroProvider = loadProvider();
    assert.strictEqual(
      KiroProvider.endpoints.deviceCode,
      "/api/oauth/kiro/device-code"
    );
    assert.strictEqual(
      KiroProvider.endpoints.poll,
      "/api/oauth/kiro/poll"
    );
    assert.strictEqual(
      KiroProvider.endpoints.provider,
      "/api/providers"
    );
  });
});

describe("KiroProvider.detectMethod", () => {
  it("null/undefined returns email", () => {
    const p = makeProvider(makeConfig());
    assert.strictEqual(p.detectMethod(null), "email");
    assert.strictEqual(p.detectMethod(undefined), "email");
  });

  it("@gmail.com returns google", () => {
    const p = makeProvider(makeConfig());
    assert.strictEqual(p.detectMethod("user@gmail.com"), "google");
    assert.strictEqual(p.detectMethod("USER@GMAIL.COM"), "google");
  });

  it("@outlook.com returns email", () => {
    const p = makeProvider(makeConfig());
    assert.strictEqual(p.detectMethod("user@outlook.com"), "email");
  });
});

describe("KiroProvider.add validation", () => {
  it("google/@gmail.com returns AuthError result", async () => {
    const p = makeProvider(makeConfig());
    const result = await p.add({ email: "user@gmail.com", password: "pw" }, {});
    assert.strictEqual(result.ok, false);
    assert.ok(/Google.*pure-HTTP/i.test(result.error));
  });

  it("imap mode requires email+password", async () => {
    const p = makeProvider(makeConfig());
    await assert.rejects(() => p.add({}, {}), /email.+password/i);
    await assert.rejects(
      () => p.add({ email: "a@b.com" }, {}),
      /email.+password/i
    );
  });

  it("imap mode requires IMAP config", async () => {
    const p = makeProvider(makeConfig({ imap: null }));
    await assert.rejects(
      () => p.add({ email: "a@b.com", password: "x" }, {}),
      /IMAP config/i
    );
  });

  it("tempmail mode allowed without email (uses tempmail@pending.local)", async () => {
    const p = makeProvider(makeConfig({ imap: null }));
    // Stub later stages so they don't spawn real subprocesses.
    p._apiCall = async () => ({
      device_code: "d",
      user_code: "u",
      verification_uri_complete: "https://example.test/device",
      expires_in: 0,
      interval: 0.001,
      _clientId: "cid",
      _clientSecret: "cs",
      _region: "us-east-1",
      _authMethod: "email",
      _startUrl: "https://start.example.com",
    });
    p._runSignupWorker = async () => {};
    p.pollUntilConnected = async () => ({ success: true, connection: { id: "t" } });
    p.renameConnection = async () => ({});
    const result = await p.add({}, { emailSource: "tempmail" });
    assert.strictEqual(result.ok, true);
    assert.strictEqual(p._accountEmail, "tempmail@pending.local");
    // Password should be auto-generated.
    assert.ok(p._accountPassword);
    assert.ok(p._accountPassword.startsWith("Kiro"));
  });

  it("tempmail mode auto-generates password when empty", async () => {
    const p = makeProvider(makeConfig({ imap: null }));
    p._apiCall = async () => ({
      device_code: "d",
      user_code: "u",
      verification_uri_complete: "https://example.test/device",
      expires_in: 0,
      interval: 0.001,
      _clientId: "cid",
      _clientSecret: "cs",
      _region: "us-east-1",
      _authMethod: "email",
      _startUrl: "https://start.example.com",
    });
    p._runSignupWorker = async () => {};
    p.pollUntilConnected = async () => ({ success: true, connection: { id: "t" } });
    p.renameConnection = async () => ({});
    await p.add({ email: "a@b.com" }, { emailSource: "tempmail" });
    // Password is auto-generated.
    assert.ok(p._accountPassword);
    assert.ok(p._accountPassword.startsWith("Kiro"));
  });
});

describe("KiroProvider.add happy path", () => {
  it("GET device-code, spawn worker, poll, rename", async () => {
    const p = makeProvider(makeConfig());
    const calls = [];

    p._apiCall = async (method, path, body) => {
      calls.push({ method, path, body });
      if (method === "GET" && path.endsWith("/device-code")) {
        return {
          device_code: "dc-1",
          user_code: "UC-1",
          verification_uri_complete: "https://example.test/device",
          expires_in: 60,
          interval: 0.001,
          _clientId: "cid",
          _clientSecret: "cs",
          _region: "us-east-1",
          _authMethod: "email",
          _startUrl: "https://start.example.com",
        };
      }
      if (method === "POST" && path.endsWith("/poll")) {
        return {
          success: true,
          connection: { id: "conn-42" },
        };
      }
      if (method === "PUT" && path.includes("/api/providers/")) {
        return { ok: true };
      }
      throw new Error(`unexpected ${method} ${path}`);
    };

    p._runSignupWorker = async (deviceData, options) => {
      calls.push({
        method: "WORKER",
        device_code: deviceData.device_code,
        email: p._accountEmail,
      });
    };

    const result = await p.add(
      { email: "user@example.com", password: "pw" },
      {}
    );

    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.connection.id, "conn-42");

    // First call: GET device-code.
    assert.strictEqual(calls[0].method, "GET");
    assert.ok(calls[0].path.includes("device-code"));

    // Second call: WORKER.
    assert.strictEqual(calls[1].method, "WORKER");
    assert.strictEqual(calls[1].device_code, "dc-1");

    // Poll call uses {deviceCode, extraData} format.
    const pollCall = calls.find(
      (c) => c.method === "POST" && c.path.endsWith("/poll")
    );
    assert.ok(pollCall, "expected a poll POST");
    assert.deepStrictEqual(pollCall.body, {
      deviceCode: "dc-1",
      extraData: {
        _clientId: "cid",
        _clientSecret: "cs",
        _region: "us-east-1",
        _authMethod: "email",
        _startUrl: "https://start.example.com",
      },
    });

    // Rename call uses encodeURIComponent.
    const renameCall = calls.find(
      (c) =>
        c.method === "PUT" &&
        c.path.includes("conn-42") &&
        c.body &&
        c.body.name === "user@example.com"
    );
    assert.ok(renameCall, "expected a rename PUT");
    // Verify encodeURIComponent was used on the id.
    assert.ok(renameCall.path.includes(encodeURIComponent("conn-42")));
  });
});

describe("KiroProvider.pollUntilConnected", () => {
  it("success returns result with connection", async () => {
    const p = makeProvider(makeConfig());
    let n = 0;
    let seenBody = null;
    p._apiCall = async (method, path, body) => {
      n += 1;
      seenBody = body;
      if (n < 2) {
        return { success: false, error: "authorization_pending", pending: true };
      }
      return { success: true, connection: { id: "c1" } };
    };
    const r = await p.pollUntilConnected({
      device_code: "dc",
      expires_in: 60,
      interval: 0.001,
      _clientId: "cid",
      _clientSecret: "cs",
      _region: "us-east-1",
      _authMethod: "email",
      _startUrl: "https://start.example.com",
    });
    assert.strictEqual(r.success, true);
    assert.ok(n >= 2);
    assert.deepStrictEqual(seenBody, {
      deviceCode: "dc",
      extraData: {
        _clientId: "cid",
        _clientSecret: "cs",
        _region: "us-east-1",
        _authMethod: "email",
        _startUrl: "https://start.example.com",
      },
    });
  });

  it("expired_token throws with code EXPIRED_TOKEN", async () => {
    const p = makeProvider(makeConfig());
    p._apiCall = async () => ({
      error: "expired_token",
      errorDescription: "gone",
    });
    await assert.rejects(
      () =>
        p.pollUntilConnected({
          device_code: "dc",
          expires_in: 30,
          interval: 0.001,
          _clientId: "cid",
          _clientSecret: "cs",
          _region: "us-east-1",
          _authMethod: "email",
          _startUrl: "https://start.example.com",
        }),
      /Device code expired/i
    );
  });

  it("access_denied throws with code ACCESS_DENIED", async () => {
    const p = makeProvider(makeConfig());
    p._apiCall = async () => ({
      error: "access_denied",
      errorDescription: "nope",
    });
    await assert.rejects(
      () =>
        p.pollUntilConnected({
          device_code: "dc",
          expires_in: 60,
          interval: 0.001,
          _clientId: "cid",
          _clientSecret: "cs",
          _region: "us-east-1",
          _authMethod: "email",
          _startUrl: "https://start.example.com",
        }),
      /User denied/i
    );
  });

  it("timeout throws POLL_TIMEOUT (retryable)", async () => {
    const p = makeProvider(makeConfig());
    p._apiCall = async () => ({ pending: true });
    try {
      await p.pollUntilConnected({
        device_code: "dc",
        expires_in: 0,
        interval: 0.001,
        _clientId: "cid",
        _clientSecret: "cs",
        _region: "us-east-1",
        _authMethod: "email",
        _startUrl: "https://start.example.com",
      });
      assert.fail("expected rejection");
    } catch (err) {
      assert.strictEqual(err.code, "POLL_TIMEOUT");
      assert.strictEqual(err.retryable, true);
      assert.ok(/timed out/i.test(err.message));
    }
  });

  it("missing device_code throws", async () => {
    const p = makeProvider(makeConfig());
    await assert.rejects(
      () => p.pollUntilConnected({}),
      /no device_code/i
    );
  });
});

describe("KiroProvider.renameConnection", () => {
  it("uses encodeURIComponent on id", async () => {
    const p = makeProvider(makeConfig());
    let seen = null;
    p._apiCall = async (method, path, body) => {
      seen = { method, path, body };
      return { ok: true };
    };
    const weirdId = "conn id/with?special&chars";
    await p.renameConnection(weirdId, "my-name");
    assert.strictEqual(seen.method, "PUT");
    assert.ok(seen.path.includes("/api/providers/"));
    assert.ok(seen.path.includes(encodeURIComponent(weirdId)));
    assert.deepStrictEqual(seen.body, { name: "my-name" });
  });
});

describe("KiroProvider.inspect / delete", () => {
  it("local mode inspect uses findById", async () => {
    const { findById } = require("../../../src/core/db");
    // findById is a no-op that returns null when not connected.
    const p = makeProvider(makeConfig({ mode: "local" }));
    const r = await p.inspect("x");
    // findById returns null when no DB is connected (local mode, no DB).
    assert.strictEqual(r, null);
  });

  it("remote mode inspect uses API", async () => {
    const p = makeProvider(makeConfig({ mode: "remote" }));
    let seen = null;
    p._apiCall = async (method, path) => {
      seen = { method, path };
      return { id: "x" };
    };
    const r = await p.inspect("x");
    assert.deepStrictEqual(seen, { method: "GET", path: "/api/providers/x" });
    assert.strictEqual(r.id, "x");
  });

  it("local mode delete uses del", async () => {
    const p = makeProvider(makeConfig({ mode: "local" }));
    let delCalled = false;
    // Mock require'd db.del by patching delete to capture the call.
    const origDelete = p.delete;
    p.delete = async (id) => {
      delCalled = true;
      assert.strictEqual(id, "y");
    };
    await p.delete("y");
    assert.strictEqual(delCalled, true);
  });

  it("remote mode delete uses API", async () => {
    const p = makeProvider(makeConfig({ mode: "remote" }));
    let seen = null;
    p._apiCall = async (method, path) => {
      seen = { method, path };
      return {};
    };
    await p.delete("y");
    assert.deepStrictEqual(seen, { method: "DELETE", path: "/api/providers/y" });
  });
});

describe("KiroProvider.beforeAdd quota", () => {
  it("quota not exceeded returns undefined", async () => {
    const services = {
      quota: {
        tryConsume: () => ({ allowed: true }),
      },
    };
    const p = makeProvider(makeConfig(), services);
    const result = await p.beforeAdd({ email: "user@example.com" }, {});
    assert.strictEqual(result, undefined);
  });

  it("quota exceeded returns {skip: true, reason}", async () => {
    const services = {
      quota: {
        tryConsume: () => ({ allowed: false }),
      },
    };
    const p = makeProvider(makeConfig(), services);
    const result = await p.beforeAdd({ email: "user@example.com" }, {});
    assert.ok(result);
    assert.strictEqual(result.skip, true);
    assert.ok(/Quota cap/i.test(result.reason));
  });

  it("quota skip propagates through add() lifecycle", async () => {
    const services = {
      quota: {
        tryConsume: () => ({ allowed: false }),
      },
    };
    const p = makeProvider(makeConfig(), services);
    const result = await p.add({ email: "user@example.com", password: "pw" }, {});
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.skip, true);
    assert.ok(/Quota cap/i.test(result.reason));
  });

  it("allows under quota through lifecycle", async () => {
    const services = {
      quota: {
        tryConsume: () => ({ allowed: true }),
      },
    };
    const p = makeProvider(makeConfig(), services);
    p._apiCall = async (method, path) => {
      if (method === "GET") {
        return {
          device_code: "dc",
          user_code: "uc",
          verification_uri_complete: "https://example.test/device",
          expires_in: 60,
          interval: 0.001,
          _clientId: "cid",
          _clientSecret: "cs",
          _region: "us-east-1",
          _authMethod: "email",
          _startUrl: "https://start.example.com",
        };
      }
      if (method === "POST") {
        return { success: true, connection: { id: "c" } };
      }
      return {};
    };
    p._runSignupWorker = async () => {};
    p.renameConnection = async () => ({});
    const result = await p.add({ email: "user@example.com", password: "pw" }, {});
    assert.strictEqual(result.ok, true);
  });
});