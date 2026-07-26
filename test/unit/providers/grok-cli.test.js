"use strict";

const { describe, it, beforeEach } = require("node:test");
const assert = require("node:assert");
const path = require("path");

function loadProvider() {
  const p = path.resolve(__dirname, "../../../src/providers/grok-cli/index.js");
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
      "grok-cli": {
        quotaCap: 3,
        otpSubject: "confirmation code",
        otpSenderDomain: "x.ai",
      },
    },
    providerConfig: {
      quotaCap: 3,
      otpSubject: "confirmation code",
      otpSenderDomain: "x.ai",
    },
    ...overrides,
  };
}

function makeProvider(config, services = {}) {
  const GrokCliProvider = loadProvider();
  // api is unused when _apiCall is stubbed; pass a no-op.
  return new GrokCliProvider(config, { request: async () => ({}) }, services);
}

describe("GrokCliProvider statics", () => {
  it("providerName is grok-cli", () => {
    const GrokCliProvider = loadProvider();
    assert.strictEqual(GrokCliProvider.providerName, "grok-cli");
  });

  it("endpoints returns deviceCode and poll", () => {
    const GrokCliProvider = loadProvider();
    assert.strictEqual(
      GrokCliProvider.endpoints.deviceCode,
      "/api/oauth/grok-cli/device-code"
    );
    assert.strictEqual(
      GrokCliProvider.endpoints.poll,
      "/api/oauth/grok-cli/poll"
    );
  });
});

describe("GrokCliProvider.add validation", () => {
  it("requires email and password", async () => {
    const p = makeProvider(makeConfig());
    await assert.rejects(() => p.add({}, {}), /email \+ password/i);
    await assert.rejects(
      () => p.add({ email: "a@b.com" }, {}),
      /email \+ password/i
    );
  });

  it("requires IMAP config (imap mode)", async () => {
    const p = makeProvider(makeConfig({ imap: null }));
    await assert.rejects(
      () => p.add({ email: "a@b.com", password: "x" }, {}),
      /IMAP config/i
    );
  });

  it("allows tempmail mode without IMAP config", async () => {
    const p = makeProvider(makeConfig({ imap: null }));
    // Stub later stages so they don't spawn real subprocesses.
    p._apiCall = async () => ({
      device_code: "d", user_code: "u",
      expires_in: 0, interval: 0.001, codeVerifier: "v",
    });
    p._runSignupWorker = async () => {};
    // Make poll happy so add() resolves — we only test validation here.
    p.pollUntilConnected = async () => ({ success: true, connection: { id: "t" } });
    p.renameConnection = async () => ({});
    const result = await p.add({ password: "x" }, { emailSource: "tempmail" });
    assert.strictEqual(result.ok, true);
  });

  it("requires email+password in imap mode", async () => {
    const p = makeProvider(makeConfig());
    await assert.rejects(
      () => p.add({ password: "x" }, {}),
      /requires email/
    );
  });

  it("allows missing email in tempmail mode", async () => {
    const p = makeProvider(makeConfig({ imap: null }));
    // Stub later stages so they don't spawn real subprocesses.
    p._apiCall = async () => ({
      device_code: "d", user_code: "u",
      expires_in: 0, interval: 0.001, codeVerifier: "v",
    });
    p._runSignupWorker = async () => {};
    p.pollUntilConnected = async () => ({ success: true, connection: { id: "t" } });
    p.renameConnection = async () => ({});
    const result = await p.add({ password: "x" }, { emailSource: "tempmail" });
    assert.strictEqual(result.ok, true);
  });
});

describe("GrokCliProvider.add happy path", () => {
  it("GET device-code, spawn worker, poll, rename", async () => {
    const p = makeProvider(makeConfig());
    const calls = [];

    p._apiCall = async (method, path, body) => {
      calls.push({ method, path, body });
      if (method === "GET" && path.endsWith("/device-code")) {
        return {
          device_code: "dc-1",
          user_code: "UC-1",
          expires_in: 60,
          interval: 0.001,
          codeVerifier: "cv",
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

    p._runSignupWorker = async (deviceData, credentials) => {
      calls.push({
        method: "WORKER",
        user_code: deviceData.user_code,
        email: credentials.email,
      });
      // Security: device_code must be present in Node but not passed further here.
      assert.strictEqual(deviceData.device_code, "dc-1");
      assert.strictEqual(deviceData.codeVerifier, "cv");
    };

    const result = await p.add(
      { email: "user@example.com", password: "pw" },
      {}
    );

    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.connection.id, "conn-42");

    assert.strictEqual(calls[0].method, "GET");
    assert.ok(calls[0].path.includes("device-code"));
    assert.strictEqual(calls[1].method, "WORKER");
    assert.strictEqual(calls[1].user_code, "UC-1");
    const pollCall = calls.find(
      (c) => c.method === "POST" && c.path.endsWith("/poll")
    );
    assert.ok(pollCall, "expected a poll POST");
    // 9router requires both — missing codeVerifier is the live failure mode.
    assert.deepStrictEqual(pollCall.body, {
      deviceCode: "dc-1",
      codeVerifier: "cv",
    });
    assert.ok(
      calls.some(
        (c) =>
          c.method === "PUT" &&
          c.path.includes("conn-42") &&
          c.body &&
          c.body.name === "user@example.com"
      )
    );
  });
});

describe("GrokCliProvider.pollUntilConnected", () => {
  it("returns on success and sends codeVerifier", async () => {
    const p = makeProvider(makeConfig());
    let n = 0;
    let seenBody = null;
    p._apiCall = async (method, path, body) => {
      n += 1;
      seenBody = body;
      if (n < 2) return { success: false, error: "authorization_pending", pending: true };
      return { success: true, connection: { id: "c1" } };
    };
    // Avoid rename side-effect noise.
    p.renameConnection = async () => ({});
    const r = await p.pollUntilConnected(
      {
        device_code: "dc",
        codeVerifier: "verifier-secret",
        expires_in: 60,
        interval: 0.001,
      },
      "e@x.com"
    );
    assert.strictEqual(r.success, true);
    assert.ok(n >= 2);
    assert.deepStrictEqual(seenBody, {
      deviceCode: "dc",
      codeVerifier: "verifier-secret",
    });
  });

  it("throws when codeVerifier missing", async () => {
    const p = makeProvider(makeConfig());
    await assert.rejects(
      () =>
        p.pollUntilConnected(
          { device_code: "dc", expires_in: 30, interval: 0.001 },
          "e@x.com"
        ),
      /no device_code or codeVerifier/i
    );
  });

  it("throws on expired_token", async () => {
    const p = makeProvider(makeConfig());
    p._apiCall = async () => ({ error: "expired_token", errorDescription: "gone" });
    await assert.rejects(
      () =>
        p.pollUntilConnected(
          {
            device_code: "dc",
            codeVerifier: "cv",
            expires_in: 30,
            interval: 0.001,
          },
          "e@x.com"
        ),
      /Device code expired/i
    );
  });

  it("throws on access_denied", async () => {
    const p = makeProvider(makeConfig());
    p._apiCall = async () => ({ error: "access_denied", errorDescription: "nope" });
    await assert.rejects(
      () =>
        p.pollUntilConnected(
          {
            device_code: "dc",
            codeVerifier: "cv",
            expires_in: 60,
            interval: 0.001,
          },
          "e@x.com"
        ),
      /User denied/i
    );
  });

  it("throws on timeout", async () => {
    const p = makeProvider(makeConfig());
    p._apiCall = async () => ({ pending: true });
    await assert.rejects(
      () =>
        p.pollUntilConnected(
          {
            device_code: "dc",
            codeVerifier: "cv",
            expires_in: 0,
            interval: 0.001,
          },
          "e@x.com"
        ),
      /timed out/i
    );
  });
});

describe("GrokCliProvider.renameConnection", () => {
  it("PUT /api/providers/:id", async () => {
    const p = makeProvider(makeConfig());
    let seen = null;
    p._apiCall = async (method, path, body) => {
      seen = { method, path, body };
      return { ok: true };
    };
    await p.renameConnection("abc");
    assert.strictEqual(seen.method, "PUT");
    assert.strictEqual(seen.path, "/api/providers/abc");
    assert.deepStrictEqual(seen.body, { name: "grok-cli" });
  });
});

describe("GrokCliProvider.inspect / delete", () => {
  it("remote inspect uses API", async () => {
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

  it("remote delete uses API", async () => {
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

describe("GrokCliProvider.beforeAdd quota", () => {
  it("rejects over quota via QuotaError lifecycle", async () => {
    const services = {
      quota: {
        tryConsume: () => ({ allowed: false }),
      },
    };
    const p = makeProvider(makeConfig(), services);
    // BaseProvider converts QuotaError into a skip result.
    const result = await p.add(
      { email: "user@example.com", password: "pw" },
      {}
    );
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.skip, true);
    assert.ok(/Quota cap/i.test(result.reason));
  });

  it("allows under quota", async () => {
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
          expires_in: 60,
          interval: 0.001,
          codeVerifier: "cv",
        };
      }
      if (method === "POST") {
        return { success: true, connection: { id: "c" } };
      }
      return {};
    };
    p._runSignupWorker = async () => {};
    p.renameConnection = async () => ({});
    const result = await p.add(
      { email: "user@example.com", password: "pw" },
      {}
    );
    assert.strictEqual(result.ok, true);
  });
});
