"use strict";
const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");
const os = require("os");

function loadAuthModule() {
  delete require.cache[require.resolve("../../../src/core/auth")];
  return require("../../../src/core/auth");
}

// Shared fixture setup so both describe blocks can use the same machine-id file.
const tmpDir = path.join(os.tmpdir(), "9router-auth-test-" + Date.now());
const machineIdPath = path.join(tmpDir, "machine-id");

before(() => {
  fs.mkdirSync(tmpDir, { recursive: true });
  fs.writeFileSync(machineIdPath, "test-machine-id-123");
});

after(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("cliToken", () => {
  it("should produce a 16-char hex token", () => {
    const { cliToken } = loadAuthModule();
    const token = cliToken({
      machineIdPath,
      cliSecret: "my-secret",
    });
    assert.strictEqual(token.length, 16);
    assert.ok(/^[0-9a-f]+$/.test(token));
  });

  it("should produce consistent output for same inputs", () => {
    const { cliToken } = loadAuthModule();
    const a = cliToken({ machineIdPath, cliSecret: "my-secret" });
    const b = cliToken({ machineIdPath, cliSecret: "my-secret" });
    assert.strictEqual(a, b);
  });
});

describe("resolveAuthHeaders", () => {
  it("should return cli-token headers in local mode", async () => {
    const { resolveAuthHeaders } = loadAuthModule();
    // Use the shared machineIdPath fixture (file-level before hook creates it)
    const headers = await resolveAuthHeaders({
      mode: "local",
      cliSecret: "test",
      machineIdPath,
    });
    assert.ok(headers["X-9R-CLI-Auth"]);
    assert.strictEqual(headers["Content-Type"], "application/json");
  });

  it("should return session headers in remote mode", async () => {
    const { resolveAuthHeaders } = loadAuthModule();
    let loginCalled = false;
    const mockHttp = {
      request: async (cfg, opts) => {
        loginCalled = true;
        assert.strictEqual(opts.path, "/api/auth/login");
        assert.strictEqual(opts.method, "POST");
        assert.strictEqual(JSON.parse(opts.body).password, "test-pass");
        return {
          statusCode: 200,
          headers: { "set-cookie": "connect.sid=s%3Aabc123.xyz; Path=/; HttpOnly" },
          body: { ok: true },
        };
      },
    };
    const headers = await resolveAuthHeaders(
      { mode: "remote", host: "localhost", port: 3000, proto: "http", password: "test-pass" },
      mockHttp
    );
    assert.ok(loginCalled);
    assert.ok(headers["Cookie"]);
    assert.strictEqual(headers["Content-Type"], "application/json");
  });
});
