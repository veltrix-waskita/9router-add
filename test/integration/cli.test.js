"use strict";
const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const http = require("http");
const fs = require("fs");
const path = require("path");
const os = require("os");

// Start a mock 9router API server for integration testing
const tmpDir = path.join(os.tmpdir(), "9router-int-test-" + Date.now());
const testConfig = {
  host: "localhost",
  port: 0, // random port
  proto: "http",
  mode: "remote",
  password: "test-password",
  machineIdPath: "/nonexistent",
};

describe("CLI Integration", () => {
  let server;
  let port;
  let loginCalled = false;
  let authorizeCalled = false;

  before(async () => {
    fs.mkdirSync(tmpDir, { recursive: true });

    // Create mock provider for testing
    const providerDir = path.join(__dirname, "..", "..", "src", "providers", "testint");
    fs.mkdirSync(providerDir, { recursive: true });
    fs.writeFileSync(
      path.join(providerDir, "index.js"),
      `
      "use strict";
      const { BaseProvider } = require("../../base/provider");
      class TestIntProvider extends BaseProvider {
        static get providerName() { return "testint"; }
        async add(creds, opts) {
          return { ok: true, email: creds.email, provider: "testint" };
        }
      }
      module.exports = TestIntProvider;
      `
    );

    // Start mock API server
    server = http.createServer((req, res) => {
      if (req.url === "/api/auth/login" && req.method === "POST") {
        loginCalled = true;
        res.writeHead(200, {
          "Content-Type": "application/json",
          "Set-Cookie": "connect.sid=s%3Atest.xyz; Path=/; HttpOnly",
        });
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true, path: req.url }));
    });
    await new Promise((r) => server.listen(0, r));
    port = server.address().port;
  });

  after(() => {
    server.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
    // Clean up mock provider
    const providerDir = path.join(__dirname, "..", "..", "src", "providers", "testint");
    try { fs.rmSync(providerDir, { recursive: true, force: true }); } catch {}
  });

  it("should load providers and dispatch add command", async () => {
    const { loadProviders, loadServices, run } = require("../../src/core/cli");
    const { request } = require("../../src/core/http-client");
    const { resolveAuthHeaders } = require("../../src/core/auth");

    const config = { ...testConfig, port };
    const api = { request };
    const authHeaders = await resolveAuthHeaders(config, api);
    api.request = (cfg, opts) => request(cfg, { ...opts, headers: { ...authHeaders, ...opts.headers } });

    const providers = loadProviders(config, api);
    assert.ok(providers.testint);

    // Capture stdout
    const logs = [];
    const origLog = console.log;
    console.log = (msg) => logs.push(msg);

    await run(["add", "testint", "--email=int@test.com"], config, api, providers);

    console.log = origLog;
    const output = logs.join(" ");
    assert.ok(output.includes("ok"));
    assert.ok(loginCalled, "Dashboard login should be called");
  });
});
