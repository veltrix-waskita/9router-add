"use strict";
const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const fs = require("fs");
const os = require("os");

// Load module fresh each test by clearing require cache
function loadConfigModule() {
  delete require.cache[require.resolve("../../../src/core/config")];
  return require("../../../src/core/config");
}

describe("isLocalHost", () => {
  it("should return true for localhost", () => {
    const { isLocalHost } = loadConfigModule();
    assert.strictEqual(isLocalHost("localhost"), true);
    assert.strictEqual(isLocalHost("127.0.0.1"), true);
    assert.strictEqual(isLocalHost("::1"), true);
  });
  it("should return false for external hosts", () => {
    const { isLocalHost } = loadConfigModule();
    assert.strictEqual(isLocalHost("example.com"), false);
    assert.strictEqual(isLocalHost("192.168.1.1"), false);
  });
});

describe("resolveMode", () => {
  it("should return local when machine-id exists and host is localhost", () => {
    const { resolveMode } = loadConfigModule();
    const result = resolveMode({ host: "localhost", mode: "auto" });
    // machine-id check depends on ~/.9router/machine-id existence
    // We just test the logic: if host is localhost and mode is auto
    assert.strictEqual(result, "local");
  });
  it("should return remote when host is external", () => {
    const { resolveMode } = loadConfigModule();
    const result = resolveMode({ host: "vps.example.com", mode: "auto" });
    assert.strictEqual(result, "remote");
  });
  it("should return explicit mode as-is", () => {
    const { resolveMode } = loadConfigModule();
    assert.strictEqual(resolveMode({ host: "localhost", mode: "remote" }), "remote");
    assert.strictEqual(resolveMode({ host: "vps.example.com", mode: "local" }), "local");
  });
});

describe("loadConfig", () => {
  const origEnv = { ...process.env };
  const configDir = path.join(os.tmpdir(), "9router-add-test-" + Date.now());
  const configPath = path.join(configDir, "config.json");

  before(() => {
    fs.mkdirSync(configDir, { recursive: true });
    fs.writeFileSync(configPath, JSON.stringify({
      host: "custom.local",
      port: 4000,
      proto: "https",
    }));
  });

  after(() => {
    fs.rmSync(configDir, { recursive: true, force: true });
    // Restore env
    for (const k of Object.keys(process.env)) {
      if (k.startsWith("9R_ADD_")) delete process.env[k];
    }
  });

  it("should use defaults when no config or env", () => {
    const { loadConfig } = loadConfigModule();
    const cfg = loadConfig([], { secure: false }); // disable file lookup for this test
    assert.strictEqual(cfg.host, "localhost");
    assert.strictEqual(cfg.port, 3000);
    assert.strictEqual(cfg.proto, "http");
  });

  it("should read from config file", () => {
    const { loadConfig } = loadConfigModule();
    const cfg = loadConfig([], { configPath });
    assert.strictEqual(cfg.host, "custom.local");
    assert.strictEqual(cfg.port, 4000);
    assert.strictEqual(cfg.proto, "https");
  });

  it("should override with env vars", () => {
    process.env["9R_ADD_HOST"] = "env.host";
    process.env["9R_ADD_PORT"] = "5000";
    const { loadConfig } = loadConfigModule();
    const cfg = loadConfig([], { configPath });
    assert.strictEqual(cfg.host, "env.host");
    assert.strictEqual(cfg.port, 5000);
    delete process.env["9R_ADD_HOST"];
    delete process.env["9R_ADD_PORT"];
  });

  it("should throw on remote + http + non-localhost", () => {
    const { loadConfig } = loadConfigModule();
    assert.throws(() => {
      loadConfig([], {
        mode: "remote",
        host: "vps.example.com",
        proto: "http",
        secure: false,
      });
    }, /HTTPS required/i);
  });
});
