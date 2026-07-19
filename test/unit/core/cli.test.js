"use strict";
const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");
const os = require("os");

function loadCli() {
  delete require.cache[require.resolve("../../../src/core/cli")];
  return require("../../../src/core/cli");
}

describe("parseArgs", () => {
  it("should parse --key=value", () => {
    const { parseArgs } = loadCli();
    const args = parseArgs(["add", "test", "--email=foo@bar.com", "--password=secret"]);
    assert.strictEqual(args._[0], "add");
    assert.strictEqual(args._[1], "test");
    assert.strictEqual(args.email, "foo@bar.com");
    assert.strictEqual(args.password, "secret");
  });
  it("should parse --flag without value", () => {
    const { parseArgs } = loadCli();
    const args = parseArgs(["add", "test", "--dry-run"]);
    assert.strictEqual(args["dry-run"], true);
  });
  it("should parse --key value (space separated)", () => {
    const { parseArgs } = loadCli();
    const args = parseArgs(["add", "test", "--email", "foo@bar.com"]);
    assert.strictEqual(args.email, "foo@bar.com");
  });
});

describe("loadServices", () => {
  it("should return all services", () => {
    const { loadServices } = loadCli();
    const svc = loadServices({});
    assert.ok(svc.fingerprint);
    assert.ok(svc.cfRouting);
  });
  it("should load imap only when config has imap", () => {
    const { loadServices } = loadCli();
    const svc = loadServices({ imap: { user: "x", password: "y" } });
    assert.ok(svc.imap);
  });
  it("should load proxy only when config has proxyFile", () => {
    const { loadServices } = loadCli();
    const svc = loadServices({ proxyFile: "/tmp/proxies.txt" });
    assert.ok(svc.proxy);
  });
});
