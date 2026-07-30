"use strict";

const { describe, it } = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");
const os = require("os");

const {
  randomPassword,
  randomName,
  resolveAliasDomain,
  generateAccounts,
} = require("../../../src/services/credentials");

describe("randomPassword", () => {
  it("has upper, lower, digit, special", () => {
    const pw = randomPassword();
    assert.ok(pw.length >= 12);
    assert.match(pw, /[A-Z]/);
    assert.match(pw, /[a-z]/);
    assert.match(pw, /[0-9]/);
    assert.match(pw, /[!@#$%^&*_+=\-]/);
  });
});

describe("randomName", () => {
  it("returns first + last", () => {
    const n = randomName();
    assert.match(n, /^\S+ \S+$/);
  });
});

describe("resolveAliasDomain", () => {
  it("reads providers.<name>.aliasDomain", () => {
    const d = resolveAliasDomain(
      { providers: { "grok-cli": { aliasDomain: "minom.my.id" } } },
      "grok-cli"
    );
    assert.strictEqual(d, "minom.my.id");
  });

  it("returns null when missing", () => {
    assert.strictEqual(resolveAliasDomain({}, "grok-cli"), null);
  });
});

describe("generateAccounts", () => {
  it("builds N accounts and saves file", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cred-"));
    const saveFile = path.join(dir, "out.json");
    const aliasFile = path.join(dir, "aliases.txt");
    const { accounts, domain } = generateAccounts({
      config: { providers: { "grok-cli": { aliasDomain: "example.test" } } },
      providerName: "grok-cli",
      count: 3,
      saveFile,
      aliasFile,
    });
    assert.strictEqual(domain, "example.test");
    assert.strictEqual(accounts.length, 3);
    for (const a of accounts) {
      assert.match(a.credentials.email, /@example\.test$/);
      assert.ok(a.credentials.password.length >= 12);
      assert.ok(a.credentials.name.includes(" "));
    }
    const saved = JSON.parse(fs.readFileSync(saveFile, "utf8"));
    assert.strictEqual(saved.accounts.length, 3);
    const ledger = fs.readFileSync(aliasFile, "utf8").trim().split("\n");
    assert.strictEqual(ledger.length, 3);
  });

  it("plus-mode: full gmail aliasDomain emits base+tag@gmail.com", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "cred-"));
    const saveFile = path.join(dir, "out.json");
    const aliasFile = path.join(dir, "aliases.txt");
    const { accounts, domain } = generateAccounts({
      config: { providers: { kiro: { aliasDomain: "base@gmail.com" } } },
      providerName: "kiro",
      count: 3,
      saveFile,
      aliasFile,
    });
    assert.strictEqual(domain, "base@gmail.com");
    assert.strictEqual(accounts.length, 3);
    for (const a of accounts) {
      assert.match(a.credentials.email, /^base\+[a-z0-9]{12}@gmail\.com$/);
    }
    const ledger = fs.readFileSync(aliasFile, "utf8").trim().split("\n");
    assert.strictEqual(ledger.length, 3);
  });

  it("throws without aliasDomain", () => {
    assert.throws(
      () =>
        generateAccounts({
          config: {},
          providerName: "grok-cli",
          count: 1,
        }),
      /aliasDomain/
    );
  });
});
