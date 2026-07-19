"use strict";
const { describe, it } = require("node:test");
const assert = require("node:assert");
const cf = require("../../../src/services/cloudflare-routing");

describe("generateAliases", () => {
  it("should generate requested count", () => {
    const aliases = cf.generateAliases("minom.my.id", 3);
    assert.strictEqual(aliases.length, 3);
  });
  it("should all have the domain", () => {
    const aliases = cf.generateAliases("test.com", 5);
    for (const a of aliases) {
      assert.ok(a.endsWith("@test.com"));
    }
  });
  it("should not produce duplicates in one batch", () => {
    const aliases = cf.generateAliases("test.com", 50);
    const unique = new Set(aliases);
    assert.strictEqual(unique.size, aliases.length);
  });
});

describe("randomLocalPart", () => {
  it("should return a non-empty string", () => {
    assert.ok(cf.randomLocalPart().length > 0);
  });
  it("should not contain @ symbol", () => {
    assert.ok(!cf.randomLocalPart().includes("@"));
  });
});
