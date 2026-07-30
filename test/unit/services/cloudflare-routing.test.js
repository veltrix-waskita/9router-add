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

describe("randomTag", () => {
  it("should default to 12 chars of lowercase a-z0-9", () => {
    const tag = cf.randomTag();
    assert.strictEqual(tag.length, 12);
    assert.match(tag, /^[a-z0-9]{12}$/);
  });
  it("should honor a custom length", () => {
    assert.strictEqual(cf.randomTag(6).length, 6);
    assert.match(cf.randomTag(6), /^[a-z0-9]{6}$/);
  });
});

describe("generateAliases plus-mode (full address argument)", () => {
  it("should emit base+tag@host when given a full gmail address", () => {
    const aliases = cf.generateAliases("tauvindpwtuba@gmail.com", 4);
    assert.strictEqual(aliases.length, 4);
    for (const a of aliases) {
      assert.match(a, /^tauvindpwtuba\+[a-z0-9]{12}@gmail\.com$/);
    }
  });
  it("should not produce duplicate tags in one batch", () => {
    const aliases = cf.generateAliases("base@gmail.com", 50);
    assert.strictEqual(new Set(aliases).size, 50);
  });
});
