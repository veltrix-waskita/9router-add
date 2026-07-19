"use strict";
const { describe, it } = require("node:test");
const assert = require("node:assert");
const { generateFingerprint } = require("../../../src/services/fingerprint");

describe("generateFingerprint", () => {
  it("should return an object with all expected keys", () => {
    const fp = generateFingerprint();
    assert.ok(fp.userAgent);
    assert.ok(fp.viewport);
    assert.ok(fp.viewport.width);
    assert.ok(fp.viewport.height);
    assert.ok(fp.locale);
    assert.ok(fp.timezoneId);
    assert.ok(fp.hardwareConcurrency);
    assert.ok(fp.deviceMemory);
    assert.ok(fp.languages);
  });
  it("should be deterministic with seed", () => {
    const a = generateFingerprint(42);
    const b = generateFingerprint(42);
    assert.deepStrictEqual(a, b);
  });
  it("should produce different results for different seeds", () => {
    const a = generateFingerprint(1);
    const b = generateFingerprint(2);
    assert.notDeepStrictEqual(a, b);
  });
});
