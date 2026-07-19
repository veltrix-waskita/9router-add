"use strict";
const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");
const os = require("os");
const quota = require("../../../src/services/quota");

const tmpFile = path.join(os.tmpdir(), "quota-test-" + Date.now() + ".json");

describe("quota", () => {
  after(() => {
    try { fs.unlinkSync(tmpFile); } catch {}
  });

  it("should allow when under cap", () => {
    const { allowed } = quota.tryConsume(tmpFile, "test@example.com", 5);
    assert.strictEqual(allowed, true);
  });
  it("should block when over cap", () => {
    // Use up all quota
    for (let i = 0; i < 5; i++) {
      quota.tryConsume(tmpFile, "test@example.com", 5);
    }
    const { allowed } = quota.tryConsume(tmpFile, "test@example.com", 5);
    assert.strictEqual(allowed, false);
  });
  it("should track per-domain separately", () => {
    const { allowed: a1 } = quota.tryConsume(tmpFile, "other@different.com", 5);
    assert.strictEqual(a1, true);
  });
  it("should prune old entries", () => {
    const stats = { "2020-01-01": { "old.com": 5 }, "2099-01-01": { "new.com": 3 } };
    const pruned = quota.pruneOld(stats, 30);
    assert.ok(!pruned["2020-01-01"]);
    assert.ok(pruned["2099-01-01"]);
  });
});
