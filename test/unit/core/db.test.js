"use strict";
const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");
const os = require("os");

function loadDbModule() {
  delete require.cache[require.resolve("../../../src/core/db")];
  return require("../../../src/core/db");
}

const tmpDir = path.join(os.tmpdir(), "9router-db-test-" + Date.now());
const dbPath = path.join(tmpDir, "data.sqlite");

describe("db", () => {
  before(() => {
    fs.mkdirSync(tmpDir, { recursive: true });
  });

  after(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("should insert a connection and return id", async () => {
    const { insert } = loadDbModule();
    const result = await insert(
      { dbPath },
      { provider: "test", authType: "oauth", name: "Test", email: "test@example.com", data: { foo: "bar" } }
    );
    assert.ok(result.id);
    assert.strictEqual(result.id.length, 36); // UUID
  });

  it("should find by id", async () => {
    const { insert, findById } = loadDbModule();
    const { id } = await insert(
      { dbPath },
      { provider: "test", authType: "oauth", name: "Find Me", email: "find@example.com" }
    );
    const found = await findById({ dbPath }, id);
    assert.ok(found);
    assert.strictEqual(found.name, "Find Me");
    assert.strictEqual(found.provider, "test");
  });

  it("should find by provider", async () => {
    const { findByProvider } = loadDbModule();
    const results = await findByProvider({ dbPath }, "test");
    assert.ok(Array.isArray(results));
    assert.ok(results.length >= 2);
  });

  it("should update data", async () => {
    const { insert, update, findById } = loadDbModule();
    const { id } = await insert(
      { dbPath },
      { provider: "test", authType: "oauth", name: "Update Test", email: "update@example.com" }
    );
    await update({ dbPath }, id, { newField: "value" });
    const found = await findById({ dbPath }, id);
    assert.strictEqual(found.data.newField, "value");
  });

  it("should delete by id", async () => {
    const { insert, del, findById } = loadDbModule();
    const { id } = await insert(
      { dbPath },
      { provider: "test", authType: "oauth", name: "Delete Me", email: "delete@example.com" }
    );
    await del({ dbPath }, id);
    const found = await findById({ dbPath }, id);
    assert.strictEqual(found, null);
  });
});
