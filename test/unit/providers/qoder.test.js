"use strict";

const test = require("node:test");
const assert = require("node:assert");
const QoderProvider = require("../../../src/providers/qoder/index.js");

test("qoder provider registers name + endpoints", () => {
  const p = new QoderProvider({ mode: "local" }, {}, {});
  assert.strictEqual(QoderProvider.providerName, "qoder");
  assert.ok(p.add && typeof p.add === "function");
});