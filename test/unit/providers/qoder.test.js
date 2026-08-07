"use strict";

const test = require("node:test");
const assert = require("node:assert");
const QoderProvider = require("../../../src/providers/qoder/index.js");
const {
  buildWorkerEnv,
  parseWorkerLine,
} = require("../../../src/providers/qoder/worker-bridge.js");

test("qoder provider registers name + endpoints", () => {
  const p = new QoderProvider({ mode: "local" }, {}, {});
  assert.strictEqual(QoderProvider.providerName, "qoder");
  assert.ok(p.add && typeof p.add === "function");
});

test("parseWorkerLine keeps result payload (pat/email survive round-trip)", () => {
  const parsed = parseWorkerLine(
    JSON.stringify({ kind: "result", ok: true, step: "register2", pat: "pt-x", email: "a@b" })
  );
  assert.strictEqual(parsed.kind, "result");
  assert.strictEqual(parsed.ok, true);
  assert.strictEqual(parsed.step, "register2");
  assert.ok(parsed.payload, "result line must carry the full payload for the provider");
  assert.strictEqual(parsed.payload.pat, "pt-x");
  assert.strictEqual(parsed.payload.email, "a@b");
});

test("buildWorkerEnv emits QODER_* keys for the worker os.getenv", () => {
  const env = buildWorkerEnv({
    credentials: { email: "a@b.com", password: "pw", name: "Sam" },
    config: { providers: { qoder: {} }, providerConfig: {} },
    options: {},
  });
  assert.strictEqual(env.QODER_EMAIL, "a@b.com");
  assert.strictEqual(env.QODER_PASSWORD, "pw");
  assert.strictEqual(env.QODER_NAME, "Sam");
  assert.strictEqual(env.QODER_EMAIL_SOURCE, "tempmail");
  assert.ok(env.QODER_SIGNUP_URL.includes("qoder.com"));
  assert.strictEqual(env.PURE_HTTP, "1");
});