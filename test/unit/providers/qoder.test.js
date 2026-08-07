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

test("buildWorkerEnv imap mode wires config.imap into QODER_IMAP_* keys", () => {
  const env = buildWorkerEnv({
    credentials: { email: "you+tag@gmail.com", password: "pw", name: "Sam" },
    config: {
      providers: { qoder: { otpSubject: "Qoder code" } },
      providerConfig: {},
      imap: {
        host: "imap.gmail.com",
        port: 993,
        user: "tauvindpwtuba@gmail.com",
        password: "app-pw",
        tls: true,
        deleteAfterRead: true,
      },
    },
    options: { emailSource: "imap" },
  });
  assert.strictEqual(env.QODER_EMAIL_SOURCE, "imap");
  assert.strictEqual(env.QODER_IMAP_HOST, "imap.gmail.com");
  assert.strictEqual(env.QODER_IMAP_PORT, "993");
  assert.strictEqual(env.QODER_IMAP_USER, "tauvindpwtuba@gmail.com");
  assert.strictEqual(env.QODER_IMAP_PASSWORD, "app-pw");
  assert.strictEqual(env.QODER_IMAP_TLS, "true");
  assert.strictEqual(env.QODER_IMAP_DELETE_AFTER_READ, "true");
  assert.strictEqual(env.QODER_OTP_SUBJECT, "Qoder code");
  assert.ok(env.QODER_OTP_SENDER_DOMAIN.includes("qoder.com"));
});

test("buildWorkerEnv tempmail mode does not require QODER_IMAP_* keys", () => {
  const env = buildWorkerEnv({
    credentials: { email: "", password: "pw", name: "Sam" },
    config: { providers: { qoder: {} }, providerConfig: {}, imap: {} },
    options: { emailSource: "tempmail" },
  });
  assert.strictEqual(env.QODER_EMAIL_SOURCE, "tempmail");
  assert.strictEqual(env.QODER_IMAP_USER, undefined);
  assert.strictEqual(env.QODER_IMAP_PASSWORD, undefined);
  assert.strictEqual(env.QODER_IMAP_HOST, undefined);
});

test("parseWorkerLine classifies worker step lines as events (not debug)", () => {
  // Worker emits {"event":"step",...} (kiro convention). Tempmail address
  // capture in add() depends on these reaching the provider as events.
  const parsed = parseWorkerLine(
    JSON.stringify({ event: "step", step: "tempmail_create", status: "ok", address: "iron@nca.my.id" })
  );
  assert.strictEqual(parsed.kind, "event");
  assert.strictEqual(parsed.event, "step");
  assert.strictEqual(parsed.payload.step, "tempmail_create");
  assert.strictEqual(parsed.payload.address, "iron@nca.my.id");
});

test("add() captures the worker's tempmail address for the connection email", async () => {
  const p = new QoderProvider({ mode: "local" }, {}, {});
  // Worker first reports the real temp-mail address, then the final PAT result.
  p._spawnSignupWorker = async (workerDir, env, { onEvent }) => {
    onEvent(parseWorkerLine(
      JSON.stringify({ event: "step", step: "tempmail_create", status: "ok", address: "iron@nca.my.id" })
    ));
    onEvent(parseWorkerLine(
      JSON.stringify({ kind: "result", ok: true, step: "register2", email: "iron@nca.my.id", pat: "pt-x", name: "Nexus" })
    ));
  };
  const origLog = console.log;
  console.log = () => {};
  try {
    const result = await p.add(
      { email: "tempmail@pending.local", password: "pw" },
      { emailSource: "tempmail" }
    );
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.connection.email, "iron@nca.my.id");
    assert.strictEqual(result.connection.data.apiKey, "pt-x");
  } finally {
    console.log = origLog;
  }
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

test("add() never logs the PAT; result payload still reaches the provider", async () => {
  const p = new QoderProvider({ mode: "local" }, {}, {});
  const SECRET_PAT = "pt-super-secret-123";
  // DI seam: fake the worker spawn, feed a real PAT-carrying result line to onEvent.
  p._spawnSignupWorker = async (workerDir, env, { onEvent }) => {
    onEvent(parseWorkerLine(
      JSON.stringify({ kind: "result", ok: true, step: "register2", pat: SECRET_PAT, email: "a@b" })
    ));
  };

  const logs = [];
  const origLog = console.log;
  console.log = (...args) => logs.push(args.join(" "));
  try {
    const result = await p.add({ email: "a@b.com", password: "pw" }, {});
    // Provider receives the PAT internally.
    assert.strictEqual(result.ok, true);
    assert.strictEqual(result.connection.data.apiKey, SECRET_PAT);
  } finally {
    console.log = origLog;
  }

  const all = logs.join("\n");
  assert.ok(!all.includes(SECRET_PAT), "PAT leaked to console.log");
  assert.ok(!all.includes("super-secret"), "PAT substring leaked to console.log");
});
test("afterAdd appends PAT-only + full-account sidecar files", async () => {
  const os = require("os");
  const path = require("path");
  const fs = require("fs");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "qoder-pats-"));
  const p = new QoderProvider({ mode: "local", accountsDir: dir }, {}, {});
  const result = {
    ok: true,
    connection: {
      provider: "qoder",
      email: "qodertest@minom.my.id",
      password: "pw",
      authType: "apikey",
      data: { apiKey: "pt-abc-123", name: "Sam Lane" },
    },
  };
  await p.afterAdd(result);
  await p.afterAdd(result);
  await p.afterAdd({ ok: true, connection: { data: { apiKey: "pt-other" } } });

  const pats = fs.readFileSync(path.join(dir, "qoder-pats.txt"), "utf8");
  assert.strictEqual(pats, "pt-abc-123\npt-abc-123\npt-other\n");
  const accounts = fs.readFileSync(path.join(dir, "qoder-accounts.txt"), "utf8");
  assert.ok(accounts.includes("qodertest@minom.my.id | Sam Lane | pt-abc-123"));
  // Never the password.
  assert.ok(!accounts.includes("pw"));
  assert.ok(!pats.includes("pw"));
});

test("afterAdd skips sidecar write when result has no PAT", async () => {
  const os = require("os");
  const path = require("path");
  const fs = require("fs");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "qoder-pats-"));
  const p = new QoderProvider({ mode: "local", accountsDir: dir }, {}, {});
  await p.afterAdd({ ok: false, error: "boom" });
  await p.afterAdd({ ok: true, connection: { data: {} } });
  await p.afterAdd();
  assert.ok(!fs.existsSync(path.join(dir, "qoder-pats.txt")));
  assert.ok(!fs.existsSync(path.join(dir, "qoder-accounts.txt")));
});
