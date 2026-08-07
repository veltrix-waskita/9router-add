#!/usr/bin/env node
/**
 * tmp/qoder-smoke.js — Qoder single-account E2E smoke (task 4, step 3/4).
 *
 * Drives the REAL provider integration end-to-end:
 *   provider.add() -> buildWorkerEnv (QODER_* keys) -> spawn worker/signup.py
 *   -> parse JSONL result -> connection {email, password, apiKey=PAT}.
 *
 * Env knobs (all optional):
 *   QODER_EMAIL_SOURCE  tempmail (default) | imap
 *   QODER_EMAIL          required in imap mode (e.g. tauvindpwtuba+frog@gmail.com)
 *   QODER_PASSWORD       worker password (auto-generated if unset)
 *   QODER_NAME           signup display name (default "Nexus")
 *   QODER_PROXY          optional proxy URL
 *   QODER_SIGNUP_URL     optional override
 *
 * Emits the provider result (pat/email) to stdout and, on success, writes
 * generated-accounts-qoder-<stamp>.json (mode 0600, gitignored).
 */
"use strict";

const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const ROOT = path.join(__dirname, "..");

function loadConfig() {
  const cfgPath = path.join(ROOT, "config.json");
  if (fs.existsSync(cfgPath)) {
    try {
      return JSON.parse(fs.readFileSync(cfgPath, "utf8"));
    } catch {
      /* fall through to minimal config */
    }
  }
  return { mode: "local", providers: { qoder: {} } };
}

function runPassword() {
  if (process.env.QODER_PASSWORD) return process.env.QODER_PASSWORD;
  return `Qoder${crypto.randomBytes(6).toString("base64").slice(0, 8)}!A1`;
}

async function main() {
  const config = loadConfig();
  const QoderProvider = require(path.join(ROOT, "src", "providers", "qoder", "index.js"));
  const provider = new QoderProvider(config, {}, {});

  const emailSource = (process.env.QODER_EMAIL_SOURCE || "tempmail")
    .trim()
    .toLowerCase();

  const email = process.env.QODER_EMAIL || "";
  const password = runPassword();
  const name = process.env.QODER_NAME || "Nexus";

  const options = { emailSource };
  if (process.env.QODER_PROXY) options.proxy = process.env.QODER_PROXY;
  if (process.env.QODER_SIGNUP_URL) options.signupUrl = process.env.QODER_SIGNUP_URL;

  // Hermetic success-path check: QODER_SMOKE_MOCK=1 feeds a real PAT-carrying
  // result through onEvent (no network, no subprocess) — verifies the
  // provider spawn+parse and the generated-accounts write end to end.
  if (process.env.QODER_SMOKE_MOCK === "1") {
    const { parseWorkerLine } = require(path.join(ROOT, "src", "providers", "qoder", "worker-bridge.js"));
    const mockEmail = emailSource === "tempmail" ? "mocked_alias@nca.my.id" : (email || "mocked@example.com");
    provider._spawnSignupWorker = async (workerDir, env, { onEvent }) => {
      onEvent(parseWorkerLine(
        JSON.stringify({ event: "step", step: "tempmail_create", status: "ok", address: mockEmail })
      ));
      onEvent(parseWorkerLine(
        JSON.stringify({ kind: "result", ok: true, step: "register2", email: mockEmail, pat: "pt-mocked-token", name })
      ));
    };
  }

  console.error(`[smoke] qoder emailSource=${emailSource} spawn one worker...`);
  const started = Date.now();

  const result = await provider.add({ email, password, name }, options);

  const conn = (result && result.connection) || {};
  const apiKey = (conn.data && conn.data.apiKey) || null;
  const elapsed = ((Date.now() - started) / 1000).toFixed(1);

  if (result.ok !== true || !apiKey) {
    console.error(`[smoke] provider add() did not yield a PAT (ok=${result.ok})`);
    process.exit(2);
  }

  const stamp = new Date()
    .toISOString()
    .replace(/[:.]/g, "-")
    .replace("T", "_")
    .slice(0, 19);
  const saveFile = path.join(ROOT, `generated-accounts-qoder-${stamp}.json`);
  const payload = {
    generatedAt: new Date().toISOString(),
    provider: "qoder",
    mode: emailSource,
    accounts: [
      {
        credentials: { email: conn.email, password, name },
        options,
        connection: {
          authType: "apikey",
          data: { apiKey, name },
        },
      },
    ],
  };
  fs.writeFileSync(saveFile, JSON.stringify(payload, null, 2) + "\n", {
    mode: 0o600,
  });

  console.log(
    JSON.stringify({
      ok: true,
      email: conn.email,
      pat: apiKey,
      elapsed_s: Number(elapsed),
      saved: saveFile,
    })
  );

  // Keep the raw save file content visible for review without printing secrets timing.
  console.error(`[smoke] DONE in ${elapsed}s -> ${saveFile}`);
}

main().catch((e) => {
  console.error(`[smoke] FAILED: ${e.message}`);
  process.exit(1);
});