#!/usr/bin/env node
"use strict";
/**
 * Direct smoke test: kiro provider via tempmail + pure-HTTP.
 * Avoids TUI/readline of runner.js.
 */
const path = require("path");
const { loadConfig } = require("../src/core/config");
const { resolveAuthHeaders } = require("../src/core/auth");
const { request } = require("../src/core/http-client");

async function main() {
  const config = loadConfig([
    "--provider", "kiro",
    "--count", "1",
    "--emailSource", "tempmail",
    "--mode", "local",
  ]);

  console.log(`[smoke] Config: ${config.host}:${config.port} (${config.mode})`);

  // Resolve auth and inject into config.headers used by api.request
  const httpClient = { request };
  const authHeaders = await resolveAuthHeaders(config, httpClient);
  // The provider's _apiCall uses this.api.request(this.config, ...) — the
  // config object is passed through to the raw request() which reads
  // config.host, config.port, and opts.headers. We need default headers
  // on every outgoing call, so merge auth into config.authHeader and wrap
  // the api.request call.
  const authReq = (method, path, body) => {
    const bodyStr = body ? JSON.stringify(body) : undefined;
    return request(config, {
      method,
      path,
      body: bodyStr,
      headers: bodyStr
        ? { ...authHeaders, "Content-Type": "application/json" }
        : authHeaders,
    });
  };

  // Get device code
  const deviceRes = await authReq("GET", "/api/oauth/kiro/device-code");
  if (deviceRes.statusCode >= 400) {
    throw new Error(`Device-code HTTP ${deviceRes.statusCode}: ${JSON.stringify(deviceRes.body).slice(0, 200)}`);
  }
  const deviceData = deviceRes.body;
  console.log(`[smoke] Device code received (len=${deviceData.user_code?.length || "?"})`);

  // Import and instantiate KiroProvider — override apiCall to inject auth headers
  const KiroProvider = require("../src/providers/kiro");
  const provider = new KiroProvider(config, httpClient, {});
  // Patch _apiCall to use our authenticated wrapper
  provider._apiCall = async (method, path, body) => {
    const res = await authReq(method, path, body);
    if (res.statusCode >= 400) {
      const errBody = typeof res.body === "object" ? JSON.stringify(res.body).slice(0, 200) : String(res.body).slice(0, 200);
      throw new Error(`HTTP ${res.statusCode} from ${path}: ${errBody}`);
    }
    return res.body;
  };

  // Add account via tempmail
  // (Worker progress is logged to stdout by _runSignupWorker internally)
  console.log("[smoke] Starting add(credentials, { emailSource: 'tempmail' })...");
  const result = await provider.add(
    {},
    { emailSource: "tempmail", deviceData, proxy: null }
  );

  console.log("[smoke] Result:", JSON.stringify(result, null, 2));
  process.exit(0);
}

main().catch((err) => {
  console.error("[smoke] ERROR:", err.message);
  if (err.stack) console.error(err.stack.split("\n").slice(1, 4).join("\n"));
  process.exit(1);
});
