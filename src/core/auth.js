"use strict";

const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

function cliToken(config) {
  const homedir = require("os").homedir();
  const dataDir = (config.dataDir && config.dataDir.trim()) || ".omni";
  // Dashboard (azma-router) derives the CLI token as
  // sha256(machineId + "9r-cli-auth" + cliSecret) from its own data dir
  // (~/.omni) — machine-id + auth/cli-secret files, NOT config.cliSecret.
  // Try the configured dir, fall back to the legacy ~/.9router layout.
  const candidates = [
    path.join(homedir, dataDir),
    path.join(homedir, ".omni"),
    path.join(homedir, ".9router"),
  ];
  for (const dir of candidates) {
    try {
      const machineId = fs.readFileSync(path.join(dir, "machine-id"), "utf8").trim();
      const secretPath = path.join(dir, "auth", "cli-secret");
      let secret;
      try {
        secret = fs.readFileSync(secretPath, "utf8").trim();
      } catch {
        secret = config.cliSecret || "";
      }
      const hash = crypto
        .createHash("sha256")
        .update(machineId + "9r-cli-auth" + secret)
        .digest("hex");
      return hash.slice(0, 16);
    } catch {
      // try next candidate dir
    }
  }
  throw new Error("Cannot read machine-id / cli-secret (tried ~/.omni, ~/.9router)");
}

async function dashboardSession(config, httpClient) {
  const res = await httpClient.request(config, {
    method: "POST",
    path: "/api/auth/login",
    body: JSON.stringify({ password: config.password }),
    headers: { "Content-Type": "application/json" },
  });
  if (res.statusCode !== 200) {
    throw new Error(`Dashboard login failed: ${res.statusCode}`);
  }
  const setCookie = res.headers["set-cookie"];
  if (!setCookie) throw new Error("No session cookie returned");
  // Node.js returns set-cookie as an array (one entry per cookie); use first.
  const cookieRaw = Array.isArray(setCookie) ? setCookie[0] : setCookie;
  // Extract cookie value before semicolon
  const cookie = cookieRaw.split(";")[0].trim();
  return cookie;
}

async function resolveAuthHeaders(config, httpClient) {
  if (config.mode === "local") {
    const token = cliToken(config);
    return {
      "x-9r-cli-token": token,
      "Content-Type": "application/json",
    };
  }
  // Remote mode
  const cookie = await dashboardSession(config, httpClient);
  return {
    Cookie: cookie,
    "Content-Type": "application/json",
  };
}

module.exports = { cliToken, dashboardSession, resolveAuthHeaders };
