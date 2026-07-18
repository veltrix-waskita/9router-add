"use strict";

const crypto = require("crypto");
const fs = require("fs");

function cliToken(config) {
  const machineIdPath = config.machineIdPath || require("path").join(require("os").homedir(), ".9router", "machine-id");
  let machineId;
  try {
    machineId = fs.readFileSync(machineIdPath, "utf8").trim();
  } catch {
    throw new Error(`Cannot read machine-id from ${machineIdPath}`);
  }
  const hash = crypto.createHash("sha256").update(machineId + "9r-cli-auth" + config.cliSecret).digest("hex");
  return hash.slice(0, 16);
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
  // Extract cookie value before semicolon
  const cookie = setCookie.split(";")[0].trim();
  return cookie;
}

async function resolveAuthHeaders(config, httpClient) {
  if (config.mode === "local") {
    const token = cliToken(config);
    return {
      "X-9R-CLI-Auth": token,
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
