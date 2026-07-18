"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");

const DEFAULTS = {
  host: "localhost",
  port: 3000,
  proto: "http",
  mode: "auto",
};

function isLocalHost(host) {
  if (!host) return false;
  const lower = host.toLowerCase();
  return lower === "localhost" || lower === "127.0.0.1" || lower === "::1" || lower === "0.0.0.0";
}

function resolveMode(cfg) {
  if (cfg.mode && cfg.mode !== "auto") return cfg.mode;
  const machineIdPath = path.join(os.homedir(), ".9router", "machine-id");
  const hasMachineId = fs.existsSync(machineIdPath);
  if (hasMachineId && isLocalHost(cfg.host)) return "local";
  return "remote";
}

function loadConfig(argv, opts = {}) {
  let cfg = { ...DEFAULTS };

  // 1. Config file
  const configPaths = [];
  if (opts.configPath) {
    configPaths.push(opts.configPath);
  } else {
    configPaths.push(path.join(process.cwd(), "config.json"));
    configPaths.push(path.join(os.homedir(), ".9router-add", "config.json"));
  }
  for (const cp of configPaths) {
    if (fs.existsSync(cp)) {
      try {
        const fileCfg = JSON.parse(fs.readFileSync(cp, "utf8"));
        cfg = { ...cfg, ...fileCfg };
        break;
      } catch (e) {
        console.warn(`[config] warning: ignoring invalid config file ${cp}: ${e.message}`);
      }
    }
  }

  // 2. Environment variables
  const envMap = {
    "9R_ADD_HOST": "host",
    "9R_ADD_PORT": "port",
    "9R_ADD_PROTO": "proto",
    "9R_ADD_PASSWORD": "password",
    "9R_ADD_CLI_SECRET": "cliSecret",
    "9R_ADD_MODE": "mode",
  };
  for (const [envKey, cfgKey] of Object.entries(envMap)) {
    if (process.env[envKey]) {
      cfg[cfgKey] = cfgKey === "port" ? Number(process.env[envKey]) : process.env[envKey];
    }
  }

  // 3. CLI flags (override anything)
  if (opts.mode) cfg.mode = opts.mode;
  if (opts.host) cfg.host = opts.host;
  if (opts.port) cfg.port = opts.port;
  if (opts.proto) cfg.proto = opts.proto;

  // 4. Resolve mode
  cfg.mode = resolveMode(cfg);

  // 5. Security guard
  if (cfg.mode === "remote" && cfg.proto === "http" && !isLocalHost(cfg.host)) {
    throw new Error(
      `Security: HTTPS required for remote mode (${cfg.host}). Set proto=https or use local mode.`
    );
  }

  // 6. Provider-specific config
  cfg.providerConfig = (cfg.providers && cfg.providers[cfg._provider]) || {};

  return cfg;
}

module.exports = { loadConfig, resolveMode, isLocalHost, DEFAULTS };
