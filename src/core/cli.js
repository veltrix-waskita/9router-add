"use strict";

const fs = require("fs");
const path = require("path");

const PROVIDERS_DIR = path.join(__dirname, "..", "providers");

/**
 * Parse a CLI argv array into a simple object with positional `_` array and
 * `--key=value` / `--key value` / `--flag` properties.
 *
 * @param {string[]} argv - argv tokens (e.g. process.argv.slice(2))
 * @returns {{ _: string[] } & Record<string, string | boolean>} parsed args
 */
function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith("--")) {
      const eq = argv[i].indexOf("=");
      if (eq !== -1) {
        args[argv[i].slice(2, eq)] = argv[i].slice(eq + 1);
      } else {
        const next = argv[i + 1];
        if (next && !next.startsWith("--")) {
          args[argv[i].slice(2)] = next;
          i++;
        } else {
          args[argv[i].slice(2)] = true;
        }
      }
    } else {
      args._.push(argv[i]);
    }
  }
  return args;
}

/**
 * Auto-discover provider classes under `src/providers/<name>/index.js`.
 * Each module must export a class with a static `providerName`.
 *
 * @param {object} config - merged config (unused here, kept for API parity)
 * @param {object} api - shared API client (unused here, kept for API parity)
 * @returns {Record<string, Function>} map of providerName -> ProviderClass
 */
function loadProviders(config, api) {
  const providers = {};
  let entries;
  try {
    entries = fs.readdirSync(PROVIDERS_DIR, { withFileTypes: true });
  } catch {
    return providers;
  }
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const indexPath = path.join(PROVIDERS_DIR, entry.name, "index.js");
    if (!fs.existsSync(indexPath)) continue;
    try {
      const ProviderClass = require(indexPath);
      const name = ProviderClass.providerName;
      if (name) providers[name] = ProviderClass;
    } catch (e) {
      console.warn(`[cli] warning: failed to load provider ${entry.name}: ${e.message}`);
    }
  }
  return providers;
}

/**
 * Lazily assemble a services bag based on config flags. Services are only
 * required when their config keys are present, so unused services do not
 * incur import cost.
 *
 * @param {object} config - merged config; recognized keys:
 *   - `imap` — IMAP credentials object enables the imap-otp service
 *   - `proxyFile` — path to proxy list enables the proxy service
 *   - `quotaFile` — quota file path enables the quota service
 * @returns {{ imap?: object, proxy?: object, fingerprint: object, quota?: object, cfRouting: object }} services bag
 */
function loadServices(config) {
  const services = {};

  if (config.imap) {
    services.imap = require("../services/imap-otp");
  }
  if (config.proxyFile) {
    const proxy = require("../services/proxy");
    services.proxy = {
      loadProxies: () => proxy.loadProxies(config.proxyFile),
      getProxyForAccount: proxy.getProxyForAccount,
      chromiumArgsForProxy: proxy.chromiumArgsForProxy,
    };
  }
  services.fingerprint = require("../services/fingerprint");
  if (config.quotaFile) {
    services.quota = require("../services/quota");
  }
  services.cfRouting = require("../services/cloudflare-routing");

  return services;
}

/**
 * Dispatch a CLI invocation: parse argv, resolve the requested provider,
 * and run one of: add / inspect / delete / list / batch.
 *
 * @param {string[]} argv - argv tokens (e.g. process.argv.slice(2))
 * @param {object} config - merged config
 * @param {object} api - shared API client
 * @param {Record<string, Function>} providers - provider map from loadProviders
 * @returns {Promise<void>} resolves after the command completes or prints help
 */
async function run(argv, config, api, providers) {
  const args = parseArgs(argv);
  const command = args._[0];
  const providerName = args._[1];

  if (!command) {
    console.log("Usage: node . <command> <provider> [options]");
    console.log("Commands: add, inspect, delete, list, batch");
    console.log("Providers:", Object.keys(providers).join(", "));
    return;
  }

  if (command === "list") {
    const { findByProvider } = require("./db");
    const targetProvider = providerName;
    if (targetProvider) {
      const rows = await findByProvider(config, targetProvider);
      console.log(JSON.stringify(rows, null, 2));
    } else {
      // List all providers
      for (const name of Object.keys(providers)) {
        const rows = await findByProvider(config, name);
        if (rows.length > 0) {
          console.log(`\n--- ${name} (${rows.length}) ---`);
          console.log(JSON.stringify(rows, null, 2));
        }
      }
    }
    return;
  }

  if (!providerName || !providers[providerName]) {
    console.error(`Unknown provider: ${providerName}`);
    console.error("Available:", Object.keys(providers).join(", "));
    process.exit(1);
  }

  const Provider = providers[providerName];
  const services = loadServices(config);
  config._provider = providerName;
  const finalConfig = { ...config, providerConfig: (config.providers && config.providers[providerName]) || {} };
  const provider = new Provider(finalConfig, api, services);

  switch (command) {
    case "add": {
      const credentials = { email: args.email, password: args.password, name: args.name };
      const options = { proxy: args.proxy, dryRun: args["dry-run"] === true };
      const result = await provider.add(credentials, options);
      console.log(JSON.stringify(result, null, 2));
      break;
    }
    case "inspect": {
      const id = args._[2];
      if (!id) { console.error("Usage: node . inspect <provider> <id>"); process.exit(1); }
      const result = await provider.inspect(id);
      console.log(JSON.stringify(result, null, 2));
      break;
    }
    case "delete": {
      const id = args._[2];
      if (!id) { console.error("Usage: node . delete <provider> <id>"); process.exit(1); }
      await provider.delete(id);
      console.log("Deleted.");
      break;
    }
    case "batch": {
      const batchFile = args._[2] || args.file;
      if (!batchFile) { console.error("Usage: node . batch <file.json>"); process.exit(1); }
      const batch = JSON.parse(fs.readFileSync(batchFile, "utf8"));
      const accounts = batch.accounts || [];
      for (let i = 0; i < accounts.length; i++) {
        const acct = accounts[i];
        const p = new Provider(finalConfig, api, loadServices(config));
        try {
          const r = await p.add(acct.credentials || {}, acct.options || {});
          console.log(`[${i + 1}/${accounts.length}] ${r.ok ? "OK" : "FAIL"}: ${JSON.stringify(r)}`);
        } catch (e) {
          console.error(`[${i + 1}/${accounts.length}] ERROR: ${e.message}`);
        }
      }
      break;
    }
    default:
      console.error(`Unknown command: ${command}`);
      process.exit(1);
  }
}

module.exports = { parseArgs, loadProviders, loadServices, run };
