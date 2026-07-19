"use strict";

const { loadConfig } = require("./core/config");
const { resolveAuthHeaders } = require("./core/auth");
const { request } = require("./core/http-client");
const { loadProviders, run } = require("./core/cli");

async function main() {
  const config = loadConfig(process.argv.slice(2));
  const api = { request };
  const authHeaders = await resolveAuthHeaders(config, api);
  // Attach auth headers to every request
  const originalRequest = api.request;
  api.request = (cfg, opts) => {
    return originalRequest(cfg, {
      ...opts,
      headers: { ...authHeaders, ...opts.headers },
    });
  };

  const providers = loadProviders(config, api);
  await run(process.argv.slice(2), config, api, providers);
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
