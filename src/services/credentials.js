"use strict";

/**
 * Auto-generate account credentials for email-method providers
 * (grok-cli, kiro email). Uses Cloudflare catch-all aliases on a
 * user-owned domain + strong random password + realistic name.
 *
 * Prerequisites:
 *   - aliasDomain in provider config (e.g. minom.my.id)
 *   - CF Email Routing catch-all → IMAP Gmail
 *   - IMAP credentials in config (OTP delivery)
 */

const crypto = require("crypto");
const path = require("path");
const fs = require("fs");
const {
  generateAliases,
  appendAliasesToFile,
} = require("./cloudflare-routing");

const FIRST = [
  "Alex", "Jordan", "Taylor", "Morgan", "Casey", "Riley", "Sam", "Jamie",
  "Drew", "Quinn", "Avery", "Cameron", "Harper", "Logan", "Parker", "Reese",
];
const LAST = [
  "Rivera", "Bennett", "Carter", "Reyes", "Ellis", "Novak", "Frost", "Hale",
  "Brooks", "Lane", "Walsh", "Chen", "Patel", "Nguyen", "Kim", "Garcia",
];

/**
 * Strong-enough password for xAI / AWS signup forms.
 * Guarantees upper, lower, digit, special; ~16 chars.
 * @returns {string}
 */
function randomPassword() {
  const raw = crypto.randomBytes(12).toString("base64url"); // url-safe, mixed
  // Force character classes so validation rules never reject us.
  return `Gx${raw.slice(0, 10)}!A9`;
}

/**
 * Realistic display name.
 * @returns {string}
 */
function randomName() {
  const first = FIRST[Math.floor(Math.random() * FIRST.length)];
  const last = LAST[Math.floor(Math.random() * LAST.length)];
  return `${first} ${last}`;
}

/**
 * Resolve alias domain from config for a provider.
 * @param {object} config
 * @param {string} providerName
 * @returns {string|null}
 */
function resolveAliasDomain(config, providerName) {
  const fromProvider =
    config &&
    config.providers &&
    config.providers[providerName] &&
    config.providers[providerName].aliasDomain;
  const fromCfg = config && config.providerConfig && config.providerConfig.aliasDomain;
  const fromTop = config && config.aliasDomain;
  return fromProvider || fromCfg || fromTop || null;
}

/**
 * Generate N credential sets for email-method signup.
 *
 * @param {object} opts
 * @param {object} opts.config - full app config
 * @param {string} opts.providerName - e.g. "grok-cli"
 * @param {number} [opts.count=1]
 * @param {string} [opts.aliasFile] - optional path to append aliases (default aliases.txt)
 * @param {string} [opts.saveFile] - optional path to persist full credentials JSON
 * @param {string} [opts.proxy] - optional proxy URL applied to every account
 * @returns {{ accounts: Array<{credentials: object, options: object}>, domain: string }}
 */
function generateAccounts({
  config,
  providerName,
  count = 1,
  aliasFile,
  saveFile,
  proxy,
} = {}) {
  const domain = resolveAliasDomain(config, providerName);
  if (!domain) {
    throw new Error(
      `Auto-credentials need providers.${providerName}.aliasDomain in config.json ` +
        `(e.g. "minom.my.id" with CF Email Routing catch-all).`
    );
  }
  const n = Math.max(1, Math.min(Number(count) || 1, 500));
  const emails = generateAliases(domain, n);

  // Track aliases for later audit (gitignored ideally).
  const aliasPath =
    aliasFile ||
    path.join(process.cwd(), "aliases.txt");
  try {
    appendAliasesToFile(aliasPath, emails);
  } catch (e) {
    // Non-fatal — generation still works without the ledger.
    console.warn(`[credentials] could not append aliases.txt: ${e.message}`);
  }

  const accounts = emails.map((email) => {
    const credentials = {
      email,
      password: randomPassword(),
      name: randomName(),
    };
    const options = {};
    if (proxy) options.proxy = proxy;
    return { credentials, options };
  });

  if (saveFile) {
    const payload = {
      generatedAt: new Date().toISOString(),
      provider: providerName,
      domain,
      accounts,
    };
    fs.writeFileSync(saveFile, JSON.stringify(payload, null, 2) + "\n", {
      mode: 0o600,
    });
  }

  return { accounts, domain, aliasPath };
}

module.exports = {
  randomPassword,
  randomName,
  resolveAliasDomain,
  generateAccounts,
};
