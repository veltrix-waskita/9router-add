"use strict";

// Cloudflare Email Routing helpers — generate aliases on a domain the user
// controls (e.g. minom.my.id). All aliases auto-forward to the destination
// Gmail via a catch-all rule configured once in the Cloudflare dashboard.
//
// Why CF Email Routing > third-party forwarder:
// - User-owned domain → AWS will never blocklist it (no disposable-email
//   signal that can be pushed to the AWS blocklist).
// - Unlimited aliases; CF free tier is sufficient (200+ destinations, unlimited rules).
// - No signup / API to any other provider.
//
// Prerequisites (one-time setup, in the Cloudflare dashboard):
// 1. Domain minom.my.id must already be on Cloudflare DNS.
// 2. Open Email > Email Routing > Enable. Set the destination address
//    (target Gmail) and click the verification link.
// 3. Add a catch-all rule: "Catch all addresses that route to my destination".
// 4. After setup, all *@minom.my.id will be forwarded to the target Gmail.
//
// This module generates a random local-part and appends it to aliases.txt.
// The IMAP bot just reads Gmail — no API call to CF on the hot path.

const fs = require("fs");
const path = require("path");

// Local-part generator — produces aliases that look like real human names
// (e.g. "emma.walker37" instead of "5w0kuqx05p"). Pattern: dictionary word
// (first name) + surname + 1–99 digit. Looks more natural to the AWS
// fingerprint heuristic (which treats alias-like email addresses as a
// "looks like real user" signal).
//
// `len` is ignored (kept for backward-compat with the CLI signature).
const FIRST_WORDS = [
  "emma", "liam", "olivia", "noah", "ava", "sophia", "mason", "isabella",
  "lucas", "mia", "logan", "harper", "ethan", "amelia", "james", "ella",
  "henry", "scarlett", "benjamin", "grace", "sebastian", "lily", "owen",
  "elena", "jack", "aria", "leo", "nora", "caleb", "ruby", "ryan",
  "sophie", "daniel", "claire", "matthew", "sarah", "andrew", "anna",
  "david", "emma", "chris", "kate", "tom", "liz", "mark", "amy",
  "paul", "jane", "alex", "kim", "luke", "may",
];

const LAST_WORDS = [
  "walker", "turner", "hall", "king", "wright", "lopez", "hill", "green",
  "adams", "baker", "clark", "davis", "evans", "ford", "garcia", "harris",
  "irwin", "jones", "kelly", "lewis", "miller", "nash", "owen", "perry",
  "quinn", "reed", "scott", "taylor", "underwood", "vega", "ward", "young",
  "zimmer", "carter", "fisher", "hughes", "jenkins", "knight", "lawson",
  "morris", "nelson", "palmer", "rice", "spencer", "tucker", "walsh",
];

/** @returns {string} */
function randomLocalPart() {
  const first = FIRST_WORDS[Math.floor(Math.random() * FIRST_WORDS.length)];
  const last = LAST_WORDS[Math.floor(Math.random() * LAST_WORDS.length)];
  const num = Math.floor(Math.random() * 90) + 10; // 10-99
  // Two formats are both used: "emma.walker37" and "emmaw37" — picked
  // randomly so not every alias shares the same structure.
  if (Math.random() < 0.5) return `${first}.${last}${num}`;
  return `${first.slice(0, 4)}${last.slice(0, 2)}${num}`;
}

// Generate N random aliases on a domain. Local-part uses the name-like format
// (see randomLocalPart).
/** @param {string} domain @param {number} [count=1] @returns {Array<string>} */
function generateAliases(domain, count = 1) {
  const out = [];
  for (let i = 0; i < count; i++) {
    out.push(`${randomLocalPart()}@${domain}`);
  }
  return out;
}

// Append aliases to a file (gitignored). Automatic dedupe (existing entries
// are ignored). Returns the number of aliases that were actually added.
/** @param {string} filePath @param {Array<string>} aliases @returns {number} */
function appendAliasesToFile(filePath, aliases) {
  let existing = "";
  if (fs.existsSync(filePath)) {
    existing = fs.readFileSync(filePath, "utf8");
  }
  const seen = new Set(
    existing.split(/\r?\n/).map((s) => s.trim().toLowerCase()).filter(Boolean)
  );
  const fresh = [];
  for (const a of aliases) {
    const lower = a.toLowerCase();
    if (seen.has(lower)) continue;
    seen.add(lower);
    fresh.push(a);
  }
  if (fresh.length === 0) return 0;
  fs.appendFileSync(filePath, fresh.join("\n") + "\n");
  return fresh.length;
}

module.exports = {
  randomLocalPart,
  generateAliases,
  appendAliasesToFile,
};
