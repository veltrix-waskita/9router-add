"use strict";

// Helpers for reading OTP from Gmail (forwarder alias -> Gmail) via IMAP.
// Replaces scraping priyo.email. Used by bot.js in `email` mode.

/**
 * Extract a verification code from raw email content (HTML or plain text).
 * Tries ordered patterns plus multi-language fallbacks.
 *
 * Supported languages: English, Indonesian.
 * Add new language keywords to `keywords` below as needed.
 *
 * @param {string|null|undefined} raw - Raw email body (HTML or plain text).
 * @returns {string|null} Extracted 4–8 digit code, or null if none found.
 */
function extractOtpFromRaw(raw) {
  if (!raw || typeof raw !== "string") return null;

  // Multi-language keywords matching near a digit block.
  const codeKeywords = [
    "code", "codes", "verification", "verify",
    "kode", "kode verifikasi", "kode\\s*verifikasi", "verifikasi",
    "otp",
  ].join("|");

  const patterns = [
    // Language-agnostic: class="code" div
    /<div[^>]*class=["'][^"']*code[^"']*["'][^>]*>\s*(\d{4,8})\s*<\/div>/i,
    // Explicit "Verification code:" prefix (English or similar)
    /Verification code:\s*(?:<\/[^>]+>\s*)*<[^>]+>\s*(\d{4,8})/i,
    // Any keyword within 300 chars before the digit block
    new RegExp(`(?:${codeKeywords})[\\s\\S]{0,300}?(\\d{4,8})`, "i"),
  ];
  for (const re of patterns) {
    const m = raw.match(re);
    if (m && m[1]) return m[1];
  }
  // Fallback: 6-digit block within 500 chars of a keyword
  const ctxMatch = raw.match(new RegExp(`(?:${codeKeywords})[^<]{0,500}?(\\d{6})`, "i"));
  if (ctxMatch) return ctxMatch[1];
  // Ultimate fallback: any standalone 6-digit number.
  // Relies on the caller (pickRecencyMatch) to confirm recency and source.
  // Avoids matching embedded digits (e.g. dates, IDs) by requiring
  // non-digit boundaries on both sides.
  const generic = raw.match(/(?<!\d)(\d{6})(?!\d)/);
  if (generic) return generic[1];
  return null;
}

/**
 * Build a Gmail X-GM-RAW search query targeting a specific alias recipient
 * and subject. Includes `in:anywhere` so Spam/Trash are also searched.
 *
 * @param {string} alias - Forwarder alias address (the To: recipient).
 * @param {string} subject - Expected email subject line.
 * @returns {string} Gmail raw search query string.
 */
function buildGmrawQuery(alias, subject) {
  return `to:${alias} subject:"${subject}" in:anywhere`;
}

/**
 * Build a fallback Gmail X-GM-RAW query that matches by sender domain
 * (signin.aws) and a broader subject pattern. The subject regex catches
 * both English and Indonesian AWS Builder ID verification email subjects:
 *
 *   EN: "Verify your AWS Builder ID email address"
 *   ID: "Verifikasi alamat email AWS Builder ID Anda"
 *
 * @param {string} _subject - Ignored; a broad subject pattern is used.
 * @returns {string} Gmail raw search query string.
 */
function buildGmrawFallbackQuery(_subject) {
  // Match either English or Indonesian subject patterns.
  return `from:signin.aws subject:{Verify your AWS Verifikasi alamat} in:anywhere`;
}

/**
 * From a list of fetched messages (with `internalDate` + `source`), pick
 * the newest one whose internalDate is within the recency window
 * (`since - slackMs` to now) AND whose body contains an OTP.
 *
 * @param {Array<{internalDate: Date|number|string, source: string}>} messages - Fetched messages.
 * @param {{since?: number, slackMs?: number}} [opts] - `since` is epoch ms; `slackMs` extends the window backwards.
 * @returns {{message: object, otp: string}|null} Picked match or null.
 */
function pickRecencyMatch(messages, { since = 0, slackMs = 60000 } = {}) {
  const floor = since - slackMs;
  const sorted = [...messages].sort(
    (a, b) => Number(a.internalDate) - Number(b.internalDate)
  );
  for (let i = sorted.length - 1; i >= 0; i--) {
    const msg = sorted[i];
    if (Number(msg.internalDate) < floor) continue;
    const otp = extractOtpFromRaw(String(msg.source || ""));
    if (otp) return { message: msg, otp };
  }
  return null;
}

/**
 * Default factory: create and connect an ImapFlow client using the given
 * IMAP config. `imapflow` is lazy-required so unit tests that inject
 * `opts.clientFactory` don't need the package installed.
 *
 * @param {{host?: string, port?: number, tls?: boolean, user: string, password: string}} imapCfg - IMAP connection config.
 * @returns {Promise<object>} A connected ImapFlow client.
 */
async function defaultClientFactory(imapCfg) {
  const { ImapFlow } = require("imapflow");
  const client = new ImapFlow({
    host: imapCfg.host || "imap.gmail.com",
    port: imapCfg.port || 993,
    secure: imapCfg.tls !== false,
    auth: { user: imapCfg.user, pass: imapCfg.password },
    logger: false,
  });
  await client.connect();
  return client;
}

/**
 * Find the Spam folder path on the connected IMAP client. Prefers the
 * `\Junk` special-use box, falls back to a path matching `/spam/i`,
 * and finally to the literal `[Gmail]/Spam`.
 *
 * @param {object} client - Connected ImapFlow client.
 * @returns {Promise<string>} Resolved Spam folder path.
 */
async function findSpamPath(client) {
  try {
    const boxes = await client.list();
    const junk = boxes.find((b) => b.specialUse === "\\Junk");
    if (junk && junk.path) return junk.path;
    const namedSpam = boxes.find((b) => /spam/i.test(b.path || ""));
    if (namedSpam) return namedSpam.path;
  } catch {}
  return "[Gmail]/Spam";
}

function formatFrom(envelope) {
  const from = envelope && envelope.from;
  if (Array.isArray(from) && from[0] && from[0].address) return from[0].address;
  return "";
}

/**
 * Read an OTP code from Gmail for the given alias, polling until the
 * code is found or the timeout elapses.
 *
 * @param {{user: string, password: string, host?: string, port?: number, tls?: boolean, deleteAfterRead?: boolean}} imapCfg - IMAP credentials/config.
 * @param {string} alias - Forwarder alias to search for (the To: recipient).
 * @param {{since?: number, slackMs?: number, pollMs?: number, maxWaitMs?: number, subject?: string, clientFactory?: Function}} [opts] - Behavior overrides; `clientFactory` lets tests inject a fake.
 * @returns {Promise<{ok: true, otp: string, from: string, subject: string, received: string, debug: object} | {ok: false, error: string, debug: object}>}
 */
async function getOtpViaImap(imapCfg, alias, opts = {}) {
  const since = Number(opts.since) || 0;
  const slackMs = Number(opts.slackMs) || 60000;
  const pollMs = Number(opts.pollMs) || 5000;
  const maxWaitMs = Number(opts.maxWaitMs) || 120000;
  const subject = opts.subject || "Verify your AWS Builder ID email address";
  const deleteAfterRead = imapCfg && imapCfg.deleteAfterRead !== false; // default true
  const clientFactory = opts.clientFactory || defaultClientFactory;

  const debug = { searchedFolders: [], matchCount: 0, usedGmraw: false };

  if (!imapCfg || !imapCfg.user || !imapCfg.password) {
    return { ok: false, error: "IMAP creds tidak lengkap (user/password)", debug };
  }

  let client;
  try {
    client = await clientFactory(imapCfg);
  } catch (e) {
    return { ok: false, error: `IMAP connect/auth gagal: ${e.message}`, debug };
  }

  const useGmraw = !!(
    client.capabilities && client.capabilities.has && client.capabilities.has("X-GM-EXT-1")
  );
  // IMPORTANT: `in:anywhere` in X-GM-RAW does not actually bypass mailbox
  // scope (verified E2E 2026-07-11). Every folder to be searched must be
  // locked first. Always search Spam too — forwarders often land in Spam,
  // and a `to:alias` IMAP search in the Spam folder is a safety net if the
  // server does not advertise X-GM-EXT-1.
  const folders = ["INBOX", await findSpamPath(client)];

  const start = Date.now();
  try {
    while (Date.now() - start < maxWaitMs) {
      const seen = new Set();
      const messages = [];
      let usedFallbackThisRound = false;

      for (const folder of folders) {
        const lock = await client.getMailboxLock(folder).catch(() => null);
        if (!lock) continue;
        try {
          // Build the query list: primary (to: alias) plus a fallback
          // (subject + sender) for forwarders that rewrite the To header
          // (e.g. Firefox Relay).
          let queries;
          if (useGmraw) {
            queries = [
              { q: buildGmrawQuery(alias, subject), type: "to" },
              { q: buildGmrawFallbackQuery(subject), type: "fallback" },
            ];
            debug.usedGmraw = true;
          } else {
            // Plain IMAP: try broad subject (strips "email address")
            // then fall back to from: signin.aws (catches localized
            // subjects like Indonesian "Verifikasi alamat...")
            const broadSubject = subject.replace(/\s*email address\s*/i, " ").trim();
            queries = [
              { q: { to: alias, subject: broadSubject }, type: "imap" },
              { q: { from: "signin.aws", subject: broadSubject }, type: "imap" },
              { q: { from: "signin.aws" }, type: "imap" },
            ];
          }

          let uids = [];
          let usedFallback = false;
          for (const { q, type } of queries) {
            const r = type === "imap"
              ? await client.search(q, { uid: true })
              : await client.search({ gmraw: q }, { uid: true });
            if (r && r.length > 0) {
              uids = r;
              if (type === "fallback") usedFallback = true;
              break;
            }
          }
          if (usedFallback) usedFallbackThisRound = true;

          if (!uids || uids.length === 0) {
            if (!debug.searchedFolders.includes(folder)) debug.searchedFolders.push(folder);
            continue;
          }
          debug.matchCount = Math.max(debug.matchCount, uids.length);

          for (const uid of uids.slice(-3)) {
            if (seen.has(uid)) continue;
            seen.add(uid);
            const msg = await client.fetchOne(
              uid,
              { source: true, envelope: true, internalDate: true },
              { uid: true }
            );
            if (!msg) continue;
            messages.push({
              uid,
              folder,
              source: msg.source ? msg.source.toString() : "",
              envelope: msg.envelope || {},
              internalDate: msg.internalDate ? new Date(msg.internalDate) : new Date(0),
            });
          }
        } finally {
          try { lock.release(); } catch {}
        }
      }
      debug.usedFallback = debug.usedFallback || usedFallbackThisRound;

      const picked = pickRecencyMatch(messages, { since, slackMs });
      if (picked) {
        const { message, otp } = picked;
        const result = {
          ok: true,
          otp,
          from: formatFrom(message.envelope),
          subject: (message.envelope && message.envelope.subject) || subject,
          received: message.internalDate.toISOString(),
          debug,
        };
        if (deleteAfterRead && message.folder) {
          // Need to re-lock folder for delete (lock is released every round).
          const lock = await client.getMailboxLock(message.folder).catch(() => null);
          if (lock) {
            try {
              await client.messageDelete(message.uid, { uid: true });
            } catch {}
            try { lock.release(); } catch {}
          }
        }
        return result;
      }
      await new Promise((r) => setTimeout(r, pollMs));
    }
  } finally {
    try { await client.logout(); } catch {}
  }
  return { ok: false, error: `OTP timeout ${Math.round(maxWaitMs / 1000)}s`, debug };
}

module.exports = {
  extractOtpFromRaw,
  buildGmrawQuery,
  buildGmrawFallbackQuery,
  pickRecencyMatch,
  findSpamPath,
  getOtpViaImap,
};
