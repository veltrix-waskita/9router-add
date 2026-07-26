"use strict";

/**
 * Temp-mail service — dual-mode email source for grok-cli and kiro.
 *
 * Wraps @wanglinsaputra/tempmail-wrapper (ESM) with CJS-friendly
 * dynamic import. Supports create → poll OTP for kiro; grok-cli uses
 * the Python EmailBox port (worker/tempmail.py) instead of this file.
 *
 * @module services/tempmail
 */

const BLOCKED_DOMAINS = new Set([
  "yopmail.com", "mailto.plus", "tempmail.plus", "guerrillamail.com",
  "mailinator.com", "10minutemail.com", "temp-mail.org",
  "throwaway.email", "sharklasers.com",
]);

// -- xAI OTP extraction (ported from x-farm _extract_code) ----------

/** xAI hyphen code: "confirmation code: HPN-7Z9" */
const OTP_HYPHEN_RE =
  /(?:confirmation\s+)?code[:\s]+([A-Z0-9]{3}-[A-Z0-9]{3})\b/i;
/** Bare hyphen code — only accepted with xAI context */
const OTP_HYPHEN_BARE_RE = /\b([A-Z0-9]{3}-[A-Z0-9]{3})\b/i;
/** Legacy 6-char alnum: "confirmation code: AX3BBY" */
const OTP_LEGACY_RE =
  /(?:confirmation\s+)?code[:\s]+([A-Z0-9]{6})\b/i;
/** Labeled 6-digit: "verification code: 123456" */
const OTP_DIGIT6_RE =
  /(?:verification\s+code|confirmation\s+code|otp|one[- ]time(?:\s+pass(?:word|code)?))[:\s#]*(\d{6})\b/i;

/** Hyphen patterns that are never OTP codes (ads, CSS values) */
const SKIP_HYPHEN = new Set([
  "per-100", "max-100", "min-100", "dir-top", "top-dir", "moz-osx",
  "pre-built", "pre-made", "one-time", "set-up", "sign-up", "log-in",
  "opt-out", "opt-in", "non-stop", "all-in", "end-to", "to-end",
]);

/** Legacy/case-insensitive tokens that are never OTP */
const SKIP_LEGACY = new Set([
  "signup", "verify", "account", "please", "gmail", "xaiapp", "spacex",
  "edge", "chrome", "safari", "webkit", "mozilla", "button", "submit",
  "create", "ignore", "footer", "strong", "hidden", "center", "inline",
  "mobile", "column", "screen", "border", "margin", "height", "weight",
  "family", "system", "domain", "tensor", "mailto", "adjust", "bottom",
  "unleash", "online", "tools", "power", "ultimate", "directory",
]);

/** Ad subject/from markers — never OTP */
const AD_MARKERS = [
  "ai tools", "unleash the power", "adsvpn", "buysellads",
  "directory of online", "temp mail", "emailnator", "disposable gmail",
];

/** xAI context markers — required for bare hyphen and 6-digit paths */
const XAI_MARKERS = [
  "x.ai", "xai", "grok", "spacex", "confirmation code", "validation code",
  "verify your email", "email verification", "accounts.x.ai",
];

// -------------------------------------------------------------------

/**
 * Normalize a providers value — array or comma-separated string → string[].
 *
 * @param {string|string[]} [listOrString]
 * @param {string[]} [defaultList]
 * @returns {string[]}
 */
function normalizeProviders(listOrString, defaultList = ["ncaori", "zoromail"]) {
  if (Array.isArray(listOrString)) return listOrString.filter(Boolean);
  if (typeof listOrString === "string" && listOrString.trim()) {
    return listOrString.split(",").map((s) => s.trim()).filter(Boolean);
  }
  return [...defaultList];
}

/**
 * Check whether a domain is in the blocked set.
 *
 * @param {string} domain
 * @returns {boolean}
 */
function isBlockedDomain(domain) {
  return BLOCKED_DOMAINS.has(domain.toLowerCase().trim());
}

/**
 * Strip soft line breaks (quoted-printable style) and collapse whitespace.
 * Mirror of x-farm _decode_qpish.
 *
 * @param {string} text
 * @returns {string}
 */
function _decodeQpish(text) {
  return (text || "").replace(/=\r?\n/g, "").replace(/\r?\n/g, " ");
}

/**
 * Check whether concatenated subject+from+body looks like an ad rather
 * than a real OTP email.
 *
 * @param {string} text
 * @returns {boolean}
 */
function _looksLikeAd(text) {
  const low = (text || "").toLowerCase();
  const hasAd = AD_MARKERS.some((m) => low.includes(m));
  if (!hasAd) return false;
  // If xAI context also present, it's a real email with ad-ish content
  return !XAI_MARKERS.some((m) => low.includes(m));
}

/**
 * Check whether text contains xAI-related keywords.
 *
 * @param {string} text
 * @returns {boolean}
 */
function _hasXaiContext(text) {
  const low = (text || "").toLowerCase();
  return XAI_MARKERS.some((m) => low.includes(m));
}

/**
 * Extract an OTP code from temp-mail email text (subject + body).
 *
 * Ported from x-farm `_extract_code`. Priority:
 * 1. Labeled hyphen code: "confirmation code: HPN-7Z9"
 * 2. Bare hyphen code (only with xAI context)
 * 3. Labeled legacy 6-char alnum: "code: AX3BBY"
 * 4. Labeled 6-digit (only with xAI context)
 *
 * @param {string} blob - Concatenated subject + body text
 * @returns {string|null} The OTP code, or null if none found
 */
function extractTempmailOtp(blob) {
  if (!blob || typeof blob !== "string") return null;
  const text = _decodeQpish(blob);
  if (!text || _looksLikeAd(text)) return null;
  const xaiish = _hasXaiContext(text);

  // 1) Labeled hyphen code
  const m1 = text.match(OTP_HYPHEN_RE);
  if (m1) {
    const code = m1[1].toUpperCase();
    if (!SKIP_HYPHEN.has(code.toLowerCase())) return code;
  }

  // 2) Bare hyphen code — only when xAI context present
  if (xaiish) {
    const m2 = text.match(OTP_HYPHEN_BARE_RE);
    if (m2) {
      const code = m2[1].toUpperCase();
      if (!SKIP_HYPHEN.has(code.toLowerCase())) return code;
    }
  }

  // 3) Labeled legacy 6-char alnum
  const m3 = text.match(OTP_LEGACY_RE);
  if (m3) {
    const code = m3[1].toUpperCase();
    if (SKIP_LEGACY.has(code.toLowerCase())) return null;
    // Only accept pure digits with strong xAI label nearby
    if (/^\d{6}$/.test(code)) {
      if (!xaiish) return null;
      const window = text.slice(Math.max(0, m3.index - 40), m3.index + m3[0].length + 10);
      if (!/(?:confirmation|verification|otp|one[- ]time)/i.test(window)) return null;
    }
    return code;
  }

  // 4) Labeled 6-digit (xAI only)
  if (xaiish) {
    const m4 = text.match(OTP_DIGIT6_RE);
    if (m4) return m4[1];
  }

  return null;
}

/**
 * Create a mailbox via the wrapper's createProvider factory.
 *
 * Round-robins through the provider list, trying each until one succeeds.
 * If a provider creates an email using a blocked domain, that provider is
 * skipped and the next is tried.
 *
 * @param {object} [opts]
 * @param {string[]} [opts.providers] - Provider names in preference order
 * @param {Set<string>} [opts.blockedDomains] - Additional domains to block
 * @returns {Promise<{email: string, provider: string, client: object}>}
 */
async function createMailbox({ providers, blockedDomains } = {}) {
  const list = normalizeProviders(providers);
  const blocked = new Set(BLOCKED_DOMAINS);
  if (blockedDomains) {
    for (const d of blockedDomains) blocked.add(d.toLowerCase());
  }

  // Module-level index for round-robin start
  const startIdx = (_createMailboxIdx = (_createMailboxIdx || 0) + 1) % list.length;
  const reordered = [...list.slice(startIdx), ...list.slice(0, startIdx)];

  const errors = [];
  for (const name of reordered) {
    try {
      // Dynamic import of ESM wrapper from CJS
      /** @type {import('@wanglinsaputra/tempmail-wrapper')} */
      const wrap = await import("@wanglinsaputra/tempmail-wrapper");
      const client = wrap.createProvider(name);
      const email = await client.generateEmail();
      const domain = email.split("@").pop()?.toLowerCase() || "";
      if (blocked.has(domain)) {
        client._email = null;
        errors.push(`${name}: blocked domain ${domain}`);
        continue;
      }
      return { email, provider: name, client };
    } catch (err) {
      errors.push(`${name}: ${err.message}`);
    }
  }

  throw new AggregateError(
    errors,
    `All temp-mail providers failed: ${errors.join(" | ")}`,
  );
}

/** @type {number|undefined} */
let _createMailboxIdx;

/**
 * Wait for an OTP code to arrive in the inbox.
 *
 * Polls the provider's getInbox (and optionally readMessage) until the
 * OTP regex matches. Tries subject/preview first, then full body.
 *
 * @param {object} client - Provider instance from createProvider
 * @param {string} email - The temp-mail address
 * @param {object} [opts]
 * @param {number} [opts.timeoutMs=120000]
 * @param {number} [opts.intervalMs=3000]
 * @returns {Promise<string>} The extracted OTP code
 */
async function waitForOtp(client, email, { timeoutMs = 120000, intervalMs = 3000 } = {}) {
  const deadline = Date.now() + timeoutMs;
  const seen = new Set();

  while (Date.now() < deadline) {
    const inbox = await client.getInbox(email);
    for (const msg of inbox) {
      if (seen.has(msg.id)) continue;
      seen.add(msg.id);

      // Try subject + sender first (fast path)
      const previewBlob = `${msg.subject || ""} ${msg.sender || ""} ${msg.preview || ""}`;
      let code = extractTempmailOtp(previewBlob);
      if (code) return code;

      // Try full body
      try {
        const detail = await client.readMessage(msg.id);
        const bodyBlob = `${detail.subject || ""} ${detail.sender || ""} ${detail.bodyText || ""} ${detail.bodyHtml || ""}`;
        code = extractTempmailOtp(bodyBlob);
        if (code) return code;
      } catch {
        // Some providers (e.g. NcaoriMail) embed full content in inbox
        // and throw on readMessage; skip those gracefully.
      }
    }

    await sleep(intervalMs);
  }

  throw new Error(
    `OTP timeout after ${Math.round(timeoutMs / 1000)}s for ${email}`,
  );
}

/**
 * Promise-based sleep.
 * @param {number} ms
 * @returns {Promise<void>}
 */
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

module.exports = {
  normalizeProviders,
  isBlockedDomain,
  extractTempmailOtp,
  createMailbox,
  waitForOtp,
  // Export internal helpers for testing
  _decodeQpish,
  _looksLikeAd,
  _hasXaiContext,
};
