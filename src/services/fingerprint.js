"use strict";

// Browser fingerprint randomization — generate realistic-looking per-account
// profile. Purpose: bypass AWS per-fingerprint throttle that proxy rotation
// alone does not fix (proxy = new IP, but fingerprint stays the same = continued throttle).
//
// Randomized components:
//   - User-Agent (Chrome desktop, Windows/Mac/Linux)
//   - Viewport (realistic desktop sizes)
//   - Timezone (IANA, common zones)
//   - Locale (en-US, en-GB, de-DE, etc.)
//   - Accept-Language (derived from locale)
//   - Hardware concurrency + device memory
//   - navigator.languages
//
// Source: real-world browser distribution. Ranges are realistic so the AWS
// fingerprint API does not flag them as obviously bot-generated.

const UAs = [
  // Chrome 149 (current) — Windows
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
  // Chrome 148 Windows
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.7778.96 Safari/537.36",
  // Chrome 149 macOS
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
  // Chrome 148 macOS ARM
  "Mozilla/5.0 (Macintosh; ARM Mac OS X 13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.7778.96 Safari/537.36",
  // Chrome 149 Linux
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36",
  // Chrome 148 Linux
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.7778.96 Safari/537.36",
];

const VIEWPORTS = [
  // Common desktop sizes
  { width: 1920, height: 1080 },
  { width: 1536, height: 864 },
  { width: 1440, height: 900 },
  { width: 1366, height: 768 },
  { width: 1680, height: 1050 },
  { width: 1280, height: 800 },
  { width: 1280, height: 720 },
];

const LOCALES = [
  { locale: "en-US", lang: "en-US,en;q=0.9" },
  { locale: "en-GB", lang: "en-GB,en;q=0.9" },
  { locale: "en-AU", lang: "en-AU,en;q=0.9" },
  { locale: "de-DE", lang: "de-DE,de;q=0.9,en;q=0.8" },
  { locale: "fr-FR", lang: "fr-FR,fr;q=0.9,en;q=0.8" },
  { locale: "es-ES", lang: "es-ES,es;q=0.9,en;q=0.8" },
  { locale: "ja-JP", lang: "ja-JP,ja;q=0.9,en;q=0.8" },
  { locale: "en",     lang: "en,en-US;q=0.9" },
];

const TIMEZONES = [
  "America/New_York",
  "America/Chicago",
  "America/Los_Angeles",
  "America/Denver",
  "Europe/London",
  "Europe/Berlin",
  "Europe/Paris",
  "Asia/Tokyo",
  "Asia/Singapore",
  "Australia/Sydney",
];

const HARDWARE_CONCURRENCY = [2, 4, 8, 12, 16];
const DEVICE_MEMORY = [2, 4, 8, 16, 32];

// Pick a random element from an array.
function pick(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

// Generate a full fingerprint. `seed` is optional — when provided, returns a
// deterministic result (for tests). Otherwise uses Math.random.
/**
 * Generate a randomized browser fingerprint. Deterministic when seed provided.
 * @param {number} [seed]
 * @returns {object}
 */
function generateFingerprint(seed) {
  let rng = Math.random;
  if (seed !== undefined) {
    // Mulberry32 — small fast deterministic PRNG.
    let s = seed >>> 0;
    rng = () => {
      s = (s + 0x6D2B79F5) >>> 0;
      let t = s;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  const pick = (arr) => arr[Math.floor(rng() * arr.length)];
  const ua = pick(UAs);
  const viewport = pick(VIEWPORTS);
  const loc = pick(LOCALES);
  const tz = pick(TIMEZONES);
  return {
    userAgent: ua,
    viewport: { width: viewport.width, height: viewport.height },
    locale: loc.locale,
    acceptLanguage: loc.lang,
    timezoneId: tz,
    hardwareConcurrency: pick(HARDWARE_CONCURRENCY),
    deviceMemory: pick(DEVICE_MEMORY),
    languages: [loc.locale, loc.locale.split("-")[0]],
  };
}

module.exports = { generateFingerprint };
