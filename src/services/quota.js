"use strict";

// Per-UTC-day quota tracker — count registrations per email domain.
//
// Tujuan: AWS Builder ID rate-limit (ERR-837) triggered per IP+fingerprint.
// Bekerja dengan membatasi akun per domain per hari UTC. Counter dipersist ke
// .batch-stats.json (gitignored) supaya batch lanjut besok pakai sisa quota
// otomatis.
//
// Schema:
//   {
//     "2026-07-11": { "mozmail.com": 17, "aleeas.com": 3 },
//     "2026-07-10": { "mozmail.com": 8 }
//   }

const fs = require("fs");
const path = require("path");

/** @param {Date} [d] */
function utcDateKey(d = new Date()) {
  return d.toISOString().slice(0, 10);
}

/**
 * @param {string} email
 * @returns {string|null}
 */
function domainOf(email) {
  if (!email || typeof email !== "string") return null;
  const at = email.lastIndexOf("@");
  if (at === -1) return null;
  return email.slice(at + 1).toLowerCase();
}

// Load .batch-stats.json. Return {} kalau file gak ada / corrupt.
// Corrupt JSON di-treat sebagai kosong (warning) — biar batch tidak
// terblokir karena file rusak.
/**
 * @param {string} filePath
 * @returns {object}
 */
function loadStats(filePath) {
  if (!filePath || !fs.existsSync(filePath)) return {};
  try {
    const parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
    return typeof parsed === "object" && parsed !== null ? parsed : {};
  } catch (e) {
    console.warn(`[quota] stats file corrupt: ${e.message} — treating as empty`);
    return {};
  }
}

// Save atomically (write tmp + rename) supaya crash mid-write gak rusak file.
/**
 * @param {string} filePath
 * @param {object} stats
 */
function saveStats(filePath, stats) {
  if (!filePath) return;
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const tmp = filePath + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(stats, null, 2));
  fs.renameSync(tmp, filePath);
}

// Apakah domain ini punya sisa quota hari ini?
// `cap` = max registrations per domain per UTC day.
/**
 * @param {object} stats
 * @param {string} email
 * @param {number} cap
 * @returns {boolean}
 */
function isAllowed(stats, email, cap) {
  const domain = domainOf(email);
  if (!domain) return false;
  const used = (stats[utcDateKey()] && stats[utcDateKey()][domain]) || 0;
  return used < cap;
}

// Increment counter atomically (load, mutate, save). Return updated used count.
/**
 * @param {object} stats
 * @param {string} email
 * @returns {number}
 */
function increment(stats, email) {
  const domain = domainOf(email);
  if (!domain) return 0;
  const day = utcDateKey();
  if (!stats[day]) stats[day] = {};
  const newUsed = (stats[day][domain] || 0) + 1;
  stats[day][domain] = newUsed;
  return newUsed;
}

// Wrap + increment. Return true kalau di-allow (dan increment dicatat),
// false kalau sudah cap.
// Function ini yang dipakai bot.js per akun: kalau return false, skip akun.
/**
 * @param {string} filePath
 * @param {string} email
 * @param {number} cap
 * @returns {{allowed: boolean, stats: object}}
 */
function tryConsume(filePath, email, cap) {
  const stats = loadStats(filePath);
  if (!isAllowed(stats, email, cap)) return { allowed: false, stats };
  increment(stats, email);
  saveStats(filePath, stats);
  return { allowed: true, stats };
}

// Optional cleanup: keep hanya N hari terakhir. Limit growth.
/**
 * @param {object} stats
 * @param {number} [keepDays=30]
 * @returns {object}
 */
function pruneOld(stats, keepDays = 30) {
  const cutoff = Date.now() - keepDays * 24 * 60 * 60 * 1000;
  const out = {};
  for (const [k, v] of Object.entries(stats || {})) {
    const t = Date.parse(k + "T00:00:00Z");
    if (!Number.isNaN(t) && t >= cutoff) out[k] = v;
  }
  return out;
}

module.exports = {
  utcDateKey,
  domainOf,
  loadStats,
  saveStats,
  isAllowed,
  increment,
  tryConsume,
  pruneOld,
};
