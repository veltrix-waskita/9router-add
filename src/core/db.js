"use strict";

const sqlite3 = require("sqlite3");
const path = require("path");
const crypto = require("crypto");

/**
 * Generate a random UUID v4 string.
 * @returns {string} UUID
 */
function uuid() {
  return crypto.randomUUID();
}

/**
 * Open (or create) the SQLite database at config.dbPath and ensure the
 * providerConnections table exists. Resolves with the sqlite3 Database instance.
 * @param {{ dbPath?: string }} config - Config object with optional dbPath.
 * @returns {Promise<sqlite3.Database>} Open database instance.
 */
function getDb(config) {
  const dbPath = config.dbPath || path.join(require("os").homedir(), ".9router", "db", "data.sqlite");
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(dbPath, (err) => {
      if (err) return reject(err);
      // Ensure table exists
      db.run(`CREATE TABLE IF NOT EXISTS providerConnections (
        id TEXT PRIMARY KEY,
        provider TEXT NOT NULL,
        authType TEXT NOT NULL DEFAULT 'oauth',
        name TEXT,
        email TEXT,
        isActive INTEGER DEFAULT 1,
        data TEXT DEFAULT '{}',
        createdAt TEXT DEFAULT (datetime('now')),
        updatedAt TEXT DEFAULT (datetime('now'))
      )`, (err2) => {
        if (err2) return reject(err2);
        resolve(db);
      });
    });
  });
}

/**
 * Insert a provider connection row and return it with its generated id.
 * @param {{ dbPath?: string }} config - Config object with optional dbPath.
 * @param {Object} connection - Connection fields (provider, authType, name, email, isActive, data).
 * @returns {Promise<{ id: string }>} Inserted connection with assigned id.
 */
async function insert(config, connection) {
  const db = await getDb(config);
  const id = uuid();
  const now = new Date().toISOString();
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO providerConnections (id, provider, authType, name, email, isActive, data, createdAt, updatedAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        id,
        connection.provider,
        connection.authType || "oauth",
        connection.name || null,
        connection.email || null,
        connection.isActive !== undefined ? (connection.isActive ? 1 : 0) : 1,
        JSON.stringify(connection.data || {}),
        now,
        now,
      ],
      (err) => {
        db.close();
        if (err) return reject(err);
        resolve({ id, ...connection });
      }
    );
  });
}

/**
 * Find a provider connection by id.
 * @param {{ dbPath?: string }} config - Config object with optional dbPath.
 * @param {string} id - Connection id (UUID).
 * @returns {Promise<Object|null>} Connection row with parsed `data`, or null if not found.
 */
async function findById(config, id) {
  const db = await getDb(config);
  return new Promise((resolve, reject) => {
    db.get("SELECT * FROM providerConnections WHERE id = ?", [id], (err, row) => {
      db.close();
      if (err) return reject(err);
      if (!row) return resolve(null);
      row.data = JSON.parse(row.data || "{}");
      resolve(row);
    });
  });
}

/**
 * Find all provider connections for a given provider, newest first.
 * @param {{ dbPath?: string }} config - Config object with optional dbPath.
 * @param {string} provider - Provider name to filter by.
 * @returns {Promise<Array>} Array of connection rows with parsed `data` fields.
 */
async function findByProvider(config, provider) {
  const db = await getDb(config);
  return new Promise((resolve, reject) => {
    db.all("SELECT * FROM providerConnections WHERE provider = ? ORDER BY createdAt DESC", [provider], (err, rows) => {
      db.close();
      if (err) return reject(err);
      for (const row of rows) {
        row.data = JSON.parse(row.data || "{}");
      }
      resolve(rows);
    });
  });
}

/**
 * Update the JSON `data` blob and `updatedAt` timestamp of a connection.
 * @param {{ dbPath?: string }} config - Config object with optional dbPath.
 * @param {string} id - Connection id to update.
 * @param {Object} data - New data object (will be JSON-stringified into the `data` column).
 * @returns {Promise<void>} Resolves when the row has been updated.
 */
async function update(config, id, data) {
  const db = await getDb(config);
  const now = new Date().toISOString();
  return new Promise((resolve, reject) => {
    db.run(
      "UPDATE providerConnections SET data = ?, updatedAt = ? WHERE id = ?",
      [JSON.stringify(data), now, id],
      (err) => {
        db.close();
        if (err) return reject(err);
        resolve();
      }
    );
  });
}

/**
 * Delete a provider connection by id.
 * @param {{ dbPath?: string }} config - Config object with optional dbPath.
 * @param {string} id - Connection id to delete.
 * @returns {Promise<void>} Resolves when the row has been deleted (or was already missing).
 */
async function del(config, id) {
  const db = await getDb(config);
  return new Promise((resolve, reject) => {
    db.run("DELETE FROM providerConnections WHERE id = ?", [id], (err) => {
      db.close();
      if (err) return reject(err);
      resolve();
    });
  });
}

module.exports = { getDb, insert, findById, findByProvider, update, del };
