"use strict";

const http = require("http");
const { spawn } = require("child_process");

/**
 * Manage the captcha-solver sidecar process and make solve requests.
 *
 * The captcha-solver (FastAPI + CloakBrowser) runs as a subprocess on port 8877.
 * It solves Cloudflare Turnstile/JS Challenge via a two-step approach:
 *   1. type=cloudflare → obtains cf_clearance cookie
 *   2. type=turnstile (with cookies from step 1) → obtains valid Turnstile token
 *
 * Both steps must use the same proxy IP since cf_clearance is IP-bound.
 */

const CAPTCHA_SOLVER_PORT = 8877;
const START_TIMEOUT_MS = 30000;
const REQUEST_TIMEOUT_MS = 120000;

let _process = null;

/**
 * Start the captcha-solver subprocess.
 *
 * @param {string} solverPath - Path to the captcha-solver directory containing server.py.
 * @param {object} [env={}] - Extra environment variables to pass (e.g. SOLVER_ALLOW_PRIVATE).
 * @returns {Promise<void>}
 * @throws {Error} If the process fails to start or becomes ready within START_TIMEOUT_MS.
 */
async function start(solverPath, env = {}) {
  if (_process) return; // already running

  return new Promise((resolve, reject) => {
    // Prefer the project's own venv; fall back to system python3.
    const pythonBin = (() => {
      const fs = require("fs");
      const path = require("path");
      const candidates = [
        path.join(solverPath, "venv", "bin", "python3"),
        path.join(solverPath, ".venv", "bin", "python3"),
      ];
      for (const c of candidates) if (fs.existsSync(c)) return c;
      return "python3";
    })();

    const child = spawn(
      pythonBin,
      [
        "-m", "uvicorn", "server:app",
        "--host", "0.0.0.0",
        "--port", String(CAPTCHA_SOLVER_PORT),
      ],
      {
        cwd: solverPath,
        stdio: ["ignore", "pipe", "pipe"],
        env: { ...process.env, ...env, PORT: String(CAPTCHA_SOLVER_PORT) },
      }
    );

    let started = false;

    const onData = (chunk) => {
      const text = chunk.toString();
      if (!started && text.includes("Uvicorn running on")) {
        started = true;
        _process = child;
        resolve();
      }
    };

    child.stdout.on("data", onData);
    child.stderr.on("data", onData);

    child.on("error", (err) => {
      if (!started) reject(new Error(`captcha-solver failed to start: ${err.message}`));
    });

    child.on("close", (code) => {
      if (!started) reject(new Error(`captcha-solver exited before ready (code ${code})`));
    });

    setTimeout(() => {
      if (!started) reject(new Error("captcha-solver start timed out"));
    }, START_TIMEOUT_MS);
  });
}

/**
 * Check if the captcha-solver subprocess is currently running.
 * @returns {boolean}
 */
function isRunning() {
  return _process !== null && !_process.killed && _process.exitCode === null;
}

/**
 * Stop the captcha-solver subprocess.
 */
async function stop() {
  if (!isRunning()) return;
  _process.kill("SIGTERM");
  // Give it a moment to gracefully shut down.
  await new Promise((r) => setTimeout(r, 2000));
  if (isRunning()) _process.kill("SIGKILL");
  _process = null;
}

/**
 * Make an HTTP request to the captcha-solver API.
 *
 * @param {string} path - API path (e.g. "/solve").
 * @param {object} body - JSON body to POST.
 * @returns {Promise<object>}
 */
async function _request(path, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request(
      {
        hostname: "127.0.0.1",
        port: CAPTCHA_SOLVER_PORT,
        path,
        method: "POST",
        headers: { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) },
        timeout: REQUEST_TIMEOUT_MS,
      },
      (res) => {
        let body = "";
        res.on("data", (chunk) => (body += chunk));
        res.on("end", () => {
          try {
            resolve(JSON.parse(body));
          } catch {
            reject(new Error(`captcha-solver invalid JSON: ${body.slice(0, 200)}`));
          }
        });
      }
    );
    req.on("error", (err) => reject(new Error(`captcha-solver request failed: ${err.message}`)));
    req.on("timeout", () => { req.destroy(); reject(new Error("captcha-solver request timed out")); });
    req.write(data);
    req.end();
  });
}

/**
 * Solve a Cloudflare Turnstile challenge in two steps.
 *
 * Step 1: Solve cf_clearance (JS Challenge).
 * Step 2: Solve Turnstile token (using cookies from step 1 for the same IP binding).
 *
 * @param {object} params
 * @param {string} params.url - The page URL where Turnstile is rendered.
 * @param {string} params.sitekey - The Turnstile sitekey.
 * @param {string} params.proxy - Proxy URL string (HTTP/SOCKS).
 * @param {string} [params.userAgent] - Optional User-Agent.
 * @returns {Promise<{token: string, cfClearance: string, cookies: object[]}>}
 */
async function solveTurnstileTwoStep(params) {
  const step1 = await _request("/solve", {
    type: "cloudflare",
    url: params.url,
    proxy: params.proxy,
    userAgent: params.userAgent,
  });
  if (!step1.success) {
    throw new Error(`captcha-solver cloudflare step failed: ${step1.error || "unknown"}`);
  }

  const step2 = await _request("/solve", {
    type: "turnstile",
    url: params.url,
    sitekey: params.sitekey,
    proxy: params.proxy,
    userAgent: params.userAgent,
    cookies: step1.cookies,
  });
  if (!step2.success || !step2.token) {
    throw new Error(`captcha-solver turnstile step failed: ${step2.error || "no token"}`);
  }

  return {
    token: step2.token,
    cfClearance: step1.cfClearance || "",
    cookies: step1.cookies || [],
  };
}

module.exports = { start, stop, isRunning, solveTurnstileTwoStep };
