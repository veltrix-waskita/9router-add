"use strict";

const http = require("http");
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");

/**
 * Manage the captcha-solver sidecar process and make solve requests.
 *
 * Expects a FastAPI app at solverPath (uvicorn server:app) on port 8877.
 * Contract used by grok-cli worker:
 *   POST /solve { type:"turnstile", url, sitekey } → { solved, token|solution.token }
 */

const CAPTCHA_SOLVER_PORT = 8877;
const START_TIMEOUT_MS = 60000; // camoufox engine can take a while on first boot
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
  if (isRunning()) return;

  const absSolverPath = path.resolve(solverPath);

  return new Promise((resolve, reject) => {
    // Prefer the project's own venv; fall back to system python3.
    // Always absolute — relative bins can ENOENT under some spawns.
    const candidates = [
      path.join(absSolverPath, "venv", "bin", "python3"),
      path.join(absSolverPath, ".venv", "bin", "python3"),
    ];
    let pythonBin = "python3";
    for (const c of candidates) {
      if (fs.existsSync(c)) {
        pythonBin = c;
        break;
      }
    }

    const child = spawn(
      pythonBin,
      [
        "-m",
        "uvicorn",
        "server:app",
        "--host",
        "127.0.0.1",
        "--port",
        String(CAPTCHA_SOLVER_PORT),
      ],
      {
        cwd: absSolverPath,
        stdio: ["ignore", "pipe", "pipe"],
        env: {
          ...process.env,
          ...env,
          PORT: String(CAPTCHA_SOLVER_PORT),
          HOST: "127.0.0.1",
        },
      }
    );

    let settled = false;
    let started = false;

    const settle = (fn, arg) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn(arg);
    };

    const onData = (chunk) => {
      const text = chunk.toString();
      // Keep quiet by default; surface only readiness (runner can log).
      if (!started && text.includes("Uvicorn running on")) {
        started = true;
        _process = child;
        settle(resolve);
      }
    };

    child.stdout.on("data", onData);
    child.stderr.on("data", onData);

    child.on("error", (err) => {
      if (!started) settle(reject, new Error(`captcha-solver failed to start: ${err.message}`));
    });

    child.on("close", (code) => {
      if (_process === child) _process = null;
      if (!started) {
        settle(reject, new Error(`captcha-solver exited before ready (code ${code})`));
      }
    });

    const timer = setTimeout(() => {
      if (!started) {
        try {
          child.kill("SIGTERM");
        } catch {
          /* ignore */
        }
        settle(reject, new Error("captcha-solver start timed out"));
      }
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
 * Stop the captcha-solver subprocess (only the one we started).
 */
async function stop() {
  if (!isRunning()) {
    _process = null;
    return;
  }
  const child = _process;
  _process = null;
  try {
    child.kill("SIGTERM");
  } catch {
    /* ignore */
  }
  await new Promise((r) => setTimeout(r, 2000));
  if (child.exitCode === null && !child.killed) {
    try {
      child.kill("SIGKILL");
    } catch {
      /* ignore */
    }
  }
}

/**
 * Make an HTTP request to the captcha-solver API.
 *
 * @param {string} reqPath - API path (e.g. "/solve").
 * @param {object} body - JSON body to POST.
 * @returns {Promise<object>}
 */
async function _request(reqPath, body) {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify(body);
    const req = http.request(
      {
        hostname: "127.0.0.1",
        port: CAPTCHA_SOLVER_PORT,
        path: reqPath,
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(data),
        },
        timeout: REQUEST_TIMEOUT_MS,
      },
      (res) => {
        let resBody = "";
        res.on("data", (chunk) => (resBody += chunk));
        res.on("end", () => {
          try {
            resolve(JSON.parse(resBody));
          } catch {
            reject(new Error(`captcha-solver invalid JSON: ${resBody.slice(0, 200)}`));
          }
        });
      }
    );
    req.on("error", (err) =>
      reject(new Error(`captcha-solver request failed: ${err.message}`))
    );
    req.on("timeout", () => {
      req.destroy();
      reject(new Error("captcha-solver request timed out"));
    });
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
  if (!step1.success && !step1.solved) {
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
  const token =
    step2.token || (step2.solution && step2.solution.token) || "";
  if ((!step2.success && !step2.solved) || !token) {
    throw new Error(`captcha-solver turnstile step failed: ${step2.error || "no token"}`);
  }

  return {
    token,
    cfClearance: step1.cfClearance || "",
    cookies: step1.cookies || [],
  };
}

module.exports = {
  start,
  stop,
  isRunning,
  solveTurnstileTwoStep,
  CAPTCHA_SOLVER_PORT,
};
