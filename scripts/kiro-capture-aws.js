#!/usr/bin/env node
/**
 * Phase D0 — AWS Builder ID endpoint discovery via browser capture.
 *
 * BLOCKING GATE for Task 6 (worker step implementation).
 *
 * This script:
 *   1. Connects to a live 9router instance (config.json or CLI args)
 *   2. Requests a fresh kiro device-code from 9router
 *   3. Launches a real Chrome browser (stealth) pointed at the AWS Builder ID
 *      device-code activation URL (verification_uri_complete)
 *   4. Captures ALL fetch/XHR network traffic with request/response bodies
 *   5. Opens a 180-second interactive window for you to complete the signup
 *      flow manually: email → OTP → password → name → consent
 *   6. Saves the captured endpoint map to
 *      docs/superpowers/specs/2026-07-23-kiro-aws-endpoint-map.md
 *   7. Also prints a concise summary to stdout
 *
 * Usage:
 *   node scripts/kiro-capture-aws.js
 *   # or with overrides:
 *   node scripts/kiro-capture-aws.js --host 10.0.0.5 --port 20128
 *
 * During the 180s window:
 *   - Switch to the Chrome window that opens
 *   - Complete the AWS Builder ID signup flow (email → ... → consent)
 *   - Watch the terminal for captured endpoint names as they appear
 *   - The script saves results automatically when time runs out
 *
 * Security: all request/response bodies are redacted in the saved map
 * (passwords, tokens, OTP codes, device_code replaced with <REDACTED>).
 */

"use strict";

const fs = require("fs");
const path = require("path");

const { loadConfig } = require("../src/core/config");
const { resolveAuthHeaders } = require("../src/core/auth");
const { request } = require("../src/core/http-client");
const { launchStealthBrowser, randomRealisticName } = require("../src/services/browser");

// ─── Redaction helpers ──────────────────────────────────────────────────────

/** Patterns whose value must be redacted in output. */
const REDACT_PATTERNS = [
  /\b(password|passwd|pwd)\s*[:=]\s*[^\s&"]+/gi,
  /\b(otp|otp_code|verification_code|confirmation_code)\s*[:=]\s*[^\s&"]+/gi,
  /\b(device_code|code_verifier|codeVerifier)\s*[:=]\s*[^\s&"]+/gi,
  /\b(client_secret|_clientSecret|client_id|_clientId)\s*[:=]\s*[^\s&"]+/gi,
  /\b(authorization|bearer)\s+[A-Za-z0-9._\-+/=]+/gi,
  /\b(access_token|refresh_token|id_token)\s*[:=]\s*[^\s&"]+/gi,
  /\b(session_token|csrf_token|_csrf)\s*[:=]\s*[^\s&"]+/gi,
  /\b[0-9A-Za-z+/]{20,}={0,2}\b/g,  // base64-ish blobs
];

function redactValue(key, value) {
  const str = String(value ?? "");
  if (!str) return str;
  // Always redact known secret keys
  const secretKeys = [
    "password", "passwd", "pwd", "otp", "otp_code",
    "verification_code", "confirmation_code", "code_verifier",
    "device_code", "client_secret", "client_id",
    "access_token", "refresh_token", "id_token",
    "fullname", "full_name", "display_name",
  ];
  if (secretKeys.some((k) => key.toLowerCase().includes(k))) {
    return "<REDACTED>";
  }
  // Redact any value matching redact patterns
  let result = str;
  for (const re of REDACT_PATTERNS) {
    result = result.replace(re, (match) => {
      const colonIdx = match.indexOf(":");
      const eqIdx = match.indexOf("=");
      const sepIdx = colonIdx >= 0 ? colonIdx : eqIdx;
      if (sepIdx >= 0) {
        return match.slice(0, sepIdx + 1) + "<REDACTED>";
      }
      return "<REDACTED>";
    });
  }
  return result;
}

function redactBody(body) {
  if (!body) return body;
  if (typeof body === "string") {
    let result = body;
    for (const re of REDACT_PATTERNS) {
      result = result.replace(re, (match) => {
        const colonIdx = match.indexOf(":");
        const eqIdx = match.indexOf("=");
        const sepIdx = colonIdx >= 0 ? colonIdx : eqIdx;
        if (sepIdx >= 0) {
          return match.slice(0, sepIdx + 1) + "<REDACTED>";
        }
        return "<REDACTED>";
      });
    }
    return result;
  }
  if (typeof body === "object") {
    return redactObject(body);
  }
  return body;
}

function redactObject(obj) {
  if (!obj || typeof obj !== "object") return obj;
  if (Array.isArray(obj)) return obj.map((v) => redactObject(v));
  const result = {};
  for (const [key, value] of Object.entries(obj)) {
    result[key] = redactValue(key, value);
  }
  return result;
}

// ─── Core capture logic ─────────────────────────────────────────────────────

async function main() {
  // 1. Load config
  const config = loadConfig(process.argv.slice(2));
  console.log(`[capture] Config loaded: ${config.host}:${config.port} (mode=${config.mode})`);

  // 2. Resolve auth headers to 9router
  const httpClient = { request };
  const authHeaders = await resolveAuthHeaders(config, httpClient);
  console.log("[capture] Auth resolved for 9router");

  // 3. Build a simple API call helper
  async function apiCall(method, path, body) {
    const bodyStr = body ? JSON.stringify(body) : undefined;
    const res = await request(config, {
      method,
      path,
      body: bodyStr,
      headers: bodyStr
        ? { ...authHeaders, "Content-Type": "application/json" }
        : authHeaders,
    });
    if (res.statusCode >= 400) {
      const errBody =
        typeof res.body === "string"
          ? res.body.slice(0, 200)
          : JSON.stringify(res.body).slice(0, 200);
      throw new Error(`9router HTTP ${res.statusCode} from ${path}: ${errBody}`);
    }
    return res.body;
  }

  // 4. Get a fresh device code
  console.log("[capture] Requesting kiro device-code from 9router...");
  const deviceData = await apiCall("GET", "/api/oauth/kiro/device-code");
  if (!deviceData || !deviceData.verification_uri_complete) {
    console.error("[capture] Failed: no verification_uri_complete in device-code response");
    console.error(JSON.stringify(deviceData, null, 2));
    process.exit(1);
  }

  const deviceUrl = deviceData.verification_uri_complete;
  console.log(`[capture] Device code received (user_code=${deviceData.user_code || "?"})`);
  console.log(`[capture] Activation URL: ${deviceUrl}`);

  // 5. Launch browser with stealth (visible, headless: false)
  console.log("[capture] Launching stealth browser...");
  const services = {};
  config.headless = false; // force visible for manual input
  const { browser, page } = await launchStealthBrowser(config, services);

  // 6. Set up network capture
  const captured = [];
  const seenUrls = new Set();

  // Capture all outgoing requests
  page.on("request", (req) => {
    const url = req.url();
    const resourceType = req.resourceType();

    // Only capture XHR, fetch, and document navigation
    if (!["xhr", "fetch", "document"].includes(resourceType)) return;

    const entry = {
      url,
      method: req.method(),
      resourceType,
      timestamp: Date.now(),
      headers: req.headers(),
      postData: req.postData() || null,
    };
    captured.push(entry);
    seenUrls.add(url);
  });

  // Capture responses (match to request entries)
  page.on("response", async (resp) => {
    const url = resp.url();
    const resourceType = resp.request().resourceType();
    if (!["xhr", "fetch", "document"].includes(resourceType)) return;

    // Find the matching request entry (last one with this URL and no response)
    let entry = null;
    for (let i = captured.length - 1; i >= 0; i--) {
      if (captured[i].url === url && !captured[i].response) {
        entry = captured[i];
        break;
      }
    }
    if (!entry) return;

    let bodyText;
    try {
      bodyText = await resp.text();
    } catch {
      bodyText = "<unreadable>";
    }

    entry.response = {
      status: resp.status(),
      statusText: resp.statusText(),
      contentType: resp.headers()["content-type"] || "",
      body: bodyText,
    };
  });

  // 7. Navigate to the AWS Builder ID device-code activation URL
  console.log("\n[capture] Navigating to AWS Builder ID activation URL...\n");
  await page.goto(deviceUrl, { waitUntil: "networkidle2", timeout: 30000 });

  // 8. Interactive capture window
  const CAPTURE_SECONDS = 180;
  console.log(
    `\n╔══════════════════════════════════════════════════════════════╗\n` +
      `║  CAPTURE WINDOW: ${String(CAPTURE_SECONDS).padStart(3, " ")} seconds                         ║\n` +
      `║                                                              ║\n` +
      `║  Switch to the Chrome window and complete the AWS Builder    ║\n` +
      `║  ID signup flow:                                             ║\n` +
      `║                                                              ║\n` +
      `║    1. Enter email address                                    ║\n` +
      `║    2. Check inbox for OTP code                               ║\n` +
      `║    3. Enter OTP (6-digit verification code)                  ║\n` +
      `║    4. Set password                                           ║\n` +
      `║    5. Enter name / display name                              ║\n` +
      `║    6. Complete consent/device-authorize                      ║\n` +
      `║                                                              ║\n` +
      `║  The script saves captured endpoints automatically after     ║\n` +
      `║  the timer expires.                                          ║\n` +
      `╚══════════════════════════════════════════════════════════════╝\n`
  );

  // Countdown timer in terminal
  const startTime = Date.now();
  const countdownInterval = setInterval(() => {
    const elapsed = Math.round((Date.now() - startTime) / 1000);
    const remaining = CAPTURE_SECONDS - elapsed;
    if (remaining > 0) {
      const endpoints = captured.filter(
        (r) => r.resourceType === "xhr" || r.resourceType === "fetch"
      ).length;
      process.stdout.write(
        `\r[capture] ${String(remaining).padStart(3, " ")}s remaining · ${String(endpoints).padStart(2, " ")} endpoints captured  `
      );
    }
  }, 1000);

  await new Promise((r) => setTimeout(r, CAPTURE_SECONDS * 1000));
  clearInterval(countdownInterval);
  process.stdout.write("\n");

  // 9. Process and write endpoint map
  console.log("\n[capture] Capture window closed. Processing endpoints...");

  // Filter to interesting endpoints (XHR/fetch + API-like document URLs)
  const apiEndpoints = captured.filter(
    (r) =>
      r.resourceType === "xhr" ||
      r.resourceType === "fetch" ||
      r.url.includes("/api/") ||
      r.url.includes("/oauth/") ||
      r.url.includes("/auth/") ||
      r.url.includes("/signin") ||
      r.url.includes("/signup") ||
      r.url.includes("/register")
  );

  // Group by URL pathname (without query params)
  const grouped = {};
  for (const entry of apiEndpoints) {
    try {
      const u = new URL(entry.url);
      // Skip static assets and google-related cruft
      if (
        u.pathname.match(/\.(js|css|png|jpg|gif|svg|ico|woff2?|ttf|eot)$/i) ||
        u.hostname.includes("google") ||
        u.hostname.includes("gstatic") ||
        u.hostname.includes("facebook") ||
        u.hostname.includes("recaptcha")
      ) {
        continue;
      }
      const key = `${entry.method} ${u.pathname}`;
      if (!grouped[key]) {
        grouped[key] = {
          method: entry.method,
          pathname: u.pathname,
          hostname: u.hostname,
          fullUrl: entry.url,
          count: 0,
          requestHeaders: null,
          postData: null,
          responseStatus: null,
          responseBody: null,
          contentType: null,
        };
      }
      grouped[key].count++;
      // Keep the first request/response data
      if (!grouped[key].requestHeaders) {
        grouped[key].requestHeaders = entry.headers;
        grouped[key].postData = entry.postData;
      }
      if (entry.response && !grouped[key].responseStatus) {
        grouped[key].responseStatus = entry.response.status;
        grouped[key].responseBody = entry.response.body;
        grouped[key].contentType = entry.response.contentType;
      }
    } catch {
      // skip malformed URLs
    }
  }

  const sortedKeys = Object.keys(grouped).sort();

  // 10. Write the endpoint map markdown file
  const mapPath = path.join(
    __dirname,
    "..",
    "docs",
    "superpowers",
    "specs",
    "2026-07-23-kiro-aws-endpoint-map.md"
  );
  const ensureDir = path.dirname(mapPath);
  if (!fs.existsSync(ensureDir)) {
    fs.mkdirSync(ensureDir, { recursive: true });
  }

  const lines = [];
  lines.push("# AWS Builder ID — Captured Endpoint Map");
  lines.push("");
  lines.push(
    `> Captured ${new Date().toISOString()} via kiro device-code activation URL`
  );
  lines.push("> All secrets redacted: passwords, OTP codes, tokens replaced with `<REDACTED>`");
  lines.push("");
  lines.push("## Summary");
  lines.push("");
  lines.push(
    `- **Total XHR/fetch requests captured:** ${apiEndpoints.length}`
  );
  lines.push(
    `- **Unique API endpoint groups:** ${sortedKeys.length}`
  );
  lines.push(
    `- **Capture duration:** ${CAPTURE_SECONDS}s`
  );
  lines.push(
    `- **Source:** kiro device-code → AWS Builder ID (IAM Identity Center)`
  );
  lines.push(
    `- **User agent:** Chrome (stealth puppeteer)`
  );
  lines.push("");
  lines.push(
    "> **Note:** Redacted fields (`<REDACTED>`) indicate where credentials, tokens, OTP codes, or other secrets were scrubbed from request/response bodies."
  );
  lines.push("");
  lines.push("---");
  lines.push("");
  lines.push("## Captured Endpoints");
  lines.push("");
  lines.push(
    "Endpoints are grouped by METHOD + pathname. Multiple occurrences of the same endpoint (e.g., redirects or polling) are counted but only the first request/response pair is shown."
  );
  lines.push("");

  for (const key of sortedKeys) {
    const ep = grouped[key];
    lines.push(`### ${ep.method} \`${ep.pathname}\``);
    lines.push("");
    lines.push(`- **Host:** \`${ep.hostname}\``);
    lines.push(`- **Full URL:** \`${redactBody(ep.fullUrl)}\``);
    lines.push(`- **Occurrences:** ${ep.count}`);
    if (ep.contentType) {
      lines.push(`- **Content-Type:** ${ep.contentType}`);
    }
    lines.push("");

    // Request headers (redacted, show structure only)
    if (ep.requestHeaders) {
      lines.push("**Request Headers (sample):**");
      lines.push("```");
      const headerKeys = Object.keys(ep.requestHeaders).sort();
      for (const hk of headerKeys) {
        if (hk.toLowerCase() === "cookie" || hk.toLowerCase() === "authorization") {
          lines.push(`${hk}: <REDACTED>`);
        } else if (
          hk.toLowerCase() === "user-agent" ||
          hk.toLowerCase() === "origin" ||
          hk.toLowerCase() === "referer"
        ) {
          lines.push(`${hk}: ${redactBody(ep.requestHeaders[hk])}`);
        } else {
          lines.push(`${hk}: ${redactBody(ep.requestHeaders[hk])}`);
        }
      }
      lines.push("```");
      lines.push("");
    }

    // Request body (redacted)
    if (ep.postData) {
      lines.push("**Request Body (redacted):**");
      lines.push("```");
      lines.push(redactBody(ep.postData));
      lines.push("```");
      lines.push("");
    }

    // Response
    if (ep.responseStatus !== null) {
      lines.push(`**Response:** HTTP ${ep.responseStatus}`);
      if (ep.responseBody) {
        // Only show up to 5KB of response body
        const bodyForDisplay =
          typeof ep.responseBody === "string"
            ? ep.responseBody.slice(0, 5000)
            : JSON.stringify(ep.responseBody).slice(0, 5000);
        lines.push("```");
        lines.push(redactBody(bodyForDisplay));
        lines.push("```");
      }
      lines.push("");
    }

    lines.push("---");
    lines.push("");
  }

  // 11. Add Appendix section with field map for worker implementation
  lines.push("## Appendix: Field Map for Worker Implementation");
  lines.push("");
  lines.push(
    "The table below maps each captured endpoint to the worker step that needs it. Fill in the exact field names from the captured request/response bodies above."
  );
  lines.push("");
  lines.push("| Endpoint | Worker Step | Method | Required Fields (from capture) |");
  lines.push("|----------|-------------|--------|-------------------------------|");

  // Auto-generate from captured endpoints grouped by step
  const stepPatterns = [
    { step: "bootstrap", keywords: ["/device-code", "/activate"] },
    { step: "email_entry", keywords: ["/signin", "/email", "/verify", "/account"] },
    { step: "otp", keywords: ["/otp", "/code", "/verify"] },
    { step: "password", keywords: ["/password", "/credential"] },
    { step: "name", keywords: ["/name", "/profile", "/user"] },
    { step: "consent", keywords: ["/consent", "/authorize", "/oauth", "/token"] },
    { step: "device_confirm", keywords: ["/confirm", "/device"] },
  ];

  const assigned = new Set();
  for (const { step, keywords } of stepPatterns) {
    const matches = sortedKeys.filter(
      (k) => keywords.some((kw) => k.toLowerCase().includes(kw)) && !assigned.has(k)
    );
    for (const m of matches) {
      assigned.add(m);
      const ep = grouped[m];
      // Extract field names from postData
      let fields = "—";
      if (ep.postData) {
        try {
          const pd =
            typeof ep.postData === "string" ? JSON.parse(ep.postData) : ep.postData;
          if (typeof pd === "object" && pd !== null) {
            fields = Object.keys(pd)
              .map((k) => `\`${k}\``)
              .join(", ");
          }
        } catch {
          // just use the raw keys from form-encoded data
          const rawKeys = ep.postData.match(/\b(\w+)=/g);
          if (rawKeys) {
            fields = rawKeys
              .map((s) => s.replace("=", ""))
              .map((s) => `\`${s}\``)
              .join(", ");
          }
        }
      }
      lines.push(`| \`${m}\` | ${step} | ${ep.method} | ${fields} |`);
    }
  }

  // Unassigned endpoints
  const unassigned = sortedKeys.filter((k) => !assigned.has(k));
  for (const m of unassigned) {
    const ep = grouped[m];
    lines.push(`| \`${m}\` | _unmapped_ | ${ep.method} | — |`);
  }

  lines.push("");
  lines.push(
    "> **Note for Task 6 (worker implementation):** The `_unmapped` rows above are endpoints that were hit during the capture session but don't obviously map to a known worker step. Review them and either assign to a step or note as noise."
  );
  lines.push("");

  fs.writeFileSync(mapPath, lines.join("\n") + "\n");
  console.log(`[capture] Endpoint map saved to: ${mapPath}`);

  // 12. Print concise summary
  console.log("\n=== CAPTURED ENDPOINT SUMMARY ===\n");
  for (const key of sortedKeys) {
    const ep = grouped[key];
    const status = ep.responseStatus ? ` → ${ep.responseStatus}` : "";
    const count = ep.count > 1 ? ` (×${ep.count})` : "";
    console.log(`  ${ep.method} ${ep.pathname}${status}${count}`);
  }
  console.log(`\nTotal unique API endpoint groups: ${sortedKeys.length}`);

  // 13. Close browser
  await browser.close();
  console.log("[capture] Done.");
}

main().catch((err) => {
  console.error("\n[capture] FATAL:", err.message);
  process.exit(1);
});
