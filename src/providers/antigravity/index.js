"use strict";

const crypto = require("crypto");
const { BaseProvider } = require("../../base/provider");
const { safeUrl } = require("../../services/browser");

/**
 * Antigravity provider — automates Google OAuth account registration against
 * the 9router OAuth bridge.
 *
 * Flow (faithful port of the working reference bot.js):
 *   1. GET /api/oauth/antigravity/authorize?redirect_uri=<callbackUrl>
 *      -> { authUrl, codeVerifier, state, codeChallenge, redirectUri, ... }
 *   2. Browser automation: open authUrl, log into Google (email + password),
 *      handle consent / TOS / native-app / challenge pages, capture the
 *      OAuth `code` from the /callback?code= redirect via a frame-navigation
 *      listener.
 *   3. POST /api/oauth/antigravity/exchange { code, redirectUri, codeVerifier, state }
 *      -> 9router stores the connection and returns the token block.
 *
 * The PKCE fields (`codeVerifier`, `state`) are carried from the authorize
 * response through to the exchange — omitting them is what broke the previous
 * implementation.
 */
class AntigravityProvider extends BaseProvider {
  static get providerName() {
    return "antigravity";
  }

  static get endpoints() {
    return {
      authorize: "/api/oauth/antigravity/authorize",
      exchange: "/api/oauth/antigravity/exchange",
      provider: "/api/providers",
    };
  }

  /**
   * Call the 9router API with the reference's error semantics.
   *
   * Wraps BaseProvider.apiCall to:
   *   - JSON-stringify an object body (the underlying HTTP layer writes raw strings)
   *   - throw on HTTP >= 400 with the server's error message
   *   - return the parsed response body directly (not the {statusCode, headers, body} envelope)
   *
   * @param {string} method - HTTP method.
   * @param {string} path - Request path.
   * @param {object|null} [body] - JSON-serializable request body (null for GET/DELETE).
   * @returns {Promise<any>} Parsed response body.
   */
  async _apiCall(method, path, body) {
    const bodyStr = body !== null && body !== undefined ? JSON.stringify(body) : null;
    const res = await this.apiCall(method, path, bodyStr);
    if (res.statusCode >= 400) {
      const msg = res.body && res.body.error ? res.body.error : `HTTP ${res.statusCode}`;
      throw new Error(`${msg} (at ${method} ${path})`);
    }
    return res.body;
  }

  /**
   * Build the OAuth redirect_uri (the callback URL Google redirects back to).
   *
   * This is 9router's `/callback` path on the SAME host as the API — NOT an
   * arbitrary connection host. In local mode that is
   * `http://localhost:20128/callback`. In remote mode the operator may set
   * `config.oauthCallbackUrl` explicitly to match Google's registered
   * callback for the 9router client.
   *
   * Ported from reference buildCallbackUrl (bot.js 58-60), which read
   * `config.oauthCallbackUrl`; our config does not carry that field so we
   * compute it from proto/host/port.
   *
   * @returns {string} The callback URL.
   */
  _buildCallbackUrl() {
    if (this.config.oauthCallbackUrl) return this.config.oauthCallbackUrl;
    const proto = this.config.proto || "http";
    const host = this.config.host || "localhost";
    const port = this.config.port || 20128;
    return `${proto}://${host}:${port}/callback`;
  }

  /**
   * Execute the Antigravity account creation flow.
   *
   * Mirrors the reference's automateGoogleLogin (browser command):
   * request the authorize URL (with PKCE), run the Google OAuth browser
   * flow to capture the code, exchange the code for tokens. 9router stores
   * the resulting connection itself (with the access token); we do not
   * write to the local SQLite DB from this flow.
   *
   * @param {{email?: string, password?: string, name?: string}} credentials - Google account credentials.
   * @param {{proxy?: object, fingerprint?: object}} [options={}] - Run options.
   * @returns {Promise<{ok: boolean, id?: string, existing?: boolean, connection?: object}>}
   */
  async add(credentials, options = {}) {
    if (!credentials.email || !credentials.password) {
      throw new Error("Antigravity add requires email + password");
    }

    const callbackUrl = this._buildCallbackUrl();

    // 1. Request the authorize URL (GET with redirect_uri query param).
    //    Response carries the PKCE fields we must pass back at exchange time.
    const authData = await this._apiCall(
      "GET",
      `${this.constructor.endpoints.authorize}?redirect_uri=${encodeURIComponent(callbackUrl)}`,
    );
    if (!authData.authUrl) {
      throw new Error("Authorize response missing authUrl");
    }
    console.log(
      `[${credentials.email}] Authorize URL received (codeVerifier length ${String(authData.codeVerifier || "").length})`,
    );

    // 2. Browser flow: Google login + capture the OAuth code from /callback redirect.
    const browserResult = await this.automateGoogleLogin(authData, credentials, options);

    // Already-connected short-circuit: the page landed on /dashboard or /settings,
    // meaning a prior session already linked this account.
    if (browserResult.existing) {
      console.log(`[${credentials.email}] Account already linked (session exists)`);
      return { ok: true, existing: true };
    }

    // 3. Exchange the code for tokens. All four PKCE fields are required.
    console.log(`[${credentials.email}] Exchanging OAuth code...`);
    const exchangeResult = await this._apiCall("POST", this.constructor.endpoints.exchange, {
      code: browserResult.code,
      redirectUri: callbackUrl,
      codeVerifier: authData.codeVerifier,
      state: browserResult.state || authData.state,
    });
    console.log(`[${credentials.email}] Exchange complete`);

    // 9router stores the connection itself via the exchange endpoint (with the
    // access token). We must NOT injectToDb here in local mode — doing so
    // creates a duplicate row WITHOUT the token (the exchange response does
    // not return it; only 9router holds it internally). list/inspect/delete
    // read 9router's row directly via core/db.
    return { ok: true, connection: exchangeResult };
  }

  // ============================================================
  // GOOGLE OAUTH BROWSER AUTOMATION
  // ============================================================

  /**
   * Drive the Antigravity OAuth flow via Google login.
   *
   * Opens the Google authorization URL, logs in with email + password,
   * handles the post-login pages (native-app confirm, consent, Workspace
   * TOS / speedbump, rejection detection), pre-warms the Cloud Console so
   * Google registers the account as a GCP user before 9router onboards it,
   * then waits for the /callback redirect that carries the OAuth code.
   *
   * The code is captured from BOTH a frame-navigation listener and a load
   * listener (belt + suspenders), because Google sometimes delivers the
   * redirect as a top-level navigation and sometimes inside a frame.
   *
   * Ported from reference automateGoogleLogin (bot.js 169-695).
   *
   * @param {object} authData - Authorize response (must include authUrl).
   * @param {{email: string, password: string}} credentials - Google account credentials.
   * @param {{proxy?: object, fingerprint?: object}} [options={}] - Run options (unused for this flow; kept for API parity).
   * @returns {Promise<{code: string, state?: string}|{existing: true}>} Captured OAuth code+state, or `{existing:true}` if already linked.
   */
  async automateGoogleLogin(authData, credentials, options = {}) {
    const { email, password } = credentials;
    console.log(`\n[${email}] Starting Antigravity OAuth flow...`);

    // Launch WITHOUT a url: the reference attaches the /callback frame
    // listener BEFORE navigating, because Google can in rare cases redirect
    // straight to /callback during the initial load (already-authorized +
    // no consent). Passing `url` to launchBrowser would navigate first and
    // miss that one-shot redirect. We navigate manually after the listeners
    // are wired, matching the reference's ordering.
    console.log(`[${email}] 1/5 Launching browser...`);
    const { browser, page } = await this.launchBrowser({});

    /** Captured from the /callback redirect. */
    let code = null;
    let state = null;
    let callbackUrl = null;

    try {
      console.log(`[${email}] 2/5 Listening for /callback redirect...`);

      // Frame navigation listener: Google sometimes delivers the OAuth
      // redirect inside a child frame. Match both /callback?code= and
      // /callback?token= (the reference handles both).
      page.on("framenavigated", async (frame) => {
        try {
          const frameUrl = frame.url();
          if (
            frameUrl &&
            (frameUrl.includes("/callback?code=") ||
              frameUrl.includes("/callback?token="))
          ) {
            callbackUrl = frameUrl;
            const url = new URL(callbackUrl);
            const captured =
              url.searchParams.get("code") || url.searchParams.get("token");
            const capturedState = url.searchParams.get("state");
            if (captured) {
              code = captured;
              state = capturedState;
              console.log(
                `[${email}]    OAuth code captured from frame redirect (length ${code.length})`,
              );
            }
          }
        } catch {
          // Frame URL reads can throw during teardown — ignore.
        }
      });

      // Load listener: backup capture path for top-level navigations.
      page.on("load", () => {
        try {
          const url = page.url();
          if (url && url.includes("/callback")) {
            const urlObj = new URL(url);
            const captured =
              urlObj.searchParams.get("code") || urlObj.searchParams.get("token");
            const capturedState = urlObj.searchParams.get("state");
            if (captured) {
              callbackUrl = url;
              code = captured;
              state = capturedState;
              console.log(
                `[${email}]    OAuth code captured from load event (length ${code.length})`,
              );
            }
          }
        } catch {
          // Ignore — page may have navigated away already.
        }
      });

      // Step 3: Navigate to the Google authorization URL NOW that the
      // listeners are wired. networkidle0 matches the reference's waitUntil
      // (the default launchBrowser uses networkidle2; we override here for
      // parity with the reference's Google-login behavior).
      console.log(`[${email}] 3/5 Navigating to Google login...`);
      await page.goto(authData.authUrl, { waitUntil: "networkidle0", timeout: 30000 });
      await new Promise((r) => setTimeout(r, 2000));

      // === GOOGLE LOGIN AUTOMATION ===
      // Handle the common cases: email -> password -> post-login redirects.
      let currentUrl = safeUrl(page);
      if (
        currentUrl.includes("accounts.google.com") ||
        currentUrl.includes("google.com/o/oauth2")
      ) {
        // --- EMAIL STEP ---
        // Google's signin page: email lives in input#identifierId (type="text",
        // NOT type="email" as a naive port would assume).
        const emailField = await page
          .waitForSelector("#identifierId", { timeout: 15000 })
          .catch(() => null);
        if (emailField) {
          console.log(`[${email}]    Entering email...`);
          await new Promise((r) => setTimeout(r, 500));
          await emailField.type(email, { delay: 60 });
          await new Promise((r) => setTimeout(r, 1000));

          // Click the "Next" button. Prefer the known selector, fall back to Enter.
          const nextBtn = await page.$(
            '#identifierNext button, button[jsname="V67aGc"], div[role="button"][jsname="V67aGc"]',
          );
          if (nextBtn) {
            try {
              await page.evaluate((el) => el.click(), nextBtn);
            } catch {
              await page.keyboard.press("Enter");
            }
          } else {
            await page.keyboard.press("Enter");
          }
          console.log(`[${email}]    Email submitted, waiting for password page...`);

          // Wait for the email field to disappear (transition to password page).
          await page
            .waitForFunction(() => !document.querySelector("#identifierId"), {
              timeout: 15000,
            })
            .catch(() => {});
          await new Promise((r) => setTimeout(r, 2000));
        }

        // --- PASSWORD STEP ---
        // The visible password field appears only AFTER email submission.
        // (Google keeps a hidden name="hiddenPassword" in the DOM earlier, so
        // we wait for a visible one via the default visible check.)
        const pwField = await page
          .waitForSelector('input[type="password"]', { timeout: 15000 })
          .catch(() => null);
        if (pwField && password) {
          console.log(`[${email}]    Entering password...`);
          await new Promise((r) => setTimeout(r, 500));
          await pwField.type(password, { delay: 40 });
          await new Promise((r) => setTimeout(r, 1000));

          try {
            const pwNextBtn = await page.$(
              '#passwordNext button, button[jsname="V67aGc"], div[role="button"][jsname="V67aGc"]',
            );
            if (pwNextBtn) {
              await page.evaluate((el) => el.click(), pwNextBtn);
            } else {
              await page.keyboard.press("Enter");
            }
          } catch {
            await page.keyboard.press("Enter");
          }
          console.log(`[${email}]    Password submitted, waiting for redirect...`);
          await new Promise((r) => setTimeout(r, 5000));
        }

        // --- POST-LOGIN PAGE LOOP ---
        // Google may show (in any order): a native-app "Sign in" confirm,
        // an OAuth consent screen, a Workspace TOS / speedbump. Loop for up
        // to 30s, clicking through each. A button click on one iteration
        // triggers a navigation; the next iteration's page.evaluate can then
        // run against a destroyed execution context — recover by waiting and
        // retrying (the callback check at the top of the loop runs first).
        const postLoginTimeout = Date.now() + 30000;
        while (Date.now() < postLoginTimeout) {
          currentUrl = safeUrl(page);
          const pageTitle = await page.title().catch(() => "");

          if (
            currentUrl.includes("/callback?") ||
            currentUrl.includes("/callback#")
          ) {
            // Redirected to 9router callback — done.
            break;
          }

          // Collect visible button labels. An earlier click may have destroyed
          // the execution context mid-navigation; wait and retry.
          let buttons = [];
          try {
            buttons = await page.evaluate(() => {
              return Array.from(
                document.querySelectorAll(
                  'button, div[role="button"], a[role="button"]',
                ),
              )
                .map((b) => b.innerText.trim())
                .filter((t) => t.length > 0 && t.length < 50);
            });
          } catch (e) {
            if (
              /Execution context|Target closed|Session closed|navigation/i.test(
                e.message,
              )
            ) {
              await new Promise((r) => setTimeout(r, 1500));
              continue;
            }
            throw e;
          }

          const actions = [];

          // Native-app confirmation page: a standalone "Sign in" button.
          if (
            currentUrl.includes("/firstparty/nativeapp") ||
            buttons.includes("Sign in")
          ) {
            const signInBtn = await page.evaluate(() => {
              const btns = Array.from(document.querySelectorAll("button"));
              const b = btns.find((x) => x.innerText.trim() === "Sign in");
              if (b) {
                b.click();
                return true;
              }
              return false;
            });
            if (signInBtn) actions.push("Sign in (native app)");
          }

          // OAuth consent screen: "Continue" / "Allow" (+ locale variants).
          if (
            currentUrl.includes("/consent") ||
            buttons.some((t) =>
              [
                "Continue",
                "Allow",
                "Izinkan",
                "Lanjutkan",
                "Setujui",
                "Konfirmasi",
              ].includes(t),
            )
          ) {
            const consentClicked = await page.evaluate(() => {
              const btns = Array.from(document.querySelectorAll("button"));
              const continueBtn = btns.find((b) =>
                [
                  "Continue",
                  "Allow",
                  "Izinkan",
                  "Lanjutkan",
                  "Setujui",
                  "Konfirmasi",
                ].includes(b.innerText.trim()),
              );
              if (continueBtn) {
                continueBtn.click();
                return true;
              }
              // Fallback: old Google consent button id.
              const oldConsent = document.querySelector("#submit_approve_access");
              if (oldConsent) {
                oldConsent.click();
                return true;
              }
              return false;
            });
            if (consentClicked) actions.push("Consent/Continue");
          }

          // Workspace TOS / speedbump: may need a checkbox tick + scroll
          // before the Accept button enables.
          if (
            currentUrl.includes("/speedbump/") ||
            currentUrl.includes("/terms")
          ) {
            const ssPath = `/tmp/agy-tos-${Date.now()}.png`;
            await page.screenshot({ path: ssPath }).catch(() => {});
            console.log(`[${email}]    TOS page detected, screenshot: ${ssPath}`);

            // Tick the agreement checkbox if present.
            const hasCheckbox = await page.evaluate(() => {
              const cb = document.querySelector(
                'input[type="checkbox"], div[role="checkbox"]',
              );
              if (cb && !cb.checked) {
                cb.click();
                return true;
              }
              return false;
            });
            if (hasCheckbox) {
              console.log(`[${email}]    TOS checkbox clicked`);
              await new Promise((r) => setTimeout(r, 1000));
            }

            // Scroll the TOS content to the bottom (some TOS pages require
            // this to enable the accept button). Guard against a mid-
            // navigation state where document.body is null.
            try {
              await page.evaluate(() => {
                if (!document || !document.body) return;
                const scrollContainer = document.querySelector(
                  '.terms-scroll, [role="document"], .tos-scroll, .signed-out, main, article, section, div[jsname], div[jscontroller]',
                );
                if (
                  scrollContainer &&
                  typeof scrollContainer.scrollHeight === "number"
                ) {
                  scrollContainer.scrollTop = scrollContainer.scrollHeight;
                }
                window.scrollTo(0, document.body.scrollHeight);
              });
            } catch (e) {
              if (
                !/Execution context|Target closed|Session closed|navigation/i.test(
                  e.message,
                )
              ) {
                throw e;
              }
            }
            await new Promise((r) => setTimeout(r, 2000));

            const tosClicked = await page.evaluate(() => {
              const btns = Array.from(
                document.querySelectorAll(
                  'button, div[role="button"], a[role="button"]',
                ),
              );
              const labels = [
                "Accept",
                "Agree",
                "I understand",
                "Continue",
                "Saya Setuju",
                "Setuju",
                "Lanjutkan",
                "Saya mengerti",
                "Konfirmasi",
              ];
              // Prefer an enabled, visible button.
              const acceptBtn = btns.find(
                (b) =>
                  labels.includes(b.innerText.trim()) &&
                  !b.disabled &&
                  b.offsetParent !== null,
              );
              if (acceptBtn) {
                acceptBtn.click();
                return true;
              }
              // Fallback: any matching button (even if disabled).
              const fallbackBtn = btns.find((b) =>
                labels.includes(b.innerText.trim()),
              );
              if (fallbackBtn) {
                fallbackBtn.click();
                return true;
              }
              return false;
            });
            if (tosClicked) actions.push("Accept TOS");
            else console.log(`[${email}]    No TOS accept button found`);
          }

          if (actions.length > 0) {
            console.log(`[${email}]    ${actions.join(", ")}`);
            // The click triggers a Google navigation; give it time to settle
            // so the next iteration's page reads don't hit a destroyed context.
            await new Promise((r) => setTimeout(r, 2500));
          }

          // No action taken and still on Google: could be a security
          // challenge, wrong password, CAPTCHA, etc. Detect the
          // "couldn't sign you in" rejection and bail with a screenshot.
          if (
            actions.length === 0 &&
            currentUrl.includes("accounts.google.com")
          ) {
            const bodyText = await page
              .evaluate(() => document.body.innerText.substring(0, 200))
              .catch(() => "");
            if (
              bodyText.includes("Couldn't sign you in") ||
              bodyText.includes("could not be found")
            ) {
              const ssPath = `/tmp/agy-rejected-${Date.now()}.png`;
              await page.screenshot({ path: ssPath }).catch(() => {});
              console.log(
                `[${email}]    Google rejected sign-in! Screenshot: ${ssPath}`,
              );
              throw new Error(
                "Google rejected sign-in (wrong password, CAPTCHA, or verification required).",
              );
            }
          }

          await new Promise((r) => setTimeout(r, 1000));
        }

        // --- PRE-WARM: visit the Cloud Console in a new tab so Google
        // registers the account as a GCP user before 9router's onboardUser
        // fires. The shared browser context carries cookies/identity over.
        // All wrapped: pre-warm must never break the main OAuth flow.
        try {
          const warmPage = await browser.newPage();
          console.log(
            `[${email}]    Pre-warm: visiting console.cloud.google.com...`,
          );
          await warmPage.goto("https://console.cloud.google.com/", {
            waitUntil: "domcontentloaded",
            timeout: 15000,
          });
          await new Promise((r) => setTimeout(r, 2000));
          await warmPage
            .evaluate(() => {
              const labels = ["Agree & continue", "I agree", "Setuju", "Accept"];
              const btns = Array.from(
                document.querySelectorAll("button, a, div[role='button']"),
              );
              for (const t of labels) {
                const b = btns.find((el) => el.innerText.trim() === t);
                if (b) {
                  b.click();
                  return true;
                }
              }
              return false;
            })
            .catch(() => {});
          // A brief visit is enough to register account activity.
          await new Promise((r) => setTimeout(r, 3000));
          await warmPage.close().catch(() => {});
          console.log(`[${email}]    Pre-warm done`);
        } catch (e) {
          console.log(
            `[${email}]    Pre-warm skipped (${e.message.split("\n")[0]})`,
          );
        }
      }

      // --- WAIT FOR THE /callback REDIRECT (max 120s) ---
      console.log(
        `[${email}] 4/5 Waiting for redirect to 9router callback (max 120s)...`,
      );
      const maxWait = 120000;
      const checkInterval = 2000;
      let waited = 0;
      let lastLogUrl = "";
      let existing = false;

      while (!code && waited < maxWait) {
        try {
          currentUrl = safeUrl(page);

          // Log URL changes — strip the query string (may carry tokens).
          if (currentUrl !== lastLogUrl) {
            const title = await page.title().catch(() => "?");
            console.log(
              `[${email}]    URL: ${currentUrl.split("?")[0].slice(0, 100)} | Title: ${title.substring(0, 60)}`,
            );
            lastLogUrl = currentUrl;
          }

          if (currentUrl.includes("/callback?")) {
            callbackUrl = currentUrl;
            const urlObj = new URL(currentUrl);
            const captured =
              urlObj.searchParams.get("code") || urlObj.searchParams.get("token");
            state = urlObj.searchParams.get("state");
            if (captured) {
              code = captured;
              console.log(`[${email}]    OAuth code captured from page URL!`);
              break;
            }
          }

          // Already-linked short-circuit: landed on the dashboard/settings.
          if (
            currentUrl.includes("/dashboard") ||
            currentUrl.includes("/settings")
          ) {
            console.log(
              `[${email}]    Already on 9router dashboard (account previously linked)`,
            );
            existing = true;
            break;
          }

          // Debug screenshot every 15s.
          if (waited > 0 && waited % 15000 === 0) {
            const ssPath = `/tmp/9router-agy-${Date.now()}.png`;
            await page
              .screenshot({ path: ssPath, fullPage: false })
              .catch(() => {});
            console.log(`[${email}]    Screenshot: ${ssPath}`);
          }
        } catch {
          // Page may have closed or navigated — retry on the next tick.
        }

        await new Promise((r) => setTimeout(r, checkInterval));
        waited += checkInterval;
      }

      if (existing) {
        return { existing: true };
      }

      if (!code) {
        throw new Error(
          `Timeout: no redirect to callback within ${maxWait / 1000}s`,
        );
      }

      console.log(`[${email}] 5/5 OAuth code captured; ready for exchange.`);
      return { code, state };
    } catch (err) {
      console.error(`[${email}] Failed: ${err.message}`);
      throw err;
    } finally {
      // Always close the browser. Close all pages first so any pending
      // navigations don't keep the process alive.
      try {
        const pages = await browser.pages();
        await Promise.all(pages.map((p) => p.close()));
        await browser.close();
        console.log(`[${email}]    Browser closed`);
      } catch {
        // Ignore close errors during teardown.
      }
    }
  }

  /**
   * Quota pre-check hook. Skips add() when the email's domain has already
   * hit its per-UTC-day cap. Mirrors the kiro provider's quota handling.
   *
   * @param {{email?: string}} credentials - Account credentials.
   * @param {object} [options] - Run options.
   * @returns {Promise<{skip?: boolean, reason?: string}|void>}
   */
  async beforeAdd(credentials, options) {
    const { quota } = this.services;
    if (quota && credentials.email) {
      const cap =
        (this.config.providerConfig && this.config.providerConfig.quotaCap) || 3;
      const { allowed } = quota.tryConsume(
        this.config.quotaFile || ".batch-stats.json",
        credentials.email,
        cap,
      );
      if (!allowed) {
        return {
          skip: true,
          reason: `Quota cap (${cap}/day) reached for ${credentials.email}`,
        };
      }
    }
  }

  /**
   * Inspect a connection by ID. Uses GET /api/providers/:id (remote mode) or
   * a direct DB lookup (local mode).
   *
   * Ported from reference inspect (bot.js 717) / listAccountsRemote (708).
   *
   * @param {string} id - Connection ID.
   * @returns {Promise<object|null>}
   */
  async inspect(id) {
    if (this.config.mode === "local") {
      const { findById } = require("../../core/db");
      return findById(this.config, id);
    }
    return this._apiCall(
      "GET",
      `${this.constructor.endpoints.provider}/${encodeURIComponent(id)}`,
    );
  }

  /**
   * Delete a connection by ID. Uses DELETE /api/providers/:id (remote mode)
   * or a direct DB delete (local mode).
   *
   * Ported from reference deleteAccountCmd (bot.js 800).
   *
   * @param {string} id - Connection ID.
   * @returns {Promise<void>}
   */
  async delete(id) {
    if (this.config.mode === "local") {
      const { del } = require("../../core/db");
      await del(this.config, id);
      return;
    }
    await this._apiCall(
      "DELETE",
      `${this.constructor.endpoints.provider}/${encodeURIComponent(id)}`,
    );
  }
}

module.exports = AntigravityProvider;
