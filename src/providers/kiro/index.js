"use strict";

const crypto = require("crypto");
const { BaseProvider } = require("../../base/provider");
const {
  safeUrl,
  lang,
  clickByText,
  clickBySelector,
  dismissCookieBanner,
  clickPrimaryButton,
  clickPrimaryButtonMouse,
  focusPage,
  randomRealisticName,
  reactTypeInput,
} = require("../../services/browser");

/**
 * Kiro provider — automates Kiro AI account registration against the
 * 9router OAuth bridge.
 *
 * Flow (mirrors the working reference bot.js):
 *   1. GET /api/oauth/kiro/device-code  -> device_code + verification_uri_complete
 *   2. Browser automation:
 *      - google method: Google OAuth login on the AWS device page
 *      - email method:  AWS Builder ID registration (alias + name + OTP + password)
 *   3. POST /api/oauth/kiro/poll {deviceCode, extraData} until result.success
 *   4. PUT /api/providers/:id {name} to rename the connection
 *
 * The provider auto-selects the method based on the email domain:
 *   - @gmail.com -> google
 *   - anything else -> email (requires IMAP config to read the OTP)
 */
class KiroProvider extends BaseProvider {
  static get providerName() {
    return "kiro";
  }

  static get endpoints() {
    return {
      deviceCode: "/api/oauth/kiro/device-code",
      poll: "/api/oauth/kiro/poll",
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
   * Execute the Kiro account creation flow.
   *
   * Mirrors the reference's processAccount(): request a device code, launch
   * the appropriate browser flow (google or email), poll 9router until the
   * connection is stored, then rename it. In local mode the connection is
   * also inserted into the SQLite DB.
   *
   * @param {{email?: string, password?: string, name?: string}} credentials - Account credentials.
   * @param {{proxy?: object, fingerprint?: object, accountIndex?: number, generateAlias?: boolean, aliasDomain?: string}} [options={}] - Run options.
   * @returns {Promise<{ok: boolean, id?: string, connection?: object}>}
   */
  async add(credentials, options = {}) {
    const method = this.detectMethod(credentials.email);

    // 1. Request device code (GET — no body).
    const deviceData = await this._apiCall("GET", this.constructor.endpoints.deviceCode);
    console.log(`[${credentials.email}] Device code received (length ${String(deviceData.user_code || "").length})`);

    // 2-3. Run the appropriate browser flow.
    let resolvedEmail = credentials.email;
    if (method === "google") {
      if (!credentials.email || !credentials.password) {
        throw new Error("Method 'google' requires email + password");
      }
      await this.automateGoogleLogin(deviceData, credentials, options);
      resolvedEmail = credentials.email;
    } else {
      // email method requires IMAP credentials.
      if (!this.config.imap || !this.config.imap.user || !this.config.imap.password) {
        throw new Error(
          "Method 'email' requires IMAP config (imap.user + imap.password). Set the 'imap' block in config.json."
        );
      }
      const result = await this.automateEmailLogin(deviceData, credentials, options);
      resolvedEmail = result.email || credentials.email;
    }

    // 4. Poll until 9router stores the connection (includes rename step).
    const pollResult = await this.pollUntilConnected(deviceData, resolvedEmail);

    // 5. Local mode: mirror into the SQLite DB.
    if (this.config.mode === "local") {
      const dbResult = await this.injectToDb({
        provider: "kiro",
        authType: method,
        name: resolvedEmail,
        email: resolvedEmail,
        data: pollResult,
      });
      return { ok: true, ...dbResult };
    }

    return { ok: true, ...pollResult };
  }

  /**
   * Choose the registration method based on the email's domain.
   *
   * @param {string} [email] - Account email.
   * @returns {"google"|"email"} "google" for @gmail.com, otherwise "email".
   */
  detectMethod(email) {
    if (!email) return "email";
    return email.toLowerCase().endsWith("@gmail.com") ? "google" : "email";
  }

  // ============================================================
  // GOOGLE OAUTH AUTOMATION
  // ============================================================

  /**
   * Drive the Kiro OAuth flow via Google login.
   *
   * Opens the AWS verification URL, clicks "Continue with Google",
   * submits email + password on accounts.google.com, then polls the
   * resulting device-confirmation / consent / agreement pages until
   * the device is approved.
   *
   * Ported from reference automateKiroGoogleLogin (bot.js 419-658).
   *
   * @param {object} deviceData - Device-code response (must include verification_uri_complete).
   * @param {{email: string, password: string}} credentials - Google account credentials.
   * @param {object} [options] - Run options (unused for google flow; kept for API parity).
   * @returns {Promise<boolean>} Resolves true when the device is approved; throws on rejection/timeout.
   */
  async automateGoogleLogin(deviceData, credentials, options = {}) {
    const { email, password } = credentials;
    console.log(`\n[${email}] Starting Kiro OAuth flow...`);

    console.log(`[${email}] 1/5 Launching browser...`);
    const { browser, page } = await this.launchBrowser({
      url: deviceData.verification_uri_complete,
    });

    let approved = false;

    try {
      console.log(`[${email}] 2/5 Opened AWS verification page...`);
      await new Promise((r) => setTimeout(r, 3000));

      console.log(`[${email}] 3/5 Click 'Continue with Google'...`);
      let clicked = await clickByText(page, ["Continue with Google"]);
      if (!clicked) {
        // Fallback: locate a Google button/link by attribute.
        const googleFallback = await page.$(
          "a[href*='google'], button[data-provider='google']"
        );
        if (googleFallback) await googleFallback.click();
      }
      await new Promise((r) => setTimeout(r, 5000));

      console.log(`[${email}] 4/5 Automated Google login...`);
      const currentUrl = safeUrl(page);
      if (currentUrl.includes("accounts.google.com")) {
        const emailField = await page
          .waitForSelector("#identifierId", { timeout: 15000 })
          .catch(() => null);
        if (emailField) {
          console.log(`[${email}]    Entering email...`);
          await emailField.type(email, { delay: 60 });
          await new Promise((r) => setTimeout(r, 1000));
          await page.keyboard.press("Enter");
          await new Promise((r) => setTimeout(r, 4000));
        }

        const pwField = await page
          .waitForSelector('input[type="password"]', { timeout: 15000 })
          .catch(() => null);
        if (pwField) {
          console.log(`[${email}]    Entering password...`);
          await pwField.type(password, { delay: 40 });
          await new Promise((r) => setTimeout(r, 1000));
          await page.keyboard.press("Enter");
          await new Promise((r) => setTimeout(r, 6000));
        }
      }

      console.log(`[${email}] 5/5 Waiting for device approval & consent (max 120s)...`);
      const maxWait = 120000;
      const checkInterval = 3000;
      let waited = 0;
      let lastLogUrl = "";

      while (waited < maxWait) {
        const url = safeUrl(page);
        const body = await page.evaluate(() => document.body.innerText).catch(() => "");

        if (url !== lastLogUrl) {
          console.log(`[${email}]    URL: ${url.split("?")[0].slice(0, 100)}`);
          lastLogUrl = url;
        }

        let sel = null;

        if (body.includes("Authorization requested") || body.includes("Confirm this code")) {
          console.log(`[${email}]    Device-code confirmation page detected`);
          sel = await clickByText(page, ["Confirm and continue"]);
          if (!sel) sel = await clickBySelector(page, 'button[class*="primary" i]');
          if (!sel) sel = await clickPrimaryButton(page);
        } else if (body.includes("Allow kiro-oauth-client") || body.includes("access your data")) {
          console.log(`[${email}]    Kiro consent page detected`);
          sel = await clickByText(page, ["Allow access", "Allow"]);
          if (!sel) sel = await clickBySelector(page, 'button[class*="allow" i]');
          if (!sel) sel = await clickPrimaryButton(page);
        } else if (
          url.includes("view.awsapps.com") &&
          (body.includes("AWS Customer Agreement") ||
            body.includes("AWS Builder ID") ||
            body.includes("Accept agreement") ||
            body.includes("Accept terms") ||
            body.includes("Accept Terms") ||
            body.includes("confirm agreement") ||
            body.includes("user agreement"))
        ) {
          console.log(`[${email}]    AWS agreement/TOS page detected`);
          // Scroll the agreement container to the bottom before accepting.
          await page
            .evaluate(() => {
              const containers = Array.from(document.querySelectorAll("div, section, article"));
              const box = containers.find((el) => {
                const style = window.getComputedStyle(el);
                return (
                  (style.overflowY === "auto" || style.overflowY === "scroll") &&
                  el.scrollHeight > el.clientHeight
                );
              });
              if (box) {
                box.scrollTop = box.scrollHeight;
              } else {
                window.scrollTo(0, document.body.scrollHeight);
              }
            })
            .catch(() => {});
          await new Promise((r) => setTimeout(r, 800));

          // Tick the agreement checkbox if one is present.
          const checkbox = await page.$(
            'input[type="checkbox"][name*="agree" i], input[type="checkbox"][id*="agree" i], input[type="checkbox"][id*="terms" i], input[type="checkbox"][id*="accept" i]'
          );
          if (checkbox) {
            await checkbox.click().catch(() => {});
            await new Promise((r) => setTimeout(r, 500));
          }

          sel = await clickByText(page, [
            "Accept and continue",
            "Agree and continue",
            "I agree",
            "Accept terms",
            "Accept agreement",
            "Accept",
            "Agree",
            "Confirm",
            "Continue",
          ]);
          if (!sel) {
            sel = await clickBySelector(
              page,
              'button[class*="accept" i], button[class*="agree" i], button[class*="primary" i]'
            );
          }
          if (!sel) sel = await clickPrimaryButton(page);
        } else if (
          url.includes("workspacetermsofservice") ||
          (url.includes("accounts.google.com") &&
            (body.includes("Workspace Terms of Service") ||
              body.includes("Google Workspace Terms") ||
              body.includes("I agree to the Workspace Terms") ||
              body.includes("I accept the Terms")))
        ) {
          console.log(`[${email}]    Google Workspace Terms of Service page detected`);
          // Google Workspace ToS buttons are usually "I understand" / "I accept".
          sel = await clickByText(page, [
            "I understand",
            "I accept",
            "I agree",
            "Accept",
            "Agree",
            "Continue",
            "Aceptar",
            "Acepto",
            "Aceitar",
            "Accetto",
            "J'accepte",
          ]);
          if (!sel) {
            // Fallback: click any button whose class hints at submit/primary/accept/agree.
            sel = await page.evaluate(() => {
              const buttons = Array.from(
                document.querySelectorAll("button, input[type='submit']")
              );
              for (const b of buttons) {
                if (b.disabled) continue;
                const cls = (b.className || "").toString().toLowerCase();
                if (
                  cls.includes("submit") ||
                  cls.includes("primary") ||
                  cls.includes("accept") ||
                  cls.includes("agree") ||
                  b.type === "submit"
                ) {
                  b.click();
                  return (b.innerText || b.value || "submit") + " (submit)";
                }
              }
              return null;
            });
          }
          if (!sel) sel = await clickBySelector(page, 'button[type="submit"], input[type="submit"]');
          if (!sel) sel = await clickPrimaryButton(page);
        } else if (url.includes("accounts.google.com") && url.includes("challenge/pwd")) {
          // Google password challenge: don't click anything preemptively.
          // Only press Enter when the password field already has focus
          // (i.e. the user/automation has finished typing).
          const pwdActive = await page.$('input[type="password"]:focus');
          if (pwdActive) {
            await page.keyboard.press("Enter");
          }
        } else if (url.includes("accounts.google.com")) {
          // Google consent pages.
          sel = await clickByText(page, ["Continue", "Allow"]);
        }

        if (sel) console.log(`[${email}]    Clicked: ${sel}`);

        if (
          body.includes("Request approved") ||
          body.includes("You can close this window") ||
          body.includes("device approved")
        ) {
          console.log(`[${email}] Device approved!`);
          approved = true;
          break;
        }

        // Detect a rejected sign-in.
        if (body.includes("Couldn't sign you in") || body.includes("could not be found")) {
          const ssPath = `/tmp/kiro-rejected-${Date.now()}.png`;
          await page.screenshot({ path: ssPath }).catch(() => {});
          throw new Error(`Google rejected sign-in for ${email}. Screenshot: ${ssPath}`);
        }

        await new Promise((r) => setTimeout(r, checkInterval));
        waited += checkInterval;
      }

      if (!approved) {
        throw new Error(`Timeout: Device not approved within ${maxWait / 1000}s`);
      }
    } catch (err) {
      console.error(`[${email}] Failed: ${err.message}`);
      throw err;
    } finally {
      try {
        const pages = await browser.pages();
        await Promise.all(pages.map((p) => p.close()));
        await browser.close();
        console.log(`[${email}]    Browser closed`);
      } catch {
        // ignore
      }
    }

    return approved;
  }

  // ============================================================
  // EMAIL / AWS BUILDER ID AUTOMATION
  // ============================================================

  /**
   * Drive the Kiro OAuth flow via AWS Builder ID email registration.
   *
   * Opens the AWS verification URL, picks "Sign in with email", submits
   * the alias address, fills the display name, waits for the AWS OTP via
   * IMAP, submits the OTP, sets the account password, then polls the
   * device-confirmation + Kiro consent pages until the device is approved.
   *
   * Ported from reference automateKiroEmailLogin (bot.js 663-1461).
   *
   * @param {object} deviceData - Device-code response (must include verification_uri_complete).
   * @param {{email: string, password?: string, name?: string}} credentials - Alias + optional name/password.
   * @param {{proxy?: object, fingerprint?: object, accountIndex?: number}} [options={}] - Run options.
   * @returns {Promise<{approved: boolean, email: string}>} Resolves with the resolved email when approved; throws on failure.
   */
  async automateEmailLogin(deviceData, credentials, options = {}) {
    const account = credentials;
    const alias = account.email;
    if (!alias || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(alias)) {
      throw new Error(
        `Method 'email' requires a valid forwarder alias in the 'email' field (got: "${alias || ""}")`
      );
    }
    const label = alias;
    console.log(`\n[${label}] Starting Kiro OAuth flow (email via alias forwarder + IMAP)...`);

    // Resolve per-account proxy + fingerprint.
    const currentProxy = options.proxy || null;
    if (currentProxy) {
      console.log(
        `[${label}]    Proxy: ${currentProxy.protocol}://${currentProxy.host}:${currentProxy.port}${currentProxy.username ? " (auth)" : ""}`
      );
    }
    const fingerprint = options.fingerprint || null;
    if (fingerprint) {
      const chromeMatch = fingerprint.userAgent.match(/Chrome\/[\d.]+/);
      console.log(
        `[${label}]    Fingerprint: ${fingerprint.viewport.width}x${fingerprint.viewport.height}, ${chromeMatch ? chromeMatch[0] : "?"}, ${fingerprint.timezoneId}`
      );
    }

    const { browser, page } = await this.launchBrowser({
      url: deviceData.verification_uri_complete,
      proxy: currentProxy,
      fingerprint,
    });

    let approved = false;
    const resolvedEmail = alias;
    let submitTime = 0;

    try {
      console.log(`[${label}] 1/6 Opening AWS verification page...`);
      // Use domcontentloaded — networkidle2 never resolves for the AWS SPA.
      await page.goto(deviceData.verification_uri_complete, {
        waitUntil: "domcontentloaded",
        timeout: 45000,
      });
      // The AWS SPA is slow to render. Poll the body text until a button or
      // input appears, up to 30s.
      await page
        .waitForFunction(
          () => {
            const txt = (document.body.innerText || "").trim();
            if (txt.length < 5) return false;
            if (/continue with google|sign in with email|use my email/i.test(txt)) return true;
            const inputs = Array.from(
              document.querySelectorAll('input[type="email"], input[name="email"]')
            );
            if (inputs.length > 0 && inputs[0].offsetParent !== null) return true;
            // Fallback: wait for at least 200 chars of body text.
            return txt.length > 200;
          },
          { timeout: 30000, polling: 1500 }
        )
        .catch(() => null);
      await new Promise((r) => setTimeout(r, 2000));

      // Pick email sign-in.
      console.log(`[${label}] 2/6 Pick 'Sign in with email'...`);
      const ssStep2 = `/tmp/kiro-step2-${Date.now()}.png`;
      await page.screenshot({ path: ssStep2, fullPage: true }).catch(() => {});
      const pageState = await page.evaluate(() => ({
        url: location.href,
        title: document.title,
        bodyLen: (document.body.innerText || "").length,
        bodyPreview: (document.body.innerText || "").slice(0, 500),
        emailInputs: document.querySelectorAll(
          'input[type="email"], input[name="email"], input[autocomplete*="email" i]'
        ).length,
        buttons: Array.from(
          document.querySelectorAll("button, a, div[role='button'], span[role='button']")
        )
          .slice(0, 20)
          .map((b) => (b.innerText || b.textContent || "").trim())
          .filter((t) => t && t.length < 80),
      }));
      console.log(`[${label}]    step2 screenshot: ${ssStep2}`);
      console.log(`[${label}]    state: ${JSON.stringify(pageState)}`);
      const emailEntry = await page.evaluate(() => {
        const candidates = Array.from(
          document.querySelectorAll("button, a, div[role='button'], span[role='button']")
        );
        const patterns = [
          /sign in with email/i,
          /use my email/i,
          /continue with email/i,
          /email$/i,
          /email me a code/i,
        ];
        for (const el of candidates) {
          const t = (el.innerText || el.textContent || "").trim();
          if (!t) continue;
          if (patterns.some((p) => p.test(t))) {
            let target = el;
            while (
              target &&
              target.tagName !== "BUTTON" &&
              target.tagName !== "A" &&
              target.tagName !== "BODY"
            ) {
              target = target.parentElement;
            }
            if (target && target.tagName !== "BODY") {
              target.click();
              return t;
            }
            el.click();
            return t;
          }
        }
        return null;
      });
      if (!emailEntry) {
        // Fallback: look for a bare email input.
        const hasEmailInput = await page.$(
          'input[type="email"], input[name="email"], input[autocomplete*="email" i]'
        );
        if (!hasEmailInput) {
          const url = safeUrl(page);
          const body = await page
            .evaluate(() => document.body.innerText.slice(0, 500))
            .catch(() => "");
          const ss = `/tmp/kiro-aws-noemail-${Date.now()}.png`;
          await page.screenshot({ path: ss, fullPage: true }).catch(() => {});
          throw new Error(
            `Could not find a 'Sign in with email' option on the AWS page. URL: ${url.split("?")[0]} Body: ${body.replace(/\s+/g, " ").slice(0, 200)} Screenshot: ${ss}`
          );
        }
        console.log(`[${label}]    Email input field already present on page`);
      } else {
        console.log(`[${label}]    Clicked: ${emailEntry}`);
      }
      await new Promise((r) => setTimeout(r, 2000));

      // Alias is supplied via account.email (from caller).
      console.log(`[${label}] 3/6 Alias forwarder: ${alias} (OTP read via IMAP)`);

      // Submit the alias to AWS.
      console.log(`[${label}] 4/6 Submitting email to AWS Builder ID...`);
      await focusPage(page);
      await dismissCookieBanner(page);
      const emailInput = await page
        .waitForSelector(
          'input[type="email"], input[name="email"], input[autocomplete*="email" i]',
          { timeout: 15000 }
        )
        .catch(() => null);
      if (!emailInput) {
        const ssPath = `/tmp/kiro-email-input-${Date.now()}.png`;
        await page.screenshot({ path: ssPath }).catch(() => {});
        throw new Error(`Email input field not found. Screenshot: ${ssPath}`);
      }
      await emailInput.focus();
      await emailInput.type(alias, { delay: 60 });
      await new Promise((r) => setTimeout(r, 800));
      // Submit via button or Enter.
      let submitted = await clickByText(page, ["Next", "Continue", "Send code", "Submit"]);
      if (!submitted) {
        await page.keyboard.press("Enter");
      }
      // Wait for the AWS SPA to transition to the name step. It switches the
      // URL hash to /signup/enter-email OR shows a name input, up to 30s.
      await focusPage(page);
      await page
        .waitForFunction(
          () => {
            const hash = location.hash || "";
            if (/enter-email|enter-name/i.test(hash)) return true;
            const inputs = Array.from(document.querySelectorAll("input"));
            for (const inp of inputs) {
              if (inp.offsetParent === null) continue;
              const name = (inp.name || "").toLowerCase();
              const id = (inp.id || "").toLowerCase();
              const ac = (inp.getAttribute("autocomplete") || "").toLowerCase();
              const ph = (inp.placeholder || "").toLowerCase();
              if (
                name.includes("name") ||
                id.includes("name") ||
                ac.includes("name") ||
                ph.includes("name")
              ) {
                return true;
              }
            }
            return false;
          },
          { timeout: 30000, polling: 1500 }
        )
        .catch(() => null);
      await new Promise((r) => setTimeout(r, 2500));

      // Step 4b: AWS shows a NAME field after the email (Builder ID registration).
      // Stay focused on the AWS tab until the name is filled and submitted.
      console.log(`[${label}] 4b/6 Check & fill AWS Builder ID name field...`);
      await focusPage(page);
      await dismissCookieBanner(page);

      /**
       * Dump the current page's input/button state for debugging.
       * Pierces shadow DOM so custom components are also listed.
       *
       * @param {string} tag - Label for the log line.
       * @returns {Promise<object|null>}
       */
      async function dumpNamePageState(tag) {
        try {
          const dump = await page.evaluate(() => {
            const collect = (root, out) => {
              const inputs = Array.from(
                root.querySelectorAll(
                  "input,textarea,[contenteditable='true'],[contenteditable='']"
                )
              );
              for (const inp of inputs) {
                if (inp.offsetParent === null && inp.tagName !== "INPUT") continue;
                const rect = inp.getBoundingClientRect
                  ? inp.getBoundingClientRect()
                  : { width: 0, height: 0 };
                out.push({
                  tag: inp.tagName,
                  type: inp.getAttribute("type") || "",
                  name: inp.getAttribute("name") || "",
                  id: inp.id || "",
                  placeholder: inp.getAttribute("placeholder") || "",
                  autocomplete: inp.getAttribute("autocomplete") || "",
                  ariaLabel: inp.getAttribute("aria-label") || "",
                  cls: (inp.className || "").toString().slice(0, 80),
                  visible: rect.width > 0 && rect.height > 0,
                  w: Math.round(rect.width || 0),
                  h: Math.round(rect.height || 0),
                });
              }
              // Pierce shadow DOM.
              const all = Array.from(root.querySelectorAll("*"));
              for (const el of all) {
                if (el.shadowRoot) collect(el.shadowRoot, out);
              }
            };
            const out = [];
            collect(document, out);
            return {
              url: location.href,
              hash: location.hash,
              bodyLen: (document.body.innerText || "").length,
              bodyPreview: (document.body.innerText || "")
                .replace(/\s+/g, " ")
                .slice(0, 300),
              inputs: out,
            };
          });
          console.log(
            `[${label}]    [dump:${tag}] url=${dump.url} hash=${dump.hash} bodyLen=${dump.bodyLen}`
          );
          console.log(`[${label}]    [dump:${tag}] body: ${dump.bodyPreview}`);
          console.log(`[${label}]    [dump:${tag}] inputs (${dump.inputs.length}):`);
          for (const inp of dump.inputs) {
            console.log(
              `[${label}]      <${inp.tag}${inp.type ? ` type="${inp.type}"` : ""}${inp.name ? ` name="${inp.name}"` : ""}${inp.id ? ` id="${inp.id}"` : ""}${inp.placeholder ? ` ph="${inp.placeholder}"` : ""}${inp.autocomplete ? ` ac="${inp.autocomplete}"` : ""}${inp.ariaLabel ? ` lb="${inp.ariaLabel}"` : ""} cls="${inp.cls}" vis=${inp.visible} ${inp.w}x${inp.h}>`
            );
          }
          return dump;
        } catch (e) {
          console.log(`[${label}]    [dump:${tag}] error: ${e.message}`);
          return null;
        }
      }

      // Poll for the name input. Handles several signatures:
      //   - input[name*="name"], input[autocomplete="name"]
      //   - input with a name placeholder
      //   - a visible text input on the enter-email/enter-name step (heuristic)
      // Also pierces shadow DOM. Excludes email/password/hidden inputs so a
      // stray email field with "name" in its CSS class does not get overwritten
      // with the display name (which would make AWS send the OTP to an invalid
      // address and time out).
      const nameInputInfo = await page
        .waitForFunction(
          () => {
            const collectAll = (root) => {
              const list = Array.from(
                root.querySelectorAll(
                  "input,textarea,[contenteditable='true'],[contenteditable='']"
                )
              );
              const allEls = Array.from(root.querySelectorAll("*"));
              for (const el of allEls) {
                if (el.shadowRoot) list.push(...collectAll(el.shadowRoot));
              }
              return list;
            };
            const hash = location.hash || "";
            const onNameStep =
              /enter-name|enter-email|signup|name/i.test(hash) ||
              /enter your name|your name/i.test(document.body.innerText || "");
            const nodes = collectAll(document);
            for (const inp of nodes) {
              const rect = inp.getBoundingClientRect
                ? inp.getBoundingClientRect()
                : { width: 0, height: 0 };
              const visible = rect.width > 0 && rect.height > 0;
              if (!visible) continue;
              // Exclude input types that cannot be the name field.
              const inpType = (inp.getAttribute("type") || "").toLowerCase();
              if (
                inpType === "email" ||
                inpType === "password" ||
                inpType === "hidden" ||
                inpType === "checkbox" ||
                inpType === "radio" ||
                inpType === "submit" ||
                inpType === "button"
              ) {
                continue;
              }
              const attrs = [
                inp.getAttribute("name") || "",
                inp.id || "",
                inp.getAttribute("autocomplete") || "",
                inp.getAttribute("placeholder") || "",
                inp.getAttribute("aria-label") || "",
                (inp.className || "").toString(),
                inp.getAttribute("data-testid") || "",
              ]
                .join(" ")
                .toLowerCase();
              // 1) Explicit attribute match.
              if (
                attrs.includes("name") ||
                /first|last|given|family|fullname|full-name|full_name|display/i.test(attrs)
              ) {
                return {
                  name: inp.getAttribute("name") || "",
                  id: inp.id || "",
                  placeholder: inp.getAttribute("placeholder") || "",
                  tag: inp.tagName,
                  type: inp.getAttribute("type") || "",
                };
              }
              // 2) Heuristic: on the name step with a visible text input (not email/password).
              if (onNameStep && inp.tagName === "INPUT") {
                const t = (inp.getAttribute("type") || "text").toLowerCase();
                if (t === "text" || t === "") {
                  return {
                    name: inp.getAttribute("name") || "",
                    id: inp.id || "",
                    placeholder: inp.getAttribute("placeholder") || "",
                    tag: inp.tagName,
                    type: t,
                  };
                }
              }
            }
            return null;
          },
          { timeout: 25000, polling: 1000 }
        )
        .catch(() => null);

      if (nameInputInfo) {
        const info = await nameInputInfo.jsonValue();
        const userName = account.name || randomRealisticName();
        // Build the best selector: id > name > placeholder > type.
        const sel =
          (info.id && `#${info.id}`) ||
          (info.name && `input[name="${info.name}"]`) ||
          (info.placeholder && `input[placeholder="${info.placeholder}"]`) ||
          `input[type="${info.type || "text"}"]`;
        console.log(
          `[${label}]    Name field found (${sel} tag=${info.tag} type=${info.type}), value: ${userName}`
        );
        await focusPage(page);
        await page.focus(sel).catch(async () => {
          // Fallback: focus via evaluateHandle.
          const handle = await page.evaluateHandle((selector) => {
            const el = document.querySelector(selector);
            if (el) {
              el.focus();
              return el;
            }
            return null;
          }, sel);
          const isElement = await handle.evaluate((e) => !!e);
          if (!isElement) {
            console.log(
              `[${label}]    Selector ${sel} could not be focused; trying keyboard.type directly`
            );
            await page.keyboard.type(userName, { delay: 40 });
          }
        });
        if (await page.$(sel)) {
          // Clear any existing value, then type.
          await page.click(sel, { clickCount: 3 }).catch(() => {});
          await page.keyboard.press("Backspace").catch(() => {});
          await page.focus(sel).catch(() => {});
          await page.keyboard.type(userName, { delay: 40 });
        }
        // The AWS SPA needs time to register the input and enable the Continue
        // button. Clicking too fast causes ERR-837 ("Sorry, there was an error
        // processing your request") because the form is submitted with an
        // incomplete state.
        await new Promise((r) => setTimeout(r, 3000));
        const clickResult = await clickByText(page, [
          "Next",
          "Continue",
          "Send code",
          "Submit",
          "Create account",
        ]);
        console.log(
          `[${label}]    Name submit click result: ${clickResult || "(none, falling back to Enter)"}`
        );
        if (!clickResult) await page.keyboard.press("Enter");
        // Submitting the name is what triggers AWS to send the verification code.
        submitTime = Date.now();
        // Wait for AWS to transition after the name submit.
        const submittedOk = await page
          .waitForFunction(
            () => {
              const txt = (document.body.innerText || "").trim();
              return txt.length > 50 && !/enter-name|enter-email/i.test(location.hash);
            },
            { timeout: 15000 }
          )
          .catch(() => null);
        if (!submittedOk) {
          console.log(`[${label}]    No transition after name submit`);
          await dumpNamePageState("post-submit");
          const ssPostSubmit = `/tmp/kiro-aws-postname-${Date.now()}.png`;
          await page.screenshot({ path: ssPostSubmit, fullPage: true }).catch(() => {});
          console.log(`[${label}]    Screenshot: ${ssPostSubmit}`);
          // Check whether AWS rejected the domain (ERR-837 etc.).
          const awsErr = await page
            .evaluate(() => {
              const t = document.body.innerText || "";
              const m = t.match(/ERR-\d+/);
              return m ? m[0] : null;
            })
            .catch(() => null);
          if (awsErr) {
            // Forwarder alias is fixed (no domain rotation here).
            // This account fails -> caller should try the next alias.
            throw new Error(`AWS rejected alias "${alias}" (${awsErr}) — use a different alias.`);
          }
        }
        await new Promise((r) => setTimeout(r, 2000));
      } else {
        const ssNoName = `/tmp/kiro-aws-noname-${Date.now()}.png`;
        await page.screenshot({ path: ssNoName, fullPage: true }).catch(() => {});
        console.log(`[${label}]    Name field NOT found within 25s.`);
        console.log(`[${label}]    Screenshot: ${ssNoName}`);
        await dumpNamePageState("noname");
      }

      // Wait for the AWS verification code via IMAP (Gmail forwarded via alias).
      if (!submitTime) submitTime = Date.now();
      console.log(`[${label}] 5/6 Waiting for verification code via IMAP (max 150s)...`);
      // Initial delay so AWS has time to send + Relay forward + Gmail receive
      // before the first poll. Without it, the first poll usually misses the
      // email and wastes cycles.
      const initialDelayMs = 15000;
      console.log(
        `[${label}]    Initial delay ${initialDelayMs / 1000}s (AWS send -> Relay forward -> Gmail receive)...`
      );
      await new Promise((r) => setTimeout(r, initialDelayMs));
      const otpResult = await this.services.imap.getOtpViaImap(this.config.imap, alias, {
        since: submitTime,
        maxWaitMs: 135000,
      });
      if (!otpResult.ok) {
        console.log(`[${label}]    IMAP error: ${otpResult.error}`);
        console.log(
          `[${label}]    debug: ${JSON.stringify(otpResult.debug).slice(0, 500)}`
        );
        throw new Error(`Could not read verification code via IMAP. ${otpResult.error}`);
      }
      const code = otpResult.otp;
      console.log(
        `[${label}]    OTP code received (length ${code.length}, from="${otpResult.from}" received="${otpResult.received}")`
      );

      // Submit the code to AWS.
      // AWS Builder ID verify-otp can be either: (a) one whole-code input, or
      // (b) six separate 1-digit boxes. Detect the layout first so the code
      // lands in the right place.
      await focusPage(page);
      await page
        .waitForSelector(
          'input[autocomplete="one-time-code"], input[inputmode="numeric"], input[name="code" i], input[type="text"], input[maxlength]',
          { timeout: 15000 }
        )
        .catch(() => null);

      const verifyLayout = await page
        .evaluate(() => {
          const inputs = Array.from(
            document.querySelectorAll(
              'input[autocomplete="one-time-code"], input[inputmode="numeric"], input[name="code" i], input[type="text"], input[maxlength]'
            )
          ).filter((i) => {
            const r = i.getBoundingClientRect();
            return r.width > 0 && r.height > 0;
          });
          return {
            count: inputs.length,
            maxlengths: inputs.map((i) => i.getAttribute("maxlength")),
            autocompletes: inputs.map((i) => i.getAttribute("autocomplete")),
            names: inputs.map((i) => i.name || ""),
          };
        })
        .catch(() => ({ count: 0 }));
      const otpSs = `/tmp/kiro-verify-otp-${Date.now()}.png`;
      await page.screenshot({ path: otpSs }).catch(() => {});
      console.log(
        `[${label}]    verify-otp layout: ${JSON.stringify(verifyLayout)} screenshot: ${otpSs}`
      );

      const singleInput = await page
        .$(
          'input[autocomplete="one-time-code"], input[inputmode="numeric"][maxlength="1"], input[name="code" i]'
        )
        .catch(() => null);

      if (verifyLayout.count >= 6 && verifyLayout.maxlengths.some((m) => m === "1")) {
        // Six-box layout: type per-digit into each box (focus auto-advances,
        // but keyboard.type follows the focus handler).
        console.log(`[${label}]    Six-box layout detected, typing per-digit`);
        const firstBox = await page
          .$(
            'input[autocomplete="one-time-code"], input[inputmode="numeric"], input[maxlength="1"]'
          )
          .catch(() => null);
        if (firstBox) {
          await firstBox.focus();
          await page.keyboard.type(code, { delay: 80 });
        } else {
          await page.keyboard.type(code, { delay: 80 });
        }
      } else if (singleInput) {
        console.log(`[${label}]    Single-input layout detected`);
        await singleInput.focus();
        await singleInput.type(code, { delay: 60 });
      } else {
        // Fallback: first visible input[type=text] / [maxlength].
        const fallback = await page.$('input[type="text"], input[maxlength]').catch(() => null);
        if (!fallback) throw new Error("Verification code input field not found");
        await fallback.focus();
        await fallback.type(code, { delay: 60 });
      }
      await new Promise((r) => setTimeout(r, 900));
      // Submit the code: AWS Builder ID "Continue" sometimes ignores a
      // programmatic .click(). Use a real mouse click at the button center,
      // then fall back to Enter if the page hasn't advanced.
      const beforeSubmitUrl = safeUrl(page);
      const otpClicked = await clickPrimaryButtonMouse(page, [
        "Verify",
        "Continue",
        "Next",
        "Submit",
      ]);
      if (!otpClicked) {
        submitted = await clickByText(page, ["Verify", "Continue", "Next", "Submit"]);
      }
      await new Promise((r) => setTimeout(r, 1800));
      // If still on the same URL, press Enter on the input.
      if (safeUrl(page) === beforeSubmitUrl) {
        const inp = await page
          .$(
            'input[autocomplete="one-time-code"], input[inputmode="numeric"], input[type="text"]'
          )
          .catch(() => null);
        if (inp) {
          await inp.focus();
          await page.keyboard.press("Enter");
        } else {
          await page.keyboard.press("Enter");
        }
      }
      await new Promise((r) => setTimeout(r, 3500));

      // Check whether we're still on verify-otp (wrong code / didn't land).
      // If so, capture the error message + a screenshot for diagnosis.
      const postUrl = safeUrl(page);
      if (/verify-otp|enter-otp|verification code/i.test(postUrl)) {
        const postState = await page
          .evaluate(() => {
            const errs = Array.from(
              document.querySelectorAll(
                '[role="alert"], .alert, .error, .invalid-feedback, [class*="error" i]'
              )
            )
              .map((e) => (e.innerText || "").trim())
              .filter(Boolean);
            const inputs = Array.from(document.querySelectorAll("input"))
              .filter((i) => i.getBoundingClientRect().width > 0)
              .map((i) => ({
                name: i.name || "",
                type: i.type,
                value: (i.value || "").slice(0, 12),
                autocomplete: i.getAttribute("autocomplete") || "",
              }));
            return { errors: errs.slice(0, 5), inputs: inputs.slice(0, 10) };
          })
          .catch(() => ({ errors: [], inputs: [] }));
        const stuckSs = `/tmp/kiro-verify-stuck-${Date.now()}.png`;
        await page.screenshot({ path: stuckSs }).catch(() => {});
        console.log(
          `[${label}]    Still on verify-otp after submit. state: ${JSON.stringify(postState).slice(0, 400)} screenshot: ${stuckSs}`
        );
      }

      // Step 5b: Set up password + confirmation (Builder ID registration).
      // After verify-otp succeeds, AWS navigates to /signup?registrationCode=...
      // which asks for a new password. This page needs time to render, so
      // WAIT for the password field to appear rather than checking once.
      console.log(`[${label}] 5b/6 Check AWS Builder ID password field...`);
      await focusPage(page);
      const pwdPwd = await page
        .waitForSelector('input[type="password"]', { timeout: 45000, visible: true })
        .catch(() => null);
      const passwordFields = await page.evaluate(() => {
        const pwdInputs = Array.from(document.querySelectorAll('input[type="password"]'));
        return pwdInputs.map((inp, idx) => {
          const rect = inp.getBoundingClientRect();
          return {
            idx,
            visible: rect.width > 0 && rect.height > 0,
            name: inp.name || "",
            id: inp.id || "",
            autocomplete: inp.getAttribute("autocomplete") || "",
            placeholder: inp.placeholder || "",
            ariaLabel: inp.getAttribute("aria-label") || "",
          };
        });
      });
      if (pwdPwd && passwordFields.length > 0) {
        const pwd = account.password || `Kiro${crypto.randomBytes(6).toString("base64").slice(0, 8)}!A1`;
        console.log(
          `[${label}]    Found ${passwordFields.length} password field(s), filling password...`
        );

        // Fill ALL visible password fields (password + confirm) via direct
        // element handles. page.focus(selector) often fails on AWS custom
        // form fields, but handle.click() + reactTypeInput(handle) is
        // reliable. reactTypeInput triggers React's onChange via the native
        // setter — plain handle.type() sometimes does not propagate to
        // AWS CloudScape controlled components, leaving password and confirm
        // out of sync and producing "Passwords do not match" errors.
        for (let attempt = 0; attempt < 3; attempt++) {
          await focusPage(page);
          const handles = await page.$$('input[type="password"]');
          let allFilled = true;
          for (const h of handles) {
            const vis = await h
              .evaluate((el) => {
                const r = el.getBoundingClientRect();
                return r.width > 0 && r.height > 0;
              })
              .catch(() => false);
            if (!vis) continue;
            const curLen = await h.evaluate((el) => (el.value || "").length).catch(() => 0);
            if (curLen > 0) continue;
            allFilled = false;
            await h.click({ clickCount: 3 }).catch(() => {});
            await new Promise((r) => setTimeout(r, 150));
            await reactTypeInput(h, pwd);
            await new Promise((r) => setTimeout(r, 400));
          }
          if (allFilled) break;
          await new Promise((r) => setTimeout(r, 700));
        }

        // Verify all fields are filled.
        const verifyFill = await page
          .evaluate(() => {
            return Array.from(document.querySelectorAll('input[type="password"]')).map((inp) => {
              const r = inp.getBoundingClientRect();
              return { id: inp.id || "", vis: r.width > 0 && r.height > 0, len: (inp.value || "").length };
            });
          })
          .catch(() => []);
        console.log(`[${label}]    Password fields after fill: ${JSON.stringify(verifyFill)}`);

        const pwdSs = `/tmp/kiro-pwd-page-${Date.now()}.png`;
        await page.screenshot({ path: pwdSs }).catch(() => {});
        const btnState = await page
          .evaluate(() => {
            const btns = Array.from(
              document.querySelectorAll('button, [role="button"], input[type="submit"]')
            );
            return btns
              .filter((b) => {
                const r = b.getBoundingClientRect();
                return r.width > 0 && r.height > 0;
              })
              .slice(0, 12)
              .map((b) => ({
                text: (b.innerText || b.textContent || b.value || "").trim().slice(0, 30),
                disabled: b.disabled,
                cls: (b.className || "").toString().slice(0, 50),
              }));
          })
          .catch(() => []);
        console.log(`[${label}]    Buttons: ${JSON.stringify(btnState)} screenshot: ${pwdSs}`);

        await new Promise((r) => setTimeout(r, 600));
        // Submit via a real mouse click (reliable on AWS components).
        const pwdClicked = await clickPrimaryButtonMouse(page, [
          "Create account",
          "Create Account",
          "Complete",
          "Complete signup",
          "Sign in",
          "Continue",
          "Next",
          "Submit",
        ]);
        if (pwdClicked) {
          console.log(`[${label}]    Password submit (mouse click): ${pwdClicked}`);
        } else {
          console.log(
            `[${label}]    Password submit via fallback (button may be disabled)`
          );
          await clickByText(page, lang(["Create account", "Continue", "Next", "Submit"]));
          await page.keyboard.press("Enter");
        }
        await new Promise((r) => setTimeout(r, 4500));

        // Check whether we're still on /signup (password failed). Dump errors.
        const postPwdUrl = safeUrl(page);
        if (/\/signup|registrationCode/i.test(postPwdUrl)) {
          const pwdErr = await page
            .evaluate(() => {
              const errs = Array.from(
                document.querySelectorAll(
                  '[role="alert"], .alert, .error, .invalid-feedback, [class*="error" i], [data-error]'
                )
              )
                .map((e) => (e.innerText || "").trim())
                .filter(Boolean);
              const btns = Array.from(document.querySelectorAll("button")).filter((b) => {
                const r = b.getBoundingClientRect();
                return r.width > 0 && r.height > 0;
              }).map((b) => ({ t: (b.innerText || "").trim().slice(0, 20), disabled: b.disabled }));
              return { errors: errs.slice(0, 5), buttons: btns.slice(0, 8) };
            })
            .catch(() => ({ errors: [], buttons: [] }));
          const stuckSs = `/tmp/kiro-pwd-stuck-${Date.now()}.png`;
          await page.screenshot({ path: stuckSs }).catch(() => {});
          console.log(
            `[${label}]    Still on signup after password submit. state: ${JSON.stringify(pwdErr).slice(0, 500)} screenshot: ${stuckSs}`
          );
        } else {
          console.log(
            `[${label}]    Password setup done, navigated to: ${postPwdUrl.slice(0, 80)}`
          );
        }
      } else {
        console.log(
          `[${label}]    Password field not found within 25s (account may already exist / went straight to consent)`
        );
      }

      // Remaining: device confirmation + Kiro consent (same as Google flow).
      console.log(`[${label}] 6/6 Waiting for device approval & consent (max 150s)...`);
      const maxWait = 150000;
      const checkInterval = 3000;
      let waited = 0;
      let lastLogUrl = "";
      let stableCount = 0;
      let sel = null;

      while (waited < maxWait) {
        await focusPage(page);
        const url = safeUrl(page);
        const body = await page.evaluate(() => document.body.innerText).catch(() => "");

        if (url !== lastLogUrl) {
          console.log(`[${label}]    URL: ${url.split("?")[0].slice(0, 100)}`);
          lastLogUrl = url;
          stableCount = 0;
        } else {
          stableCount++;
          // If URL + click pattern has been stable for >5 cycles (15s) and we
          // have already tried clicking, the page is likely stuck (invalid
          // form). Throw so the caller can move on to the next account.
          if (stableCount > 5 && sel === null) {
            throw new Error(
              `Stuck on ${url.slice(0, 60)} for ${(stableCount * checkInterval) / 1000}s — page not responsive`
            );
          }
        }

        sel = null;

        // The registrationCode step sometimes appears before device consent.
        // AWS CloudScape moves from /device?user_code to /signup?registrationCode
        // for invited accounts or secondary auth. Detect by URL + presence of a
        // password field or "Create Account" button.
        if (/signup|registrationCode/i.test(url)) {
          const regState = await page
            .evaluate(() => {
              const pwd = document.querySelector('input[type="password"]');
              const inputs = Array.from(document.querySelectorAll("input")).filter(
                (i) => i.getBoundingClientRect().width > 0 && i.type !== "hidden"
              );
              return {
                hasPwd: !!pwd,
                inputCount: inputs.length,
                inputs: inputs.slice(0, 5).map((i) => ({
                  name: i.name,
                  type: i.type,
                  placeholder: i.placeholder,
                })),
              };
            })
            .catch(() => null);
          if (regState && regState.hasPwd) {
            // Password page appeared during step 6 (step 5b missed it). Fill now.
            console.log(
              `[${label}]    Registration-code page with password field detected (step 5b miss) — fill now`
            );
            const pwd2 = account.password || `Kiro${crypto.randomBytes(6).toString("base64").slice(0, 8)}!A1`;
            const handles = await page.$$('input[type="password"]');
            for (const h of handles) {
              const vis = await h
                .evaluate((el) => el.getBoundingClientRect().width > 0)
                .catch(() => false);
              if (!vis) continue;
              const curLen = await h.evaluate((el) => (el.value || "").length).catch(() => 0);
              if (curLen > 0) continue;
              await h.click({ clickCount: 3 }).catch(() => {});
              await new Promise((r) => setTimeout(r, 150));
              await reactTypeInput(h, pwd2);
            }
            await new Promise((r) => setTimeout(r, 1500));
            sel = await clickByText(page, lang(["Create account", "Continue", "Sign up", "Next"]));
            if (!sel) sel = await clickPrimaryButton(page);
          } else {
            // Another registration page (button-only). Click the primary button.
            const clicked = await clickByText(
              page,
              lang([
                "Continue",
                "Next",
                "Create account",
                "Sign up",
                "Allow access",
                "Allow",
              ])
            );
            if (clicked) sel = clicked;
            else sel = await clickPrimaryButton(page);
          }
        } else if (body.includes("Authorization requested") || body.includes("Confirm this code")) {
          console.log(`[${label}]    Device-code confirmation page detected`);
          sel = await clickByText(page, lang(["Confirm and continue"]));
          if (!sel) sel = await clickBySelector(page, 'button[class*="primary" i]');
          if (!sel) sel = await clickPrimaryButton(page);
        } else if (body.includes("Allow kiro-oauth-client") || body.includes("access your data")) {
          console.log(`[${label}]    Kiro consent page detected`);
          sel = await clickByText(page, lang(["Allow access", "Allow"]));
          if (!sel) sel = await clickBySelector(page, 'button[class*="allow" i]');
          if (!sel) sel = await clickPrimaryButton(page);
        } else if (
          url.includes("view.awsapps.com") &&
          (body.includes("AWS Customer Agreement") ||
            body.includes("AWS Builder ID") ||
            body.includes("Accept agreement") ||
            body.includes("Accept terms") ||
            body.includes("Accept Terms") ||
            body.includes("confirm agreement") ||
            body.includes("user agreement"))
        ) {
          console.log(`[${label}]    AWS agreement/TOS page detected`);
          await page
            .evaluate(() => {
              const containers = Array.from(document.querySelectorAll("div, section, article"));
              const box = containers.find((el) => {
                const style = window.getComputedStyle(el);
                return (
                  (style.overflowY === "auto" || style.overflowY === "scroll") &&
                  el.scrollHeight > el.clientHeight
                );
              });
              if (box) box.scrollTop = box.scrollHeight;
              else window.scrollTo(0, document.body.scrollHeight);
            })
            .catch(() => {});
          await new Promise((r) => setTimeout(r, 800));
          const checkbox = await page.$(
            'input[type="checkbox"][name*="agree" i], input[type="checkbox"][id*="agree" i], input[type="checkbox"][id*="terms" i], input[type="checkbox"][id*="accept" i]'
          );
          if (checkbox) await checkbox.click().catch(() => {});
          await new Promise((r) => setTimeout(r, 500));
          sel = await clickByText(page, [
            "Accept and continue",
            "Agree and continue",
            "I agree",
            "Accept terms",
            "Accept agreement",
            "Accept",
            "Agree",
            "Confirm",
            "Continue",
          ]);
          if (!sel) {
            sel = await clickBySelector(
              page,
              'button[class*="accept" i], button[class*="agree" i], button[class*="primary" i]'
            );
          }
          if (!sel) sel = await clickPrimaryButton(page);
        }

        if (sel) console.log(`[${label}]    Clicked: ${sel}`);

        if (
          body.includes("Request approved") ||
          body.includes("You can close this window") ||
          body.includes("device approved")
        ) {
          console.log(`[${label}] Device approved!`);
          approved = true;
          break;
        }

        await new Promise((r) => setTimeout(r, checkInterval));
        waited += checkInterval;
      }

      if (!approved) {
        throw new Error(`Timeout: Device not approved within ${maxWait / 1000}s`);
      }
    } catch (err) {
      console.error(`[${label}] Failed: ${err.message}`);
      throw err;
    } finally {
      try {
        const pages = await browser.pages();
        await Promise.all(pages.map((p) => p.close()));
        await browser.close();
        console.log(`[${label}]    Browser closed`);
      } catch {
        // ignore
      }
    }

    // Return resolved email (alias) so the caller can use it for renaming.
    return { approved, email: resolvedEmail };
  }

  // ============================================================
  // POLLING + RENAME
  // ============================================================

  /**
   * Poll /api/oauth/kiro/poll until 9router stores the OAuth token, then
   * rename the new connection to the resolved email.
   *
   * The extraData block carries the underscore-prefixed fields returned by
   * the device-code endpoint (_clientId, _clientSecret, _region, _authMethod,
   * _startUrl) — 9router needs them to complete the token exchange.
   *
   * Ported from reference pollUntilConnected (bot.js 1463-1504).
   *
   * @param {object} deviceData - Device-code response. Must include device_code and the underscore-prefixed fields.
   * @param {string} email - Resolved email/alias used as the connection name.
   * @returns {Promise<object>} The poll response body on success.
   */
  async pollUntilConnected(deviceData, email) {
    console.log(`[${email}] Polling 9router to persist the token...`);
    const extraData = {
      _clientId: deviceData._clientId,
      _clientSecret: deviceData._clientSecret,
      _region: deviceData._region,
      _authMethod: deviceData._authMethod,
      _startUrl: deviceData._startUrl,
    };

    const expiresAt = Date.now() + (deviceData.expires_in || 600) * 1000;
    const intervalMs = (deviceData.interval || 1) * 1000;

    while (Date.now() < expiresAt) {
      try {
        const result = await this._apiCall("POST", this.constructor.endpoints.poll, {
          deviceCode: deviceData.device_code,
          extraData,
        });
        if (result.success) {
          const connectionId = result.connection && result.connection.id;
          console.log(`[${email}] Kiro account registered! ID: ${connectionId}`);
          if (connectionId) {
            try {
              await this.renameConnection(connectionId, email);
              console.log(`[${email}]    Connection renamed to: ${email}`);
            } catch (renameErr) {
              console.warn(`[${email}]    Failed to rename connection: ${renameErr.message}`);
            }
          }
          return result;
        }
        if (result.pending) {
          console.log(`[${email}]    Waiting for approval... (${result.error || "pending"})`);
        } else {
          throw new Error(`Poll failed: ${result.error} - ${result.errorDescription || ""}`);
        }
      } catch (e) {
        console.error(`[${email}]    Poll error: ${e.message}`);
      }
      await new Promise((r) => setTimeout(r, intervalMs));
    }

    throw new Error("Device code expired before approval");
  }

  /**
   * Rename a stored connection via PUT /api/providers/:id.
   *
   * Ported from reference updateConnectionName (bot.js 73-78).
   *
   * @param {string} id - Connection ID returned by the poll step.
   * @param {string} name - New name (typically the resolved email/alias).
   * @returns {Promise<object>} The API response body.
   */
  async renameConnection(id, name) {
    return this._apiCall(
      "PUT",
      `${this.constructor.endpoints.provider}/${encodeURIComponent(id)}`,
      { name }
    );
  }

  /**
   * Quota pre-check hook. Skips add() when the email's domain has already
   * hit its per-UTC-day cap. Mirrors the reference's quota handling.
   *
   * @param {{email?: string}} credentials - Account credentials.
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
        cap
      );
      if (!allowed) {
        return { skip: true, reason: `Quota cap (${cap}/day) reached for ${credentials.email}` };
      }
    }
  }

  /**
   * Inspect a connection by ID. Uses GET /api/providers/:id (remote mode) or
   * a direct DB lookup (local mode).
   *
   * @param {string} id - Connection ID.
   * @returns {Promise<object|null>}
   */
  async inspect(id) {
    if (this.config.mode === "local") {
      const { findById } = require("../../core/db");
      return findById(this.config, id);
    }
    return this._apiCall("GET", `${this.constructor.endpoints.provider}/${encodeURIComponent(id)}`);
  }

  /**
   * Delete a connection by ID. Uses DELETE /api/providers/:id (remote mode)
   * or a direct DB delete (local mode).
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
      `${this.constructor.endpoints.provider}/${encodeURIComponent(id)}`
    );
  }
}

module.exports = KiroProvider;
