"use strict";

const { BaseProvider } = require("../../base/provider");

class AntigravityProvider extends BaseProvider {
  static get providerName() { return "antigravity"; }

  static get endpoints() {
    return {
      authorize: "/api/oauth/antigravity/authorize",
      exchange: "/api/oauth/antigravity/exchange",
    };
  }

  async add(credentials, options = {}) {
    // 1. Get authorization URL from 9router
    const authRes = await this.apiCall("GET", this.constructor.endpoints.authorize);
    const authUrl = authRes.body.authorizationUrl || authRes.body.url;
    if (!authUrl) throw new Error("No authorization URL in response");

    // 2. Browser automation: Google login, capture code from redirect
    const code = await this.automateGoogleLogin(authUrl, credentials);

    // 3. Exchange code for token
    const exchangeRes = await this.apiCall("POST", this.constructor.endpoints.exchange, { code });

    // 4. Save to DB (local mode) or return for API (remote mode)
    if (this.config.mode === "local") {
      const dbResult = await this.injectToDb({
        provider: "antigravity",
        authType: "oauth",
        name: credentials.name || credentials.email,
        email: credentials.email,
        data: exchangeRes.body,
      });
      return { ok: true, ...dbResult };
    }

    return { ok: true, ...exchangeRes.body };
  }

  async automateGoogleLogin(authUrl, credentials) {
    const { browser, page } = await this.launchBrowser({ url: authUrl });
    try {
      // Step 1: Enter email
      await page.waitForSelector('input[type="email"]', { timeout: 15000 });
      await page.type('input[type="email"]', credentials.email);
      await page.click("#identifierNext");

      // Step 2: Enter password
      await page.waitForSelector('input[type="password"]', { timeout: 10000 });
      await page.type('input[type="password"]', credentials.password);
      await page.click("#passwordNext");

      // Step 3: Handle consent screen if present
      try {
        await page.waitForSelector('[data-agreeto="true"]', { timeout: 5000 });
        await page.click('[data-agreeto="true"]');
      } catch {
        // No consent screen — continue
      }

      // Step 4: Wait for redirect to /callback?code=...
      await page.waitForFunction(
        () => window.location.href.includes("/callback?code="),
        { timeout: 30000 }
      );
      const url = page.url();
      const code = new URL(url).searchParams.get("code");
      if (!code) throw new Error("No authorization code in redirect URL");
      return code;
    } finally {
      await browser.close();
    }
  }

  async inspect(id) {
    const res = await this.apiCall("GET", `/api/providers/antigravity?id=${id}`);
    return res.body;
  }

  async delete(id) {
    if (this.config.mode === "local") {
      const { del } = require("../../core/db");
      await del(this.config, id);
      return;
    }
    await this.apiCall("DELETE", `/api/providers/antigravity?id=${id}`);
  }
}

module.exports = AntigravityProvider;
