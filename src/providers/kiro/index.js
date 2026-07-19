"use strict";

const { BaseProvider } = require("../../base/provider");

class KiroProvider extends BaseProvider {
  static get providerName() { return "kiro"; }

  static get endpoints() {
    return {
      deviceCode: "/api/oauth/kiro/device-code",
      poll: "/api/oauth/kiro/poll",
    };
  }

  async add(credentials, options = {}) {
    const method = this.detectMethod(credentials.email);

    // 1. Request device code from 9router
    const dcRes = await this.apiCall("POST", this.constructor.endpoints.deviceCode, {
      provider: "kiro",
      authType: method,
    });
    const { deviceCode, userCode, verificationUri } = dcRes.body;
    if (!deviceCode || !userCode) throw new Error("No device code in response");

    // 2. Browser automation based on method
    if (method === "google") {
      await this.automateGoogleLogin(verificationUri, userCode, credentials);
    } else {
      await this.automateEmailLogin(verificationUri, userCode, credentials, options);
    }

    // 3. Poll until connected
    const pollRes = await this.pollUntilConnected(deviceCode);

    // 4. Save to DB (local mode) or return (remote mode)
    if (this.config.mode === "local") {
      const dbResult = await this.injectToDb({
        provider: "kiro",
        authType: method,
        name: credentials.name || credentials.email,
        email: credentials.email,
        data: pollRes.body,
      });
      return { ok: true, ...dbResult };
    }

    return { ok: true, ...pollRes.body };
  }

  detectMethod(email) {
    if (!email) return "email";
    return email.toLowerCase().endsWith("@gmail.com") ? "google" : "email";
  }

  async automateGoogleLogin(verificationUri, userCode, credentials) {
    const { browser, page } = await this.launchBrowser({ url: verificationUri });
    try {
      // Enter user code on the device code confirmation page
      await page.waitForSelector("input", { timeout: 10000 });
      await page.type("input", userCode);
      await page.click("button[type=submit], button:has-text('Continue'), button:has-text('Next')");

      // Google login
      await page.waitForSelector('input[type="email"]', { timeout: 15000 });
      await page.type('input[type="email"]', credentials.email);
      await page.click("#identifierNext");
      await page.waitForSelector('input[type="password"]', { timeout: 10000 });
      await page.type('input[type="password"]', credentials.password);
      await page.click("#passwordNext");

      // Wait for approval confirmation
      try {
        await page.waitForFunction(
          () => window.location.href.includes("/device/success") || document.body.innerText.includes("approved"),
          { timeout: 30000 }
        );
      } catch {
        // May already be approved
      }
    } finally {
      await browser.close();
    }
  }

  async automateEmailLogin(verificationUri, userCode, credentials, options) {
    // Generate alias if needed
    let email = credentials.email;
    if (this.services.cfRouting && options.generateAlias) {
      const domain = options.aliasDomain || (this.config.providerConfig || {}).aliasDomain;
      if (domain) {
        const aliases = this.services.cfRouting.generateAliases(domain, 1);
        email = aliases[0];
      }
    }

    // Resolve proxy + fingerprint for this account
    let proxy = options.proxy;
    if (!proxy && this.services.proxy) {
      const proxies = this.services.proxy.loadProxies();
      proxy = this.services.proxy.getProxyForAccount(proxies, options.accountIndex || 0);
    }
    let fingerprint = options.fingerprint;
    if (!fingerprint && this.services.fingerprint) {
      fingerprint = this.services.fingerprint.generateFingerprint();
    }

    const { browser, page } = await this.launchBrowser({
      url: verificationUri,
      proxy,
      fingerprint,
    });
    try {
      // Enter user code
      await page.waitForSelector("input", { timeout: 10000 });
      await page.type("input", userCode);
      await page.click("button[type=submit], button:has-text('Continue')");

      // AWS Builder ID registration flow
      // Name field
      if (credentials.name) {
        await page.waitForSelector('input[name="name"], input[placeholder*="name" i]', { timeout: 10000 });
        const { reactTypeInput } = require("../../services/browser");
        await reactTypeInput(page, 'input[name="name"], input[placeholder*="name" i]', credentials.name);
      }

      // Set password
      if (credentials.password) {
        await page.waitForSelector('input[type="password"]', { timeout: 10000 });
        await page.type('input[type="password"]', credentials.password);
        // Confirm password
        const passwordInputs = await page.$$('input[type="password"]');
        if (passwordInputs.length > 1) {
          await passwordInputs[1].type(credentials.password);
        }
      }

      // Submit form
      const { clickByText } = require("../../services/browser");
      await clickByText(page, /continue|next|submit|create/i);

      // Wait for OTP email
      if (this.services.imap && this.config.imap) {
        const otpResult = await this.services.imap.getOtpViaImap(
          this.config.imap,
          email,
          { subject: "Verify your AWS Builder ID email address" }
        );
        if (!otpResult.ok) throw new Error(`OTP failed: ${otpResult.error}`);

        // Enter OTP
        const otpInputs = await page.$$('input[type="tel"], input[autocomplete="one-time-code"], input[inputmode="numeric"]');
        if (otpInputs.length > 0) {
          for (let i = 0; i < otpResult.otp.length && i < otpInputs.length; i++) {
            await otpInputs[i].type(otpResult.otp[i]);
          }
        } else {
          await page.type('input', otpResult.otp);
        }

        // Submit OTP
        await clickByText(page, /continue|verify|submit/i);
      }
    } finally {
      await browser.close();
    }
  }

  async pollUntilConnected(deviceCode) {
    const timeout = (this.config.providerConfig && this.config.providerConfig.pollTimeout) || 120000;
    const interval = (this.config.providerConfig && this.config.providerConfig.pollInterval) || 3000;
    const start = Date.now();

    while (Date.now() - start < timeout) {
      const res = await this.apiCall("POST", this.constructor.endpoints.poll, { deviceCode });
      if (res.body.status === "connected" || res.body.connected) {
        return res;
      }
      if (res.body.status === "expired") {
        throw new Error("Device code expired");
      }
      await new Promise((r) => setTimeout(r, interval));
    }
    throw new Error("Poll timeout — device code not connected");
  }

  async beforeAdd(credentials, options) {
    // Quota check
    const { quota } = this.services;
    if (quota && credentials.email) {
      const cap = (this.config.providerConfig && this.config.providerConfig.quotaCap) || 3;
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

  async inspect(id) {
    const res = await this.apiCall("GET", `/api/providers/kiro?id=${id}`);
    return res.body;
  }

  async delete(id) {
    if (this.config.mode === "local") {
      const { del } = require("../../core/db");
      await del(this.config, id);
      return;
    }
    await this.apiCall("DELETE", `/api/providers/kiro?id=${id}`);
  }
}

module.exports = KiroProvider;
