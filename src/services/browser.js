"use strict";

const puppeteer = require("puppeteer-extra");
const StealthPlugin = require("puppeteer-extra-plugin-stealth");
puppeteer.use(StealthPlugin());

/**
 * Launch a stealth browser with optional proxy and fingerprint.
 * @param {Object} config
 * @param {Object} services - { proxy, fingerprint }
 * @param {Object} [options]
 * @param {string} [options.url] - URL to navigate to after launch
 * @param {Object} [options.proxy] - Pre-resolved proxy object
 * @param {Object} [options.fingerprint] - Pre-generated fingerprint
 * @returns {Promise<{browser: Browser, page: Page}>}
 */
async function launchStealthBrowser(config, services, options = {}) {
  const proxy = options.proxy || (services.proxy && services.proxy.loadProxies()[0]);
  const fingerprint = options.fingerprint || (services.fingerprint && services.fingerprint.generateFingerprint());

  const launchArgs = [];
  if (proxy) {
    const { chromiumArgsForProxy } = require("./proxy");
    launchArgs.push(...chromiumArgsForProxy(proxy));
  }
  // Common Puppeteer args
  launchArgs.push("--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage");

  const browser = await puppeteer.launch({
    headless: config.headless !== false ? true : false,
    args: launchArgs,
  });

  const page = await newStealthPage(browser, fingerprint);

  // Proxy authentication
  if (proxy && proxy.username && proxy.password) {
    await page.authenticate({ username: proxy.username, password: proxy.password });
  }

  if (options.url) {
    await page.goto(options.url, { waitUntil: "networkidle2", timeout: 30000 });
  }

  return { browser, page };
}

/**
 * Create a new page with fingerprint overrides.
 * @param {Browser} browser
 * @param {Object} fingerprint
 * @returns {Promise<Page>}
 */
async function newStealthPage(browser, fingerprint) {
  const page = await browser.newPage();

  if (fingerprint) {
    // Viewport
    if (fingerprint.viewport) {
      await page.setViewport(fingerprint.viewport);
    }
    // Locale & timezone via CDP
    const cdp = await page.createCDPSession();
    await cdp.send("Emulation.setLocaleOverride", { locale: fingerprint.locale || "en-US" });
    if (fingerprint.timezoneId) {
      await cdp.send("Emulation.setTimezoneOverride", { timezoneId: fingerprint.timezoneId });
    }
    // User-Agent
    if (fingerprint.userAgent) {
      await page.setUserAgent(fingerprint.userAgent);
    }
    // Extra headers
    if (fingerprint.acceptLanguage) {
      await page.setExtraHTTPHeaders({ "Accept-Language": fingerprint.acceptLanguage });
    }
  }

  return page;
}

/**
 * Set value on React-controlled input fields.
 * React components often ignore page.type() because they use synthetic events.
 * This dispatches the native input event + React's setter.
 *
 * @param {Page} page - Puppeteer page.
 * @param {string} selector - CSS selector for the input element.
 * @param {string} value - Value to set on the input.
 * @returns {Promise<void>}
 */
async function reactTypeInput(page, selector, value) {
  await page.evaluate(
    ({ sel, val }) => {
      const input = document.querySelector(sel);
      if (!input) return;
      const nativeInputValueSetter = Object.getOwnPropertyDescriptor(
        window.HTMLInputElement.prototype,
        "value"
      ).set;
      nativeInputValueSetter.call(input, val);
      input.dispatchEvent(new Event("input", { bubbles: true }));
      input.dispatchEvent(new Event("change", { bubbles: true }));
    },
    { sel: selector, val: value }
  );
}

/**
 * Click a button by its visible text content.
 * Scores buttons by text match, prefers primary/continue buttons,
 * avoids cookie/consent banners.
 * @param {Page} page
 * @param {string|RegExp} text
 * @param {Object} [opts]
 * @returns {Promise<boolean>} Whether a button was clicked
 */
async function clickByText(page, text, opts = {}) {
  const buttons = await page.$$("button, a, input[type=submit], [role=button]");
  const candidates = [];

  for (const btn of buttons) {
    const btnText = (await btn.evaluate((el) => el.textContent.trim().toLowerCase())) || "";
    const type = await btn.evaluate((el) => (el.type || "").toLowerCase());
    const href = await btn.evaluate((el) => el.getAttribute("href") || "");

    // Skip cookie/consent banners
    if (/cookie|consent|privacy|gdpr/i.test(btnText)) continue;

    const match = typeof text === "string" ? btnText.includes(text.toLowerCase()) : text.test(btnText);
    if (match) {
      candidates.push({ btn, text: btnText, type, href });
    }
  }

  // Sort: prefer <button> over <a>, prefer type=submit
  candidates.sort((a, b) => {
    const scoreA = (a.type === "submit" ? 2 : 0) + (a.href ? 0 : 1);
    const scoreB = (b.type === "submit" ? 2 : 0) + (b.href ? 0 : 1);
    return scoreB - scoreA;
  });

  if (candidates.length === 0) return false;
  await candidates[0].btn.click();
  return true;
}

/**
 * Click at specific coordinates using mouse events.
 * Useful for elements that intercept click events via JS.
 *
 * @param {Page} page - Puppeteer page.
 * @param {{x: number, y: number}} coords - Click coordinates.
 * @returns {Promise<void>}
 */
async function clickPrimaryButtonMouse(page, coords) {
  await page.mouse.click(coords.x, coords.y, { button: "left" });
}

module.exports = {
  launchStealthBrowser,
  newStealthPage,
  reactTypeInput,
  clickByText,
  clickPrimaryButtonMouse,
};
