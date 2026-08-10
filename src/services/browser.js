"use strict";

const puppeteer = require("puppeteer-extra");
const StealthPlugin = require("puppeteer-extra-plugin-stealth");
puppeteer.use(StealthPlugin());

// ============================================================
// Multi-language button text translations (used by lang()).
// AWS CloudScape renders in the user's locale, so button text may appear
// in Spanish / Portuguese / French / German / Japanese / etc. The lang()
// helper expands an EN array into a multi-language array so clickByText
// still matches regardless of the page locale.
// ============================================================
const LANG_BUTTONS = {
  // "Continue" -> EN + es + pt + fr + de + it + jp + zh
  Continue: ["Continuar", "Continuar", "Continuer", "Weiter", "Continua", "続行", "继续"],
  // "Next" -> es + fr + de
  Next: ["Siguiente", "Suivant", "Weiter"],
  // "Allow access" -> es + fr
  "Allow access": ["Permitir acceso", "Autoriser l'accès", "Acceso permitido"],
  Allow: ["Permitir", "Autoriser", "Erlauben", "許可", "允许"],
  // "Confirm and continue" -> es + pt + fr + de
  "Confirm and continue": [
    "Confirmar y continuar",
    "Confirmar e continuar",
    "Confirmer et continuer",
    "Bestätigen und fortfahren",
  ],
  // "Create account" -> es + pt + fr + de
  "Create account": ["Crear cuenta", "Criar conta", "Créer un compte", "Konto erstellen"],
  // "Sign up" -> es + pt + fr + de
  "Sign up": ["Registrarse", "Inscrever-se", "S'inscrire", "Registrieren"],
  Submit: ["Enviar", "Envoyer", "Senden", "送信", "提交"],
  // "Send code" -> es + fr
  "Send code": ["Enviar código", "Envoyer le code", "Code senden"],
};

// ============================================================
// Realistic name pools (used by randomRealisticName()).
// Used to populate the "Your name" field on AWS Builder ID so accounts
// don't all look like "User Kiro".
// ============================================================
const REALISTIC_FIRST_NAMES = [
  "James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael", "Linda",
  "William", "Elizabeth", "David", "Barbara", "Richard", "Susan", "Joseph", "Jessica",
  "Thomas", "Sarah", "Chris", "Karen", "Daniel", "Nancy", "Matthew", "Lisa",
  "Anthony", "Betty", "Mark", "Sandra", "Donald", "Ashley", "Steven", "Kimberly",
  "Andrew", "Donna", "Paul", "Emily", "Joshua", "Michelle", "Kenneth", "Carol",
  "Kevin", "Amanda", "Brian", "Melissa", "George", "Deborah", "Edward", "Stephanie",
  "Ronald", "Rebecca", "Carlos", "Laura", "Diego", "Helen", "Ahmed", "Maria",
  "Wei", "Sofia", "Hassan", "Yuki", "Omar", "Mei", "Raj", "Priya",
  "Lucas", "Chloe", "Felix", "Nina", "Ivan", "Ana", "Mateo", "Elena",
];
const REALISTIC_LAST_NAMES = [
  "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
  "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson",
  "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson",
  "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson", "Walker",
  "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores",
  "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell",
  "Carter", "Roberts", "Kumar", "Singh", "Khan", "Patel", "Tanaka", "Suzuki",
  "Müller", "Novak", "Rossi", "Dubois", "Andersen", "Larsen", "Costa", "Silva",
];

/**
 * Launch a stealth browser with optional proxy and fingerprint.
 *
 * @param {object} config - Resolved config (uses config.headless).
 * @param {object} services - Shared services bag ({ proxy, fingerprint }).
 * @param {object} [options={}] - Launch options.
 * @param {string} [options.url] - URL to navigate to after launch.
 * @param {object} [options.proxy] - Pre-resolved proxy object (skips auto-load).
 * @param {object} [options.fingerprint] - Pre-generated fingerprint (skips auto-gen).
 * @returns {Promise<{browser: import("puppeteer").Browser, page: import("puppeteer").Page}>}
 */
async function launchStealthBrowser(config, services, options = {}) {
  // Proxy resolution: explicit options.proxy wins; otherwise auto-load from
  // services.proxy ONLY if a proxy file exists with entries. If the proxy
  // file is empty/missing → direct connection (dead/expired creds would
  // break the initial navigation, e.g. Google OAuth login).
  let proxy = options.proxy;
  if (proxy === undefined && services.proxy) {
    const pool =
      typeof services.proxy.loadProxies === "function"
        ? services.proxy.loadProxies()
        : null;
    if (pool && pool.length) {
      // Prefer a live proxy; if none alive, use first anyway (may still work).
      proxy =
        typeof services.proxy.pickLiveOrFirst === "function"
          ? await services.proxy.pickLiveOrFirst(pool)
          : pool[0];
    } else {
      proxy = null; // empty proxy file → direct connection
    }
  }
  const fingerprint = options.fingerprint || (services.fingerprint && services.fingerprint.generateFingerprint());

  const launchArgs = [];
  if (proxy) {
    const { chromiumArgsForProxy } = require("./proxy");
    launchArgs.push(...chromiumArgsForProxy(proxy));
  }
  // Common Puppeteer args
  launchArgs.push("--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage");

  // Per-provider chromiumPath override > top-level config. Some providers
  // need CloakBrowser's anti-detect Chromium for JA3 fingerprint matching;
  // others (kiro, antigravity) are happy with the default.
  const chromiumPath =
    options.chromiumPath || config.chromiumPath || config.executablePath;

  const browser = await puppeteer.launch({
    headless: config.headless !== false ? true : false,
    executablePath: chromiumPath,
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
 * Create a new page with fingerprint overrides applied via CDP.
 *
 * @param {import("puppeteer").Browser} browser - Puppeteer browser instance.
 * @param {object} [fingerprint] - Fingerprint overrides (viewport, locale, timezoneId, userAgent, acceptLanguage).
 * @returns {Promise<import("puppeteer").Page>}
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
 * React-compatible value setter for an input element handle.
 *
 * React components often ignore Puppeteer's page.type() because they use
 * synthetic events. This invokes the native value setter on the prototype
 * and dispatches input + change events so React's onChange fires.
 *
 * @param {import("puppeteer").ElementHandle} handle - Element handle for the input.
 * @param {string} value - Value to set.
 * @returns {Promise<void>}
 */
async function reactTypeInput(handle, value) {
  await handle.evaluate((el, v) => {
    const proto = Object.getPrototypeOf(el);
    const desc = Object.getOwnPropertyDescriptor(proto, "value");
    if (desc && desc.set) desc.set.call(el, v);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }, value);
}

/**
 * Click a button by matching its visible text against a list of target strings.
 *
 * Scores all candidates (visible, BUTTON tag, inside form, primary class) and
 * prefers the highest-scoring match. Walks up to the nearest clickable
 * ancestor (BUTTON / role=button / A) before dispatching the click so that
 * wrapper elements (e.g. a span inside a button) still produce a real click.
 * Cookie-banner elements are penalized.
 *
 * @param {import("puppeteer").Page} page - Puppeteer page.
 * @param {string[]} texts - Target button texts to match (substring match).
 * @returns {Promise<string|null>} The matched text (with " (ancestor)" suffix when the click was dispatched via an ancestor), or null if nothing matched.
 */
async function clickByText(page, texts) {
  return page.evaluate((targets) => {
    const all = Array.from(
      document.querySelectorAll('button, div[role="button"], a[role="button"], input[type="submit"], span')
    );
    // Score: prefer visible, prefer inside form, prefer BUTTON tag.
    const score = (el) => {
      let s = 0;
      const rect = el.getBoundingClientRect();
      if (rect.width > 0 && rect.height > 0) s += 100;
      if (el.tagName === "BUTTON") s += 50;
      if (el.closest && el.closest("form")) s += 30;
      const cls = (
        (el.className || "").toString() + " " + (el.getAttribute("type") || "")
      ).toLowerCase();
      if (/primary|cta|submit|awsui_button/i.test(cls)) s += 20;
      // Cookie-banner detection: id/class awsccc-*
      if (/(awsccc|cookie)/i.test(cls) || (el.closest && el.closest("[id*='awsccc']"))) s -= 200;
      return s;
    };
    const visible = all.filter((b) => {
      const r = b.getBoundingClientRect();
      return r.width > 0 && r.height > 0;
    });
    visible.sort((a, b) => score(b) - score(a));
    for (const t of targets) {
      const btn = visible.find((b) => {
        const text = (b.innerText || b.textContent || "").trim();
        return text === t || text.includes(t);
      });
      if (btn) {
        let el = btn;
        while (
          el &&
          el.tagName !== "BUTTON" &&
          el.getAttribute("role") !== "button" &&
          el.tagName !== "A" &&
          el.tagName !== "BODY"
        ) {
          el = el.parentElement;
        }
        if (el && el.tagName !== "BODY") {
          el.click();
          return t + " (ancestor)";
        }
        btn.click();
        return t;
      }
    }
    return null;
  }, texts);
}

/**
 * Safely read the current page URL. Returns "" if the page/tab has been
 * closed or is otherwise unavailable (avoids throwing during teardown).
 *
 * @param {import("puppeteer").Page} page - Puppeteer page.
 * @returns {string}
 */
function safeUrl(page) {
  try {
    return page.url() || "";
  } catch {
    return "";
  }
}

/**
 * Expand an array of EN button-text labels to include common translations.
 * Idempotent: labels that are already multi-lang are still processed
 * correctly (substring match). Used to make clickByText resilient to
 * AWS CloudScape locale switching.
 *
 * @param {string[]} arr - Array of English button labels.
 * @returns {string[]} Expanded array with translations appended.
 */
function lang(arr) {
  const out = [];
  for (const t of arr) {
    out.push(t);
    if (LANG_BUTTONS[t]) {
      for (const tl of LANG_BUTTONS[t]) {
        if (!out.includes(tl)) out.push(tl);
      }
    }
  }
  return out;
}

/**
 * Click an element by CSS selector. Returns the selector on success,
 * or null if the element was not found or the click failed.
 *
 * @param {import("puppeteer").Page} page - Puppeteer page.
 * @param {string} selector - CSS selector.
 * @returns {Promise<string|null>}
 */
async function clickBySelector(page, selector) {
  try {
    const el = await page.$(selector);
    if (el) {
      await el.click();
      return selector;
    }
  } catch {}
  return null;
}

/**
 * Dismiss an AWS / GDPR cookie banner if one is visible. Clicks the first
 * matching button (Accept cookies / Accept / Dismiss / OK / Got it / etc.).
 * The banner frequently overlays the form and misroutes clickByText.
 *
 * @param {import("puppeteer").Page} page - Puppeteer page.
 * @returns {Promise<string|null>} The label of the clicked button, or null.
 */
async function dismissCookieBanner(page) {
  try {
    const clicked = await page.evaluate(() => {
      const buttons = Array.from(
        document.querySelectorAll("button, a[role='button'], div[role='button']")
      );
      const labels = [
        /accept cookies/i,
        /^accept$/i,
        /^accept all$/i,
        /^dismiss$/i,
        /^ok$/i,
        /^got it$/i,
        /^decline$/i,
        /^decline all$/i,
        /^reject all$/i,
        /^i decline$/i,
      ];
      for (const b of buttons) {
        const rect = b.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) continue;
        const txt = (b.innerText || b.textContent || "").trim();
        if (!txt) continue;
        if (labels.some((p) => p.test(txt))) {
          b.click();
          return txt;
        }
      }
      return null;
    });
    if (clicked) {
      await new Promise((r) => setTimeout(r, 500));
      console.log(`Dismiss cookie banner: ${clicked}`);
    }
    return clicked;
  } catch {
    return null;
  }
}

/**
 * Click the primary button on the page via in-page JS click.
 *
 * Looks for the first visible, enabled BUTTON whose class contains
 * primary/cta/allow/confirm. Falls back to the last visible button on
 * the page.
 *
 * Note: this is DIFFERENT from clickPrimaryButtonMouse, which clicks at
 * coordinates via a real mouse event. Use this when a JS click is enough;
 * use clickPrimaryButtonMouse for AWS custom components that ignore
 * programmatic clicks.
 *
 * @param {import("puppeteer").Page} page - Puppeteer page.
 * @returns {Promise<string|null>} The clicked button's label, or null.
 */
async function clickPrimaryButton(page) {
  return page.evaluate(() => {
    const buttons = Array.from(document.querySelectorAll("button")).filter((b) => {
      if (b.disabled) return false;
      const rect = b.getBoundingClientRect();
      return rect.width > 0 && rect.height > 0;
    });
    const primary = buttons.find((b) => {
      const cls = (b.className || "").toLowerCase();
      return cls.includes("primary") || cls.includes("cta") || cls.includes("allow") || cls.includes("confirm");
    });
    const target = primary || buttons[buttons.length - 1];
    if (target) {
      target.click();
      return target.innerText.trim();
    }
    return null;
  });
}

/**
 * Click a button via a real mouse event at its center coordinates.
 *
 * More reliable than a programmatic .click() for custom AWS Builder ID
 * components that frequently ignore synthetic clicks. Finds visible,
 * enabled buttons (not in a cookie banner) whose label matches one of
 * `texts`, and clicks the largest (or topmost) match.
 *
 * @param {import("puppeteer").Page} page - Puppeteer page.
 * @param {string[]} texts - Lowercase substrings to match against button labels.
 * @param {{preferLargest?: boolean}} [opts] - When false, prefer the topmost match instead of the largest.
 * @returns {Promise<string|null>} The clicked button's label (truncated to 40 chars), or null.
 */
async function clickPrimaryButtonMouse(page, texts, opts = {}) {
  const preferLargest = opts.preferLargest !== false;
  const coord = await page.evaluate(
    (targets, wantLargest) => {
      const all = Array.from(
        document.querySelectorAll('button, [role="button"], input[type="submit"]')
      );
      const candidates = all.filter((b) => {
        if (b.disabled) return false;
        const t = (b.innerText || b.textContent || b.value || "").trim().toLowerCase();
        const match = targets.some((tg) => t === tg || t.includes(tg));
        if (!match) return false;
        const r = b.getBoundingClientRect();
        if (r.width === 0 || r.height === 0) return false;
        if (b.closest && b.closest("[id*='awsccc']")) return false; // skip cookie banner
        return true;
      });
      const list = candidates;
      if (wantLargest) {
        list.sort((a, b) => {
          const ra = a.getBoundingClientRect(), rb = b.getBoundingClientRect();
          return rb.width * rb.height - ra.width * ra.height;
        });
      } else {
        list.sort((a, b) => {
          const ra = a.getBoundingClientRect(), rb = b.getBoundingClientRect();
          return ra.y - rb.y; // topmost first
        });
      }
      const pick = list[0];
      if (pick) {
        const r = pick.getBoundingClientRect();
        return {
          x: r.x + r.width / 2,
          y: r.y + r.height / 2,
          label: (pick.innerText || pick.textContent || "").trim().slice(0, 40),
        };
      }
      return null;
    },
    texts,
    preferLargest
  );
  if (!coord) return null;
  await page.mouse.click(coord.x, coord.y);
  return coord.label;
}

/**
 * Bring a specific puppeteer page/tab to the front so user-agent key
 * events and clicks land on it instead of the most recently opened tab.
 *
 * @param {import("puppeteer").Page} page - Puppeteer page.
 * @returns {Promise<void>}
 */
async function focusPage(page) {
  try {
    await page.bringToFront();
  } catch {}
}

/**
 * Generate a realistic human name (first + last) for the "Your name"
 * field on AWS Builder ID. Prevents every account from looking like
 * "User Kiro".
 *
 * @returns {string} A realistic "<first> <last>" name.
 */
function randomRealisticName() {
  const first = REALISTIC_FIRST_NAMES[Math.floor(Math.random() * REALISTIC_FIRST_NAMES.length)];
  const last = REALISTIC_LAST_NAMES[Math.floor(Math.random() * REALISTIC_LAST_NAMES.length)];
  return `${first} ${last}`;
}

module.exports = {
  launchStealthBrowser,
  newStealthPage,
  reactTypeInput,
  clickByText,
  clickPrimaryButtonMouse,
  safeUrl,
  lang,
  clickBySelector,
  dismissCookieBanner,
  clickPrimaryButton,
  focusPage,
  randomRealisticName,
};
