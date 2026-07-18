# 9router-add: Modular Provider Account Automation

**Date:** 2026-07-19
**Status:** Draft
**Author:** Claude + elzanom

## 1. Overview

Modular automation system for adding accounts to various providers (VPN, proxy, etc.) integrated with 9router. Supports both local (same machine as 9router) and remote (VPS-based) modes.

**Key requirement:** Modularity — many providers will be supported with different automation flows (OAuth authorization code, OAuth device code, form-based, API-key, etc.). The system must make adding a new provider simple without duplicating infrastructure code.

### Scope

- **In scope:** Provider account creation, inspection, deletion; batch processing; quota tracking; browser automation with proxy/fingerprint; IMAP-based OTP extraction; local SQLite and remote API modes.
- **Out of scope:** 9router core (dashboard, API, database schema) — this system only integrates with existing 9router APIs. Provider-specific automation beyond the two initial providers (Antigravity, Kiro).

### References

- `/home/elzanom/work/tools/9router-agy/` — Antigravity provider (Google OAuth authorize/exchange flow, ~900 lines bot.js)
- `/home/elzanom/work/tools/9router-kiro/` — Kiro provider (device code + poll + IMAP OTP flow, ~2184 lines bot.js)
- Both projects share identical `config.js`, `auth.js`, `http-client.js` (duplicated code)

## 2. Architecture

### 2.1 Pattern: Class-based Provider Plugin

Each provider is a class extending `BaseProvider` with lifecycle hooks. Providers are auto-discovered from `src/providers/`.

**Why this approach over alternatives:**
- **Pipeline config (JSON):** Browser automation is too complex for declarative actions (multi-language buttons, conditional flows, error recovery). Would require Turing-complete config.
- **Plugin modules (exports):** No enforcement of interface. Developer can forget to implement required methods.
- **Class-based (chosen):** Clear contract via abstract methods, lifecycle hooks for cross-cutting concerns, auto-discovery, JSDoc type checking without TypeScript dependency.

### 2.2 Directory Structure

```
/home/elzanom/WORKER/9router-add/
├── src/
│   ├── core/                    # Shared infrastructure
│   │   ├── config.js            # Config loader: CLI → env → config.json → defaults
│   │   ├── auth.js              # cliToken() + dashboardSession() + resolveAuthHeaders()
│   │   ├── http-client.js       # HTTP request wrapper (http/https proto-aware)
│   │   ├── db.js                # SQLite wrapper (local mode: insert, update, find, delete)
│   │   └── cli.js               # CLI dispatcher + auto-discovery + argparse
│   │
│   ├── base/                    # Base classes & interfaces
│   │   ├── provider.js          # BaseProvider class — abstract methods + shared helpers
│   │   └── errors.js            # ProviderError, AuthError, QuotaError, RetryableError, BrowserError
│   │
│   ├── services/                # Cross-cutting services (reusable across providers)
│   │   ├── browser.js           # Browser launcher + helpers (extracted from monolith bot.js)
│   │   ├── imap-otp.js          # Gmail IMAP OTP extraction (copy from kiro, 233 lines)
│   │   ├── proxy.js             # Proxy rotation (copy from kiro, 103 lines)
│   │   ├── fingerprint.js       # Browser fingerprint randomization (copy from kiro, 110 lines)
│   │   ├── quota.js             # Per-UTC-day per-domain quota tracker (copy from kiro, 105 lines)
│   │   └── cloudflare-routing.js # Email alias generator (copy from kiro, 99 lines)
│   │
│   ├── providers/               # Plugin folder — auto-discovered
│   │   ├── antigravity/         # Google OAuth authorize/exchange
│   │   │   ├── index.js         # class Antigravity extends BaseProvider (~120 lines)
│   │   │   └── config.json      # Provider-specific defaults
│   │   └── kiro/                # Device code + poll + IMAP OTP
│   │       ├── index.js         # class Kiro extends BaseProvider (~200 lines)
│   │       └── config.json
│   │
│   └── index.js                 # Entry point: load config, auth, providers, dispatch CLI
│
├── test/
│   ├── unit/
│   │   ├── base/provider.test.js
│   │   ├── core/{config,auth,http-client}.test.js
│   │   └── services/{proxy,fingerprint,quota,cloudflare-routing,imap-otp}.test.js
│   ├── integration/
│   │   ├── antigravity.test.js
│   │   └── kiro.test.js
│   └── fixtures/
│
├── config.json                  # User config (gitignored)
├── package.json
├── CLAUDE.md
└── README.md
```

### 2.3 Data Flow

```
CLI (node . add antigravity --email=x@gmail.com)
    │
    ▼
index.js
    ├── loadConfig()            → Config object (CLI flags → env → config.json → defaults)
    ├── resolveAuthHeaders()    → Auth headers (CLI token or session cookie)
    ├── loadProviders()         → Auto-discover { antigravity: AntigravityProvider, ... }
    ├── loadServices()          → Init services (imap, proxy, fingerprint, quota, cfRouting)
    │
    ▼
new AntigravityProvider(config, api, services)
    │
    ▼
provider.add(credentials, options)
    ├── beforeAdd()             → [optional hook] Quota check, validation
    ├── apiCall(GET, /authorize)→ Dapat authorization URL dari 9router
    ├── launchBrowser()         → Browser + fingerprint + proxy via services
    ├── automateGoogleLogin()   → Login, capture OAuth code dari redirect
    ├── apiCall(POST, /exchange, {code}) → Tukar code untuk token
    ├── injectToDb()            → [local mode] SQLite insert
    └── afterAdd()              → [optional hook] Cleanup, log
```

## 3. Core Modules

### 3.1 config.js

Priority chain: CLI flags → env vars → config.json → defaults.

**Environment variables:** `9R_ADD_HOST`, `9R_ADD_PORT`, `9R_ADD_PROTO`, `9R_ADD_PASSWORD`, `9R_ADD_CLI_SECRET`, `9R_ADD_CONFIG`

**Config file candidates:** `process.cwd() + "/config.json"`, then `os.homedir() + "/.9router-add/config.json"`

**`resolveMode()`:** `auto` → local if `~/.9router/machine-id` exists AND host is localhost, otherwise remote.

**Provider-specific config:** `config.providers[name]` available as `this.config.providerConfig` in each provider instance.

**Security guard:** `if (cfg.mode === "remote" && cfg.proto === "http" && !isLocalHost(cfg.host))` → throw error. Never send dashboard password over HTTP to non-localhost.

### 3.2 auth.js

- **`cliToken()`:** SHA256 hash of `machineId + "9r-cli-auth" + cliSecret`, first 16 hex chars. Sent as `X-9R-CLI-Auth` header.
- **`dashboardSession()`:** POST to `/api/auth/login` with password, parse `Set-Cookie` for session cookie.
- **`resolveAuthHeaders()`:** Dispatches to local or remote auth based on config.mode.

### 3.3 http-client.js

- **`request(config, { method, path, body, cookies, headers })`** → `{ statusCode, headers, body }`
- Uses `http` or `https` module based on `config.proto`.
- Remote mode enforces HTTPS to non-localhost.

### 3.4 db.js

Local mode direct SQLite access to `~/.9router/db/data.sqlite`.

- `insert(connection)` — INSERT INTO providerConnections
- `update(id, data)` — UPDATE data JSON field
- `findById(id)` — SELECT by id
- `findByProvider(name)` — SELECT all by provider
- `delete(id)` — DELETE by id

**Schema** (providerConnections table):
| Column | Type | Notes |
|--------|------|-------|
| id | TEXT | UUID |
| provider | TEXT | e.g. "antigravity", "kiro" |
| authType | TEXT | "oauth", "google", "email" |
| name | TEXT | Display name |
| email | TEXT | Credential email |
| isActive | INTEGER | 0/1 |
| data | TEXT | JSON blob |
| createdAt | TEXT | ISO timestamp |
| updatedAt | TEXT | ISO timestamp |

### 3.5 cli.js

**Auto-discovery:** `fs.readdirSync("./src/providers/")` → `require` each `index.js` → map `providerName` → class.

**Commands:**
- `node . add <provider> [--email=] [--password=] [--name=] [--proxy=] [--dry-run]`
- `node . inspect <provider> <id>`
- `node . delete <provider> <id>`
- `node . list [provider]`
- `node . batch <file.json>`

**Argparse:** Minimal parser without dependencies (yargs/commander). Supports `--key=value`, `--flag`, `--key value`.

## 4. BaseProvider

### 4.1 Interface

```js
class BaseProvider {
  constructor(config, api, services)     // Services injected
  static get providerName()              // Abstract — must override
  static get endpoints()                 // Default: {}
  async add(credentials, options)        // Abstract — main flow
  async beforeAdd(credentials, options)  // Optional hook
  async afterAdd(result)                 // Optional hook
  async onError(err, context)            // Optional hook
  async inspect(id)                      // Optional
  async delete(id)                       // Optional
  // Shared helpers:
  apiCall(method, path, body, opts)
  injectToDb(connection)
  launchBrowser(options)
}
```

### 4.2 Lifecycle Hooks

- **`beforeAdd`** — Called before `add()`. Return `{ skip: true, reason }` to skip without error. Used for quota checks, credential validation.
- **`afterAdd`** — Called after successful `add()`. Used for logging, cleanup, stats update.
- **`onError`** — Called when `add()` throws. Can clean up resources (close browser, release locks).

### 4.3 Error Handling in BaseProvider

```js
async add(credentials, options) {
  try {
    await this.beforeAdd(credentials, options);
    // ... flow ...
    await this.afterAdd(result);
    return result;
  } catch (err) {
    await this.onError(err, { credentials, options });
    if (err instanceof QuotaError) return { ok: false, skip: true, reason: err.message };
    if (err instanceof AuthError) return { ok: false, error: err.message };
    throw err; // Unhandled → crash with stack trace
  }
}
```

## 5. Error Classes

| Class | Base | Code | Recoverable | Retryable | When |
|-------|------|------|-------------|-----------|------|
| ProviderError | Error | — | configurable | configurable | Base for all provider errors |
| AuthError | ProviderError | AUTH_FAILED | true | false | Login failed, token expired |
| QuotaError | ProviderError | QUOTA_EXCEEDED | true | false | Daily quota cap reached |
| RetryableError | ProviderError | RETRYABLE | false | true | Network timeout, 5xx |
| BrowserError | ProviderError | BROWSER_ERROR | false | true | Browser crash, element not found |

## 6. Services

### 6.1 browser.js (NEW — extracted from monoliths)

- `launchStealthBrowser(config, services, options)` — Launch Puppeteer with proxy + fingerprint
- `newStealthPage(browser, fingerprint)` — Per-page fingerprint overrides (viewport, locale, timezone)
- `reactTypeInput(page, selector, value)` — React-compatible value setter
- `clickByText(page, text, opts)` — Smart button clicker with multi-language support
- `clickPrimaryButtonMouse(page, coords)` — Click via real mouse events

### 6.2 imap-otp.js (copy from kiro, 233 lines)

- `getOtpViaImap(imapCfg, alias, opts)` — Poll Gmail IMAP for OTP, search INBOX + Spam, auto-delete
- `extractOtpFromRaw(raw)` — 3 regex patterns + fallback for 6-digit codes
- `buildGmrawQuery(alias, subject)` / `buildGmrawFallbackQuery(subject)` — X-GM-RAW queries
- `pickRecencyMatch(messages, opts)` — Select newest email in time window
- `findSpamPath(client)` — Detect Spam folder path via special-use \Junk

### 6.3 proxy.js (copy from kiro, 103 lines)

- `parseProxyLine(line)` — 3 format parsers (protocol://, host:port:user:pass, user:pass@host:port)
- `loadProxies(filePath)` — From file, skip invalid lines
- `getProxyForAccount(proxies, accountIndex)` — Cycle through pool by index
- `chromiumArgsForProxy(proxy)` — Build Puppeteer `--proxy-server` args

### 6.4 fingerprint.js (copy from kiro, 110 lines)

- `generateFingerprint(seed)` — Randomize UA, viewport, locale, timezone, hardware concurrency, device memory
- Seed option for deterministic output (Mulberry32 PRNG)

### 6.5 quota.js (copy from kiro, 105 lines)

- `tryConsume(filePath, email, cap)` — Check-and-increment atomically
- `loadStats()` / `saveStats()` — Atomic write (tmp + rename)
- `pruneOld(stats, keepDays)` — Keep only last 30 days
- Schema: `{ "2026-07-11": { "mozmail.com": 17 } }`

### 6.6 cloudflare-routing.js (copy from kiro, 99 lines)

- `generateAliases(domain, count)` — Realistic name-like aliases (e.g. "emma.walker37@minom.my.id")
- `appendAliasesToFile(filePath, aliases)` — Deduped append to file

## 7. Provider Implementations

### 7.1 Antigravity (~120 lines)

OAuth authorization code flow:
1. `GET /api/oauth/antigravity/authorize` → get authorization URL
2. Launch browser, Google login, wait for redirect to `/callback?code=...`
3. Capture `code` from redirect URL
4. `POST /api/oauth/antigravity/exchange` with code → get token
5. Inject to SQLite (local mode) or return for API (remote mode)

### 7.2 Kiro (~200 lines)

Device code + poll flow:
1. `POST /api/oauth/kiro/device-code` → get device code + verification URI
2. Auto-detect method: `@gmail.com` → Google login, else → email via alias forwarder
3. Browser automation: enter user code, complete AWS Builder ID registration
4. For email method: proxy rotation, fingerprint, IMAP OTP extraction
5. `POST /api/oauth/kiro/poll` until status === "connected"
6. BeforeAdd hook: quota check via services.quota

## 8. Security

- Dashboard password never sent over HTTP to non-localhost (remote mode requires HTTPS).
- Local auth uses `~/.9router/machine-id` + `cli-secret` → SHA256 → CLI token.
- Session cookie from dashboard login reused for all API calls in remote mode.
- Config file can contain sensitive values (passwords, IMAP credentials) — file should be gitignored.

## 9. Testing

### Unit Tests (node:test)
- `BaseProvider` — instantiation, abstract method enforcement, error handling
- Services — all pure functions, testable without browser/network
- `imap-otp.js` — injectable `clientFactory` for mock IMAP
- `config.js` — priority chain, mode resolution, security guard

### Integration Tests
- Mock API endpoints + mock browser for Antigravity flow
- Mock device code + mock IMAP for Kiro flow

## 10. File Size Comparison

| Component | Monolith (kiro) | Modular |
|-----------|:-:|:-:|
| bot.js | 2184 lines | ~200 lines (provider) |
| browser helpers | inline | ~150 lines (service) |
| imap-otp.js | 233 lines | 233 lines (copy) |
| proxy.js | 103 lines | 103 lines (copy) |
| fingerprint.js | 110 lines | 110 lines (copy) |
| quota.js | 105 lines | 105 lines (copy) |
| cloudflare-routing.js | 99 lines | 99 lines (copy) |
| **Total per new provider** | **~2200 lines** | **~200 lines** |

## 11. Adding a New Provider

1. Create folder `src/providers/<name>/`
2. Create `index.js` with class extending `BaseProvider`
3. Implement `providerName`, `add()`, (optionally) `inspect`/`delete`/hooks
4. Done — CLI auto-discovers, services available via `this.services`

No changes needed to `index.js`, `cli.js`, `config.js`, or any core module.

---

*End of design spec.*