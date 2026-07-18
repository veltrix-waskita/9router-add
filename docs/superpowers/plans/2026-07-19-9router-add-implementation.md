# 9router-add Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a modular provider account automation system for 9router with class-based provider plugins, shared services, and dual local/remote mode support.

**Architecture:** Class-based Provider Plugin pattern. Each provider extends `BaseProvider` with lifecycle hooks, auto-discovered from `src/providers/`. Shared infrastructure in `src/core/`, cross-cutting services in `src/services/`. Providers are ~200 lines instead of ~2200-line monoliths.

**Tech Stack:** Node.js 18+, CommonJS, Puppeteer-extra + stealth plugin, SQLite (sqlite3), imapflow, node:test (built-in test runner).

## Global Constraints

- Node.js 18+ required, CommonJS modules (`require`/`module.exports`) — no ESM, no TypeScript
- No external CLI argument parser — use minimal inline argparse
- `puppeteer-extra` + `puppeteer-extra-plugin-stealth` for browser automation
- `sqlite3` package for local SQLite access to `~/.9router/db/data.sqlite`
- `imapflow` for IMAP OTP extraction (Gmail)
- `node:test` for unit tests (built-in, no extra dependency)
- Config priority: CLI flags → env vars → `config.json` → defaults
- Security: never send dashboard password over HTTP to non-localhost
- All new provider code goes in `src/providers/<name>/index.js` — no core module changes needed

---
## File Structure

```
/home/elzanom/WORKER/9router-add/
├── src/
│   ├── core/
│   │   ├── config.js            # loadConfig(), resolveMode(), isLocalHost()
│   │   ├── auth.js              # cliToken(), dashboardSession(), resolveAuthHeaders()
│   │   ├── http-client.js       # request(config, opts) → { statusCode, headers, body }
│   │   ├── db.js                # insert, update, findById, findByProvider, delete
│   │   └── cli.js               # loadProviders(), loadServices(), parseArgs()
│   ├── base/
│   │   ├── provider.js          # BaseProvider class
│   │   └── errors.js            # ProviderError, AuthError, QuotaError, RetryableError, BrowserError
│   ├── services/
│   │   ├── browser.js           # launchStealthBrowser, newStealthPage, reactTypeInput, clickByText, clickPrimaryButtonMouse
│   │   ├── imap-otp.js          # getOtpViaImap, extractOtpFromRaw, buildGmrawQuery, pickRecencyMatch, findSpamPath
│   │   ├── proxy.js             # parseProxyLine, loadProxies, getProxyForAccount, chromiumArgsForProxy
│   │   ├── fingerprint.js       # generateFingerprint
│   │   ├── quota.js             # tryConsume, loadStats, saveStats, isAllowed, increment, pruneOld
│   │   └── cloudflare-routing.js # generateAliases, appendAliasesToFile, randomLocalPart
│   ├── providers/
│   │   ├── antigravity/
│   │   │   ├── index.js         # class Antigravity extends BaseProvider
│   │   │   └── config.json      # { "endpoints": { ... } }
│   │   └── kiro/
│   │       ├── index.js         # class Kiro extends BaseProvider
│   │       └── config.json      # { "endpoints": { ... }, "pollTimeout": 120000 }
│   └── index.js                 # main(): load config, auth, providers, dispatch CLI
├── test/
│   ├── unit/
│   │   ├── core/
│   │   │   ├── config.test.js
│   │   │   ├── auth.test.js
│   │   │   ├── http-client.test.js
│   │   │   └── db.test.js
│   │   ├── base/
│   │   │   ├── provider.test.js
│   │   │   └── errors.test.js
│   │   └── services/
│   │       ├── proxy.test.js
│   │       ├── fingerprint.test.js
│   │       ├── quota.test.js
│   │       ├── cloudflare-routing.test.js
│   │       └── imap-otp.test.js
│   ├── integration/
│   │   └── cli.test.js
│   └── fixtures/
│       ├── proxies.txt
│       └── test-config.json
├── package.json
├── CLAUDE.md
├── .gitignore
└── README.md
```

### Dependency Map

```
index.js
  ├── core/config.js       ← no deps
  ├── core/auth.js         ← depends on core/config
  ├── core/http-client.js  ← no deps (uses built-in http/https)
  ├── core/cli.js          ← discovers src/providers/*/index.js
  ├── core/db.js           ← depends on sqlite3
  ├── base/provider.js     ← depends on base/errors.js, core/http-client.js (optional)
  ├── base/errors.js       ← no deps
  ├── services/*           ← independent modules (no internal deps between them)
  └── providers/*          ← depends on base/provider.js, services/*
```

Build order: errors.js → config.js → auth.js → http-client.js → db.js → BaseProvider → services → cli.js → index.js → providers

---

### Task 1: Project Scaffolding

**Files:**
- Create: `package.json`
- Create: `.gitignore`
- Create: `README.md`
- Create: `test/fixtures/test-config.json`
- Create: `test/fixtures/proxies.txt`
- Create: `config.json` (example)

**Interfaces:**
- Consumes: nothing (first task)
- Produces: `package.json` with scripts, `npm test` works

- [ ] **Step 1: Create package.json**

```json
{
  "name": "9router-add",
  "version": "0.1.0",
  "private": true,
  "type": "commonjs",
  "main": "src/index.js",
  "scripts": {
    "test": "node --test",
    "start": "node src/index.js"
  },
  "dependencies": {
    "puppeteer-core": "^25.3.0",
    "puppeteer-extra": "^3.3.6",
    "puppeteer-extra-plugin-stealth": "^2.11.2",
    "sqlite3": "^6.0.1",
    "imapflow": "^1.4.7"
  },
  "devDependencies": {}
}
```

- [ ] **Step 2: Create .gitignore**

```
node_modules/
config.json
.env
*.log
test/fixtures/aliases.txt
.batch-stats.json
proxies.txt
```

- [ ] **Step 3: Create directory structure**

Run: `mkdir -p src/core src/base src/services src/providers/antigravity src/providers/kiro test/unit/core test/unit/base test/unit/services test/integration test/fixtures`

- [ ] **Step 4: Create test fixtures**

`test/fixtures/test-config.json`:
```json
{
  "host": "localhost",
  "port": 3000,
  "proto": "http",
  "mode": "local",
  "cliSecret": "test-secret-123"
}
```

`test/fixtures/proxies.txt`:
```
http://user1:pass1@192.168.1.1:8080
10.0.0.1:3128:user2:pass2
user3:pass3@proxy.example.com:8888
# comment line
192.168.1.2:8080
```

- [ ] **Step 5: Create README.md**

```markdown
# 9router-add

Modular automation system for adding accounts to providers integrated with 9router.

## Usage

```bash
node . add <provider> --email=x@y.com --password=xxx
node . list
node . inspect <provider> <id>
node . delete <provider> <id>
node . batch <batch-file.json>
```

## Setup

1. `npm install`
2. Copy `config.example.json` to `config.json` and edit
3. Run `node . add antigravity --email=... --password=...`
```

- [ ] **Step 6: Verify structure**

Run: `ls -R src/ test/` — verify all directories exist

- [ ] **Step 7: Commit**

```bash
git init
git add package.json .gitignore README.md test/fixtures/ test/unit/
git commit -m "chore: scaffold project structure"

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
```

---

### Task 2: Core — errors.js (Custom Error Classes)

**Files:**
- Create: `src/base/errors.js`
- Create: `test/unit/base/errors.test.js`

**Interfaces:**
- Produces: `ProviderError`, `AuthError`, `QuotaError`, `RetryableError`, `BrowserError` — all extending Error with `.code`, `.recoverable`, `.retryable` properties

- [ ] **Step 1: Write the failing test**

`test/unit/base/errors.test.js`:
```js
"use strict";
const { describe, it } = require("node:test");
const assert = require("node:assert");
const {
  ProviderError,
  AuthError,
  QuotaError,
  RetryableError,
  BrowserError,
} = require("../../src/base/errors");

describe("ProviderError", () => {
  it("should set message, code, recoverable, retryable", () => {
    const err = new ProviderError("test", { code: "TEST", recoverable: true, retryable: false });
    assert.strictEqual(err.message, "test");
    assert.strictEqual(err.code, "TEST");
    assert.strictEqual(err.recoverable, true);
    assert.strictEqual(err.retryable, false);
    assert.strictEqual(err.name, "ProviderError");
  });
  it("should default to recoverable=false, retryable=false", () => {
    const err = new ProviderError("default");
    assert.strictEqual(err.recoverable, false);
    assert.strictEqual(err.retryable, false);
  });
});

describe("AuthError", () => {
  it("should set code=AUTH_FAILED, recoverable=true", () => {
    const err = new AuthError("login failed");
    assert.strictEqual(err.message, "login failed");
    assert.strictEqual(err.code, "AUTH_FAILED");
    assert.strictEqual(err.recoverable, true);
    assert.strictEqual(err.name, "AuthError");
  });
});

describe("QuotaError", () => {
  it("should set code=QUOTA_EXCEEDED, recoverable=true", () => {
    const err = new QuotaError("mozmail.com");
    assert.ok(err.message.includes("mozmail.com"));
    assert.strictEqual(err.code, "QUOTA_EXCEEDED");
    assert.strictEqual(err.recoverable, true);
    assert.strictEqual(err.name, "QuotaError");
  });
});

describe("RetryableError", () => {
  it("should set retryable=true", () => {
    const err = new RetryableError("timeout");
    assert.strictEqual(err.retryable, true);
    assert.strictEqual(err.name, "RetryableError");
  });
});

describe("BrowserError", () => {
  it("should set retryable=true, code=BROWSER_ERROR", () => {
    const err = new BrowserError("crash");
    assert.strictEqual(err.retryable, true);
    assert.strictEqual(err.code, "BROWSER_ERROR");
    assert.strictEqual(err.name, "BrowserError");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/unit/base/errors.test.js`
Expected: FAIL — "Cannot find module" errors.js

- [ ] **Step 3: Write minimal implementation**

`src/base/errors.js`:
```js
"use strict";

class ProviderError extends Error {
  constructor(message, { code, recoverable = false, retryable = false } = {}) {
    super(message);
    this.name = "ProviderError";
    this.code = code || null;
    this.recoverable = recoverable;
    this.retryable = retryable;
  }
}

class AuthError extends ProviderError {
  constructor(message, code = "AUTH_FAILED") {
    super(message, { code, recoverable: true });
    this.name = "AuthError";
  }
}

class QuotaError extends ProviderError {
  constructor(domain) {
    super(`Quota cap reached for domain: ${domain}`, {
      code: "QUOTA_EXCEEDED",
      recoverable: true,
    });
    this.name = "QuotaError";
  }
}

class RetryableError extends ProviderError {
  constructor(message, code = "RETRYABLE") {
    super(message, { code, retryable: true });
    this.name = "RetryableError";
  }
}

class BrowserError extends ProviderError {
  constructor(message, code = "BROWSER_ERROR") {
    super(message, { code, retryable: true });
    this.name = "BrowserError";
  }
}

module.exports = { ProviderError, AuthError, QuotaError, RetryableError, BrowserError };
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test test/unit/base/errors.test.js`
Expected: PASS (all 5 test cases)

- [ ] **Step 5: Commit**

```bash
git add src/base/errors.js test/unit/base/errors.test.js
git commit -m "feat: add custom error classes (ProviderError, AuthError, QuotaError, RetryableError, BrowserError)"

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
```

---

### Task 3: Core — config.js

**Files:**
- Create: `src/core/config.js`
- Create: `test/unit/core/config.test.js`

**Interfaces:**
- Exports: `loadConfig(argv)` → `{ host, port, proto, mode, cliSecret, password, providerConfig, ... }`
- Exports: `resolveMode(cfg)` → `"local"` or `"remote"`
- Exports: `isLocalHost(host)` → `boolean`

- [ ] **Step 1: Write the failing test**

`test/unit/core/config.test.js`:
```js
"use strict";
const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const path = require("path");
const fs = require("fs");
const os = require("os");

// Load module fresh each test by clearing require cache
function loadConfigModule() {
  delete require.cache[require.resolve("../../src/core/config")];
  return require("../../src/core/config");
}

describe("isLocalHost", () => {
  it("should return true for localhost", () => {
    const { isLocalHost } = loadConfigModule();
    assert.strictEqual(isLocalHost("localhost"), true);
    assert.strictEqual(isLocalHost("127.0.0.1"), true);
    assert.strictEqual(isLocalHost("::1"), true);
  });
  it("should return false for external hosts", () => {
    const { isLocalHost } = loadConfigModule();
    assert.strictEqual(isLocalHost("example.com"), false);
    assert.strictEqual(isLocalHost("192.168.1.1"), false);
  });
});

describe("resolveMode", () => {
  it("should return local when machine-id exists and host is localhost", () => {
    const { resolveMode } = loadConfigModule();
    const result = resolveMode({ host: "localhost", mode: "auto" });
    // machine-id check depends on ~/.9router/machine-id existence
    // We just test the logic: if host is localhost and mode is auto
    assert.strictEqual(result, "local");
  });
  it("should return remote when host is external", () => {
    const { resolveMode } = loadConfigModule();
    const result = resolveMode({ host: "vps.example.com", mode: "auto" });
    assert.strictEqual(result, "remote");
  });
  it("should return explicit mode as-is", () => {
    const { resolveMode } = loadConfigModule();
    assert.strictEqual(resolveMode({ host: "localhost", mode: "remote" }), "remote");
    assert.strictEqual(resolveMode({ host: "vps.example.com", mode: "local" }), "local");
  });
});

describe("loadConfig", () => {
  const origEnv = { ...process.env };
  const configDir = path.join(os.tmpdir(), "9router-add-test-" + Date.now());
  const configPath = path.join(configDir, "config.json");

  before(() => {
    fs.mkdirSync(configDir, { recursive: true });
    fs.writeFileSync(configPath, JSON.stringify({
      host: "custom.local",
      port: 4000,
      proto: "https",
    }));
  });

  after(() => {
    fs.rmSync(configDir, { recursive: true, force: true });
    // Restore env
    for (const k of Object.keys(process.env)) {
      if (k.startsWith("9R_ADD_")) delete process.env[k];
    }
  });

  it("should use defaults when no config or env", () => {
    const { loadConfig } = loadConfigModule();
    const cfg = loadConfig([], { secure: false }); // disable file lookup for this test
    assert.strictEqual(cfg.host, "localhost");
    assert.strictEqual(cfg.port, 3000);
    assert.strictEqual(cfg.proto, "http");
  });

  it("should read from config file", () => {
    const { loadConfig } = loadConfigModule();
    const cfg = loadConfig([], { configPath });
    assert.strictEqual(cfg.host, "custom.local");
    assert.strictEqual(cfg.port, 4000);
    assert.strictEqual(cfg.proto, "https");
  });

  it("should override with env vars", () => {
    process.env["9R_ADD_HOST"] = "env.host";
    process.env["9R_ADD_PORT"] = "5000";
    const { loadConfig } = loadConfigModule();
    const cfg = loadConfig([], { configPath });
    assert.strictEqual(cfg.host, "env.host");
    assert.strictEqual(cfg.port, 5000);
    delete process.env["9R_ADD_HOST"];
    delete process.env["9R_ADD_PORT"];
  });

  it("should throw on remote + http + non-localhost", () => {
    const { loadConfig } = loadConfigModule();
    assert.throws(() => {
      loadConfig([], {
        mode: "remote",
        host: "vps.example.com",
        proto: "http",
        secure: false,
      });
    }, /HTTPS required/i);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/unit/core/config.test.js`
Expected: FAIL — "Cannot find module" config.js

- [ ] **Step 3: Write minimal implementation**

`src/core/config.js`:
```js
"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");

const DEFAULTS = {
  host: "localhost",
  port: 3000,
  proto: "http",
  mode: "auto",
};

function isLocalHost(host) {
  if (!host) return false;
  const lower = host.toLowerCase();
  return lower === "localhost" || lower === "127.0.0.1" || lower === "::1" || lower === "0.0.0.0";
}

function resolveMode(cfg) {
  if (cfg.mode && cfg.mode !== "auto") return cfg.mode;
  const machineIdPath = path.join(os.homedir(), ".9router", "machine-id");
  const hasMachineId = fs.existsSync(machineIdPath);
  if (hasMachineId && isLocalHost(cfg.host)) return "local";
  return "remote";
}

function loadConfig(argv, opts = {}) {
  let cfg = { ...DEFAULTS };

  // 1. Config file
  const configPaths = [];
  if (opts.configPath) {
    configPaths.push(opts.configPath);
  } else {
    configPaths.push(path.join(process.cwd(), "config.json"));
    configPaths.push(path.join(os.homedir(), ".9router-add", "config.json"));
  }
  for (const cp of configPaths) {
    if (fs.existsSync(cp)) {
      try {
        const fileCfg = JSON.parse(fs.readFileSync(cp, "utf8"));
        cfg = { ...cfg, ...fileCfg };
        break;
      } catch (e) {
        console.warn(`[config] warning: ignoring invalid config file ${cp}: ${e.message}`);
      }
    }
  }

  // 2. Environment variables
  const envMap = {
    "9R_ADD_HOST": "host",
    "9R_ADD_PORT": "port",
    "9R_ADD_PROTO": "proto",
    "9R_ADD_PASSWORD": "password",
    "9R_ADD_CLI_SECRET": "cliSecret",
    "9R_ADD_MODE": "mode",
  };
  for (const [envKey, cfgKey] of Object.entries(envMap)) {
    if (process.env[envKey]) {
      cfg[cfgKey] = cfgKey === "port" ? Number(process.env[envKey]) : process.env[envKey];
    }
  }

  // 3. CLI flags (override anything)
  if (opts.mode) cfg.mode = opts.mode;
  if (opts.host) cfg.host = opts.host;
  if (opts.port) cfg.port = opts.port;
  if (opts.proto) cfg.proto = opts.proto;

  // 4. Resolve mode
  cfg.mode = resolveMode(cfg);

  // 5. Security guard
  if (cfg.mode === "remote" && cfg.proto === "http" && !isLocalHost(cfg.host)) {
    throw new Error(
      `Security: HTTPS required for remote mode (${cfg.host}). Set proto=https or use local mode.`
    );
  }

  // 6. Provider-specific config
  cfg.providerConfig = (cfg.providers && cfg.providers[cfg._provider]) || {};

  return cfg;
}

module.exports = { loadConfig, resolveMode, isLocalHost, DEFAULTS };
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test test/unit/core/config.test.js`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/core/config.js test/unit/core/config.test.js
git commit -m "feat: add config loader with priority chain, mode resolution, security guard"

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
```

---

### Task 4: Core — auth.js

**Files:**
- Create: `src/core/auth.js`
- Create: `test/unit/core/auth.test.js`

**Interfaces:**
- Exports: `cliToken(config)` → `string` (16 hex chars)
- Exports: `dashboardSession(config, httpClient)` → `string` (cookie)
- Exports: `resolveAuthHeaders(config, httpClient)` → `Object` (headers dict)

- [ ] **Step 1: Write the failing test**

`test/unit/core/auth.test.js`:
```js
"use strict";
const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");
const os = require("os");

function loadAuthModule() {
  delete require.cache[require.resolve("../../src/core/auth")];
  return require("../../src/core/auth");
}

describe("cliToken", () => {
  const tmpDir = path.join(os.tmpdir(), "9router-auth-test-" + Date.now());
  const machineIdPath = path.join(tmpDir, "machine-id");

  before(() => {
    fs.mkdirSync(tmpDir, { recursive: true });
    fs.writeFileSync(machineIdPath, "test-machine-id-123");
  });

  after(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("should produce a 16-char hex token", () => {
    const { cliToken } = loadAuthModule();
    const token = cliToken({
      machineIdPath,
      cliSecret: "my-secret",
    });
    assert.strictEqual(token.length, 16);
    assert.ok(/^[0-9a-f]+$/.test(token));
  });

  it("should produce consistent output for same inputs", () => {
    const { cliToken } = loadAuthModule();
    const a = cliToken({ machineIdPath, cliSecret: "my-secret" });
    const b = cliToken({ machineIdPath, cliSecret: "my-secret" });
    assert.strictEqual(a, b);
  });
});

describe("resolveAuthHeaders", () => {
  it("should return cli-token headers in local mode", () => {
    const { resolveAuthHeaders } = loadAuthModule();
    // Mock cliToken to return a known value
    const headers = resolveAuthHeaders({
      mode: "local",
      cliSecret: "test",
      machineIdPath: "/nonexistent",
    });
    assert.ok(headers["X-9R-CLI-Auth"]);
    assert.strictEqual(headers["Content-Type"], "application/json");
  });

  it("should return session headers in remote mode", async () => {
    const { resolveAuthHeaders } = loadAuthModule();
    let loginCalled = false;
    const mockHttp = {
      request: async (cfg, opts) => {
        loginCalled = true;
        assert.strictEqual(opts.path, "/api/auth/login");
        assert.strictEqual(opts.method, "POST");
        assert.strictEqual(JSON.parse(opts.body).password, "test-pass");
        return {
          statusCode: 200,
          headers: { "set-cookie": "connect.sid=s%3Aabc123.xyz; Path=/; HttpOnly" },
          body: { ok: true },
        };
      },
    };
    const headers = await resolveAuthHeaders(
      { mode: "remote", host: "localhost", port: 3000, proto: "http", password: "test-pass" },
      mockHttp
    );
    assert.ok(loginCalled);
    assert.ok(headers["Cookie"]);
    assert.strictEqual(headers["Content-Type"], "application/json");
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/unit/core/auth.test.js`
Expected: FAIL — "Cannot find module"

- [ ] **Step 3: Write minimal implementation**

`src/core/auth.js`:
```js
"use strict";

const crypto = require("crypto");
const fs = require("fs");

function cliToken(config) {
  const machineIdPath = config.machineIdPath || require("path").join(require("os").homedir(), ".9router", "machine-id");
  let machineId;
  try {
    machineId = fs.readFileSync(machineIdPath, "utf8").trim();
  } catch {
    throw new Error(`Cannot read machine-id from ${machineIdPath}`);
  }
  const hash = crypto.createHash("sha256").update(machineId + "9r-cli-auth" + config.cliSecret).digest("hex");
  return hash.slice(0, 16);
}

async function dashboardSession(config, httpClient) {
  const res = await httpClient.request(config, {
    method: "POST",
    path: "/api/auth/login",
    body: JSON.stringify({ password: config.password }),
    headers: { "Content-Type": "application/json" },
  });
  if (res.statusCode !== 200) {
    throw new Error(`Dashboard login failed: ${res.statusCode}`);
  }
  const setCookie = res.headers["set-cookie"];
  if (!setCookie) throw new Error("No session cookie returned");
  // Extract cookie value before semicolon
  const cookie = setCookie.split(";")[0].trim();
  return cookie;
}

async function resolveAuthHeaders(config, httpClient) {
  if (config.mode === "local") {
    const token = cliToken(config);
    return {
      "X-9R-CLI-Auth": token,
      "Content-Type": "application/json",
    };
  }
  // Remote mode
  const cookie = await dashboardSession(config, httpClient);
  return {
    Cookie: cookie,
    "Content-Type": "application/json",
  };
}

module.exports = { cliToken, dashboardSession, resolveAuthHeaders };
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test test/unit/core/auth.test.js`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/core/auth.js test/unit/core/auth.test.js
git commit -m "feat: add auth module (cliToken, dashboardSession, resolveAuthHeaders)"

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
```

---

### Task 5: Core — http-client.js

**Files:**
- Create: `src/core/http-client.js`
- Create: `test/unit/core/http-client.test.js`

**Interfaces:**
- Exports: `request(config, { method, path, body, headers, cookies })` → `{ statusCode, headers, body }`

- [ ] **Step 1: Write the failing test**

`test/unit/core/http-client.test.js`:
```js
"use strict";
const { describe, it } = require("node:test");
const assert = require("node:assert");
const http = require("http");

function loadHttpModule() {
  delete require.cache[require.resolve("../../src/core/http-client")];
  return require("../../src/core/http-client");
}

describe("request", () => {
  it("should make a GET request and return response", async () => {
    const { request } = loadHttpModule();
    // Start a local test server
    const server = http.createServer((req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true, path: req.url }));
    });
    await new Promise(r => server.listen(0, r));
    const port = server.address().port;

    const result = await request(
      { host: "localhost", port, proto: "http" },
      { method: "GET", path: "/api/test" }
    );
    assert.strictEqual(result.statusCode, 200);
    assert.strictEqual(result.body.ok, true);
    assert.strictEqual(result.body.path, "/api/test");

    server.close();
  });

  it("should POST with body", async () => {
    const { request } = loadHttpModule();
    const server = http.createServer((req, res) => {
      let body = "";
      req.on("data", c => body += c);
      req.on("end", () => {
        res.writeHead(201, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ received: JSON.parse(body) }));
      });
    });
    await new Promise(r => server.listen(0, r));
    const port = server.address().port;

    const result = await request(
      { host: "localhost", port, proto: "http" },
      { method: "POST", path: "/api/test", body: JSON.stringify({ hello: "world" }) }
    );
    assert.strictEqual(result.statusCode, 201);
    assert.strictEqual(result.body.received.hello, "world");

    server.close();
  });

  it("should include custom headers", async () => {
    const { request } = loadHttpModule();
    const server = http.createServer((req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ auth: req.headers["x-9r-cli-auth"] }));
    });
    await new Promise(r => server.listen(0, r));
    const port = server.address().port;

    const result = await request(
      { host: "localhost", port, proto: "http" },
      { method: "GET", path: "/api/test", headers: { "X-9R-CLI-Auth": "abc123" } }
    );
    assert.strictEqual(result.body.auth, "abc123");

    server.close();
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/unit/core/http-client.test.js`
Expected: FAIL — "Cannot find module"

- [ ] **Step 3: Write minimal implementation**

`src/core/http-client.js`:
```js
"use strict";

const http = require("http");
const https = require("https");

function request(config, { method = "GET", path = "/", body, headers = {}, cookies } = {}) {
  return new Promise((resolve, reject) => {
    const mod = config.proto === "https" ? https : http;
    const reqHeaders = { ...headers };

    if (cookies) {
      reqHeaders["Cookie"] = cookies;
    }
    if (body && !reqHeaders["Content-Type"]) {
      reqHeaders["Content-Type"] = "application/json";
    }
    if (body && !reqHeaders["Content-Length"]) {
      reqHeaders["Content-Length"] = Buffer.byteLength(body, "utf8");
    }

    const options = {
      hostname: config.host,
      port: config.port,
      path,
      method,
      headers: reqHeaders,
      rejectUnauthorized: config.proto === "https",
    };

    const req = mod.request(options, (res) => {
      const data = [];
      res.on("data", (chunk) => data.push(chunk));
      res.on("end", () => {
        const raw = Buffer.concat(data).toString("utf8");
        let parsed;
        try {
          parsed = JSON.parse(raw);
        } catch {
          parsed = raw;
        }
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: parsed,
        });
      });
    });

    req.on("error", reject);
    req.setTimeout(30000, () => { req.destroy(new Error("Request timeout")); });

    if (body) req.write(body);
    req.end();
  });
}

module.exports = { request };
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test test/unit/core/http-client.test.js`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/core/http-client.js test/unit/core/http-client.test.js
git commit -m "feat: add http-client module (proto-aware request wrapper)"

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
```

---

### Task 6: Core — db.js (SQLite Wrapper)

**Files:**
- Create: `src/core/db.js`
- Create: `test/unit/core/db.test.js`

**Interfaces:**
- Exports: `insert(config, connection)` → `{ id }`
- Exports: `findById(config, id)` → `Object|null`
- Exports: `findByProvider(config, provider)` → `Array`
- Exports: `update(config, id, data)` → `void`
- Exports: `delete(config, id)` → `void`
- Exports: `getDb(config)` → `Database` (sqlite3 instance)

- [ ] **Step 1: Write the failing test**

`test/unit/core/db.test.js`:
```js
"use strict";
const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");
const os = require("os");

function loadDbModule() {
  delete require.cache[require.resolve("../../src/core/db")];
  return require("../../src/core/db");
}

const tmpDir = path.join(os.tmpdir(), "9router-db-test-" + Date.now());
const dbPath = path.join(tmpDir, "data.sqlite");

describe("db", () => {
  before(() => {
    fs.mkdirSync(tmpDir, { recursive: true });
  });

  after(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("should insert a connection and return id", async () => {
    const { insert } = loadDbModule();
    const result = await insert(
      { dbPath },
      { provider: "test", authType: "oauth", name: "Test", email: "test@example.com", data: { foo: "bar" } }
    );
    assert.ok(result.id);
    assert.strictEqual(result.id.length, 36); // UUID
  });

  it("should find by id", async () => {
    const { insert, findById } = loadDbModule();
    const { id } = await insert(
      { dbPath },
      { provider: "test", authType: "oauth", name: "Find Me", email: "find@example.com" }
    );
    const found = await findById({ dbPath }, id);
    assert.ok(found);
    assert.strictEqual(found.name, "Find Me");
    assert.strictEqual(found.provider, "test");
  });

  it("should find by provider", async () => {
    const { findByProvider } = loadDbModule();
    const results = await findByProvider({ dbPath }, "test");
    assert.ok(Array.isArray(results));
    assert.ok(results.length >= 2);
  });

  it("should update data", async () => {
    const { insert, update, findById } = loadDbModule();
    const { id } = await insert(
      { dbPath },
      { provider: "test", authType: "oauth", name: "Update Test", email: "update@example.com" }
    );
    await update({ dbPath }, id, { newField: "value" });
    const found = await findById({ dbPath }, id);
    assert.strictEqual(found.data.newField, "value");
  });

  it("should delete by id", async () => {
    const { insert, del, findById } = loadDbModule();
    const { id } = await insert(
      { dbPath },
      { provider: "test", authType: "oauth", name: "Delete Me", email: "delete@example.com" }
    );
    await del({ dbPath }, id);
    const found = await findById({ dbPath }, id);
    assert.strictEqual(found, null);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/unit/core/db.test.js`
Expected: FAIL — "Cannot find module"

- [ ] **Step 3: Write minimal implementation**

`src/core/db.js`:
```js
"use strict";

const sqlite3 = require("sqlite3");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

function uuid() {
  return crypto.randomUUID();
}

function getDb(config) {
  const dbPath = config.dbPath || path.join(require("os").homedir(), ".9router", "db", "data.sqlite");
  return new Promise((resolve, reject) => {
    const db = new sqlite3.Database(dbPath, (err) => {
      if (err) return reject(err);
      // Ensure table exists
      db.run(`CREATE TABLE IF NOT EXISTS providerConnections (
        id TEXT PRIMARY KEY,
        provider TEXT NOT NULL,
        authType TEXT NOT NULL DEFAULT 'oauth',
        name TEXT,
        email TEXT,
        isActive INTEGER DEFAULT 1,
        data TEXT DEFAULT '{}',
        createdAt TEXT DEFAULT (datetime('now')),
        updatedAt TEXT DEFAULT (datetime('now'))
      )`, (err2) => {
        if (err2) return reject(err2);
        resolve(db);
      });
    });
  });
}

async function insert(config, connection) {
  const db = await getDb(config);
  const id = uuid();
  const now = new Date().toISOString();
  return new Promise((resolve, reject) => {
    db.run(
      `INSERT INTO providerConnections (id, provider, authType, name, email, isActive, data, createdAt, updatedAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        id,
        connection.provider,
        connection.authType || "oauth",
        connection.name || null,
        connection.email || null,
        connection.isActive !== undefined ? (connection.isActive ? 1 : 0) : 1,
        JSON.stringify(connection.data || {}),
        now,
        now,
      ],
      (err) => {
        db.close();
        if (err) return reject(err);
        resolve({ id, ...connection });
      }
    );
  });
}

async function findById(config, id) {
  const db = await getDb(config);
  return new Promise((resolve, reject) => {
    db.get("SELECT * FROM providerConnections WHERE id = ?", [id], (err, row) => {
      db.close();
      if (err) return reject(err);
      if (!row) return resolve(null);
      row.data = JSON.parse(row.data || "{}");
      resolve(row);
    });
  });
}

async function findByProvider(config, provider) {
  const db = await getDb(config);
  return new Promise((resolve, reject) => {
    db.all("SELECT * FROM providerConnections WHERE provider = ? ORDER BY createdAt DESC", [provider], (err, rows) => {
      db.close();
      if (err) return reject(err);
      for (const row of rows) {
        row.data = JSON.parse(row.data || "{}");
      }
      resolve(rows);
    });
  });
}

async function update(config, id, data) {
  const db = await getDb(config);
  const now = new Date().toISOString();
  return new Promise((resolve, reject) => {
    db.run(
      "UPDATE providerConnections SET data = ?, updatedAt = ? WHERE id = ?",
      [JSON.stringify(data), now, id],
      (err) => {
        db.close();
        if (err) return reject(err);
        resolve();
      }
    );
  });
}

async function del(config, id) {
  const db = await getDb(config);
  return new Promise((resolve, reject) => {
    db.run("DELETE FROM providerConnections WHERE id = ?", [id], (err) => {
      db.close();
      if (err) return reject(err);
      resolve();
    });
  });
}

module.exports = { getDb, insert, findById, findByProvider, update, del };
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test test/unit/core/db.test.js`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/core/db.js test/unit/core/db.test.js
git commit -m "feat: add SQLite db wrapper (insert, findById, findByProvider, update, delete)"

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
```

---

### Task 7: Base — provider.js (BaseProvider)

**Files:**
- Create: `src/base/provider.js`
- Create: `test/unit/base/provider.test.js`

**Interfaces:**
- Exports: `BaseProvider` class
  - `constructor(config, api, services)` — stores all three
  - `static get providerName()` — throws if not overridden
  - `static get endpoints()` — returns `{}`
  - `async add(credentials, options)` — throws if not overridden
  - `async beforeAdd(credentials, options)` — no-op, returns undefined
  - `async afterAdd(result)` — no-op
  - `async onError(err, context)` — no-op
  - `async inspect(id)` — throws if not overridden
  - `async delete(id)` — throws if not overridden
  - `apiCall(method, path, body, opts)` — delegates to `this.api.request`
  - `injectToDb(connection)` — delegates to `db.insert`
  - `launchBrowser(options)` — delegates to `browser.launchStealthBrowser`
  - `add()` wraps with `beforeAdd`/`afterAdd`/`onError` lifecycle

- [ ] **Step 1: Write the failing test**

`test/unit/base/provider.test.js`:
```js
"use strict";
const { describe, it } = require("node:test");
const assert = require("node:assert");
const { ProviderError, AuthError } = require("../../src/base/errors");

function loadProvider() {
  delete require.cache[require.resolve("../../src/base/provider")];
  return require("../../src/base/provider");
}

describe("BaseProvider", () => {
  it("should throw if instantiated directly", () => {
    const { BaseProvider } = loadProvider();
    assert.throws(() => new BaseProvider(), /cannot be instantiated/i);
  });

  it("should require providerName to be overridden", () => {
    const { BaseProvider } = loadProvider();
    class TestProvider extends BaseProvider {}
    assert.strictEqual(TestProvider.providerName, undefined);
  });

  it("should allow valid subclass", () => {
    const { BaseProvider } = loadProvider();
    class ValidProvider extends BaseProvider {
      static get providerName() { return "valid"; }
      async add(creds, opts) { return { ok: true }; }
    }
    const inst = new ValidProvider({}, { request: async () => ({}) }, {});
    assert.strictEqual(ValidProvider.providerName, "valid");
  });

  it("should call beforeAdd, add, afterAdd in order", async () => {
    const { BaseProvider } = loadProvider();
    const calls = [];
    class OrderedProvider extends BaseProvider {
      static get providerName() { return "ordered"; }
      async add(creds, opts) { calls.push("add"); return { ok: true }; }
      async beforeAdd(creds, opts) { calls.push("beforeAdd"); }
      async afterAdd(result) { calls.push("afterAdd"); }
    }
    const inst = new OrderedProvider({}, { request: async () => ({}) }, {});
    await inst.add({}, {});
    assert.deepStrictEqual(calls, ["beforeAdd", "add", "afterAdd"]);
  });

  it("should call onError when add throws", async () => {
    const { BaseProvider } = loadProvider();
    const calls = [];
    class ErrorProvider extends BaseProvider {
      static get providerName() { return "error"; }
      async add(creds, opts) { throw new Error("boom"); }
      async onError(err, ctx) { calls.push("onError"); }
    }
    const inst = new ErrorProvider({}, { request: async () => ({}) }, {});
    await assert.rejects(() => inst.add({}, {}), /boom/);
    assert.strictEqual(calls[0], "onError");
  });

  it("should return skip result when beforeAdd returns skip", async () => {
    const { BaseProvider } = loadProvider();
    class SkipProvider extends BaseProvider {
      static get providerName() { return "skip"; }
      async beforeAdd(creds, opts) { return { skip: true, reason: "quota" }; }
      async add(creds, opts) { return { ok: true }; }
    }
    const inst = new SkipProvider({}, { request: async () => ({}) }, {});
    const result = await inst.add({}, {});
    assert.strictEqual(result.skip, true);
    assert.strictEqual(result.reason, "quota");
  });

  it("should convert AuthError to error result", async () => {
    const { BaseProvider } = loadProvider();
    class AuthFailProvider extends BaseProvider {
      static get providerName() { return "authfail"; }
      async add(creds, opts) { throw new AuthError("bad password"); }
    }
    const inst = new AuthFailProvider({}, { request: async () => ({}) }, {});
    const result = await inst.add({}, {});
    assert.strictEqual(result.ok, false);
    assert.strictEqual(result.error, "bad password");
  });

  it("should provide apiCall helper", async () => {
    const { BaseProvider } = loadProvider();
    let called = false;
    const mockApi = {
      request: async (cfg, opts) => {
        called = true;
        assert.strictEqual(opts.method, "GET");
        assert.strictEqual(opts.path, "/api/test");
        return { statusCode: 200, headers: {}, body: { ok: true } };
      },
    };
    class ApiProvider extends BaseProvider {
      static get providerName() { return "api"; }
      async add(creds, opts) { return this.apiCall("GET", "/api/test"); }
    }
    const inst = new ApiProvider({}, mockApi, {});
    const result = await inst.add({}, {});
    assert.ok(called);
    assert.strictEqual(result.statusCode, 200);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/unit/base/provider.test.js`
Expected: FAIL — "Cannot find module"

- [ ] **Step 3: Write minimal implementation**

`src/base/provider.js`:
```js
"use strict";

const { AuthError, QuotaError, ProviderError } = require("./errors");

class BaseProvider {
  constructor(config, api, services) {
    if (new.target === BaseProvider) {
      throw new Error("BaseProvider cannot be instantiated directly");
    }
    this.config = config;
    this.api = api;
    this.services = services;
  }

  static get providerName() {
    return undefined;
  }

  static get endpoints() {
    return {};
  }

  async add(credentials, options) {
    throw new Error("add() must be implemented");
  }

  async beforeAdd(credentials, options) {
    // optional hook
  }

  async afterAdd(result) {
    // optional hook
  }

  async onError(err, context) {
    // optional hook
  }

  async inspect(id) {
    throw new Error("inspect() not implemented");
  }

  async delete(id) {
    throw new Error("delete() not implemented");
  }

  async apiCall(method, path, body, opts = {}) {
    return this.api.request(this.config, { method, path, body, ...opts });
  }

  async injectToDb(connection) {
    const { insert } = require("../core/db");
    return insert(this.config, connection);
  }

  async launchBrowser(options = {}) {
    const { launchStealthBrowser } = require("../services/browser");
    return launchStealthBrowser(this.config, this.services, options);
  }
}

// Wrap add() with lifecycle hooks
const origAdd = BaseProvider.prototype.add;
BaseProvider.prototype.add = async function (credentials, options) {
  try {
    const beforeResult = await this.beforeAdd(credentials, options);
    if (beforeResult && beforeResult.skip) {
      return { ok: false, skip: true, reason: beforeResult.reason };
    }
    const result = await origAdd.call(this, credentials, options);
    await this.afterAdd(result);
    return result;
  } catch (err) {
    await this.onError(err, { credentials, options });
    if (err instanceof QuotaError) {
      return { ok: false, skip: true, reason: err.message };
    }
    if (err instanceof AuthError) {
      return { ok: false, error: err.message };
    }
    throw err;
  }
};

module.exports = { BaseProvider };
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test test/unit/base/provider.test.js`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/base/provider.js test/unit/base/provider.test.js
git commit -m "feat: add BaseProvider abstract class with lifecycle hooks"

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
```

---

### Task 8: Services — proxy, fingerprint, quota, cloudflare-routing (copy from kiro)

**Files:**
- Create: `src/services/proxy.js` (copy from kiro, 103 lines)
- Create: `src/services/fingerprint.js` (copy from kiro, 110 lines)
- Create: `src/services/quota.js` (copy from kiro, 105 lines)
- Create: `src/services/cloudflare-routing.js` (copy from kiro, 99 lines)
- Create: `test/unit/services/proxy.test.js` (new)
- Create: `test/unit/services/fingerprint.test.js` (new)
- Create: `test/unit/services/quota.test.js` (new)
- Create: `test/unit/services/cloudflare-routing.test.js` (new)

**Interfaces:**
- `proxy.js`: `parseProxyLine(line)`, `loadProxies(filePath)`, `getProxyForAccount(proxies, index)`, `chromiumArgsForProxy(proxy)`
- `fingerprint.js`: `generateFingerprint(seed)`
- `quota.js`: `tryConsume(filePath, email, cap)`, `loadStats(filePath)`, `saveStats(filePath, stats)`, `isAllowed(stats, email, cap)`, `increment(stats, email)`, `pruneOld(stats, keepDays)`
- `cloudflare-routing.js`: `generateAliases(domain, count)`, `appendAliasesToFile(filePath, aliases)`, `randomLocalPart()`

- [ ] **Step 1: Copy proxy.js from kiro and write test**

Read source: `cat /home/elzanom/work/tools/9router-kiro/proxy.js` then write to `src/services/proxy.js`

`test/unit/services/proxy.test.js`:
```js
"use strict";
const { describe, it } = require("node:test");
const assert = require("node:assert");
const proxy = require("../../src/services/proxy");

describe("parseProxyLine", () => {
  it("should parse protocol://user:pass@host:port", () => {
    const p = proxy.parseProxyLine("http://user1:pass1@192.168.1.1:8080");
    assert.strictEqual(p.protocol, "http");
    assert.strictEqual(p.host, "192.168.1.1");
    assert.strictEqual(p.port, 8080);
    assert.strictEqual(p.username, "user1");
    assert.strictEqual(p.password, "pass1");
  });
  it("should parse host:port:user:pass", () => {
    const p = proxy.parseProxyLine("10.0.0.1:3128:user2:pass2");
    assert.strictEqual(p.protocol, "http");
    assert.strictEqual(p.host, "10.0.0.1");
    assert.strictEqual(p.port, 3128);
    assert.strictEqual(p.username, "user2");
  });
  it("should parse user:pass@host:port", () => {
    const p = proxy.parseProxyLine("user3:pass3@proxy.example.com:8888");
    assert.strictEqual(p.host, "proxy.example.com");
    assert.strictEqual(p.port, 8888);
  });
  it("should return null for comment lines", () => {
    assert.strictEqual(proxy.parseProxyLine("# comment"), null);
    assert.strictEqual(proxy.parseProxyLine(""), null);
  });
  it("should parse host:port without auth", () => {
    const p = proxy.parseProxyLine("192.168.1.2:8080");
    assert.strictEqual(p.host, "192.168.1.2");
    assert.strictEqual(p.port, 8080);
    assert.strictEqual(p.username, null);
  });
});

describe("getProxyForAccount", () => {
  it("should cycle through proxies by index", () => {
    const proxies = [
      { host: "a.com", port: 1 },
      { host: "b.com", port: 2 },
    ];
    assert.strictEqual(proxy.getProxyForAccount(proxies, 0).host, "a.com");
    assert.strictEqual(proxy.getProxyForAccount(proxies, 1).host, "b.com");
    assert.strictEqual(proxy.getProxyForAccount(proxies, 2).host, "a.com"); // cycle
  });
  it("should return null for empty pool", () => {
    assert.strictEqual(proxy.getProxyForAccount([], 0), null);
  });
});

describe("chromiumArgsForProxy", () => {
  it("should return --proxy-server arg", () => {
    const p = { protocol: "http", host: "1.2.3.4", port: 8080 };
    const args = proxy.chromiumArgsForProxy(p);
    assert.ok(args[0].includes("--proxy-server=http://1.2.3.4:8080"));
  });
  it("should return empty array for null proxy", () => {
    assert.deepStrictEqual(proxy.chromiumArgsForProxy(null), []);
  });
});
```

- [ ] **Step 2: Copy fingerprint.js and write test**

`test/unit/services/fingerprint.test.js`:
```js
"use strict";
const { describe, it } = require("node:test");
const assert = require("node:assert");
const { generateFingerprint } = require("../../src/services/fingerprint");

describe("generateFingerprint", () => {
  it("should return an object with all expected keys", () => {
    const fp = generateFingerprint();
    assert.ok(fp.userAgent);
    assert.ok(fp.viewport);
    assert.ok(fp.viewport.width);
    assert.ok(fp.viewport.height);
    assert.ok(fp.locale);
    assert.ok(fp.timezoneId);
    assert.ok(fp.hardwareConcurrency);
    assert.ok(fp.deviceMemory);
    assert.ok(fp.languages);
  });
  it("should be deterministic with seed", () => {
    const a = generateFingerprint(42);
    const b = generateFingerprint(42);
    assert.deepStrictEqual(a, b);
  });
  it("should produce different results for different seeds", () => {
    const a = generateFingerprint(1);
    const b = generateFingerprint(2);
    assert.notDeepStrictEqual(a, b);
  });
});
```

- [ ] **Step 3: Copy quota.js and write test**

`test/unit/services/quota.test.js`:
```js
"use strict";
const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");
const os = require("os");
const quota = require("../../src/services/quota");

const tmpFile = path.join(os.tmpdir(), "quota-test-" + Date.now() + ".json");

describe("quota", () => {
  after(() => {
    try { fs.unlinkSync(tmpFile); } catch {}
  });

  it("should allow when under cap", () => {
    const { allowed } = quota.tryConsume(tmpFile, "test@example.com", 5);
    assert.strictEqual(allowed, true);
  });
  it("should block when over cap", () => {
    // Use up all quota
    for (let i = 0; i < 5; i++) {
      quota.tryConsume(tmpFile, "test@example.com", 5);
    }
    const { allowed } = quota.tryConsume(tmpFile, "test@example.com", 5);
    assert.strictEqual(allowed, false);
  });
  it("should track per-domain separately", () => {
    const { allowed: a1 } = quota.tryConsume(tmpFile, "other@different.com", 5);
    assert.strictEqual(a1, true);
  });
  it("should prune old entries", () => {
    const stats = { "2020-01-01": { "old.com": 5 }, "2099-01-01": { "new.com": 3 } };
    const pruned = quota.pruneOld(stats, 30);
    assert.ok(!pruned["2020-01-01"]);
    assert.ok(pruned["2099-01-01"]);
  });
});
```

- [ ] **Step 4: Copy cloudflare-routing.js and write test**

`test/unit/services/cloudflare-routing.test.js`:
```js
"use strict";
const { describe, it } = require("node:test");
const assert = require("node:assert");
const cf = require("../../src/services/cloudflare-routing");

describe("generateAliases", () => {
  it("should generate requested count", () => {
    const aliases = cf.generateAliases("minom.my.id", 3);
    assert.strictEqual(aliases.length, 3);
  });
  it("should all have the domain", () => {
    const aliases = cf.generateAliases("test.com", 5);
    for (const a of aliases) {
      assert.ok(a.endsWith("@test.com"));
    }
  });
  it("should not produce duplicates in one batch", () => {
    const aliases = cf.generateAliases("test.com", 50);
    const unique = new Set(aliases);
    assert.strictEqual(unique.size, aliases.length);
  });
});

describe("randomLocalPart", () => {
  it("should return a non-empty string", () => {
    assert.ok(cf.randomLocalPart().length > 0);
  });
  it("should not contain @ symbol", () => {
    assert.ok(!cf.randomLocalPart().includes("@"));
  });
});
```

- [ ] **Step 5: Copy all four files from kiro**

Run: `cp /home/elzanom/work/tools/9router-kiro/proxy.js src/services/proxy.js`
Run: `cp /home/elzanom/work/tools/9router-kiro/fingerprint.js src/services/fingerprint.js`
Run: `cp /home/elzanom/work/tools/9router-kiro/quota.js src/services/quota.js`
Run: `cp /home/elzanom/work/tools/9router-kiro/cloudflare-routing.js src/services/cloudflare-routing.js`

- [ ] **Step 6: Run all service tests**

Run: `node --test test/unit/services/proxy.test.js test/unit/services/fingerprint.test.js test/unit/services/quota.test.js test/unit/services/cloudflare-routing.test.js`
Expected: PASS (all tests)

- [ ] **Step 7: Commit**

```bash
git add src/services/proxy.js src/services/fingerprint.js src/services/quota.js src/services/cloudflare-routing.js test/unit/services/proxy.test.js test/unit/services/fingerprint.test.js test/unit/services/quota.test.js test/unit/services/cloudflare-routing.test.js
git commit -m "feat: add services (proxy, fingerprint, quota, cloudflare-routing) from kiro"

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
```

---

### Task 9: Services — imap-otp.js (copy from kiro)

**Files:**
- Create: `src/services/imap-otp.js` (copy from kiro, 233 lines)
- Create: `test/unit/services/imap-otp.test.js`

**Interfaces:**
- `extractOtpFromRaw(raw)` → `string|null`
- `buildGmrawQuery(alias, subject)` → `string`
- `buildGmrawFallbackQuery(subject)` → `string`
- `pickRecencyMatch(messages, opts)` → `{ message, otp }|null`
- `findSpamPath(client)` → `string`
- `getOtpViaImap(imapCfg, alias, opts)` → `{ ok, otp, from, subject, received }|{ ok: false, error }`

- [ ] **Step 1: Write the failing test**

`test/unit/services/imap-otp.test.js`:
```js
"use strict";
const { describe, it } = require("node:test");
const assert = require("node:assert");
const imap = require("../../src/services/imap-otp");

describe("extractOtpFromRaw", () => {
  it("should extract 6-digit code from div with class 'code'", () => {
    const html = '<div class="code"> 123456 </div>';
    assert.strictEqual(imap.extractOtpFromRaw(html), "123456");
  });
  it("should extract from 'Verification code:' pattern", () => {
    const html = 'Verification code: <strong>789012</strong>';
    assert.strictEqual(imap.extractOtpFromRaw(html), "789012");
  });
  it("should extract 6-digit near 'code' context as fallback", () => {
    const text = 'Your verification code is 345678. Please enter it.';
    assert.strictEqual(imap.extractOtpFromRaw(text), "345678");
  });
  it("should return null for no match", () => {
    assert.strictEqual(imap.extractOtpFromRaw("hello world"), null);
  });
  it("should return null for empty input", () => {
    assert.strictEqual(imap.extractOtpFromRaw(""), null);
    assert.strictEqual(imap.extractOtpFromRaw(null), null);
  });
});

describe("buildGmrawQuery", () => {
  it("should build gmail search query with to: and subject:", () => {
    const q = imap.buildGmrawQuery("test@example.com", "Verify your email");
    assert.ok(q.includes("to:test@example.com"));
    assert.ok(q.includes('subject:"Verify your email"'));
    assert.ok(q.includes("in:anywhere"));
  });
});

describe("pickRecencyMatch", () => {
  it("should pick the newest message with OTP", () => {
    const messages = [
      { internalDate: new Date("2026-07-19T10:00:00Z"), source: "no code here" },
      { internalDate: new Date("2026-07-19T10:01:00Z"), source: "code is 123456" },
      { internalDate: new Date("2026-07-19T10:02:00Z"), source: "no digits" },
    ];
    const picked = imap.pickRecencyMatch(messages, { since: Date.parse("2026-07-19T10:00:00Z") });
    assert.ok(picked);
    assert.strictEqual(picked.otp, "123456");
  });
  it("should return null if no messages within window", () => {
    const messages = [
      { internalDate: new Date("2020-01-01"), source: "code is 123456" },
    ];
    const picked = imap.pickRecencyMatch(messages, { since: Date.now() });
    assert.strictEqual(picked, null);
  });
});
```

- [ ] **Step 2: Copy imap-otp.js from kiro**

Run: `cp /home/elzanom/work/tools/9router-kiro/imap-otp.js src/services/imap-otp.js`

- [ ] **Step 3: Run test to verify**

Run: `node --test test/unit/services/imap-otp.test.js`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add src/services/imap-otp.js test/unit/services/imap-otp.test.js
git commit -m "feat: add imap-otp service from kiro"

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
```

---

### Task 10: Services — browser.js (browser launcher, extracted from monoliths)

**Files:**
- Create: `src/services/browser.js`

**Interfaces:**
- `launchStealthBrowser(config, services, options)` → `{ browser, page }`
- `newStealthPage(browser, fingerprint)` → `Page`
- `reactTypeInput(page, selector, value)` → `void`
- `clickByText(page, text, opts)` → `boolean`
- `clickPrimaryButtonMouse(page, coords)` → `void`

Note: This module requires Puppeteer and browser binaries. Tests are skipped in CI without a browser.

- [ ] **Step 1: Write browser.js**

`src/services/browser.js`:
```js
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
    headless: config.headless !== false ? "new" : false,
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
```

- [ ] **Step 2: Verify module loads without errors**

Run: `node -e "require('./src/services/browser')" 2>&1 || echo "Expected: may fail if puppeteer not installed — check syntax only"`
Expected: syntax OK (may fail if puppeteer not installed yet, but no syntax errors)

- [ ] **Step 3: Commit**

```bash
git add src/services/browser.js
git commit -m "feat: add browser service (stealth launcher, fingerprint, helpers)"

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
```

---

### Task 11: Core — cli.js (CLI Dispatcher + Auto-Discovery)

**Files:**
- Create: `src/core/cli.js`
- Create: `test/unit/core/cli.test.js`

**Interfaces:**
- `loadProviders(config, api)` → `{ [providerName]: ProviderClass }`
- `loadServices(config)` → `{ imap, proxy, fingerprint, quota, cfRouting }`
- `parseArgs(argv)` → `{ _: [commands...], [key]: value }`
- `run(argv, config, api, providers)` → `void`

- [ ] **Step 1: Write the failing test**

`test/unit/core/cli.test.js`:
```js
"use strict";
const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const fs = require("fs");
const path = require("path");
const os = require("os");

function loadCli() {
  delete require.cache[require.resolve("../../src/core/cli")];
  return require("../../src/core/cli");
}

describe("parseArgs", () => {
  it("should parse --key=value", () => {
    const { parseArgs } = loadCli();
    const args = parseArgs(["add", "test", "--email=foo@bar.com", "--password=secret"]);
    assert.strictEqual(args._[0], "add");
    assert.strictEqual(args._[1], "test");
    assert.strictEqual(args.email, "foo@bar.com");
    assert.strictEqual(args.password, "secret");
  });
  it("should parse --flag without value", () => {
    const { parseArgs } = loadCli();
    const args = parseArgs(["add", "test", "--dry-run"]);
    assert.strictEqual(args["dry-run"], true);
  });
  it("should parse --key value (space separated)", () => {
    const { parseArgs } = loadCli();
    const args = parseArgs(["add", "test", "--email", "foo@bar.com"]);
    assert.strictEqual(args.email, "foo@bar.com");
  });
});

describe("loadServices", () => {
  it("should return all services", () => {
    const { loadServices } = loadCli();
    const svc = loadServices({});
    assert.ok(svc.fingerprint);
    assert.ok(svc.cfRouting);
  });
  it("should load imap only when config has imap", () => {
    const { loadServices } = loadCli();
    const svc = loadServices({ imap: { user: "x", password: "y" } });
    assert.ok(svc.imap);
  });
  it("should load proxy only when config has proxyFile", () => {
    const { loadServices } = loadCli();
    const svc = loadServices({ proxyFile: "/tmp/proxies.txt" });
    assert.ok(svc.proxy);
  });
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/unit/core/cli.test.js`
Expected: FAIL — "Cannot find module"

- [ ] **Step 3: Write minimal implementation**

`src/core/cli.js`:
```js
"use strict";

const fs = require("fs");
const path = require("path");

const PROVIDERS_DIR = path.join(__dirname, "..", "providers");

function parseArgs(argv) {
  const args = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith("--")) {
      const eq = argv[i].indexOf("=");
      if (eq !== -1) {
        args[argv[i].slice(2, eq)] = argv[i].slice(eq + 1);
      } else {
        const next = argv[i + 1];
        if (next && !next.startsWith("--")) {
          args[argv[i].slice(2)] = next;
          i++;
        } else {
          args[argv[i].slice(2)] = true;
        }
      }
    } else {
      args._.push(argv[i]);
    }
  }
  return args;
}

function loadProviders(config, api) {
  const providers = {};
  let entries;
  try {
    entries = fs.readdirSync(PROVIDERS_DIR, { withFileTypes: true });
  } catch {
    return providers;
  }
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const indexPath = path.join(PROVIDERS_DIR, entry.name, "index.js");
    if (!fs.existsSync(indexPath)) continue;
    try {
      const ProviderClass = require(indexPath);
      const name = ProviderClass.providerName;
      if (name) providers[name] = ProviderClass;
    } catch (e) {
      console.warn(`[cli] warning: failed to load provider ${entry.name}: ${e.message}`);
    }
  }
  return providers;
}

function loadServices(config) {
  const services = {};

  if (config.imap) {
    services.imap = require("../services/imap-otp");
  }
  if (config.proxyFile) {
    const proxy = require("../services/proxy");
    services.proxy = {
      loadProxies: () => proxy.loadProxies(config.proxyFile),
      getProxyForAccount: proxy.getProxyForAccount,
      chromiumArgsForProxy: proxy.chromiumArgsForProxy,
    };
  }
  services.fingerprint = require("../services/fingerprint");
  if (config.quotaFile) {
    services.quota = require("../services/quota");
  }
  services.cfRouting = require("../services/cloudflare-routing");

  return services;
}

async function run(argv, config, api, providers) {
  const args = parseArgs(argv);
  const command = args._[0];
  const providerName = args._[1];

  if (!command) {
    console.log("Usage: node . <command> <provider> [options]");
    console.log("Commands: add, inspect, delete, list, batch");
    console.log("Providers:", Object.keys(providers).join(", "));
    return;
  }

  if (command === "list") {
    const { findByProvider } = require("./db");
    const targetProvider = providerName;
    if (targetProvider) {
      const rows = await findByProvider(config, targetProvider);
      console.log(JSON.stringify(rows, null, 2));
    } else {
      // List all providers
      for (const name of Object.keys(providers)) {
        const rows = await findByProvider(config, name);
        if (rows.length > 0) {
          console.log(`\n--- ${name} (${rows.length}) ---`);
          console.log(JSON.stringify(rows, null, 2));
        }
      }
    }
    return;
  }

  if (!providerName || !providers[providerName]) {
    console.error(`Unknown provider: ${providerName}`);
    console.error("Available:", Object.keys(providers).join(", "));
    process.exit(1);
  }

  const Provider = providers[providerName];
  const services = loadServices(config);
  config._provider = providerName;
  const finalConfig = { ...config, providerConfig: (config.providers && config.providers[providerName]) || {} };
  const provider = new Provider(finalConfig, api, services);

  switch (command) {
    case "add": {
      const credentials = { email: args.email, password: args.password, name: args.name };
      const options = { proxy: args.proxy, dryRun: args["dry-run"] === true };
      const result = await provider.add(credentials, options);
      console.log(JSON.stringify(result, null, 2));
      break;
    }
    case "inspect": {
      const id = args._[2];
      if (!id) { console.error("Usage: node . inspect <provider> <id>"); process.exit(1); }
      const result = await provider.inspect(id);
      console.log(JSON.stringify(result, null, 2));
      break;
    }
    case "delete": {
      const id = args._[2];
      if (!id) { console.error("Usage: node . delete <provider> <id>"); process.exit(1); }
      await provider.delete(id);
      console.log("Deleted.");
      break;
    }
    case "batch": {
      const batchFile = args._[2] || args.file;
      if (!batchFile) { console.error("Usage: node . batch <file.json>"); process.exit(1); }
      const batch = JSON.parse(fs.readFileSync(batchFile, "utf8"));
      const accounts = batch.accounts || [];
      for (let i = 0; i < accounts.length; i++) {
        const acct = accounts[i];
        const p = new Provider(finalConfig, api, loadServices(config));
        try {
          const r = await p.add(acct.credentials || {}, acct.options || {});
          console.log(`[${i + 1}/${accounts.length}] ${r.ok ? "OK" : "FAIL"}: ${JSON.stringify(r)}`);
        } catch (e) {
          console.error(`[${i + 1}/${accounts.length}] ERROR: ${e.message}`);
        }
      }
      break;
    }
    default:
      console.error(`Unknown command: ${command}`);
      process.exit(1);
  }
}

module.exports = { parseArgs, loadProviders, loadServices, run };
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test test/unit/core/cli.test.js`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/core/cli.js test/unit/core/cli.test.js
git commit -m "feat: add CLI dispatcher with auto-discovery, argparse, commands"

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
```

---

### Task 12: Entry Point — index.js

**Files:**
- Create: `src/index.js`

**Interfaces:**
- Entry point: `node src/index.js <command> <provider> [options]`
- Consumes: all core modules, auto-discovers providers

- [ ] **Step 1: Write index.js**

`src/index.js`:
```js
"use strict";

const { loadConfig } = require("./core/config");
const { resolveAuthHeaders } = require("./core/auth");
const { request } = require("./core/http-client");
const { loadProviders, run } = require("./core/cli");

async function main() {
  const config = loadConfig(process.argv.slice(2));
  const api = { request };
  const authHeaders = await resolveAuthHeaders(config, api);
  // Attach auth headers to every request
  const originalRequest = api.request;
  api.request = (cfg, opts) => {
    return originalRequest(cfg, {
      ...opts,
      headers: { ...authHeaders, ...opts.headers },
    });
  };

  const providers = loadProviders(config, api);
  await run(process.argv.slice(2), config, api, providers);
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
```

- [ ] **Step 2: Verify entry point loads without errors**

Run: `node -e "require('./src/index.js')" 2>&1 || true`
Expected: Loads without syntax errors (may exit with usage message if no args, which is fine)

- [ ] **Step 3: Commit**

```bash
git add src/index.js
git commit -m "feat: add main entry point (index.js)"

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
```

---

### Task 13: Provider — Antigravity

**Files:**
- Create: `src/providers/antigravity/index.js`
- Create: `src/providers/antigravity/config.json`

**Interfaces:**
- Exports: `class Antigravity extends BaseProvider`
- `providerName` = `"antigravity"`
- `endpoints` = `{ authorize: "/api/oauth/antigravity/authorize", exchange: "/api/oauth/antigravity/exchange" }`
- `add(credentials, options)` → OAuth authorization code flow

- [ ] **Step 1: Create provider config**

`src/providers/antigravity/config.json`:
```json
{
  "endpoints": {
    "authorize": "/api/oauth/antigravity/authorize",
    "exchange": "/api/oauth/antigravity/exchange"
  }
}
```

- [ ] **Step 2: Create provider index.js**

`src/providers/antigravity/index.js`:
```js
"use strict";

const BaseProvider = require("../../base/provider");

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
```

- [ ] **Step 3: Verify provider loads correctly**

Run: `node -e "const P = require('./src/providers/antigravity/index.js'); console.log(P.providerName); console.log(P.endpoints);"`
Expected: `antigravity` and endpoints object

- [ ] **Step 4: Commit**

```bash
git add src/providers/antigravity/index.js src/providers/antigravity/config.json
git commit -m "feat: add Antigravity provider (OAuth authorize/exchange flow)"

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
```

---

### Task 14: Provider — Kiro

**Files:**
- Create: `src/providers/kiro/index.js`
- Create: `src/providers/kiro/config.json`

**Interfaces:**
- Exports: `class Kiro extends BaseProvider`
- `providerName` = `"kiro"`
- `endpoints` = `{ deviceCode: "/api/oauth/kiro/device-code", poll: "/api/oauth/kiro/poll" }`
- `add(credentials, options)` → Device code + poll flow, with Google OAuth or Email via IMAP

- [ ] **Step 1: Create provider config**

`src/providers/kiro/config.json`:
```json
{
  "endpoints": {
    "deviceCode": "/api/oauth/kiro/device-code",
    "poll": "/api/oauth/kiro/poll"
  },
  "pollTimeout": 120000,
  "pollInterval": 3000
}
```

- [ ] **Step 2: Create provider index.js**

`src/providers/kiro/index.js`:
```js
"use strict";

const BaseProvider = require("../../base/provider");

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

    // 2. Browser automation berdasarkan method
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
    // Generate alias jika diperlukan
    let email = credentials.email;
    if (this.services.cfRouting && options.generateAlias) {
      const domain = options.aliasDomain || (this.config.providerConfig || {}).aliasDomain;
      if (domain) {
        const aliases = this.services.cfRouting.generateAliases(domain, 1);
        email = aliases[0];
      }
    }

    // Resolve proxy + fingerprint untuk akun ini
    let proxy = options.proxy;
    if (!proxy && this.services.proxy) {
      const proxies = this.services.proxy.loadProxies();
      proxy = this.services.proxy.getProxyForAccount(proxies, options.accountIndex || 0);
    }
    let fingerprint = options.fingerprint;
    if (!fingerprint && this.services.fingerprint) {
      fingerprint = this.services.fingerprint.generateFingerprint();
    }

    const { browser, page } = await this.launchBrowser(this.config, this.services, {
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
```

- [ ] **Step 3: Verify provider loads correctly**

Run: `node -e "const P = require('./src/providers/kiro/index.js'); console.log(P.providerName); console.log(P.endpoints);"`
Expected: `kiro` and endpoints object

- [ ] **Step 4: Commit**

```bash
git add src/providers/kiro/index.js src/providers/kiro/config.json
git commit -m "feat: add Kiro provider (device code + poll + IMAP OTP flow)"

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
```

---

### Task 15: Integration Test — CLI End-to-End

**Files:**
- Create: `test/integration/cli.test.js`

- [ ] **Step 1: Write integration test**

`test/integration/cli.test.js`:
```js
"use strict";
const { describe, it, before, after } = require("node:test");
const assert = require("node:assert");
const http = require("http");
const fs = require("fs");
const path = require("path");
const os = require("os");

// Start a mock 9router API server for integration testing
const tmpDir = path.join(os.tmpdir(), "9router-int-test-" + Date.now());
const testConfig = {
  host: "localhost",
  port: 0, // random port
  proto: "http",
  mode: "remote",
  password: "test-password",
  machineIdPath: "/nonexistent",
};

describe("CLI Integration", () => {
  let server;
  let port;
  let loginCalled = false;
  let authorizeCalled = false;

  before(async () => {
    fs.mkdirSync(tmpDir, { recursive: true });

    // Create mock provider for testing
    const providerDir = path.join(__dirname, "..", "..", "src", "providers", "testint");
    fs.mkdirSync(providerDir, { recursive: true });
    fs.writeFileSync(
      path.join(providerDir, "index.js"),
      `
      "use strict";
      const BaseProvider = require("../../base/provider");
      class TestIntProvider extends BaseProvider {
        static get providerName() { return "testint"; }
        async add(creds, opts) {
          return { ok: true, email: creds.email, provider: "testint" };
        }
      }
      module.exports = TestIntProvider;
      `
    );

    // Start mock API server
    server = http.createServer((req, res) => {
      if (req.url === "/api/auth/login" && req.method === "POST") {
        loginCalled = true;
        res.writeHead(200, {
          "Content-Type": "application/json",
          "Set-Cookie": "connect.sid=s%3Atest.xyz; Path=/; HttpOnly",
        });
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true, path: req.url }));
    });
    await new Promise((r) => server.listen(0, r));
    port = server.address().port;
  });

  after(() => {
    server.close();
    fs.rmSync(tmpDir, { recursive: true, force: true });
    // Clean up mock provider
    const providerDir = path.join(__dirname, "..", "..", "src", "providers", "testint");
    try { fs.rmSync(providerDir, { recursive: true, force: true }); } catch {}
  });

  it("should load providers and dispatch add command", async () => {
    const { loadProviders, loadServices, run } = require("../../src/core/cli");
    const { request } = require("../../src/core/http-client");
    const { resolveAuthHeaders } = require("../../src/core/auth");

    const config = { ...testConfig, port };
    const api = { request };
    const authHeaders = await resolveAuthHeaders(config, api);
    api.request = (cfg, opts) => request(cfg, { ...opts, headers: { ...authHeaders, ...opts.headers } });

    const providers = loadProviders(config, api);
    assert.ok(providers.testint);

    // Capture stdout
    const logs = [];
    const origLog = console.log;
    console.log = (msg) => logs.push(msg);

    await run(["add", "testint", "--email=int@test.com"], config, api, providers);

    console.log = origLog;
    const output = logs.join(" ");
    assert.ok(output.includes("ok"));
    assert.ok(loginCalled, "Dashboard login should be called");
  });
});
```

- [ ] **Step 2: Run integration test**

Run: `node --test test/integration/cli.test.js`
Expected: PASS

- [ ] **Step 3: Run all tests**

Run: `node --test test/unit/... test/integration/...`
Expected: All PASS

- [ ] **Step 4: Commit**

```bash
git add test/integration/cli.test.js
git commit -m "test: add CLI integration test (mock API + mock provider)"

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
```

---

### Task 16: Final Verification

- [ ] **Step 1: Run full test suite**

Run: `node --test`
Expected: All tests pass

- [ ] **Step 2: Verify CLI help output**

Run: `node src/index.js`
Expected: Usage message with available providers (antigravity, kiro)

- [ ] **Step 3: Final commit if needed**

```bash
git add -A
git commit -m "chore: finalize initial implementation"

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>
```

---

*End of implementation plan.*