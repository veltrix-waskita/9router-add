# Kiro Pure-HTTP Implementation Plan

> **For agentic workers:** This plan is designed for **superpowers:subagent-driven-development** — dispatch a fresh subagent per task, review between tasks, fast iteration. If you prefer to execute inline, each task has self-contained checkbox steps with exact file paths and commands.

---

## Goal

Rewrite `src/providers/kiro/` from a Puppeteer/browser-based provider into a pure-HTTP (email-only) provider mirroring the `grok-cli` architecture:

- **Node orchestrator** (slim `index.js`) handles device-code request, poll loop, and 9router integration
- **Python `curl_cffi` worker** (stub → full implementation) handles email entry, OTP extraction, password set, and consent
- **No Puppeteer for the email path** — Google/@gmail.com accounts are hard-rejected in v1

## Architecture

```
┌─────────────┐     ┌────────────────────────────────────┐
│  9router    │     │  Node (orchestrator)                │
│  API        │◄────│  index.js                           │
│  /oauth/    │     │  ┌──────────────────────────────┐   │
│  device-code│     │  │ worker-bridge.js             │   │
│  /oauth/poll│     │  │  buildWorkerEnv(secrets out)  │   │
│  /providers │     │  │  spawnSignupWorker → stdout   │   │
└─────────────┘     │  │  parseWorkerLine              │   │
                    │  └──────────────────────────────┘   │
                    └──────────┬──────────────────────────┘
                               │ env (no device_code!)
                    ┌──────────▼──────────────────────────┐
                    │  Python worker (signup.py)           │
                    │  ┌──────────────────────────────┐    │
                    │  │ curl_cffi (Chrome 131)       │    │
                    │  │ IMAP OTP reader              │    │
                    │  │ tempmail.py (port)           │    │
                    │  │ JSONL stdout protocol        │    │
                    │  └──────────────────────────────┘    │
                    └─────────────────────────────────────┘
```

### Data flow (no secrets across boundary)

```
Node                          Python worker
────                          ─────────────
GET device_code               ──→ deviceData.verification_uri_complete
                                → KIRO_DEVICE_URL (env, carries user_code only)
buildWorkerEnv()                → KIRO_EMAIL, KIRO_PASSWORD, KIRO_NAME
                                → KIRO_EMAIL_SOURCE = imap|tempmail
                                → KIRO_PROXY
                                → PURE_HTTP=1
                                ⚠ device_code/codeVerifier/_clientSecret
                                  NEVER in env
spawn worker ──────────────────→ stdout JSONL lines
                                  {kind:"result", ok:...}

Node poll loop sends:
  POST /api/oauth/kiro/poll
  {deviceCode, extraData}       ⚠ stays in Node, never to worker
```

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Provider class | Node.js 18+, CommonJS, extends `BaseProvider` |
| Worker process | Python 3.10+, `curl-cffi>=0.9.0,<0.10.0` (Chrome 131) |
| OTP (IMAP) | Python `imaplib` + `email` stdlib |
| OTP (temp-mail) | Python `requests` + JSON APIs |
| Tests (Node) | `node:test` built-in runner (`npm test`) |
| Tests (Python) | `unittest` style, runnable via pytest |
| DB | SQLite via `sqlite3` npm (local mode) |

## Global Constraints (from spec — hard rules, not guidelines)

1. **Never log password, OTP, `device_code`, `codeVerifier`.**
2. **Worker never receives `device_code`, `codeVerifier`, or poll `extraData` secrets.**
3. **No `injectToDb` after poll** — 9router stores the connection.
4. **Remote non-localhost still requires HTTPS** (core unchanged).
5. **Google/@gmail.com hard-rejected in v1** — `detectMethod` returns `"google"` → throw before any API call.
6. **Phase D0 is a BLOCKING gate** — worker steps implemented ONLY after endpoint map is committed.
7. **JSONL stdout protocol** — worker emits structured JSON lines; terminal line is `{"kind":"result","ok":…}`.

---

## File Structure

```
src/providers/kiro/
├── index.js                 # Slim provider (puppeteer-free)
├── worker-bridge.js         # Worker spawn + env builder + line parser
└── worker/
    ├── requirements.txt     # curl-cffi dependency
    ├── signup.py            # Main worker script
    ├── tempmail.py          # Temp-mail API adapters (ported from grok-cli)
    └── test_otp.py          # OTP/IMAP unit tests (unittest)

test/unit/providers/
├── kiro.test.js             # Provider tests (node:test)
└── kiro-worker.test.js      # Worker-bridge tests (node:test)

scripts/
└── kiro-capture-aws.js      # Phase D0: AWS endpoint discovery via browser

docs/superpowers/specs/
└── 2026-07-23-kiro-aws-endpoint-map.md   # Phase D0 output (paths + shapes)
```

---

## Task 1: Scaffolding — Worker skeleton + tempmail port

**Goal:** Create the worker directory, `.gitignore` entry, stub `signup.py` that fails with `not-implemented`, and port `tempmail.py` from grok-cli with AWS keywords.

### Steps

<checkbox>
- [ ] **1a. Add kiro venv to `.gitignore`**

  Insert before the grok-cli `.venv` line:

  ```
  src/providers/kiro/worker/.venv/
  ```

  Verify with `git diff .gitignore`.

- [ ] **1b. Create `src/providers/kiro/worker/requirements.txt`**

  ```txt
  curl-cffi>=0.9.0,<0.10.0
  ```

- [ ] **1c. Create stub `src/providers/kiro/worker/signup.py`**

  ```python
  #!/usr/bin/env python3
  """Kiro pure-HTTP account signup worker.
     Phase D1 stub — fails with not-implemented until endpoint map is committed.
  """
  import json, os, sys, time
  from typing import Any

  def emit(obj: dict) -> None:
      sys.stdout.write(json.dumps(obj) + "\n")
      sys.stdout.flush()

  def emit_step(step: str, status: str = "ok", **extra: Any) -> None:
      payload = {"event": "step", "step": step, "status": status}
      payload.update(extra)
      emit(payload)

  def emit_result(ok: bool, error: str | None = None, step: str | None = None) -> None:
      obj: dict[str, Any] = {"kind": "result", "ok": ok}
      obj["event"] = "result"
      if error:
          obj["error"] = error
      if step:
          obj["step"] = step
      emit(obj)

  def run() -> int:
      email = os.getenv("KIRO_EMAIL", "")
      password = os.getenv("KIRO_PASSWORD", "")
      device_url = os.getenv("KIRO_DEVICE_URL", "")

      if not email or not password or not device_url:
          emit_result(False, error="missing-required-env", step="init")
          return 1

      emit_step("bootstrap", "ok")
      # Phase D1: replace this stub with real HTTP steps against the endpoint map
      emit_result(False, error="not-implemented", step="bootstrap")
      return 1

  if __name__ == "__main__":
      raise SystemExit(run())
  ```

- [ ] **1d. Port `tempmail.py` to kiro worker**

  Copy from `src/providers/grok-cli/worker/tempmail.py` and apply these changes:

  | Change | Value |
  |--------|-------|
  | `XAI_MARKERS` → AWS markers | `("signin.aws", "aws", "amazon", "amazon web services", "verify your email", "email verification", "builder id", "aws builder id")` |
  | `GROK_TEMPMAIL_PROVIDERS` → `KIRO_TEMPMAIL_PROVIDERS` | Read from env in `_providers_from_env()` |
  | Zoromail username prefix `"xai"` → `"aws"` | `"aws" + uuid4().hex[:10]` |
  | `_has_xai_context` → `_has_aws_context` | Match against AWS markers |
  | `extract_code` 6-digit regex | Prefer 6-digit codes over hyphenated formats |
  | `OTP_HYPHEN_RE` | Keep but lower priority — AWS uses 6-digit codes |
  | `OTP_DIGIT6_RE` | Make primary — matches `(?:\d{6})\b` with AWS context labels |

  Key section — `extract_code` priority:
  1. Labeled 6-digit (AWS "verification code: 123456")
  2. Labeled hyphen (for cross-provider compatibility)
  3. Bare hyphen if has AWS context
  4. Labeled 6-char legacy

  **IMPORTANT:** `email_box.wait_code()` already has `timeout=150` default — keep it.

- [ ] **1e. Set up venv and verify stub runs**

  ```bash
  cd src/providers/kiro/worker
  python3 -m venv .venv
  .venv/bin/pip install -r requirements.txt
  KIRO_EMAIL=test@example.com KIRO_PASSWORD=Test123! KIRO_DEVICE_URL=https://example.com/device .venv/bin/python3 signup.py
  ```

  Expected output:
  ```jsonl
  {"event": "step", "step": "bootstrap", "status": "ok"}
  {"kind": "result", "ok": false, "event": "result", "error": "not-implemented", "step": "bootstrap"}
  ```

  Exit code: 1.
</checkbox>

---

## Task 2: Worker-bridge module + Node tests

**Goal:** Create `src/providers/kiro/worker-bridge.js` (ported from grok-cli with KIRO_* env contract) and its unit tests. Must include the **security env test** that asserts `device_code` / `codeVerifier` / `_clientSecret` never appear in worker env.

### Steps

<checkbox>
- [ ] **2a. Create `src/providers/kiro/worker-bridge.js`**

  Port from `src/providers/grok-cli/worker-bridge.js` with these changes:

  | Aspect | grok-cli | kiro |
  |--------|----------|------|
  | env prefix | `GROK_*` | `KIRO_*` |
  | sign-in URL | `buildSignInUrl(deviceData)` → `GROK_SIGNIN_URL` | `KIRO_DEVICE_URL` = `deviceData.verification_uri_complete` directly |
  | name fields | `GROK_FIRST` + `GROK_LAST` (separate) | `KIRO_NAME` single string |
  | name pool | `pickName(name)` → `{first, last}` | `pickName(name)` → string (keeps same FIRST_NAMES/LAST_NAMES pools) |
  | OTP subject default | x.ai | `Verify your AWS Builder ID email address` |
  | OTP sender domain default | `x.ai` | `signin.aws` |
  | IMAP delete default | `true` | `false` (bridge side: `imap.deleteAfterRead === true`; env default "false") |
  | imap_cfg_from_env key | `GROK_IMAP_USER/PASSWORD` | `KIRO_IMAP_USER/PASSWORD` |
  | worker error prefix | `grok-cli worker` | `kiro worker` |
  | tempmail providers env | `GROK_TEMPMAIL_PROVIDERS` | `KIRO_TEMPMAIL_PROVIDERS` |

  **Exported API:**

  - `buildWorkerEnv({deviceData, credentials, config, options})` → `{...env}`
  - `parseWorkerLine(line)` → `{kind, ok?, error?, step?, payload?}`
  - `runSignupWorker({command, args, env, cwd, onEvent, timeoutMs})` → `Promise<{ok, step?, error?}>`
  - `spawnSignupWorker(workerDir, env, opts)` → shorthand using `pythonBin`
  - `pythonBin(workerDir)` → `path.join(workerDir, ".venv", "bin", "python3")`
  - `pickName(name)` → full name string, or random from names pool
  - `errCodeFrom(error)` → uppercase slug code
  - `KIRO_TEMPMAIL_PROVIDERS` = `"ncaori,zoromail"`

  **`buildWorkerEnv` contract (forbidden env vars):**

  Must NOT include: `KIRO_DEVICE_CODE`, `KIRO_CODE_VERIFIER`, `KIRO_CLIENT_SECRET`, `KIRO_CLIENT_ID`, or any raw poll `extraData`.

  **`runSignupWorker` behavior:**

  - Spawns with `{...process.env, ...env}`, stdio `["ignore", "pipe", "pipe"]`
  - Line-buffers stdout, parses each line with `parseWorkerLine`
  - Stderr capped at 4000 chars, surfaced in error
  - Resolves `{ok: true}` on exit 0 + `{kind: "result", ok: true}`
  - Rejects `ProviderError` with codes:
    - `WORKER_TIMEOUT` (retryable) — worker didn't finish in time
    - `WORKER_SPAWN` — failed to spawn process
    - `WORKER_PROTOCOL` — exit 0 but no result line
    - `errCodeFrom(error)` for other errors, `retryable: /timeout|temp|transient/i.test(error)`
  - Error messages prefixed `"kiro worker ..."`

- [ ] **2b. Create `test/unit/providers/kiro-worker.test.js`**

  Port from `test/unit/providers/grok-cli-worker.test.js`:

  ```js
  // Structure:
  // 1. buildWorkerEnv — security test: assert no SECRET_DEVICE_CODE/SECRET_VERIFIER keys
  // 2. buildWorkerEnv — verify KIRO_DEVICE_URL from deviceData.verification_uri_complete
  // 3. buildWorkerEnv — verify KIRO_NAME single string format
  // 4. buildWorkerEnv — verify KIRO_EMAIL_SOURCE, KIRO_PASSWORD, PURE_HTTP=1
  // 5. buildWorkerEnv — proxy string passthrough + object → URL form
  // 6. parseWorkerLine — debug, event, result, skip kinds
  // 7. parseWorkerLine — accepts both kind:result and event:result
  // 8. parseWorkerLine — step event with payload
  // 9. runSignupWorker — ok (FAKE_WORKER_MODE=ok)
  // 10. runSignupWorker — fail (FAKE_WORKER_MODE=fail, /turnstile-timeout/i, code TURNSTILE_TIMEOUT, retryable true)
  // 11. runSignupWorker — timeout (300ms, code WORKER_TIMEOUT, retryable true)
  // 12. runSignupWorker — noresult (code WORKER_PROTOCOL)
  // 13. pickName — null → random, string → full name preserved
  ```

  Uses `test/fixtures/fake-worker.py` via `command: "python3"` + `FAKE_WORKER_MODE` env.

  **Security test (critical):**
  ```js
  it("must not leak secrets to worker env", () => {
    const deviceData = {
      device_code: "secret-dc",
      verification_uri_complete: "https://example.com/activate?user_code=ABC123",
      codeVerifier: "secret-verifier",
      extraData: { _clientId: "cid", _clientSecret: "cs" },
    };
    const env = buildWorkerEnv({deviceData, ...});
    const envStr = JSON.stringify(env);
    assert(!envStr.includes("secret-dc"), "device_code leaked");
    assert(!envStr.includes("secret-verifier"), "codeVerifier leaked");
    assert(!envStr.includes("_clientSecret"), "clientSecret leaked");
    assert(!envStr.includes("_clientId"), "clientId leaked");
    assert(env.KIRO_DEVICE_URL === deviceData.verification_uri_complete);
    assert(!Object.keys(env).some(k => k.includes("DEVICE_CODE")));
  });
  ```

- [ ] **2c. Run worker-bridge tests**

  ```bash
  npm test -- test/unit/providers/kiro-worker.test.js
  ```

  All tests pass.
</checkbox>

---

## Task 3: Slim `index.js` rewrite + provider tests

**Goal:** Rewrite `src/providers/kiro/index.js` as a slim pure-HTTP provider — no browser imports, no Puppeteer. All browser logic replaced by spawning the Python worker.

### Steps

<checkbox>
- [ ] **3a. Verify current `index.js` size and drop top-level browser requires**

  Current file: 1532 lines. Slim target: ~300-400 lines.

  Top-level requires that MUST be dropped (existing line 1-16):
  - `crypto` (still needed for password gen)
  - `BaseProvider` + errors (keep)
  - `safeUrl, lang, clickByText, clickBySelector, dismissCookieBanner, clickPrimaryButton, clickPrimaryButtonMouse, focusPage, randomRealisticName, reactTypeInput` from `../../services/browser` (DROP entirely)

  New top-level requires:
  ```js
  "use strict";
  const crypto = require("crypto");
  const { BaseProvider } = require("../../base/provider");
  const { AuthError, QuotaError } = require("../../base/errors");
  const {
    buildWorkerEnv,
    parseWorkerLine,
    spawnSignupWorker,
    pickName,
  } = require("./worker-bridge");
  ```

- [ ] **3b. Implement `static` members**

  ```js
  static get providerName() { return "kiro" }

  static get endpoints() {
    return {
      deviceCode: "/api/oauth/kiro/device-code",
      poll: "/api/oauth/kiro/poll",
      provider: "/api/providers",
    };
  }

  detectMethod(email) {
    if (!email) return "email";
    if (email.toLowerCase().endsWith("@gmail.com")) return "google";
    return "email";
  }
  ```

- [ ] **3c. Implement `add()` method**

  ```
  async add(credentials = {}, options = {}) {
    1. Validate:
       - detectMethod(email) === "google" → throw AuthError("Google...pure-HTTP v1")
       - imap mode: require credentials.email + credentials.password AND config.imap.user + config.imap.password
       - tempmail mode: allow email="" → tempmail@pending.local, require password (auto-gen if empty)
       - NO browser/launchBrowser call
    2. Set instance fields:
       - this._accountEmail = credentials.email
       - this._accountPassword = password || `Kiro${crypto.randomBytes(6).toString("base64").slice(0,8)}!A1`
    3. GET device-code:
       - const deviceData = await this._apiCall("GET", this.constructor.endpoints.deviceCode)
       - deviceData must have device_code, verification_uri_complete, expires_in, interval
    4. Spawn worker:
       - await this._runSignupWorker(deviceData, options)
       - captures tempmail address from tempmail_create event if applicable
    5. Poll:
       - const pollResult = await this.pollUntilConnected(deviceData, this._accountEmail)
    6. Return {ok: true, id: pollResult.connection?.id, ...pollResult}
  }
  ```

- [ ] **3d. Implement `_runSignupWorker(deviceData, options)`**

  Port from grok-cli with kiro-specific changes:

  ```js
  async _runSignupWorker(deviceData, options) {
    const timeoutMs = Math.max(60000, (deviceData.expires_in ?? 600) * 1000 - 60000);
    const env = buildWorkerEnv({
      deviceData,
      credentials: {
        email: this._accountEmail,
        password: this._accountPassword,
      },
      config: this.config,
      options,
    });
    const workerDir = path.join(__dirname, "worker");

    await spawnSignupWorker(workerDir, env, {
      onEvent: (line) => {
        if (line.kind === "event" && line.step === "tempmail_create" && line.payload?.address) {
          this._tempmailAddress = line.payload.address;
        }
        if (line.kind === "event" || line.kind === "debug") {
          this.logger?.debug?.("[kiro worker]", line);
        }
        if (line.kind === "result") {
          this.logger?.debug?.("[kiro worker] result:", line);
        }
      },
      timeoutMs,
    });
  }
  ```

- [ ] **3e. Implement `pollUntilConnected(deviceData, email)`**

  Port from grok-cli but with kiro-specific poll body (`{deviceCode, extraData}`):

  ```js
  async pollUntilConnected(deviceData) {
    if (!deviceData.device_code) {
      throw new Error("No device_code in deviceData");
    }

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
      const result = await this._apiCall("POST", this.constructor.endpoints.poll, {
        deviceCode: deviceData.device_code,
        extraData,
      });

      if (result.success && result.connection) {
        await this.renameConnection(result.connection.id, this._accountEmail || this.constructor.providerName);
        return result;
      }
      if (result.pending) {
        await new Promise(r => setTimeout(r, intervalMs));
        continue;
      }
      if (result.expired_token) {
        throw Object.assign(new Error("Device code expired before approval"), { code: "EXPIRED_TOKEN" });
      }
      if (result.access_denied) {
        throw Object.assign(new Error("User denied the device authorization request"), { code: "ACCESS_DENIED" });
      }
      throw new Error(`Poll failed: ${result.error || result}`);
    }

    const err = new Error("Device code expired (timed out)");
    err.code = "POLL_TIMEOUT";
    err.retryable = true;
    throw err;
  }
  ```

- [ ] **3f. Implement remaining lifecycle methods**

  ```js
  async beforeAdd(credentials, options) {
    const { quota } = this.services;
    if (quota && credentials.email) {
      const cap = (this.config.providerConfig?.quotaCap) || 3;
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

  async afterAdd(result) {
    if (!result.ok) return;
    try {
      const name = this._accountEmail || this.config.providers?.kiro?.name || this.constructor.providerName;
      await this.renameConnection(result.id, name);
    } catch (err) {
      this.logger?.warn?.("kiro afterAdd rename failed:", err.message);
    }
  }

  async inspect(id) {
    if (this.config.mode === "local") {
      const { findById } = require("../../core/db");
      return findById(this.config, id);
    }
    return this._apiCall("GET", `${this.constructor.endpoints.provider}/${encodeURIComponent(id)}`);
  }

  async delete(id) {
    if (this.config.mode === "local") {
      const { del } = require("../../core/db");
      await del(this.config, id);
      return;
    }
    await this._apiCall("DELETE", `${this.constructor.endpoints.provider}/${encodeURIComponent(id)}`);
  }

  async renameConnection(id, name) {
    return this._apiCall("PUT",
      `${this.constructor.endpoints.provider}/${encodeURIComponent(id)}`,
      { name }
    );
  }
  ```

- [ ] **3g. Implement `_apiCall` helper**

  Same as grok-cli pattern:

  ```js
  async _apiCall(method, path, body) {
    const bodyStr = body ? JSON.stringify(body) : undefined;
    const res = await this.apiCall(method, path, bodyStr, {
      headers: bodyStr ? { "Content-Type": "application/json" } : undefined,
    });
    if (res.status && res.status >= 400) {
      const errBody = typeof res.body === "string" ? res.body : JSON.stringify(res.body);
      throw new Error(`HTTP ${res.status} from ${path}: ${errBody}`);
    }
    return res.body || res;
  }
  ```

- [ ] **3h. Create `test/unit/providers/kiro.test.js`**

  Port from `test/unit/providers/grok-cli.test.js` with kiro-specific changes:

  ```js
  // Structure:
  // 1. static providerName === "kiro"
  // 2. static endpoints — deviceCode, poll, provider
  // 3. detectMethod — null→email, @gmail.com→google, @outlook.com→email
  // 4. add validation — google/@gmail.com throws AuthError (/Google.*pure-HTTP/i)
  // 5. add validation — imap mode requires email+password (/email.+password/i)
  // 6. add validation — imap mode requires imap config (/IMAP config/i)
  // 7. add validation — tempmail mode allowed without email (/pending.local/)
  // 8. add validation — tempmail mode with missing password auto-generates
  // 9. add happy path — GET device-code → worker → poll → rename
  // 10. add happy path — asserts poll body deepStrictEqual {deviceCode, extraData}
  // 11. pollUntilConnected — success
  // 12. pollUntilConnected — expired_token → EXPIRED_TOKEN
  // 13. pollUntilConnected — access_denied → ACCESS_DENIED
  // 14. pollUntilConnected — timeout → POLL_TIMEOUT (retryable)
  // 15. pollUntilConnected — missing device_code throws
  // 16. renameConnection — uses encodeURIComponent
  // 17. inspect — local mode uses findById
  // 18. inspect — remote mode uses API
  // 19. delete — local mode uses del
  // 20. delete — remote mode uses API
  // 21. beforeAdd — quota not exceeded → undefined
  // 22. beforeAdd — quota exceeded → {ok: false, skip: true, reason: /Quota cap/i}
  ```

  Key helpers (port from grok-cli test):
  - `loadProvider()` — clears require.cache
  - `makeConfig(overrides)` — mode, baseUrl, imap, providers, providerConfig
  - `makeProvider(config, services)` — passes no-op api `{request: async () => ({})}`

- [ ] **3i. Run provider tests**

  ```bash
  npm test -- test/unit/providers/kiro.test.js
  ```

  All pass.
</checkbox>

---

## Task 4: Python OTP/IMAP helpers + unit tests

**Goal:** Port OTP extraction and IMAP reading from grok-cli's `signup.py` into kiro worker with AWS-specific 6-digit code handling. Tests are `unittest`-style.

### Steps

<checkbox>
- [ ] **4a. Add `extract_otp` (AWS 6-digit version) to `signup.py`**

  Port from grok-cli with NEW regex for AWS:

  ```python
  import re, email, html, quopri
  from email.header import decode_header

  # AWS OTP patterns (6-digit codes)
  _OTP_DIGIT6_RE = re.compile(
      r"(?:(?:verification|confirmation)\s+code|otp|one[- ]time(?: pass(?:word|code)?))"
      r"[:\s#]*(\d{6})\b",
      re.IGNORECASE
  )
  # Fallback: bare 6-digit with AWS context nearby
  _OTP_DIGIT6_BARE_RE = re.compile(r"\b(\d{6})\b")

  _AWS_MARKERS = ("signin.aws", "aws", "amazon web services", "builder id")

  _OTP_NOISE = {"111111", "222222", "123456", "000000", "999999", "666666"}

  def extract_otp(text: str, subject: str = "") -> str | None:
      """Extract 6-digit AWS OTP code from text."""
      # Step 1: Labeled 6-digit (primary)
      m = _OTP_DIGIT6_RE.search(text)
      if m and m.group(1) not in _OTP_NOISE:
          return m.group(1)
      # Step 2: Bare 6-digit if AWS context
      has_aws = any(marker in text.lower() for marker in _AWS_MARKERS)
      if has_aws:
          for m in _OTP_DIGIT6_BARE_RE.finditer(text):
              if m.group(1) not in _OTP_NOISE:
                  return m.group(1)
      return None
  ```

- [ ] **4b. Add `extract_otp_from_message` and `_decode_subject` / `_strip_html`**

  Port verbatim from grok-cli `signup.py` (lines 336-380):

  ```python
  def _decode_subject(subject: bytes | str | None) -> str:
      if not subject:
          return ""
      if isinstance(subject, bytes):
          subject = subject.decode("utf-8", errors="replace")
      parts = decode_header(subject)
      return " ".join(
          part.decode(charset or "utf-8", errors="replace") if isinstance(part, bytes)
          else str(part)
          for part, charset in parts
      )

  def _strip_html(html_text: str) -> str:
      clean = re.sub(r"<style[^>]*>.*?</style>", "", html_text, flags=re.DOTALL)
      clean = re.sub(r"<script[^>]*>.*?</script>", "", clean, flags=re.DOTALL)
      clean = re.sub(r"<[^>]+>", " ", clean)
      clean = html.unescape(clean)
      clean = re.sub(r"\s+", " ", clean).strip()
      return clean

  def extract_otp_from_message(raw_bytes: bytes) -> str | None:
      try:
          msg = email.message_from_bytes(raw_bytes)
      except Exception:
          return None

      subject = _decode_subject(msg["Subject"])

      body = ""
      if msg.is_multipart():
          for part in msg.walk():
              ct = part.get_content_type()
              if ct == "text/plain":
                  try:
                      body = part.get_payload(decode=True).decode("utf-8", errors="replace")
                  except Exception:
                      body = ""
              elif ct == "text/html" and not body:
                  try:
                      body = _strip_html(part.get_payload(decode=True).decode("utf-8", errors="replace"))
                  except Exception:
                      body = ""
      else:
          ct = msg.get_content_type()
          try:
              payload = msg.get_payload(decode=True)
              if payload is None:
                  return None
              raw = payload.decode("utf-8", errors="replace")
              if ct == "text/html":
                  body = _strip_html(raw)
              else:
                  body = raw
          except Exception:
              return None

      code = extract_otp(subject)
      if code:
          return code
      return extract_otp(body)
  ```

- [ ] **4c. Add IMAP helpers with `KIRO_*` env vars**

  ```python
  def imap_cfg_from_env() -> dict:
      return {
          "host": os.getenv("KIRO_IMAP_HOST", "imap.gmail.com"),
          "port": os.getenv("KIRO_IMAP_PORT", "993"),
          "user": os.getenv("KIRO_IMAP_USER", ""),
          "password": os.getenv("KIRO_IMAP_PASSWORD", ""),
          "tls": os.getenv("KIRO_IMAP_TLS", "true"),
          "delete_after_read": os.getenv("KIRO_IMAP_DELETE_AFTER_READ", "false"),
          "subject": os.getenv("KIRO_OTP_SUBJECT", ""),
          "sender_domain": os.getenv("KIRO_OTP_SENDER_DOMAIN", "signin.aws"),
      }
  ```

  Port these helpers from grok-cli with `KIRO_*` env:

  - `_mailboxes_for(host)` — same logic (gmail → INBOX + Spam + All Mail)
  - `_select_mailbox(m, mailbox)` — same, debug events on failure
  - `_search_ids(m, target_email, sender_domain)` — same
  - `read_otp(target_email, cfg, retries=40, delay=3.0)` — same retry loop but with `KIRO_*` defaults (`delay=5.0` for AWS which may be slower)

  Key change: `read_otp` uses `KIRO_OTP_SENDER_DOMAIN` default `"signin.aws"` in search: `(TO "{target}" FROM "{domain}")`.

- [ ] **4d. Create `worker/test_otp.py` (unittest style)**

  ```python
  import os, sys, unittest
  sys.path.insert(0, os.path.dirname(__file__))
  from signup import extract_otp, extract_otp_from_message, _strip_html, _decode_subject

  class TestOTPExtraction(unittest.TestCase):
      def test_labeled_6digit_code(self):
          self.assertEqual(extract_otp("Your verification code: 482916"), "482916")

      def test_confirmation_code(self):
          self.assertEqual(extract_otp("Confirmation code: 735182"), "735182")

      def test_otp_labeled(self):
          self.assertEqual(extract_otp("Your OTP is 284619"), "284619")

      def test_one_time_password(self):
          self.assertEqual(extract_otp("One-time password: 918273"), "918273")

      def test_noise_rejected(self):
          self.assertIsNone(extract_otp("Code: 123456"))
          self.assertIsNone(extract_otp("Code: 000000"))

      def test_bare_6digit_with_aws_context(self):
          self.assertEqual(extract_otp("AWS verification: code 374829"), "374829")

      def test_bare_6digit_no_context(self):
          self.assertIsNone(extract_otp("Your number is 482916"))

      def test_subject_extraction(self):
          subj = _decode_subject("=?UTF-8?B?VmVyaWZ5IHlvdXIgQVdTIEJ1aWxkZXIgSUQgZW1haWwgYWRkcmVzcw==?=")
          # Subject: "Verify your AWS Builder ID email address"
          self.assertIn("AWS", subj)

      def test_strip_html(self):
          html_str = "<html><body><p>Your code: <b>482916</b></p></body></html>"
          self.assertIn("482916", _strip_html(html_str))

      def test_extract_from_message_html(self):
          raw = (
              b"From: sender@signin.aws\r\n"
              b"Subject: Verify your AWS Builder ID email address\r\n"
              b"Content-Type: text/html; charset=utf-8\r\n\r\n"
              b"<html><body><p>Your verification code: 482916</p></body></html>"
          )
          self.assertEqual(extract_otp_from_message(raw), "482916")

      def test_extract_from_message_plain(self):
          raw = (
              b"From: sender@signin.aws\r\n"
              b"Subject: Verify your AWS Builder ID email address\r\n"
              b"Content-Type: text/plain; charset=utf-8\r\n\r\n"
              b"Your verification code: 482916"
          )
          self.assertEqual(extract_otp_from_message(raw), "482916")

  if __name__ == "__main__":
      unittest.main()
  ```

- [ ] **4e. Run Python OTP tests**

  ```bash
  cd src/providers/kiro/worker && .venv/bin/python3 -m pytest test_otp.py -v
  ```

  All pass.
</checkbox>

---

## Task 5: Phase D0 — AWS endpoint discovery (BLOCKING GATE)

**Goal:** Map the real AWS Builder ID OAuth device-code + signup endpoints before implementing any worker HTTP steps. This is a BLOCKING gate — Task 6 MUST NOT start until this is committed.

### Steps

<checkbox>
- [ ] **5a. Create `scripts/kiro-capture-aws.js`**

  This is a standalone Node script that:
  1. Loads config via `loadConfig(process.argv.slice(2))`
  2. Launches a real browser using `launchStealthBrowser(config, services, options)` from `../../src/services/browser`
  3. Navigates to the kiro device-code URL from 9router
  4. Captures all outgoing requests (method, URL, headers, body) during the email-entry flow
  5. Saves captured endpoint map to `docs/superpowers/specs/2026-07-23-kiro-aws-endpoint-map.md`

  ```js
  // scripts/kiro-capture-aws.js
  "use strict";
  const path = require("path");
  const { loadConfig } = require("../src/core/config");
  const { launchStealthBrowser } = require("../src/services/browser");

  async function main() {
    const config = loadConfig(process.argv.slice(2));
    const services = {};
    const captured = [];

    const { browser, page } = await launchStealthBrowser(config, services);

    page.on("request", req => {
      captured.push({
        url: req.url(),
        method: req.method(),
        headers: req.headers(),
        postData: req.postData(),
        resourceType: req.resourceType(),
      });
    });

    page.on("response", async resp => {
      // Skip static assets; capture API responses
      if (resp.url().includes("/api/") || resp.url().includes("/oauth/")) {
        let body;
        try { body = await resp.text(); } catch { body = "<unreadable>"; }
        captured[captured.length - 1].response = {
          status: resp.status(),
          body: body.substring(0, 5000),
        };
      }
    });

    // Navigate to the AWS device-code activation URL
    const deviceUrl = process.env.CAPTURE_DEVICE_URL;
    if (!deviceUrl) {
      console.error("Set CAPTURE_DEVICE_URL env to the device-code activation URL");
      await browser.close();
      process.exit(1);
    }
    await page.goto(deviceUrl, { waitUntil: "networkidle2" });
    console.log("Navigated to device URL. Waiting 120s for manual email entry...");

    // Wait for user to complete the flow, then keyboard interrupt to save
    await new Promise(r => setTimeout(r, 120000));

    // Write endpoint map
    const fs = require("fs");
    const mapPath = path.join(__dirname, "../docs/superpowers/specs/2026-07-23-kiro-aws-endpoint-map.md");
    const lines = [
      "# AWS Builder ID — Captured Endpoint Map",
      `> Captured ${new Date().toISOString()}`,
      "",
      "## Endpoints",
      "",
    ];
    for (const req of captured) {
      if (req.resourceType === "xhr" || req.resourceType === "fetch" || req.url.includes("/api/")) {
        lines.push(`### ${req.method} ${new URL(req.url).pathname}`);
        lines.push(`- **Full URL:** \`${req.url}\``);
        lines.push(`- **Method:** ${req.method}`);
        if (req.postData) lines.push(`- **Body:** \`\`\`\n${req.postData}\n\`\`\``);
        if (req.response) {
          lines.push(`- **Status:** ${req.response.status}`);
          lines.push(`- **Response (truncated):** \`\`\`\n${req.response.body}\n\`\`\``);
        }
        if (req.headers["content-type"]) lines.push(`- **Content-Type:** ${req.headers["content-type"]}`);
        lines.push("");
      }
    }
    fs.writeFileSync(mapPath, lines.join("\n"));
    console.log(`Endpoint map saved to ${mapPath}`);

    // Print to stdout for immediate use
    console.log("\n=== CAPTURED ENDPOINTS ===");
    for (const req of captured) {
      if (req.resourceType === "xhr" || req.resourceType === "fetch" || req.url.includes("/api/")) {
        console.log(`${req.method} ${new URL(req.url).pathname}`);
      }
    }

    await browser.close();
  }

  main().catch(err => { console.error(err); process.exit(1); });
  ```

- [ ] **5b. Manual capture session**

  ```bash
  # 1. Get a fresh device-code URL from 9router
  #    (run the kiro add command up to the point it prints the device URL, then abort)
  CAPTURE_DEVICE_URL="<device-url>" node scripts/kiro-capture-aws.js
  ```

  During the 120s window:
  1. Switch to the Chrome window
  2. Enter an email address
  3. Complete the flow up to device-confirm/consent
  4. Wait for the script to save results

  Alternatively run `node scripts/kiro-capture-aws.js` without env and manually navigate.

- [ ] **5c. Review and commit endpoint map**

  After capture:
  1. Review `docs/superpowers/specs/2026-07-23-kiro-aws-endpoint-map.md` for any secrets in logged request bodies
  2. Scrub any secrets (passwords, tokens, codes) replacing with `<REDACTED>`
  3. Keep only: URL paths, HTTP methods, required headers, body field names (not values), response field names (not values)
  4. Commit:

  ```bash
  git add docs/superpowers/specs/2026-07-23-kiro-aws-endpoint-map.md scripts/kiro-capture-aws.js
  git commit -m "feat(kiro): Phase D0 AWS endpoint map + capture script"
  ```

- [ ] **5d. Update spec Appendix A**

  Copy the endpoint map paths into `docs/superpowers/specs/2026-07-23-kiro-pure-http-design.md` Appendix A.

  ✅ **Phase D0 gate passed.** Only now may Task 6 begin.
</checkbox>

---

## Task 6: Implement worker signup steps against endpoint map

**Goal:** Replace the `not-implemented` stub in `signup.py` with real HTTP steps using `curl_cffi`, following the captured endpoint map. Each step is implemented and tested iteratively.

### Steps

<checkbox>
- [ ] **6a. Add `_ensure_creq()` lazy import to `signup.py`**

  ```python
  # Lazy import so OTP/unit helpers work without curl_cffi
  _creq_module = None
  def _ensure_creq():
      global _creq_module
      if _creq_module is None:
          from curl_cffi import requests as _creq_module  # type: ignore
      return _creq_module
  ```

- [ ] **6b. Implement step: `email_entry`**

  From endpoint map, identify the email-submission endpoint. POST the email from `KIRO_EMAIL`.

  ```python
  def step_email_entry(session, email: str) -> bool:
      """Submit email address to AWS device-code flow."""
      emit_step("email_entry", "pending")
      # TODO: use captured endpoint from map
      # Example:
      # url = f"{base_url}/some/email/endpoint"
      # resp = session.post(url, json={"email": email})
      # resp.raise_for_status()
      emit_step("email_entry", "ok")
      return True
  ```

  Implement based on actual captured endpoint.

- [ ] **6c. Implement step: `name` / `password`**

  Submit the full name and password to the name-entry and password-set endpoints.

  ```python
  def step_name(session, name: str) -> bool: ...
  def step_password(session, password: str) -> bool: ...
  ```

- [ ] **6d. Implement step: `otp`**

  Call IMAP `read_otp()` or tempmail `wait_code()` depending on `KIRO_EMAIL_SOURCE`.

  ```python
  def step_otp(session, email: str, cfg: dict) -> str | None:
      emit_step("otp", "pending", source=os.getenv("KIRO_EMAIL_SOURCE", "imap"))
      if os.getenv("KIRO_EMAIL_SOURCE") == "tempmail":
          from tempmail import EmailBox  # local import
          box = EmailBox(prefer=os.getenv("KIRO_TEMPMAIL_PROVIDERS", "").split(","))
          address = email
          code = box.wait_code(timeout=150)
      else:
          code = read_otp(email, cfg)
      if code:
          emit_step("otp", "ok", elapsed_s=round(time.time() - _step_start, 1))
          return code
      emit_step("otp", "failed")
      return None
  ```

- [ ] **6e. Implement step: `otp_verify`**

  POST the OTP code to the verification endpoint.

- [ ] **6f. Implement step: `device_confirm` + `consent`**

  Handle device confirmation and OAuth consent screens if needed.

- [ ] **6g. Update `run()` to call the steps**

  Replace the stub in `run()`:

  ```python
  def run() -> int:
      email = os.getenv("KIRO_EMAIL", "")
      password = os.getenv("KIRO_PASSWORD", "")
      device_url = os.getenv("KIRO_DEVICE_URL", "")
      name = os.getenv("KIRO_NAME", "")

      if not email or not password or not device_url:
          emit_result(False, error="missing-required-env", step="init")
          return 1

      emit_step("bootstrap", "ok")

      session = _ensure_creq()
      impersonate = "chrome131"
      proxy = os.getenv("KIRO_PROXY")

      step = "bootstrap"
      try:
          # Build session with impersonation
          session_kwargs = {"impersonate": impersonate}
          if proxy:
              session_kwargs["proxies"] = {"http": proxy, "https": proxy}

          with session.Session() as s:
              s.headers.update({"User-Agent": "Mozilla/5.0 ..."})

              step = "email_entry"
              step_email_entry(s, email)

              step = "name"
              step_name(s, name)

              step = "otp"
              code = step_otp(s, email, imap_cfg_from_env())
              if not code:
                  emit_result(False, error="otp-not-found", step=step)
                  return 1

              step = "otp_verify"
              step_otp_verify(s, code)

              step = "password"
              step_password(s, password)

              step = "device_confirm"
              step_device_confirm(s)

              step = "consent"
              step_consent(s)

          emit_step("done", "ok")
          emit_result(True)
          return 0

      except Exception as e:
          # Redact secrets in error message
          err_str = re.sub(
              r"(password|otp|token|code)=[^\s&]+",
              r"\1=<redacted>",
              str(e)[:300]
          )
          emit_step(step, "error", message=err_str)
          emit_result(False, error=err_str, step=step)
          return 1
  ```

- [ ] **6h. Live smoke test**

  After all steps implemented, run a live test:

  ```bash
  # Prerequisites: config.json has valid imap credentials
  # or use tempmail mode
  node . add kiro --email test-user@example.com --tempmail
  ```

  Expected: worker runs through all steps, device gets authorized, 9router stores connection.

- [ ] **6i. Handle WAF blocks**

  If `curl_cffi` triggers WAF:
  1. Log the blocking page signature (status code, response body keywords)
  2. Stop and escalate — do NOT silently reintroduce browser
  3. Possible mitigations to try:
     - Rotate proxy
     - Adjust impersonation parameters
     - Add request delays
  4. If all mitigations fail, WAF block must be documented as blocker

- [ ] **6j. Commit worker implementation**

  ```bash
  git add src/providers/kiro/worker/signup.py
  git commit -m "feat(kiro): Phase D1 worker signup steps against endpoint map"
  ```
</checkbox>

---

## Task 7 (Optional): Remove Puppeteer paths + cleanup

**Goal:** After live smoke is green, clean up the old browser code and update docs.

### Steps

<checkbox>
- [ ] **7a. Deprecate browser-based kiro `detectMethod("google")`**

  Ensure `detectMethod` still rejects `@gmail.com` but can be extended in future.

- [ ] **7b. Update docs**

  - `docs/superpowers/specs/2026-07-23-kiro-pure-http-design.md` — add note about live smoke results
  - Update `docs/superpowers/specs/2026-07-23-temp-mail-dual-mode-design.md` to note kiro OTP moved into worker

- [ ] **7c. Remove old kiro Puppeteer code**

  Only after live smoke is consistently green:
  - Remove browser related requires/commented-out code
  - No functional change — the slim `index.js` already excluded them
  </checkbox>

---

## Self-Review Checklist

Before marking the plan as complete:

- [ ] **Spec coverage:** Every rule from `2026-07-23-kiro-pure-http-design.md` is reflected in at least one task step
- [ ] **Placeholder scan:** No `FIXME`, `TODO`, `XXX` in committed code (stub `not-implemented` is intentional — flagged by task)
- [ ] **Type consistency:** `parseWorkerLine` returns `{kind: string, ok?: boolean, error?: string, step?: string, payload?: any}` consistent across bridge and tests
- [ ] **Env contract:** `buildWorkerEnv` never leaks `device_code`, `codeVerifier`, `_clientSecret` (Task 2b security test)
- [ ] **Error strings:** All worker error messages prefixed `"kiro worker"` (not `"grok-cli worker"`)
- [ ] **Phase D0 blocking gate:** Task 5 MUST complete before Task 6 begins
- [ ] **Quota behavior:** `beforeAdd` returns `{skip: true, reason}` not `throws QuotaError` (kiro-specific divergence)

---

## Execution Handoff

Plan complete and saved to `docs/superpowers/plans/2026-07-23-kiro-pure-http-plan.md`.

Two execution options:

**1. Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration. Subagents work independently with full context per task. I review results and adjust between tasks.

**2. Inline Execution** — Execute tasks in this session step by step, with periodic checkpoints. Full visibility into each command and output. Slower but more transparent.

Which approach?
