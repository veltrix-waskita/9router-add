# Qoder Provider Design (pure-HTTP — register + PAT)

**Date:** 2026-08-07
**Status:** Approved (brainstorming)
**Branch:** master

## Goal

Add a **qoder** provider to 9router-add that registers a Qoder account (qoder.com)
fully via HTTP — no browser — and returns a Personal Access Token (PAT). Email OTP
read is dual-mode (tempmail via ncaori / IMAP Gmail+minom). Output saved to
`generated-accounts-qoder-*.json` (no 9router inject).

## Context (all live-verified 2026-08-07)

Sources:
- `qoder-autoreg` (github.com/wuzzstoreservice/qoder-autoreg, cloned) — browser
  flow (Playwright), Aliyun slider CAPTCHA solver, TMD anti-bot workaround.
- `qoder.json` (512KB HAR capture, repo root, user-provided) — every request/
  response to qoder.com from a real browser session.

### Endpoints (from HAR)
- `POST /api/v1/users` — register. Payload:
  `{"type":"email_pwd","email","password","code","name","invitation_code":"","bx-ua":"<fp>"}`
- `GET /api/v1/users/sign-up` (page, serves csrf = `_echo_csrf_using_sec_fetch_site_`)
- `GET /api/v1/me` — auth check after register
- `GET/POST /api/v1/me/personal-access-tokens` — PAT create/list
- `GET /api/v1/auth/check-login-type` — email existence check (optional)

### Feasibility tests (live):
1. **`bx-ua` empty + no cookie → TMD punish.** POST `/api/v1/users` with `bx-ua:""`
   returned HTTP 200 body = `<script>...punish?...x5secdata=...</script>`
   (`/api/v1/users/_____tmd_____/punish`). TMD anti-bot block.
2. **`bx-ua` non-empty (random 100 chars) → TMD bypassed.** GET `/users/sign-up`
   (200, sets no cookies — CSRF is Sec-Fetch-Site echo, not a token), then POST
   `/api/v1/users` with `bx-ua:"<random>"` returned **HTTP 400**:
   `{"errorCode":"BadRequest","errorMessage":"Key: 'RegisterRequest.Code' ... 'Code' failed on the 'required' tag"}`
   → TMD gone; server wants the OTP `code` (normal register step). Pure-HTTP
   register is FEASIBLE.
3. HTML serves `window.AliyunCaptchaConfig = {region:"sgp", prefix:...}` — the
   signup page embeds Aliyun slider CAPTCHA config (the browser-era solves it;
   our pure-HTTP path may need it only if a second challenge appears after OTP).

### Why pure-HTTP (not browser)
- Register POST works with non-empty `bx-ua` (verified). No Playwright needed.
- CSRF is Sec-Fetch-Site echo, not a token to mbar.
- Repo pattern: kiro/grok are pure-HTTP curl_cffi workers.

## Component Design

### `src/providers/qoder/worker/signup.py` — the pure-HTTP worker
Follows kiro/grok worker pattern: curl_cffi (impersonate chrome131), step events
emitted as JSON lines (`emit_step`), env-driven (`QODER_EMAIL`, `QODER_PASSWORD`,
`QODER_EMAIL_SOURCE` = imap|tempmail, `QODER_NAME`, `QODER_PROXY`).

Flow (`run()`):
1. `GET /users/sign-up` → warm session cookies (`qoder_locale=en`, `_ga`, ...).
2. `POST /api/v1/users` with `{type:email_pwd, email, password, code:"",
   name, invitation_code:"", bx-ua:"<crypto.randomBytes(64).toString('base64')>"}`
   headers: `Content-Type:application/json`, `Referer:/users/sign-up`,
   `Origin:qoder.com`, `Sec-Fetch-Site:same-origin`, `Sec-Fetch-Mode:cors`.
   - If response body contains `x5secdata` / `_____tmd_____` → retry with a new
     random `bx-ua` (up to 3). (TMD requires non-empty `bx-ua`; random suffices.)
   - If 400 `BadRequest ... 'Code' required` → normal (OTP pending). Continue.
   - Any other 4xx/5xx → surface.
3. **OTP poll** (dual):
   - tempmail: reuse `src/providers/kiro/worker/temppmail`? no — use a standalone
     ncaori poll (mail_tm pattern) or, cleaner, reuse the existing
     `src/services/tempmail.js`-style poll inside the worker.
   - imap: reuse `read_otp`-style IMAP poll for Gmail/minom alias.
   Extract 6-digit/5-digit code.
4. `POST /api/v1/users` again with `code:<otp>` → expect 200/201, session cookie
   set.
5. `GET /api/v1/me` → confirm authenticated (status 200 + body has user id).
6. `POST /api/v1/me/personal-access-tokens` → create PAT. Payload shape:
   confirm from sample HAR (available) — likely `{name:"...", description:"..."}`
   or a body from the create-token form.
7. Emit result `{ok:true, email, password, pat}`; caller writes
   `generated-accounts-qoder-<stamp>.json`.

### `src/modules/qoder/index.js` — provider class
`module.exports = class QoderProvider extends BaseProvider` with `providerName:
"qoder"`, endpoints. Spawns the worker (pseudo-http bridge like kiro worker-bridge).
`add(credentials, {emailSource})` → call worker, parse result, build connection
object. `PROVIDER_INFO.qoder` added to runner.js:
`{label:"Qoder", methods:["email"], needsBrowser:false, needsWorker:true,
needsSolver:false, batch:true, autoCredentials:true, supportsTempmail:true,
needsImap:false}`.

### Email OTP plumbing
- **tempmail**: poll ncaori (ncaori.my.id) inbox for the Qoder code (reuse mail_tm
  in the worker). No IMAP.
- **imap**: reuse kiro `read_otp`/`_mailboxes_for` logic (Gmail/minom) — sender
  domain likely qoder.com; verify from HAR (the OTP email From).

### PAT creation
From HAR: `GET/POST /api/v1/me/personal-access-tokens`. The create-token modal
posts a body; extract exact payload+endpoint from HAR response before coding.
Fallback: if PAT endpoint needs UI (not plain POST), list existing or emit
session cookies only with a note.

### Tests
- Python unit tests (worker): payload shape, bx-ua non-empty, TMD-response
  detect, OTP code extract, PAT response parser (mock responses).
- npm tests: provider class + runner entry registered.

## Error handling
- TMD punish: retry new `bx-ua` (3×)
- OTP timeout: retry with fresh email (source does 3 attempts)
- 400 `Code required`: treat as "advance to OTP step"
- Network/proxy failures: retryable

## Security
- Never log password / PAT / OTP. Mask 6-digit runs.
- `bx-ua` random blob (no real fingerprint data stored).
- `generated-accounts-qoder-*.json` written with private-most perms; never commit.
- `qoder.json` (HAR) contains a live password (`Lucky123!`) — DO NOT commit, and
  it is a user file in repo root (untracked); mention to rotate.

## Out of scope
- 9router inject / device-code flow
- Aliyun CAPTCHA re-engineer (pure-HTTP bypass verified for register)
- Mocasus email provider (using ncaori instead)