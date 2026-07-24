# Kiro pure-HTTP (email-only) — Design

**Date:** 2026-07-23  
**Status:** Written — awaiting user review before implementation plan  
**Scope:** Replace browser-based Kiro **email** (AWS Builder ID) registration with a pure-HTTP worker, mirroring grok-cli.  
**Approach:** Node orchestrator + Python `curl_cffi` worker (Approach 1).  
**Related:** [2026-07-23-tempmail-dual-mode-design.md](./2026-07-23-tempmail-dual-mode-design.md), grok-cli provider (`src/providers/grok-cli/`).

## Problem

`src/providers/kiro/index.js` drives Kiro OAuth with Puppeteer:

1. `GET /api/oauth/kiro/device-code`
2. Browser on `verification_uri_complete` (`view.awsapps.com`)
3. Either **Google** (“Continue with Google”) or **email** (AWS Builder ID: alias → name → OTP → password → device confirm → Kiro consent)
4. `POST /api/oauth/kiro/poll` until 9router stores the connection

Email automation is ~1k lines of DOM brittle against CloudScape SPA changes. grok-cli already proves a cleaner split: Node owns device-code/poll/secrets; a Python pure-HTTP worker owns signup + device authorize.

## Goals

1. **Email-only pure HTTP** for Kiro — no browser, no Puppeteer for the email path.
2. Same security split as grok-cli: `device_code`, poll `extraData` (`_clientId`, `_clientSecret`, …), and any `codeVerifier` **never leave Node**. Worker only receives `user_code` via `KIRO_DEVICE_URL` (`verification_uri_complete`).
3. Dual email source: **imap** | **tempmail**, consistent with the tempmail dual-mode design; for pure-HTTP kiro, **OTP lives in the Python worker** (not Node mid-flight injection).
4. Reuse 9router contracts unchanged: device-code GET, poll POST, rename PUT. No `injectToDb` after poll.
5. Never log password, OTP, `device_code`, or `codeVerifier`.

## Non-goals (v1)

- Pure-HTTP (or any) **Google** OAuth path for Kiro.
- Dual-path “browser fallback if HTTP fails.”
- Automatic multi-retry of a failed alias inside one `add()` (except OTP poll + 9router poll loops).
- Changing remote-mode auth or HTTPS rules.
- Live AWS calls in unit tests / CI.
- Guaranteeing cleanup of orphan AWS Builder ID accounts if poll expires after worker success.

## Feasibility summary

| Path | Pure HTTP? | Notes |
|------|------------|--------|
| **email** (Builder ID + IMAP/tempmail OTP) | **Yes, after discovery** | Same pattern as grok; hard part is mapping AWS SPA → HTTP APIs. |
| **google** | **No for v1** | accounts.google.com anti-bot; out of scope. |

## Architecture

```
┌─ Node: src/providers/kiro/ ─────────────────────────────┐
│  add()                                                   │
│   1. Reject method=google / @gmail.com (v1)              │
│   2. Validate emailSource (imap | tempmail)              │
│   3. GET /api/oauth/kiro/device-code                     │
│   4. spawn worker (user_code only; no device_code)       │
│   5. POST /api/oauth/kiro/poll until connected           │
│   6. rename connection                                   │
│  device_code + extraData stay in Node                    │
└──────────────────────────┬──────────────────────────────┘
                           │ env + JSONL
                           ▼
┌─ Python: worker/signup.py (curl_cffi Chrome 131) ───────┐
│  1. Session to KIRO_DEVICE_URL                           │
│  2. AWS Builder ID: email → name → OTP → password        │
│  3. Device confirm + Kiro consent                        │
│  4. JSONL steps + {"kind":"result","ok":...}             │
└──────────────────────────────────────────────────────────┘
```

### Components

| Piece | Role |
|-------|------|
| `src/providers/kiro/index.js` | Slim `BaseProvider`: validate, device-code, spawn, poll, rename. Remove Puppeteer email/google automation from the pure-HTTP cut. |
| `src/providers/kiro/worker-bridge.js` | Env contract, spawn, JSONL parse (grok-cli bridge pattern, `KIRO_*` names). |
| `src/providers/kiro/worker/signup.py` | Pure-HTTP AWS Builder ID + consent pipeline. |
| `src/providers/kiro/worker/requirements.txt` | `curl-cffi` (same pin style as grok-cli). |
| `src/providers/kiro/worker/tempmail.py` | Optional: reuse/port EmailBox subset (same as grok worker) for tempmail OTP. |
| OTP imap | Worker-side IMAP (defaults aligned with current `signin.aws` + Builder ID subject). |

### Hard rules

- Never log password, OTP, `device_code`, `codeVerifier`.
- Worker never receives `device_code`, `codeVerifier`, or poll `extraData` secrets.
- No `injectToDb` after poll (9router stores the connection).
- Remote non-localhost still requires HTTPS (core unchanged).

## Data flow

### Happy path

1. **Node `add(credentials, options)`**
   - If `detectMethod(email) === "google"` or email ends with `@gmail.com` → throw clear error: pure-HTTP kiro is email-only.
   - `emailSource=imap` (default): require `config.imap.user` + `config.imap.password`; require valid alias email.
   - `emailSource=tempmail`: require Builder ID password (or generate in Node before spawn); email may be created in worker.
   - Generate Builder ID password in **Node** if missing (same strength policy intent as current kiro); always pass explicitly to worker.
   - `GET /api/oauth/kiro/device-code`.
2. **Spawn worker** with env below; stream JSONL events to dashboard/logs (compact, secret-filtered).
3. **Worker** completes Builder ID + device consent (steps after discovery map).
4. **Node** `POST /api/oauth/kiro/poll` with:
   ```js
   {
     deviceCode: deviceData.device_code,
     extraData: {
       _clientId, _clientSecret, _region, _authMethod, _startUrl
     }
   }
   ```
   until `success` → rename connection to resolved email → return `{ ok: true, ...pollResult }`.

### Env contract (`buildWorkerEnv`)

| Env | Source | Notes |
|-----|--------|--------|
| `KIRO_EMAIL` | credentials.email | Alias or `tempmail@pending.local` placeholder |
| `KIRO_PASSWORD` | credentials.password (Node-generated if empty) | Builder ID password |
| `KIRO_NAME` | credentials.name or random realistic full name | Display name |
| `KIRO_DEVICE_URL` | `deviceData.verification_uri_complete` | Carries `user_code` only |
| `KIRO_EMAIL_SOURCE` | `imap` \| `tempmail` | |
| `KIRO_IMAP_HOST/PORT/USER/PASSWORD/TLS` | config.imap | imap mode only |
| `KIRO_IMAP_DELETE_AFTER_READ` | config.imap | |
| `KIRO_OTP_SUBJECT` | provider config or default Builder ID subject | |
| `KIRO_OTP_SENDER_DOMAIN` | default `signin.aws` | |
| `KIRO_TEMPMAIL_PROVIDERS` | options / config.tempmail | tempmail mode |
| `KIRO_PROXY` | options.proxy as URL | optional |
| `PURE_HTTP` | `1` | |

**Forbidden in env:** `device_code`, `codeVerifier`, `_clientSecret`, `_clientId`, raw poll `extraData`.

### JSONL events (parity with grok-cli)

| Event | When |
|-------|------|
| `{"event":"step","step":"bootstrap","status":"ok"}` | Session established on device URL |
| `{"event":"step","step":"email_entry","status":"ok"}` | Alias submitted |
| `{"event":"step","step":"name","status":"ok"}` | Display name submitted |
| `{"event":"step","step":"otp","status":"pending"}` | Each OTP poll |
| `{"event":"step","step":"otp","status":"ok","elapsed_s":N}` | OTP received (no code value) |
| `{"event":"step","step":"otp_verify","status":"ok"}` | Code accepted |
| `{"event":"step","step":"password","status":"ok"}` | Password set |
| `{"event":"step","step":"device_confirm","status":"ok"}` | Device confirmed |
| `{"event":"step","step":"consent","status":"ok"}` | Kiro/app consent |
| `{"kind":"result","ok":true}` | Success |
| `{"kind":"result","ok":false,"error":"...","step":"..."}` | Failure |

Debug events allowed without secrets: `{"event":"debug","msg":"..."}`.

## Discovery plan (blocking gate)

AWS Builder ID is a CloudScape SPA. Implementation of real HTTP steps in `signup.py` **starts only after** a captured endpoint map exists.

### Phase D0 — Capture

1. Run one successful browser email flow with network recording (HAR, mitmproxy, or Puppeteer request dump).
2. For each logical step record: method, URL, cookies/CSRF/`x-amz-*` headers, body shape, status, Set-Cookie, response keys.
3. Map:

| Step id | UI today | Capture target |
|---------|----------|----------------|
| `bootstrap` | open `verification_uri_complete` | session cookies, bootstrap APIs |
| `email_entry` | Sign in with email + alias | submit email |
| `name` | display name | continue / register name |
| `otp` | wait for mail | confirm code-sent; OTP via IMAP/tempmail |
| `otp_verify` | 6-box or single field | verify code API |
| `password` | create + confirm password | registration (`registrationCode` if present) |
| `device_confirm` | Confirm and continue | device authorization approve |
| `consent` | Kiro / app agreement | consent grant |
| `done` | authorized SPA | poll can succeed |

4. Commit findings as appendix in this doc or `docs/superpowers/specs/2026-07-23-kiro-aws-endpoint-map.md` (paths + shapes only — no secrets).
5. **Gate:** happy-path sequence replayable with `curl_cffi` (live smoke with one alias or fixture replay).

### Phase D1 — Impersonation

- `curl_cffi` `impersonate="chrome131"`.
- Proxy via `KIRO_PROXY`.
- If WAF blocks pure TLS → stop and escalate; **do not** silently reintroduce browser in v1.

### Phase D2 — OTP ownership

- **imap:** worker IMAP poll; defaults `from:signin.aws` + Builder ID verify subject (aligned with current Node imap-otp).
- **tempmail:** worker creates mailbox + polls OTP (Python EmailBox / grok worker pattern). Node does not create the mailbox mid-flight.
- This supersedes “Node tempmail service drives kiro browser” for pure-HTTP kiro. The tempmail dual-mode design’s Node wrapper remains relevant for any non-worker callers; pure-HTTP kiro uses the Python path.

## Error handling

| Condition | Worker | Node |
|-----------|--------|------|
| Missing email/password/device URL | `ok:false step=init` | Prefer throw before spawn |
| AWS domain ban (`ERR-837` etc.) | fail at `email_entry`/`name` with code | Message: use different alias; no same-alias retry |
| OTP timeout | `step=otp` | fail account |
| Wrong OTP / stuck verify | `step=otp_verify` | fail (no silent re-prompt v1) |
| Weak / rejected password | `step=password` | fail; may log policy text, never password value |
| Consent not granted | `device_confirm` / `consent` | fail; poll may pending until expiry |
| Worker crash / no result line | — | `ProviderError`, last step if known |
| Poll pending | — | retry until `expires_in` |
| Poll hard fail / expired | — | throw; possible orphan Builder ID (document) |
| Google / `@gmail.com` | not spawned | hard reject at `add()` |

**Retries (v1):** only OTP poll loop and 9router poll loop. Domain ban → next batch account, not same alias.

## Testing & rollout

### Unit (no live AWS)

- `worker-bridge.js`: env never contains `device_code` / `_clientSecret` / `codeVerifier`; `KIRO_DEVICE_URL` present; proxy + imap/tempmail modes.
- `index.js`: rejects google; imap requires imap config; tempmail path; poll/rename mocked (mirror grok-cli tests).
- Fake worker fixture (JSONL) for spawn happy/fail.

### Worker

- OTP extract tests for AWS Builder ID mail samples (subject/body), no network.
- Optional HTTP fixtures after discovery (nice-to-have, not a gate).

### Live smoke (manual)

1. venv + `curl_cffi`
2. One IMAP alias: full add → poll → connection named
3. One tempmail add
4. Confirm logs/dashboard never show secrets

### Rollout order

1. Discovery map committed.
2. Bridge + slim `index.js` + worker stub that fails `not-implemented` until map filled (optional intermediate).
3. Implement worker steps against map.
4. Remove Puppeteer email/google paths from kiro once live smoke green.
5. Runner/batch: google-targeted kiro accounts fail fast with explicit message.

### User migration

Pure-HTTP kiro is **email-only**. Existing Google automations need another path or an older browser-based revision until a separate design.

## Interaction with tempmail dual-mode spec

| Topic | Tempmail dual-mode (2026-07-23) | This design |
|-------|----------------------------------|-------------|
| Modes | imap \| tempmail for grok-cli + kiro | same modes for pure-HTTP kiro |
| kiro OTP host | Node package for browser kiro | **Python worker** for pure-HTTP kiro |
| grok-cli | Python EmailBox | unchanged |

When pure-HTTP kiro ships, update tempmail dual-mode docs to note kiro OTP moves into the worker (browser Node path removed).

## Implementation sketch (post-approval plan, not code)

1. Capture AWS endpoint map (D0).
2. Add `worker-bridge.js` + `worker/` skeleton + requirements.
3. Rewrite `index.js` to grok-cli lifecycle (no Puppeteer).
4. Implement `signup.py` steps per map.
5. Unit tests + live smoke.
6. Delete browser helpers usage from kiro; drop fingerprint requirement for pure-HTTP email.

## Open questions resolved in conversation

- **Scope:** Option A — email-only pure HTTP.
- **Architecture:** Approach 1 — Node + Python worker like grok-cli.
- **Google:** out of scope for v1.
- **Browser fallback:** no.

## Appendix A — Endpoint map

> Filled from Phase D0 capture (2026-07-24). 27 unique endpoint groups across 3 sub-flows:
> **Profile API** (`profile.aws.amazon.com`), **Platform Signin** (`us-east-1.signin.aws`),
> **Device Authorization** (`oidc.us-east-1.amazonaws.com` + `portal.sso` + `vs.aws.amazon.com`).
> Full captured bodies at [`2026-07-23-kiro-aws-endpoint-map.md`](./2026-07-23-kiro-aws-endpoint-map.md).

### Step ordering (approximate flow)

```
verification_uri_complete → portal.sso signin → email_entry → otp_wait (IMAP) → otp_verify + name + password → device_confirm → consent → token
```

### Bootstrap (step: bootstrap)

| Method | Host + path | Request keys | When |
|--------|-------------|--------------|------|
| `GET` | `view.awsapps.com` (redirect chain to `portal.sso.us-east-1.amazonaws.com/login`) | — | Start of flow |
| `GET` | `portal.sso.us-east-1.amazonaws.com/login` | — | SSO login page |
| `GET` | `portal.sso.us-east-1.amazonaws.com/token/whoAmI` | — | Token verification after sign-in |

### Profile API — workflow start (called after signin page load)

| Method | Host + path | Request keys | When |
|--------|-------------|--------------|------|
| `POST` | `profile.aws.amazon.com/api/start` | `workflowID`, `browserData` | Start Builder ID workflow |
| `POST` | `profile.aws.amazon.com/api/get-config` | — | Feature flags |
| `POST` | `profile.aws.amazon.com/api/get-app-context` | `workflowID` | App context |
| `POST` | `profile.aws.amazon.com/api/send-otp` | `workflowState`, `email`, `browserData` | Send 6-digit OTP to email |

### OTP verification + Name + Password (step: otp_verify / name / password)

These are submitted together in `POST /api/create-identity`:

| Method | Host + path | Request keys | When |
|--------|-------------|--------------|------|
| `POST` | `profile.aws.amazon.com/api/create-identity` | `workflowState`, `userData{email,fullName}`, `otpCode`, `browserData` | Submit OTP + name in one call |

### Platform Signin — execute steps

The `signup/api/execute` endpoint handles multi-step signup forms (locale pages, credential collection, etc.):

| Method | Host + path | Request keys | When |
|--------|-------------|--------------|------|
| `POST` | `us-east-1.signin.aws/platform/d-*/signup/api/execute` | `stepId`, `workflowStateHandle`, `inputs[]`, `visitorId`, `requestId` | Multi-step signup execution |
| `POST` | `us-east-1.signin.aws/platform/d-*/api/execute` | `stepId`, `workflowStateHandle`, `inputs[]`, `requestId` | General step execution |
| `POST` | `us-east-1.signin.aws/platform/user-event/send-event` | `inputs[]`, `requestId` | Page-load/user-event tracking |

### Device authorization (steps: device_confirm)

| Method | Host + path | Request keys | When |
|--------|-------------|--------------|------|
| `POST` | `oidc.us-east-1.amazonaws.com/device_authorization/accept_user_code` | `userCode`, `userSessionId` | User approves the device |
| `POST` | `oidc.us-east-1.amazonaws.com/device_authorization/associate_token` | `deviceContext`, `userSessionId` | Associate SSO token with device |

### Consent + Token exchange (step: consent)

| Method | Host + path | Request keys | When |
|--------|-------------|--------------|------|
| `POST` | `oidc.us-east-1.amazonaws.com/consent_details` | `deviceContextId`, `clientId`, `clientType`, `userSessionId` | Get Kiro consent screen details |
| `POST` | `portal.sso.us-east-1.amazonaws.com/auth/sso-token` | — | Exchange SSO for session token |
| `POST` | `vs.aws.amazon.com/token` | — | Final access-token exchange |

### Telemetry / noise (skip in worker)

| Method | Host + path | Notes |
|--------|-------------|-------|
| `POST` | `d2c.aws.amazon.com/csds/collector/v1/events/batch` | Usage metrics |
| `POST` | `us-east-1.prod.pl.panorama.console.api.aws/panoramaroute` | Panorama telemetry |
| `POST` | `us-east-1.signin.aws/metrics/fingerprint` | Browser fingerprint |
| `POST` | `log.sso-portal.us-east-1.amazonaws.com/log` | Client-side logging |
| `GET` | `us-east-1.signin.aws/assets/locales/en/*.json` | Locale bundles |
| `GET` | `profile.aws.amazon.com/dist/locales/*.json` | Locale bundles |
| `GET` | `us-east-1.signin.aws/platform/d-*/signup` | Signup page HTML |

## Appendix B — Security checklist

- [ ] `buildWorkerEnv` unit test asserts no `device_code` / `codeVerifier` / `_clientSecret`
- [ ] Logs use length-only for codes
- [ ] Dashboard `SECRET_RE` still covers kiro worker lines
- [ ] Poll secrets only in Node `_apiCall` body
