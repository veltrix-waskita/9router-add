# 9router-add

Modular automation system for adding accounts to providers integrated with 9router.

## Providers

| Provider | Method | Flow | Email source |
|---|---|---|---|
| **antigravity** | Google OAuth | browser-based (legacy) | Google account |
| **kiro** (Kiro AI / AWS Builder ID) | email | pure-HTTP worker (curl_cffi, chrome131) — signup OTP → password → login OTP → consent | tempmail (ncaori) / imap (Gmail plus-alias or minom.my.id catch-all) |
| **grok-cli** (xAI / Grok) | email | pure-HTTP worker — OTP → turnstile (local solver :8877) → create user → device consent | tempmail / imap |
| **qoder** (Qoder AI) | email | pure-HTTP worker — register → aliyun captcha (local solver) → OTP → PAT | tempmail (ncaori) / imap |

All email providers support dual email sources:
- `emailSource=tempmail` — disposable inbox (no IMAP config needed)
- `emailSource=imap` — Gmail (plus-alias) or minom.my.id catch-all via IMAP

## Usage

```bash
node . add <provider> --email=x@y.com --password=xxx
node . list
node . inspect <provider> <id>
node . delete <provider> <id>
node . batch <batch-file.json>
node runner.js        # interactive TUI (mode → provider → single/batch/auto)
```

## Setup

1. `npm install`
2. Copy `config.example.json` to `config.json` and edit
   - `imap` block for imap emailSource (Gmail creds)
   - `providers.<name>.aliasDomain` for auto-credentials (e.g. `minom.my.id`)
   - qoder: `providers.qoder` optional (`aliasDomain`, `pollTimeout`)
3. Provider workers need their Python venv (auto-detected; missing venv errors tell you the command)
4. `node . add antigravity --email=... --password=...`

## Captcha Solver (:8877)

The local solver at `127.0.0.1:8877` handles Turnstile (grok-cli) and Aliyun
slide CAPTCHA (qoder). Start it when needed:

```bash
cd captcha-solver && venv/bin/python3 universal_solver.py
```

- Turnstile — used by grok-cli (accounts.x.ai)
- Aliyun — used by qoder (verificationCodes `X-Captcha-Verify-Param` header;
  scene `1r7eif79x`, prefix `13lbkb5`, region `sgp`)

## Architecture

- **Node orchestrates, Python works**: each pure-HTTP provider spawns a Python
  worker (curl_cffi, Chrome 131 TLS impersonation) as a subprocess; the Node
  provider class parses JSON-lines output (`{event:step}` / `{kind:result}`).
- **No browser** for kiro/grok/qoder — full HTTP flows (except the Aliyun/Turnstile
  captcha solve which is delegated to the local solver).
- Results: `generated-accounts-<provider>-*.json` (private, gitignored).

## Security

- Passwords/PATs/OTPs are never logged (worker redacts; provider scrubs console).
- `qoder.json` (HAR capture) contains live credentials — do not commit; rotate.
