# 9router-add

Modular automation system for adding accounts to providers integrated with 9router.

---

## 5W+1H

### What — Apa ini?
Sebuah sistem otomasi modular yang mendaftarkan akun ke berbagai provider AI/cloud
secara **full HTTP (tanpa browser)** dan menghubungkannya ke **9router** (gateway AI
yang menyediakan API key terpusat). Setiap provider adalah plugin Python worker yang
dijalankan dari Node.js orchestrator.

### Why — Kenapa?
- **Membuat banyak akun secara otomatis** (mass registration) untuk provider AI seperti
  Kiro (AWS Builder ID), Grok (xAI), dan Qoder — tanpa interaksi manual.
- **Konsisten & murah**: flow pure-HTTP (curl_cffi, TLS impersonation) menghindari
  dependency browser; lebih cepat, lebih hemat resource, bisa dijalankan headless/batch.
- **Terintegrasi 9router**: hasil akun + API key langsung siap pakai di ekosistem
  9router.

### Who — Untuk siapa?
- Operator/pengembang yang mengelola **banyak akun provider AI** untuk digunakan
  via 9router gateway.
- Tim yang butuh **akun massal dengan API key** (PAT/token) untuk aplikasi AI mereka.

### When — Kapan dipakai?
- Ketika perlu membuat **akun baru** (satu atau batch) pada provider yang didukung.
- Ketika akun existing perlu **di-inspect** atau **dihapus**.
- Saat provider memblokir browser automation → solusi pure-HTTP ini jalan.

### Where — Di mana?
- **Lokal**: mesin yang sama dengan 9router (CLI token + SQLite langsung).
- **Remote**: VPS (dashboard password → session cookie → HTTPS API).
- Provider worker: Python venv per provider (`src/providers/<name>/worker/`).
- Captcha solver lokal: `127.0.0.1:8877`.

### How — Bagaimana cara kerja?
1. **Node orchestrates, Python works**: provider class (Node) spawns Python worker
   (curl_cffi, Chrome 131 TLS impersonation) sebagai subprocess; output JSON-lines
   (`{"event":"step"}` / `{"kind":"result"}`) diparse oleh Node.
2. **No browser**: kiro/grok/qoder = full HTTP. CAPTCHA (Turnstile untuk grok, Aliyun
   untuk qoder) diselesaikan oleh solver lokal :8877.
3. **Dual email source**: `tempmail` (disposable inbox) atau `imap` (Gmail plus-alias
   / minom.my.id catch-all).
4. **Hasil**: `generated-accounts-<provider>-*.json` (private, gitignored) + (opsional)
   inject ke 9router.

---

## Providers

| Provider | Method | Flow | Email source |
|---|---|---|---|
| **antigravity** | Google OAuth | browser-based (legacy) | Google account |
| **kiro** (Kiro AI / AWS Builder ID) | email | pure-HTTP — signup OTP → password → login OTP → consent | tempmail (ncaori) / imap |
| **grok-cli** (xAI / Grok) | email | pure-HTTP — OTP → turnstile (:8877) → create user → device consent | tempmail / imap |
| **qoder** (Qoder AI) | email | pure-HTTP — register → aliyun captcha (:8877) → OTP → PAT | tempmail / imap |

Semua email provider support dual email source:
- `emailSource=tempmail` — disposable inbox (tanpa IMAP config)
- `emailSource=imap` — Gmail (plus-alias) atau minom.my.id catch-all via IMAP

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
2. Copy `config.example.json` ke `config.json` dan edit
   - `imap` block untuk imap emailSource (Gmail creds)
   - `providers.<name>.aliasDomain` untuk auto-credentials (mis. `minom.my.id`)
   - qoder: `providers.qoder` opsional (`aliasDomain`, `pollTimeout`)
3. Provider workers butuh Python venv (auto-detected; error akan kasih command-nya)
4. `node . add antigravity --email=... --password=...`

## Captcha Solver (:8877)

Solver lokal di `127.0.0.1:8877` menangani Turnstile (grok-cli) dan Aliyun slide
CAPTCHA (qoder). Start saat dibutuhkan:

```bash
cd captcha-solver && venv/bin/python3 universal_solver.py
```

- Turnstile — grok-cli (accounts.x.ai)
- Aliyun — qoder (verificationCodes `X-Captcha-Verify-Param` header;
  scene `1r7eif79x`, prefix `13lbkb5`, region `sgp`)

## Security

- Password/PAT/OTP **tidak pernah di-log** (worker redacts; provider scrubs console).
- `qoder.json` (HAR capture) berisi live credentials — **jangan commit; rotate**.
- `generated-accounts-*.json` (PAT asli) — gitignored, jangan commit.
