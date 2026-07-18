# 9router-add — Modular Provider Account Automation

## Project Overview

Modular automation system for adding accounts to providers (VPN, proxy, etc.) integrated with 9router. Supports dual modes:
- **Local**: same machine as 9router, uses CLI token + direct SQLite
- **Remote**: VPS-based, uses dashboard password → session cookie + HTTPS API

## Architecture

**Class-based Provider Plugin pattern.** Each provider is a class extending `BaseProvider` with lifecycle hooks. Providers are auto-discovered from `src/providers/`.

### Key Design Decisions
- **Node.js 18+** with CommonJS (`require`/`module.exports`)
- **Puppeteer-extra** + stealth plugin for browser automation
- **SQLite** (`sqlite3` package) for local DB access
- **No TypeScript** — JSDoc for type hints
- Each provider is a self-contained folder under `src/providers/`
- Cross-cutting services (IMAP, proxy, fingerprint, quota) are standalone modules in `src/services/`

### Directory Structure
```
src/
├── core/          # Shared infrastructure (config, auth, HTTP, DB, CLI)
├── base/          # BaseProvider class + custom errors
├── services/      # Reusable services (imap-otp, proxy, fingerprint, quota, cloudflare-routing)
├── providers/     # Auto-discovered provider plugins
│   ├── antigravity/
│   └── kiro/
└── index.js       # Entry point
```

## Provider Interface

Every provider must export a class that extends `BaseProvider`:

```js
class MyProvider extends BaseProvider {
  static get providerName() { return 'my-provider' }

  // Required: execute the account creation flow
  async add(credentials, options) {}

  // Optional: inspect an existing connection
  async inspect(id) {}

  // Optional: delete a connection
  async delete(id) {}

  // Optional: lifecycle hooks
  async beforeAdd(credentials, options) {}
  async afterAdd(result) {}
  async onError(err, context) {}
}
```

## Reference Projects

- `/home/elzanom/work/tools/9router-agy/` — Antigravity provider (Google OAuth authorize/exchange flow)
- `/home/elzanom/work/tools/9router-kiro/` — Kiro provider (device code + poll + IMAP OTP flow)

## Config Priority

CLI flags → env vars → config.json → defaults

## Security

- Never send dashboard password over HTTP to non-localhost (remote mode requires HTTPS)
- `~/.9router/machine-id` + `cli-secret` for local auth
- SHA256 hash of `machineId + "9r-cli-auth" + cliSecret` for CLI token