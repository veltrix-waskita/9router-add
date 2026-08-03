# Pateway-Farm Wiring — Design

**Date:** 2026-08-04
**Status:** Approved
**Branch:** feat/kiro-tes-device-coherence-and-grok-cli

## Goal

Wire the pateway.ai mass-registration farm (from `pateway-farm.zip`, already
deployed at `/home/elzanom/work/tools/pateway-farm/`) into the 9router-add
repo so it can be operated from the same entry points as other providers.

## Context

- `pateway-farm.zip` is a byte-identical snapshot of
  `/home/elzanom/work/tools/pateway-farm/` (verified via diff). That dir is
  the live, working copy — it has runtime state (`.state.json`: 1 failed
  attempt "ncaori aliyun fail"; `.config.json`: target=1), a `.venv`, and
  `__pycache__`.
- The farm is a **standalone Python farm based on cloakbrowser (browser)** —
  NOT a class-based `BaseProvider` pure-HTTP worker like kiro. It must stay
  standalone; no port to the provider-plugin pattern.
- The workbase is NOT a git repo (unlike siblings GAC, 9router-kiro, x-farm).
  Git-ifying it was **not selected** by the user.

## Scope (selected by user)

1. **Sync solver** — `captcha-solver/universal_solver.py` ← copy of
   `/home/elzanom/work/tools/pateway-farm/solver/universal_solver.py`
   (90KB, has aliyun raw mode + botguard/datadome — repo's 72KB version
   lacks aliyun, which pateway send-code needs). **User explicitly approved
   overwriting** the existing file (which carries uncommitted modifications
   incl. an unreviewed `/api-proxy` cambria.gg endpoint — those are NOT
   preserved; the farm version becomes baseline).
2. **Fix inject DB path** — `inject_9router.py` `resolve_db()` must also
   detect `/home/elzanom/.omni/db/data.sqlite` (the actual local 9router DB,
   per config.json `dbPath`). Its current candidates are missing it.
3. **Register pateway in runner.js** — add `PROVIDER_INFO.pateway`
   (batch farm launcher, not a BaseProvider port).

Out of scope: git-ify workbase, migrate farm to pure-HTTP, touch
`mail_tm.py` / `accounts.jsonl` / proxies.

## Design

### 1. Solver sync

- Copy farm solver → repo:
  `cp /home/elzanom/work/tools/pateway-farm/solver/universal_solver.py captcha-solver/universal_solver.py`
- Do NOT touch `captcha-solver/venv/`, `server.py`, `requirements.txt`,
  `solver.env*` (they stay as-is).
- Result: one solver at `:8877` serving kiro/grok + pateway with aliyun
  support.

### 2. inject_9router.py fix

- `resolve_db()` candidates get `/home/elzanom/.omni/db/data.sqlite` appended
  (before the fallback list) so injection works on this machine without
  `NINE_ROUTER_DB`.
- Schema verified compatible: `providerNodes` (`id,type,name,data,createdAt,updatedAt`)
  and `providerConnections` (`id,provider,authType,name,email,priority,isActive,data,createdAt,updatedAt`)
  match what `inject_9router.py` queries/inserts.
- `ensure_node`/`existing_keys`/`_insert_one` logic unchanged.

### 3. runner.js entry

- `PROVIDER_INFO.pateway = {
    label: "Pateway (AI farm)",
    methods: ["farm"],
    needsBrowser: true,
    batch: true,
    launch: { dir: "/home/elzanom/work/tools/pateway-farm", script: "pateway_farm.py" }
  }`
- `checkWorker`/preflight: verify the farm dir exists + venv present; warn
  clearly if solver `:8877` isn't up (curl `/health`).
- Runner delegates the actual farm run (spawns `pateway_farm.py` with
  args/config from the farm's own `.config.json`/`.state.json`) — it does
  NOT implement the farm logic.
- The user-selected label "Daftarkan pateway di runner.js" is satisfied by
  this delegating entry — NOT by a full BaseProvider port (Pendekatan A).

## Error Handling

- `inject_9router.py`: DB missing → resolve_db returns first candidate (as
  today); clear error surfaces via existing `{"errors":1,...}` shape.
- Farm failure (e.g. aliyun fail like `.state.json`) → runner reports the
  farm's status line; runner itself must not crash.
- Solver down → runner preflight prints "start solver first" and exits
  cleanly.

## Testing

- `node --check runner.js`
- `node runner.js pateway --help` (dry-run, no farm spawn)
- `python3 -m py_compile inject_9router.py`
- Manual inject dry-run against a temp DB to verify node/connection schema
- `curl http://127.0.0.1:8877/health` (if solver started)

## Notes / Risks

- `captcha-solver/universal_solver.py` is one of the "DO NOT TOUCH" files
  from prior sessions — user explicitly approved the overwrite for this
  sync.
- No new secrets introduced; no proxy/OTP/password logging changes.
- Farm remains browser-based (cloakbrowser); kiro's "no browser
  reintroduction" rule applies to kiro only, not to this standalone farm.
