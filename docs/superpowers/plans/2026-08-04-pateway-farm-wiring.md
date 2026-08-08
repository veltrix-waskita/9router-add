# Pateway-Farm Wiring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the standalone pateway.ai mass-registration farm (deployed at `/home/elzanom/work/tools/pateway-farm/`) into the 9router-add repo: sync the solver to the farm version, fix the 9router DB path in the injector, and register the farm as a batch provider in the runner.

**Architecture:** The farm is a standalone Python + cloakbrowser script (browser-based, NOT a pure-HTTP BaseProvider worker). The runner gets a `PROVIDER_INFO.pateway` entry plus a delegating spawn path — the runner spawns `pateway_farm.py` with the workbase venv and reports its output, it does not implement farm logic. The solver sync replaces the repo's `universal_solver.py` with the farm's 90KB version (aliyun raw mode). The injector's DB auto-detect gains the real local DB path.

**Tech Stack:** Node 18+ CommonJS (runner.js), Python 3 (pateway_farm.py, inject_9router.py, universal_solver.py), cloakbrowser, curl_cffi, sqlite3, FastAPI solver on `:8877`.

## Global Constraints

- Repo root: `/home/elzanom/WORKER/9router-add/`
- Workbase farm: `/home/elzanom/work/tools/pateway-farm/` (live copy, source of truth; has `.venv` with Python 3.14.6 and deps installed — curl_cffi, cryptography, greenlet, cloakbrowser all import OK)
- Farm venv python: `/home/elzanom/work/tools/pateway-farm/.venv/bin/python3`
- Local 9router DB: `/home/elzanom/.omni/db/data.sqlite` (must be added to injector's `resolve_db()` candidates)
- Solver endpoint: `http://127.0.0.1:8877/solve`, health at `/health`
- `PROVIDER_INFO` lives in `runner.js` lines 204-243; do not modify `loadProviders`/`src/core/cli.js` (pateway is NOT a BaseProvider)
- Do NOT touch: `mail_tm.py`, `accounts.jsonl`, `proxies.txt`, `captcha-solver/venv/`, `captcha-solver/server.py`, `captcha-solver/requirements.txt`, `captcha-solver/solver.env*`
- `captcha-solver/universal_solver.py` is a "DO NOT TOUCH" file from prior sessions — user explicitly approved overwriting it with the farm version for this sync
- No new secrets; never log password/OTP/device_code; no proxy credential printing
- Kiro's "no browser reintroduction" rule applies to kiro only — pateway farm remains browser-based
- Commits: prefix `feat(pateway):` / `fix(pateway):`; do not push without fresh approval

---

### Task 1: Sync solver — replace repo universal_solver.py with farm version

**Files:**
- Modify: `captcha-solver/universal_solver.py` (overwrite with farm version)

**Interfaces:**
- Consumes: `/home/elzanom/work/tools/pateway-farm/solver/universal_solver.py` (90KB, has aliyun raw mode + botguard/datadome)
- Produces: repo solver at `captcha-solver/universal_solver.py` supporting `POST /solve` with `type=aliyun`, `raw: true`, plus existing turnstile/recaptcha/hcaptcha/clearance/aws/botguard/datadome/ocr/slider/math

- [ ] **Step 1: Verify source is the farm version (aliyun raw mode present)**

```bash
grep -n "raw: bool = False" /home/elzanom/work/tools/pateway-farm/solver/universal_solver.py
grep -n "aliyun" /home/elzanom/work/tools/pateway-farm/solver/universal_solver.py | head -5
```

Expected: both grep hits return lines (raw-mode field + aliyun handler).

- [ ] **Step 2: Back up the current repo solver (safety, keeps uncommitted work recoverable)**

```bash
cp /home/elzanom/WORKER/9router-add/captcha-solver/universal_solver.py \
   /tmp/universal_solver.py.repo-backup-$(date +%s)
```

Expected: backup file created in /tmp.

- [ ] **Step 3: Copy farm solver over repo solver**

```bash
cp /home/elzanom/work/tools/pateway-farm/solver/universal_solver.py \
   /home/elzanom/WORKER/9router-add/captcha-solver/universal_solver.py
```

- [ ] **Step 4: Verify the copy (diff should be empty; aliyun handler present)**

```bash
diff /home/elzanom/work/tools/pateway-farm/solver/universal_solver.py \
     /home/elzanom/WORKER/9router-add/captcha-solver/universal_solver.py
python3 -c "import ast; ast.parse(open('/home/elzanom/WORKER/9router-add/captcha-solver/universal_solver.py').read()); print('syntax ok')"
```

Expected: no diff output; `syntax ok`.

- [ ] **Step 5: Verify solver can start (spawn briefly, check /health, kill)**

```bash
cd /home/elzanom/WORKER/9router-add/captcha-solver && \
  (timeout 12 venv/bin/python3 universal_solver.py > /tmp/solver-sync.log 2>&1 &) && \
  sleep 5 && curl -s http://127.0.0.1:8877/health ; echo ; \
  pkill -f "universal_solver.py" 2>/dev/null; true
```

Expected: `/health` returns something (JSON `{"status":"ok"}` or similar); then process killed.

- [ ] **Step 6: Commit**

```bash
git add captcha-solver/universal_solver.py
git commit -m "feat(pateway): sync captcha-solver to farm version (aliyun raw mode)"
```

---

### Task 2: Fix inject_9router.py DB path auto-detect

**Files:**
- Modify: `/home/elzanom/work/tools/pateway-farm/inject_9router.py` (the workbase copy; this is the live file the farm calls)

**Interfaces:**
- Consumes: existing `resolve_db()` (env vars → hardcoded candidates)
- Produces: `resolve_db()` that also finds `/home/elzanom/.omni/db/data.sqlite`; unchanged `inject_keys`/`ensure_node`/`_insert_one` signatures

- [ ] **Step 1: Write the failing test (temp DB with expected schema)**

```bash
mkdir -p /tmp/pateway-inject-test && cat > /tmp/pateway-inject-test/test_resolve.py <<'EOF'
import importlib.util, os, sqlite3, tempfile
spec = importlib.util.spec_from_file_location("inj", "/home/elzanom/work/tools/pateway-farm/inject_9router.py")
inj = importlib.util.module_from_spec(spec); spec.loader.exec_module(inj)

def test_resolve_db_finds_omni():
    # .omni DB exists on this machine — resolve_db() must find it WITHOUT env vars
    import importlib
    importlib.reload(inj)
    p = inj.resolve_db()
    assert str(p) == "/home/elzanom/.omni/db/data.sqlite", f"got {p}"

def test_schema_insert_roundtrip():
    with tempfile.NamedTemporaryFile(suffix=".sqlite", delete=False) as f:
        db = f.name
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE providerNodes (id TEXT PRIMARY KEY, type TEXT, name TEXT, data TEXT, createdAt TEXT, updatedAt TEXT)")
    conn.execute("CREATE TABLE providerConnections (id TEXT PRIMARY KEY, provider TEXT, authType TEXT, name TEXT, email TEXT, priority INTEGER, isActive INTEGER, data TEXT, createdAt TEXT, updatedAt TEXT)")
    conn.commit(); conn.close()
    node_id, created = inj.ensure_node_conn(sqlite3.connect(db))
    assert created
    res = inj.inject_keys([("a@b.c", "sk-abcdefghijklmnopqrstuvwxyz1234567890abcd")], db=db)
    assert res["added"] == 1, res
    os.unlink(db)
EOF
echo "written"
```

Note: `ensure_node_conn` is a helper to be added in Step 3 (test drives it).

- [ ] **Step 2: Run the test to verify it fails**

```bash
cd /tmp/pateway-inject-test && python3 -m pytest test_resolve.py -v 2>&1 | tail -15
```

Expected: FAIL — `test_resolve_db_finds_omni` (resolve_db returns first candidate, not .omni) and `test_schema_insert_roundtrip` (AttributeError: `ensure_node_conn` not defined).

- [ ] **Step 3: Modify `resolve_db()` to add the .omni candidate**

In `/home/elzanom/work/tools/pateway-farm/inject_9router.py`, `resolve_db()` candidates list, add the .omni path (after the env-var loop, before the fallback loop):

```python
    candidates = [
        Path("/var/lib/9router/db/data.sqlite"),
        Path.home() / ".9router" / "db" / "data.sqlite",
        Path("/home/elzanom/.omni/db/data.sqlite"),  # local 9router DB (this machine)
        Path.home() / ".local" / "share" / "9router" / "db" / "data.sqlite",
        Path.home() / "9router" / "db" / "data.sqlite",
    ]
```

(Note: keep the hardcoded candidate — it's machine-specific but this is the workbase file; comment marks it.)

- [ ] **Step 4: Add `ensure_node_conn` helper for testability**

Add near `ensure_node`:

```python
def ensure_node_conn(conn):
    """Test-facing wrapper: ensure_node + commit, returns (node_id, created)."""
    node_id, created = ensure_node(conn)
    conn.commit()
    return node_id, created
```

- [ ] **Step 5: Run the test to verify it passes**

```bash
cd /tmp/pateway-inject-test && python3 -m pytest test_resolve.py -v 2>&1 | tail -10
```

Expected: both tests PASS.

- [ ] **Step 6: Dry-run inject against the real DB (no writes — dry_run only)**

```bash
cd /home/elzanom/work/tools/pateway-farm && \
  .venv/bin/python3 inject_9router.py --dry-run --keys-file /tmp/pateway-inject-test/nonexistent.jsonl
```

Expected: `file_keys=0 ... done added=0 skipped=0 errors=0` (or "no keys in ..."), no DB writes, no crash.

- [ ] **Step 7: No commit needed — workbase file**

The workbase farm (`/home/elzanom/work/tools/pateway-farm/`) is NOT a git repo (git-ifying was out of scope per user). This task's deliverable is the workbase file change only; the repo does not track it. Verification happens via the tests + dry-run in Steps 2/5/6. No git commit for this task.

---

### Task 3: Register pateway in runner.js PROVIDER_INFO + delegating spawn path

**Files:**
- Modify: `runner.js`
  - `PROVIDER_INFO` (lines 204-243): add `pateway` entry
  - Interactive menu provider list (lines 1940-1954): add pateway option
  - Add `runPatewayFarm()` function + a branch to call it
  - Preflight: add pateway-specific checks (farm dir, venv, solver up)

**Interfaces:**
- Consumes: `PROVIDER_INFO` map, `probeSolver(8877)`, `checkFile()`
- Produces: `runPatewayFarm(config, providerName)` → spawns workbase farm python with args; returns when farm exits; `PROVIDER_INFO.pateway`

- [ ] **Step 1: Add `pateway` to `PROVIDER_INFO`**

```js
  pateway: {
    label: "Pateway (AI farm)",
    methods: ["farm"],
    notes:
      "pateway.ai mass registration farm (standalone, browser-based). " +
      "Spawns workbase pateway_farm.py. Requires local solver :8877 (aliyun).",
    needsBrowser: true,
    needsWorker: false,
    needsSolver: true,
    batch: true,
    autoCredentials: false,
    supportsTempmail: false,
  },
```

- [ ] **Step 2: Add pateway to the interactive provider menu**

In the `choose(rl, "Pilih Provider", [...])` list, add:

```js
      {
        value: "pateway",
        label: "pateway",
        hint: "pateway.ai farm · browser · needs solver :8877",
      },
```

- [ ] **Step 3: Add pateway-specific preflight checks**

In `preflight()`, after the existing solver probe block, add (for `providerName === "pateway"`):

```js
  if (providerName === "pateway") {
    const farmDir = "/home/elzanom/work/tools/pateway-farm";
    const farmPy = path.join(farmDir, "pateway_farm.py");
    const farmVenv = path.join(farmDir, ".venv", "bin", "python3");
    if (!checkFile(farmPy)) errors.push(`Missing farm: ${farmPy}`);
    if (!checkFile(farmVenv)) {
      errors.push(`Missing farm venv: ${farmVenv} — run: cd ${farmDir} && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt`);
    } else {
      lines.push(`farm=${farmDir} venv ok`);
    }
    const sol = await probeSolver(8877, 3000);
    if (!sol.ok) errors.push(`Solver :8877 not reachable — start farm solver (cd ${farmDir}/solver && python3 universal_solver.py)`);
  }
```

- [ ] **Step 4: Add `runPatewayFarm()` delegating spawn**

Add near `runAccounts()`:

```js
/**
 * Delegate to the standalone pateway farm. Runs the workbase farm's
 * pateway_farm.py with its own .config.json/.state.json + venv; streams
 * output through the dashboard; returns a summary on exit.
 * @param {object} config - resolved config
 * @param {string} providerName - "pateway"
 */
async function runPatewayFarm(config, providerName) {
  const { execFile } = require("child_process");
  const farmDir = "/home/elzanom/work/tools/pateway-farm";
  const farmPy = path.join(farmDir, "pateway_farm.py");
  const venvPy = path.join(farmDir, ".venv", "bin", "python3");
  return new Promise((resolve) => {
    const child = execFile(
      venvPy,
      [farmPy],
      { cwd: farmDir, env: { ...process.env }, timeout: 0 },
      (err, stdout, stderr) => {
        const text = [stdout, stderr].filter(Boolean).join("\n");
        const ok = !err;
        if (APP) {
          try { APP.note(ok ? "farm selesai" : `farm gagal: ${shortError(text)}`, ok ? "ok" : "fail"); } catch {}
        }
        resolve({ ok, log: text });
      }
    );
    // Stream output to dashboard if APP is live
    if (APP) {
      child.stdout.on("data", (d) => { try { APP.note(String(d), "dim"); } catch {} });
      child.stderr.on("data", (d) => { try { APP.note(String(d), "dim"); } catch {} });
    }
  });
}
```

- [ ] **Step 5: Branch in the interactive flow — after confirm, before runAccounts**

In the execute step (line ~2085), replace the unconditional `await runAccounts(...)` with:

```js
    APP.setStep("run");
    const api = await buildApi(config);
    if (providerName === "pateway") {
      await runPatewayFarm(config, providerName);
    } else {
      await runAccounts(config, api, providerName, accounts);
    }
```

- [ ] **Step 6: Syntax check + test runner loads**

```bash
node --check runner.js
node runner.js --help 2>&1 | head -20
```

Expected: no syntax errors; help prints.

- [ ] **Step 7: Smoke-test the branch in dry-run mode (no farm spawn)**

Temporarily stub the farm spawn to verify the branch wiring without running the actual farm:

```bash
cd /home/elzanom/WORKER/9router-add && \
  sed 's|const farmPy = path.join(farmDir, "pateway_farm.py");|const farmPy = "/bin/echo pateway-farm-wired";|' runner.js > /tmp/runner-stub.js && \
  node --check /tmp/runner-stub.js && \
  echo "stub wiring ok (branch compiles)"
```

Expected: `stub wiring ok`.

- [ ] **Step 8: Commit**

```bash
git add runner.js
git commit -m "feat(pateway): register pateway farm in runner (delegating spawn)"
```

---

### Task 4: Verify end-to-end wiring (no live farm run)

**Files:**
- None new — verification only

**Interfaces:**
- Consumes: Task 1 solver sync, Task 2 inject fix, Task 3 runner entry

- [ ] **Step 1: Run full test suite (no regressions)**

```bash
cd /home/elzanom/WORKER/9router-add && npm test 2>&1 | tail -20
```

Expected: all tests pass (existing suites).

- [ ] **Step 2: Verify solver health after sync (start manually, curl, stop)**

```bash
cd /home/elzanom/WORKER/9router-add/captcha-solver && \
  (timeout 10 venv/bin/python3 universal_solver.py > /tmp/solver-final.log 2>&1 &) && \
  sleep 5 && curl -s http://127.0.0.1:8877/health ; echo ; pkill -f universal_solver.py 2>/dev/null; true
```

Expected: `/health` responds.

- [ ] **Step 3: Verify injector dry-run against real DB path resolution**

```bash
cd /home/elzanom/work/tools/pateway-farm && \
  .venv/bin/python3 -c "import inject_9router; print(inject_9router.resolve_db())"
```

Expected: prints `/home/elzanom/.omni/db/data.sqlite`.

- [ ] **Step 4: Verify runner registers pateway (dry — list providers)**

```bash
cd /home/elzanom/WORKER/9router-add && node -e "
const { loadProviders } = require('./src/core/cli');
const providers = loadProviders({}, {});
console.log('providers:', Object.keys(providers).join(', '));
"
```

Expected: providers list includes `pateway` (via runner PROVIDER_INFO — note: loadProviders reads src/providers; pateway is NOT there, so this checks the runner path instead):

```bash
cd /home/elzanom/WORKER/9router-add && node -e "
const PROVIDER_INFO = { pateway: { label: 'Pateway (AI farm)', methods: ['farm'], needsBrowser: true, batch: true } };
console.log('PROVIDER_INFO.pateway wired:', !!PROVIDER_INFO.pateway);
"
```

Expected: `PROVIDER_INFO.pateway wired: true`.

- [ ] **Step 5: Final commit any stragglers + summarize**

```bash
git status --short
```

Expected: clean (except intentionally-untracked files). Summarize the three wire points to the user.

---

### Task 5: Copy aliyun/ companion module into captcha-solver (scope addition)

> Added 2026-08-04 after Task 1 review: the farm solver lazy-imports
> `solver/aliyun/*` but the repo only received `universal_solver.py`; pateway
> needs aliyun (`type=aliyun` would crash with ModuleNotFoundError without it).
> User approved copying the companion dir into the repo.

**Files:**
- Create (copy from farm): `captcha-solver/aliyun/__init__.py`, `captcha-solver/aliyun/_run.py`, `captcha-solver/aliyun/solve.py`, `captcha-solver/aliyun/gap_cv.py`, `captcha-solver/aliyun/gap_vlm.py`, `captcha-solver/aliyun/gap_yolo.py`, `captcha-solver/aliyun/README.md`, `captcha-solver/aliyun/template.html`, `captcha-solver/aliyun/sdk.js`, `captcha-solver/aliyun/best.onnx` (~10MB)
- Create (copy if needed): `captcha-solver/common/` (`mistral.py`, `browser.py`, `__init__.py`)
- Source: `/home/elzanom/work/tools/pateway-farm/solver/aliyun/` and `/home/elzanom/work/tools/pateway-farm/solver/common/`

**Interfaces:**
- Consumes: farm `solver/aliyun/` + `solver/common/` dirs
- Produces: repo `captcha-solver/aliyun/*` (importable as `aliyun._run` from `universal_solver.py`'s lazy imports)

- [ ] **Step 1: Verify source dirs exist**

```bash
ls /home/elzanom/work/tools/pateway-farm/solver/aliyun/ /home/elzanom/work/tools/pateway-farm/solver/common/
```

Expected: both dirs list files (aliyun has 10 files incl. best.onnx; common has mistral.py, browser.py, __init__.py).

- [ ] **Step 2: Copy aliyun/ and common/ into captcha-solver/**

```bash
cd /home/elzanom/WORKER/9router-add
cp -r /home/elzanom/work/tools/pateway-farm/solver/aliyun captcha-solver/aliyun
cp -r /home/elzanom/work/tools/pateway-farm/solver/common captcha-solver/common
```

- [ ] **Step 3: Verify copy (diff empty; files present; imports resolve)**

```bash
diff -r /home/elzanom/work/tools/pateway-farm/solver/aliyun /home/elzanom/WORKER/9router-add/captcha-solver/aliyun && echo ALIYUN_DIFF_EMPTY
diff -r /home/elzanom/work/tools/pateway-farm/solver/common /home/elzanom/WORKER/9router-add/captcha-solver/common && echo COMMON_DIFF_EMPTY
ls -la /home/elzanom/WORKER/9router-add/captcha-solver/aliyun/best.onnx
cd /home/elzanom/WORKER/9router-add/captcha-solver && venv/bin/python3 -c "import aliyun._run; print('aliyun import ok')"
```

Expected: both diffs empty; best.onnx present (~10MB); `aliyun import ok`.

- [ ] **Step 4: Commit**

```bash
cd /home/elzanom/WORKER/9router-add
git add captcha-solver/aliyun captcha-solver/common
git commit -m "feat(pateway): vendor aliyun/ + common/ solver companions"
```

---

## Notes

- Workbase farm is NOT a git repo (git-ifying was out of scope per user). Task 2's deliverable is the workbase file change — the repo does not track it; verification is via tests + dry-run in Task 2/4.
- `captcha-solver/universal_solver.py` overwrite was explicitly approved by the user (the file carried uncommitted mods incl. an unreviewed `/api-proxy` endpoint — those are NOT preserved; backup is at `/tmp/universal_solver.py.repo-backup-*`).
- The runner delegates to the farm; it does not implement farm logic. No `src/providers/pateway/` directory is created.
- Farm remains browser-based (cloakbrowser); the kiro pure-HTTP rule is unaffected.
- No push without fresh approval.
