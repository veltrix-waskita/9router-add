#!/usr/bin/env python3
"""E2E smoke test: kiro pure-HTTP via 9router device code + tempmail."""
import hashlib, json, os, sys, subprocess, time, urllib.request, urllib.error

WORKER_DIR = "/home/elzanom/WORKER/9router-add/src/providers/kiro/worker"
VENV_PYTHON = os.path.join(WORKER_DIR, ".venv", "bin", "python3")

# 1. Compute CLI auth token for 9router
machine_id = open(os.path.expanduser("~/.9router/machine-id")).read().strip()
cli_secret = "test-cli-secret"  # from config.json
token = hashlib.sha256(f"{machine_id}9r-cli-auth{cli_secret}".encode()).hexdigest()[:16]

# 2. Get real device code from 9router
print("[smoke] Getting device code from 9router...")
try:
    req = urllib.request.Request("http://localhost:20128/api/oauth/kiro/device-code")
    req.add_header("x-9r-cli-token", token)
    resp = urllib.request.urlopen(req, timeout=10)
    dc = json.loads(resp.read())
    device_url = dc.get("verification_uri_complete", "")
    print(f"[smoke] device_url: {device_url[:80]}...")
except Exception as e:
    print(f"[smoke] FAILED to get device code: {e}")
    sys.exit(1)

# 2. Launch worker
env = {
    **os.environ,
    "KIRO_EMAIL": "",
    "KIRO_PASSWORD": "TestPass123!A1",
    "KIRO_NAME": "Alex Rivera",
    "KIRO_DEVICE_URL": device_url,
    "KIRO_EMAIL_SOURCE": "tempmail",
    "KIRO_TEMPMAIL_PROVIDERS": "ncaori",
    "PURE_HTTP": "1",
    "TEMPMAIL_API_URL": "http://localhost:8877",
}

print(f"[smoke] Starting signup.py...")
proc = subprocess.Popen(
    [VENV_PYTHON, "-u", os.path.join(WORKER_DIR, "signup.py")],
    env=env,
    cwd=WORKER_DIR,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    bufsize=1,
)

start = time.time()
timeout = 300
result_event = None
for line in proc.stdout:
    elapsed = time.time() - start
    sys.stdout.write(f"[{elapsed:6.1f}s] {line}")
    sys.stdout.flush()
    if elapsed > timeout:
        proc.kill()
        print("[smoke] TIMEOUT")
        break
    try:
        obj = json.loads(line)
        if isinstance(obj, dict) and obj.get("event") in ("result", "error"):
            result_event = obj
            break
    except (json.JSONDecodeError, ValueError):
        pass

proc.wait(timeout=10)
stderr_text = proc.stderr.read()
if stderr_text.strip():
    # Only show stderr if non-empty and result wasn't clean success
    if not (result_event and result_event.get("data", {}).get("success")):
        sys.stderr.write(f"[smoke] STDERR ({len(stderr_text)} bytes):\n{stderr_text[:3000]}\n")
    else:
        sys.stderr.write(f"[smoke] STDERR ({len(stderr_text)} bytes — suppressed on success)\n")

print(f"[smoke] Exit: {proc.returncode}")
if result_event:
    print(f"[smoke] Result event: {json.dumps(result_event, indent=2)[:500]}")
