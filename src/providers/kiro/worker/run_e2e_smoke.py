#!/usr/bin/env python3
"""E2E smoke test runner for kiro pure-HTTP signup.py"""
import os, subprocess, sys, time

os.chdir("/home/elzanom/WORKER/9router-add/src/providers/kiro/worker")
ts = str(int(time.time()))
email = f"smoke{ts}@ncaori.my.id"
os.environ.update({
    "KIRO_EMAIL": email,
    "KIRO_PASSWORD": "TestPass123!A1",
    "KIRO_NAME": "Smoke Test",
    "KIRO_DEVICE_URL": "https://view.awsapps.com/start/#/device?user_code=FXQL-DSDQ",
    "KIRO_EMAIL_SOURCE": "tempmail",
    "KIRO_TEMPMAIL_PROVIDERS": "ncaori",
    "PURE_HTTP": "1",
})
print(f"EMAIL={email}", flush=True)
p = subprocess.run(
    [".venv/bin/python3", "-u", "signup.py"],
    capture_output=False,
    timeout=240,
)
sys.exit(p.returncode)
