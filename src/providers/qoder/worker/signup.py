import json, os, sys, base64

from curl_cffi import requests as creq

BASE = "https://qoder.com"
TMD_IN_URL = "_____tmd_____"
TYPES_REDUCED = set()  # reserved

def emit_step(step, status, **kv):
    print(json.dumps({"kind": "step", "step": step, "status": status, **kv}), flush=True)

def emit_result(ok, **kv):
    print(json.dumps({"kind": "result", "ok": bool(ok), **kv}), flush=True)

def encode_bx_ua():
    # non-empty random blob is enough to bypass TMD (verified live)
    return base64.b64encode(os.urandom(64)).decode()

def _session():
    return creq.Session(impersonate="chrome131")

def is_tmd_punish(body):
    if not isinstance(body, dict):
        return False
    return TMD_IN_URL in json.dumps(body) or "x5secdata" in json.dumps(body)

def signup_page(s):
    r = s.get(f"{BASE}/users/sign-up", timeout=30)
    return r.status_code < 400

def register(s, email, password, name, code="", proxy=None):
    payload = {"type": "email_pwd", "email": email, "password": password, "code": code,
               "name": name, "invitation_code": "", "bx-ua": encode_bx_ua()}
    h = {"Content-Type": "application/json", "Referer": f"{BASE}/users/sign-up",
         "Origin": BASE, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors"}
    r = s.post(f"{BASE}/api/v1/users", json=payload, headers=h, impersonate="chrome131", timeout=30)
    return r

if __name__ == "__main__":
    if "--self-test" in sys.argv:
        try:
            import curl_cffi  # noqa: F401
            assert len(encode_bx_ua()) > 10
            assert is_tmd_punish({"x5secdata": "xx"})
            assert not is_tmd_punish({"errorMessage": "Code required"})
            emit_result(True, step="self_test")
            sys.exit(0)
        except Exception as e:
            emit_result(False, error=str(e), step="self_test")
            sys.exit(1)

    # Task 3 fills real run
    emit_result(True, step="stub")
