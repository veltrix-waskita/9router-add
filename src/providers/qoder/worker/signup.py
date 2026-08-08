#!/usr/bin/env python3
"""Qoder pure-HTTP account signup worker (register + OTP + PAT).

Task 3 — full flow. Spawned by src/providers/qoder/worker-bridge.js. Emits
JSON lines on stdout ({kind:"step"...}, and a final {kind:"result"...}).

Flow:
  signup_page -> register(code="") [OTP pending] -> poll_otp (tempmail via
  ncaori EmailBox, or IMAP via imap_otp.read_otp) -> register(code) step2 ->
  create_pat -> login_me -> emit_result.

Security:
  - NEVER log password, PAT, or OTP. 6-digit runs are masked in any emitted
    text (errors may echo the code). The success result carries the PAT as
    `pat` only so the Node provider can build the connection; index.js
    scrubs it (scrubForLog) before any console output.
  - Import must stay silent outside __main__ (the Node bridge imports nothing,
    but unit tests import signup without network / tempmail / imap deps).
"""
from __future__ import annotations

import base64
import json
import os
import re
import sys
import subprocess
import time
from typing import Any

from curl_cffi import requests as creq

BASE = "https://qoder.com"
CLAIM_API_BASE = os.getenv("QODER_CLAIM_API_BASE", "https://openapi.qoder.sh")
TMD_IN_URL = "_____tmd_____"
TYPES_REDUCED = set()  # reserved

_MASK6 = re.compile(r"\d{6}")


def _mask6(text: Any) -> str:
    """Mask 6-digit runs in arbitrary text (OTP hygiene for emitted strings)."""
    if text is None:
        return ""
    return _MASK6.sub("******", str(text))


def emit_step(step: str, status: str = "ok", **kv: Any) -> None:
    # {"event":"step"} matches the bridge parseWorkerLine convention (kiro
    # emits the same shape), so Node classifies step lines as events and can
    # capture fields like the tempmail_create address.
    print(json.dumps({"event": "step", "step": step, "status": status, **kv}), flush=True)


def emit_result(ok: bool, **kv: Any) -> None:
    # Success payload always carries PAT as `pat`. New fields (best-effort claims):
    #   trial: True if Pro Trial 300 credits claimed
    #   ultimate: True if Ultimate 200 free calls claimed
    #   qwen800 / qwen2000: Qwen3.8-Max claim status
    #   credits: sum(300,200,800,2000) of successful activities
    print(json.dumps({"kind": "result", "ok": bool(ok), **kv}), flush=True)


def encode_bx_ua() -> str:
    # non-empty random blob is enough to bypass TMD (verified live)
    return base64.b64encode(os.urandom(64)).decode()


def _session(proxy: str | None = None) -> Any:
    kw = {"impersonate": "chrome131"}
    if proxy:
        kw["proxy"] = proxy
    return creq.Session(**kw)


def _body_json(r: Any) -> Any:
    """Parse response JSON safely (curl_cffi 0.16 has no json_or_None)."""
    try:
        return r.json()
    except Exception:
        return None


SOLVER_URL = os.getenv("QODER_SOLVER_URL", "http://127.0.0.1:8877/solve")
QODER_ALIYUN_SCENE = "1r7eif79x"      # from HAR InitCaptchaV3
QODER_ALIYUN_PREFIX = "13lbkb5"       # from HTML AliyunCaptchaConfig


def solve_captcha(scene_id: str = QODER_ALIYUN_SCENE, prefix: str = QODER_ALIYUN_PREFIX) -> str | None:
    """Solve the Aliyun slider CAPTCHA via the local solver (:8877) and return
    the base64 X-Captcha-Verify-Param header value.

    Qoder's verificationCodes requires the captcha proof in the
    X-Captcha-Verify-Param HEADER (server 400s "with no captcha verify param"
    otherwise). The server expects base64 of:
      {"certifyId":..., "sceneId":..., "isSign":true, "securityToken":...}
    where certifyId + securityToken come from the aliyun VerifyCaptchaV3
    pipeline — so the solver MUST run with raw=false (verify in page), which
    returns verify_code T001 + security_token (128 chars). raw=true yields
    only deviceToken/data which the server rejects.
    """
    try:
        r = creq.post(
            SOLVER_URL,
            json={
                "type": "aliyun",
                "scene_id": scene_id,
                "prefix": prefix,
                "region": "sgp",
                "timeout_s": 100,
                "raw": False,  # verify in page → securityToken (raw=true gives none)
            },
            headers={"Content-Type": "application/json"},
            impersonate="chrome",
            timeout=115,
        )
        d = r.json()
        if not d.get("solved") or d.get("verify_code") != "T001":
            emit_step("captcha_solve_fail", "warn", error=str(d.get("error", ""))[:80])
            return None
        tok = d["token"]
        st = d.get("security_token") or ""
        if not st:
            emit_step("captcha_no_security_token", "warn")
            return None
        payload = {
            "certifyId": tok.get("certifyId", ""),
            "sceneId": tok.get("sceneId", scene_id),
            "isSign": True,
            "securityToken": st,
        }
        return base64.b64encode(json.dumps(payload).encode()).decode()
    except Exception as e:
        emit_step("captcha_solve_error", "warn", error=str(e)[:80])
        return None


def is_tmd_punish(body: Any) -> bool:
    """True when the response is a TMD jail / punish page instead of the clean
    400 "Code required" OTP handshake.

    The live punish response is an HTTP 200 HTML page carrying ``x5secdata``
    (and/or ``_____tmd_____``); the JSON variant serializes a dict exposing the
    same marker. Accept both a parsed dict (via _body_json) and raw str text
    (via r.text) so detection also fires for the HTML punish that _body_json
    cannot parse.
    """
    if isinstance(body, dict):
        dumped = json.dumps(body)
        return TMD_IN_URL in dumped or "x5secdata" in dumped
    if isinstance(body, str):
        return TMD_IN_URL in body or "x5secdata" in body
    return False


def signup_page(s: Any) -> bool:
    r = s.get(f"{BASE}/users/sign-up", timeout=30)
    return r.status_code < 400


def register(
    s: Any,
    email: str,
    password: str,
    name: str,
    code: str = "",
    proxy: str | None = None,
) -> Any:
    """POST /api/v1/users — completes registration with the OTP `code`.

    Flow per HAR: the OTP is delivered by POST /api/v1/verificationCodes
    (see send_verification_code), then this endpoint is called WITH the code
    (200, empty body, session cookie set). A code-less call returns
    400 "Code required" — it does NOT trigger OTP delivery.

    A fresh random bx-ua is generated on every call (TMD bypass).
    """
    payload = {
        "type": "email_pwd",
        "email": email,
        "password": password,
        "code": code,
        "name": name,
        "invitation_code": "",
        "bx-ua": encode_bx_ua(),
    }
    h = {
        "Content-Type": "application/json",
        "Referer": f"{BASE}/users/sign-up",
        "Origin": BASE,
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
    }
    kw: dict[str, Any] = {"json": payload, "headers": h, "impersonate": "chrome131", "timeout": 30}
    if proxy:
        kw["proxy"] = proxy
    return s.post(f"{BASE}/api/v1/users", **kw)


def send_verification_code(
    s: Any,
    email: str,
    proxy: str | None = None,
) -> Any:
    """POST /api/v1/verificationCodes — THE endpoint that delivers the OTP.

    HAR capture (2026-08-07): {channel:"email", scene:"register", email, bx-ua}
    → 200. Called BEFORE /api/v1/users; the register call then carries the
    received code. Server now REQUIRES a captchaVerifyParam (400 "with no
    captcha verify param" otherwise) — solved via the local aliyun solver.
    """
    captcha_param = solve_captcha()
    payload = {
        "channel": "email",
        "scene": "register",
        "email": email,
        "bx-ua": encode_bx_ua(),
    }
    h = {
        "Content-Type": "application/json",
        "Referer": f"{BASE}/users/sign-up",
        "Origin": BASE,
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "X-Csrf-Token": "_echo_csrf_using_sec_fetch_site_",
        "X-Requested-With": "XMLHttpRequest",
        "Bx-V": "2.5.35",
    }
    if captcha_param:
        # The captcha proof must be a HEADER (base64 JSON), not a body field —
        # qoder 400s "with no captcha verify param" when it's in the body.
        h["X-Captcha-Verify-Param"] = captcha_param
    kw: dict[str, Any] = {"json": payload, "headers": h, "impersonate": "chrome131", "timeout": 30}
    if proxy:
        kw["proxy"] = proxy
    return s.post(f"{BASE}/api/v1/verificationCodes", **kw)


def check_login_type(s: Any, email: str, proxy: str | None = None) -> Any:
    """POST /api/v1/auth/check-login-type — returns the login type for an email.

    HAR order: called before verificationCodes. Payload {email, bx-ua}.
    Optional pre-flight; a failure here is non-fatal (register still proceeds).
    """
    payload = {"email": email, "bx-ua": encode_bx_ua()}
    h = {
        "Content-Type": "application/json",
        "Referer": f"{BASE}/users/sign-up",
        "Origin": BASE,
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
    }
    kw: dict[str, Any] = {"json": payload, "headers": h, "impersonate": "chrome131", "timeout": 30}
    if proxy:
        kw["proxy"] = proxy
    return s.post(f"{BASE}/api/v1/auth/check-login-type", **kw)


# ---- OTP polling -----------------------------------------------------------


def poll_otp(
    email: str,
    source: str,
    proxy: str | None = None,
    box: Any = None,
    timeout: int = 180,
    interval: int = 5,
) -> str | None:
    """Wait for the qoder signup OTP.

    source == "tempmail": box must be a tempmail.EmailBox already tied to the
    registered address (created in run() so the OTP lands in the same
    mailbox). source == "imap": imap_otp.read_otp with QODER_IMAP_* cfg.
    Returns the 6-digit code or None. Never logs the code value.
    """
    emit_step("otp", "pending", source=source)
    if source == "tempmail":
        if box is None:
            raise RuntimeError("tempmail-box-missing")
        try:
            code = box.wait_code(timeout=timeout)
        except Exception:
            code = None
        if code and str(code).isdigit():
            emit_step("otp", "ok", source=source)
            return str(code)
        emit_step("otp", "failed", source=source)
        return None
    # imap (and default)
    from imap_otp import read_otp  # lazy (needs imaplib)

    cfg = imap_cfg_from_env()
    retries = max(1, timeout // max(1, interval)) if timeout else 40
    code = read_otp(email, cfg, retries=retries, delay=max(1.0, float(interval)))
    if code:
        emit_step("otp", "ok", source=source)
        return code
    emit_step("otp", "failed", source=source)
    return None


def imap_cfg_from_env() -> dict:
    """IMAP OTP polling config (QODER_* env, defaults = Gmail 993)."""
    return {
        "host": os.getenv("QODER_IMAP_HOST", "imap.gmail.com"),
        "port": os.getenv("QODER_IMAP_PORT", "993"),
        "user": os.getenv("QODER_IMAP_USER", ""),
        "password": os.getenv("QODER_IMAP_PASSWORD", ""),
        "tls": os.getenv("QODER_IMAP_TLS", "true"),
        "delete_after_read": os.getenv("QODER_IMAP_DELETE_AFTER_READ", "false"),
        "subject": os.getenv("QODER_OTP_SUBJECT", ""),
        "sender_domain": os.getenv(
            "QODER_OTP_SENDER_DOMAIN", "qoder.com,noreply.qoder.com"
        ),
    }


# ---- me + PAT --------------------------------------------------------------


def login_me(s: Any) -> Any:
    """GET /api/v1/me — returns the user payload dict on success, True as a
    weak fallback, None on any error."""
    try:
        r = s.get(f"{BASE}/api/v1/me", impersonate="chrome131", timeout=20)
        if r.status_code < 400:
            try:
                data = r.json()
                if isinstance(data, dict):
                    return data.get("data", data)
                return data or True
            except Exception:
                return True
    except Exception:
        pass
    return None


def create_pat(s: Any, name: str = "default") -> str | None:
    """POST /api/v1/me/personal-access-tokens.

    Payload {"name":..., "expires_at": 2534023007999} (year 9999). Returns
    the raw token text (field "token", e.g. "pt-...") or None. Never logged.
    """
    try:
        h = {
            "Content-Type": "application/json",
            "Referer": f"{BASE}/account/integrations",
            "Origin": BASE,
            "Sec-Fetch-Site": "same-origin",
        }
        r = s.post(
            f"{BASE}/api/v1/me/personal-access-tokens",
            json={"name": name, "expires_at": 2534023007999},
            headers=h,
            impersonate="chrome131",
            timeout=20,
        )
        if r.status_code < 400:
            data = _body_json(r)
            if isinstance(data, dict):
                tok = data.get("token") or data.get("raw_token") or data.get("pat")
                if tok:
                    return str(tok)
                return str(data.get("token_id") or "")
            if r.text:
                return str(r.text).strip()
    except Exception:
        pass
    return None


def get_status(auth_headers: dict[str, str], proxy: str | None = None) -> dict[str, Any]:
    """GET /api/v3/user/status — return plan/email/quota from user profile."""
    try:
        h = {**auth_headers, "Accept": "application/json"}
        kw: dict[str, Any] = {"headers": h, "impersonate": "chrome131", "timeout": 20}
        if proxy:
            kw["proxy"] = proxy
        r = creq.get(f"{CLAIM_API_BASE}/api/v3/user/status", **kw)
        if r.status_code < 400:
            data = r.json()
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def claim_activity_with_eligibility(
    auth_headers: dict[str, str], activity_id: str, proxy: str | None = None
) -> tuple[bool, dict[str, Any]]:
    """Claim single activity by first checking eligibility list, then attempt.

    Returns (claimed=True/False, response_dict). Follows dual_claim.py pattern:
      1. GET /api/v2/activity/claim/eligibility → list [{activityId, canClaim}]
      2. Try POST for matching ID where canClaim=True
      3. If no match but ID provided, try anyway (some accounts auto-grant)
    """
    result: dict[str, Any] = {"claimed": False, "error": None}
    try:
        elig_resp = creq.get(
            f"{CLAIM_API_BASE}/api/v2/activity/claim/eligibility",
            headers={**auth_headers, "Accept": "application/json"},
            impersonate="chrome131",
            timeout=20,
        )
        activities = []
        if elig_resp.status_code < 400:
            try:
                elig_data = elig_resp.json()
                if isinstance(elig_data, dict):
                    activities = elig_data.get("data", []) or []
            except Exception:
                pass

        # Try claiming via eligibility list first
        for act in activities:
            if act.get("activityId") == activity_id and act.get("canClaim"):
                claim_resp = creq.post(
                    f"{CLAIM_API_BASE}/api/v2/activity/claim?activityId={activity_id}",
                    headers={**auth_headers, "Accept": "application/json"},
                    impersonate="chrome131",
                    timeout=20,
                )
                if claim_resp.status_code < 400:
                    try:
                        claim_data = claim_resp.json()
                        if claim_data.get("code") == 0:
                            result["claimed"] = True
                            result["response"] = claim_data
                        else:
                            result["error"] = claim_data
                        return result["claimed"], result
                    except Exception:
                        pass

        # Fallback: try direct POST even if not in eligibility list
        claim_resp = creq.post(
            f"{CLAIM_API_BASE}/api/v2/activity/claim?activityId={activity_id}",
            headers={**auth_headers, "Accept": "application/json"},
            impersonate="chrome131",
            timeout=20,
        )
        if claim_resp.status_code < 400:
            try:
                claim_data = claim_resp.json()
                if claim_data.get("code") == 0:
                    result["claimed"] = True
                    result["response"] = claim_data
                else:
                    result["error"] = claim_data
            except Exception:
                pass
    except Exception as e:
        result["error"] = str(e)
    return result["claimed"], result


def check_pro_trial(auth_headers: dict[str, str], proxy: str | None = None) -> dict[str, Any]:
    """Check if Pro Trial is active by reading user status/plan.

    Returns: {'is_pro': bool, 'plan': str, 'email': str, 'quota': int}
    """
    status = get_status(auth_headers, proxy=proxy)
    if status:
        plan = status.get("plan", "")
        is_pro = "PRO_TRIAL" in plan.upper() or "PRO" in plan.upper()
        return {
            "is_pro": is_pro,
            "plan": plan,
            "email": status.get("email", ""),
            "quota": status.get("quota", 0),
        }
    return {"is_pro": False, "error": "Could not get status"}


def exchange_job_token(pat: str, proxy: str | None = None) -> str | None:
    """POST /api/v1/jobToken/exchange — exchange PAT for a short-lived job token."""
    try:
        h = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        kw: dict[str, Any] = {"json": {"personal_token": pat}, "headers": h, "impersonate": "chrome131", "timeout": 20}
        if proxy:
            kw["proxy"] = proxy
        r = creq.post(f"{CLAIM_API_BASE}/api/v1/jobToken/exchange", **kw)
        if r.status_code < 400:
            try:
                data = r.json()
                tok = data.get("token") or data.get("data", {}).get("token")
                if tok:
                    return str(tok)
            except Exception:
                pass
    except Exception:
        pass
    return None


def claim_post_pat(pat: str, proxy: str | None = None) -> dict:
    """Exchange PAT → job-token → check eligibility → claim activities.

    Mirrors dual_claim.py flow:
      1. Exchange PAT for job token
      2. Check Pro Trial via user status API (PLAN_TIER_PRO_TRIAL)
      3. Claim Ultimate 200 if eligible
      4. Claim Qwen3.8-Max 800/2000 if eligible
      5. Return summary (best-effort: failures don't block signup)

    Never logs the PAT or tokens.
    """
    result: dict[str, Any] = {"trial": False, "ultimate": False, "qwen800": False, "qwen2000": False, "credits": 0}

    emit_step("claim_post_pat", "pending")
    job_token = exchange_job_token(pat, proxy=proxy)
    if not job_token:
        emit_step("claim_post_pat", "skipped", reason="job-token-exchange-failed")
        return result

    auth_headers = {"Authorization": f"Bearer {job_token}"}

    # ===== STEP 1: Check Pro Trial via STATUS API (NOT hardcoded activity ID) =====
    # Dual claim.py pattern: read user plan first
    pro_result = check_pro_trial(auth_headers, proxy=proxy)
    is_trial_active = pro_result.get("is_pro", False)

    if is_trial_active:
        result["trial"] = True
        result["credits"] += 300
        emit_step("claim_pro_trial", "ok", credits=300, plan=pro_result.get("plan", ""))
    else:
        emit_step("claim_pro_trial", "skipped", reason=f"plan={pro_result.get('plan','?')}")

    # ===== STEP 2: Try Ultimate 200 claims (dynamic eligibility list) =====
    claimed_ult, ult_resp = claim_activity_with_eligibility(auth_headers, "ultimate_200_free_invoke", proxy=proxy)
    if claimed_ult:
        result["ultimate"] = True
        result["credits"] += 200
        emit_step("claim_ultimate", "ok", credits=200)
    else:
        emit_step("claim_ultimate", "skipped", error=ult_resp.get("error", "unknown"))

    # ===== STEP 3: Try Qwen3.8-Max 800 & 2000 =====
    claimed_800, qwen800_resp = claim_activity_with_eligibility(auth_headers, "qwen38_800_invoke", proxy=proxy)
    if claimed_800:
        result["qwen800"] = True
        result["credits"] += 800
        emit_step("claim_qwen800", "ok", credits=800)
    else:
        emit_step("claim_qwen800", "skipped", error=qwen800_resp.get("error", "unknown"))

    claimed_2000, qwen2000_resp = claim_activity_with_eligibility(auth_headers, "qwen38_2000_invoke", proxy=proxy)
    if claimed_2000:
        result["qwen2000"] = True
        result["credits"] += 2000
        emit_step("claim_qwen2000", "ok", credits=2000)
    else:
        emit_step("claim_qwen2000", "skipped", error=qwen2000_resp.get("error", "unknown"))

    emit_step("claim_post_pat", "ok", **result)
    return result



def run_background_claim(pat: str, proxy: str | None = None) -> tuple[bool, dict]:
    """Run dual_claim.py as subprocess to claim Pro Trial 300 credits.

    Best-effort background work — NEVER blocks signup. Returns (success, result_dict).
    
    Expects:
      - /home/elzanom/work/tools/qoker_trial/dual_claim.py exists
      - Python venv at src/providers/qoker/worker/.venv
    
    Output parsing looks for "Pro Trial:" + "ACTIVE" status.
    """
    import sys

    # Determine worker dir (where signup.py is located)
    worker_dir = os.path.dirname(os.path.abspath(__file__))
    # qoder-trial/ lives at repo root, 4 levels up from worker/signup.py
    # (worker → qoder → providers → src → repo_root)
    repo_root = os.path.abspath(os.path.join(worker_dir, "..", "..", "..", ".."))
    trial_dir = os.path.join(repo_root, "qoder-trial")

    dual_claim_py = os.path.join(trial_dir, "dual_claim.py")
    venv_python = os.path.join(worker_dir, ".venv", "bin", "python3")
    
    emit_step("background_claim", "starting")
    
    if not os.path.exists(dual_claim_py):
        emit_step("background_claim", "skipped", reason=f"dual_claim.py not found: {dual_claim_py}")
        return False, {"error": "dual_claim.py not found"}
    if not os.path.exists(venv_python):
        emit_step("background_claim", "skipped", reason=f"venv python not found: {venv_python}")
        return False, {"error": "venv not found"}
    
    subprocess_cmd = [venv_python, dual_claim_py, "--pat", pat, "--generate"]
    # Set env vars so dual_claim.py finds vendored assets inside qoder-trial/
    # (runtime-info binary, spoof_hw.so hook, generate_identity.py)
    env = os.environ.copy()
    env["QODER_IDENTITY_DIR"] = trial_dir
    env["QODER_RUNTIME_INFO"] = os.path.join(trial_dir, "runtime-info-linux-x64")
    env["QODER_SPOOF_SO"] = os.path.join(trial_dir, "hooks", "spoof_hw.so")

    # Trial claim needs MULTIPLE attempts with ~30s cooldown between them
    # (qoder.com anti-fraud: fresh account usually shows PLAN_TIER_FREE for a
    # while before the trial grant becomes claimable). Loop until active.
    MAX_ATTEMPTS = int(os.getenv("QODER_CLAIM_MAX_ATTEMPTS", "10"))
    COOLDOWN_S = int(os.getenv("QODER_CLAIM_COOLDOWN_S", "60"))

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            emit_step("background_claim", "spawning", attempt=attempt, max=MAX_ATTEMPTS)
            r = subprocess.run(
                subprocess_cmd, capture_output=True, text=True, timeout=300,
                cwd=trial_dir, env=env,
            )

            stdout = (r.stdout or "") + "\n" + (r.stderr or "")
            success = r.returncode == 0

            # Parse trial status from output
            trial_active = "Pro Trial:" in stdout and "ACTIVE" in stdout.split("Pro Trial:")[1][:60]
            credits_match = re.search(r"Credits:\s*([\d.]+)", stdout)
            credits = int(float(credits_match.group(1))) if credits_match else 0

            result = {
                "trial": trial_active,
                "ultimate": "ULTIMATE] CLAIMED" in stdout,
                "qwen800": "QWEN3.8 800" in stdout and "CLAIMED" in stdout,
                "credits": credits,
                "success": success,
                "attempt": attempt,
            }

            emit_step("background_claim", "ok" if trial_active else "failed", **result)
            if trial_active:
                return True, result

            # Cooldown before next attempt (unless last)
            if attempt < MAX_ATTEMPTS:
                emit_step("background_claim", "cooldown", wait_s=COOLDOWN_S, attempt=attempt)
                time.sleep(COOLDOWN_S)
        except subprocess.TimeoutExpired:
            emit_step("background_claim", "failed", reason=f"TIMEOUT 300s (attempt {attempt})")
            return False, {"error": "TIMEOUT 300s"}
        except Exception as e:
            emit_step("background_claim", "failed", error=str(e)[:100], attempt=attempt)
            return False, {"error": str(e)}

    emit_step("background_claim", "failed", reason=f"trial-not-claimed-after-{MAX_ATTEMPTS}")
    return False, {"error": f"trial-not-claimed-after-{MAX_ATTEMPTS}"}


# ---- run -------------------------------------------------------------------


def run() -> int:
    email = (os.getenv("QODER_EMAIL") or "").strip()
    password = os.getenv("QODER_PASSWORD") or ""
    name = (os.getenv("QODER_NAME") or "").strip() or "Alex Rivera"
    source = (os.getenv("QODER_EMAIL_SOURCE") or "tempmail").strip().lower()
    proxy = (os.getenv("QODER_PROXY") or "").strip() or None

    # Env guard BEFORE any network: tempmail mode generates the email, but a
    # missing password (or a missing email for imap) must fail fast, offline.
    if source != "tempmail" and not email:
        emit_result(False, error="missing-email-or-password", step="init")
        return 1
    if not password:
        emit_result(False, error="missing-email-or-password", step="init")
        return 1

    box: Any = None
    if source == "tempmail":
        emit_step("tempmail_init", "ok")
        from tempmail import EmailBox  # local import (needs curl_cffi + network)

        box = EmailBox(prefer=["ncaori", "zoromail"])
        email = box.create_account()
        emit_step("tempmail_create", "ok", address=email)

    if not email:
        emit_result(False, error="missing-email-or-password", step="init")
        return 1

    s = _session(proxy=proxy)
    try:
        emit_step("bootstrap", "ok")
        signup_page(s)

        # step1a: optional check-login-type pre-flight (HAR order). Non-fatal.
        try:
            check_login_type(s, email, proxy=proxy)
            emit_step("check_login_type", "ok")
        except Exception:
            emit_step("check_login_type", "warn")

        # step1b: send_verification_code -> triggers the OTP email delivery.
        # Live punish is HTTP 200 HTML; check raw text too.
        emit_step("verification_code", "pending")
        rv = send_verification_code(s, email, proxy=proxy)
        if is_tmd_punish(rv.text) or is_tmd_punish(_body_json(rv)):
            emit_step("tmd", "warn")
            ok = False
            for _attempt in range(3):
                rv = send_verification_code(s, email, proxy=proxy)
                if is_tmd_punish(rv.text) or is_tmd_punish(_body_json(rv)):
                    continue
                ok = True
                break
            if not ok:
                emit_result(False, error="tmd-persistent", step="spam")
                return 1
        else:
            emit_step("verification_code", "ok")

        code = poll_otp(email, source, proxy=proxy, box=box)
        if not code:
            emit_result(False, error="otp-timeout", step="otp")
            return 1

        # step2: register WITH the OTP code (completes verification + session).
        emit_step("register", "pending")
        r2 = register(s, email, password, name, code=code, proxy=proxy)
        if r2.status_code >= 400:
            emit_result(
                False,
                error=f"register http-{r2.status_code} {_mask6(r2.text[:120])}",
                step="register",
            )
            return 1
        emit_step("register", "ok")

        # PAT + auth check
        pat = create_pat(s, name)
        if not pat:
            # The Node provider's connection object requires a real PAT
            # (apiKey); an account without one is a false success.
            emit_result(False, error="pat-missing", step="pat")
            return 1
        me = login_me(s)

        # ===== STEP: Best-effort background claim to Pro Trial 300 credits =====
        # Spawn dual_claim.py subprocess — NEVER blocks signup on failure
        trial_active, claim_result = run_background_claim(pat, proxy=proxy)

        # Merge claim result into final payload so afterAdd() can filter trial accounts
        result_kwargs = {
            "email": email,
            "name": name,
            "pat": pat,
            "me": bool(me),
        }
        # Filter to ONLY safe fields for final emit (no debug data)
        safe_fields = {k: v for k, v in claim_result.items() 
                      if k in ("trial", "ultimate", "qwen800", "qwen2000", "credits")}
        result_kwargs.update(safe_fields)
        
        emit_result(True, **result_kwargs)
        return 0
    finally:
        try:
            s.close()
        except Exception:
            pass


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        try:
            import curl_cffi  # noqa: F401
            assert len(encode_bx_ua()) > 10
            assert is_tmd_punish({"x5secdata": "xx"})
            assert not is_tmd_punish({"errorMessage": "Code required"})
            assert _mask6("code is 123456 now") == "code is ****** now"
            assert "707124" not in _mask6("707124")
            emit_result(True, step="self_test")
            sys.exit(0)
        except Exception as e:
            emit_result(False, error=str(e), step="self_test")
            sys.exit(1)

    # Task 3: real flow
    sys.exit(run())
