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
from typing import Any

from curl_cffi import requests as creq

BASE = "https://qoder.com"
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
    → 200. This is called BEFORE /api/v1/users; the register call then carries
    the received code. A code-less /users call alone never sends the email.
    """
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
    }
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
        emit_result(
            True,
            email=email,
            name=name,
            pat=pat,
            me=bool(me),
        )
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
