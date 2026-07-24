#!/usr/bin/env python3
"""Kiro pure-HTTP account signup worker (AWS Builder ID email path).

Phase D1 — curl_cffi Chrome 131 against the committed endpoint map
(docs/superpowers/specs/2026-07-23-kiro-aws-endpoint-map.md).

Spawned by src/providers/kiro/worker-bridge.js. Emits JSONL on stdout.

Security:
  - NEVER log password, OTP, device_code, or codeVerifier.
  - Worker only receives KIRO_DEVICE_URL (user_code via verification_uri_complete).
  - device_code / poll extraData stay in Node.
"""
from __future__ import annotations

import base64
import email as emaillib
import html
import imaplib
import json
import os
import re
import sys
import time
import uuid
from typing import Any
from urllib.parse import parse_qs, unquote, urlencode, urlparse

# Lazy — OTP/unit helpers import without curl_cffi installed.
creq = None


def _ensure_creq():
    global creq
    if creq is None:
        from curl_cffi import requests as _creq

        creq = _creq
    return creq


# ---- constants (from Phase D0 endpoint map) --------------------------------

WORKFLOW_ID = "050d5017-f505-464b-861f-aedabd3d10fa"
DIRECTORY_ID = "d-9067642ac7"
OIDC_CLIENT_ID = "0o3EowjdaDUHB9N0ZH-OInVzLWVhc3QtMQ"
PROFILE_BASE = "https://profile.aws.amazon.com"
SIGNIN_BASE = "https://us-east-1.signin.aws"
PORTAL_SSO = "https://portal.sso.us-east-1.amazonaws.com"
OIDC_BASE = "https://oidc.us-east-1.amazonaws.com"
VS_TOKEN_URL = "https://vs.aws.amazon.com/token"
VIEW_BASE = "https://view.awsapps.com"

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
IMPERSONATE = "chrome131"

# Password POST body was redacted in capture. These input_type names are
# best-effort from createPasswordPage locale keys + signup/api/execute shapes.
# Live smoke may need a second capture pass if AWS rejects them.
_PASSWORD_INPUT_TYPE = "UserPasswordInput"
_FINGERPRINT_INPUT_TYPE = "FingerPrintInput"
_USER_EVENT_INPUT_TYPE = "UserEventBatch"


# ---- OTP extraction (AWS 6-digit primary) ----------------------------------

_OTP_DIGIT6_RE = re.compile(
    r"(?:(?:verification|confirmation)\s+code|otp|one[- ]time(?: pass(?:word|code)?))"
    r"[:\s#]*(\d{6})\b",
    re.IGNORECASE,
)
_OTP_DIGIT6_BARE_RE = re.compile(r"\b(\d{6})\b")
_OTP_HYPHEN_RE = re.compile(
    r"(?:confirmation\s+)?code[:\s]+([A-Z0-9]{3}-[A-Z0-9]{3})\b",
    re.I,
)
_AWS_MARKERS = ("signin.aws", "aws", "amazon web services", "builder id")
_OTP_NOISE = {"111111", "222222", "123456", "000000", "999999", "666666"}


def extract_otp(text: str, subject: str = "") -> str | None:
    """Extract 6-digit AWS OTP code from text."""
    m = _OTP_DIGIT6_RE.search(text)
    if m and m.group(1) not in _OTP_NOISE:
        return m.group(1)
    for m in _OTP_HYPHEN_RE.finditer(text):
        return m.group(1).upper()
    has_aws = any(marker in text.lower() for marker in _AWS_MARKERS)
    if has_aws:
        for m in _OTP_DIGIT6_BARE_RE.finditer(text):
            if m.group(1) not in _OTP_NOISE:
                return m.group(1)
    return None


def _decode_subject(subject: bytes | str | None) -> str:
    from email.header import decode_header

    if not subject:
        return ""
    if isinstance(subject, bytes):
        subject = subject.decode("utf-8", errors="replace")
    parts = decode_header(subject)
    return " ".join(
        part.decode(charset or "utf-8", errors="replace") if isinstance(part, bytes)
        else str(part)
        for part, charset in parts
    )


def _strip_html(html_text: str) -> str:
    clean = re.sub(r"<style[^>]*>.*?</style>", "", html_text, flags=re.DOTALL)
    clean = re.sub(r"<script[^>]*>.*?</script>", "", clean, flags=re.DOTALL)
    clean = re.sub(r"<[^>]+>", " ", clean)
    clean = html.unescape(clean)
    clean = re.sub(r"\s+", " ", clean).strip()
    return clean


def extract_otp_from_message(raw_bytes: bytes) -> str | None:
    try:
        msg = emaillib.message_from_bytes(raw_bytes)
    except Exception:
        return None

    subject = _decode_subject(msg["Subject"])

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct == "text/plain":
                try:
                    body = part.get_payload(decode=True).decode("utf-8", errors="replace")
                except Exception:
                    body = ""
            elif ct == "text/html" and not body:
                try:
                    body = _strip_html(
                        part.get_payload(decode=True).decode("utf-8", errors="replace")
                    )
                except Exception:
                    body = ""
    else:
        ct = msg.get_content_type()
        try:
            payload = msg.get_payload(decode=True)
            if payload is None:
                return None
            raw = payload.decode("utf-8", errors="replace")
            if ct == "text/html":
                body = _strip_html(raw)
            else:
                body = raw
        except Exception:
            return None

    code = extract_otp(subject)
    if code:
        return code
    return extract_otp(body)


# ---- IMAP config + poll (ported from grok-cli, KIRO defaults) --------------


def imap_cfg_from_env() -> dict:
    return {
        "host": os.getenv("KIRO_IMAP_HOST", "imap.gmail.com"),
        "port": os.getenv("KIRO_IMAP_PORT", "993"),
        "user": os.getenv("KIRO_IMAP_USER", ""),
        "password": os.getenv("KIRO_IMAP_PASSWORD", ""),
        "tls": os.getenv("KIRO_IMAP_TLS", "true"),
        "delete_after_read": os.getenv("KIRO_IMAP_DELETE_AFTER_READ", "false"),
        "subject": os.getenv("KIRO_OTP_SUBJECT", ""),
        "sender_domain": os.getenv("KIRO_OTP_SENDER_DOMAIN", "signin.aws"),
    }


def _mailboxes_for(host: str) -> list[str]:
    """Ordered mailboxes to search. Gmail: INBOX + Spam (+ All Mail)."""
    h = (host or "").lower()
    if h.endswith("gmail.com"):
        return [
            "INBOX",
            '"[Gmail]/Spam"',
            '"[Google Mail]/Spam"',
            '"[Gmail]/All Mail"',
        ]
    return ["INBOX"]


def _select_mailbox(m: imaplib.IMAP4, mailbox: str) -> bool:
    """SELECT mailbox; return True only when state becomes SELECTED.

    Critical: imaplib.select() does NOT raise on NO/BAD — it resets state to
    AUTH and returns (typ, dat). Searching after a failed select raises
    "command SEARCH illegal in state AUTH".
    """
    try:
        typ, dat = m.select(mailbox)
    except Exception as e:
        emit(
            {
                "event": "debug",
                "msg": "imap-select-error",
                "mailbox": mailbox[:40],
                "error": str(e)[:100],
            }
        )
        return False
    if typ == "OK" and m.state == "SELECTED":
        return True
    detail = ""
    try:
        if dat and dat[0] is not None:
            raw = dat[0]
            detail = (
                raw.decode(errors="replace")
                if isinstance(raw, (bytes, bytearray))
                else str(raw)
            )[:80]
    except Exception:
        detail = ""
    emit(
        {
            "event": "debug",
            "msg": "imap-select-failed",
            "mailbox": mailbox[:40],
            "typ": typ,
            "detail": detail,
        }
    )
    return False


def _search_ids(m: imaplib.IMAP4, target_email: str, sender_domain: str) -> list:
    """SEARCH for candidate message ids. Caller must be in SELECTED state."""
    typ, data = m.search(None, f'(TO "{target_email}" FROM "{sender_domain}")')
    ids = data[0].split() if typ == "OK" and data and data[0] else []
    if not ids:
        typ, data = m.search(None, f'(FROM "{sender_domain}")')
        ids = data[0].split() if typ == "OK" and data and data[0] else []
    return ids


def read_otp(
    target_email: str,
    cfg: dict,
    retries: int = 40,
    delay: float = 5.0,
) -> str | None:
    """Poll IMAP for the AWS Builder ID code. Returns code|None.

    Never logs the code value — only lengths/prose via emit_step.
    Defaults: sender_domain=signin.aws, delay=5s (KIRO).
    """
    host = cfg["host"]
    port = int(cfg["port"])
    user = cfg["user"]
    pw = cfg["password"]
    use_tls = str(cfg.get("tls", "true")).lower() == "true"
    delete_after = str(cfg.get("delete_after_read", "false")).lower() == "true"
    sender_domain = (cfg.get("sender_domain") or "signin.aws").strip() or "signin.aws"
    mailboxes = _mailboxes_for(host)
    t0 = time.time()
    for attempt in range(retries):
        emit_step("otp", "pending", attempt=attempt + 1, elapsed_s=int(time.time() - t0))
        try:
            m = imaplib.IMAP4_SSL(host, port) if use_tls else imaplib.IMAP4(host, port)
            try:
                m.login(user, pw)
                found = None
                selected_any = False
                for mailbox in mailboxes:
                    if not _select_mailbox(m, mailbox):
                        continue
                    selected_any = True
                    ids = _search_ids(m, target_email, sender_domain)
                    for i in reversed(ids[-8:]):
                        _, dt = m.fetch(i, "(RFC822)")
                        raw = (
                            dt[0][1]
                            if dt and dt[0] and isinstance(dt[0], tuple)
                            else b""
                        )
                        code = extract_otp_from_message(raw)
                        if code:
                            found = code
                            if delete_after:
                                try:
                                    m.store(i, "+FLAGS", "\\Deleted")
                                except Exception:
                                    pass
                            break
                    if found:
                        break
                if not selected_any:
                    emit(
                        {
                            "event": "debug",
                            "msg": "imap-no-mailbox",
                            "tried": [mb[:30] for mb in mailboxes],
                        }
                    )
                if delete_after and found:
                    try:
                        m.expunge()
                    except Exception:
                        pass
                if found:
                    emit_step("otp", "ok", elapsed_s=int(time.time() - t0))
                    return found
            finally:
                try:
                    m.logout()
                except Exception:
                    pass
        except Exception as e:
            emit({"event": "debug", "msg": "imap-error", "error": str(e)[:120]})
        time.sleep(delay)
    return None


# ---- emit helpers ----------------------------------------------------------


def emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def emit_step(step: str, status: str = "ok", **extra: Any) -> None:
    payload = {"event": "step", "step": step, "status": status}
    payload.update(extra)
    emit(payload)


def emit_result(ok: bool, error: str | None = None, step: str | None = None) -> None:
    obj: dict[str, Any] = {"kind": "result", "ok": ok}
    obj["event"] = "result"
    if error:
        obj["error"] = error
    if step:
        obj["step"] = step
    emit(obj)


def redact_err(err: BaseException | str) -> str:
    s = str(err)[:300]
    s = re.sub(r"(password|otp|token|code|authCode|state)=[^\s&\"']+", r"\1=<redacted>", s, flags=re.I)
    s = re.sub(r"\b\d{6}\b", "<otp>", s)
    return s


# ---- URL / browser-data helpers --------------------------------------------


def user_code_from_device_url(url: str) -> str:
    """Extract user_code from KIRO_DEVICE_URL (verification_uri_complete)."""
    if not url:
        raise RuntimeError("KIRO_DEVICE_URL missing")
    qs = parse_qs(urlparse(url).query)
    if "user_code" in qs and qs["user_code"]:
        return qs["user_code"][0]
    # Hash fragment: #/device?user_code=XXXX
    frag = urlparse(url).fragment or ""
    if "user_code=" in frag:
        m = re.search(r"user_code=([A-Za-z0-9\-]+)", frag)
        if m:
            return m.group(1)
    return_to = qs.get("return_to", [None])[0]
    if return_to:
        inner = unquote(return_to)
        m = re.search(r"user_code=([A-Za-z0-9\-]+)", inner)
        if m:
            return m.group(1)
    m = re.search(r"user_code=([A-Za-z0-9\-]+)", unquote(url))
    if m:
        return m.group(1)
    raise RuntimeError("user_code not found in KIRO_DEVICE_URL")


def _new_ubid() -> str:
    # Captured shape: "485-8321923-7639224"
    a = str(uuid.uuid4().int % 900 + 100)
    b = str(uuid.uuid4().int % 9_000_000 + 1_000_000)
    c = str(uuid.uuid4().int % 9_000_000 + 1_000_000)
    return f"{a}-{b}-{c}"


def _fingerprint() -> str:
    # Captured shape: "ECdITeCs:<base64>"
    raw = uuid.uuid4().bytes + uuid.uuid4().bytes
    return "ECdITeCs:" + base64.b64encode(raw).decode("ascii")


def _iso_now() -> str:
    # Match capture: "2026-07-24T10:16:42.103Z"
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()) + f".{int(time.time() * 1000) % 1000:03d}Z"


def browser_data(
    page_name: str | None = None,
    event_type: str = "PageLoad",
    time_spent_ms: int = 150,
    fingerprint: str | None = None,
    ubid: str | None = None,
) -> dict:
    attrs: dict[str, str] = {
        "fingerprint": fingerprint or _fingerprint(),
        "eventTimestamp": _iso_now(),
        "timeSpentOnPage": str(time_spent_ms),
        "eventType": event_type,
        "ubid": ubid or _new_ubid(),
    }
    if page_name:
        attrs["pageName"] = page_name
    return {"attributes": attrs, "cookies": {}}


def _new_request_id() -> str:
    return str(uuid.uuid4())


def _json_or_empty(resp: Any) -> dict:
    try:
        if resp is None or not getattr(resp, "content", None):
            return {}
        data = resp.json()
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _raise_http(step: str, resp: Any, label: str = "") -> None:
    status = getattr(resp, "status_code", 0) or 0
    text = (getattr(resp, "text", None) or "")[:200]
    low = text.lower()
    # WAF / bot block signals — escalate, do not fall back to browser.
    if status in (403, 429, 503) and any(
        k in low for k in ("captcha", "waf", "cloudfront", "access denied", "request blocked", "challenge")
    ):
        raise RuntimeError(f"waf-blocked status={status} step={step} {label}".strip())
    if status >= 400:
        raise RuntimeError(f"http-{status} step={step} {label} body={text!r}".strip())


# ---- HTTP session helpers --------------------------------------------------


def make_session(proxy: str | None = None) -> Any:
    s = _ensure_creq().Session()
    s.headers.update(
        {
            "User-Agent": UA,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "sec-ch-ua": '"Google Chrome";v="131", "Chromium";v="131", ";Not A Brand";v="99"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        }
    )
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    return s


def _get(s: Any, url: str, **kw: Any) -> Any:
    return s.get(url, impersonate=IMPERSONATE, timeout=kw.pop("timeout", 45), **kw)


def _post_json(s: Any, url: str, body: dict, headers: dict | None = None, **kw: Any) -> Any:
    h = {
        "Content-Type": "application/json;charset=UTF-8",
        "Origin": urlparse(url).scheme + "://" + urlparse(url).netloc,
    }
    if headers:
        h.update(headers)
    return s.post(
        url,
        json=body,
        headers=h,
        impersonate=IMPERSONATE,
        timeout=kw.pop("timeout", 45),
        **kw,
    )


def _post_form(s: Any, url: str, data: dict, headers: dict | None = None, **kw: Any) -> Any:
    h = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": urlparse(url).scheme + "://" + urlparse(url).netloc,
    }
    if headers:
        h.update(headers)
    return s.post(
        url,
        data=urlencode(data),
        headers=h,
        impersonate=IMPERSONATE,
        timeout=kw.pop("timeout", 45),
        **kw,
    )


# ---- Flow state ------------------------------------------------------------


class FlowState:
    """Mutable state carried across HTTP steps."""

    def __init__(self) -> None:
        self.user_code: str = ""
        self.csrf_token: str = ""
        self.directory_id: str = DIRECTORY_ID
        self.workflow_state: str = ""
        self.workflow_state_handle: str = ""
        self.visitor_id: str = str(uuid.uuid4())
        self.fingerprint: str = _fingerprint()
        self.ubid: str = _new_ubid()
        self.registration_code: str = ""
        self.sign_in_state: str = ""
        self.user_session_id: str = ""
        self.device_context: dict | None = None
        self.auth_code: str = ""
        self.sso_state: str = ""
        self.email: str = ""
        self.name: str = ""
        self.password: str = ""


# ---- Steps -----------------------------------------------------------------


def step_bootstrap(s: Any, st: FlowState, device_url: str) -> None:
    """Open device URL, hit portal.sso /login, follow to signin page."""
    emit_step("bootstrap", "pending")
    st.user_code = user_code_from_device_url(device_url)

    # Warm device page (cookies on view.awsapps.com)
    r0 = _get(s, device_url, allow_redirects=True)
    # Soft-check — SPA may return 200 HTML regardless.
    emit(
        {
            "event": "debug",
            "msg": "device-url-open",
            "status": getattr(r0, "status_code", 0),
            "user_code_len": len(st.user_code),
        }
    )

    redirect_url = (
        f"{VIEW_BASE}/start/#/device?user_code={st.user_code}"
    )
    login_url = (
        f"{PORTAL_SSO}/login"
        f"?directory_id=view&redirect_url={_url_quote(redirect_url)}"
    )
    r = _get(s, login_url, headers={"Referer": f"{VIEW_BASE}/", "Accept": "application/json"})
    if r.status_code >= 400:
        _raise_http("bootstrap", r, "portal.sso/login")
    data = _json_or_empty(r)
    st.csrf_token = str(data.get("csrfToken") or "")
    signin_redirect = str(data.get("redirectUrl") or "")
    if not signin_redirect:
        # Fallback: construct login URL with a fresh handle placeholder; real
        # handle comes from profile /api/start later.
        signin_redirect = (
            f"{SIGNIN_BASE}/platform/{st.directory_id}/login"
        )
    # Follow HTML login page
    r2 = _get(s, signin_redirect, headers={"Referer": f"{VIEW_BASE}/"})
    # Extract workflowStateHandle from redirect URL if present
    qs = parse_qs(urlparse(signin_redirect).query)
    if qs.get("workflowStateHandle"):
        st.workflow_state_handle = qs["workflowStateHandle"][0]
    # Also try final URL after redirects
    final = getattr(r2, "url", "") or ""
    qs2 = parse_qs(urlparse(final).query)
    if qs2.get("workflowStateHandle"):
        st.workflow_state_handle = qs2["workflowStateHandle"][0]

    emit_step("bootstrap", "ok")


def _url_quote(u: str) -> str:
    from urllib.parse import quote

    return quote(u, safe="")


def step_email_entry(s: Any, st: FlowState, email: str) -> None:
    """Profile /api/start + /api/send-otp (email submission)."""
    emit_step("email_entry", "pending")
    st.email = email

    # Load profile SPA entry (sets cookies)
    profile_url = f"{PROFILE_BASE}/?workflowID={WORKFLOW_ID}"
    _get(
        s,
        profile_url,
        headers={"Referer": f"{SIGNIN_BASE}/"},
    )

    # Optional config warm-ups (captured; non-fatal)
    try:
        _post_json(
            s,
            f"{PROFILE_BASE}/api/get-config",
            {},
            headers={"Referer": profile_url, "Origin": PROFILE_BASE},
        )
        _post_json(
            s,
            f"{PROFILE_BASE}/api/get-app-context",
            {"workflowID": WORKFLOW_ID},
            headers={"Referer": profile_url, "Origin": PROFILE_BASE},
        )
    except Exception as e:
        emit({"event": "debug", "msg": "profile-warmup-soft-fail", "error": redact_err(e)})

    bd = browser_data(
        event_type="PageLoad",
        time_spent_ms=134,
        fingerprint=st.fingerprint,
        ubid=st.ubid,
    )
    r = _post_json(
        s,
        f"{PROFILE_BASE}/api/start",
        {"workflowID": WORKFLOW_ID, "browserData": bd},
        headers={"Referer": profile_url, "Origin": PROFILE_BASE},
    )
    _raise_http("email_entry", r, "profile/api/start")
    start = _json_or_empty(r)
    st.workflow_state = str(start.get("workflowState") or "")
    if not st.workflow_state:
        raise RuntimeError("profile-start-missing-workflowState")
    # Capture any signup/login redirect hints
    if start.get("redirectUrl"):
        qs = parse_qs(urlparse(str(start["redirectUrl"])).query)
        if qs.get("workflowStateHandle"):
            st.workflow_state_handle = qs["workflowStateHandle"][0]

    # send-otp
    bd2 = browser_data(
        page_name="EMAIL_COLLECTION",
        event_type="PageSubmit",
        time_spent_ms=7000,
        fingerprint=st.fingerprint,
        ubid=st.ubid,
    )
    r2 = _post_json(
        s,
        f"{PROFILE_BASE}/api/send-otp",
        {
            "workflowState": st.workflow_state,
            "email": email,
            "browserData": bd2,
        },
        headers={"Referer": profile_url, "Origin": PROFILE_BASE},
    )
    _raise_http("email_entry", r2, "profile/api/send-otp")
    # Some responses refresh workflowState
    sent = _json_or_empty(r2)
    if sent.get("workflowState"):
        st.workflow_state = str(sent["workflowState"])

    # Also mirror captured signup/api/execute UserRequestInput (username=email)
    # when we already have a workflowStateHandle on the signin platform.
    if st.workflow_state_handle:
        try:
            rid = _new_request_id()
            body = {
                "stepId": "",
                "workflowStateHandle": st.workflow_state_handle,
                "inputs": [
                    {"input_type": "UserRequestInput", "username": email},
                    {
                        "input_type": _FINGERPRINT_INPUT_TYPE,
                        "fingerPrint": st.fingerprint,
                    },
                ],
                "visitorId": st.visitor_id,
                "requestId": rid,
            }
            r3 = _post_json(
                s,
                f"{SIGNIN_BASE}/platform/{st.directory_id}/signup/api/execute",
                body,
                headers={
                    "Referer": (
                        f"{SIGNIN_BASE}/platform/{st.directory_id}/signup"
                        f"?workflowStateHandle={st.workflow_state_handle}"
                    ),
                    "Origin": SIGNIN_BASE,
                    "x-amzn-requestid": rid,
                },
            )
            if r3.status_code < 400:
                ex = _json_or_empty(r3)
                if ex.get("workflowStateHandle"):
                    st.workflow_state_handle = str(ex["workflowStateHandle"])
        except Exception as e:
            emit(
                {
                    "event": "debug",
                    "msg": "signup-execute-email-soft-fail",
                    "error": redact_err(e),
                }
            )

    emit_step("email_entry", "ok")


def step_otp(email: str, email_source: str, box: Any | None = None) -> str:
    """Wait for OTP via IMAP or tempmail. Returns code (never logged)."""
    t0 = time.time()
    emit_step("otp", "pending", source=email_source)
    code: str | None = None
    if email_source == "tempmail":
        if box is None:
            raise RuntimeError("tempmail-box-missing")
        try:
            code = box.wait_code(timeout=150)
        except Exception as e:
            emit_step("otp", "failed", error=redact_err(e))
            raise RuntimeError(f"tempmail-otp-timeout: {redact_err(e)}") from e
        emit_step("otp", "ok", elapsed_s=int(time.time() - t0), source="tempmail")
    else:
        code = read_otp(email, imap_cfg_from_env(), retries=40, delay=5.0)
        if not code:
            emit_step("otp", "failed")
            raise RuntimeError("otp-not-found")
    return code


def step_create_identity(s: Any, st: FlowState, otp_code: str) -> None:
    """POST /api/create-identity — OTP + name + email in one call."""
    emit_step("otp_verify", "pending")
    emit_step("name", "pending")
    profile_url = f"{PROFILE_BASE}/?workflowID={WORKFLOW_ID}"
    bd = browser_data(
        page_name="EMAIL_VERIFICATION",
        event_type="EmailVerification",
        time_spent_ms=13000,
        fingerprint=st.fingerprint,
        ubid=st.ubid,
    )
    body = {
        "workflowState": st.workflow_state,
        "userData": {"email": st.email, "fullName": st.name},
        "otpCode": otp_code,
        "browserData": bd,
    }
    r = _post_json(
        s,
        f"{PROFILE_BASE}/api/create-identity",
        body,
        headers={"Referer": profile_url, "Origin": PROFILE_BASE},
    )
    _raise_http("otp_verify", r, "profile/api/create-identity")
    data = _json_or_empty(r)
    st.registration_code = str(data.get("registrationCode") or st.workflow_state or "")
    st.sign_in_state = str(data.get("signInState") or "")
    if not st.registration_code:
        raise RuntimeError("create-identity-missing-registrationCode")
    emit_step("otp_verify", "ok")
    emit_step("name", "ok")


def step_password(s: Any, st: FlowState) -> None:
    """Best-effort password set via signup page + signup/api/execute.

    Capture gap: password POST body was fully redacted. We reconstruct from
    createPasswordPage locale keys + execute shape. If AWS rejects, fail at
    step=password (no browser fallback).
    """
    emit_step("password", "pending")
    if not st.password:
        raise RuntimeError("password-missing")

    signup_qs = {"registrationCode": st.registration_code}
    if st.sign_in_state:
        signup_qs["state"] = st.sign_in_state
    signup_url = (
        f"{SIGNIN_BASE}/platform/{st.directory_id}/signup?{urlencode(signup_qs)}"
    )
    r_page = _get(s, signup_url, headers={"Referer": PROFILE_BASE + "/"})
    # HTML SPA — 200 expected
    if r_page.status_code >= 400:
        _raise_http("password", r_page, "signup-page")

    # Telemetry PAGE_LOAD CREDENTIAL_COLLECTION (captured; non-fatal)
    try:
        rid = _new_request_id()
        _post_json(
            s,
            f"{SIGNIN_BASE}/platform/user-event/send-event",
            {
                "inputs": [
                    {
                        "input_type": _USER_EVENT_INPUT_TYPE,
                        "directoryId": st.directory_id,
                        "userName": st.email,
                        "userEvents": [
                            {
                                "input_type": "UserEvent",
                                "eventType": "PAGE_LOAD",
                                "pageName": "CREDENTIAL_COLLECTION",
                            }
                        ],
                    },
                    {
                        "input_type": _FINGERPRINT_INPUT_TYPE,
                        "fingerPrint": st.fingerprint,
                    },
                ],
                "requestId": rid,
            },
            headers={
                "Referer": signup_url,
                "Origin": SIGNIN_BASE,
                "x-amzn-requestid": rid,
            },
        )
    except Exception as e:
        emit({"event": "debug", "msg": "user-event-soft-fail", "error": redact_err(e)})

    # Prefer registrationCode as workflow handle when platform handle unknown
    handle = st.workflow_state_handle or st.registration_code
    rid = _new_request_id()
    # Try a few plausible password payload shapes (capture redacted the real one).
    candidates = [
        {
            "stepId": "",
            "workflowStateHandle": handle,
            "inputs": [
                {
                    "input_type": _PASSWORD_INPUT_TYPE,
                    "password": st.password,
                    "passwordConfirm": st.password,
                },
                {
                    "input_type": _FINGERPRINT_INPUT_TYPE,
                    "fingerPrint": st.fingerprint,
                },
            ],
            "visitorId": st.visitor_id,
            "requestId": rid,
        },
        {
            "stepId": "",
            "workflowStateHandle": handle,
            "inputs": [
                {
                    "input_type": "NewPasswordInput",
                    "newPassword": st.password,
                    "retypePassword": st.password,
                },
                {
                    "input_type": _FINGERPRINT_INPUT_TYPE,
                    "fingerPrint": st.fingerprint,
                },
            ],
            "visitorId": st.visitor_id,
            "requestId": rid,
        },
        {
            "stepId": "createPassword",
            "workflowStateHandle": handle,
            "inputs": [
                {
                    "input_type": "UserPasswordInput",
                    "newPassword": st.password,
                    "confirmPassword": st.password,
                },
                {
                    "input_type": _FINGERPRINT_INPUT_TYPE,
                    "fingerPrint": st.fingerprint,
                },
            ],
            "visitorId": st.visitor_id,
            "requestId": rid,
            "registrationCode": st.registration_code,
        },
    ]

    last_err = "password-execute-failed"
    for i, body in enumerate(candidates):
        # Fresh requestId per attempt
        body = dict(body)
        body["requestId"] = _new_request_id()
        try:
            r = _post_json(
                s,
                f"{SIGNIN_BASE}/platform/{st.directory_id}/signup/api/execute",
                body,
                headers={
                    "Referer": signup_url,
                    "Origin": SIGNIN_BASE,
                    "x-amzn-requestid": body["requestId"],
                },
            )
            if r.status_code < 400:
                data = _json_or_empty(r)
                if data.get("workflowStateHandle"):
                    st.workflow_state_handle = str(data["workflowStateHandle"])
                # Pull authCode/state from redirect-ish fields if present
                for key in ("redirectUrl", "redirect", "location"):
                    ru = data.get(key)
                    if isinstance(ru, str) and ru:
                        _pull_auth_from_url(st, ru)
                emit(
                    {
                        "event": "debug",
                        "msg": "password-execute-ok",
                        "attempt": i + 1,
                        "stepId": data.get("stepId"),
                    }
                )
                emit_step("password", "ok")
                return
            last_err = f"password-http-{r.status_code}"
            emit(
                {
                    "event": "debug",
                    "msg": "password-execute-reject",
                    "attempt": i + 1,
                    "status": r.status_code,
                }
            )
        except Exception as e:
            last_err = redact_err(e)
            emit(
                {
                    "event": "debug",
                    "msg": "password-execute-error",
                    "attempt": i + 1,
                    "error": last_err,
                }
            )

    raise RuntimeError(last_err)


def _pull_auth_from_url(st: FlowState, url: str) -> None:
    qs = parse_qs(urlparse(url).query)
    if qs.get("authCode"):
        st.auth_code = qs["authCode"][0]
    if qs.get("code") and not st.auth_code:
        st.auth_code = qs["code"][0]
    if qs.get("state"):
        st.sso_state = qs["state"][0]
    frag = urlparse(url).fragment or ""
    if "authCode=" in frag or "code=" in frag:
        m = re.search(r"(?:authCode|code)=([^&]+)", frag)
        if m:
            st.auth_code = unquote(m.group(1))
    if "state=" in frag and not st.sso_state:
        m = re.search(r"state=([^&]+)", frag)
        if m:
            st.sso_state = unquote(m.group(1))


def step_device_confirm(s: Any, st: FlowState) -> None:
    """accept_user_code + associate_token after session is established."""
    emit_step("device_confirm", "pending")

    # Ensure we have a user session (SSO token). Try whoAmI first.
    _ensure_user_session(s, st)
    if not st.user_session_id:
        raise RuntimeError("user-session-missing")

    r = _post_json(
        s,
        f"{OIDC_BASE}/device_authorization/accept_user_code",
        {"userCode": st.user_code, "userSessionId": st.user_session_id},
        headers={"Referer": f"{VIEW_BASE}/", "Origin": VIEW_BASE},
    )
    _raise_http("device_confirm", r, "accept_user_code")
    data = _json_or_empty(r)
    st.device_context = data.get("deviceContext") if isinstance(data.get("deviceContext"), dict) else None
    if not st.device_context:
        raise RuntimeError("accept_user_code-missing-deviceContext")

    # associate_token
    r2 = _post_json(
        s,
        f"{OIDC_BASE}/device_authorization/associate_token",
        {
            "deviceContext": {
                "deviceContextId": st.device_context.get("deviceContextId"),
                "clientId": st.device_context.get("clientId") or OIDC_CLIENT_ID,
                "clientType": st.device_context.get("clientType") or "public",
            },
            "userSessionId": st.user_session_id,
        },
        headers={"Referer": f"{VIEW_BASE}/", "Origin": VIEW_BASE},
    )
    _raise_http("device_confirm", r2, "associate_token")
    emit_step("device_confirm", "ok")


def _ensure_user_session(s: Any, st: FlowState) -> None:
    """Populate st.user_session_id via whoAmI and/or sso-token exchange."""
    # whoAmI may already work if password step set session cookies
    try:
        r = _get(
            s,
            f"{PORTAL_SSO}/token/whoAmI",
            headers={
                "Referer": f"{VIEW_BASE}/",
                "Accept": "application/json, text/plain, */*",
            },
        )
        if r.status_code < 400:
            data = _json_or_empty(r)
            # Capture uses "token" null on whoAmI after auth; session may be cookie-based.
            # originSessionId / userIdentifier may identify session; OIDC wants the SSO token string.
            tok = data.get("token")
            if isinstance(tok, str) and tok:
                st.user_session_id = tok
            # Some builds put the session in authorization header echoes — keep going.
    except Exception as e:
        emit({"event": "debug", "msg": "whoAmI-soft-fail", "error": redact_err(e)})

    # sso-token exchange if we have authCode from password redirect
    if not st.user_session_id and st.auth_code:
        try:
            headers = {
                "Referer": f"{VIEW_BASE}/",
                "Accept": "application/json, text/plain, */*",
            }
            if st.csrf_token:
                headers["x-amz-sso-csrf-token"] = st.csrf_token
            r2 = _post_form(
                s,
                f"{PORTAL_SSO}/auth/sso-token",
                {
                    "authCode": st.auth_code,
                    "state": st.sso_state or st.sign_in_state or "",
                    "orgId": "view",
                },
                headers=headers,
            )
            if r2.status_code < 400:
                data2 = _json_or_empty(r2)
                tok = data2.get("token")
                if isinstance(tok, str) and tok:
                    st.user_session_id = tok
                if data2.get("redirectUrl"):
                    _pull_auth_from_url(st, str(data2["redirectUrl"]))
        except Exception as e:
            emit({"event": "debug", "msg": "sso-token-soft-fail", "error": redact_err(e)})

    # Fallback: scan cookies for a long session-like value (last resort)
    if not st.user_session_id:
        try:
            jar = getattr(s, "cookies", None)
            if jar is not None:
                for c in jar:
                    name = getattr(c, "name", "") or ""
                    val = getattr(c, "value", "") or ""
                    if len(val) > 80 and any(
                        k in name.lower() for k in ("token", "session", "x-amz", "sso")
                    ):
                        st.user_session_id = val
                        break
        except Exception:
            pass


def step_consent(s: Any, st: FlowState) -> None:
    """consent_details + vs/token finalization."""
    emit_step("consent", "pending")
    if not st.device_context:
        raise RuntimeError("consent-missing-deviceContext")
    if not st.user_session_id:
        _ensure_user_session(s, st)
    if not st.user_session_id:
        raise RuntimeError("consent-missing-userSession")

    body = {
        "deviceContextId": st.device_context.get("deviceContextId"),
        "clientId": st.device_context.get("clientId") or OIDC_CLIENT_ID,
        "clientType": st.device_context.get("clientType") or "public",
        "userSessionId": st.user_session_id,
    }
    r = _post_json(
        s,
        f"{OIDC_BASE}/consent_details",
        body,
        headers={"Referer": f"{VIEW_BASE}/", "Origin": VIEW_BASE},
    )
    _raise_http("consent", r, "consent_details")
    details = _json_or_empty(r)
    status = str(details.get("consentStatus") or "")
    emit(
        {
            "event": "debug",
            "msg": "consent-details",
            "consentStatus": status,
            "clientName": details.get("clientName"),
        }
    )

    # Final token exchange (captured as POST {} to vs.aws.amazon.com/token)
    try:
        r2 = _post_json(
            s,
            VS_TOKEN_URL,
            {},
            headers={"Referer": f"{SIGNIN_BASE}/", "Origin": SIGNIN_BASE},
        )
        if r2.status_code >= 400:
            emit(
                {
                    "event": "debug",
                    "msg": "vs-token-soft-fail",
                    "status": r2.status_code,
                }
            )
    except Exception as e:
        emit({"event": "debug", "msg": "vs-token-error", "error": redact_err(e)})

    emit_step("consent", "ok")


# ---- run() -----------------------------------------------------------------


def run() -> int:
    email = (os.getenv("KIRO_EMAIL") or "").strip()
    password = os.getenv("KIRO_PASSWORD") or ""
    device_url = (os.getenv("KIRO_DEVICE_URL") or "").strip()
    name = (os.getenv("KIRO_NAME") or "").strip() or "Alex Rivera"
    email_source = (os.getenv("KIRO_EMAIL_SOURCE") or "imap").strip().lower()
    proxy = (os.getenv("KIRO_PROXY") or "").strip() or None

    if not password or not device_url:
        emit_result(False, error="missing-required-env", step="init")
        return 1
    if email_source != "tempmail" and not email:
        emit_result(False, error="missing-required-env", step="init")
        return 1
    # Hard reject gmail in worker too (belt + Node check)
    if email.lower().endswith("@gmail.com"):
        emit_result(False, error="google-not-supported-v1", step="init")
        return 1

    step = "bootstrap"
    box = None
    st = FlowState()
    st.name = name
    st.password = password

    try:
        # Tempmail: create mailbox first so we have a real address
        if email_source == "tempmail":
            step = "tempmail_init"
            emit_step("tempmail_init", "ok")
            from tempmail import EmailBox  # local import (needs curl_cffi)

            prefer_raw = os.getenv("KIRO_TEMPMAIL_PROVIDERS", "")
            prefer = [p.strip() for p in prefer_raw.split(",") if p.strip()] or None
            box = EmailBox(prefer=prefer)
            email = box.create_account()
            emit_step("tempmail_create", "ok", address=email)

        st.email = email

        s = make_session(proxy=proxy)
        try:
            step = "bootstrap"
            step_bootstrap(s, st, device_url)

            step = "email_entry"
            step_email_entry(s, st, email)

            step = "otp"
            code = step_otp(email, email_source, box=box)

            step = "otp_verify"
            step_create_identity(s, st, code)

            step = "password"
            step_password(s, st)

            step = "device_confirm"
            step_device_confirm(s, st)

            step = "consent"
            step_consent(s, st)

            emit_step("done", "ok")
            emit_result(True)
            return 0
        finally:
            try:
                s.close()
            except Exception:
                pass

    except Exception as e:
        err_str = redact_err(e)
        # Never echo secrets that might appear in exception args
        if password:
            err_str = err_str.replace(password, "<redacted>")
        emit_step(step, "error", message=err_str)
        emit_result(False, error=err_str, step=step)
        return 1


if __name__ == "__main__":
    raise SystemExit(run())
