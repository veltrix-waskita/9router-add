#!/usr/bin/env python3
"""grok-cli signup worker (pure-HTTP via curl_cffi).

Spawned one-per-run by src/providers/grok-cli/index.js (Node). Drives the
xAI accounts.x.ai signup + device-authorize flow with curl_cffi Chrome 131
impersonation — no browser, no nodriver, no CloakBrowser.

Emits one JSON object per line (JSONL) to stdout for the Node parent to parse,
and signals success via exit code (0 = ok).

Security: NEVER log the password, OTP value, device_code, or codeVerifier.
Only the user_code crosses the boundary, embedded in GROK_SIGNIN_URL; we do
not receive device_code/codeVerifier at all. Logs use lengths/prose only.

Config via env (see plan: pure-HTTP worker).
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
from urllib.parse import parse_qs, quote, unquote, urlparse

from proto_util import (
    build_create_email_validation_code,
    build_validate_password,
    build_verify_email_validation_code,
    parse_fields,
    unwrap_grpc_web,
)

# Lazy so OTP/unit helpers import without curl_cffi installed (e.g. bare python3 tests).
creq = None


def _ensure_creq():
    global creq
    if creq is None:
        from curl_cffi import requests as _creq

        creq = _creq
    return creq


# ---- constants (from x-farm mass_regist) -----------------------------------

SIGNUP_URL = "https://accounts.x.ai/sign-up?redirect=grok-com&return_to=%2F"
TURNSTILE_SITEKEY = "0x4AAAAAAAhr9JGVDZbrZOo0"
# Fallback only — xAI rotates this on every deploy. Prefer discover_next_action().
# Last-resort seed only — Next.js rotates this hash on EVERY deploy, and a
# stale value answers `HTTP 404 "Server action not found."`. discover_next_action()
# scrapes the live id; this constant is just the bootstrap/fallback value.
# Verified live 2026-07-26: stale 7fed37ce… -> 404, scraped 7fe62086… -> 200.
NEXT_ACTION_CREATE_USER = "7fe62086186e534f952cbaf993efbf7ba7e61ed8e8"

GRPC_BASE = "https://accounts.x.ai/auth_mgmt.AuthManagement"
CREATE_EMAIL = f"{GRPC_BASE}/CreateEmailValidationCode"
VERIFY_EMAIL = f"{GRPC_BASE}/VerifyEmailValidationCode"
VALIDATE_PW = f"{GRPC_BASE}/ValidatePassword"

DEVICE_CONSENT_URL = "https://accounts.x.ai/oauth2/device/consent"
DEVICE_DONE_URL = "https://accounts.x.ai/oauth2/device/done"
DEVICE_PAGE = "https://accounts.x.ai/oauth2/device"
ACCOUNT_URL = "https://accounts.x.ai/account"
GROK_HOME = "https://grok.com/"

UA_FALLBACK = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)

SOLVER_URL = os.getenv("SOLVER_URL", "http://127.0.0.1:8877").rstrip("/")

# UUID (principal_id / userId). Kept as a raw group for reuse in patterns.
_UUID = r"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"

# Consent / RSC flight / form field patterns for principal_id (= userId).
# Order matters: prefer explicit userId / principal_id keys over looser matches.
_USER_ID_PATTERNS = (
    r'\\+"userId\\+"\s*:\s*\\+"' + _UUID + r'\\+"',
    r'"userId"\s*:\s*"' + _UUID + r'"',
    r"userId\\?\":\\?\"" + _UUID,
    r'name="principal_id"\s+value="' + _UUID + r'"',
    r'"principal_id"\s*:\s*"' + _UUID + r'"',
    r'\\+"principalId\\+"\s*:\s*\\+"' + _UUID + r'\\+"',
    r'"principalId"\s*:\s*"' + _UUID + r'"',
    r"principalId\\?\":\\?\"" + _UUID,
    r'"user_id"\s*:\s*"' + _UUID + r'"',
    r'\\+"user_id\\+"\s*:\s*\\+"' + _UUID + r'\\+"',
)

_SSO_COOKIE_NAMES = ("sso", "sso-rw", "sso-session", "sso-refresh-token")
_PRINCIPAL_COOKIE_NAMES = ("x-userid", "x_userid", "userid", "user_id")


# ---- JSONL emit (lengths/prose only) ---------------------------------------

def emit(obj: dict) -> None:
    """Write one JSONL event to stdout and flush."""
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def emit_step(step: str, status: str = "ok", **extra: Any) -> None:
    payload = {"event": "step", "step": step, "status": status}
    payload.update(extra)
    emit(payload)


def emit_result(ok: bool, error: str | None = None, step: str | None = None) -> None:
    obj: dict[str, Any] = {"kind": "result", "ok": ok}
    # Also emit event=result shape so parseWorkerLine (legacy) accepts both.
    obj["event"] = "result"
    if error:
        obj["error"] = error
    if step:
        obj["step"] = step
    emit(obj)


# ---- principal_id extraction (pure; tested by test_principal.py) ----------

def extract_user_id_from_text(text: str | None) -> str | None:
    """Pull a userId/principal_id UUID out of HTML / RSC flight / JSON text.

    Consent pages usually embed the signed-in user as heavily-escaped RSC
    JSON (\\"userId\\":\\"uuid\\"). createUser responses sometimes do too.
    Returns the first match or None. Does not log the value.
    """
    if not text:
        return None
    for pat in _USER_ID_PATTERNS:
        m = re.search(pat, text)
        if m and m.group(1):
            return m.group(1)
    return None


def extract_user_id_from_cookies(cookies: Any) -> str | None:
    """Read principal UUID from cookie jar / mapping (x-userid etc.).

    GAC captures show x-userid on .grok.com as the plain UUID. curl_cffi
    cookies support .get(name); plain dicts work too. Value must look like
    a UUID — never treat session JWTs as user ids.
    """
    if cookies is None:
        return None

    def _get(name: str) -> str | None:
        try:
            if hasattr(cookies, "get"):
                v = cookies.get(name)
                if v:
                    return str(v)
        except Exception:
            pass
        try:
            # mapping-like
            if name in cookies:  # type: ignore[operator]
                return str(cookies[name])  # type: ignore[index]
        except Exception:
            pass
        # curl_cffi / requests sometimes need domain-less iteration
        try:
            if hasattr(cookies, "items"):
                for k, v in cookies.items():
                    if str(k).lower() == name.lower() and v:
                        return str(v)
        except Exception:
            pass
        return None

    for name in _PRINCIPAL_COOKIE_NAMES:
        val = _get(name)
        if not val:
            continue
        m = re.fullmatch(_UUID, val.strip())
        if m:
            return m.group(1)
    return None


def extract_user_id_from_set_cookie_urls(text: str | None) -> str | None:
    """Decode auth.*.com/set-cookie?q=JWT middle segment for a user id.

    The JWT payload is a config blob (success_url, …). Walk nested dicts
    for keys that look like userId / principal_id / user_id.
    """
    if not text:
        return None
    norm = (
        text.replace("\\/", "/")
        .replace("\\u0026", "&")
        .replace("\\u003d", "=")
        .replace("\\u003f", "?")
        .replace("\\u002F", "/")
        .replace("\\u003A", ":")
    )
    norm = unquote(norm)
    urls = re.findall(
        r"https://auth\.(?:grokipedia|grokusercontent)\.com/set-cookie\?q=[A-Za-z0-9_\-\.]+",
        norm,
    )
    keys_of_interest = {
        "userid",
        "user_id",
        "userId",
        "principal_id",
        "principalId",
        "principalid",
    }

    def walk(obj: Any) -> str | None:
        if isinstance(obj, dict):
            for k, v in obj.items():
                if str(k) in keys_of_interest or str(k).lower() in {
                    "userid",
                    "user_id",
                    "principal_id",
                    "principalid",
                }:
                    if isinstance(v, str) and re.fullmatch(_UUID, v.strip()):
                        return v.strip()
                found = walk(v)
                if found:
                    return found
        elif isinstance(obj, list):
            for item in obj:
                found = walk(item)
                if found:
                    return found
        elif isinstance(obj, str) and re.fullmatch(_UUID, obj.strip()):
            # only accept bare UUIDs when parent key was checked above;
            # skip free-floating UUIDs to avoid conversionId noise.
            return None
        return None

    for u in urls:
        try:
            q = u.split("q=", 1)[1]
            part = q.split(".")[1]
            part += "=" * ((4 - len(part) % 4) % 4)
            cfg = json.loads(base64.urlsafe_b64decode(part))
            found = walk(cfg)
            if found:
                return found
        except Exception:
            continue
    return None


def resolve_principal_id(
    *,
    consent_html: str | None = None,
    cookies: Any = None,
    create_user_body: str | None = None,
    known: str | None = None,
) -> tuple[str | None, str | None]:
    """Multi-source principal_id resolution.

    Order:
      1. known (already cached on the session)
      2. consent HTML (RSC flight / form field)
      3. cookies (x-userid)
      4. createUser response body
      5. set-cookie JWT config inside createUser body

    Returns (user_id, source) where source is a short label for debug
    events (never includes the id itself beyond the return value).
    """
    if known and re.fullmatch(_UUID, known.strip()):
        return known.strip(), "cached"

    uid = extract_user_id_from_text(consent_html)
    if uid:
        return uid, "consent_html"

    uid = extract_user_id_from_cookies(cookies)
    if uid:
        return uid, "cookie"

    uid = extract_user_id_from_text(create_user_body)
    if uid:
        return uid, "create_user_body"

    uid = extract_user_id_from_set_cookie_urls(create_user_body)
    if uid:
        return uid, "set_cookie_jwt"

    # Last-ditch: set-cookie URLs may also appear on the consent page itself.
    uid = extract_user_id_from_set_cookie_urls(consent_html)
    if uid:
        return uid, "consent_set_cookie_jwt"

    return None, None


# ---- OTP extraction (pure; tested by test_otp.py) --------------------------

_OTP_NOISE = {"per-100", "rgb-255", "max-age"}

_OTP_PATTERNS = [
    r"\b([A-Z0-9]{3}-[A-Z0-9]{3})\s+xAI\b",
    r"(?:SpaceXAI|xAI)\s+confirmation\s+code[:\s]+([A-Z0-9]{3}-[A-Z0-9]{3})\b",
    r"confirmation\s+code[:\s]+([A-Z0-9]{3}-[A-Z0-9]{3})\b",
    r"\b([A-Z0-9]{3}-[A-Z0-9]{3})\b",
]


def extract_otp(text: str = "", subject: str = "") -> str | None:
    """Return the xAI 'XXX-XXX' code from subject/body, or None.

    Subject is checked first. CSS/HTML noise (per-100, rgb-255, max-age) is
    rejected. The returned code is uppercase with a dash.
    """
    haystacks = []
    if subject:
        haystacks.append(subject)
    if text:
        haystacks.append(text)
    for hay in haystacks:
        for pat in _OTP_PATTERNS:
            m = re.search(pat, hay or "", re.IGNORECASE)
            if not m:
                continue
            code = m.group(1).upper()
            if re.fullmatch(r"[A-Z0-9]{3}-[A-Z0-9]{3}", code) and code.lower() not in _OTP_NOISE:
                return code
    return None


def _decode_subject(raw: str) -> str:
    try:
        from email.header import decode_header

        out = []
        for part, enc in decode_header(raw or ""):
            if isinstance(part, bytes):
                out.append(part.decode(enc or "utf-8", errors="replace"))
            else:
                out.append(part)
        return "".join(out)
    except Exception:
        return str(raw or "")


def _strip_html(s: str) -> str:
    s = re.sub(r"<(style|script)[^>]*>.*?</\1>", " ", s or "", flags=re.S | re.I)
    s = re.sub(r"<[^>]+>", " ", s)
    return html.unescape(s)


def extract_otp_from_message(raw_bytes: bytes) -> str | None:
    """Parse RFC822 bytes -> OTP code (or None). Pure (no network)."""
    try:
        msg = emaillib.message_from_bytes(raw_bytes)
    except Exception:
        return None
    subj = _decode_subject(msg.get("Subject", ""))
    code = extract_otp("", subj)
    if code:
        return code
    body = ""
    for part in msg.walk():
        ct = part.get_content_type()
        if ct == "text/html":
            try:
                body = _strip_html(part.get_payload(decode=True).decode(errors="replace"))
            except Exception:
                body = ""
            break
        if ct == "text/plain" and not body:
            try:
                body = part.get_payload(decode=True).decode(errors="replace")
            except Exception:
                body = ""
    return extract_otp(body, subj)


# ---- IMAP fetcher ----------------------------------------------------------

def _mailbox_for(host: str) -> str:
    """Primary mailbox for host (compat helper for tests / callers).

    Prefer :func:`_mailboxes_for` — Gmail must search INBOX + Spam, not only
    All Mail (locale-dependent name; SELECT often returns NO).
    """
    return _mailboxes_for(host)[0]


def _mailboxes_for(host: str) -> list[str]:
    """Ordered mailboxes to search. Mirrors src/services/imap-otp.js.

    imaplib does not auto-quote args (Python 3.12+), so names with spaces /
    brackets are returned pre-quoted for the wire. INBOX is never quoted.
    """
    h = (host or "").lower()
    if h.endswith("gmail.com"):
        # All Mail is locale-dependent ("Semua Mail", etc.) and often NO's.
        # Forwarded xAI OTPs commonly land in Spam — search both.
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
    delay: float = 3.0,
) -> str | None:
    """Poll IMAP for the xAI code addressed to target_email. Returns code|None.

    `cfg` = {host, port, user, password, tls, delete_after_read, subject, sender_domain}.
    Network failures are logged as debug events and retried (no value logged).
    """
    host = cfg["host"]
    port = int(cfg["port"])
    user = cfg["user"]
    pw = cfg["password"]
    use_tls = str(cfg.get("tls", "true")).lower() == "true"
    delete_after = str(cfg.get("delete_after_read", "false")).lower() == "true"
    sender_domain = (cfg.get("sender_domain") or "x.ai").strip() or "x.ai"
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


# ---- user_code extraction from sign-in URL ---------------------------------

def user_code_from_signin_url(url: str) -> str:
    """Extract user_code from GROK_SIGNIN_URL (embedded in return_to)."""
    if not url:
        raise RuntimeError("GROK_SIGNIN_URL missing")
    # Direct query
    qs = parse_qs(urlparse(url).query)
    if "user_code" in qs and qs["user_code"]:
        return qs["user_code"][0]
    # Nested in return_to=...user_code=XXXX
    return_to = qs.get("return_to", [None])[0]
    if return_to:
        inner = unquote(return_to)
        m = re.search(r"user_code=([A-Za-z0-9\-]+)", inner)
        if m:
            return m.group(1)
    # Last resort: any user_code= in the whole string
    m = re.search(r"user_code=([A-Za-z0-9\-]+)", unquote(url))
    if m:
        return m.group(1)
    raise RuntimeError("user_code not found in GROK_SIGNIN_URL")


# ---- Turnstile via local solver :8877 --------------------------------------

def discover_next_action(session: Any, page_url: str = SIGNUP_URL) -> str:
    """Scrape the current createUser next-action id from the sign-up page JS.

    Next.js binds server actions as:
      createServerReference)("HASH", callServer, ...)
    The HASH rotates on every deploy; hardcoding it yields HTTP 404
    "Server action not found". Prefer the id co-located with
    createUserAndSession in the same chunk.
    """
    try:
        # xAI CF blocks a plain GET without browser-like headers + TLS
        # impersonate (403 "Attention Required" / 5.8KB stub) — mirror the
        # bootstrap request: UA + Accept + impersonate.
        ua = getattr(session, "ua", None) or UA_FALLBACK
        imp = getattr(session, "impersonate", None) or "chrome131"
        r = session.get(
            page_url,
            headers={"User-Agent": ua, "Accept": "text/html"},
            impersonate=imp,
            **{"timeout": 30},
        )
        html = r.text or ""
    except Exception as e:
        emit({"event": "debug", "msg": "discover_action_page_fail", "error": str(e)[:100]})
        return NEXT_ACTION_CREATE_USER

    srcs = list(
        dict.fromkeys(
            re.findall(r'/_next/static/[^"\']+\.js', html)
        )
    )
    # Prefer chunks that also mention createUserAndSession; fall back to any ref.
    preferred: list[str] = []
    fallback: list[str] = []
    for src in srcs:
        try:
            jr = session.get(
                "https://accounts.x.ai" + src,
                headers={"User-Agent": ua, "Accept": "*/*"},
                impersonate=imp,
                **{"timeout": 30},
            )
            text = jr.text or ""
        except Exception:
            continue
        refs = re.findall(
            r'createServerReference\)\(\s*["\']([a-f0-9]{40,44})["\']',
            text,
        )
        if not refs:
            continue
        if "createUserAndSession" in text or "emailValidationCode" in text:
            preferred.extend(refs)
        else:
            fallback.extend(refs)

    chosen = (preferred or fallback or [None])[0]
    if chosen:
        emit(
            {
                "event": "debug",
                "msg": "discover_action",
                "action_len": len(chosen),
                "preferred": bool(preferred),
            }
        )
        return chosen
    emit({"event": "debug", "msg": "discover_action_miss", "chunks": len(srcs)})
    return NEXT_ACTION_CREATE_USER


def solve_turnstile(url: str = SIGNUP_URL, sitekey: str = TURNSTILE_SITEKEY, retries: int = 3) -> str:
    """POST local solver :8877/solve for a Turnstile token."""
    import urllib.error
    import urllib.request

    last_err = "no attempts"
    for attempt in range(max(1, retries)):
        t0 = time.time()
        try:
            payload = json.dumps(
                {
                    "type": "turnstile",
                    "url": url,
                    "sitekey": sitekey,
                }
            ).encode()
            req = urllib.request.Request(
                f"{SOLVER_URL}/solve",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=90) as r:
                data = json.loads(r.read())
            tok = data.get("token") or (data.get("solution") or {}).get("token") or ""
            if data.get("solved") and tok and len(tok) > 50:
                emit_step("turnstile", "ok", ms=int((time.time() - t0) * 1000), attempt=attempt + 1)
                return tok
            if tok and len(tok) > 100:
                emit_step("turnstile", "ok", ms=int((time.time() - t0) * 1000), attempt=attempt + 1)
                return tok
            last_err = data.get("error") or f"unsolved keys={list(data)[:6]}"
        except urllib.error.HTTPError as e:
            try:
                last_err = e.read().decode()[:200]
            except Exception:
                last_err = f"HTTP {e.code}"
        except Exception as e:
            last_err = str(e)[:200]
        time.sleep(1.0 + attempt)
    raise RuntimeError(f"turnstile-solve-failed: {last_err}")


# ---- XaiSession (pure-HTTP) ------------------------------------------------

class XaiSession:
    def __init__(
        self,
        email: str,
        password: str,
        first: str,
        last: str,
        signin_url: str,
        proxy: str | None = None,
        impersonate: str = "chrome131",
    ):
        self.s = _ensure_creq().Session()
        self.impersonate = impersonate
        self.ua = UA_FALLBACK
        self.email = email
        self.password = password
        self.first = first
        self.last = last
        self.signin_url = signin_url
        self.proxy = proxy
        self.user_code = user_code_from_signin_url(signin_url)
        # Cached principal_id (userId UUID) harvested during createUser / warm.
        self.principal_id: str | None = None
        # Last createUser response body (for multi-source principal fallback).
        self._create_user_body: str | None = None

    def _req_kw(self, **extra) -> dict:
        kw = {"impersonate": self.impersonate, **extra}
        if self.proxy:
            kw["proxy"] = self.proxy
        return kw

    def _headers(self, extra: dict | None = None) -> dict:
        h = {
            "User-Agent": self.ua,
            "Accept": "*/*",
            "Origin": "https://accounts.x.ai",
            "Referer": SIGNUP_URL,
        }
        if extra:
            h.update(extra)
        return h

    def bootstrap_cf(self) -> None:
        """Bootstrap session cookies for accounts.x.ai (pure-HTTP: plain GET)."""
        r = self.s.get(
            SIGNUP_URL,
            headers={"User-Agent": self.ua, "Accept": "text/html"},
            **self._req_kw(timeout=45),
        )
        if r.status_code != 200 or "Attention Required" in (r.text or ""):
            raise RuntimeError(f"signup blocked status={r.status_code}")
        emit_step("bootstrap", "ok", status_code=r.status_code)

    def grpc(self, url: str, body: bytes) -> tuple[int, bytes, dict]:
        r = self.s.post(
            url,
            data=body,
            headers=self._headers(
                {
                    "Content-Type": "application/grpc-web+proto",
                    "x-grpc-web": "1",
                    "x-user-agent": "connect-es/2.1.1",
                    "Accept": "application/grpc-web+proto",
                }
            ),
            **self._req_kw(timeout=45),
        )
        return r.status_code, r.content, {k.lower(): v for k, v in r.headers.items()}

    def create_email_code(self, castle: str = "") -> dict:
        body = build_create_email_validation_code(self.email, castle)
        status, raw, headers = self.grpc(CREATE_EMAIL, body)
        payload = unwrap_grpc_web(raw)
        fields = parse_fields(payload) if payload else []
        if status >= 400:
            raise RuntimeError(f"CreateEmailValidationCode HTTP {status}")
        grpc_status = headers.get("grpc-status")
        if grpc_status and str(grpc_status) not in ("0", "0.0"):
            raise RuntimeError(
                f"CreateEmailValidationCode grpc-status={grpc_status} "
                f"msg={headers.get('grpc-message')}"
            )
        emit_step("create_email_code", "ok", fields=len(fields))
        return {"status": status, "fields": fields, "headers": headers}

    def verify_email_code(self, code: str) -> dict:
        # API may accept HPN-7Z9 or HPN7Z9 — try as-is first, then stripped
        candidates = [code]
        stripped = code.replace("-", "").replace(" ", "")
        if stripped != code:
            candidates.append(stripped)
        last_err = None
        for c in candidates:
            body = build_verify_email_validation_code(self.email, c)
            status, raw, headers = self.grpc(VERIFY_EMAIL, body)
            grpc_status = headers.get("grpc-status")
            if raw and b"grpc-status:0" in raw and not grpc_status:
                grpc_status = "0"
            if status >= 400:
                last_err = f"HTTP {status}"
                continue
            if grpc_status and str(grpc_status) not in ("0", "0.0"):
                last_err = f"grpc={grpc_status} msg={headers.get('grpc-message')}"
                continue
            emit_step("verify_email_code", "ok")
            return {"status": status, "code_used": c}
        raise RuntimeError(f"Verify failed: {last_err}")

    def validate_password(self) -> None:
        body = build_validate_password(self.email, self.password)
        status, raw, _ = self.grpc(VALIDATE_PW, body)
        emit({"event": "debug", "msg": "validate_password", "status": status, "body_len": len(raw)})

    def create_user(
        self,
        code: str,
        turnstile: str,
        castle: str = "",
        action_id: str | None = None,
    ) -> dict:
        conversion_id = str(uuid.uuid4())
        action = action_id or NEXT_ACTION_CREATE_USER
        payload = [
            {
                "emailValidationCode": code,
                "createUserAndSessionRequest": {
                    "email": self.email,
                    "givenName": self.first,
                    "familyName": self.last,
                    "clearTextPassword": self.password,
                    "tosAcceptedVersion": 1,
                },
                "turnstileToken": turnstile,
                "conversionId": conversion_id,
                "castleRequestToken": castle,
            },
            {"client": "$T", "meta": "$undefined", "mutationKey": "$undefined"},
        ]
        router_tree = quote(
            '["",{"children":["(app)",{"children":["(auth)",{"children":["sign-up",'
            '{"children":["__PAGE__",{},null,null]},null,null]},null,null]},null,null]},'
            "null,null,true]",
            safe="",
        )
        def _post(act: str) -> Any:
            return self.s.post(
                SIGNUP_URL,
                data=json.dumps(payload, separators=(",", ":")),
                headers=self._headers(
                    {
                        "Accept": "text/x-component",
                        "Content-Type": "text/plain;charset=UTF-8",
                        "next-action": act,
                        "next-router-state-tree": router_tree,
                    }
                ),
                **self._req_kw(timeout=60),
            )

        r = _post(action)
        # 404 "Server action not found." == the hash rotated (xAI redeploys
        # often, and discover_next_action() silently falls back to the baked-in
        # constant when scraping misses). Re-scrape once and retry rather than
        # failing the whole signup on a stale id.
        if r.status_code == 404:
            fresh = discover_next_action(self.s)
            emit({
                "event": "debug",
                "msg": "create_user_action_rotated",
                "stale_action": action[:12],
                "fresh_action": (fresh or "")[:12],
                "changed": bool(fresh and fresh != action),
            })
            if fresh and fresh != action:
                r = _post(fresh)

        text = r.text if r.text else ""
        if r.status_code >= 400:
            hint = (
                " (next-action hash is stale and re-discovery failed —"
                " check discover_next_action against the live sign-up page)"
                if r.status_code == 404
                else ""
            )
            raise RuntimeError(f"createUser HTTP {r.status_code}: {text[:300]}{hint}")

        if "ExistingEmailSignInMethods" in text or "ExistingUserWithEmail" in text:
            raise RuntimeError("createUser existing email")

        # Next.js RSC action errors: 1:{"error":"...","traceId":"..."}
        first_json_err = None
        for line in text.splitlines()[:30]:
            line = line.strip()
            if not line:
                continue
            payload_line = line
            if len(line) > 2 and line[0].isdigit() and line[1] == ":":
                payload_line = line[2:]
            if not (payload_line.startswith("{") and '"error"' in payload_line):
                continue
            try:
                obj = json.loads(payload_line)
            except Exception:
                continue
            if isinstance(obj, dict) and obj.get("error") and obj.get("error") != "$undefined":
                if "traceId" in obj or "Failed" in str(obj.get("error")) or "[internal]" in str(
                    obj.get("error")
                ):
                    first_json_err = str(obj["error"])
                    break
        if first_json_err:
            raise RuntimeError(f"createUser action error: {first_json_err}")

        self._create_user_body = text
        # Harvest principal early from createUser body / set-cookie JWT if present.
        early_uid, early_src = resolve_principal_id(create_user_body=text)
        if early_uid:
            self.principal_id = early_uid
            emit(
                {
                    "event": "debug",
                    "msg": "principal_cached",
                    "source": early_src,
                    "id_prefix": early_uid[:8],
                }
            )

        sso = self._establish_sso_from_create_response(text)
        emit_step("create_user", "ok", cookies=list(dict.fromkeys(self.s.cookies.keys())))
        return {
            "status": r.status_code,
            "sso": sso,
            "cookies": list(dict.fromkeys(self.s.cookies.keys())),
            "full_body": text,
        }

    def _cookie_names(self) -> list[str]:
        return list(dict.fromkeys(self.s.cookies.keys()))

    def _has_sso(self, names: list[str] | None = None) -> bool:
        names = names if names is not None else self._cookie_names()
        return any(n in names for n in _SSO_COOKIE_NAMES)

    def _has_sso_pair(self, names: list[str] | None = None) -> bool:
        """Prefer both session + refresh cookies when available (more durable bind)."""
        names = names if names is not None else self._cookie_names()
        return ("sso" in names or "sso-session" in names) and (
            "sso-rw" in names or "sso-refresh-token" in names
        )

    def _warm_account_session(self) -> dict:
        """Hit /account (+ optional grok.com) to materialize sso-rw / x-userid.

        After set-cookie chain, some runs only have `sso` and the consent
        page then omits userId. google_login warms /account for the same
        reason. Best-effort — never raises.
        """
        out: dict[str, Any] = {"ok": False, "steps": []}
        before = self._cookie_names()
        out["cookies_before"] = before

        for url, label in ((ACCOUNT_URL, "account"), (GROK_HOME, "grok")):
            try:
                rr = self.s.get(
                    url,
                    headers=self._headers(
                        {
                            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                            "Referer": SIGNUP_URL,
                            "Upgrade-Insecure-Requests": "1",
                        }
                    ),
                    **self._req_kw(timeout=45, allow_redirects=True),
                )
                body = rr.text or ""
                out["steps"].append(
                    {
                        "label": label,
                        "status": rr.status_code,
                        "url": str(rr.url)[:160],
                        "len": len(body),
                    }
                )
                # Account / grok pages may embed userId in RSC flight.
                if not self.principal_id:
                    uid = extract_user_id_from_text(body)
                    if uid:
                        self.principal_id = uid
                        emit(
                            {
                                "event": "debug",
                                "msg": "principal_cached",
                                "source": f"warm_{label}",
                                "id_prefix": uid[:8],
                            }
                        )
            except Exception as e:
                out["steps"].append({"label": label, "error": str(e)[:120]})

            # Cookie-side principal (x-userid often lands on .grok.com).
            if not self.principal_id:
                uid = extract_user_id_from_cookies(self.s.cookies)
                if uid:
                    self.principal_id = uid
                    emit(
                        {
                            "event": "debug",
                            "msg": "principal_cached",
                            "source": "cookie_after_warm",
                            "id_prefix": uid[:8],
                        }
                    )

            names = self._cookie_names()
            if self._has_sso_pair(names) or extract_user_id_from_cookies(self.s.cookies):
                # Good enough — stop after account if we already have pair/userid.
                if label == "account":
                    # Still try grok.com once for x-userid domain if missing.
                    if extract_user_id_from_cookies(self.s.cookies):
                        break
                    continue
                break

        after = self._cookie_names()
        out["cookies_after"] = after
        out["ok"] = self._has_sso(after)
        out["has_pair"] = self._has_sso_pair(after)
        out["has_x_userid"] = bool(extract_user_id_from_cookies(self.s.cookies))
        emit(
            {
                "event": "debug",
                "msg": "session_warm",
                "ok": out["ok"],
                "has_pair": out["has_pair"],
                "has_x_userid": out["has_x_userid"],
                "cookies": after,
                "steps": len(out["steps"]),
            }
        )
        return out

    def _establish_sso_from_create_response(self, text: str) -> dict:
        """Follow set-cookie chain URLs from createUser response to collect SSO cookies."""
        out: dict[str, Any] = {"ok": False, "urls": [], "final": None, "cookies": []}
        raw = text or ""
        norm = (
            raw.replace("\\/", "/")
            .replace("\\u0026", "&")
            .replace("\\u003d", "=")
            .replace("\\u003f", "?")
            .replace("\\u002F", "/")
            .replace("\\u003A", ":")
        )
        norm = unquote(norm)
        urls = re.findall(
            r"https://auth\.(?:grokipedia|grokusercontent)\.com/set-cookie\?q=[A-Za-z0-9_\-\.]+",
            norm,
        )
        nested: list[str] = []
        for u in urls:
            try:
                q = u.split("q=", 1)[1]
                part = q.split(".")[1]
                part += "=" * ((4 - len(part) % 4) % 4)
                cfg = json.loads(base64.urlsafe_b64decode(part))
                su = (cfg.get("config") or cfg).get("success_url")
                if su and su.startswith("http"):
                    nested.append(su)
            except Exception:
                pass
        ordered: list[str] = []
        for u in urls + nested:
            if u not in ordered:
                ordered.append(u)
        ordered.sort(key=lambda u: (0 if "grokusercontent" in u else 1, u))
        out["urls"] = [u[:120] for u in ordered]

        def _follow(url_list: list[str]) -> None:
            for u in url_list:
                try:
                    rr = self.s.get(
                        u,
                        headers=self._headers(
                            {
                                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                                "Referer": SIGNUP_URL,
                                "Upgrade-Insecure-Requests": "1",
                            }
                        ),
                        **self._req_kw(timeout=45, allow_redirects=True),
                    )
                    out["final"] = str(rr.url)[:200]
                    out.setdefault("attempts", []).append(
                        {
                            "host": u.split("/")[2],
                            "status": rr.status_code,
                            "final": str(rr.url)[:120],
                        }
                    )
                except Exception as e:
                    out.setdefault("attempts", []).append(
                        {"url": u[:80], "error": str(e)[:120]}
                    )
                    continue

        _follow(ordered)

        cookie_names = self._cookie_names()
        # Incomplete bind (only sso, no sso-rw) → re-hit set-cookie once + warm.
        if self._has_sso(cookie_names) and not self._has_sso_pair(cookie_names) and ordered:
            emit({"event": "debug", "msg": "sso_incomplete_retry", "cookies": cookie_names})
            _follow(ordered)

        # Always warm /account (and maybe grok.com) so x-userid / sso-rw materialize.
        warm = self._warm_account_session()
        out["warm"] = {
            "ok": warm.get("ok"),
            "has_pair": warm.get("has_pair"),
            "has_x_userid": warm.get("has_x_userid"),
        }

        cookie_names = self._cookie_names()
        out["cookies"] = cookie_names
        has_sso = self._has_sso(cookie_names)
        out["ok"] = has_sso
        out["has_pair"] = self._has_sso_pair(cookie_names)
        emit_step(
            "sso",
            "ok" if has_sso else "fail",
            cookies=cookie_names,
            has_pair=out["has_pair"],
            has_x_userid=bool(extract_user_id_from_cookies(self.s.cookies)),
        )
        if not has_sso:
            raise RuntimeError(f"createUser OK but SSO cookies missing: cookies={cookie_names}")
        return out

    def try_device_consent(self, user_code: str | None = None) -> dict:
        """Approve device code with SSO cookies via real form endpoints."""
        user_code = user_code or self.user_code
        # normalize display form XXXX-XXXX
        raw = user_code.replace("-", "").replace(" ", "").strip().upper()
        if len(raw) == 8:
            user_code = raw[:4] + "-" + raw[4:]
        else:
            user_code = user_code.strip().upper()

        result: dict[str, Any] = {"user_code": user_code, "approved": False}

        # 1) open device page
        r = self.s.get(
            f"{DEVICE_PAGE}?user_code={user_code}",
            headers=self._headers({"Accept": "text/html", "Referer": SIGNUP_URL}),
            **self._req_kw(timeout=45, allow_redirects=True),
        )
        result["device_get"] = {"status": r.status_code, "url": str(r.url)[:160]}

        # 2) verify user_code
        verify_url = "https://auth.x.ai/oauth2/device/verify"
        rv = self.s.post(
            verify_url,
            data={"user_code": user_code},
            headers=self._headers(
                {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Origin": "https://accounts.x.ai",
                    "Referer": f"{DEVICE_PAGE}?user_code={user_code}",
                    "Upgrade-Insecure-Requests": "1",
                }
            ),
            **self._req_kw(timeout=45, allow_redirects=True),
        )
        result["verify"] = {
            "status": rv.status_code,
            "url": str(rv.url)[:200],
            "history": [f"{h.status_code}:{str(h.url)[:80]}" for h in (rv.history or [])],
        }
        if "device/done" in str(rv.url).lower():
            result["approved"] = True
            result["cookies"] = self._cookie_names()
            emit_step("device_consent", "ok", approved=True, via="verify-redirect")
            return result

        # 3) consent page — extract principal_id (multi-source)
        consent_url = f"{DEVICE_CONSENT_URL}?user_code={user_code}"
        if "device/consent" in str(rv.url) and rv.status_code == 200:
            rc = rv
        else:
            rc = self.s.get(
                consent_url,
                headers=self._headers({"Accept": "text/html", "Referer": str(rv.url)}),
                **self._req_kw(timeout=45, allow_redirects=True),
            )
        html_body = rc.text or ""
        result["consent_get"] = {
            "status": rc.status_code,
            "url": str(rc.url)[:200],
            "len": len(html_body),
        }

        # What principal does this page actually offer? A successful token
        # carries a team_id, and the approve POST hardcodes principal_type=User
        # — if xAI now expects a Team principal (or the account has no team),
        # approve returns 200/device-done but the token exchange answers
        # invalid_grant "Access denied". Emit shape only, never the ids.
        try:
            _low = html_body.lower()
            emit({
                "event": "debug",
                "msg": "consent_principals",
                "principal_types": sorted(set(re.findall(
                    r'principal_type["\']?\s*[:=]\s*["\']?(\w+)', html_body))),
                "principal_id_fields": len(re.findall(
                    r'name=["\']principal_id["\']', html_body)),
                "mentions_team": "team" in _low,
                "team_id_present": bool(re.search(r'team_?id', html_body, re.I)),
                "mentions_workspace": "workspace" in _low,
                "consent_len": len(html_body),
            })
        except Exception as e:
            emit({"event": "debug", "msg": "consent_principals_error", "error": str(e)[:120]})

        user_id, source = resolve_principal_id(
            consent_html=html_body,
            cookies=self.s.cookies,
            create_user_body=self._create_user_body,
            known=self.principal_id,
        )

        # One more warm + re-fetch consent if still missing (session bind race).
        if not user_id:
            emit({"event": "debug", "msg": "principal_miss_rewarm"})
            self._warm_account_session()
            try:
                rc = self.s.get(
                    consent_url,
                    headers=self._headers({"Accept": "text/html", "Referer": str(rv.url)}),
                    **self._req_kw(timeout=45, allow_redirects=True),
                )
                html_body = rc.text or ""
                result["consent_get_retry"] = {
                    "status": rc.status_code,
                    "url": str(rc.url)[:200],
                    "len": len(html_body),
                }
            except Exception as e:
                result["consent_get_retry"] = {"error": str(e)[:120]}
            user_id, source = resolve_principal_id(
                consent_html=html_body,
                cookies=self.s.cookies,
                create_user_body=self._create_user_body,
                known=self.principal_id,
            )

        result["principal_id"] = user_id
        result["principal_source"] = source
        result["principal_type"] = "User"
        if user_id:
            self.principal_id = user_id

        if not user_id:
            cookie_names = self._cookie_names()
            signed_in = (
                "Signed in as" in html_body or "signed in as" in html_body.lower()
            )
            result["error"] = "principal_id/userId not found on consent page"
            if not signed_in:
                result["error"] += " (no Signed-in banner — SSO may not bind to accounts.x.ai)"
            result["cookies"] = cookie_names
            # Diagnostics only — no secrets (cookie names, lengths, flags).
            emit(
                {
                    "event": "debug",
                    "msg": "principal_miss",
                    "consent_status": result["consent_get"].get("status"),
                    "consent_len": result["consent_get"].get("len"),
                    "signed_in_banner": signed_in,
                    "cookies": cookie_names,
                    "has_pair": self._has_sso_pair(cookie_names),
                    "has_x_userid": bool(extract_user_id_from_cookies(self.s.cookies)),
                    "cached_principal": bool(self.principal_id),
                }
            )
            emit_step("device_consent", "fail", error=result["error"])
            return result

        # 3b) The consent page carries its own principal_id hidden input, and
        # that value is authoritative: it is what the server rendered for THIS
        # signed-in session and THIS user_code. resolve_principal_id() puts
        # `known` (cached from createUser) first, so whenever the cache is
        # populated the page's value is never even read — approving for a
        # principal the grant does not belong to. The server still answers
        # 200 -> /device/done, and only the later token exchange rejects it
        # with invalid_grant "Access denied", which is why this looked like a
        # 9router problem. Prefer the page; fall back to the resolved id.
        # The page is a ~120KB Next.js RSC document, so principal_id lives in
        # the flight JSON, not an <input> tag — use the full pattern set.
        page_uid = extract_user_id_from_text(html_body)
        emit({
            "event": "debug",
            "msg": "principal_compare",
            "page_uid_found": bool(page_uid),
            "chosen_source": source,
            "matches_chosen": bool(page_uid) and page_uid == user_id,
        })
        if page_uid and page_uid != user_id:
            emit({
                "event": "debug",
                "msg": "principal_override",
                "from_source": source,
                "to_source": "consent_page",
            })
            user_id, source = page_uid, "consent_page"
        result["principal_source"] = source

        # 3c) Entitlement probe. The approve below succeeds (200 -> /device/done)
        # and the principal is verified correct, yet the token exchange answers
        # invalid_grant "Access denied" — xAI's own error_description, so the
        # grant is refused server-side rather than mis-sent. A token that DID
        # work (2026-07-24) carries a team_id, and this worker never creates or
        # joins a team. Record what the account page says about team/plan so
        # the hypothesis can be settled from a log instead of guessed at.
        try:
            racc = self.s.get(
                ACCOUNT_URL,
                headers=self._headers({"Accept": "text/html"}),
                **self._req_kw(timeout=30, allow_redirects=True),
            )
            acc = racc.text or ""
            acc_l = acc.lower()
            emit({
                "event": "debug",
                "msg": "account_entitlement",
                "status": racc.status_code,
                "url": str(racc.url)[:120],
                "len": len(acc),
                "mentions_team": "team" in acc_l,
                "mentions_workspace": "workspace" in acc_l,
                "team_uuid_found": bool(re.search(r'team_?id["\']?\s*[:=]\s*["\']?' + _UUID, acc, re.I)),
                "mentions_subscribe": "subscribe" in acc_l or "subscription" in acc_l,
                "mentions_free": "free" in acc_l,
                "mentions_verify": "verify" in acc_l or "verification" in acc_l,
            })
        except Exception as e:
            emit({"event": "debug", "msg": "account_entitlement_error", "error": str(e)[:120]})

        # 4) approve form POST
        approve_url = "https://auth.x.ai/oauth2/device/approve"
        ra = self.s.post(
            approve_url,
            data={
                "user_code": user_code,
                "action": "allow",
                "principal_type": "User",
                "principal_id": user_id,
            },
            headers=self._headers(
                {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Origin": "https://accounts.x.ai",
                    "Referer": str(rc.url),
                    "Upgrade-Insecure-Requests": "1",
                }
            ),
            **self._req_kw(timeout=45, allow_redirects=True),
        )
        body_head = (ra.text or "")[:400]
        result["approve"] = {
            "status": ra.status_code,
            "url": str(ra.url)[:200],
            "history": [f"{h.status_code}:{str(h.url)[:100]}" for h in (ra.history or [])],
            "body_head": body_head,
        }
        final = str(ra.url).lower()
        body_l = (ra.text or "").lower()
        body_short = (ra.text or "").strip()
        hard_session = (
            ra.status_code in (401, 403)
            or body_short.lower() == "session expired"
            or (
                len(body_short) < 80
                and "session expired" in body_short.lower()
                and "<html" not in body_l
            )
        )
        if hard_session:
            result["approved"] = False
            result["error"] = result.get("error") or f"approve {ra.status_code}: {body_head[:60]}"
        elif "device/done" in final:
            result["approved"] = True
        elif "device authorized" in body_l or "has been authorized" in body_l:
            result["approved"] = True
        elif (
            ra.status_code < 400
            and "device/consent" not in final
            and "error=" not in final
            and "sign-in" not in final
            and "login" not in final
        ):
            result["approved"] = True
            result["approve_soft"] = True

        # 5) hit done page (best-effort)
        try:
            rd = self.s.get(
                DEVICE_DONE_URL,
                headers=self._headers({"Accept": "text/html"}),
                **self._req_kw(timeout=30, allow_redirects=True),
            )
            result["done"] = {"status": rd.status_code, "url": str(rd.url)[:160]}
        except Exception as e:
            result["done"] = {"error": str(e)[:120]}

        # 6) verify a SOFT approval actually took.
        #
        # approve_soft fires whenever the response merely fails to look like an
        # error page, which is a guess, not a confirmation — and the token
        # endpoint then answers `invalid_grant / Access denied` (note: NOT
        # authorization_pending, i.e. the grant was rejected outright, so the
        # approve POST did not register). Re-fetch the consent page: if it
        # still offers the approve form, the device is not authorized.
        # Only ever downgrades the guess — hard signals above are left alone.
        if result.get("approved") and result.get("approve_soft"):
            try:
                rv = self.s.get(
                    f"{DEVICE_CONSENT_URL}?user_code={user_code}",
                    headers=self._headers({"Accept": "text/html"}),
                    **self._req_kw(timeout=30, allow_redirects=True),
                )
                vb = (rv.text or "").lower()
                still_pending = (
                    "device/approve" in vb
                    or 'name="user_code"' in vb
                    or 'value="allow"' in vb
                )
                result["verify"] = {
                    "status": rv.status_code,
                    "url": str(rv.url)[:160],
                    "still_pending": still_pending,
                }
                if still_pending:
                    result["approved"] = False
                    result["error"] = (
                        "approve-not-effective: consent page still pending after allow"
                    )
            except Exception as e:
                result["verify"] = {"error": str(e)[:120]}

        result["cookies"] = self._cookie_names()
        emit_step(
            "device_consent",
            "ok" if result.get("approved") else "fail",
            approved=bool(result.get("approved")),
            principal_id=user_id,
            principal_source=source,
            # Surfaced so a run can be diagnosed without the full worker log:
            # "approved" alone hid whether it was confirmed or merely guessed.
            approve_soft=bool(result.get("approve_soft")),
            approve_status=(result.get("approve") or {}).get("status"),
            approve_url=(result.get("approve") or {}).get("url"),
            verify=result.get("verify"),
            error=result.get("error"),
        )
        return result


# ---- pipeline --------------------------------------------------------------

def imap_cfg_from_env() -> dict:
    return {
        "host": os.getenv("GROK_IMAP_HOST", "imap.gmail.com"),
        "port": os.getenv("GROK_IMAP_PORT", "993"),
        "user": os.getenv("GROK_IMAP_USER", ""),
        "password": os.getenv("GROK_IMAP_PASSWORD", ""),
        "tls": os.getenv("GROK_IMAP_TLS", "true"),
        "delete_after_read": os.getenv("GROK_IMAP_DELETE_AFTER_READ", "true"),
        "subject": os.getenv("GROK_OTP_SUBJECT", ""),
        "sender_domain": os.getenv("GROK_OTP_SENDER_DOMAIN", "x.ai"),
    }


def run() -> int:
    email = (os.getenv("GROK_EMAIL") or "").strip()
    password = os.getenv("GROK_PASSWORD") or ""
    first = (os.getenv("GROK_FIRST") or "Alex").strip() or "Alex"
    last = (os.getenv("GROK_LAST") or "Rivera").strip() or "Rivera"
    signin_url = os.getenv("GROK_SIGNIN_URL") or ""
    proxy = (os.getenv("GROK_PROXY") or "").strip() or None

    if not email or not password:
        emit_result(False, error="missing-email-or-password", step="init")
        return 1
    if not signin_url:
        emit_result(False, error="missing-signin-url", step="init")
        return 1

    email_source = (os.getenv("GROK_EMAIL_SOURCE", "imap") or "imap").strip().lower()

    box = None  # only used in tempmail mode
    if email_source == "tempmail":
        # Temp-mail mode: create mailbox address, defer OTP wait until after
        # create_email_code sends the email.
        step = "tempmail_init"
        emit({"event": "step", "step": "tempmail_init", "status": "ok"})
        from tempmail import EmailBox  # lazy import (needs curl_cffi)
        box = EmailBox()
        addr = box.create_account()
        emit({"event": "step", "step": "tempmail_create", "status": "ok", "address": addr})
        email = addr
    else:
        # Traditional IMAP mode.
        imap_cfg = imap_cfg_from_env()
        if not imap_cfg["user"] or not imap_cfg["password"]:
            emit_result(False, error="missing-imap-config", step="init")
            return 1

    step = "init"
    try:
        xs = XaiSession(
            email=email,
            password=password,
            first=first,
            last=last,
            signin_url=signin_url,
            proxy=proxy,
        )
        emit(
            {
                "event": "debug",
                "msg": "start",
                "email_len": len(email),
                "user_code_len": len(xs.user_code or ""),
                "proxy": bool(proxy),
                "pure_http": True,
            }
        )

        step = "bootstrap"
        xs.bootstrap_cf()

        # Discover createUser next-action id early (rotates on deploy).
        action_id = discover_next_action(xs.s)

        # pure-HTTP: empty castle token is accepted today
        step = "create_email_code"
        xs.create_email_code(castle="")

        if email_source == "tempmail":
            step = "otp"
            code = box.wait_code(timeout=180)
            if not code:
                raise RuntimeError("tempmail-otp-timeout")
            emit({"event": "step", "step": "tempmail_otp", "status": "ok", "elapsed_s": 0})
        else:
            step = "otp"
            code = read_otp(email, imap_cfg)
            if not code:
                raise RuntimeError("otp-timeout")

        step = "verify_email_code"
        vres = xs.verify_email_code(code)
        code = vres.get("code_used") or code

        step = "turnstile"
        turnstile = solve_turnstile()

        # Optional password validation (soft)
        if os.getenv("SKIP_VALIDATE_PASSWORD", "1") != "1":
            try:
                xs.validate_password()
            except Exception as e:
                emit({"event": "debug", "msg": "validate_password_soft_fail", "error": str(e)[:120]})

        step = "create_user"
        xs.create_user(code, turnstile, castle="", action_id=action_id)

        step = "device_consent"
        consent = xs.try_device_consent()
        if not consent.get("approved"):
            err = consent.get("error") or "device-not-approved"
            raise RuntimeError(f"device-consent-failed: {err}")

        emit_result(True)
        return 0
    except Exception as e:
        err = str(e)[:300]
        # Never include password/OTP-like secrets; redact common keys
        err = re.sub(r"(password|otp|token|code)=[^\s&]+", r"\1=<redacted>", err, flags=re.I)
        emit_result(False, error=err, step=step)
        return 1


def main() -> int:
    # --check: validate imports + env shape without network
    if "--check" in sys.argv or "--self-test" in sys.argv:
        try:
            from curl_cffi import requests as _  # noqa: F401
            from proto_util import build_create_email_validation_code as _b  # noqa: F401

            emit({"event": "step", "step": "self_test", "status": "ok", "pure_http": True})
            emit_result(True)
            return 0
        except Exception as e:
            emit_result(False, error=f"self-test: {e}", step="self_test")
            return 1
    return run()


if __name__ == "__main__":
    raise SystemExit(main())
