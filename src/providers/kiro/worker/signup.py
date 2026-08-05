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
from email.utils import getaddresses
import hashlib
import html
import imaplib
import json
import os
import random
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


# ---- password encryption (signin SPA PasswordEncryptor port) ---------------
#
# The signin SPA encrypts new passwords before POSTing them:
#   [resultType, encrypted, errorLog] = await encryptPassword(pw, ctx)
# where ctx = workflowResponseData.encryptionContextResponse =
#   {publicKey: JWK, issuer, audience, region}.
# encryptPassword → new PasswordEncryptor(issuer, region)
#   .encrypt(publicKey, password, audience) → JWE compact serialization.
# On success the wire input for password *creation* (CreatePasswordPage.ce) is
#   {input_type: "PasswordRequestInput", password: <JWE>,
#    successfullyEncrypted: "SUCCESSFUL"}
# (ENCRYPTION_RESULT_TYPE enum: SUCCESSFUL | FAILED | NOT_APPLICABLE).
# UpdatePasswordRequestInput/newPassword is the *change*-password page — it
# needs currentPassword and 400s here (live-verified 2026-07-28).
#
# JWE layout (jose-jwe-jws via WebCrypto):
#   protected header: alg=RSA-OAEP-256, kid=<jwk.kid>, enc=A256GCM,
#                     cty="enc", typ="application/aws+signin+jwe"
#   claims: {iss, iat, nbf, jti, exp: iat+300, aud, password}
#     iss = region ? region + "." + issuer : issuer
#     aud = region ? region + "." + audience : audience
#
# WebCrypto's "RSA-OAEP-256" uses MGF1 with the SAME hash (SHA-256) — unlike
# RFC 7518's RSA-OAEP-256 (MGF1-SHA1). The server decrypts what browsers
# produce, so we mirror WebCrypto: OAEP(SHA-256, MGF1(SHA-256)).

_JWE_TYP = "application/aws+signin+jwe"
_JWE_PASSWORD_PERIOD = 300  # exp = iat + 300s (PASSWORD_PERIOD)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _jwk_to_public_key(jwk: dict) -> Any:
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

    n = int.from_bytes(base64.urlsafe_b64decode(jwk["n"] + "=" * (-len(jwk["n"]) % 4)), "big")
    e = int.from_bytes(base64.urlsafe_b64decode(jwk["e"] + "=" * (-len(jwk["e"]) % 4)), "big")
    return RSAPublicNumbers(e, n).public_key()


def _encrypt_password_jwe(password: str, ctx: dict) -> str:
    """Encrypt a password exactly like the signin SPA's PasswordEncryptor.

    Returns the JWE compact serialization. Raises on any crypto failure —
    callers fall back to the plaintext/NOT_APPLICABLE path (the SPA's own
    FAILED branch), which AWS accepts for some steps but not password
    creation.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    jwk = ctx["publicKey"]
    if jwk.get("alg") != "RSA-OAEP-256":
        raise ValueError(f"unsupported jwk alg: {jwk.get('alg')}")
    issuer = str(ctx.get("issuer") or "")
    audience = str(ctx.get("audience") or "")
    region = str(ctx.get("region") or "")

    protected = {
        "alg": "RSA-OAEP-256",
        "kid": jwk.get("kid", ""),
        "enc": "A256GCM",
        "cty": "enc",
        "typ": _JWE_TYP,
    }
    protected_b64 = _b64url(json.dumps(protected, separators=(",", ":")).encode())

    now = int(time.time())
    claims = {
        "iss": f"{region}.{issuer}" if region else issuer,
        "iat": now,
        "nbf": now,
        "jti": str(uuid.uuid4()),
        "exp": now + _JWE_PASSWORD_PERIOD,
        "aud": f"{region}.{audience}" if region else audience,
        "password": password,
    }
    plaintext = json.dumps(claims, separators=(",", ":")).encode()

    cek = os.urandom(32)  # A256GCM content-encryption key
    iv = os.urandom(12)  # 96-bit GCM nonce
    aad = protected_b64.encode("ascii")
    ct_and_tag = AESGCM(cek).encrypt(iv, plaintext, aad)
    ct, tag = ct_and_tag[:-16], ct_and_tag[-16:]

    pub = _jwk_to_public_key(jwk)
    encrypted_key = pub.encrypt(
        cek,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return ".".join([
        protected_b64,
        _b64url(encrypted_key),
        _b64url(iv),
        _b64url(ct),
        _b64url(tag),
    ])


def _build_password_input(password: str, encryption_context: dict | None) -> dict:
    """Build the PasswordRequestInput the SPA sends for ANY password step.

    Both the login page (get-password) and the creation page
    (get-new-password-for-password-creation) encrypt with the same
    PasswordEncryptor and send {input_type:"PasswordRequestInput",
    password:<jwe>, successfullyEncrypted, errorLog?} with actionId:SUBMIT.
    Plaintext survives only as the SPA's no-WebCrypto fallback
    (successfullyEncrypted NOT_APPLICABLE) — AWS 400s it on steps that
    require encryption (live-verified for creation and login 2026-07-28).
    """
    result_type = "NOT_APPLICABLE"
    error_log: str | None = None
    pw = password
    if encryption_context:
        try:
            pw = _encrypt_password_jwe(password, encryption_context)
            result_type = "SUCCESSFUL"
        except Exception as e:
            # Mirror the SPA's FAILED branch: plaintext + error name.
            result_type = "FAILED"
            error_log = type(e).__name__
            emit({"event": "debug", "msg": "password-encrypt-failed", "error": redact_err(e)})
    else:
        emit({"event": "debug", "msg": "password-encrypt-no-context"})
    inp: dict[str, Any] = {
        "input_type": _PASSWORD_INPUT_TYPE,
        "password": pw,
        "successfullyEncrypted": result_type,
    }
    if error_log:
        inp["errorLog"] = error_log
    return inp


# ---- constants (from Phase D0 endpoint map) --------------------------------

# Hardcoded capture workflowID is NOT durable — live IDs are minted per signup
# via the platform signin EMPTY→START handoff (see _mint_profile_workflow_id).
DIRECTORY_ID = "d-9067642ac7"
OIDC_CLIENT_ID = "0o3EowjdaDUHB9N0ZH-OInVzLWVhc3QtMQ"
PROFILE_BASE = "https://profile.aws.amazon.com"
SIGNIN_BASE = "https://us-east-1.signin.aws"
PORTAL_SSO = "https://portal.sso.us-east-1.amazonaws.com"
OIDC_BASE = "https://oidc.us-east-1.amazonaws.com"
VS_TOKEN_URL = "https://vs.aws.amazon.com/token"
VIEW_BASE = "https://view.awsapps.com"
_WORKFLOW_ID_RE = re.compile(
    r"workflowID=([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
)

# curl_cffi 0.15.0 supports chrome146 (TLS/JA3). Capture map was Chrome 149;
# aligning UA/sec-ch-ua/TLS to 146 minimizes TES mismatch signals.
UPGRADED = "curl_cffi 0.9.0->0.15.0 chrome131->chrome146"
UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)
SEC_CH_UA = '"Google Chrome";v="146", "Chromium";v="146", "Not-A.Brand";v="24"'
IMPERSONATE = "chrome146"

# Password POST body was redacted in capture. Input type extracted from
# signin_app.js createPasswordPage: "PasswordRequestInput" (NOT "UserPasswordInput").
# Payload requires actionId:"SUBMIT" + successfullyEncrypted/errorLog fields.
_PASSWORD_INPUT_TYPE = "PasswordRequestInput"
# SPA (signin_app.js execute middleware): input_type:"FingerPrintRequestInput"
# Wrong name → AWS 400 "Please try signing in again" when fingerprint is present.
_FINGERPRINT_INPUT_TYPE = "FingerPrintRequestInput"
_USER_EVENT_INPUT_TYPE = "UserEventBatch"
# SPA (signin_app.js EmailOTPAuthentication component): input_type for login OTP step.
# Uses EmailOTPLoginRequestInput with emailOTPLoginResponseCode field.
# Routes through Service.SignInLogin → /api/execute (no /signup/ prefix).
_EMAIL_OTP_LOGIN_INPUT_TYPE = "EmailOTPLoginRequestInput"


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


_GMAIL_FALLBACK_MAILBOXES = [
    "INBOX",
    '"[Gmail]/Spam"',
    '"[Google Mail]/Spam"',
    '"[Gmail]/All Mail"',
]


def _quote_mailbox(name: str) -> str:
    """IMAP-quote a mailbox name (RFC 3501 9): backslash-escape \\ and "."""
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _parse_list_entry(entry: bytes) -> tuple[set[str], str] | None:
    """Parse one IMAP LIST response entry -> (flags, mailbox-name) or None.

    Entry shape (RFC 3501): (\\flags) "delim" name, where name is quoted
    ("[Gmail]/Semua Email") or a bare atom (INBOX).
    """
    try:
        text = entry.decode(errors="replace") if isinstance(entry, (bytes, bytearray)) else str(entry)
    except Exception:
        return None
    m = re.match(r"\(([^)]*)\)\s+\"[^\"]*\"\s+(.*)$", text.strip())
    if not m:
        return None
    flags = {f.lower() for f in m.group(1).split()}
    rest = m.group(2).strip()
    if rest.startswith('"'):
        qm = re.match(r'"((?:[^"\\]|\\.)*)"', rest)
        if not qm:
            return None
        name = qm.group(1).replace('\\"', '"').replace("\\\\", "\\")
    else:
        name = rest.split()[0] if rest.split() else ""
    return (flags, name) if name else None


def _mailboxes_for(host: str, m: imaplib.IMAP4 | None = None) -> list[str]:
    """Ordered mailboxes to search. Gmail: INBOX + Junk + All Mail.

    Gmail localizes folder names (Indonesian: [Gmail]/Semua Email), so with
    a live connection resolve the real names via RFC 6154 special-use LIST
    flags (\\Junk, \\All). Any failure — no connection, LIST error, no
    special-use flags — falls back to the English hardcoded names, which
    still work for English-locale accounts.
    """
    h = (host or "").lower()
    if not h.endswith("gmail.com"):
        return ["INBOX"]
    if m is None:
        return list(_GMAIL_FALLBACK_MAILBOXES)
    try:
        typ, data = m.list()
    except Exception as e:
        emit(
            {
                "event": "debug",
                "msg": "imap-list-error",
                "error": str(e)[:100],
            }
        )
        return list(_GMAIL_FALLBACK_MAILBOXES)
    if typ != "OK" or not data:
        return list(_GMAIL_FALLBACK_MAILBOXES)
    junk = allmail = None
    for entry in data:
        if not isinstance(entry, (bytes, bytearray)):
            continue
        parsed = _parse_list_entry(entry)
        if not parsed:
            continue
        flags, name = parsed
        if junk is None and "\\junk" in flags:
            junk = name
        if allmail is None and "\\all" in flags:
            allmail = name
    if not junk and not allmail:
        return list(_GMAIL_FALLBACK_MAILBOXES)
    boxes = ["INBOX"]
    for name in (junk, allmail):
        if name and name.upper() != "INBOX":
            boxes.append(_quote_mailbox(name))
    return boxes


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
    """SEARCH for candidate message ids. Caller must be in SELECTED state.

    sender_domain may be a single domain or a comma-separated list. kiro's
    login OTP comes from login.awsapps.com while the signup OTP comes from
    signin.aws — searching only one misses the other (task #133: 3 login
    OTPs sat in Spam unread because the search was FROM signin.aws).
    """
    domains = [d.strip() for d in sender_domain.split(",") if d.strip()] or ["signin.aws"]
    ids: list[bytes] = []
    for dom in domains:
        try:
            typ, data = m.search(None, f'(TO "{target_email}" FROM "{dom}")')
            got = data[0].split() if typ == "OK" and data and data[0] else []
            ids.extend(got)
        except Exception:
            pass
    if not ids:
        # FROM-only fallback (recipient checked later in _message_for).
        for dom in domains:
            try:
                typ, data = m.search(None, f'(FROM "{dom}")')
                got = data[0].split() if typ == "OK" and data and data[0] else []
                ids.extend(got)
            except Exception:
                pass
    # de-dup preserving order
    seen: set[bytes] = set()
    out: list[bytes] = []
    for i in ids:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def _message_for(raw: bytes, target_email: str) -> bool:
    """True if raw RFC822 message is addressed to target_email (To/Cc).

    Gmail plus-aliases (base+tag@gmail.com) all share one inbox, and the
    FROM-only SEARCH fallback in _search_ids ignores the recipient entirely
    — without this check a code meant for another alias (or a stale code
    from an earlier run) would be accepted. Exact address match via
    getaddresses (not substring) so "xbase+tag@gmail.com" never matches
    "base+tag@gmail.com"; display names and comma lists are handled too.
    """
    try:
        msg = emaillib.message_from_bytes(raw)
    except Exception:
        return False
    target = (target_email or "").strip().lower()
    if not target:
        return False
    headers = (msg.get_all("To") or []) + (msg.get_all("Cc") or [])
    return any(addr.lower() == target for _, addr in getaddresses(headers))


# ---- consumed-OTP tracking -------------------------------------------------
#
# AWS Builder ID signup has two OTP moments in one worker process: the signup
# OTP (run() → step_otp) and — post-password — the minted login workflow's
# get-email-otp-login-credential step (step_otp again, same target_email).
# Gmail plus-aliases share ONE inbox across aliases, and Gmail EXPUNGE is
# label-scoped: expunging from INBOX leaves the message searchable in All Mail
# (whose localized name varies per account locale, so deletion alone cannot
# guarantee the stale mail is unreachable). Without tracking, the second
# read_otp re-serves the already-consumed signup code and AWS rejects it with
# EMAIL_OTP_AUTHENTICATION_FAILED. tempmail's Ncaori.wait_code has the
# equivalent guard (_seen_ids).
#
# Keyed by target_email (lowercased) so distinct aliases sharing one inbox
# never mask each other; values are sha256 of the fetched RFC822 bytes —
# message identity, NOT the code value, because AWS may send the same 6-digit
# code in both mails. Process lifetime == one account run (worker-bridge
# spawns signup.py per account), so the sets stay bounded to the run's mails.
_CONSUMED_OTP_KEYS: dict[str, set[str]] = {}


def _otp_key(raw: bytes) -> str:
    """Message-identity key for consumed-OTP tracking (never the code value)."""
    return hashlib.sha256(raw).hexdigest()


def _mark_otp_consumed(target_email: str, raw: bytes) -> None:
    """Record that raw's code was handed to the caller for target_email."""
    _CONSUMED_OTP_KEYS.setdefault((target_email or "").strip().lower(), set()).add(
        _otp_key(raw)
    )


def _was_otp_consumed(target_email: str, raw: bytes) -> bool:
    """True if raw was already consumed by an earlier read for this target."""
    return _otp_key(raw) in _CONSUMED_OTP_KEYS.get(
        (target_email or "").strip().lower(), set()
    )


def read_otp(
    target_email: str,
    cfg: dict,
    retries: int = 40,
    delay: float = 5.0,
) -> str | None:
    """Poll IMAP for the AWS Builder ID code. Returns code|None.

    Never logs the code value — only lengths/prose via emit_step.
    Defaults: sender_domain=signin.aws, delay=5s (KIRO).

    Messages whose code was already returned by an earlier read_otp call in
    this process (same target_email) are skipped — see _CONSUMED_OTP_KEYS.
    """
    host = cfg["host"]
    port = int(cfg["port"])
    user = cfg["user"]
    pw = cfg["password"]
    use_tls = str(cfg.get("tls", "true")).lower() == "true"
    delete_after = str(cfg.get("delete_after_read", "false")).lower() == "true"
    # Both AWS OTP senders: signup code = signin.aws, login code =
    # login.awsapps.com. Searching only one left login OTPs unread in Spam
    # (task #133).
    sender_domain = (
        cfg.get("sender_domain")
        or "signin.aws,login.awsapps.com"
    ).strip() or "signin.aws,login.awsapps.com"
    t0 = time.time()
    for attempt in range(retries):
        emit_step("otp", "pending", attempt=attempt + 1, elapsed_s=int(time.time() - t0))
        try:
            m = imaplib.IMAP4_SSL(host, port) if use_tls else imaplib.IMAP4(host, port)
            try:
                m.login(user, pw)
                # Resolve locale-dependent Gmail names per connection via
                # RFC 6154 LIST (#131); English fallback when LIST fails.
                mailboxes = _mailboxes_for(host, m)
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
                        # Skip mails already consumed by an earlier OTP read
                        # in this process (see _CONSUMED_OTP_KEYS). Deletion
                        # cannot guarantee removal: Gmail EXPUNGE is label-
                        # scoped and All Mail's name is locale-dependent.
                        if raw and _was_otp_consumed(target_email, raw):
                            emit(
                                {
                                    "event": "debug",
                                    "msg": "otp-consumed-skip",
                                    "mailbox": mailbox[:30],
                                }
                            )
                            continue
                        code = extract_otp_from_message(raw)
                        if code:
                            # Recipient check: the FROM-only SEARCH fallback
                            # (and shared plus-alias inboxes) can surface a
                            # code addressed to a different alias.
                            if not _message_for(raw, target_email):
                                emit(
                                    {
                                        "event": "debug",
                                        "msg": "otp-recipient-mismatch",
                                        "mailbox": mailbox[:30],
                                    }
                                )
                                continue
                            found = code
                            # Mark consumed only on a returned code: marking
                            # gate-rejected mails would break the contract
                            # (consumed == code handed to the caller).
                            _mark_otp_consumed(target_email, raw)
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


def _safe_body_snapshot(data: Any) -> dict:
    """Redaction-safe summary of an /api/execute response body for debug emit.

    Strings truncated to 120 chars, nested dict values collapsed to their type
    name unless short strings, lists to their first 20 elements. actionIdList
    etc. are workflow action names, not secrets — collapsing them to "list"
    would hide the server's own contract; long opaque tokens
    (workflowStateHandle) survive only as a 120-char prefix.
    """
    if not isinstance(data, dict):
        return {}
    out: dict[str, Any] = {}
    for k, v in data.items():
        if isinstance(v, str):
            out[k] = v[:120] if len(v) > 120 else v
        elif isinstance(v, bool | int | float | None):
            out[k] = v
        elif isinstance(v, dict):
            out[k] = {sk: sv if isinstance(sv, str) and len(sv) < 80 else str(type(sv).__name__) for sk, sv in v.items()}
        elif isinstance(v, list):
            out[k] = [sv if isinstance(sv, str) and len(sv) < 80 else str(type(sv).__name__) for sv in v[:20]]
        else:
            out[k] = str(type(v).__name__)
    return out


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
    # SPA: GC(999)+"-"+GC(9999999)+"-"+GC(9999999)  (0..998 / 0..9999998)
    a = str(uuid.uuid4().int % 999)
    b = str(uuid.uuid4().int % 9_999_999)
    c = str(uuid.uuid4().int % 9_999_999)
    return f"{a}-{b}-{c}"


# SPA cookie names (profile_app.js Ue enum + Shortbread essential category).
_PROFILE_UBID_COOKIE = "aws-user-profile-ubid"


def _set_profile_ubid_cookie(s: Any, ubid: str) -> None:
    """Mirror SPA browserData path: setCookie(Ubid) before profile API posts.

    profile_app.js form component:
      hasCookie(Ubid) || setCookie(Ubid, GC(999)+"-"+..., 31556952)
      then browserData.attributes.ubid = readCookie(Ubid)

    Capture send-otp includes a Cookie header; without this jar entry the
    request only carries ubid in JSON attributes.
    """
    if not ubid:
        return
    jar = getattr(s, "cookies", None)
    if jar is None:
        return
    # Shortbread DEFAULT_DOMAIN = ".aws.amazon.com"; also set host-scoped.
    for domain in (".aws.amazon.com", "profile.aws.amazon.com"):
        try:
            jar.set(_PROFILE_UBID_COOKIE, ubid, domain=domain, path="/")
        except Exception:
            try:
                jar.set(_PROFILE_UBID_COOKIE, ubid)
            except Exception:
                pass


# One device per RUN, a different device each run.
#
# The seed draws the whole device identity (timeZone, gpu, plugins,
# screenInfo, math, capabilities). Hardcoding it made every account we ever
# create come from a byte-identical "device": coherent within a run (which is
# what TES wants) but a reuse signal across runs. After ~10 signups on the
# fixed seed, send-otp — the first checkpoint, previously rock solid — started
# getting BLOCKED even from a fresh proxy IP, so the flag tracked the device,
# not the address.
#
# Draw once per process and use it for every fingerprint: coherent inside the
# session, unique between sessions. Set KIRO_FP_SEED to pin it for repro.
def _run_fp_seed() -> int:
    env = (os.getenv("KIRO_FP_SEED") or "").strip()
    if env.isdigit():
        return int(env)
    return random.randrange(1, 1_000_000)


FP_SEED_RUN = _run_fp_seed()

FP_SEED_BOOTSTRAP = FP_SEED_RUN  # init / metrics — no TES check
FP_SEED_START = FP_SEED_RUN  # profile/api/start PageLoad — no TES check
# Seed choice targets fp_len, NOT body_len. smoke-18 PASSED TES at fp_len=6529
# (body_len 6836, i.e. -55 vs the 6891 capture); seed 54 hits body_len 6892
# (diff +1) but fp_len=6585 and is BLOCKED. TES scores fingerprint structure,
# not payload size — matching the capture body length is the wrong target.
# Seeds 2/12/84/93 all yield fp_len=6529; use 12 so send-otp does not reuse
# FP_SEED_START's fingerprint on the same page.
FP_SEED_SEND_OTP = FP_SEED_RUN
# Deliberately the SAME seed as send-otp — not a size match.
#
# Neither size metric is causal. Evidence (create-identity):
#   smoke-18  fp_len 6581  body_len 6955  PASS
#   smoke-19  fp_len 6593  body_len 6970 (== capture, byte-identical)  BLOCKED
#   smoke-20  fp_len 6529  body_len 6901 (fp_len == passing send-otp)  BLOCKED
# 6529 < 6581 < 6593 with only the middle passing, so no monotonic size
# theory survives. A fresh egress IP (smoke-21) blocked identically, ruling
# out IP reputation.
#
# The seed draws the *device identity* (timeZone, gpu, plugins, screenInfo,
# math, capabilities). A different seed per step fabricated a different
# device on every request — timeZone alone varied -5/-6/-8/1/-7 within one
# session, which no real browser does. Reusing FP_SEED_SEND_OTP makes both
# TES-checked requests present one coherent device, and specifically the
# device TES already accepted at send-otp (twice, across two IPs). dwell_ms
# does not consume RNG, so the device fields are identical across steps while
# timings still differ per event.
FP_SEED_CREATE_IDENTITY = FP_SEED_SEND_OTP


def _fingerprint(
    *,
    dwell_ms: int | None = None,
    location: str | None = None,
    referrer: str | None = None,
    form_key: str = "email",
    rng: random.Random | None = None,
) -> str:
    """Real FWCIM v4.0.0 collect+encrypt (not random base64).

    TES on profile/api/send-otp rejects short random fingerprints; capture
    bodies are multi-KB XXTEA ciphertext over CRC#JSON collector payload.

    SPA re-runs ``fwcim.report()`` on every PageLoad/PageSubmit — never reuse
    a bootstrap ciphertext for send-otp. ``dwell_ms`` should track
    ``timeSpentOnPage`` for that event (capture PageSubmit ≈ 7031).

    ``form_key`` controls the form telemetry key name (``"email"`` for
    EMAIL_COLLECTION, ``"otp"`` for EMAIL_VERIFICATION) and the canvas
    emailHash (number for email pages, ``"~"`` for OTP pages).

    Pass a deterministic ``rng`` (``random.Random(seed)``) for reproducible
    fingerprint body length across runs — required for TES tolerance.
    """
    from fwcim import collect_and_encrypt

    # Keep FWCIM userAgent aligned with HTTP UA (capture Chrome 149).
    return collect_and_encrypt(
        dwell_ms=dwell_ms,
        user_agent=UA,
        location=location,
        referrer=referrer,
        form_key=form_key,
        rng=rng,
    )


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
        "fingerprint": fingerprint or _fingerprint(rng=random.Random(FP_SEED_BOOTSTRAP)),
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


def _cookie_names(s: Any) -> list[str]:
    """Non-secret cookie *names* currently in the jar (values never logged)."""
    jar = getattr(s, "cookies", None)
    if jar is None:
        return []
    names: set[str] = set()
    try:
        # curl_cffi / requests Cookies: iterable of morsels or .keys()
        if hasattr(jar, "keys"):
            for k in jar.keys():
                if k:
                    names.add(str(k))
        for c in jar:
            n = getattr(c, "name", None) or (c[0] if isinstance(c, (tuple, list)) and c else None)
            if n:
                names.add(str(n))
    except Exception:
        pass
    return sorted(names)[:40]


def _raise_http(step: str, resp: Any, label: str = "") -> None:
    status = getattr(resp, "status_code", 0) or 0
    # Keep enough of the body that message.* detail survives — the nested
    # message.errorCode is the only field that says *why* (top-level errorCode
    # is null on workflow errors). 600 cut SIGNIN_BAD_REQUEST_ERROR bodies off
    # right after "heading".
    text = (getattr(resp, "text", None) or "")[:2500]
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
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        }
    )
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    return s


def _get(s: Any, url: str, **kw: Any) -> Any:
    h = {
        "sec-ch-ua": SEC_CH_UA,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
    }
    extra_headers = kw.pop("headers", None)
    if extra_headers:
        h.update(extra_headers)
    return s.get(url, impersonate=IMPERSONATE, timeout=kw.pop("timeout", 45), headers=h, **kw)


def _fetch_headers(url: str) -> dict:
    """XHR/fetch-style sec-fetch headers that match browser SPA API calls.

    curl_cffi impersonation emits page-navigation sec-fetch-* by default
    (document/navigate/none/?1).  SPA XHR/fetch calls send cors/empty/same-origin.
    TES scores the mismatch.  Override on every API post.
    """
    netloc = urlparse(url).netloc
    origin = "https://" + netloc
    site = "same-origin"
    return {
        "Content-Type": "application/json;charset=UTF-8",
        "Origin": origin,
        "sec-ch-ua": SEC_CH_UA,
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": site,
        "Priority": "u=1, i",
    }


def _post_json(s: Any, url: str, body: dict, headers: dict | None = None, **kw: Any) -> Any:
    h = _fetch_headers(url)
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
    h = _fetch_headers(url)
    h["Content-Type"] = "application/x-www-form-urlencoded"
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


# SPA (signin_app.js FingerprintMetricsConstants + reportMetric):
#   POST /metrics/fingerprint  content-type application/x-www-form-urlencoded
#   body: name=...&value=...&operation=AWSSignin:FingerprintMetrics:<suffix>
#   — FileLoaded value="1"; Generated value=<ECdITeCs ciphertext>
# Capture content-length ≈ 6064 matches Generated (full FP in value), not FileLoaded.
_FP_METRICS_PATH = f"{SIGNIN_BASE}/metrics/fingerprint"
_FP_METRICS_OP_PREFIX = "AWSSignin:FingerprintMetrics"
_FP_METRICS_FILE_LOADED_OK = "IsFingerprintFileLoaded:Success"
_FP_METRICS_GENERATED_OK = "IsFingerprintGenerated:Success"
# SPA page/event suffixes (FingerprintMetricsConstants)
_FP_METRICS_ONLOAD_USERNAME = "OnLoad_Username_Page"
_FP_METRICS_ONCLICK_NEXT = "OnClick_Next_Button"
_FP_METRICS_OP_START = "start"  # generateFingerprintString(stepId) → operation ...:start


def _report_fingerprint_metric(
    s: Any,
    *,
    name: str,
    value: str,
    operation_suffix: str,
    referer: str,
) -> None:
    """POST signin /metrics/fingerprint. Soft-fail; never log value (may be FP).

    SPA reportMetric builds the body by string concat (no encodeURIComponent);
    axios sends that raw form body. Match that so +/= in base64 survive.
    """
    op = f"{_FP_METRICS_OP_PREFIX}:{operation_suffix}"
    # Deliberately raw concat — urlencode would bloat CL vs capture (~6064).
    body = f"name={name}&value={value}&operation={op}"
    try:
        r = s.post(
            _FP_METRICS_PATH,
            data=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
                "Origin": SIGNIN_BASE,
                "Referer": referer,
                "Accept": "application/json, text/plain, */*",
                "sec-ch-ua": SEC_CH_UA,
                "sec-ch-ua-mobile": "?0",
                "sec-ch-ua-platform": '"Windows"',
            },
            impersonate=IMPERSONATE,
            timeout=20,
        )
        emit(
            {
                "event": "debug",
                "msg": "metrics-fingerprint",
                "name": name,
                "op_suffix": operation_suffix,
                "status": getattr(r, "status_code", 0),
                "body_len": len(body),
            }
        )
    except Exception as e:
        emit(
            {
                "event": "debug",
                "msg": "metrics-fingerprint-soft-fail",
                "name": name,
                "op_suffix": operation_suffix,
                "error": redact_err(e),
            }
        )


# ---- Flow state ------------------------------------------------------------


class FlowState:
    """Mutable state carried across HTTP steps."""

    def __init__(self) -> None:
        self.user_code: str = ""
        self.csrf_token: str = ""
        self.directory_id: str = DIRECTORY_ID
        # Live profile registration workflowID (minted via signin signup handoff).
        self.workflow_id: str = ""
        self.workflow_state: str = ""
        self.workflow_state_handle: str = ""
        self.login_url: str = ""
        self.visitor_id: str = str(uuid.uuid4())
        self.fingerprint: str = _fingerprint(rng=random.Random(FP_SEED_BOOTSTRAP))
        self.ubid: str = _new_ubid()
        self.registration_code: str = ""
        self.sign_in_state: str = ""
        self.user_session_id: str = ""
        self.device_context: dict | None = None
        # signin SPA stores workflowResponseData.encryptionContextResponse
        # ({publicKey: JWK, issuer, audience, region}) and uses it to JWE-
        # encrypt passwords before execute. Captured opportunistically from
        # any execute response that carries it.
        self.encryption_context: dict | None = None
        self.auth_code: str = ""
        # Provenance of auth_code ("<query|fragment>:<host><path>[:<param>]")
        # — which URL minted it. A value NOT from view.awsapps.com means the
        # extractor matched a non-portal URL (garbage for the sso-token
        # exchange).
        self.auth_code_source: str = ""
        self.sso_state: str = ""
        self.email: str = ""
        self.name: str = ""
        self.password: str = ""
        self.email_source: str = "imap"
        self.tempmail_box: Any = None


# ---- Steps -----------------------------------------------------------------


def _url_quote(u: str) -> str:
    from urllib.parse import quote

    return quote(u, safe="")


def _extract_workflow_id(url: str) -> str:
    m = _WORKFLOW_ID_RE.search(url or "")
    return m.group(1) if m else ""


def _signin_execute(
    s: Any,
    st: FlowState,
    *,
    path: str,
    step_id: str,
    handle: str,
    referer: str,
    action_id: str | None = None,
    inputs: list | None = None,
    visitor_id: str | None = None,
) -> dict:
    """POST platform login or signup /api/execute. Returns JSON body."""
    rid = _new_request_id()
    body: dict[str, Any] = {
        "stepId": step_id,
        "workflowStateHandle": handle,
        "requestId": rid,
        "inputs": inputs if inputs is not None else [],
    }
    if action_id:
        body["actionId"] = action_id
    if visitor_id:
        body["visitorId"] = visitor_id
    url = f"{SIGNIN_BASE}/platform/{st.directory_id}/{path}"
    r = _post_json(
        s,
        url,
        body,
        headers={
            "Referer": referer,
            "Origin": SIGNIN_BASE,
            "x-amzn-requestid": rid,
            "Accept": "application/json, text/plain, */*",
        },
    )
    label = f"signin/{path} stepId={step_id or 'EMPTY'}" + (f" action={action_id}" if action_id else "")
    _raise_http("bootstrap", r, label)
    data = _json_or_empty(r)
    if data.get("workflowStateHandle"):
        st.workflow_state_handle = str(data["workflowStateHandle"])
    # The SPA stores workflowResponseData.encryptionContextResponse from ANY
    # execute response and uses it for subsequent password submissions.
    wrd = data.get("workflowResponseData")
    if isinstance(wrd, dict) and isinstance(wrd.get("encryptionContextResponse"), dict):
        st.encryption_context = wrd["encryptionContextResponse"]
        emit({
            "event": "debug",
            "msg": "encryption-context-captured",
            "stepId": step_id,
            "has_public_key": "publicKey" in st.encryption_context,
            "issuer": st.encryption_context.get("issuer"),
            "audience": st.encryption_context.get("audience"),
            "region": st.encryption_context.get("region"),
        })
    return data


def _mint_profile_workflow_id(s: Any, st: FlowState, email: str = "") -> str:
    """Mint a live profile workflowID via the platform signin signup handoff.

    Confirmed pure-HTTP chain (2026-07-24 probe + capture):
      portal.sso/login → redirectUrl(handle)
      login/api/execute stepId=start
      login/api/execute stepId=start + actionId=SIGNUP → get-identity-user
      login/api/execute stepId=get-identity-user + actionId=SIGNUP → signup redirect
      GET signup page
      signup/api/execute stepId="" (EMPTY) + username/fingerPrint → registers email
      signup/api/execute stepId=start → redirect profile/#/signup/start?workflowID=<live>

    Capture (10:16:05) submits username at the signin layer BEFORE profile
    /api/start + /api/send-otp. Omitting it yields TES BLOCKED on send-otp.
    """
    if not st.workflow_state_handle:
        raise RuntimeError("mint-workflow-missing-login-handle")
    login_url = st.login_url or (
        f"{SIGNIN_BASE}/platform/{st.directory_id}/login"
        f"?workflowStateHandle={st.workflow_state_handle}"
    )
    handle = st.workflow_state_handle

    # SPA fires FileLoaded metric on username-page mount (before execute).
    # Capture has 3× /metrics/fingerprint; worker previously sent none.
    _report_fingerprint_metric(
        s,
        name=_FP_METRICS_FILE_LOADED_OK,
        value="1",
        operation_suffix=_FP_METRICS_ONLOAD_USERNAME,
        referer=login_url,
    )

    # 1) start (login)
    j = _signin_execute(
        s, st, path="api/execute", step_id="start", handle=handle, referer=login_url
    )
    handle = str(j.get("workflowStateHandle") or st.workflow_state_handle)

    # 2) start + SIGNUP → get-identity-user
    j = _signin_execute(
        s,
        st,
        path="api/execute",
        step_id="start",
        handle=handle,
        referer=login_url,
        action_id="SIGNUP",
    )
    handle = str(j.get("workflowStateHandle") or st.workflow_state_handle)
    step = str(j.get("stepId") or "get-identity-user")

    # 3) get-identity-user + SIGNUP → signup redirect
    j = _signin_execute(
        s,
        st,
        path="api/execute",
        step_id=step,
        handle=handle,
        referer=login_url,
        action_id="SIGNUP",
    )
    redir = ""
    if isinstance(j.get("redirect"), dict):
        redir = str(j["redirect"].get("url") or "")
    if not redir:
        redir = str(j.get("redirectUrl") or "")
    if not redir:
        raise RuntimeError("mint-workflow-missing-signup-redirect")

    qs = parse_qs(urlparse(redir).query)
    signup_handle = (qs.get("workflowStateHandle") or [None])[0]
    if not signup_handle:
        raise RuntimeError("mint-workflow-missing-signup-handle")
    st.workflow_state_handle = str(signup_handle)

    # 4) warm signup page
    _get(s, redir, headers={"Referer": login_url})

    # SPA: Next click → FileLoaded(OnClick_Next_Button); generateFingerprintString
    # reports Generated Success with value=<ciphertext>, operation ...:start.
    # Capture body content-length 6064 is this Generated post (FP in value).
    # Fresh FP for metrics + execute so ciphertext matches what SPA would mint.
    st.fingerprint = _fingerprint(dwell_ms=800, rng=random.Random(FP_SEED_BOOTSTRAP))
    _report_fingerprint_metric(
        s,
        name=_FP_METRICS_FILE_LOADED_OK,
        value="1",
        operation_suffix=_FP_METRICS_ONCLICK_NEXT,
        referer=redir,
    )
    _report_fingerprint_metric(
        s,
        name=_FP_METRICS_GENERATED_OK,
        value=st.fingerprint,
        operation_suffix=_FP_METRICS_OP_START,
        referer=redir,
    )

    # 5) EMPTY signup/api/execute — capture (10:16:05) shape:
    #   stepId="", handle=<signup page handle>,
    #   inputs=[{UserRequestInput,username},{FingerPrintRequestInput,fingerPrint}],
    #   visitorId=<uuid>
    # Root cause of prior 400s: wrong fingerprint input_type "FingerPrintInput"
    # (SPA uses "FingerPrintRequestInput"). With the correct type, username
    # registers on the first EMPTY — do NOT bare-EMPTY first (burns the handle).
    username_on = "none"
    username_inputs = None
    if email:
        username_inputs = [
            {"input_type": "UserRequestInput", "username": email},
            {
                "input_type": _FINGERPRINT_INPUT_TYPE,
                "fingerPrint": st.fingerprint,
            },
        ]
        try:
            j = _signin_execute(
                s,
                st,
                path="signup/api/execute",
                step_id="",
                handle=st.workflow_state_handle,
                referer=redir,
                inputs=username_inputs,
                visitor_id=st.visitor_id,
            )
            username_on = "empty"
        except RuntimeError as e:
            emit(
                {
                    "event": "debug",
                    "msg": "signup-username-empty-soft-fail",
                    "error": redact_err(e),
                }
            )
            j = None
    else:
        j = None

    if j is None:
        # Fallback: bare EMPTY (mint still works; TES may still block later).
        bare_inputs = (
            [
                {
                    "input_type": _FINGERPRINT_INPUT_TYPE,
                    "fingerPrint": st.fingerprint,
                }
            ]
            if st.fingerprint
            else []
        )
        j = _signin_execute(
            s,
            st,
            path="signup/api/execute",
            step_id="",
            handle=st.workflow_state_handle,
            referer=redir,
            inputs=bare_inputs or None,
            visitor_id=st.visitor_id if bare_inputs else None,
        )

    handle2 = str(j.get("workflowStateHandle") or st.workflow_state_handle)
    next_step = str(j.get("stepId") or "start")

    ctx = j.get("presentationContext") if isinstance(j.get("presentationContext"), dict) else {}
    emit(
        {
            "event": "debug",
            "msg": "signup-username-submitted",
            "has_email": bool(email),
            "username_on": username_on,
            "ctx_has_username": bool(ctx.get("username")),
            "next_stepId": next_step,
        }
    )

    # 6) START signup/api/execute → profile workflowID redirect if not already present.
    # SPA EmptyExecuteStepPage auto-dispatches executeStep; execute middleware ALWAYS
    # re-injects UserRequestInput from workflowReducer.username (when set) THEN
    # appends FingerPrintRequestInput. Smoke-10 sent FP-only on START → mint
    # ctx_has_username=false and profile /api/start has_email=false (capture binds
    # email). Mirror middleware: username first, then FP.
    profile_redir = ""
    if isinstance(j.get("redirect"), dict):
        profile_redir = str(j["redirect"].get("url") or "")
    if not profile_redir:
        profile_redir = str(j.get("redirectUrl") or "")
    blob = json.dumps(j, default=str)
    wf = _extract_workflow_id(profile_redir) or _extract_workflow_id(blob)
    start_inputs = []
    if email:
        start_inputs.append(
            {"input_type": "UserRequestInput", "username": email}
        )
    if st.fingerprint:
        start_inputs.append(
            {
                "input_type": _FINGERPRINT_INPUT_TYPE,
                "fingerPrint": st.fingerprint,
            }
        )
    start_inputs = start_inputs or None
    if not wf:
        j = _signin_execute(
            s,
            st,
            path="signup/api/execute",
            step_id=next_step if next_step else "start",
            handle=handle2,
            referer=redir,
            inputs=start_inputs,
            visitor_id=st.visitor_id,
        )
        profile_redir = ""
        if isinstance(j.get("redirect"), dict):
            profile_redir = str(j["redirect"].get("url") or "")
        if not profile_redir:
            profile_redir = str(j.get("redirectUrl") or "")
        blob = json.dumps(j, default=str)
        wf = _extract_workflow_id(profile_redir) or _extract_workflow_id(blob)
    # SPA GET_VERIFIED_USERNAME = SpinnerForRedirect: GET/POST redirect.url.
    # Follow non-secret redirect so profile session cookies match browser handoff.
    redir_followed = False
    redir_method = "GET"
    redir_host = ""
    if profile_redir and profile_redir.startswith("http"):
        try:
            redir_host = urlparse(profile_redir).hostname or ""
            # Prefer redirect.method/postParams when present (SpinnerForRedirect).
            redir_obj = j.get("redirect") if isinstance(j.get("redirect"), dict) else {}
            redir_method = str(redir_obj.get("method") or "GET").upper()
            post_params = redir_obj.get("postParams") if redir_method == "POST" else None
            if redir_method == "POST" and isinstance(post_params, list):
                form = {}
                for p in post_params:
                    if isinstance(p, dict) and p.get("name") is not None:
                        form[str(p["name"])] = str(p.get("value") or "")
                _post_form(
                    s,
                    profile_redir,
                    form,
                    headers={"Referer": redir},
                )
            else:
                redir_method = "GET"
                _get(s, profile_redir, headers={"Referer": redir})
            redir_followed = True
            if not wf:
                wf = _extract_workflow_id(profile_redir)
        except Exception as e:
            emit(
                {
                    "event": "debug",
                    "msg": "profile-redirect-follow-soft-fail",
                    "error": redact_err(e),
                }
            )
    if not wf:
        raise RuntimeError("mint-workflow-missing-profile-workflowID")
    st.workflow_id = wf
    mint_ctx = j.get("presentationContext") if isinstance(j.get("presentationContext"), dict) else {}
    emit(
        {
            "event": "debug",
            "msg": "profile-workflow-minted",
            "workflow_id_len": len(wf),
            "stepId": str(j.get("stepId") or ""),
            "username_on": username_on,
            "ctx_has_username": bool(mint_ctx.get("username")),
            "redir_followed": redir_followed,
            "has_profile_redir": bool(profile_redir),
            "start_had_fp_input": bool(
                start_inputs
                and any(
                    isinstance(x, dict) and x.get("input_type") == _FINGERPRINT_INPUT_TYPE
                    for x in start_inputs
                )
            ),
            "start_had_username_input": bool(
                start_inputs
                and any(
                    isinstance(x, dict) and x.get("input_type") == "UserRequestInput"
                    for x in start_inputs
                )
            ),
            "redir_method": redir_method,
            "redir_host": redir_host,
        }
    )
    return wf


def step_bootstrap(s: Any, st: FlowState, device_url: str, email: str = "") -> None:
    """Open device URL, portal.sso /login, then mint a live profile workflowID."""
    emit_step("bootstrap", "pending")
    # Log the device seed (not a secret) so a run can be reproduced with
    # KIRO_FP_SEED=<n> when diagnosing a TES decision.
    emit({"event": "debug", "msg": "fp-seed", "seed": FP_SEED_RUN})
    st.user_code = user_code_from_device_url(device_url)

    # Warm device page (cookies on view.awsapps.com)
    r0 = _get(s, device_url, allow_redirects=True)
    emit(
        {
            "event": "debug",
            "msg": "device-url-open",
            "status": getattr(r0, "status_code", 0),
            "user_code_len": len(st.user_code),
        }
    )

    redirect_url = f"{VIEW_BASE}/start/#/device?user_code={st.user_code}"
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
        signin_redirect = f"{SIGNIN_BASE}/platform/{st.directory_id}/login"

    # Follow HTML login page
    r2 = _get(s, signin_redirect, headers={"Referer": f"{VIEW_BASE}/"})
    qs = parse_qs(urlparse(signin_redirect).query)
    if qs.get("workflowStateHandle"):
        st.workflow_state_handle = qs["workflowStateHandle"][0]
    final = getattr(r2, "url", "") or ""
    qs2 = parse_qs(urlparse(final).query)
    if qs2.get("workflowStateHandle"):
        st.workflow_state_handle = qs2["workflowStateHandle"][0]
    st.login_url = signin_redirect if "workflowStateHandle" in signin_redirect else (
        f"{SIGNIN_BASE}/platform/{st.directory_id}/login"
        f"?workflowStateHandle={st.workflow_state_handle}"
        if st.workflow_state_handle
        else signin_redirect
    )

    # Mint live profile workflowID; register email at signin layer when known.
    _mint_profile_workflow_id(s, st, email=email or st.email or "")
    if not st.workflow_id:
        raise RuntimeError("bootstrap-missing-workflow-id")

    emit_step("bootstrap", "ok")


def step_email_entry(s: Any, st: FlowState, email: str) -> None:
    """Profile /api/start + /api/send-otp (email submission)."""
    emit_step("email_entry", "pending")
    st.email = email
    if not st.workflow_id:
        raise RuntimeError("email-entry-missing-workflow-id")

    # Load profile SPA entry (sets cookies) with the live workflowID.
    profile_url = f"{PROFILE_BASE}/?workflowID={st.workflow_id}"
    _get(
        s,
        profile_url,
        headers={"Referer": f"{SIGNIN_BASE}/"},
    )
    # SPA sets aws-user-profile-ubid on first browserData build (essential cookie).
    _set_profile_ubid_cookie(s, st.ubid)
    emit(
        {
            "event": "debug",
            "msg": "profile-ubid-cookie-set",
            "has_ubid": bool(st.ubid),
            "ubid_len": len(st.ubid or ""),
        }
    )

    # Optional config warm-ups (captured; non-fatal). get-app-context often 404s.
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
            {"workflowID": st.workflow_id},
            headers={"Referer": profile_url, "Origin": PROFILE_BASE},
        )
    except Exception as e:
        emit({"event": "debug", "msg": "profile-warmup-soft-fail", "error": redact_err(e)})

    # Fresh FWCIM per SPA report() call — do not reuse bootstrap st.fingerprint.
    # location = full profile href (SPA window.location.href includes workflowID).
    start_dwell = 134
    start_fp = _fingerprint(
        dwell_ms=start_dwell,
        location=profile_url,
        referrer=f"{SIGNIN_BASE}/",
        rng=random.Random(FP_SEED_START),
    )
    bd = browser_data(
        event_type="PageLoad",
        time_spent_ms=start_dwell,
        fingerprint=start_fp,
        ubid=st.ubid,
    )
    r = _post_json(
        s,
        f"{PROFILE_BASE}/api/start",
        {"workflowID": st.workflow_id, "browserData": bd},
        headers={"Referer": profile_url, "Origin": PROFILE_BASE},
    )
    _raise_http("email_entry", r, "profile/api/start")
    start = _json_or_empty(r)
    st.workflow_state = str(start.get("workflowState") or "")
    if not st.workflow_state:
        raise RuntimeError("profile-start-missing-workflowState")
    # Capture start response binds email into the profile workflow:
    #   {"email":"<addr>","redirectUrl":"...","workflowState":"..."}
    # has_email is the binding signal — never log the address itself.
    start_email = start.get("email")
    has_email = isinstance(start_email, str) and bool(start_email.strip())
    cookie_names = _cookie_names(s)
    emit(
        {
            "event": "debug",
            "msg": "profile-start-ok",
            "status": getattr(r, "status_code", 0),
            "has_workflow_state": bool(st.workflow_state),
            "has_email": has_email,
            "has_redirect_url": bool(start.get("redirectUrl")),
            "has_post_create_redirect": bool(start.get("postCreateRedirectUrl")),
            "start_key_count": len(start.keys()),
            "fp_len": len(start_fp),
            "start_keys": sorted(start.keys())[:16],
            "cookie_names": cookie_names,
            "cookie_count": len(cookie_names),
        }
    )
    # Capture any signup/login redirect hints
    if start.get("redirectUrl"):
        qs = parse_qs(urlparse(str(start["redirectUrl"])).query)
        if qs.get("workflowStateHandle"):
            st.workflow_state_handle = qs["workflowStateHandle"][0]

    # send-otp — SPA form timer starts on mount (ref = Date.now() in useEffect
    # after /api/start paints email form). Capture timeSpentOnPage ≈ 7031 and
    # eventTimestamp is ~7s after start's. Hardcoding 7031 while posting within
    # ms of start is a TES-visible clock skew. Sleep wall-clock from form mount.
    form_t0 = time.time()  # approximate form mount = post-start
    target_submit_s = 7.031
    elapsed_s = time.time() - form_t0
    if elapsed_s < target_submit_s:
        time.sleep(target_submit_s - elapsed_s)
    submit_dwell = max(1, int((time.time() - form_t0) * 1000))
    submit_fp = _fingerprint(
        dwell_ms=submit_dwell,
        location=profile_url,
        referrer=f"{SIGNIN_BASE}/",
        rng=random.Random(FP_SEED_SEND_OTP),
    )
    bd2 = browser_data(
        page_name="EMAIL_COLLECTION",
        event_type="PageSubmit",
        time_spent_ms=submit_dwell,
        fingerprint=submit_fp,
        ubid=st.ubid,
    )
    body2 = {
        "workflowState": st.workflow_state,
        "email": email,
        "browserData": bd2,
    }
    # Size only — never log fingerprint/email/OTP.
    try:
        body2_len = len(json.dumps(body2, separators=(",", ":")))
    except Exception:
        body2_len = -1
    emit(
        {
            "event": "debug",
            "msg": "profile-send-otp-request",
            "body_len": body2_len,
            "fp_len": len(submit_fp),
            "capture_body_len": 6891,
            "submit_dwell_ms": submit_dwell,
            "wall_sleep": True,
        }
    )
    r2 = _post_json(
        s,
        f"{PROFILE_BASE}/api/send-otp",
        body2,
        headers={"Referer": profile_url, "Origin": PROFILE_BASE},
    )
    _raise_http("email_entry", r2, "profile/api/send-otp")
    sent = _json_or_empty(r2)
    if sent.get("workflowState"):
        st.workflow_state = str(sent["workflowState"])

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


def step_create_identity(
    s: Any,
    st: FlowState,
    otp_code: str,
    *,
    verify_t0: float | None = None,
) -> None:
    """POST /api/create-identity — OTP + name + email in one call.

    Capture: fresh FWCIM per SPA report(), pageName=EMAIL_VERIFICATION,
    eventType=EmailVerification, timeSpentOnPage≈13033 (form mount after
    send-otp → submit). Reusing bootstrap st.fingerprint + instant post is a
    TES-visible skew (smoke-17 cleared send-otp then blocked here).
    """
    emit_step("otp_verify", "pending")
    emit_step("name", "pending")
    if not st.workflow_id:
        raise RuntimeError("create-identity-missing-workflow-id")
    profile_url = f"{PROFILE_BASE}/?workflowID={st.workflow_id}"

    # SPA verification form mount ≈ post send-otp. Capture wall ≈14.7s between
    # send-otp and create-identity with timeSpentOnPage 13033. Tempmail can
    # return OTP in ~2s — pad wall-clock so dwell matches capture.
    if verify_t0 is None:
        verify_t0 = time.time()
    target_verify_s = 13.033
    elapsed_s = time.time() - verify_t0
    if elapsed_s < target_verify_s:
        time.sleep(target_verify_s - elapsed_s)
    verify_dwell = max(1, int((time.time() - verify_t0) * 1000))

    # Fresh form-path FWCIM — never reuse bootstrap st.fingerprint here.
    verify_fp = _fingerprint(
        dwell_ms=verify_dwell,
        location=profile_url,
        referrer=f"{SIGNIN_BASE}/",
        form_key="email",
        rng=random.Random(FP_SEED_CREATE_IDENTITY),
    )
    bd = browser_data(
        page_name="EMAIL_VERIFICATION",
        event_type="EmailVerification",
        time_spent_ms=verify_dwell,
        fingerprint=verify_fp,
        ubid=st.ubid,
    )
    body = {
        "workflowState": st.workflow_state,
        "userData": {"email": st.email, "fullName": st.name},
        "otpCode": otp_code,
        "browserData": bd,
    }
    try:
        body_len = len(json.dumps(body, separators=(",", ":")))
    except Exception:
        body_len = -1
    emit(
        {
            "event": "debug",
            "msg": "profile-create-identity-request",
            "body_len": body_len,
            "fp_len": len(verify_fp),
            "capture_body_len": 6970,
            "verify_dwell_ms": verify_dwell,
            "wall_sleep": True,
            # never log otp/email/fp ciphertext
        }
    )
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
    """Set password via signup/api/execute.

    Payload shape from signin_app.js createPasswordPage (verified against SPA):
      {stepId, actionId:"SUBMIT",
       inputs:[{input_type:"PasswordRequestInput", password,
                successfullyEncrypted, errorLog}]}

    No FingerPrintRequestInput in password inputs (SPA does not send one).
    Password is sent plaintext when no Web Crypto encryption context is
    available (successfullyEncrypted="NOT_APPLICABLE").
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

    # Prefer workflow_state_handle; fall back to registration_code
    handle = st.workflow_state_handle or st.registration_code

    # SPA doesn't send FingerPrintRequestInput with password.
    # Password is sent as-is (no encryption context available).
    base = {
        "actionId": "SUBMIT",
        "workflowStateHandle": handle,
        "inputs": [
            {
                "input_type": _PASSWORD_INPUT_TYPE,
                "password": st.password,
                "successfullyEncrypted": "NOT_APPLICABLE",
                "errorLog": None,
            }
        ],
    }

    # stepId candidates — SPA uses the current workflow stepId (from stepReducer).
    # We don't have the SPA runtime state, so try the known values.
    stepid_candidates = [""]
    # If workflow_state_handle differs from registration_code, try "createPassword"
    # as the stepId (matching the CREDENTIAL_COLLECTION page name).
    if st.workflow_state_handle:
        stepid_candidates.append("createPassword")
    # Also try the current workflow stepId if available from cookie/state
    if st.workflow_state:
        stepid_candidates.append(st.workflow_state)

    last_err = "password-execute-failed"
    password_set = False
    for step_id in stepid_candidates:
        body = dict(base)
        body["stepId"] = step_id
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
            _log_response_debug(r, "password", step_id=step_id)
            if r.status_code < 400:
                data = _json_or_empty(r)
                if data.get("workflowStateHandle"):
                    st.workflow_state_handle = str(data["workflowStateHandle"])
                # Pull authCode/state from redirect-ish fields if present
                for key in ("redirectUrl", "redirect", "location"):
                    ru = data.get(key)
                    if isinstance(ru, str) and ru:
                        _pull_auth_from_url(st, ru)
                body_keys = list(data.keys())
                safe_vals = {}
                for k in body_keys:
                    v = data[k]
                    if isinstance(v, str):
                        safe_vals[k] = v[:120] if len(v) > 120 else v
                    elif isinstance(v, bool | int | float | None):
                        safe_vals[k] = v
                    elif isinstance(v, dict):
                        safe_vals[k] = {sk: sv if isinstance(sv, str) and len(sv) < 80 else str(type(sv).__name__) for sk, sv in v.items()}
                    else:
                        safe_vals[k] = str(type(v).__name__)
                emit(
                    {
                        "event": "debug",
                        "msg": "password-execute-ok",
                        "stepId": step_id,
                        "next_stepId": data.get("stepId"),
                        "has_auth_code": bool(st.auth_code),
                        "has_sso_state": bool(st.sso_state),
                        "body_keys": body_keys,
                        "body_snapshot": safe_vals,
                    }
                )

                # Password was accepted but response returned stepId:"start" with
                # presentationContext (clientId, identityPoolId, SSO_INDIVIDUAL_ID),
                # NOT an authCode-bearing redirect. The SPA continues calling
                # signup/api/execute until the OIDC authorize redirect fires.
                # Continue the loop if no authCode was extracted yet.
                if st.auth_code:
                    emit_step("password", "ok")
                    return
                password_set = True
                emit({"event": "debug", "msg": "password-set-continue-execute-loop"})
                break  # exit step_id candidates loop, enter continuation loop
            last_err = f"password-http-{r.status_code}"
            _log_response_body(r, "password", step_id)
            emit(
                {
                    "event": "debug",
                    "msg": "password-execute-reject",
                    "stepId": step_id,
                    "status": r.status_code,
                }
            )
        except Exception as e:
            last_err = redact_err(e)
            emit(
                {
                    "event": "debug",
                    "msg": "password-execute-error",
                    "stepId": step_id,
                    "error": last_err,
                }
            )

    if not password_set:
        raise RuntimeError(last_err)

    # ---- Post-password execute loop -------------------------------------------
    # The password submit succeeded but the workflow returned stepId:"start"
    # with no authCode.  The SPA continues calling signup/.../execute until
    # the OIDC authorize redirect (which carries authCode) fires.
    #
    # After password is accepted the workflow advances through a login OTP
    # credential step (get-email-otp-login-credential) which routes through
    # Service.SignInLogin → /api/execute (no /signup/ prefix) with
    # EmailOTPLoginRequestInput.  The loop detects this stepId and switches
    # to the login endpoint + OTP input type.
    emit({"event": "debug", "msg": "post-password-execute-loop-start"})
    max_iterations = 10
    for i in range(max_iterations):
        loop_handle = st.workflow_state_handle or st.registration_code
        loop_step_id = "start"  # response always says "start" until done
        loop_rid = _new_request_id()

        # Build inputs: username + fingerprint (matching SPA middleware)
        loop_inputs: list[dict] = []
        if st.email:
            loop_inputs.append(
                {"input_type": "UserRequestInput", "username": st.email}
            )
        loop_inputs.append(
            {
                "input_type": _FINGERPRINT_INPUT_TYPE,
                "fingerPrint": st.fingerprint,
            }
        )
        loop_body = {
            "stepId": loop_step_id,
            "workflowStateHandle": loop_handle,
            "inputs": loop_inputs,
            "visitorId": st.visitor_id,
            "requestId": loop_rid,
        }
        try:
            r = _post_json(
                s,
                f"{SIGNIN_BASE}/platform/{st.directory_id}/signup/api/execute",
                loop_body,
                headers={
                    "Referer": signup_url,
                    "Origin": SIGNIN_BASE,
                    "x-amzn-requestid": loop_rid,
                },
            )
            _log_response_debug(r, "password-execute-loop", iteration=i)

            if r.status_code >= 400:
                _log_response_body(r, "password-execute-loop", i)
                # The signup API may return HTTP 500 when the workflow has
                # transitioned to the login phase — the body still carries
                # stepId so we can detect the switch.
                err_data = _json_or_empty(r)
                err_step_id = err_data.get("stepId") if isinstance(err_data, dict) else None
                # The 500 body may also carry a rotated workflowStateHandle
                # that the login endpoint needs — update if present.
                if isinstance(err_data, dict) and err_data.get("workflowStateHandle"):
                    st.workflow_state_handle = str(err_data["workflowStateHandle"])
                if err_step_id == "get-email-otp-login-credential":
                    emit({"event": "debug", "msg": "password-loop-500-step-detected", "iteration": i})
                    otp_ok = _handle_otp_login_credential(s, st, signup_url)
                    if otp_ok and st.auth_code:
                        emit_step("password", "ok")
                        return
                    # OTP step didn't resolve — fall through to continue
                last_err = f"password-loop-http-{r.status_code}"
                emit({"event": "debug", "msg": last_err, "iteration": i})
                time.sleep(1.0)
                continue

            data = _json_or_empty(r)
            if data.get("workflowStateHandle"):
                st.workflow_state_handle = str(data["workflowStateHandle"])

            # Check for authCode-bearing redirect (OIDC authorize)
            for key in ("redirectUrl", "redirect", "location"):
                ru = data.get(key)
                if isinstance(ru, str) and ru:
                    _pull_auth_from_url(st, ru)

            next_step_id = data.get("stepId")

            body_keys = list(data.keys())
            safe_vals = _safe_body_snapshot(data)

            emit({
                "event": "debug",
                "msg": "password-execute-loop-ok",
                "iteration": i,
                "has_auth_code": bool(st.auth_code),
                "has_sso_state": bool(st.sso_state),
                "has_redirect": any(data.get(k) for k in ("redirectUrl", "redirect", "location") if isinstance(data.get(k), str)),
                "next_stepId": next_step_id,
                "body_keys": body_keys,
                "body_snapshot": safe_vals,
            })

            if st.auth_code:
                emit({"event": "debug", "msg": "password-loop-auth-code-obtained", "iteration": i})
                emit_step("password", "ok")
                return

            # Detect get-email-otp-login-credential → switch to login endpoint
            if next_step_id == "get-email-otp-login-credential":
                emit({"event": "debug", "msg": "password-loop-otp-login-credential-detected", "iteration": i})
                otp_ok = _handle_otp_login_credential(s, st, signup_url)
                if otp_ok and st.auth_code:
                    emit_step("password", "ok")
                    return
                # OTP step failed or didn't yield authCode. The signup workflow
                # has handed off to the login workflow — its handle is dead, so
                # retrying the signup endpoint only burns iterations on
                # INVALID_CSRF_TOKEN (smoke-116 try1: 10× 400). Stop here;
                # _ensure_user_session may still recover from cookies.
                emit({"event": "debug", "msg": "password-loop-otp-login-did-not-resolve-authcode"})
                break

            # Wait briefly between iterations to avoid hammering
            if i < max_iterations - 1:
                time.sleep(0.5)

        except Exception as e:
            last_err = redact_err(e)
            emit({"event": "debug", "msg": "password-execute-loop-error", "iteration": i, "error": last_err})
            if i < max_iterations - 1:
                time.sleep(1.0)
            continue

    # Exhausted without an authCode. Downstream whoAmI / cookie-based session
    # recovery may still work, so we do NOT raise here — but this step did not
    # succeed, and reporting "ok" hid that: smoke-22 logged password:ok with
    # has_auth_code=false, which made device_confirm look like the culprit.
    emit({
        "event": "debug",
        "msg": "password-loop-exhausted",
        "last_error": last_err,
        "has_auth_code": bool(st.auth_code),
    })
    emit_step(
        "password",
        "error",
        message=f"execute loop exhausted without authCode (last_error={last_err})",
    )


def _handle_otp_login_credential(s: Any, st: FlowState, referer: str) -> bool:
    """Handle get-email-otp-login-credential execute step.

    After password creation the signup workflow transitions through a login OTP
    credential step (Service.SignInLogin). This handler:

    1. Sends RETRY action (empty code) to /api/execute to trigger OTP delivery
    2. Waits for OTP via IMAP/tempmail (step_otp)
    3. Sends SUBMIT action with the 6-digit code via /api/execute (login variant)
    4. Checks for authCode-bearing redirect in the response

    Returns True when authCode is obtained, False if OTP extraction failed.
    """
    # Mint a BRAND-NEW login workflow before answering any login step.
    #
    # After the password succeeds the signup workflow completes and AWS hands
    # off to a LOGIN workflow. Reusing the signup handle/cookie fails both ways:
    #   login endpoint  + signup handle/cookie -> INVALID_CSRF_TOKEN (scope)
    #   signup endpoint + a login step         -> INTERNAL_FAILURE (wrong wf)
    # CSRF here is workflow-scoped and the client sends no CSRF header at all
    # (verified in the signin SPA bundle), so the cookie must belong to the
    # workflow being addressed. Loading /login?workflowStateHandle=<signup
    # handle> does not mint one (smoke-23: 200, zero new cookies).
    #
    # Same chain step_bootstrap uses: portal.sso/login -> redirectUrl carrying
    # a fresh handle -> GET that page so its cookies are set.
    redirect_url = f"{VIEW_BASE}/start/#/device?user_code={st.user_code}"
    portal_login = (
        f"{PORTAL_SSO}/login"
        f"?directory_id=view&redirect_url={_url_quote(redirect_url)}"
    )
    try:
        rp = _get(
            s,
            portal_login,
            headers={"Referer": f"{VIEW_BASE}/", "Accept": "application/json"},
        )
        pdata = _json_or_empty(rp)
    except Exception as e:
        emit({"event": "debug", "msg": "login-workflow-portal-error", "error": redact_err(e)})
        return False
    if pdata.get("csrfToken"):
        st.csrf_token = str(pdata["csrfToken"])
    signin_redirect = str(pdata.get("redirectUrl") or "")
    if not signin_redirect:
        emit({"event": "debug", "msg": "login-workflow-no-redirect", "status": getattr(rp, "status_code", 0)})
        return False

    r2 = _get(s, signin_redirect, headers={"Referer": f"{VIEW_BASE}/"})
    login_handle = ""
    for cand in (getattr(r2, "url", "") or "", signin_redirect):
        q = parse_qs(urlparse(cand).query)
        if q.get("workflowStateHandle"):
            login_handle = q["workflowStateHandle"][0]
            break
    if not login_handle:
        emit({"event": "debug", "msg": "login-workflow-no-handle"})
        return False

    # Downstream helpers read st.workflow_state_handle — point it at the LOGIN
    # workflow now that signup is finished.
    st.workflow_state_handle = login_handle
    login_referer = (
        f"{SIGNIN_BASE}/platform/{st.directory_id}/login"
        f"?workflowStateHandle={login_handle}"
    )
    login_execute = f"{SIGNIN_BASE}/platform/{st.directory_id}/api/execute"
    emit({
        "event": "debug",
        "msg": "login-workflow-established",
        "handle_len": len(login_handle),
        "page_status": getattr(r2, "status_code", 0),
        "cookie_names": _cookie_names(s),
    })

    # Drive the fresh login workflow to completion, following the server's
    # stepId instead of assuming one. For an account created moments ago AWS
    # may ask for the password (get-password) or an email OTP
    # (get-email-otp-login-credential) — both are in the SPA's login step enum.
    def _lex(step_id: str, inputs: list, action_id: str | None = None) -> dict | None:
        try:
            return _signin_execute(
                s,
                st,
                path="api/execute",
                step_id=step_id,
                handle=st.workflow_state_handle,
                referer=login_referer,
                inputs=inputs,
                action_id=action_id,
            )
        except Exception as e:
            # redact_err truncates at 300 chars — that cut off message.errorCode,
            # the only field that says *why* (top-level errorCode is null on
            # workflow errors). Parse the embedded body for the nested error.
            detail: dict[str, Any] = {"raw": redact_err(e)}
            m = re.search(r"body=(['\"])(.*)\1\s*$", str(e), re.S)
            if m:
                # The body is truncated upstream (_raise_http [:600]) so it is
                # not parseable JSON — pull the fields out by regex instead.
                body_text = m.group(2)
                ec = re.search(r'"errorCode"\s*:\s*"([^"]*)"', body_text)
                hd = re.search(r'"heading"\s*:\s*"([^"]*)"', body_text)
                detail = {
                    "errorCode": ec.group(1) if ec else None,
                    "heading": hd.group(1) if hd else None,
                    "has_handle": '"workflowStateHandle"' in body_text,
                    "body_len": len(body_text),
                }
            emit({
                "event": "debug",
                "msg": "login-exec-error",
                "stepId": step_id,
                "action": action_id,
                "error": detail,
            })
            return None

    login_fp = _fingerprint(
        dwell_ms=1500,
        location=login_referer,
        referrer=f"{VIEW_BASE}/",
        rng=random.Random(FP_SEED_SEND_OTP),
    )
    fp_input = {"input_type": _FINGERPRINT_INPUT_TYPE, "fingerPrint": login_fp}

    j = _lex("start", [fp_input])
    if j is None:
        return False
    step = str(j.get("stepId") or "start")

    # Headroom: the post-registration login is start -> get-password ->
    # (portal redirect | OTP) -> authCode, and each POST consumes one
    # iteration. range(8) exhausted on the get-password POST itself
    # (smoke-116 try2) — its response never got processed.
    for it in range(12):
        for key in ("redirectUrl", "redirect", "location"):
            ru = j.get(key)
            if isinstance(ru, dict):
                ru = ru.get("url")
            if isinstance(ru, str) and ru:
                _pull_auth_from_url(st, ru)
        if st.auth_code:
            emit({
                "event": "debug",
                "msg": "login-auth-code-obtained",
                "iteration": it,
                "auth_code_source": st.auth_code_source,
                "auth_code_len": len(st.auth_code),
                "has_sso_state": bool(st.sso_state),
            })
            return True

        emit({"event": "debug", "msg": "login-step", "iteration": it, "stepId": step})

        if step in ("start", "get-identity-user"):
            j = _lex(step, [{"input_type": "UserRequestInput", "username": st.email}, fp_input])
        elif step == "get-password":
            # Login password: the SPA encrypts it with the same
            # PasswordEncryptor as creation and posts
            # PasswordRequestInput + successfullyEncrypted + actionId:SUBMIT.
            # Plaintext 400s (live-verified: SIGNIN_BAD_REQUEST_ERROR,
            # smoke-116 try2 — the first run ever to reach this branch).
            ctx = st.encryption_context or {}
            pk = ctx.get("publicKey") if isinstance(ctx, dict) else None
            emit({
                "event": "debug",
                "msg": "login-password-submit",
                "has_ctx": bool(st.encryption_context),
                "ctx_kid": pk.get("kid") if isinstance(pk, dict) else None,
            })
            j = _lex(step, [_build_password_input(st.password, st.encryption_context)],
                     action_id="SUBMIT")
        elif step in (
            "get-new-password-for-password-creation",
            "get-new-password-and-perform-reset-password",
        ):
            # Password *creation*. SPA (app.js CreatePasswordPage.ce):
            #   [resultType, encrypted, errorLog] = await encryptPassword(pw, ctx)
            #   inputs:[{input_type:"PasswordRequestInput", password: encrypted,
            #            successfullyEncrypted: resultType, errorLog}]
            #   actionId:SUBMIT
            # ctx = encryptionContextResponse captured from an earlier execute
            # response. Same input type as login (get-password) — the earlier
            # "different input" theory was disproven live 2026-07-28: login
            # with plaintext 400s identically. (UpdatePasswordRequestInput/
            # newPassword is the *change*-password page, which needs
            # currentPassword — live 400 confirmed it is wrong here.)
            pw_input = _build_password_input(st.password, st.encryption_context)
            ctx = st.encryption_context or {}
            pk = ctx.get("publicKey") if isinstance(ctx, dict) else None
            emit({
                "event": "debug",
                "msg": "password-creation-submit",
                "encrypted": pw_input.get("successfullyEncrypted"),
                "newPassword_len": len(str(pw_input.get("password") or "")),
                "ctx_issuer": ctx.get("issuer"),
                "ctx_audience": ctx.get("audience"),
                "ctx_region": ctx.get("region"),
                "ctx_kid": pk.get("kid") if isinstance(pk, dict) else None,
            })
            j = _lex(step, [pw_input], action_id="SUBMIT")
        elif step in ("resume-signup-create-password", "user-signup"):
            # NOT execute steps. The signin SPA maps both to
            # <WorkflowRedirect to={...url}> — posting to them returns 400.
            # Follow the redirect the response carries instead.
            redir = ""
            if isinstance(j.get("redirect"), dict):
                redir = str(j["redirect"].get("url") or "")
            if not redir:
                redir = str(j.get("redirectUrl") or "")
            if not redir:
                emit({"event": "debug", "msg": "login-redirect-missing", "stepId": step})
                return False
            _pull_auth_from_url(st, redir)
            try:
                rr = _get(s, redir, headers={"Referer": login_referer}, allow_redirects=True)
            except Exception as e:
                emit({"event": "debug", "msg": "login-redirect-error", "error": redact_err(e)})
                return False
            final_url = getattr(rr, "url", "") or redir
            _pull_auth_from_url(st, final_url)
            fp = urlparse(final_url)
            emit({
                "event": "debug",
                "msg": "login-redirect-followed",
                "stepId": step,
                "status": getattr(rr, "status_code", 0),
                "dest_host": fp.netloc,
                "dest_path": fp.path,
                "has_auth_code": bool(st.auth_code),
            })
            if st.auth_code:
                return True
            q = parse_qs(fp.query)
            if q.get("workflowStateHandle"):
                st.workflow_state_handle = q["workflowStateHandle"][0]
            j = _lex("start", [fp_input])
        elif step == "end-of-user-registration-success":
            # Terminal success step. The SPA (SignupWorkflow) maps it to
            # <WorkflowRedirect to={stepReducer.redirect.url}> — a client-side
            # navigation, not an execute step (posting → 400). Live-verified:
            # the redirect chain lands on the SPA's /login shell (state in
            # query, NO authCode). The workflow handle this response rotated
            # to is dead — posting `start` with it yields INVALID_CSRF_TOKEN
            # (CSRF is workflow-scoped). The capture shows the browser
            # bootstrapping a FRESH login workflow here, so mint one exactly
            # like the top of this function does.
            redir = ""
            if isinstance(j.get("redirect"), dict):
                redir = str(j["redirect"].get("url") or "")
            if not redir:
                redir = str(j.get("redirectUrl") or "")
            if not redir:
                emit({
                    "event": "debug",
                    "msg": "end-of-registration-redirect-missing",
                    "body_keys": list(j.keys()),
                })
                return False
            _pull_auth_from_url(st, redir)
            try:
                rr = _get(s, redir, headers={"Referer": login_referer}, allow_redirects=True)
            except Exception as e:
                emit({"event": "debug", "msg": "end-of-registration-redirect-error", "error": redact_err(e)})
                return False
            final_url = getattr(rr, "url", "") or redir
            _pull_auth_from_url(st, final_url)
            fp = urlparse(final_url)
            emit({
                "event": "debug",
                "msg": "end-of-registration-redirect-followed",
                "status": getattr(rr, "status_code", 0),
                "dest_host": fp.netloc,
                "dest_path": fp.path,
                "has_auth_code": bool(st.auth_code),
                "has_sso_state": bool(st.sso_state),
            })
            if st.auth_code:
                return True
            # The redirect lands on the SPA's /login route (a static shell).
            # Mint a fresh post-registration login workflow — same chain as
            # the top of this function: portal.sso/login → redirectUrl → GET
            # → handle from the final URL. Reusing any existing handle fails
            # workflow-scoped CSRF (v1 smoke: INVALID_CSRF_TOKEN).
            redirect_url = f"{VIEW_BASE}/start/#/device?user_code={st.user_code}"
            portal_login = (
                f"{PORTAL_SSO}/login"
                f"?directory_id=view&redirect_url={_url_quote(redirect_url)}"
            )
            try:
                rp = _get(
                    s,
                    portal_login,
                    headers={"Referer": f"{VIEW_BASE}/", "Accept": "application/json"},
                )
                pdata = _json_or_empty(rp)
            except Exception as e:
                emit({"event": "debug", "msg": "end-of-registration-mint-error", "error": redact_err(e)})
                return False
            if pdata.get("csrfToken"):
                st.csrf_token = str(pdata["csrfToken"])
            signin_redirect = str(pdata.get("redirectUrl") or "")
            if not signin_redirect:
                emit({"event": "debug", "msg": "end-of-registration-mint-no-redirect",
                      "status": getattr(rp, "status_code", 0)})
                return False
            r3 = _get(s, signin_redirect, headers={"Referer": f"{VIEW_BASE}/"})
            new_handle = ""
            for cand in (getattr(r3, "url", "") or "", signin_redirect):
                q3 = parse_qs(urlparse(cand).query)
                if q3.get("workflowStateHandle"):
                    new_handle = q3["workflowStateHandle"][0]
                    break
            if not new_handle:
                emit({"event": "debug", "msg": "end-of-registration-mint-no-handle"})
                return False
            st.workflow_state_handle = new_handle
            login_referer = (
                f"{SIGNIN_BASE}/platform/{st.directory_id}/login"
                f"?workflowStateHandle={new_handle}"
            )
            emit({"event": "debug", "msg": "end-of-registration-login-minted",
                  "handle_len": len(new_handle),
                  "page_status": getattr(r3, "status_code", 0),
                  "cookie_names": _cookie_names(s)})
            # Drive the fresh workflow. For an account that just registered the
            # server may hand back a portal redirect straight away (authCode
            # in its chain) or ask for the password (get-password) / an email
            # OTP — return j to the loop so those branches handle it.
            j = _lex("start", [fp_input])
            if j is None:
                return False
            redir2 = ""
            if isinstance(j.get("redirect"), dict):
                redir2 = str(j["redirect"].get("url") or "")
            if not redir2:
                redir2 = str(j.get("redirectUrl") or "")
            if not redir2:
                emit({"event": "debug", "msg": "end-of-registration-start-no-redirect",
                      "stepId": j.get("stepId"), "body_keys": list(j.keys())})
            else:
                _pull_auth_from_url(st, redir2)
                try:
                    rr2 = _get(s, redir2, headers={"Referer": login_referer}, allow_redirects=True)
                except Exception as e:
                    emit({"event": "debug", "msg": "end-of-registration-portal-error", "error": redact_err(e)})
                    return False
                final2 = getattr(rr2, "url", "") or redir2
                _pull_auth_from_url(st, final2)
                fp2 = urlparse(final2)
                emit({"event": "debug", "msg": "end-of-registration-portal-followed",
                      "status": getattr(rr2, "status_code", 0),
                      "dest_host": fp2.netloc, "dest_path": fp2.path,
                      "has_auth_code": bool(st.auth_code),
                      "has_sso_state": bool(st.sso_state)})
                if st.auth_code:
                    return True
        elif step == "get-email-otp-login-credential":
            # RETRY = "resend the OTP"; it carries no credential input.
            rj = _lex(step, [], action_id="RETRY")
            # #133 forensics: the RETRY body is the sole unobserved datum in
            # the plus-alias login-OTP non-delivery (Risk #3) — capture it.
            # Snapshot semantics match password-execute-loop-ok so CONTROL vs
            # PLUS bodies diff apples-to-apples; ok=false records a thrown
            # RETRY (_lex already emitted login-exec-error with the detail).
            emit({
                "event": "debug",
                "msg": "login-retry-response",
                "stepId": step,
                "ok": rj is not None,
                "body_len": len(json.dumps(rj)) if rj is not None else None,
                "body_snapshot": _safe_body_snapshot(rj),
            })
            time.sleep(2.0)
            try:
                code = step_otp(st.email, st.email_source, box=st.tempmail_box)
            except Exception as e:
                emit({"event": "debug", "msg": "login-otp-failed", "error": redact_err(e)})
                return False
            if not code:
                emit({"event": "debug", "msg": "login-otp-not-found"})
                return False
            j = _lex(
                step,
                [{
                    "input_type": _EMAIL_OTP_LOGIN_INPUT_TYPE,
                    "emailOTPLoginResponseCode": code,
                }],
                action_id="SUBMIT",
            )
        elif step == "end-of-workflow-success":
            # Terminal step of the (post-registration) LOGIN workflow, reached
            # after the JWE password is accepted (live-verified 2026-07-28).
            # The SPA maps it to <WorkflowRedirect to={redirect.url}> — the
            # portal handoff whose redirect chain mints the authCode. Follow
            # it; do NOT post `start` (the workflow is complete — its handle
            # is dead, same as end-of-user-registration-success).
            redir = ""
            if isinstance(j.get("redirect"), dict):
                redir = str(j["redirect"].get("url") or "")
            if not redir:
                redir = str(j.get("redirectUrl") or "")
            if not redir:
                emit({
                    "event": "debug",
                    "msg": "end-of-workflow-redirect-missing",
                    "body_keys": list(j.keys()),
                })
                return False
            _pull_auth_from_url(st, redir)
            # Walk the chain hop by hop (allow_redirects=False): curl_cffi
            # 0.15 exposes no redirect history, and the authCode may ride an
            # intermediate Location (or its fragment) that a blind follow
            # would consume invisibly (live run landed on view.awsapps.com
            # /start/ with has_auth_code=false, no portal.sso cookie set).
            hops: list[dict] = []
            cur = redir
            rr = None
            for _hop in range(10):
                try:
                    rr = _get(s, cur, headers={"Referer": login_referer}, allow_redirects=False)
                except Exception as e:
                    hops.append({"url": cur[:200], "error": redact_err(e)})
                    rr = None
                    break
                loc = ""
                if rr.status_code in (301, 302, 303, 307, 308):
                    loc = str(rr.headers.get("Location") or "")
                    if loc and not urlparse(loc).netloc:
                        base = urlparse(cur)
                        loc = f"{base.scheme}://{base.netloc}{loc}"
                _pull_auth_from_url(st, loc)
                hops.append({
                    "url": cur[:200],
                    "status": rr.status_code,
                    "loc": loc[:200],
                    "set_cookie": (rr.headers.get("Set-Cookie") or "")[:120],
                })
                if not loc:
                    break
                cur = loc
            final_url = cur
            _pull_auth_from_url(st, final_url)
            fp = urlparse(final_url)
            emit({
                "event": "debug",
                "msg": "end-of-workflow-redirect-walked",
                "original": redir[:600],
                "original_len": len(redir),
                "hops": hops,
                "dest_host": fp.netloc,
                "dest_path": fp.path,
                "has_auth_code": bool(st.auth_code),
                "has_sso_state": bool(st.sso_state),
                "cookie_names": _cookie_names(s),
            })
            if st.auth_code:
                return True
            return False
        else:
            emit({
                "event": "debug",
                "msg": "login-step-unhandled",
                "stepId": step,
                "body_keys": list(j.keys()),
            })
            return False

        if j is None:
            return False
        step = str(j.get("stepId") or "")

    emit({"event": "debug", "msg": "login-loop-exhausted", "has_auth_code": bool(st.auth_code)})
    return bool(st.auth_code)


def _log_response_debug(r: Any, step_name: str, **extra: Any) -> None:
    """Log response summary (status + content-type + approximate size)."""
    ct = (r.headers.get("Content-Type") or "") if hasattr(r, "headers") else ""
    body_len = len(r.text or "") if hasattr(r, "text") else -1
    emit({
        "event": "debug",
        "msg": f"{step_name}-response",
        "status": getattr(r, "status_code", 0),
        "content_type": ct,
        "body_len": body_len,
        **extra,
    })


def _log_response_body(r: Any, step_name: str, step_id: str) -> None:
    """Log safe fields from response body (errorCode, message — no secrets)."""
    try:
        data = _json_or_empty(r)
        if not data:
            emit({
                "event": "debug",
                "msg": f"{step_name}-body-empty",
                "stepId": step_id,
            })
            return
        safe = {
            k: v for k, v in data.items()
            if k.lower() not in ("password", "otp", "code", "secret", "token", "authorization")
            and not isinstance(v, str) or len(str(v)) < 200
        }
        emit({
            "event": "debug",
            "msg": f"{step_name}-body",
            "stepId": step_id,
            "keys": list(data.keys()),
            # Top-level errorCode is often null while the real code is nested in
            # message.errorCode (e.g. INVALID_CSRF_TOKEN) — surface both.
            "errorCode": data.get("errorCode")
            or (data.get("message") or {}).get("errorCode")
            if isinstance(data.get("message"), dict)
            else data.get("errorCode"),
            "message": data.get("message"),
            "workflowStateHandle_len": len(data.get("workflowStateHandle") or ""),
            "safe_keys_sample": safe,
        })
    except Exception as e:
        emit({
            "event": "debug",
            "msg": f"{step_name}-body-parse-error",
            "error": redact_err(e),
        })


def _pull_auth_from_url(st: FlowState, url: str) -> None:
    pu = urlparse(url)
    qs = parse_qs(pu.query)
    host = pu.netloc.lower()
    # The signin workflow's end-of-workflow redirect hands off to the portal
    # as view.awsapps.com/start/?workflowResultHandle=<uuid>&state=<KMS blob>;
    # the portal SPA reads workflowResultHandle from the query and POSTs it to
    # /auth/sso-token as `authCode` (bundle: getOrchestratorToken,
    # loggedApiOperation GetTokenFromIDPOrchestratorAuthCode).
    #
    # HOST GATE: only the portal handoff host (view.awsapps.com) carries a
    # real authCode. The signin SPA's own redirects (us-east-1.signin.aws)
    # also carry `state`/`code`-ish params for its internal navigation, and
    # the loop-top pull runs on EVERY response's redirectUrl — an ungated
    # match there bails the login loop early with a garbage authCode that
    # then 400s the sso-token exchange (smoke-116 try3: auth_code obtained
    # at iteration 5 with no end-of-workflow-success in the log).
    is_portal = host == "view.awsapps.com"
    src = f"{host}{pu.path}"
    for key in ("authCode", "workflowResultHandle", "code"):
        if qs.get(key) and not st.auth_code and is_portal:
            st.auth_code = qs[key][0]
            st.auth_code_source = f"query:{src}:{key}"
    # sso_state is portal-handoff state too — the exchange posts it alongside
    # the authCode. The signin SPA's own `state` is a different opaque blob;
    # capturing it here would shadow st.sign_in_state in the exchange.
    if qs.get("state") and is_portal:
        st.sso_state = qs["state"][0]
    frag = pu.fragment or ""
    if is_portal and re.search(r"(?:authCode|workflowResultHandle|code)=", frag):
        m = re.search(r"(?:authCode|workflowResultHandle|code)=([^&]+)", frag)
        if m and not st.auth_code:
            st.auth_code = unquote(m.group(1))
            st.auth_code_source = f"fragment:{src}"
    if is_portal and "state=" in frag and not st.sso_state:
        m = re.search(r"state=([^&]+)", frag)
        if m:
            st.sso_state = unquote(m.group(1))


def step_device_confirm(s: Any, st: FlowState) -> None:
    """accept_user_code + associate_token after session is established."""
    emit_step("device_confirm", "pending")

    # Ensure we have a user session (SSO token). Try whoAmI first.
    _ensure_user_session(s, st)
    emit({
        "event": "debug",
        "msg": "device-confirm-diag",
        "has_user_session": bool(st.user_session_id),
        "has_auth_code": bool(st.auth_code),
        "auth_code_source": st.auth_code_source,
        "auth_code_len": len(st.auth_code),
        "has_sso_state": bool(st.sso_state),
        "has_sign_in_state": bool(st.sign_in_state),
        "has_csrf_token": bool(st.csrf_token),
        "has_registration_code": bool(st.registration_code),
        "has_workflow_state_handle": bool(st.workflow_state_handle),
        "cookie_names": _cookie_names(s),
    })
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
    # NOTE: associate_token is NOT called here. The portal SPA names it
    # `approveDeviceAuthorization` — it is the consent APPROVAL action that
    # CONSUMES the user code. Capture order is:
    #   accept_user_code → consent_details (PENDING) → associate_token (approve)
    # Calling associate_token before consent_details burns the code and
    # consent_details then 400s "Invalid user code provided" (smoke-117).
    # associate_token lives in step_consent, after consent_details.
    emit_step("device_confirm", "ok")


def _ensure_user_session(s: Any, st: FlowState) -> None:
    """Populate st.user_session_id via whoAmI and/or sso-token exchange."""
    # whoAmI may already work if password step set session cookies
    whoami: dict[str, Any] = {}
    try:
        r = _get(
            s,
            f"{PORTAL_SSO}/token/whoAmI",
            headers={
                # Portal SPA runs on view.awsapps.com — every portal.sso call
                # is cross-origin from there, so the browser stamps Origin:
                # view.awsapps.com. _fetch_headers derives it from the TARGET
                # url (portal.sso.…), which the server rejects: smoke-117
                # "Origin not allowed: https://portal.sso.us-east-1.amazonaws.com".
                "Origin": VIEW_BASE,
                "Referer": f"{VIEW_BASE}/",
                "Accept": "application/json, text/plain, */*",
            },
        )
        whoami["status"] = r.status_code
        if r.status_code < 400:
            data = _json_or_empty(r)
            # Capture uses "token" null on whoAmI after auth; session may be cookie-based.
            # originSessionId / userIdentifier may identify session; OIDC wants the SSO token string.
            tok = data.get("token")
            if isinstance(tok, str) and tok:
                st.user_session_id = tok
            whoami["has_token"] = bool(tok)
            whoami["body_keys"] = sorted(data.keys())[:10]
        else:
            whoami["body"] = (r.text or "")[:300]
        # Some builds put the session in authorization header echoes — keep going.
    except Exception as e:
        emit({"event": "debug", "msg": "whoAmI-soft-fail", "error": redact_err(e)})

    # sso-token exchange if we have authCode from password redirect
    if not st.user_session_id and st.auth_code:
        try:
            headers = {
                "Origin": VIEW_BASE,  # cross-origin from the SPA — see whoAmI note
                "Referer": f"{VIEW_BASE}/",
                "Accept": "application/json, text/plain, */*",
            }
            csrf_sent = False
            if st.csrf_token:
                headers["x-amz-sso-csrf-token"] = st.csrf_token
                csrf_sent = True
            state_used = st.sso_state or st.sign_in_state or ""
            r2 = _post_form(
                s,
                f"{PORTAL_SSO}/auth/sso-token",
                {
                    "authCode": st.auth_code,
                    "state": state_used,
                    "orgId": "view",
                },
                headers=headers,
            )
            diag: dict[str, Any] = {
                "status": r2.status_code,
                "csrf_sent": csrf_sent,
                "state_source": "sso_state" if st.sso_state else ("sign_in_state" if st.sign_in_state else "empty"),
                "state_len": len(state_used),
                "auth_code_len": len(st.auth_code),
                "auth_code_source": st.auth_code_source,
            }
            if r2.status_code < 400:
                data2 = _json_or_empty(r2)
                tok = data2.get("token")
                if isinstance(tok, str) and tok:
                    st.user_session_id = tok
                if data2.get("redirectUrl"):
                    _pull_auth_from_url(st, str(data2["redirectUrl"]))
                diag["has_token"] = bool(tok)
                diag["has_redirect_url"] = bool(data2.get("redirectUrl"))
                diag["init_type"] = data2.get("initType")
                diag["error_message"] = data2.get("errorMessage")
            else:
                # The exchange 400'd SILENTLY in smoke-116 try3 (no else
                # branch here) — the errorMessage/errorCode in the body is
                # the only signal for why (stale authCode, wrong state,
                # csrf). Never swallow this again.
                diag["body"] = (r2.text or "")[:500]
            emit({"event": "debug", "msg": "sso-token-exchange", **diag})
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

    # associate_token — the consent APPROVAL (portal SPA names it
    # approveDeviceAuthorization). Must come AFTER consent_details: it
    # consumes the user code, so calling it first makes consent_details
    # 400 "Invalid user code provided" (smoke-117). Capture order is
    # accept_user_code → consent_details (PENDING) → associate_token.
    r_assoc = _post_json(
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
    _raise_http("consent", r_assoc, "associate_token")
    emit({"event": "debug", "msg": "associate-token-ok", "status": r_assoc.status_code})

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


def is_bare_gmail(email: str) -> bool:
    """True if email is a bare @gmail.com address (needs Google OAuth, unsupported).

    Plus-aliases (base+tag@gmail.com) are allowed: they register as distinct
    AWS accounts but deliver to the base inbox for OTP reads. A non-empty tag
    after "+" is required: "user+@gmail.com" has an empty tag, which Gmail
    normalizes to bare "user@gmail.com" (the google path).

    Mirrors KiroProvider.detectMethod in index.js — keep both in sync.
    """
    lower_email = (email or "").strip().lower()
    if not lower_email.endswith("@gmail.com"):
        return False
    local_part = lower_email.split("@", 1)[0]
    plus_idx = local_part.find("+")
    has_tag = plus_idx != -1 and len(local_part[plus_idx + 1:]) > 0
    return not has_tag


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
    # Hard reject bare gmail in worker too (belt + Node check).
    if is_bare_gmail(email):
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
        st.email_source = email_source
        st.tempmail_box = box

        s = make_session(proxy=proxy)
        try:
            step = "bootstrap"
            # Email is known before bootstrap (tempmail creates first; imap is CLI arg)
            # so signin EMPTY signup can register username before profile send-otp.
            step_bootstrap(s, st, device_url, email=email)

            step = "email_entry"
            step_email_entry(s, st, email)
            # SPA EMAIL_VERIFICATION form mounts after send-otp success.
            # Capture: ~14.7s wall to create-identity, timeSpentOnPage≈13033.
            verify_form_t0 = time.time()

            step = "otp"
            code = step_otp(email, email_source, box=box)

            step = "otp_verify"
            step_create_identity(s, st, code, verify_t0=verify_form_t0)

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
        # Include traceback for bootstrap errors (line number, file, call chain)
        import traceback
        tb = traceback.format_exc()
        emit({"event": "debug", "msg": "unhandled-exception", "traceback": tb[:2000]})
        sys.stderr.write(tb + "\n")
        sys.stderr.flush()
        emit_step(step, "error", message=err_str)
        emit_result(False, error=err_str, step=step)
        return 1


if __name__ == "__main__":
    raise SystemExit(run())
