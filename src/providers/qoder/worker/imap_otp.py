#!/usr/bin/env python3
"""IMAP OTP polling for the qoder worker (ported from kiro's imap helpers).

Deliberately self-contained: signup.py imports it lazily inside poll_otp so
unit tests and --self-test never require a network or an IMAP account.

Defaults target Gmail (imap.gmail.com:993) — the same plus-alias inbox
mechanics as kiro — but sender_domain defaults to qoder.com. Callers
override via imap_cfg_from_env() (QODER_IMAP_* env vars).
"""
from __future__ import annotations

import email as emaillib
from email.utils import getaddresses
import hashlib
import html
import imaplib
import json
import os
import re
import sys
import time
from typing import Any

# ---- OTP extraction (qoder = 6-digit, plain) --------------------------------


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
_QODER_MARKERS = ("qoder", "verification", "verify")
_OTP_NOISE = {"111111", "222222", "123456", "000000", "999999", "666666"}


def extract_otp(text: str, subject: str = "") -> str | None:
    """Extract a 6-digit OTP code from text. None = no match/noise."""
    m = _OTP_DIGIT6_RE.search(text)
    if m and m.group(1) not in _OTP_NOISE:
        return m.group(1)
    for m in _OTP_HYPHEN_RE.finditer(text):
        return m.group(1).upper()
    has_qoder = any(marker in text.lower() for marker in _QODER_MARKERS)
    if has_qoder:
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
    return re.sub(r"\s+", " ", clean).strip()


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
            body = _strip_html(raw) if ct == "text/html" else raw
        except Exception:
            return None

    code = extract_otp(subject)
    if code:
        return code
    return extract_otp(body)


# ── IMAP polling (ported from kiro) ────────────────────────────────────────

_GMAIL_FALLBACK_MAILBOXES = [
    "INBOX",
    '"[Gmail]/Spam"',
    '"[Google Mail]/Spam"',
    '"[Gmail]/All Mail"',
]


def _quote_mailbox(name: str) -> str:
    return '"' + name.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _parse_list_entry(entry: bytes) -> tuple[set[str], str] | None:
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

    Resolves locale-localized Gmail names via RFC 6154 special-use LIST flags
    (\\Junk, \\All); falls back to English names.
    """
    h = (host or "").lower()
    if not h.endswith("gmail.com"):
        return ["INBOX"]
    if m is None:
        return list(_GMAIL_FALLBACK_MAILBOXES)
    try:
        typ, data = m.list()
    except Exception:
        return list(_GMAIL_FALLBACK_MAILBOXES)
    if typ != "OK" or not data:
        return list(_GMAIL_FALLBACK_MAILBOXES)
    junk = allmail = None
    for entry in data:
        if not isinstance(entry, (bytes, bytearray)):
            continue
        try:
            parsed = _parse_list_entry(entry)
        except Exception:
            continue
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
    """SELECT mailbox; return True only when state becomes SELECTED."""
    try:
        typ, dat = m.select(mailbox)
    except Exception:
        return False
    return bool(typ == "OK" and m.state == "SELECTED")


def _search_ids(m: imaplib.IMAP4, target_email: str, sender_domain: str) -> list:
    """SEARCH candidate ids. sender_domain may be a comma-separated list."""
    domains = [d.strip() for d in sender_domain.split(",") if d.strip()] or ["qoder.com"]
    ids: list[bytes] = []
    for dom in domains:
        try:
            typ, data = m.search(None, f'(TO "{target_email}" FROM "{dom}")')
            got = data[0].split() if typ == "OK" and data and data[0] else []
            ids.extend(got)
        except Exception:
            pass
    if not ids:
        for dom in domains:
            try:
                typ, data = m.search(None, f'(FROM "{dom}")')
                got = data[0].split() if typ == "OK" and data and data[0] else []
                ids.extend(got)
            except Exception:
                pass
    seen: set[bytes] = set()
    out: list[bytes] = []
    for i in ids:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def _message_for(raw: bytes, target_email: str) -> bool:
    """True if raw RFC822 message is addressed to target_email (To/Cc)."""
    try:
        msg = emaillib.message_from_bytes(raw)
    except Exception:
        return False
    target = (target_email or "").strip().lower()
    if not target:
        return False
    headers = (msg.get_all("To") or []) + (msg.get_all("Cc") or [])
    try:
        return any(addr.lower() == target for _, addr in getaddresses(headers))
    except Exception:
        return False


# consumed-OTP tracking (passes per-process; same-process second reads skip)
_CONSUMED_OTP_KEYS: dict[str, set[str]] = {}


def _otp_key(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _mark_otp_consumed(target_email: str, raw: bytes) -> None:
    _CONSUMED_OTP_KEYS.setdefault((target_email or "").strip().lower(), set()).add(_otp_key(raw))


def _was_otp_consumed(target_email: str, raw: bytes) -> bool:
    return _otp_key(raw) in _CONSUMED_OTP_KEYS.get((target_email or "").strip().lower(), set())


def read_otp(
    target_email: str,
    cfg: dict,
    retries: int = 40,
    delay: float = 5.0,
) -> str | None:
    """Poll IMAP for the qoder code. Returns the 6-digit code or None.

    Never logs the code value. Defaults: sender_domain=qoder.com, delay=5s.
    """
    host = cfg["host"]
    port = int(cfg["port"])
    user = cfg["user"]
    pw = cfg["password"]
    use_tls = str(cfg.get("tls", "true")).lower() == "true"
    delete_after = str(cfg.get("delete_after_read", "false")).lower() == "true"
    sender_domain = (
        cfg.get("sender_domain") or "qoder.com"
    ).strip() or "qoder.com"
    t0 = time.time()
    for _ in range(retries):
        try:
            m = imaplib.IMAP4_SSL(host, port) if use_tls else imaplib.IMAP4(host, port)
            try:
                if not user or not pw:
                    return None
                m.login(user, pw)
                mailboxes = _mailboxes_for(host, m)
                found = None
                selected_any = False
                for mailbox in mailboxes:
                    if not _select_mailbox(m, mailbox):
                        continue
                    selected_any = True
                    ids = _search_ids(m, target_email, sender_domain)
                    for i in reversed(ids[-8:]):
                        try:
                            _, dt = m.fetch(i, "(RFC822)")
                        except Exception:
                            continue
                        raw = (
                            dt[0][1]
                            if dt and dt[0] and isinstance(dt[0], tuple)
                            else b""
                        )
                        if raw and _was_otp_consumed(target_email, raw):
                            continue
                        code = extract_otp_from_message(raw)
                        if code:
                            if not _message_for(raw, target_email):
                                continue
                            found = code
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
                    sys.stderr.write("qoder imap: no mailbox selected\n")
                if delete_after and found:
                    try:
                        m.expunge()
                    except Exception:
                        pass
                if found:
                    return found
            finally:
                try:
                    m.logout()
                except Exception:
                    pass
        except Exception as e:
            sys.stderr.write(f"qoder imap: {str(e)[:120]}\n")
        time.sleep(delay)
    return None