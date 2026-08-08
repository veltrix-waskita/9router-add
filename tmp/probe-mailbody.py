#!/usr/bin/env python3
"""Probe #7 (decisive for the user's "otp masuk kok ke imap"): inspect the ONE
amazonaws.com mail probe #6 surfaced (20:13:14 UTC, mo88wgk9 alias) — is it an
OTP mail from a different sender domain? Prints full subject + headers and a
DIGIT-MASKED body preview (every 4+ digit run → [Ndigits]); NEVER prints a code
value. Fork:
- body has a 6-digit pattern + OTP-ish wording → login OTP from @amazonaws.com
  → Risk #3 COLLAPSES; real bug = production FROM-filter (otpSenderDomain too
  narrow) — fixable, and explains CONTROL-pass/IMAP-fail asymmetry.
- notification/nudge wording, no code → unrelated; Risk #3 stands for PLUS_A.
"""
import imaplib
import json
import os
import re
from email import message_from_bytes
from email.policy import default as default_policy

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def mask(text: str) -> str:
    return re.sub(r"\d{4,}", lambda m: f"[{len(m.group(0))}digits]", text)


def main() -> None:
    with open(os.path.join(REPO, "config.json")) as f:
        cfg = json.load(f)
    ic = cfg["imap"]
    m = imaplib.IMAP4_SSL(ic.get("host") or "imap.gmail.com", int(ic.get("port") or 993))
    m.login(ic["user"].strip().lower(), ic["password"])
    typ, _ = m.select('"[Gmail]/Semua Email"')
    assert typ == "OK"
    typ, data = m.search(None, 'FROM "amazonaws.com" SINCE "29-Jul-2026"')
    ids = data[0].split() if typ == "OK" and data and data[0] else []
    print(f"[probe7] amazonaws.com mails since 29-Jul: count={len(ids)}")
    for j in ids[:3]:
        _, dt = m.fetch(j, "(BODY.PEEK[])")
        raw = dt[0][1] if dt and dt[0] and isinstance(dt[0], tuple) else b""
        msg = message_from_bytes(raw, policy=default_policy)
        print(f"[probe7] === mail {j.decode()} ===")
        print(f"[probe7] Date: {msg.get('Date')}")
        print(f"[probe7] From: {msg.get('From')}")
        print(f"[probe7] To: {msg.get('To')}")
        print(f"[probe7] Subject: {msg.get('Subject')}")
        body = msg.get_body(preferencelist=("plain", "html"))
        content = body.get_content() if body else ""
        if body is not None and body.get_content_subtype() == "html":
            content = re.sub(r"<[^>]+>", " ", content)
        content = re.sub(r"\s+", " ", content).strip()
        print(f"[probe7] body-chars={len(content)}")
        print(f"[probe7] body-masked[:600]: {mask(content[:600])}")
        sixes = re.findall(r"\b\d{6}\b", content)
        print(f"[probe7] six-digit-code-present: {bool(sixes)} (count={len(sixes)})")
    m.logout()


if __name__ == "__main__":
    main()
