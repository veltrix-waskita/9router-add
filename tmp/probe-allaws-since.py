#!/usr/bin/env python3
"""Probe #5 (fork resolver): enumerate ALL AWS mails in this Gmail since the
Stage 1 re-run, regardless of recipient. Probe #4 found exactly 1 mail To:
plus_a alias (the signup OTP). If AWS sent the login OTP with the +tag
STRIPPED from To: (Risk #2's second half), probe #4's TO-search would miss it
but it is still in All Mail. Prints To/Date/Subject/Message-ID-prefix only —
NO body, NO code values, NO secrets.

Fork:
- only the 21:46:39 signup mail exists → AWS never sent the login OTP (AWS-side).
- a later mail with To: base@gmail.com (no tag) → tag stripped at login moment
  → read_otp's TO-search/gate missed a delivered mail (our bug, fixable).
"""
import imaplib
import json
import os
from email import message_from_bytes

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def main() -> None:
    with open(os.path.join(REPO, "config.json")) as f:
        cfg = json.load(f)
    ic = cfg["imap"]
    pk = (cfg.get("providers") or {}).get("kiro") or cfg.get("providerConfig") or {}
    sender = (pk.get("otpSenderDomain") or "signin.aws").strip() or "signin.aws"
    m = imaplib.IMAP4_SSL(ic.get("host") or "imap.gmail.com", int(ic.get("port") or 993))
    m.login(ic["user"].strip().lower(), ic["password"])

    # All Mail = superset minus Trash/Spam; Spam already probed (#4: count=0).
    # Trash included for exhaustiveness (locale name "[Gmail]/Tong Sampah").
    for mb in ('"[Gmail]/Semua Email"', '"[Gmail]/Tong Sampah"'):
        typ, _ = m.select(mb)
        if typ != "OK":
            print(f"[probe5] {mb}: select FAILED")
            continue
        typ, data = m.search(None, f'(FROM "{sender}" SINCE "29-Jul-2026")')
        ids = data[0].split() if typ == "OK" and data and data[0] else []
        print(f"[probe5] {mb} AWS-mails since 29-Jul-2026: count={len(ids)}")
        for j in ids[:20]:
            _, dt = m.fetch(j, "(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID TO SUBJECT DATE)])")
            hdr = dt[0][1] if dt and dt[0] and isinstance(dt[0], tuple) else b""
            hmsg = message_from_bytes(hdr)
            print(f"[probe5]   date=[{hmsg.get('Date','')}] "
                  f"to=[{(hmsg.get('To') or '')[:60]}] "
                  f"subj=[{(hmsg.get('Subject') or '')[:45]}] "
                  f"mid=[{(hmsg.get('Message-ID') or '?')[:40]}]")
    m.logout()


if __name__ == "__main__":
    main()
