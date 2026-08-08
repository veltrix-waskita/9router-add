#!/usr/bin/env python3
"""Probe #4 (decisive for PLUS_A): did AWS ever send the LOGIN OTP to the
plus_a alias? Stage 1 re-run c2e51w6y: signup OTP read at 21.8s, then the
login OTP step polled 320s with no code. Count signin.aws mails addressed to
the plus_a alias in INBOX / All Mail / Spam and print header metadata only
(Message-ID, To, Subject, Date — NO body, NO code values, NO secrets).

If count == 1 everywhere → AWS sent only the signup OTP (AWS-side).
If count >= 2 → the login OTP WAS delivered; read_otp missed it (our bug).
"""
import imaplib
import json
import os
from email import message_from_bytes

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TARGET = "tauvindpwtuba+stage1ac2e51w6y@gmail.com"


def main() -> None:
    with open(os.path.join(REPO, "config.json")) as f:
        cfg = json.load(f)
    ic = cfg["imap"]
    pk = (cfg.get("providers") or {}).get("kiro") or cfg.get("providerConfig") or {}
    sender = (pk.get("otpSenderDomain") or "signin.aws").strip() or "signin.aws"
    m = imaplib.IMAP4_SSL(ic.get("host") or "imap.gmail.com", int(ic.get("port") or 993))
    m.login(ic["user"].strip().lower(), ic["password"])

    for mb in ("INBOX", '"[Gmail]/Semua Email"', '"[Gmail]/Spam"'):
        typ, _ = m.select(mb)
        if typ != "OK":
            print(f"[probe4] {mb}: select FAILED")
            continue
        typ, data = m.search(None, f'(TO "{TARGET}" FROM "{sender}")')
        ids = data[0].split() if typ == "OK" and data and data[0] else []
        print(f"[probe4] {mb}: match_count={len(ids)}")
        for j in ids[:6]:
            _, dt = m.fetch(j, "(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID TO SUBJECT DATE)])")
            hdr = dt[0][1] if dt and dt[0] and isinstance(dt[0], tuple) else b""
            hmsg = message_from_bytes(hdr)
            print(f"[probe4]   mid=[{(hmsg.get('Message-ID') or '?')[:70]}] "
                  f"date=[{hmsg.get('Date','')}] "
                  f"subj=[{(hmsg.get('Subject') or '')[:50]}]")
    m.logout()


if __name__ == "__main__":
    main()
