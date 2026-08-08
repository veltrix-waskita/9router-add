#!/usr/bin/env python3
"""Probe #3 (decisive): probe #1 expunged PLUS_B's signup mail from INBOX but
could not check All Mail — this account is Indonesian-locale, so All Mail is
"[Gmail]/Semua Email" and Trash is "[Gmail]/Tong Sampah" (probe #2 LIST).

Now verify: INBOX search returns 0 (expunge worked) while the SAME message is
still returned by the identical _search_ids query in Semua Email (re-surfaced).
That is the live proof that Gmail EXPUNGE strips only the INBOX label.

Prints counts + Message-ID prefixes + To: only. No secrets.
"""
import imaplib
import json
import os
from email import message_from_bytes

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TARGET = "tauvindpwtuba+stage1bmo88wgk9@gmail.com"


def main() -> None:
    with open(os.path.join(REPO, "config.json")) as f:
        cfg = json.load(f)
    ic = cfg["imap"]
    pk = (cfg.get("providers") or {}).get("kiro") or cfg.get("providerConfig") or {}
    sender = (pk.get("otpSenderDomain") or "signin.aws").strip() or "signin.aws"
    m = imaplib.IMAP4_SSL(ic.get("host") or "imap.gmail.com", int(ic.get("port") or 993))
    m.login(ic["user"].strip().lower(), ic["password"])

    for mb in ("INBOX", '"[Gmail]/Semua Email"', '"[Gmail]/Tong Sampah"',
               '"[Gmail]/Spam"'):
        typ, _ = m.select(mb)
        if typ != "OK":
            print(f"[probe3] {mb}: select FAILED")
            continue
        typ, data = m.search(None, f'(TO "{TARGET}" FROM "{sender}")')
        ids = data[0].split() if typ == "OK" and data and data[0] else []
        print(f"[probe3] {mb}: match_count={len(ids)}")
        for j in ids[:4]:
            _, dt = m.fetch(j, "(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID TO SUBJECT)])")
            hdr = dt[0][1] if dt and dt[0] and isinstance(dt[0], tuple) else b""
            hmsg = message_from_bytes(hdr)
            print(f"[probe3]   mid=[{(hmsg.get('Message-ID') or '?')[:70]}] "
                  f"To=[{hmsg.get('To','')}] Subj=[{(hmsg.get('Subject') or '')[:50]}]")
    m.logout()


if __name__ == "__main__":
    main()
