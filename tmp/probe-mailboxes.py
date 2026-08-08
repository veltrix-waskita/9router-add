#!/usr/bin/env python3
"""Probe #2: what mailboxes does this Gmail account actually expose via IMAP,
and can each All Mail / Trash variant be SELECTed? Resolves whether probe #1's
select failures are a namespace/locale issue or IMAP-visibility setting.

Prints mailbox NAMES only (no message content, no secrets).
"""
import imaplib
import json
import os

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def main() -> None:
    with open(os.path.join(REPO, "config.json")) as f:
        cfg = json.load(f)
    ic = cfg["imap"]
    m = imaplib.IMAP4_SSL(ic.get("host") or "imap.gmail.com", int(ic.get("port") or 993))
    m.login(ic["user"].strip().lower(), ic["password"])

    typ, boxes = m.list()
    print(f"[probe2] LIST typ={typ} count={len(boxes or [])}")
    for b in boxes or []:
        # b is like: (\\HasNoChildren) "/" "[Gmail]/All Mail"
        print(f"[probe2]   {b.decode(errors='replace')}")

    candidates = [
        '"[Gmail]/All Mail"',
        '"[Google Mail]/All Mail"',
        '"[Gmail]/Trash"',
        '"[Google Mail]/Trash"',
        '"[Gmail]/Papierkorb"',
        '"[Google Mail]/Papierkorb"',
        '"[Gmail]/Spam"',
        '"[Google Mail]/Spam"',
    ]
    for mb in candidates:
        try:
            typ, data = m.select(mb)
            n = data[0].decode() if data and data[0] else "?"
            print(f"[probe2] SELECT {mb}: typ={typ} exists={n}")
        except Exception as e:
            print(f"[probe2] SELECT {mb}: EXC {type(e).__name__}")
        try:
            m.close()  # unselect (no expunge) before next select
        except Exception:
            pass
    m.logout()


if __name__ == "__main__":
    main()
