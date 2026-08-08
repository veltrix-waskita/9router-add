#!/usr/bin/env python3
"""Probe #6 (user challenge: "otp masuk kok ke imap"): re-enumerate with WIDER
coverage than probe #5, which had three holes: (a) Spam not scanned FROM-only
(All Mail EXCLUDES Spam), (b) sender filtered to signin.aws only (a login OTP
could come from @amazon.com / @email.amazon.com), (c) hidden Gmail labels are
invisible to IMAP entirely (filters with "skip inbox" + hidden label). Prints
visible mailbox list + Date/From/To/Subject/Message-ID-prefix — NO body, NO
code values, NO secrets.

Forks:
- count unchanged (2 signup mails only) → user may be seeing the signup OTP or
  a web-UI-only (IMAP-hidden) mail → ask which folder/subject they see.
- a NEW mail (later date, OTP-ish subject) → late delivery or Spam/other-sender
  → Risk #3 collapses; blocker = our read path (fixable).
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
    m = imaplib.IMAP4_SSL(ic.get("host") or "imap.gmail.com", int(ic.get("port") or 993))
    m.login(ic["user"].strip().lower(), ic["password"])

    typ, boxes = m.list()
    visible = boxes if typ == "OK" and boxes else []
    print(f"[probe6] IMAP-visible mailboxes: count={len(visible)}")
    for b in visible:
        print(f"[probe6]   {b.decode(errors='replace')[:110]}")

    # Broad sender net: signin.aws OR amazon OR aws; SINCE the run day.
    query = '(OR FROM "signin.aws" (OR FROM "amazon" FROM "aws")) SINCE "29-Jul-2026"'
    # INBOX + Spam + All Mail + Trash = full account coverage (All Mail
    # excludes Spam and Trash, hence all four).
    for mb in ("INBOX", '"[Gmail]/Spam"', '"[Gmail]/Semua Email"', '"[Gmail]/Tong Sampah"'):
        typ, _ = m.select(mb)
        if typ != "OK":
            print(f"[probe6] {mb}: select FAILED")
            continue
        typ, data = m.search(None, query)
        ids = data[0].split() if typ == "OK" and data and data[0] else []
        print(f"[probe6] {mb}: count={len(ids)}")
        for j in ids[:25]:
            _, dt = m.fetch(j, "(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID FROM TO SUBJECT DATE)])")
            hdr = dt[0][1] if dt and dt[0] and isinstance(dt[0], tuple) else b""
            h = message_from_bytes(hdr)
            print(f"[probe6]   date=[{h.get('Date','')}] "
                  f"from=[{(h.get('From') or '')[:45]}] "
                  f"to=[{(h.get('To') or '')[:55]}] "
                  f"subj=[{(h.get('Subject') or '')[:40]}]")
    m.logout()


if __name__ == "__main__":
    main()
