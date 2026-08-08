#!/usr/bin/env python3
"""Read-only probe: list recent AWS signin.aws mails in the destination Gmail
with INTERNALDATE + To + masked subject. Answers "why did the sign-in OTP
arrive 3x": mails minutes apart = one run looping; mails hours/days apart (or
to different aliases) = separate runs. No AWS calls, zero spend.
6-digit runs (OTP codes) masked; passwords never touched/printed.
"""
import email
import imaplib
import json
import os
import re
import sys

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
with open(os.path.join(REPO, "config.json")) as f:
    cfg = json.load(f)["imap"]

MASK = re.compile(r"\b\d{6}\b")
BOXES = ["INBOX", '"[Gmail]/Semua Email"', '"[Gmail]/All Mail"',
         '"[Google Mail]/All Mail"', '"[Gmail]/Spam"', '"[Google Mail]/Spam"']

m = imaplib.IMAP4_SSL(cfg["host"], int(cfg["port"]))
m.login(cfg["user"], cfg["password"])
seen = set()
rows = []
for box in BOXES:
    typ, _ = m.select(box, readonly=True)
    if typ != "OK":
        continue
    typ, data = m.search(None, "FROM", '"signin.aws"')
    if typ != "OK" or not data or not data[0]:
        continue
    ids = data[0].split()[-12:]
    for i in reversed(ids):
        typ2, dt = m.fetch(i, "(INTERNALDATE RFC822)")
        if typ2 != "OK" or not dt or not dt[0]:
            continue
        idate = ""
        raw = b""
        for part in dt:
            if isinstance(part, tuple):
                preamble = part[0].decode("utf-8", "replace")
                mm = re.search(r'INTERNALDATE "([^"]+)"', preamble)
                idate = mm.group(1) if mm else ""
                raw = part[1]
        if not raw:
            continue
        mail = email.message_from_bytes(raw)
        mid = mail.get("Message-ID", "")
        if mid in seen:
            continue  # All Mail duplicates INBOX copies
        seen.add(mid)
        rows.append((
            idate,
            box,
            (mail.get("To") or "")[:40],
            MASK.sub("******", (mail.get("Subject") or ""))[:70],
        ))
m.logout()

print(f"{'INTERNALDATE':<28} {'TO':<42} SUBJECT")
for idate, box, to, subj in sorted(rows, key=lambda r: r[0]):
    print(f"{idate:<28} to={to:<40} {subj}")
print(f"\ntotal unique mails from signin.aws: {len(rows)}")
