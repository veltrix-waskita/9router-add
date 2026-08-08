#!/usr/bin/env python3
"""Zero-TES-cost empirical check: does Gmail IMAP EXPUNGE in INBOX leave the
message searchable in [Gmail]/All Mail?

Reproduces production read_otp read #1 (store \\Deleted on the newest gated
hit in SELECTED INBOX, then EXPUNGE) against the PLUS_B signup mail from run
mo88wgk9, then SEARCHes All Mail / Trash with the exact _search_ids query.

Decisive either way:
  All Mail contains_expunged_mid=True  → production delete=true is a no-op for
      the shared-inbox two-OTP path → latent production bug → fix signup.py.
  All Mail contains_expunged_mid=False → expunge really deletes → bug was
      orchestrator-only (delete=false) → orchestrator delete=true suffices.

Secrets: imap password never printed; sender domain used but not printed.
"""
import imaplib
import json
import os
from email import message_from_bytes

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
TARGET = "tauvindpwtuba+stage1bmo88wgk9@gmail.com"  # PLUS_B alias, run mo88wgk9


def main() -> None:
    with open(os.path.join(REPO, "config.json")) as f:
        cfg = json.load(f)
    ic = cfg["imap"]
    pk = (cfg.get("providers") or {}).get("kiro") or cfg.get("providerConfig") or {}
    sender = (pk.get("otpSenderDomain") or "signin.aws").strip() or "signin.aws"
    m = imaplib.IMAP4_SSL(ic.get("host") or "imap.gmail.com", int(ic.get("port") or 993))
    m.login(ic["user"].strip().lower(), ic["password"])

    # ---- read #1 exactly as production read_otp does it (delete_after=true):
    # SELECT INBOX → SEARCH TO+FROM → newest-first → store \Deleted → EXPUNGE.
    typ, _ = m.select("INBOX")
    assert typ == "OK", "select INBOX failed"
    typ, data = m.search(None, f'(TO "{TARGET}" FROM "{sender}")')
    ids = data[0].split() if typ == "OK" and data and data[0] else []
    print(f"[probe] inbox_search_count={len(ids)}")
    deleted_mid = ""
    if ids:
        i = ids[-1]  # reversed(ids[-8:]) takes the newest first
        _, dt = m.fetch(i, "(RFC822)")
        raw = dt[0][1] if dt and dt[0] and isinstance(dt[0], tuple) else b""
        msg = message_from_bytes(raw)
        deleted_mid = (msg.get("Message-ID") or "").strip()
        print(f"[probe] inbox_newest To=[{msg.get('To','')}] "
              f"Message-ID=[{deleted_mid[:60]}]")
        m.store(i, "+FLAGS", "\\Deleted")
        m.expunge()
        print("[probe] inbox store(+\\Deleted)+expunge=done")
    else:
        print("[probe] nothing to expunge — mail already gone; All Mail check "
              "below still shows whether earlier expunges re-surface")

    # ---- read #2 as production's sweep would reach it: All Mail, then Trash.
    for mb in ('"[Gmail]/All Mail"', '"[Gmail]/Trash"'):
        typ, _ = m.select(mb)
        if typ != "OK":
            print(f"[probe] {mb}: select FAILED")
            continue
        typ, data = m.search(None, f'(TO "{TARGET}" FROM "{sender}")')
        ids2 = data[0].split() if typ == "OK" and data and data[0] else []
        mids = []
        for j in ids2:
            _, dt = m.fetch(j, "(BODY.PEEK[HEADER.FIELDS (MESSAGE-ID TO SUBJECT)])")
            hdr = dt[0][1] if dt and dt[0] and isinstance(dt[0], tuple) else b""
            hmsg = message_from_bytes(hdr)
            mids.append((hmsg.get("Message-ID") or "?").strip())
        present = bool(deleted_mid) and deleted_mid in mids
        print(f"[probe] {mb}: count={len(ids2)} "
              f"contains_expunged_mid={present}")
    m.logout()


if __name__ == "__main__":
    main()
