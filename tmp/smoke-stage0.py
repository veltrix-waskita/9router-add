#!/usr/bin/env python3
"""Stage 0 smoke — gmail plus-alias plumbing (no AWS, no TES).

Proves against LIVE Gmail what unit tests cannot (they only exercise code
logic against synthetic bytes):

  G1 delivery            mail to base+tagA / base+tagB lands in the base inbox
  G2 To-header preserve  the delivered RFC822 To: literally contains base+tag
                         (the _message_for gate depends on this — SPOF)
  G3 gate agreement      signup._message_for(raw, target) returns the correct
                         True/False on REAL delivered bytes, incl. cross-alias
  (informational)        IMAP SEARCH (TO "base+tag") recall/precision, and
                         whether SEARCH (TO "base@") collapses all aliases

Method: self-send via Gmail SMTP (base -> its own plus-aliases). This isolates
Gmail's delivery/header behavior from AWS's mailer; the AWS-side half (does
AWS put the plus-alias in To: when it sends the OTP) is Stage 1.

Credentials come from config.json (imap block). The password is NEVER printed.
Exit code 0 only if G1 + G2 + G3 all pass.
"""
import imaplib
import json
import os
import secrets
import smtplib
import string
import sys
import time
from email import message_from_bytes
from email.message import EmailMessage

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WORKER = os.path.join(REPO, "src", "providers", "kiro", "worker")
sys.path.insert(0, WORKER)
from signup import _message_for  # noqa: E402  (the real gate, not a copy)

POLL_TIMEOUT_S = 90
POLL_INTERVAL_S = 5
# Same mailbox order the worker searches (_mailboxes_for in signup.py).
MAILBOXES = ["INBOX", '"[Gmail]/Spam"', '"[Google Mail]/Spam"', '"[Gmail]/All Mail"']


def load_imap_cfg() -> dict:
    with open(os.path.join(REPO, "config.json")) as f:
        cfg = json.load(f)
    ic = cfg.get("imap") or {}
    user = (ic.get("user") or "").strip().lower()
    pw = ic.get("password") or ""
    if "@" not in user or not user.endswith("@gmail.com"):
        sys.exit(f"FAIL: config.json imap.user is not a gmail address (host={user.split('@')[-1] if '@' in user else '?'})")
    if not pw:
        sys.exit("FAIL: config.json imap.password is empty")
    return {
        "user": user,
        "password": pw,
        "host": ic.get("host") or "imap.gmail.com",
        "port": int(ic.get("port") or 993),
        "tls": str(ic.get("tls", "true")).lower() == "true",
    }


def send_mail(cfg: dict, to: str, subject: str, body: str) -> None:
    msg = EmailMessage()
    msg["From"] = cfg["user"]
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=30) as s:
        s.login(cfg["user"], cfg["password"])
        s.send_message(msg)


def connect_imap(cfg: dict) -> imaplib.IMAP4:
    m = (
        imaplib.IMAP4_SSL(cfg["host"], cfg["port"])
        if cfg["tls"]
        else imaplib.IMAP4(cfg["host"], cfg["port"])
    )
    m.login(cfg["user"], cfg["password"])
    return m


def select(m: imaplib.IMAP4, mailbox: str) -> bool:
    try:
        typ, _ = m.select(mailbox)
    except Exception:
        return False
    return typ == "OK" and m.state == "SELECTED"


def fetch_all_by_subject(m: imaplib.IMAP4, marker: str) -> dict:
    """{subject: {mailbox, sid, raw}} for every message whose Subject has marker."""
    out = {}
    for mb in MAILBOXES:
        if not select(m, mb):
            continue
        typ, data = m.search(None, f'(SUBJECT "{marker}")')
        if typ != "OK" or not data or not data[0]:
            continue
        for sid in data[0].split():
            _, dt = m.fetch(sid, "(RFC822)")
            raw = dt[0][1] if dt and dt[0] and isinstance(dt[0], tuple) else b""
            if not raw:
                continue
            subj = message_from_bytes(raw).get("Subject", "")
            out[subj] = {"mailbox": mb, "sid": sid, "raw": raw}
    return out


def search_ids(m: imaplib.IMAP4, criteria: str) -> set:
    typ, data = m.search(None, criteria)
    if typ != "OK" or not data or not data[0]:
        return set()
    return set(data[0].split())


def main() -> int:
    cfg = load_imap_cfg()
    base = cfg["user"]
    local, dom = base.split("@", 1)

    suffix = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    alias_a = f"{local}+smokea{suffix}@{dom}"
    alias_b = f"{local}+smokeb{suffix}@{dom}"
    marker = f"stage0-{suffix}"
    subj_a = f"{marker}-A"
    subj_b = f"{marker}-B"

    print(f"base    : {base}")
    print(f"alias A : {alias_a}")
    print(f"alias B : {alias_b}")
    print(f"marker  : {marker}")

    # ---- send two self-mails --------------------------------------------
    print("\n[send] SMTP_SSL smtp.gmail.com:465 ...")
    try:
        send_mail(cfg, alias_a, subj_a, f"Stage0 delivery probe A for {alias_a}")
        send_mail(cfg, alias_b, subj_b, f"Stage0 delivery probe B for {alias_b}")
    except Exception as e:
        print(f"FAIL: SMTP send failed: {type(e).__name__}: {e}")
        return 1
    print("[send] both messages accepted by Gmail SMTP")

    # ---- G1: poll for delivery ------------------------------------------
    print(f"\n[G1] polling IMAP ({cfg['host']}) for up to {POLL_TIMEOUT_S}s ...")
    m = connect_imap(cfg)
    found = {}
    deadline = time.time() + POLL_TIMEOUT_S
    while time.time() < deadline:
        found = fetch_all_by_subject(m, marker)
        if subj_a in found and subj_b in found:
            break
        time.sleep(POLL_INTERVAL_S)
    g1 = subj_a in found and subj_b in found
    for label, subj, alias in (("A", subj_a, alias_a), ("B", subj_b, alias_b)):
        if subj in found:
            print(f"[G1] message {label} FOUND in {found[subj]['mailbox']}")
        else:
            print(f"[G1] message {label} ({alias}) NOT FOUND in any of {MAILBOXES}")
    print(f"[G1] delivery {'PASS' if g1 else 'FAIL'}")
    if not g1:
        m.logout()
        return 1

    raw_a = found[subj_a]["raw"]
    raw_b = found[subj_b]["raw"]

    # ---- G2: To-header preservation (the SPOF) ---------------------------
    to_a = message_from_bytes(raw_a).get_all("To") or []
    to_b = message_from_bytes(raw_b).get_all("To") or []
    lit_a = alias_a in " ".join(to_a).lower()
    lit_b = alias_b in " ".join(to_b).lower()
    g2 = lit_a and lit_b
    print(f"\n[G2] raw To: of message A: {to_a}")
    print(f"[G2]   contains {alias_a} literally? {lit_a}")
    print(f"[G2] raw To: of message B: {to_b}")
    print(f"[G2]   contains {alias_b} literally? {lit_b}")
    print(f"[G2] To-header preservation {'PASS' if g2 else 'FAIL'}")

    # ---- G3: the real gate on real bytes ---------------------------------
    checks = {
        f"_message_for(A, {alias_a}) is True": _message_for(raw_a, alias_a) is True,
        f"_message_for(A, {alias_b}) is False": _message_for(raw_a, alias_b) is False,
        f"_message_for(B, {alias_b}) is True": _message_for(raw_b, alias_b) is True,
        f"_message_for(B, {alias_a}) is False": _message_for(raw_b, alias_a) is False,
    }
    g3 = all(checks.values())
    print("\n[G3] real gate on real delivered bytes:")
    for desc, ok in checks.items():
        print(f"[G3]   {'ok  ' if ok else 'BAD '}{desc}")
    print(f"[G3] gate agreement {'PASS' if g3 else 'FAIL'}")

    # ---- informational: SEARCH TO behavior -------------------------------
    print("\n[info] IMAP SEARCH TO behavior (in the mailbox where A landed):")
    mb_a = found[subj_a]["mailbox"]
    sid_a = found[subj_a]["sid"]
    sid_b = found[subj_b]["sid"]
    if select(m, mb_a):
        to_search_a = search_ids(m, f'(TO "{alias_a}")')
        to_search_b = search_ids(m, f'(TO "{alias_b}")')
        to_search_base = search_ids(m, f'(TO "{base}")')
        pipe_primary = search_ids(m, f'(TO "{alias_a}" FROM "{base}")')
        print(f"[info] SEARCH (TO \"{alias_a}\")      -> recall(A in result)={sid_a in to_search_a}  precision(B NOT in result)={sid_b not in to_search_a}")
        print(f"[info] SEARCH (TO \"{alias_b}\")      -> recall(B in result)={sid_b in to_search_b}  precision(A NOT in result)={sid_a not in to_search_b}")
        print(f"[info] SEARCH (TO \"{base}\") -> collapses aliases onto base? A={sid_a in to_search_base} B={sid_b in to_search_base}")
        print(f"[info] pipeline primary SEARCH (TO aliasA FROM base) -> A in result={sid_a in pipe_primary}")
        print("[info] (if TO-search recall is False, the FROM-only fallback in signup.py carries the flow)")
    else:
        print(f"[info] could not re-select {mb_a}; skipping SEARCH probes")

    m.logout()
    print(f"\nRESULT: G1={'PASS' if g1 else 'FAIL'}  G2={'PASS' if g2 else 'FAIL'}  G3={'PASS' if g3 else 'FAIL'}")
    return 0 if (g1 and g2 and g3) else 1


if __name__ == "__main__":
    sys.exit(main())
