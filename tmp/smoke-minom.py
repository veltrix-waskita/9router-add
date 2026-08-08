#!/usr/bin/env python3
"""#134 smoke — CF Email Routing catch-all domain (minom.my.id) E2E proof.

Catch-all aliases (e.g. emma.walker37@minom.my.id) carry NO '+' tag, so AWS
sees a normal unique address — shape-identical to the proven-green tempmail
CONTROL path, NOT the plus-alias path that hits AWS-side Risk #3 (login OTP
never delivered to plus-tagged addresses). A green run here proves the
production path.

  Phase 0  CF forwarding pre-check v2: send a marker from a SECOND email
           account (config.json precheckSender — NOT the destination Gmail,
           whose self-forward Gmail loop-dedups) to
           <randomLocalPart>@minom.my.id, poll IMAP, and REQUIRE a
           Delivered-To header naming the minom address on the found mail
           (that header only exists on a delivered/forwarded copy, never on
           a sent copy). ABORT if it never arrives — zero AWS/TES spend.
           Set KIRO_MINOM_PHASE0_ONLY=1 to stop after Phase 0 (isolated
           forwarding proof, independent of the TES window).
           KIRO_MINOM_ALLOW_LOOP=1 downgrades the same-account guard to a
           warning — negative control ONLY (must end in NO_DELIVERED_TO).
           KIRO_MINOM_SKIP_PHASE0=1 skips Phase 0 entirely — the AWS signup
           OTP then doubles as the non-loop forwarding proof if Phase 1
           greens (trades the zero-spend pre-check for one TES-window bet).
  Phase 1  ONE signup.py E2E with KIRO_EMAIL=<same address>, imap OTP, fresh
           proxy+device. Verdicts: PASS = production path proven;
           TES_BLOCKED = environmental (same shape as CONTROL); FAIL@X =
           attributable.

Secrets: imap password / precheckSender password / account password /
device_code / proxy credentials never printed; 6-digit runs (OTP) masked in
any header displayed.
"""
import email
import importlib.util
import imaplib
import json
import os
import secrets
import smtplib
import subprocess
import sys
import time
from email.message import EmailMessage

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Reuse the stage1 harness helpers verbatim (load_cfg / cli_token /
# get_device_code / pick_proxies / run_worker / classify / redact6).
_spec = importlib.util.spec_from_file_location(
    "smoke_stage1", os.path.join(REPO, "tmp", "smoke-stage1.py"))
s1 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(s1)

# The REAL production alias generator (src/services/cloudflare-routing.js),
# so the smoke address has exactly the shape production will mint.
_random_local_part = subprocess.run(
    ["node", "-e",
     "process.stdout.write(require('./src/services/cloudflare-routing')"
     ".randomLocalPart())"],
    cwd=REPO, capture_output=True, text=True,
).stdout.strip()
if not _random_local_part:
    sys.exit("[minom] FAIL: cloudflare-routing.randomLocalPart() returned empty")

DOMAIN = "minom.my.id"
SMTP_HOST, SMTP_PORT = "smtp.gmail.com", 465
PRECHECK_TIMEOUT_S = 150
PRECHECK_POLL_S = 5
# INBOX + Spam + All Mail, incl. the locale variant (the #131 lesson: Gmail
# mailbox names are locale-dependent — All Mail = "Semua Email" in id-ID).
PRECHECK_MAILBOXES = ["INBOX", '"[Gmail]/Spam"', '"[Google Mail]/Spam"',
                      '"[Gmail]/All Mail"', '"[Gmail]/Semua Email"',
                      '"[Google Mail]/All Mail"']

# Phase 0 v2 sender: a SECOND account (any provider), read straight from
# config.json (load_cfg returns a curated subset without it). Sending from
# the destination Gmail itself is the self-loop Gmail dedups — refused below.
with open(os.path.join(REPO, "config.json")) as _f:
    SENDER = (json.load(_f).get("precheckSender") or {})


def precheck_v2(cfg: dict, addr: str, marker: str) -> str:
    """Send marker from the second account; require Delivered-To proof.

    Returns "OK" | "NO_DELIVERY" | "NO_DELIVERED_TO:<diag>". With a foreign
    sender, any copy in the destination IMAP must be CF's forward (the sent
    copy stays in the sender's own account) — the Delivered-To check is the
    forensic artifact that makes the proof explicit.
    """
    user = (SENDER.get("user") or "").strip()
    password = SENDER.get("password") or ""
    if not user or not password or "FILL_ME" in user or "FILL_ME" in password:
        sys.exit("[minom] FAIL: config.json precheckSender block not filled "
                 "(need user + password of a SECOND email account — Gmail "
                 "needs an app password; smtpHost/smtpPort default to "
                 "smtp.gmail.com:465).")
    if user.lower() == cfg["imap_user"]:
        if os.getenv("KIRO_MINOM_ALLOW_LOOP") != "1":
            sys.exit("[minom] FAIL: precheckSender.user == imap.user — that "
                     "is exactly the self-loop Gmail dedups. Use a DIFFERENT "
                     "account (or KIRO_MINOM_ALLOW_LOOP=1 for a negative "
                     "control that must end in NO_DELIVERED_TO).")
        print("[minom] [precheck] WARNING: sender == destination Gmail — "
              "negative-control mode (expect NO_DELIVERED_TO: the loop's "
              "sent copy has no Delivered-To header).")
    smtp_host = (SENDER.get("smtpHost") or "").strip() or SMTP_HOST
    smtp_port = int(SENDER.get("smtpPort") or SMTP_PORT)
    msg = EmailMessage()
    msg["From"] = user
    msg["To"] = addr
    msg["Subject"] = f"minom-precheck {marker}"
    msg.set_content("CF catch-all forwarding pre-check (#134). Safe to delete.")
    print(f"[minom] [precheck] sending marker from second account via "
          f"{smtp_host}:{smtp_port} ...")
    with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=30) as s:
        s.login(user, password)
        s.send_message(msg)
    print(f"[minom] [precheck] sent. polling IMAP up to {PRECHECK_TIMEOUT_S}s "
          f"({len(PRECHECK_MAILBOXES)} mailboxes) ...")
    deadline = time.time() + PRECHECK_TIMEOUT_S
    while time.time() < deadline:
        try:
            m = imaplib.IMAP4_SSL(cfg["imap_host"], int(cfg["imap_port"]))
            m.login(cfg["imap_user"], cfg["imap_password"])
            for box in PRECHECK_MAILBOXES:
                try:
                    typ, _ = m.select(box, readonly=True)
                    if typ != "OK":
                        continue  # mailbox absent under this locale — skip
                    # imaplib does NOT quote criteria — a multi-word value
                    # must be pre-quoted or Gmail parses the 2nd word as an
                    # (invalid) search key and silently returns no match.
                    typ, data = m.search(None, "SUBJECT",
                                         f'"minom-precheck {marker}"')
                    if typ != "OK" or not data or not data[0]:
                        continue
                    uid = data[0].split()[0]
                    typ2, fetched = m.fetch(uid, "(RFC822)")
                    m.logout()
                    if typ2 != "OK" or not fetched or not fetched[0]:
                        return f"NO_DELIVERED_TO:fetch-failed-in-{box}"
                    mail = email.message_from_bytes(fetched[0][1])
                    hops = mail.get_all("Received") or []
                    has_cf = any("cloudflare" in h.lower() for h in hops)
                    dts = " | ".join(mail.get_all("Delivered-To") or [])
                    if addr.lower() in dts.lower():
                        print(f"[minom] [precheck] FOUND in {box}: "
                              f"Delivered-To names {addr} "
                              f"(cloudflare-hop={has_cf}, "
                              f"{len(hops)} Received hops)")
                        return "OK"
                    return (f"NO_DELIVERED_TO:found-in-{box} but "
                            f"Delivered-To=[{dts[:120]}] "
                            f"cloudflare-hop={has_cf} hops={len(hops)} "
                            f"— NOT a CF forward")
                except imaplib.IMAP4.error:
                    continue
            m.logout()
        except Exception as e:
            print(f"[minom] [precheck] IMAP poll error: {type(e).__name__}")
        time.sleep(PRECHECK_POLL_S)
    return "NO_DELIVERY"


def main() -> int:
    cfg = s1.load_cfg()
    suffix = secrets.token_hex(4)
    local = _random_local_part
    addr = f"{local}@{DOMAIN}"
    marker = secrets.token_hex(6)
    print(f"[minom] suffix={suffix} address={addr}")

    # ---- Phase 0 v2: CF forwarding proof via NON-loop sender (zero AWS spend)
    if os.getenv("KIRO_MINOM_SKIP_PHASE0") == "1":
        print("\n[minom] PHASE 0 — SKIPPED (KIRO_MINOM_SKIP_PHASE0=1; the AWS "
              "signup OTP doubles as the non-loop forwarding proof if Phase 1 "
              "greens)")
    else:
        print("\n[minom] PHASE 0 — CF catch-all forwarding pre-check "
              "(v2: non-loop sender + Delivered-To proof)")
        v0 = precheck_v2(cfg, addr, marker)
        if v0 == "OK":
            print("[minom] PHASE 0 verdict: OK — CF catch-all forwarding "
                  "PROVEN (Delivered-To verified on a non-loop mail)")
        elif v0 == "NO_DELIVERY":
            print(f"[minom] PHASE 0 verdict: NO_DELIVERY — marker from the "
                  f"second account never reached {cfg['imap_user']} within "
                  f"{PRECHECK_TIMEOUT_S}s (check CF dashboard: Email Routing "
                  f"enabled + destination verified + catch-all rule; and the "
                  f"second account's Sent folder to confirm the send left). "
                  f"ABORT before any AWS/TES spend.")
            return 2
        else:
            print(f"[minom] PHASE 0 verdict: {v0} — ABORT.")
            return 2
        if os.getenv("KIRO_MINOM_PHASE0_ONLY") == "1":
            print("[minom] KIRO_MINOM_PHASE0_ONLY=1 — stopping after Phase 0 "
                  "(isolated forwarding proof; no AWS/TES spend).")
            return 0

    # ---- Phase 1: single E2E (imap source, fresh proxy+device)
    print("\n[minom] PHASE 1 — single signup.py E2E (imap OTP)")
    token = s1.cli_token(cfg)
    proxies = s1.pick_proxies(1, scan=20)
    proxy, egress = proxies[0]
    print(f"[minom] egress={egress}")
    rr = s1.run_worker("minom", cfg, token, proxy, suffix, addr, "imap",
                       "Emma Walker")
    v = s1.classify(rr)

    print("\n[minom] ================= SUMMARY =================")
    print(f"[minom] address : {addr}")
    print(f"[minom] egress  : {egress}")
    print(f"[minom] elapsed : {rr.elapsed_s:.0f}s")
    print(f"[minom] log     : {rr.log_path}")
    print(f"[minom] verdict : {v}")
    if v == "PASS":
        print("[minom] VERDICT: CF catch-all production path PROVEN E2E "
              "(shape-identical to the green tempmail CONTROL — no + tag).")
        return 0
    if v == "TES_BLOCKED":
        print("[minom] VERDICT: environmental TES block (same shape as "
              "CONTROL runs) — NOT attributable to the minom path. Re-run "
              "later with rotated IP+device if desired.")
        return 2
    print(f"[minom] VERDICT: attributable failure at "
          f"{rr.error_step}: {s1.redact6(rr.error_msg)[:200]}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
