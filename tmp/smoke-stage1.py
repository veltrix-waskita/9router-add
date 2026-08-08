#!/usr/bin/env python3
"""Stage 1 smoke — AWS-side proof for gmail plus-alias (#127).

Stage 0 proved the *Gmail* half (delivery + To: preservation + _message_for
agreement on real bytes). Stage 1 proves the *AWS* half against the live
signup flow, spending a TES window to do it:

  CONTROL   catch-all tempmail E2E (the known-green smoke-119 shape) on a
            fresh proxy+device. GATE: if this does not pass, the TES window
            is closed and NOTHING below it can be attributed to plus-aliases.
  PLUS_A    full E2E with KIRO_EMAIL=base+stage1a{sfx}@gmail.com, imap OTP,
            fresh proxy+device. Proves AWS treats alias A as a distinct
            account (Risk #1) AND that AWS's mailer keeps the alias in the
            delivered To: (Risk #2 — verified from the real OTP mail).
  PLUS_B    same with +stage1b{sfx}. Two distinct aliases prove batch
            throughput, not just a one-off.
  RESUBMIT  re-run alias A's exact address (only if PLUS_A passed). Expected:
            early rejection (AWS dedupes by email). If it instead completes
            via the login route, that is a discovery, not a failure.

Per-phase isolation: distinct egress IP (pre-validated via api.ipify.org),
fresh random FP seed per worker process (KIRO_FP_SEED explicitly unset),
fresh device code from 9router.

Secrets: imap password / account password / device_code / proxy credentials
never printed. Worker stdout is already redacted by signup.redact_err; this
script additionally redacts 6-digit runs in any header it displays (AWS puts
the OTP in the Subject sometimes).

Exit: 0 iff CONTROL + PLUS_A + PLUS_B all pass. 2 = window closed/infra.
1 = a plus-alias run failed with an attributable cause.
"""
import hashlib
import imaplib
import json
import os
import queue
import re
import secrets
import string
import subprocess
import sys
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from email import message_from_bytes

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WORKER = os.path.join(REPO, "src", "providers", "kiro", "worker")
VENV_PYTHON = os.path.join(WORKER, ".venv", "bin", "python3")
PROXIES_FILE = os.path.join(REPO, "proxies.txt")
ROUTER_URL = os.environ.get("ROUTER_URL", "http://localhost:20128")
RUN_TIMEOUT_S = 360  # delete=true 2nd-OTP poll can take ~200s + flow overhead
MAILBOXES = ["INBOX", '"[Gmail]/Spam"', '"[Google Mail]/Spam"', '"[Gmail]/All Mail"']
NAMES = ["Alex Rivera", "Jordan Blake", "Sam Carter", "Taylor Reed"]

sys.path.insert(0, WORKER)
from signup import _message_for  # noqa: E402  (the real gate, for diagnosis)


def redact6(s: str) -> str:
    """AWS sometimes embeds the OTP in the Subject — never print 6-digit runs."""
    return re.sub(r"\b\d{6}\b", "<6dig>", str(s))


def proxy_label(p: str) -> str:
    """Show only host:port of a proxy line (user:pass stays hidden)."""
    return "..." + p.split("@")[-1] if "@" in p else p


def load_cfg() -> dict:
    with open(os.path.join(REPO, "config.json")) as f:
        cfg = json.load(f)
    if not cfg.get("cliSecret"):
        sys.exit("[stage1] FAIL: config.json has no cliSecret")
    ic = cfg.get("imap") or {}
    user = (ic.get("user") or "").strip().lower()
    if not user.endswith("@gmail.com") or not ic.get("password"):
        sys.exit("[stage1] FAIL: config.json imap block incomplete (need gmail user + password)")
    # Mirror worker-bridge.buildWorkerEnv's provider-config lookup: config.json's
    # otpSenderDomain DIFFERS from signup.py's default "signin.aws", and it drives
    # the worker's IMAP SEARCH FROM clause. Without this, plus-alias runs would
    # search the wrong sender domain and fail OTP for an infra reason that the
    # tempmail CONTROL gate cannot catch.
    pk = (cfg.get("providers") or {}).get("kiro") or cfg.get("providerConfig") or {}
    sender_domain = (pk.get("otpSenderDomain") or "signin.aws").strip() or "signin.aws"
    return {
        "cliSecret": cfg["cliSecret"],
        "imap_user": user,
        "imap_password": ic["password"],
        "imap_host": ic.get("host") or "imap.gmail.com",
        "imap_port": str(ic.get("port") or 993),
        "imap_tls": str(ic.get("tls", "true")).lower(),
        "otp_sender_domain": sender_domain,
    }


def cli_token(cfg: dict) -> str:
    machine_id = open(os.path.expanduser("~/.9router/machine-id")).read().strip()
    return hashlib.sha256(f"{machine_id}9r-cli-auth{cfg['cliSecret']}".encode()).hexdigest()[:16]


def get_device_code(token: str) -> dict:
    req = urllib.request.Request(f"{ROUTER_URL}/api/oauth/kiro/device-code")
    req.add_header("x-9r-cli-token", token)
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read())


def pick_proxies(n: int, scan: int = 20) -> list:
    """n working proxies with DISTINCT egress IPs, from a randomized window.

    The start offset is random so reruns rotate egress IPs — TES saturation
    is environmental, so IP rotation between attempts is the lever, not code.
    """
    if not os.path.exists(PROXIES_FILE):
        sys.exit(f"[stage1] FAIL: {PROXIES_FILE} missing")
    lines = [l.strip() for l in open(PROXIES_FILE) if l.strip()]
    if len(lines) > scan:
        offset = secrets.randbelow(len(lines) - scan + 1)
        window = lines[offset:offset + scan]
        print(f"[stage1] proxy window: lines {offset + 1}..{offset + scan} "
              f"of {len(lines)} (randomized for IP rotation)")
    else:
        offset, window = 0, lines
    picked, seen_ips = [], set()
    for p in window:
        try:
            r = subprocess.run(
                ["curl", "-s", "-m", "12", "-x", p, "https://api.ipify.org"],
                capture_output=True, text=True,
            )
            ip = (r.stdout or "").strip()
        except Exception:
            ip = ""
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip) and ip not in seen_ips:
            seen_ips.add(ip)
            picked.append((p, ip))
            print(f"[stage1] proxy ok  {proxy_label(p)} egress={ip}")
            if len(picked) == n:
                return picked
        else:
            print(f"[stage1] proxy skip {proxy_label(p)} (ip={ip or 'dead'})")
    sys.exit(f"[stage1] FAIL: only {len(picked)}/{n} distinct working proxies "
             f"in scanned window of {scan}")


@dataclass
class RunResult:
    phase: str
    ok: bool = False
    timed_out: bool = False
    error_step: str | None = None
    error_msg: str = ""
    steps: list = field(default_factory=list)   # (step, status)
    elapsed_s: float = 0.0
    log_path: str = ""
    tempmail_addr: str = ""
    reached_otp: bool = False


def run_worker(phase: str, cfg: dict, token: str, proxy: str, suffix: str,
               email: str, source: str, name: str) -> RunResult:
    """One full signup.py run: fresh device code, fresh seed, live-streamed events."""
    rr = RunResult(phase=phase)
    try:
        dc = get_device_code(token)
    except Exception as e:
        rr.error_step = "device_code"
        rr.error_msg = f"device-code fetch failed: {type(e).__name__}"
        print(f"[stage1] [{phase}] {rr.error_msg}")
        return rr
    device_url = dc.get("verification_uri_complete", "")
    if not device_url:
        rr.error_step = "device_code"
        rr.error_msg = "device-code response missing verification_uri_complete"
        return rr
    print(f"[stage1] [{phase}] device code ok (user_code len={len(dc.get('user_code',''))}, "
          f"expires={dc.get('expires_in')}s)")

    password = f"Kiro{secrets.token_hex(4)}!A1"
    env = {**os.environ,
           "KIRO_EMAIL": email,
           "KIRO_PASSWORD": password,
           "KIRO_NAME": name,
           "KIRO_DEVICE_URL": device_url,
           "KIRO_EMAIL_SOURCE": source,
           "KIRO_PROXY": proxy,
           "PURE_HTTP": "1"}
    # Guarantee a fresh random device per run (never inherit a pinned seed).
    env.pop("KIRO_FP_SEED", None)
    for k in list(env):
        if k.startswith("KIRO_IMAP_"):
            env.pop(k)
    if source == "tempmail":
        env["KIRO_TEMPMAIL_PROVIDERS"] = "ncaori"
        env["TEMPMAIL_API_URL"] = "http://localhost:8877"
    else:
        env["KIRO_IMAP_USER"] = cfg["imap_user"]
        env["KIRO_IMAP_PASSWORD"] = cfg["imap_password"]
        env["KIRO_IMAP_HOST"] = cfg["imap_host"]
        env["KIRO_IMAP_PORT"] = cfg["imap_port"]
        env["KIRO_IMAP_TLS"] = cfg["imap_tls"]
        # Production parity: config.json sets deleteAfterRead=true. With false,
        # the signup-OTP mail survives in the shared alias inbox and the login
        # workflow's second read_otp re-serves that stale code → AWS rejects
        # with EMAIL_OTP_AUTHENTICATION_FAILED. Deletion is the same-alias
        # stale-code defense (_message_for only covers cross-alias).
        env["KIRO_IMAP_DELETE_AFTER_READ"] = "true"
        env["KIRO_OTP_SENDER_DOMAIN"] = cfg["otp_sender_domain"]
        # KIRO_OTP_SUBJECT deliberately omitted: buildWorkerEnv sets it but
        # signup.py never reads cfg["subject"] (dead field, grok-cli residue).

    rr.log_path = f"/tmp/kiro_stage1_{phase}_{suffix}.log"
    logf = open(rr.log_path, "w")
    q: queue.Queue = queue.Queue()
    t0 = time.time()

    try:
        proc = subprocess.Popen(
            [VENV_PYTHON, "-u", os.path.join(WORKER, "signup.py")],
            env=env, cwd=WORKER, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1,
        )
    except Exception as e:
        logf.close()
        rr.error_step = "spawn"
        rr.error_msg = f"worker spawn failed: {type(e).__name__}: {e}"
        print(f"[stage1] [{phase}] {rr.error_msg}")
        return rr

    def pump(stream, tag):
        for line in stream:
            q.put((tag, line))
        q.put(("eof", tag))

    err_lines: list[str] = []
    threading.Thread(target=pump, args=(proc.stdout, "out"), daemon=True).start()
    threading.Thread(target=pump, args=(proc.stderr, "err"), daemon=True).start()

    result_event = None
    deadline = t0 + RUN_TIMEOUT_S
    eofs = 0
    while time.time() < deadline and eofs < 2:
        try:
            tag, payload = q.get(timeout=0.5)
        except queue.Empty:
            continue
        if tag == "eof":
            eofs += 1
            continue
        if tag == "err":
            err_lines.append(payload)
            continue
        # stdout line: persist verbatim, parse events, print live.
        logf.write(payload)
        try:
            obj = json.loads(payload)
        except (json.JSONDecodeError, ValueError):
            continue
        ev = obj.get("event")
        if ev == "step":
            step, status = obj.get("step"), obj.get("status")
            rr.steps.append((step, status))
            if step == "otp":
                rr.reached_otp = True
            extra = ""
            if step == "tempmail_create" and obj.get("address"):
                rr.tempmail_addr = obj["address"]
                extra = f" address={obj['address']}"
            if status == "error" and obj.get("message"):
                rr.error_step, rr.error_msg = step, obj["message"]
                extra = f" msg={redact6(obj['message'])[:160]}"
            print(f"[stage1] [{phase}]   [{time.time()-t0:5.1f}s] step={step} status={status}{extra}")
        elif ev == "result":
            result_event = obj

    rr.elapsed_s = time.time() - t0
    if result_event is None and proc.poll() is None:
        rr.timed_out = True
        proc.kill()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    # Drain anything still buffered in the pipes after kill/exit.
    time.sleep(0.2)
    while not q.empty():
        try:
            tag, payload = q.get_nowait()
        except queue.Empty:
            break
        if tag == "out":
            logf.write(payload)
        elif tag == "err":
            err_lines.append(payload)
    logf.write("\n----- stderr -----\n")
    logf.writelines(err_lines)
    logf.close()

    if result_event:
        rr.ok = bool(result_event.get("ok"))
        if not rr.ok:
            rr.error_msg = rr.error_msg or result_event.get("error") or ""
            rr.error_step = rr.error_step or result_event.get("step")
    print(f"[stage1] [{phase}] done ok={rr.ok} timed_out={rr.timed_out} "
          f"elapsed={rr.elapsed_s:.1f}s log={rr.log_path}")
    return rr


def classify(rr: RunResult) -> str:
    if rr.timed_out:
        return "TIMEOUT"
    if rr.ok:
        return "PASS"
    blob = rr.error_msg.upper()
    if "BLOCKED" in blob:
        return "TES_BLOCKED"
    if rr.error_step in ("bootstrap", "email_entry") and re.search(
            r"EXIST|ALREADY|DUPLICATE", blob):
        return "ALREADY_EXISTS"
    if rr.error_step == "otp":
        return "OTP_NOT_MATCHED"
    return f"FAIL@{rr.error_step or '?'}"


def imap_diagnose(cfg: dict, aliases: list, suffix: str) -> None:
    """Print every recent signin.aws mail's To:/Subject (redacted) and whether
    _message_for accepts it for each alias. This is the Risk-#2 evidence."""
    print(f"[stage1] [diagnose] scanning {cfg['imap_host']} for recent "
          f"{cfg['otp_sender_domain']} mail ...")
    since = time.strftime("%d-%b-%Y")
    seen = set()
    total = 0
    try:
        m = imaplib.IMAP4_SSL(cfg["imap_host"], int(cfg["imap_port"]))
        m.login(cfg["imap_user"], cfg["imap_password"])
    except Exception as e:
        print(f"[stage1] [diagnose] IMAP connect failed: {type(e).__name__}")
        return
    for mb in MAILBOXES:
        try:
            typ, _ = m.select(mb)
            if typ != "OK":
                continue
            typ, data = m.search(None, f'(FROM "{cfg["otp_sender_domain"]}" SINCE "{since}")')
            if typ != "OK" or not data or not data[0]:
                continue
            for sid in data[0].split():
                _, dt = m.fetch(sid, "(RFC822)")
                raw = dt[0][1] if dt and dt[0] and isinstance(dt[0], tuple) else b""
                if not raw:
                    continue
                msg = message_from_bytes(raw)
                mid = msg.get("Message-ID", f"{mb}:{sid}")
                if mid in seen:
                    continue
                seen.add(mid)
                total += 1
                to_hdr = redact6(" | ".join(msg.get_all("To") or ["<none>"]))
                subj = redact6(msg.get("Subject", "<none>"))
                verdicts = " ".join(
                    f"{a.split('+')[1].split('@')[0]}={'Y' if _message_for(raw, a) else 'N'}"
                    for a in aliases
                )
                print(f"[stage1] [diagnose] #{total} box={mb} To=[{to_hdr[:120]}] "
                      f"Subj=[{subj[:80]}] gate({verdicts})")
                if total >= 12:
                    break
        except Exception:
            continue
        if total >= 12:
            break
    m.logout()
    if total == 0:
        print(f"[stage1] [diagnose] ZERO {cfg['otp_sender_domain']} mails today — "
              "AWS sent nothing (dedupe or pre-send block)")


def main() -> int:
    cfg = load_cfg()
    token = cli_token(cfg)
    base = cfg["imap_user"]
    local, dom = base.split("@", 1)
    suffix = "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(8))
    alias_a = f"{local}+stage1a{suffix}@{dom}"
    alias_b = f"{local}+stage1b{suffix}@{dom}"
    print(f"[stage1] base={base} suffix={suffix}")
    print(f"[stage1] alias_a={alias_a}")
    print(f"[stage1] alias_b={alias_b}")

    print("[stage1] validating proxies (distinct egress IPs) ...")
    proxies = pick_proxies(4)

    # ---- CONTROL: known-green shape must pass or nothing below is attributable
    print("\n[stage1] PHASE CONTROL (tempmail catch-all, the smoke-119 shape)")
    rc = run_worker("control", cfg, token, proxies[0][0], suffix, "", "tempmail", NAMES[0])
    vc = classify(rc)
    print(f"[stage1] CONTROL verdict: {vc}")
    if vc != "PASS":
        if vc == "TES_BLOCKED":
            print("[stage1] ABORT: TES window CLOSED — plus-alias runs would be "
                  "unattributable. Rotate IP pool / wait, retry later.")
        else:
            print(f"[stage1] ABORT: infra/control failure ({vc}) — fix before "
                  "attributing anything to plus-aliases.")
        return 2

    # ---- PLUS_A / PLUS_B
    verdicts = {"control": vc}
    runs = {"control": rc}
    for phase, alias, (proxy, ip), name in (
        ("plus_a", alias_a, proxies[1], NAMES[1]),
        ("plus_b", alias_b, proxies[2], NAMES[2]),
    ):
        print(f"\n[stage1] PHASE {phase.upper()} alias={alias} egress={ip}")
        rr = run_worker(phase, cfg, token, proxy, suffix, alias, "imap", name)
        v = classify(rr)
        verdicts[phase] = v
        runs[phase] = rr
        if rr.reached_otp or v != "PASS":
            imap_diagnose(cfg, [alias_a, alias_b], suffix)
        print(f"[stage1] {phase.upper()} verdict: {v}")

    # ---- RESUBMIT: only meaningful if PLUS_A proved the alias registers
    verdicts["resubmit"] = "SKIPPED"
    if verdicts.get("plus_a") == "PASS":
        print(f"\n[stage1] PHASE RESUBMIT (same alias_a again — expect early rejection)")
        rr = run_worker("resubmit", cfg, token, proxies[3][0], suffix, alias_a, "imap", NAMES[3])
        v = classify(rr)
        verdicts["resubmit"] = v
        runs["resubmit"] = rr
        print(f"[stage1] RESUBMIT verdict: {v} (step={rr.error_step})")
        if v == "PASS":
            print("[stage1] NOTE: resubmit COMPLETED — AWS allowed re-registration "
                  "or routed to the login flow. Investigate before trusting dedupe.")
        elif v == "TES_BLOCKED":
            print("[stage1] NOTE: resubmit TES-blocked — inconclusive on dedupe.")
        else:
            print("[stage1] NOTE: resubmit rejected early — AWS dedupes by email "
                  "as expected.")

    # ---- summary
    print("\n[stage1] ================= SUMMARY =================")
    for k in ("control", "plus_a", "plus_b", "resubmit"):
        rr = runs.get(k)
        el = f"{rr.elapsed_s:.0f}s" if rr else "-"
        print(f"[stage1] {k:<9} {verdicts[k]:<16} {el}")
    a_ok = verdicts.get("plus_a") == "PASS"
    b_ok = verdicts.get("plus_b") == "PASS"
    if a_ok and b_ok:
        print("[stage1] VERDICT: plus-aliases are DISTINCT AWS accounts AND OTP "
              "mail carried the alias (both E2E green). Risk #1 + #2 cleared.")
        return 0
    print("[stage1] VERDICT: plus-alias path NOT fully proven — see per-phase "
          "verdicts + /tmp/kiro_stage1_*.log + diagnose output above.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
