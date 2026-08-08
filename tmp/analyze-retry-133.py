#!/usr/bin/env python3
"""#133 verdict: diff login-retry-response events CONTROL vs PLUS_A/PLUS_B.

Reads the newest /tmp/kiro_stage1_{control,plus_a,plus_b}_*.log worker logs,
extracts the login-retry-response debug events emitted by the instrumented
get-email-otp-login-credential handler, and reports:

  - per-phase: ok, body_len, body_keys, body_snapshot (already worker-sanitized)
  - CONTROL-vs-PLUS snapshot diff: keys added/removed, values changed

Interpretation matrix (task #133):
  (a) all ok=true + identical snapshots  -> AWS divergence is mailer-internal
                                            -> close plus-alias as AWS-side limit
  (b) PLUS snapshot differs              -> the diff names the client-side lever
  (c) PLUS ok=false                      -> new lever: RETRY itself rejected
                                            (login-exec-error has the detail)

Secrets: snapshots are truncated/type-collapsed by signup._safe_body_snapshot;
this script additionally masks 6-digit runs in case a subject-like string ever
appears. Never prints raw log lines.

Comparison semantics: per-run volatile fields (requestId, workflowStateHandle,
presentationContext.username) are normalized out before diff/equality, so
"identical" means identical workflow SHAPE — fresh UUIDs and the by-design
email difference between CONTROL (tempmail) and PLUS phases are not divergence.
"""
import glob
import json
import os
import re
import sys


def redact6(s: str) -> str:
    return re.sub(r"\b\d{6}\b", "<6dig>", str(s))


# Per-run volatile fields: differ between ANY two runs of the same flow shape
# (fresh UUIDs per request/workflow; username differs by design between the
# tempmail CONTROL and plus-alias PLUS phases).
VOLATILE_TOP = {"requestId", "workflowStateHandle"}


def normalize_snapshot(snap: dict) -> dict:
    """Strip per-run volatile fields so identity compares workflow shape only."""
    out = {k: v for k, v in snap.items() if k not in VOLATILE_TOP}
    pc = out.get("presentationContext")
    if isinstance(pc, dict) and "username" in pc:
        pc = dict(pc)
        pc["username"] = "<email>"
        out["presentationContext"] = pc
    return out


def newest(pattern: str) -> str | None:
    paths = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
    return paths[0] if paths else None


def extract_retry_events(log_path: str) -> list:
    events = []
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if obj.get("event") == "debug" and obj.get("msg") == "login-retry-response":
                events.append(obj)
    return events


def diff_snapshots(a: dict, b: dict, label_a: str, label_b: str) -> list:
    """Return human-readable diff lines between two body_snapshot dicts."""
    out = []
    keys_a, keys_b = set(a), set(b)
    for k in sorted(keys_a - keys_b):
        out.append(f"  key only in {label_a}: {k} = {redact6(repr(a[k]))[:120]}")
    for k in sorted(keys_b - keys_a):
        out.append(f"  key only in {label_b}: {k} = {redact6(repr(b[k]))[:120]}")
    for k in sorted(keys_a & keys_b):
        if a[k] != b[k]:
            out.append(f"  value differs [{k}]:")
            out.append(f"    {label_a}: {redact6(repr(a[k]))[:160]}")
            out.append(f"    {label_b}: {redact6(repr(b[k]))[:160]}")
    return out


def main() -> int:
    phases = {}
    for phase in ("control", "plus_a", "plus_b"):
        path = newest(f"/tmp/kiro_stage1_{phase}_*.log")
        if not path:
            print(f"[133] {phase}: no log found (/tmp/kiro_stage1_{phase}_*.log)")
            continue
        events = extract_retry_events(path)
        phases[phase] = (path, events)
        print(f"[133] {phase}: {os.path.basename(path)} — "
              f"{len(events)} login-retry-response event(s)")
        for i, ev in enumerate(events):
            print(f"  #{i} ok={ev.get('ok')} body_len={ev.get('body_len')} "
                  f"body_keys={sorted(ev.get('body_snapshot') or {})}")
            snap = ev.get("body_snapshot") or {}
            for k in sorted(snap):
                print(f"      {k} = {redact6(repr(snap[k]))[:140]}")

    if "control" not in phases:
        print("[133] NO CONTROL LOG — cannot verdict (gate never ran or log missing)")
        return 2

    ctrl_path, ctrl_events = phases["control"]
    if not ctrl_events:
        print("[133] CONTROL emitted NO login-retry-response — CONTROL did not "
              "reach get-email-otp-login-credential; check its step trail")
        return 2
    ctrl = ctrl_events[-1]  # last = the login-flow RETRY if emitted twice

    verdict_lines = []
    for phase in ("plus_a", "plus_b"):
        if phase not in phases:
            verdict_lines.append(f"[133] {phase}: (no log — run did not reach this phase)")
            continue
        _, events = phases[phase]
        if not events:
            verdict_lines.append(f"[133] {phase}: NO retry event — never reached "
                                 "get-email-otp-login-credential (failed earlier)")
            continue
        plus = events[-1]
        verdict_lines.append(f"[133] {phase} vs control:")
        verdict_lines.append(f"  ok: control={ctrl.get('ok')} {phase}={plus.get('ok')}")
        verdict_lines.append(f"  body_len: control={ctrl.get('body_len')} "
                             f"{phase}={plus.get('body_len')}")
        if ctrl.get("ok") and plus.get("ok"):
            d = diff_snapshots(normalize_snapshot(ctrl.get("body_snapshot") or {}),
                               normalize_snapshot(plus.get("body_snapshot") or {}),
                               "control", phase)
            if not d:
                verdict_lines.append("  snapshot: IDENTICAL (post-normalization)")
            else:
                n = len([l for l in d if l.startswith("  ") and not l.startswith("    ")])
                verdict_lines.append(f"  snapshot: {n} difference(s):")
                verdict_lines.extend(d)
        else:
            verdict_lines.append("  snapshot: not comparable (ok mismatch)")

    print("\n[133] ================= VERDICT DIFF =================")
    print("[133] (requestId / workflowStateHandle / presentationContext.username "
          "normalized out — per-run volatile, not workflow divergence)")
    for l in verdict_lines:
        print(l)

    # Machine-readable final classification
    plus_phases = [p for p in ("plus_a", "plus_b") if p in phases and phases[p][1]]
    if not plus_phases:
        print("\n[133] CLASSIFICATION: INCONCLUSIVE (no plus-alias retry events)")
        return 1
    oks = [phases[p][1][-1].get("ok") for p in plus_phases]
    if not ctrl.get("ok"):
        print("\n[133] CLASSIFICATION: CONTROL RETRY FAILED — new lever (control-side)")
        return 1
    if any(o is not True for o in oks):
        print("\n[133] CLASSIFICATION: (c) PLUS RETRY HTTP-FAILED — "
              "resend rejection is the lever")
        return 1
    ctrl_norm = normalize_snapshot(ctrl.get("body_snapshot") or {})
    all_identical = all(
        normalize_snapshot(phases[p][1][-1].get("body_snapshot") or {}) == ctrl_norm
        for p in plus_phases
    )
    if all_identical:
        print("\n[133] CLASSIFICATION: (a) IDENTICAL — Risk #3 conclusively "
              "AWS-mailer-internal; close plus-alias as AWS-side limitation")
        return 0
    print("\n[133] CLASSIFICATION: (b) SNAPSHOTS DIFFER — diff above names the lever")
    return 1


if __name__ == "__main__":
    sys.exit(main())
