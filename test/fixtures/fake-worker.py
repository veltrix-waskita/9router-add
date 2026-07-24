#!/usr/bin/env python3
"""Deterministic fake worker for Node bridge unit tests.

Behaviour is controlled via FAKE_WORKER_MODE env var:
  ok        - emit a few step events then ok result, exit 0 (default)
  fail      - emit fail result, exit 1
  hang      - sleep forever (used for timeout tests)
  noresult  - emit only steps, exit 0 (protocol violation)
  stderr    - write to stderr then fail
"""
from __future__ import annotations

import json
import os
import sys
import time


def emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main() -> int:
    mode = (os.environ.get("FAKE_WORKER_MODE") or "ok").strip().lower()

    if mode == "hang":
        while True:
            time.sleep(60)

    emit({"event": "step", "step": "bootstrap", "status": "ok"})
    emit({"event": "step", "step": "create_email_code", "status": "ok"})

    if mode == "noresult":
        return 0

    if mode == "stderr":
        sys.stderr.write("fake worker boom\n")
        sys.stderr.flush()
        emit({"kind": "result", "event": "result", "ok": False, "error": "fake-stderr", "step": "create_user"})
        return 1

    if mode == "fail":
        emit({"kind": "result", "event": "result", "ok": False, "error": "turnstile-timeout", "step": "turnstile"})
        return 1

    # ok
    emit({"event": "step", "step": "device_consent", "status": "ok", "approved": True})
    emit({"kind": "result", "event": "result", "ok": True})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
