#!/usr/bin/env bash
# tmp/qoder-smoke.sh — Qoder single-account live E2E smoke (task 4).
#
# Usage:
#   QODER_EMAIL_SOURCE=tempmail bash tmp/qoder-smoke.sh          # disposable inbox (default)
#   QODER_EMAIL=you+tag@gmail.com QODER_EMAIL_SOURCE=imap bash tmp/qoder-smoke.sh
#
# Env: QODER_EMAIL (imap mode), QODER_PASSWORD (optional), QODER_NAME,
#      QODER_EMAIL_SOURCE, QODER_PROXY, QODER_SIGNUP_URL.
# Emits {ok, email, pat} and writes generated-accounts-qoder-<stamp>.json.
set -euo pipefail
cd "$(dirname "$0")/.."

: "${QODER_EMAIL_SOURCE:=tempmail}"
if [ "$QODER_EMAIL_SOURCE" = "imap" ] && [ -z "${QODER_EMAIL:-}" ]; then
  echo "error: QODER_EMAIL required when QODER_EMAIL_SOURCE=imap" >&2
  exit 2
fi

node tmp/qoder-smoke.js
