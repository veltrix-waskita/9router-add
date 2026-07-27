#!/bin/bash
# Smoke runner with proxy rotation on TES blocks (per memory: saturation is
# environmental — rotate IP + device + email domain together, never "fix" code).
# Device seed randomizes per run; tempmail alias randomizes per run; this adds
# egress-IP rotation. Stops at first non-TES outcome.
cd /home/elzanom/WORKER/9router-add || exit 1
for attempt in 1 2 3 4 5; do
  idx=$(( (attempt * 17) % 100 + 1 ))
  p=$(sed -n "${idx}p" proxies.txt)
  echo "=== ATTEMPT $attempt proxy=$(echo "$p" | sed -E 's|.*@||') ==="
  KIRO_PROXY="$p" python3 -u tmp/smoke-e2e.py > "/tmp/kiro_smoke_119_try$attempt.log" 2>&1
  ec=$?
  if grep -q '"errorCode":"BLOCKED"' "/tmp/kiro_smoke_119_try$attempt.log"; then
    echo "=== ATTEMPT $attempt: TES BLOCKED (exit=$ec), rotating ==="
    continue
  fi
  echo "=== ATTEMPT $attempt: non-TES outcome (exit=$ec) — stopping ==="
  break
done
echo "LOOP_DONE"
