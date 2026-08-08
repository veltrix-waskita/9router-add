#!/usr/bin/env python3
"""
generate_pool.py — Generate banyak machine credentials uniik per identitas.

Alur per entri:
  1. Rotasi identity: hapus ~/.config/.locale_cfg (bridge regenerate token baru)
  2. (opsional) Generate identitas pesudonim via generate_identity.py (env SPOOF_*)
  3. Jalankan runtime-info bridge → machineToken/Type/Code
  4. Kumpulkan → pool JSON (format qoder_creds_10k.json, siap dipakai blob dual_claim)

Usage:
  python3 generate_pool.py --count 50                # 50 creds rotasi murni
  python3 generate_pool.py --count 50 --platform macos   # + identitas GPU mac
  python3 generate_pool.py --emails akun.txt --platform linux  # 1 identitas per email (deterministik)
  python3 generate_pool.py --count 20 --output pool.json

Catatan: guard reader — cek isVm; kalau bridge bilang isVm=true, creds di-shm
(dengan warning) tapi tetap disimpan (format-valid; server memutuskan sendiri).
Fungsi: TOKEN = P1gA..., TYPE 16hex, CODE 18hex — format yang di-validasi.
"""
import argparse
import glob
import json
import os
import re
import subprocess
import time
from pathlib import Path

HOME = Path.home()
LOCALE_CFG = HOME / ".config" / ".locale_cfg"
HERE = Path(__file__).resolve().parent
BRIDGE_CANDIDATES = [
    HERE / "runtime-info-linux-x64",
    *sorted(glob.glob(str(HOME / ".qoder" / ".bin" / "runtime-info-linux-x64*"))),
]
BRIDGE = next((Path(p) for p in BRIDGE_CANDIDATES if Path(p).exists()), None)


def find_bridge() -> Path:
    if BRIDGE is None:
        raise SystemExit("❌ runtime-info bridge tidak ditemukan. Install qodercli atau salin binary.")
    return BRIDGE


def rotate():
    if LOCALE_CFG.exists():
        LOCALE_CFG.unlink()


def identity_env(email: str, platform: str) -> str:
    """Kumpulkan SPOOF_* env dari generate_identity.py (dipecah menjadi dict)."""
    out = subprocess.run(
        [os.sys.executable, str(HERE / "generate_identity.py"),
         "--seed", email, "--platform", platform, "--env"],
        capture_output=True, text=True, timeout=20,
    )
    env = {}
    for line in out.stdout.splitlines():
        if line.startswith(("SPOOF_", "COSY_")):
            k, _, v = line.partition("=")
            env[k] = v
    return env


def run_bridge(extra_env: list = None) -> dict:
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
    r = subprocess.run([str(find_bridge())], capture_output=True, text=True, timeout=20, env=env)
    if r.returncode != 0:
        raise RuntimeError(f"bridge gagal: {r.stderr[:200]}")
    return json.loads(r.stdout)


def make_entry(seed: str, platform: str, use_identity: bool) -> dict:
    rotate()
    env = None
    if use_identity:
        env = identity_env(seed, platform)
    d = run_bridge(env)
    m = {
        "machineToken": d["machineToken"],
        "machineType": d["machineType"],
        "machineCode": d["machineCode"],
    }
    m["_meta"] = {
        "seed": seed,
        "isVm": d["vmInfo"]["isVm"],
        "platform": platform,
        "mutate": None,
    }
    return m


def validate(entry: dict) -> bool:
    t = entry["machineToken"]
    if not t.startswith("P1gA") or len(t) < 80: return False
    if len(entry["machineType"]) not in (16, 18): return False
    if len(entry["machineCode"]) != 18: return False
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--count", type=int, default=20)
    ap.add_argument("--emails", type=str, default=None, help="file email per baris (seed)")
    ap.add_argument("--platform", choices=["macos", "linux"], default="macos")
    ap.add_argument("--output", default="qoder_creds_10k.json")
    ap.add_argument("--no-identity", action="store_true", help="tanpa env SPOOF (rotasi murni)")
    args = ap.parse_args()

    if args.emails:
        seeds = [l.strip() for l in Path(args.emails).read_text().splitlines() if l.strip()]
        print(f"[*] {len(seeds)} seed dari file")
    else:
        seeds = [f"seed-{i:04d}" for i in range(args.count)]

    pool, bad = [], []
    for i, seed in enumerate(seeds[:args.count], 1):
        try:
            e = make_entry(seed, args.platform, not args.no_identity)
        except Exception as err:
            print(f"  ❌ [{i}/{min(args.count,len(seeds))}] {seed}: {err}")
            continue
        ok = validate(e)
        (pool if ok else bad).append(e)
        flag = "🚫VM" if e["_meta"]["isVm"] else "✅clean"
        print(f"  [{i}/{min(args.count,len(seeds))}] {seed[:24]:24} {e['machineToken'][:14]}... type={e['machineType'][:8]} {flag}")

    out = Path(args.output)
    clean = [e for e in pool if not e["_meta"]["isVm"]]
    out.write_text(json.dumps(pool, indent=2))
    print(f"\n✅ {len(pool)} valid (clean={len(clean)}, VM={len(pool)-len(clean)}) → {out}")
    if bad: print(f"⚠️ {len(bad)} format-invalid (ditolak: {[b['_meta']['seed'] for b in bad[:5]]})")
    print(f"⚠️ device saat ini isVm={pool[0]['_meta']['isVm'] if pool else 'n/a'} — kalau 'true', pertimbangkan unload kvm/docker dulu")


if __name__ == "__main__":
    main()