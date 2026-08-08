#!/usr/bin/env python3
"""
generate_identity.py — Generate deterministic fake hardware identity per account.

Supports Linux and macOS (Intel MacBook Pro) profiles.

Usage:
    python3 generate_identity.py --email bolin9824@geusil.com
    python3 generate_identity.py --index 42
    python3 generate_identity.py --seed "custom-seed"
    python3 generate_identity.py --seed "custom-seed" --platform macos

Output: JSON with all env vars for spoof_hw.so LD_PRELOAD hook.
"""

import hashlib
import json
import sys
import argparse
import uuid
import random


# ── Apple Hardware Profiles ──────────────────────────────────────────

APPLE_OUI_PREFIXES = [
    "DC:A6:32",  # Apple, Inc.
    "AC:DE:48",  # Apple, Inc.
    "F8:FF:C2",  # Apple, Inc.
    "3C:22:FB",  # Apple, Inc.
    "A4:83:E7",  # Apple, Inc.
    "50:EA:F6",  # Apple, Inc.
    "B4:96:91",  # Intel Corporate (used in Macs with Intel WiFi)
    "00:03:93",  # Apple, Inc.
    "00:05:02",  # Apple, Inc.
    "00:0A:27",  # Apple, Inc.
    "60:FB:42",  # Apple, Inc.
    "70:56:81",  # Apple, Inc.
    "88:66:A5",  # Apple, Inc.
    "98:B8:63",  # Apple, Inc.
    "A8:20:66",  # Apple, Inc.
    "CC:08:E0",  # Apple, Inc.
    "E0:B9:BA",  # Apple, Inc.
    "F0:DB:E2",  # Apple, Inc.
]

APPLE_FACTORIES = [
    "C02", "C07", "C17", "C1M", "D25", "DMP", "F5V", "W89", "W80"
]

APPLE_BOARD_IDS = [
    "Mac-E1008331FDC96864",  # MacBookPro16,1 (16-inch 2019)
    "Mac-1E7E29AD0135F9BC",  # MacBookPro16,2 (13-inch 2020)
    "Mac-A61BADE1FDAD7B05",  # MacBookPro16,3 (13-inch 2020)
    "Mac-5F645D601C968E6F",  # MacBookPro16,4 (16-inch 2019)
    "Mac-B4831CEBD52A0C4C",  # MacBookPro15,4 (13-inch 2019)
    "Mac-827FAC58A8FDFA22",  # MacBookPro15,1 (15-inch 2019)
    "Mac-63001698E7A34814",  # MacBookPro15,2 (13-inch 2019)
    "Mac-AA95B1DDAB278B95",  # iMacPro1,1 (2017)
    "Mac-7BA5B2D9E42DDD94",  # iMac18,3 (27-inch 2017)
    "Mac-BE088AF8C5EB4FA2",  # iMac19,1 (27-inch 2019)
]

APPLE_PRODUCT_NAMES = [
    "MacBookPro16,1",   # 16-inch 2019
    "MacBookPro16,2",   # 13-inch 2020
    "MacBookPro15,1",   # 15-inch 2019
    "MacBookPro15,2",   # 13-inch 2019
    "MacBookPro15,4",   # 13-inch 2019
    "iMac19,1",         # 27-inch 2019
    "iMac20,1",         # 27-inch 2020
    "iMacPro1,1",       # 2017
]

APPLE_BIOS_VERSIONS = [
    "2069.0.0.0.0",
    "2060.0.0.0.0",
    "2058.0.0.0.0",
    "1916.0.0.0.0",
    "1856.0.0.0.0",
]

# CPU profiles for Intel Macs
INTEL_MAC_CPUS = [
    {"name": "Intel(R) Core(TM) i7-9750H CPU @ 2.60GHz", "family": "6", "model": "158", "stepping": "10"},
    {"name": "Intel(R) Core(TM) i9-9980HK CPU @ 2.40GHz", "family": "6", "model": "158", "stepping": "10"},
    {"name": "Intel(R) Core(TM) i7-8850H CPU @ 2.60GHz", "family": "6", "model": "158", "stepping": "10"},
    {"name": "Intel(R) Core(TM) i5-1038NG7 CPU @ 2.00GHz", "family": "6", "model": "126", "stepping": "0"},
    {"name": "Intel(R) Core(TM) i7-1068NG7 CPU @ 2.30GHz", "family": "6", "model": "126", "stepping": "0"},
    {"name": "Intel(R) Core(TM) i5-8259U CPU @ 2.30GHz", "family": "6", "model": "142", "stepping": "10"},
    {"name": "Intel(R) Core(TM) i7-8750H CPU @ 2.20GHz", "family": "6", "model": "158", "stepping": "10"},
    {"name": "Intel(R) Core(TM) i9-8950HK CPU @ 2.90GHz", "family": "6", "model": "158", "stepping": "10"},
]


def _rng_from_seed(seed: str) -> random.Random:
    """Create deterministic RNG from seed."""
    h = hashlib.sha256(seed.encode()).digest()
    return random.Random(int.from_bytes(h[:8], 'big'))


def generate_apple_serial(rng: random.Random) -> str:
    """Generate Apple-style 12-character serial number."""
    factory = rng.choice(APPLE_FACTORIES)
    # Year/week chars + random + checksum-like
    chars = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ"  # Apple serial charset (no I,O)
    year_week = rng.choice(chars) + rng.choice(chars)
    random_part = ''.join(rng.choice(chars) for _ in range(4))
    check_chars = ''.join(rng.choice(chars) for _ in range(3))
    return f"{factory}{year_week}{random_part}{check_chars}"


def generate_apple_board_serial(rng: random.Random, product_serial: str) -> str:
    """Generate Apple 17-char board serial from product serial."""
    chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    suffix = ''.join(rng.choice(chars) for _ in range(5))
    return f"{product_serial}{suffix}"


def generate_identity_linux(seed: str) -> dict:
    """Generate Linux desktop hardware identity."""
    h1 = hashlib.sha256(seed.encode()).hexdigest()
    h2 = hashlib.sha256((seed + "_uuid").encode()).hexdigest()
    h3 = hashlib.sha256((seed + "_mac").encode()).hexdigest()
    h4 = hashlib.sha256((seed + "_serial").encode()).hexdigest()

    machine_id = h1[:32]
    product_uuid = str(uuid.UUID(h2[:32]))

    # MAC: locally administered
    mac_bytes = ["02"] + [h3[i:i+2].upper() for i in range(0, 10, 2)]
    mac_address = ":".join(mac_bytes)

    product_serial = h4[:12].upper()
    board_serial = hashlib.sha256((seed + "_board").encode()).hexdigest()[:16].upper()
    cpu_serial = hashlib.sha256((seed + "_cpu").encode()).hexdigest()[:16]
    hostname = "DESKTOP-" + h1[:7].upper()

    return {
        "seed": seed,
        "platform": "linux",
        "cosy_machine_os": "x86_64_linux",
        "SPOOF_MACHINE_ID": machine_id,
        "SPOOF_PRODUCT_UUID": product_uuid,
        "SPOOF_MAC": mac_address,
        "SPOOF_PRODUCT_SERIAL": product_serial,
        "SPOOF_BOARD_SERIAL": board_serial,
        "SPOOF_CPU_SERIAL": cpu_serial,
        "SPOOF_HOSTNAME": hostname,
        "SPOOF_BIOS_VENDOR": "American Megatrends Inc.",
        "SPOOF_PRODUCT_NAME": "ROG STRIX X570-E",
        "SPOOF_SYS_VENDOR": "ASUSTeK COMPUTER INC.",
        "SPOOF_BOARD_NAME": "ROG STRIX X570-E GAMING",
        "SPOOF_CHASSIS_TYPE": "3",  # desktop
    }


def generate_identity_macos(seed: str) -> dict:
    """
    Generate Intel MacBook Pro hardware identity.
    Spoofs a realistic Intel Mac that runs Qoder CLI natively.
    """
    rng = _rng_from_seed(seed)
    h1 = hashlib.sha256(seed.encode()).hexdigest()

    # Product name & board
    product_name = rng.choice(APPLE_PRODUCT_NAMES)
    board_name = rng.choice(APPLE_BOARD_IDS)
    bios_version = rng.choice(APPLE_BIOS_VERSIONS)

    # Apple-format serials
    product_serial = generate_apple_serial(rng)
    board_serial = generate_apple_board_serial(rng, product_serial)

    # Product UUID (Apple format — standard UUID but seeded)
    product_uuid = str(uuid.UUID(h1[:32]))

    # Machine ID — use UUID without dashes (Apple IOPlatformUUID style)
    machine_id = h1[:32]

    # MAC address — Apple OUI prefix + random suffix
    oui = rng.choice(APPLE_OUI_PREFIXES)
    mac_suffix = ':'.join(f'{rng.randint(0,255):02X}' for _ in range(3))
    mac_address = f"{oui}:{mac_suffix}"

    # CPU — pick from Intel Mac profiles
    cpu = rng.choice(INTEL_MAC_CPUS)
    cpu_serial = hashlib.sha256((seed + "_cpu").encode()).hexdigest()[:16]

    # Hostname — Mac-style
    adjectives = ["MacBook", "Mac", "Air", "Pro"]
    nouns = ["of", "from"]
    names = ["John", "Alex", "Sarah", "Emma", "Mike", "Lisa", "Tom", "Dan",
             "Kate", "Jake", "Nick", "Chris", "Sam", "Max", "Leo", "Eve"]
    name = rng.choice(names)
    hostname = f"{name}s-{rng.choice(adjectives)}-{rng.randint(1000,9999)}"

    # CPU info content — Apple Mac-style (no hypervisor flag)
    cpuinfo_content = (
        f"processor\t: 0\n"
        f"vendor_id\t: GenuineIntel\n"
        f"cpu family\t: {cpu['family']}\n"
        f"model\t\t: {cpu['model']}\n"
        f"model name\t: {cpu['name']}\n"
        f"stepping\t: {cpu['stepping']}\n"
        f"microcode\t: 0xde\n"
        f"cpu MHz\t\t: 2600.000\n"
        f"cache size\t: 12288 KB\n"
        f"physical id\t: 0\n"
        f"siblings\t: 12\n"
        f"core id\t\t: 0\n"
        f"cpu cores\t: 6\n"
        f"apicid\t\t: 0\n"
        f"initial apicid\t: 0\n"
        f"Serial\t\t: {cpu_serial}\n"
        f"\n"
    )

    return {
        "seed": seed,
        "platform": "macos",
        "cosy_machine_os": "x86_64_darwin",
        "mac_profile": product_name,
        "SPOOF_MACHINE_ID": machine_id,
        "SPOOF_PRODUCT_UUID": product_uuid,
        "SPOOF_MAC": mac_address,
        "SPOOF_PRODUCT_SERIAL": product_serial,
        "SPOOF_BOARD_SERIAL": board_serial,
        "SPOOF_CPU_SERIAL": cpu_serial,
        "SPOOF_HOSTNAME": hostname,
        "SPOOF_BIOS_VENDOR": "Apple Inc.",
        "SPOOF_PRODUCT_NAME": product_name,
        "SPOOF_SYS_VENDOR": "Apple Inc.",
        "SPOOF_BOARD_NAME": board_name,
        "SPOOF_CHASSIS_TYPE": "10",  # notebook/laptop
        "SPOOF_CPUINFO_CONTENT": cpuinfo_content,
    }


def main():
    parser = argparse.ArgumentParser(description="Generate fake hardware identity")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--email", help="Email address as seed")
    group.add_argument("--index", type=int, help="Account index as seed")
    group.add_argument("--seed", help="Custom seed string")
    parser.add_argument("--platform", choices=["linux", "macos"], default="macos",
                        help="Hardware profile (default: macos)")
    parser.add_argument("--env", action="store_true", help="Output as shell env vars")
    parser.add_argument("--export", action="store_true", help="Output as export commands")
    args = parser.parse_args()

    if args.email:
        seed = args.email
    elif args.index is not None:
        seed = f"account_{args.index}"
    else:
        seed = args.seed

    if args.platform == "macos":
        identity = generate_identity_macos(seed)
    else:
        identity = generate_identity_linux(seed)

    if args.export:
        for key, val in identity.items():
            if key.startswith("SPOOF_") or key.startswith("cosy_"):
                print(f'export {key.upper()}="{val}"')
    elif args.env:
        for key, val in identity.items():
            if key.startswith("SPOOF_") or key.startswith("cosy_"):
                print(f'{key.upper()}={val}')
    else:
        print(json.dumps(identity, indent=2))


if __name__ == "__main__":
    main()
