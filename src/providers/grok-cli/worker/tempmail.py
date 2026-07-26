#!/usr/bin/env python3
"""Temp-mail providers for grok-cli signup — pure HTTP, no browser.

Ported from x-farm mail_tm.py subset. Provides two proven xAI providers
(ncaori, zoromail) wrapped in a unified EmailBox interface with round-robin
create + fallback.

Usage:
    box = EmailBox()
    addr = box.create_account()      # tries ncaori → zoromail
    code = box.wait_code(timeout=120)  # polls inbox, blocks
    print(box.provider_name, box.address, code)
"""

from __future__ import annotations

import os
import random
import re
import time
import uuid
from typing import Any

# Lazy — so extract_code() and EmailBox unit helpers import without curl_cffi.
creq = None


def _ensure_creq():
    global creq
    if creq is None:
        from curl_cffi import requests as _creq
        creq = _creq
    return creq


JSON_HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json",
}

# ── OTP extraction (from x-farm _extract_code) ──────────────────────

OTP_HYPHEN_RE = re.compile(
    r"(?:confirmation\s+)?code[:\s]+([A-Z0-9]{3}-[A-Z0-9]{3})\b",
    re.I,
)
OTP_HYPHEN_BARE_RE = re.compile(r"\b([A-Z0-9]{3}-[A-Z0-9]{3})\b", re.I)
OTP_LEGACY_RE = re.compile(
    r"(?:confirmation\s+)?code[:\s]+([A-Z0-9]{6})\b",
    re.I,
)
OTP_DIGIT6_RE = re.compile(
    r"(?:verification\s+code|confirmation\s+code|otp|one[- ]time"
    r"(?:\s+pass(?:word|code)?))[:\s#]*(\d{6})\b",
    re.I,
)

SKIP_HYPHEN = {
    "per-100", "max-100", "min-100", "dir-top", "top-dir", "moz-osx",
    "pre-built", "pre-made", "one-time", "set-up", "sign-up", "log-in",
    "opt-out", "opt-in", "non-stop", "all-in", "end-to", "to-end",
}
SKIP_LEGACY = {
    "signup", "verify", "account", "please", "gmail", "xaiapp", "spacex",
    "edge", "chrome", "safari", "webkit", "mozilla", "button", "submit",
    "create", "ignore", "footer", "strong", "hidden", "center", "inline",
    "mobile", "column", "screen", "border", "margin", "height", "weight",
    "family", "system", "domain", "tensor", "mailto", "adjust", "bottom",
    "unleash", "online", "tools", "power", "ultimate", "directory",
}
AD_MARKERS = (
    "ai tools", "unleash the power", "adsvpn", "buysellads",
    "directory of online", "temp mail", "emailnator", "disposable gmail",
)
XAI_MARKERS = (
    "x.ai", "xai", "grok", "spacex", "confirmation code", "validation code",
    "verify your email", "email verification", "accounts.x.ai",
)


def _decode_qpish(blob: str) -> str:
    return (blob or "").replace("=\r\n", "").replace("=\n", "")


def _looks_like_ad(blob: str) -> bool:
    low = (blob or "").lower()
    return any(m in low for m in AD_MARKERS) and not any(m in low for m in XAI_MARKERS)


def _has_xai_context(blob: str) -> bool:
    low = (blob or "").lower()
    return any(m in low for m in XAI_MARKERS)


def extract_code(blob: str) -> str | None:
    """Extract OTP from email subject+body text.  None = no match/ad."""
    text = _decode_qpish(blob)
    if not text or _looks_like_ad(text):
        return None
    xaiish = _has_xai_context(text)

    # 1) Labeled hyphen code
    for m in OTP_HYPHEN_RE.finditer(text):
        code = m.group(1).upper()
        if code.lower() not in SKIP_HYPHEN:
            return code

    # 2) Bare hyphen — xAI context required
    if xaiish:
        for m in OTP_HYPHEN_BARE_RE.finditer(text):
            code = m.group(1).upper()
            if code.lower() in SKIP_HYPHEN:
                continue
            return code

    # 3) Labeled legacy 6-char alnum
    for m in OTP_LEGACY_RE.finditer(text):
        code = m.group(1).upper()
        if code.lower() in SKIP_LEGACY:
            continue
        if code.isdigit():
            if not xaiish:
                continue
            window = text[max(0, m.start() - 40): m.end() + 10]
            if not re.search(r"confirmation|verification|otp|one[- ]time", window, re.I):
                continue
        return code

    # 4) Labeled 6-digit (xAI only)
    if xaiish:
        for m in OTP_DIGIT6_RE.finditer(text):
            return m.group(1)

    return None


# ── Providers ───────────────────────────────────────────────────────


class NcaoriMail:
    """ncaori.my.id / nca.my.id — invent address, poll API for inbox."""

    BASE = "https://www.nca.my.id"
    DOMAINS = ("ncaori.my.id", "nca.my.id")
    WORDS1 = (
        "swift", "crystal", "storm", "frost", "shadow", "ember", "azure",
        "phantom", "silver", "iron", "crimson", "golden", "neo", "cosmic",
        "lunar", "solar", "dark", "light", "void", "flux",
    )
    WORDS2 = (
        "core", "leaf", "forge", "wave", "peak", "gate", "pulse", "blade",
        "shard", "drift", "hive", "node", "edge", "beacon", "nova", "cloud",
        "moon", "star", "wind", "spark",
    )

    def __init__(self, impersonate: str = "chrome131"):
        self.s = _ensure_creq().Session()
        self.impersonate = impersonate
        self.address: str | None = None

    def create_account(self) -> str:
        local = f"{random.choice(self.WORDS1)}_{random.choice(self.WORDS2)}{uuid.uuid4().hex[:4]}"
        domain = random.choice(self.DOMAINS)
        self.address = f"{local}@{domain}"
        # Warm the inbox endpoint (no explicit create endpoint)
        r = self.s.get(
            f"{self.BASE}/api/emails",
            params={"recipient": self.address},
            headers=JSON_HEADERS,
            impersonate=self.impersonate,
            timeout=30,
        )
        if r.status_code >= 500:
            raise RuntimeError(f"ncaori warm {r.status_code}: {(r.text or '')[:120]}")
        return self.address

    def wait_code(self, timeout: int = 150) -> str:
        if not self.address:
            raise RuntimeError("ncaori: no address")
        deadline = time.time() + timeout
        seen: set[str] = set()
        poll = float(os.getenv("OTP_POLL_S", "0.8"))
        poll_max = float(os.getenv("OTP_POLL_MAX_S", "2.0"))
        t0 = time.time()
        while time.time() < deadline:
            r = self.s.get(
                f"{self.BASE}/api/emails",
                params={"recipient": self.address},
                headers=JSON_HEADERS,
                impersonate=self.impersonate,
                timeout=15,
            )
            if r.status_code < 400 and r.content:
                try:
                    data = r.json()
                except Exception:
                    data = {}
                msgs = data.get("emails") if isinstance(data, dict) else []
                for m in msgs or []:
                    mid = str(m.get("id") or "")
                    if mid and mid in seen:
                        continue
                    if mid:
                        seen.add(mid)
                    blob = " ".join(
                        str(m.get(k, "") or "")
                        for k in ("subject", "sender", "body_text", "body_html", "preview")
                    )
                    code = extract_code(blob)
                    if code:
                        return code
            if time.time() - t0 > 12:
                poll = min(poll_max, poll * 1.15)
            time.sleep(poll)
        raise TimeoutError(f"ncaori: no OTP for {self.address}")


class Zoromail:
    """zoromail.com — REST API domains/create/list."""

    API = "https://zoromail.com/public_api.php/v1"

    def __init__(self, impersonate: str = "chrome131"):
        self.s = _ensure_creq().Session()
        self.impersonate = impersonate
        self.address: str | None = None

    def _api(self, method: str, path: str, **kw) -> Any:
        r = self.s.request(
            method,
            self.API + path,
            headers={**JSON_HEADERS, **kw.pop("headers", {})},
            impersonate=self.impersonate,
            timeout=kw.pop("timeout", 30),
            **kw,
        )
        if r.status_code >= 400:
            raise RuntimeError(
                f"zoromail {method} {path} -> {r.status_code} {(r.text or '')[:160]}"
            )
        try:
            payload = r.json() if r.content else {}
        except Exception as e:
            raise RuntimeError(f"zoromail bad json: {e}") from e
        if not isinstance(payload, dict) or payload.get("success") is not True:
            err = (payload or {}).get("error") if isinstance(payload, dict) else payload
            raise RuntimeError(f"zoromail api error: {err}")
        return payload.get("data")

    def create_account(self) -> str:
        domains = self._api("GET", "/domains")
        if not isinstance(domains, list) or not domains:
            raise RuntimeError("zoromail: no domains available")
        domain = random.choice(domains)
        username = "xai" + uuid.uuid4().hex[:10]
        data = self._api(
            "POST",
            "/emails",
            json={"username": username, "domain": domain},
        )
        if isinstance(data, dict):
            self.address = data.get("email") or f"{username}@{domain}"
        else:
            self.address = f"{username}@{domain}"
        return self.address

    def wait_code(self, timeout: int = 150) -> str:
        if not self.address:
            raise RuntimeError("zoromail: no address")
        deadline = time.time() + timeout
        seen: set[str] = set()
        while time.time() < deadline:
            try:
                msgs = self._api("GET", f"/emails/{self.address}/messages") or []
            except Exception:
                msgs = []
            if not isinstance(msgs, list):
                msgs = []
            for m in msgs:
                mid = str(m.get("id") or "")
                if mid and mid in seen:
                    continue
                if mid:
                    seen.add(mid)
                blob = " ".join(str(m.get(k, "") or "") for k in ("subject", "from", "preview", "text"))
                code = extract_code(blob)
                if code:
                    return code
                if mid:
                    try:
                        full = self._api("GET", f"/messages/{mid}") or {}
                        blob2 = " ".join(
                            str(full.get(k, "") or "")
                            for k in ("subject", "from", "text", "body_text", "html", "body_html")
                        )
                        code = extract_code(blob2)
                        if code:
                            return code
                    except Exception:
                        pass
            time.sleep(3)
        raise TimeoutError(f"zoromail: no OTP for {self.address}")


# ── Unified EmailBox ────────────────────────────────────────────────


class EmailBox:
    """Unified mailbox: create_account() + wait_code() + address/provider_name.

    Provider preference list can be set via constructor or GROK_TEMPMAIL_PROVIDERS
    env var (comma-separated). Defaults: ncaori, zoromail.
    """

    DEFAULT_PREFER = ["ncaori", "zoromail"]

    def __init__(
        self,
        prefer: list[str] | None = None,
    ):
        self.prefer = prefer or self._providers_from_env() or list(self.DEFAULT_PREFER)
        self.provider_name: str | None = None
        self.impl: Any = None
        self.address: str | None = None

    @staticmethod
    def _providers_from_env() -> list[str] | None:
        raw = os.getenv("GROK_TEMPMAIL_PROVIDERS", "")
        if not raw.strip():
            return None
        return [s.strip() for s in raw.split(",") if s.strip()]

    def _make(self, name: str) -> Any:
        key = name.lower().replace(" ", "")
        if key in ("ncaori", "ncaorimail", "nca"):
            return NcaoriMail()
        if key in ("zoromail", "zoro"):
            return Zoromail()
        raise ValueError(f"unknown mail provider: {name}")

    def create_account(self) -> str:
        errors: list[str] = []
        for name in self.prefer:
            try:
                impl = self._make(name)
                addr = impl.create_account()
                self.impl = impl
                self.provider_name = name
                self.address = addr
                return addr
            except Exception as e:
                errors.append(f"{name}: {e}")
        raise RuntimeError(
            "all temp-mail providers failed: " + " | ".join(errors)
        )

    def wait_code(self, timeout: int = 150) -> str:
        if not self.impl:
            raise RuntimeError("no mailbox — call create_account first")
        return self.impl.wait_code(timeout=timeout)


if __name__ == "__main__":
    box = EmailBox()
    addr = box.create_account()
    print(f"provider={box.provider_name} address={addr}")
