"""AWS FWCIM (Fraud Web Client Identity Module) v4.0.0 pure-HTTP port.

Reversed from profile.aws.amazon.com SPA (`profile_app.js`):
  fingerprint = "ECdITeCs:" + base64( XXTEA( hex(CRC32(utf8(json))) + "#" + utf8(json) ) )

Key material (keyProvider order):
  identifier = "ECdITeCs"
  material   = [1888420705, 2576816180, 2347232058, 874813317]

Used by kiro worker browserData.attributes.fingerprint. No browser required.
"""
from __future__ import annotations

import base64
import json
import random
import struct
import time
import zlib
from typing import Any

FWCIM_VERSION = "4.0.0"
FWCIM_IDENTIFIER = "ECdITeCs"
# SPA: return{identifier:e[2], material:[e[0], e[4], e[1], e[3]]}
# with array [1888420705, 2347232058, "ECdITeCs", 874813317, 2576816180]
FWCIM_MATERIAL = [1888420705, 2576816180, 2347232058, 874813317]
_XXTEA_DELTA = 2654435769  # 0x9E3779B9
_HEX_ALPHABET = "0123456789ABCDEF"

# Chrome 131 / Windows ANGLE — WebGL1 getSupportedExtensions() bulk (gpu collector).
_WEBGL_EXTENSIONS = [
    "ANGLE_instanced_arrays",
    "EXT_blend_minmax",
    "EXT_color_buffer_half_float",
    "EXT_disjoint_timer_query",
    "EXT_float_blend",
    "EXT_frag_depth",
    "EXT_shader_texture_lod",
    "EXT_texture_compression_bptc",
    "EXT_texture_compression_rgtc",
    "EXT_texture_filter_anisotropic",
    "EXT_sRGB",
    "KHR_parallel_shader_compile",
    "OES_element_index_uint",
    "OES_fbo_render_mipmap",
    "OES_standard_derivatives",
    "OES_texture_float",
    "OES_texture_float_linear",
    "OES_texture_half_float",
    "OES_texture_half_float_linear",
    "OES_vertex_array_object",
    "WEBGL_color_buffer_float",
    "WEBGL_compressed_texture_s3tc",
    "WEBGL_compressed_texture_s3tc_srgb",
    "WEBGL_debug_renderer_info",
    "WEBGL_debug_shaders",
    "WEBGL_depth_texture",
    "WEBGL_draw_buffers",
    "WEBGL_lose_context",
    "WEBGL_multi_draw",
]

# SPA capabilities collector (profile_app.js):
#   CSS_PROPERTIES = textShadow, textStroke, boxShadow, borderRadius, borderImage,
#                    opacity, transform, transform3d, transition
#   CSS_PREFIXES   = Webkit, Moz, O, ms, khtml
# Chrome recognizes most unprefixed; textStroke is Webkit-only; transform3d is not a
# real CSS prop so typically absent (or only under a prefix that also fails).
_CSS_CAPABILITIES_CHROME = {
    "textShadow": 1,
    "WebkitTextStroke": 1,
    "boxShadow": 1,
    "borderRadius": 1,
    "borderImage": 1,
    "opacity": 1,
    "transform": 1,
    "transition": 1,
}


def _to_uint32(n: int) -> int:
    return n & 0xFFFFFFFF


def xxtea_encrypt(plaintext: str, key: list[int]) -> bytes:
    """SPA `doEncrypt` — XXTEA over Latin1 string, returns raw cipher bytes.

    Packs 4-byte little-endian words (missing bytes → 0 via charCodeAt undefined→NaN→0
    in JS; we pad with 0). Rounds = floor(6 + 52/n).
    """
    if not plaintext:
        return b""
    data = plaintext.encode("latin-1", errors="replace")
    # ceil(len/4) words
    n = (len(data) + 3) // 4
    words = [0] * n
    for i in range(n):
        b0 = data[4 * i] if 4 * i < len(data) else 0
        b1 = data[4 * i + 1] if 4 * i + 1 < len(data) else 0
        b2 = data[4 * i + 2] if 4 * i + 2 < len(data) else 0
        b3 = data[4 * i + 3] if 4 * i + 3 < len(data) else 0
        words[i] = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)

    k = [_to_uint32(x) for x in key]
    rounds = 6 + 52 // n
    z = words[n - 1]
    y = words[0]
    summary = 0
    for _ in range(rounds):
        summary = _to_uint32(summary + _XXTEA_DELTA)
        e = (summary >> 2) & 3
        for p in range(n):
            y = words[(p + 1) % n]
            # c = a[u] += (c>>>5 ^ i<<2) + (i>>>3 ^ c<<4) ^ (s^i) + (o[3&u^d]^c)
            mx = _to_uint32(
                ((z >> 5) ^ _to_uint32(y << 2))
                + ((y >> 3) ^ _to_uint32(z << 4))
                ^ (summary ^ y)
                + (k[(p & 3) ^ e] ^ z)
            )
            words[p] = _to_uint32(words[p] + mx)
            z = words[p]

    out = bytearray()
    for w in words:
        out.append(w & 0xFF)
        out.append((w >> 8) & 0xFF)
        out.append((w >> 16) & 0xFF)
        out.append((w >> 24) & 0xFF)
    return bytes(out)


def crc32_ieee(data: str) -> int:
    """SPA CRC32: poly 0xEDB88320, init/final XOR 0xFFFFFFFF, over charCodeAt bytes.

    For ASCII/Latin1 strings this matches zlib.crc32 with the same convention.
    """
    raw = data.encode("latin-1", errors="replace")
    return zlib.crc32(raw) & 0xFFFFFFFF


def hex_encode_u32(n: int) -> str:
    """SPA hexEncoder — 8 uppercase hex digits, MSB first."""
    n = _to_uint32(n)
    return "".join(_HEX_ALPHABET[(n >> shift) & 15] for shift in (28, 24, 20, 16, 12, 8, 4, 0))


def encode_payload(payload: dict[str, Any]) -> str:
    """hex(crc32(json)) + '#' + json  (utf8 is identity for our ASCII JSON)."""
    # Compact JSON like JSON.stringify (no spaces; default key order insertion-order).
    js = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
    return hex_encode_u32(crc32_ieee(js)) + "#" + js


def encrypt_fingerprint(payload: dict[str, Any]) -> str:
    """Full FWCIM encrypt → 'ECdITeCs:<base64>'."""
    encoded = encode_payload(payload)
    cipher = xxtea_encrypt(encoded, FWCIM_MATERIAL)
    return FWCIM_IDENTIFIER + ":" + base64.b64encode(cipher).decode("ascii")


def _amazon_style_id(rng: random.Random) -> str:
    """Shape: X##-#######-#######:<epoch_s> (SPA amznfbgid / lsUbid validator)."""
    a = rng.randint(10, 99)
    b = rng.randint(1_000_000, 9_999_999)
    c = rng.randint(1_000_000, 9_999_999)
    ts = int(time.time())
    return f"X{a}-{b}-{c}:{ts}"


def _screen_info(rng: random.Random) -> str:
    """SPA screenInfo collector (profile_app.js):

    width-height-availHeight-colorDepth-deviceXDPI-logicalXDPI-fontSmoothing
    e.g. ``1920-1080-1040-24-*-*-[01]``  (``*`` when device/logical XDPI undefined)
    """
    widths = [
        (1920, 1080, 1040),
        (2560, 1440, 1400),
        (1536, 864, 824),
        (1440, 900, 860),
        (1366, 768, 728),
    ]
    w, h, avail_h = widths[rng.randrange(len(widths))]
    color_depth = 24
    # Chrome on Windows rarely exposes deviceXDPI/logicalXDPI → "*"
    device_xdpi = "*"
    logical_xdpi = "*"
    # fontSmoothingEnabled truthy → "1", falsy → "0", undefined → "*"
    font_smoothing = "1"
    return (
        f"{w}-{h}-{avail_h}-{color_depth}-"
        f"{device_xdpi}-{logical_xdpi}-{font_smoothing}"
    )


def _chrome_pdf_plugins() -> list[dict[str, str]]:
    """Default Chromium PDF plugins (navigator.plugins on Chrome 131).

    SPA builds per-plugin ``str = name + " " + description.replace(/[^0-9]/g, "")``.
    Chrome's built-in PDF entries have no digits in the description, so each
    ``str`` ends with a trailing space (name + " " + "").
    """
    # (name, description) — version is unused for str/plugins concat
    entries = [
        ("PDF Viewer", "Portable Document Format"),
        ("Chrome PDF Viewer", "Portable Document Format"),
        ("Chromium PDF Viewer", "Portable Document Format"),
        ("Microsoft Edge PDF Viewer", "Portable Document Format"),
        ("WebKit built-in PDF", "Portable Document Format"),
    ]
    out: list[dict[str, str]] = []
    for name, desc in entries:
        digits = "".join(ch for ch in desc if ch.isdigit())
        out.append({
            "name": name,
            "version": "",
            "str": f"{name} {digits}",
        })
    return out


def _synthetic_interaction(rng: random.Random, *, dwell_ms: int, mode: str = "email") -> dict[str, Any]:
    """SPA interaction collector — full telemetry object (profile_app.js).

    Collector data init:
      clicks, touches, keyPresses, cuts, copies, pastes,
      keyPressTimeIntervals[], mouseClickPositions[] ("x,y" strings, max 10),
      keyCycles[], mouseCycles[], touchCycles[]  (raw {start,end} objects)

    After transformCycles the emitted interaction object is:
      { ...data, keyCycles: durations, mouseCycles: durations, touchCycles: durations }

    Mode ``email`` (default): 18-36 keypresses for email text input (~20-35 chars).
    Mode ``otp``: 6 keypresses for 6-digit OTP with slower deliberate timing.
    """
    if mode == "otp":
        # 6-digit OTP: exactly 6 keypresses, slower per-digit dwell.
        n_keys = 6
        n_mouse = rng.randint(1, 3)
        n_clicks = rng.randint(1, min(2, n_mouse))
        key_cycles = [rng.randint(60, 250) for _ in range(n_keys)]
        key_intervals: list[int] = []
        if n_keys > 1:
            # OTP typing: deliberate per-digit pauses 200-600ms
            for _ in range(n_keys - 1):
                key_intervals.append(rng.randint(200, 600))
    else:
        # Email input: ~18-36 key events, faster typing.
        n_keys = rng.randint(18, 36)
        n_mouse = rng.randint(2, 5)
        n_clicks = rng.randint(1, min(3, n_mouse))
        key_cycles = [rng.randint(40, 180) for _ in range(n_keys)]
        key_intervals = []
        if n_keys > 1:
            for _ in range(n_keys - 1):
                key_intervals.append(rng.randint(80, 280))

    mouse_cycles = [rng.randint(80, 350) for _ in range(n_mouse)]
    click_positions = [
        f"{rng.randint(40, 420)},{rng.randint(8, 28)}"
        for _ in range(n_clicks)
    ]

    return {
        "clicks": n_clicks,
        "touches": 0,
        "keyPresses": n_keys,
        "cuts": 0,
        "copies": 0,
        "pastes": 0,
        "keyPressTimeIntervals": key_intervals,
        "mouseClickPositions": click_positions,
        "keyCycles": key_cycles,
        "mouseCycles": mouse_cycles,
        "touchCycles": [],
    }


# JS Math.tan/sin/cos(-1e300) stringified — stable across V8/Chrome (math collector).
_MATH_FP = {
    "tan": "-1.4214488238747245",
    "sin": "0.8178819121159085",
    "cos": "-0.5753861119575491",
}

# Profile SPA bootstrap + common follow-on assets (scripts collector scrapes <script src>).
# Live profile index only ships the main bundle; after SPA boot the document still
# typically exposes that one external script. Extra cloudfront/chunk URLs are only
# added when they would actually appear as <script> tags — keep the list tight.
# Absolute URLs as they appear after browser resolution of relative <script src>.
# Profile bootstrap ships the main bundle; SPA boot may also leave vendor/runtime
# tags in documentElement.innerHTML. Keep only plausible profile.aws assets.
_PROFILE_SCRIPT_URLS = [
    "https://profile.aws.amazon.com/dist/main/app_dc1a861e892db180ecf3.min.js",
]


def _performance_timing(rng: random.Random, *, nav_start_ms: int) -> dict[str, int]:
    """SPA performance collector: ``window.performance.timing.toJSON()``.

    Navigation Timing Level 1 fields (absolute epoch-ms). Synthetic but monotonic
    and Chrome-shaped — this is the bulk of form-path FP size after canvas.
    """
    t = nav_start_ms
    # unload/redirect usually 0 on a top-level profile navigation
    unload_s = unload_e = redirect_s = redirect_e = 0
    fetch = t + rng.randint(0, 2)
    dns_s = fetch + rng.randint(0, 1)
    dns_e = dns_s + rng.randint(0, 8)
    conn_s = dns_e
    conn_e = conn_s + rng.randint(20, 80)
    ssl_s = conn_s + rng.randint(1, 10)  # secureConnectionStart
    req_s = conn_e + rng.randint(0, 3)
    res_s = req_s + rng.randint(40, 180)
    res_e = res_s + rng.randint(5, 40)
    dom_loading = res_e + rng.randint(0, 5)
    dom_interactive = dom_loading + rng.randint(200, 900)
    dcl_s = dom_interactive + rng.randint(5, 40)
    dcl_e = dcl_s + rng.randint(0, 8)
    dom_complete = dcl_e + rng.randint(100, 600)
    load_s = dom_complete + rng.randint(0, 5)
    load_e = load_s + rng.randint(0, 15)
    return {
        "navigationStart": t,
        "unloadEventStart": unload_s,
        "unloadEventEnd": unload_e,
        "redirectStart": redirect_s,
        "redirectEnd": redirect_e,
        "fetchStart": fetch,
        "domainLookupStart": dns_s,
        "domainLookupEnd": dns_e,
        "connectStart": conn_s,
        "connectEnd": conn_e,
        "secureConnectionStart": ssl_s,
        "requestStart": req_s,
        "responseStart": res_s,
        "responseEnd": res_e,
        "domLoading": dom_loading,
        "domInteractive": dom_interactive,
        "domContentLoadedEventStart": dcl_s,
        "domContentLoadedEventEnd": dcl_e,
        "domComplete": dom_complete,
        "loadEventStart": load_s,
        "loadEventEnd": load_e,
    }


def _canvas_fingerprint(rng: random.Random, *, email_on_page: bool = True) -> dict[str, Any]:
    """SPA canvas collector (module 63): ``{hash, emailHash, histogramBins}``.

    Real SPA draws geometry/text then:
      hash      = CRC32(join(isPointInPath flags + toDataURL()))
      emailHash = "~" when no email input, else CRC32(toDataURL after fillText(email))
      histogramBins = 256-bin count of getImageData(...).data bytes

    Canvas is 150×60; getImageData returns 150*60*4 = 36000 RGBA bytes, so
    ``sum(histogramBins)`` must be exactly 36000. Under-sum (~17k) is a clear
    TES red flag on synthetic collectors.

    When ``email_on_page=False`` (e.g. OTP verification page), emailHash is "~".
    """
    seed = rng.randint(0, 0xFFFFFFFF)
    base = f"canvas-fp:{seed:08x}|150x60|chrome131"
    canvas_hash = crc32_ieee(base)
    # SPA sets emailHash="~" when querySelectorAll(email) length is 0
    # (e.g. EMAIL_VERIFICATION page has OTP input, not email).
    if not email_on_page:
        email_hash = "~"
    else:
        email_hash = crc32_ieee(base + "|email")

    # Real histogram: opaque white-ish background + anti-aliased strokes/text
    # and multi-color arcs inflate mid/high buckets. Build then renormalize to
    # exactly CANVAS_PIXELS * 4 so TES cannot score sum(bins) alone.
    canvas_bytes = 150 * 60 * 4  # 36000
    bins = [0] * 256
    # Dominant: opaque white / near-white background (A=255, RGB≈255)
    bins[255] = int(canvas_bytes * 0.42)
    bins[254] = int(canvas_bytes * 0.06)
    bins[253] = int(canvas_bytes * 0.03)
    # Clear / black residual from paths before fill
    bins[0] = int(canvas_bytes * 0.08)
    bins[1] = int(canvas_bytes * 0.02)
    bins[2] = int(canvas_bytes * 0.01)
    # Mid-tone anti-alias + gradient stops (dense non-zero elsewhere)
    remaining = canvas_bytes - sum(bins)
    weights = [rng.randint(1, 12) for _ in range(256)]
    # Keep background buckets from the weight pool so we don't double-count
    for locked in (0, 1, 2, 253, 254, 255):
        weights[locked] = 0
    wsum = sum(weights) or 1
    for i in range(256):
        if weights[i]:
            bins[i] += max(1, int(remaining * weights[i] / wsum))
    # Exact fix-up: clamp negatives then adjust bin 255 to hit canvas_bytes
    for i in range(256):
        if bins[i] < 0:
            bins[i] = 0
    delta = canvas_bytes - sum(bins)
    bins[255] = max(0, bins[255] + delta)
    # Final guard — never ship a wrong-sum histogram
    if sum(bins) != canvas_bytes:
        bins[255] = max(0, bins[255] + (canvas_bytes - sum(bins)))
    return {
        "hash": canvas_hash,
        "emailHash": email_hash,
        "histogramBins": bins,
    }


def _scripts_collector(rng: random.Random) -> dict[str, Any]:
    """SPA scripts collector (module 46).

    Scrapes ``document.documentElement.innerHTML`` for ``<script>`` tags:
      - external: strip ``src="..."`` → push URL (substring after src=" / before ")
      - inline:   CRC32(full tag text) → inlineHashes
    Profile bootstrap is a single external bundle; inlineHashes usually empty.
    """
    # Use absolute URLs as they appear after browser resolution in innerHTML.
    dynamic = list(_PROFILE_SCRIPT_URLS)
    # Occasionally SPA injects a small runtime/config script — keep rare so we
    # don't invent assets that never exist; 0 inline is the common profile path.
    inline: list[int] = []
    elapsed = rng.randint(0, 3)
    return {
        "dynamicUrls": dynamic,
        "inlineHashes": inline,
        "elapsed": elapsed,
        "dynamicUrlCount": len(dynamic),
        "inlineHashesCount": len(inline),
    }


def _automation_collector() -> dict[str, Any]:
    """SPA automation collector (module 50) — clean Chrome → empty property lists."""
    return {
        "wd": {
            "properties": {
                "document": [],
                "window": [],
                "navigator": [],
            }
        },
        "phantom": {
            "properties": {
                "window": [],
            }
        },
    }


def build_collector_payload(
    *,
    time_zone_hours: int | None = None,
    rng: random.Random | None = None,
    dwell_ms: int | None = None,
    location: str | None = None,
    referrer: str | None = None,
    user_agent: str | None = None,
    form_method: str = "post",
    include_canvas: bool = True,
    page_has_captcha: bool = False,
    form_key: str = "email",
) -> dict[str, Any]:
    """SPA form-path FWCIM collector merge (profileForm / report) — version 4.0.0.

    Profile signup binds ``window.fwcim.profileForm("#"+formId)`` then reports via
    ``window.fwcim.report(...)``. Form COLLECTORS (module 27) are:

      main COLLECTORS (module 10):
        start, interaction, scripts, history, battery, performance, automation, end
      then form extras:
        start, tz, plugins(fp2), lsubid, browser, capabilities, gpu, dnt, math,
        timeToSubmit, form telemetry, canvas, captcha, pow, formMethod, end

    Compound merge (module 9) folds each collector's object and records
    ``metrics[collectorName] = wall_ms``. ``collectAndEncrypt`` then sets
    ``version = "4.0.0"`` and concatenates initialization errors.

    **Do not invent fields.** No canvasFingerprint / webglFingerprint /
    audioFingerprint / fonts / flat cssCapabilities / top-level navigator.
    """
    rng = rng or random.Random()
    now_ms = int(time.time() * 1000)
    # Capture send-otp timeSpentOnPage ≈ 7031ms — dwell should be multi-second
    # for PageSubmit EMAIL_COLLECTION, not sub-second bootstrap.
    if dwell_ms is None:
        dwell_ms = rng.randint(4500, 9000)
    start_ms = now_ms - dwell_ms
    end_ms = now_ms
    # Nav timing anchors slightly before collector start (page loaded earlier).
    nav_start = start_ms - rng.randint(800, 2500)

    if time_zone_hours is None:
        # SPA tz collector: (local midnight - GMT-stripped midnight) / 36e5
        time_zone_hours = rng.choice([-8, -7, -6, -5, -4, 0, 1, 2])

    ls_ubid = _amazon_style_id(rng)

    # plugins / fp2 (module 15 + 56 + 55)
    screen = _screen_info(rng)
    plugin_entries = _chrome_pdf_plugins()
    seen: set[str] = set()
    unique_strs: list[str] = []
    all_strs: list[str] = []
    for p in plugin_entries:
        all_strs.append(p["str"])
        if p["name"] not in seen:
            seen.add(p["name"])
            unique_strs.append(p["str"])
    plugins_str = "".join(unique_strs) + "||" + screen
    duped_str = "".join(all_strs) + "||" + screen
    flash_version = "unknown"

    interaction = _synthetic_interaction(rng, dwell_ms=dwell_ms, mode="email" if form_key == "email" else "otp")
    scripts = _scripts_collector(rng)
    perf_timing = _performance_timing(rng, nav_start_ms=nav_start)

    gpu = {
        "vendor": "Google Inc. (NVIDIA)",
        "model": (
            "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 SUPER "
            "Direct3D11 vs_5_0 ps_5_0, D3D11)"
        ),
        "extensions": list(_WEBGL_EXTENSIONS),
    }

    js_caps = {
        "audio": True,
        "geolocation": True,
        "localStorage": "supported",
        "touch": False,
        "video": True,
        "webWorker": True,
    }
    capabilities = {
        "css": dict(_CSS_CAPABILITIES_CHROME),
        "js": js_caps,
        "elapsed": rng.randint(0, 3),
    }

    # browser collector (module 22). Profile URLs are not in the pharmacy/health
    # obfuscation map and path is not /ap|/a → referrer/location pass through.
    if user_agent is None:
        # Soft-match capture Chrome 149; TLS impersonate remains chrome131.
        user_agent = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/149.0.0.0 Safari/537.36"
        )
    if location is None:
        location = "https://profile.aws.amazon.com/"
    if referrer is None:
        referrer = "https://us-east-1.signin.aws/"

    # metrics keys = collectorName (module 9). start/end time collectors have no
    # collectorName → omitted. interaction wrapper reports as "el".
    metrics = {
        "el": rng.randint(0, 4),
        "script": rng.randint(0, 4),
        "h": rng.randint(0, 2),
        "batt": rng.randint(0, 2),
        "perf": rng.randint(0, 2),
        "auto": rng.randint(0, 2),
        "tz": rng.randint(0, 2),
        "fp2": rng.randint(1, 12),
        "lsubid": rng.randint(0, 2),
        "browser": rng.randint(0, 2),
        "capabilities": rng.randint(0, 4),
        "gpu": rng.randint(3, 20),
        "dnt": rng.randint(0, 1),
        "math": rng.randint(0, 1),
        "tts": rng.randint(0, 1),
        "input": rng.randint(0, 3),
        "canvas": rng.randint(5, 30),
        "pow": rng.randint(0, 2),
    }

    # Insertion order ≈ SPA Object.assign merge order (main then form extras).
    # Later keys overwrite earlier ones for start/end (form re-adds them).
    payload: dict[str, Any] = {
        # --- main COLLECTORS ---
        "start": start_ms,
        "interaction": interaction,
        "scripts": scripts,
        "history": {"length": rng.randint(2, 4)},
        # Desktop Chrome without battery API → collector returns {}
        # (no top-level "battery" key). Emit empty merge contribution by omission.
        "performance": {"timing": perf_timing},
        "automation": _automation_collector(),
        # --- form extras ---
        "timeZone": time_zone_hours,
        "flashVersion": flash_version,
        "plugins": plugins_str,
        "dupedPlugins": duped_str,
        "screenInfo": screen,
        "lsUbid": ls_ubid,
        "referrer": referrer,
        "userAgent": user_agent,
        "location": location,
        "webDriver": False,
        "capabilities": capabilities,
        "gpu": gpu,
        "dnt": 0,
        "math": dict(_MATH_FP),
        # timeToSubmit only when form was submitted (PageSubmit path)
        "timeToSubmit": max(dwell_ms - rng.randint(50, 400), 100),
        # form input telemetry (module 54) — key depends on page (form_key param)
        "form": {
            form_key: _synthetic_interaction(
                rng, dwell_ms=max(dwell_ms - 500, 500),
                mode="otp" if form_key != "email" else "email",
            ),
        },
        "auth": {"form": {"method": (form_method or "post").lower()}},
        # pow token (module 52) — no captcha on profile email form → no solve
        "token": {
            "isCompatible": True,
            "pageHasCaptcha": 1 if page_has_captcha else 0,
        },
        "end": end_ms,
        "metrics": metrics,
        "errors": [],
        "version": FWCIM_VERSION,
    }
    if include_canvas:
        payload["canvas"] = _canvas_fingerprint(rng, email_on_page=(form_key == "email"))
    return payload


def collect_and_encrypt(
    *,
    time_zone_hours: int | None = None,
    rng: random.Random | None = None,
    dwell_ms: int | None = None,
    location: str | None = None,
    referrer: str | None = None,
    user_agent: str | None = None,
    form_key: str = "email",
) -> str:
    """collectAndEncrypt equivalent — synthetic form-path collectors + encrypt."""
    payload = build_collector_payload(
        time_zone_hours=time_zone_hours,
        rng=rng,
        dwell_ms=dwell_ms,
        location=location,
        referrer=referrer,
        user_agent=user_agent,
        form_key=form_key,
    )
    return encrypt_fingerprint(payload)
