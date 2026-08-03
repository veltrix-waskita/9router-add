#!/usr/bin/env python3
"""
UNIVERSAL CAPTCHA SOLVER — single local endpoint (:8877)
Merge of Boterdrop (Camoufox anti-detect page-pool) + free local + Capsolver.

ENGINE  : Camoufox (Firefox anti-detect) page-pool
          → Turnstile / cf_clearance / aws-waf-token / reCAPTCHA / hCaptcha (native)
FREE     : math (eval), text/image (tesseract OCR), slider (opencv)
FALLBACK : Capsolver → funcaptcha/arkose, geetest, datadome + failed browser types
           (hCaptcha prefers local first; Capsolver often blocks sitekeys)

Solve ANY captcha through one API. Sync (POST /solve) + async (GET /turnstile → GET /result?id=) both supported.
By FEB-FRMN · https://saweria.co/febfrmn
"""
import os, sys, io, re, json, time, uuid, base64, asyncio, logging, hashlib
import urllib.request, urllib.error
from urllib.parse import urlparse
from typing import Optional

from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from loguru import logger
import uvicorn

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

# ─── Config ───────────────────────────────────────────────────────────────
PORT              = int(os.getenv("PORT", "8877"))
# NOTE (2026-08-04, operator decision): binding 0.0.0.0 + the regex-prefix SSRF
# guard below are DELIBERATE accepted risk, carried over from the workbase farm
# sync — not an oversight. The repo version used to default to 127.0.0.1 with a
# DNS-resolving guard; we keep the farm's posture so aliyun solves work. The
# runner reaches the solver only via loopback (127.0.0.1:8877), so grok-cli and
# pateway are unaffected by the wider bind. Restrict to HOST=127.0.0.1 if this
# host sits on an untrusted network.
HOST              = os.getenv("HOST", "0.0.0.0")
HEADLESS          = os.getenv("SOLVER_HEADLESS", "1") != "0"
THREADS           = int(os.getenv("SOLVER_THREADS", "2"))
PAGES_PER_THREAD  = int(os.getenv("SOLVER_PAGES", "1"))
CLEANUP_MIN       = int(os.getenv("SOLVER_CLEANUP_MIN", "10"))
PROXY_SUPPORT     = os.getenv("SOLVER_PROXY_SUPPORT", "0") == "1"
PROXY_FILE        = os.getenv("SOLVER_PROXY_FILE", "proxies.txt")
ALLOW_PRIVATE     = os.getenv("SOLVER_ALLOW_PRIVATE", "0") == "1"
CAPSOLVER_API_KEY = os.getenv("CAPSOLVER_API_KEY", "")
SOLVER_MODE       = os.getenv("SOLVER_MODE", "auto").lower()   # auto | local | capsolver
SOLVER_ENGINE     = os.getenv("SOLVER_ENGINE", "camoufox").lower()  # primary: camoufox | cloak
# hCaptcha can use a SEPARATE engine (dual-pool). Cloak (Chromium stealth) tends
# to earn a higher hCaptcha trust score → easier challenges. Turnstile MUST stay
# on camoufox: cloak headless can't render the Turnstile iframe (verified).
SOLVER_HCAPTCHA_ENGINE = os.getenv("SOLVER_HCAPTCHA_ENGINE", SOLVER_ENGINE).lower()
CLOAK_LICENSE_KEY = os.getenv("CLOAK_LICENSE_KEY", "")  # optional; free tier works without
SOLVER_HUMANIZE   = os.getenv("SOLVER_HUMANIZE", "1") != "0"  # cloak: human-like mouse/kbd
# separate pool sizing for the hcaptcha engine (keeps memory bounded)
HC_THREADS        = int(os.getenv("SOLVER_HC_THREADS", "1"))
HC_PAGES          = int(os.getenv("SOLVER_HC_PAGES", "2"))

DEMO_TOKENS = {
    "1x00000000000000000000AA": "XXXX.DUMMY.TOKEN.XXXX",
    "3x00000000000000000000AA": "XXXX.DUMMY.TOKEN.XXXX",
    "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI": "03AGdBq25H3K...",
}

SUPPORTED = ["math", "text", "image", "slider", "turnstile", "recaptcha",
             "recaptchav3", "hcaptcha", "funcaptcha", "geetest", "datadome",
             "cloudflare", "awswaf", "botguard", "aliyun", "akamai",
             "perimeterx", "arkose"]

log = logging.getLogger("solver")

# ─── SSRF guard ─────────────────────────────────────────────────────────────
# NOTE (2026-08-04): this is the farm's WEAKER guard — a literal regex prefix
# match on the hostname string, NOT DNS resolution (a name like `evil.test`
# that resolves to 127.0.0.1 sails through). The old repo version resolved the
# name and judged every address it mapped to. Kept deliberately to match the
# farm sync (see HOST note above), but the deny list below now includes
# 169.254.0.0/16 (cloud metadata, e.g. 169.254.169.254) which was missing.
_PRIV = [re.compile(p) for p in [
    r"^127\.\d+\.\d+\.\d+", r"^10\.\d+\.\d+\.\d+",
    r"^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+", r"^192\.168\.\d+\.\d+",
    r"^169\.254\.\d+\.\d+",        # link-local — cloud metadata lives here
    r"^0\.0\.0\.0$", r"^localhost$", r"^::1$"]]
def check_ssrf(u):
    if ALLOW_PRIVATE or not u:
        return
    p = urlparse(u)
    if p.scheme not in ("http", "https"):
        raise HTTPException(400, f"Bad scheme: {p.scheme}")
    for r in _PRIV:
        if r.search(p.hostname or ""):
            raise HTTPException(400, f"Private host: {p.hostname}")

# ─── image helpers ──────────────────────────────────────────────────────────
def load_image_bytes(src: str) -> bytes:
    if not src:
        raise ValueError("no image provided")
    s = src.strip()
    if s.startswith("data:"):
        s = s.split(",", 1)[1]
    if s.startswith("http://") or s.startswith("https://"):
        # /solve only validated req.url — req.image / req.bg_image / req.puzzle_image
        # were fetched unvalidated. Same guard here so a caller can't point the
        # solver at 127.0.0.1/169.254.169.254 via an image field.
        check_ssrf(s)
        req = urllib.request.Request(s, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read()
    if os.path.exists(s):
        with open(s, "rb") as f:
            return f.read()
    return base64.b64decode(s)

def image_to_b64(src: str) -> str:
    s = src.strip()
    if s.startswith("data:"):
        return s.split(",", 1)[1]
    if s.startswith("http") or os.path.exists(s):
        return base64.b64encode(load_image_bytes(s)).decode()
    return s

# ─── FREE: math ─────────────────────────────────────────────────────────────
_WORDS = {"zero":0,"one":1,"two":2,"three":3,"four":4,"five":5,"six":6,"seven":7,
          "eight":8,"nine":9,"ten":10,"eleven":11,"twelve":12,
          "plus":"+","minus":"-","times":"*","multiplied":"*","divided":"/"}
def solve_math(text: str):
    if not text:
        return {"solved": False, "error": "no text"}
    raw = text.lower()
    for w, v in _WORDS.items():
        raw = re.sub(rf"\b{w}\b", str(v), raw)
    expr = re.sub(r"[^0-9+\-*/(). ]", " ", raw)
    m = re.search(r"[-+]?\d[\d\s+\-*/().]*\d", expr)
    if not m:
        m2 = re.search(r"[-+]?\d+", expr)
        return ({"solved": True, "solution": m2.group(), "answer": m2.group()}
                if m2 else {"solved": False, "error": "no expression"})
    e = m.group().replace(" ", "")
    if not re.fullmatch(r"[0-9+\-*/(). ]+", e):
        return {"solved": False, "error": "unsafe expression"}
    try:
        val = eval(e, {"__builtins__": {}}, {})
        if isinstance(val, float) and val.is_integer():
            val = int(val)
        return {"solved": True, "solution": str(val), "answer": str(val), "expr": e}
    except Exception as ex:
        return {"solved": False, "error": f"eval failed: {ex}"}

# ─── FREE: OCR ──────────────────────────────────────────────────────────────
def solve_ocr(image_src: str, is_math=False):
    try:
        import pytesseract
        from PIL import Image, ImageFilter, ImageOps
    except Exception as e:
        return {"solved": False, "error": f"OCR deps missing: {e}"}
    try:
        img = Image.open(io.BytesIO(load_image_bytes(image_src))).convert("L")
        img = img.resize((img.width * 2, img.height * 2), Image.LANCZOS)
        img = ImageOps.autocontrast(img)
        img = img.point(lambda p: 255 if p > 140 else 0)
        img = img.filter(ImageFilter.MedianFilter(3))
        txt = pytesseract.image_to_string(img, config="--psm 8 --oem 3").strip()
        txt = re.sub(r"\s+", "", txt)
        if is_math:
            return solve_math(txt)
        clean = re.sub(r"[^A-Za-z0-9]", "", txt)
        return ({"solved": True, "solution": clean, "answer": clean, "raw": txt}
                if clean else {"solved": False, "error": "OCR empty", "raw": txt})
    except Exception as e:
        return {"solved": False, "error": str(e)}

# ─── FREE: slider ───────────────────────────────────────────────────────────
def solve_slider(bg_src: str, puzzle_src: str):
    try:
        import cv2, numpy as np
    except Exception as e:
        return {"solved": False, "error": f"opencv missing: {e}"}
    try:
        bg = cv2.imdecode(np.frombuffer(load_image_bytes(bg_src), np.uint8), cv2.IMREAD_COLOR)
        pz = cv2.imdecode(np.frombuffer(load_image_bytes(puzzle_src), np.uint8), cv2.IMREAD_COLOR)
        res = cv2.matchTemplate(cv2.Canny(bg, 100, 200), cv2.Canny(pz, 100, 200), cv2.TM_CCOEFF_NORMED)
        _, maxv, _, maxloc = cv2.minMaxLoc(res)
        return {"solved": True, "solution": str(int(maxloc[0])), "answer": str(int(maxloc[0])),
                "x": int(maxloc[0]), "y": int(maxloc[1]), "confidence": round(float(maxv), 3)}
    except Exception as e:
        return {"solved": False, "error": str(e)}

# ─── UNIVERSAL Capsolver fallback ────────────────────────────────────────────
def _cap_post(endpoint, payload):
    data = json.dumps(payload).encode()
    req = urllib.request.Request(f"https://api.capsolver.com/{endpoint}",
        data=data, headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())

def _extract_solution(sol):
    if not isinstance(sol, dict):
        return None, sol
    for k in ("gRecaptchaResponse", "token", "text", "value"):
        if sol.get(k):
            return sol[k], sol
    if sol.get("cookie"):
        return sol["cookie"], sol
    if any(k in sol for k in ("challenge", "captcha_output", "lot_number")):
        return sol, sol
    return None, sol

def build_cap_task(req):
    t = req.type.lower()
    ent = req.enterprise
    if t in ("math", "text", "image"):
        return {"type": "ImageToTextTask", "body": image_to_b64(req.image or "")}, True
    if t == "turnstile":
        meta = {"action": req.action or ""}
        if req.cdata:
            meta["cdata"] = req.cdata
        return {"type": "AntiTurnstileTaskProxyLess", "websiteURL": req.url,
                "websiteKey": req.sitekey or "", "metadata": meta}, False
    if t == "recaptchav3" or (t == "recaptcha" and req.version == "v3"):
        tt = "ReCaptchaV3EnterpriseTaskProxyLess" if ent else "ReCaptchaV3TaskProxyLess"
        return {"type": tt, "websiteURL": req.url, "websiteKey": req.sitekey or "",
                "pageAction": req.action or "verify"}, False
    if t == "recaptcha":
        tt = "ReCaptchaV2EnterpriseTaskProxyLess" if ent else "ReCaptchaV2TaskProxyLess"
        return {"type": tt, "websiteURL": req.url, "websiteKey": req.sitekey or ""}, False
    if t == "hcaptcha":
        tt = "HCaptchaEnterpriseTaskProxyLess" if ent else "HCaptchaTaskProxyLess"
        return {"type": tt, "websiteURL": req.url, "websiteKey": req.sitekey or ""}, False
    if t in ("funcaptcha", "arkose"):
        return {"type": "FunCaptchaTaskProxyLess", "websiteURL": req.url,
                "websitePublicKey": req.public_key or req.sitekey or ""}, False
    if t == "geetest":
        if req.captcha_id:
            return {"type": "GeeTestTaskProxyLess", "websiteURL": req.url, "captchaId": req.captcha_id}, False
        return {"type": "GeeTestTaskProxyLess", "websiteURL": req.url,
                "gt": req.gt or "", "challenge": req.challenge or ""}, False
    if t == "datadome":
        task = {"type": "DatadomeSliderTask", "websiteURL": req.url, "captchaUrl": req.url,
                "userAgent": req.user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36"}
        if req.proxy:
            task["proxy"] = req.proxy
        return task, False
    if t == "awswaf":
        return {"type": "AntiAwsWafTaskProxyLess", "websiteURL": req.url}, False
    if t == "cloudflare":
        return {"type": "AntiCloudflareTask", "websiteURL": req.url, "proxy": req.proxy or ""}, False
    raise ValueError(f"no capsolver mapping for type={t}")

def capsolver_solve(req):
    if not CAPSOLVER_API_KEY:
        return {"solved": False, "error": "no CAPSOLVER_API_KEY", "note": "capsolver_skipped"}
    try:
        task, _ = build_cap_task(req)
    except ValueError as e:
        return {"solved": False, "error": str(e)}
    try:
        cr = _cap_post("createTask", {"clientKey": CAPSOLVER_API_KEY, "task": task})
        if cr.get("errorId"):
            return {"solved": False, "error": cr.get("errorDescription", "createTask error")}
        if cr.get("status") == "ready" and cr.get("solution"):
            tok, sol = _extract_solution(cr["solution"])
            return {"solved": bool(tok), "token": tok, "solution": sol, "note": "capsolver_immediate"}
        tid = cr.get("taskId")
        if not tid:
            return {"solved": False, "error": "no taskId"}
        start = time.time()
        while time.time() - start < req.timeout_s:
            time.sleep(2)
            pr = _cap_post("getTaskResult", {"clientKey": CAPSOLVER_API_KEY, "taskId": tid})
            if pr.get("errorId"):
                return {"solved": False, "error": pr.get("errorDescription", "getTaskResult error")}
            if pr.get("status") == "ready":
                tok, sol = _extract_solution(pr.get("solution", {}))
                return {"solved": bool(tok), "token": tok, "solution": sol, "note": "capsolver"}
            if pr.get("status") == "failed":
                return {"solved": False, "error": pr.get("errorDescription", "capsolver failed")}
        return {"solved": False, "error": "capsolver timeout"}
    except Exception as e:
        return {"solved": False, "error": f"capsolver: {e}"}

# ─── Request model ──────────────────────────────────────────────────────────
class SolveRequest(BaseModel):
    type: str
    url: str = ""
    sitekey: Optional[str] = None
    action: Optional[str] = None
    cdata: Optional[str] = None
    version: Optional[str] = "v2"
    enterprise: bool = False
    image: Optional[str] = None
    bg_image: Optional[str] = None
    puzzle_image: Optional[str] = None
    text: Optional[str] = None
    public_key: Optional[str] = None
    gt: Optional[str] = None
    challenge: Optional[str] = None
    captcha_id: Optional[str] = None
    timeout_s: int = 90
    proxy: Optional[str] = None
    user_agent: Optional[str] = None
    real_page: bool = False  # hCaptcha: open live URL instead of stub inject
    force_capsolver: bool = False  # skip local browser for this request
    # aliyun raw mode: skip _verify_in_page, return unconsumed token for backend verify
    raw: bool = False
    # botguard (Google OAuth bgRequest token) — page-level, no sitekey
    email: Optional[str] = None
    password: Optional[str] = None
    # datadome: framing Referer so DataDome scores the same config as the real
    # flow (e.g. https://github.com/ when harvesting via octocaptcha).
    referer: Optional[str] = None
    # aliyun (slide-puzzle): challenge identity is scene_id + prefix (no sitekey).
    scene_id: Optional[str] = None
    prefix: Optional[str] = None
    region: Optional[str] = "sgp"
    # fingerprint: dict generated by fingerprint.py — applied to the browser for
    # token binding, returned in the response so the caller replays the same
    # headers on the target API request.
    fingerprint: Optional[dict] = None
    # perimeterx: named render trigger when the gate doesn't show on plain load
    render_flow: Optional[str] = None
    # arkose: game type (public_key already declared above)
    game_type: Optional[str] = "4"
    # page-level solvers (akamai): pre/post actions
    pre_actions: Optional[list] = None
    post_fetch: Optional[list] = None

# ─── Camoufox engine (page-pool) ─────────────────────────────────────────────
class CamoufoxEngine:
    HTML = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js?onload=onloadTurnstileCallback" async defer></script>
</head><body><!-- cf turnstile --><p id="ip-display"></p></body></html>"""

    def __init__(self, headless, threads, pages, proxy_support, proxy_file, cleanup_min, engine_kind=None):
        self.headless = headless
        self.threads = threads
        self.pages = pages
        self.proxy_support = proxy_support
        self.proxy_file = proxy_file
        self.cleanup_min = cleanup_min
        # which browser backend this pool uses: "camoufox" | "cloak"
        self.engine_kind = (engine_kind or SOLVER_ENGINE).lower()
        self.page_pool = asyncio.Queue()
        self.browser_args = ["--no-sandbox", "--disable-setuid-sandbox"]
        self.camoufox = None
        self.browser = None
        self.results = {}
        self.contexts = []
        self.proxies = []
        self._pidx = 0
        self.max_task = threads * pages
        self.ready = False

    def _load_proxies(self):
        if not self.proxy_support or not os.path.isfile(self.proxy_file):
            return
        with open(self.proxy_file) as f:
            self.proxies = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
        logger.info(f"Loaded {len(self.proxies)} proxies")

    def _next_proxy(self):
        if not self.proxies:
            return None
        p = self.proxies[self._pidx % len(self.proxies)]
        self._pidx += 1
        return p

    async def _ctx(self, proxy=None):
        if not proxy:
            return await self.browser.new_context()
        pr = urlparse(proxy)
        if not pr.scheme or not pr.hostname:
            return await self.browser.new_context()
        server = f"{pr.scheme}://{pr.hostname}:{pr.port}"
        if pr.username and pr.password:
            return await self.browser.new_context(proxy={"server": server, "username": pr.username, "password": pr.password})
        return await self.browser.new_context(proxy={"server": server})

    async def _launch_browser(self):
        """Launch the underlying Playwright browser per this pool's engine_kind.

        camoufox → AsyncCamoufox (Firefox anti-detect). Stored in self.camoufox
                   so it can be re-.start()'d on rebuild.
        cloak    → CloakBrowser (stealth Chromium). launch_async() returns a
                   Playwright Browser directly; no persistent manager object.
        Both return a Playwright Browser, so all downstream new_context /
        new_page / close calls are identical.
        """
        if self.engine_kind == "cloak":
            import cloakbrowser as cb
            kwargs = dict(headless=self.headless, humanize=SOLVER_HUMANIZE,
                          args=self.browser_args)
            if CLOAK_LICENSE_KEY:
                kwargs["license_key"] = CLOAK_LICENSE_KEY
            self.camoufox = None
            return await cb.launch_async(**kwargs)
        # default: camoufox
        from camoufox import DefaultAddons
        from camoufox.async_api import AsyncCamoufox
        self.camoufox = AsyncCamoufox(headless=self.headless,
                                      exclude_addons=[DefaultAddons.UBO],
                                      args=self.browser_args)
        return await self.camoufox.start()

    async def start(self):
        self._load_proxies()
        self.browser = await self._launch_browser()
        await self._build_pool()
        self.ready = True
        logger.success(f"{self.engine_kind} pool ready: {self.page_pool.qsize()} pages")
        asyncio.create_task(self._cleanup_expired())
        asyncio.create_task(self._periodic_restart(self.cleanup_min))

    async def stop(self):
        try:
            await self.browser.close()
        except Exception:
            pass

    async def _build_pool(self):
        self.contexts = []
        self._pidx = 0
        for _ in range(self.threads):
            proxy = self._next_proxy() if self.proxy_support else None
            ctx = await self._ctx(proxy)
            self.contexts.append(ctx)
            for _ in range(self.pages):
                page = await ctx.new_page()
                await self.page_pool.put((page, ctx))

    async def _cleanup_expired(self):
        while True:
            await asyncio.sleep(300)
            now = time.time()
            for tid in list(self.results.keys()):
                res = self.results.get(tid)
                if not isinstance(res, dict):
                    continue
                age = now - res.get("start_time", now)
                if res.get("status") == "process" and age > 300:
                    self.results[tid] = {"status": "error", "value": "timeout",
                                         "message": "task timeout 300s", "start_time": res.get("start_time", now)}
                elif res.get("status") != "process" and age > 600:
                    self.results.pop(tid, None)

    async def _periodic_restart(self, minutes):
        while True:
            await asyncio.sleep(minutes * 60)
            collected = []
            try:
                while True:
                    collected.append(self.page_pool.get_nowait())
            except asyncio.QueueEmpty:
                pass
            deadline = time.time() + 60
            while len(collected) < self.max_task and time.time() < deadline:
                try:
                    collected.append(await asyncio.wait_for(self.page_pool.get(), timeout=max(0.1, deadline - time.time())))
                except asyncio.TimeoutError:
                    break
            old = list(self.contexts)
            self.contexts = []
            for page, _ in collected:
                try: await page.close()
                except Exception: pass
            for ctx in old:
                try: await ctx.close()
                except Exception: pass
            try:
                while True:
                    sp, _ = self.page_pool.get_nowait()
                    try: await sp.close()
                    except Exception: pass
            except asyncio.QueueEmpty:
                pass
            try:
                await self._build_pool()
                logger.success(f"Pool restarted: {self.page_pool.qsize()} pages")
            except Exception as e:
                logger.error(f"Rebuild failed: {e}, restarting browser")
                try:
                    await self.browser.close()
                except Exception:
                    pass
                self.browser = await self._launch_browser()
                await self._build_pool()

    async def _ctx_fingerprint(self, fingerprint, proxy=None):
        """Dedicated context with a full fingerprint applied at context level.

        new_context(user_agent=..., locale=..., timezone_id=..., viewport=...)
        patches navigator.userAgent etc. to match — unlike page-level
        extra_http_headers, which leaves JS UA ≠ HTTP UA and fails Turnstile.
        """
        from fingerprint import headers_from_fingerprint
        kw = {"user_agent": fingerprint["user_agent"],
              "locale": fingerprint.get("locale", "en-US"),
              "timezone_id": fingerprint.get("timezone"),
              "viewport": fingerprint.get("viewport"),
              "color_scheme": fingerprint.get("color_scheme"),
              "extra_http_headers": headers_from_fingerprint(fingerprint)}
        if proxy:
            pr = urlparse(proxy)
            if pr.scheme and pr.hostname:
                server = f"{pr.scheme}://{pr.hostname}:{pr.port}"
                if pr.username and pr.password:
                    kw["proxy"] = {"server": server, "username": pr.username, "password": pr.password}
                else:
                    kw["proxy"] = {"server": server}
        return await self.browser.new_context(**kw)

    # ── Turnstile (in-session, most reliable) ──
    async def solve_turnstile(self, task_id, url, sitekey, action=None, cdata=None,
                              fingerprint=None):
        t0 = time.time()
        own = False
        if fingerprint:
            # dedicated fingerprint context (never shared/pooled — token binds to
            # this exact UA/fingerprint and the caller replays it on the API call)
            try:
                ctx = await self._ctx_fingerprint(fingerprint)
                page = await ctx.new_page()
                own = True
            except Exception as e:
                self.results[task_id] = {"status": "error", "value": "fingerprint_ctx_fail",
                                         "message": str(e), "elapsed_time": round(time.time() - t0, 3)}
                return
        else:
            page, ctx = await self.page_pool.get()
        try:
            # Warm cookies for a fresh fingerprint context: visit the real site
            # first (Cloudflare drops a session; turnstile in a cold context
            # serves interactive challenges that the checkbox flow can't pass).
            if own:
                try:
                    await page.goto(url, wait_until="domcontentloaded", timeout=15000)
                    await page.wait_for_timeout(2500)
                except Exception:
                    pass
            url_slash = url if url.endswith("/") else url + "/"
            div = (f'<div class="cf-turnstile" style="background:white;" data-sitekey="{sitekey}"'
                   + (f' data-action="{action}"' if action else "")
                   + (f' data-cdata="{cdata}"' if cdata else "") + "></div>")
            page_data = self.HTML.replace("<!-- cf turnstile -->", div)
            for rnd in range(1, 3):
                if rnd > 1 and self.proxy_support and self.proxies:
                    proxy = self._next_proxy()
                    try:
                        nc = await self._ctx(proxy)
                        np_ = await nc.new_page()
                        try: await page.close()
                        except Exception: pass
                        try: await ctx.close()
                        except Exception: pass
                        page, ctx = np_, nc
                    except Exception:
                        pass
                try: await page.unroute_all()
                except Exception: pass
                await page.route(url_slash, lambda route: route.fulfill(body=page_data, status=200))
                await page.goto(url_slash)
                try:
                    await page.eval_on_selector("//div[@class='cf-turnstile']", "el => el.style.width = '70px'")
                except Exception:
                    pass
                for _ in range(80):
                    try:
                        val = await page.input_value("[name=cf-turnstile-response]", timeout=400)
                        if val == "":
                            await page.locator("//div[@class='cf-turnstile']").click(timeout=400)
                            await asyncio.sleep(0.3)
                        else:
                            ua = await page.evaluate("navigator.userAgent")
                            self.results[task_id] = {"status": "success", "elapsed_time": round(time.time() - t0, 3), "value": val, "user_agent": ua, "fingerprint": fingerprint}
                            return
                    except Exception:
                        pass
            self.results[task_id] = {"status": "error", "value": "captcha_fail", "elapsed_time": round(time.time() - t0, 3)}
        except Exception as e:
            self.results[task_id] = {"status": "error", "value": "captcha_fail", "message": str(e), "elapsed_time": round(time.time() - t0, 3)}
        finally:
            try: await page.unroute_all()
            except Exception: pass
            if own:
                try: await ctx.close()
                except Exception: pass
            elif ctx in self.contexts:
                await self.page_pool.put((page, ctx))

    # ── cf_clearance ──
    async def solve_clearance(self, task_id, url, timeout=30):
        t0 = time.time()
        page, ctx = await self.page_pool.get()
        try:
            ua = await page.evaluate("navigator.userAgent")
            await page.goto(url, wait_until="domcontentloaded", timeout=timeout * 1000)
            deadline = time.time() + timeout
            cf = None
            while time.time() < deadline:
                title = await page.title()
                cookie = next((c for c in await ctx.cookies() if c["name"] == "cf_clearance"), None)
                if cookie and "just a moment" not in title.lower():
                    cf = cookie["value"]
                    break
                await asyncio.sleep(1)
            if cf:
                cookies = await ctx.cookies()
                self.results[task_id] = {"status": "success", "elapsed_time": round(time.time() - t0, 3),
                    "cf_clearance": cf, "user_agent": ua,
                    "cookies": "; ".join(f"{c['name']}={c['value']}" for c in cookies)}
            else:
                self.results[task_id] = {"status": "error", "value": "clearance_fail", "elapsed_time": round(time.time() - t0, 3)}
        except Exception as e:
            self.results[task_id] = {"status": "error", "value": str(e), "elapsed_time": round(time.time() - t0, 3)}
        finally:
            try: await ctx.clear_cookies()
            except Exception: pass
            try: await page.goto("about:blank")
            except Exception: pass
            if ctx in self.contexts:
                await self.page_pool.put((page, ctx))

    # ── aws-waf-token ──
    async def solve_aws(self, task_id, url, timeout=30):
        t0 = time.time()
        page, ctx = await self.page_pool.get()
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=timeout * 1000)
            deadline = time.time() + timeout
            waf = None
            while time.time() < deadline:
                waf = next((c for c in await ctx.cookies() if c["name"] == "aws-waf-token"), None)
                if waf:
                    break
                await asyncio.sleep(1)
            if waf:
                ua = await page.evaluate("navigator.userAgent")
                cookies = await ctx.cookies()
                self.results[task_id] = {"status": "success", "elapsed_time": round(time.time() - t0, 3),
                    "aws_waf_token": waf["value"], "user_agent": ua,
                    "cookies": "; ".join(f"{c['name']}={c['value']}" for c in cookies)}
            else:
                self.results[task_id] = {"status": "error", "value": "waf_fail", "elapsed_time": round(time.time() - t0, 3)}
        except Exception as e:
            self.results[task_id] = {"status": "error", "value": str(e), "elapsed_time": round(time.time() - t0, 3)}
        finally:
            try: await ctx.clear_cookies()
            except Exception: pass
            try: await page.goto("about:blank")
            except Exception: pass
            if ctx in self.contexts:
                await self.page_pool.put((page, ctx))

    # ── BotGuard (Google OAuth bgRequest token) — page-level, no sitekey ──
    async def solve_botguard(self, task_id, url, email=None, password=None, timeout=90):
        """Extract a Google BotGuard (bgRequest) token via a real Camoufox session.

        BotGuard tokens can't be generated offline (polymorphic per-session VM,
        runtime+iframe-realm bound). We drive the Google sign-in flow, intercept
        the account-lookup (MI613e) or password-submit (B4hajb) batchexecute RPC
        that carries the token, ABORT it so the token stays unused, and return
        token + session cookies + UA so the caller can replay once over HTTP.

        Adapted from waguriagentic/captcha-solver botguard/solve.py — same
        route-intercept protocol, ported from CloakBrowser to our Camoufox pool.
        """
        import urllib.parse as _uparse
        t0 = time.time()
        page, ctx = await self.page_pool.get()
        SIGNIN = ("https://accounts.google.com/signin/v2/identifier"
                  "?flowName=GlifWebSignIn")
        TOKEN_RPCS = ("MI613e", "B4hajb")
        # password given → wait for the hard-gate B4hajb; email-only → either
        wanted = ("B4hajb",) if (email and password) else TOKEN_RPCS
        BG_BLOB = re.compile(r"[A-Za-z0-9_\-]{200,}")
        grab = {"body": None, "url": None, "headers": None, "rpc": None}
        try:
            target = (url or SIGNIN).strip()

            async def route_handler(route):
                req = route.request
                try:
                    if (req.method == "POST" and "batchexecute" in req.url
                            and any(r in req.url for r in wanted)
                            and grab["body"] is None):
                        grab["body"] = req.post_data
                        grab["url"] = req.url
                        try:
                            grab["headers"] = await req.all_headers()
                        except Exception:
                            grab["headers"] = {}
                        grab["rpc"] = next((r for r in TOKEN_RPCS if r in req.url), None)
                        await route.abort()
                        return
                except Exception:
                    pass
                await route.continue_()

            await page.route("**/batchexecute*", route_handler)
            try:
                await page.goto(target, wait_until="networkidle", timeout=45000)
            except Exception as e:
                log.warning(f"botguard nav: {e}")
            await asyncio.sleep(2)

            # step 1: email
            if email:
                for sel in ('input#identifierId', 'input[type="email"]',
                            'input[name="identifier"]'):
                    try:
                        await page.fill(sel, email, timeout=6000)
                        break
                    except Exception:
                        continue
                for sel in ('#identifierNext', 'button:has-text("Next")',
                            'button:has-text("Berikutnya")'):
                    try:
                        await page.click(sel, timeout=6000)
                        break
                    except Exception:
                        continue
                await asyncio.sleep(6)

            # step 2 (optional): password → drives to B4hajb hard-gate token
            if email and password:
                filled = False
                for sel in ('input[type="password"]', 'input[name="Passwd"]'):
                    try:
                        await page.fill(sel, password, timeout=8000)
                        filled = True
                        break
                    except Exception:
                        continue
                if filled:
                    for sel in ('#passwordNext', 'button:has-text("Next")',
                                'button:has-text("Berikutnya")'):
                        try:
                            await page.click(sel, timeout=6000)
                            break
                        except Exception:
                            continue
                    await asyncio.sleep(5)

            cookies = await ctx.cookies()
            try:
                ua = await page.evaluate("() => navigator.userAgent")
            except Exception:
                ua = None

            if not grab["body"]:
                self.results[task_id] = {
                    "status": "error", "value": "botguard_no_token",
                    "message": ("no token-bearing RPC intercepted "
                                "(email required; SSO redirect or flow changed?)"),
                    "elapsed_time": round(time.time() - t0, 3)}
                return

            dec = _uparse.unquote_plus(grab["body"])
            blobs = BG_BLOB.findall(dec)
            token = max(blobs, key=len) if blobs else ""
            cookie_header = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
            self.results[task_id] = {
                "status": "success",
                "value": token,
                "token_len": len(token),
                "rpc": grab["rpc"],
                "gate": "password" if grab["rpc"] == "B4hajb" else "account-lookup",
                "user_agent": ua,
                "cookies": cookie_header,
                "replay_url": grab["url"],
                "replay_body": grab["body"],
                "replay_headers": {
                    k: v for k, v in (grab["headers"] or {}).items()
                    if k.lower() not in ("content-length", "host", "cookie")},
                "elapsed_time": round(time.time() - t0, 3)}
        except Exception as e:
            self.results[task_id] = {"status": "error", "value": str(e),
                                     "elapsed_time": round(time.time() - t0, 3)}
        finally:
            try:
                await page.unroute_all()
            except Exception:
                pass
            try:
                await ctx.clear_cookies()
            except Exception:
                pass
            try:
                await page.goto("about:blank")
            except Exception:
                pass
            if ctx in self.contexts:
                await self.page_pool.put((page, ctx))

    # ── DataDome clearance cookie ──
    # Harvest a `datadome=...` clearance token by letting tags.js run in a real
    # Camoufox page (it builds the byte-accurate jspl payload for free) and
    # intercepting the api-js.datadome.co/js/ POST response to parse the cookie.
    # Cookie is IP+UA bound — caller must replay from the same proxy IP + UA.
    # Ported from waguri-solver datadome/solve.py (same route-intercept protocol
    # as botguard above). Site-agnostic: caller passes the DataDome-fronted url
    # (e.g. https://octocaptcha.com/datadome?origin_page=github_signup_redesign)
    # + referer (https://github.com/) so DataDome serves the same config/scoring.
    async def solve_datadome(self, task_id, url, referer=None, timeout=60):
        import json as _json
        import re as _re
        t0 = time.time()
        page, ctx = await self.page_pool.get()
        captured = {"cookie": None, "endpoint_status": None, "raw_json": None}
        try:
            async def on_response(resp):
                if "api-js.datadome.co/js/" in (resp.url or "") and resp.request.method == "POST":
                    try:
                        body = await resp.text()
                        captured["raw_json"] = body[:500]
                        try:
                            data = _json.loads(body)
                            ck = data.get("cookie", "") or ""
                            m = _re.search(r"datadome=([^;]+)", ck)
                            captured["endpoint_status"] = data.get("status")
                            if m:
                                captured["cookie"] = m.group(1)
                                captured["cookie_domain"] = (
                                    _re.search(r"Domain=([^;]+)", ck).group(1)
                                    if _re.search(r"Domain=([^;]+)", ck) else None)
                                captured["cookie_max_age"] = (
                                    int(_re.search(r"Max-Age=([0-9]+)", ck).group(1))
                                    if _re.search(r"Max-Age=([0-9]+)", ck) else None)
                        except Exception:
                            pass
                    except Exception as e:
                        captured["resp_err"] = str(e)

            page.on("response", lambda r: asyncio.create_task(on_response(r)))
            if referer:  # match framing Referer so DataDome scores the same config
                try:
                    await page.set_extra_http_headers({"Referer": referer})
                except Exception:
                    pass

            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=45000)
            except Exception as e:
                log.warning(f"datadome goto: {e}")

            deadline = time.time() + max(5, int(timeout or 60))
            while time.time() < deadline and not captured["cookie"]:
                await asyncio.sleep(1)

            try:
                ua = await page.evaluate("() => navigator.userAgent")
            except Exception:
                ua = None

            if captured["cookie"]:
                self.results[task_id] = {
                    "status": "success",
                    "value": captured["cookie"],
                    "datadome_cookie": captured["cookie"],
                    "cookie_domain": captured.get("cookie_domain") or ".github.com",
                    "cookie_max_age": captured.get("cookie_max_age"),
                    "endpoint_status": captured["endpoint_status"],
                    "user_agent": ua,
                    "method": "datadome-silent-pass",
                    "elapsed_time": round(time.time() - t0, 3)}
            else:
                self.results[task_id] = {
                    "status": "error", "value": "datadome_fail",
                    "endpoint_status": captured["endpoint_status"],
                    "raw_json": captured["raw_json"],
                    "message": ("no datadome cookie (endpoint_status="
                                f"{captured['endpoint_status']}); DataDome may have "
                                "returned a challenge — check raw_json"),
                    "elapsed_time": round(time.time() - t0, 3)}
        except Exception as e:
            self.results[task_id] = {"status": "error", "value": str(e),
                                     "elapsed_time": round(time.time() - t0, 3)}
        finally:
            try:
                await page.unroute_all()
            except Exception:
                pass
            try:
                await ctx.clear_cookies()
            except Exception:
                pass
            try:
                await page.goto("about:blank")
            except Exception:
                pass
            if ctx in self.contexts:
                await self.page_pool.put((page, ctx))

    # ── reCAPTCHA v3 (real page, grecaptcha.execute) ──
    async def solve_recaptcha_v3(self, task_id, url, sitekey, action="submit"):
        t0 = time.time()
        page, ctx = await self.page_pool.get()
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=30000)
            try:
                await page.wait_for_function(
                    "() => typeof grecaptcha!=='undefined' && typeof grecaptcha.execute==='function'", timeout=15000)
            except Exception:
                await page.evaluate("""(key)=>new Promise((res,rej)=>{const s=document.createElement('script');
                    s.src='https://www.google.com/recaptcha/api.js?render='+key;
                    s.onload=()=>{const i=setInterval(()=>{if(typeof grecaptcha!=='undefined'&&grecaptcha.execute){clearInterval(i);res(1)}},100);
                    setTimeout(()=>{clearInterval(i);rej(0)},10000)};s.onerror=()=>rej(0);document.head.appendChild(s)})""", sitekey)
            token = await page.evaluate("""([key,act])=>new Promise((res,rej)=>{grecaptcha.ready(()=>{
                grecaptcha.execute(key,{action:act}).then(res).catch(rej)})})""", [sitekey, action])
            self.results[task_id] = {"status": "success", "elapsed_time": round(time.time() - t0, 3), "value": token}
        except Exception as e:
            self.results[task_id] = {"status": "error", "value": "captcha_fail", "message": str(e), "elapsed_time": round(time.time() - t0, 3)}
        finally:
            try: await page.goto("about:blank")
            except Exception: pass
            if ctx in self.contexts:
                await self.page_pool.put((page, ctx))

    # ── reCAPTCHA v2 (stub page, checkbox click) ──
    async def solve_recaptcha_v2(self, task_id, url, sitekey):
        t0 = time.time()
        page, ctx = await self.page_pool.get()
        try:
            html = f"""<html><head><script src="https://www.google.com/recaptcha/api.js" async defer></script></head>
<body><div class="g-recaptcha" data-sitekey="{sitekey}"></div></body></html>"""
            target = (url if url.endswith("/") else url + "/") if url else "https://local.test/"
            try: await page.unroute_all()
            except Exception: pass
            await page.route(target, lambda route: route.fulfill(body=html, status=200))
            await page.goto(target)
            token = ""
            try:
                frame = page.frame_locator("iframe[title*='recaptcha']")
                await frame.locator(".recaptcha-checkbox-border").click(timeout=6000)
                await asyncio.sleep(3)
            except Exception:
                pass
            token = await page.evaluate("document.getElementById('g-recaptcha-response')?.value || ''")
            if token:
                self.results[task_id] = {"status": "success", "elapsed_time": round(time.time() - t0, 3), "value": token}
            else:
                self.results[task_id] = {"status": "error", "value": "captcha_fail", "elapsed_time": round(time.time() - t0, 3)}
        except Exception as e:
            self.results[task_id] = {"status": "error", "value": "captcha_fail", "message": str(e), "elapsed_time": round(time.time() - t0, 3)}
        finally:
            try: await page.unroute_all()
            except Exception: pass
            try: await page.goto("about:blank")
            except Exception: pass
            if ctx in self.contexts:
                await self.page_pool.put((page, ctx))

    # ── hCaptcha (native Camoufox — checkbox / real-page widget) ──
    async def solve_hcaptcha(self, task_id, url, sitekey, timeout=120, real_page=False):
        """Solve hCaptcha locally via Camoufox.

        Strategy:
          A) real_page=True  → open live URL, find existing hCaptcha, click checkbox
          B) default         → inject stub page with sitekey on origin URL (route fulfill)
          C) fallback        → hcaptcha.render() API on blank page at target origin

        Works well on easy checkbox challenges with clean residential IP.
        Image-grid challenges usually fail without paid vision solver.
        """
        t0 = time.time()
        page, ctx = await self.page_pool.get()
        token = ""
        err = ""
        try:
            if not sitekey:
                raise ValueError("hcaptcha needs sitekey")
            base = (url or "https://accounts.hcaptcha.com").strip()
            if not base.startswith("http"):
                base = "https://" + base
            # keep origin for domain binding of the token
            parsed = urlparse(base)
            origin = f"{parsed.scheme}://{parsed.netloc}"
            target = base if base.endswith("/") else base + "/"

            async def _read_token():
                """Pull response token from textarea / data-hcaptcha-response / callback."""
                js = """() => {
                    const areas = [
                      ...document.querySelectorAll('textarea[name="h-captcha-response"]'),
                      ...document.querySelectorAll('textarea[name="g-recaptcha-response"]'),
                      ...document.querySelectorAll('[data-hcaptcha-response]'),
                      ...document.querySelectorAll('iframe[data-hcaptcha-response]'),
                    ];
                    for (const el of areas) {
                      const v = el.value || el.getAttribute('data-hcaptcha-response') || '';
                      if (v && v.length > 20) return v;
                    }
                    // widget container attribute
                    const w = document.querySelector('[data-hcaptcha-widget-id]');
                    if (w) {
                      const v = w.getAttribute('data-hcaptcha-response') || '';
                      if (v && v.length > 20) return v;
                    }
                    if (window.__hcaptcha_token && window.__hcaptcha_token.length > 20)
                      return window.__hcaptcha_token;
                    return '';
                }"""
                try:
                    return await page.evaluate(js) or ""
                except Exception:
                    return ""

            async def _click_checkbox():
                """Click hCaptcha checkbox inside iframe (several selectors)."""
                selectors = [
                    "iframe[src*='hcaptcha.com'][src*='frame=checkbox']",
                    "iframe[src*='newassets.hcaptcha.com']",
                    "iframe[title*='checkbox' i]",
                    "iframe[data-hcaptcha-widget-id]",
                    "iframe[src*='hcaptcha.com']",
                ]
                for sel in selectors:
                    try:
                        n = await page.locator(sel).count()
                        if n == 0:
                            continue
                        frame = page.frame_locator(sel).first
                        for inner in (
                            "#checkbox",
                            "div#checkbox",
                            ".check",
                            "[role='checkbox']",
                            "#anchor-state",
                            "body",
                        ):
                            try:
                                box = frame.locator(inner).first
                                await box.wait_for(state="visible", timeout=2500)
                                await box.click(timeout=2500, force=True)
                                logger.info(f"hcaptcha clicked {sel} → {inner}")
                                return True
                            except Exception:
                                continue
                        try:
                            await page.locator(sel).first.click(timeout=2000, force=True)
                            logger.info(f"hcaptcha clicked iframe box {sel}")
                            return True
                        except Exception:
                            pass
                    except Exception:
                        continue
                return False

            async def _solve_image_challenge():
                """Solve hCaptcha image grid via Mistral vision (numbered grid overlay)."""
                last_scattered_hash = ""
                try:
                    from mistral_vision import KeyPool
                    from hcaptcha_image_solve import (
                        _find_challenge_frame, _challenge_meta, _get_canvas_b64,
                        _grid_overlay, _pick_cells, _click_tiles, _click_submit,
                        _solve_drag, _GRID, is_hard_challenge, _is_scattered,
                        _pick_scattered_point, _click_point, _get_best_canvas,
                        _canvas_is_scattered,
                    )
                    keyfile = os.path.join(os.path.dirname(__file__), "apikey.txt")
                    # Vision backend: gemini (default) | mistral. Gemini is far
                    # stronger on hCaptcha odd-one-out / reasoning challenges and
                    # much faster (flash-lite ~1s/call vs mistral 5-10s).
                    backend = os.getenv("HCAPTCHA_VISION", "gemini")
                    if backend == "mistral":
                        from mistral_vision import KeyPool
                        model = os.getenv("HCAPTCHA_MISTRAL_MODEL", "mistral-large-latest")
                        keypool = KeyPool(keyfile, model=model)
                    else:
                        from gemini_vision import KeyPool
                        keypool = KeyPool(keyfile)
                    if not getattr(keypool, "keys", None):
                        logger.warning("hcaptcha vision: no keys, skipping image solve")
                        return False
                    logger.info(f"hcaptcha vision: backend={backend} keys={len(keypool.keys)} "
                                f"models={getattr(keypool, 'models', keypool.model)}")

                    for round_no in range(6):
                        fr = _find_challenge_frame(page)
                        if not fr:
                            logger.info("hcaptcha vision: no challenge frame")
                            break

                        # wait for canvas to render (up to 8s)
                        canvas_found = False
                        for _wait in range(16):
                            meta = await _challenge_meta(fr)
                            if meta.get("canvasRect"):
                                canvas_found = True
                                break
                            await asyncio.sleep(0.5)
                        if not canvas_found:
                            logger.info("hcaptcha vision: no canvas after wait")
                            break

                        if meta.get("isDrag"):
                            solved = await _solve_drag(fr, page, keypool)
                            if not solved:
                                await _click_submit(fr)
                            await asyncio.sleep(2)
                            tok = await _read_token()
                            if tok:
                                return tok
                            continue

                        target = meta.get("target", "")
                        if not target:
                            logger.info("hcaptcha vision: no target text")
                            break

                        # Skip hard challenges (odd-one-out, rotation, abstract
                        # reasoning) — vision models reliably fail these.
                        if is_hard_challenge(target):
                            logger.info(f"hcaptcha vision: hard challenge skip ({target!r})")
                            await _click_submit(fr)
                            await asyncio.sleep(2)
                            continue

                        # Scattered odd-one-out layout → click the shape's center
                        # coordinates, not a 4x4 grid cell. Detect via target
                        # wording AND canvas aspect ratio (scattered canvases are
                        # rectangular 1000x940; grids are square).
                        cr = meta.get("canvasRect") or {}
                        cw, ch = cr.get("w", 0), cr.get("h", 0)
                        try:
                            canvas_scattered = _canvas_is_scattered(cw, ch)
                        except Exception:
                            canvas_scattered = False
                        if _is_scattered(target) or canvas_scattered:
                            logger.info(f"hcaptcha vision: scattered layout ({target!r} "
                                        f"canvas {cw}x{ch})")
                            # Canvas-hash guard: if this canvas matches the
                            # previous round, we ALREADY clicked it — clicking
                            # the same shape again toggles DESELECT in
                            # hCaptcha, so just try to verify/advance.
                            b64g, _ci = await _get_best_canvas(fr)
                            chash = (hashlib.md5(b64g.encode()).hexdigest()[:12]
                                     if b64g else "")
                            if chash and chash == last_scattered_hash:
                                logger.info(f"hcaptcha vision: same canvas {chash} — no re-click, verify/advance")
                                await _click_submit(fr, wait_for_btn=4, mode="verify")
                                await asyncio.sleep(2)
                                tok = await _read_token()
                                if tok:
                                    return tok
                                continue
                            last_scattered_hash = chash
                            # ONE pick (it already votes across 2-3 models
                            # internally — flash-lite/flash + 3.1-pro confirm),
                            # then ONE click. Clicking the same shape twice
                            # toggles DESELECT in hCaptcha, which is why the
                            # old click-per-round loop always failed.
                            pts, cidx = await _pick_scattered_point(fr, keypool, target)
                            if not pts:
                                logger.warning("hcaptcha vision: scattered no picks — submit/skip")
                                await _click_submit(fr, wait_for_btn=3)
                                await asyncio.sleep(2)
                                continue
                            best = pts[0]
                            logger.info(f"hcaptcha vision scattered point: {best} (canvas idx {cidx})")
                            await _click_point(page, fr, best, cidx)
                            await asyncio.sleep(1.5)
                            try:
                                await page.screenshot(path="/tmp/hc_after_click.png")
                            except Exception:
                                pass
                            # scattered challenges show the verify button only
                            # after a shape is selected — poll up to 6s for it
                            await _click_submit(fr, wait_for_btn=6, mode="verify")
                            # JS fallback: force-click .button-submit if Playwright
                            # click landed but didn't trigger the iframe handler
                            try:
                                await fr.evaluate(
                                    "() => { const b = document.querySelector('.button-submit');"
                                    " if (b) b.click(); }"
                                )
                            except Exception:
                                pass
                            # Poll for canvas change (new challenge page)
                            for _wait in range(8):
                                await asyncio.sleep(1)
                                try:
                                    new_b64, _ = await _get_best_canvas(fr)
                                    new_hash = hashlib.md5(new_b64.encode()).hexdigest()[:12] if new_b64 else ""
                                    if new_hash and new_hash != chash:
                                        logger.info(f"hcaptcha vision: canvas advanced → {new_hash}")
                                        break
                                except Exception:
                                    pass
                            tok = await _read_token()
                            if tok:
                                return tok
                            continue

                        # Collect 3 vision picks on the SAME canvas (no clicks in
                        # between = stable image). Each _pick_cells already votes
                        # across 3 prompt strategies internally.
                        round_picks: list[set[int]] = []
                        for _v in range(3):
                            picks = await _pick_cells(fr, keypool, target)
                            logger.info(f"hcaptcha vision round {round_no+1} pick {_v+1}: {picks}")
                            if picks:
                                round_picks.append(set(picks))
                            await asyncio.sleep(0.3)

                        if not round_picks:
                            logger.warning("hcaptcha vision: no picks — clicking skip")
                            await _click_submit(fr)
                            await asyncio.sleep(2)
                            continue

                        # Majority vote: cells agreed by >=2 of 3 picks.
                        from collections import Counter
                        cnt = Counter(c for s in round_picks for c in s)
                        majority = [c for c, n in cnt.most_common() if n >= 2]
                        if majority:
                            logger.info(f"hcaptcha vision voted: {majority} "
                                        f"(from {[sorted(s) for s in round_picks]})")
                            await _click_tiles(page, fr, majority)
                            await asyncio.sleep(1)
                            await _click_submit(fr)
                            await asyncio.sleep(2)
                            tok = await _read_token()
                            if tok:
                                return tok
                        else:
                            # No consensus — click the most frequent cells anyway
                            # (better than skipping; hCaptcha grants a retry on
                            # wrong clicks, skip just wastes the round).
                            fallback = [c for c, n in cnt.most_common() if n >= 1][:4]
                            logger.warning(f"hcaptcha vision no consensus "
                                           f"{[sorted(s) for s in round_picks]} — "
                                           f"clicking fallback {fallback}")
                            if fallback:
                                await _click_tiles(page, fr, fallback)
                                await asyncio.sleep(1)
                            await _click_submit(fr)
                            await asyncio.sleep(2)
                            tok = await _read_token()
                            if tok:
                                return tok
                    return ""
                except ImportError as e:
                    logger.warning(f"hcaptcha vision import fail: {e}")
                    return ""
                except Exception as e:
                    import traceback
                    logger.warning(f"hcaptcha vision error: {e}\n{traceback.format_exc()}")
                    return ""

            async def _poll_token(seconds, early_challenge_fail=True):
                deadline = time.time() + seconds
                clicked = False
                challenge_seen_at = None
                while time.time() < deadline:
                    tok = await _read_token()
                    if tok:
                        return tok
                    # challenge iframe present → try Mistral vision solve
                    try:
                        ch = await page.locator("iframe[src*='frame=challenge']").count()
                        if ch > 0:
                            if challenge_seen_at is None:
                                challenge_seen_at = time.time()
                            # give 5s for auto-pass, then try vision solve
                            if early_challenge_fail and (time.time() - challenge_seen_at) > 5:
                                logger.info("hcaptcha: image challenge detected, trying vision solve")
                                vision_tok = await _solve_image_challenge()
                                if vision_tok:
                                    return vision_tok
                                # vision failed, don't keep retrying
                                raise RuntimeError("image_challenge_vision_failed")
                    except RuntimeError:
                        raise
                    except Exception:
                        pass
                    if not clicked or (int(time.time() - t0) % 4 == 0):
                        try:
                            clicked = await _click_checkbox() or clicked
                        except Exception:
                            pass
                    await asyncio.sleep(0.45)
                return await _read_token()

            # ── A) real page ──
            if real_page:
                await page.goto(base, wait_until="domcontentloaded", timeout=45000)
                await asyncio.sleep(1.5)
                # inject callback sniffer
                await page.evaluate(
                    """() => {
                    window.__hcaptcha_token = '';
                    const wrap = (name) => {
                      try {
                        if (window.hcaptcha && window.hcaptcha.render && !window.__hc_wrapped) {
                          const orig = window.hcaptcha.render.bind(window.hcaptcha);
                          window.hcaptcha.render = function(el, opts) {
                            opts = opts || {};
                            const prev = opts.callback;
                            opts.callback = function(t) {
                              window.__hcaptcha_token = t || '';
                              if (typeof prev === 'function') prev(t);
                              if (typeof prev === 'string' && window[prev]) window[prev](t);
                            };
                            return orig(el, opts);
                          };
                          window.__hc_wrapped = true;
                        }
                      } catch(e) {}
                    };
                    wrap();
                    setInterval(wrap, 500);
                }"""
                )
                token = await _poll_token(min(timeout, 90))
            else:
                # ── B) stub inject on target origin ──
                html = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<script src="https://js.hcaptcha.com/1/api.js?render=explicit&onload=__onHcaptchaLoad" async defer></script>
<script>
window.__hcaptcha_token = '';
window.__onHcaptchaLoad = function() {{
  try {{
    hcaptcha.render('hc-box', {{
      sitekey: '{sitekey}',
      size: 'normal',
      callback: function(t) {{ window.__hcaptcha_token = t || ''; }},
      'expired-callback': function() {{ window.__hcaptcha_token = ''; }},
      'error-callback': function(e) {{ window.__hcaptcha_err = String(e||'err'); }}
    }});
  }} catch(e) {{ window.__hcaptcha_err = String(e); }}
}};
</script>
</head>
<body style="margin:40px;background:#fff">
<div id="hc-box"></div>
<textarea id="dump" name="h-captcha-response" style="width:1px;height:1px;opacity:0"></textarea>
</body></html>"""
                try:
                    await page.unroute_all()
                except Exception:
                    pass
                # fulfill exact URL + origin root so relative script loads ok
                async def _fulfill(route):
                    await route.fulfill(
                        status=200,
                        content_type="text/html; charset=utf-8",
                        body=html,
                    )

                await page.route(target, _fulfill)
                # also catch bare origin/
                root = origin.rstrip("/") + "/"
                if root != target:
                    await page.route(root, _fulfill)
                try:
                    await page.goto(target, wait_until="domcontentloaded", timeout=45000)
                except Exception as e1:
                    err = f"goto_stub:{e1}"
                    try:
                        await page.goto(root, wait_until="domcontentloaded", timeout=30000)
                    except Exception as e2:
                        raise RuntimeError(f"goto failed: {e1} / {e2}")

                # wait for hcaptcha api
                try:
                    await page.wait_for_function(
                        "() => typeof hcaptcha !== 'undefined' && typeof hcaptcha.render === 'function'",
                        timeout=20000,
                    )
                except Exception:
                    # manual script inject fallback
                    await page.evaluate(
                        """(key) => new Promise((res, rej) => {
                        if (typeof hcaptcha !== 'undefined') return res(1);
                        const s = document.createElement('script');
                        s.src = 'https://js.hcaptcha.com/1/api.js?render=explicit';
                        s.onload = () => {
                          const i = setInterval(() => {
                            if (typeof hcaptcha !== 'undefined') { clearInterval(i); res(1); }
                          }, 100);
                          setTimeout(() => { clearInterval(i); rej('hcaptcha api timeout'); }, 15000);
                        };
                        s.onerror = () => rej('script load fail');
                        document.head.appendChild(s);
                    })""",
                        sitekey,
                    )
                    await page.evaluate(
                        """(key) => {
                        window.__hcaptcha_token = '';
                        if (!document.getElementById('hc-box')) {
                          const d = document.createElement('div'); d.id='hc-box'; document.body.appendChild(d);
                        }
                        hcaptcha.render('hc-box', {
                          sitekey: key,
                          callback: (t) => { window.__hcaptcha_token = t || ''; }
                        });
                    }""",
                        sitekey,
                    )

                await asyncio.sleep(1.2)
                # debug snapshot of frames
                try:
                    frames = [f.url[:120] for f in page.frames]
                    logger.info(f"hcaptcha frames({len(frames)}): {frames[:8]}")
                    has_api = await page.evaluate("() => typeof hcaptcha !== 'undefined'")
                    hc_err = await page.evaluate("() => window.__hcaptcha_err || ''")
                    logger.info(f"hcaptcha api={has_api} err={hc_err!r}")
                except Exception as e:
                    logger.warning(f"hcaptcha debug fail: {e}")

                token = await _poll_token(min(timeout, 100))

                # ── C) if still empty, try execute/render again ──
                if not token:
                    try:
                        await page.evaluate(
                            """(key) => {
                            window.__hcaptcha_token = window.__hcaptcha_token || '';
                            try {
                              const id = hcaptcha.render('hc-box', {
                                sitekey: key,
                                callback: (t) => { window.__hcaptcha_token = t || ''; }
                              });
                              window.__hc_id = id;
                            } catch(e) {
                              try { hcaptcha.execute(window.__hc_id); } catch(e2) {}
                            }
                        }""",
                            sitekey,
                        )
                        await _click_checkbox()
                        token = await _poll_token(25)
                    except Exception as e:
                        err = f"{err}|rerender:{e}"

            if token and len(token) > 20:
                self.results[task_id] = {
                    "status": "success",
                    "elapsed_time": round(time.time() - t0, 3),
                    "value": token,
                    "note": "camoufox_hcaptcha",
                }
            else:
                # detect challenge type for better error
                challenge = False
                try:
                    challenge = (await page.locator("iframe[src*='frame=challenge']").count()) > 0
                except Exception:
                    pass
                # dump fail artifacts
                try:
                    import pathlib
                    d = pathlib.Path("/tmp/hc_fail")
                    d.mkdir(exist_ok=True)
                    ts = int(time.time())
                    await page.screenshot(path=str(d / f"{ts}.png"), full_page=True)
                    (d / f"{ts}.html").write_text(await page.content(), encoding="utf-8", errors="ignore")
                    frames = [f.url for f in page.frames]
                    (d / f"{ts}.frames.txt").write_text("\n".join(frames), encoding="utf-8")
                    logger.warning(f"hcaptcha fail dump → {d}/{ts}.* frames={len(frames)}")
                except Exception as e:
                    logger.warning(f"hcaptcha dump fail: {e}")
                msg = "image_challenge" if challenge else (err or "captcha_fail")
                self.results[task_id] = {
                    "status": "error",
                    "value": msg,
                    "message": msg,
                    "elapsed_time": round(time.time() - t0, 3),
                }
        except asyncio.CancelledError:
            # hard-cancelled by await timeout — still mark result + free page
            try:
                if task_id in self.results and self.results[task_id].get("status") == "process":
                    self.results[task_id] = {
                        "status": "error",
                        "value": "cancelled",
                        "message": "cancelled",
                        "elapsed_time": round(time.time() - t0, 3),
                    }
            except Exception:
                pass
            raise
        except Exception as e:
            self.results[task_id] = {
                "status": "error",
                "value": "captcha_fail",
                "message": str(e),
                "elapsed_time": round(time.time() - t0, 3),
            }
        finally:
            try:
                await page.unroute_all()
            except Exception:
                pass
            try:
                await page.goto("about:blank")
            except Exception:
                pass
            try:
                if ctx in self.contexts:
                    await self.page_pool.put((page, ctx))
            except Exception:
                pass


engine: Optional[CamoufoxEngine] = None
hc_engine: Optional[CamoufoxEngine] = None  # separate pool for hCaptcha when engines differ
app = FastAPI(title="Universal Captcha Solver FEB-FRMN", version="5.1")
solve_log = []


@app.on_event("startup")
async def _startup():
    global engine, hc_engine
    engine = CamoufoxEngine(HEADLESS, THREADS, PAGES_PER_THREAD, PROXY_SUPPORT,
                            PROXY_FILE, CLEANUP_MIN, engine_kind=SOLVER_ENGINE)
    await engine.start()
    # Dual-engine: if hCaptcha wants a different backend than the primary,
    # spin up a second, smaller pool dedicated to hCaptcha. Otherwise reuse
    # the primary engine for everything.
    if SOLVER_HCAPTCHA_ENGINE and SOLVER_HCAPTCHA_ENGINE != SOLVER_ENGINE:
        hc_engine = CamoufoxEngine(HEADLESS, HC_THREADS, HC_PAGES, PROXY_SUPPORT,
                                   PROXY_FILE, CLEANUP_MIN,
                                   engine_kind=SOLVER_HCAPTCHA_ENGINE)
        await hc_engine.start()
        logger.success(f"hcaptcha engine: {SOLVER_HCAPTCHA_ENGINE} "
                       f"(primary={SOLVER_ENGINE})")
    else:
        hc_engine = engine

@app.on_event("shutdown")
async def _shutdown():
    if engine:
        await engine.stop()
    if hc_engine and hc_engine is not engine:
        await hc_engine.stop()


# ─── async browser-task dispatcher (returns task_id) ──
def _engine_for(t: str) -> "CamoufoxEngine":
    """Pick which pool serves this captcha type. hCaptcha → hc_engine
    (may be cloak); everything else → primary engine (camoufox)."""
    if t.lower() == "hcaptcha" and hc_engine is not None:
        return hc_engine
    return engine


async def _spawn_browser(req: SolveRequest):
    t = req.type.lower()
    eng = _engine_for(t)
    if not eng or not eng.ready:
        raise HTTPException(503, "browser engine not ready")
    if eng.page_pool.qsize() == 0:
        raise HTTPException(429, "pool full, retry")
    tid = str(uuid.uuid4())
    eng.results[tid] = {"status": "process", "start_time": time.time()}
    if t == "turnstile":
        task = asyncio.create_task(eng.solve_turnstile(tid, req.url, req.sitekey, req.action, req.cdata,
                                                       fingerprint=req.fingerprint))
    elif t == "cloudflare":
        task = asyncio.create_task(eng.solve_clearance(tid, req.url, req.timeout_s))
    elif t == "awswaf":
        task = asyncio.create_task(eng.solve_aws(tid, req.url, req.timeout_s))
    elif t == "recaptchav3" or (t == "recaptcha" and req.version == "v3"):
        task = asyncio.create_task(eng.solve_recaptcha_v3(tid, req.url, req.sitekey, req.action or "submit"))
    elif t == "recaptcha":
        task = asyncio.create_task(eng.solve_recaptcha_v2(tid, req.url, req.sitekey))
    elif t == "hcaptcha":
        task = asyncio.create_task(
            eng.solve_hcaptcha(
                tid,
                req.url,
                req.sitekey,
                timeout=req.timeout_s or 120,
                real_page=bool(req.real_page),
            )
        )
    elif t == "botguard":
        task = asyncio.create_task(
            eng.solve_botguard(
                tid,
                req.url,
                email=req.email,
                password=req.password,
                timeout=req.timeout_s or 90,
            )
        )
    elif t == "datadome":
        task = asyncio.create_task(
            eng.solve_datadome(
                tid,
                req.url,
                referer=req.referer,
                timeout=req.timeout_s or 60,
            )
        )
    else:
        eng.results.pop(tid, None)
        return None
    eng.tasks = getattr(eng, "tasks", {})
    eng.tasks[tid] = task
    return tid


async def _await_task(tid, timeout_s, eng=None):
    eng = eng or engine
    deadline = time.time() + max(5, int(timeout_s or 60))
    while time.time() < deadline:
        res = eng.results.get(tid)
        if res and res.get("status") != "process":
            eng.results.pop(tid, None)
            try:
                getattr(eng, "tasks", {}).pop(tid, None)
            except Exception:
                pass
            return res
        await asyncio.sleep(0.4)
    # hard stop stuck browser task so page returns to pool
    task = getattr(eng, "tasks", {}).pop(tid, None)
    if task and not task.done():
        task.cancel()
        try:
            # Do NOT use shield() here — cancelled task must finish its finally
            # (return page to pool). Catch CancelledError so it never bubbles to FastAPI.
            await asyncio.wait_for(task, timeout=5)
        except (asyncio.TimeoutError, asyncio.CancelledError, Exception):
            pass
    stuck = eng.results.pop(tid, None) or {}
    if stuck.get("status") and stuck.get("status") != "process":
        return stuck
    return {"status": "error", "value": "timeout", "message": "await timeout"}


def _normalize(res, ctype):
    """Map engine result → uniform {solved, token, ...}."""
    ok = res.get("status") == "success"
    out = {"solved": ok, "type": ctype}
    # Only trust value as token on success — error paths reuse "value" for reason codes
    tok = None
    if ok:
        tok = res.get("value") or res.get("aws_waf_token") or res.get("cf_clearance")
        if isinstance(tok, str) and tok.lower() in {
            "timeout", "captcha_fail", "image_challenge", "clearance_fail", "waf_fail", ""
        }:
            tok = None
            ok = False
            out["solved"] = False
    if tok:
        out["token"] = tok
    for k in ("cf_clearance", "aws_waf_token", "user_agent", "cookies", "elapsed_time", "message", "note",
              "rpc", "gate", "token_len", "replay_url", "replay_body", "replay_headers", "fingerprint"):
        if k in res:
            out[k] = res[k]
    if not ok and "error" not in out:
        out["error"] = res.get("message") or res.get("value") or "failed"
    return out


# ─── unified dispatcher ──
async def dispatch(req: SolveRequest):
    t = req.type.lower()
    # 1) free local (no browser)
    if t == "math":
        if req.text:
            return solve_math(req.text)
        if req.image:
            return await asyncio.to_thread(solve_ocr, req.image, True)
        return {"solved": False, "error": "math needs text or image"}
    if t in ("text", "image"):
        return await asyncio.to_thread(solve_ocr, req.image, False)
    if t == "slider":
        return await asyncio.to_thread(solve_slider, req.bg_image, req.puzzle_image)
    # 1.5) CloakBrowser page-level solvers (merged from waguri-solver) — each
    #      launches its own browser, so they bypass the pool entirely.
    if t == "aliyun":
        # Subprocess runner: Aliyun's drag trajectory is fidelity-sensitive to the
        # MAIN thread + clean event loop (see aliyun/README.md: direct-call 3/3
        # T001 vs on-loop 0/12 F001). A fresh process reproduces the working path.
        import os as _os
        _to = req.timeout_s or 90
        _raw = "1" if req.raw else ""
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "aliyun._run",
            req.scene_id or "", req.prefix or "", req.region or "sgp",
            str(_to), req.proxy or "", req.referer or "", _raw,
            cwd=_os.path.dirname(_os.path.abspath(__file__)),
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        try:
            out, _err = await asyncio.wait_for(proc.communicate(), timeout=_to + 30)
        except asyncio.TimeoutError:
            proc.kill()
            return {"solved": False, "error": "aliyun subprocess deadline"}
        r = {"solved": False, "error": "aliyun: no result from runner"}
        for line in (out or b"").decode(errors="replace").splitlines():
            if line.startswith("__ALIYUN_RESULT__"):
                r = json.loads(line[len("__ALIYUN_RESULT__"):])
                break
        return r
    if t == "akamai":
        from akamai.solve import solve_akamai
        return await solve_akamai(
            url=req.url, proxy=req.proxy, timeout_s=req.timeout_s or 90,
            pre_actions=req.pre_actions, post_fetch=req.post_fetch)
    if t == "perimeterx":
        from perimeterx.solve import solve_perimeterx
        return await solve_perimeterx(
            url=req.url or None, render_flow=req.render_flow,
            proxy=req.proxy, timeout_s=req.timeout_s or 200)
    if t == "arkose":
        from arkose.solve import solve_arkose
        return await solve_arkose(
            public_key=req.public_key or "", page_url=req.url or None,
            game_type=req.game_type or "4", proxy=req.proxy,
            timeout_s=req.timeout_s or 120, pre_actions=req.pre_actions)
    # 2) demo tokens
    if req.sitekey in DEMO_TOKENS:
        return {"solved": True, "token": DEMO_TOKENS[req.sitekey], "note": "demo_key"}
    # 3) browser-solvable via Camoufox (local-first)
    # hCaptcha is local-first now (Capsolver blocks many sitekeys incl. Forge)
    browser_types = ("turnstile", "recaptcha", "recaptchav3", "cloudflare", "awswaf", "hcaptcha", "botguard", "datadome")
    # Turnstile: local stub-page tokens (~666 chars) get rejected by real sites
    # (e.g. accounts.x.ai). Prefer Capsolver when key is present unless
    # TURNSTILE_LOCAL=1 is set. force_capsolver=true on the request also skips local.
    force_cap = bool(getattr(req, "force_capsolver", False))
    prefer_cap_ts = (
        t == "turnstile"
        and bool(CAPSOLVER_API_KEY)
        and SOLVER_MODE in ("auto", "capsolver")
        and (force_cap or os.getenv("TURNSTILE_LOCAL", "0") != "1")
    )
    if prefer_cap_ts:
        cap = await asyncio.to_thread(capsolver_solve, req)
        cap.setdefault("type", req.type)
        if cap.get("solved"):
            return cap
        # if Capsolver fails, fall through to local as last resort
    if t in browser_types and SOLVER_MODE in ("auto", "local") and not force_cap:
        tid = await _spawn_browser(req)
        if tid:
            res = await _await_task(tid, req.timeout_s, _engine_for(t))
            norm = _normalize(res, req.type)
            if norm.get("solved"):
                note = res.get("note") or f"{_engine_for(t).engine_kind}_local"
                norm["note"] = note
                tok = norm.get("token") or ""
                # Short stub tokens: try Capsolver fallback instead of returning junk
                if (
                    t == "turnstile"
                    and CAPSOLVER_API_KEY
                    and SOLVER_MODE in ("auto", "capsolver")
                    and len(tok) < 700
                ):
                    pass  # fall through
                else:
                    return norm
            elif SOLVER_MODE == "local":
                # hCaptcha: allow capsolver fallback even in local mode
                if not (t == "hcaptcha" and os.getenv("HCAPTCHA_CAPSOLVER_FALLBACK", "0") == "1"):
                    return norm
            # hCaptcha: only fall through to Capsolver if explicitly wanted
            # (many sitekeys return "We don't support this service")
            elif t == "hcaptcha" and os.getenv("HCAPTCHA_CAPSOLVER_FALLBACK", "0") != "1":
                return norm
            # else fall through to capsolver
    # 4) Capsolver universal fallback (funcaptcha/geetest/datadome + failed browser types)
    if SOLVER_MODE in ("auto", "capsolver") or (
        t == "hcaptcha" and os.getenv("HCAPTCHA_CAPSOLVER_FALLBACK", "0") == "1"
    ):
        cap = await asyncio.to_thread(capsolver_solve, req)
        cap.setdefault("type", req.type)
        return cap
    return {"solved": False, "error": f"no solver available for {t}"}


# ─── API ──
@app.get("/health")
async def health():
    return {"status": "ok", "supported": SUPPORTED, "engine": SOLVER_ENGINE,
            "hcaptcha_engine": SOLVER_HCAPTCHA_ENGINE,
            "pool": engine.page_pool.qsize() if engine and engine.ready else 0,
            "hc_pool": hc_engine.page_pool.qsize() if hc_engine and hc_engine.ready else 0,
            "capsolver": bool(CAPSOLVER_API_KEY), "mode": SOLVER_MODE,
            "hcaptcha_local": True, "botguard_local": True,
            "aliyun_local": True, "akamai_local": True,
            "perimeterx_local": True, "arkose_local": True,
            "version": "5.4", "by": "FEB-FRMN", "saweria": "https://saweria.co/febfrmn"}

@app.get("/status")
async def status():
    solved = sum(1 for e in solve_log if e.get("solved"))
    return {"log_size": len(solve_log), "solved": solved, "mode": SOLVER_MODE,
            "pool": engine.page_pool.qsize() if engine and engine.ready else 0,
            "capsolver_enabled": bool(CAPSOLVER_API_KEY)}

@app.get("/logs")
async def logs(lines: int = 50):
    return {"total": len(solve_log), "entries": solve_log[-lines:]}

@app.post("/solve")
async def solve(req: SolveRequest):
    t0 = time.time()
    if req.url:
        check_ssrf(req.url)
    if req.type.lower() not in SUPPORTED:
        raise HTTPException(400, f"Unsupported type: {req.type}. Supported: {SUPPORTED}")
    logger.info(f"Solve {req.type} sitekey={str(req.sitekey)[:12] if req.sitekey else '-'} url={req.url[:50]}")
    result = await dispatch(req)
    result["type"] = req.type
    result["elapsed"] = round(time.time() - t0, 2)
    solve_log.append({"type": req.type, "solved": result.get("solved", False),
                      "note": result.get("note", ""), "elapsed": result["elapsed"]})
    if len(solve_log) > 100:
        solve_log.pop(0)
    return result

# ─── Boterdrop-compatible async endpoints (backward-compat with bai-farmer) ──
@app.get("/turnstile")
async def r_turnstile(url: str = Query(...), sitekey: str = Query(...),
                      action: str = Query(None), cdata: str = Query(None)):
    tid = await _spawn_browser(SolveRequest(type="turnstile", url=url, sitekey=sitekey, action=action, cdata=cdata))
    return JSONResponse({"task_id": tid, "status": "accepted"}, status_code=202)

@app.get("/clearance")
async def r_clearance(url: str = Query(...), timeout: int = Query(30)):
    tid = await _spawn_browser(SolveRequest(type="cloudflare", url=url, timeout_s=timeout))
    return JSONResponse({"task_id": tid, "status": "accepted"}, status_code=202)

@app.get("/aws-token")
async def r_aws(url: str = Query(...), timeout: int = Query(30)):
    tid = await _spawn_browser(SolveRequest(type="awswaf", url=url, timeout_s=timeout))
    return JSONResponse({"task_id": tid, "status": "accepted"}, status_code=202)

@app.api_route("/recaptchaV3", methods=["GET", "POST"])
async def r_recaptcha(url: str = Query(...), sitekey: str = Query(...), action: str = Query("submit")):
    tid = await _spawn_browser(SolveRequest(type="recaptchav3", url=url, sitekey=sitekey, action=action))
    return JSONResponse({"task_id": tid, "status": "accepted"}, status_code=202)

@app.get("/result")
async def r_result(task_id: str = Query(..., alias="id")):
    if not engine or task_id not in engine.results:
        return JSONResponse({"status": "error", "message": "task_id invalid/expired"}, status_code=404)
    res = engine.results[task_id]
    if res.get("status") == "process":
        if time.time() - res.get("start_time", time.time()) > 300:
            engine.results[task_id] = {"status": "error", "value": "timeout"}
        else:
            return JSONResponse(res, status_code=202)
    res = engine.results.pop(task_id)
    code = 200 if res.get("status") == "success" else (408 if res.get("value") == "timeout" else 422)
    return JSONResponse(res, status_code=code)


if __name__ == "__main__":
    print(f"""
╔══════════════════════════════════════════════════╗
║        UNIVERSAL CAPTCHA SOLVER v5.1              ║
║        Camoufox engine + free local + Capsolver   ║
║        BY FEB-FRMN                                ║
║        https://saweria.co/febfrmn                 ║
╚══════════════════════════════════════════════════╝
  http://{HOST}:{PORT}   mode={SOLVER_MODE}  headless={HEADLESS}
  camoufox : turnstile | recaptcha | hcaptcha | cloudflare | awswaf
  free     : math | text | image (OCR) | slider (opencv)
  capsolver: funcaptcha | geetest | datadome (+ optional hcaptcha fallback)
  compat   : GET /turnstile /clearance /aws-token /recaptchaV3 → poll GET /result?id=
""")
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")
