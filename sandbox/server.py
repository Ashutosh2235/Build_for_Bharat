"""Isolated link sandbox: POST /visit {"url": ...} → page facts + screenshot.

Runs in its own container (context file §6). Defence in depth:
  * every request the page makes is checked: non-public destinations are aborted (SSRF);
  * downloads are never saved — the attempt is only recorded;
  * fresh browser context per visit, hard timeouts, browser recycled every N visits;
  * container: non-root, read-only rootfs, no capabilities, memory/pid limits (docker-compose).
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import socket
import time
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException
from page_analysis import EXTRACT_JS, brand_hits, classify_forms, is_download_response, is_public_ip
from playwright.async_api import Browser, Route, async_playwright
from playwright.async_api import Error as PWError
from pydantic import BaseModel

log = logging.getLogger("sandbox")
SCREEN_DIR = Path(os.environ.get("SCREEN_DIR", "/screens"))
CONCURRENCY = int(os.environ.get("SANDBOX_CONCURRENCY", "2"))
NAV_TIMEOUT_MS = int(os.environ.get("NAV_TIMEOUT_MS", "15000"))
JOB_TIMEOUT_S = float(os.environ.get("JOB_TIMEOUT_S", "25"))
RECYCLE_AFTER = int(os.environ.get("RECYCLE_AFTER", "50"))
CHROMIUM_PATH = os.environ.get("CHROMIUM_PATH") or None        # local dev: use an installed Chrome
# DEV/TEST ONLY: lets the sandbox open pages on localhost. Never set this in a deployed container.
ALLOW_PRIVATE = os.environ.get("SANDBOX_ALLOW_PRIVATE_FOR_TESTS") == "1"
UA = ("Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36")
BRAND_WORDS = {  # words shown on fake pages; kept small and generic on purpose
    "SBI": ["sbi", "state bank of india", "yono"], "HDFC": ["hdfc bank", "hdfc"], "ICICI": ["icici"],
    "AXIS": ["axis bank"], "KOTAK": ["kotak"], "PAYTM": ["paytm"], "PHONEPE": ["phonepe"],
    "INDIAPOST": ["india post", "speed post"], "INCOMETAX": ["income tax"], "UIDAI": ["uidai", "aadhaar"],
    "DEMOBANK": ["bharat demo bank"],
}

state: dict = {"pw": None, "browser": None, "visits": 0, "sem": asyncio.Semaphore(CONCURRENCY)}


async def _browser() -> Browser:
    if state["browser"] is None or state["visits"] >= RECYCLE_AFTER or not state["browser"].is_connected():
        if state["browser"] is not None:
            try:
                await state["browser"].close()
            except PWError:
                pass
        state["browser"] = await state["pw"].chromium.launch(
            executable_path=CHROMIUM_PATH,
            args=["--disable-dev-shm-usage", "--no-first-run", "--disable-extensions",
                  "--disable-background-networking", "--disable-sync", "--mute-audio"])
        state["visits"] = 0
    return state["browser"]


@asynccontextmanager
async def lifespan(_: FastAPI):
    logging.basicConfig(level=logging.INFO)
    if ALLOW_PRIVATE:
        log.warning("SANDBOX_ALLOW_PRIVATE_FOR_TESTS=1 — SSRF guard DISABLED. Never deploy like this.")
    SCREEN_DIR.mkdir(parents=True, exist_ok=True)
    state["pw"] = await async_playwright().start()
    yield
    if state["browser"]:
        await state["browser"].close()
    await state["pw"].stop()


app = FastAPI(title="ScamShield sandbox", lifespan=lifespan)


class VisitIn(BaseModel):
    url: str


_dns_cache: dict[str, tuple[float, bool]] = {}


async def host_is_public(host: str) -> bool:
    if not host:
        return False
    if ALLOW_PRIVATE:
        return True
    now = time.time()
    hit = _dns_cache.get(host)
    if hit and now - hit[0] < 60:
        return hit[1]
    try:
        if is_public_ip(host):
            ok = True
        else:
            infos = await asyncio.get_running_loop().getaddrinfo(host, 443, type=socket.SOCK_STREAM)
            ips = {i[4][0] for i in infos}
            ok = bool(ips) and all(is_public_ip(ip) for ip in ips)
    except (socket.gaierror, UnicodeError):
        ok = False
    if host.replace(".", "").isdigit() or ":" in host:   # IP literal
        ok = is_public_ip(host)
    _dns_cache[host] = (now, ok)
    return ok


@app.get("/health")
async def health() -> dict:
    return {"ok": True, "visits_since_recycle": state["visits"]}


@app.post("/visit")
async def visit(body: VisitIn) -> dict:
    parts = urlsplit(body.url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise HTTPException(400, "only http(s) urls")
    async with state["sem"]:
        try:
            return await asyncio.wait_for(_visit(body.url), timeout=JOB_TIMEOUT_S)
        except TimeoutError:
            return {"input": body.url, "error": "timeout"}


async def _visit(url: str) -> dict:
    result: dict = {"input": url, "final_url": url, "title": "", "forms": [], "download_attempt": False,
                    "blocked_requests": [], "brand_hits": [], "screenshot": None, "errors": []}
    browser = await _browser()
    state["visits"] += 1
    ctx = await browser.new_context(user_agent=UA, viewport={"width": 412, "height": 915}, is_mobile=True,
                                    has_touch=True, accept_downloads=False, java_script_enabled=True,
                                    locale="en-IN", timezone_id="Asia/Kolkata", service_workers="block")
    try:
        async def guard(route: Route):
            host = urlsplit(route.request.url).hostname or ""
            scheme = urlsplit(route.request.url).scheme
            if scheme in ("data", "blob", "about"):
                return await route.continue_()
            if scheme not in ("http", "https") or not await host_is_public(host):
                result["blocked_requests"].append(route.request.url[:200])
                return await route.abort("blockedbyclient")
            return await route.continue_()

        await ctx.route("**/*", guard)
        page = await ctx.new_page()

        def on_response(resp):
            h = resp.headers
            if is_download_response(h.get("content-type", ""), resp.url, h.get("content-disposition", "")):
                result["download_attempt"] = True
                result.setdefault("download_urls", []).append(resp.url[:300])

        page.on("response", on_response)
        page.on("download", lambda d: result.update(download_attempt=True))
        try:
            await page.goto(url, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
            try:
                await page.wait_for_load_state("networkidle", timeout=5000)
            except PWError:
                pass
        except PWError as e:
            result["errors"].append(str(e).splitlines()[0][:200])
        result["final_url"] = page.url
        try:
            dom = await page.evaluate(EXTRACT_JS)
            host = urlsplit(page.url).hostname or ""
            result["title"] = dom.get("title", "")[:200]
            result["forms"] = classify_forms(dom.get("forms", []), host)
            result["iframes"] = dom.get("iframes", 0)
            result["meta_refresh"] = dom.get("meta_refresh", "")
            result["script_hosts"] = sorted(set(dom.get("script_hosts", [])))[:30]
            result["brand_hits"] = brand_hits(dom.get("text", ""), dom.get("title", ""), BRAND_WORDS)
        except PWError as e:
            result["errors"].append(f"dom: {str(e)[:150]}")
        try:
            name = hashlib.sha256(f"{url}|{time.time()}".encode()).hexdigest()[:20] + ".png"
            await page.screenshot(path=str(SCREEN_DIR / name), full_page=False, timeout=5000)
            result["screenshot"] = name
        except PWError as e:
            result["errors"].append(f"screenshot: {str(e)[:150]}")
    finally:
        await ctx.close()
    return result
