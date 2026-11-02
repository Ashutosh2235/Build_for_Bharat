"""Fictional phishing-style demo page for live demos and testing (no real brand).

GET /demo/kyc      "Bharat Demo Bank" KYC page: login + OTP form, then tries to download an "app"
GET /demo/kyc.apk  a few harmless bytes served with the Android-package content type

Send an SMS containing  <your public server address>/demo/kyc  — the link sandbox opens it like a
real scam site and should report LOGIN_FORM + DOWNLOAD_ATTEMPT. The form submits nowhere.
Turn off with DEMO_PAGES_ENABLED=false.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, Response

from app.core.config import get_settings

router = APIRouter(prefix="/demo", include_in_schema=False)

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bharat Demo Bank - KYC Update</title>
<style>
 body{font-family:system-ui,sans-serif;margin:0;background:#f4f6fb;color:#1d2433}
 header{background:#5b2a86;color:#fff;padding:14px 18px;font-weight:700}
 main{max-width:420px;margin:18px auto;background:#fff;border-radius:10px;padding:18px;box-shadow:0 2px 8px #0002}
 .alert{background:#fde8e8;color:#9b1c1c;padding:10px;border-radius:6px;font-size:14px}
 label{display:block;margin-top:12px;font-size:14px} input{width:100%;padding:10px;margin-top:4px;box-sizing:border-box}
 button{margin-top:16px;width:100%;padding:12px;background:#5b2a86;color:#fff;border:0;border-radius:6px;font-size:16px}
 footer{text-align:center;font-size:11px;color:#777;margin:18px}
</style></head>
<body>
<header>Bharat Demo Bank</header>
<main>
 <p class="alert">Your account is suspended due to pending KYC. Verify within 2 hours to avoid permanent block.</p>
 <form action="#" onsubmit="return false">
  <label>Customer ID<input name="userid" autocomplete="username" placeholder="Customer ID"></label>
  <label>Net banking password<input type="password" name="password" placeholder="Password"></label>
  <label>OTP<input name="otp" inputmode="numeric" placeholder="Enter OTP"></label>
  <button type="submit">Verify KYC</button>
 </form>
 <p style="font-size:13px">Or install the <a href="kyc.apk">KYC Verification App</a>.</p>
</main>
<footer>ScamShield DEMO PAGE &middot; fictional bank &middot; nothing you type here is sent anywhere</footer>
<script>setTimeout(function(){ location.href = "kyc.apk"; }, 800);</script>
</body></html>"""


def _enabled() -> None:
    if not get_settings().demo_pages_enabled:
        raise HTTPException(404)


@router.get("/kyc", response_class=HTMLResponse)
async def kyc_page() -> HTMLResponse:
    _enabled()
    return HTMLResponse(PAGE, headers={"Cache-Control": "no-store"})


@router.get("/kyc.apk")
async def kyc_apk() -> Response:
    _enabled()
    return Response(b"ScamShield demo file - not an app\n", media_type="application/vnd.android.package-archive",
                    headers={"Content-Disposition": 'attachment; filename="BDB-KYC.apk"'})
