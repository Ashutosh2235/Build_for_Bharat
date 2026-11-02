#!/usr/bin/env python3
"""Offline end-to-end demo: register a device, scan a fake 'Bharat Demo Bank' scam SMS, upload the
SMS log and produce the demo-mode report (PDF + JSON + .eml in <out>/outbox). Network calls
(redirects, RDAP, sandbox) are simulated, so this runs anywhere — handy for slides and for
checking the report layout.

    python tools/demo_report.py [out_dir] [screenshot.png]
"""
from __future__ import annotations

import asyncio
import os
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "demo-out").resolve()
SHOT = Path(sys.argv[2]) if len(sys.argv) > 2 else None
(OUT / "screens").mkdir(parents=True, exist_ok=True)
os.environ.update({
    "DATABASE_URL": "sqlite+aiosqlite:///:memory:", "API_KEY": "demo", "DEEP_SCAN_ENABLED": "true",
    "SANDBOX_ENABLED": "true", "REPORT_MODE": "demo", "DEMO_RECIPIENTS": "team-demo@yourdomain.in", "SMTP_HOST": "",
    "SCREENSHOT_DIR": str(OUT / "screens"), "REPORT_DIR": str(OUT),
    "FERNET_KEY": "ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg=",
})
sys.path.insert(0, str(ROOT / "backend"))

import httpx  # noqa: E402
from app import jobs  # noqa: E402
from app.db import create_all  # noqa: E402
from app.main import app  # noqa: E402
from app.services import net_intel, sandbox_client  # noqa: E402
from app.services.net_intel import ExpandResult  # noqa: E402

FINAL = "https://bharat-demobank-kyc.example.net/login"
TEXT = "Bharat Demo Bank: your account is suspended due to pending KYC. Verify immediately at bit.ly/bdb-kyc"


async def fake_expand(url, *a, **k):
    return ExpandResult(input=url, final_url=FINAL, hops=[
        {"url": url, "status": 301}, {"url": "https://t.example.org/r", "status": 302}, {"url": FINAL, "status": 200}])


async def fake_age(domain, *a, **k):
    return 2


async def fake_visit(url, *a, **k):
    return {"final_url": url, "download_attempt": True, "screenshot": "demo.png" if SHOT else None,
            "forms": [{"action_host": "collect.evil-demo.example", "password": True, "otp": True}]}


async def main() -> None:
    if SHOT:
        shutil.copy(SHOT, OUT / "screens" / "demo.png")
    net_intel.expand_url, net_intel.domain_age_days, sandbox_client.visit = fake_expand, fake_age, fake_visit
    jobs.INLINE = True
    await create_all()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://demo") as c:
        token = (await c.post("/v1/devices/register", headers={"X-Api-Key": "demo"}, json={
            "state_code": "PB", "consent_server_check": True, "consent_auto_report": True, "consent_version": 1,
        })).json()["device_token"]
        h = {"X-Api-Key": "demo", "X-Device-Token": token}
        scan = (await c.post("/v1/scan", headers=h, json={
            "message_id": "1", "sender": "+91 91234 56780", "text": TEXT, "received_at": "2026-11-01T14:30:00+05:30",
        })).json()
        scan = (await c.get(f"/v1/scan/{scan['scan_id']}", headers=h)).json()
        print(f"verdict {scan['verdict']} {scan['score']}/100:", ", ".join(r["code"] for r in scan["reasons"]))
        rep = (await c.post("/v1/report/log", headers=h, json={"scan_id": scan["scan_id"], "messages": [
            {"sender": "+919123456780", "text": TEXT, "received_at": "2026-11-01T14:30:00+05:30"},
            {"sender": "+919123456780", "text": "Last reminder: your account will be closed today. Verify KYC now.",
             "received_at": "2026-11-01T15:05:00+05:30"},
        ]})).json()
        print(f"report {rep['id']} → {rep['status']}  (files in {OUT})")


if __name__ == "__main__":
    asyncio.run(main())
