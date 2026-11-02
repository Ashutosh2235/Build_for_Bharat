import base64
import uuid

import httpx
import pytest
import pytest_asyncio
from app import jobs
from app.core.config import get_settings
from app.db import create_all, dispose, sessionmaker
from app.main import app
from app.models import FeedEntry
from app.services import link_checks, mailer, net_intel, sandbox_client
from app.services.link_checks import CheckResult
from app.services.net_intel import ExpandResult

KEY = {"X-Api-Key": "test-key"}
# Lookalike link (evidence) + bank claim from a mobile + KYC + OTP → "surely fraud"
SCAM_TEXT = ("Dear HDFC customer, your account will be blocked today. Update KYC at "
             "https://hdfcbank-kyc-update.co/login and share the OTP to verify.")
# Strong wording + sender signs but NO link and nothing in any database → "surely spam"
SPAM_TEXT = "Sir I am from ICICI bank, your account will be blocked today. Please share the OTP to stop it."


@pytest_asyncio.fixture
async def client(monkeypatch, tmp_path):
    s = get_settings()
    monkeypatch.setattr(s, "report_dir", tmp_path / "reports")
    monkeypatch.setattr(s, "screenshot_dir", tmp_path / "screens")
    monkeypatch.setattr(s, "deep_scan_enabled", False)
    monkeypatch.setattr(s, "sandbox_enabled", False)
    monkeypatch.setattr(s, "report_mode", "demo")
    jobs.INLINE = True
    await dispose()
    from app import models  # noqa: F401  (register tables)
    from app.db import Base, get_engine
    async with get_engine().begin() as conn:   # clean slate (matters when testing against PostgreSQL)
        await conn.run_sync(Base.metadata.drop_all)
    await create_all()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        yield c
    await dispose()


@pytest.fixture
def outbox(monkeypatch):
    sent = []

    async def fake_send(msg):
        sent.append(msg)
        return msg["Message-ID"]

    monkeypatch.setattr(mailer, "send", fake_send)
    return sent


async def register(client, **kw):
    body = {"app_version": "test", "state_code": "PB", "consent_version": 1,
            "consent_server_check": True, "report_mode": "auto"} | kw
    r = await client.post("/v1/devices/register", json=body, headers=KEY)
    assert r.status_code == 200
    return KEY | {"X-Device-Token": r.json()["device_token"]}


async def scan(client, h, sender, text=None, **kw):
    body = {"message_id": str(uuid.uuid4()), "sender": sender, "text": text,
            "received_at": "2026-11-01T14:30:00+05:30"} | kw
    return await client.post("/v1/scan", json=body, headers=h)


async def test_auth_required(client):
    assert (await client.post("/v1/devices/register", json={})).status_code == 401
    assert (await client.post("/v1/scan", json={}, headers=KEY)).status_code == 401


async def test_health(client):
    r = await client.get("/v1/health")
    assert r.json()["ok"] and r.json()["report_mode"] == "demo"


async def test_genuine_otp_shows_nothing(client):
    h = await register(client)
    j = (await scan(client, h, "VM-HDFCBK-T", "482913 is your OTP for txn of Rs 500. Do not share it with anyone.")).json()
    assert j["verdict"] == "NONE" and j["label"] is None and j["reasons"] == [] and j["report"] is None
    assert j["checks"][0]["name"] == "ScamShield sender database"


async def test_no_server_consent_forbidden(client):
    h = await register(client, consent_server_check=False)
    assert (await scan(client, h, "9876543210", "hi")).status_code == 403


async def test_pending_shows_nothing_until_checks_finish(client, monkeypatch):
    """Rule 1: no label (and no reasons) before the database + link checks are done."""
    monkeypatch.setattr(get_settings(), "deep_scan_enabled", True)
    queued = []

    async def hold(fn, *args):
        queued.append((fn, args))

    monkeypatch.setattr(jobs, "enqueue", hold)
    h = await register(client)
    r = await scan(client, h, "9876543210", SCAM_TEXT)
    j = r.json()
    assert r.status_code == 202 and j["status"] == "partial" and j["verdict"] == "PENDING"
    assert j["label"] is None and j["reasons"] == [] and j["urls"] == [] and j["report"] is None
    assert not j["can_report"] and j["portals"] == []

    async def no_net(url, *a, **k):
        return ExpandResult(input=url, final_url=url, hops=[{"url": url, "status": 200}])

    async def unknown_age(domain, *a, **k):
        return None

    async def checks(p, client=None):
        return [CheckResult("Google Safe Browsing", "skipped", "no API key configured"),
                CheckResult("Quad9 threat DNS", "clean")]

    monkeypatch.setattr(net_intel, "expand_url", no_net)
    monkeypatch.setattr(net_intel, "domain_age_days", unknown_age)
    monkeypatch.setattr(link_checks, "run_all", checks)
    fn, args = queued[0]
    await fn(*args)                                   # the background job finishes
    j = (await client.get(f"/v1/scan/{j['scan_id']}", headers=h)).json()
    assert j["status"] == "complete" and j["verdict"] == "FRAUD" and j["label"] == "Surely fraud"
    names = [c["name"] for c in j["urls"][0]["checks"]]
    assert names == ["Threat-feed database", "Google Safe Browsing", "Quad9 threat DNS", "Isolated browser sandbox"]


async def test_fraud_auto_report_demo_flow(client, outbox):
    h = await register(client)
    j = (await scan(client, h, "9876543210", SCAM_TEXT)).json()
    assert j["verdict"] == "FRAUD" and j["label"] == "Surely fraud" and j["status"] == "complete"
    assert "LOOKALIKE_DOMAIN" in j["evidence"] and j["impersonated_brand"] == "HDFC"
    assert {p["id"] for p in j["portals"]} >= {"ncrp", "chakshu"}
    rep = j["report"]
    assert rep["status"] == "awaiting_log" and rep["needs_log"] and rep["mode"] == "demo"
    assert not j["can_report"]                         # already being reported automatically
    assert any(x["kind"] == "state_cyber_cell" and not x["verified"] for x in rep["intended"])

    log = {"scan_id": j["scan_id"], "messages": [
        {"sender": "+91 98765 43210", "text": SCAM_TEXT, "received_at": "2026-11-01T14:30:00+05:30"},
        {"sender": "9876543210", "text": "Reminder: complete KYC now", "received_at": "2026-11-01T15:00:00+05:30"},
        {"sender": "9999999999", "text": "unrelated personal message — must NOT be included"},
    ]}
    r = await client.post("/v1/report/log", json=log, headers=h)
    assert r.json()["status"] == "demo_sent"
    assert len(outbox) == 1
    msg = outbox[0]
    assert msg["To"] == "team-demo@example.com"
    assert msg["Subject"].startswith("[DEMO] [ScamShield Auto-Report SS-")
    body = msg.get_body(("plain",)).get_content()
    assert "would be sent to" in body and "UNVERIFIED" in body and "unrelated personal" not in body
    pdf = next(p for p in msg.iter_attachments() if p.get_filename().endswith(".pdf")).get_content()
    assert pdf[:4] == b"%PDF" and len(pdf) > 2000

    j2 = (await scan(client, h, "9876543210", SCAM_TEXT)).json()      # same sender + domain again
    assert j2["report"]["status"] == "duplicate"
    assert [x["status"] for x in (await client.get("/v1/reports", headers=h)).json()] == ["duplicate", "demo_sent"]


async def test_fraud_manual_mode_reports_only_when_user_taps(client, outbox):
    """Rule 2: manual mode never reports by itself; the Report button does."""
    h = await register(client, report_mode="manual")
    j = (await scan(client, h, "9876543210", SCAM_TEXT)).json()
    assert j["verdict"] == "FRAUD" and j["report"] is None and j["report_mode"] == "manual"
    assert j["can_report"] and "Punjab State Cyber Crime Cell" in j["report_preview"]
    assert outbox == []

    body = {"scan_id": j["scan_id"], "messages": [
        {"sender": "9876543210", "text": SCAM_TEXT, "received_at": "2026-11-01T14:30:00+05:30"},
        {"sender": "8888888888", "text": "someone else — must NOT be included"}]}
    r = await client.post("/v1/reports", json=body, headers=h)
    assert r.status_code == 200 and r.json()["status"] == "demo_sent" and len(outbox) == 1
    assert "someone else" not in outbox[0].get_body(("plain",)).get_content()
    again = await client.post("/v1/reports", json=body, headers=h)      # double tap → same report
    assert again.json()["id"] == r.json()["id"] and len(outbox) == 1
    j = (await client.get(f"/v1/scan/{j['scan_id']}", headers=h)).json()
    assert not j["can_report"] and j["report"]["status"] == "demo_sent"


async def test_switch_report_mode(client, outbox):
    h = await register(client, report_mode="manual")
    r = await client.put("/v1/devices/me", headers=h, json={"consent_server_check": True, "report_mode": "auto",
                                                            "state_code": "PB", "consent_version": 1})
    assert r.status_code == 204
    j = (await scan(client, h, "9876543210", SCAM_TEXT)).json()
    assert j["report_mode"] == "auto" and j["report"]["status"] == "awaiting_log"


async def test_legacy_client_flag_maps_to_auto(client):
    h = await register(client, report_mode=None, consent_auto_report=True)
    assert (await scan(client, h, "9876543210", SCAM_TEXT)).json()["report_mode"] == "auto"


async def test_spam_is_labelled_but_never_reported(client, outbox):
    h = await register(client)
    j = (await scan(client, h, "9876501234", SPAM_TEXT)).json()
    assert j["verdict"] == "SPAM" and j["label"] == "Surely spam" and j["score"] >= 60
    assert j["evidence"] == [] and j["report"] is None and not j["can_report"] and j["portals"] == []
    assert {"MOBILE_BRAND_CLAIM", "OTP_REQUEST"} <= {r["code"] for r in j["reasons"]}
    r = await client.post("/v1/reports", json={"scan_id": j["scan_id"], "messages": []}, headers=h)
    assert r.status_code == 409 and outbox == []


async def test_weak_signs_show_nothing(client):
    h = await register(client)
    j = (await scan(client, h, "+923001234567", "Congratulations you won a lottery! Claim your prize now")).json()
    assert 0 < j["score"] < 60 and j["verdict"] == "NONE" and j["reasons"] == []


async def test_live_mode_skips_unverified(client, outbox, monkeypatch):
    monkeypatch.setattr(get_settings(), "report_mode", "live")
    h = await register(client)
    j = (await scan(client, h, "9876543210", SCAM_TEXT)).json()
    r = await client.post("/v1/report/log", json={"scan_id": j["scan_id"], "messages": []}, headers=h)
    assert r.json()["status"] == "no_recipient" and outbox == []


async def test_feed_hit_is_fraud(client):
    async with sessionmaker()() as s:
        s.add(FeedEntry(feed="openphish", indicator="totally-legit-parcel.top", type="domain"))
        await s.commit()
    h = await register(client)
    j = (await scan(client, h, "VM-ABCDEF", "Track your order at https://www.totally-legit-parcel.top/track")).json()
    assert j["verdict"] == "FRAUD" and j["score"] == 100 and j["evidence"][0] == "FEED_HIT"
    assert j["reasons"][0]["code"] == "FEED_HIT" and j["urls"][0]["feed_hits"] == ["openphish"]
    assert j["urls"][0]["checks"][0] == {"name": "Threat-feed database", "status": "hit", "detail": "openphish"}


async def test_private_mode_uses_device_codes(client):
    h = await register(client)
    j = (await scan(client, h, "9876543210", None, urls=["https://hdfcbank-kyc-update.co/login"],
                    local={"score": 70, "reasons": ["KYC_BLOCK_THREAT", "OTP_REQUEST", "BRAND_CLAIM", "BOGUS"]})).json()
    codes = {x["code"] for x in j["reasons"]}
    assert {"KYC_BLOCK_THREAT", "OTP_REQUEST", "MOBILE_BRAND_CLAIM", "LOOKALIKE_DOMAIN"} <= codes
    assert "BOGUS" not in codes and j["verdict"] == "FRAUD"


async def test_admin_block_sender_and_blocklist(client):
    h = await register(client)
    await scan(client, h, "+91 70000 00001", "Congratulations you won KBC lottery, claim prize")
    auth = {"Authorization": "Basic " + base64.b64encode(b"admin:change-me").decode()}
    assert (await client.put("/admin/senders/+917000000001", json={"status": "blocked"}, headers=auth)).status_code == 200
    j = (await scan(client, h, "7000000001", "hello")).json()
    assert j["verdict"] == "FRAUD" and j["reasons"][0]["code"] == "SENDER_BLOCKED"
    assert j["checks"][0]["status"] == "hit"
    bl = (await client.get("/v1/sync/blocklist", headers=h)).json()
    assert "+917000000001" in bl["senders"] and bl["full"]
    assert (await client.get("/admin/stats")).status_code == 401


async def test_deep_scan_redirects_rdap_sandbox(client, outbox, monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "deep_scan_enabled", True)
    monkeypatch.setattr(s, "sandbox_enabled", True)

    async def fake_expand(url, *a, **k):
        return ExpandResult(input=url, final_url="https://bharat-demobank-kyc.example.net/login", hops=[
            {"url": url, "status": 301}, {"url": "https://t.example.org/r", "status": 302},
            {"url": "https://bharat-demobank-kyc.example.net/login", "status": 200}])

    async def fake_age(domain, *a, **k):
        return 2

    async def fake_visit(url, *a, **k):
        return {"final_url": url, "forms": [{"action_host": "x", "password": True}], "download_attempt": False,
                "screenshot": "abc.png"}

    async def checks(p, client=None):
        return [CheckResult("Google Safe Browsing", "clean"), CheckResult("Quad9 threat DNS", "unavailable", "ConnectError")]

    monkeypatch.setattr(net_intel, "expand_url", fake_expand)
    monkeypatch.setattr(net_intel, "domain_age_days", fake_age)
    monkeypatch.setattr(sandbox_client, "visit", fake_visit)
    monkeypatch.setattr(link_checks, "run_all", checks)
    h = await register(client)
    r = await scan(client, h, "9123456780", "Bharat Demo Bank: your account is suspended. Verify at bit.ly/bdb-kyc")
    j = (await client.get(f"/v1/scan/{r.json()['scan_id']}", headers=h)).json()
    codes = {x["code"] for x in j["reasons"]}
    assert j["status"] == "complete" and j["verdict"] == "FRAUD" and j["score"] == 100
    assert {"REDIRECT_CHAIN", "LOOKALIKE_DOMAIN", "DOMAIN_NEW", "LOGIN_FORM", "MOBILE_BRAND_CLAIM"} <= codes
    assert j["impersonated_brand"] == "DEMOBANK"
    u = j["urls"][0]
    assert u["final"] == "https://bharat-demobank-kyc.example.net/login" and u["screenshot_url"].endswith("/v1/screens/abc.png")
    status = {c["name"]: c["status"] for c in u["checks"]}
    assert status == {"Threat-feed database": "clean", "Google Safe Browsing": "clean",
                      "Quad9 threat DNS": "unavailable", "Isolated browser sandbox": "hit"}
    assert any(x["kind"] == "brand" and x["verified"] for x in j["report"]["intended"])


async def test_online_check_hit_is_fraud_and_cert_age_fallback(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "deep_scan_enabled", True)

    async def fake_expand(url, *a, **k):
        return ExpandResult(input=url, final_url=url, hops=[{"url": url, "status": 200}])

    async def no_rdap(domain, *a, **k):
        return None              # RDAP has no date → certificate history is used instead

    async def checks(p, client=None):
        return [CheckResult("Google Safe Browsing", "hit", "SOCIAL_ENGINEERING"),
                CheckResult("Certificate history (crt.sh)", "hit", "first certificate 4 days ago", age_days=4)]

    monkeypatch.setattr(net_intel, "expand_url", fake_expand)
    monkeypatch.setattr(net_intel, "domain_age_days", no_rdap)
    monkeypatch.setattr(link_checks, "run_all", checks)
    h = await register(client)
    j = (await scan(client, h, "VM-ABCDEF", "Your parcel update: https://track-parcel-now.example/x")).json()
    j = (await client.get(f"/v1/scan/{j['scan_id']}", headers=h)).json()
    codes = {r["code"] for r in j["reasons"]}
    assert j["verdict"] == "FRAUD" and j["score"] == 100 and {"FEED_HIT", "CERT_NEW"} <= codes
    assert "Google Safe Browsing" in j["urls"][0]["feed_hits"]


async def test_files_only_demo_mode_and_stale_report_release(client, outbox, monkeypatch):
    from datetime import timedelta

    from app.models import Report
    from app.services import reporter
    s = get_settings()
    monkeypatch.setattr(s, "demo_recipients", [])
    monkeypatch.setattr(s, "smtp_host", "")
    h = await register(client)
    j = (await scan(client, h, "9876543210", SCAM_TEXT)).json()
    assert j["report"]["status"] == "awaiting_log"
    async with sessionmaker()() as session:      # phone never uploads the log; 11 minutes pass
        rep = await session.get(Report, 1)
        rep.created_at = rep.created_at - timedelta(minutes=11)
        await session.commit()
        assert await reporter.release_stale(session, 10) == [rep.id]
        rep = await session.get(Report, rep.id)
        await reporter.send_report(session, rep)
        assert rep.status == "demo_sent" and rep.sent_to == ["demo-inbox@localhost"]
    assert "share the OTP" in outbox[0].get_body(("plain",)).get_content()


async def test_schema_upgrade_keeps_old_database(tmp_path, monkeypatch):
    """A database created by the previous build (no report_mode / checks columns) is upgraded in place."""
    import sqlite3

    from app.db import create_all, dispose
    path = tmp_path / "old.db"
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE devices (id INTEGER PRIMARY KEY, token_hash VARCHAR(64), consent_auto_report BOOLEAN)")
    con.execute("INSERT INTO devices (id, token_hash, consent_auto_report) VALUES (1, 'x', 1)")
    con.commit()
    con.close()
    monkeypatch.setattr(get_settings(), "database_url", f"sqlite+aiosqlite:///{path}")
    await dispose()
    await create_all()
    await dispose()
    con = sqlite3.connect(path)
    cols = {r[1] for r in con.execute("PRAGMA table_info(devices)")}
    assert {"report_mode", "token_hash"} <= cols
    assert con.execute("SELECT token_hash, report_mode FROM devices").fetchone() == ("x", "manual")
    assert "checks" in {r[1] for r in con.execute("PRAGMA table_info(urls)")}
    con.close()


async def test_demo_page(client, monkeypatch):
    r = await client.get("/demo/kyc")
    assert r.status_code == 200 and "Bharat Demo Bank" in r.text and 'type="password"' in r.text
    r = await client.get("/demo/kyc.apk")
    assert r.headers["content-type"] == "application/vnd.android.package-archive"
    monkeypatch.setattr(get_settings(), "demo_pages_enabled", False)
    assert (await client.get("/demo/kyc")).status_code == 404


async def test_sandbox_navigation_failure_is_unavailable_not_clean(client, monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "deep_scan_enabled", True)
    monkeypatch.setattr(s, "sandbox_enabled", True)

    async def fake_expand(url, *a, **k):
        return ExpandResult(input=url, final_url=url, hops=[{"url": url, "status": 200}])

    async def fake_age(domain, *a, **k):
        return 900

    async def blocked(url, *a, **k):
        return {"final_url": url, "forms": [{"password": True}], "download_attempt": True,
                "errors": ["Page.goto: net::ERR_BLOCKED_BY_CLIENT at " + url]}

    async def no_checks(p, client=None):
        return []

    monkeypatch.setattr(net_intel, "expand_url", fake_expand)
    monkeypatch.setattr(net_intel, "domain_age_days", fake_age)
    monkeypatch.setattr(sandbox_client, "visit", blocked)
    monkeypatch.setattr(link_checks, "run_all", no_checks)
    h = await register(client)
    j = (await scan(client, h, "VM-ABCDEF", "See https://some-shop.example/x")).json()
    j = (await client.get(f"/v1/scan/{j['scan_id']}", headers=h)).json()
    assert j["verdict"] == "NONE"                         # error page content is ignored
    async with sessionmaker()() as session:
        from app.models import Url
        from sqlalchemy import select
        row = (await session.execute(select(Url))).scalar_one()
        sandbox = next(c for c in row.checks if c["name"] == "Isolated browser sandbox")
        assert sandbox["status"] == "unavailable" and "could not be opened" in sandbox["detail"]
