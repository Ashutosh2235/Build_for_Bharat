"""Online link checks and the extra feeds — recorded/realistic responses, no network."""
import json
from datetime import UTC, datetime, timedelta

import dns.message
import dns.rcode
import dns.rrset
import httpx
import pytest
from app.core.config import get_settings
from app.feeds import parsers, sync
from app.services import link_checks
from app.services.ruleset import get_ruleset
from app.services.url_intel import parse_url

rs = get_ruleset()


def P(url):
    return parse_url(url, rs)


@pytest.fixture(autouse=True)
def _fresh():
    link_checks.clear_cache()
    yield
    link_checks.clear_cache()


# ------------------------------------------------------------------ Google Safe Browsing
async def test_safe_browsing_hit_and_cache(monkeypatch):
    monkeypatch.setattr(get_settings(), "google_safebrowsing_key", "k")
    calls = []

    def handler(req: httpx.Request):
        body = json.loads(req.content)
        calls.append([e["url"] for e in body["threatInfo"]["threatEntries"]])
        assert req.url.params["key"] == "k" and body["threatInfo"]["platformTypes"] == ["ANY_PLATFORM"]
        return httpx.Response(200, json={"matches": [
            {"threatType": "SOCIAL_ENGINEERING", "platformType": "ANY_PLATFORM", "threatEntryType": "URL",
             "threat": {"url": "http://bad.example/login"}}]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        r = await link_checks.safe_browsing(P("http://bad.example/login"), c)
        assert (r.status, r.detail) == ("hit", "SOCIAL_ENGINEERING")
        r2 = await link_checks.safe_browsing(P("http://bad.example/login"), c)
        assert r2.status == "hit" and len(calls) == 1               # cached
    assert calls[0] == ["http://bad.example/login", "http://bad.example/"]


async def test_safe_browsing_clean_skipped_and_errors(monkeypatch):
    monkeypatch.setattr(get_settings(), "google_safebrowsing_key", "k")
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={}))) as c:
        assert (await link_checks.safe_browsing(P("https://ok.example/"), c)).status == "clean"
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(403))) as c:
        r = await link_checks.safe_browsing(P("https://x.example/"), c)
        assert (r.status, r.detail) == ("unavailable", "HTTP 403")
    monkeypatch.setattr(get_settings(), "google_safebrowsing_key", "")
    async with httpx.AsyncClient() as c:
        assert (await link_checks.safe_browsing(P("https://x.example/"), c)).status == "skipped"


# ------------------------------------------------------------------ Protective DNS
def dns_server(answers):
    """Mock DoH endpoint: answers[resolver_host] = (rcode, [A records])."""
    def handler(req: httpx.Request):
        assert req.headers["content-type"] == "application/dns-message"
        q = dns.message.from_wire(req.content)
        rcode, addrs = answers[req.url.host]
        resp = dns.message.make_response(q)
        resp.set_rcode(rcode)
        if addrs:
            resp.answer.append(dns.rrset.from_text(q.question[0].name, 300, "IN", "A", *addrs))
        return httpx.Response(200, content=resp.to_wire(), headers={"content-type": "application/dns-message"})
    return handler


BLOCKING = {
    "dns.quad9.net": (dns.rcode.NXDOMAIN, []),                          # Quad9 blocks with NXDOMAIN
    "dns10.quad9.net": (dns.rcode.NOERROR, ["203.0.113.7"]),
    "security.cloudflare-dns.com": (dns.rcode.NOERROR, ["0.0.0.0"]),    # Cloudflare sinkholes to 0.0.0.0
    "cloudflare-dns.com": (dns.rcode.NOERROR, ["203.0.113.7"]),
}


async def test_dns_checks_detect_blocks():
    async with httpx.AsyncClient(transport=httpx.MockTransport(dns_server(BLOCKING))) as c:
        q9 = await link_checks._dns_check("quad9")(P("https://phish.example/a"), c)
        cf = await link_checks._dns_check("cloudflare")(P("https://phish.example/a"), c)
    assert (q9.name, q9.status) == ("Quad9 threat DNS", "hit")
    assert (cf.name, cf.status) == ("Cloudflare security DNS", "hit")


async def test_dns_checks_clean_and_nonexistent():
    clean = {h: (dns.rcode.NOERROR, ["203.0.113.7"]) for h in BLOCKING}
    nxd = {h: (dns.rcode.NXDOMAIN, []) for h in BLOCKING}        # domain doesn't exist anywhere
    for answers in (clean, nxd):
        link_checks.clear_cache()
        async with httpx.AsyncClient(transport=httpx.MockTransport(dns_server(answers))) as c:
            assert (await link_checks._dns_check("quad9")(P("https://ok.example/"), c)).status == "clean"
            assert (await link_checks._dns_check("cloudflare")(P("https://ok.example/"), c)).status == "clean"


def test_dns_blocked_logic():
    real = (dns.rcode.NOERROR, {"203.0.113.7"})
    assert link_checks.dns_blocked((dns.rcode.NXDOMAIN, set()), real)
    assert link_checks.dns_blocked((dns.rcode.NOERROR, {"0.0.0.0"}), real)
    assert not link_checks.dns_blocked(real, real)
    assert not link_checks.dns_blocked((dns.rcode.NXDOMAIN, set()), (dns.rcode.NXDOMAIN, set()))


# ------------------------------------------------------------------ Certificate history
async def test_certificate_age_new_and_old():
    def make(days):
        nb = (datetime.now(UTC) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")
        return lambda r: httpx.Response(200, json=[{"not_before": nb}, {"not_before": "garbage"}])

    async with httpx.AsyncClient(transport=httpx.MockTransport(make(3))) as c:
        r = await link_checks.certificate_age(P("https://kyc.fresh-scam.example/x"), c)
    assert (r.status, r.age_days) == ("hit", 3) and r.detail == "first certificate 3 days ago"
    link_checks.clear_cache()
    async with httpx.AsyncClient(transport=httpx.MockTransport(make(900))) as c:
        r = await link_checks.certificate_age(P("https://shop.example/"), c)
    assert r.status == "clean" and r.age_days == 900


# ------------------------------------------------------------------ runner
async def test_run_all_never_raises_and_reports_unavailable(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "google_safebrowsing_key", "k")
    monkeypatch.setattr(s, "secure_dns_enabled", True)
    monkeypatch.setattr(s, "crtsh_enabled", True)

    def boom(req):
        raise httpx.ConnectError("blocked by network")

    async with httpx.AsyncClient(transport=httpx.MockTransport(boom)) as c:
        res = await link_checks.run_all(P("https://x.example/"), client=c)
    assert [r.name for r in res] == ["Google Safe Browsing", "Quad9 threat DNS", "Cloudflare security DNS",
                                     "Certificate history (crt.sh)"]
    assert {r.status for r in res} == {"unavailable"}
    assert link_checks._cache == {}                       # failures are not cached


async def test_run_all_respects_settings(monkeypatch):
    s = get_settings()
    monkeypatch.setattr(s, "google_safebrowsing_key", "")
    monkeypatch.setattr(s, "secure_dns_enabled", False)
    monkeypatch.setattr(s, "crtsh_enabled", False)
    res = await link_checks.run_all(P("https://x.example/"))
    assert [(r.name, r.status) for r in res] == [("Google Safe Browsing", "skipped")]


# ------------------------------------------------------------------ Feeds: ThreatFox + phishunt
THREATFOX = {"query_status": "ok", "data": [
    {"id": "1", "ioc": "evil-c2.example", "ioc_type": "domain", "threat_type": "botnet_cc", "confidence_level": 100},
    {"id": "2", "ioc": "https://pay-kyc.example/apk/update.apk", "ioc_type": "url", "threat_type": "payload_delivery"},
    {"id": "3", "ioc": "203.0.113.9:8443", "ioc_type": "ip:port", "threat_type": "botnet_cc"},
    {"id": "4", "ioc": "d41d8cd98f00b204e9800998ecf8427e", "ioc_type": "md5_hash"},
]}


def test_parse_threatfox():
    assert list(parsers.parse_threatfox_json(json.dumps(THREATFOX))) == [
        ("evil-c2.example", "domain"), ("pay-kyc.example/apk/update.apk", "url"), ("203.0.113.9", "ip")]
    assert list(parsers.parse_threatfox_json('{"query_status":"no_result","data":"..."}')) == []


def test_parse_phishunt():
    doc = {"count": 2, "results": [
        {"url": "https://hdfc-netbanking-kyc.example/login", "domain": "hdfc-netbanking-kyc.example", "company": "hdfc"},
        {"url": "", "domain": "SBI-Rewards.example"}]}
    assert list(parsers.parse_phishunt_json(json.dumps(doc))) == [
        ("hdfc-netbanking-kyc.example/login", "url"), ("hdfc-netbanking-kyc.example", "domain"),
        ("sbi-rewards.example", "domain")]


async def test_sync_threatfox_posts_with_key(monkeypatch):
    from app.db import create_all, dispose
    monkeypatch.setattr(get_settings(), "abusech_auth_key", "AK")
    await dispose()
    await create_all()
    seen = {}

    def handler(req):
        seen["method"], seen["key"], seen["body"] = req.method, req.headers.get("Auth-Key"), json.loads(req.content)
        return httpx.Response(200, json=THREATFOX)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        n = await sync.sync_feed("threatfox", client=c)
    assert n == 3 and seen == {"method": "POST", "key": "AK", "body": {"query": "get_iocs", "days": 7}}
    await dispose()


async def test_sync_phishunt_uses_verified_tier():
    from app.db import create_all, dispose
    await dispose()
    await create_all()
    seen = {}
    doc = {"results": [{"url": "https://hdfc-netbanking-kyc.example/login", "domain": "hdfc-netbanking-kyc.example"}]}

    def handler(req):
        seen["url"] = str(req.url)
        return httpx.Response(200, json=doc)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        assert await sync.sync_feed("phishunt", client=c) == 2
    assert "tier=verified" in seen["url"]
    await dispose()


async def test_threatfox_skipped_without_key(monkeypatch):
    monkeypatch.setattr(get_settings(), "abusech_auth_key", "")
    assert await sync.sync_feed("threatfox") == 0
