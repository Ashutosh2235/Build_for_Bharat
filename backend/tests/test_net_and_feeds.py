import json

import httpx
import pytest
from app.feeds import parsers
from app.services.net_intel import BlockedDestination, _is_public, assert_public_host, expand_url


async def allow_all(host, port=None):
    return None


async def test_expand_follows_redirect_chain():
    routes = {
        "http://bit.ly/x": (301, "https://mid.example.org/r?a=1"),
        "https://mid.example.org/r?a=1": (302, "/final"),
        "https://mid.example.org/final": (200, None),
    }

    def handler(req: httpx.Request):
        status, loc = routes[str(req.url)]
        return httpx.Response(status, headers={"location": loc} if loc else {})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        res = await expand_url("http://bit.ly/x", client=c, resolver=allow_all)
    assert res.final_url == "https://mid.example.org/final"
    assert [h["status"] for h in res.hops] == [301, 302, 200]
    assert res.cross_domain and res.error is None


async def test_expand_falls_back_to_get_when_head_rejected():
    def handler(req):
        if req.method == "HEAD":
            return httpx.Response(405)
        return httpx.Response(302, headers={"location": "https://x.example.org/"}) if "y.example" in str(req.url) \
            else httpx.Response(200)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        res = await expand_url("https://y.example.org/", client=c, resolver=allow_all)
    assert res.final_url == "https://x.example.org/"


async def test_ssrf_guard_blocks_private_hops():
    def handler(req):
        return httpx.Response(302, headers={"location": "http://169.254.169.254/latest/meta-data"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        res = await expand_url("https://8.8.8.8/", client=c)  # real guard, IP literals need no DNS
    assert res.error and res.error.startswith("blocked")
    assert res.final_url == "http://169.254.169.254/latest/meta-data"  # recorded, never requested


@pytest.mark.parametrize("ip,public", [("8.8.8.8", True), ("10.0.0.1", False), ("127.0.0.1", False),
                                       ("169.254.169.254", False), ("172.18.0.3", False), ("::1", False),
                                       ("::ffff:10.0.0.1", False), ("2606:4700:4700::1111", True)])
def test_is_public(ip, public):
    assert _is_public(ip) is public


async def test_assert_public_host_rejects_loopback():
    with pytest.raises(BlockedDestination):
        await assert_public_host("127.0.0.1")


def test_feed_parsers():
    assert list(parsers.parse_url_lines("https://Evil.example.com/Login/\n# comment\n\nevil2.top/x")) == [
        ("evil.example.com/Login", "url"), ("evil2.top/x", "url")]
    assert list(parsers.parse_domain_lines("Bad.Example.COM\nnot a domain\n#x\nfoo")) == [("bad.example.com", "domain")]
    data = json.dumps({"query_status": "ok", "urls": [{"url": "http://1.2.3.4/mozi.m"}, {"url": ""}]})
    assert list(parsers.parse_urlhaus_json(data)) == [("1.2.3.4/mozi.m", "url")]
    items = [("docs.google.com", "domain"), ("evil.com", "domain"), ("docs.google.com/forms/x", "url")]
    assert list(parsers.filter_allowlisted(items, {"google.com"})) == [("evil.com", "domain"), ("docs.google.com/forms/x", "url")]
