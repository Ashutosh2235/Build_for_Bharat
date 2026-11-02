"""Online link-reputation checks, run in parallel on each link's FINAL address (after redirects).

    Google Safe Browsing     needs GOOGLE_SAFEBROWSING_KEY (free, non-commercial)
    Quad9 threat DNS         no key — Quad9 refuses (NXDOMAIN) domains on its threat lists
    Cloudflare security DNS  no key — 1.1.1.2 answers 0.0.0.0 for malware/phishing domains
    Certificate history      no key — crt.sh: when was the domain's first HTTPS certificate issued

The DNS checks compare each operator's filtering resolver with its non-filtering one over
DNS-over-HTTPS (port 443, so they work on networks that block plain DNS / unusual ports).
The downloaded feeds (OpenPhish, URLhaus, ThreatFox, phishunt, Phishing.Database) are checked
separately from the local database (app/feeds/lookup.py).

Each check reports: hit | clean | unavailable (network/quota — the scan still completes) | skipped
(not configured). Only the link/hostname is ever sent — never the message text.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass
from datetime import UTC, datetime

import dns.message
import dns.rcode
import dns.rdatatype
import httpx

from app.core.config import get_settings
from app.services.url_intel import ParsedUrl

log = logging.getLogger(__name__)

HIT, CLEAN, UNAVAILABLE, SKIPPED = "hit", "clean", "unavailable", "skipped"
CACHE_TTL_S = 6 * 3600
SINKHOLE = {"0.0.0.0", "::", "127.0.0.1"}


@dataclass
class CheckResult:
    name: str                     # shown to the user
    status: str
    detail: str | None = None
    age_days: int | None = None   # certificate history only

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass(frozen=True)
class DnsProvider:
    label: str
    filtered: str      # DoH URL of the blocking resolver
    unfiltered: str    # DoH URL of the same operator's non-blocking resolver


DNS_PROVIDERS = {
    "quad9": DnsProvider("Quad9 threat DNS", "https://dns.quad9.net/dns-query", "https://dns10.quad9.net/dns-query"),
    "cloudflare": DnsProvider("Cloudflare security DNS", "https://security.cloudflare-dns.com/dns-query",
                              "https://cloudflare-dns.com/dns-query"),
}
SB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
SB_TYPES = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"]
CRTSH_URL = "https://crt.sh/"

_cache: dict[str, tuple[float, CheckResult]] = {}


def clear_cache() -> None:
    _cache.clear()


def _cached(key: str) -> CheckResult | None:
    hit = _cache.get(key)
    return hit[1] if hit and time.time() - hit[0] < CACHE_TTL_S else None


def _store(key: str, r: CheckResult) -> CheckResult:
    if r.status in (HIT, CLEAN):          # never cache failures
        _cache[key] = (time.time(), r)
    return r


# ----------------------------------------------------------------------------- Google Safe Browsing
async def safe_browsing(p: ParsedUrl, client: httpx.AsyncClient) -> CheckResult:
    name = "Google Safe Browsing"
    key = get_settings().google_safebrowsing_key
    if not key:
        return CheckResult(name, SKIPPED, "no API key configured")
    if (c := _cached(f"sb:{p.url}")):
        return c
    entries = list(dict.fromkeys([p.url, f"{p.scheme}://{p.host}/"]))
    body = {"client": {"clientId": "scamshield", "clientVersion": "0.2"},
            "threatInfo": {"threatTypes": SB_TYPES, "platformTypes": ["ANY_PLATFORM"],
                           "threatEntryTypes": ["URL"], "threatEntries": [{"url": u} for u in entries]}}
    r = await client.post(SB_ENDPOINT, params={"key": key}, json=body)
    if r.status_code != 200:
        return CheckResult(name, UNAVAILABLE, f"HTTP {r.status_code}")
    kinds = sorted({m.get("threatType", "UNKNOWN") for m in r.json().get("matches", []) or []})
    if kinds:
        return _store(f"sb:{p.url}", CheckResult(name, HIT, ", ".join(kinds)))
    return _store(f"sb:{p.url}", CheckResult(name, CLEAN))


# ----------------------------------------------------------------------------- protective DNS
async def _doh(client: httpx.AsyncClient, url: str, host: str) -> tuple[int, set[str]]:
    """(rcode, A-record addresses) via RFC 8484 DNS-over-HTTPS."""
    q = dns.message.make_query(host, dns.rdatatype.A)
    q.id = 0
    r = await client.post(url, content=q.to_wire(),
                          headers={"content-type": "application/dns-message", "accept": "application/dns-message"})
    r.raise_for_status()
    msg = dns.message.from_wire(r.content)
    return msg.rcode(), {rr.address for rrset in msg.answer if rrset.rdtype == dns.rdatatype.A for rr in rrset}


def dns_blocked(filtered: tuple[int, set[str]], unfiltered: tuple[int, set[str]]) -> bool:
    f_rcode, f_addrs = filtered
    u_rcode, u_addrs = unfiltered
    if not (u_rcode == dns.rcode.NOERROR and u_addrs - SINKHOLE):
        return False     # domain doesn't exist / no real address — nothing to compare
    return f_rcode == dns.rcode.NXDOMAIN or (bool(f_addrs) and f_addrs <= SINKHOLE)


def _dns_check(key: str):
    provider = DNS_PROVIDERS[key]

    async def check(p: ParsedUrl, client: httpx.AsyncClient) -> CheckResult:
        if p.is_ip:
            return CheckResult(provider.label, SKIPPED, "IP address, no domain")
        if (c := _cached(f"dns:{key}:{p.host}")):
            return c
        filtered, unfiltered = await asyncio.gather(_doh(client, provider.filtered, p.host),
                                                    _doh(client, provider.unfiltered, p.host))
        status = HIT if dns_blocked(filtered, unfiltered) else CLEAN
        return _store(f"dns:{key}:{p.host}",
                      CheckResult(provider.label, status, "domain blocked as malicious" if status == HIT else None))

    check.__name__ = f"dns_{key}"
    check.label = provider.label  # type: ignore[attr-defined]
    return check


# ----------------------------------------------------------------------------- certificate history
async def certificate_age(p: ParsedUrl, client: httpx.AsyncClient) -> CheckResult:
    """Days since the domain's FIRST certificate (Certificate Transparency logs via crt.sh)."""
    name = "Certificate history (crt.sh)"
    if p.is_ip or not p.registered_domain:
        return CheckResult(name, SKIPPED, "IP address, no domain")
    dom = p.registered_domain
    if (c := _cached(f"crt:{dom}")):
        return c
    r = await client.get(CRTSH_URL, params={"q": dom, "output": "json"})
    if r.status_code != 200:
        return CheckResult(name, UNAVAILABLE, f"HTTP {r.status_code}")
    dates = []
    for row in (r.json() if r.content.strip() else []):
        try:
            dates.append(datetime.fromisoformat(str(row["not_before"])).replace(tzinfo=UTC))
        except (KeyError, ValueError, TypeError):
            continue
    if not dates:
        return _store(f"crt:{dom}", CheckResult(name, CLEAN, "no certificates on record"))
    age = max(0, (datetime.now(UTC) - min(dates)).days)
    return _store(f"crt:{dom}", CheckResult(name, HIT if age < 30 else CLEAN,
                                            f"first certificate {age} day{'s' if age != 1 else ''} ago", age_days=age))


certificate_age.label = "Certificate history (crt.sh)"  # type: ignore[attr-defined]
safe_browsing.label = "Google Safe Browsing"  # type: ignore[attr-defined]


def providers() -> list:
    s = get_settings()
    out = [safe_browsing]
    if s.secure_dns_enabled:
        out += [_dns_check(k) for k in s.secure_dns_providers if k in DNS_PROVIDERS]
    if s.crtsh_enabled:
        out.append(certificate_age)
    return out


async def run_all(p: ParsedUrl, client: httpx.AsyncClient | None = None) -> list[CheckResult]:
    """Run every configured check concurrently. Never raises."""
    s = get_settings()
    own = client is None
    client = client or httpx.AsyncClient(timeout=s.link_check_timeout_s, follow_redirects=False,
                                         headers={"User-Agent": "ScamShield/0.2 link-reputation"})

    async def guarded(fn) -> CheckResult:
        try:
            return await asyncio.wait_for(fn(p, client), timeout=s.link_check_timeout_s + 2)
        except Exception as e:  # network, DNS, JSON, timeout
            log.info("link check %s unavailable: %s", fn.label, type(e).__name__)
            return CheckResult(fn.label, UNAVAILABLE, type(e).__name__)

    try:
        return list(await asyncio.gather(*(guarded(f) for f in providers())))
    finally:
        if own:
            await client.aclose()
