"""Network-side URL intelligence: SSRF-safe redirect expansion and RDAP domain age.

Everything here touches untrusted URLs, so:
  * never follow redirects automatically — each hop is resolved and checked first;
  * never send cookies/credentials; small timeouts; no response bodies are read.
"""
from __future__ import annotations

import asyncio
import ipaddress
import socket
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urljoin, urlsplit

import httpx

from app.core.config import get_settings

UA_MOBILE = ("Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 "
             "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36")
MAX_HOPS = 10


class BlockedDestination(Exception):
    pass


def _is_public(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast
                or addr.is_reserved or addr.is_unspecified or
                (isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None
                 and not _is_public(str(addr.ipv4_mapped))))


async def assert_public_host(host: str, port: int | None = None) -> None:
    """Raise BlockedDestination if the host resolves to any non-public address (SSRF guard)."""
    host = host.strip("[]")
    try:
        ipaddress.ip_address(host)
        ips = [host]
    except ValueError:
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(host, port or 443, type=socket.SOCK_STREAM)
        except socket.gaierror as e:
            raise BlockedDestination(f"DNS failure for {host}") from e
        ips = list({i[4][0] for i in infos})
    for ip in ips:
        if not _is_public(ip):
            raise BlockedDestination(f"{host} resolves to non-public address {ip}")


@dataclass
class ExpandResult:
    input: str
    final_url: str
    hops: list[dict] = field(default_factory=list)   # [{url, status}]
    error: str | None = None

    @property
    def cross_domain(self) -> bool:
        hosts = {urlsplit(h["url"]).hostname for h in self.hops}
        return len(hosts) > 1


async def expand_url(url: str, client: httpx.AsyncClient | None = None,
                     resolver=assert_public_host) -> ExpandResult:
    """Follow redirects hop by hop (HEAD, falling back to GET), recording the chain."""
    s = get_settings()
    own = client is None
    client = client or httpx.AsyncClient(timeout=s.http_timeout_s, follow_redirects=False,
                                         headers={"User-Agent": UA_MOBILE})
    res = ExpandResult(input=url, final_url=url)
    current = url
    try:
        for _ in range(MAX_HOPS):
            parts = urlsplit(current)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                res.error = f"unsupported url {current}"
                break
            await resolver(parts.hostname, parts.port)
            resp = await client.head(current)
            if resp.status_code in (403, 405, 501) or (resp.status_code >= 400 and resp.status_code != 404):
                async with client.stream("GET", current) as r2:   # body never read
                    resp = r2
            res.hops.append({"url": current, "status": resp.status_code})
            loc = resp.headers.get("location")
            if resp.status_code in (301, 302, 303, 307, 308) and loc:
                current = urljoin(current, loc)
                res.final_url = current
                continue
            break
        else:
            res.error = "too many redirects"
    except BlockedDestination as e:
        res.error = f"blocked: {e}"
    except httpx.HTTPError as e:
        res.error = f"{type(e).__name__}: {e}"[:200]
    finally:
        if own:
            await client.aclose()
    return res


_rdap_cache: dict[str, tuple[float, int | None]] = {}
RDAP_TTL_S = 7 * 24 * 3600


async def domain_age_days(domain: str, client: httpx.AsyncClient | None = None) -> int | None:
    """Days since registration via RDAP (rdap.org bootstrap). None if unknown."""
    now = time.time()
    hit = _rdap_cache.get(domain)
    if hit and now - hit[0] < RDAP_TTL_S:
        return hit[1]
    s = get_settings()
    own = client is None
    client = client or httpx.AsyncClient(timeout=s.http_timeout_s, follow_redirects=True)
    age: int | None = None
    try:
        r = await client.get(f"https://rdap.org/domain/{domain}", headers={"Accept": "application/rdap+json"})
        if r.status_code == 200:
            for ev in r.json().get("events", []):
                if ev.get("eventAction") == "registration" and ev.get("eventDate"):
                    created = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                    age = max(0, (datetime.now(UTC) - created).days)
                    break
    except (httpx.HTTPError, ValueError):
        age = None
    finally:
        if own:
            await client.aclose()
    _rdap_cache[domain] = (now, age)
    return age
