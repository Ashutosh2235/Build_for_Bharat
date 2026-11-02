"""Pure parsers for each feed format → (indicator, type) pairs. No network here (unit-testable)."""
from __future__ import annotations

import json
from collections.abc import Iterable, Iterator
from urllib.parse import urlsplit


def url_key(url: str) -> str | None:
    """Canonical key for URL indicators: host + path (+query), lowercase host, no scheme, no trailing '/'."""
    u = url.strip()
    if not u or u.startswith("#"):
        return None
    if "://" not in u:
        u = "http://" + u
    try:
        p = urlsplit(u)
        host = (p.hostname or "").lower().strip(".")
    except ValueError:
        return None
    if not host:
        return None
    key = host + (p.path or "")
    if p.query:
        key += "?" + p.query
    return key.rstrip("/")


def _clean_domain(line: str) -> str | None:
    d = line.strip().lower().strip(".")
    if not d or d.startswith("#") or " " in d or "/" in d or "." not in d:
        return None
    return d


def parse_url_lines(text: str) -> Iterator[tuple[str, str]]:
    """OpenPhish feed.txt, Phishing.Database links lists: one URL per line."""
    for line in text.splitlines():
        k = url_key(line)
        if k:
            yield k, "url"


def parse_domain_lines(text: str) -> Iterator[tuple[str, str]]:
    """Phishing.Database domains list: one domain per line."""
    for line in text.splitlines():
        d = _clean_domain(line)
        if d:
            yield d, "domain"


def parse_urlhaus_json(text: str) -> Iterator[tuple[str, str]]:
    """URLhaus API /v1/urls/recent/ JSON."""
    data = json.loads(text)
    for row in data.get("urls", []) or []:
        k = url_key(row.get("url", ""))
        if k:
            yield k, "url"


def parse_threatfox_json(text: str) -> Iterator[tuple[str, str]]:
    """ThreatFox API `get_iocs` JSON: ioc_type is domain | url | ip:port (others ignored)."""
    data = json.loads(text)
    if data.get("query_status") != "ok":
        return
    for row in data.get("data", []) or []:
        ioc, typ = (row.get("ioc") or "").strip(), row.get("ioc_type")
        if not ioc:
            continue
        if typ == "domain":
            d = _clean_domain(ioc)
            if d:
                yield d, "domain"
        elif typ == "url":
            k = url_key(ioc)
            if k:
                yield k, "url"
        elif typ == "ip:port":
            yield ioc.rsplit(":", 1)[0].strip("[]"), "ip"


def parse_phishunt_json(text: str) -> Iterator[tuple[str, str]]:
    """phishunt.io /api/v1/domains JSON → URL and domain indicators."""
    data = json.loads(text)
    for row in data.get("results", []) or []:
        k = url_key(row.get("url") or "")
        if k:
            yield k, "url"
        d = _clean_domain(row.get("domain") or "")
        if d:
            yield d, "domain"


def filter_allowlisted(items: Iterable[tuple[str, str]], allow: set[str]) -> Iterator[tuple[str, str]]:
    """Drop DOMAIN entries for big shared platforms/official brands (a phishing page on
    docs.google.com must not blacklist all of Google). URL entries stay — they're specific."""
    for ind, typ in items:
        if typ == "domain" and (ind in allow or any(ind.endswith("." + a) for a in allow)):
            continue
        yield ind, typ
