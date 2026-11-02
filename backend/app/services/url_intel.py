"""URL extraction + static (offline) URL analysis. Mirrored in Android UrlExtractor.kt / UrlHeuristics.kt."""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from functools import lru_cache
from urllib.parse import urlsplit

from app.services.ruleset import RuleSet
from app.services.signals import Signal
from app.services.text_utils import levenshtein, skeleton

TRAILING = ".,;:!?)]}'\"»”’>"


@lru_cache(maxsize=4)
def _extract_re(tlds: tuple[str, ...]) -> re.Pattern[str]:
    tld_alt = "|".join(sorted((re.escape(t) for t in tlds), key=len, reverse=True))
    return re.compile(
        r"(?:https?://|www\.)[^\s<>\"']+"
        r"|upi://[^\s<>\"']+"
        r"|(?<![@\w.])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:" + tld_alt + r")(?![a-z0-9-])(?::\d{2,5})?(?:/[^\s<>\"']*)?",
        re.IGNORECASE,
    )


def extract_urls(text: str, rs: RuleSet) -> list[str]:
    out: list[str] = []
    for m in _extract_re(rs.common_tlds).finditer(text or ""):
        u = m.group(0).rstrip(TRAILING)
        if u and u.lower() not in (x.lower() for x in out):
            out.append(u)
    return out


@dataclass
class ParsedUrl:
    raw: str
    url: str                  # normalized, with scheme
    scheme: str
    host: str                 # lowercase, IDNA (punycode) form
    path: str
    registered_domain: str
    tld: str
    had_scheme: bool
    has_userinfo: bool
    is_ip: bool
    is_upi: bool = False
    upi_payee: str | None = None
    unicode_host: bool = False


def registered_domain(host: str, rs: RuleSet) -> str:
    labels = [x for x in host.lower().strip(".").split(".") if x]
    if len(labels) <= 2:
        return ".".join(labels)
    last2 = ".".join(labels[-2:])
    last3 = ".".join(labels[-3:])
    if last3 in rs.multi_suffixes and len(labels) >= 4:
        return ".".join(labels[-4:])
    if last2 in rs.multi_suffixes:
        return last3
    return last2


def parse_url(raw: str, rs: RuleSet) -> ParsedUrl | None:
    raw = raw.strip()
    if raw.lower().startswith("upi://"):
        payee = re.search(r"[?&]pa=([^&\s]+)", raw, re.IGNORECASE)
        return ParsedUrl(raw, raw, "upi", "", "", "", "", True, False, False, True,
                         payee.group(1) if payee else None)
    had_scheme = bool(re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.IGNORECASE))
    url = raw if had_scheme else "http://" + raw
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
    except ValueError:
        return None
    if not host:
        return None
    unicode_host = any(ord(c) > 127 for c in host)
    try:
        host_ascii = host.encode("idna").decode("ascii") if unicode_host else host
    except UnicodeError:
        host_ascii = host
    host_ascii = host_ascii.lower().strip(".")
    is_ip = False
    try:
        ipaddress.ip_address(host_ascii.strip("[]"))
        is_ip = True
    except ValueError:
        pass
    reg = host_ascii if is_ip else registered_domain(host_ascii, rs)
    tld = "" if is_ip else host_ascii.rsplit(".", 1)[-1]
    norm = f"{parts.scheme.lower()}://{host_ascii}{(':' + str(parts.port)) if parts.port else ''}{parts.path or '/'}"
    if parts.query:
        norm += "?" + parts.query
    return ParsedUrl(raw, norm, parts.scheme.lower(), host_ascii, parts.path or "/", reg, tld,
                     had_scheme, "@" in (parts.netloc or ""), is_ip, unicode_host=unicode_host)


def official_brand(p: ParsedUrl, rs: RuleSet) -> str | None:
    """Brand id if the host is an official domain (or a subdomain of one)."""
    host = p.host
    for dom, bid in rs.official_domains.items():
        if host == dom or host.endswith("." + dom):
            return bid
    for suf in rs.trusted_suffixes:
        if host.endswith("." + suf):
            return "TRUSTED_SUFFIX"
    return None


def lookalike_brand(p: ParsedUrl, rs: RuleSet) -> str | None:
    """Brand id this (non-official) host imitates, if any."""
    if p.is_ip or not p.host:
        return None
    host_no_suffix = p.host
    reg = p.registered_domain
    reg_label = reg.split(".")[0]
    # labels of subdomains + registered label, split on '-' as well
    parts = [x for x in re.split(r"[-.]", host_no_suffix[: len(host_no_suffix) - len(reg)] + reg_label) if x]
    for b in rs.brands.values():
        for tok in b.tokens:
            if len(tok) < 3:
                continue
            for part in parts:
                if part == tok or (len(tok) >= 5 and tok in part):
                    return b.id
        for dom in b.domains:
            off_label = dom.split(".")[0]
            if len(off_label) < 6 or reg_label == off_label:
                continue
            max_dist = 1 if len(off_label) < 8 else 2
            if levenshtein(reg_label, off_label, max_dist) <= max_dist:
                return b.id
            if skeleton(reg_label) == skeleton(off_label) and reg_label != off_label:
                return b.id
    return None


@dataclass
class UrlStatic:
    parsed: ParsedUrl
    signals: list[Signal] = field(default_factory=list)
    official: str | None = None
    imitates: str | None = None


def static_url_signals(raw: str, rs: RuleSet) -> UrlStatic | None:
    p = parse_url(raw, rs)
    if p is None:
        return None
    res = UrlStatic(p)
    sig = res.signals
    if p.is_upi:
        sig.append(Signal("UPI_LINK", 0, "Contains a UPI payment link", "url", detail=p.upi_payee))
        return res

    res.official = official_brand(p, rs)
    if res.official:
        sig.append(Signal("OFFICIAL_DOMAIN", rs.pts("OFFICIAL_DOMAIN"),
                          f"Link goes to an official domain ({p.registered_domain})", "url", detail=p.host))
    else:
        res.imitates = lookalike_brand(p, rs)
        if res.imitates:
            sig.append(Signal("LOOKALIKE_DOMAIN", rs.pts("LOOKALIKE_DOMAIN"),
                              f"Link imitates {rs.brands[res.imitates].name} ({p.host})", "url", detail=p.host))
    if p.is_ip or p.has_userinfo or "xn--" in p.host or p.unicode_host:
        sig.append(Signal("IP_OR_PUNYCODE_URL", rs.pts("IP_OR_PUNYCODE_URL"),
                          "Link hides its real address (IP address, look-alike characters or '@' trick)", "url",
                          detail=p.host))
    ext = p.path.rsplit(".", 1)[-1].lower() if "." in p.path.rsplit("/", 1)[-1] else ""
    if ext in rs.download_extensions:
        sig.append(Signal("DOWNLOAD_LINK", rs.pts("DOWNLOAD_LINK"),
                          f"Link downloads a file (.{ext}) — scam apps are spread this way", "url", detail=p.url))
    if p.host in rs.shorteners:
        sig.append(Signal("SHORTENER", rs.pts("SHORTENER"), "Uses a link shortener that hides the destination",
                          "url", detail=p.host))
    if p.host in rs.messaging_hosts:
        sig.append(Signal("MESSAGING_LINK", rs.pts("MESSAGING_LINK"),
                          "Moves the conversation to WhatsApp/Telegram", "url", detail=p.host))
    if p.had_scheme and p.scheme == "http" and not res.official:
        sig.append(Signal("NO_HTTPS", rs.pts("NO_HTTPS"), "Link is not encrypted (http)", "url", detail=p.host))
    if p.tld in rs.risky_tlds and not res.official:
        sig.append(Signal("RISKY_TLD", rs.pts("RISKY_TLD"), f"Uses a domain ending (.{p.tld}) common in scams",
                          "url", detail=p.host))
    return res
