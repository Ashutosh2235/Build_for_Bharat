"""Loads shared/rules.yaml + shared/brands.yaml into typed, compiled structures.

The Android app loads the same data (exported to JSON) into identical structures in
`core/security/RuleSet.kt`. Keep the two in sync.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

from app.core.config import get_settings


@dataclass(frozen=True)
class ContentCategory:
    code: str
    points: int
    text: str
    group: str | None
    patterns: tuple[re.Pattern[str], ...]
    negations: tuple[re.Pattern[str], ...] = ()


@dataclass(frozen=True)
class Brand:
    id: str
    name: str
    category: str
    tokens: tuple[str, ...]
    domains: tuple[str, ...]
    headers: tuple[tuple[str, bool], ...]  # (HEADER, verified)


@dataclass
class RuleSet:
    version: int
    content: dict[str, ContentCategory]
    brand_claim: tuple[re.Pattern[str], ...]
    shorteners: frozenset[str]
    risky_tlds: frozenset[str]
    common_tlds: tuple[str, ...]
    multi_suffixes: frozenset[str]
    download_extensions: frozenset[str]
    messaging_hosts: frozenset[str]
    points: dict[str, int]
    weak_signal_cap: int
    threshold_suspicious: int
    threshold_scam: int
    threshold_auto_report: int
    brands: dict[str, Brand]
    trusted_suffixes: tuple[str, ...]
    fraud_evidence: frozenset[str] = frozenset()
    # derived
    official_domains: dict[str, str] = field(default_factory=dict)   # domain -> brand id
    header_index: dict[str, tuple[str, bool]] = field(default_factory=dict)  # HEADER -> (brand, verified)

    def pts(self, code: str) -> int:
        return self.points[code]


def _compile(patterns: list[str]) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p, re.IGNORECASE | re.UNICODE) for p in patterns)


def load_ruleset(shared_dir: Path) -> RuleSet:
    rules = yaml.safe_load((shared_dir / "rules.yaml").read_text(encoding="utf-8"))
    brands_doc = yaml.safe_load((shared_dir / "brands.yaml").read_text(encoding="utf-8"))

    content = {
        code: ContentCategory(
            code=code,
            points=int(c["points"]),
            text=c["text"],
            group=c.get("group"),
            patterns=_compile(c["patterns"]),
            negations=_compile(c.get("negations", [])),
        )
        for code, c in rules["content"].items()
    }
    url = rules["url"]
    brands = {
        bid: Brand(
            id=bid,
            name=b["name"],
            category=b["category"],
            tokens=tuple(t.lower() for t in b.get("tokens", [])),
            domains=tuple(d.lower() for d in b.get("domains", [])),
            headers=tuple((h["id"].upper(), bool(h.get("verified", False))) for h in b.get("headers", [])),
        )
        for bid, b in brands_doc["brands"].items()
    }
    rs = RuleSet(
        version=int(rules["version"]),
        content=content,
        brand_claim=_compile(rules["brand_claim_patterns"]),
        shorteners=frozenset(s.lower() for s in url["shorteners"]),
        risky_tlds=frozenset(t.lower() for t in url["risky_tlds"]),
        common_tlds=tuple(t.lower() for t in url["common_tlds"]),
        multi_suffixes=frozenset(s.lower() for s in url["multi_suffixes"]),
        download_extensions=frozenset(e.lower() for e in url["download_extensions"]),
        messaging_hosts=frozenset(h.lower() for h in url["messaging_hosts"]),
        points={k: int(v) for k, v in rules["points"].items()},
        weak_signal_cap=int(rules["weak_signal_cap"]),
        threshold_suspicious=int(rules["thresholds"]["suspicious"]),
        threshold_scam=int(rules["thresholds"]["scam"]),
        threshold_auto_report=int(rules["thresholds"]["auto_report"]),
        brands=brands,
        trusted_suffixes=tuple(s.lower() for s in brands_doc.get("trusted_suffixes", [])),
        fraud_evidence=frozenset(rules.get("fraud_evidence", [])),
    )
    for b in brands.values():
        for d in b.domains:
            rs.official_domains[d] = b.id
        for h, verified in b.headers:
            rs.header_index[h] = (b.id, verified)
    return rs


@lru_cache
def get_ruleset() -> RuleSet:
    return load_ruleset(get_settings().shared_dir)
