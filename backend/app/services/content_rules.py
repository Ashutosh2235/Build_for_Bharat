"""Content analysis: keyword/regex categories from shared/rules.yaml."""
from __future__ import annotations

import re
import unicodedata

from app.services.ruleset import RuleSet
from app.services.signals import Signal


def normalize_text(text: str) -> str:
    """NFKC (folds full-width / styled Unicode letters scammers use), collapse whitespace."""
    text = unicodedata.normalize("NFKC", text)
    return re.sub(r"\s+", " ", text).strip()


def content_signals(text: str, rs: RuleSet) -> list[Signal]:
    t = normalize_text(text)
    out: list[Signal] = []
    for cat in rs.content.values():
        subject = t
        for neg in cat.negations:
            subject = neg.sub(" ", subject)
        if any(p.search(subject) for p in cat.patterns):
            out.append(Signal(cat.code, cat.points, cat.text, "content", group=cat.group))
    return out


def signals_from_device_codes(codes: list[str], rs: RuleSet) -> list[Signal]:
    """When the message text is NOT shared (privacy default), trust the device's
    content category codes, but take the points/text from the server rule set."""
    out = []
    for code in dict.fromkeys(codes):
        cat = rs.content.get(code)
        if cat:
            out.append(Signal(cat.code, cat.points, cat.text, "device", group=cat.group))
    return out


def claims_brand(text: str, rs: RuleSet) -> bool:
    t = normalize_text(text)
    return any(p.search(t) for p in rs.brand_claim)


def brands_mentioned(text: str, rs: RuleSet) -> list[str]:
    """Brand ids whose tokens appear as whole words in the text (for report routing)."""
    t = normalize_text(text).lower()
    found = []
    for b in rs.brands.values():
        for tok in b.tokens:
            if len(tok) >= 3 and re.search(rf"(?<![a-z0-9]){re.escape(tok)}(?![a-z0-9])", t):
                found.append(b.id)
                break
    return found
