"""Sender analysis for Indian SMS senders (mirrored in Android SenderAnalyzer.kt).

Formats:
  DLT header : 'VM-HDFCBK', 'JD-HDFCBK-S'  (prefix = operator/circle, suffix P/S/T/G since May 2025)
  Bare header: 'HDFCBK' (some phones hide the prefix)
  Mobile     : '9876543210', '+919876543210', '09876543210'
  Intl       : '+92…', '+234…' or long non-Indian digit strings
  Short code : numeric, <= 6 digits
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from app.services.ruleset import RuleSet
from app.services.signals import Signal
from app.services.text_utils import levenshtein

HEADER_RE = re.compile(r"^([A-Z]{2})-([A-Z0-9]{3,9})(?:-([PSTG]))?$")
BARE_HEADER_RE = re.compile(r"^(?=.*[A-Z])[A-Z0-9]{3,9}$")

SENSITIVE_FOR_PROMO = frozenset({"OTP_REQUEST", "KYC_BLOCK_THREAT"})
COMMERCIAL_LURES = frozenset({"PRIZE_LOTTERY", "REFUND_CASHBACK", "JOB_LOAN_FEE"})


@dataclass(frozen=True)
class SenderInfo:
    raw: str
    norm: str            # stable key used in the DB / blocklist
    kind: str            # header | mobile | intl | short | other
    prefix: str | None = None
    header: str | None = None
    suffix: str | None = None

    @property
    def is_header(self) -> bool:
        return self.kind == "header"


def classify_sender(raw: str) -> SenderInfo:
    s = (raw or "").strip()
    up = s.upper().replace(" ", "")
    m = HEADER_RE.match(up)
    if m:
        prefix, header, suffix = m.group(1), m.group(2), m.group(3)
        return SenderInfo(raw, f"HDR:{header}", "header", prefix, header, suffix)

    digits = re.sub(r"[^\d]", "", s)
    plus = s.startswith("+") or s.startswith("00")
    if digits:
        if s.startswith("00"):
            digits = digits[2:]
        if len(digits) <= 6 and not plus:
            return SenderInfo(raw, f"SHORT:{digits}", "short")
        if len(digits) == 10 and digits[0] in "6789" and not plus:
            return SenderInfo(raw, f"+91{digits}", "mobile")
        if len(digits) == 11 and digits.startswith("0") and digits[1] in "6789":
            return SenderInfo(raw, f"+91{digits[1:]}", "mobile")
        if len(digits) == 12 and digits.startswith("91") and digits[2] in "6789":
            return SenderInfo(raw, f"+91{digits[2:]}", "mobile")
        if plus or len(digits) > 10:
            return SenderInfo(raw, f"+{digits}", "intl")
        if re.fullmatch(r"[\d+\-\s()]+", s):
            return SenderInfo(raw, f"NUM:{digits}", "other")

    if BARE_HEADER_RE.match(up):
        return SenderInfo(raw, f"HDR:{up}", "header", None, up, None)
    return SenderInfo(raw, f"RAW:{up}", "other")


def _header_brand(header: str, rs: RuleSet, suffix: str | None = None) -> tuple[str | None, bool, str | None]:
    """Returns (brand_id, is_known_exact, impersonated_brand_id).
    Token matches are skipped for -G headers (government category needs DLT verification)."""
    known = rs.header_index.get(header)
    if known:
        return known[0], True, None
    h = header.lower()
    for kh, (bid, _verified) in rs.header_index.items():
        if len(kh) >= 5 and levenshtein(h, kh.lower(), 2) <= 1:
            return None, False, bid
    if suffix == "G":
        return None, False, None
    for b in rs.brands.values():
        for tok in b.tokens:
            if len(tok) >= 3 and tok in h:
                return None, False, b.id
    return None, False, None


def sender_signals(
    info: SenderInfo,
    rs: RuleSet,
    *,
    brand_claimed: bool,
    content_codes: set[str],
    in_contacts: bool = False,
) -> tuple[list[Signal], str | None]:
    """Returns signals + brand id this sender is impersonating (if any)."""
    out: list[Signal] = []
    impersonated: str | None = None

    if info.kind == "mobile" and brand_claimed and not in_contacts:
        out.append(Signal("MOBILE_BRAND_CLAIM", rs.pts("MOBILE_BRAND_CLAIM"),
                          "Claims to be a bank/company/government office but comes from a personal mobile number",
                          "sender", detail=info.norm))
    elif info.kind == "mobile" and not in_contacts and content_codes & COMMERCIAL_LURES:
        out.append(Signal("MOBILE_COMMERCIAL", rs.pts("MOBILE_COMMERCIAL"),
                          "Prize, job, loan or refund offer from a personal number — genuine businesses use registered sender IDs",
                          "sender", detail=info.norm))
    elif info.kind == "intl":
        out.append(Signal("INTL_SENDER", rs.pts("INTL_SENDER"),
                          "Sent from an international number", "sender", detail=info.norm))
    elif info.kind == "header" and info.header:
        _brand, known, imp = _header_brand(info.header, rs, info.suffix)
        if imp:
            impersonated = imp
            out.append(Signal("HEADER_IMPERSONATION", rs.pts("HEADER_IMPERSONATION"),
                              f"Sender ID '{info.header}' looks like {rs.brands[imp].name} but is not its registered header",
                              "sender", detail=info.header))
        if info.suffix == "P" and content_codes & SENSITIVE_FOR_PROMO:
            out.append(Signal("HEADER_SUFFIX_MISMATCH", rs.pts("HEADER_SUFFIX_MISMATCH"),
                              "Promotional sender (-P) is asking about OTP/KYC/account security", "sender",
                              detail=info.raw))

    if in_contacts:
        out.append(Signal("IN_CONTACTS", rs.pts("IN_CONTACTS"), "Sender is in your contacts", "sender"))
    return out, impersonated
