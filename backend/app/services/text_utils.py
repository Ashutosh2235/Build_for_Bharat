"""Small helpers shared by the analyzers (mirrored in Android core/security/TextUtils.kt)."""
from __future__ import annotations

import hashlib

_SKELETON = (("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("4", "a"), ("5", "s"), ("7", "t"), ("8", "b"), ("i", "l"))


def levenshtein(a: str, b: str, limit: int = 3) -> int:
    """Edit distance, early-exit once it exceeds `limit` (returns limit + 1)."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        row_min = cur[0]
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
            row_min = min(row_min, cur[j])
        if row_min > limit:
            return limit + 1
        prev = cur
    return prev[-1]


def skeleton(s: str) -> str:
    """Collapse common homoglyph / leetspeak substitutions: 'hdfcbanl<' style tricks."""
    s = s.lower()
    for a, b in _SKELETON:
        s = s.replace(a, b)
    return s


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def domain_hash(domain: str) -> str:
    """Hash shipped to devices for blocklist lookups (first 16 hex chars of sha256)."""
    return sha256_hex(domain.lower().strip("."))[:16]
