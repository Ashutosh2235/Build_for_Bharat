"""Signal = one explainable reason that adds (or removes) risk points."""
from __future__ import annotations

from dataclasses import asdict, dataclass

# Signals whose points are pooled and capped together (rules.yaml: weak_signal_cap)
WEAK_CODES = frozenset({"URGENCY", "NO_HTTPS", "RISKY_TLD", "SHORTENER", "MESSAGING_LINK"})


@dataclass(frozen=True)
class Signal:
    code: str
    points: int
    text: str
    source: str                 # sender | content | url | deep | classifier | db | device
    absolute: bool = False      # instant SCAM (feed hit, blocked sender)
    group: str | None = None    # categories in one group don't stack
    detail: str | None = None   # e.g. the URL or brand that triggered it

    def to_reason(self) -> dict:
        d = {"code": self.code, "text": self.text, "points": self.points}
        if self.detail:
            d["detail"] = self.detail
        return d

    def as_dict(self) -> dict:
        return asdict(self)
