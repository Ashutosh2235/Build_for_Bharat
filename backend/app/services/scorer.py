"""Deterministic, explainable scoring (context file §5.4). Mirrored in Android LocalScorer.kt."""
from __future__ import annotations

from dataclasses import dataclass

from app.services.ruleset import RuleSet
from app.services.signals import WEAK_CODES, Signal


@dataclass
class ScoreResult:
    score: int
    verdict: str                  # SAFE | SUSPICIOUS | SCAM
    auto_report: bool
    signals: list[Signal]         # de-duplicated, in display order

    @property
    def reasons(self) -> list[dict]:
        return [s.to_reason() for s in self.signals]


def dedupe(signals: list[Signal]) -> list[Signal]:
    """One signal per code (keep the strongest); absolute ones first, then by points."""
    best: dict[str, Signal] = {}
    for s in signals:
        cur = best.get(s.code)
        if cur is None or (s.absolute, abs(s.points)) > (cur.absolute, abs(cur.points)):
            best[s.code] = s
    return sorted(best.values(), key=lambda s: (not s.absolute, -s.points))


def score(signals: list[Signal], rs: RuleSet) -> ScoreResult:
    sigs = dedupe(signals)
    absolute = any(s.absolute for s in sigs)

    weak = sum(s.points for s in sigs if s.code in WEAK_CODES and s.points > 0)
    weak = min(weak, rs.weak_signal_cap)

    grouped: dict[str, int] = {}
    strong = 0
    for s in sigs:
        if s.code in WEAK_CODES or s.points <= 0:
            continue
        if s.group:
            grouped[s.group] = max(grouped.get(s.group, 0), s.points)
        else:
            strong += s.points
    strong += sum(grouped.values())

    negative = sum(s.points for s in sigs if s.points < 0 and s.code != "OFFICIAL_DOMAIN")
    # An official destination only lowers risk when nothing else is wrong.
    if strong == 0 and any(s.code == "OFFICIAL_DOMAIN" for s in sigs):
        negative += rs.pts("OFFICIAL_DOMAIN")

    total = 100 if absolute else max(0, min(100, strong + weak + negative))
    if total >= rs.threshold_scam:
        verdict = "SCAM"
    elif total >= rs.threshold_suspicious:
        verdict = "SUSPICIOUS"
    else:
        verdict = "SAFE"
    auto = verdict == "SCAM" and (absolute or total >= rs.threshold_auto_report)
    shown = [s for s in sigs if s.points != 0 or s.absolute or s.code == "UPI_LINK"]
    return ScoreResult(total, verdict, auto, shown)
