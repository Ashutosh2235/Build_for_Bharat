"""The ONLY place a message is labelled (shared/rules.yaml → fraud_evidence).

A decision is made only once the scan is complete — the sender database, the threat feeds and every
link check have been consulted. Before that, and whenever the evidence isn't strong enough, the
answer is "show nothing".

    PENDING  checks still running             → app shows nothing
    FRAUD    "Surely fraud": score ≥ threshold AND confirmed by a database or a link check
    SPAM     "Surely spam":  score ≥ threshold, strong sender/wording signs, but nothing confirmed it
    NONE     not enough evidence               → app shows nothing
"""
from __future__ import annotations

from app.services.ruleset import RuleSet
from app.services.scorer import ScoreResult

PENDING, FRAUD, SPAM, NONE = "PENDING", "FRAUD", "SPAM", "NONE"
LABELS = {FRAUD: "Surely fraud", SPAM: "Surely spam"}


def evidence(result: ScoreResult, rs: RuleSet) -> list[str]:
    return [s.code for s in result.signals if s.code in rs.fraud_evidence and (s.points > 0 or s.absolute)]


def decide(result: ScoreResult, rs: RuleSet, *, complete: bool) -> str:
    if not complete:
        return PENDING
    if result.score < rs.threshold_scam:
        return NONE
    return FRAUD if evidence(result, rs) else SPAM
