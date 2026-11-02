"""Quality gate on a labelled Indian SMS corpus (static analysis only — no network).
Positive = verdict SUSPICIOUS or SCAM. CI fails below the thresholds in the context file §14."""
import json
from pathlib import Path

from app.services.content_rules import claims_brand, content_signals
from app.services.ruleset import get_ruleset
from app.services.scorer import score
from app.services.sender_intel import classify_sender, sender_signals
from app.services.url_intel import extract_urls, static_url_signals

rs = get_ruleset()
CORPUS = Path(__file__).parent / "corpus" / "sms_corpus.jsonl"


def verdict(sender: str, text: str) -> str:
    cs = content_signals(text, rs)
    ss, _ = sender_signals(classify_sender(sender), rs, brand_claimed=claims_brand(text, rs),
                           content_codes={c.code for c in cs})
    us = [s for u in extract_urls(text, rs) for s in (static_url_signals(u, rs).signals if static_url_signals(u, rs) else [])]
    return score(cs + ss + us, rs).verdict


def test_corpus_precision_recall():
    rows = [json.loads(line) for line in CORPUS.read_text(encoding="utf-8").splitlines() if line.strip()]
    tp = fp = fn = 0
    misses = []
    for r in rows:
        v = verdict(r["sender"], r["text"])
        pos = v in ("SUSPICIOUS", "SCAM")
        if r["label"] == "scam":
            tp += pos
            fn += not pos
            if not pos:
                misses.append(("missed", v, r["text"][:70]))
        else:
            fp += pos
            if pos:
                misses.append(("false alarm", v, r["text"][:70]))
    precision = tp / (tp + fp) if tp + fp else 0
    recall = tp / (tp + fn) if tp + fn else 0
    print(f"\nprecision={precision:.2f} recall={recall:.2f} n={len(rows)}")
    for m in misses:
        print("  ", m)
    assert precision >= 0.9, misses
    assert recall >= 0.8, misses
