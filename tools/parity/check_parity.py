#!/usr/bin/env python3
"""Compare the Android (Kotlin) scanner with the Python backend on the same corpus.

Usage: python tools/parity/check_parity.py <kotlin-output.jsonl> [corpus.jsonl]
The Kotlin output comes from Parity.kt (see tools/parity/run_parity.sh).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "backend"))

from app.services.content_rules import claims_brand, content_signals  # noqa: E402
from app.services.ruleset import get_ruleset  # noqa: E402
from app.services.scorer import score  # noqa: E402
from app.services.sender_intel import classify_sender, sender_signals  # noqa: E402
from app.services.url_intel import extract_urls, static_url_signals  # noqa: E402


def python_result(sender: str, text: str, rs) -> dict:
    cs = content_signals(text, rs)
    ss, _ = sender_signals(classify_sender(sender), rs, brand_claimed=claims_brand(text, rs),
                           content_codes={c.code for c in cs})
    urls = extract_urls(text, rs)
    us = [s for u in urls if (st := static_url_signals(u, rs)) for s in st.signals]
    r = score(cs + ss + us, rs)
    return {"score": r.score, "verdict": r.verdict, "codes": sorted(s.code for s in r.signals), "urls": urls}


def main() -> int:
    kotlin = [json.loads(x) for x in Path(sys.argv[1]).read_text().splitlines() if x.strip()]
    corpus_path = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "backend/tests/corpus/sms_corpus.jsonl"
    rows = [json.loads(x) for x in corpus_path.read_text(encoding="utf-8").splitlines() if x.strip()]
    rs = get_ruleset()
    bad = 0
    for row, k in zip(rows, kotlin, strict=True):
        p = python_result(row["sender"], row["text"], rs)
        if p != k:
            bad += 1
            print("MISMATCH:", row["text"][:80], "\n  python:", p, "\n  kotlin:", k)
    print(f"{len(rows) - bad}/{len(rows)} identical")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
