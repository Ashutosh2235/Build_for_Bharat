#!/usr/bin/env python3
"""Export shared/*.yaml → android/app/src/main/assets/*.json (the app ships JSON, not YAML).

Run after editing rules:  python tools/export_rules.py
CI fails if the committed JSON is stale:  python tools/export_rules.py --check
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "shared"
DST = ROOT / "android" / "app" / "src" / "main" / "assets"
FILES = ("rules", "brands")


def render(name: str) -> str:
    data = yaml.safe_load((SRC / f"{name}.yaml").read_text(encoding="utf-8"))
    return json.dumps(data, ensure_ascii=False, indent=1, sort_keys=True) + "\n"


def main() -> int:
    check = "--check" in sys.argv
    DST.mkdir(parents=True, exist_ok=True)
    stale = []
    for name in FILES:
        out = DST / f"{name}.json"
        text = render(name)
        if check:
            if not out.exists() or out.read_text(encoding="utf-8") != text:
                stale.append(out)
        else:
            out.write_text(text, encoding="utf-8")
            print(f"wrote {out.relative_to(ROOT)}")
    if stale:
        print("stale (run tools/export_rules.py):", *map(str, stale), sep="\n  ")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
