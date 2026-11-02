"""Who a report would go to (data/authorities.yaml)."""
from __future__ import annotations

from functools import lru_cache

import yaml

from app.core.config import get_settings


@lru_cache
def authorities() -> dict:
    path = get_settings().data_dir / "authorities.yaml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def intended_recipients(state_code: str | None, brand_id: str | None) -> list[dict]:
    """[{kind, label, address, verified}] — verified=False addresses are never emailed in live mode."""
    a = authorities()
    out: list[dict] = []
    cell = (a.get("state_cyber_cells") or {}).get((state_code or "").upper())
    if cell:
        for e in cell.get("emails", []):
            out.append({"kind": "state_cyber_cell", "label": cell["label"], "address": e["address"],
                        "verified": bool(e.get("verified"))})
    contact = (a.get("brand_fraud_contacts") or {}).get(brand_id or "")
    if contact:
        for e in contact.get("emails", []):
            out.append({"kind": "brand", "label": contact["label"], "address": e["address"],
                        "verified": bool(e.get("verified"))})
    return out


def portals() -> list[dict]:
    return list(authorities().get("national_portals") or [])
