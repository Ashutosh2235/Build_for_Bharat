"""Client for the isolated Playwright sandbox service (sandbox/server.py)."""
from __future__ import annotations

import logging

import httpx

from app.core.config import get_settings

log = logging.getLogger(__name__)


async def visit(url: str, client: httpx.AsyncClient | None = None) -> dict | None:
    s = get_settings()
    if not s.sandbox_enabled:
        return None
    own = client is None
    client = client or httpx.AsyncClient(timeout=s.sandbox_timeout_s)
    try:
        r = await client.post(f"{s.sandbox_url.rstrip('/')}/visit", json={"url": url})
        r.raise_for_status()
        return r.json()
    except (httpx.HTTPError, ValueError) as e:
        log.warning("sandbox visit failed: %s", e)
        return {"error": str(e)[:200]}
    finally:
        if own:
            await client.aclose()
