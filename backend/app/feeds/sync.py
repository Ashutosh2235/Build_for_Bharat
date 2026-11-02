"""Feed sync: download → parse → upsert into feed_entries.

Run manually:   python -m app.feeds.sync [openphish|phishing_db|urlhaus|all]
In production the worker's beat schedule runs it (hourly / daily).
"""
from __future__ import annotations

import asyncio
import logging
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass

import httpx
from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.db import create_all, sessionmaker
from app.feeds import parsers
from app.models import FeedEntry, utcnow
from app.services.ruleset import get_ruleset

log = logging.getLogger(__name__)
CHUNK = 2000


@dataclass(frozen=True)
class FeedSpec:
    name: str
    url_attr: str                      # Settings attribute holding the URL
    parser: Callable[[str], Iterable[tuple[str, str]]]
    needs_key: str | None = None       # Settings attribute that must be non-empty
    header: str | None = None          # header name for the key
    max_age_days: int = 14             # entries not seen for this long are dropped
    post_json: dict | None = None      # POST this body instead of GET


FEEDS: dict[str, FeedSpec] = {
    "openphish": FeedSpec("openphish", "openphish_url", parsers.parse_url_lines, max_age_days=7),
    "phishing_db_domains": FeedSpec("phishing_db_domains", "phishing_db_domains_url", parsers.parse_domain_lines),
    "phishing_db_links": FeedSpec("phishing_db_links", "phishing_db_links_url", parsers.parse_url_lines),
    "urlhaus": FeedSpec("urlhaus", "urlhaus_recent_url", parsers.parse_urlhaus_json,
                        needs_key="abusech_auth_key", header="Auth-Key", max_age_days=30),
    "threatfox": FeedSpec("threatfox", "threatfox_url", parsers.parse_threatfox_json,
                          needs_key="abusech_auth_key", header="Auth-Key", max_age_days=30,
                          post_json={"query": "get_iocs", "days": 7}),
    "phishunt": FeedSpec("phishunt", "phishunt_feed_url", parsers.parse_phishunt_json, max_age_days=7),
}


def allowlist() -> set[str]:
    s = get_settings()
    allow = {ln.strip().lower() for ln in (s.data_dir / "feed_allowlist.txt").read_text().splitlines()
             if ln.strip() and not ln.startswith("#")}
    allow |= set(get_ruleset().official_domains)
    return allow


async def upsert_entries(session: AsyncSession, feed: str, items: Iterable[tuple[str, str]]) -> int:
    dialect = session.bind.dialect.name
    ins = pg_insert if dialect == "postgresql" else sqlite_insert
    now = utcnow()
    batch: list[dict] = []
    total = 0

    async def flush():
        nonlocal batch, total
        if not batch:
            return
        stmt = ins(FeedEntry).values(batch)
        stmt = stmt.on_conflict_do_update(index_elements=["feed", "indicator"], set_={"last_seen": now})
        await session.execute(stmt)
        await session.commit()          # short transactions: phones' requests never wait for a whole feed
        total += len(batch)
        batch = []
        await asyncio.sleep(0)          # let the API serve requests between chunks (in-process mode)

    seen: set[str] = set()
    for ind, typ in items:
        if ind in seen:
            continue
        seen.add(ind)
        batch.append({"feed": feed, "indicator": ind, "type": typ, "first_seen": now, "last_seen": now})
        if len(batch) >= CHUNK:
            await flush()
    await flush()
    return total


async def prune(session: AsyncSession, spec: FeedSpec) -> None:
    from datetime import timedelta
    cutoff = utcnow() - timedelta(days=spec.max_age_days)
    await session.execute(delete(FeedEntry).where(FeedEntry.feed == spec.name, FeedEntry.last_seen < cutoff))
    await session.commit()


async def sync_feed(name: str, client: httpx.AsyncClient | None = None) -> int:
    s = get_settings()
    spec = FEEDS[name]
    headers = {"User-Agent": "ScamShield-feed-sync/1.0"}
    if spec.needs_key:
        key = getattr(s, spec.needs_key)
        if not key:
            log.warning("feed %s skipped: %s not configured", name, spec.needs_key.upper())
            return 0
        headers[spec.header or "Authorization"] = key
    own = client is None
    client = client or httpx.AsyncClient(timeout=60, follow_redirects=True)
    try:
        url = getattr(s, spec.url_attr)
        if spec.post_json is not None:
            r = await client.post(url, headers=headers, json=spec.post_json)
        else:
            r = await client.get(url, headers=headers)
        r.raise_for_status()
        items = parsers.filter_allowlisted(spec.parser(r.text), allowlist())
        async with sessionmaker()() as session:
            n = await upsert_entries(session, name, items)
            await prune(session, spec)
        log.info("feed %s: %d indicators", name, n)
        return n
    finally:
        if own:
            await client.aclose()


async def main(which: str) -> None:
    await create_all()
    names = list(FEEDS) if which == "all" else [which]
    for n in names:
        try:
            await sync_feed(n)
        except Exception as e:  # keep going with the other feeds
            log.error("feed %s failed: %s", n, e)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main(sys.argv[1] if len(sys.argv) > 1 else "all"))
