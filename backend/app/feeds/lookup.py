"""Check a parsed URL against stored feed indicators."""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.feeds.parsers import url_key
from app.models import FeedEntry
from app.services.url_intel import ParsedUrl


async def feed_hits(session: AsyncSession, p: ParsedUrl) -> list[str]:
    """Names of feeds listing this exact URL, its host, or its registered domain."""
    if p.is_upi or not p.host:
        return []
    keys = {k for k in (url_key(p.url), p.host, p.registered_domain) if k}
    rows = (await session.execute(
        select(FeedEntry.feed, FeedEntry.indicator, FeedEntry.type).where(FeedEntry.indicator.in_(keys))
    )).all()
    hits = []
    for feed, ind, typ in rows:
        if typ == "url" or ind in (p.host, p.registered_domain):
            hits.append(feed)
    return sorted(set(hits))
