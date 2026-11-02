"""Background job runner.

Phase 1 runs jobs as asyncio tasks inside the API process (fine for a hackathon on one VPS).
Swap `enqueue` for Celery/RQ later without touching callers. Tests set INLINE = True so
jobs run to completion before the request returns.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable

from sqlalchemy import select

from app.db import sessionmaker
from app.models import Device, Report, Scan
from app.services import pipeline, reporter

log = logging.getLogger(__name__)
INLINE = False
_tasks: set[asyncio.Task] = set()


async def enqueue(fn: Callable[..., Awaitable], *args) -> None:
    if INLINE:
        await fn(*args)
        return
    t = asyncio.create_task(_guard(fn, *args))
    _tasks.add(t)
    t.add_done_callback(_tasks.discard)


async def _guard(fn, *args):
    try:
        await fn(*args)
    except Exception:
        log.exception("background job %s failed", getattr(fn, "__name__", fn))


async def drain() -> None:
    """Wait for running jobs (shutdown / tests)."""
    while _tasks:
        await asyncio.gather(*list(_tasks), return_exceptions=True)


# ------------------------------------------------------------------ jobs
async def job_deep_scan(scan_id: int) -> None:
    async with sessionmaker()() as session:
        scan = await pipeline.deep_scan(session, scan_id)
        if scan is not None:
            await after_complete(session, scan)


async def after_complete(session, scan: Scan) -> None:
    """Scan finished → maybe create an auto-report."""
    if scan.status != "complete" or not scan.auto_report:
        return
    device = await session.get(Device, scan.device_id)
    await reporter.create_report(session, scan, device)


async def report_watchdog(every_s: int = 60, stale_minutes: int = 10) -> None:
    """Runs inside the API: sends reports stuck waiting for a phone's SMS log, and retries failed ones."""
    while True:
        try:
            async with sessionmaker()() as session:
                ids = await reporter.release_stale(session, stale_minutes)
                failed = (await session.execute(
                    select(Report.id).where(Report.status == "failed", Report.attempts < 5))).scalars().all()
            for rid in [*ids, *failed]:
                await job_send_report(rid)
        except Exception:
            log.exception("report watchdog error")
        await asyncio.sleep(every_s)


async def job_send_report(report_id: int) -> None:
    async with sessionmaker()() as session:
        rep = await session.get(Report, report_id)
        if rep is not None:
            await reporter.send_report(session, rep)
