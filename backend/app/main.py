"""FastAPI entry point: `uvicorn app.main:app`."""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app import jobs
from app.api import admin, demo, v1
from app.core.config import get_settings
from app.db import create_all, dispose


@asynccontextmanager
async def lifespan(_: FastAPI):
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    # Creates missing tables only (idempotent). Move to Alembic migrations once the schema settles.
    await create_all()
    watchdog = asyncio.create_task(jobs.report_watchdog())
    feeds_task = None
    if get_settings().feeds_in_process:
        from app.feeds.scheduler import run_forever
        feeds_task = asyncio.create_task(run_forever(create_tables=False))
    yield
    watchdog.cancel()
    if feeds_task:
        feeds_task.cancel()
    await jobs.drain()
    await dispose()


app = FastAPI(title="ScamShield API", version="0.1.0", lifespan=lifespan)
app.include_router(v1.router)
app.include_router(admin.router)
app.include_router(demo.router)
