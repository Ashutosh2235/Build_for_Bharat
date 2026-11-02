"""Async SQLAlchemy engine/session. PostgreSQL in production, SQLite for local dev/tests."""
from __future__ import annotations

from collections.abc import AsyncIterator

from sqlalchemy import JSON, event
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import StaticPool

from app.core.config import get_settings

JSONType = JSON().with_variant(JSONB(), "postgresql")


class Base(DeclarativeBase):
    pass


_engine: AsyncEngine | None = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def get_engine() -> AsyncEngine:
    global _engine, _sessionmaker
    if _engine is None:
        url = get_settings().database_url
        kwargs: dict = {"pool_pre_ping": True}
        if url.startswith("sqlite") and ":memory:" in url:
            kwargs = {"poolclass": StaticPool, "connect_args": {"check_same_thread": False}}
        elif url.startswith("sqlite"):
            # File SQLite (no-Docker PC mode): wait for locks instead of failing, allow concurrent readers
            kwargs = {"connect_args": {"timeout": 30}}
        _engine = create_async_engine(url, **kwargs)
        if url.startswith("sqlite") and ":memory:" not in url:
            @event.listens_for(_engine.sync_engine, "connect")
            def _pragmas(dbapi_conn, _record):
                cur = dbapi_conn.cursor()
                cur.execute("PRAGMA journal_mode=WAL")
                cur.execute("PRAGMA busy_timeout=30000")
                cur.close()
        _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False)
    return _engine


def sessionmaker() -> async_sessionmaker[AsyncSession]:
    get_engine()
    assert _sessionmaker is not None
    return _sessionmaker


async def get_session() -> AsyncIterator[AsyncSession]:
    async with sessionmaker()() as session:
        yield session


async def create_all() -> None:
    """Create missing tables, then add columns that newer versions introduced (keeps the data of
    a database created by an earlier build). Alembic can replace this once the schema settles."""
    from app import models  # noqa: F401  (register tables)

    async with get_engine().begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_add_missing_columns)


def _add_missing_columns(sync_conn) -> None:
    from sqlalchemy import inspect, text

    insp = inspect(sync_conn)
    dialect = sync_conn.dialect
    for table in Base.metadata.sorted_tables:
        existing = {c["name"] for c in insp.get_columns(table.name)}
        for col in table.columns:
            if col.name in existing:
                continue
            ddl = f'ALTER TABLE {table.name} ADD COLUMN {col.name} {col.type.compile(dialect=dialect)}'
            if col.server_default is not None:
                ddl += f" DEFAULT '{col.server_default.arg}'"
                if not col.nullable:
                    ddl += " NOT NULL"
            sync_conn.execute(text(ddl))


async def dispose() -> None:
    global _engine, _sessionmaker
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _sessionmaker = None
