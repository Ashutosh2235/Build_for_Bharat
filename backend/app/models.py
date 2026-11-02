"""Database models (context file §5.2)."""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from app.db import Base, JSONType


def utcnow() -> datetime:
    return datetime.now(UTC)


TS = DateTime(timezone=True)


class Device(Base):
    __tablename__ = "devices"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    app_version: Mapped[str | None] = mapped_column(String(32))
    state_code: Mapped[str | None] = mapped_column(String(4))
    consent_version: Mapped[int] = mapped_column(Integer, default=0)
    consent_server_check: Mapped[bool] = mapped_column(Boolean, default=False)
    consent_auto_report: Mapped[bool] = mapped_column(Boolean, default=False)   # = report_mode == "auto" (legacy)
    # What happens with a "surely fraud" message: auto = reported without asking; manual = user taps Report
    report_mode: Mapped[str] = mapped_column(String(8), default="manual", server_default="manual")
    consent_at: Mapped[datetime | None] = mapped_column(TS)
    reporter_name: Mapped[str | None] = mapped_column(String(120))
    reporter_phone: Mapped[str | None] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(TS, default=utcnow)


class Sender(Base):
    __tablename__ = "senders"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    sender_norm: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    sender_raw: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(10))
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    report_count: Mapped[int] = mapped_column(Integer, default=0)   # distinct devices with a SCAM verdict
    status: Mapped[str] = mapped_column(String(10), default="unknown")  # unknown|suspect|blocked|trusted
    source: Mapped[str] = mapped_column(String(20), default="app")
    first_seen: Mapped[datetime] = mapped_column(TS, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(TS, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(TS, default=utcnow)


class SenderDevice(Base):
    """Which devices flagged a sender (to count distinct reporters)."""
    __tablename__ = "sender_devices"
    sender_id: Mapped[int] = mapped_column(ForeignKey("senders.id"), primary_key=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), primary_key=True)


class Url(Base):
    __tablename__ = "urls"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    url_norm: Mapped[str] = mapped_column(Text, unique=True)
    url_final: Mapped[str | None] = mapped_column(Text)
    host: Mapped[str] = mapped_column(String(255), index=True)
    registered_domain: Mapped[str] = mapped_column(String(255), index=True)
    verdict: Mapped[str | None] = mapped_column(String(12))
    deep_signals: Mapped[list | None] = mapped_column(JSONType)  # serialized Signals from deep analysis
    hops: Mapped[list | None] = mapped_column(JSONType)
    domain_age_days: Mapped[int | None] = mapped_column(Integer)
    sandbox: Mapped[dict | None] = mapped_column(JSONType)
    checks: Mapped[list | None] = mapped_column(JSONType)    # [{name, status, detail}] — what was consulted
    screenshot: Mapped[str | None] = mapped_column(String(255))
    first_seen: Mapped[datetime] = mapped_column(TS, default=utcnow)
    last_checked: Mapped[datetime | None] = mapped_column(TS)


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    public_id: Mapped[str] = mapped_column(String(36), unique=True, index=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"), index=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey("senders.id"), index=True)
    message_id: Mapped[str] = mapped_column(String(64))
    text_hash: Mapped[str | None] = mapped_column(String(64))
    text_enc: Mapped[str | None] = mapped_column(Text)
    received_at: Mapped[datetime | None] = mapped_column(TS)
    features: Mapped[dict | None] = mapped_column(JSONType)
    urls: Mapped[list | None] = mapped_column(JSONType)          # per-URL summary for the app
    signals: Mapped[list | None] = mapped_column(JSONType)
    score: Mapped[int] = mapped_column(Integer, default=0)
    verdict: Mapped[str] = mapped_column(String(12), default="SAFE")
    status: Mapped[str] = mapped_column(String(12), default="complete")  # partial|complete
    auto_report: Mapped[bool] = mapped_column(Boolean, default=False)
    impersonated_brand: Mapped[str | None] = mapped_column(String(20))
    created_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    __table_args__ = (UniqueConstraint("device_id", "message_id", name="uq_scan_device_message"),)


class Report(Base):
    __tablename__ = "reports"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), unique=True)
    sender_norm: Mapped[str] = mapped_column(String(64), index=True)
    primary_domain: Mapped[str | None] = mapped_column(String(255))
    mode: Mapped[str] = mapped_column(String(8))
    # awaiting_log | queued | sent | demo_sent | duplicate | no_recipient | failed | disabled
    status: Mapped[str] = mapped_column(String(14), default="queued", index=True)
    intended: Mapped[list | None] = mapped_column(JSONType)       # [{label, address, verified, kind}]
    sent_to: Mapped[list | None] = mapped_column(JSONType)
    duplicate_of: Mapped[int | None] = mapped_column(ForeignKey("reports.id"))
    duplicate_count: Mapped[int] = mapped_column(Integer, default=0)
    log_enc: Mapped[str | None] = mapped_column(Text)             # encrypted SMS log (JSON)
    smtp_message_id: Mapped[str | None] = mapped_column(String(255))
    pdf_path: Mapped[str | None] = mapped_column(String(255))
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(TS, default=utcnow)
    sent_at: Mapped[datetime | None] = mapped_column(TS)

    @property
    def public_id(self) -> str:
        return f"SS-{self.created_at.year}-{self.id:04d}"


class FeedEntry(Base):
    __tablename__ = "feed_entries"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    feed: Mapped[str] = mapped_column(String(32))
    indicator: Mapped[str] = mapped_column(Text)
    type: Mapped[str] = mapped_column(String(8))  # url | domain | ip | number
    first_seen: Mapped[datetime] = mapped_column(TS, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(TS, default=utcnow)
    __table_args__ = (
        UniqueConstraint("feed", "indicator", name="uq_feed_indicator"),
        Index("ix_feed_entries_indicator", "indicator"),
    )


class Feedback(Base):
    __tablename__ = "feedback"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"))
    label: Mapped[str] = mapped_column(String(10))  # scam | not_scam
    created_at: Mapped[datetime] = mapped_column(TS, default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[str] = mapped_column(String(64))
    action: Mapped[str] = mapped_column(String(64))
    target: Mapped[str | None] = mapped_column(String(255))
    at: Mapped[datetime] = mapped_column(TS, default=utcnow)
