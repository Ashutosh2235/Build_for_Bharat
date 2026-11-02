"""Minimal admin API (HTTP Basic, user `admin`, password ADMIN_PASSWORD). The React dashboard
(phase 2) calls these; they also work from curl during the demo."""
from __future__ import annotations

import hmac

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import jobs
from app.core.config import get_settings
from app.db import get_session
from app.models import AuditLog, FeedEntry, Report, Scan, Sender, utcnow
from app.services import reporter

basic = HTTPBasic()


def require_admin(c: HTTPBasicCredentials = Depends(basic)) -> str:
    s = get_settings()
    ok = hmac.compare_digest(c.username, "admin") and hmac.compare_digest(c.password, s.admin_password)
    if not ok or (s.is_production and s.admin_password == "change-me"):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, headers={"WWW-Authenticate": "Basic"})
    return c.username


router = APIRouter(prefix="/admin", dependencies=[Depends(require_admin)])


@router.get("/stats")
async def stats(session: AsyncSession = Depends(get_session)) -> dict:
    verdicts = dict((await session.execute(select(Scan.verdict, func.count()).group_by(Scan.verdict))).all())
    feeds = dict((await session.execute(select(FeedEntry.feed, func.count()).group_by(FeedEntry.feed))).all())
    return {"scans": verdicts, "reports": await reporter.count_by_status(session), "feed_entries": feeds,
            "report_mode": get_settings().report_mode}


@router.get("/senders")
async def senders(status_: str | None = None, limit: int = 100, session: AsyncSession = Depends(get_session)):
    q = select(Sender).order_by(Sender.risk_score.desc(), Sender.last_seen.desc()).limit(min(limit, 500))
    if status_:
        q = q.where(Sender.status == status_)
    rows = (await session.execute(q)).scalars().all()
    return [{"sender": r.sender_norm, "raw": r.sender_raw, "kind": r.kind, "risk_score": r.risk_score,
             "risk_tier": tier(r.risk_score), "report_count": r.report_count, "status": r.status,
             "last_seen": r.last_seen} for r in rows]


def tier(score: int) -> str:
    """Same three tiers as DoT's Financial Fraud Risk Indicator."""
    return "very_high" if score >= 80 else "high" if score >= 60 else "medium" if score >= 30 else "low"


class SenderStatusIn(BaseModel):
    status: str = Field(pattern="^(unknown|suspect|blocked|trusted)$")


@router.put("/senders/{sender_norm}")
async def set_sender_status(sender_norm: str, body: SenderStatusIn, who: str = Depends(require_admin),
                            session: AsyncSession = Depends(get_session)) -> dict:
    snd = (await session.execute(select(Sender).where(Sender.sender_norm == sender_norm))).scalar_one_or_none()
    if snd is None:
        raise HTTPException(404, "sender not found")
    snd.status = body.status
    snd.updated_at = utcnow()
    session.add(AuditLog(actor=who, action=f"sender.{body.status}", target=sender_norm))
    await session.commit()
    return {"sender": sender_norm, "status": snd.status}


@router.get("/reports")
async def reports(limit: int = 100, session: AsyncSession = Depends(get_session)):
    rows = (await session.execute(select(Report).order_by(Report.id.desc()).limit(min(limit, 500)))).scalars().all()
    return [{"id": r.public_id, "status": r.status, "mode": r.mode, "sender": r.sender_norm,
             "domain": r.primary_domain, "intended": r.intended, "sent_to": r.sent_to, "error": r.error,
             "duplicates": r.duplicate_count, "created_at": r.created_at, "sent_at": r.sent_at} for r in rows]


@router.post("/reports/{report_id}/send")
async def resend(report_id: str, session: AsyncSession = Depends(get_session)) -> dict:
    """Retry a failed report, or force-send one still waiting for the device's SMS log."""
    try:
        rid = int(report_id.rsplit("-", 1)[-1])
    except ValueError:
        raise HTTPException(400, "bad report id") from None
    rep = await session.get(Report, rid)
    if rep is None:
        raise HTTPException(404, "report not found")
    if rep.status == "awaiting_log":
        rep.status = "queued"
        await session.commit()
    await jobs.enqueue(jobs.job_send_report, rep.id)
    return {"id": rep.public_id, "status": "enqueued"}
