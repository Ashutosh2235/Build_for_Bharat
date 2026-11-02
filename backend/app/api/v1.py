"""Public API for the Android app (context file §5.3)."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import FileResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app import jobs
from app.core.config import get_settings
from app.core.security import current_device, new_device_token, require_api_key
from app.db import get_session
from app.models import Device, Feedback, FeedEntry, Report, Scan, Sender, Url, utcnow
from app.schemas import (
    BlocklistOut,
    ConsentIn,
    FeedbackIn,
    ManualReportIn,
    Reason,
    RegisterIn,
    RegisterOut,
    ReportLogIn,
    ReportRef,
    ScanIn,
    ScanOut,
    UrlOut,
)
from app.services import pipeline, reporter, routing
from app.services.decision import FRAUD, LABELS, SPAM
from app.services.ruleset import get_ruleset
from app.services.text_utils import domain_hash

router = APIRouter(prefix="/v1")


@router.get("/health")
async def health(session: AsyncSession = Depends(get_session)) -> dict:
    await session.execute(select(1))
    s = get_settings()
    feeds = dict((await session.execute(select(FeedEntry.feed, func.count()).group_by(FeedEntry.feed))).all())
    return {"ok": True, "rules_version": get_ruleset().version, "report_mode": s.report_mode,
            "deep_scan": s.deep_scan_enabled, "sandbox": s.sandbox_enabled,
            "checks": {"safe_browsing": bool(s.google_safebrowsing_key), "secure_dns": s.secure_dns_enabled,
                       "abusech_feeds": bool(s.abusech_auth_key), "email": "smtp" if s.smtp_host else "files"},
            "feed_entries": feeds}


# ------------------------------------------------------------------ devices
def _apply_consent(dev: Device, body: RegisterIn) -> None:
    dev.app_version = body.app_version
    dev.state_code = (body.state_code or "").upper() or None
    dev.consent_version = body.consent_version
    dev.consent_server_check = body.consent_server_check
    dev.report_mode = body.report_mode or ("auto" if body.consent_auto_report else "manual")
    dev.consent_auto_report = dev.report_mode == "auto"
    dev.consent_at = utcnow()
    dev.reporter_name = body.reporter_name
    dev.reporter_phone = body.reporter_phone


@router.post("/devices/register", response_model=RegisterOut, dependencies=[Depends(require_api_key)])
async def register(body: RegisterIn, session: AsyncSession = Depends(get_session)) -> RegisterOut:
    token, token_hash = new_device_token()
    dev = Device(token_hash=token_hash)
    _apply_consent(dev, body)
    session.add(dev)
    await session.commit()
    return RegisterOut(device_token=token)


@router.put("/devices/me", status_code=204)
async def update_consent(body: ConsentIn, device: Device = Depends(current_device),
                         session: AsyncSession = Depends(get_session)) -> Response:
    dev = await session.get(Device, device.id)
    _apply_consent(dev, body)
    await session.commit()
    return Response(status_code=204)


# ------------------------------------------------------------------ scan
async def _scan_out(session: AsyncSession, scan: Scan, base_url: str = "", device: Device | None = None) -> ScanOut:
    s = get_settings()
    base = (s.public_base_url or base_url).rstrip('/')
    rs = get_ruleset()
    rep = (await session.execute(select(Report).where(Report.scan_id == scan.id))).scalar_one_or_none()
    report = None
    if rep is not None:
        report = ReportRef(id=rep.public_id, status=rep.status, mode=rep.mode,
                           needs_log=rep.status == "awaiting_log", intended=rep.intended or [])
    urls = [UrlOut(input=u["input"], final=u.get("final"), host=u.get("host"), hops=u.get("hops", 0),
                   screenshot_url=f"{base}/v1/screens/{u['screenshot']}" if u.get("screenshot") else None,
                   feed_hits=u.get("feed_hits", []), verdict=pipeline.url_verdict(u, rs), checks=u.get("checks", []))
            for u in scan.urls or []]
    fraud = scan.verdict == FRAUD
    shown = scan.verdict in (FRAUD, SPAM)
    device = device or await session.get(Device, scan.device_id)
    preview = []
    if fraud:
        preview = list(dict.fromkeys(r["label"] for r in
                                     routing.intended_recipients(device.state_code, scan.impersonated_brand)))
    return ScanOut(
        scan_id=scan.public_id, status=scan.status, verdict=scan.verdict, label=LABELS.get(scan.verdict),
        score=scan.score,
        # Reasons only once a decision is shown: nothing leaks to the UI while checks are pending
        reasons=[Reason(**{k: r.get(k) for k in ("code", "text", "points", "detail")})
                 for r in scan.signals or []] if shown else [],
        urls=urls if shown else [], report=report, impersonated_brand=scan.impersonated_brand if shown else None,
        portals=routing.portals() if fraud else [],
        checks=(scan.features or {}).get("db_checks", []),
        evidence=[r["code"] for r in scan.signals or [] if r["code"] in rs.fraud_evidence] if fraud else [],
        report_mode=device.report_mode, can_report=fraud and rep is None, report_preview=preview,
    )


@router.post("/scan", response_model=ScanOut)
async def scan(body: ScanIn, response: Response, request: Request, device: Device = Depends(current_device),
               session: AsyncSession = Depends(get_session)) -> ScanOut:
    if not device.consent_server_check:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "server checks not consented")
    sc = await pipeline.quick_scan(session, device, body)
    if sc.status == "partial":
        await jobs.enqueue(jobs.job_deep_scan, sc.id)
        await session.refresh(sc)
    else:
        await jobs.after_complete(session, sc)
    if sc.status == "partial":
        response.status_code = status.HTTP_202_ACCEPTED
    return await _scan_out(session, sc, str(request.base_url), device)


async def _own_scan(session: AsyncSession, device: Device, scan_id: str) -> Scan:
    sc = (await session.execute(select(Scan).where(Scan.public_id == scan_id))).scalar_one_or_none()
    if sc is None or sc.device_id != device.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan not found")
    return sc


@router.get("/scan/{scan_id}", response_model=ScanOut)
async def get_scan(scan_id: str, request: Request, device: Device = Depends(current_device),
                   session: AsyncSession = Depends(get_session)) -> ScanOut:
    return await _scan_out(session, await _own_scan(session, device, scan_id), str(request.base_url))


# ------------------------------------------------------------------ reports
@router.post("/reports", response_model=ReportRef)
async def report_manually(body: ManualReportIn, device: Device = Depends(current_device),
                          session: AsyncSession = Depends(get_session)) -> ReportRef:
    """Manual mode: the user tapped Report on a "surely fraud" message (also works in auto mode)."""
    sc = await _own_scan(session, device, body.scan_id)
    if sc.verdict != FRAUD or sc.status != "complete":
        raise HTTPException(status.HTTP_409_CONFLICT, "only messages decided as surely fraud can be reported")
    dev = await session.get(Device, device.id)
    rep = await reporter.create_report(session, sc, dev, manual=True)
    if rep is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "report could not be created")
    if rep.status == "awaiting_log":
        await reporter.attach_log(session, rep, [m.model_dump(mode="json") for m in body.messages])
        await jobs.enqueue(jobs.job_send_report, rep.id)
        await session.refresh(rep)
    return ReportRef(id=rep.public_id, status=rep.status, mode=rep.mode, intended=rep.intended or [])


@router.post("/report/log", response_model=ReportRef)
async def report_log(body: ReportLogIn, device: Device = Depends(current_device),
                     session: AsyncSession = Depends(get_session)) -> ReportRef:
    sc = await _own_scan(session, device, body.scan_id)
    rep = (await session.execute(select(Report).where(Report.scan_id == sc.id))).scalar_one_or_none()
    if rep is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no report for this scan")
    if rep.status == "awaiting_log":
        await reporter.attach_log(session, rep, [m.model_dump(mode="json") for m in body.messages])
        await jobs.enqueue(jobs.job_send_report, rep.id)
        await session.refresh(rep)
    return ReportRef(id=rep.public_id, status=rep.status, mode=rep.mode, intended=rep.intended or [])


@router.get("/reports", response_model=list[ReportRef])
async def my_reports(device: Device = Depends(current_device),
                     session: AsyncSession = Depends(get_session)) -> list[ReportRef]:
    rows = (await session.execute(
        select(Report).join(Scan, Scan.id == Report.scan_id).where(Scan.device_id == device.id)
        .order_by(Report.id.desc()).limit(100)
    )).scalars().all()
    return [ReportRef(id=r.public_id, status=r.status, mode=r.mode, needs_log=r.status == "awaiting_log",
                      intended=r.intended or []) for r in rows]


# ------------------------------------------------------------------ feedback
@router.post("/feedback", status_code=204)
async def feedback(body: FeedbackIn, device: Device = Depends(current_device),
                   session: AsyncSession = Depends(get_session)) -> Response:
    sc = await _own_scan(session, device, body.scan_id)
    session.add(Feedback(scan_id=sc.id, device_id=device.id, label=body.label))
    await session.commit()
    return Response(status_code=204)


# ------------------------------------------------------------------ blocklist
@router.get("/sync/blocklist", response_model=BlocklistOut)
async def blocklist(since: datetime | None = Query(default=None), device: Device = Depends(current_device),
                    session: AsyncSession = Depends(get_session)) -> BlocklistOut:
    s = get_settings()
    now = utcnow()
    sq = select(Sender.sender_norm).where(Sender.status == "blocked")
    fq = select(FeedEntry.indicator).where(FeedEntry.type == "domain")
    uq = select(Url.registered_domain).where(Url.verdict == "SCAM")
    if since:
        sq = sq.where(Sender.updated_at >= since)
        fq = fq.where(FeedEntry.last_seen >= since)
    senders = list((await session.execute(sq)).scalars())
    domains = list((await session.execute(fq.order_by(FeedEntry.last_seen.desc()).limit(s.blocklist_max_domains))).scalars())
    domains += list((await session.execute(uq)).scalars())
    return BlocklistOut(version=now.isoformat(), senders=senders,
                        domain_hashes=sorted({domain_hash(d) for d in domains if d}), full=since is None)


# ------------------------------------------------------------------ sandbox screenshots
@router.get("/screens/{name}")
async def screenshot(name: str) -> FileResponse:
    if "/" in name or ".." in name or not name.endswith(".png"):
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    path = Path(get_settings().screenshot_dir) / name
    if not path.exists():
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    return FileResponse(path, media_type="image/png")
