"""Auto-report pipeline (context file §7).

  create_report  — called when a scan is complete, SCAM, above the auto-report bar, and the
                   device consented. Applies de-duplication. Status: awaiting_log | duplicate | disabled
  attach_log     — device uploads the messages from the scam sender  → queued
  send_report    — build JSON + PDF + email; demo mode sends to DEMO_RECIPIENTS only
"""
from __future__ import annotations

import html
import json
import logging
from datetime import timedelta
from pathlib import Path

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.crypto import decrypt_json, encrypt_json
from app.models import Device, Report, Scan, Sender, utcnow
from app.services import mailer, routing
from app.services.pdf_report import build_pdf, ist
from app.services.ruleset import get_ruleset
from app.services.sender_intel import classify_sender

log = logging.getLogger(__name__)

ACTIVE = ("awaiting_log", "queued", "sent", "demo_sent")
SCAM_TYPE_LABELS = {
    "KYC_BLOCK_THREAT": "KYC / account-block scam", "OTP_REQUEST": "OTP theft", "PRIZE_LOTTERY": "Lottery / prize scam",
    "REFUND_CASHBACK": "Fake refund / cashback", "JOB_LOAN_FEE": "Job / loan fee scam", "UPI_COLLECT": "UPI collect / QR scam",
    "DIGITAL_ARREST": "'Digital arrest' / impersonating police", "ELECTRICITY_CUTOFF": "Electricity bill scam",
    "PARCEL_CUSTOMS": "Parcel / courier scam", "LOOKALIKE_DOMAIN": "Phishing website", "LOGIN_FORM": "Credential phishing page",
    "DOWNLOAD_ATTEMPT": "Malicious app download", "DOWNLOAD_LINK": "Malicious app download", "FEED_HIT": "Known phishing/malware link",
    "SAFE_BROWSING_HIT": "Known phishing/malware link",
    "SECURE_DNS_BLOCK": "Known phishing/malware link",
}


def primary_domain(scan: Scan) -> str | None:
    for u in scan.urls or []:
        if u.get("registered_domain"):
            return u["registered_domain"]
    return None


async def create_report(session: AsyncSession, scan: Scan, device: Device, *, manual: bool = False) -> Report | None:
    """Only "surely fraud" scans are reportable. Automatic mode: called when the scan completes.
    Manual mode: called when the user taps Report (manual=True)."""
    s = get_settings()
    if scan.verdict != "FRAUD" or scan.status != "complete":
        return None
    if not manual and device.report_mode != "auto":
        return None
    existing = (await session.execute(select(Report).where(Report.scan_id == scan.id))).scalar_one_or_none()
    if existing:
        return existing
    sender = await session.get(Sender, scan.sender_id)
    dom = primary_domain(scan)
    intended = routing.intended_recipients(device.state_code, scan.impersonated_brand)
    rep = Report(scan_id=scan.id, sender_norm=sender.sender_norm, primary_domain=dom, mode=s.report_mode,
                 intended=intended, status="awaiting_log")
    if not s.reports_enabled:
        rep.status = "disabled"
    else:
        cutoff = utcnow() - timedelta(hours=_auth()["dedupe_hours"])
        q = select(Report).where(Report.sender_norm == sender.sender_norm, Report.status.in_(ACTIVE),
                                 Report.created_at >= cutoff)
        q = q.where(Report.primary_domain == dom) if dom else q.where(Report.primary_domain.is_(None))
        original = (await session.execute(q.order_by(Report.id).limit(1))).scalar_one_or_none()
        if original:
            rep.status = "duplicate"
            rep.duplicate_of = original.id
            original.duplicate_count += 1
    session.add(rep)
    await session.commit()
    return rep


def _auth() -> dict:
    a = routing.authorities()
    return {"dedupe_hours": int(a.get("dedupe_hours", 24)),
            "max_per_day": int(a.get("max_per_authority_per_day", 20))}


async def attach_log(session: AsyncSession, rep: Report, messages: list[dict]) -> Report:
    """Store the SMS log (only messages from the scam sender) encrypted, then queue for sending."""
    scan = await session.get(Scan, rep.scan_id)
    norm = (await session.get(Sender, scan.sender_id)).sender_norm
    clean = [m for m in messages if classify_sender(m["sender"]).norm == norm][:50]
    rep.log_enc = encrypt_json(clean)
    if rep.status == "awaiting_log":
        rep.status = "queued"
    await session.commit()
    return rep


def _scam_types(reasons: list[dict]) -> list[str]:
    return list(dict.fromkeys(SCAM_TYPE_LABELS[r["code"]] for r in reasons if r["code"] in SCAM_TYPE_LABELS))


async def report_payload(session: AsyncSession, rep: Report) -> dict:
    s = get_settings()
    rs = get_ruleset()
    scan = await session.get(Scan, rep.scan_id)
    device = await session.get(Device, scan.device_id)
    sender = await session.get(Sender, scan.sender_id)
    log_msgs = decrypt_json(rep.log_enc) or []
    if not log_msgs:
        own = decrypt_json(scan.text_enc)
        if own:
            log_msgs = [{"sender": scan.features.get("sender", sender.sender_raw), "text": own["text"],
                         "received_at": scan.received_at.isoformat() if scan.received_at else None}]
    for m in log_msgs:
        if m.get("received_at") and not isinstance(m["received_at"], str):
            m["received_at"] = m["received_at"].isoformat()
    reasons = scan.signals or []
    reasons_out = [{"code": r["code"], "text": r["text"], "points": r["points"], "detail": r.get("detail")} for r in reasons]
    brand = rs.brands.get(scan.impersonated_brand or "")
    return {
        "report_id": rep.public_id,
        "generated_at": utcnow().isoformat(),
        "mode": rep.mode,
        "message": {"sender": scan.features.get("sender", sender.sender_raw), "sender_kind": sender.kind,
                    "received_at": scan.received_at.isoformat() if scan.received_at else None,
                    "sim_slot": scan.features.get("sim_slot")},
        "analysis": {
            "verdict": scan.verdict, "score": scan.score, "reasons": reasons_out,
            "scam_types": _scam_types(reasons_out),
            "impersonated": brand.name if brand else None,
            "urls": [{"input": u["input"], "final": u.get("final"), "hops": u.get("hops", 0),
                      "feed_hits": u.get("feed_hits", []), "screenshot": u.get("screenshot"),
                      "verdict": _url_verdict(u)} for u in scan.urls or []],
        },
        "sms_log": log_msgs,
        "sender_history": {"distinct_reporting_devices": sender.report_count, "status": sender.status},
        "reporter": {"state": device.state_code,
                     "name": device.reporter_name, "phone": device.reporter_phone},
        "routing": {"intended": rep.intended or [], "portals": routing.portals(),
                    "mode": rep.mode, "demo_recipients": s.demo_recipients if rep.mode == "demo" else []},
        "duplicates_since_first_report": rep.duplicate_count,
    }


def _url_verdict(u: dict) -> str:
    from app.services.pipeline import url_verdict
    return url_verdict(u, get_ruleset())


def _email_bodies(data: dict) -> tuple[str, str, str]:
    m, a = data["message"], data["analysis"]
    scam = ", ".join(a["scam_types"]) or "fraud"
    state = data["reporter"].get("state") or "—"
    subject = f"[ScamShield Auto-Report {data['report_id']}] Suspected {scam} SMS from {m['sender']} — {state}"
    if data["mode"] == "demo":
        subject = "[DEMO] " + subject
    lines = [
        f"ScamShield automated report {data['report_id']}",
        "",
        f"Sender: {m['sender']} ({m['sender_kind']})",
        f"Verdict: {a['verdict']} — risk score {a['score']}/100",
        f"Scam type: {scam}",
        f"Imitating: {a.get('impersonated') or '—'}",
        "",
        "Why it was flagged:",
        *[f"  - {r['text']}" + (f" ({r['detail']})" if r.get("detail") else "") for r in a["reasons"]],
        "",
        "Links:",
        *([f"  - {u['input']} -> {u.get('final') or '?'} [{u['verdict']}]" for u in a["urls"]] or ["  (none)"]),
        "",
        "SMS log:",
        *[f"  [{ist(_dt(x.get('received_at')))}] {x['text']}" for x in data["sms_log"]],
        "",
    ]
    if data["mode"] == "demo":
        intended = [f"  - {r['label']} <{r['address']}>{'' if r['verified'] else ' (UNVERIFIED address)'}"
                    for r in data["routing"]["intended"]] or ["  (no matching authority configured)"]
        lines += ["DEMO MODE — in live mode this report would be sent to:", *intended, ""]
    lines += ["Portals for manual follow-up:", *[f"  - {p['label']}: {p['url']}" for p in data["routing"]["portals"]],
              "", "Automated detection can be wrong; this is not a legal determination. "
              "Sent with the user's consent. Links were analysed in an isolated server sandbox."]
    text = "\n".join(lines)
    body_html = "<pre style='font-family:system-ui,sans-serif;white-space:pre-wrap'>" + html.escape(text) + "</pre>"
    return subject, text, body_html


def _dt(v):
    from datetime import datetime
    return datetime.fromisoformat(v) if v else None


def _recipients(rep: Report) -> list[str]:
    s = get_settings()
    if rep.mode == "demo":
        if not s.demo_recipients and not s.smtp_host:
            return ["demo-inbox@localhost"]     # files-only mode: still produce the report
        return list(s.demo_recipients)
    return [r["address"] for r in rep.intended or [] if r.get("verified")]


async def _over_daily_cap(session: AsyncSession, address: str) -> bool:
    since = utcnow() - timedelta(days=1)
    rows = (await session.execute(select(Report.sent_to).where(Report.status == "sent", Report.sent_at >= since))).all()
    return sum(1 for (to,) in rows if to and address in to) >= _auth()["max_per_day"]


async def send_report(session: AsyncSession, rep: Report) -> Report:
    s = get_settings()
    if rep.status not in ("queued", "failed"):
        return rep
    to = _recipients(rep)
    if rep.mode == "live":
        to = [a for a in to if not await _over_daily_cap(session, a)]
    if not to:
        rep.status = "no_recipient"
        rep.error = "no verified recipient (live) / DEMO_RECIPIENTS empty (demo)"
        await session.commit()
        return rep
    data = await report_payload(session, rep)
    report_dir = Path(s.report_dir) / rep.public_id
    pdf = build_pdf(report_dir / f"{rep.public_id}.pdf", data, Path(s.screenshot_dir))
    js = json.dumps(data, ensure_ascii=False, indent=2).encode()
    (report_dir / f"{rep.public_id}.json").write_bytes(js)
    subject, text, body_html = _email_bodies(data)
    msg = mailer.build_message(to=to, subject=subject, text=text, html=body_html, attachments=[
        (f"{rep.public_id}.pdf", pdf.read_bytes(), "application/pdf"),
        (f"{rep.public_id}.json", js, "application/json"),
    ])
    rep.attempts += 1
    try:
        rep.smtp_message_id = await mailer.send(msg)
        rep.status = "demo_sent" if rep.mode == "demo" else "sent"
        rep.sent_to = to
        rep.sent_at = utcnow()
        rep.pdf_path = str(pdf)
        rep.error = None
    except Exception as e:  # SMTP errors: keep for retry
        log.error("report %s send failed: %s", rep.public_id, e)
        rep.status = "failed"
        rep.error = str(e)[:500]
    await session.commit()
    return rep


async def release_stale(session: AsyncSession, minutes: int = 10) -> list[int]:
    """Reports whose phone never uploaded the SMS log (offline, app killed) are queued anyway
    after `minutes`; they're sent with the scanned message only (if its text was shared)."""
    cutoff = utcnow() - timedelta(minutes=minutes)
    rows = (await session.execute(
        select(Report).where(Report.status == "awaiting_log", Report.created_at < cutoff)
    )).scalars().all()
    for r in rows:
        r.status = "queued"
    await session.commit()
    return [r.id for r in rows]


async def count_by_status(session: AsyncSession) -> dict[str, int]:
    rows = (await session.execute(select(Report.status, func.count()).group_by(Report.status))).all()
    return dict(rows)
