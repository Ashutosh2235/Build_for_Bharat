"""Outgoing mail via the company SMTP server. Without SMTP_HOST (local dev) messages are
written to <REPORT_DIR>/outbox/*.eml instead."""
from __future__ import annotations

import logging
from email.message import EmailMessage
from email.utils import make_msgid
from pathlib import Path

import aiosmtplib

from app.core.config import get_settings

log = logging.getLogger(__name__)


def build_message(*, to: list[str], subject: str, text: str, html: str,
                  attachments: list[tuple[str, bytes, str]]) -> EmailMessage:
    s = get_settings()
    msg = EmailMessage()
    msg["From"] = s.mail_from
    msg["To"] = ", ".join(to)
    if s.mail_reply_to:
        msg["Reply-To"] = s.mail_reply_to
    msg["Subject"] = subject
    domain = s.mail_from.rsplit("@", 1)[-1].rstrip(">").strip() or "scamshield.local"
    msg["Message-ID"] = make_msgid(domain=domain)
    msg.set_content(text)
    msg.add_alternative(html, subtype="html")
    for filename, data, mime in attachments:
        maintype, subtype = mime.split("/", 1)
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=filename)
    return msg


async def send(msg: EmailMessage) -> str:
    """Send and return the Message-ID. Raises on SMTP failure."""
    s = get_settings()
    if not s.smtp_host:
        outbox = Path(s.report_dir) / "outbox"
        outbox.mkdir(parents=True, exist_ok=True)
        name = msg["Message-ID"].strip("<>").replace("@", "_")
        (outbox / f"{name}.eml").write_bytes(bytes(msg))
        log.info("SMTP_HOST not set — wrote %s to outbox", name)
        return msg["Message-ID"]
    await aiosmtplib.send(
        msg, hostname=s.smtp_host, port=s.smtp_port,
        username=s.smtp_user or None, password=s.smtp_password or None,
        start_tls=s.smtp_starttls and s.smtp_port != 465, use_tls=s.smtp_port == 465, timeout=30,
    )
    return msg["Message-ID"]
