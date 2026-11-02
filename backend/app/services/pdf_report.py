"""Report PDF (ReportLab). Devanagari is stored/sent in the JSON + email body; ReportLab cannot
shape Indic scripts, so the PDF notes when the original text contains them."""
from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

IST = timezone(timedelta(hours=5, minutes=30))
_FONT_CANDIDATES = [
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"),
]
_INDIC = re.compile(r"[ऀ-෿]")


def _fonts() -> tuple[str, str]:
    for reg, bold in _FONT_CANDIDATES:
        if Path(reg).exists() and Path(bold).exists():
            if "DejaVu" not in pdfmetrics.getRegisteredFontNames():
                pdfmetrics.registerFont(TTFont("DejaVu", reg))
                pdfmetrics.registerFont(TTFont("DejaVu-Bold", bold))
            return "DejaVu", "DejaVu-Bold"
    return "Helvetica", "Helvetica-Bold"


def ist(dt: datetime | None) -> str:
    if dt is None:
        return "—"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(IST).strftime("%d %b %Y, %H:%M IST")


def _p(text: str, style) -> Paragraph:
    t = escape(str(text))
    if _INDIC.search(t):
        t = _INDIC.sub("·", t) + " <i>[contains Indic script — see the email body / JSON for the original]</i>"
    return Paragraph(t.replace("\n", "<br/>"), style)


def build_pdf(path: Path, data: dict, screenshot_dir: Path | None = None) -> Path:
    """`data` is the report JSON produced by reporter.report_payload()."""
    regular, bold = _fonts()
    ss = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=ss["BodyText"], fontName=regular, fontSize=9.5, leading=13)
    small = ParagraphStyle("s", parent=body, fontSize=8, textColor=colors.HexColor("#555555"))
    h1 = ParagraphStyle("h1", parent=ss["Title"], fontName=bold, fontSize=16, spaceAfter=2)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], fontName=bold, fontSize=11.5, spaceBefore=10, spaceAfter=4)
    th = ParagraphStyle("th", parent=body, fontName=bold)

    def table(rows, widths, header=False):
        t = Table([[c if isinstance(c, Paragraph) else _p(c, body) for c in r] for r in rows], colWidths=widths)
        style = [("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#BBBBBB")),
                 ("VALIGN", (0, 0), (-1, -1), "TOP"),
                 ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4)]
        if header:
            style.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#EEEEEE")))
        t.setStyle(TableStyle(style))
        return t

    m = data["message"]
    a = data["analysis"]
    story = [
        Paragraph(f"Suspected fraud SMS — automated report {escape(data['report_id'])}", h1),
        _p(f"Generated {ist(datetime.fromisoformat(data['generated_at']))} by ScamShield "
           f"({'DEMO MODE — not sent to authorities' if data['mode'] == 'demo' else 'live'})", small),
        Spacer(1, 6),
        Paragraph("Summary", h2),
        table([
            ["Sender", m["sender"]],
            ["Sender type", m["sender_kind"]],
            ["Received", ist(datetime.fromisoformat(m["received_at"])) if m.get("received_at") else "—"],
            ["Verdict", f"{a['verdict']} (risk score {a['score']}/100)"],
            ["Scam type", ", ".join(a["scam_types"]) or "—"],
            ["Imitating", a.get("impersonated") or "—"],
            ["Reporter state", data["reporter"].get("state") or "—"],
        ], [40 * mm, 130 * mm]),
        Paragraph("Why it was flagged", h2),
        table([[Paragraph("Signal", th), Paragraph("Explanation", th), Paragraph("Pts", th)]] +
              [[r["code"], r["text"] + (f" — {r['detail']}" if r.get("detail") else ""), str(r["points"])]
               for r in a["reasons"]], [42 * mm, 115 * mm, 13 * mm], header=True),
    ]
    if a["urls"]:
        story.append(Paragraph("Links in the message", h2))
        story.append(table(
            [[Paragraph("Link", th), Paragraph("Final destination", th), Paragraph("Notes", th)]] +
            [[u["input"], u.get("final") or "—",
              "; ".join(filter(None, [f"{u.get('hops', 0)} redirect hop(s)",
                                      ("feeds: " + ", ".join(u["feed_hits"])) if u.get("feed_hits") else "",
                                      f"verdict {u.get('verdict')}"]))]
             for u in a["urls"]], [55 * mm, 65 * mm, 50 * mm], header=True))
        for u in a["urls"]:
            shot = u.get("screenshot")
            if shot and screenshot_dir and (screenshot_dir / shot).exists():
                story.append(Spacer(1, 4))
                story.append(_p(f"Sandbox screenshot of {u.get('final') or u['input']} (opened on a server, not the phone):", small))
                img = Image(str(screenshot_dir / shot))
                scale = min(60 * mm / img.drawWidth, 120 * mm / img.drawHeight, 1)
                img.drawWidth *= scale
                img.drawHeight *= scale
                story.append(img)
    story.append(Paragraph("SMS log (messages from this sender)", h2))
    log_rows = [[Paragraph("Received", th), Paragraph("Message", th)]] + \
        [[ist(datetime.fromisoformat(x["received_at"])) if x.get("received_at") else "—", x["text"]]
         for x in data["sms_log"]]
    story.append(table(log_rows, [38 * mm, 132 * mm], header=True))
    story.append(Paragraph("Routing", h2))
    story.append(table([[r["label"], r["address"], "verified" if r["verified"] else "UNVERIFIED address"]
                        for r in data["routing"]["intended"]] or [["—", "no matching authority configured", ""]],
                       [70 * mm, 70 * mm, 30 * mm]))
    story.append(Spacer(1, 4))
    story.append(_p("National portals (manual submission): " +
                    "; ".join(f"{p['label']}: {p['url']}" for p in data["routing"]["portals"]), small))
    story.append(Spacer(1, 10))
    story.append(_p("This report was generated automatically by ScamShield with the recipient's consent. "
                    "Automated detection can be wrong; this is not a legal determination. "
                    "Links were analysed in an isolated server sandbox and were not opened on the user's phone.", small))

    path.parent.mkdir(parents=True, exist_ok=True)
    SimpleDocTemplate(str(path), pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                      topMargin=16 * mm, bottomMargin=16 * mm,
                      title=f"ScamShield report {data['report_id']}").build(story)
    return path
