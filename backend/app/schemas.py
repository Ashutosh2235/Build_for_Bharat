"""Request/response DTOs (context file §5.3). Android mirrors these in core/network/Dto.kt."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class RegisterIn(BaseModel):
    app_version: str | None = None
    state_code: str | None = Field(default=None, max_length=4)
    consent_version: int = 0
    consent_server_check: bool = False
    # "auto": surely-fraud messages are reported without asking; "manual": the user taps Report
    report_mode: Literal["auto", "manual"] | None = None
    consent_auto_report: bool = False      # legacy clients (= report_mode "auto")
    reporter_name: str | None = Field(default=None, max_length=120)
    reporter_phone: str | None = Field(default=None, max_length=20)


class RegisterOut(BaseModel):
    device_token: str


class ConsentIn(RegisterIn):
    pass


class LocalResult(BaseModel):
    score: int = 0
    reasons: list[str] = []


class ScanFeatures(BaseModel):
    in_contacts: bool = False
    lang: str | None = None


class ScanIn(BaseModel):
    message_id: str = Field(max_length=64)
    sender: str = Field(max_length=64)
    received_at: datetime | None = None
    sim_slot: int | None = None
    urls: list[str] = Field(default_factory=list, max_length=20)
    local: LocalResult = LocalResult()
    features: ScanFeatures = ScanFeatures()
    text: str | None = Field(default=None, max_length=5000)   # only with consent


class Reason(BaseModel):
    code: str
    text: str
    points: int = 0
    detail: str | None = None


class UrlOut(BaseModel):
    input: str
    final: str | None = None
    host: str | None = None
    hops: int = 0
    screenshot_url: str | None = None
    feed_hits: list[str] = []
    verdict: str | None = None
    checks: list[dict] = []          # [{name, status: hit|clean|unavailable|skipped, detail}]


class ReportRef(BaseModel):
    id: str
    status: str
    mode: str
    needs_log: bool = False
    intended: list[dict] = []


class ScanOut(BaseModel):
    scan_id: str
    status: str            # partial (checks still running) | complete
    # PENDING (show nothing yet) | FRAUD | SPAM | NONE (show nothing). Decided only after the
    # database lookups and all link checks are complete.
    verdict: str
    label: str | None = None          # "Surely fraud" / "Surely spam"
    score: int
    reasons: list[Reason]
    urls: list[UrlOut] = []
    report: ReportRef | None = None
    impersonated_brand: str | None = None
    portals: list[dict] = []
    checks: list[dict] = []           # message-level database lookups (sender DB)
    evidence: list[str] = []          # codes that confirmed a FRAUD decision
    report_mode: str = "manual"       # this device's choice
    can_report: bool = False          # FRAUD and not reported yet → show the Report button
    report_preview: list[str] = []    # who a report would go to (labels)


class LogMessage(BaseModel):
    sender: str = Field(max_length=64)
    text: str = Field(max_length=5000)
    received_at: datetime | None = None
    sim_slot: int | None = None


class ReportLogIn(BaseModel):
    scan_id: str
    messages: list[LogMessage] = Field(max_length=50)


class ManualReportIn(BaseModel):
    scan_id: str
    messages: list[LogMessage] = Field(default_factory=list, max_length=50)


class FeedbackIn(BaseModel):
    scan_id: str
    label: str = Field(pattern="^(scam|not_scam)$")


class BlocklistOut(BaseModel):
    version: str
    senders: list[str]
    domain_hashes: list[str]
    full: bool
