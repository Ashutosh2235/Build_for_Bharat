"""Runtime configuration (env vars, see deploy/.env.example)."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated

from pydantic import field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]
REPO_DIR = BACKEND_DIR.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "development"
    api_key: str = "dev-api-key"
    jwt_secret: str = "dev-jwt-secret"
    admin_password: str = "change-me"

    database_url: str = "sqlite+aiosqlite:///./scamshield-dev.db"
    redis_url: str = "redis://localhost:6379/0"

    # Where the shared rule files (rules.yaml, brands.yaml) and server data live
    shared_dir: Path = REPO_DIR / "shared"
    data_dir: Path = BACKEND_DIR / "data"
    screenshot_dir: Path = Path("./var/screens")
    report_dir: Path = Path("./var/reports")
    # Empty = derive from each request (works behind a tunnel whose address changes)
    public_base_url: str = ""

    # Deep analysis
    deep_scan_enabled: bool = True
    sandbox_enabled: bool = False
    sandbox_url: str = "http://sandbox:8100"
    sandbox_timeout_s: float = 30.0
    http_timeout_s: float = 6.0
    max_urls_per_message: int = 5
    url_cache_hours: int = 24

    # Reporting
    reports_enabled: bool = True          # global kill switch
    report_mode: str = "demo"             # demo | live
    demo_recipients: Annotated[list[str], NoDecode] = []
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_password: str = ""
    smtp_starttls: bool = True
    mail_from: str = "ScamShield Reports <reports@example.com>"
    mail_reply_to: str = ""

    # Threat feeds
    abusech_auth_key: str = ""            # URLhaus + ThreatFox feeds
    google_safebrowsing_key: str = ""     # live link check (services/link_checks.py)
    crtsh_enabled: bool = True            # certificate age via crt.sh (no key)
    link_check_timeout_s: float = 8.0
    # Protective-DNS check (no key needed): providers from services/link_checks.py
    secure_dns_enabled: bool = True
    secure_dns_providers: Annotated[list[str], NoDecode] = ["quad9", "cloudflare"]
    threatfox_url: str = "https://threatfox-api.abuse.ch/api/v1/"
    # Verified tier only: phishunt's unfiltered feed also lists unconfirmed "suspicious" domains
    phishunt_feed_url: str = "https://phishunt.io/api/v1/domains?tier=verified&limit=1000"
    # Feeds to download (app/feeds/sync.py). phishing_db_links (66 MB, ~1M URLs) is off by default.
    feeds: Annotated[list[str], NoDecode] = ["openphish", "urlhaus", "threatfox", "phishunt", "phishing_db_domains"]
    # Fictional phishing-style page at /demo/kyc for live demos (app/api/demo.py)
    demo_pages_enabled: bool = True
    # Run the threat-feed refresher inside the API process (single-process / no-Docker mode)
    feeds_in_process: bool = False
    openphish_url: str = "https://openphish.com/feed.txt"
    phishing_db_domains_url: str = (
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"
    )
    phishing_db_links_url: str = (
        "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt"
    )
    urlhaus_recent_url: str = "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    blocklist_max_domains: int = 50_000

    # Privacy
    fernet_key: str = ""                  # required in production; dev generates an ephemeral one

    @field_validator("demo_recipients", "secure_dns_providers", "feeds", mode="before")
    @classmethod
    def _split_csv(cls, v):  # "a@x.in,b@y.in" -> list
        if isinstance(v, str):
            return [x.strip() for x in v.split(",") if x.strip()]
        return v

    @field_validator("report_mode")
    @classmethod
    def _mode(cls, v: str) -> str:
        v = v.lower().strip()
        if v not in {"demo", "live"}:
            raise ValueError("REPORT_MODE must be 'demo' or 'live'")
        return v

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
