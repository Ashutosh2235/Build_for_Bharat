import os
import sys
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

# Test configuration (must be set before app modules read settings)
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("API_KEY", "test-key")
os.environ.setdefault("DEEP_SCAN_ENABLED", "false")
os.environ.setdefault("SANDBOX_ENABLED", "false")
os.environ.setdefault("SECURE_DNS_ENABLED", "false")   # tests enable network checks explicitly
os.environ.setdefault("CRTSH_ENABLED", "false")
os.environ.setdefault("GOOGLE_SAFEBROWSING_KEY", "")
os.environ.setdefault("REPORT_MODE", "demo")
os.environ.setdefault("DEMO_RECIPIENTS", "team-demo@example.com")
os.environ.setdefault("SMTP_HOST", "smtp.test.invalid")
os.environ.setdefault("FERNET_KEY", "ZmDfcTF7_60GrrY167zsiPd67pEvs0aGOv2oasOM1Pg=")
