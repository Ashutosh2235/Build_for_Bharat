#!/usr/bin/env python3
"""ScamShield server on this PC WITHOUT Docker (fallback when Docker Desktop can't be used).

    python run-native.py            start API + link sandbox + feeds (+ tunnel if cloudflared is installed)
    python run-native.py selftest   run the self-test against the running server (second terminal)

One-time setup (see docs/2_SERVER_ON_PC.md, section 4):
    python -m venv .venv  &&  activate it
    pip install -r backend/requirements.txt -r sandbox/requirements.txt
    python -m playwright install chromium          (for the link sandbox)
    + cloudflared on PATH for the public address   (optional for local testing)

Data: local-data/ (SQLite database, reports, screenshots). Settings: deploy/native.env (created on first run).
Stop with Ctrl+C.
"""
from __future__ import annotations

import base64
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "local-data"
ENV_FILE = ROOT / "deploy" / "native.env"
PY = sys.executable
API_PORT = int(os.environ.get("SCAMSHIELD_PORT", "8000"))
SANDBOX_PORT = 8100

TEMPLATE = """# ScamShield native (no-Docker) settings. Keep comments on their own lines.
APP_ENV=production
API_KEY={api_key}
ADMIN_PASSWORD={admin}
FERNET_KEY={fernet}
DATABASE_URL=sqlite+aiosqlite:///{db}
REPORT_DIR={reports}
SCREENSHOT_DIR={screens}
PUBLIC_BASE_URL=
FEEDS_IN_PROCESS=true
DEEP_SCAN_ENABLED=true
# auto = on if Playwright + Chromium are installed
SANDBOX_ENABLED=auto
SANDBOX_URL=http://127.0.0.1:{sandbox_port}
SECURE_DNS_ENABLED=true
# Certificate history via crt.sh (no key)
CRTSH_ENABLED=true
REPORT_MODE=demo
REPORTS_ENABLED=true
DEMO_RECIPIENTS=
# Email (leave SMTP_HOST empty to save reports as files in local-data/reports/outbox)
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
MAIL_FROM=ScamShield Reports <you@gmail.com>
MAIL_REPLY_TO=
GOOGLE_SAFEBROWSING_KEY=
ABUSECH_AUTH_KEY=
# Fixed Cloudflare tunnel (optional): token from Zero Trust > Networks > Tunnels
TUNNEL_TOKEN=
# Optional: path to an installed Chrome/Chromium for the sandbox instead of Playwright's download
CHROMIUM_PATH=
"""


def read_env() -> dict[str, str]:
    env = {}
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


def ensure_env() -> dict[str, str]:
    if not ENV_FILE.exists():
        DATA.mkdir(exist_ok=True)
        ENV_FILE.write_text(TEMPLATE.format(
            api_key=secrets.token_hex(24), admin=secrets.token_hex(24),
            fernet=base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
            db=(DATA / "scamshield.db").as_posix(), reports=(DATA / "reports").as_posix(),
            screens=(DATA / "screens").as_posix(), sandbox_port=SANDBOX_PORT), encoding="utf-8")
        print(f"Created {ENV_FILE.relative_to(ROOT)} with fresh secrets.")
    return read_env()


def have_playwright(env: dict[str, str]) -> bool:
    try:
        import playwright  # noqa: F401
    except ImportError:
        return False
    if env.get("CHROMIUM_PATH"):
        return Path(env["CHROMIUM_PATH"]).exists()
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            return Path(p.chromium.executable_path).exists()
    except Exception:
        return False


def wait_http(url: str, seconds: float) -> bool:
    end = time.time() + seconds
    while time.time() < end:
        try:
            with urllib.request.urlopen(url, timeout=3) as r:
                if r.status == 200:
                    return True
        except OSError:
            time.sleep(1)
    return False


class Proc:
    def __init__(self, name: str, args: list[str], cwd: Path, env: dict[str, str], log: Path, watch=None):
        self.name, self.log = name, log
        self.fh = open(log, "a", encoding="utf-8")
        self.p = subprocess.Popen(args, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  text=True, encoding="utf-8", errors="replace", bufsize=1)
        self.watch = watch
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self):
        for line in self.p.stdout:
            self.fh.write(line)
            self.fh.flush()
            if self.watch:
                self.watch(line)

    def stop(self):
        if self.p.poll() is None:
            self.p.terminate()
            try:
                self.p.wait(10)
            except subprocess.TimeoutExpired:
                self.p.kill()


def start() -> int:
    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
    except ImportError:
        print("Missing Python packages. Run:  pip install -r backend/requirements.txt -r sandbox/requirements.txt")
        return 1
    env = ensure_env()
    DATA.mkdir(exist_ok=True)
    (DATA / "logs").mkdir(exist_ok=True)
    base_env = {**os.environ, **{k: v for k, v in env.items() if v != ""}}

    sandbox_on = env.get("SANDBOX_ENABLED", "auto").lower()
    sandbox_on = have_playwright(env) if sandbox_on == "auto" else sandbox_on == "true"
    base_env["SANDBOX_ENABLED"] = "true" if sandbox_on else "false"
    procs: list[Proc] = []

    def shutdown(*_):
        for pr in reversed(procs):
            pr.stop()
        print("\nScamShield stopped.")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, shutdown)

    if sandbox_on:
        sb_env = {**base_env, "SCREEN_DIR": env["SCREENSHOT_DIR"]}
        procs.append(Proc("sandbox", [PY, "-m", "uvicorn", "server:app", "--host", "127.0.0.1", "--port", str(SANDBOX_PORT)],
                          ROOT / "sandbox", sb_env, DATA / "logs" / "sandbox.log"))
        if not wait_http(f"http://127.0.0.1:{SANDBOX_PORT}/health", 60):
            print("Sandbox did not start (see local-data/logs/sandbox.log) — continuing without it.")
            base_env["SANDBOX_ENABLED"] = "false"
    else:
        print("Link sandbox OFF (install it: pip install -r sandbox/requirements.txt && python -m playwright install chromium)")

    procs.append(Proc("api", [PY, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(API_PORT),
                              "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1"],
                      ROOT / "backend", base_env, DATA / "logs" / "api.log"))
    if not wait_http(f"http://127.0.0.1:{API_PORT}/v1/health", 90):
        print("API did not start. Last log lines:")
        print("".join((DATA / "logs" / "api.log").read_text(encoding="utf-8", errors="replace").splitlines(True)[-25:]))
        shutdown()

    public = {"url": None}
    cloudflared = shutil.which("cloudflared")
    if cloudflared:
        def watch(line: str):
            m = re.search(r"https://[a-z0-9-]+\.trycloudflare\.com", line)
            if m:
                public["url"] = m.group(0)
        args = ([cloudflared, "tunnel", "--no-autoupdate", "run", "--token", env["TUNNEL_TOKEN"]] if env.get("TUNNEL_TOKEN")
                else [cloudflared, "tunnel", "--no-autoupdate", "--url", f"http://127.0.0.1:{API_PORT}"])
        procs.append(Proc("tunnel", args, ROOT, base_env, DATA / "logs" / "tunnel.log", watch))
        if not env.get("TUNNEL_TOKEN"):
            for _ in range(30):
                if public["url"]:
                    break
                time.sleep(1)
        else:
            public["url"] = "(your fixed hostname from the Cloudflare tunnel settings)"

    print("\n==================== ScamShield server is running ====================")
    local_only = f"(no tunnel - install cloudflared; local only: http://127.0.0.1:{API_PORT})"
    print(f" Public address : {public['url'] or local_only}")
    print(f" API key        : {env['API_KEY']}")
    print(f" Admin login    : admin / {env['ADMIN_PASSWORD']}")
    print(f" Link sandbox   : {'on' if base_env['SANDBOX_ENABLED'] == 'true' else 'off'}")
    print(f" Reports        : {'emailed via ' + env['SMTP_HOST'] if env.get('SMTP_HOST') else 'saved in local-data/reports'}")
    print("\n On the phone: ScamShield > Settings > Server > URL + API key > Save & connect")
    print(" Self-test (second terminal):  python run-native.py selftest")
    print(" Logs: local-data/logs/   Stop: Ctrl+C")
    print("=======================================================================\n")
    while True:
        time.sleep(2)
        for pr in procs:
            if pr.p.poll() is not None:
                print(f"{pr.name} stopped unexpectedly (see {pr.log.relative_to(ROOT)}). Shutting down.")
                shutdown()


def selftest() -> int:
    env = ensure_env()
    os.environ.update({"API_KEY": env["API_KEY"], "ADMIN_PASSWORD": env["ADMIN_PASSWORD"]})
    sys.path.insert(0, str(ROOT / "backend"))
    from app.selftest import main as run
    sys.argv = [sys.argv[0], "--base", f"http://127.0.0.1:{API_PORT}", *sys.argv[2:]]
    return run()


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "start"
    sys.exit(selftest() if cmd == "selftest" else start())
