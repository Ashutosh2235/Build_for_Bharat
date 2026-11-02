"""End-to-end self-test: plays the phone's part against a running ScamShield server.

    python -m app.selftest                         # uses API_KEY / ADMIN_PASSWORD from the environment
    python -m app.selftest --base https://xyz.trycloudflare.com --api-key K --admin-password P

Inside Docker the launchers run it for you:  run-local.ps1 selftest  /  ./run-local.sh selftest
Creates a few test scans/reports (sender numbers 9000000xxx) and cleans up the sender it blocks.
Exit code 0 = no failures.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
import uuid

import httpx

GENUINE = ("VM-HDFCBK-T", "482913 is your OTP for txn of Rs 500.00 at Amazon. Do not share it with anyone. -HDFC Bank")
FRAUD_AUTO = ("9000000101", "Dear HDFC customer, your account will be blocked today. Update KYC at "
              "https://hdfcbank-kyc-update.co/login and share the OTP to verify.")
FRAUD_MANUAL = ("9000000104", "Dear SBI customer, your YONO account is suspended. Update PAN now at "
                "https://sbi-yono-kyc-update.co/verify")
SPAM = ("9000000105", "Sir I am from ICICI bank, your account will be blocked today. Please share the OTP to stop it.")
HINDI = ("9000000102", "आपका एसबीआई खाता आज बंद हो जाएगा। तुरंत केवाईसी अपडेट करें: http://sbi-kyc-update.cfd")
WEAK = ("+923001234567", "Congratulations you won a lottery! Claim your prize now")
BLOCK_ME = "9000000199"

results: list[tuple[str, str, str]] = []


def record(status: str, name: str, detail: str = "") -> None:
    results.append((status, name, detail))
    mark = {"PASS": "\033[32mPASS\033[0m", "FAIL": "\033[31mFAIL\033[0m", "WARN": "\033[33mWARN\033[0m",
            "INFO": "INFO"}[status]
    print(f"  {mark}  {name}" + (f"  — {detail}" if detail else ""), flush=True)


def check(cond: bool, name: str, detail: str = "", warn: bool = False) -> bool:
    record("PASS" if cond else ("WARN" if warn else "FAIL"), name, detail)
    return cond


class Phone:
    def __init__(self, base: str, api_key: str, timeout: float, report_mode: str = "auto"):
        self.c = httpx.Client(base_url=base.rstrip("/"), timeout=timeout, headers={"X-Api-Key": api_key})
        self.token: str | None = None
        self.report_mode = report_mode

    def h(self) -> dict:
        return {"X-Device-Token": self.token} if self.token else {}

    def register(self) -> None:
        r = self.c.post("/v1/devices/register", json={
            "app_version": "selftest", "state_code": "PB", "consent_version": 1,
            "consent_server_check": True, "report_mode": self.report_mode})
        r.raise_for_status()
        self.token = r.json()["device_token"]

    def scan(self, sender: str, text: str | None, **extra) -> dict:
        body = {"message_id": f"selftest-{uuid.uuid4()}", "sender": sender, "text": text,
                "received_at": time.strftime("%Y-%m-%dT%H:%M:%S+05:30")} | extra
        r = self.c.post("/v1/scan", json=body, headers=self.h())
        r.raise_for_status()
        return r.json()

    def wait(self, scan: dict, seconds: float) -> dict:
        end = time.time() + seconds
        while scan["status"] == "partial" and time.time() < end:
            time.sleep(2)
            scan = self.c.get(f"/v1/scan/{scan['scan_id']}", headers=self.h()).json()
        return scan


def codes(scan: dict) -> set[str]:
    return {r["code"] for r in scan["reasons"]}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default=os.environ.get("SELFTEST_BASE", "http://127.0.0.1:8000"))
    ap.add_argument("--api-key", default=os.environ.get("API_KEY", "dev-api-key"))
    ap.add_argument("--admin-password", default=os.environ.get("ADMIN_PASSWORD", ""))
    ap.add_argument("--sandbox-target", default="",
                    help="page the sandbox should open (default: this server's /demo/kyc phishing demo page)")
    ap.add_argument("--wait", type=float, default=60, help="seconds to wait for link analysis")
    a = ap.parse_args()

    print(f"\nScamShield self-test against {a.base}\n")
    phone = Phone(a.base, a.api_key, timeout=30)

    # 1. server up
    try:
        health = phone.c.get("/v1/health").json()
    except (httpx.HTTPError, ValueError) as e:
        record("FAIL", "server reachable", str(e))
        return summary()
    check(health.get("ok") is True, "server reachable", f"report mode {health.get('report_mode')}")
    feeds = health.get("feed_entries", {})
    checks = health.get("checks", {})
    record("INFO", "link checks enabled",
           ", ".join(k for k, v in {**checks, "sandbox": health.get("sandbox"), "deep_scan": health.get("deep_scan")}.items()
                     if v and k != "email") + f"; reports by {checks.get('email', '?')}")
    check(sum(feeds.values()) > 0, "threat feeds downloaded",
          ", ".join(f"{k}: {v}" for k, v in feeds.items()) or "none yet — they download a minute after start; needs internet",
          warn=True)

    try:
        run_steps(phone, a, health)
    except httpx.HTTPError as e:
        record("FAIL", "request failed", f"{type(e).__name__}: {e} — server overloaded or address wrong?")
    return summary()


def shown(scan: dict) -> bool:
    return scan["verdict"] in ("FRAUD", "SPAM")


def wait_report(phone: Phone, rep_id: str, status: str) -> str:
    for _ in range(15):
        if status != "queued":
            break
        time.sleep(1)
        status = next((x["status"] for x in phone.c.get("/v1/reports", headers=phone.h()).json() if x["id"] == rep_id), status)
    return status


def run_steps(phone: Phone, a, health: dict) -> None:
    # 2. phone registration (automatic reporting)
    try:
        phone.register()
        record("PASS", "phone registration (API key accepted)")
    except httpx.HTTPStatusError as e:
        record("FAIL", "phone registration", f"HTTP {e.response.status_code} — API key wrong?")
        return

    # 3. genuine message → nothing shown
    s = phone.scan(*GENUINE)
    check(s["verdict"] == "NONE" and not s["reasons"], "genuine bank OTP: nothing shown", f"score {s['score']}")

    # 4. fraud: nothing shown while checks run, then "Surely fraud" + automatic report
    s = phone.scan(*FRAUD_AUTO)
    if s["status"] == "partial":
        check(s["verdict"] == "PENDING" and not s["reasons"] and s["label"] is None,
              "nothing shown while database + link checks run")
    s = phone.wait(s, a.wait)
    check(s["status"] == "complete", "database + link checks finished", s["status"])
    check(s["verdict"] == "FRAUD", "fake-bank KYC message is 'Surely fraud'",
          f"score {s['score']}, evidence: {', '.join(s.get('evidence', []))}")
    consulted = [f"{c['name']}={c['status']}" for u in s.get("urls", []) for c in u.get("checks", [])]
    record("INFO", "link checks consulted", "; ".join(consulted) or "-")
    check(s.get("impersonated_brand") == "HDFC", "imitated brand identified", str(s.get("impersonated_brand")))
    rep = s.get("report")
    if check(rep is not None, "automatic mode: report created without asking", rep and f"{rep['id']} {rep['status']}"):
        if rep["status"] == "awaiting_log":
            r = phone.c.post("/v1/report/log", headers=phone.h(), json={"scan_id": s["scan_id"], "messages": [
                {"sender": FRAUD_AUTO[0], "text": FRAUD_AUTO[1], "received_at": time.strftime("%Y-%m-%dT%H:%M:%S+05:30")}]})
            st = wait_report(phone, rep["id"], r.json().get("status"))
            check(st in ("demo_sent", "sent"), "report emailed / saved", st, warn=st in ("no_recipient", "failed", "duplicate"))
        else:
            record("INFO", "report status", rep["status"])
        s2 = phone.wait(phone.scan(*FRAUD_AUTO), a.wait)
        check(s2.get("report") is not None and s2["report"]["status"] == "duplicate",
              "repeat fraud is de-duplicated (no second email)", (s2.get("report") or {}).get("status", "-"))

    # 5. manual reporting: nothing is sent until the user taps Report
    manual = Phone(phone.c.base_url.__str__(), phone.c.headers["X-Api-Key"], 30, report_mode="manual")
    manual.register()
    s = manual.wait(manual.scan(*FRAUD_MANUAL), a.wait)
    if check(s["verdict"] == "FRAUD" and s["report"] is None and s["can_report"],
             "manual mode: 'Surely fraud' shown, nothing reported yet", f"would go to: {', '.join(s['report_preview']) or '-'}"):
        r = manual.c.post("/v1/reports", headers=manual.h(), json={"scan_id": s["scan_id"], "messages": [
            {"sender": FRAUD_MANUAL[0], "text": FRAUD_MANUAL[1], "received_at": time.strftime("%Y-%m-%dT%H:%M:%S+05:30")}]})
        st = wait_report(manual, r.json().get("id", ""), r.json().get("status")) if r.status_code == 200 else f"HTTP {r.status_code}"
        check(st in ("demo_sent", "sent", "duplicate"), "manual mode: Report button sends the report", st,
              warn=st in ("no_recipient", "failed"))

    # 6. spam: labelled, never reported
    s = phone.wait(phone.scan(*SPAM), a.wait)
    check(s["verdict"] == "SPAM" and s["report"] is None, "strong signs without database/link proof are 'Surely spam'",
          f"score {s['score']}")
    r = phone.c.post("/v1/reports", headers=phone.h(), json={"scan_id": s["scan_id"], "messages": []})
    check(r.status_code == 409, "spam cannot be reported to authorities", f"HTTP {r.status_code}")

    # 7. weak signs → nothing
    s = phone.wait(phone.scan(*WEAK), a.wait)
    check(not shown(s), "weak signs only: nothing shown", f"{s['verdict']} score {s['score']}")

    # 8. privacy mode (no text sent, only on-device reason codes)
    s = phone.wait(phone.scan("9000000103", None, urls=["https://hdfcbank-kyc-update.co/login"],
                              local={"score": 70, "reasons": ["KYC_BLOCK_THREAT", "OTP_REQUEST", "BRAND_CLAIM"]}), a.wait)
    check(s["verdict"] == "FRAUD", "privacy mode (link + codes only) works", f"score {s['score']}")

    # 9. Hindi
    s = phone.wait(phone.scan(*HINDI), a.wait)
    check(s["verdict"] == "FRAUD", "Hindi KYC scam with look-alike link", f"{s['verdict']} {s['score']}")

    # 10. sandbox opens the fictional phishing page (/demo/kyc on this server) → evidence → "Surely fraud"
    target = a.sandbox_target or f"{a.base.rstrip('/')}/demo/kyc"
    host = httpx.URL(target).host
    if not health.get("sandbox"):
        record("INFO", "sandbox", "disabled (SANDBOX_ENABLED=false)")
    elif host in ("127.0.0.1", "localhost") and not a.sandbox_target:
        record("INFO", "sandbox test skipped", "the sandbox refuses local addresses by design — "
               "run the self-test with --base <public tunnel address> to include it")
    else:
        s = phone.wait(phone.scan("9000000106", f"Bharat Demo Bank: your account is suspended. Verify now: {target}"), a.wait)
        sandbox = [c for u in s.get("urls", []) for c in u.get("checks", []) if c["name"] == "Isolated browser sandbox"]
        found = {"LOGIN_FORM", "DOWNLOAD_ATTEMPT"} & codes(s)
        check(s["verdict"] == "FRAUD" and bool(found), "sandbox: demo phishing page is 'Surely fraud'",
              f"{s['verdict']}; sandbox: {sandbox[0]['detail'] if sandbox else 'no result'}", warn=not sandbox)
        shot = next((u.get("screenshot_url") for u in s.get("urls", []) if u.get("screenshot_url")), None)
        if shot:
            img = phone.c.get(shot)
            check(img.status_code == 200 and img.content[:4] == b"\x89PNG", "sandbox screenshot downloadable", shot)

    # 11. feedback
    r = phone.c.post("/v1/feedback", headers=phone.h(), json={"scan_id": s["scan_id"], "label": "not_scam"})
    check(r.status_code == 204, "'Not a scam' feedback accepted")

    # 12. admin block → instant "Surely fraud" → offline blocklist
    if a.admin_password:
        phone.scan(BLOCK_ME, "hello")
        auth = ("admin", a.admin_password)
        r = phone.c.put(f"/admin/senders/+91{BLOCK_ME}", auth=auth, json={"status": "blocked"})
        if check(r.status_code == 200, "admin login + block sender", f"HTTP {r.status_code}"):
            s = phone.scan(BLOCK_ME, "hi again")
            check(s["verdict"] == "FRAUD" and "SENDER_BLOCKED" in codes(s), "blocked sender is 'Surely fraud'")
            bl = phone.c.get("/v1/sync/blocklist", headers=phone.h()).json()
            check(f"+91{BLOCK_ME}" in bl["senders"], "blocklist sync for phones",
                  f"{len(bl['senders'])} senders, {len(bl['domain_hashes'])} domain hashes")
            phone.c.put(f"/admin/senders/+91{BLOCK_ME}", auth=auth, json={"status": "unknown"})
        stats = phone.c.get("/admin/stats", auth=auth)
        check(stats.status_code == 200, "admin stats", str(stats.json().get("reports")) if stats.status_code == 200 else "")
    else:
        record("INFO", "admin checks skipped", "pass --admin-password to include them")


def summary() -> int:
    fails = sum(1 for r in results if r[0] == "FAIL")
    warns = sum(1 for r in results if r[0] == "WARN")
    passes = sum(1 for r in results if r[0] == "PASS")
    print(f"\n{passes} passed, {warns} warnings, {fails} failed\n")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
