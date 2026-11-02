# ScamShield SMS

An Android **default SMS app** (SMS + MMS + dual SIM) with a security layer. Every incoming message is
checked by the ScamShield server: the sender against its database, and every link against threat
databases, Google Safe Browsing, security DNS, domain/certificate age and an isolated browser.
Only after all of that does the phone show a label:

| Label | Rule | What the user can do |
|---|---|---|
| **Surely fraud** | strong signs **and** confirmed by a database or link check | report to the state cyber-crime cell + imitated organisation — **automatically or after confirming** (user's choice) |
| **Surely spam** | strong signs, nothing confirmed them | forward to TRAI 1909 |
| *(nothing)* | everything else, and anything still being checked | — |

For the hackathon the server runs **on your own PC** behind a free Cloudflare Tunnel.

## Start here

| # | Guide | For |
|---|---|---|
| 1 | [**Set up on the phone**](docs/1_SETUP_ON_PHONE.md) | build the APK, install with adb, default SMS app, reporting choice, connect |
| 2 | [**Run the server on your PC**](docs/2_SERVER_ON_PC.md) | Docker (`run-local`) or native Python (`run-native.py`), tunnel, keys, email, self-test |
| 3 | [**Manual testing**](docs/3_MANUAL_TESTING.md) | checklist with expected results for every feature |

Order on the day before: **2 → 1 → 3**. Background and design: [`docs/SCAMSHIELD_SMS_CONTEXT.md`](docs/SCAMSHIELD_SMS_CONTEXT.md).
Moving to a VPS later: [`docs/HOSTING.md`](docs/HOSTING.md).

## Quick start

```bash
# PC — Docker
powershell -ExecutionPolicy Bypass -File run-local.ps1     # Windows
./run-local.sh                                             # macOS / Linux
#   …or without Docker (Python 3.12 + cloudflared):
python run-native.py

# then, in a second terminal
run-local.ps1 selftest  |  ./run-local.sh selftest  |  python run-native.py selftest
```
Phone: install the APK with `adb install -r app-debug.apk` → make it the default SMS app →
*Settings → Server* → paste the **Public address** and **API key** from the start box → *Save & connect*.

## Repository

```
android/        Kotlin + Jetpack Compose default SMS app
backend/        FastAPI API: analysis, decision, link checks, threat feeds, reports, admin, self-test
sandbox/        isolated Playwright browser that opens links
shared/         rules.yaml (points, thresholds, fraud_evidence) + brands.yaml — single source of rules
deploy/         docker-compose.local.yml + local.env.example (PC) · docker-compose.yml (VPS)
run-local.ps1 / run-local.sh    PC server with Docker
run-native.py                   PC server without Docker
tools/          export_rules.py · parity/ (Kotlin ↔ Python check) · demo_report.py
.github/        CI: backend tests, Android debug APK
```

## Developers

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r backend/requirements-dev.txt
cd backend && pytest -q          # 96 tests (SQLite); DATABASE_URL=postgresql+asyncpg://… to run them on PostgreSQL
```
- After editing `shared/`, run `python tools/export_rules.py` (CI checks it).
- `tools/parity/run_parity.sh` proves the phone and the server compute the same reason codes.
- Sample report without a server: `python tools/demo_report.py demo-out`.

## Safety rules built in

- Reports start in **demo mode**: emails go only to `DEMO_RECIPIENTS` (or are saved as files).
  In live mode only addresses marked `verified: true` in `backend/data/authorities.yaml` are emailed.
- Government portals (NCRP, Chakshu, 1930) are shown as manual channels — they are never automated.
- Only links are sent to third-party check services, never message text. A report contains only the
  reported sender's messages.
- Never share or commit `deploy/local.env`, `deploy/native.env`, `local-data/` or `android/local.properties`.
