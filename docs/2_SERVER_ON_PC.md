# 2 · Run the ScamShield server on your PC

For the hackathon there is no hosting service. Your PC runs the whole server, and a free
**Cloudflare Tunnel** gives it a public `https://` address the phone can reach from any network.
The server is alive while the launcher runs; close it and it is gone.

```
Phone (Wi-Fi or mobile data)
   │  HTTPS
   ▼
Cloudflare ──── tunnel (outbound connection started by your PC) ────▶ your PC
                                                                       ├─ API            (port 8000, 127.0.0.1 only)
                                                                       ├─ link sandbox   (isolated browser)
                                                                       ├─ database       (PostgreSQL in Docker / SQLite native)
                                                                       └─ threat-feed sync
```

Nothing on your PC is opened to the internet or to your Wi-Fi. The tunnel is an outgoing connection,
and the API listens on `127.0.0.1` only.

Next documents: [1 · Set up the phone](1_SETUP_ON_PHONE.md) · [3 · Manual testing](3_MANUAL_TESTING.md)

---

## 0. Pick a way to run it

| | **Option A — Docker (recommended)** | **Option B — Native Python (no Docker)** |
|---|---|---|
| Start command | `run-local.ps1` / `run-local.sh` | `python run-native.py` |
| Database | PostgreSQL 16 (container) | SQLite file in `local-data/` |
| Link sandbox | Locked-down container (read-only, no LAN, 1 GB limit) | Separate process on your PC (still refuses LAN / private addresses) |
| Install size | ~3 GB first download | ~400 MB (Python packages + Chromium) |
| Use when | Docker Desktop installs and runs | Docker won't install (old Windows, no admin rights, low RAM) |

Both give the phone the same API, the same checks and the same decisions.

---

## 1. What the server does with each message

Read this once — it is why some test messages show a label and others show nothing.

1. The phone sends the **sender**, the **links**, and the on-device warning-sign codes (and the message
   text only if the user allowed it). While the server works, the phone shows **no label at all**.
2. The server **checks the sender** against its own database (numbers blocked by the admin, numbers
   already reported).
3. The server **checks every link**:

   | Check | Needs | What counts as proof |
   |---|---|---|
   | Threat-feed database — OpenPhish, phishunt (verified), Phishing.Database; URLhaus + ThreatFox with an abuse.ch key | nothing (downloaded every few hours) | link or domain is listed |
   | Google Safe Browsing | free API key | link is listed |
   | Quad9 threat DNS · Cloudflare security DNS | nothing | the security resolver blocks the domain while the normal resolver answers |
   | Domain age (RDAP) · certificate age (crt.sh) | nothing | domain or certificate younger than 30 days |
   | Look-alike / IP / punycode / APK link | nothing | e.g. `hdfcbank-kyc-update.co` imitating HDFC |
   | Redirect expansion | nothing | follows `bit.ly` etc. to the real destination |
   | Isolated browser sandbox | Playwright Chromium | page has a login/OTP/card form, or tries to download an app |

4. Only when **all** of that is finished does the server decide:

   | Decision | Rule | Phone shows | Reportable |
   |---|---|---|---|
   | **Surely fraud** | risk score ≥ 60 **and** at least one proof from step 2 or 3 | red label + alarm notification | yes (auto or manual, see below) |
   | **Surely spam** | risk score ≥ 60, but no database or link check confirmed it | amber label, silent notification | no — only "Forward to TRAI 1909" |
   | *(nothing)* | everything else, including checks still running | nothing | — |

A check that is unreachable (no internet, no key, provider down) is recorded as *unavailable* — it
never counts as proof and never blocks the decision.

**Reporting a "Surely fraud" message** depends on the setting the user picks on the phone:
- **Automatic** — the report is created as soon as the decision is made; the phone uploads that
  sender's messages and the server emails the report.
- **Manual (default)** — the phone shows a *Report to authorities* button; nothing is sent until the user confirms.

Reports go to the state cyber-crime cell and the organisation being imitated. In **demo mode**
(the default, keep it for the hackathon) every email goes only to your `DEMO_RECIPIENTS`, or is saved
as a file if no email is set up. The same sender + domain is reported at most once per 24 hours.

---

## 2. What you need

| | Option A (Docker) | Option B (native) |
|---|---|---|
| OS | Windows 10/11 64-bit, macOS, Linux | same |
| RAM / free disk | 8 GB RAM (give Docker ≥ 4 GB) · 15 GB | 4 GB RAM · 2 GB |
| Software | Docker Desktop | Python **3.12** (3.11+ works), `cloudflared` |
| Network | internet on the PC; the tunnel needs **outbound port 7844** (see §8) | same |

Do the first start **at home, the day before** — the downloads are large and college Wi-Fi often blocks them.

---

## 3. Option A — Docker (recommended)

### 3.1 One-time setup

1. Install **Docker Desktop**: https://www.docker.com/products/docker-desktop/ → start it → wait for *Engine running*.
   - Windows: it installs WSL 2 itself; reboot if asked. *Settings → Resources* → memory ≥ 4 GB if the slider is shown.
2. Unzip the project somewhere short, e.g. `C:\scamshield` or `~/scamshield`.
3. Open a terminal **in that folder** and start it (10–15 min the first time):
   - Windows (PowerShell):
     ```powershell
     powershell -ExecutionPolicy Bypass -File run-local.ps1
     ```
   - macOS / Linux:
     ```bash
     ./run-local.sh
     ```
4. The first run creates `deploy/local.env` with random secrets (API key, admin password, database
   password, encryption key). **Keep that file** and never share or commit it.
5. It ends with:
   ```
   ==================== ScamShield server is running ====================
    Public address : https://random-words-here.trycloudflare.com
    API key        : 3f9c…
    Admin login    : admin / 8a1d…
    Report mode    : demo   (emails: saved as files — ./run-local.sh reports)
   ```
   Put **Public address** and **API key** into the phone ([1 · Set up the phone](1_SETUP_ON_PHONE.md), step 5).
6. Run the self-test (see §6). Expect `… passed, 0 failed`.

### 3.2 Commands

`run-local.ps1 <command>` on Windows, `./run-local.sh <command>` on macOS/Linux:

| Command | Does |
|---|---|
| `start` (default) | start everything, print the phone settings |
| `url` | print the public address again |
| `status` | containers + health |
| `logs` | live logs (Ctrl+C stops watching, not the server) |
| `selftest` | play the phone's part against the running server (PASS/FAIL list) |
| `reports` | copy generated reports (PDF, JSON, `.eml`) to `local-reports/` |
| `stop` | stop everything — data is kept |
| `reset` | stop and **delete** all data (after the hackathon) |

---

## 4. Option B — Native Python (no Docker)

### 4.1 One-time setup

1. Install **Python 3.12** from https://www.python.org/downloads/ (Windows: tick *Add python.exe to PATH*).
2. Install **cloudflared** (gives the public address):
   - Windows: `winget install --id Cloudflare.cloudflared` (or download the `.msi` from
     https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/)
   - macOS: `brew install cloudflared` · Linux: the `.deb`/`.rpm` from the same page
   - Check: `cloudflared --version`
3. In the project folder:
   - Windows (PowerShell):
     ```powershell
     py -3.12 -m venv .venv
     .venv\Scripts\Activate.ps1          # if blocked: Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
     pip install -r backend/requirements.txt -r sandbox/requirements.txt
     python -m playwright install chromium
     ```
   - macOS / Linux:
     ```bash
     python3.12 -m venv .venv && . .venv/bin/activate
     pip install -r backend/requirements.txt -r sandbox/requirements.txt
     python -m playwright install chromium      # Linux may also need: python -m playwright install-deps chromium
     ```
   Already have Chrome and the Chromium download fails? Set `CHROMIUM_PATH=` in `deploy/native.env`
   to your Chrome executable (e.g. `C:\Program Files\Google\Chrome\Application\chrome.exe`).

### 4.2 Start

```bash
python run-native.py            # with the .venv activated
```
- First run creates `deploy/native.env` with fresh secrets and `local-data/` (database, reports, screenshots, logs).
- It starts the sandbox, the API (feeds download inside the API), and `cloudflared` if it is installed,
  then prints the same box as Option A.
- `Link sandbox : off` means Playwright/Chromium isn't installed — the server still works, but pages
  aren't opened, so fewer messages reach "Surely fraud".
- Stop with **Ctrl+C**. Logs: `local-data/logs/api.log`, `sandbox.log`, `tunnel.log`.
- Self-test, in a second terminal (activate the `.venv` there too): `python run-native.py selftest` (see §6).

---

## 5. Settings (`deploy/local.env` for Docker, `deploy/native.env` for native)

Edit the file, then restart (`stop` + `start`, or Ctrl+C + `python run-native.py`).
Keep comments on their own lines.

### 5.1 Link-check services (all free)

| Setting | Get it | Turns on |
|---|---|---|
| `GOOGLE_SAFEBROWSING_KEY=` | Google Cloud console → new project → *APIs & Services → Library* → **Safe Browsing API** → Enable → *Credentials → Create credentials → API key* | Google Safe Browsing |
| `ABUSECH_AUTH_KEY=` | https://auth.abuse.ch → sign in (Google/GitHub/X/LinkedIn) → *Optional → Auth-Key* | URLhaus + ThreatFox feeds |
| `SECURE_DNS_ENABLED=true` | nothing | Quad9 + Cloudflare security DNS |
| `CRTSH_ENABLED=true` | nothing | certificate age |

Without any key you still have OpenPhish, phishunt, Phishing.Database, both security DNS checks,
domain/certificate age, look-alike detection and the sandbox. Only **links** are sent to these
services — never message text.

### 5.2 Email for reports

- **Nothing set (default):** reports are saved as files — Docker: `reports` command → `local-reports/`;
  native: `local-data/reports/` (each email is an `.eml` in `outbox/`, open it in Outlook/Thunderbird).
- **Gmail:** turn on 2-Step Verification → https://myaccount.google.com/apppasswords → create an app password →
  ```
  SMTP_HOST=smtp.gmail.com
  SMTP_PORT=587
  SMTP_USER=yourname@gmail.com
  SMTP_PASSWORD=abcdefghijklmnop
  MAIL_FROM=ScamShield Reports <yourname@gmail.com>
  DEMO_RECIPIENTS=team-inbox@gmail.com
  ```
- **Company mailbox:** the same fields with its SMTP server (e.g. `smtp.hostinger.com`, `smtp.zoho.in`).

Leave `REPORT_MODE=demo` for the hackathon. In `live` mode the server emails only authority addresses
marked `verified: true` in `backend/data/authorities.yaml` — check each one against the official
nodal-officer list on cybercrime.gov.in before switching.

### 5.3 Fixed address (optional, recommended)

The free quick tunnel gives a **new address every start**, so the phone must be updated each time.
With a domain on Cloudflare you can have a permanent `https://scamshield-api.yourdomain.in`:

1. Cloudflare dashboard → **Zero Trust** → *Networks* → **Tunnels** → *Create a tunnel* → **Cloudflared** → name `scamshield-pc` → Save.
2. On *Install connector*, copy only the long token after `--token` (starts with `eyJ`).
3. Next → **Public hostname**: subdomain `scamshield-api`, your domain, type **HTTP**, URL:
   - Option A (Docker): **`api:8000`**
   - Option B (native): **`localhost:8000`**
4. Put it in the settings file: `TUNNEL_TOKEN=eyJ…` → restart. The launcher switches to the fixed tunnel by itself.
5. Phone: Server URL = `https://scamshield-api.yourdomain.in` (once).

---

## 6. Self-test (do this before every demo)

| | Command |
|---|---|
| Docker | `run-local.ps1 selftest` / `./run-local.sh selftest` |
| Native | `python run-native.py selftest` — add `--base https://<your public address>` to include the sandbox step |

It plays the phone's part and prints PASS / WARN / FAIL lines. What it checks:

| Step | Expected |
|---|---|
| server reachable · phone registration | PASS |
| threat feeds downloaded | PASS (WARN in the first minute after start, or without internet) |
| genuine bank OTP | nothing shown |
| fake-bank KYC message | nothing shown while checks run → **Surely fraud**; HDFC identified; *link checks consulted* lists every check and its result |
| automatic mode | report created without asking → emailed / saved → repeat is de-duplicated |
| manual mode | Surely fraud shown, **nothing reported** until the Report call → then sent |
| OTP request without link | **Surely spam**; reporting it is refused (HTTP 409) |
| weak signs only | nothing shown |
| privacy mode, Hindi | Surely fraud |
| sandbox | opens this server's fictional phishing page `/demo/kyc` → login form found → Surely fraud, screenshot downloadable |
| admin block | blocked number becomes Surely fraud, appears in the phones' offline blocklist |

Last line: `N passed, 0 warnings, 0 failed`. The sandbox step is skipped (INFO) when the test runs
against `127.0.0.1`, because the sandbox refuses local addresses by design.

---

## 7. On hackathon day

1. Start Docker Desktop (Option A) → `run-local … start`, or activate `.venv` → `python run-native.py`.
2. Quick tunnel? Copy the new **Public address** into the phone: *Settings → Server → Save & connect*.
3. Run the self-test.
4. Keep the PC awake and plugged in:
   - Windows: `powercfg /change standby-timeout-ac 0`, and *Settings → Power → Lid close → Do nothing* on a laptop
   - macOS: `caffeinate -dims` in a terminal window you leave open
5. Watch it during the demo: Docker `logs`, native `local-data/logs/api.log`.
   Admin view (in a browser, login `admin` + the admin password): `https://<public address>/admin/stats`, `/admin/reports`, `/admin/senders`.

---

## 8. College Wi-Fi

- The **phone** can be on any network — it only talks to Cloudflare over HTTPS.
- The **PC's** tunnel connects out on **port 7844**, which many campus networks block. If the address
  shows *not ready* or `tunnel.log` / `logs` show connection errors, connect the **PC to a phone hotspot**.
  The tunnel and checks use very little data.
- Gmail SMTP (port 587) can be blocked the same way — the hotspot fixes it, otherwise reports are still saved as files.
- Online checks (Safe Browsing, DNS, crt.sh, RDAP) also need the PC's internet. If they are blocked
  they show *unavailable*: fewer messages reach "Surely fraud", but nothing breaks.

---

## 9. Is it safe to run on my PC?

- Suspicious pages are opened only by the sandbox, never by the phone. It refuses private/LAN
  addresses, so a scam link can't reach your router or other devices. With Docker it also runs
  read-only, without your files and memory-limited. Natively it's a normal process with the same
  address checks — prefer Docker when you can.
- The scam websites see your internet connection's public IP address. Acceptable for a hackathon.
- Admin pages need the random admin password. The API needs the API key.
- Data stays on your PC: Docker volumes (`reset` deletes) or `local-data/` (delete the folder).
- Never share `deploy/local.env`, `deploy/native.env` or `local-data/`.

---

## 10. Troubleshooting

| Problem | Fix |
|---|---|
| "Docker is not running" | Start Docker Desktop, wait for *Engine running* |
| First build fails with network errors | Retry on a better connection (home Wi-Fi / hotspot) |
| Public address "not ready" | Port 7844 blocked → PC on a hotspot → restart |
| Native: `cloudflared` not found | Install it (§4.1), open a **new** terminal, check `cloudflared --version` |
| Native: `Link sandbox : off` | `pip install -r sandbox/requirements.txt` + `python -m playwright install chromium`, or set `CHROMIUM_PATH` |
| Native: "Missing Python packages" | Activate `.venv` first, then `pip install -r backend/requirements.txt -r sandbox/requirements.txt` |
| Native: port 8000 already in use | Close the other program, or `SCAMSHIELD_PORT=8010 python run-native.py` (PowerShell: `$env:SCAMSHIELD_PORT=8010`) |
| Phone: "Server not reachable" | Quick-tunnel address changed → `url` (Docker) or read the start box → re-enter on the phone |
| Phone: 401 / invalid API key | Re-copy `API_KEY` from the settings file |
| Self-test: every link check *unavailable* | PC has no internet / a proxy blocks it → hotspot |
| Self-test: report `no_recipient` | Demo mode with SMTP set but `DEMO_RECIPIENTS` empty → add your inbox |
| Server did not start | Docker `logs`, native `local-data/logs/api.log` — usually a broken line in the settings file |
| Windows: "running scripts is disabled" | Use the full `powershell -ExecutionPolicy Bypass -File run-local.ps1` |
| Start over completely | Docker: `reset`. Native: stop it, delete `local-data/` (and `deploy/native.env` for new secrets — the phone must then reconnect) |
