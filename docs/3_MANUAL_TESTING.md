# 3 · Manual testing

A checklist to go through on the phone before the demo. Each test says what to do and what you
should see. Tick them off; if one fails, see §7.

Before you start:
- Server running on the PC and its **self-test** passes ([2 · Server on your PC](2_SERVER_ON_PC.md) §6).
- Phone set up, ScamShield is the default SMS app, *Settings* shows **Connected** ([1 · Set up the phone](1_SETUP_ON_PHONE.md)).
- *Settings → Privacy & reporting*: first option ON, *Also send the full text* ON, state set,
  **When a message is surely fraud = Ask me first (manual)** (we switch to automatic in §3).

How decisions work (so you know what "correct" looks like):

| You see | Means |
|---|---|
| no label | genuine, weak signs only, **or checks still running / couldn't run** |
| **Surely fraud** (red) | score ≥ 60 and confirmed by the sender database or a link check |
| **Surely spam** (amber) | score ≥ 60 but no database or link check confirmed it |

There is never a label before the server has finished — not even for a second.

Tools used below:
- **Test tools** = *Settings → Test tools*: pick a preset → **Simulate incoming SMS**. It drops a
  realistic incoming SMS into the inbox and runs the full pipeline. Works with one phone.
- **Second phone** = any phone that can send you a real SMS.
- **PC** = the server's terminal / files.

---

## 1. Basic SMS app (no server involvement)

| # | Do | Expect | ✓ |
|---|---|---|---|
| 1.1 | Open ScamShield | Your existing conversations are listed, newest first, with contact names | |
| 1.2 | Open a conversation with a friend, type, send | "sending" → "sent" → "delivered" (if the network reports it); friend receives it | |
| 1.3 | Dual SIM phone: tap **SIM 1** in the composer, choose SIM 2, send | Sent from SIM 2 | |
| 1.4 | *New* → enter a number → send | New conversation appears | |
| 1.5 | Friend replies | Notification with sender + text; **Reply** from the shade works without opening the app | |
| 1.6 | Long-press a message | Text copied | |
| 1.7 | Message containing a link from a friend | Link is plain text, not tappable | |
| 1.8 | Long message (> 160 characters) | Composer shows "2 SMS"; arrives as one message | |
| 1.9 | MMS (photo) from the second phone | Appears in the thread (mobile data must be on for MMS) | |

---

## 2. Decisions (manual reporting mode)

### 2.1 Surely fraud — look-alike bank link

| # | Do | Expect | ✓ |
|---|---|---|---|
| 2.1.1 | Test tools → **Fraud: fake bank KYC link** → Simulate | Normal new-message notification, thread with **no label** at first | |
| 2.1.2 | Wait 5–30 s | Notification **⚠ Surely fraud — 9123456780** (alarm channel). Conversation list: red avatar + *Surely fraud* chip. Thread: red banner *"Surely fraud — don't tap links… Tap to see why and report."*, red border | |
| 2.1.3 | Tap the message | Details sheet: label + explanation; **Why**: personal mobile number claiming to be a bank, link imitating HDFC (`hdfcbank-kyc-update.co`), OTP request, KYC/block threat | |
| 2.1.4 | Same sheet → **What was checked** | *ScamShield sender database* plus, per link: *Threat-feed database*, *Google Safe Browsing*, *Quad9 threat DNS*, *Cloudflare security DNS*, *Certificate history (crt.sh)*, *Isolated browser sandbox* — each ✓ clean / ⚠ hit / ? unavailable / – skipped | |
| 2.1.5 | Report section | *"Reporting is set to manual. Nothing has been sent."* and a red **Report to authorities** button | |
| 2.1.6 | PC: Docker `reports` / native `local-data/reports/` | **No new report yet** | |
| 2.1.7 | Tap **Report to authorities** | Dialog *"Report this fraud?"* listing where it goes (e.g. *Punjab State Cyber Crime Cell*) and *"Your other conversations are never sent."* | |
| 2.1.8 | **Report** | Status becomes *SS-2026-000N: demo report sent to the team inbox (demo mode — authorities were not emailed)* | |
| 2.1.9 | 📋 Reports screen | The report with the sender and status | |
| 2.1.10 | PC: open the report folder | `SS-2026-000N.pdf` (message, analysis, link checks, screenshot if any, SMS log), `.json`, and the email as `.eml` in `outbox/` — or in `DEMO_RECIPIENTS` inbox if SMTP is set | |
| 2.1.11 | Portal buttons in the sheet (NCRP, Chakshu, 1930) | Open the official site / dialer — these are manual channels | |

> The bank itself only appears as a recipient once its fraud-reporting address is filled in and
> verified in `backend/data/authorities.yaml`. In demo mode everything goes to your inbox anyway.

### 2.2 Surely fraud — the isolated browser opens a phishing page

The preset links to `/demo/kyc` on **your own server** — a fictional "Bharat Demo Bank" login page
that is safe to open.

| # | Do | Expect | ✓ |
|---|---|---|---|
| 2.2.1 | Test tools → **Fraud: demo phishing page** → Simulate | No label at first | |
| 2.2.2 | Wait up to ~40 s (the sandbox loads the page) | **Surely fraud** | |
| 2.2.3 | Tap → What was checked | *Isolated browser sandbox ⚠ hit* — login / OTP form found; under the link: *"Opened in ScamShield's isolated browser (not on your phone)"* with a **screenshot** of the fake page | |

Needs the sandbox on (start box says *Link sandbox : on*) and a **public https** server address in the
app — the sandbox refuses local addresses on purpose.

### 2.3 Surely spam — strong signs, nothing to confirm them

| # | Do | Expect | ✓ |
|---|---|---|---|
| 2.3.1 | Test tools → **Spam: OTP request, no link** → Simulate | No label at first, then amber **Surely spam**; notification is silent | |
| 2.3.2 | Tap the message | Why: bank claim from a personal number, OTP request, block threat. **No** "Report to authorities" button | |
| 2.3.3 | **Forward to TRAI 1909 (spam complaint)** | Confirmation dialog first (sends a real SMS from your SIM to 1909 — normal charges). **Cancel** unless you really want to file it | |

### 2.4 No label

| # | Do | Expect | ✓ |
|---|---|---|---|
| 2.4.1 | Test tools → **No label: genuine bank OTP** (`VM-HDFCBK-T`) | Never a label; tapping does nothing special | |
| 2.4.2 | Test tools → **No label: weak lottery text** (Hindi, no link) | Never a label (some warning signs, but below the threshold) | |
| 2.4.3 | Normal SMS from a friend | Never a label | |

### 2.5 Real SMS from a second phone

| # | Do | Expect | ✓ |
|---|---|---|---|
| 2.5.1 | Second phone sends: `Dear SBI customer your YONO account will be blocked today. Update PAN at http://sbi-yono-kyc-update.co/u` | No label → **Surely fraud** (link imitating SBI) | |
| 2.5.2 | Second phone sends: `Your account will be blocked. Share OTP to the executive now` | **Surely spam** or no label (depends on wording strength) — never *Surely fraud* without a link/database proof | |
| 2.5.3 | Second phone sends: `Hi, are we meeting at 5?` | No label | |

---

## 3. Automatic reporting

*Settings → Privacy & reporting → When a message is surely fraud → **Report it automatically***
(Settings should show *Saved*).

| # | Do | Expect | ✓ |
|---|---|---|---|
| 3.1 | Second phone sends a *new* look-alike link message, e.g. `HDFC: your netbanking is locked. Re-verify KYC at https://hdfc-netbanking-verify.co/kyc` | Surely fraud, and **without asking**: report status *preparing the report…* → *demo report sent to the team inbox* | |
| 3.2 | PC: newest report | The SMS log in the PDF contains **only messages from that second phone's number**, nothing from other conversations | |
| 3.3 | Send the **same** message again | Surely fraud; report status *already reported (same sender and link)* — no second email | |
| 3.4 | Test tools → Spam preset | Surely spam; **no** report even in automatic mode | |
| 3.5 | Switch back to **Ask me first** | New fraud messages show the Report button again | |

---

## 4. Server-side controls

Use the admin login from the start box (user `admin`). Browser: `https://<public address>/admin/stats`.

| # | Do | Expect | ✓ |
|---|---|---|---|
| 4.1 | Open `/admin/stats` | Counts of FRAUD / SPAM / NONE scans, reports by status, feed sizes | |
| 4.2 | Open `/admin/reports` | Every report, its intended recipients and where it was actually sent | |
| 4.3 | Block a number (PC terminal, one line):<br>`curl -u admin:<ADMIN_PASSWORD> -X PUT https://<public address>/admin/senders/+919123456783 -H "content-type: application/json" -d "{\"status\":\"blocked\"}"`<br>(the sender must have messaged you once first — use Test tools with `From` = `9123456783` and any text) | `{"sender":"+919123456783","status":"blocked"}` | |
| 4.4 | Test tools, `From` = `9123456783`, text `hello` → Simulate | **Surely fraud** — *ScamShield sender database ⚠ hit* (blocked by admin) | |
| 4.5 | Unblock: same command with `"unknown"` | Later messages from it get no label again | |

---

## 5. Privacy and consent

| # | Do | Expect | ✓ |
|---|---|---|---|
| 5.1 | Settings → *Also send the full text* OFF → Fraud KYC preset | Still **Surely fraud** (server gets sender + link + warning codes only) | |
| 5.2 | Settings → first option (*Check links and senders…*) OFF → any fraud preset | **No label at all** — ScamShield behaves as a plain SMS app. Turn it back ON | |
| 5.3 | Look at any test report PDF | Contains the reported message, that sender's messages and the analysis; nothing else from the phone | |
| 5.4 | Tap **Not fraud** / **Not spam** on a labelled message | *Thanks!* — feedback stored on the server | |

---

## 6. Robustness

| # | Do | Expect | ✓ |
|---|---|---|---|
| 6.1 | Stop the server, simulate the Fraud preset | Message arrives normally, **no label** | |
| 6.2 | Start the server again → Settings → Server → (new address if quick tunnel) → **Save & connect** | The waiting message is checked again right away and gets its label. Without tapping, the app retries by itself with growing pauses (30 s, 1, 2, 4, 8 … min) | |
| 6.3 | Airplane mode, simulate a fraud preset, turn airplane mode off | No label while offline; label appears after reconnecting | |
| 6.4 | Restart the phone, send a test message from the second phone | Still received and checked | |
| 6.5 | PC on college Wi-Fi vs. hotspot | If the address shows *not ready* on college Wi-Fi, use the hotspot (see [2 · Server on your PC](2_SERVER_ON_PC.md) §8) | |
| 6.6 | Several fraud presets quickly in a row | All get labels; no crash | |

---

## 7. When something fails

| Symptom | Check |
|---|---|
| No label on anything | Settings → **Connected**? first option ON? Server self-test passes? Address current? |
| Fraud preset shows only *Surely spam* | All link checks *unavailable* (PC has no internet) and no look-alike proof → fix the PC's internet; with a fresh domain the look-alike check alone should still prove it |
| Demo phishing page stays without label / sandbox *unavailable* | Start box says *Link sandbox : on*? App uses the public `https://` address, not `127.0.0.1`? |
| Report status *no verified authority address for your state yet* | Demo mode with SMTP set but `DEMO_RECIPIENTS` empty, or live mode with no verified address for that state |
| Report status *sending failed* | SMTP settings / port 587 blocked → hotspot, or leave SMTP empty to save files |
| App crash | Collect a log (below) |

```bash
adb logcat -c
# reproduce, then:
adb logcat -d -s AndroidRuntime:E WM-WorkerWrapper:E OkHttp:I > scamshield-log.txt
```
Server side: Docker `logs`, native `local-data/logs/api.log` and `sandbox.log`.

---

## 8. After testing

- Delete test conversations: open the thread → 🗑.
- Keep one *Surely fraud* thread (KYC preset) and one *Surely spam* thread for the live demo.
- Before the judges: restart the server, update the address on the phone, run the self-test once.
