# 1 · Set up ScamShield on the phone

ScamShield replaces the phone's SMS app (SMS + MMS, dual SIM). Every incoming message is checked by
**your server** ([2 · Server on your PC](2_SERVER_ON_PC.md)). A label appears only after the server
has checked the sender against its database and checked every link:

- **Surely fraud** (red) — confirmed by a database or a link check. Can be reported to authorities.
- **Surely spam** (amber) — strong scam/spam signs, but nothing confirmed it. Not reported; you can forward it to TRAI 1909.
- **Nothing** — everything else, and every message whose checks are still running or couldn't run.

Then: [3 · Manual testing](3_MANUAL_TESTING.md)

---

## What you need

| | |
|---|---|
| Phone | Android **10 or newer** (Android 13+ recommended), a SIM with SMS for real-message tests |
| Computer | to build/install the APK (Windows, macOS or Linux) |
| Cable | USB data cable (or Wi-Fi pairing on Android 11+) |
| Server | running on your PC with its **Public address** and **API key** (from the start box) |

---

## Step 1 — Get the APK (pick one)

### Option A — GitHub Actions (no Android Studio, ~10 min)

1. Create an empty **private** repository on GitHub, e.g. `scamshield`.
2. Push the project (from the unzipped folder):
   ```bash
   git init -b main
   git add .
   git commit -m "ScamShield"
   git remote add origin https://github.com/<you>/scamshield.git
   git push -u origin main
   ```
   `.gitignore` already keeps out `deploy/local.env`, `deploy/native.env` and `local-data/` — double-check
   with `git status` before the first commit that none of them is listed.
3. GitHub → repository → **Actions** → the `android` workflow starts by itself (or *android → Run workflow*).
4. When it is green: open the run → **Artifacts** → `scamshield-debug-apk` → download → unzip → `app-debug.apk`.
   Red? Open the failed step and copy the error text.

Optional — bake in your server so the phone needs no typing (only useful with the **fixed** tunnel address):
repository → *Settings → Secrets and variables → Actions* → **Variables**: `SCAMSHIELD_API_BASE_URL=https://scamshield-api.yourdomain.in/`
and **Secrets**: `SCAMSHIELD_API_KEY=<API_KEY from the settings file>` → re-run the workflow.

### Option B — Android Studio

1. Install Android Studio (Ladybug or newer) → *Open* → the `android/` folder → wait for Gradle sync (accept an AGP upgrade prompt if shown).
2. Optional baked-in server: create `android/local.properties` (never commit it):
   ```
   scamshield.apiBaseUrl=https://scamshield-api.yourdomain.in/
   scamshield.apiKey=<API_KEY>
   ```
3. *Build → Build App Bundle(s) / APK(s) → Build APK(s)* → `android/app/build/outputs/apk/debug/app-debug.apk`,
   or connect the phone and press ▶ **Run** (installs directly — skip Step 2).

The debug build is called **ScamShield (debug)** with package `com.scamshield.sms.debug`, version 0.2.0.

---

## Step 2 — Install with adb (not by tapping the APK)

Install over USB with **adb**. Opening the APK from a browser, WhatsApp or a file manager often fails
in India: Play Protect's fraud-protection pilot blocks sideloaded apps that request SMS permissions,
and Google's developer-verification flow adds extra blocks for unknown developers. `adb install` is
not affected.

1. Phone: *Settings → About phone* → tap **Build number** 7 times → back → *System → Developer options* → **USB debugging** ON.
2. Computer: download **SDK Platform-Tools** — https://developer.android.com/tools/releases/platform-tools — and unzip it.
3. Connect the phone, unlock it, accept **Allow USB debugging?** (tick *Always allow*).
4. In the platform-tools folder:
   ```bash
   adb devices                     # your phone must show as "device" (not "unauthorized")
   adb install -r app-debug.apk    # Windows PowerShell: .\adb install -r app-debug.apk
   ```
   Wireless (Android 11+): *Developer options → Wireless debugging → Pair device with pairing code* →
   `adb pair IP:PORT` (enter the code) → `adb connect IP:PORT` → `adb install -r app-debug.apk`.

**Updating from an older ScamShield build** fails with `INSTALL_FAILED_UPDATE_INCOMPATIBLE` when the
new APK was signed by a different machine (each GitHub run can use a new debug key). Fix:
```bash
adb uninstall com.scamshield.sms.debug
adb install app-debug.apk
```
Your SMS are not lost — they live in Android's shared message store, not inside the app. The app's
own settings and labels are reset; the cache from older builds is rebuilt anyway (new database version).

---

## Step 3 — Make ScamShield the default SMS app

1. Open **ScamShield (debug)** → *Get started*.
2. **Step 1 · Make ScamShield your SMS app** → *Set as default SMS app* → confirm the system dialog.
   - Greyed out or "Restricted setting"? *Settings → Apps → ScamShield (debug) → ⋮ (top right) → Allow restricted settings*, then try again.
   - Existing messages stay where they are and appear in ScamShield.
3. *Continue* → allow **Contacts**, **Phone** and **Notifications** when asked.
   (Without Notifications you won't see fraud alerts; without Phone, dual-SIM choice isn't available.)

---

## Step 4 — Your choices (privacy and reporting)

| Option | Recommended for testing | What it does |
|---|---|---|
| **Check links and senders with ScamShield servers** | ON (required) | Sends the sender, the links and the warning-sign codes — not the text. **Off = ScamShield is a plain SMS app and shows no labels.** |
| **Also send the full text** | ON | Better server checks (wording, brand). Optional. |
| **When a message is surely fraud** | *Ask me first (manual)* first, then try *Report it automatically* | see below |
| **State** | your state (e.g. Punjab) | chooses the state cyber-crime cell for reports |

**Report it automatically** — when the server decides "Surely fraud", the report is created at once.
The phone sends that message plus the other messages **from the same sender in that conversation**,
and the server emails the report. Nothing from other conversations is ever sent.

**Ask me first (manual)** — the default. The message gets a red **Report to authorities** button; you
see who it would go to and nothing is sent until you confirm.

"Surely spam" is never reported to authorities in either mode.

You can change all of this later in *Settings → Privacy & reporting*.

---

## Step 5 — Connect to your server

On **Step 3 · Where should reports go?** (or later in *Settings → Server*):

1. **Server URL** = the **Public address** from the server's start box, e.g. `https://random-words.trycloudflare.com`
   (use the `https://` tunnel address — the server only listens on the PC itself, so `http://<PC-IP>:8000` won't work).
2. **API key** = the **API key** from the same box.
3. Optional: your name for reports.
4. *Finish* / **Save & connect** → *Settings* shows **Connected**.

If it says the server isn't reachable: check the PC is running, the address is current (the quick
tunnel changes on every server start), and the API key has no extra spaces.

**Every time the server restarts with a quick tunnel:** *Settings → Server* → paste the new address → **Save & connect**.

---

## Step 6 — Quick check (2 minutes)

1. *Settings → Test tools* → **Fraud: fake bank KYC link** → **Simulate incoming SMS**.
2. A normal "new message" notification appears immediately — **no label yet** (the server is checking).
3. Within ~5–30 s: notification **⚠ Surely fraud — 9123456780**, and the thread shows the red banner.
4. Tap the message → **What was checked** lists every database and link check with ✓ / ⚠ / ? / –.

Works? Continue with [3 · Manual testing](3_MANUAL_TESTING.md). Delete test threads afterwards
(open the thread → 🗑 in the top bar).

---

## Everyday use

| | |
|---|---|
| Read / reply / new message | as in any SMS app; dual-SIM picker in the composer |
| Reply from the notification | *Reply* in the notification shade |
| Links | never tappable inside ScamShield — long-press to copy text if you really need it |
| Why a label? | tap the message → *Why* + *What was checked* + screenshot of the page from the sandbox |
| Wrong label | *Not fraud* / *Not spam* in the details sheet (helps tune the rules) |
| Block a number | 🚫 in the thread's top bar or *Block sender* in the details (uses Android's own block list) |
| Delete a conversation | 🗑 in the thread's top bar |
| Reports | 📋 icon on the main screen: every report and its status |

## Switching back to your normal SMS app

*Settings → Apps → Default apps → SMS app →* Messages (or your phone's app). All messages ScamShield
received are in the shared store and show up there too. RCS chats only work in Google Messages.

## Troubleshooting

| Problem | Fix |
|---|---|
| `adb devices` empty / "unauthorized" | Different USB cable (data, not charge-only), unlock phone, accept the prompt, *Revoke USB debugging authorizations* and retry |
| "App not installed" / blocked by Play Protect | Use `adb install`, not the file manager |
| Can't select ScamShield as default | *Allow restricted settings* (Step 3) |
| No label ever appears | *Settings*: first option must be ON and status **Connected**; run the server self-test; check the PC/tunnel |
| "Server not reachable" | New quick-tunnel address → re-enter; PC asleep; API key wrong |
| No fraud notification | Allow notifications; *Settings → Apps → ScamShield (debug) → Notifications → Scam alerts* ON |
| Battery saver delays checks | *Settings → Apps → ScamShield (debug) → Battery → Unrestricted* |

**Collect a log for a bug report:**
```bash
adb logcat -c
# reproduce the problem on the phone, then:
adb logcat -d -s AndroidRuntime:E WM-WorkerWrapper:E OkHttp:I > scamshield-log.txt
```
