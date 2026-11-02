# Hosting ScamShield on the Hostinger VPS

> For the hackathon the server runs on your PC instead — see [`2_SERVER_ON_PC.md`](2_SERVER_ON_PC.md). Keep this guide for later.

One way, start to finish. Your existing sites (StimOPTI, CEMOPTI, CTOPTI …) keep running untouched:
ScamShield runs in its own Docker containers, listens only on `127.0.0.1:8000`, and your existing
web server forwards two new subdomains to it.

```
Phone ──HTTPS──▶ Cloudflare ──▶ VPS :443 (your existing Nginx/Caddy)
                                   ├─ api.<domain>   ─▶ 127.0.0.1:8000  (ScamShield API)
                                   └─ admin.<domain> ─▶ 127.0.0.1:8000/admin/
                                 Docker (project "scamshield"):
                                   api · feed-sync · sandbox (isolated) · postgres · backup
```

Replace `yourdomain.in` with your real domain everywhere below.

| Step | What | Time |
|---|---|---|
| 0 | Check the VPS has room | 2 min |
| 1 | DNS + TLS certificate on Cloudflare | 10 min |
| 2 | Install Docker | 5 min |
| 3 | Put the code on the VPS | 5 min |
| 4 | Fill in `.env` | 10 min |
| 5 | Start the containers | 10–15 min (first build) |
| 6 | Connect your web server | 10 min |
| 7 | Test | 5 min |
| 8 | (Optional) Auto-deploy from GitHub | 15 min |

**No SSH on college Wi-Fi?** Use **hPanel → VPS → Browser terminal** (runs in the browser over HTTPS),
or connect through your phone's hotspot.

---

## 0. Check the VPS has room

```bash
nproc; free -h; df -h /; sudo ss -ltnp | grep -E ':(80|443|8000)\s'
```
- Need: **2 vCPU, ≥ 3 GB RAM free, ≥ 15 GB disk free** (the browser sandbox alone uses up to 1 GB).
- Note **which program owns ports 80/443** (`nginx`, `caddy`, `traefik`, `lshttpd`/OpenLiteSpeed …) — step 6 depends on it.
- Port 8000 must be free. If something already uses it, change `127.0.0.1:8000:8000` in `deploy/docker-compose.yml` to e.g. `127.0.0.1:8010:8000` and use 8010 in step 6.

## 1. DNS + TLS on Cloudflare

1. **DNS** → *Add record* twice: type `A`, name `api` and `admin`, IPv4 = VPS IP, **Proxied (orange cloud)**.
2. **SSL/TLS → Origin Server → Create certificate** (RSA, hostnames `*.yourdomain.in, yourdomain.in`, 15 years).
   Save both boxes on the VPS:
   ```bash
   sudo mkdir -p /etc/ssl/cloudflare
   sudo nano /etc/ssl/cloudflare/yourdomain.pem    # paste "Origin Certificate"
   sudo nano /etc/ssl/cloudflare/yourdomain.key    # paste "Private Key"
   sudo chmod 600 /etc/ssl/cloudflare/yourdomain.key
   ```
   (If your other sites already use a Cloudflare origin certificate for `*.yourdomain.in`, reuse it.)
3. **SSL/TLS → Overview → Full (strict)**.
   (Only if every other site on this domain already has a valid certificate — otherwise set it per hostname with a Configuration Rule.)

## 2. Install Docker (skip if `docker compose version` already works)

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER && newgrp docker
docker compose version
```

## 3. Put the code on the VPS

From the GitHub repo you made for the APK build (private repo → create a *fine-grained token* with
**Contents: Read-only** for that repo at github.com/settings/personal-access-tokens):
```bash
sudo mkdir -p /opt/scamshield && sudo chown $USER /opt/scamshield
git clone https://<github-user>:<token>@github.com/<github-user>/scamshield.git /opt/scamshield
```
No GitHub repo? Upload the zip instead: `scp scamshield-phase1-v2.zip root@<vps-ip>:/opt/` then
`cd /opt && unzip scamshield-phase1-v2.zip` (gives `/opt/scamshield`).

## 4. Fill in `.env`

```bash
cd /opt/scamshield/deploy
cp .env.example .env && chmod 600 .env
openssl rand -hex 24                          # run 3×: for API_KEY, ADMIN_PASSWORD, DB_PASSWORD
openssl rand -base64 32 | tr '+/' '-_'        # for FERNET_KEY
nano .env
```

| Variable | Set to |
|---|---|
| `API_KEY`, `ADMIN_PASSWORD`, `DB_PASSWORD` | the three random strings |
| `FERNET_KEY` | the base64 string (**back it up** — without it stored message text can't be read) |
| `PUBLIC_BASE_URL` | `https://api.yourdomain.in` |
| `REPORT_MODE` | keep `demo` |
| `DEMO_RECIPIENTS` | the team inbox that should receive demo reports (comma-separated) |
| `SMTP_*`, `MAIL_FROM` | the company mailbox (Hostinger Email: `smtp.hostinger.com`, port `587`, full address as user) |
| `ABUSECH_AUTH_KEY` | optional, free at auth.abuse.ch (URLhaus feed) |

Mail deliverability (so reports don't land in spam) — in Cloudflare DNS, records **DNS only (grey cloud)**:
- **SPF** `TXT @` → value from your mail provider (Hostinger: `v=spf1 include:_spf.mail.hostinger.com ~all`)
- **DKIM** → the record your mail provider shows (hPanel → Emails → DNS settings)
- **DMARC** `TXT _dmarc` → `v=DMARC1; p=none; rua=mailto:reports@yourdomain.in`

No mailbox yet? Leave `SMTP_HOST` empty — reports are then saved as `.eml` files inside the container instead of being sent.

## 5. Start the containers

```bash
cd /opt/scamshield/deploy
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build
docker compose ps                              # all "running"/"healthy"
curl -s http://127.0.0.1:8000/v1/health        # {"ok":true,...,"report_mode":"demo",...}
```
The first build downloads the browser image (~2 GB) — 10–15 minutes.

## 6. Connect your web server

Use the block that matches what owns ports 80/443 (step 0).

**Nginx** (most common):
```bash
sudo cp /opt/scamshield/deploy/nginx/scamshield.conf /etc/nginx/sites-available/scamshield.conf
sudo sed -i 's/yourdomain\.in/YOUR-DOMAIN/g' /etc/nginx/sites-available/scamshield.conf   # e.g. example.in
sudo ln -s /etc/nginx/sites-available/scamshield.conf /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```
(If your Nginx uses `/etc/nginx/conf.d/` instead, copy the file there.)

**Caddy** — add to the Caddyfile, then `sudo systemctl reload caddy`:
```
api.yourdomain.in {
    @admin path /admin/*
    respond @admin 404
    reverse_proxy 127.0.0.1:8000
}
admin.yourdomain.in {
    handle /admin/* { reverse_proxy 127.0.0.1:8000 }
    respond 404
}
```

**Traefik / CloudPanel / CyberPanel**: add a reverse-proxy site for `api.yourdomain.in` (and `admin.`)
pointing to `http://127.0.0.1:8000`.

## 7. Test

```bash
curl -s https://api.yourdomain.in/v1/health
curl -s -u admin:<ADMIN_PASSWORD> https://admin.yourdomain.in/admin/stats
```
Phone: ScamShield → *Settings → Server* → URL `https://api.yourdomain.in`, API key = `API_KEY` →
**Save & connect** → "Connected". Then *Test tools → Scam: fake bank KYC*: after a few seconds the
*Why* sheet shows link analysis, and *Reports* shows a demo report; the email arrives at `DEMO_RECIPIENTS`.

To bake the server into future APKs instead: GitHub → repo → *Settings → Secrets and variables → Actions* →
variable `SCAMSHIELD_API_BASE_URL=https://api.yourdomain.in/`, secret `SCAMSHIELD_API_KEY=<API_KEY>`.

## 8. (Optional) Auto-deploy on every push

After this, `git push` to `main` → tests → images built on GitHub → VPS updated. Deploys run from
GitHub's servers, so college Wi-Fi doesn't matter.

1. On the VPS, create a deploy key for GitHub Actions:
   ```bash
   ssh-keygen -t ed25519 -f ~/.ssh/scamshield_deploy -N ""
   cat ~/.ssh/scamshield_deploy.pub >> ~/.ssh/authorized_keys
   cat ~/.ssh/scamshield_deploy        # copy this PRIVATE key into the secret below
   ```
2. GitHub → repo → *Settings → Secrets and variables → Actions*:
   - Secrets: `VPS_HOST` (VPS IP), `VPS_USER` (e.g. `root`), `VPS_SSH_KEY` (the private key), `VPS_SSH_PORT` (only if not 22)
   - Variable: `DEPLOY_ENABLED` = `true`
3. Let the VPS pull the images: GitHub → *Settings → Developer settings → Personal access tokens (classic)* →
   scope `read:packages` → on the VPS `echo <token> | docker login ghcr.io -u <github-user> --password-stdin`.
   (Or make the two `scamshield-*` packages public on GitHub.)
4. Make sure `GHCR_OWNER` in `.env` is your GitHub username in **lowercase**.
5. Push any change to `backend/`, `sandbox/`, `shared/` or `deploy/` → *Actions → backend* → `deploy` job ends with the health JSON.

From then on the VPS runs the GHCR images (`docker compose up -d`, without the build file).

---

## Day-to-day

| Task | Command (in `/opt/scamshield/deploy`) |
|---|---|
| Status | `docker compose ps` |
| Logs | `docker compose logs -f api` (or `sandbox`, `feed-sync`) |
| Update manually | `git -C /opt/scamshield pull && docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build` |
| Restart | `docker compose restart api` |
| Stop everything | `docker compose down` (data is kept in volumes) |
| Backups | daily `pg_dump` into `deploy/backups/` (7 days kept) — copy them off the server now and then |
| Block a scam sender | `curl -u admin:<pw> -X PUT https://admin.yourdomain.in/admin/senders/+919123456780 -H 'content-type: application/json' -d '{"status":"blocked"}'` |
| Report list | `curl -u admin:<pw> https://admin.yourdomain.in/admin/reports` |

**Going live with real reports:** verify every address in `backend/data/authorities.yaml` against the
official nodal-officer list on cybercrime.gov.in, set `verified: true`, commit/redeploy, then set
`REPORT_MODE=live` in `.env` and `docker compose up -d`. Unverified addresses are never emailed.

**Strongly recommended after the hackathon:** move the `sandbox` service to a second small VPS. It opens
scam websites, and doing that from the same IP as your other sites can get that IP blocklisted.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `curl 127.0.0.1:8000/v1/health` fails | `docker compose logs api` — usually a missing `FERNET_KEY` or `DB_PASSWORD` in `.env` |
| HTTPS gives Cloudflare error 521/522 | web server not reloaded, or `nginx -t` failed; check the `server_name` lines |
| Error 526 | Cloudflare is "Full (strict)" but the origin certificate path in the config is wrong |
| 404 on `https://api.…/v1/health` | the request hit another site's config — check `server_name api.yourdomain.in` exists and Nginx was reloaded |
| Phone says "Server not reachable" | URL must start with `https://`, API key must equal `API_KEY`; try the health URL in the phone's browser |
| `401 invalid api key` in logs | API key on the phone ≠ `API_KEY` in `.env` |
| Reports stay "queued"/"failed" | `docker compose logs api \| grep report` — SMTP host/port/password; port 587 open outbound |
| Sandbox keeps restarting | not enough RAM — `free -h`; lower `SANDBOX_CONCURRENCY` to `1` in `docker-compose.yml` |
| `pull access denied` for ghcr.io | step 8.3 (docker login) or use the build file instead |
