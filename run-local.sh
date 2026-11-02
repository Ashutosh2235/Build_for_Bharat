#!/usr/bin/env bash
# ScamShield server on this PC (macOS / Linux / Windows WSL).
#   ./run-local.sh            start (first run builds images: ~10-15 min) and print the phone settings
#   ./run-local.sh url        print the public address again
#   ./run-local.sh status     container status + health
#   ./run-local.sh logs       follow server logs (Ctrl+C to stop watching)
#   ./run-local.sh selftest   play the phone's part against the running server (PASS/FAIL list)
#   ./run-local.sh reports    copy generated reports to ./local-reports
#   ./run-local.sh stop       stop everything (data is kept)
#   ./run-local.sh reset      stop and DELETE all data (database, reports)
set -euo pipefail
cd "$(dirname "$0")/deploy"
ENVF=local.env

need() { command -v "$1" >/dev/null 2>&1 || { echo "Missing: $1. $2"; exit 1; }; }
need docker "Install Docker Desktop (https://www.docker.com/products/docker-desktop/) and start it."
docker info >/dev/null 2>&1 || { echo "Docker is installed but not running. Start Docker Desktop and retry."; exit 1; }

rand_hex() { od -An -tx1 -N24 /dev/urandom | tr -d ' \n'; }
rand_fernet() { head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '\n'; }
setv() { # setv KEY VALUE  (only if empty)
  if grep -qE "^$1=$" "$ENVF"; then
    local tmp; tmp=$(mktemp); awk -v k="$1" -v v="$2" -F= 'BEGIN{OFS="="} $1==k && $2=="" {print k"="v; next} {print}' "$ENVF" > "$tmp" && mv "$tmp" "$ENVF"
  fi
}
getv() { grep -E "^$1=" "$ENVF" | head -1 | cut -d= -f2-; }

profile() { [ -n "$(getv TUNNEL_TOKEN)" ] && echo named || echo quick; }
dc() { docker compose -f docker-compose.local.yml --env-file "$ENVF" --profile "$(profile)" "$@"; }

tunnel_url() {
  if [ "$(profile)" = named ]; then echo "(your fixed hostname from the Cloudflare tunnel settings)"; return; fi
  for _ in $(seq 1 30); do
    u=$(dc logs tunnel 2>/dev/null | grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' | tail -1 || true)
    [ -n "$u" ] && { echo "$u"; return; }
    sleep 2
  done
  echo "(not ready — run: ./run-local.sh logs, and check that the network allows outbound port 7844)"
}

print_phone() {
  local url; url=$(tunnel_url)
  cat <<MSG

==================== ScamShield server is running ====================
 Public address : $url
 API key        : $(getv API_KEY)
 Admin login    : admin / $(getv ADMIN_PASSWORD)
 Report mode    : $(getv REPORT_MODE)   (emails: $( [ -n "$(getv SMTP_HOST)" ] && echo "via $(getv SMTP_HOST)" || echo "saved as files — ./run-local.sh reports"))

 On the phone: ScamShield → Settings → Server
   Server URL = the public address above,  API key = the key above  → Save & connect
 Check everything works:  ./run-local.sh selftest
 Keep this PC awake and Docker running for the whole hackathon.
=======================================================================
MSG
}

cmd="${1:-start}"
case "$cmd" in
  start)
    if [ ! -f "$ENVF" ]; then
      cp local.env.example "$ENVF"; chmod 600 "$ENVF"
      setv API_KEY "$(rand_hex)"; setv ADMIN_PASSWORD "$(rand_hex)"; setv DB_PASSWORD "$(rand_hex)"; setv FERNET_KEY "$(rand_fernet)"
      echo "Created deploy/local.env with fresh secrets (edit it to add email settings)."
    fi
    dc up -d --build
    echo -n "Waiting for the server"
    for _ in $(seq 1 60); do curl -fs http://127.0.0.1:8000/v1/health >/dev/null 2>&1 && break; echo -n "."; sleep 3; done; echo
    curl -fs http://127.0.0.1:8000/v1/health >/dev/null || { echo "Server did not start. Showing logs:"; dc logs --tail 40 api; exit 1; }
    print_phone ;;
  url) tunnel_url ;;
  status) dc ps; curl -fs http://127.0.0.1:8000/v1/health && echo ;;
  logs) dc logs -f --tail 50 api feed-sync sandbox ;;
  selftest) shift
    # Through the public address when there is one: also tests the tunnel and lets the sandbox open /demo/kyc
    u=$(tunnel_url); case "$u" in https://*) base=(--base "$u");; *) base=();; esac
    dc exec -T api python -m app.selftest "${base[@]}" "$@" ;;
  reports) mkdir -p ../local-reports && dc cp api:/data/reports/. ../local-reports/ && echo "Copied to $(cd ../local-reports && pwd)" ;;
  stop) dc down ;;
  reset) read -r -p "Delete ALL ScamShield data on this PC? (yes/no) " a; [ "$a" = yes ] && dc down -v ;;
  *) echo "usage: $0 [start|url|status|logs|selftest|reports|stop|reset]"; exit 1 ;;
esac
