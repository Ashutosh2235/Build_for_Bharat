# ScamShield server on this Windows PC.
#   powershell -ExecutionPolicy Bypass -File run-local.ps1            start + print phone settings
#   powershell -ExecutionPolicy Bypass -File run-local.ps1 url        public address again
#   powershell -ExecutionPolicy Bypass -File run-local.ps1 status     container status + health
#   powershell -ExecutionPolicy Bypass -File run-local.ps1 logs       follow logs (Ctrl+C to stop watching)
#   powershell -ExecutionPolicy Bypass -File run-local.ps1 selftest   play the phone's part (PASS/FAIL list)
#   powershell -ExecutionPolicy Bypass -File run-local.ps1 reports    copy reports to .\local-reports
#   powershell -ExecutionPolicy Bypass -File run-local.ps1 stop       stop (data is kept)
#   powershell -ExecutionPolicy Bypass -File run-local.ps1 reset      stop and DELETE all data
param([string]$Command = "start")
# Continue: docker writes progress to stderr, which Windows PowerShell 5.1 would otherwise treat as fatal
$ErrorActionPreference = "Continue"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location (Join-Path $Root "deploy")
$EnvFile = "local.env"

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "Docker is not installed. Install Docker Desktop: https://www.docker.com/products/docker-desktop/" -ForegroundColor Red; exit 1
}
docker info *> $null
if ($LASTEXITCODE -ne 0) { Write-Host "Docker Desktop is not running. Start it and retry." -ForegroundColor Red; exit 1 }

function New-Hex([int]$n = 24) {
    $b = New-Object byte[] $n; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    ($b | ForEach-Object { $_.ToString("x2") }) -join ""
}
function New-FernetKey {
    $b = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
    [Convert]::ToBase64String($b).Replace('+', '-').Replace('/', '_')
}
function Get-Val([string]$key) {
    $line = Get-Content $EnvFile | Where-Object { $_ -match "^$key=" } | Select-Object -First 1
    if ($line) { return $line.Substring($key.Length + 1) } else { return "" }
}
function Set-IfEmpty([string]$key, [string]$value) {
    $lines = Get-Content $EnvFile
    $lines = $lines | ForEach-Object { if ($_ -eq "$key=") { "$key=$value" } else { $_ } }
    [IO.File]::WriteAllLines((Join-Path (Get-Location) $EnvFile), [string[]]$lines)   # UTF-8 without BOM
}
function Get-Profile { if ((Get-Val "TUNNEL_TOKEN") -ne "") { "named" } else { "quick" } }
function Invoke-Dc { docker compose -f docker-compose.local.yml --env-file $EnvFile --profile (Get-Profile) @args }

function Get-TunnelUrl {
    if ((Get-Profile) -eq "named") { return "(your fixed hostname from the Cloudflare tunnel settings)" }
    for ($i = 0; $i -lt 30; $i++) {
        $log = (Invoke-Dc logs tunnel 2>&1) | Out-String
        $m = [regex]::Matches($log, "https://[a-z0-9-]+\.trycloudflare\.com")
        if ($m.Count -gt 0) { return $m[$m.Count - 1].Value }
        Start-Sleep -Seconds 2
    }
    return "(not ready - run: run-local.ps1 logs, and check the network allows outbound port 7844)"
}

function Show-PhoneSettings {
    $url = Get-TunnelUrl
    $mail = if ((Get-Val "SMTP_HOST") -ne "") { "via " + (Get-Val "SMTP_HOST") } else { "saved as files - run-local.ps1 reports" }
    Write-Host ""
    Write-Host "==================== ScamShield server is running ====================" -ForegroundColor Green
    Write-Host " Public address : $url"
    Write-Host " API key        : $(Get-Val 'API_KEY')"
    Write-Host " Admin login    : admin / $(Get-Val 'ADMIN_PASSWORD')"
    Write-Host " Report mode    : $(Get-Val 'REPORT_MODE')   (emails: $mail)"
    Write-Host ""
    Write-Host " On the phone: ScamShield > Settings > Server"
    Write-Host "   Server URL = public address above, API key = key above > Save & connect"
    Write-Host " Check everything works:  run-local.ps1 selftest"
    Write-Host " Keep this PC awake and Docker Desktop running for the whole hackathon."
    Write-Host "=======================================================================" -ForegroundColor Green
}

function Test-Health {
    try { Invoke-RestMethod -Uri "http://127.0.0.1:8000/v1/health" -TimeoutSec 3 | Out-Null; return $true } catch { return $false }
}

switch ($Command) {
    "start" {
        if (-not (Test-Path $EnvFile)) {
            Copy-Item "local.env.example" $EnvFile
            Set-IfEmpty "API_KEY" (New-Hex); Set-IfEmpty "ADMIN_PASSWORD" (New-Hex)
            Set-IfEmpty "DB_PASSWORD" (New-Hex); Set-IfEmpty "FERNET_KEY" (New-FernetKey)
            Write-Host "Created deploy\local.env with fresh secrets (edit it to add email settings)."
        }
        Invoke-Dc up -d --build
        if ($LASTEXITCODE -ne 0) { Write-Host "docker compose failed (see above)." -ForegroundColor Red; exit 1 }
        Write-Host -NoNewline "Waiting for the server"
        for ($i = 0; $i -lt 60; $i++) { if (Test-Health) { break }; Write-Host -NoNewline "."; Start-Sleep -Seconds 3 }
        Write-Host ""
        if (-not (Test-Health)) { Write-Host "Server did not start. Last logs:" -ForegroundColor Red; Invoke-Dc logs --tail 40 api; exit 1 }
        Show-PhoneSettings
    }
    "url"     { Get-TunnelUrl }
    "status"  { Invoke-Dc ps; if (Test-Health) { Write-Host "health: OK" } else { Write-Host "health: DOWN" } }
    "logs"    { Invoke-Dc logs -f --tail 50 api feed-sync sandbox }
    "selftest" {
        # Through the public address when there is one: also tests the tunnel and lets the sandbox open /demo/kyc
        $u = Get-TunnelUrl
        if ($u -like "https://*") { Invoke-Dc exec -T api python -m app.selftest --base $u } else { Invoke-Dc exec -T api python -m app.selftest }
    }
    "reports" {
        $dest = Join-Path $Root "local-reports"; New-Item -ItemType Directory -Force $dest | Out-Null
        Invoke-Dc cp "api:/data/reports/." $dest; Write-Host "Copied to $dest"
    }
    "stop"    { Invoke-Dc down }
    "reset"   { if ((Read-Host "Delete ALL ScamShield data on this PC? (yes/no)") -eq "yes") { Invoke-Dc down -v } }
    default   { Write-Host "usage: run-local.ps1 [start|url|status|logs|selftest|reports|stop|reset]"; exit 1 }
}
