param(
    [string]$ApiBaseUrl = "http://127.0.0.1:8000/api",
    [string]$Hostname = "edupkimanager.com",
    [string]$WwwHostname = "www.edupkimanager.com",
    [switch]$TrustRootCa
)

$ErrorActionPreference = "Stop"

$hostsPath = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"
$hostsEntry = "127.0.0.1 $Hostname $WwwHostname"
$currentHosts = Get-Content -LiteralPath $hostsPath -Raw

if ($currentHosts -notmatch "(^|\s)$([regex]::Escape($Hostname))(\s|$)") {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        throw "Run PowerShell as Administrator to update $hostsPath, then run this script again."
    }
    Add-Content -LiteralPath $hostsPath -Value "`r`n$hostsEntry"
    ipconfig /flushdns | Out-Null
    Write-Host "Hosts entry added: $hostsEntry"
} else {
    Write-Host "Hosts entry already exists for $Hostname"
}

$rootCaDir = Join-Path (Get-Location) "artifacts\tls"
New-Item -ItemType Directory -Force -Path $rootCaDir | Out-Null
$rootCaPath = Join-Path $rootCaDir "edupki-root-ca.pem"
Invoke-WebRequest -Uri "$ApiBaseUrl/ca/root.pem" -OutFile $rootCaPath
Write-Host "Root CA downloaded: $rootCaPath"

if ($TrustRootCa) {
    certutil -user -addstore Root $rootCaPath | Out-Null
    Write-Host "Root CA imported into CurrentUser Root store."
} else {
    Write-Host "Root CA was not imported. Re-run with -TrustRootCa to trust HTTPS in Edge/Chrome."
}

Write-Host "Open: https://$Hostname"
