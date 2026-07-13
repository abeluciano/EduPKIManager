param(
    [string]$ApiBaseUrl = "http://127.0.0.1:8000/api",
    [string]$Hostname = "edupkimanager.com",
    [string]$WwwHostname = "www.edupkimanager.com",
    [switch]$TrustRootCa,
    [switch]$Remove
)

$ErrorActionPreference = "Stop"

$hostsPath = Join-Path $env:SystemRoot "System32\drivers\etc\hosts"
$hostsEntry = "127.0.0.1 $Hostname $WwwHostname"
$managedHostsPattern = "^\s*127\.0\.0\.1\s+$([regex]::Escape($Hostname))\s+$([regex]::Escape($WwwHostname))\s*$"
$rootCaDir = Join-Path (Get-Location) "artifacts\tls"
$rootCaPath = Join-Path $rootCaDir "edupki-root-ca.pem"
$thumbprintPath = Join-Path $rootCaDir "edupki-root-ca.thumbprint"

function Test-IsAdministrator {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if ($Remove) {
    $hostLines = @(Get-Content -LiteralPath $hostsPath)
    $managedHostsLines = @($hostLines | Where-Object { $_ -match $managedHostsPattern })
    if ($managedHostsLines.Count -gt 0) {
        if (-not (Test-IsAdministrator)) {
            throw "Run PowerShell as Administrator to remove the EduPKIManager hosts entry."
        }
        $remainingHostsLines = @($hostLines | Where-Object { $_ -notmatch $managedHostsPattern })
        Set-Content -LiteralPath $hostsPath -Value $remainingHostsLines -Encoding ASCII
        ipconfig /flushdns | Out-Null
        Write-Host "Hosts entry removed: $hostsEntry"
    } else {
        Write-Host "No managed hosts entry was found."
    }

    $thumbprints = @()
    if (Test-Path -LiteralPath $thumbprintPath) {
        $thumbprints += (Get-Content -LiteralPath $thumbprintPath -Raw).Trim()
    } elseif (Test-Path -LiteralPath $rootCaPath) {
        $rootCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($rootCaPath)
        $thumbprints += $rootCertificate.Thumbprint
    } else {
        $thumbprints += @(
            Get-ChildItem Cert:\CurrentUser\Root | Where-Object {
                $_.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) -eq "EduPKIManager Root CA"
            } | ForEach-Object { $_.Thumbprint }
        )
    }

    $removedCertificates = 0
    foreach ($thumbprint in @($thumbprints | Where-Object { $_ })) {
        $certificatePath = "Cert:\CurrentUser\Root\$thumbprint"
        if (Test-Path -LiteralPath $certificatePath) {
            Remove-Item -LiteralPath $certificatePath -Force
            $removedCertificates += 1
        }
    }
    Write-Host "Trusted Root CA certificates removed: $removedCertificates"

    Remove-Item -LiteralPath $rootCaPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $thumbprintPath -Force -ErrorAction SilentlyContinue
    if ((Test-Path -LiteralPath $rootCaDir) -and -not (Get-ChildItem -LiteralPath $rootCaDir -Force)) {
        Remove-Item -LiteralPath $rootCaDir -Force
    }
    Write-Host "EduPKIManager local TLS configuration removed."
    return
}

$currentHosts = Get-Content -LiteralPath $hostsPath -Raw

if ($currentHosts -notmatch "(^|\s)$([regex]::Escape($Hostname))(\s|$)") {
    if (-not (Test-IsAdministrator)) {
        throw "Run PowerShell as Administrator to update $hostsPath, then run this script again."
    }
    Add-Content -LiteralPath $hostsPath -Value "`r`n$hostsEntry"
    ipconfig /flushdns | Out-Null
    Write-Host "Hosts entry added: $hostsEntry"
} else {
    Write-Host "Hosts entry already exists for $Hostname"
}

New-Item -ItemType Directory -Force -Path $rootCaDir | Out-Null
Invoke-WebRequest -Uri "$ApiBaseUrl/ca/root.pem" -OutFile $rootCaPath
Write-Host "Root CA downloaded: $rootCaPath"

if ($TrustRootCa) {
    certutil -user -addstore Root $rootCaPath | Out-Null
    $rootCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($rootCaPath)
    Set-Content -LiteralPath $thumbprintPath -Value $rootCertificate.Thumbprint -Encoding ASCII
    Write-Host "Root CA imported into CurrentUser Root store."
} else {
    Write-Host "Root CA was not imported. Re-run with -TrustRootCa to trust HTTPS in Edge/Chrome."
}

Write-Host "Open: https://$Hostname"
