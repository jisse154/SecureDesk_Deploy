<#
.SYNOPSIS
  Épingle les installeurs officiels (version, URL, SHA-256) dans src/SecureDesk.Core/Installers/installers.json.
.DESCRIPTION
  Exécuté par la CI Windows avant la publication. Chaque fichier est téléchargé depuis le site OFFICIEL de l'éditeur,
  sa signature Authenticode est vérifiée (éditeur attendu), puis son empreinte est figée dans l'exécutable publié.
  À l'exécution sur vos PC, SecureDesk refuse tout fichier dont l'empreinte diffère.
#>
[CmdletBinding()]
param(
    [string]$Manifest = (Join-Path $PSScriptRoot '..\src\SecureDesk.Core\Installers\installers.json'),
    [string]$WorkDir = (Join-Path ([IO.Path]::GetTempPath()) 'securedesk-pin')
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$json = Get-Content $Manifest -Raw | ConvertFrom-Json

function Get-Latest([string]$IndexUrl, [string]$Pattern) {
    $html = (Invoke-WebRequest -Uri $IndexUrl -UseBasicParsing).Content
    $found = [regex]::Matches($html, $Pattern) | ForEach-Object {
        [pscustomobject]@{ Name = $_.Groups[0].Value; Version = [version]$_.Groups['v'].Value }
    } | Sort-Object Version -Descending | Select-Object -First 1
    if (-not $found) { throw "Aucun fichier correspondant à $Pattern sur $IndexUrl" }
    return $found
}

function Test-Signer([string]$Path, [string]$Expected) {
    $sig = Get-AuthenticodeSignature -FilePath $Path
    Write-Host "  Signature : $($sig.Status) — $($sig.SignerCertificate.Subject)"
    if ($Expected) {
        if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notlike "*$Expected*") {
            throw "Signature inattendue pour $Path (attendu : $Expected)"
        }
    }
    return $sig
}

# --- WireGuard (MSI signé « WireGuard LLC ») ---
$wgIndex = 'https://download.wireguard.com/windows-client/'
$wg = Get-Latest $wgIndex 'wireguard-amd64-(?<v>\d+(\.\d+)+)\.msi'
$wgUrl = $wgIndex + $wg.Name
$wgFile = Join-Path $WorkDir $wg.Name
Write-Host "WireGuard $($wg.Version) : $wgUrl"
Invoke-WebRequest -Uri $wgUrl -OutFile $wgFile -UseBasicParsing
Test-Signer $wgFile $json.wireguard.signerSubjectContains | Out-Null
$json.wireguard.version = "$($wg.Version)"
$json.wireguard.url = $wgUrl
$json.wireguard.sha256 = (Get-FileHash $wgFile -Algorithm SHA256).Hash

# --- multiOTP Credential Provider (page officielle de téléchargement) ---
try {
    $mIndex = 'https://download.multiotp.net/credential-provider/'
    $m = Get-Latest $mIndex 'multiOTPCredentialProvider[-_A-Za-z]*?(?<v>\d+(\.\d+){2,3})[-_A-Za-z0-9]*\.(zip|msi)'
    $mUrl = $mIndex + $m.Name
    $mFile = Join-Path $WorkDir $m.Name
    Write-Host "multiOTP CP $($m.Version) : $mUrl"
    Invoke-WebRequest -Uri $mUrl -OutFile $mFile -UseBasicParsing
    $json.multiotp.version = "$($m.Version)"
    $json.multiotp.url = $mUrl
    $json.multiotp.sha256 = (Get-FileHash $mFile -Algorithm SHA256).Hash
    if ($mFile -like '*.zip') {
        $x = Join-Path $WorkDir 'multiotp'
        Expand-Archive -Path $mFile -DestinationPath $x -Force
        Get-ChildItem $x -Recurse -Filter *.msi | ForEach-Object { Write-Host "  MSI : $($_.Name)"; Test-Signer $_.FullName $json.multiotp.signerSubjectContains | Out-Null }
    } else {
        Test-Signer $mFile $json.multiotp.signerSubjectContains | Out-Null
    }
} catch {
    Write-Warning "multiOTP non épinglé automatiquement : $($_.Exception.Message). L'installation exigera un MSI local et son empreinte (--multiotp-msi, --sha256)."
}

$json | ConvertTo-Json -Depth 5 | Set-Content -Path $Manifest -Encoding utf8
Write-Host "Manifeste mis à jour : $Manifest"
Get-Content $Manifest
