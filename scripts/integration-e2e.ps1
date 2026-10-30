<#
.SYNOPSIS
  Scénario de bout en bout sur un runner Windows éphémère (GitHub Actions) avec l'exécutable publié.
.DESCRIPTION
  Simule le serveur ET le client sur la même machine (deux dossiers de données distincts, deux tunnels) :
  dry-run → init → idempotence → join → add-peer → handshake → accounts → harden → diagnose (aucun secret) → uninstall
  → vérification du retour à l'état initial. NE PAS exécuter sur un vrai PC.
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Exe)
$ErrorActionPreference = 'Stop'
$env:SECUREDESK_TEST_ALLOW_ANY_EDITION = '1'
$root = Join-Path $env:RUNNER_TEMP 'sd-e2e'
$srv = Join-Path $root 'server'; $cli = Join-Path $root 'client'; $out = Join-Path $root 'out'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$pass = 'Phrase-De-Test-CI-2026!'
$userPwd = 'Mot2Passe-CI-Robuste!'
$port = 51999

function SD([string]$Data, [string[]]$Arguments, [string[]]$Stdin = @()) {
    $env:SECUREDESK_DATA_DIR = $Data
    Write-Host "`n>>> SecureDesk $($Arguments -join ' ')" -ForegroundColor Cyan
    $Stdin | & $Exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Échec de « $($Arguments -join ' ') » (code $LASTEXITCODE)" }
}
function Assert([bool]$Condition, [string]$Message) { if (-not $Condition) { throw "ÉCHEC : $Message" } else { Write-Host "OK : $Message" -ForegroundColor Green } }
function OwnedRules { @(Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.Name -like 'SecureDesk-*' -or $_.DisplayName -like 'SecureDesk-*' }) }
$tsNames = 'UserAuthentication', 'SecurityLayer', 'MinEncryptionLevel', 'MaxIdleTime', 'MaxDisconnectionTime', 'fDisableClip', 'fDisableCdm', 'fDisableCpm', 'fDisableCcm', 'fDisableLPT', 'fDisablePNPRedir'
function TsPolicy {
    $p = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -ErrorAction SilentlyContinue
    $o = [ordered]@{}; foreach ($n in $tsNames) { $o[$n] = if ($p) { $p.$n } else { $null } }; [pscustomobject]$o
}
function SeceditValues {
    $f = Join-Path $root 'secedit.inf'; secedit /export /cfg $f /areas SECURITYPOLICY /quiet | Out-Null
    (Get-Content $f -Encoding Unicode) | Where-Object { $_ -match '^(MinimumPasswordLength|PasswordComplexity|LockoutBadCount|ResetLockoutCount|LockoutDuration)\s*=' } | Sort-Object
}

# --- État initial ---
$before = @{
    Rules = (OwnedRules).Count
    Policy = (TsPolicy | ConvertTo-Json -Compress)
    Secedit = (SeceditValues) -join ';'
}
Assert ($before.Rules -eq 0) 'aucune règle SecureDesk au départ'

& $Exe version; if ($LASTEXITCODE -ne 0) { throw 'version' }

# --- 1. dry-run : aucune modification ---
SD $srv @('init', '--dry-run', '--yes', '--endpoint', '127.0.0.1', '--port', "$port", '--users', 'sdtest1,sdtest2')
Assert ((OwnedRules).Count -eq 0) 'dry-run : aucune règle créée'
Assert (-not (Get-Service 'WireGuardTunnel$securedesk' -ErrorAction SilentlyContinue)) 'dry-run : aucun service de tunnel'

# --- 2. init serveur ---
SD $srv @('init', '--yes', '--endpoint', '127.0.0.1', '--port', "$port", '--users', 'sdtest1,sdtest2', '--out', (Join-Path $out 'pairing-server.sdpair')) @('', $pass, $pass)
$rules = OwnedRules
Assert ($rules.Count -eq 5) "5 règles de pare-feu créées (trouvé $($rules.Count))"
Assert ((Get-Service 'WireGuardTunnel$securedesk').Status -eq 'Running') 'service de tunnel serveur actif'
Assert ((Get-Service 'WireGuardTunnel$securedesk').StartType -eq 'Automatic') 'service de tunnel serveur en démarrage automatique'
$conf = Join-Path $srv 'wireguard\securedesk.conf'
$acl = (Get-Acl $conf).Access | ForEach-Object { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value }
Assert (@($acl | Where-Object { $_ -notin @('S-1-5-18', 'S-1-5-32-544') }).Count -eq 0) 'ACL de la configuration : SYSTEM + Administrateurs uniquement'
$serverFile = Get-Content (Join-Path $out 'pairing-server.sdpair') -Raw
Assert ($serverFile -notmatch 'PrivateKey|PresharedKey') 'fichier serveur sans clé en clair'

# --- 3. idempotence ---
SD $srv @('init', '--yes', '--endpoint', '127.0.0.1', '--port', "$port", '--users', 'sdtest1,sdtest2') @('', $pass, $pass)
$rules2 = OwnedRules
Assert ($rules2.Count -eq 5) 'relance : toujours 5 règles (aucun doublon)'
Assert (@($rules2.Name | Sort-Object -Unique).Count -eq 5) 'relance : noms uniques'

# --- 4. client (même machine, tunnel distinct) ---
$clientCfg = Join-Path $root 'client.json'
'{ "server": { "tunnelName": "sdclient" }, "client": { "autoStartTunnel": true, "createRdpShortcut": true } }' | Set-Content $clientCfg -Encoding utf8
SD $cli @('join', (Join-Path $out 'pairing-server.sdpair'), '--yes', '--config', $clientCfg, '--out', (Join-Path $out 'pairing-client.sdpair')) @($pass)
Assert ((Get-Service 'WireGuardTunnel$sdclient').Status -eq 'Running') 'service de tunnel client actif'
$clientFile = Get-Content (Join-Path $out 'pairing-client.sdpair') -Raw
Assert ($clientFile -match '"kind": "client"') 'fichier client produit'

# --- 5. add-peer + handshake ---
SD $srv @('add-peer', (Join-Path $out 'pairing-client.sdpair'), '--yes')
$wg = Join-Path $env:ProgramFiles 'WireGuard\wg.exe'
$ok = $false
for ($i = 0; $i -lt 45 -and -not $ok; $i++) {
    $hs = & $wg show securedesk latest-handshakes
    if ($hs -match '\s([1-9]\d+)\s*$') { $ok = $true } else { Start-Sleep 2 }
}
Assert $ok 'handshake WireGuard établi entre client et serveur'
SD $srv @('list-peers')

# --- 6. comptes + durcissement ---
SD $srv @('accounts', '--yes', '--users', 'sdtest1,sdtest2') @($userPwd, $userPwd, $userPwd, $userPwd)
Assert ($null -ne (Get-LocalUser sdtest1 -ErrorAction SilentlyContinue)) 'compte sdtest1 créé'
Assert (@(Get-LocalGroupMember -SID 'S-1-5-32-555' | Where-Object Name -like '*sdtest2').Count -eq 1) 'sdtest2 dans Utilisateurs du Bureau à distance'
SD $srv @('harden', '--yes', '--users', 'sdtest1,sdtest2')
$pol = TsPolicy
Assert ($pol.UserAuthentication -eq 1 -and $pol.SecurityLayer -eq 2 -and $pol.MinEncryptionLevel -eq 3) 'NLA + TLS + chiffrement élevé'
Assert ($pol.fDisableClip -eq 1 -and $pol.fDisableCdm -eq 1) 'redirections désactivées par défaut'
SD $srv @('harden', '--yes', '--users', 'sdtest1,sdtest2')

# --- 7. diagnose : aucun secret ---
$report = Join-Path $out 'diagnostic.txt'
SD $srv @('diagnose', '--export', $report)
$keys = Select-String -Path $conf, (Join-Path $cli 'wireguard\sdclient.conf') -Pattern '^(PrivateKey|PresharedKey)\s*=\s*(\S+)' | ForEach-Object { $_.Matches[0].Groups[2].Value }
Assert ($keys.Count -ge 3) 'clés de test récupérées pour la vérification'
$haystack = (Get-Content $report -Raw) + (Get-ChildItem (Join-Path $srv 'logs'), (Join-Path $cli 'logs') -File | Get-Content -Raw) + $serverFile + $clientFile
foreach ($k in $keys) { Assert (-not $haystack.Contains($k)) "secret absent des journaux, rapports et fichiers d'appairage (…$($k.Substring(40)))" }
Assert (-not $haystack.Contains($pass)) "phrase de passe absente des journaux"
Assert (-not $haystack.Contains($userPwd)) "mot de passe de compte absent des journaux"

# --- 8. désinstallation ---
SD $cli @('uninstall', '--yes', '--config', $clientCfg)
Assert (-not (Get-Service 'WireGuardTunnel$sdclient' -ErrorAction SilentlyContinue)) 'tunnel client supprimé'
SD $srv @('uninstall', '--yes', '--remove-accounts')
Assert ((OwnedRules).Count -eq 0) 'règles de pare-feu supprimées'
Assert (-not (Get-Service 'WireGuardTunnel$securedesk' -ErrorAction SilentlyContinue)) 'tunnel serveur supprimé'
Assert ($null -eq (Get-LocalUser sdtest1 -ErrorAction SilentlyContinue)) 'comptes de test supprimés (--remove-accounts)'
Assert ((TsPolicy | ConvertTo-Json -Compress) -eq $before.Policy) 'stratégies RDP restaurées à l''identique'
Assert (((SeceditValues) -join ';') -eq $before.Secedit) 'stratégie de mots de passe restaurée à l''identique'
Assert (-not (Test-Path $conf)) 'configuration serveur effacée'
Write-Host "`nScénario de bout en bout réussi." -ForegroundColor Green
