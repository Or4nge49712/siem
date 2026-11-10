<#
  Préparation de la VM Windows (endpoint surveillé) - PowerShell en administrateur :
    Set-ExecutionPolicy -Scope Process Bypass -Force
    .\setup-windows.ps1 -StackVersion 8.19.4
  Fait : réseau, nom, journalisation (audit, ligne de commande, PowerShell), taille des journaux,
         Sysmon (config sysmon-modular), Winlogbeat (service). winlogbeat.yml doit être à côté du script.

  Version corrigée (10/11/2026) :
    - attente de la reprise du réseau après la configuration IP (sinon échec DNS au téléchargement) ;
    - configuration Sysmon prise dans les Releases de sysmon-modular (le fichier n'est plus à la racine du dépôt) ;
    - contrôles avant de commencer (droits admin, winlogbeat.yml présent et mot de passe renseigné) ;
    - téléchargements réutilisés s'ils sont déjà présents (relance plus rapide) ;
    - les commandes externes ne font plus échouer le script à tort, et leurs vraies erreurs sont détectées ;
    - fichier enregistré en UTF-8 avec BOM : les accents s'affichent correctement.
  Le script peut être relancé sans risque.
#>
param(
  [string]$StackVersion = "8.19.4",
  [string]$IP = "10.10.10.20",
  [string]$Gateway = "10.10.10.10",
  [string[]]$Dns = @("1.1.1.1", "9.9.9.9"),
  [string]$ComputerName = "WS01",
  [string]$SysmonConfigUrl = "https://github.com/olafhartong/sysmon-modular/releases/download/configs-a45dedb13a43/sysmonconfig.xml",
  [switch]$SkipNetwork
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"      # téléchargements beaucoup plus rapides
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Work = "C:\LabSetup"; New-Item -ItemType Directory -Force -Path $Work | Out-Null

# Exécute un programme externe sans que sa sortie d'erreur ne fasse planter PowerShell 5.1,
# puis vérifie son code de retour.
function Invoke-Native([scriptblock]$Cmd, [string]$What) {
  $old = $ErrorActionPreference; $ErrorActionPreference = "Continue"
  try { & $Cmd } finally { $ErrorActionPreference = $old }
  if ($LASTEXITCODE -ne 0) { throw "Échec : $What (code $LASTEXITCODE)" }
}

# Téléchargement avec plusieurs essais (le réseau peut mettre quelques secondes à revenir).
function Get-File([string]$Url, [string]$OutFile) {
  for ($i = 1; $i -le 5; $i++) {
    try { Invoke-WebRequest $Url -OutFile $OutFile -UseBasicParsing; return }
    catch {
      if ($_.Exception.Response -and [int]$_.Exception.Response.StatusCode -eq 404) {
        throw "Fichier introuvable (404) : $Url"
      }
      if ($i -eq 5) { throw "Téléchargement impossible : $Url`n$($_.Exception.Message)" }
      Write-Host "    Essai $i échoué, nouvel essai dans 5 s..." -ForegroundColor Yellow
      Clear-DnsClientCache; Start-Sleep -Seconds 5
    }
  }
}

# 0. Contrôles préalables -------------------------------------------------------
$id = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $id.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Lancer ce script dans un PowerShell administrateur."
}
$WlbConfig = Join-Path $PSScriptRoot "winlogbeat.yml"
if (-not (Test-Path $WlbConfig)) { throw "winlogbeat.yml introuvable à côté du script ($PSScriptRoot)." }
if (Select-String -Path $WlbConfig -Pattern "CHANGEME|changeme|<mdp>" -Quiet) {
  throw "winlogbeat.yml contient encore un mot de passe à remplacer (mettre celui du compte elastic, 2 fois)."
}

# 1. Réseau statique et nom de machine ------------------------------------
if (-not $SkipNetwork) {
  $nic = Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1
  if (-not $nic) { throw "Aucune carte réseau active." }
  Write-Host "[1] IP $IP sur $($nic.Name)"
  $already = Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
             Where-Object IPAddress -eq $IP
  if ($already) {
    Write-Host "    Adresse déjà en place, carte inchangée."
  } else {
    Set-NetIPInterface -InterfaceIndex $nic.ifIndex -Dhcp Disabled
    Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
    Get-NetRoute -InterfaceIndex $nic.ifIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
      Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
    New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $IP -PrefixLength 24 -DefaultGateway $Gateway | Out-Null
  }
  Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses $Dns
}
# Attendre que le réseau et le DNS répondent (après une nouvelle adresse, Windows met quelques secondes)
Write-Host "    Vérification de l'accès Internet..."
Clear-DnsClientCache
$ok = $false
for ($i = 1; $i -le 12; $i++) {
  try { Resolve-DnsName "download.sysinternals.com" -ErrorAction Stop | Out-Null; $ok = $true; break }
  catch { Start-Sleep -Seconds 5; Clear-DnsClientCache }
}
if (-not $ok) {
  throw "Pas d'accès Internet/DNS. SIEM01 est-elle démarrée (passerelle $Gateway) ? Tester : ping $Gateway ; ping 1.1.1.1"
}
Write-Host "    Réseau OK."

Set-TimeZone -Id "Romance Standard Time"      # Paris
$old = $ErrorActionPreference; $ErrorActionPreference = "Continue"
w32tm /resync /force 2>&1 | Out-Null           # échoue sans gravité si le service de temps est arrêté
$ErrorActionPreference = $old

# 2. Stratégie d'audit avancée (GUID = indépendant de la langue de Windows) --
Write-Host "[2] Audit policy"
$audit = @{
  "{0CCE922B-69AE-11D9-BED3-505054503030}" = "Process Creation (4688)"
  "{0CCE9215-69AE-11D9-BED3-505054503030}" = "Logon (4624/4625)"
  "{0CCE921B-69AE-11D9-BED3-505054503030}" = "Special Logon (4672)"
  "{0CCE923F-69AE-11D9-BED3-505054503030}" = "Credential Validation (4776)"
  "{0CCE9235-69AE-11D9-BED3-505054503030}" = "User Account Management (4720...)"
  "{0CCE9237-69AE-11D9-BED3-505054503030}" = "Security Group Management (4732...)"
  "{0CCE9211-69AE-11D9-BED3-505054503030}" = "Security System Extension (4697)"
  "{0CCE9227-69AE-11D9-BED3-505054503030}" = "Other Object Access (4698 tâches planifiées)"
}
foreach ($g in $audit.Keys) {
  Invoke-Native { auditpol /set /subcategory:"$g" /success:enable /failure:enable | Out-Null } "auditpol $($audit[$g])"
  Write-Host "    $($audit[$g])"
}
# Forcer la stratégie avancée sur la stratégie de base
Invoke-Native { reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f | Out-Null } "reg SCENoApplyLegacyAuditPolicy"
# Ligne de commande dans l'événement 4688
Invoke-Native { reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null } "reg ProcessCreationIncludeCmdLine"

# 3. Journalisation PowerShell ---------------------------------------------
Write-Host "[3] PowerShell Script Block + Module Logging"
$ps = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
New-Item -Path "$ps\ScriptBlockLogging" -Force | Out-Null
Set-ItemProperty -Path "$ps\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1 -Type DWord
New-Item -Path "$ps\ModuleLogging\ModuleNames" -Force | Out-Null
Set-ItemProperty -Path "$ps\ModuleLogging" -Name EnableModuleLogging -Value 1 -Type DWord
Set-ItemProperty -Path "$ps\ModuleLogging\ModuleNames" -Name "*" -Value "*"

# 4. Taille des journaux ----------------------------------------------------
Write-Host "[4] Taille des journaux"
Invoke-Native { wevtutil sl Security /ms:1073741824 } "taille journal Security"
Invoke-Native { wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:268435456 } "taille journal PowerShell"
Invoke-Native { wevtutil sl System /ms:134217728 } "taille journal System"

# 5. Sysmon + config sysmon-modular ----------------------------------------
Write-Host "[5] Sysmon"
if (-not (Test-Path "$Work\Sysmon\Sysmon64.exe")) {
  Get-File "https://download.sysinternals.com/files/Sysmon.zip" "$Work\Sysmon.zip"
  Expand-Archive "$Work\Sysmon.zip" -DestinationPath "$Work\Sysmon" -Force
} else { Write-Host "    Sysmon déjà téléchargé." }
# La configuration n'est plus à la racine du dépôt : elle est publiée dans les Releases.
# Release figée (configs-a45dedb13a43) pour que l'installation reste reproductible.
Get-File $SysmonConfigUrl "$Work\sysmonconfig.xml"
if ((Get-Item "$Work\sysmonconfig.xml").Length -lt 10KB) { throw "sysmonconfig.xml semble vide ou incomplet." }
$sysmonExe = "$Work\Sysmon\Sysmon64.exe"
if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) {
  Invoke-Native { & $sysmonExe -c "$Work\sysmonconfig.xml" 2>&1 | Out-Null } "mise à jour de la configuration Sysmon"
  Write-Host "    Configuration Sysmon mise à jour."
} else {
  Invoke-Native { & $sysmonExe -accepteula -i "$Work\sysmonconfig.xml" 2>&1 | Out-Null } "installation de Sysmon"
  Write-Host "    Sysmon installé."
}
Invoke-Native { wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:536870912 } "taille journal Sysmon"

# 6. Winlogbeat ---------------------------------------------------------------
Write-Host "[6] Winlogbeat $StackVersion"
$zip = "winlogbeat-$StackVersion-windows-x86_64"
if (-not (Test-Path "$Work\$zip\winlogbeat.exe")) {
  Get-File "https://artifacts.elastic.co/downloads/beats/winlogbeat/$zip.zip" "$Work\$zip.zip"
  Expand-Archive "$Work\$zip.zip" -DestinationPath $Work -Force
} else { Write-Host "    Winlogbeat déjà téléchargé." }
$Dest = "C:\Program Files\Winlogbeat"
if (Get-Service winlogbeat -ErrorAction SilentlyContinue) { Stop-Service winlogbeat -Force }
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Copy-Item "$Work\$zip\*" $Dest -Recurse -Force
Copy-Item $WlbConfig "$Dest\winlogbeat.yml" -Force
Push-Location $Dest
try {
  if (-not (Get-Service winlogbeat -ErrorAction SilentlyContinue)) {
    & ".\install-service-winlogbeat.ps1" | Out-Null
  }
  Write-Host "    Test de la configuration..."
  Invoke-Native { & ".\winlogbeat.exe" test config -c ".\winlogbeat.yml" } "winlogbeat test config (fichier winlogbeat.yml invalide ?)"
  Write-Host "    Test de la connexion à Elasticsearch..."
  Invoke-Native { & ".\winlogbeat.exe" test output -c ".\winlogbeat.yml" } "winlogbeat test output (SIEM01 éteinte ou mot de passe elastic incorrect ?)"
  Write-Host "    Modèles d'index, pipelines et tableaux de bord (1 à 3 minutes)..."
  Invoke-Native { & ".\winlogbeat.exe" setup -c ".\winlogbeat.yml" 2>&1 | Out-Null } "winlogbeat setup (relancer à la main avec -e pour voir le détail)"
} finally { Pop-Location }
Set-Service winlogbeat -StartupType Automatic
Start-Service winlogbeat

# 7. Bilan --------------------------------------------------------------------
Write-Host "`n=== Bilan ==="
Get-Service Sysmon64, winlogbeat | Format-Table Name, Status, StartType -AutoSize
Test-NetConnection $Gateway -Port 9200 -WarningAction SilentlyContinue | Format-Table ComputerName, RemotePort, TcpTestSucceeded -AutoSize
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 3 -ErrorAction SilentlyContinue | Format-Table TimeCreated, Id -AutoSize
auditpol /get /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}"
if ($env:COMPUTERNAME -ne $ComputerName) {
  Rename-Computer -NewName $ComputerName -Force
  Write-Host "Nom changé en $ComputerName : redémarrez la VM (Restart-Computer) puis prenez le snapshot telemetry-ready." -ForegroundColor Yellow
} else {
  Write-Host "Terminé. Prenez le snapshot telemetry-ready de WS01." -ForegroundColor Green
}
