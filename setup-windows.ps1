<#
  Préparation de la VM Windows (endpoint surveillé) - PowerShell en administrateur :
    Set-ExecutionPolicy -Scope Process Bypass -Force
    .\setup-windows.ps1 -StackVersion 8.19.4
  Fait : réseau, nom, journalisation (audit, ligne de commande, PowerShell), taille des journaux,
         Sysmon (config sysmon-modular), Winlogbeat (service). winlogbeat.yml doit être à côté du script.
#>
param(
  [string]$StackVersion = "8.19.4",
  [string]$IP = "10.10.10.20",
  [string]$Gateway = "10.10.10.10",
  [string[]]$Dns = @("1.1.1.1", "9.9.9.9"),
  [string]$ComputerName = "WS01",
  [switch]$SkipNetwork
)
$ErrorActionPreference = "Stop"
$Work = "C:\LabSetup"; New-Item -ItemType Directory -Force -Path $Work | Out-Null

# 1. Réseau statique et nom de machine ------------------------------------
if (-not $SkipNetwork) {
  $nic = Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1
  Write-Host "[1] IP $IP sur $($nic.Name)"
  Get-NetIPAddress -InterfaceIndex $nic.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
  Get-NetRoute -InterfaceIndex $nic.ifIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
  New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $IP -PrefixLength 24 -DefaultGateway $Gateway | Out-Null
  Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses $Dns
}
Set-TimeZone -Id "Romance Standard Time"      # Paris
w32tm /resync /force | Out-Null

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
  auditpol /set /subcategory:"$g" /success:enable /failure:enable | Out-Null
  Write-Host "    $($audit[$g])"
}
# Forcer la stratégie avancée sur la stratégie de base
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f | Out-Null
# Ligne de commande dans l'événement 4688
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null

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
wevtutil sl Security /ms:1073741824
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:268435456
wevtutil sl System /ms:134217728

# 5. Sysmon + config sysmon-modular ----------------------------------------
Write-Host "[5] Sysmon"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "$Work\Sysmon.zip"
Expand-Archive "$Work\Sysmon.zip" -DestinationPath "$Work\Sysmon" -Force
Invoke-WebRequest "https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml" -OutFile "$Work\sysmonconfig.xml"
if (Get-Service Sysmon64 -ErrorAction SilentlyContinue) {
  & "$Work\Sysmon\Sysmon64.exe" -c "$Work\sysmonconfig.xml"
} else {
  & "$Work\Sysmon\Sysmon64.exe" -accepteula -i "$Work\sysmonconfig.xml"
}

# 6. Winlogbeat ---------------------------------------------------------------
Write-Host "[6] Winlogbeat $StackVersion"
$zip = "winlogbeat-$StackVersion-windows-x86_64"
Invoke-WebRequest "https://artifacts.elastic.co/downloads/beats/winlogbeat/$zip.zip" -OutFile "$Work\$zip.zip"
Expand-Archive "$Work\$zip.zip" -DestinationPath $Work -Force
$Dest = "C:\Program Files\Winlogbeat"
if (Get-Service winlogbeat -ErrorAction SilentlyContinue) { Stop-Service winlogbeat }
New-Item -ItemType Directory -Force -Path $Dest | Out-Null
Copy-Item "$Work\$zip\*" $Dest -Recurse -Force
Copy-Item "$PSScriptRoot\winlogbeat.yml" "$Dest\winlogbeat.yml" -Force
Set-Location $Dest
& ".\install-service-winlogbeat.ps1"
& ".\winlogbeat.exe" test config -c ".\winlogbeat.yml" -e
& ".\winlogbeat.exe" test output -c ".\winlogbeat.yml" -e
& ".\winlogbeat.exe" setup -c ".\winlogbeat.yml" -e     # modèles d'index, pipelines, dashboards
Start-Service winlogbeat

# 7. Bilan --------------------------------------------------------------------
Write-Host "`n=== Bilan ==="
Get-Service Sysmon64, winlogbeat | Format-Table Name, Status
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 3 | Format-Table TimeCreated, Id
auditpol /get /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}"
if ($env:COMPUTERNAME -ne $ComputerName) {
  Rename-Computer -NewName $ComputerName -Force
  Write-Host "Nom changé en $ComputerName : redémarrez la VM puis prenez le snapshot telemetry-ready." -ForegroundColor Yellow
}
