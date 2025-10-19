# ==============================
# IT_Request_Report (UTF-8, key:value, with Summary)
# ==============================

# Collect into a StringBuilder, then write once as UTF-8 (no BOM) to avoid UTF-16 spacing issues
$sb = New-Object System.Text.StringBuilder
function Add([string]$s) { [void]$sb.AppendLine($s) }
function AddBlank() { Add "" }
function AddBlock([string]$title) { AddBlank; Add("--- $title ---") }

# Safe helper to append lines from command output
function AddLines($lines, [string]$indent = "  ") {
  if ($null -ne $lines) { $lines | ForEach-Object { Add("$indent$_") } }
}

# ---------- Gather facts ----------
$now = Get-Date
$userName = whoami
$wi = [Security.Principal.WindowsIdentity]::GetCurrent()
$wp = New-Object Security.Principal.WindowsPrincipal($wi)
$isElevated = $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

# Local admin group membership (might throw on locked-down images)
$localAdminMember = $false
try {
  $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
  $localAdminMember = $admins.Name -contains $wi.Name
} catch { $localAdminMember = $false }

$os = Get-CimInstance Win32_OperatingSystem
$cs = Get-CimInstance Win32_ComputerSystem
$lastBoot = [Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime)

# Permission probes (non-destructive)
$programFilesWrite = $false; $programFilesWriteErr = $null
$pfTest = "C:\Program Files\perm_test_{0}.tmp" -f ([guid]::NewGuid().ToString("N"))
try {
  New-Item -Path $pfTest -ItemType File -Force -ErrorAction Stop | Out-Null
  $programFilesWrite = $true
} catch { $programFilesWrite = $false; $programFilesWriteErr = $_.Exception.Message }
finally { if (Test-Path $pfTest) { Remove-Item $pfTest -Force -ErrorAction SilentlyContinue } }

$canReadSysEvent = $false; $sysEventErr = $null
try { Get-EventLog -LogName System -Newest 1 -ErrorAction Stop | Out-Null; $canReadSysEvent = $true }
catch { $canReadSysEvent = $false; $sysEventErr = $_.Exception.Message }

# Network summary
$upIfs = Get-NetAdapter | Where-Object Status -eq Up
$ipv4 = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '169.254.*' -and $_.IPAddress -ne '127.0.0.1' }

# Disk (system drive if present)
$volC = Get-Volume -DriveLetter C -ErrorAction SilentlyContinue

# ---------- SUMMARY ----------
Add("=== IT Request Report ===")
Add(("Generated: {0:yyyy-MM-dd HH:mm:ss}" -f $now))
Add("RunContext: Non-elevated PowerShell session")
AddBlank()
Add("=== Summary ===")
Add(("User: {0}" -f $userName))
Add(("Computer: {0}" -f $env:COMPUTERNAME))
Add(("DomainJoined: {0}" -f $cs.PartOfDomain))
Add(("DomainOrWorkgroup: {0}" -f $cs.Domain))
Add(("IsElevatedToken: {0}" -f $isElevated))
Add(("LocalAdminsGroupMember: {0}" -f $localAdminMember))
Add(("OS: {0}" -f $os.Caption))
Add(("Version: {0} (Build {1})" -f $os.Version, $os.BuildNumber))
Add(("InstallDate: {0}" -f ([Management.ManagementDateTimeConverter]::ToDateTime($os.InstallDate))))
Add(("LastBoot: {0}" -f $lastBoot))
if ($volC) {
  Add(("SystemDrive C: SizeGB={0:N1} FreeGB={1:N1}" -f ($volC.Size/1GB), ($volC.SizeRemaining/1GB)))
}
Add(("RAM_GB: {0:N1}" -f ($cs.TotalPhysicalMemory/1GB)))
Add(("ProgramFiles_WriteAllowed: {0}" -f $programFilesWrite))
if (-not $programFilesWrite -and $programFilesWriteErr) { Add(("ProgramFiles_WriteError: {0}" -f $programFilesWriteErr)) }
Add(("CanRead_SystemEventLog: {0}" -f $canReadSysEvent))
if (-not $canReadSysEvent -and $sysEventErr) { Add(("SystemEventLog_Error: {0}" -f $sysEventErr)) }
if ($upIfs) {
  $netSummary = $upIfs | ForEach-Object {
    $name = $_.Name
    $ips = ($ipv4 | Where-Object InterfaceIndex -eq $_.IfIndex | Select-Object -ExpandProperty IPAddress)
    if ($ips) { "{0}=[{1}]" -f $name, ($ips -join ',') } else { "{0}=[no IPv4]" -f $name }
  }
  Add(("ActiveNetwork: {0}" -f ($netSummary -join ' ; ')))
}
AddBlank()

# ---------- DETAILS ----------
AddBlock "Current user & elevation"
Add(("User: {0}" -f $userName))
Add(("IsElevatedToken: {0}" -f $isElevated))
Add("Whoami /groups:")
AddLines (whoami /groups 2>&1)
Add("Whoami /priv:")
AddLines (whoami /priv 2>&1)

AddBlock "Local Administrators group members"
try { AddLines ((Get-LocalGroupMember Administrators 2>&1)) } catch { Add("  Access denied or cannot query local group") }

AddBlock "OS & system info"
Add(("Name: {0}" -f $os.Caption))
Add(("Version: {0}" -f $os.Version))
Add(("BuildNumber: {0}" -f $os.BuildNumber))
Add(("InstallDate: {0}" -f ([Management.ManagementDateTimeConverter]::ToDateTime($os.InstallDate))))
Add(("Architecture: {0}" -f (Get-ComputerInfo -Property OsArchitecture).OsArchitecture))
Add(("LastBoot: {0}" -f $lastBoot))

AddBlock "Installed applications (registry)"
$apps = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* ,
                        HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* ,
                        HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* 2>$null |
        Where-Object { $_.DisplayName } | Sort-Object DisplayName
foreach ($a in $apps) {
  Add(("App: {0}" -f $a.DisplayName))
  Add(("  Version: {0}" -f $a.DisplayVersion))
  Add(("  Publisher: {0}" -f $a.Publisher))
  Add(("  InstallDate: {0}" -f $a.InstallDate))
}

AddBlock "Group policy (user gpresult /R)"
AddLines (gpresult /R 2>&1)

AddBlock "Services summary"
Get-Service | Sort-Object Name | ForEach-Object {
  Add(("Service: {0}" -f $_.Name))
  Add(("  DisplayName: {0}" -f $_.DisplayName))
  Add(("  Status: {0}" -f $_.Status))
  Add(("  StartType: {0}" -f $_.StartType))
}

AddBlock "Network adapters"
$adapters = Get-NetAdapter
foreach ($a in $adapters) {
  Add(("Adapter: {0}" -f $a.Name))
  Add(("  Status: {0}" -f $a.Status))
  Add(("  MAC: {0}" -f $a.MacAddress))
  $ips = $ipv4 | Where-Object InterfaceIndex -eq $a.IfIndex | Select-Object -ExpandProperty IPAddress
  if ($ips) { Add(("  IPv4: {0}" -f ($ips -join ', '))) }
}

AddBlock "IP configuration (ipconfig /all)"
AddLines (ipconfig /all 2>&1)

AddBlock "Drives"
Get-PSDrive -PSProvider FileSystem | ForEach-Object {
  Add(("Drive: {0}" -f $_.Name))
  Add(("  Root: {0}" -f $_.Root))
  if ($_.Free -ne $null) { Add(("  FreeGB: {0:N1}" -f ($_.Free/1GB))) }
  if ($_.Used -ne $null) { Add(("  UsedGB: {0:N1}" -f ($_.Used/1GB))) }
}

AddBlock "Volumes"
Get-Volume | ForEach-Object {
  Add(("DriveLetter: {0}" -f $_.DriveLetter))
  Add(("  Label: {0}" -f $_.FileSystemLabel))
  Add(("  FileSystem: {0}" -f $_.FileSystem))
  Add(("  SizeGB: {0:N1}" -f ($_.Size/1GB)))
  Add(("  FreeGB: {0:N1}" -f ($_.SizeRemaining/1GB)))
}

AddBlock "Folder ACLs"
Add("Program Files ACL:")
try { (Get-Acl "C:\Program Files").Access | ForEach-Object { Add(("  {0}: {1}" -f $_.IdentityReference, $_.FileSystemRights)) } }
catch { Add("  Access denied") }
Add("Windows ACL:")
try { (Get-Acl "C:\Windows").Access | ForEach-Object { Add(("  {0}: {1}" -f $_.IdentityReference, $_.FileSystemRights)) } }
catch { Add("  Access denied") }

AddBlock "Event log access test"
if ($canReadSysEvent) {
  Get-EventLog -LogName System -Newest 3 | ForEach-Object {
    Add(("Event: {0} {1} {2}" -f $_.TimeGenerated, $_.Source, $_.EntryType))
  }
} else {
  Add(("  Access denied or restricted: {0}" -f $sysEventErr))
}

AddBlock "Summary note"
Add("Commands executed non-elevated to show privilege restrictions.")
Add("Send this report to IT to request admin rights.")

# ---------- Write files as UTF-8 (no BOM) ----------
$OutFile = Join-Path $env:USERPROFILE "Desktop\IT_Request_Report.txt"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($OutFile, $sb.ToString(), $utf8NoBom)

Write-Host "✅ Report created:" $OutFile
