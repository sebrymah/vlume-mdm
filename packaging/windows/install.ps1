# install.ps1 — install the device agent on Windows.
#
# BE CLEAR ABOUT WHAT THIS IS. It registers a scheduled task running as
# SYSTEM, not a real Windows service. A service needs the service control
# manager plumbing (golang.org/x/sys/windows/svc), which is not built, and
# the difference matters: a scheduled task does not restart on failure the
# way a service does, and it does not appear where an administrator looks
# for one.
#
# What else is missing here, stated rather than discovered:
#   * the binary is not Authenticode signed, so SmartScreen will warn
#   * the permission checks in `agent doctor` are not implemented on
#     Windows, and the command says so rather than giving a clean report
#   * there is no uninstaller; remove the task and the folder by hand
#
# This is enough to run a pilot on Windows and is not enough to ship.

param(
  [Parameter(Mandatory=$true)][string]$Server,
  [string]$TokenFile = "",
  [string]$Binary = ".\mdm-agent-windows-amd64.exe",
  [string]$Dir = "C:\ProgramData\mdm-agent",
  [string]$Every = "15m"
)

$ErrorActionPreference = "Stop"

if (-not ([Security.Principal.WindowsPrincipal] `
      [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
      [Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "This must run from an elevated prompt."
}

# Read the token before anything is installed, so a mistyped one does not
# leave a half-installed task behind. It is never passed as an argument:
# another user can read a process's command line here too.
if ($TokenFile -ne "") {
  $Token = (Get-Content -Raw $TokenFile).Trim()
} else {
  $Secure = Read-Host -AsSecureString "Enrolment token"
  $Token = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure))
}
if ([string]::IsNullOrWhiteSpace($Token)) { throw "No enrolment token given." }

$LibExec = "C:\Program Files\mdm-agent"
New-Item -ItemType Directory -Force -Path $LibExec | Out-Null
Copy-Item $Binary (Join-Path $LibExec "mdm-agent.exe") -Force
New-Item -ItemType Directory -Force -Path $Dir | Out-Null

# Administrators and SYSTEM only. The folder holds the private key that IS
# this device's identity.
icacls $Dir /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null

$Exe = Join-Path $LibExec "mdm-agent.exe"
$Token | & $Exe -server $Server -dir $Dir enrol
Remove-Variable Token

$Action = New-ScheduledTaskAction -Execute $Exe `
  -Argument "-server $Server -dir `"$Dir`" -every $Every run"
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)

Register-ScheduledTask -TaskName "mdm-agent" -Action $Action -Trigger $Trigger `
  -Principal $Principal -Settings $Settings -Force | Out-Null
Start-ScheduledTask -TaskName "mdm-agent"

Write-Host ""
Write-Host "Installed as a scheduled task running as SYSTEM."
Write-Host "This is not a Windows service: it will not restart the way one does."
Write-Host "Locking and wiping need a privileged helper this build does not ship."
