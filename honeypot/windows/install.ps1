#Requires -Version 5.1
<#
.SYNOPSIS
    Install the honeypot as an auto-starting service on Windows.

.DESCRIPTION
    Copies the honeypot to C:\ProgramData\Honeypot, writes a config, creates
    logs under C:\ProgramData\Honeypot\logs, registers a Scheduled Task that
    runs it at system startup under the low-privilege LOCAL SERVICE account,
    and (optionally) opens the honeypot ports in Windows Firewall.

    Run from an elevated PowerShell (Run as Administrator):
        powershell -ExecutionPolicy Bypass -File windows\install.ps1

.PARAMETER OpenFirewall
    Also add inbound allow rules for the honeypot ports so remote hosts can reach it.

.PARAMETER Ports
    Ports to open when -OpenFirewall is given. Defaults to the config's 2222,2323,8080.
#>
[CmdletBinding()]
param(
    [switch]$OpenFirewall,
    [int[]]$Ports = @(2222, 2323, 8080)
)

$ErrorActionPreference = 'Stop'

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Please run this script from an elevated PowerShell (Run as Administrator).'
    }
}

function Find-Python {
    foreach ($candidate in @('pythonw.exe', 'python.exe', 'py.exe')) {
        $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }
    throw 'Python 3 was not found on PATH. Install it from https://www.python.org/ (tick "Add to PATH").'
}

Assert-Admin

$AppDir   = Join-Path $env:ProgramData 'Honeypot'
$LogDir   = Join-Path $AppDir 'logs'
$StateDir = Join-Path $AppDir 'state'
$DecoyDir = Join-Path $StateDir 'decoys'
$CfgPath  = Join-Path $AppDir 'config.json'
$Script   = Join-Path $AppDir 'honeypot.py'
$SrcDir   = Split-Path -Parent $PSScriptRoot
$TaskName = 'Honeypot'

Write-Host "==> Installing application to $AppDir"
New-Item -ItemType Directory -Force -Path $AppDir, $LogDir, $StateDir, $DecoyDir | Out-Null
# ProgramData lets ordinary users read files and add new ones to subfolders. Logs
# hold captured credentials, and a planted module would run as the service account.
# Well-known SIDs: SYSTEM, Administrators, LOCAL SERVICE.
& icacls.exe $AppDir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-19:(OI)(CI)RX' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Could not restrict permissions on $AppDir" }
foreach ($f in 'honeypot.py', 'honeytokens.py', 'tokens.py', 'alerts.py', 'protocols.py') {
    Copy-Item (Join-Path $SrcDir $f) (Join-Path $AppDir $f) -Force
}

Write-Host "==> Writing config to $CfgPath"
if (Test-Path $CfgPath) {
    Write-Host '    config.json already exists, leaving it untouched'
} else {
    $cfg = Get-Content (Join-Path $SrcDir 'config.example.json') -Raw
    # Point the log and state dirs at ProgramData (JSON needs doubled backslashes).
    $cfg = $cfg -replace '"log_dir": null',   ('"log_dir": "'   + ($LogDir   -replace '\\','\\') + '"')
    $cfg = $cfg -replace '"state_dir": null', ('"state_dir": "' + ($StateDir -replace '\\','\\') + '"')
    Set-Content -Path $CfgPath -Value $cfg -Encoding UTF8
}

$python = Find-Python
Write-Host "==> Using Python at $python"

Write-Host '==> Installing paramiko for SSH credential capture'
$pip = Join-Path (Split-Path $python) 'python.exe'      # pythonw.exe has no console output
if (-not (Test-Path $pip)) { $pip = $python }
& $pip -m pip install --quiet --upgrade --target (Join-Path $AppDir 'lib') -r (Join-Path $SrcDir 'requirements.txt')
if ($LASTEXITCODE -ne 0) { Write-Warning 'paramiko not installed; real SSH clients will only be fingerprinted.' }

Write-Host "==> Registering the '$TaskName' scheduled task (starts at boot, runs as LOCAL SERVICE)"
$action    = New-ScheduledTaskAction -Execute $python -Argument """$Script"" -c ""$CfgPath""" -WorkingDirectory $AppDir
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'LOCAL SERVICE' -LogonType ServiceAccount -RunLevel Limited
$settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                -StartWhenAvailable -RestartInterval (New-TimeSpan -Minutes 1) -RestartCount 3 `
                -ExecutionTimeLimit ([TimeSpan]::Zero)

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null

# Let LOCAL SERVICE write to the log and state directories.
foreach ($dir in @($LogDir, $StateDir)) {
    $acl  = Get-Acl $dir
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        'LOCAL SERVICE', 'Modify', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
    Set-Acl -Path $dir -AclObject $acl
}

if ($OpenFirewall) {
    foreach ($p in $Ports) {
        $ruleName = "Honeypot TCP $p"
        if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Action Allow `
                -Protocol TCP -LocalPort $p | Out-Null
            Write-Host "    opened inbound TCP $p"
        }
    }
}

Write-Host "==> Starting the honeypot now"
Start-ScheduledTask -TaskName $TaskName

Write-Host ''
Write-Host 'Done. The honeypot runs at startup under the low-privilege LOCAL SERVICE account.'
Write-Host "  Logs:    $LogDir\honeypot.log"
Write-Host "  Config:  $CfgPath   (edit, then re-run the task or reboot)"
Write-Host "  Status:  Get-ScheduledTask -TaskName $TaskName | Get-ScheduledTaskInfo"
Write-Host "  Stop:    Stop-ScheduledTask -TaskName $TaskName"
Write-Host "  Remove:  powershell -ExecutionPolicy Bypass -File windows\uninstall.ps1"
Write-Host ''
Write-Host 'Default ports: 2222 (ssh), 2323 (telnet), 8080 (http).'
if (-not $OpenFirewall) {
    Write-Host 'Firewall was NOT changed. Re-run with -OpenFirewall to allow remote hosts in.'
}
Write-Host ''
Write-Host 'Plant honeytokens:'
Write-Host "  python `"$AppDir\honeytokens.py`" -c `"$CfgPath`" new web --label 'canary in budget.xlsx' --base-url http://YOUR-HONEYPOT:8080"
Write-Host "  python `"$AppDir\honeytokens.py`" -c `"$CfgPath`" list"
Write-Host 'New tokens are picked up automatically; no restart needed.'
