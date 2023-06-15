#Requires -Version 5.1
<#
.SYNOPSIS
    Remove the honeypot scheduled task and firewall rules from Windows.
.DESCRIPTION
    Run from an elevated PowerShell (Run as Administrator):
        powershell -ExecutionPolicy Bypass -File windows\uninstall.ps1
    Captured logs under C:\ProgramData\Honeypot\logs are left in place (evidence).
#>
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Please run from an elevated PowerShell (Run as Administrator).'
}

$AppDir = Join-Path $env:ProgramData 'Honeypot'

Stop-ScheduledTask -TaskName 'Honeypot' -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'Honeypot' -Confirm:$false -ErrorAction SilentlyContinue
Write-Host 'Removed the scheduled task.'

Get-NetFirewallRule -DisplayName 'Honeypot TCP *' -ErrorAction SilentlyContinue |
    Remove-NetFirewallRule -ErrorAction SilentlyContinue
Write-Host 'Removed Honeypot firewall rules (if any).'

foreach ($f in 'honeypot.py', 'honeytokens.py', 'tokens.py', 'alerts.py') {
    Remove-Item -Path (Join-Path $AppDir $f) -Force -ErrorAction SilentlyContinue
}
Write-Host "Left in place: $AppDir\config.json, $AppDir\logs,"
Write-Host "               $AppDir\state (honeytokens + decoy files)."
Write-Host "Delete them manually if you want: Remove-Item -Recurse -Force '$AppDir'"
