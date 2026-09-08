#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$RouterAddress,
    [string]$SshUser = "root",
    [string]$CredentialSource = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "router-smoke.ps1: KN-1011 hardware gate"
Write-Host "router=$RouterAddress user=$SshUser"
if (-not $CredentialSource) {
    Write-Host "NOT RUN: CredentialSource is required and must not be a committed secret."
    exit 2
}

Write-Host "Hardware checks are not implemented this wave (R0/R2/R3 bootstrap)."
exit 2
