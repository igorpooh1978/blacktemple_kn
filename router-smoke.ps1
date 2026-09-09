#requires -Version 5.1
<#!
.SYNOPSIS
  KN-1011 hardware gate and read-only capability probe (Windows OpenSSH).

.PARAMETER Mode
  Smoke (default, unimplemented hardware gate) or Probe (read-only capability dump).

.PARAMETER RouterAddress
  Router host or LAN address. Alias: -Router. Env: BTKN_ROUTER.

.PARAMETER SshUser
  SSH user. Alias: -User. Default root. Env: BTKN_SSH_USER.

.PARAMETER CredentialSource
  Path to an IdentityFile for Smoke/Probe. Never a committed secret.

.PARAMETER IdentityFile
  SSH private key path. Env: BTKN_SSH_IDENTITY.
#>
[CmdletBinding()]
param(
    [ValidateSet('Smoke', 'Probe')]
    [string]$Mode = 'Smoke',

    [Parameter()]
    [Alias('Router')]
    [string]$RouterAddress = $(if ($env:BTKN_ROUTER) { $env:BTKN_ROUTER } else { '' }),

    [Alias('User')]
    [string]$SshUser = $(if ($env:BTKN_SSH_USER) { $env:BTKN_SSH_USER } else { 'root' }),

    [string]$CredentialSource = '',

    [string]$IdentityFile = $(if ($env:BTKN_SSH_IDENTITY) { $env:BTKN_SSH_IDENTITY } else { '' })
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-OpenSshTool {
    param([Parameter(Mandatory = $true)][string]$Name)
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -ne $cmd -and $cmd.Source) {
        return [string]$cmd.Source
    }
    $fallback = Join-Path $env:WINDIR "System32\OpenSSH\$Name"
    if (Test-Path -LiteralPath $fallback) {
        return $fallback
    }
    return $null
}

function Write-ProbeNotRun {
    param([string]$Reason)
    Write-Host 'REAL KN-1011 PROBE: NOT RUN'
    Write-Host "reason: $Reason"
}

function Resolve-IdentityPath {
    if ($IdentityFile) {
        return $IdentityFile
    }
    if ($CredentialSource -and (Test-Path -LiteralPath $CredentialSource)) {
        return $CredentialSource
    }
    return ''
}

Write-Host "router-smoke.ps1: KN-1011 hardware gate mode=$Mode"

if ($Mode -eq 'Smoke') {
    Write-Host "router=$RouterAddress user=$SshUser"
    if (-not $RouterAddress) {
        Write-Host 'NOT RUN: RouterAddress is required.'
        exit 2
    }
    if (-not $CredentialSource) {
        Write-Host 'NOT RUN: CredentialSource is required and must not be a committed secret.'
        exit 2
    }
    Write-Host 'Hardware checks are not implemented this wave (R0/R2/R3 bootstrap).'
    exit 2
}

# Mode Probe
$sshExe = Get-OpenSshTool -Name 'ssh.exe'
$scpExe = Get-OpenSshTool -Name 'scp.exe'
if (-not $sshExe -or -not $scpExe) {
    Write-ProbeNotRun -Reason 'ssh.exe/scp.exe not found (Windows OpenSSH required)'
    exit 0
}

if (-not $RouterAddress) {
    Write-ProbeNotRun -Reason 'no router address (pass -Router or set BTKN_ROUTER)'
    exit 0
}

Write-Host "router=$RouterAddress user=$SshUser"
$idPath = Resolve-IdentityPath
$port = 22
if ($env:BTKN_SSH_PORT) {
    $port = [int]$env:BTKN_SSH_PORT
}

$probeLocal = Join-Path $PSScriptRoot 'scripts\router-probe.sh'
if (-not (Test-Path -LiteralPath $probeLocal)) {
    Write-Host "ERROR: missing $probeLocal"
    exit 1
}

$sshArgs = @(
    '-o', 'BatchMode=yes',
    '-o', 'ConnectTimeout=15',
    '-o', 'StrictHostKeyChecking=accept-new'
)
if ($idPath) {
    $sshArgs += @('-i', $idPath, '-o', 'IdentitiesOnly=yes')
}
$scpArgs = @($sshArgs)
$sshArgs += @('-p', [string]$port)
$scpArgs += @('-P', [string]$port)

$remoteScript = '/tmp/btkn-router-probe.sh'
$remoteTarget = "${SshUser}@${RouterAddress}:${remoteScript}"

$lfPath = Join-Path $env:TEMP 'btkn-router-probe.sh'
$probeText = [System.IO.File]::ReadAllText($probeLocal).Replace("`r`n", "`n").Replace("`r", "`n")
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText($lfPath, $probeText, $utf8NoBom)

Write-Host 'copying read-only probe via scp.exe'
$scpAll = $scpArgs + @($lfPath, $remoteTarget)
& $scpExe @scpAll
if ($LASTEXITCODE -ne 0) {
    if (-not $idPath) {
        Write-Host 'SSH_KEY_REQUIRED'
        Write-ProbeNotRun -Reason 'scp failed without IdentityFile/BTKN_SSH_IDENTITY/SSH agent; password SSH is not automated'
        exit 0
    }
    Write-ProbeNotRun -Reason "scp failed (exit $LASTEXITCODE); connection or credentials"
    exit 0
}

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$traceDir = Join-Path $PSScriptRoot '.research-local\hardware'
New-Item -ItemType Directory -Force -Path $traceDir | Out-Null
$rawPath = Join-Path $traceDir "kn1011-probe-$stamp.txt"

$sshRun = $sshArgs + @('-l', $SshUser, $RouterAddress, "sh $remoteScript")
$ErrorActionPreference = 'Continue'
$probeOut = & $sshExe @sshRun 2>&1
$code = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
$lines = @()
if ($null -ne $probeOut) {
    $lines = @($probeOut | ForEach-Object { [string]$_ })
}
[System.IO.File]::WriteAllLines($rawPath, $lines, $utf8NoBom)

if ($code -ne 0) {
    Write-ProbeNotRun -Reason "ssh probe failed (exit $code); connection or remote shell"
    Write-Host "RAW TRACE: $rawPath"
    exit 0
}

Write-Host 'REAL KN-1011 PROBE: RUN'
Write-Host "RAW TRACE: $rawPath (gitignored)"
exit 0
