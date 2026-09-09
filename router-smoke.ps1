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

  Optional local .env (gitignored): BTKN_ROUTER, BTKN_SSH_USER, BTKN_SSH_PASSWORD,
  BTKN_SSH_PORT, BTKN_SSH_IDENTITY. Password auth uses SSH_ASKPASS; the secret
  is not placed on the ssh/scp command line.
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

function Import-DotEnv {
    $path = Join-Path $PSScriptRoot '.env'
    if (-not (Test-Path -LiteralPath $path)) {
        return
    }
    Get-Content -LiteralPath $path | ForEach-Object {
        $line = $_.Trim()
        if ($line -eq '' -or $line.StartsWith('#')) {
            return
        }
        $eq = $line.IndexOf('=')
        if ($eq -lt 1) {
            return
        }
        $name = $line.Substring(0, $eq).Trim()
        $value = $line.Substring($eq + 1).Trim()
        if ($value.Length -ge 2) {
            $q = $value[0]
            if (($q -eq [char]'"' -or $q -eq [char]"'") -and $value[-1] -eq $q) {
                $value = $value.Substring(1, $value.Length - 2)
            }
        }
        if ($name) {
            Set-Item -Path ("Env:" + $name) -Value $value
        }
    }
}

Import-DotEnv
if (-not $RouterAddress -and $env:BTKN_ROUTER) {
    $RouterAddress = $env:BTKN_ROUTER
}
if ($env:BTKN_SSH_USER) {
    $SshUser = $env:BTKN_SSH_USER
}
if (-not $IdentityFile -and $env:BTKN_SSH_IDENTITY) {
    $IdentityFile = $env:BTKN_SSH_IDENTITY
}

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
if (-not $sshExe) {
    Write-ProbeNotRun -Reason 'ssh.exe not found (Windows OpenSSH required)'
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
$usePassword = -not [string]::IsNullOrEmpty($env:BTKN_SSH_PASSWORD)

$probeLocal = Join-Path $PSScriptRoot 'scripts\router-probe.sh'
if (-not (Test-Path -LiteralPath $probeLocal)) {
    Write-Host "ERROR: missing $probeLocal"
    exit 1
}

$sshArgs = @(
    '-o', 'ConnectTimeout=15',
    '-o', 'StrictHostKeyChecking=accept-new'
)
if ($usePassword) {
    $askPass = Join-Path $env:TEMP 'btkn-ssh-askpass.cmd'
    $askBody = "@echo off`r`necho(%BTKN_SSH_PASSWORD%"
    [System.IO.File]::WriteAllText($askPass, $askBody)
    $env:SSH_ASKPASS = $askPass
    $env:SSH_ASKPASS_REQUIRE = 'force'
    $env:DISPLAY = 'localhost:0'
    $sshArgs += @(
        '-o', 'BatchMode=no',
        '-o', 'PreferredAuthentications=password,keyboard-interactive',
        '-o', 'PubkeyAuthentication=no',
        '-o', 'PasswordAuthentication=yes',
        '-o', 'KbdInteractiveAuthentication=yes',
        '-o', 'NumberOfPasswordPrompts=1'
    )
    Write-Host 'auth=password (SSH_ASKPASS; secret not on argv)'
} else {
    $sshArgs += @('-o', 'BatchMode=yes')
    Write-Host 'auth=key/agent (BatchMode)'
}
if ($idPath) {
    $sshArgs += @('-i', $idPath, '-o', 'IdentitiesOnly=yes')
}
$sshArgs += @('-p', [string]$port)

$remoteScript = '/tmp/btkn-router-probe.sh'

$lfPath = Join-Path $env:TEMP 'btkn-router-probe.sh'
$probeText = [System.IO.File]::ReadAllText($probeLocal).Replace("`r`n", "`n").Replace("`r", "`n")
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText($lfPath, $probeText, $utf8NoBom)

function Format-NativeArgs {
    param([string[]]$Parts)
    return (($Parts | ForEach-Object {
        if ($_ -match '[\s"]') {
            '"' + ($_ -replace '"', '\"') + '"'
        } else {
            $_
        }
    }) -join ' ')
}

function Copy-ProbeViaSshCat {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $sshExe
    $psi.Arguments = Format-NativeArgs ($sshArgs + @('-l', $SshUser, $RouterAddress, "cat > $remoteScript"))
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    $proc = New-Object System.Diagnostics.Process
    $proc.StartInfo = $psi
    [void]$proc.Start()
    $inBytes = [System.IO.File]::ReadAllBytes($lfPath)
    $proc.StandardInput.BaseStream.Write($inBytes, 0, $inBytes.Length)
    $proc.StandardInput.Close()
    if (-not $proc.WaitForExit(60000)) {
        $proc.Kill()
        return 124
    }
    $script:SshCopyStderr = $proc.StandardError.ReadToEnd()
    return $proc.ExitCode
}

Write-Host 'copying read-only probe via ssh cat (no SFTP)'
$copyCode = Copy-ProbeViaSshCat
if ($copyCode -ne 0) {
    if ($script:SshCopyStderr) {
        Write-Host ($script:SshCopyStderr.Trim())
    }
    if (-not $idPath -and -not $usePassword) {
        Write-Host 'SSH_KEY_REQUIRED'
        Write-ProbeNotRun -Reason 'ssh copy failed without IdentityFile/BTKN_SSH_IDENTITY/SSH agent and without BTKN_SSH_PASSWORD'
        exit 0
    }
    Write-ProbeNotRun -Reason "ssh cat copy failed (exit $copyCode); connection or credentials"
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
