#requires -Version 5.1
<#!
.SYNOPSIS
  KN-1011 hardware gate: read-only probe and gated mutating routing smoke (Windows OpenSSH).

.PARAMETER Mode
  Smoke (default): live IPv4 hybrid routing smoke. Requires BOTH
  BTKN_ALLOW_ROUTING_MUTATION=1 and BTKN_ALLOW_XKEEN_STOP=1, otherwise prints
  LIVE ROUTING SMOKE: NOT RUN and exits 0.
  Probe: read-only capability dump (never mutates).

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
  is not placed on the ssh/scp command line and is never printed.

  .env search: worktree .env, parent directories, then sibling main repo
  blacktemple_kn/.env (worktree layout). .env is never committed.
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

function Import-DotEnvFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    Get-Content -LiteralPath $Path | ForEach-Object {
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

function Import-DotEnv {
    $candidates = New-Object System.Collections.Generic.List[string]
    $dir = $PSScriptRoot
    for ($i = 0; $i -lt 5; $i++) {
        [void]$candidates.Add((Join-Path $dir '.env'))
        $parent = Split-Path -Parent $dir
        if (-not $parent -or $parent -eq $dir) {
            break
        }
        $dir = $parent
    }
    $wtParent = Split-Path -Parent $PSScriptRoot
    if ($wtParent -and ($wtParent -like '*-wt')) {
        $projects = Split-Path -Parent $wtParent
        if ($projects) {
            [void]$candidates.Add((Join-Path $projects 'blacktemple_kn\.env'))
        }
    }
    foreach ($path in $candidates) {
        if (Test-Path -LiteralPath $path) {
            Import-DotEnvFile -Path $path
            return
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

function Write-LiveSmokeNotRun {
    param([string]$Reason)
    Write-Host 'LIVE ROUTING SMOKE: NOT RUN'
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

function Initialize-SshSession {
    $script:SshExe = Get-OpenSshTool -Name 'ssh.exe'
    if (-not $script:SshExe) {
        return 'ssh.exe not found (Windows OpenSSH required)'
    }
    if (-not $RouterAddress) {
        return 'no router address (pass -Router or set BTKN_ROUTER)'
    }
    $script:SshUserName = $SshUser
    $script:SshIdPath = Resolve-IdentityPath
    $script:SshPort = 22
    if ($env:BTKN_SSH_PORT) {
        $script:SshPort = [int]$env:BTKN_SSH_PORT
    }
    $script:SshUsePassword = -not [string]::IsNullOrEmpty($env:BTKN_SSH_PASSWORD)
    $script:SshArgs = @(
        '-o', 'ConnectTimeout=15',
        '-o', 'StrictHostKeyChecking=accept-new'
    )
    if ($script:SshUsePassword) {
        $askPass = Join-Path $env:TEMP 'btkn-ssh-askpass.cmd'
        $askBody = "@echo off`r`necho(%BTKN_SSH_PASSWORD%"
        [System.IO.File]::WriteAllText($askPass, $askBody)
        $env:SSH_ASKPASS = $askPass
        $env:SSH_ASKPASS_REQUIRE = 'force'
        $env:DISPLAY = 'localhost:0'
        $script:SshArgs += @(
            '-o', 'BatchMode=no',
            '-o', 'PreferredAuthentications=password,keyboard-interactive',
            '-o', 'PubkeyAuthentication=no',
            '-o', 'PasswordAuthentication=yes',
            '-o', 'KbdInteractiveAuthentication=yes',
            '-o', 'NumberOfPasswordPrompts=1'
        )
        Write-Host 'auth=password (SSH_ASKPASS; secret not on argv)'
    } else {
        $script:SshArgs += @('-o', 'BatchMode=yes')
        Write-Host 'auth=key/agent (BatchMode)'
    }
    if ($script:SshIdPath) {
        $script:SshArgs += @('-i', $script:SshIdPath, '-o', 'IdentitiesOnly=yes')
    }
    $script:SshArgs += @('-p', [string]$script:SshPort)
    return ''
}

function Copy-ScriptViaSshCat {
    param(
        [Parameter(Mandatory = $true)][string]$LocalPath,
        [Parameter(Mandatory = $true)][string]$RemotePath
    )
    $lfPath = Join-Path $env:TEMP ('btkn-upload-' + [IO.Path]::GetFileName($RemotePath))
    $probeText = [System.IO.File]::ReadAllText($LocalPath).Replace("`r`n", "`n").Replace("`r", "`n")
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    [System.IO.File]::WriteAllText($lfPath, $probeText, $utf8NoBom)
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $script:SshExe
    $psi.Arguments = Format-NativeArgs ($script:SshArgs + @('-l', $script:SshUserName, $RouterAddress, "cat > $RemotePath"))
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

function Invoke-RemoteSh {
    param(
        [Parameter(Mandatory = $true)][string]$RemoteCommand,
        [int]$TimeoutMs = 120000
    )
    $sshRun = $script:SshArgs + @('-l', $script:SshUserName, $RouterAddress, $RemoteCommand)
    $ErrorActionPreference = 'Continue'
    $out = & $script:SshExe @sshRun 2>&1
    $code = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    $lines = @()
    if ($null -ne $out) {
        $lines = @($out | ForEach-Object { [string]$_ })
    }
    return [pscustomobject]@{
        ExitCode = $code
        Lines    = $lines
    }
}

function Invoke-GatedRemote {
    param([Parameter(Mandatory = $true)][string]$Subcommand)
    $remote = "/tmp/btkn-router-smoke-routing.sh"
    $cmd = "BTKN_ALLOW_ROUTING_MUTATION=1 BTKN_ALLOW_XKEEN_STOP=1 sh $remote $Subcommand"
    Write-Host "remote: $Subcommand"
    $result = Invoke-RemoteSh -RemoteCommand $cmd
    foreach ($line in @($result.Lines)) {
        Write-Host $line
    }
    return $result
}

function Invoke-LiveRoutingSmoke {
    Write-Host "router=$RouterAddress user=$SshUser"
    $sshErr = Initialize-SshSession
    if ($sshErr) {
        Write-LiveSmokeNotRun -Reason $sshErr
        exit 0
    }

    $localSh = Join-Path $PSScriptRoot 'scripts\router-smoke-routing.sh'
    if (-not (Test-Path -LiteralPath $localSh)) {
        Write-Host "ERROR: missing $localSh"
        exit 1
    }

    Write-Host 'copying gated routing smoke via ssh cat (no SFTP)'
    $copyCode = Copy-ScriptViaSshCat -LocalPath $localSh -RemotePath '/tmp/btkn-router-smoke-routing.sh'
    if ($copyCode -ne 0) {
        if ($script:SshCopyStderr) {
            Write-Host ($script:SshCopyStderr.Trim())
        }
        Write-LiveSmokeNotRun -Reason "ssh cat copy failed (exit $copyCode); connection or credentials"
        exit 0
    }

    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $traceDir = Join-Path $PSScriptRoot '.research-local\hardware'
    New-Item -ItemType Directory -Force -Path $traceDir | Out-Null
    $rawPath = Join-Path $traceDir "kn1011-smoke-$stamp.txt"
    $utf8NoBom = New-Object System.Text.UTF8Encoding $false
    $log = New-Object System.Collections.Generic.List[string]

    Write-Host 'XKeen restore runs in finally (BTKN cleanup, stop test BlackTemple, restore XKeen, verify Xray and xkeen chains)'
    $snapOk = $false
    try {
        $snap = Invoke-GatedRemote -Subcommand 'snapshot'
        foreach ($line in @($snap.Lines)) { [void]$log.Add($line) }
        if ($snap.ExitCode -ne 0) {
            throw "snapshot failed (exit $($snap.ExitCode))"
        }
        $snapOk = $true
        $apply = Invoke-GatedRemote -Subcommand 'apply'
        foreach ($line in @($apply.Lines)) { [void]$log.Add($line) }
        $verify = Invoke-GatedRemote -Subcommand 'verify'
        foreach ($line in @($verify.Lines)) { [void]$log.Add($line) }
        Write-Host 'LIVE ROUTING SMOKE: RUN (harness; not a TPROXY SUPPORTED claim)'
    } finally {
        Write-Host 'finally: remove BTKN, stop test BlackTemple, restore XKeen, verify'
        try {
            $cleanup = Invoke-GatedRemote -Subcommand 'cleanup-btkn'
            foreach ($line in @($cleanup.Lines)) { [void]$log.Add($line) }
            $stopBt = Invoke-GatedRemote -Subcommand 'stop-blacktemple'
            foreach ($line in @($stopBt.Lines)) { [void]$log.Add($line) }
            if ($snapOk) {
                $restore = Invoke-GatedRemote -Subcommand 'restore-xkeen'
                foreach ($line in @($restore.Lines)) { [void]$log.Add($line) }
            } else {
                Write-Host 'finally: skip XKeen restore (snapshot did not complete)'
            }
            $after = Invoke-GatedRemote -Subcommand 'verify'
            foreach ($line in @($after.Lines)) { [void]$log.Add($line) }
        } catch {
            Write-Host "finally restore error: $($_.Exception.Message)"
        }
        [System.IO.File]::WriteAllLines($rawPath, @($log), $utf8NoBom)
        Write-Host "RAW TRACE: $rawPath (gitignored)"
    }
}

Write-Host "router-smoke.ps1: KN-1011 hardware gate mode=$Mode"

if ($Mode -eq 'Smoke') {
    $allowMut = $env:BTKN_ALLOW_ROUTING_MUTATION
    $allowStop = $env:BTKN_ALLOW_XKEEN_STOP
    if ($allowMut -ne '1' -or $allowStop -ne '1') {
        Write-LiveSmokeNotRun -Reason 'requires BTKN_ALLOW_ROUTING_MUTATION=1 and BTKN_ALLOW_XKEEN_STOP=1'
        Write-Host 'Production daemon never stops XKeen. This harness is gated and was not executed.'
        exit 0
    }
    Invoke-LiveRoutingSmoke
    exit 0
}

# Mode Probe
$sshErr = Initialize-SshSession
if ($sshErr) {
    Write-ProbeNotRun -Reason $sshErr
    exit 0
}

Write-Host "router=$RouterAddress user=$SshUser"

$probeLocal = Join-Path $PSScriptRoot 'scripts\router-probe.sh'
if (-not (Test-Path -LiteralPath $probeLocal)) {
    Write-Host "ERROR: missing $probeLocal"
    exit 1
}

$remoteScript = '/tmp/btkn-router-probe.sh'
Write-Host 'copying read-only probe via ssh cat (no SFTP)'
$copyCode = Copy-ScriptViaSshCat -LocalPath $probeLocal -RemotePath $remoteScript
if ($copyCode -ne 0) {
    if ($script:SshCopyStderr) {
        Write-Host ($script:SshCopyStderr.Trim())
    }
    $idPath = Resolve-IdentityPath
    $usePassword = -not [string]::IsNullOrEmpty($env:BTKN_SSH_PASSWORD)
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
$utf8NoBom = New-Object System.Text.UTF8Encoding $false

$run = Invoke-RemoteSh -RemoteCommand "sh $remoteScript"
$probeLines = @($run.Lines)
[System.IO.File]::WriteAllLines($rawPath, $probeLines, $utf8NoBom)
foreach ($line in $probeLines) {
    Write-Host $line
}

if ($run.ExitCode -ne 0) {
    Write-ProbeNotRun -Reason "ssh probe failed (exit $($run.ExitCode)); connection or remote shell"
    Write-Host "RAW TRACE: $rawPath"
    exit 0
}

Write-Host 'REAL KN-1011 PROBE: RUN'
Write-Host "RAW TRACE: $rawPath (gitignored)"
exit 0
