#requires -Version 5.1
<#!
.SYNOPSIS
  QEMU Malta MIPSLE integration lab (not KN-1011, not MT7621).

.PARAMETER Action
  test     - unit tests that do not need qemu-system-mipsel
  prepare  - download/verify pinned image and build overlay
  smoke    - unit tests + live boot/SSH smoke when QEMU is installed
  all      - same as smoke (default)

Live QEMU is experimental. Missing QEMU is QEMU_NOT_INSTALLED, not a fake PASS.
#>
[CmdletBinding()]
param(
    [ValidateSet("test", "prepare", "smoke", "all")]
    [string]$Action = "all",
    [switch]$AllowHostLAN,
    [string]$Daemon = "",
    [string]$Xray = "",
    [string]$Config = "",
    [string]$Geodata = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
Set-Location $Root
$env:CGO_ENABLED = "0"

function Write-QemuMissing {
    Write-Host "QEMU_NOT_INSTALLED"
    Write-Host "QEMU is not installed. This lab does not install QEMU automatically."
    Write-Host "Windows (official): https://www.qemu.org/download/#windows"
    Write-Host "Windows installer: https://qemu.weilnetz.de/w64/"
    Write-Host "Windows winget (verified microsoft/winget-pkgs): winget install --id SoftwareFreedomConservancy.QEMU"
    Write-Host "Need qemu-system-mipsel. QEMU Malta is not an MT7621 emulator and is not KN-1011."
}

function Invoke-LabTests {
    Write-Host "==> lab unit tests (no live QEMU)"
    go test ./lab/...
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        throw "go test ./lab/... failed with exit $LASTEXITCODE"
    }
}

function Find-QemuMipsel {
    if ($env:QEMU_SYSTEM_MIPSEL -and (Test-Path -LiteralPath $env:QEMU_SYSTEM_MIPSEL)) {
        return $env:QEMU_SYSTEM_MIPSEL
    }
    foreach ($name in @("qemu-system-mipsel.exe", "qemu-system-mipsel")) {
        $cmd = Get-Command $name -ErrorAction SilentlyContinue
        if ($cmd) { return $cmd.Source }
    }
    $qemuDirs = @()
    if ($env:ProgramFiles) {
        $qemuDirs += (Join-Path $env:ProgramFiles "qemu")
    }
    $programFilesX86 = ${env:ProgramFiles(x86)}
    if ($programFilesX86) {
        $qemuDirs += (Join-Path $programFilesX86 "qemu")
    }
    foreach ($dir in $qemuDirs) {
        $p = Join-Path $dir "qemu-system-mipsel.exe"
        if (Test-Path -LiteralPath $p) { return $p }
    }
    return $null
}

function Invoke-Qemulab([string]$LabAction) {
    $goArgs = @(
        "run",
        "./lab/cmd/qemulab",
        "-action", $LabAction,
        "-root", $Root
    )
    if ($AllowHostLAN) { $goArgs += @("-allow-host-lan") }
    if ($Daemon) { $goArgs += @("-daemon", $Daemon) }
    if ($Xray) { $goArgs += @("-xray", $Xray) }
    if ($Config) { $goArgs += @("-config", $Config) }
    if ($Geodata) { $goArgs += @("-geodata", $Geodata) }
    & go @goArgs
    return $LASTEXITCODE
}

switch ($Action) {
    "test" {
        Invoke-LabTests
        exit 0
    }
    "prepare" {
        $qemu = Find-QemuMipsel
        if (-not $qemu) {
            Write-QemuMissing
            exit 3
        }
        $code = Invoke-Qemulab "prepare"
        exit $code
    }
    default {
        Invoke-LabTests
        $qemu = Find-QemuMipsel
        if (-not $qemu) {
            Write-QemuMissing
            Write-Host "QEMU: NOT RUN / QEMU_NOT_INSTALLED"
            Write-Host "IMAGE: 24.10.8 openwrt-24.10.8-malta-le-vmlinux-initramfs.elf"
            Write-Host "MIPSLE EXECUTION: NOT RUN"
            Write-Host "BLACKTEMPLED: NOT RUN"
            Write-Host "XRAY: NOT RUN"
            Write-Host "NETWORK: NOT RUN"
            Write-Host "ENTWARE EQUIVALENCE: NOT CLAIMED"
            exit 3
        }
        $code = Invoke-Qemulab "smoke"
        exit $code
    }
}
