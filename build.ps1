#requires -Version 5.1
<#!
.SYNOPSIS
  Windows build pipeline for BlackTemple KN (multi-MIPS Entware IPK).

.PARAMETER Target
  kn-mipsel (default, P0): linux/mipsle softfloat, IPK Architecture mipsel-3.4_kn
  entware-mipsel (P1): linux/mipsle softfloat, IPK Architecture mipsel-3.4
  entware-mips (P1): linux/mips GOMIPS=softfloat, IPK Architecture mips-3.4
  all-mips: all three

.PARAMETER SkipFrontend
  Skip npm install/test/build/size-gate. Uses existing embedded UI assets.

.PARAMETER IncludeXray
  Fetch the pinned Xray zip from third_party/xray.lock.json, verify SHA256,
  extract only binaryInZip (xray_softfloat), ELF-check it, and install as
  /opt/blacktemple-kn/bin/xray in the IPK. Default: off (hello-only IPK).

.PARAMETER Offline
  Do not download. With -IncludeXray, fail if .cache/xray/<sha256>.zip is missing.

Config preservation: packaging/control/conffiles lists
/opt/blacktemple-kn/config/config.json so opkg does not overwrite a user-modified
file on upgrade once that file exists. Hello-service does not ship a default
config body yet. Xray is never installed to /opt/bin/xray (xkeen coexistence).
#>
[CmdletBinding()]
param(
    [ValidateSet("kn-mipsel", "entware-mipsel", "entware-mips", "all-mips")]
    [string]$Target = "kn-mipsel",
    [switch]$SkipFrontend,
    [switch]$IncludeXray,
    [switch]$Offline,
    [string]$Version = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
Set-Location $Root

if (-not $Version) {
    $Version = (Get-Content -Raw "$Root\VERSION").Trim()
}

$Out = Join-Path $Root "out"
New-Item -ItemType Directory -Force -Path $Out | Out-Null

$env:CGO_ENABLED = "0"
$env:GOFLAGS = "-trimpath"

function Invoke-Checked([string]$Label, [scriptblock]$Block) {
    Write-Host "==> $Label"
    & $Block
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        throw "$Label failed with exit $LASTEXITCODE"
    }
}

function Write-UnixText([string]$Path, [string]$Text) {
    $utf8 = New-Object System.Text.UTF8Encoding $false
    $normalized = $Text -replace "`r`n", "`n" -replace "`r", "`n"
    if (-not $normalized.EndsWith("`n")) {
        $normalized += "`n"
    }
    [System.IO.File]::WriteAllText($Path, $normalized, $utf8)
}

function Get-HostGoArch {
    $a = go env GOHOSTARCH
    if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
        throw "go env GOHOSTARCH failed"
    }
    return ([string]$a).Trim()
}

function Restore-HostGoEnv {
    $env:GOOS = "windows"
    $env:GOARCH = Get-HostGoArch
    if (Test-Path Env:GOMIPS) {
        Remove-Item Env:GOMIPS
    }
}

$script:TargetMap = @{
    "kn-mipsel" = @{
        GoArch         = "mipsle"
        ElfEndian      = "le"
        IpkArch        = "mipsel-3.4_kn"
        XrayLockTarget = "linux-mipsle-softfloat"
    }
    "entware-mipsel" = @{
        GoArch         = "mipsle"
        ElfEndian      = "le"
        IpkArch        = "mipsel-3.4"
        XrayLockTarget = "linux-mipsle-softfloat"
    }
    "entware-mips" = @{
        GoArch         = "mips"
        ElfEndian      = "be"
        IpkArch        = "mips-3.4"
        XrayLockTarget = "linux-mips-softfloat"
    }
}

if (-not $SkipFrontend) {
    Invoke-Checked "frontend install" {
        Push-Location "$Root\web"
        if (Test-Path package-lock.json) { npm ci } else { npm install }
        Pop-Location
    }
    Invoke-Checked "frontend test" {
        Push-Location "$Root\web"
        npm test
        Pop-Location
    }
    Invoke-Checked "frontend build" {
        Push-Location "$Root\web"
        npm run build
        Pop-Location
    }
    Invoke-Checked "frontend size gate" {
        Push-Location "$Root\web"
        npm run size
        Pop-Location
    }
    $assets = Join-Path $Root "src\cmd\blacktempled\assets"
    Get-ChildItem $assets -Force | Where-Object { $_.Name -ne ".gitkeep" } | Remove-Item -Recurse -Force
    Copy-Item -Recurse -Force "$Root\web\dist\*" $assets
}

Invoke-Checked "go fmt" { gofmt -w src tools }
$fmtNeeded = gofmt -l src tools
if ($fmtNeeded) {
    throw "gofmt would still change:`n$fmtNeeded"
}

Invoke-Checked "go vet" { go vet ./src/... ./tools/... }
Invoke-Checked "go test" { go test ./src/... ./tools/... }

$binDir = Join-Path $Out "bin"
New-Item -ItemType Directory -Force -Path $binDir | Out-Null
Restore-HostGoEnv

$elfcheck = Join-Path $binDir "elfcheck.exe"
$ipkpack = Join-Path $binDir "ipkpack.exe"
$xrayfetch = Join-Path $binDir "xrayfetch.exe"
Write-Host "==> build host tools"
go build -o $elfcheck ./tools/elfcheck
if ($LASTEXITCODE -ne 0) { throw "go build elfcheck failed" }
go build -o $ipkpack ./tools/ipkpack
if ($LASTEXITCODE -ne 0) { throw "go build ipkpack failed" }
go build -o $xrayfetch ./tools/xrayfetch
if ($LASTEXITCODE -ne 0) { throw "go build xrayfetch failed" }

$targetNames = @($Target)
if ($Target -eq "all-mips") {
    $targetNames = @("kn-mipsel", "entware-mipsel", "entware-mips")
}

$daemonByArch = @{}
$reportLines = New-Object System.Collections.Generic.List[string]
$checksumLines = New-Object System.Collections.Generic.List[string]
$reportLines.Add("version=$Version") | Out-Null
$reportLines.Add("cgo=0") | Out-Null
$reportLines.Add("include_xray=$([bool]$IncludeXray)") | Out-Null
$reportLines.Add("offline=$([bool]$Offline)") | Out-Null

foreach ($name in $targetNames) {
    $def = $script:TargetMap[$name]
    $goArch = [string]$def.GoArch
    $elfEndian = [string]$def.ElfEndian
    $ipkArch = [string]$def.IpkArch
    $xrayLockTarget = [string]$def.XrayLockTarget

    if (-not $daemonByArch.ContainsKey($goArch)) {
        $daemonPath = Join-Path $binDir "blacktempled-$goArch"
        $env:CGO_ENABLED = "0"
        $env:GOFLAGS = "-trimpath"
        $env:GOOS = "linux"
        $env:GOARCH = $goArch
        $env:GOMIPS = "softfloat"
        Write-Host "==> cross compile linux/$goArch softfloat"
        go build -ldflags "-s -w -X main.version=$Version" -o $daemonPath ./src/cmd/blacktempled
        if ($LASTEXITCODE -ne 0) { throw "go build daemon failed ($goArch)" }
        Restore-HostGoEnv
        Invoke-Checked "ELF verify $goArch" { & $elfcheck -class 32 -endian $elfEndian -machine mips $daemonPath }
        $daemonByArch[$goArch] = $daemonPath
        $elfSize = (Get-Item $daemonPath).Length
        $reportLines.Add("blacktempled_$goArch=$elfSize") | Out-Null
    }

    $daemon = [string]$daemonByArch[$goArch]
    $stage = Join-Path $Out "rootfs-$name"
    if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
    $opt = Join-Path $stage "opt\blacktemple-kn"
    New-Item -ItemType Directory -Force -Path "$opt\bin", "$opt\config", "$opt\data\lists", "$opt\data\cache", "$opt\run", "$opt\backup", "$opt\logs" | Out-Null
    Copy-Item $daemon "$opt\bin\blacktempled"

    $initDstDir = Join-Path $stage "opt\etc\init.d"
    New-Item -ItemType Directory -Force -Path $initDstDir | Out-Null
    Copy-Item "$Root\packaging\init\S99blacktemple-kn" "$initDstDir\S99blacktemple-kn"

    if ($IncludeXray) {
        $xrayDst = Join-Path $opt "bin\xray"
        $cacheDir = Join-Path $Root ".cache\xray"
        Write-Host "==> obtain pinned Xray ($xrayLockTarget) from third_party/xray.lock.json"
        $fetchArgs = @(
            "-lock", "$Root\third_party\xray.lock.json",
            "-target", $xrayLockTarget,
            "-cache", $cacheDir,
            "-out", $xrayDst
        )
        if ($Offline) { $fetchArgs += "-offline" }
        & $xrayfetch @fetchArgs
        if ($LASTEXITCODE -ne 0) { throw "xrayfetch failed for $name" }
        Invoke-Checked "ELF verify xray $name" { & $elfcheck -class 32 -endian $elfEndian -machine mips $xrayDst }
    }

    $controlStage = Join-Path $Out "control-$name"
    if (Test-Path $controlStage) { Remove-Item -Recurse -Force $controlStage }
    New-Item -ItemType Directory -Force -Path $controlStage | Out-Null
    Copy-Item "$Root\packaging\control\*" $controlStage
    $controlFile = Join-Path $controlStage "control"
    $ctrl = [System.IO.File]::ReadAllText($controlFile)
    $ctrl = [regex]::Replace($ctrl, "(?m)^Version: .*", "Version: $Version")
    $ctrl = [regex]::Replace($ctrl, "(?m)^Architecture: .*", "Architecture: $ipkArch")
    Write-UnixText $controlFile $ctrl

    $chmod = "opt/blacktemple-kn/bin/blacktempled=0755,opt/etc/init.d/S99blacktemple-kn=0755"
    if ($IncludeXray) {
        $chmod += ",opt/blacktemple-kn/bin/xray=0755"
    }
    $ipk = Join-Path $Out "blacktemple-kn_${Version}_${ipkArch}.ipk"
    Invoke-Checked "build IPK $name" {
        & $ipkpack -data $stage -control $controlStage -out $ipk -epoch 0 -expect-arch $ipkArch -chmod $chmod
    }

    $sha = (Get-FileHash -Algorithm SHA256 $ipk).Hash.ToLower()
    $ipkSize = (Get-Item $ipk).Length
    $ipkLeaf = Split-Path $ipk -Leaf
    $reportLines.Add("target_$name=PASS") | Out-Null
    $reportLines.Add("ipk_$name=$ipkSize") | Out-Null
    $reportLines.Add("ipk_sha256_$name=$sha") | Out-Null
    $reportLines.Add("ipk_arch_$name=$ipkArch") | Out-Null
    $checksumLines.Add("$sha  $ipkLeaf") | Out-Null
    Write-Host "IPK $ipk size=$ipkSize sha256=$sha"
}

$report = ($reportLines -join "`n") + "`n"
Write-UnixText (Join-Path $Out "size-report.txt") $report
Write-UnixText (Join-Path $Out "checksums.sha256") (($checksumLines -join "`n") + "`n")
Write-Host $report.TrimEnd()
