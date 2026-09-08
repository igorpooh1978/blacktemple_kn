#requires -Version 5.1
<#!
.SYNOPSIS
  Windows build pipeline for BlackTemple KN.
#>
[CmdletBinding()]
param(
    [switch]$SkipFrontend,
    [switch]$IncludeXray,
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

$env:GOOS = "linux"
$env:GOARCH = "mipsle"
$env:GOMIPS = "softfloat"
$daemon = Join-Path $binDir "blacktempled"
Write-Host "==> cross compile linux/mipsle softfloat"
go build -ldflags "-s -w -X main.version=$Version" -o $daemon ./src/cmd/blacktempled
if ($LASTEXITCODE -ne 0) { throw "go build daemon failed" }

$elfcheck = Join-Path $binDir "elfcheck.exe"
$ipkpack = Join-Path $binDir "ipkpack.exe"
$env:GOOS = "windows"
$env:GOARCH = "amd64"
Remove-Item Env:GOMIPS -ErrorAction SilentlyContinue
go build -o $elfcheck ./tools/elfcheck
if ($LASTEXITCODE -ne 0) { throw "go build elfcheck failed" }
go build -o $ipkpack ./tools/ipkpack
if ($LASTEXITCODE -ne 0) { throw "go build ipkpack failed" }

Invoke-Checked "ELF verify" { & $elfcheck -class 32 -endian le -machine mips $daemon }

$stage = Join-Path $Out "rootfs"
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
$opt = Join-Path $stage "opt\blacktemple-kn"
New-Item -ItemType Directory -Force -Path "$opt\bin", "$opt\config", "$opt\data\lists", "$opt\data\cache", "$opt\run", "$opt\backup", "$opt\logs" | Out-Null
Copy-Item $daemon "$opt\bin\blacktempled"

$initDstDir = Join-Path $stage "opt\etc\init.d"
New-Item -ItemType Directory -Force -Path $initDstDir | Out-Null
Copy-Item "$Root\packaging\init\S99blacktemple-kn" "$initDstDir\S99blacktemple-kn"

if ($IncludeXray) {
    Write-Host "==> obtain pinned Xray (see third_party/xray.lock.json)"
    throw "IncludeXray download is not executed in R0 hello IPK. Pin exists; fetch belongs to a later wave or explicit implementer run."
}

$controlStage = Join-Path $Out "control"
if (Test-Path $controlStage) { Remove-Item -Recurse -Force $controlStage }
New-Item -ItemType Directory -Force -Path $controlStage | Out-Null
Copy-Item "$Root\packaging\control\*" $controlStage
$controlFile = Join-Path $controlStage "control"
$ctrl = Get-Content -Raw $controlFile
$ctrl = $ctrl -replace "Version: .*", "Version: $Version"
Set-Content -NoNewline -Path $controlFile -Value $ctrl

$ipk = Join-Path $Out "blacktemple-kn_${Version}_mipsel-3.4_kn.ipk"
Invoke-Checked "build IPK" { & $ipkpack -data $stage -control $controlStage -out $ipk -epoch 0 }

$sha = (Get-FileHash -Algorithm SHA256 $ipk).Hash.ToLower()
$elfSize = (Get-Item $daemon).Length
$ipkSize = (Get-Item $ipk).Length
$report = @"
version=$Version
blacktempled=$elfSize
ipk=$ipkSize
ipk_sha256=$sha
cgo=0
goarch=mipsle
gomips=softfloat
"@
Set-Content -Path (Join-Path $Out "size-report.txt") -Value $report
Set-Content -Path (Join-Path $Out "checksums.sha256") -Value "$sha  $(Split-Path $ipk -Leaf)"
Write-Host $report
Write-Host "IPK $ipk"
