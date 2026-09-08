#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$env:CGO_ENABLED = "0"
gofmt -l src tools
go vet ./src/... ./tools/...
go test ./src/... ./tools/...
if (Test-Path "web\package.json") {
    Push-Location web
    if (-not (Test-Path node_modules)) { npm install }
    npm test
    Pop-Location
}
