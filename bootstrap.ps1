#requires -Version 5.1
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "bootstrap: checking toolchain"
go version
node --version
npm --version
git --version
gh --version
Write-Host "bootstrap: ok"
