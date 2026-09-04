# Builds release binaries for linux/windows/darwin on amd64 and arm64.
# Usage:  .\build.ps1 [-Version 1.0.0]
param(
    [string]$Version = "1.0.0",
    [switch]$SkipTests
)

$ErrorActionPreference = "Stop"
$targets = @(
    @{ OS = "linux";   Arch = "amd64" },
    @{ OS = "linux";   Arch = "arm64" },
    @{ OS = "darwin";  Arch = "amd64" },
    @{ OS = "darwin";  Arch = "arm64" },
    @{ OS = "windows"; Arch = "amd64" },
    @{ OS = "windows"; Arch = "arm64" }
)

if (-not $SkipTests) {
    Write-Host "==> go vet + go test"
    go vet ./...
    if ($LASTEXITCODE) { throw "go vet failed" }
    go test ./...
    if ($LASTEXITCODE) { throw "go test failed" }
}

New-Item -ItemType Directory -Force -Path dist | Out-Null
$ldflags = "-s -w -X main.version=$Version"

foreach ($t in $targets) {
    $name = "ckz2json-$($t.OS)-$($t.Arch)"
    $ext = if ($t.OS -eq "windows") { ".exe" } else { "" }
    $bin = "dist\$name$ext"
    Write-Host "==> building $name"
    $env:CGO_ENABLED = "0"
    $env:GOOS = $t.OS
    $env:GOARCH = $t.Arch
    go build -trimpath -ldflags $ldflags -o $bin ./cmd/ckz2json
    if ($LASTEXITCODE) { throw "build failed: $name" }
    Compress-Archive -Path $bin -DestinationPath "dist\$name.zip" -Force
}

Remove-Item Env:GOOS -ErrorAction SilentlyContinue
Remove-Item Env:GOARCH -ErrorAction SilentlyContinue

Get-ChildItem dist | Format-Table Name, Length
