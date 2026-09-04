# Builds release binaries for linux/windows/darwin on amd64 and arm64.
# - syncs the Windows file-version resources with the given version
# - produces dist/ binaries, zips and SHA256SUMS.txt
# Usage:  .\build.ps1 [-Version 1.0.0] [-SkipTests]
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

# --- sync Windows resource versions with $Version ---
$winresPath = (Resolve-Path "cmd\ckz2json\winres.json").Path
$t = [IO.File]::ReadAllText($winresPath)
$t = $t -replace '"file_version": "[^"]*"', "`"file_version`": `"$Version.0`""
$t = $t -replace '"product_version": "[^"]*"', "`"product_version`": `"$Version.0`""
$t = $t -replace '"FileVersion": "[^"]*"', "`"FileVersion`": `"$Version`""
$t = $t -replace '"ProductVersion": "[^"]*"', "`"ProductVersion`": `"$Version`""
[IO.File]::WriteAllText($winresPath, $t, (New-Object System.Text.UTF8Encoding($false)))

Write-Host "==> regenerating Windows resources (.syso)"
go run github.com/tc-hib/go-winres@latest make --arch amd64,arm64,386 `
    --in cmd/ckz2json/winres.json --out cmd/ckz2json/winres
if ($LASTEXITCODE) {
    Write-Warning "go-winres недоступен (нет сети?) - используются .syso из репозитория"
    $LASTEXITCODE = 0
}

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

Write-Host "==> SHA256SUMS.txt"
$sums = Get-ChildItem dist\*.zip | ForEach-Object {
    "{0}  {1}" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(), $_.Name
}
[IO.File]::WriteAllLines("$PWD\dist\SHA256SUMS.txt", $sums)

Get-ChildItem dist | Format-Table Name, Length
