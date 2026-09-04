#!/usr/bin/env bash
# Builds release binaries for linux/windows/darwin on amd64 and arm64.
# Usage:  ./build.sh [version]   (default 1.0.0)
set -euo pipefail
cd "$(dirname "$0")"

VERSION="${1:-1.0.0}"
DIST="dist"
LDFLAGS="-s -w -X main.version=${VERSION}"
APP="ckz2json"

echo "==> go vet + go test"
go vet ./...
go test ./...

mkdir -p "$DIST"

for target in linux_amd64 linux_arm64 darwin_amd64 darwin_arm64 windows_amd64 windows_arm64; do
    os="${target%_*}"
    arch="${target#*_}"
    ext=""
    [ "$os" = "windows" ] && ext=".exe"
    name="${APP}-${os}-${arch}"

    echo "==> building ${name}"
    CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
        go build -trimpath -ldflags "$LDFLAGS" -o "${DIST}/${name}${ext}" ./cmd/"$APP"

    # zip is used when available, otherwise tar.gz
    if command -v zip >/dev/null 2>&1; then
        ( cd "$DIST" && zip -q "${name}.zip" "${name}${ext}" )
    else
        tar -czf "${DIST}/${name}.tar.gz" -C "$DIST" "${name}${ext}"
    fi
done

echo
ls -la "$DIST"
