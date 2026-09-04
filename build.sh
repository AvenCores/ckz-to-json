#!/usr/bin/env bash
# Builds release binaries for linux/windows/darwin on amd64 and arm64.
# - syncs the Windows file-version resources with the given version
# - produces dist/ binaries, archives and SHA256SUMS.txt
# Usage:  ./build.sh [version]   (default 1.1.0)
set -euo pipefail
cd "$(dirname "$0")"

VERSION="${1:-1.1.0}"
DIST="dist"
LDFLAGS="-s -w -X main.version=${VERSION}"
APP="ckz2json"
WINRES="cmd/$APP/winres.json"

echo "==> sync Windows resource versions ($VERSION)"
sed -i.bak \
    -e "s|\"file_version\": \"[^\"]*\"|\"file_version\": \"$VERSION.0\"|" \
    -e "s|\"product_version\": \"[^\"]*\"|\"product_version\": \"$VERSION.0\"|" \
    -e "s|\"FileVersion\": \"[^\"]*\"|\"FileVersion\": \"$VERSION\"|" \
    -e "s|\"ProductVersion\": \"[^\"]*\"|\"ProductVersion\": \"$VERSION\"|" \
    "$WINRES"
rm -f "$WINRES.bak"

echo "==> regenerating Windows resources (.syso)"
if ! go run github.com/tc-hib/go-winres@latest make --arch amd64,arm64,386 \
        --in "$WINRES" --out "cmd/$APP/winres" 2>/dev/null; then
    echo "note: go-winres недоступен (нет сети?) - используются .syso из репозитория" >&2
fi

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

echo "==> SHA256SUMS.txt"
(
    cd "$DIST"
    rm -f SHA256SUMS.txt
    for f in "${APP}"-*.zip "${APP}"-*.tar.gz; do
        [ -e "$f" ] || continue
        if command -v sha256sum >/dev/null 2>&1; then
            sha256sum "$f" >> SHA256SUMS.txt
        else
            shasum -a 256 "$f" >> SHA256SUMS.txt
        fi
    done
)

echo
ls -la "$DIST"
