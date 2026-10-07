#!/usr/bin/env bash
# Fetch Wintun, vet, test, then build bin/san_vpn.exe (Windows) and bin/san_vpn (Linux).
set -euo pipefail

cd "$(dirname "$0")"
# The release workflow passes the tag; a local build is stamped with the time.
version="${SAN_VPN_VERSION:-$(date +%Y.%m.%d-%H%M)}"

# The Windows build embeds wintun.dll (amd64), the driver library from
# wintun.net. It is not checked in; fetch it once and pin its checksum.
wintun_dir=internal/osnet/wintun
wintun_url=https://www.wintun.net/builds/wintun-0.14.1.zip
wintun_sha=07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51
if [ ! -f "$wintun_dir/wintun.dll" ]; then
    echo "fetch wintun..."
    command -v unzip >/dev/null || { echo "build.sh needs unzip to unpack wintun.zip" >&2; exit 1; }
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    curl -fsSL -o "$tmp/wintun.zip" "$wintun_url"
    echo "$wintun_sha  $tmp/wintun.zip" | sha256sum -c --quiet
    unzip -q "$tmp/wintun.zip" -d "$tmp"
    mkdir -p "$wintun_dir"
    cp "$tmp/wintun/bin/amd64/wintun.dll" "$tmp/wintun/LICENSE.txt" "$wintun_dir/"
fi

echo "vet..."
go vet ./...

echo "test..."
go test ./...

mkdir -p bin
ldflags="-X main.version=${version}"
export CGO_ENABLED=0

echo "build windows/amd64..."
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "${ldflags}" -o bin/san_vpn.exe ./cmd/san_vpn

echo "build linux/amd64..."
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "${ldflags}" -o bin/san_vpn ./cmd/san_vpn

echo "built bin/san_vpn.exe and bin/san_vpn (${version})"
