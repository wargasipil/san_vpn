#!/usr/bin/env pwsh
# Fetch Wintun, vet, test, then build bin/san_vpn.exe (Windows), bin/san_vpn (Linux)
# and bin/san_vpn-linux-arm64, bin/san_vpn-linux-arm (Linux on ARM, e.g. a Raspberry Pi).
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Push-Location $root
try {
    # The release workflow passes the tag; a local build is stamped with the time.
    $version = if ($env:SAN_VPN_VERSION) { $env:SAN_VPN_VERSION } else { Get-Date -Format "yyyy.MM.dd-HHmm" }

    # The Windows build embeds wintun.dll (amd64), the driver library from
    # wintun.net. It is not checked in; fetch it once and pin its checksum.
    $wintunDir = "internal/osnet/wintun"
    $wintunURL = "https://www.wintun.net/builds/wintun-0.14.1.zip"
    $wintunSHA = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"
    if (-not (Test-Path "$wintunDir/wintun.dll")) {
        Write-Host "fetch wintun..."
        $tmp = Join-Path ([IO.Path]::GetTempPath()) "san_vpn-wintun"
        New-Item -ItemType Directory -Force -Path $tmp | Out-Null
        $zip = Join-Path $tmp "wintun.zip"
        Invoke-WebRequest -Uri $wintunURL -OutFile $zip
        $sum = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLower()
        if ($sum -ne $wintunSHA) { throw "wintun.zip checksum is $sum, want $wintunSHA" }
        Expand-Archive -Force -Path $zip -DestinationPath $tmp
        New-Item -ItemType Directory -Force -Path $wintunDir | Out-Null
        Copy-Item "$tmp/wintun/bin/amd64/wintun.dll" $wintunDir
        Copy-Item "$tmp/wintun/LICENSE.txt" $wintunDir
    }

    Write-Host "vet..."
    go vet ./...
    if ($LASTEXITCODE -ne 0) { throw "go vet failed" }

    Write-Host "test..."
    go test ./...
    if ($LASTEXITCODE -ne 0) { throw "go test failed" }

    New-Item -ItemType Directory -Force -Path "bin" | Out-Null
    $ldflags = "-X main.version=$version"
    $env:CGO_ENABLED = "0"

    Write-Host "build windows/amd64..."
    $env:GOOS = "windows"; $env:GOARCH = "amd64"
    go build -trimpath -ldflags $ldflags -o bin/san_vpn.exe ./cmd/san_vpn
    if ($LASTEXITCODE -ne 0) { throw "windows build failed" }

    Write-Host "build linux/amd64..."
    $env:GOOS = "linux"; $env:GOARCH = "amd64"
    go build -trimpath -ldflags $ldflags -o bin/san_vpn ./cmd/san_vpn
    if ($LASTEXITCODE -ne 0) { throw "linux build failed" }

    # A 64-bit Raspberry Pi OS, and a 32-bit one. ARMv6 runs on every Pi,
    # the Pi 1 and Zero included; ARMv7 would leave those out.
    Write-Host "build linux/arm64..."
    $env:GOARCH = "arm64"
    go build -trimpath -ldflags $ldflags -o bin/san_vpn-linux-arm64 ./cmd/san_vpn
    if ($LASTEXITCODE -ne 0) { throw "linux/arm64 build failed" }

    Write-Host "build linux/arm (ARMv6)..."
    $env:GOARCH = "arm"; $env:GOARM = "6"
    go build -trimpath -ldflags $ldflags -o bin/san_vpn-linux-arm ./cmd/san_vpn
    if ($LASTEXITCODE -ne 0) { throw "linux/arm build failed" }

    Write-Host "built bin/san_vpn.exe, bin/san_vpn, bin/san_vpn-linux-arm64 and bin/san_vpn-linux-arm ($version)"
}
finally {
    Remove-Item Env:GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
    Remove-Item Env:GOARM -ErrorAction SilentlyContinue
    Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
    Pop-Location
}
