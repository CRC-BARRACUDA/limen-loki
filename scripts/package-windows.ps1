#!/usr/bin/env pwsh
# Build the native library and package a release asset for Windows.
#
# Produces, for the host architecture:
#   dist\loki-windows-<arch>.dll          the prebuilt library (the release asset)
#   dist\loki-windows-<arch>.dll.sha256   its checksum (sha256sum format)
# and refreshes the in-repo loadable (loki.dll) so a locally-run Limen picks up
# this build on Reload.
#
# The asset name must end in .dll and contain the CPU-arch token, with a matching
# .sha256 - that's exactly what Limen's module manager checks before offering a
# native module on a platform.
#
# The Unix equivalent is scripts/package.sh; this is the same contract for a
# shell that has no bash.
#
# For local testing before the SDK is published, point the git dependencies at a
# local checkout of the Limen repo (this module needs both limen-sdk-rust and
# limen-proto, and they come from the same git URL, so one path covers both):
#   $env:LIMEN_PATH = 'C:\path\to\Limen'; .\scripts\package-windows.ps1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Module root = parent of this script's dir.
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$name = 'loki'   # must match [lib] name in Cargo.toml (and `entry` in limen.toml)

# Host architecture, normalized to Rust's naming (x86_64 / aarch64).
$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'x86_64' }
    'ARM64' { 'aarch64' }
    default { $env:PROCESSOR_ARCHITECTURE.ToLower() }
}

# Resolve cargo: prefer PATH, fall back to the default rustup install location so
# the script runs even in a shell that hasn't picked up cargo's PATH entry yet.
$cargoCmd = Get-Command cargo -ErrorAction SilentlyContinue
$cargo = if ($cargoCmd) { $cargoCmd.Source } else { $null }
if (-not $cargo) {
    $fallback = Join-Path $env:USERPROFILE '.cargo\bin\cargo.exe'
    if (Test-Path $fallback) { $cargo = $fallback } else { throw "cargo not found on PATH or at $fallback" }
}

Write-Host ">> building release (windows-$arch)"
$limenPath = $env:LIMEN_PATH
if ($limenPath) {
    # Local override: resolve both git dependencies from a local checkout.
    $gitUrl = 'https://github.com/CRC-BARRACUDA/Limen.git'
    & $cargo build --release `
        --config "patch.`"$gitUrl`".limen-sdk-rust.path=`"$limenPath/src/limen-sdk-rust`"" `
        --config "patch.`"$gitUrl`".limen-proto.path=`"$limenPath/src/limen-proto`""
} else {
    & $cargo build --release
}
if ($LASTEXITCODE -ne 0) { throw "cargo build failed (exit $LASTEXITCODE)" }

# Windows has no `lib` prefix on a cdylib, so the loadable is <entry>.dll.
$built = "target\release\$name.dll"
if (-not (Test-Path $built)) { throw "build output not found: $built" }

# The loadable Limen dlopens - refresh for local dev.
Copy-Item $built "$name.dll" -Force

$dist = Join-Path $root 'dist'
New-Item -ItemType Directory -Force -Path $dist | Out-Null

$asset = "$name-windows-$arch.dll"
$target = Join-Path $dist $asset
Copy-Item $built $target -Force

Write-Host ">> checksum"
$hash = (Get-FileHash -Algorithm SHA256 $target).Hash.ToLower()
# sha256sum format: "<hash>  <filename>" (two spaces), so `sha256sum -c` can verify it.
"$hash  $asset" | Out-File -FilePath "$target.sha256" -Encoding ascii -NoNewline

Write-Host ">> packaged:"
Get-ChildItem $dist -Filter "$asset*" | Select-Object Name, @{n='Size';e={ '{0,10:N0}' -f $_.Length }}
Write-Host ">> local loadable refreshed: $name.dll"
Write-Host ""
Write-Host "Upload BOTH dist\$asset and dist\$asset.sha256 to the GitHub release."
