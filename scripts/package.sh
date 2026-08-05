#!/usr/bin/env bash
# Build the native library and package a release asset for THIS platform.
#
# Produces, for the running OS/arch:
#   dist/loki-<os>-<arch>.<ext>          the prebuilt library (the release asset)
#   dist/loki-<os>-<arch>.<ext>.sha256   its checksum (required by the manager)
# and refreshes the in-repo loadable (lib<entry>.<ext>) so a locally-run Limen
# picks up this build on Reload.
#
# The asset name must end in the platform's library extension (.so/.dll/.dylib)
# and contain the CPU-arch token, with a matching .sha256 — that's exactly what
# Limen's module manager checks before offering a native module on a platform.
#
# For local testing before the SDK is published, point the git dependencies at a
# local checkout of the Limen repo (this module needs both limen-sdk-rust and
# limen-proto, and they come from the same git URL, so one path covers both):
#   LIMEN_PATH=/path/to/Limen scripts/package.sh
set -euo pipefail

cd "$(dirname "$0")/.."

name="loki"   # must match [lib] name in Cargo.toml (and `entry` in limen.toml)

case "$(uname -s)" in
  Linux)                os=linux;   ext=so;    prefix=lib ;;
  Darwin)               os=macos;   ext=dylib; prefix=lib ;;
  MINGW*|MSYS*|CYGWIN*) os=windows; ext=dll;   prefix=""  ;;
  *) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac

case "$(uname -m)" in
  x86_64|amd64)   arch=x86_64 ;;
  aarch64|arm64)  arch=aarch64 ;;
  *)              arch="$(uname -m)" ;;
esac

echo ">> building release ($os-$arch)"
if [[ -n "${LIMEN_PATH:-}" ]]; then
  # Local override: resolve both git dependencies from a local checkout.
  git_url="https://github.com/CRC-BARRACUDA/Limen.git"
  cargo build --release \
    --config "patch.\"$git_url\".limen-sdk-rust.path=\"$LIMEN_PATH/src/limen-sdk-rust\"" \
    --config "patch.\"$git_url\".limen-proto.path=\"$LIMEN_PATH/src/limen-proto\""
else
  cargo build --release
fi

built="target/release/${prefix}${name}.${ext}"
[[ -f "$built" ]] || { echo "build output not found: $built" >&2; exit 1; }

# The loadable Limen dlopens (lib<entry>.so / <entry>.dll) — refresh for local dev.
loadable="${prefix}${name}.${ext}"
cp -f "$built" "$loadable"

# The release asset: <name>-<os>-<arch>.<ext> plus its checksum.
mkdir -p dist
asset="${name}-${os}-${arch}.${ext}"
cp -f "$built" "dist/$asset"

pushd dist >/dev/null
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$asset" > "$asset.sha256"
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$asset" > "$asset.sha256"
else
  echo "no sha256 tool (need sha256sum or shasum)" >&2; exit 1
fi
popd >/dev/null

echo ">> packaged:"
ls -la "dist/$asset" "dist/$asset.sha256"
echo ">> local loadable refreshed: $loadable"
echo
echo "Upload BOTH dist/$asset and dist/$asset.sha256 to the GitHub release."
