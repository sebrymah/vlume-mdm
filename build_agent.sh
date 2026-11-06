#!/usr/bin/env bash
# build_agent.sh — cross-compile the device agent for every platform it runs
# on, and write checksums beside the binaries.
#
#   ./build_agent.sh            build everything into ./dist
#   ./build_agent.sh darwin     build one platform's
#
# Needs Docker and nothing else. The Go toolchain cross-compiles without a
# C toolchain for any of these, which is the reason the agent has no cgo in
# it: a cgo dependency would mean a build machine per platform.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GOIMAGE="golang:1.23-alpine"
OUT="$HERE/dist"
ONLY="${1:-}"

TARGETS="darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64"

mkdir -p "$OUT"
rm -f "$OUT"/mdm-agent-* "$OUT"/SHA256SUMS

# The version is the git commit when there is one, so a binary found on a
# device years later can be traced to the source that built it.
VERSION="$(git -C "$HERE" rev-parse --short HEAD 2>/dev/null || echo unversioned)"
BUILT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

echo "==> building the agent ($VERSION)"
for target in $TARGETS; do
  goos="${target%%/*}"
  goarch="${target##*/}"
  if [ -n "$ONLY" ] && [ "$goos" != "$ONLY" ]; then
    continue
  fi
  name="mdm-agent-${goos}-${goarch}"
  [ "$goos" = "windows" ] && name="${name}.exe"

  echo "    $name"
  docker run --rm \
    -v "$HERE":/src -v mdm-gomodcache:/go/pkg/mod -w /src \
    -e GOFLAGS=-mod=mod -e CGO_ENABLED=0 \
    -e GOOS="$goos" -e GOARCH="$goarch" \
    "$GOIMAGE" sh -c "go build \
      -trimpath \
      -ldflags='-s -w -X main.version=${VERSION} -X main.built=${BUILT}' \
      -o dist/${name} ./cmd/agent"
done

# Checksums, so an administrator copying a binary onto a machine can tell it
# is the one that was built. Not a signature: a checksum beside the file it
# describes proves only that the download was not corrupted. Signing needs
# an Apple Developer ID on macOS and an Authenticode certificate on Windows,
# and neither is in place.
( cd "$OUT" && sha256sum mdm-agent-* > SHA256SUMS )

echo ""
ls -lh "$OUT" | sed 's/^/  /'
cat <<'NOTE'

  NOT SIGNED. macOS will refuse to run an unsigned, un-notarised binary
  downloaded through a browser, and Gatekeeper will quarantine it. Copying
  it with scp or installing it from an MDM payload avoids that, which is
  what the install script assumes. Proper signing needs an Apple Developer
  ID and, on Windows, an Authenticode certificate.
NOTE
