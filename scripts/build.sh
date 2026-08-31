#!/bin/sh
#
# Build and package each supported target, then generate SHA256SUMS and
# the installer manifest.
#
# VERSION=v0.1.0 scripts/build.sh
set -eu
cd "$(dirname "$0")/.."
. scripts/lib.sh

mkdir -p "$DIST"

for platform in $PLATFORMS; do
  goos="${platform%/*}"
  goarch="${platform#*/}"
  arch="$(dist_arch "$goarch")"
  stage="$DIST/${BIN}_${VERSION}_${goos}_${arch}"

  echo "building $goos/$arch"
  mkdir -p "$stage"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" GOARM="$(goarm "$goarch")" \
    go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$stage/$BIN" . \
    || die "build failed for $goos/$arch"

  cp LICENSE README.md "$stage/"
  cp -r contrib "$stage/"
  tar -czf "$stage.tar.gz" -C "$DIST" "$(basename "$stage")"
  rm -rf "$stage"
done

(
  cd "$DIST"
  : > SHA256SUMS
  for tarball in *.tar.gz; do
    sha256 "$tarball" >> SHA256SUMS
  done
)
scripts/manifest.sh
