# shellcheck shell=sh

BIN="${BIN:-tp}"
DIST="${DIST:-dist}"
VERSION="${VERSION:-dev}"

# One archive per target. Builds disable CGO, avoiding target libc dependencies
# on Linux.
PLATFORMS="${PLATFORMS:-darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 linux/386 linux/arm}"

die() { echo "${0##*/}: $*" >&2; exit 1; }

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$@"; }
else
  sha256() { shasum -a 256 "$@"; }
fi

# Map Go's 32-bit arm target to GOARM=7 and the armv7 archive suffix.
goarm() {
  if [ "$1" = arm ]; then echo 7; fi
}

dist_arch() {
  if [ "$1" = arm ]; then echo armv7; else echo "$1"; fi
}
