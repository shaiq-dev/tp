# shellcheck shell=sh
# Shared settings and helpers. Sourced by the other scripts here, not run.

BIN="${BIN:-tp}"
DIST="${DIST:-dist}"
VERSION="${VERSION:-dev}"

# One tarball per platform. CGO is off everywhere, so the binaries are static
# and do not care which libc or distro version the target has.
PLATFORMS="${PLATFORMS:-darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 linux/386 linux/arm}"

die() { echo "${0##*/}: $*" >&2; exit 1; }

if command -v sha256sum >/dev/null 2>&1; then
  sha256() { sha256sum "$@"; }
else
  sha256() { shasum -a 256 "$@"; }
fi

# goarm and dist_arch translate a Go GOARCH into the name used in file names.
# Only 32 bit arm needs the distinction.
goarm() {
  if [ "$1" = arm ]; then echo 7; fi
}

dist_arch() {
  if [ "$1" = arm ]; then echo armv7; else echo "$1"; fi
}
