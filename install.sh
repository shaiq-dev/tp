#!/bin/sh
# tp installer. Read it before you run it. It is meant to be read.
#
# Downloads are checked against a SHA-256 published in the release manifest,
# which catches a corrupted or truncated transfer. Both the manifest and the
# tarball come over HTTPS from GitHub, so GitHub is the thing being trusted.
#
#   TP_VERSION=v0.1.0 sh install.sh    install a specific tag
#   TP_PREFIX=/opt/tp sh install.sh    install somewhere else
set -eu

REPO="${TP_REPO:-shaiq-dev/tp}"
PREFIX="${TP_PREFIX:-$HOME/.local}"

if [ -n "${TP_VERSION:-}" ]; then
  BASE="https://github.com/$REPO/releases/download/$TP_VERSION"
else
  BASE="https://github.com/$REPO/releases/latest/download"
fi
BASE="${TP_RELEASE_BASE:-$BASE}"

die() { echo "tp install: $*" >&2; exit 1; }

case "$(uname -s)" in
  Darwin) os=darwin ;;
  Linux)  os=linux ;;
  *) die "unsupported operating system $(uname -s). tp ships darwin and linux only." ;;
esac

case "$(uname -m)" in
  x86_64|amd64)          arch=amd64 ;;
  arm64|aarch64|armv8*)  arch=arm64 ;;
  armv7*|armv6*|armhf|arm) arch=armv7 ;;
  i386|i486|i586|i686|x86) arch=386 ;;
  *) die "unsupported architecture $(uname -m). Build from source with: go install github.com/$REPO@latest" ;;
esac

# A 64 bit kernel often reports x86_64 or aarch64 while userspace is 32 bit.
# Ask the C library which one it actually is before picking a binary.
if [ "$os" = linux ] && command -v getconf >/dev/null 2>&1; then
  case "$arch:$(getconf LONG_BIT 2>/dev/null || echo 64)" in
    amd64:32) arch=386 ;;
    arm64:32) arch=armv7 ;;
  esac
fi
target="${os}_${arch}"

command -v curl >/dev/null 2>&1 || die "curl is required"
command -v tar  >/dev/null 2>&1 || die "tar is required"

# Whichever of these the machine has. One of them always does.
if command -v sha256sum >/dev/null 2>&1; then
  checksum() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  checksum() { shasum -a 256 "$1" | cut -d' ' -f1; }
elif command -v openssl >/dev/null 2>&1; then
  checksum() { openssl dgst -sha256 "$1" | tr ' ' '\n' | tail -n 1; }
else
  die "none of sha256sum, shasum or openssl is available, so the download cannot be checked"
fi

# HTTPS only, redirects included, unless the caller deliberately points this at
# something else.
case "$BASE" in
  https://*) fetch() { curl -fsSL --proto '=https' --tlsv1.2 -o "$1" "$2"; } ;;
  *) echo "warning: $BASE is not https" >&2
     fetch() { curl -fsSL -o "$1" "$2"; } ;;
esac

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM
cd "$tmp"

fetch manifest.json "$BASE/manifest.json" \
  || die "could not fetch the manifest from $BASE"

# The manifest is one flat line per target so a shell can read it without a
# JSON parser: "linux_amd64": { "sha256": "...", "file": "..." }
line="$(grep -F "\"$target\"" manifest.json)" || die "this release has no build for $target"
sum="$(printf '%s' "$line" | sed -n 's/.*"sha256" *: *"\([0-9a-f]\{64\}\)".*/\1/p')"
file="$(printf '%s' "$line" | sed -n 's/.*"file" *: *"\([^"]*\)".*/\1/p')"
if [ -z "$sum" ] || [ -z "$file" ]; then
  die "the manifest entry for $target is malformed"
fi

# A plain file name is all this script ever needs, and the manifest is only as
# trustworthy as the host that served it, so a path here is refused.
case "$file" in
  */*|.*|"") die "the manifest names a suspicious file: $file" ;;
esac

fetch "$file" "$BASE/$file" || die "could not download $file"
got="$(checksum "$file")"
[ "$got" = "$sum" ] || die "checksum mismatch for $file
  expected $sum
  got      $got"

# Only after the checksum passes is anything unpacked or made executable.
mkdir -p unpacked
tar -xzf "$file" -C unpacked
bin="$(find unpacked -type f -name tp -print | head -n 1)"
[ -n "$bin" ] || die "$file does not contain a tp binary"

mkdir -p "$PREFIX/bin"
chmod 0755 "$bin"
mv "$bin" "$PREFIX/bin/tp"

version="$("$PREFIX/bin/tp" version 2>/dev/null | head -n 1 || echo tp)"
echo "installed $version to $PREFIX/bin/tp"
case ":$PATH:" in
  *":$PREFIX/bin:"*) ;;
  *) echo "warning: $PREFIX/bin is not on your PATH. Add it to your shell profile yourself. This script does not edit rc files." >&2 ;;
esac
echo "Run 'tp post' to start. The daemon starts itself on first use."
echo "Shell completions: tp completion zsh   (also bash and fish)"
