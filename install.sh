#!/bin/sh
# tp installer. Read it before you run it. It is meant to be read.
#
# The trust anchor is the minisign public key embedded below. Everything else,
# including the host serving the files, is untrusted: the manifest is signed
# against that key and every download is checked against the manifest.
#
#   TP_VERSION=v0.1.0 sh install.sh    install a specific tag
#   TP_PREFIX=/opt/tp sh install.sh    install somewhere else
set -eu

REPO="${TP_REPO:-shaiq-dev/tp}"
PREFIX="${TP_PREFIX:-$HOME/.local}"
PUBKEY="untrusted comment: minisign public key
RWQZqgh7RiD98s4R6KmvhFfM+sTf/7IQIHSX5Zzj1dGNh+dJKQ3hrBmR"

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
command -v minisign >/dev/null 2>&1 || die "minisign is required to verify the release signature.
  macOS:  brew install minisign
  Debian: apt install minisign
  Fedora: dnf install minisign
  Alpine: apk add minisign
Verifying that signature is the whole point of this script, so there is no way
to skip it. To build from source instead: go install github.com/$REPO@latest"

# HTTPS only, redirects included, unless the caller deliberately points this at
# something else. The signature is what makes the artifacts trustworthy, so a
# plain HTTP mirror is survivable, but it should never happen by accident.
case "$BASE" in
  https://*) fetch() { curl -fsSL --proto '=https' --tlsv1.2 -o "$1" "$2"; } ;;
  *) echo "warning: $BASE is not https. The signature still has to verify." >&2
     fetch() { curl -fsSL -o "$1" "$2"; } ;;
esac

if command -v sha256sum >/dev/null 2>&1; then
  checksum() { sha256sum "$1" | cut -d' ' -f1; }
else
  checksum() { shasum -a 256 "$1" | cut -d' ' -f1; }
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM
cd "$tmp"

fetch manifest.json "$BASE/manifest.json" \
  || die "could not fetch the manifest from $BASE"
fetch manifest.json.minisig "$BASE/manifest.json.minisig" \
  || die "could not fetch the manifest signature from $BASE"

printf '%s\n' "$PUBKEY" > tp.pub
minisign -Vm manifest.json -p tp.pub >/dev/null \
  || die "the manifest signature does not verify. Stopping."

# The manifest is one flat line per target so a shell can read it without a
# JSON parser: "linux_amd64": { "sha256": "...", "file": "..." }
line="$(grep -F "\"$target\"" manifest.json)" || die "this release has no build for $target"
sum="$(printf '%s' "$line" | sed -n 's/.*"sha256" *: *"\([0-9a-f]\{64\}\)".*/\1/p')"
file="$(printf '%s' "$line" | sed -n 's/.*"file" *: *"\([^"]*\)".*/\1/p')"
if [ -z "$sum" ] || [ -z "$file" ]; then
  die "the manifest entry for $target is malformed"
fi

# The manifest is signed, so $file is trusted. Check it anyway. A plain file name
# is all this script ever needs and a path would be a surprise.
case "$file" in
  */*|.*|"") die "the manifest names a suspicious file: $file" ;;
esac

fetch "$file" "$BASE/$file" || die "could not download $file"
got="$(checksum "$file")"
[ "$got" = "$sum" ] || die "checksum mismatch for $file
  expected $sum
  got      $got"

# Only now, after the signature and the checksum both passed, is anything
# unpacked or made executable.
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
