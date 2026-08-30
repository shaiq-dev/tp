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

# The Go linker ad-hoc signs with the identifier "a.out", which every Go binary
# on the machine shares, so macOS has nothing to record a local network decision
# against. Re-signing with our own identifier gives the CLI an identity of its
# own, and install-agent below does the same for the daemon.
if [ "$os" = darwin ] && command -v codesign >/dev/null 2>&1; then
  codesign --force --sign - --identifier sh.tp "$PREFIX/bin/tp" 2>/dev/null \
    || echo "warning: could not re-sign tp, macOS may deny it local network access" >&2
fi

version="$("$PREFIX/bin/tp" version 2>/dev/null | head -n 1 || echo tp)"
echo "installed $version to $PREFIX/bin/tp"
case ":$PATH:" in
  *":$PREFIX/bin:"*) ;;
  *) echo "warning: $PREFIX/bin is not on your PATH. Add it to your shell profile yourself. This script does not edit rc files." >&2 ;;
esac
# Discovery is multicast, and two environments block it in ways that look like a
# bug in tp. Both are worth saying here rather than leaving to a failed fetch.
if [ "$os" = darwin ]; then
  # macOS 15 and later gate local network access per app. A daemon forked by a
  # terminal that has since exited has no app to attribute the request to, so it
  # is denied with no prompt and no entry in Settings. A launch agent has an
  # identity of its own.
  if [ -z "${TP_NO_AGENT:-}" ]; then
    echo
    echo "Installing the launch agent, so macOS has something to grant local network access to."
    if "$PREFIX/bin/tp" doctor --fix; then
      :
    else
      echo "warning: could not install the launch agent. Run 'tp doctor --fix' yourself." >&2
    fi
  else
    echo
    echo "TP_NO_AGENT is set, skipping the launch agent. On macOS 15 and later"
    echo "discovery needs it, because a forked daemon cannot be granted local"
    echo "network access. Run 'tp doctor --fix' when you want it."
  fi
fi

if [ "$os" = linux ] && grep -qiE "microsoft|wsl" /proc/sys/kernel/osrelease 2>/dev/null; then
  # NAT is the default networkingMode and keeps multicast inside the VM, so no
  # announcement ever reaches the LAN and none arrives from it.
  if ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | grep -qvE '^172\.(1[6-9]|2[0-9]|3[01])\.'; then
    echo
    echo "WSL detected, mirrored networking. Discovery should work."
  else
    echo
    echo "WSL detected, and it is in NAT mode. Multicast never leaves the VM, so"
    echo "tp cannot find other machines and they cannot find this one."
    echo
    echo "  1. in Windows, put this in %UserProfile%\\.wslconfig"
    echo "       [wsl2]"
    echo "       networkingMode=mirrored"
    echo "  2. wsl --shutdown"
    echo "  3. if inbound still fails, in an admin PowerShell:"
    echo "       Set-NetFirewallHyperVVMSetting -Name '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}' -DefaultInboundAction Allow"
    echo
    echo "Until then only 'tp get --host <addr>' works, and only outbound."
  fi
fi

echo
echo "Run 'tp post' to start. The daemon starts itself on first use."
echo "If discovery finds nothing, run 'tp doctor'."
echo "Shell completions: tp completion zsh   (also bash and fish)"
