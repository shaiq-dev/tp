#!/bin/sh
# Write manifest.json for whatever tarballs are already in $DIST.
#
# One flat line per target, so install.sh can read it with grep and sed instead
# of shipping a JSON parser.
set -eu
cd "$(dirname "$0")/.."
. scripts/lib.sh

set -- "$DIST"/*.tar.gz
[ -e "$1" ] || die "no tarballs in $DIST, run scripts/build.sh first"

{
  echo '{'
  echo "  \"version\": \"$VERSION\","
  echo '  "binaries": {'
  first=1
  for path in "$@"; do
    file="$(basename "$path")"
    target="${file#"${BIN}_${VERSION}_"}"
    target="${target%.tar.gz}"
    sum="$(sha256 "$path" | cut -d' ' -f1)"
    [ "$first" -eq 1 ] || echo ','
    first=0
    printf '    "%s": { "sha256": "%s", "file": "%s" }' "$target" "$sum" "$file"
  done
  echo
  echo '  }'
  echo '}'
} > "$DIST/manifest.json"
