#!/bin/sh
#
# Generate manifest.json from the release archives already in $DIST.
#
# Keep each target entry on one line so install.sh can extract fields with grep
# and sed without requiring a JSON parser.
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
