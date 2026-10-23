#!/usr/bin/env bash
# Regenerate every Fedora row of the dataset.
#
# Fedora builds session into the SAPI binaries (unlike Alpine), so each
# row is a single binary with the full Tier A set. Fedora ships no
# mod_php; php (cli) and php-fpm are the relevant binaries.
#
# Debug info: koji carries php-fpm-debuginfo / php-debuginfo RPMs; the
# collection-wide php-debuginfo RPM also carries the shared dwz
# alternate (/usr/lib/debug/.dwz/<name>) that .gnu_debugaltlink points
# at, so both are extracted into one tree.
#
# Requires: curl, rpm2cpio, cpio, readelf, python3, jq.
set -uo pipefail
cd "$(dirname "$0")/.."
WORK=work/fedora
ARCH="${ARCH:-x86_64}"   # ELF arch in meta + row filename (aarch64 later)
DEBUG=work/debuginfo
mkdir -p "$WORK" "$DEBUG" data
FAILURES=()

# distro|php version|release|binary path in rpm|installed path|binary_type|row suffix|binary name
ROWS=(
  "fedora-43|8.4.27|2.fc43|usr/bin/php|/usr/bin/php|static-pie|cli-php|php"
  "fedora-43|8.4.27|2.fc43|usr/bin/php-fpm|/usr/bin/php-fpm|static-pie|fpm-php-fpm|php-fpm"
)

fetch() { # url dest
  local url=$1 dest=$2
  [ -s "$dest" ] && return 0
  echo "fetch $(basename "$dest")"
  curl -fsSL --max-time 600 -o "$dest" "$url" || {
    echo "ERROR: fetch failed: $url" >&2; return 1;
  }
}

extract_rpm() { # rpm dir
  local rpm=$1 dir=$2
  mkdir -p "$dir"
  rpm2cpio "$rpm" | (cd "$dir" && cpio -idm --quiet) || {
    echo "ERROR: cpio extraction failed for $rpm" >&2; return 1;
  }
}

build_id_of() { readelf -n "$1" | sed -nE 's/.*Build ID: ([0-9a-f]+).*/\1/p' | head -1; }

for row in "${ROWS[@]}"; do
  IFS='|' read -r distro phpver rel binrel bp bt suffix bname <<<"$row"
  case $bname in
    php-fpm) pkg_rpm="php-fpm-8.4.27-${rel}.x86_64"; dbg_rpm="php-fpm-debuginfo-8.4.27-${rel}.x86_64" ;;
    # Fedora's `php` RPM is a metapackage; the CLI binary is in php-cli
    *) pkg_rpm="php-cli-8.4.27-${rel}.x86_64"; dbg_rpm="php-cli-debuginfo-8.4.27-${rel}.x86_64" ;;
  esac
  col_rpm="php-debuginfo-8.4.27-${rel}.x86_64"
  base="https://kojipkgs.fedoraproject.org/packages/php/8.4.27/${rel}/x86_64"

  deb="$WORK/${pkg_rpm}.rpm"
  dbgdeb="$WORK/${dbg_rpm}.rpm"
  coldeb="$WORK/${col_rpm}.rpm"
  fetch "$base/${pkg_rpm}.rpm" "$deb" || { FAILURES+=("$pkg_rpm"); continue; }
  fetch "$base/${dbg_rpm}.rpm" "$dbgdeb" || { FAILURES+=("$pkg_rpm"); continue; }
  if [ "$dbg_rpm" != "$col_rpm" ]; then
    fetch "$base/${col_rpm}.rpm" "$coldeb" || { FAILURES+=("$pkg_rpm"); continue; }
  fi

  xdir="$WORK/extract/${pkg_rpm}"
  [ -f "$xdir/$binrel" ] || extract_rpm "$deb" "$xdir" || { FAILURES+=("$pkg_rpm"); continue; }
  gdir="$WORK/extract/${dbg_rpm}"
  [ -d "$gdir/usr/lib/debug" ] || extract_rpm "$dbgdeb" "$gdir" || { FAILURES+=("$pkg_rpm"); continue; }
  if [ "$dbg_rpm" != "$col_rpm" ]; then
    extract_rpm "$coldeb" "$gdir" || { FAILURES+=("$pkg_rpm"); continue; }
  fi

  bin="$xdir/$binrel"
  [ -f "$bin" ] || { echo "ERROR: binary not found: $bin" >&2; FAILURES+=("$pkg_rpm"); continue; }
  bid=$(build_id_of "$bin")
  [ -n "$bid" ] || { echo "ERROR: no build-id on $bin" >&2; FAILURES+=("$pkg_rpm"); continue; }
  # in-tree path so the relative .gnu_debugaltlink resolves to .dwz/
  dbg="$gdir/usr/lib/debug/.build-id/${bid:0:2}/${bid:2}.debug"
  [ -f "$dbg" ] || { echo "ERROR: debug file for build-id $bid not found in $gdir" >&2; FAILURES+=("$pkg_rpm"); continue; }
  cp -f "$dbg" "$DEBUG/${distro}-${pkg_rpm}.debug"

  meta=$(jq -nc --arg pv "$phpver" --arg pkg "${pkg_rpm}" --arg bp "$bp" \
    --arg distro "$distro" --arg bt "$bt" --arg arch "$ARCH" \
    '{php_version:$pv, thread_safety:"NTS", arch:$arch, distro:$distro,
      package:$pkg, binary_path:$bp, binary_type:$bt}')
  out_json="data/${distro}-php-${phpver}-${rel}-${suffix}-${ARCH}.json"
  if ! python3 scripts/extract_symbols.py --binary "$bin" --debug-file "$dbg" --meta "$meta" --out "$out_json"; then
    FAILURES+=("$out_json")
  fi
done

echo "fedora pass complete: $(ls data/fedora-*.json 2>/dev/null | wc -l) rows"
if [ "${#FAILURES[@]}" -gt 0 ]; then
  echo "FAILURES:" >&2
  printf '  %s\n' "${FAILURES[@]}" >&2
  exit 1
fi
