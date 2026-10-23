#!/usr/bin/env bash
# Regenerate every Ubuntu row of the dataset.
#
# For each (suite, php): download the binary package and its matching
# -dbgsym ddeb (archive.ubuntu.com / ddebs.ubuntu.com), extract both,
# pair each SAPI binary with its build-id debug file, then run the core
# extractor over it. The debug file's symtab fills the LOCAL-symbol gaps
# of the stripped binary (see extract_symbols.py --debug-file).
#
# Ubuntu quirk: mod_php is in main, phpX-fpm is in universe (same source
# package, same version) - the pool component differs per binary package.
#
# One JSON row per (build x binary): libapache2-mod-phpX -> libphpX.so
# (shared-libphp), phpX-fpm -> /usr/sbin/php-fpmX (static-pie).
#
# Requires: curl, ar, tar (xz/zstd), readelf, python3, jq.
set -uo pipefail
cd "$(dirname "$0")/.."
ARCH="${ARCH:-x86_64}"
case "$ARCH" in
  x86_64)  DEB_ARCH=amd64; POOL="https://archive.ubuntu.com/ubuntu/pool" ;;
  aarch64) DEB_ARCH=arm64;  POOL="http://ports.ubuntu.com/ubuntu-ports/pool" ;;
  *) echo "ERROR: unsupported ARCH=$ARCH (x86_64|aarch64)" >&2; exit 1 ;;
esac
WORK=work/ubuntu-${ARCH}
DEBUG=work/debuginfo-${ARCH}
mkdir -p "$WORK" "$DEBUG" data
FAILURES=()

# suite|php|ubuntu version
ROWS=(
  "jammy|8.1|8.1.2-1ubuntu2.28"
  "noble|8.3|8.3.6-0ubuntu0.24.04.13"
  "focal|7.4|7.4.3-4ubuntu2.29"
  "bionic|7.2|7.2.24-0ubuntu0.18.04.17"
  "xenial|7.0|7.0.33-0ubuntu0.16.04.16"
)

fetch() { # url dest
  local url=$1 dest=$2
  [ -s "$dest" ] && return 0
  echo "fetch $(basename "$dest")"
  curl -fsSL --max-time 600 -o "$dest" "$url" || {
    echo "ERROR: fetch failed: $url" >&2; return 1;
  }
}

extract_deb() { # deb dir  (works for .deb and .ddeb)
  local deb=$1 dir=$2 member
  member=$(ar t "$deb" | grep -E '^data\.tar\.(xz|zst|gz)$' | head -1)
  [ -n "$member" ] || { echo "ERROR: no data.tar.* in $deb" >&2; return 1; }
  mkdir -p "$dir"
  case $member in
    *.xz) ar p "$deb" "$member" | tar -xJ -C "$dir" ;;
    *.zst) ar p "$deb" "$member" | tar --zstd -x -C "$dir" ;;
    *.gz)  ar p "$deb" "$member" | tar -xz -C "$dir" ;;
  esac
}

build_id_of() { readelf -n "$1" | sed -nE 's/.*Build ID: ([0-9a-f]+).*/\1/p' | head -1; }

for row in "${ROWS[@]}"; do
  IFS='|' read -r suite php uver <<<"$row"
  upver=${uver%%-*}
  dver="$uver"   # full package version for the row filename
  # pkg|component
  for pc in "libapache2-mod-php${php}|main" "php${php}-fpm|universe"; do
    pkg=${pc%%|*}; comp=${pc##*|}
    deb="$WORK/${pkg}_${uver}_${DEB_ARCH}.deb"
    dbgdeb="$WORK/${pkg}-dbgsym_${uver}_${DEB_ARCH}.ddeb"
    fetch "${POOL}/${comp}/p/php${php}/${pkg}_${uver}_${DEB_ARCH}.deb" "$deb" ||
      { FAILURES+=("$pkg"); continue; }
    fetch "http://ddebs.ubuntu.com/pool/${comp}/p/php${php}/${pkg}-dbgsym_${uver}_${DEB_ARCH}.ddeb" "$dbgdeb" ||
      { FAILURES+=("$pkg"); continue; }

    xdir="$WORK/extract/${pkg}"
    [ -d "$xdir/usr" ] || extract_deb "$deb" "$xdir" || { FAILURES+=("$pkg"); continue; }
    gdir="$WORK/extract/${pkg}-dbgsym"
    [ -d "$gdir/usr" ] || extract_deb "$dbgdeb" "$gdir" || { FAILURES+=("$pkg"); continue; }

    case $pkg in
      libapache2-*)
        bin="$xdir/usr/lib/apache2/modules/libphp${php}.so"
        bp="/usr/lib/apache2/modules/libphp${php}.so"; bt=shared-libphp; sapi=apache; bname=libphp ;;
      *-fpm)
        bin="$xdir/usr/sbin/php-fpm${php}"
        bp="/usr/sbin/php-fpm${php}"; bt=static-pie; sapi=fpm; bname=php-fpm ;;
    esac
    [ -f "$bin" ] || { echo "ERROR: binary not found: $bin" >&2; FAILURES+=("$pkg"); continue; }

    bid=$(build_id_of "$bin")
    [ -n "$bid" ] || { echo "ERROR: no build-id on $bin" >&2; FAILURES+=("$pkg"); continue; }
    dbg="$gdir/usr/lib/debug/.build-id/${bid:0:2}/${bid:2}.debug"
    [ -f "$dbg" ] || { echo "ERROR: debug file for build-id $bid not found in $gdir" >&2; FAILURES+=("$pkg"); continue; }
    cp -f "$dbg" "$DEBUG/ubuntu-${suite}-${pkg}.debug"

    meta=$(jq -nc --arg pv "$upver" --arg pkg "${pkg}_${uver}" --arg bp "$bp" --arg bt "$bt" \
      --arg distro "ubuntu-${suite}" --arg arch "$ARCH" \
      '{php_version:$pv, thread_safety:"NTS", arch:$arch, distro:$distro,
        package:$pkg, binary_path:$bp, binary_type:$bt}')
    # full package version in the filename: several backport revisions
    # share one upstream version (7.4.3-4ubuntu2.1 ... 2.29)
    out_json="data/ubuntu-${suite}-php-${dver}-${sapi}-${bname}-${ARCH}.json"
    # zend_reference_destroy exists upstream only from php 7.3
    case $php in 5.*|7.0|7.1|7.2) extra="--allow-missing-tier-a" ;; *) extra="" ;; esac
    if ! python3 scripts/extract_symbols.py --binary "$bin" --debug-file "$dbg" $extra --meta "$meta" --out "$out_json"; then
      FAILURES+=("$out_json")
    fi
  done
done

echo "ubuntu pass complete: $(ls data/ubuntu-*.json 2>/dev/null | wc -l) rows"
if [ "${#FAILURES[@]}" -gt 0 ]; then
  echo "FAILURES:" >&2
  printf '  %s\n' "${FAILURES[@]}" >&2
  exit 1
fi
