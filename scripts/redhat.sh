#!/usr/bin/env bash
# Regenerate every RHEL-family row of the dataset.
#
# Four sources, all RPM-based:
#   - Rocky 9 AppStream (== RHEL 9 / AlmaLinux 9 AppStream): default php
#     8.0 plus the php:8.1/8.2/8.3 module streams. RHEL 9 ships no
#     mod_php; php-fpm is the only server SAPI.
#   - Remi's el9 repo: php80..php85 SCL-style builds under
#     /opt/remi/php8X/root.
#   - Rocky 8 AppStream (== RHEL 8 / AlmaLinux 8): php 7.2 (default
#     module) plus the 7.3/7.4/8.0/8.2 module streams.
#   - Remi's el8 repo: php74..php85 SCL-style builds.
#
# For each row: download the binary RPM + matching -debuginfo RPM,
# extract both, pair the php-fpm binary with its build-id debug file,
# then run the core extractor over it. The debug file's symtab fills the
# LOCAL-symbol gaps of the stripped binary (see extract_symbols.py
# --debug-file).
#
# One JSON row per (build x binary): php-fpm -> static-pie executable.
#
# Requires: curl, rpm2cpio, cpio, readelf, python3, jq.
set -uo pipefail
cd "$(dirname "$0")/.."
ARCH="${ARCH:-x86_64}"
case "$ARCH" in
  x86_64)  RPM_ARCH=x86_64 ;;
  aarch64) RPM_ARCH=aarch64 ;;
  *) echo "ERROR: unsupported ARCH=$ARCH (x86_64|aarch64)" >&2; exit 1 ;;
esac
WORK=work/redhat-${ARCH}
DEBUG=work/debuginfo-${ARCH}
mkdir -p "$WORK" "$DEBUG" data
FAILURES=()

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

# repo|rpm NEVRA (no .rpm)|php version|binary path inside rpm|installed path|distro label
ROWS=(
  "rocky|php-fpm-8.0.30-8.el9_8.1.${RPM_ARCH}|8.0.30|usr/sbin/php-fpm|/usr/sbin/php-fpm|rocky-9"
  "rocky|php-fpm-8.1.32-1.module+el9.7.0+40003+454ed3c4.${RPM_ARCH}|8.1.32|usr/sbin/php-fpm|/usr/sbin/php-fpm|rocky-9"
  "rocky|php-fpm-8.2.35-1.module+el9.8.0+40395+2f706e64.${RPM_ARCH}|8.2.35|usr/sbin/php-fpm|/usr/sbin/php-fpm|rocky-9"
  "rocky|php-fpm-8.3.36-1.module+el9.8.0+40396+4e680bb7.${RPM_ARCH}|8.3.36|usr/sbin/php-fpm|/usr/sbin/php-fpm|rocky-9"
  "remi|php80-php-fpm-8.0.30-21.el9.remi.${RPM_ARCH}|8.0.30|opt/remi/php80/root/usr/sbin/php-fpm|/opt/remi/php80/root/usr/sbin/php-fpm|remi-el9"
  "remi|php81-php-fpm-8.1.34-6.el9.remi.${RPM_ARCH}|8.1.34|opt/remi/php81/root/usr/sbin/php-fpm|/opt/remi/php81/root/usr/sbin/php-fpm|remi-el9"
  "remi|php82-php-fpm-8.2.35-1.el9.remi.${RPM_ARCH}|8.2.35|opt/remi/php82/root/usr/sbin/php-fpm|/opt/remi/php82/root/usr/sbin/php-fpm|remi-el9"
  "remi|php83-php-fpm-8.3.36-1.el9.remi.${RPM_ARCH}|8.3.36|opt/remi/php83/root/usr/sbin/php-fpm|/opt/remi/php83/root/usr/sbin/php-fpm|remi-el9"
  "remi|php84-php-fpm-8.4.27-1.el9.remi.${RPM_ARCH}|8.4.27|opt/remi/php84/root/usr/sbin/php-fpm|/opt/remi/php84/root/usr/sbin/php-fpm|remi-el9"
  "remi|php85-php-fpm-8.5.12-1.el9.remi.${RPM_ARCH}|8.5.12|opt/remi/php85/root/usr/sbin/php-fpm|/opt/remi/php85/root/usr/sbin/php-fpm|remi-el9"
  "rocky8|php-fpm-7.2.24-1.module+el8.4.0+413+c9202dda.${RPM_ARCH}|7.2.24|usr/sbin/php-fpm|/usr/sbin/php-fpm|rocky-8"
  "rocky8|php-fpm-7.3.20-1.module+el8.4.0+414+2e7afcdd.${RPM_ARCH}|7.3.20|usr/sbin/php-fpm|/usr/sbin/php-fpm|rocky-8"
  "rocky8|php-fpm-7.4.33-8.module+el8.10.0+40393+c071e357.${RPM_ARCH}|7.4.33|usr/sbin/php-fpm|/usr/sbin/php-fpm|rocky-8"
  "rocky8|php-fpm-8.0.30-1.module+el8.10.0+1605+02e07af7.${RPM_ARCH}|8.0.30|usr/sbin/php-fpm|/usr/sbin/php-fpm|rocky-8"
  "rocky8|php-fpm-8.2.35-1.module+el8.10.0+40394+d21b33fb.${RPM_ARCH}|8.2.35|usr/sbin/php-fpm|/usr/sbin/php-fpm|rocky-8"
  "remi8|php74-php-fpm-7.4.33-31.el8.remi.${RPM_ARCH}|7.4.33|opt/remi/php74/root/usr/sbin/php-fpm|/opt/remi/php74/root/usr/sbin/php-fpm|remi-el8"
  "remi8|php80-php-fpm-8.0.30-21.el8.remi.${RPM_ARCH}|8.0.30|opt/remi/php80/root/usr/sbin/php-fpm|/opt/remi/php80/root/usr/sbin/php-fpm|remi-el8"
  "remi8|php81-php-fpm-8.1.34-6.el8.remi.${RPM_ARCH}|8.1.34|opt/remi/php81/root/usr/sbin/php-fpm|/opt/remi/php81/root/usr/sbin/php-fpm|remi-el8"
  "remi8|php82-php-fpm-8.2.35-1.el8.remi.${RPM_ARCH}|8.2.35|opt/remi/php82/root/usr/sbin/php-fpm|/opt/remi/php82/root/usr/sbin/php-fpm|remi-el8"
  "remi8|php83-php-fpm-8.3.36-1.el8.remi.${RPM_ARCH}|8.3.36|opt/remi/php83/root/usr/sbin/php-fpm|/opt/remi/php83/root/usr/sbin/php-fpm|remi-el8"
  "remi8|php84-php-fpm-8.4.27-1.el8.remi.${RPM_ARCH}|8.4.27|opt/remi/php84/root/usr/sbin/php-fpm|/opt/remi/php84/root/usr/sbin/php-fpm|remi-el8"
  "remi8|php85-php-fpm-8.5.12-1.el8.remi.${RPM_ARCH}|8.5.12|opt/remi/php85/root/usr/sbin/php-fpm|/opt/remi/php85/root/usr/sbin/php-fpm|remi-el8"
)

for row in "${ROWS[@]}"; do
  IFS='|' read -r repo rpm phpver binrel bp distro <<<"$row"
  dbg_rpm=${rpm/-fpm-/-fpm-debuginfo-}
  # collection-wide debuginfo RPM carries the shared dwz alternate
  # (/usr/lib/debug/.dwz/<name>) that .gnu_debugaltlink points at
  col_rpm=${rpm/-fpm-/-debuginfo-}
  case $repo in
    rocky)
      base="https://dl.rockylinux.org/pub/rocky/9/AppStream/${RPM_ARCH}/os/Packages/p"
      dbase="https://dl.rockylinux.org/pub/rocky/9/AppStream/${RPM_ARCH}/debug/tree/Packages/p" ;;
    remi)
      base="https://rpms.remirepo.net/enterprise/9/remi/${RPM_ARCH}"
      dbase="https://rpms.remirepo.net/enterprise/9/debug-remi/${RPM_ARCH}" ;;
    rocky8)
      base="https://dl.rockylinux.org/pub/rocky/8/AppStream/${RPM_ARCH}/os/Packages/p"
      dbase="https://dl.rockylinux.org/pub/rocky/8/AppStream/${RPM_ARCH}/debug/tree/Packages/p" ;;
    remi8)
      base="https://rpms.remirepo.net/enterprise/8/remi/${RPM_ARCH}"
      dbase="https://rpms.remirepo.net/enterprise/8/debug-remi/${RPM_ARCH}" ;;
  esac
  # '+' in NEVRAs is URL-encoded as %2B on the mirrors
  url_rpm=${rpm//+/%2B}
  url_dbg=${dbg_rpm//+/%2B}
  url_col=${col_rpm//+/%2B}

  deb="$WORK/${rpm}.rpm"
  dbgdeb="$WORK/${dbg_rpm}.rpm"
  coldeb="$WORK/${col_rpm}.rpm"
  fetch "$base/${url_rpm}.rpm" "$deb" || { FAILURES+=("$rpm"); continue; }
  fetch "$dbase/${url_dbg}.rpm" "$dbgdeb" || { FAILURES+=("$rpm"); continue; }
  fetch "$dbase/${url_col}.rpm" "$coldeb" || { FAILURES+=("$rpm"); continue; }

  xdir="$WORK/extract/${rpm}"
  [ -f "$xdir/$binrel" ] || extract_rpm "$deb" "$xdir" || { FAILURES+=("$rpm"); continue; }
  gdir="$WORK/extract/${dbg_rpm}"
  [ -d "$gdir/usr/lib/debug" ] || extract_rpm "$dbgdeb" "$gdir" || { FAILURES+=("$rpm"); continue; }
  # merge the dwz alternate into the same tree (in-place idempotent)
  extract_rpm "$coldeb" "$gdir" || { FAILURES+=("$rpm"); continue; }

  bin="$xdir/$binrel"
  [ -f "$bin" ] || { echo "ERROR: binary not found: $bin" >&2; FAILURES+=("$rpm"); continue; }
  bid=$(build_id_of "$bin")
  [ -n "$bid" ] || { echo "ERROR: no build-id on $bin" >&2; FAILURES+=("$rpm"); continue; }
  # in-tree path so the relative .gnu_debugaltlink resolves to .dwz/
  dbg="$gdir/usr/lib/debug/.build-id/${bid:0:2}/${bid:2}.debug"
  if [ ! -f "$dbg" ]; then
    # SCL-style debuginfo (Remi) mirrors the binary path instead of
    # using .build-id: usr/lib/debug/<bindir>/php-fpm-<NEVRA>.debug
    dbg=$(find "$gdir/usr/lib/debug/$(dirname "$binrel")" -maxdepth 1 -name '*.debug' 2>/dev/null | head -1)
  fi
  [ -f "$dbg" ] || { echo "ERROR: debug file for build-id $bid not found in $gdir" >&2; FAILURES+=("$rpm"); continue; }
  cp -f "$dbg" "$DEBUG/${distro}-${rpm}.debug"

  meta=$(jq -nc --arg pv "$phpver" --arg pkg "$rpm" --arg bp "$bp" \
    --arg distro "$distro" --arg arch "$ARCH" \
    '{php_version:$pv, thread_safety:"NTS", arch:$arch, distro:$distro,
      package:$pkg, binary_path:$bp, binary_type:"static-pie"}')
  out_json="data/${distro}-php-${phpver}-fpm-php-fpm-${ARCH}.json"
  # zend_reference_destroy exists upstream only from php 7.3
  case $phpver in 5.*|7.0.*|7.1.*|7.2.*) extra="--allow-missing-tier-a" ;; *) extra="" ;; esac
  if ! python3 scripts/extract_symbols.py --binary "$bin" --debug-file "$dbg" $extra --meta "$meta" --out "$out_json"; then
    FAILURES+=("$out_json")
  fi
done

echo "redhat pass complete: $(ls data/rocky-*.json data/remi-*.json 2>/dev/null | wc -l) rows"
if [ "${#FAILURES[@]}" -gt 0 ]; then
  echo "FAILURES:" >&2
  printf '  %s\n' "${FAILURES[@]}" >&2
  exit 1
fi
