#!/usr/bin/env bash
# Regenerate every docker-library/php row of the dataset.
#
# For each php:<ver>-<sapi> image: resolve the exact PHP version and NTS/ZTS
# from `php -v`, copy the SAPI binary out with docker cp, then run the core
# extractor (scripts/extract_symbols.py) over it.
#
# One JSON row per (build x binary): apache -> libphp.so, fpm -> php-fpm,
# cli -> php. Never merged.
set -uo pipefail
cd "$(dirname "$0")/.."
WORK=work/docker
ARCH="${ARCH:-x86_64}"   # ELF arch in meta + row filename (aarch64 later)
mkdir -p "$WORK" data
FAILURES=()

binpath() { case "$1" in apache) echo /usr/lib/apache2/modules/libphp.so;; fpm) echo /usr/local/sbin/php-fpm;; cli) echo /usr/local/bin/php;; esac; }
bintype() { case "$1" in apache) echo shared-libphp;; *) echo static-pie;; esac; }
suffix()  { case "$1" in apache) echo libphp;; fpm) echo php-fpm;; cli) echo php;; esac; }

for v in 8.1 8.2 8.3 8.4 8.5; do
  for s in apache fpm cli; do
    tag="php:${v}-${s}"
    bp=$(binpath "$s")
    out_bin="$WORK/php-${v}-${s}-$(basename "$bp")"

    # exact version + thread safety from the interpreter itself
    verline=$(docker run --rm --entrypoint /usr/local/bin/php "$tag" -v | head -1)
    php_version=$(echo "$verline" | sed -nE 's/^PHP ([0-9][0-9.]*) .*/\1/p')
    ts=$(echo "$verline" | grep -oE '\((NTS|ZTS)\)' | head -1 | tr -d '()')
    [ -n "$php_version" ] || { echo "ERROR: cannot parse version from: $verline" >&2; exit 1; }
    ts=${ts:-NTS}

    # extract the SAPI binary without running the container
    cid=$(docker create "$tag")
    trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT
    docker cp "$cid:$bp" "$out_bin"
    docker rm "$cid" >/dev/null
    trap - EXIT

    meta=$(jq -nc --arg pv "$php_version" --arg ts "$ts" --arg pkg "php:${v}-${s}" \
      --arg bp "$bp" --arg bt "$(bintype "$s")" --arg arch "$ARCH" \
      '{php_version:$pv, thread_safety:$ts, arch:$arch, distro:"docker-library/php",
        package:$pkg, binary_path:$bp, binary_type:$bt, symbol_source:"readelf -sW (.symtab)"}')

    out_json="data/docker-php-${php_version}-${s}-$(suffix "$s")-${ARCH}.json"
    ref_arg=""
    if [ "$s" != "apache" ] && [ -f "$WORK/php-${v}-apache-libphp.so" ]; then
      ref_arg="--reference-binary $WORK/php-${v}-apache-libphp.so"
    fi
    if ! python3 scripts/extract_symbols.py --binary "$out_bin" --meta "$meta" --out "$out_json" $ref_arg; then
      FAILURES+=("$out_json")
    fi
  done
done
echo "docker pass complete: $(ls data/docker-*.json | wc -l) rows"
if [ "${#FAILURES[@]}" -gt 0 ]; then
  echo "ROWS WITH MISSING TIER A:" >&2
  printf '  %s\n' "${FAILURES[@]}" >&2
  exit 1
fi
