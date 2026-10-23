#!/usr/bin/env bash
# Extra pinned point-release rows from local docker-library/php images.
# These are specific builds (not floating tags): regeneration requires the
# exact tags to still exist on Docker Hub or in the local image cache.
set -uo pipefail
cd "$(dirname "$0")/.."
WORK=work/docker
ARCH="${ARCH:-x86_64}"   # ELF arch in meta + row filename (aarch64 later)
mkdir -p "$WORK" data
FAILURES=()

# tag|sapi  (sapi selects binary path/type, same as docker.sh)
EXTRA=(
  "php:8.0-apache|apache"
  "php:8.2.34-apache|apache"
  "php:8.4.26-apache|apache"
  "php:8.5.11-apache|apache"
  "php:8.5.11-fpm|fpm"
  "php:8.5.12-apache|apache"
)

binpath() { case "$1" in apache) echo /usr/lib/apache2/modules/libphp.so;; fpm) echo /usr/local/sbin/php-fpm;; cli) echo /usr/local/bin/php;; esac; }
bintype() { case "$1" in apache) echo shared-libphp;; *) echo static-pie;; esac; }
suffix()  { case "$1" in apache) echo libphp;; fpm) echo php-fpm;; cli) echo php;; esac; }

for e in "${EXTRA[@]}"; do
  tag="${e%%|*}"; s="${e##*|}"
  v="${tag#php:}"; v="${v%%-*}"
  bp=$(binpath "$s")
  safe="${tag#php:}"
  out_bin="$WORK/php-${safe}-${bp##*/}"

  if ! docker image inspect "$tag" >/dev/null 2>&1; then
    echo "SKIP $tag (not local; docker pull it first)"
    continue
  fi
  verline=$(docker run --rm --entrypoint /usr/local/bin/php "$tag" -v | head -1)
  php_version=$(echo "$verline" | sed -nE 's/^PHP ([0-9][0-9.]*) .*/\1/p')
  ts=$(echo "$verline" | grep -oE '\((NTS|ZTS)\)' | head -1 | tr -d '()')
  [ -n "$php_version" ] || { echo "ERROR: cannot parse version from: $verline" >&2; exit 1; }
  ts=${ts:-NTS}

  cid=$(docker create "$tag")
  trap 'docker rm -f "$cid" >/dev/null 2>&1 || true' EXIT
  docker cp "$cid:$bp" "$out_bin"
  docker rm "$cid" >/dev/null
  trap - EXIT

  meta=$(jq -nc --arg pv "$php_version" --arg ts "$ts" --arg pkg "$tag" \
    --arg bp "$bp" --arg bt "$(bintype "$s")" --arg arch "$ARCH" \
    '{php_version:$pv, thread_safety:$ts, arch:$arch, distro:"docker-library/php",
      package:$pkg, binary_path:$bp, binary_type:$bt, symbol_source:"readelf -sW (.symtab)"}')

  ref_arg=""
  ref_v="${php_version%.*}"   # major.minor of the same version
  if [ "$s" != "apache" ] && [ -f "$WORK/php-${php_version}-apache-libphp.so" ]; then
    ref_arg="--reference-binary $WORK/php-${php_version}-apache-libphp.so"
  fi
  out_json="data/docker-php-${php_version}-${s}-$(suffix "$s")-${ARCH}.json"
  if ! python3 scripts/extract_symbols.py --binary "$out_bin" --meta "$meta" --out "$out_json" $ref_arg; then
    FAILURES+=("$out_json")
  fi
done
if [ "${#FAILURES[@]}" -gt 0 ]; then
  echo "ROWS WITH MISSING TIER A:" >&2
  printf '  %s\n' "${FAILURES[@]}" >&2
  exit 1
fi
echo "extra docker rows complete: $(ls data/docker-*.json | wc -l) total rows"
