#!/usr/bin/env bash
# Regenerate every Alpine row of the dataset.
#
# Alpine builds PHP with most extensions as SHARED modules - including
# session. The Tier A set therefore spans two binaries per build:
#   - the SAPI binary (php-fpm<XY> static-pie / mod_php<XY>.so shared):
#     core interpreter symbols; ps_globals is NOT in it
#   - session.so (shared extension): ps_globals + php_session_* symbols;
#     core symbols are UND imports
# Both rows are emitted (one JSON per binary, never merged) with
# --allow-missing-tier-a; the notes cross-reference each other.
#
# Debug info: the php<XY>-dbg apk carries usr/lib/debug/<path>.debug for
# every binary of the collection (mirrored-path layout, no .build-id).
#
# Requires: curl, bsdtar, readelf, python3, jq.
set -uo pipefail
cd "$(dirname "$0")/.."
ARCH="${ARCH:-x86_64}"
case "$ARCH" in
  x86_64)  APK_ARCH=x86_64 ;;
  aarch64) APK_ARCH=aarch64 ;;
  *) echo "ERROR: unsupported ARCH=$ARCH (x86_64|aarch64)" >&2; exit 1 ;;
esac
WORK=work/alpine-${ARCH}
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

extract_apk() { # apk dir
  mkdir -p "$2"
  bsdtar -xf "$1" -C "$2" || { echo "ERROR: bsdtar failed for $1" >&2; return 1; }
}

build_id_of() { readelf -n "$1" | sed -nE 's/.*Build ID: ([0-9a-f]+).*/\1/p' | head -1; }

# alpine branch|php XY|apk version tag
COLS=("3.22|83|8.3.36-r0" "3.22|84|8.4.27-r0" "3.18|82|8.2.16-r0" "3.16|81|8.1.22-r0")

for col in "${COLS[@]}"; do
  IFS='|' read -r branch xy aver <<<"$col"
  phpver=${aver%%-*}
  base="https://dl-cdn.alpinelinux.org/alpine/v${branch}/community/${APK_ARCH}"
  dbg_apk="$WORK/php${xy}-dbg-${aver}.apk"
  fetch "$base/php${xy}-dbg-${aver}.apk" "$dbg_apk" || { FAILURES+=("php${xy}-dbg"); continue; }
  gdir="$WORK/extract/${branch}-php${xy}-dbg"
  [ -d "$gdir/usr/lib/debug" ] || extract_apk "$dbg_apk" "$gdir" || { FAILURES+=("php${xy}-dbg"); continue; }

  # sapi|apk suffix|binary path in apk|binary_type|row suffix|binary name
  # the 3.16 php81-dbg apk ships no apache2 debug file (mod_php81.so.debug
  # is absent), and without it the stripped .so exports no zif_* handlers
  # (dynsym only) - skip apache2 on that branch
  case $branch in 3.16) sapis="fpm session" ;; *) sapis="fpm apache2 session" ;; esac
  for row in \
    "fpm|fpm|usr/sbin/php-fpm${xy}|static-pie|fpm-php-fpm|php-fpm${xy}" \
    "apache2|apache2|usr/lib/apache2/mod_php${xy}.so|shared-libphp|apache-mod_php|mod_php${xy}.so" \
    "session|session|usr/lib/php${xy}/modules/session.so|shared-ext|session-session|session.so" \
  ; do
    IFS='|' read -r sapi pkg binrel bt suffix bname <<<"$row"
    case " $sapis " in *" $sapi "*) ;; *) echo "  skip $sapi on $branch (no debug file in -dbg apk)"; continue ;; esac
    apk="$WORK/php${xy}-${pkg}-${aver}.apk"
    fetch "$base/php${xy}-${pkg}-${aver}.apk" "$apk" || { FAILURES+=("php${xy}-${pkg}"); continue; }
    xdir="$WORK/extract/${branch}-php${xy}-${pkg}"
    [ -f "$xdir/$binrel" ] || extract_apk "$apk" "$xdir" || { FAILURES+=("php${xy}-${pkg}"); continue; }

    bin="$xdir/$binrel"
    dbg="$gdir/usr/lib/debug/$binrel.debug"
    [ -f "$bin" ] || { echo "ERROR: binary not found: $bin" >&2; FAILURES+=("php${xy}-${pkg}"); continue; }
    [ -f "$dbg" ] || { echo "ERROR: debug file not found: $dbg" >&2; FAILURES+=("php${xy}-${pkg}"); continue; }
    bid=$(build_id_of "$bin")
    dbg_bid=$(build_id_of "$dbg")
    # alpine 3.16-era apks ship no .note.gnu.build-id at all; when both
    # sides lack the note the mirrored-path layout of the -dbg apk is
    # the pairing guarantee, so accept it (extractor records null)
    if [ -n "$bid" ] || [ -n "$dbg_bid" ]; then
      [ "$bid" = "$dbg_bid" ] || {
        echo "ERROR: build-id mismatch for $bin ($bid vs $dbg_bid)" >&2; FAILURES+=("php${xy}-${pkg}"); continue;
      }
    fi
    cp -f "$dbg" "$DEBUG/alpine-${branch}-php${xy}-${pkg}.debug"

    case $sapi in
      session)
        mnotes='["Alpine splits the session extension into a shared module: core interpreter symbols (zval_ptr_dtor, zif_*, zend_reference_destroy, zend_array_destroy, php_rfc1867_callback) are UND imports here - see the matching fpm/apache row for those"]' ;;
      *)
        mnotes='["Alpine builds the session extension as a shared module (php'"${xy}"'-session apk): ps_globals and the php_session_* symbols are NOT in this binary - see the matching session.so row"]' ;;
    esac
    # 3.16-era apks carry no build-id note; explain the null in-row
    [ -n "$bid" ] || mnotes=$(jq -c '. + ["packages on this alpine branch ship no .note.gnu.build-id: build_id is null; binary/debug pairing is guaranteed by the mirrored-path layout of the php'"${xy}"'-dbg apk"]' <<<"$mnotes")
    meta=$(jq -nc --arg pv "$phpver" --arg pkg "php${xy}-${pkg}-${aver}" \
      --arg bp "/$binrel" --arg bt "$bt" --arg arch "$ARCH" --arg distro "alpine-${branch}" --argjson mn "$mnotes" \
      '{php_version:$pv, thread_safety:"NTS", arch:$arch, distro:$distro,
        package:$pkg, binary_path:$bp, binary_type:$bt, notes:$mn}')
    out_json="data/alpine-${branch}-php-${phpver}-${suffix}-${ARCH}.json"
    if ! python3 scripts/extract_symbols.py --binary "$bin" --debug-file "$dbg" \
        --allow-missing-tier-a --meta "$meta" --out "$out_json"; then
      FAILURES+=("$out_json")
    fi
  done
done

echo "alpine pass complete: $(ls data/alpine-*.json 2>/dev/null | wc -l) rows"
if [ "${#FAILURES[@]}" -gt 0 ]; then
  echo "FAILURES:" >&2
  printf '  %s\n' "${FAILURES[@]}" >&2
  exit 1
fi
