#!/usr/bin/env bash
# Sweep EVERY historical backport revision of the Debian php packages
# from snapshot.debian.org - binaries only, no -dbgsym download.
#
# The stripped binaries are processed with the no-debug-info pipeline
# (dynsym exports + R_X86_64_RELATIVE relocation scan + pointer scan +
# GOT disassembly), and the local/static-symbol gaps (zend_reference_
# destroy, php_session_*, ps_*, zend_mm_*) are recovered by masked
# pattern matching against a merged reference build of the same suite:
# work/refs/debian-<suite>-<sapi>.merged is the CURRENT version's
# binary + its -dbgsym symtab fused with eu-unstrip (built by
# scripts/build_refs.sh). Pattern hits are call-annotation verified;
# unverified symbols stay null with a note.
#
# Version -> suite mapping: +debNSuX / ~debNSuX tags map to suite N;
# untagged versions map to the single suite that shipped that
# major.minor (7.0->stretch, 7.3->buster, 7.4->bullseye, 8.2->bookworm,
# 8.4->trixie). Caveat: a few untagged versions may have only lived in
# unstable/testing; the row is still the real Debian amd64 build of
# that version.
#
# snapshot.debian.org machine-readable API: only the list endpoints are
# enabled; per-version file URLs come from the HTML package page
# /package/<src>/<version>/ (archive links with timestamps).
#
# Requires: curl, ar, tar (xz/zstd), readelf, python3, jq.
set -uo pipefail
cd "$(dirname "$0")/.."
WORK=work/debian-archive
ARCH="${ARCH:-x86_64}"
REFS=work/refs
LOG=work/logs/debian-archive.log
mkdir -p "$WORK" data work/logs
FAILURES=()

# suite|php XY|suite tag N
SUITES=(
  "stretch|7.0|9"
  "buster|7.3|10"
  "bullseye|7.4|11"
  "bookworm|8.2|12"
  "trixie|8.4|13"
)

fetch() { # url dest
  local url=$1 dest=$2
  [ -s "$dest" ] && return 0
  echo "fetch $(basename "$dest")"
  curl -fsSL --max-time 600 -o "$dest" "$url" || {
    echo "ERROR: fetch failed: $url" >&2; rm -f "$dest"; return 1;
  }
}

extract_deb() { # deb dir
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

for row in "${SUITES[@]}"; do
  IFS='|' read -r suite php n <<<"$row"
  tag="deb${n}u"
  src="php${php}"
  echo "=== $suite ($src) ===" | tee -a "$LOG"

  # all source versions snapshot knows for this source package
  vers=$(curl -fsSL --max-time 120 "https://snapshot.debian.org/mr/package/${src}/" |
    jq -r '.result[].version') || { echo "ERROR: version list fetch failed for $src" | tee -a "$LOG" >&2; continue; }

  for v in $vers; do
    # suite filter (see header): tagged for this suite, or untagged with
    # matching major.minor; anything tagged for another suite or bpo skips
    case $v in
      *"$tag"*) ;;
      *deb[0-9]*|*bpo*) continue ;;
      "$php."*) ;;
      *) continue ;;
    esac
    upver=${v%%-*}
    for pkg in "libapache2-mod-php${php}" "php${php}-fpm" "php${php}-cgi"; do
      case $pkg in
        libapache2-*) sapi=apache; bname=libphp ;;
        *-fpm)        sapi=fpm;   bname=php-fpm ;;
        *-cgi)        sapi=cgi;   bname=php ;;
      esac
      out_json="data/debian-${suite}-php-${v}-${sapi}-${bname}-${ARCH}.json"
      [ -f "$out_json" ] && continue

      # per-version HTML page -> archive URLs for this binary
      page="$WORK/page-${src}-${v}.html"
      fetch "https://snapshot.debian.org/package/${src}/${v}/" "$page" || { FAILURES+=("$src $v $sapi"); continue; }
      # the href version token is percent-encoded; anchor on the binary
      # name and take every archive copy, debian/debian-security first
      urls=$(grep -oE 'href="/archive/(debian|debian-security)/[^"]*"' \
        "$page" | sed 's/^href="//;s/"$//' |
        grep -E "/${pkg}_[^/]*_amd64\.deb$" | head -3)
      [ -n "$urls" ] || { echo "  no amd64 deb for $pkg $v on the snapshot page" | tee -a "$LOG"; continue; }

      deb="$WORK/${pkg}_${v}_amd64.deb"
      ok=0
      while IFS= read -r u; do
        fetch "https://snapshot.debian.org${u}" "$deb" && { ok=1; break; }
      done <<<"$urls"
      [ $ok = 1 ] || { echo "  ERROR: all archive copies failed for $pkg $v" | tee -a "$LOG"; FAILURES+=("$pkg $v"); continue; }

      xdir="$WORK/extract/${pkg}_${v}"
      [ -d "$xdir/usr" ] || extract_deb "$deb" "$xdir" || { FAILURES+=("$pkg $v"); continue; }
      case $pkg in
        libapache2-*) bin="$xdir/usr/lib/apache2/modules/libphp${php}.so"
                      bp="/usr/lib/apache2/modules/libphp${php}.so"; bt=shared-libphp ;;
        *-fpm)        bin="$xdir/usr/sbin/php-fpm${php}"
                      bp="/usr/sbin/php-fpm${php}"; bt=static-pie ;;
        *-cgi)        bin="$xdir/usr/lib/cgi-bin/php${php}"
                      bp="/usr/lib/cgi-bin/php${php}"; bt=static-pie ;;
      esac
      [ -f "$bin" ] || { echo "ERROR: binary not found: $bin" >&2; FAILURES+=("$pkg $v"); continue; }

      ref="$REFS/debian-${suite}-${sapi}.merged"
      meta=$(jq -nc --arg pv "$upver" --arg pkg "${pkg}_${v}" --arg bp "$bp" --arg bt "$bt" \
        --arg distro "debian-${suite}" --arg arch "$ARCH" \
        '{php_version:$pv, thread_safety:"NTS", arch:$arch, distro:$distro,
          package:$pkg, binary_path:$bp, binary_type:$bt}')
      if python3 scripts/extract_symbols.py --binary "$bin" \
          --reference-binary "$ref" --allow-missing-tier-a \
          --meta "$meta" --out "$out_json" >> "$LOG" 2>&1; then
        echo "  ok: $out_json" | tee -a "$LOG"
      else
        echo "  FAIL: $out_json" | tee -a "$LOG"; FAILURES+=("$out_json")
      fi
    done
  done
done

echo "debian archive pass complete: $(ls data/debian-*.json 2>/dev/null | wc -l) debian rows" | tee -a "$LOG"
if [ "${#FAILURES[@]}" -gt 0 ]; then
  echo "FAILURES:" | tee -a "$LOG" >&2
  printf '  %s\n' "${FAILURES[@]}" | tee -a "$LOG" >&2
  exit 1
fi
