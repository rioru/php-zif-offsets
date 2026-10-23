#!/usr/bin/env bash
# Sweep EVERY historical backport revision of the Ubuntu php packages
# via the Launchpad publishing API - binaries only, no -dbgsym download.
#
# The stripped binaries are processed with the no-debug-info pipeline
# (dynsym exports + R_X86_64_RELATIVE relocation scan + pointer scan +
# GOT disassembly), and the local/static-symbol gaps are recovered by
# masked pattern matching against work/refs/ubuntu-<suite>-<sapi>.merged
# (the CURRENT version's binary + its ddeb symtab fused with eu-unstrip;
# built by scripts/build_refs.sh). Pattern hits are call-annotation
# verified; unverified symbols stay null with a note.
#
# Launchpad API route:
#   getPublishedSources?source_name=<src>&distro_series=<series>  ->
#   every source publication ever (paged, 75/page) -> dedupe by
#   version, skip Proposed-only -> <sourcepub>?ws.op=binaryFileUrls ->
#   every binary file of that publication -> filter amd64 .deb.
#
# Requires: curl, ar, tar (xz/zstd), readelf, python3, jq.
set -uo pipefail
cd "$(dirname "$0")/.."
WORK=work/ubuntu-archive
ARCH="${ARCH:-x86_64}"
REFS=work/refs
LOG=work/logs/ubuntu-archive.log
API="https://api.launchpad.net/1.0"
mkdir -p "$WORK" data work/logs
FAILURES=()

# suite|php XY
SUITES=(
  "focal|7.4"
  "bionic|7.2"
  "xenial|7.0"
  "jammy|8.1"
  "noble|8.3"
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
  IFS='|' read -r suite php <<<"$row"
  src="php${php}"
  echo "=== $suite ($src) ===" | tee -a "$LOG"

  # page through every source publication of this source package in
  # this suite; keep the first sourcepub per version (skip Proposed)
  pubs="$WORK/${src}-${suite}-pubs.tsv"
  {
    url="${API}/ubuntu/+archive/primary?ws.op=getPublishedSources&source_name=${src}&exact_match=true&distro_series=${API}/ubuntu/${suite}"
    while [ -n "$url" ]; do
      json=$(curl -fsSL --max-time 120 "$url") || { echo "ERROR: getPublishedSources failed at $url" >&2; break; }
      jq -r '.entries[] | select(.pocket != "Proposed") |
             [.source_package_version, .self_link] | @tsv' <<<"$json"
      url=$(jq -r '.next_collection_link // empty' <<<"$json")
    done
  } > "$pubs"
  # dedupe by version, newest publications first
  vers=$(awk -F'\t' '!seen[$1]++ {print $1}' "$pubs")
  echo "  $(echo "$vers" | wc -l) distinct versions" | tee -a "$LOG"

  while IFS=$'\t' read -r v publink; do
    [ -z "$v" ] && continue
    upver=${v%%-*}
    for pkg in "libapache2-mod-php${php}" "php${php}-fpm"; do
      case $pkg in
        libapache2-*) sapi=apache; bname=libphp ;;
        *-fpm)        sapi=fpm;   bname=php-fpm ;;
      esac
      out_json="data/ubuntu-${suite}-php-${v}-${sapi}-${bname}-${ARCH}.json"
      [ -f "$out_json" ] && continue

      # every binary file of this source publication; keep the amd64 deb
      deb_url=$(curl -fsSL --max-time 120 "${publink}?ws.op=binaryFileUrls" |
        jq -r '.[]' | grep -E "/${pkg}_[^/]*_amd64\.deb$" | head -1)
      [ -n "$deb_url" ] || { echo "  no amd64 deb for $pkg $v" | tee -a "$LOG"; continue; }

      deb="$WORK/${pkg}_${v}_amd64.deb"
      fetch "$deb_url" "$deb" || { FAILURES+=("$pkg $v"); continue; }
      xdir="$WORK/extract/${pkg}_${v}"
      [ -d "$xdir/usr" ] || extract_deb "$deb" "$xdir" || { FAILURES+=("$pkg $v"); continue; }
      case $pkg in
        libapache2-*) bin="$xdir/usr/lib/apache2/modules/libphp${php}.so"
                      bp="/usr/lib/apache2/modules/libphp${php}.so"; bt=shared-libphp ;;
        *-fpm)        bin="$xdir/usr/sbin/php-fpm${php}"
                      bp="/usr/sbin/php-fpm${php}"; bt=static-pie ;;
      esac
      [ -f "$bin" ] || { echo "ERROR: binary not found: $bin" >&2; FAILURES+=("$pkg $v"); continue; }

      ref="$REFS/ubuntu-${suite}-${sapi}.merged"
      meta=$(jq -nc --arg pv "$upver" --arg pkg "${pkg}_${v}" --arg bp "$bp" --arg bt "$bt" \
        --arg distro "ubuntu-${suite}" --arg arch "$ARCH" \
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
  done < <(awk -F'\t' '!seen[$1]++' "$pubs")
done

echo "ubuntu archive pass complete: $(ls data/ubuntu-*.json 2>/dev/null | wc -l) ubuntu rows" | tee -a "$LOG"
if [ "${#FAILURES[@]}" -gt 0 ]; then
  echo "FAILURES:" | tee -a "$LOG" >&2
  printf '  %s\n' "${FAILURES[@]}" | tee -a "$LOG" >&2
  exit 1
fi
