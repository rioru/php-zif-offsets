#!/usr/bin/env bash
# Regenerate Fedora rows for EVERY historical php build in koji that
# carries an fc28..fc43 release tag (the php 7.2 ... 8.5 era; pre-fc28
# Fedora used a different subpackage split and is future work).
#
# Binaries-only (no debug packages for the rows): php-cli / php-fpm
# RPMs from kojipkgs.fedoraproject.org. Local symbols are recovered by
# masked pattern match against a merged reference build: per (release,
# major.minor, SAPI) the newest build of that major.minor in that
# release, fused with its debuginfo symtab via eu-unstrip
# (work/refs/fedora-<NN>-<majmin>-<sapi>.merged) - the same scheme as
# the debian/ubuntu archive sweeps. The reference build's own row is
# also pattern-matched against its merged ref (exact code match).
#
# Resumable: existing data/ rows are skipped; RPMs and directory
# listings are cached under work/fedora-archive/.
#
# Requires: curl, rpm2cpio, cpio, readelf, eu-unstrip, python3, jq.
# Env: ARCH=x86_64   ELF arch recorded in meta and the row filename.
set -uo pipefail
cd "$(dirname "$0")/.."
WORK=work/fedora-archive
REFS=work/refs
LOG=work/logs/fedora-archive.log
ARCH="${ARCH:-x86_64}"
BASE=https://kojipkgs.fedoraproject.org/packages/php
mkdir -p "$WORK" "$REFS" data work/logs
FAILURES=()

fetch() { # url dest
  local url=$1 dest=$2
  [ -s "$dest" ] && return 0
  echo "fetch $(basename "$dest")"
  curl -fsSL --max-time 600 -o "$dest" "$url" || {
    echo "ERROR: fetch failed: $url" >&2; rm -f "$dest"; return 1;
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

# --- enumerate builds: ver|rel|NN lines for fc28..fc43 ------------------------
VERS="$WORK/versions.txt"
BUILDS="$WORK/builds.txt"
if [ ! -s "$BUILDS" ]; then
  [ -s "$VERS" ] || curl -fsSL --max-time 120 "$BASE/" |
    grep -oE 'href="[0-9][0-9.]+/"' | sed 's/href="//;s#/"##' |
    sort -V | awk '$0 >= "7.2"' > "$VERS" || { echo "ERROR: version list fetch failed" >&2; exit 1; }
  : > "$BUILDS"
  while read -r v; do
    curl -fsSL --max-time 120 "$BASE/$v/" |
      grep -oE 'href="[0-9.]+\.fc[0-9]+/"' | sed 's/href="//;s#/"##' |
      grep -E '\.fc(2[89]|3[0-9]|4[0-3])$' | while read -r rel; do
        echo "$v|$rel|${rel##*.fc}" >> "$BUILDS"
      done
    echo "listed $v ($(wc -l < "$BUILDS") builds so far)" | tee -a "$LOG"
  done < "$VERS"
fi
echo "$(wc -l < "$BUILDS") fc28+ builds enumerated" | tee -a "$LOG"

# --- reference builds: newest (ver, rel) per (NN, major.minor) ---------------
# sorted builds -> last line per group is the newest
REFLIST="$WORK/refbuilds.txt"
sort -t'|' -k3,3n -k1,1V -k2,2V "$BUILDS" |
  awk -F'|' '{ mm=$1; sub(/\.[0-9]+$/, "", mm); key=$3"|"mm; last[key]=$1"|"$2"|"$3 } END { for (k in last) print last[k] }' > "$REFLIST"
echo "$(wc -l < "$REFLIST") reference builds" | tee -a "$LOG"

build_ref() { # nn majmin ver rel sapi
  local nn=$1 mm=$2 ver=$3 rel=$4 sapi=$5
  local ref="$REFS/fedora-${nn}-${mm}-${sapi}.merged"
  [ -f "$ref" ] && return 0
  local list="$WORK/list-${ver}-${rel}.txt"
  fetch "$BASE/$ver/$rel/x86_64/" "$list" || { echo "ERROR: listing fetch failed for $ver-$rel" | tee -a "$LOG" >&2; return 1; }
  local binrpm dbg_rpm dbg_rpm2
  case $sapi in
    cli) binrpm=$(sed 's/href="//;s/"//' "$list" | grep -oE "php-cli-${ver//./\\.}-${rel//./\\.}\.x86_64\.rpm" | head -1) ;;
    fpm) binrpm=$(sed 's/href="//;s/"//' "$list" | grep -oE "php-fpm-${ver//./\\.}-${rel//./\\.}\.x86_64\.rpm" | head -1) ;;
  esac
  [ -n "$binrpm" ] || { echo "ERROR: no $sapi RPM for $ver-$rel" | tee -a "$LOG" >&2; return 1; }
  # per-subpackage debuginfo first, collection php-debuginfo as fallback
  dbg_rpm=${binrpm/php-cli-/php-cli-debuginfo-}; dbg_rpm=${dbg_rpm/php-fpm-/php-fpm-debuginfo-}
  dbg_rpm2=${binrpm/php-cli-/php-debuginfo-}; dbg_rpm2=${dbg_rpm2/php-fpm-/php-debuginfo-}
  local xdir="$WORK/extract/${binrpm%.rpm}" gdir="$WORK/extract/dbg-${ver}-${rel}-${sapi}"
  fetch "$BASE/$ver/$rel/x86_64/$binrpm" "$WORK/$binrpm" || return 1
  [ -f "$xdir/usr/bin/php" ] || [ -f "$xdir/usr/bin/php-fpm" ] || extract_rpm "$WORK/$binrpm" "$xdir" || return 1
  if [ ! -d "$gdir/usr/lib/debug" ]; then
    if fetch "$BASE/$ver/$rel/x86_64/$dbg_rpm" "$WORK/$dbg_rpm"; then
      extract_rpm "$WORK/$dbg_rpm" "$gdir" || return 1
      # the collection php-debuginfo carries the shared dwz alternate
      fetch "$BASE/$ver/$rel/x86_64/$dbg_rpm2" "$WORK/$dbg_rpm2" && extract_rpm "$WORK/$dbg_rpm2" "$gdir" || true
    elif fetch "$BASE/$ver/$rel/x86_64/$dbg_rpm2" "$WORK/$dbg_rpm2"; then
      extract_rpm "$WORK/$dbg_rpm2" "$gdir" || return 1
    else
      echo "ERROR: no debuginfo RPM for $ver-$rel ($sapi ref)" | tee -a "$LOG" >&2; return 1
    fi
  fi
  local bin bid dbg
  # php-fpm moved from /usr/sbin (fc28..fc30) to /usr/bin (fc31+)
  case $sapi in
    cli) bin="$xdir/usr/bin/php" ;;
    fpm) bin="$xdir/usr/bin/php-fpm"; [ -f "$bin" ] || bin="$xdir/usr/sbin/php-fpm" ;;
  esac
  [ -f "$bin" ] || { echo "ERROR: binary not found: $bin" >&2; return 1; }
  bid=$(build_id_of "$bin")
  dbg="$gdir/usr/lib/debug/.build-id/${bid:0:2}/${bid:2}.debug"
  [ -f "$dbg" ] || { echo "ERROR: debug file for build-id $bid not found" | tee -a "$LOG" >&2; return 1; }
  eu-unstrip "$bin" "$dbg" -o "$ref" || { echo "ERROR: eu-unstrip failed for $bin" | tee -a "$LOG" >&2; return 1; }
  echo "built ref $ref" | tee -a "$LOG"
}

while IFS='|' read -r ver rel nn; do
  mm=${ver%.*}
  build_ref "$nn" "$mm" "$ver" "$rel" cli
  build_ref "$nn" "$mm" "$ver" "$rel" fpm
done < "$REFLIST"

# --- rows ----------------------------------------------------------------------
while IFS='|' read -r ver rel nn; do
  mm=${ver%.*}
  list="$WORK/list-${ver}-${rel}.txt"
  fetch "$BASE/$ver/$rel/x86_64/" "$list" || { FAILURES+=("$ver-$rel listing"); continue; }
  for sapi in cli fpm; do
    case $sapi in
      cli) bt=static-pie; suffix=cli-php;    binrpm_pat="php-cli-" ;;
      fpm) bt=static-pie; suffix=fpm-php-fpm; binrpm_pat="php-fpm-" ;;
    esac
    out_json="data/fedora-${nn}-php-${ver}-${rel}-${suffix}-${ARCH}.json"
    [ -f "$out_json" ] && continue
    binrpm=$(sed 's/href="//;s/"//' "$list" | grep -oE "${binrpm_pat}${ver//./\\.}-${rel//./\\.}\.x86_64\.rpm" | head -1)
    [ -n "$binrpm" ] || { echo "  no $sapi RPM for $ver-$rel" | tee -a "$LOG"; continue; }
    xdir="$WORK/extract/${binrpm%.rpm}"
    fetch "$BASE/$ver/$rel/x86_64/$binrpm" "$WORK/$binrpm" || { FAILURES+=("$binrpm"); continue; }
    # php-fpm moved from /usr/sbin (fc28..fc30) to /usr/bin (fc31+)
    case $sapi in
      cli)
        [ -f "$xdir/usr/bin/php" ] || extract_rpm "$WORK/$binrpm" "$xdir" || { FAILURES+=("$binrpm"); continue; }
        bp=/usr/bin/php ;;
      fpm)
        if [ ! -f "$xdir/usr/bin/php-fpm" ] && [ ! -f "$xdir/usr/sbin/php-fpm" ]; then
          extract_rpm "$WORK/$binrpm" "$xdir" || { FAILURES+=("$binrpm"); continue; }
        fi
        bp=/usr/bin/php-fpm; [ -f "$xdir$bp" ] || bp=/usr/sbin/php-fpm ;;
    esac
    bin="$xdir$bp"
    [ -f "$bin" ] || { echo "ERROR: binary not found: $bin" >&2; FAILURES+=("$binrpm"); continue; }
    ref="$REFS/fedora-${nn}-${mm}-${sapi}.merged"
    meta=$(jq -nc --arg pv "$ver" --arg pkg "${binrpm%.rpm}" --arg bp "$bp" --arg bt "$bt" \
      --arg distro "fedora-${nn}" --arg arch "$ARCH" \
      '{php_version:$pv, thread_safety:"NTS", arch:$arch, distro:$distro,
        package:$pkg, binary_path:$bp, binary_type:$bt}')
    args=(--binary "$bin" --meta "$meta" --out "$out_json")
    case $ver in 5.*|7.0.*|7.1.*|7.2.*) args+=(--allow-missing-tier-a);; esac
    [ -f "$ref" ] && args+=(--reference-binary "$ref")
    if python3 scripts/extract_symbols.py "${args[@]}" >> "$LOG" 2>&1; then
      echo "  ok: $out_json" | tee -a "$LOG"
    else
      echo "  FAIL: $out_json" | tee -a "$LOG"; FAILURES+=("$out_json")
    fi
  done
done < "$BUILDS"

echo "fedora archive pass complete: $(ls data/fedora-*.json 2>/dev/null | wc -l) fedora rows" | tee -a "$LOG"
if [ "${#FAILURES[@]}" -gt 0 ]; then
  echo "FAILURES:" | tee -a "$LOG" >&2
  printf '  %s\n' "${FAILURES[@]}" | tee -a "$LOG" >&2
  exit 1
fi
