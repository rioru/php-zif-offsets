#!/usr/bin/env bash
# Regenerate docker-library/php rows for EVERY exact patch-release tag that
# Docker Hub still serves (5.3.29 ... 8.5.x), all SAPIs available per tag.
#
# This is the "all versions" pass: docker.sh (floating tags) covered only the
# latest patch release per minor; this script sweeps every historical patch
# release that is still pullable.
#
# Pull path per tag (the Docker Hub anonymous limit is 100 manifest GETs/h):
#   1. mirror.gcr.io/library/php          (Google's Hub cache, free)
#   2. public.ecr.aws/docker/library/php  (AWS's Hub cache, free)
#   3. raw registry v1 fallback           (schema-v1 tags, 2014-2016 era:
#                                          containerd refuses their manifest;
#                                          v1 manifest GET counts 1, layer
#                                          blobs are free via the CDN)
#   4. docker.io/library/php              (counts; paced with HUB_SLEEP)
#
# The apache modules (libphp*.so) are the only unstripped binaries in these
# images. They are fetched first and kept as --reference-binary for the
# stripped fpm/cli executables of the same version (extract_symbols.py
# recovery ladder: dynsym -> reloc trick -> pattern match -> call anchors).
#
# Resumable: existing data/ rows are skipped. Per-tag outcome goes to
# work/logs/docker-all-<minor>.log; failed tags are retried on the next run.
#
# Usage: docker_all_versions.sh [minor ...]   default: 5.4 5.5 5.6 7.0 ... 8.5
# Env:   HUB_SLEEP=40   pause after each Docker-Hub-served tag (rate limit)
#        ARCH=x86_64    ELF arch recorded in meta and in the row filename.
#                      A future aarch64 pass also needs platform-aware pulls
#                      (docker pull --platform linux/arm64; for the raw v1/v2
#                      registry rungs, manifest-list platform selection).
set -uo pipefail
cd "$(dirname "$0")/.."
WORK=work/docker-all
LOGS=work/logs
HUB_SLEEP="${HUB_SLEEP:-40}"
ARCH="${ARCH:-x86_64}"
MIRROR=mirror.gcr.io/library/php
ECR=public.ecr.aws/docker/library/php
HUB=docker.io/library/php
EMPTY_LAYER=sha256:a3ed95caeb02ffe68cdd9fd84406680ae93d633cb16422d00e8a7c22955b46d4
mkdir -p "$WORK" "$LOGS" data

# --- tag list (cached; fetched from the registry only when missing) ---------
TAGS="$WORK/tags.txt"
fetch_tag_list() {
  local tok url last
  tok=$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/php:pull" | jq -r .token)
  : > "$TAGS"
  url="https://registry-1.docker.io/v2/library/php/tags/list?n=10000"
  while [ -n "$url" ]; do
    curl -s -H "Authorization: Bearer $tok" "$url" | jq -r '.tags[]?' >> "$TAGS"
    last=$(tail -1 "$TAGS")
    [ "$(wc -l < "$TAGS")" -lt 10000 ] && break
    url="https://registry-1.docker.io/v2/library/php/tags/list?last=${last}&n=10000"
  done
}
[ -s "$TAGS" ] || fetch_tag_list

# --- helpers -----------------------------------------------------------------
# Apache module candidates: 2014-2016 era images build httpd from source
# (/usr/local/apache2/modules); later images use debian's apache2
# (/usr/lib/apache2/modules). Both are tried, in order.
binpaths() { # <minor> <sapi> -> candidate member paths, one per line
  local minor="$1" sapi="$2" mod
  case "$sapi" in
    apache)
      case "$minor" in
        5.*) mod=libphp5.so;;
        7.*) mod=libphp7.so;;
        *)   mod=libphp.so;;
      esac
      echo "/usr/lib/apache2/modules/$mod"
      echo "/usr/local/apache2/modules/$mod";;
    fpm) echo /usr/local/sbin/php-fpm;;
    cli) echo /usr/local/bin/php;;
  esac
}
bintype() { case "$1" in apache) echo shared-libphp;; *) echo static-pie;; esac; }
suffix()   { case "$1" in apache) echo libphp;; fpm) echo php-fpm;; cli) echo php;; esac; }
has_symtab() { readelf -SW "$1" 2>/dev/null | grep '\.symtab' > /dev/null; }

tag_for() { # <ver> <sapi> -> exact docker tag ("" when unavailable)
  local ver="$1" sapi="$2"
  case "$sapi" in
    cli) if grep -qx "${ver}-cli" "$TAGS"; then echo "${ver}-cli";
         elif grep -qx "$ver" "$TAGS"; then echo "$ver";
         else echo ""; fi;;
    *)   if grep -qx "${ver}-${sapi}" "$TAGS"; then echo "${ver}-${sapi}"; else echo ""; fi;;
  esac
}

fetch_via_docker() { # <ref> <members...> <out> - one pull, try each member
  local ref="$1"; shift
  local out="${@: -1}"; set -- "${@:1:$#-1}"
  local cid member
  docker pull -q "$ref" >/dev/null 2>&1 || return 1
  cid=$(docker create "$ref" 2>/dev/null) || { docker rmi "$ref" >/dev/null 2>&1 || true; return 1; }
  for member in "$@"; do
    if docker cp "$cid:$member" "$out" 2>/dev/null && [ -s "$out" ]; then
      docker rm "$cid" >/dev/null 2>&1 || true
      docker rmi "$ref" >/dev/null 2>&1 || true
      FETCH_MEMBER="$member"
      return 0
    fi
  done
  docker rm "$cid" >/dev/null 2>&1 || true
  docker rmi "$ref" >/dev/null 2>&1 || true
  return 1
}

fetch_via_v1() { # <tag> <members...> <out> - schema-v1 raw registry fallback
  local tag="$1"; shift
  local out="${@: -1}"; set -- "${@:1:$#-1}"
  local tok m sum tmp xdir member want
  tok=$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/php:pull" | jq -r .token)
  m="$WORK/v1-manifest.json"; tmp="$WORK/v1-blob.tgz"; xdir="$WORK/v1x"
  curl -s -H "Authorization: Bearer $tok" -H "Accept: application/vnd.docker.distribution.manifest.v1+prettyjws" \
    "https://registry-1.docker.io/v2/library/php/manifests/$tag" -o "$m"
  jq -e '.fsLayers' "$m" >/dev/null 2>&1 || { rm -f "$m"; return 1; }  # not a schema-v1 tag
  while read -r sum; do
    [ "$sum" = "$EMPTY_LAYER" ] && continue
    curl -sL -H "Authorization: Bearer $tok" "https://registry-1.docker.io/v2/library/php/blobs/$sum" -o "$tmp" || continue
    # NB: no `grep -q` on pipes here - its early exit SIGPIPEs tar and
    # pipefail turns the pipeline false despite the match.
    listing=$(tar -tzf "$tmp" 2>/dev/null) || continue
    for want in "$@"; do
      want="${want#/}"
      if grep -qx "$want" <<< "$listing"; then
        rm -rf "$xdir"; mkdir -p "$xdir"
        tar -xzf "$tmp" -C "$xdir" "$want" 2>/dev/null || { rm -rf "$xdir" "$tmp" "$m"; return 1; }
        mv "$xdir/$want" "$out" && rm -rf "$xdir" "$tmp" "$m" && FETCH_MEMBER="/$want" && return 0
      fi
    done
  done < <(jq -r '.fsLayers[].blobSum' "$m")
  rm -f "$tmp" "$m"
  return 1
}

FETCH_PATH=""; FETCH_MEMBER=""
fetch_via_v2raw() { # <tag> <members...> <out> - schema-v2 raw registry fallback
  local tag="$1"; shift
  local out="${@: -1}"; set -- "${@:1:$#-1}"
  local tok m sum tmp xdir member want
  tok=$(curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/php:pull" | jq -r .token)
  m="$WORK/v2-manifest.json"; tmp="$WORK/v2-blob.tgz"; xdir="$WORK/v2x"
  curl -s -H "Authorization: Bearer $tok" -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
    "https://registry-1.docker.io/v2/library/php/manifests/$tag" -o "$m"
  jq -e '.layers' "$m" >/dev/null 2>&1 || { rm -f "$m"; return 1; }  # not a schema-v2 tag
  while read -r sum; do
    [ "$sum" = "$EMPTY_LAYER" ] && continue
    curl -sL -H "Authorization: Bearer $tok" "https://registry-1.docker.io/v2/library/php/blobs/$sum" -o "$tmp" || continue
    listing=$(tar -tzf "$tmp" 2>/dev/null) || continue
    for want in "$@"; do
      want="${want#/}"
      if grep -qx "$want" <<< "$listing"; then
        rm -rf "$xdir"; mkdir -p "$xdir"
        tar -xzf "$tmp" -C "$xdir" "$want" 2>/dev/null || { rm -rf "$xdir" "$tmp" "$m"; return 1; }
        mv "$xdir/$want" "$out" && rm -rf "$xdir" "$tmp" "$m" && FETCH_MEMBER="/$want" && return 0
      fi
    done
  done < <(jq -r '.layers[].digest' "$m")
  rm -f "$tmp" "$m"
  return 1
}

fetch_binary() { # <tag> <members...> <out>  (last arg = output file)
  local tag="$1"; shift
  local out="${@: -1}"; set -- "${@:1:$#-1}"
  FETCH_PATH=""; FETCH_MEMBER=""
  if fetch_via_docker "$MIRROR:$tag" "$@" "$out"; then FETCH_PATH=mirror; return 0; fi
  if fetch_via_docker "$ECR:$tag" "$@" "$out";   then FETCH_PATH=ecr;    return 0; fi
  if fetch_via_v1 "$tag" "$@" "$out";            then FETCH_PATH=hub-v1; FETCH_MEMBER="$FETCH_MEMBER"; sleep "$HUB_SLEEP"; return 0; fi
  if fetch_via_v2raw "$tag" "$@" "$out";         then FETCH_PATH=hub-v2raw; FETCH_MEMBER="$FETCH_MEMBER"; sleep "$HUB_SLEEP"; return 0; fi
  if fetch_via_docker "$HUB:$tag" "$@" "$out";   then FETCH_PATH=hub;    sleep "$HUB_SLEEP"; return 0; fi
  return 1
}

process_row() { # <ver> <sapi> <binfile> <member> <ref> <logfile>
  local ver="$1" sapi="$2" binfile="$3" member="$4" ref="$5" log="$6"
  local minor="${ver%.*}"
  local out="data/docker-php-${ver}-${sapi}-$(suffix "$sapi")-${ARCH}.json"
  if [ -f "$out" ]; then echo "  skip (row exists): $out" >> "$log"; return 0; fi
  local meta
  meta=$(jq -nc --arg pv "$ver" --arg pkg "php:${ver}-${sapi}" --arg bp "$member" --arg bt "$(bintype "$sapi")" --arg arch "$ARCH" \
    '{php_version:$pv, thread_safety:"NTS", arch:$arch, distro:"docker-library/php",
      package:$pkg, binary_path:$bp, binary_type:$bt}')
  local args=(--binary "$binfile" --meta "$meta" --out "$out")
  # zend_reference_destroy exists upstream only from php 7.3; zval_ptr_dtor
  # is exported as _zval_ptr_dtor before 7.3 (extractor alias handles it).
  case "$minor" in 5.*|7.0|7.1|7.2) args+=(--allow-missing-tier-a);; esac
  if ! has_symtab "$binfile"; then
    args+=(--allow-missing-tier-a)
    if [ -n "$ref" ] && [ -f "$ref" ]; then args+=(--reference-binary "$ref"); fi
  fi
  if python3 scripts/extract_symbols.py "${args[@]}" >> "$log" 2>&1; then
    local missing
    missing=$(jq -r '[.exploit | to_entries[] | select(.value == null) | .key] | length' "$out" 2>/dev/null)
    echo "  ok: $out (via $FETCH_PATH, tier_a_nulls=$missing)" >> "$log"
    return 0
  else
    echo "  EXTRACTOR FAILED: $ver $sapi (via $FETCH_PATH)" >> "$log"
    rm -f "$out"
    return 1
  fi
}

run_minor() { # <minor>
  local minor="$1"
  local log="$LOGS/docker-all-${minor}.log"
  local dir="$WORK/$minor"
  mkdir -p "$dir"
  echo "=== minor $minor $(date -Is) ===" >> "$log"

  local versions=()
  while read -r v; do versions+=("$v"); done < <(grep -E "^${minor}\.[0-9]+-apache$" "$TAGS" | sed 's/-apache$//' | sort -V)
  [ "${#versions[@]}" -gt 0 ] || { echo "  no apache tags for $minor" >> "$log"; return 0; }

  # pass 1: apache binaries (the unstripped references), kept for the minor
  local ver tag bp binfile members=()
  local have_apache=()
  for ver in "${versions[@]}"; do
    tag="${ver}-apache"; binfile="$dir/apache-${ver}.so"
    if [ ! -s "$binfile" ]; then
      mapfile -t members < <(binpaths "$minor" apache)
      if ! fetch_binary "$tag" "${members[@]}" "$binfile"; then
        echo "  FETCH FAILED: $tag" >> "$log"; continue
      fi
      echo "$FETCH_MEMBER" > "$dir/apache-${ver}.member"
      echo "  fetched $tag via $FETCH_PATH ($FETCH_MEMBER)" >> "$log"
    fi
    have_apache+=("$ver")
  done

  # pass 2: apache rows (reference = nearest unstripped apache of the minor)
  local ref="" r member
  for ver in "${have_apache[@]}"; do
    binfile="$dir/apache-${ver}.so"; [ -s "$binfile" ] || continue
    ref=""
    if ! has_symtab "$binfile"; then
      for r in "${have_apache[@]}"; do
        [ -s "$dir/apache-$r.so" ] && has_symtab "$dir/apache-$r.so" && { ref="$dir/apache-$r.so"; break; }
      done
    fi
    member=$(cat "$dir/apache-${ver}.member" 2>/dev/null || binpaths "$minor" apache | head -1)
    process_row "$ver" apache "$binfile" "$member" "$ref" "$log" || true
  done

  # pass 3+4: fpm and cli rows (reference = same-version apache)
  local sapi
  for sapi in fpm cli; do
    for ver in "${have_apache[@]}"; do
      tag=$(tag_for "$ver" "$sapi"); [ -n "$tag" ] || { echo "  no tag: $ver $sapi" >> "$log"; continue; }
      binfile="$dir/${sapi}-${ver}-bin"
      mapfile -t members < <(binpaths "$minor" "$sapi")
      if ! fetch_binary "$tag" "${members[@]}" "$binfile"; then
        echo "  FETCH FAILED: $tag" >> "$log"; continue
      fi
      ref="$dir/apache-${ver}.so"; [ -s "$ref" ] || ref=""
      process_row "$ver" "$sapi" "$binfile" "$FETCH_MEMBER" "$ref" "$log" || true
      rm -f "$binfile"
    done
  done

  # keep the apache references for possible re-runs; disk is cheap
  echo "=== minor $minor done: $(ls data/docker-php-${minor}.*.json 2>/dev/null | wc -l) rows for $minor ===" >> "$log"
}

MINORS=("$@")
[ "${#MINORS[@]}" -eq 0 ] && MINORS=(5.4 5.5 5.6 7.0 7.1 7.2 7.3 7.4 8.0 8.1 8.2 8.3 8.4 8.5)
for m in "${MINORS[@]}"; do
  run_minor "$m"
done
echo "docker_all_versions complete: $(ls data/docker-php-*.json | wc -l) docker rows total"
