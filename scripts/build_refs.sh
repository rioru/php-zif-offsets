#!/usr/bin/env bash
# Build the merged-ELF pattern references for the archive sweeps.
#
# For every (family, suite, SAPI) the CURRENT version's binary is fused
# with its -dbgsym symtab via eu-unstrip; the result has the real .text
# plus every LOCAL symbol, so extract_symbols.py --reference-binary can
# pattern-match older stripped builds of the same suite against it.
# The current binaries + debug files come from the regular
# ubuntu.sh/debian.sh passes (work/<family>/extract, work/debuginfo).
set -uo pipefail
cd "$(dirname "$0")/.."
mkdir -p work/refs

build_ref() { # out bin dbg
  local out=$1 bin=$2 dbg=$3
  [ -f "$out" ] && { echo "exists $out"; return 0; }
  [ -f "$bin" ] || { echo "ERROR: binary missing: $bin" >&2; return 1; }
  [ -f "$dbg" ] || { echo "ERROR: debug file missing: $dbg" >&2; return 1; }
  eu-unstrip "$bin" "$dbg" -o "$out" || { echo "ERROR: eu-unstrip failed for $bin" >&2; return 1; }
  echo "built $out"
}

for s in focal:7.4 bionic:7.2 xenial:7.0 jammy:8.1 noble:8.3; do
  suite=${s%%:*}; php=${s##*:}
  build_ref "work/refs/ubuntu-${suite}-apache.merged" \
    "work/ubuntu/extract/libapache2-mod-php${php}/usr/lib/apache2/modules/libphp${php}.so" \
    "work/debuginfo/ubuntu-${suite}-libapache2-mod-php${php}.debug"
  build_ref "work/refs/ubuntu-${suite}-fpm.merged" \
    "work/ubuntu/extract/php${php}-fpm/usr/sbin/php-fpm${php}" \
    "work/debuginfo/ubuntu-${suite}-php${php}-fpm.debug"
done

for s in bookworm:8.2 trixie:8.4 bullseye:7.4 buster:7.3 stretch:7.0; do
  suite=${s%%:*}; php=${s##*:}
  build_ref "work/refs/debian-${suite}-apache.merged" \
    "work/debian/extract/libapache2-mod-php${php}/usr/lib/apache2/modules/libphp${php}.so" \
    "work/debuginfo/debian-${suite}-libapache2-mod-php${php}.debug"
  build_ref "work/refs/debian-${suite}-fpm.merged" \
    "work/debian/extract/php${php}-fpm/usr/sbin/php-fpm${php}" \
    "work/debuginfo/debian-${suite}-php${php}-fpm.debug"
  build_ref "work/refs/debian-${suite}-cgi.merged" \
    "work/debian/extract/php${php}-cgi/usr/lib/cgi-bin/php${php}" \
    "work/debuginfo/debian-${suite}-php${php}-cgi.debug"
done
