#!/usr/bin/env python3
"""Audit every row in data/: classify each null offset.

A null is only acceptable if it is explained by one of:
- version-legit: the symbol does not exist in that PHP version
  (boundaries derived empirically from the docker-library rows, which
  span 5.3.29-8.5.x and include unstripped symtab builds that prove
  genuine absence).
- build-legit: the build type forces the null (ZTS TSRM indirection,
  Alpine shared session module, shared-extension rows).
- documented: the extractor recorded a recovery-failure note naming
  the symbol (pattern/call-anchor/storelea attempts that did not
  verify). These are honest "measured nothing" outcomes.
- best-effort: zend_mm_safe_error is static and usually inlined; it is
  null even in unstripped symtab builds at every version.

Anything else is UNEXPLAINED and fails the audit. The exit code is 1
when any unexplained null exists.

Usage: audit.py [--quiet]
"""

import argparse
import collections
import json
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
DATA = REPO / "data"

TIERS = ("exploit", "calibration", "fingerprint")

# (tier, field) -> minimum (major, minor) PHP version that has the symbol
VERSION_MIN = {
    ("exploit", "zend_reference_destroy"): (7, 3),
    ("exploit", "zend_array_destroy"): (7, 0),
    ("calibration", "zend_mm_alloc_pages"): (7, 0),
    ("calibration", "zend_mm_free_pages"): (7, 0),
    ("calibration", "zend_mm_gc"): (7, 0),
    ("calibration", "php_session_abort"): (7, 1),
    ("calibration", "php_rshutdown_session_globals"): (7, 2),
    ("calibration", "php_session_initialize"): (5, 4),
    ("calibration", "php_session_rfc1867_callback"): (5, 4),
}

# null even in unstripped builds at every version (static, usually inlined)
BEST_EFFORT = {("calibration", "zend_mm_safe_error")}

# ZTS builds: data globals sit behind TSRM indirection (the TSRM key
# ids are recorded in meta.notes instead)
ZTS_NULL_OK = {
    ("exploit", "ps_globals"),
    ("calibration", "alloc_globals"),
    ("calibration", "sapi_globals"),
    ("calibration", "executor_globals"),
    ("calibration", "core_globals"),
    ("calibration", "compiler_globals"),
}

# Alpine builds the session extension as a shared apk module: the
# session symbols live in the paired shared-ext row, not the SAPI binary
SESSION_FIELDS = {
    ("exploit", "ps_globals"),
    ("exploit", "ps_globals_id_offset"),
    ("calibration", "php_session_initialize"),
    ("calibration", "php_session_reset_id"),
    ("calibration", "php_session_create_id"),
    ("calibration", "ps_open_files"),
    ("calibration", "ps_close_files"),
    ("calibration", "php_rshutdown_session_globals"),
    ("calibration", "php_session_rfc1867_callback"),
    ("calibration", "php_session_abort"),
}

# shared-extension rows (Alpine session.so): only these may be non-null
SHARED_EXT_MAY_HAVE = {
    ("exploit", "ps_globals"),
    ("exploit", "ps_globals_id_offset"),
    ("calibration", "php_session_initialize"),
    ("calibration", "php_session_reset_id"),
    ("calibration", "php_session_create_id"),
    ("calibration", "ps_open_files"),
    ("calibration", "ps_close_files"),
    ("calibration", "php_rshutdown_session_globals"),
    ("calibration", "php_session_rfc1867_callback"),
}

# fields that must never be null outside shared-ext rows
REQUIRED = {
    ("exploit", "zif_system"),
    ("exploit", "zif_exec"),
    ("exploit", "zif_passthru"),
    ("exploit", "zif_shell_exec"),
    ("exploit", "zval_ptr_dtor"),
    ("exploit", "php_rfc1867_callback"),
    ("fingerprint", "zif_system_mod_0x1000"),
    ("fingerprint", "zval_ptr_dtor_mod_0x1000"),
    ("calibration", "_emalloc"),
    ("calibration", "_efree"),
    ("calibration", "_erealloc"),
    ("calibration", "php_hash_environment"),
    ("calibration", "php_request_startup"),
    ("calibration", "php_request_shutdown"),
    ("calibration", "php_url_encode"),
    ("calibration", "rfc1867_post_handler"),
    ("calibration", "sapi_add_header_ex"),
    ("calibration", "sapi_header_op"),
    ("calibration", "sapi_module"),
    ("calibration", "zend_llist_destroy"),
    ("calibration", "zend_mm_shutdown"),
}

NOTE_FAILURE_WORDS = ("fail", "missing", "not found")


def version_key(v):
    try:
        parts = [int(x) for x in v.split(".")[:2]]
    except ValueError:
        return (0, 0)
    return tuple(parts)


def note_explains(notes, tier, field):
    """A recovery-failure note naming the symbol explains the null."""
    base = field
    for n in notes or []:
        if base in n and any(w in n for w in NOTE_FAILURE_WORDS):
            return True
    return False


def classify(row, tier, field):
    """Return None if the value is fine, else the explanation class."""
    meta = row["meta"]
    val = row.get(tier, {}).get(field)
    if val is not None:
        return None
    key = (tier, field)
    if meta.get("binary_type") == "shared-ext":
        if key in SHARED_EXT_MAY_HAVE:
            return "shared-ext-absent"
        return "shared-ext"
    if key in BEST_EFFORT:
        return "best-effort"
    vmin = VERSION_MIN.get(key)
    if vmin and version_key(meta["php_version"]) < vmin:
        return "version-legit"
    if meta.get("thread_safety") == "ZTS" and key in ZTS_NULL_OK:
        return "zts-legit"
    if str(meta.get("distro", "")).startswith("alpine-") and key in SESSION_FIELDS:
        return "alpine-shared-session"
    if note_explains(meta.get("notes"), tier, field):
        return "documented-recovery-failure"
    return "UNEXPLAINED"


def audit():
    failures = []
    explained = collections.Counter()
    per_field = collections.defaultdict(collections.Counter)
    rows = 0
    build_id_nulls = []

    for path in sorted(DATA.glob("*.json")):
        rows += 1
        row = json.loads(path.read_text())
        meta = row["meta"]
        if meta.get("build_id") is None:
            if meta.get("distro") == "alpine-3.16":
                explained["build_id-alpine-3.16"] += 1
            else:
                build_id_nulls.append(path.name)
        for tier in TIERS:
            for field, val in row.get(tier, {}).items():
                cls = classify(row, tier, field)
                if cls is None:
                    continue
                if cls == "UNEXPLAINED":
                    failures.append((path.name, tier, field))
                else:
                    explained[cls] += 1
                    per_field[field][cls] += 1

    return rows, failures, explained, per_field, build_id_nulls


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--quiet", action="store_true", help="only print failures")
    args = ap.parse_args()

    rows, failures, explained, per_field, build_id_nulls = audit()

    if not args.quiet:
        print(f"rows audited: {rows}")
        print("explained nulls by class:")
        for cls, n in sorted(explained.items()):
            print(f"  {cls}: {n}")
    if build_id_nulls:
        print("UNEXPLAINED null build_id:")
        for name in build_id_nulls:
            print(f"  {name}")
    if failures:
        print(f"UNEXPLAINED nulls: {len(failures)}")
        by_field = collections.Counter(f for _, _, f in failures)
        for field, n in by_field.most_common():
            print(f"  {field}: {n}")
        for name, tier, field in failures:
            print(f"  {name}: {tier}.{field}")
        raise SystemExit(1)
    if not args.quiet:
        print("audit: OK (no unexplained nulls)")


if __name__ == "__main__":
    main()
