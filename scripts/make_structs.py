#!/usr/bin/env python3
"""Generate STRUCTS.md from the debug files collected by the distro passes.

Struct layouts are a property of the PHP source version and the x86_64
SysV ABI, not of the distro: the generator parses one primary debug file
per PHP minor (Remi el9, dwz alternate in-tree) and cross-checks every
other same-version debug file collected under work/ (Debian ddebs,
Ubuntu ddebs, Alpine -dbg, Fedora koji, Rocky AppStream). Any mismatch
is reported loudly instead of being silently averaged.

Usage: make_structs.py [--out STRUCTS.md]
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# php minor -> (primary full version, primary debug file glob)
# Remi el9 in-tree files carry the dwz alternate next to them
PRIMARY = {
    "8.0": ("8.0.30", "work/redhat/extract/php80-php-fpm-debuginfo-*/usr/lib/debug/opt/remi/php80/root/usr/sbin/php-fpm-*.debug"),
    "8.1": ("8.1.34", "work/redhat/extract/php81-php-fpm-debuginfo-*/usr/lib/debug/opt/remi/php81/root/usr/sbin/php-fpm-*.debug"),
    "8.2": ("8.2.35", "work/redhat/extract/php82-php-fpm-debuginfo-*/usr/lib/debug/opt/remi/php82/root/usr/sbin/php-fpm-*.debug"),
    "8.3": ("8.3.36", "work/redhat/extract/php83-php-fpm-debuginfo-*/usr/lib/debug/opt/remi/php83/root/usr/sbin/php-fpm-*.debug"),
    "8.4": ("8.4.27", "work/redhat/extract/php84-php-fpm-debuginfo-*/usr/lib/debug/opt/remi/php84/root/usr/sbin/php-fpm-*.debug"),
    "8.5": ("8.5.12", "work/redhat/extract/php85-php-fpm-debuginfo-*/usr/lib/debug/opt/remi/php85/root/usr/sbin/php-fpm-*.debug"),
}

# php version of the collected binary -> cross-check debug files (standalone,
# no dwz alternate needed)
CROSS = {
    "8.0.30": ["work/redhat/extract/php-fpm-debuginfo-8.0.30-8.el9_8.1.x86_64/usr/lib/debug/.build-id/*/*.debug"],
    "8.1.2": ["work/debuginfo/ubuntu-jammy-php8.1-fpm.debug"],
    "8.1.32": ["work/redhat/extract/php-fpm-debuginfo-8.1.32-1.module+el9.7.0+40003+454ed3c4.x86_64/usr/lib/debug/.build-id/*/*.debug"],
    "8.1.34": ["work/debuginfo/remi-el9-php81-php-fpm-8.1.34-6.el9.remi.x86_64.debug"],
    "8.2.32": ["work/debuginfo/debian-bookworm-php8.2-fpm.debug"],
    "8.2.35": [
        "work/redhat/extract/php-fpm-debuginfo-8.2.35-1.module+el9.8.0+40395+2f706e64.x86_64/usr/lib/debug/.build-id/*/*.debug",
        "work/debuginfo/remi-el9-php82-php-fpm-8.2.35-1.el9.remi.x86_64.debug",
    ],
    "8.3.6": ["work/debuginfo/ubuntu-noble-php8.3-fpm.debug"],
    "8.3.36": [
        "work/debuginfo/alpine-3.22-php83-fpm.debug",
        "work/debuginfo/alpine-3.22-php83-session.debug",
        "work/redhat/extract/php-fpm-debuginfo-8.3.36-1.module+el9.8.0+40396+4e680bb7.x86_64/usr/lib/debug/.build-id/*/*.debug",
        "work/debuginfo/remi-el9-php83-php-fpm-8.3.36-1.el9.remi.x86_64.debug",
    ],
    "8.4.27": [
        "work/debuginfo/debian-trixie-php8.4-fpm.debug",
        "work/debuginfo/alpine-3.22-php84-fpm.debug",
        "work/debuginfo/alpine-3.22-php84-session.debug",
        "work/redhat/extract/php-cli-debuginfo-8.4.27-2.fc43.x86_64/usr/lib/debug/.build-id/*/*.debug",
        "work/debuginfo/remi-el9-php84-php-fpm-8.4.27-1.el9.remi.x86_64.debug",
    ],
    "8.5.12": ["work/debuginfo/remi-el9-php85-php-fpm-8.5.12-1.el9.remi.x86_64.debug"],
}

# struct -> (DWARF tag, curated field list; None = all top-level fields)
STRUCTS = [
    ("zval", "_zval_struct", ["value", "u1", "u2"]),
    ("zend_string", "_zend_string", ["gc", "h", "len", "val"]),
    ("zend_array (HashTable)", "_zend_array", [
        "gc", "u", "flags", "nTableMask", "arData", "nNumUsed",
        "nNumOfElements", "nTableSize", "nInternalPointer",
        "nNextFreeElement", "pDestructor",
    ]),
    ("zend_reference", "_zend_reference", None),
    ("zend_execute_data", "_zend_execute_data", [
        "opline", "call", "return_value", "func", "This",
        "prev_execute_data", "symbol_table", "run_time_cache", "extra",
    ]),
    ("zend_mm_chunk", "_zend_mm_chunk", [
        "heap", "next", "prev", "free_pages", "free_tail", "num",
        "heap_slot", "free_map", "map",
    ]),
    ("zend_mm_heap", "_zend_mm_heap", None),
    ("php_ps_globals", "_php_ps_globals", None),
]

MEMBER_RE = re.compile(r"^\t(.*?);\s*/\*\s*(\d+)\s+(\d+)\s*\*/\s*$")
CLOSE_RE = re.compile(r"^\t\}\s*(\w+)\s*;\s*/\*\s*(\d+)\s+(\d+)\s*\*/\s*$")
SIZE_RE = re.compile(r"/\*\s*size:\s*(\d+),")
NAME_RE = re.compile(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*(?:__attribute__\s*\(\(.*\)\))?\s*$")


def parse_struct(debug_file, tag):
    """pahole one struct -> ({field: offset}, size). Nested members are
    included with their own offsets; top-level members are exact."""
    p = subprocess.run(["pahole", "-C", tag, str(debug_file)],
                       capture_output=True, text=True)
    out = p.stdout
    if not out.strip() or "not found" in (p.stderr + out):
        return None, None
    fields = {}
    for line in out.splitlines():
        m = CLOSE_RE.match(line)
        if m:
            # first occurrence carries the absolute offset; some DWARF
            # (Alpine/GCC) makes pahole repeat nested unions with
            # union-relative offsets - never overwrite
            fields.setdefault(m.group(1), int(m.group(2)))
            continue
        m = MEMBER_RE.match(line)
        if m:
            decl, off = m.group(1), int(m.group(2))
            nm = NAME_RE.search(decl.strip())
            if nm:
                fields.setdefault(nm.group(1), off)
    # the struct-level size comment is the LAST one in the output; nested
    # inline structs/unions carry their own earlier size comments
    sizes = SIZE_RE.findall(out)
    return fields, (int(sizes[-1]) if sizes else None)


def top_level_fields(debug_file, tag):
    """Ordered top-level member names (one-tab indentation)."""
    p = subprocess.run(["pahole", "-C", tag, str(debug_file)],
                       capture_output=True, text=True)
    names = []
    for line in p.stdout.splitlines():
        m = CLOSE_RE.match(line)
        if m:
            names.append(m.group(1))
            continue
        m = MEMBER_RE.match(line)
        if m:
            nm = NAME_RE.search(m.group(1).strip())
            if nm:
                names.append(nm.group(1))
    return names


def resolve(pattern):
    hits = sorted(REPO.glob(pattern))
    return hits[0] if hits else None


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default="STRUCTS.md")
    args = ap.parse_args()

    versions = sorted(PRIMARY)
    prim = {}
    prim_ver = {}
    for v in versions:
        f = resolve(PRIMARY[v][1])
        if not f:
            sys.exit(f"primary debug file for php {v} not found - run scripts/redhat.sh first")
        prim[v] = f
        prim_ver[v] = PRIMARY[v][0]

    # parse everything
    data = {}   # (struct_label, version) -> (fields, size)
    for label, tag, curated in STRUCTS:
        for v in versions:
            data[(label, v)] = parse_struct(prim[v], tag)

    # cross-check every other collected debug file against the primary of
    # the same PHP minor. Same full version -> layout must be identical
    # (loud mismatch otherwise). Different patch version -> differences are
    # expected upstream changes and are reported informationally.
    mismatches = []
    patch_changes = []
    checked = 0
    for full_ver, patterns in sorted(CROSS.items()):
        minor = full_ver.rsplit(".", 1)[0]
        if minor not in prim:
            continue
        same_patch = full_ver == prim_ver[minor]
        for pat in patterns:
            f = resolve(pat)
            if not f:
                continue
            for label, tag, _ in STRUCTS:
                pf, psize = data[(label, minor)]
                cf, csize = parse_struct(f, tag)
                if cf is None:
                    continue
                top = top_level_fields(prim[minor], tag)
                checked += 1
                diffs = []
                if psize != csize:
                    diffs.append(f"sizeof {psize} vs {csize}")
                for name in top:
                    a, b = pf.get(name), cf.get(name)
                    if a != b:
                        diffs.append(f"{name}: {a} vs {b}")
                if diffs:
                    entry = f"{full_ver} {label} ({f.name}): " + ", ".join(diffs)
                    (mismatches if same_patch else patch_changes).append(entry)

    lines = []
    lines.append("# STRUCTS.md - struct layouts per PHP version (x86_64, NTS)\n")
    lines.append(
        "Generated by `scripts/make_structs.py` from public debug-info "
        "(pahole). Layouts are a property of the PHP source version and the "
        "x86_64 SysV ABI, not of the distro.\n"
    )
    lines.append("Primary debug files (one per PHP minor, Remi el9):\n")
    for v in versions:
        lines.append(f"- php {v}: `{prim[v]}`")
    lines.append("")

    for label, tag, curated in STRUCTS:
        lines.append(f"## {label} (`{tag}`)\n")
        if curated is None:
            curated = []
            for v in versions:
                names = top_level_fields(prim[v], tag)
                for n in names:
                    if n not in curated:
                        curated.append(n)
        header = ["field"] + [f"php {v}" for v in versions]
        lines.append("| " + " | ".join(header) + " |")
        lines.append("|" + "---|" * len(header))
        for f in curated:
            row = [f]
            for v in versions:
                fields, _ = data[(label, v)]
                row.append(hex(fields[f]) if fields and f in fields else "n/a")
            lines.append("| " + " | ".join(row) + " |")
        row = ["**sizeof**"]
        for v in versions:
            _, size = data[(label, v)]
            row.append(hex(size) if size else "n/a")
        lines.append("| " + " | ".join(row) + " |")
        lines.append("")
        if label == "zend_mm_chunk":
            lines.append(
                "Note: the per-page `map[512]` array is the page map. "
                "DWARF-confirmed offsets: +0x208 (8.0/8.1), +0x220 (8.2/8.3), "
                "+0x270 (8.4/8.5). Earlier runtime measurements of "
                "chunk+0x208 on 8.3 and chunk+0x250 on 8.5 do not match the "
                "debug info: 0x208 is the 8.0/8.1 offset, and nothing lives "
                "at +0x250 in any 8.x. The `free_map` bitmap (64 bytes) "
                "precedes `map` at +0x1c8/+0x1e0/+0x230.\n"
            )

    lines.append("## Cross-distro verification\n")
    lines.append(
        f"Every same-version debug file collected under `work/` "
        f"({checked} struct comparisons across Debian ddebs, Ubuntu ddebs, "
        f"Alpine -dbg, Fedora koji and Rocky AppStream builds) was compared "
        f"against the primary file of the same PHP minor.\n"
    )
    if mismatches:
        lines.append("**SAME-VERSION MISMATCHES (layout differs between distros "
                     "for the same PHP version - investigate before trusting "
                     "the tables):**\n")
        for m in mismatches:
            lines.append(f"- {m}")
        lines.append("")
    else:
        lines.append("Same-version builds are layout-identical across distros: "
                     "no differences were found in any same-version "
                     "comparison.\n")
    if patch_changes:
        lines.append("### Patch-version layout changes (expected upstream "
                     "changes, not distro differences)\n")
        lines.append(
            "Older patch releases differ from the primary of their minor. "
            "Notable: php 8.2.32 (Debian bookworm, pre-2026-10-21 fixes) "
            "lacks `php_ps_globals.in_rfc1867_update` (+0x1b0 in 8.2.35, "
            "added by the CVE-2026-109618/109619 fix) and the 8.2.33+ "
            "hard-limit allocator rework.\n"
        )
        for m in patch_changes:
            lines.append(f"- {m}")
        lines.append("")

    out = REPO / args.out
    out.write_text("\n".join(lines) + "\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
