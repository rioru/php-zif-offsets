#!/usr/bin/env python3
"""Core offline static-analysis pass: extract PHP interpreter symbol offsets from an ELF binary.

Part of the php-zif-offsets dataset (see PLAN.md). Everything here is offline,
static analysis of publicly distributed binaries / public debug-info packages.

Offsets are ELF st_value (link-time addresses), emitted as hex strings.
Runtime absolute address rule: binary's lowest mapping base in
/proc/<pid>/maps plus the offset (shared libphp.so), or the base of the
binary's own mapping for static PIE executables. See README.md.

Usage:
  extract_symbols.py --binary PATH --meta-file META.json --out ROW.json
  extract_symbols.py --binary PATH --meta '{"...": "..."}' --out ROW.json

Optional:
  --debug-file PATH   sidecar debug-info ELF (ddebs / debuginfo RPM payload).
                      Its symtab is merged into the symbol set (distro builds
                      are stripped; the full symtab lives in the debug file),
                      and pahole reads struct layouts from it (ps_globals id
                      offset). Build-ids must match.
"""

import argparse
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

# Tier A - required for every row (row is incomplete without them)
TIER_A = [
    "zval_ptr_dtor",
    "zif_system",
    "zif_exec",
    "zif_passthru",
    "zif_shell_exec",
    "zend_reference_destroy",
    "zend_array_destroy",
    "ps_globals",
    "php_rfc1867_callback",
]

# Tier B - calibration/tracing set (best-effort)
TIER_B = [
    "php_session_initialize",
    "php_session_reset_id",
    "php_session_create_id",
    "ps_open_files",
    "ps_close_files",
    "php_session_abort",
    "php_rshutdown_session_globals",
    "php_session_rfc1867_callback",
    "php_url_encode",
    "sapi_add_header_ex",
    "sapi_header_op",
    "zend_llist_destroy",
    "zend_mm_gc",
    "zend_mm_free_pages",
    "zend_mm_alloc_pages",
    "zend_mm_shutdown",
    "_efree",
    "_emalloc",
    "_erealloc",
    "zend_mm_safe_error",
    "zend_mm_panic",
    "rfc1867_post_handler",
    "php_hash_environment",
    "php_request_startup",
    "php_request_shutdown",
    "alloc_globals",
    "sapi_globals",
    "executor_globals",
    "core_globals",
    "compiler_globals",
    "sapi_module",
]

# GCC clone/mangling suffixes: php_session_abort.isra.0, foo.cold, foo.part.1, ...
MANGLE_SUFFIX = re.compile(r"^(?P<base>.+?)\.(?:isra|constprop|part|cold|unlikely)(?:\.\d+)?$")

# Version-dependent symbol names: php < 7.3 exports the dtor as
# _zval_ptr_dtor (zval_ptr_dtor is an inline wrapper there, no symbol of
# its own; php 7.3+ exports zval_ptr_dtor directly).
ALIASES = {
    "zval_ptr_dtor": ("_zval_ptr_dtor",),
}


def run(cmd, check=True):
    p = subprocess.run(cmd, capture_output=True, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(
            f"command failed rc={p.returncode}: {' '.join(cmd)}\nstderr: {p.stderr[:800]}"
        )
    return p.stdout


def get_sections(path):
    """Parse `readelf -SW` into {name: {addr, off, size, type}}."""
    out = run(["readelf", "-SW", str(path)])
    secs = {}
    for line in out.splitlines():
        m = re.match(
            r"\s*\[\s*\d+\]\s+(\S+)\s+(\S+)\s+([0-9a-f]{16})\s+([0-9a-f]+)\s+([0-9a-f]+)",
            line,
        )
        if m:
            name, typ, addr, off, size = m.groups()
            secs[name] = {
                "addr": int(addr, 16),
                "off": int(off, 16),
                "size": int(size, 16),
                "type": typ,
            }
    return secs


def get_build_id(path):
    out = run(["readelf", "-n", str(path)])
    m = re.search(r"Build ID:\s*([0-9a-f]+)", out)
    return m.group(1) if m else None


def get_symbols(path):
    """Parse `readelf -sW` into {name: {value, size, type, bind, ndx}}.

    Strips symbol versioning (name@GLIBC... / name@@...). When a name appears
    multiple times, prefer a defined section index, then GLOBAL binding,
    then larger size.
    """
    out = run(["readelf", "-sW", str(path)])
    best = {}
    for line in out.splitlines():
        m = re.match(
            r"\s*\d+:\s+([0-9a-f]+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S.*)$",
            line,
        )
        if not m:
            continue
        value, size, typ, bind, vis, ndx, name = m.groups()
        name = name.split("@")[0].strip()
        if not name or ndx == "UND":
            continue
        cand = {
            "value": int(value, 16),
            "size": int(size),
            "type": typ,
            "bind": bind,
            "ndx": ndx,
        }
        rank = (0 if ndx not in ("ABS", "COM") else 1,
                0 if bind == "GLOBAL" else 1,
                -cand["size"])
        cur = best.get(name)
        if cur is None or rank < cur[0]:
            best[name] = (rank, cand)
    return {k: v[1] for k, v in best.items()}


def merge_debug_symbols(binary, build_id, syms, debug_file, notes):
    """Merge the sidecar debug file's symtab into `syms` (distro builds).

    Distro binaries are stripped; the full symbol table lives in the
    matching ddeb / debuginfo package. The debug file carries the same
    build-id and the same link-time st_values as the binary it
    describes. The binary's own values always win (they are what the
    loader actually uses); any value conflict is recorded loudly since
    it means the debug file does not match the binary.
    Returns the number of symbols added.
    """
    dbg = Path(debug_file)
    if not dbg.exists():
        sys.exit(f"debug file not found: {dbg}")
    dbg_build_id = get_build_id(dbg)
    if build_id and dbg_build_id and build_id != dbg_build_id:
        sys.exit(
            f"debug file build-id mismatch: binary {build_id} vs debug "
            f"{dbg_build_id} ({dbg}) - wrong debug package?"
        )
    dbg_syms = get_symbols(dbg)
    conflicts = []
    added = 0
    for name, s in dbg_syms.items():
        cur = syms.get(name)
        if cur is None:
            syms[name] = s
            added += 1
        elif cur["value"] != s["value"]:
            conflicts.append((name, cur["value"], s["value"]))
        elif cur["size"] == 0 < s["size"]:
            cur["size"] = s["size"]
    if conflicts:
        notes.append(
            "DEBUG SYMTAB CONFLICTS (binary value kept): "
            + ", ".join(f"{n}={hex(bv)} vs dbg {hex(dv)}" for n, bv, dv in conflicts[:10])
            + (f" (+{len(conflicts) - 10} more)" if len(conflicts) > 10 else "")
        )
    return added


def section_bytes(path, sec):
    with open(path, "rb") as f:
        f.seek(sec["off"])
        return f.read(sec["size"])


def get_relative_relocs(path):
    """R_X86_64_RELATIVE entries from .rela.dyn/.rela.* as [(r_offset, addend)]."""
    out = run(["readelf", "-rW", str(path)])
    rel = []
    for line in out.splitlines():
        m = re.match(
            r"^([0-9a-f]+)\s+([0-9a-f]+)\s+R_X86_64_RELATIVE\s+([0-9a-f]+)\s*$",
            line,
        )
        if m:
            rel.append((int(m.group(1), 16), int(m.group(3), 16)))
    return rel


def in_sec(secs, name, vaddr):
    """True if vaddr falls inside the section's address range (works for
    NOBITS sections like .bss too)."""
    sec = secs.get(name)
    if not sec:
        return False
    return sec["addr"] <= vaddr < sec["addr"] + sec["size"]


def zif_from_reloc_trick(path, secs, fname, rel=None):
    """zend_function_entry recovery for stripped builds.

    zend_function_entry = {fname, handler, arg_info, num_args, flags}.
    PIE builds: 1. vaddr of NUL-terminated `fname` string in .rodata;
    2. R_X86_64_RELATIVE with addend == that vaddr -> fname slot (r_offset);
    3. RELATIVE at r_offset+8 -> handler (zif_*) vaddr;
    4. sanity: handler inside .text, arg_info (r_offset+16) inside
    .data.rel.ro (or NULL).
    Non-PIE builds (2014-2016 era executables) carry no RELATIVE entries -
    the entry arrays hold link-time absolute pointers - so fall back to
    scanning the pointer-bearing data sections for the fname vaddr.
    Returns (handler_vaddr, fname_slot, method) or None.
    """
    rodata = secs.get(".rodata")
    if not rodata:
        return None
    if rel is None:
        rel = get_relative_relocs(path)
    if not rel:
        return zif_from_pointer_scan(path, secs, fname)
    by_offset = {off: addend for off, addend in rel}
    blob = section_bytes(path, rodata)
    needle = fname.encode() + b"\x00"
    candidates = []
    idx = blob.find(needle)
    while idx != -1:
        candidates.append(rodata["addr"] + idx)
        idx = blob.find(needle, idx + 1)
    for cand in candidates:
        for off, addend in rel:
            if addend != cand:
                continue
            handler = by_offset.get(off + 8)
            arg_info = by_offset.get(off + 16)
            if handler is None:
                continue
            if not in_sec(secs, ".text", handler):
                continue
            # arg_info may be NULL for some entries; when present it must be
            # a valid pointer into .data.rel.ro (or .rodata on some builds).
            if arg_info not in (None, 0) and not (
                in_sec(secs, ".data.rel.ro", arg_info) or in_sec(secs, ".rodata", arg_info)
            ):
                continue
            return handler, off, "reloc"
    return None


def zif_from_pointer_scan(path, secs, fname):
    """zend_function_entry pointer scan for non-PIE builds.

    The entry arrays hold absolute link-time pointers: scan .data.rel.ro,
    .rodata (2014-2015 links place the const arrays directly in .rodata,
    with no .data.rel.ro section at all) and .data for the fname vaddr;
    handler, arg_info and num_args are the following qwords. Sanity:
    handler inside .text, arg_info NULL or inside .data.rel.ro/.rodata,
    num_args < 256.
    Returns (handler_vaddr, fname_slot, method) or None.
    """
    rodata = secs.get(".rodata")
    if not rodata:
        return None
    blob = section_bytes(path, rodata)
    needle = fname.encode() + b"\x00"
    candidates = []
    idx = blob.find(needle)
    while idx != -1:
        candidates.append(rodata["addr"] + idx)
        idx = blob.find(needle, idx + 1)
    for secname in (".data.rel.ro", ".rodata", ".data"):
        sec = secs.get(secname)
        if not sec:
            continue
        data = section_bytes(path, sec)
        for cand in candidates:
            target = struct.pack("<Q", cand)
            pos = data.find(target)
            while pos != -1:
                handler, arg_info, num_args = struct.unpack_from("<QQQ", data, pos + 8)
                if in_sec(secs, ".text", handler) and num_args < 256:
                    if arg_info == 0 or in_sec(secs, ".data.rel.ro", arg_info) or in_sec(secs, ".rodata", arg_info):
                        return handler, sec["addr"] + pos, "ptr-scan"
                pos = data.find(target, pos + 1)
    return None


def ps_id_offset_from_dwarf(debug_file):
    """pahole ground truth: offset of `id` in php_session_globals.

    The DWARF entity is the struct tag `_php_ps_globals`; the typedef
    name `php_ps_globals` resolves on some pahole versions only to a
    forward declaration, so try the struct tag first.
    """
    if not debug_file:
        return None, None
    for cname in ("_php_ps_globals", "php_ps_globals"):
        try:
            out = run(["pahole", "-C", cname, str(debug_file)])
        except RuntimeError:
            continue
        m = re.search(r"^\s*zend_string\s*\*\s*id;\s*/\*\s*(\d+)", out, re.M)
        if m:
            return int(m.group(1)), out
    return None, None


def disasm_range(path, start, stop):
    """objdump a vaddr range -> [(addr, raw_bytes, text)]."""
    out = run([
        "objdump", "-d", f"--start-address={start}", f"--stop-address={stop}", str(path),
    ])
    insns = []
    for line in out.splitlines():
        m = re.match(r"\s*([0-9a-f]+):\s*((?:[0-9a-f]{2} )+)\s*(.*?)\s*$", line)
        if m:
            insns.append((int(m.group(1), 16), bytes.fromhex(m.group(2)), m.group(3)))
    return insns


def annotation_name(text):
    """Symbol name from an objdump annotation like 'call 1234 <foo@plt>'.

    Returns None when the annotation is a raw address (stripped LOCAL call)
    or a symbol+offset form (target is not the symbol start)."""
    if re.search(r"<[^>]*\+0x[0-9a-f]+>", text):
        return None
    m = re.search(r"<([A-Za-z_.$][A-Za-z0-9_.$]*)(?:@@[A-Za-z0-9.]+)?(?:@plt)?>", text)
    return m.group(1) if m else None


def calls_in_range(path, start, stop):
    """Ordered [(name_or_None, target_addr, insn_offset_from_start)] for
    direct E8/E9 call/jmp instructions in the vaddr range."""
    out = []
    for addr, b, text in disasm_range(path, start, stop):
        if len(b) == 5 and b[0] in (0xE8, 0xE9):
            rel = int.from_bytes(b[1:5], "little", signed=True)
            out.append((annotation_name(text), addr + 5 + rel, addr - start))
    return out


def build_masked_pattern(insns):
    """Masked byte pattern + call sites from reference instructions.

    Wildcards: rel32 fields of E8/E9 (call/jmp) and the disp32 of
    rip-relative operands. Everything else must match byte-for-byte.
    Returns (pattern, calls) with calls = [(insn_offset, ref_target,
    ref_name)].
    """
    pattern = []
    calls = []
    func_start = insns[0][0]
    for addr, b, text in insns:
        off = addr - func_start
        if b[0] in (0xE8, 0xE9) and len(b) == 5:
            pattern.append(b[0])
            pattern.extend([None] * 4)
            rel = int.from_bytes(b[1:5], "little", signed=True)
            calls.append((off, addr + 5 + rel, annotation_name(text)))
        elif "(%rip)" in text and len(b) >= 5:
            pattern.extend(b[:-4])
            pattern.extend([None] * 4)
        else:
            pattern.extend(b)
    return pattern, calls


def search_masked(blob, base_addr, pattern):
    """Addresses in blob (mapped at base_addr) matching the masked pattern."""
    hits = []
    n = len(pattern)
    first_fixed = next((i for i, p in enumerate(pattern) if p is not None), None)
    if first_fixed is None:
        return hits
    fixed_idx = [i for i, p in enumerate(pattern) if p is not None]
    i = blob.find(bytes([pattern[first_fixed]]))
    # simple scan anchored on the first fixed byte
    pos = 0
    while True:
        i = blob.find(bytes([pattern[first_fixed]]), pos)
        if i == -1 or i + n > len(blob):
            break
        cand = i - first_fixed
        if cand >= 0:
            ok = True
            for j, k in enumerate(fixed_idx):
                if blob[cand + k] != pattern[k]:
                    ok = False
                    break
            if ok:
                hits.append(base_addr + cand)
        pos = i + 1
    return hits


def lookup_in(syms, name):
    """Exact match, then GCC-mangled clones (.isra.N/.cold/...)."""
    if name in syms:
        return name, syms[name]["value"]
    for sname, s in syms.items():
        m = MANGLE_SUFFIX.match(sname)
        if m and m.group("base") == name:
            return sname, s["value"]
    return None, None


def recover_via_pattern(target, secs, target_syms, ref, ref_syms, name):
    """Recover a LOCAL function symbol in a stripped binary by masked
    byte-pattern matching against an unstripped same-version build.

    Verification: the target's call instructions at the same in-function
    offsets must carry the same objdump symbol annotations (PLT/import and
    exported-domestic calls are named even in stripped binaries); at least
    one call must be verifiable this way."""
    actual, value = lookup_in(ref_syms, name)
    if actual is None:
        return None, "no reference symbol"
    ref_sym = ref_syms[actual]
    if ref_sym["size"] == 0:
        return None, "reference symbol has zero size"
    insns = disasm_range(ref, value, value + ref_sym["size"])
    if not insns:
        return None, "reference disassembly empty"
    pattern, calls = build_masked_pattern(insns)
    text = secs.get(".text")
    if not text:
        return None, "no .text"
    blob = section_bytes(target, text)
    hits = search_masked(blob, text["addr"], pattern)
    verified = []
    for hit in hits:
        tcalls = calls_in_range(target, hit, hit + ref_sym["size"])
        if len(tcalls) != len(calls):
            continue
        named, mismatch = 0, False
        for (roff, rtgt, rname), (tname, ttgt, toff) in zip(calls, tcalls):
            if roff != toff:
                mismatch = True
                break
            if rname and tname:
                if rname == tname:
                    named += 1
                else:
                    mismatch = True
                    break
        if not mismatch and named >= 1:
            verified.append(hit)
    if len(verified) == 1:
        return verified[0], f"masked pattern match vs {Path(ref).name} ({len(hits)} raw hits, call annotations verified)"
    if len(verified) > 1:
        return None, f"ambiguous: {len(verified)} verified hits"
    return None, f"no verified hit ({len(hits)} raw hits)"


def recover_via_caller(target, secs, target_syms, ref, ref_syms, name, anchor, anchor_tgt_addr=None):
    """Caller-anchored recovery: the anchor function exists in both builds;
    the missing function is called from it in source order. Align the two
    ordered call lists and take the target's call at the aligned index."""
    a_actual, a_value = lookup_in(ref_syms, anchor)
    if a_actual is None:
        return None, "anchor missing in reference"
    a_size = ref_syms[a_actual]["size"]
    n_actual, n_value = lookup_in(ref_syms, name)
    if n_actual is None:
        return None, "name missing in reference"
    rcalls = calls_in_range(ref, a_value, a_value + a_size)
    ks = [i for i, (n, t, o) in enumerate(rcalls) if t == n_value]
    if not ks:
        return None, f"anchor {anchor} does not call {name} in reference"
    if anchor_tgt_addr is None:
        t_anchor = target_syms.get(anchor)
        if not t_anchor:
            return None, f"anchor {anchor} missing in target symbol tables"
        anchor_tgt_addr = t_anchor["value"]
    tcalls = calls_in_range(target, anchor_tgt_addr, anchor_tgt_addr + a_size + 4096)
    answers = set()
    for k in ks:
        if k >= len(tcalls):
            return None, f"target anchor has fewer calls ({len(tcalls)}) than reference index ({k})"
        answers.add(tcalls[k][1])
        # neighbor sanity: named calls around k must agree
        for j in range(max(0, k - 2), min(len(rcalls), k + 3)):
            rn, tn = rcalls[j][0], tcalls[j][0]
            if rn and tn and rn != tn:
                return None, f"call-order mismatch at {j}: {rn} vs {tn}"
    if len(answers) == 1:
        ans = answers.pop()
        if not in_sec(secs, ".text", ans):
            return None, f"recovered call target {hex(ans)} outside .text"
        return ans, f"call-order anchor {anchor} (ref call #{ks[0]})"
    return None, f"ambiguous answers: {[hex(a) for a in answers]}"


def recover_via_storelea(target, secs, var_addr):
    """Recover the function assigned to a function-pointer variable in a
    MINIT-style `var = func;`: the PIE code does `lea var(%rip),%rX` then
    `lea func(%rip),%rY` and stores. Find lea-to-var sites whose window
    stores through the pointer; the nearby lea-to-.text target is func."""
    text = secs.get(".text")
    if not text or not var_addr:
        return None, "no .text or var address"
    blob = section_bytes(target, text)
    candidates = set()
    i, n = 0, len(blob)
    while True:
        i = blob.find(b"\x48\x8d", i)
        if i == -1 or i + 7 > n:
            break
        if blob[i + 2] & 0xC7 == 0x05:  # lea disp32(%rip),%r
            disp = int.from_bytes(blob[i + 3:i + 7], "little", signed=True)
            site = text["addr"] + i
            tgt = site + 7 + disp
            if tgt == var_addr:
                insn_text = disasm_1(target, site) or ""
                m = re.search(r",%(\w+)\s*(?:#.*)?$", insn_text.split("#")[0])
                if m:
                    reg = m.group(1)
                    insns = disasm_range(target, site, site + 80)
                    stores = any(
                        re.match(rf"mov\s+%\w+,\(%{reg}\)", t) for _, _, t in insns[1:9]
                    )
                    if stores:
                        for addr2, b2, t2 in insns[1:9]:
                            if t2.startswith("lea") and "(%rip)" in t2:
                                m2 = re.search(r"(-?0x[0-9a-f]+)?\(%rip\)", t2)
                                if m2:
                                    d2 = int(m2.group(1).replace("0x", ""), 16) if m2.group(1) else 0
                                    if "-" in m2.group(0):
                                        d2 = -d2
                                    cand = addr2 + len(b2) + d2
                                    if in_sec(secs, ".text", cand):
                                        candidates.add(cand)
        i += 1
    if len(candidates) == 1:
        return candidates.pop(), f"lea/store assignment into {hex(var_addr)}"
    return None, f"no unique assignment candidate ({len(candidates)})"


def disasm_1(path, addr):
    insns = disasm_range(path, addr, addr + 16)
    return insns[0][2] if insns else None


def recover_via_ps_module(target, secs, rel, mod_str="files"):
    """ps_module struct trick: {s_name, s_open(+8), s_close(+16), ...} sits
    in .data.rel.ro with R_X86_64_RELATIVE addends for every field. Find the
    module by its name string, read the open/close slots."""
    rodata = secs.get(".rodata")
    if not rodata:
        return None, "no .rodata"
    by_offset = {off: addend for off, addend in rel}
    blob = section_bytes(target, rodata)
    needle = mod_str.encode() + b"\x00"
    idx = blob.find(needle)
    while idx != -1:
        saddr = rodata["addr"] + idx
        for off, addend in rel:
            if addend != saddr:
                continue
            o = by_offset.get(off + 8)
            c = by_offset.get(off + 16)
            if o and c and in_sec(secs, ".text", o) and in_sec(secs, ".text", c):
                return (o, c), f"ps_module '{mod_str}' struct relocs (base {hex(off)})"
        idx = blob.find(needle, idx + 1)
    return None, f"ps_module '{mod_str}' struct not found"


def recover_alloc_globals(target, secs, target_syms):
    """alloc_globals is a static struct; every allocator entry loads
    AG(mm_heap) through a rip-relative access to &alloc_globals as its
    first instruction. Cross-check _emalloc/_efree/_erealloc."""
    candidates = {}
    for fname in ("_emalloc", "_efree", "_erealloc"):
        sym = target_syms.get(fname)
        if not sym or sym["size"] == 0:
            continue
        insns = disasm_range(target, sym["value"], sym["value"] + min(sym["size"], 32))
        for addr, b, text in insns[:4]:
            m = re.match(r"mov\s+(?:0x[0-9a-f]+)?\(%rip\),%\w+", text)
            if not m:
                continue
            disp = None
            mm = re.search(r"(-?0x[0-9a-f]+)?\(%rip\)", text)
            if mm:
                disp = int(mm.group(1).replace("0x", ""), 16) if mm.group(1) else 0
                if text.strip().startswith("mov -") or "-" in mm.group(0):
                    disp = -disp
            if disp is None:
                continue
            tgt = addr + len(b) + disp
            if in_sec(secs, ".data", tgt) or in_sec(secs, ".bss", tgt):
                candidates.setdefault(tgt, []).append(fname)
            break
    if len(candidates) == 1:
        tgt, srcs = next(iter(candidates.items()))
        return tgt, f"rip-relative AG(mm_heap) load in {','.join(srcs)}"
    return None, f"ambiguous candidates: { {hex(k): v for k, v in candidates.items()} }"


def ps_id_offset_from_annotations(path, secs=None):
    """PIE executables: objdump annotates direct rip-relative accesses to
    exported data as <ps_globals+0xNN> (with an optional @@Base version
    suffix). Also track registers loaded with &ps_globals and collect the
    field displacements used off them.

    Shared libraries reach ps_globals through its GOT slot; objdump
    annotates that load with the nearest preceding dynsym symbol, i.e.
    <ps_globals@@Base-0xNN> (slot address = ps_globals - 0xNN). A 64-bit
    mov from rip whose target lands in .got is therefore a &ps_globals
    base establishment, not a field access."""
    out = run(["objdump", "-d", "--no-show-raw-insn", "-j", ".text", str(path)])
    got = secs.get(".got") if secs else None
    offs = set()
    base_regs = set()
    for line in out.splitlines():
        if re.match(r"^[0-9a-f]+ <.*>:$", line.strip()):
            base_regs = set()
            continue
        # direct field access: <ps_globals+0xNN> / <ps_globals@@Base+0xNN>
        m = re.search(r"<ps_globals(?:@@[A-Za-z0-9.]+)?\+0x([0-9a-f]+)>", line)
        if m:
            offs.add(int(m.group(1), 16))
            continue
        # GOT-slot load: <ps_globals@@Base-0xNN> with the slot in .got
        m = re.search(
            r"mov\s+0x[0-9a-f]+\(%rip\),%(r\w+)\s+#\s*([0-9a-f]+)\s+<ps_globals(?:@@[A-Za-z0-9.]+)?-0x[0-9a-f]+>",
            line,
        )
        if m and got and got["addr"] <= int(m.group(2), 16) < got["addr"] + got["size"]:
            base_regs = {m.group(1)}
            continue
        # base establishment: lea/mov rip with annotation exactly <ps_globals>
        m = re.search(
            r"(?:mov|lea)\s+(?:0x[0-9a-f]+)?\(%rip\),%(\w+)\s+#\s*[0-9a-f]+\s+<ps_globals(?:@@[A-Za-z0-9.]+)?>",
            line,
        )
        if m:
            base_regs = {m.group(1)}
            continue
        # field access off a tracked base register
        for reg in list(base_regs):
            m = re.search(rf"(?:0x([0-9a-f]+))?\(%{reg}(?:,[^)]*)?\)", line)
            if m and not re.match(r"\s*lea\b", line):
                offs.add(int(m.group(1), 16) if m.group(1) else 0)
            # register overwritten as destination -> stop tracking it
            if re.search(rf",\s*%{reg}\s*$", line):
                base_regs.discard(reg)
    return sorted(offs)


def ps_id_offset_from_disasm(path, syms, secs):
    """Shared libphp.so: session code reaches ps_globals through its GOT
    slot (R_X86_64_GLOB_DAT). Find the base register in zif_session_id and
    collect the field displacements used off it."""
    sym = syms.get("zif_session_id")
    if not sym or sym["size"] == 0:
        return None, None
    insns = disasm_range(path, sym["value"], sym["value"] + sym["size"])
    base_reg = None
    disps = []
    for addr, b, text in insns:
        m = re.search(r"mov\s+(?:0x[0-9a-f]+)?\(%rip\),%(\w+)\s+#\s*[0-9a-f]+\s+<ps_globals", text)
        if m and base_reg is None:
            base_reg = m.group(1)
            continue
        if base_reg:
            m = re.search(rf"(?:0x([0-9a-f]+))?\(%{base_reg}(?:,[^)]*)?\)", text)
            if m and not text.strip().startswith("lea"):
                disps.append(int(m.group(1), 16) if m.group(1) else 0)
    return (sorted(set(disps)) if disps else None), base_reg


def hexs(v):
    return None if v is None else hex(v)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--meta", help="JSON string with meta fields")
    ap.add_argument("--meta-file", help="JSON file with meta fields")
    ap.add_argument("--out", required=True)
    ap.add_argument("--debug-file", help="sidecar debug-info ELF for pahole checks")
    ap.add_argument("--reference-binary",
                    help="unstripped same-version build (e.g. the apache libphp.so); "
                         "used to recover LOCAL symbols missing from stripped binaries "
                         "via masked pattern matching")
    ap.add_argument("--allow-missing-tier-a", action="store_true",
                    help="do not exit 2 when Tier A symbols are missing (for binaries "
                         "that legitimately lack them, e.g. Alpine's shared session.so "
                         "row or the matching fpm/apache rows that lack ps_globals)")
    args = ap.parse_args()

    binary = Path(args.binary)
    if not binary.exists():
        sys.exit(f"binary not found: {binary}")

    meta = {}
    if args.meta_file:
        meta = json.loads(Path(args.meta_file).read_text())
    elif args.meta:
        meta = json.loads(args.meta)
    for req in ("php_version", "distro", "package", "binary_path", "binary_type"):
        if req not in meta:
            sys.exit(f"meta missing required field: {req}")

    secs = get_sections(binary)
    build_id = get_build_id(binary)
    has_symtab = ".symtab" in secs
    # readelf -sW dumps every symbol table (.dynsym first, then .symtab).
    # Stripped docker fpm/cli binaries are -rdynamic: .dynsym still exports
    # ~2400 defined globals (all data symbols, most functions) - only the
    # LOCAL zif_* handlers are missing there, recovered by the reloc trick.
    syms = get_symbols(binary)

    notes = []
    symbol_names = {}
    notes.extend(meta.get("notes") or [])

    # Distro builds are stripped; their full symtab lives in the sidecar
    # debug file (ddeb / debuginfo package). Merge it in before any lookup:
    # it fills the LOCAL gaps (zif_*, session/allocator internals). The
    # binary's own values win; build-ids must match (checked inside).
    debug_added = None
    if args.debug_file:
        debug_added = merge_debug_symbols(binary, build_id, syms, args.debug_file, notes)

    # ZTS auto-detect (cross-check against driver-supplied meta). NTS builds
    # still carry stubs like tsrm_realpath, so key on tsrm_get_ls_cache;
    # 5.x ZTS builds predate that accessor and instead define the TSRM key
    # globals (executor_globals_id / ps_globals_id).
    zts_auto = "tsrm_get_ls_cache" in syms or "executor_globals_id" in syms

    exploit = {}
    for name in TIER_A:
        actual, val = lookup_in(syms, name)
        if actual is None:
            for alias in ALIASES.get(name, ()):
                actual, val = lookup_in(syms, alias)
                if actual is not None:
                    notes.append(
                        f"{name} present as {actual} (php < 7.3 naming; value "
                        "recorded under the canonical key)"
                    )
                    break
        if actual is not None and actual != name:
            symbol_names[name] = actual
        exploit[name] = hexs(val)

    calibration = {}
    for name in TIER_B:
        actual, val = lookup_in(syms, name)
        if actual is not None and actual != name:
            symbol_names[name] = actual
        calibration[name] = hexs(val)

    # Ubuntu jammy's php8.1 backport renames zend_mm_safe_error to
    # zend_mm_safe_error_ex (upstream never used the _ex name). Record the
    # variant under the canonical key so the calibration set stays useful.
    if calibration.get("zend_mm_safe_error") is None:
        actual, val = lookup_in(syms, "zend_mm_safe_error_ex")
        if actual is not None:
            calibration["zend_mm_safe_error"] = hexs(val)
            symbol_names["zend_mm_safe_error"] = actual
            notes.append(
                "zend_mm_safe_error present as zend_mm_safe_error_ex (distro backport "
                "rename, Ubuntu jammy php8.1); value recorded under the canonical key"
            )

    if meta.get("symbol_source"):
        symbol_source = meta["symbol_source"]
    elif has_symtab:
        symbol_source = "readelf -sW (.symtab)"
    elif debug_added is not None:
        symbol_source = (
            f"readelf --dyn-syms + debug-file symtab "
            f"({Path(args.debug_file).name}, +{debug_added} symbols)"
        )
    else:
        symbol_source = "readelf --dyn-syms (-rdynamic exports)"

    # zif_* fallback via the zend_function_entry relocation trick when the
    # symtab is missing or a zif symbol is absent.
    if not has_symtab or any(exploit[n] is None for n in ("zif_system", "zif_exec", "zif_passthru", "zif_shell_exec")):
        rel = get_relative_relocs(binary)
        for fname, zname in (("system", "zif_system"), ("exec", "zif_exec"),
                             ("passthru", "zif_passthru"), ("shell_exec", "zif_shell_exec")):
            if exploit.get(zname):
                continue
            hit = zif_from_reloc_trick(binary, secs, fname, rel)
            if hit:
                exploit[zname] = hexs(hit[0])
                how = ("relocation trick" if hit[2] == "reloc"
                       else "pointer scan (non-PIE link-time pointers)")
                notes.append(f"{zname} recovered via zend_function_entry {how} (fname='{fname}', slot {hex(hit[1])})")
                tag = "reloc-trick (.rela.dyn)" if hit[2] == "reloc" else "zif ptr-scan (.data.rel.ro)"
                if tag not in (symbol_source or ""):
                    symbol_source = (symbol_source + " + " + tag).strip(" +")

    # Recovery pass for LOCAL symbols absent from every available table.
    # Methods, in order of trust:
    #   - masked byte-pattern match vs an unstripped same-version build
    #     (works for functions that do not access PHP globals; the .so and
    #     PIE builds encode global accesses differently)
    #   - caller-anchored call-order alignment (anchor must be visible in
    #     this binary: dynsym export, or a zif_* recovered by the reloc trick)
    #   - lea/store assignment scan for function-pointer variables
    #   - ps_module struct relocation read for the files save-handler
    ref = Path(args.reference_binary) if args.reference_binary else None
    if ref and ref.exists():
        ref_syms = get_symbols(ref)
        rel = get_relative_relocs(binary)

        def set_found(name, hit, why):
            (exploit if name in TIER_A else calibration)[name] = hexs(hit)
            notes.append(f"{name} recovered via {why}")
            return True

        for name in TIER_A + TIER_B:
            if name == "alloc_globals" or (exploit.get(name) or calibration.get(name)):
                continue
            hit, why = recover_via_pattern(binary, secs, syms, ref, ref_syms, name)
            if hit is not None:
                set_found(name, hit, why)
                if "pattern-match" not in (symbol_source or ""):
                    symbol_source += " + pattern-match (same-version reference build)"
            else:
                notes.append(f"{name} pattern recovery failed: {why}")

        caller_plans = [
            ("php_session_initialize", "php_session_start", None),
            ("php_rshutdown_session_globals", "php_session_destroy", None),
            ("zend_mm_alloc_pages", "_emalloc_large", None),
            ("zend_mm_free_pages", "_efree", None),
            ("php_session_abort", "zif_session_abort", "session_abort"),
        ]
        for name, anchor, zif_fname in caller_plans:
            if (exploit.get(name) or calibration.get(name)):
                continue
            anchor_addr = None
            if zif_fname:
                hit = zif_from_reloc_trick(binary, secs, zif_fname, rel)
                if hit:
                    anchor_addr = hit[0]
                    notes.append(f"anchor {anchor} = {hex(anchor_addr)} via zend_function_entry reloc trick")
            hit, why = recover_via_caller(binary, secs, syms, ref, ref_syms, name, anchor, anchor_addr)
            if hit is not None:
                set_found(name, hit, why)
                if "call-anchor" not in (symbol_source or ""):
                    symbol_source += " + call-anchor"
            else:
                notes.append(f"{name} caller-anchor recovery failed: {why}")

        if not calibration.get("php_session_rfc1867_callback"):
            var = exploit.get("php_rfc1867_callback")
            var_addr = int(var, 16) if var else None
            hit, why = recover_via_storelea(binary, secs, var_addr)
            if hit is not None:
                set_found("php_session_rfc1867_callback", hit, why)
            else:
                notes.append(f"php_session_rfc1867_callback storelea recovery failed: {why}")

        if not (calibration.get("ps_open_files") and calibration.get("ps_close_files")):
            res, why = recover_via_ps_module(binary, secs, rel, "files")
            if res:
                set_found("ps_open_files", res[0], why)
                set_found("ps_close_files", res[1], why)
            else:
                notes.append(f"ps_open_files/ps_close_files recovery failed: {why}")

    if calibration.get("alloc_globals") is None:
        hit, why = recover_alloc_globals(binary, secs, syms)
        if hit is not None:
            calibration["alloc_globals"] = hexs(hit)
            notes.append(f"alloc_globals recovered via {why}")
        else:
            notes.append(f"alloc_globals recovery failed: {why}")

    # ps_globals PS(id) offset. Source layout (ext/session/php_session.h,
    # PHP 8.1-8.5): id is the third pointer field -> +0x10. Verify per
    # build: DWARF ground truth, else disassembly.
    EXPECTED_PS_ID = 0x10
    ps_id_offset = None
    ps_id_method = None
    dwarf_off, _ = ps_id_offset_from_dwarf(args.debug_file)
    if dwarf_off is not None:
        ps_id_offset = dwarf_off
        ps_id_method = "pahole php_ps_globals (DWARF)"
    elif has_symtab:
        disps, base = ps_id_offset_from_disasm(binary, syms, secs)
        if disps:
            ps_id_method = f"zif_session_id field offsets off ps_globals GOT base: {[hex(d) for d in disps]}"
            if EXPECTED_PS_ID in disps:
                ps_id_offset = EXPECTED_PS_ID
            else:
                notes.append(f"PS(id) offset NOT the expected +0x10 (accessed offsets: {[hex(d) for d in disps]}) - verify against DWARF")
        else:
            # zif_session_id may be inlined or hold ps_globals in a
            # register across accesses; fall back to the whole-binary
            # annotation scan before giving up.
            offs = ps_id_offset_from_annotations(binary, secs)
            if offs:
                ps_id_method = f"objdump <ps_globals+off> annotations: {[hex(o) for o in offs]}"
                if EXPECTED_PS_ID in offs:
                    ps_id_offset = EXPECTED_PS_ID
                else:
                    notes.append(f"PS(id) offset NOT the expected +0x10 (accessed offsets: {[hex(o) for o in offs]}) - verify against DWARF")
            else:
                notes.append("ps_globals_id_offset recovery failed: no ps_globals-relative accesses found in zif_session_id disassembly or in objdump annotations (compiler folded the base register)")
    else:
        offs = ps_id_offset_from_annotations(binary, secs)
        if offs:
            ps_id_method = f"objdump <ps_globals+off> annotations: {[hex(o) for o in offs]}"
            if EXPECTED_PS_ID in offs:
                ps_id_offset = EXPECTED_PS_ID
            else:
                notes.append(f"PS(id) offset NOT the expected +0x10 (accessed offsets: {[hex(o) for o in offs]}) - verify against DWARF")
        else:
            notes.append("ps_globals_id_offset recovery failed: no <ps_globals+off> annotations in disassembly")
    exploit["ps_globals_id_offset"] = hexs(ps_id_offset) if ps_id_offset is not None else None

    # Fingerprints
    fingerprint = {}
    for name, key in (("zval_ptr_dtor", "zval_ptr_dtor_mod_0x1000"),
                      ("zif_system", "zif_system_mod_0x1000")):
        v = exploit.get(name)
        fingerprint[key] = hexs(int(v, 16) % 0x1000) if v else None

    missing_a = [n for n in TIER_A if exploit.get(n) is None]
    if missing_a:
        notes.append("MISSING Tier A: " + ", ".join(missing_a))
    if calibration.get("zend_mm_safe_error") is None and not meta["php_version"].startswith(("5.", "7.")):
        notes.append(
            "zend_mm_safe_error absent from this build: removed upstream in the "
            "php 8.2.35/8.3.36/8.4.27/8.5.12 patch releases (present in earlier "
            "8.x patch releases; zend_mm_panic is the closest equivalent here)"
        )
    if meta.get("thread_safety") == "ZTS" and not zts_auto and has_symtab:
        notes.append("meta says ZTS but no tsrm_* symbols found - check thread_safety")
    if zts_auto:
        if meta.get("thread_safety") == "NTS":
            meta["thread_safety"] = "ZTS"
            notes.append(
                "ZTS build auto-detected from tsrm_* symbols; thread_safety "
                "corrected from the driver meta (NTS)"
            )
        tsrm_keys = []
        for key in ("executor_globals_id", "ps_globals_id"):
            s = syms.get(key)
            if s:
                tsrm_keys.append(f"{key}=0x{s['value']:x}")
        if tsrm_keys:
            notes.append(
                "ZTS build: executor_globals/ps_globals are thread-local via "
                "TSRM (no direct symbols, hence the nulls); TSRM key globals: "
                + ", ".join(tsrm_keys)
            )

    record = {
        "meta": {
            "php_version": meta["php_version"],
            "thread_safety": meta.get("thread_safety"),
            "arch": meta.get("arch", "x86_64"),
            "distro": meta["distro"],
            "package": meta["package"],
            "binary_path": meta["binary_path"],
            "binary_type": meta["binary_type"],
            "build_id": build_id,
            "stripped": not has_symtab,
            "symbol_source": symbol_source,
            "ps_id_offset_method": ps_id_method,
            "symbol_names": symbol_names or None,
            "notes": notes or None,
        },
        "exploit": exploit,
        "calibration": calibration,
        "fingerprint": fingerprint,
    }

    Path(args.out).write_text(json.dumps(record, indent=2) + "\n")
    print(f"wrote {args.out} build_id={build_id} stripped={not has_symtab} "
          f"zval_ptr_dtor={exploit['zval_ptr_dtor']} zif_system={exploit['zif_system']}")
    if missing_a:
        print(f"WARNING: missing Tier A symbols: {missing_a}", file=sys.stderr)
        if not args.allow_missing_tier_a:
            sys.exit(2)


if __name__ == "__main__":
    main()
