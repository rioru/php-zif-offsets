# Project: PHP per-build symbol-offset database (defensive security research)

## Context and framing

I am doing defensive security research on CVE-2026-109618 / CVE-2026-109619
("php2shell"), a use-after-free in PHP's session upload-progress tracking
(rfc1867.c), publicly disclosed and fixed in the PHP releases of 2026-10-21
(https://www.php.net/archive/2026.php#2026-10-21-5; technical write-up:
https://www.wiz.io/blog/php2shell-php-rce). Part of this research is a
reliability study against unpatched lab instances of many PHP builds, which
requires a static, per-build table of PHP interpreter symbol offsets, plus a
catalog of struct layouts to compare builds and versions. Everything you
produce must come from OFFLINE STATIC ANALYSIS of publicly downloadable
binaries or their public debug-info packages. No live systems are involved;
this is a build catalog for lab reproducibility and detection research.

## Goal

Produce a reproducible dataset: one JSON record per (PHP build x binary),
covering as many public builds of PHP 8.1 ... 8.5 as practical (a second pass
may extend to 7.4 / 7.x / 5.6). Store everything in a git repository with one
regeneration script per distro family so the dataset can be rebuilt from
scratch.

## Builds to cover

1. Docker official images (unstripped, `nm` works directly):
   - php:8.1-apache ... php:8.5-apache (and any later 8.x):
     /usr/local/lib/php/libphp.so
   - php:8.x-fpm: /usr/local/sbin/php-fpm (static PIE binary, symbols present)
   - php:8.x-cli: /usr/local/bin/php (static PIE binary)
   IMPORTANT: apache (shared libphp.so), fpm and cli are DIFFERENT binaries
   with DIFFERENT offsets. Emit one JSON row per binary; never merge them.
2. Distro packages (usually stripped; use debug-info, see Methods):
   - Debian 12/13: libapache2-mod-php8.x, php8.x-fpm, php8.x-cgi
   - Ubuntu 22.04/24.04: libapache2-mod-php8.x, php8.x-fpm
   - RHEL 9 / AlmaLinux / Rocky Linux: php, php-fpm (AppStream)
   - Remi repository builds (CentOS/RHEL/Alma/Rocky/Fedora)
   - Fedora: php, php-fpm
   - Alpine: php83 / php84 (apache2 module + fpm)
3. For every row record: exact package version string, NTS vs ZTS, arch
   (x86_64 first), build-id (`readelf -n`), stripped or not, and which method
   produced the symbols.

## Offsets to extract

All offsets are ELF st_value (link-time addresses), reported as hex strings.
Runtime absolute address = the binary's lowest mapping base in
/proc/<pid>/maps plus the offset (for a shared libphp.so; for static PIE
binaries, the base of the binary's own mapping). State this rule in your
README.

### Tier A - required for every row (a row is incomplete without them)

| symbol                   | role                                              |
|--------------------------|---------------------------------------------------|
| zval_ptr_dtor            | primary ASLR anchor + build fingerprint (below)   |
| zif_system               | command-execution target                           |
| zif_exec                 | fallback if zif_system is unavailable             |
| zif_passthru             | fallback                                          |
| zif_shell_exec           | fallback                                          |
| zend_reference_destroy   | refcount-release target                           |
| zend_array_destroy      | array-destroy target                              |
| ps_globals                | session globals data symbol; PS(id) lives at +0x10 - verify and report the actual offset if a build differs |
| php_rfc1867_callback     | the callback pointer variable (data symbol)      |

### Tier B - calibration/tracing set (best-effort; report what exists)

php_session_initialize, php_session_reset_id, php_session_create_id,
ps_open_files, ps_close_files, php_session_abort (may appear mangled as
php_session_abort.isra.N - record the mangled name),
php_rshutdown_session_globals, php_session_rfc1867_callback, php_url_encode,
sapi_add_header_ex, sapi_header_op, zend_llist_destroy, zend_mm_gc,
zend_mm_free_pages, zend_mm_alloc_pages, zend_mm_shutdown, _efree, _emalloc,
_erealloc, zend_mm_safe_error, zend_mm_panic, rfc1867_post_handler,
php_hash_environment, php_request_startup, php_request_shutdown, and the
data globals: alloc_globals, sapi_globals, executor_globals, core_globals,
compiler_globals, sapi_module.

## Methods

- Unstripped binaries (docker official images): `nm -a` or `readelf -sW`.
- Stripped distro binaries: use public debug-info.
  - debuginfod: `debuginfod-find debuginfo <build-id>`; set DEBUGINFOD_URLS
    to the distro's server (debuginfod.debian.org, debuginfod.ubuntu.com,
    debuginfod.fedoraproject.org covers the RHEL family).
  - Debian dbgsym packages (the ddebs archive); Ubuntu ddebs.
  - RHEL family: `dnf debuginfo-install php php-fpm`.
- zif_* on stripped builds with no function symbols - the
  zend_function_entry relocation trick:
  1. Find the vaddr of the string "system" in .rodata (it is the `fname` of
     the ext/standard builtin entry).
  2. Scan .rela.dyn for an R_X86_64_RELATIVE relocation whose addend equals
     that vaddr; its r_offset is the fname slot of that zend_function_entry.
  3. zend_function_entry layout is {fname, handler, arg_info, num_args,
     flags}; the next R_X86_64_RELATIVE entry (r_offset + 8) has an addend
     equal to zif_system's vaddr.
  4. Sanity-check: the handler must land inside .text and arg_info inside
     .data.rel.ro.
  The same trick recovers any zif_* fallback. On aarch64 the relocation
  type is R_AARCH64_RELATIVE (same addend semantics); RELR-packed builds
  (Fedora fc41+, `-z pack-relative-relocs`) carry no RELA entries at all,
  so the trick reads the in-file slot values instead (the link-time
  vaddr is stored at the relocation target).

## Output format

One JSON file per build, e.g. data/docker-php-8.3.35-apache-libphp-x86_64.json
(the trailing token is the ELF architecture; `meta.arch` records it too):

```json
{
  "meta": {
    "php_version": "8.3.35",
    "thread_safety": "NTS",
    "arch": "x86_64",
    "distro": "docker-library/php",
    "package": "php:8.3.35-apache",
    "binary_path": "/usr/local/lib/php/libphp.so",
    "binary_type": "shared-libphp",
    "build_id": "<from readelf -n>",
    "stripped": false,
    "symbol_source": "nm"
  },
  "exploit": {
    "zval_ptr_dtor": "0x49ec50",
    "zif_system": "0x3ac080",
    "zif_exec": "0x...",
    "zif_passthru": "0x...",
    "zif_shell_exec": "0x...",
    "zend_reference_destroy": "0x49ebf0",
    "zend_array_destroy": "0x4b3c60",
    "ps_globals": "0x10432a0",
    "ps_globals_id_offset": "0x10",
    "php_rfc1867_callback": "0x350df0"
  },
  "calibration": {
    "php_url_encode": "0x3e3c50",
    "zend_mm_gc": "0x470730",
    "zend_mm_shutdown": "0x...",
    "_efree": "0x473db0",
    "alloc_globals": "0x1059b50"
  },
  "fingerprint": {
    "zval_ptr_dtor_mod_0x1000": "0xc50",
    "zif_system_mod_0x1000": "0x080"
  }
}
```

Also produce:

- COLLISIONS.md - flag every pair of builds whose zval_ptr_dtor mod 0x1000
  collide (and, separately, zif_system mod 0x1000). The research tooling uses
  zval_ptr_dtor mod 0x1000 as a build fingerprint, so collisions matter.
- STRUCTS.md - from debug-info via pahole, per build: sizeof and field
  offsets of zval (value, u1, u2), zend_string (gc, h, len, val),
  zend_array/HashTable (gc, u.flags, nTableMask, arData, nNumUsed,
  nNumOfElements, nTableSize, nInternalPointer, nNextFreeElement,
  pDestructor), zend_reference (gc, zval), and the zend_mm_chunk /
  zend_mm_heap header layout (we measured the chunk page-map at chunk+0x208
  on PHP 8.3 and chunk+0x250 on PHP 8.5 - confirm from debug-info).
- README.md - method, regeneration instructions, and the
  offset-to-runtime-address rule.
- One script per distro family so the whole dataset is reproducible.

## Fingerprint fields (compute for every row)

- zval_ptr_dtor mod 0x1000
- zif_system mod 0x1000

## Example row (real measured values, docker php:8.3.35-apache libphp.so)

ps_globals=0x10432a0, php_rfc1867_callback=0x350df0, zval_ptr_dtor=0x49ec50,
zend_reference_destroy=0x49ebf0, zend_array_destroy=0x4b3c60,
zif_system=0x3ac080, php_url_encode=0x3e3c50, zend_mm_gc=0x470730,
_efree=0x473db0, alloc_globals=0x1059b50.

## What is NOT recoverable statically (do not attempt)

Heap geometry - allocation order, effective bin sizes, the page-map offset
inside a running process's chunks, live heap layout - is a runtime property
we calibrate against lab instances. Only the struct sizes and field offsets
listed for STRUCTS.md are wanted from the binaries.

## Priority order

1. docker php:8.1-8.5, apache + fpm + cli (unstripped, fastest, complete)
2. Debian + Ubuntu mod_php + fpm
3. RHEL/Alma/Rocky + Remi
4. Alpine, Fedora
5. (second pass) PHP 7.4 / 7.x / 5.6 - note zval and zend_string layouts
   differ there; STRUCTS.md matters most for these.
