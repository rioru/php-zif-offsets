# php-zif-offsets

A reproducible, per-build catalog of PHP interpreter symbol offsets for security research on CVE-2026-109618 / CVE-2026-109619
("php2shell"), a use-after-free in PHP's session upload-progress tracking
(rfc1867.c) disclosed and fixed in the PHP releases of 2026-10-21.

The dataset is a static table of ELF symbol offsets (plus struct layouts)
for many public PHP builds, used for lab reproducibility and detection
research against unpatched lab instances. Everything here comes from OFFLINE
STATIC ANALYSIS of publicly downloadable binaries (and, where needed for
reference builds only, their public debug-info packages); no live systems
are involved.

## Dataset

One JSON row per (PHP build x binary) under `data/` — x86_64, NTS except
two ZTS builds (docker-library/php 5.4.32-apache and 5.5.16-apache;
`meta.thread_safety` says which, and ZTS rows carry a note with the TSRM
key globals). SAPI binaries of the same build are different binaries with
different offsets and are never merged.

Row filenames end with the ELF architecture, e.g.
`docker-php-8.3.35-apache-libphp-x86_64.json`, and `meta.arch` records it
too; an aarch64 pass can therefore add rows without filename collisions
(the writer scripts take `ARCH=aarch64`, but platform-aware image pulls
are not implemented yet).

| family | rows | builds |
|---|---|---|
| docker-library/php | 1,256 | every tag Docker Hub still serves: 5.3.29-8.5.12, 422 versions (apache/fpm/cli; not every SAPI exists for every tag) |
| debian (snapshot.debian.org) | 750 | stretch 7.0, buster 7.3, bullseye 7.4, bookworm 8.2, trixie 8.4 — every archived source version incl. security uploads (apache/fpm/cgi) |
| ubuntu (Launchpad) | 284 | xenial 7.0, bionic 7.2, focal 7.4, jammy 8.1, noble 8.3 — every published update build (apache/fpm) |
| fedora (koji) | 742 | fc28-fc43, php 7.2-8.5 — every binary build (cli/fpm) |
| remi (el8/el9) | 13 | 7.4.33-8.5.12 (fpm) |
| rocky (8/9 AppStream) | 9 | rocky-8 7.2.24-8.2.35, rocky-9 8.0.30-8.3.36 (fpm) |
| alpine (3.16/3.18/3.22) | 11 | php81/82/83/84: fpm + apache mod_php + session.so rows |

Total: 3,065 rows. Archive rows (debian/ubuntu/fedora sweeps) are
**binaries-only**: no debug package is downloaded per row — local symbols
are recovered by masked pattern match against a merged reference build
(see Method). Rows carry the full package version string in the
filename (e.g. `7.4.3-4ubuntu2.28`, `8.4.27-2.fc43`) because archive
backports share upstream versions.

Binary types: `static-pie` executables (php-fpm, php cli/cgi), `shared-libphp`
(libphp.so / mod_php.so), and `shared-ext` (Alpine session.so).

## Row format

Each row has four objects (see PLAN.md for the full field list):

- `meta` — package version string, NTS/ZTS, arch, build-id, stripped or not,
  and which method produced the symbols (`symbol_source`), plus a `notes`
  list for build quirks.
- `exploit` — Tier A, required for every row: `zval_ptr_dtor` (primary ASLR
  anchor + build fingerprint), `zif_system` / `zif_exec` / `zif_passthru` /
  `zif_shell_exec` (command-execution targets and fallbacks),
  `zend_reference_destroy`, `zend_array_destroy`, `ps_globals` (PS(id) lives
  at `ps_globals_id_offset`, verified per build), `php_rfc1867_callback`.
- `calibration` — Tier B, best-effort tracing set: `php_session_*`, `ps_*`,
  allocator entry points (`_efree`, `_emalloc`, `zend_mm_gc`, ...), request
  lifecycle (`php_request_startup`/`php_request_shutdown`), and the data
  globals (`alloc_globals`, `sapi_globals`, `executor_globals`,
  `core_globals`, `compiler_globals`, `sapi_module`).
- `fingerprint` — `zval_ptr_dtor mod 0x1000` and `zif_system mod 0x1000`,
  the low 12 bits that survive ASLR in a leaked pointer. Collisions are
  cataloged in COLLISIONS.md.

## Offset-to-runtime-address rule

All offsets are ELF `st_value` (link-time addresses), reported as hex
strings. The runtime absolute address is:

- shared objects (`libphp.so`, `mod_php.so`, `session.so`): the binary's
  lowest mapping base in `/proc/<pid>/maps`, plus the offset;
- static PIE executables (`php-fpm`, `php` cli/cgi): the base of the
  binary's own mapping (its lowest mapping in `/proc/<pid>/maps`), plus
  the offset.

Heap geometry (allocation order, effective bin sizes, live heap layout) is a
runtime property calibrated against lab instances; only struct sizes and
field offsets are cataloged here (STRUCTS.md).

## Method

`scripts/extract_symbols.py` is the core extractor; per symbol it climbs a
recovery ladder and records in `meta.symbol_source` / `meta.notes` which rung
produced the value:

1. Dynamic symtab (`readelf --dyn-syms`) — exported symbols of the binary.
2. Debug-file symtab merge — distro builds are stripped, but the full symtab
   lives in the public sidecar debug file (Debian/Ubuntu dbgsym ddebs,
   RHEL-family debuginfo RPMs, Alpine -dbg apks, Fedora koji). The debug file
   is paired by build-id and its symtab is merged in; on conflict the
   binary's own values win.
3. `zif_*` relocation trick — for stripped builds with no function symbols:
   find the vaddr of the `"system"` string in `.rodata` (the builtin entry's
   `fname`), scan `.rela.dyn` for the `R_X86_64_RELATIVE` relocation whose
   addend equals it (the `fname` slot of that `zend_function_entry`), and read
   the next relative relocation (`r_offset + 8`): its addend is `zif_system`'s
   vaddr. Sanity-checked: handler inside `.text`, arg_info inside
   `.data.rel.ro`. The same trick recovers every `zif_*` fallback.
4. Pattern-match / caller-anchor recovery against `--reference-binary` (an
   unstripped same-version build): masked byte-pattern match over `.text`
   with call-annotation verification, caller-anchored recovery when the
   anchor function exists in both builds, store/lea recovery for data
   symbols, and `alloc_globals` via the rip-relative `AG(mm_heap)` load in
   `_emalloc`/`_efree`. For the binaries-only archive sweeps the reference
   is a merged ELF (`work/refs/<family>-<suite>-<sapi>.merged`,
   `scripts/build_refs.sh`): the newest build of the same version family
   fused with its debuginfo symtab via `eu-unstrip`, so the reference has
   the real `.text` plus every local symbol.
5. `ps_globals_id_offset` via `pahole` over the debug file's DWARF
   (`php_ps_globals` struct tag), with annotation- and disassembly-based
   fallbacks.

## Regeneration

Each distro family has one driver script; each downloads its packages into
`work/` (gitignored) and rewrites its own `data/*.json` rows:

```sh
scripts/docker_pull.sh        # pull the docker-library/php images first
scripts/docker.sh             # docker-library/php rows (apache/fpm/cli)
scripts/docker_extra.sh       # pinned point-release docker rows
scripts/docker_all_versions.sh  # docker-library/php: EVERY historical tag (5.3.29-8.5.x)
scripts/debian.sh             # debian bookworm/trixie current (apache/fpm/cgi)
scripts/ubuntu.sh             # ubuntu jammy/noble current (apache/fpm)
scripts/redhat.sh             # rocky 9 appstream + remi el9 (fpm)
scripts/alpine.sh             # alpine 3.22 (fpm/apache/session)
scripts/fedora.sh             # fedora 43 current (cli/fpm)
scripts/build_refs.sh         # eu-unstrip merged pattern references for the archive sweeps
scripts/debian_archive.sh     # debian: every historical build on snapshot.debian.org
scripts/ubuntu_archive.sh     # ubuntu: every historical build on Launchpad
scripts/fedora_archive.sh     # fedora: every historical build in koji (fc28+)
python3 scripts/make_structs.py     # STRUCTS.md (needs work/ debug files + pahole)
python3 scripts/make_collisions.py  # COLLISIONS.md (needs only data/)
python3 scripts/audit.py            # dataset audit: zero unexplained nulls expected
```

All sweep scripts are resumable (existing `data/` rows are skipped) and
cache downloads under `work/` (gitignored).

Requirements: `curl`, `ar`/`tar`/`zstd`/`bsdtar`, `rpm2cpio`/`cpio`,
`readelf`, `pahole`, `jq`, `python3`; `docker` for the docker family only.
The distro scripts are offline in the sense that they only fetch public
packages; no lab or live system is contacted.

## Caveats

- **Alpine session split rows.** Alpine builds the session extension as a
  shared module, so the Tier A set spans two binaries: the SAPI binary
  (php-fpm / mod_php.so) carries the core interpreter symbols but not
  `ps_globals`; `session.so` carries `ps_globals` and the `php_session_*`
  symbols but the core symbols are UND imports. Both rows are emitted with
  `--allow-missing-tier-a` and cross-reference each other in `meta.notes`.
  The session.so rows have null fingerprints and are excluded from the
  collision analysis.
- **`zend_mm_safe_error` removal.** Removed upstream in the php
  8.2.35/8.3.36/8.4.27/8.5.12 patch releases (present in earlier 8.x patch
  releases; `zend_mm_panic` is the closest equivalent). Ubuntu jammy renames
  it `zend_mm_safe_error_ex`; the extractor has a fallback. Rows record null
  plus a note when it is absent.
- **RHEL-family dwz.** RHEL-family debuginfo is dwz-compressed: the
  collection-wide `-debuginfo` RPM (carrying `/usr/lib/debug/.dwz/<name>`)
  must be extracted into the same tree as the per-binary debuginfo so
  `.gnu_debugaltlink` resolves. Remi uses mirrored debug paths
  (`usr/lib/debug/opt/remi/php8X/root/...`), not `.build-id` files.
- **Fedora packaging.** Fedora's `php` RPM is a metapackage; the CLI binary is
  in `php-cli`, and `php-fpm` is `/usr/bin/php-fpm` from fc31 on
  (`/usr/sbin/php-fpm` on fc28-fc30; the archive script probes both).
- **Patch-version struct changes.** Same-version layouts are identical across
  distros, but patch releases can change layouts: php 8.2.32 (Debian
  bookworm) predates the CVE fix and the 8.2.33+ allocator rework — see
  STRUCTS.md.
- **Archive gaps.** A few source versions are unrecoverable from the
  archives themselves: debian php7.0 7.0.30-1 has no snapshot.debian.org
  page (superseded by 7.0.30-2 before capture), and fedora 7.3.8-1.fc30 /
  7.3.14-1.fc30 published src-only on kojipkgs. Every other null in the
  dataset is explained: `scripts/audit.py` classifies each null as
  version-legit (symbol does not exist in that PHP version), build-legit
  (ZTS TSRM indirection, Alpine shared session module, shared-ext rows),
  a documented recovery failure (extractor note), or best-effort
  (`zend_mm_safe_error`, static and usually inlined) — the audit exits
  non-zero on anything else and currently passes clean.
- **Fingerprint collisions.** `zval_ptr_dtor mod 0x1000` is not unique across
  builds; every colliding pair is flagged in COLLISIONS.md (including two
  fully interchangeable rocky-9/remi-el9 pairs).

## Future work

- **aarch64 pass.** Row filenames and `meta.arch` already carry the arch,
  and the writer scripts take `ARCH=aarch64`; what is missing is
  platform-aware package pulls (docker `--platform linux/arm64`,
  deb/rpm `_aarch64`/`aarch64` URLs) and aarch64 merged references.
- **pre-fc28 Fedora.** koji carries php builds back to 5.1.6, but
  before fc28 the subpackage split differs (the CLI binary ships in the
  `php` RPM, mod_php exists) and debuginfo availability is uncertain.
- **Remi / Rocky historical archives.** Only current versions are
  covered; vault.rockylinux.org and the Remi mirrors keep older
  point-release packages.
- **STRUCTS.md for 5.x/7.x.** Struct layouts are generated from DWARF;
  the docker 5.x/7.x binaries are stripped without debug files, so
  those minors would need distro debuginfo (ddebs/debuginfo RPMs) as
  the pahole source.

## Index

- PLAN.md — project spec: context, tiers, methods, output format.
- data/ — one JSON row per (build x binary).
- STRUCTS.md — struct layouts per PHP minor (generated by
  `scripts/make_structs.py`).
- COLLISIONS.md — build-fingerprint collisions (generated by
  `scripts/make_collisions.py`).
- scripts/ — the core extractor, one regeneration driver per distro family,
  and the two doc generators.
