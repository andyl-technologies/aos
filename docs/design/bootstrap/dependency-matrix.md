# Bootstrap Stage Dependency Matrix

## Overview

The AOS bootstrap chain takes 229 bytes of hex0 machine code and builds up to
GCC 14.3.0 through 17 stages. This document catalogs the exact tool
dependencies at each stage, identifies gaps, and recommends fixes.

The chain as composed in `default.nix`:

| # | Name | What it produces |
|---|------|-----------------|
| 0 | seeds | hex0 (229 B), kaem (618 B) — the ONLY opaque binaries |
| 1 | mescc-tools | hex0..hex2, M0, M1, M2-Planet, kaem, blood-elf, mescc-tools-extra |
| 2 | mes | GNU Mes (mes-m2 Scheme interpreter, mescc C compiler, Mes libc) |
| 3 | tinycc | TCC 0.9.27 (from mescc), Mes libc (rebuilt), simple-patch |
| PT | posix-tools | make 3.82, sed 4.0.9, grep 2.4, patch 2.5.9 + mescc-tools-extra |
| 4 | binutils 2.20.1a | as, ld, ar, nm, objcopy, objdump, ranlib, readelf, strip |
| 5 | gcc 2.95.3 | First GCC (C only, no libgcc, Mes libc, static) |
| 6 | linux-headers 4.14 | Sanitized kernel UAPI headers |
| 7 | glibc 2.2.5 | First real C library (replaces Mes libc) |
| 8 | gcc 3.4.6 | C only, first GCC with glibc, has libgcc.a |
| 9 | gcc 4.1.2 | C only (RHEL 5) |
| 10 | gcc 4.4.7 | C+C++ (RHEL 6, last pure-C GCC source), first g++ |
| 11 | gcc 4.8.5 | C+C++ (RHEL 7, first C++ GCC source) |
| 12 | gcc 8.5.0 | C+C++ (RHEL 8) |
| 13 | gcc 11.5.0 | C+C++ (RHEL 9) |
| 14 | binutils 2.41 | Modern binutils |
| 15 | glibc 2.39 | Modern glibc + linux-headers 6.12 |
| 16 | gcc 14.3.0 | Production GCC (final output) |

---

## Tool Inventory: What Each Stage Provides

### mescc-tools-extra (from stage 1)
These are NOT POSIX-compatible replacements. They have different syntax:
- `catm <output> <input1> [input2...]` — concatenate files (NOT `cat`)
- `cp <src> <dst>` — copy one file
- `mkdir <dir>` — create one directory (no `-p`)
- `chmod <file>` — make file executable (no mode argument)
- `rm <file>` — remove one file
- `replace --file <f> --output <f> --match-on <old> --replace-with <new>`
- `untar --file <tarball>` — extract tar archive
- `ungz --file <gz> --output <tar>` — decompress gzip
- `unbz2 --file <bz2> --output <tar>` — decompress bzip2
- `unxz --file <xz> --output <tar>` — decompress xz
- `wrap` — create wrapper scripts

### posix-tools (currently built)
- `make` (GNU Make 3.82)
- `sed` (GNU sed 4.0.9)
- `grep` (GNU grep 2.4)
- `patch` (GNU patch 2.5.9)
- All mescc-tools-extra binaries (copied in as fallback)

### posix-tools (listed in header but NOT YET IMPLEMENTED)
- `bash` 2.05b
- `coreutils` 5.0 (cat, chmod, cp, echo, ln, ls, mkdir, mv, rm, touch, etc.)
- `findutils` 4.2.33 (find, xargs)
- `diffutils` 2.8.1 (cmp, diff)
- `gawk` 3.1.8 (awk)

---

## Stage-by-Stage Tool Usage Analysis

### Stage 0: seeds
**Builder**: `builtin:fetchurl` (Nix daemon, no shell)
**Tools needed**: NONE
**Tools available**: NONE
**Status**: CLEAN

### Stage 1: mescc-tools
**Builder**: `/bin/sh` (Nix sandbox provides this)
**Tools needed from /bin/sh**: `set`, `cd`, `for`, `case`, `if`, `echo`
**Tools needed (compiled from hex0)**: mkdir, symlink (compiled inline from hex0)
**External tools**: seeds.hex0, seeds.kaem
**Status**: CLEAN — fully hermetic, compiles its own mkdir/ln from hex0

### Stage 2: mes
**Builder**: `/bin/sh`
**Shell builtins used**: set, cd, echo, export, if/then, for, mkdir -p, chmod, cat, cp, rm, touch, sleep
**External tools used**: mescc-tools (M2-Planet, blood-elf, M1, hex2, catm, tar, replace, mkdir, cp, chmod)
**PROBLEM**: Uses `tar xzf` — this is `/bin/sh`'s `tar`, NOT mescc-tools. Also uses `cat >`, `cp -r`, `chmod -R`, `mkdir -p`, `rm -f` which are all shell builtins or `/bin/sh` utilities.
**Analysis**: This stage relies heavily on `/bin/sh` providing POSIX utilities. In the Nix sandbox, `/bin/sh` is dash which does NOT provide `tar`, `cp`, `cat`, `mkdir`, `chmod`, `rm`, `find`, `touch`, `sleep`. These come from the sandbox's coreutils.

**CRITICAL FINDING**: Stages 0-3 work because the **Nix sandbox provides /bin/sh AND basic coreutils** (tar, cp, cat, mkdir, chmod, rm, find, touch, sleep, ln, etc.). This is NOT the same as "using only mescc-tools". The sandbox coreutils are the hidden dependency.

### Stage 3: tinycc
**Builder**: `/bin/sh`
**Shell/coreutils used**: set, cd, echo, export, mkdir -p, tar xzf, tar xjf, chmod -R, chmod +x, cp, rm -f, cat, ln
**External tools**: mescc-tools (M1, hex2, blood-elf, catm, replace), mes (mes-m2, mescc.scm)
**PROBLEM**: Same as stage 2 — relies on sandbox coreutils for tar, cp, mkdir, chmod, rm.
**Status**: Hidden sandbox dependency

### posix-tools build (make, sed, grep, patch)
**Builder**: `/bin/sh`
**Tools used**: mescc-tools (unbz2, ungz, untar, catm), tinycc (tcc), gnumake (for sed/patch)
**Shell/coreutils used**: set, cd, cp, chmod, mkdir -p, ls, echo
**PROBLEM**: Uses `cp`, `chmod 755`, `mkdir -p` — sandbox coreutils.

### Stage 4: binutils 2.20.1a
**Builder**: `/bin/sh`
**PATH**: `posixTools/bin:tinycc/bin:mescc-tools/bin`
**Shell/coreutils used**: set, cd, echo, chmod -R, chmod +x, touch, ln, for, while, if
**External tools explicitly used**:
- `find . -name '*.sh' -exec chmod +x {} +` — **NEEDS find** (NOT in posixTools)
- `find . -name 'missing' -exec chmod +x {} +`
- `find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} +`
- `find . -name '*.c' -exec grep -l ... {} +`
- `sed -i` (have sed, but used with -i flag)
- `grep -l` (have grep)
- `chmod -R +x` (NOT mescc-tools chmod — needs real chmod)
- `touch` (NOT in posixTools)
- `ln -sf` (NOT in posixTools)
- `./configure` — **NEEDS bash or sh** (configure scripts are shell scripts)
- `make` (have it)
- `tcc` (have it)
**MISSING from posixTools**: find, touch, ln, real chmod (with args), real cp (with -r), real mkdir (with -p), bash/sh for configure scripts
**STATUS**: Relies on sandbox coreutils for find, touch, ln, chmod, cp, mkdir

### Stage 5: gcc 2.95.3
**Builder**: `/bin/sh`
**PATH**: `posixTools/bin:binutils/bin:tinycc/bin:mescc-tools/bin`
**Tools used**:
- `find . -name configure -exec chmod +x {} +`
- `find . -name '*.sh' -exec chmod +x {} +`
- `find . \( -name move-if-change ... \) -exec chmod +x {} +`
- `find . -type f -exec touch -t 200001010000 {} +`
- `sed -i 's/...'` (have it)
- `mkdir -p`
- `cp`
- `cat > file << 'WRAPPER'` — heredoc (needs shell)
- `chmod +x`
- `ln -sf`
- `./configure` — needs shell
- `make` (have it)
**MISSING**: find, touch, ln, real chmod, real cp, real mkdir, cat, bash

### Stage 6: linux-headers
**Builder**: `/bin/sh`
**PATH**: `gcc295/bin:binutils/bin:mescc-tools/bin`
**Tools used**:
- `find . -name '*.sh' -exec chmod +x {} +`
- `chmod -R u+w .`
- `make ARCH=i386 headers_install` — **kernel Makefile needs**: sh, cat, echo, test, expr, tr, sort, wc, find, xargs, awk, diff, cmp, head, tail, cut, sed, grep, basename, dirname, install, date, rm, mv, cp, ln, mkdir, touch, true, false, printf, readlink, uname
**CRITICAL**: The kernel headers_install target runs extensive shell scripts that need a nearly complete POSIX environment.
**MISSING**: Nearly everything. posixTools is not even on PATH here.

### Stage 7: glibc 2.2.5
**Builder**: `/bin/sh`
**PATH**: `gcc295/bin:binutils/bin:mescc-tools/bin`
**Tools used**:
- `find . -type f -exec touch -t ... {} +`
- `find . -name configure -exec chmod +x {} +`
- `find . -name '*.sh' -exec chmod +x {} +`
- `find . -name install-sh -exec chmod +x {} +`
- `find . -name mkinstalldirs -exec chmod +x {} +`
- `find . -name config.guess -exec chmod +x {} +`
- `find . -name config.sub -exec chmod +x {} +`
- `chmod +x scripts/*`
- `sed -i 's/...'`
- `cat > config.cache << 'EOF'`
- `cp -r`
- `./configure` — glibc's configure is very complex, needs full POSIX
- `make -j$(nproc)` — **NEEDS nproc** (NOT in posixTools or mescc-tools)
- `make install`
- `sleep 1` — **NEEDS sleep**
**MISSING**: find, touch, cat, cp -r, chmod with args, mkdir -p, ln, sleep, nproc, all tools configure expects (tr, sort, wc, expr, awk, etc.), bash

### Stages 8-13: GCC 3.4.6 through 11.5.0
**Builder**: `/bin/sh`
**PATH**: `prev-gcc/bin:binutils/bin:mescc-tools/bin`
**Common pattern** (all share this):
- `find . -name configure -exec chmod +x {} +`
- `find . -name '*.sh' -exec chmod +x {} +`
- `chmod +x move-if-change mkinstalldirs install-sh missing depcomp ylwrap`
- `find . -type f \( -name '*.c' -o -name '*.h' \) -exec touch {} +`
- `chmod -R u+w .`
- `mkdir -p`
- `./configure` — full autoconf configure
- `make -j$(nproc)`
- `make install`
- `ln -sf`
- `sed -i` (stages 8, 9 gcc wrapper)
- `cat > file << 'WRAPPER'` (stages 8, 9 gcc wrapper)
- `printf` (stage 8 smoke test)
**MISSING**: find, touch, chmod, mkdir -p, ln, cat, printf, nproc, full POSIX for configure

**NOTE**: posixTools is NOT on PATH for stages 6-13! Only mescc-tools is included. The configure/make infrastructure depends entirely on sandbox coreutils.

### Stage 14: binutils 2.41
**PATH**: `gcc115/bin:binutils220/bin:mescc-tools/bin`
**Same pattern as 8-13**: find, touch, chmod, mkdir, configure, make, install
**MISSING**: Same as above

### Stage 15: glibc 2.39
**PATH**: `gcc115/bin:binutils/bin:mescc-tools/bin`
**Additional**: `make ARCH=i386 headers_install` (kernel headers inline)
**MISSING**: Same as above + full kernel Makefile requirements

### Stage 16: gcc 14.3.0
**PATH**: `gcc115/bin:binutils/bin:mescc-tools/bin`
**Same pattern as 8-13**
**MISSING**: Same as above

---

## Complete Dependency Matrix

Tools marked:
- **S** = provided by Nix sandbox (hidden dependency)
- **M** = provided by mescc-tools/mescc-tools-extra
- **P** = provided by posix-tools
- **X** = MISSING (would fail without sandbox)
- **N** = not needed at this stage
- `-` = provided by the stage's own compiler

| Tool | Stage 0 | Stage 1 | Stage 2 | Stage 3 | PT build | Stage 4 | Stage 5 | Stage 6 | Stage 7 | Stages 8-16 |
|------|---------|---------|---------|---------|----------|---------|---------|---------|---------|-------------|
| /bin/sh | N | S | S | S | S | S | S | S | S | S |
| tar | N | N | S | S | N | N | N | N | N | N |
| cat | N | N | S | S | N | S | S | S | S | S |
| cp | N | N | S | S | S | S | S | S | S | S |
| cp -r | N | N | S | N | N | N | N | N | S | N |
| mkdir | N | hex0 | M | M | S | S | S | S | S | S |
| mkdir -p | N | N | S | S | S | S | S | S | S | S |
| chmod | N | N | M | M | S | S | S | S | S | S |
| chmod -R | N | N | S | S | N | S | S | S | S | S |
| rm | N | N | M | M | S | N | N | N | S | N |
| rm -f | N | N | S | S | N | N | N | N | N | N |
| ln | N | hex0 | N | N | N | S | S | N | N | S |
| ln -sf | N | N | N | N | N | S | S | N | N | S |
| touch | N | N | N | N | N | S | S | S | S | S |
| touch -t | N | N | N | N | N | N | S | S | S | S |
| find | N | N | N | N | N | S | S | S | S | S |
| sed | N | N | N | N | P(build) | P | P | S | S | S |
| sed -i | N | N | N | N | N | P | P | S | S | S |
| grep | N | N | N | N | P(build) | P | N | N | N | N |
| grep -l | N | N | N | N | N | P | N | N | N | N |
| make | N | N | N | N | P(build) | P | P | S | S | S |
| patch | N | N | N | N | P(build) | N | N | N | N | N |
| sleep | N | N | N | N | N | N | N | N | S | N |
| nproc | N | N | N | N | N | N | N | N | S | S |
| configure | N | N | N | N | N | S(sh) | S(sh) | S(sh) | S(sh) | S(sh) |
| echo | N | S | S | S | S | S | S | S | S | S |
| test/[ | N | S | S | S | S | S | S | S | S | S |
| expr | N | N | N | N | N | N | N | N | S | S |
| tr | N | N | N | N | N | N | N | N | S | S |
| sort | N | N | N | N | N | N | N | N | S | S |
| wc | N | N | N | N | N | N | N | N | S | S |
| head/tail | N | N | N | N | N | N | N | N | S | S |
| cut | N | N | N | N | N | N | N | N | S | S |
| awk | N | N | N | N | N | N | N | N | S | S |
| diff/cmp | N | N | N | N | N | N | N | N | S | S |
| basename | N | N | N | N | N | N | N | N | S | S |
| dirname | N | N | N | N | N | N | N | N | S | S |
| install | N | N | N | N | N | N | N | N | S | S |
| date | N | N | N | N | N | N | N | N | S | S |
| uname | N | N | N | N | N | N | N | N | S | S |
| readlink | N | N | N | N | N | N | N | N | S | S |
| printf | N | N | N | N | N | N | N | N | S | S |
| true/false | N | N | N | N | N | N | N | N | S | S |
| ls | N | N | N | N | S | N | N | N | S | S |
| xargs | N | N | N | N | N | N | N | N | S | S |
| tcc | N | N | N | - | P(build) | P | N | N | N | N |
| gcc | N | N | N | N | N | N | - | - | - | - |
| as/ld | N | N | N | N | N | - | - | - | - | - |
| M2-Planet | N | - | - | N | N | N | N | N | N | N |
| M1/hex2 | N | - | - | - | N | N | N | N | N | N |
| mescc | N | N | - | - | N | N | N | N | N | N |

---

## Key Findings

### 1. The Nix Sandbox Is the Hidden /bin/sh + Coreutils Dependency

Every stage uses `/bin/sh` as the builder, and the Nix build sandbox provides
not just `/bin/sh` (dash) but also a basic set of coreutils available in the
sandbox PATH. This includes: `tar`, `cat`, `cp`, `mkdir`, `chmod`, `rm`, `ln`,
`find`, `touch`, `sleep`, `nproc`, `echo`, `test`, `expr`, `tr`, `sort`, `wc`,
`head`, `tail`, `cut`, `awk`, `diff`, `cmp`, `basename`, `dirname`, `install`,
`date`, `uname`, `readlink`, `printf`, `true`, `false`, `ls`, `xargs`.

**This means the bootstrap is NOT fully hermetic from source**. It depends on
whatever tools the Nix sandbox provides, which come from the host's nixpkgs.

### 2. posix-tools Is Only Used by Stages 4-5 (and Even Then, Incompletely)

The `posixTools` variable is passed to stages 4-16, but only stages 4-5 put
it on PATH. Stages 6-16 use `mescc-tools/bin` directly and rely entirely on
sandbox coreutils for everything else.

Even for stages 4-5 where posixTools IS on PATH, the stages still use `find`,
`touch`, `ln`, `cat`, `chmod -R`, `mkdir -p` which are NOT in posixTools.

### 3. posix-tools Header Lists Tools Not Yet Implemented

The header comment in `stage4-posix-tools.nix` lists:
- coreutils 5.0 (cat, chmod, cp, echo, ln, ls, mkdir, mv, rm, touch, etc.)
- bash 2.05b
- findutils 4.2.33 (find, xargs)
- diffutils 2.8.1 (cmp, diff)
- gawk 3.1.8 (awk)

None of these are actually built. Only make, sed, grep, and patch are built.

### 4. posixTools Missing from PATH in Stages 6-16

Looking at `default.nix`, the `posixTools` argument IS passed to stages 6-16,
but examining the actual stage files:

- Stage 6 (linux-headers): `PATH="${gcc295}/bin:${binutils}/bin:${mescc-tools}/bin"` — **NO posixTools**
- Stage 7 (glibc 2.2.5): `PATH="${gcc295}/bin:${binutils}/bin:${mescc-tools}/bin"` — **NO posixTools**
- Stage 8 (gcc 3.4.6): `PATH="${gcc295}/bin:${binutils}/bin:${mescc-tools}/bin"` — **NO posixTools**
- Stages 9-16: Same pattern — **NO posixTools on PATH**

Despite receiving `posixTools` as an input parameter, none of these stages
actually put it on PATH. The posixTools parameter is accepted but UNUSED.

### 5. Configure Scripts Need a Full POSIX Shell Environment

GNU autoconf `configure` scripts use: sh, echo, test, cat, expr, tr, sort, wc,
find, sed, grep, awk, head, tail, cut, basename, dirname, printf, true, false,
rm, mv, cp, ln, mkdir, touch, chmod, uname, date, install, diff, cmp.

Without these, configure will fail or produce wrong results. Currently, the
sandbox provides all of them, masking the problem.

### 6. `make install` Needs `install` Command

Many `make install` targets use the `install` utility (from coreutils). This
is not provided by mescc-tools or posix-tools.

---

## Recommendations

### Phase 1: Complete the posix-tools Package (Critical)

Build these in posix-tools using TCC + Mes libc, following live-bootstrap:

1. **bash 2.05b** — Required as `$CONFIG_SHELL` for configure scripts. Live-bootstrap builds this with TCC.

2. **coreutils 5.0** — Provides: cat, chmod, chown, cp, cut, date, dd, dirname, du, echo, env, expr, false, head, id, install, join, ln, ls, md5sum, mkdir, mkfifo, mknod, mv, nl, od, paste, printf, pwd, readlink, rm, rmdir, seq, sleep, sort, split, stat, stty, sum, tail, tee, test, touch, tr, true, tsort, uname, uniq, wc, who, yes. Live-bootstrap builds these individually from TCC.

3. **findutils 4.2.33** — Provides find, xargs. Live-bootstrap builds with TCC.

4. **diffutils 2.8.1** — Provides diff, cmp. Live-bootstrap builds with TCC.

5. **gawk 3.1.8** — Provides awk. Live-bootstrap builds with TCC.

6. **tar 1.14** (or similar) — Currently using mescc-tools' `untar` for extraction, but GNU tar is needed for `make install` targets that create tarballs. Also `tar xzf` is used in stages 2-3. Live-bootstrap builds tar 1.14 with TCC.

7. **gzip 1.2.4** — For `tar xzf` support. Live-bootstrap builds with TCC.

8. **bzip2 1.0.8** — For `.tar.bz2` extraction. Live-bootstrap builds with TCC.

### Phase 2: Add posixTools to PATH in ALL Stages

Every stage from 4 onward should include posixTools on PATH:

```nix
export PATH="${posixTools}/bin:${gcc}/bin:${binutils}/bin"
```

The `mescc-tools/bin` should be LAST on PATH (or removed) since posix-tools
already copies mescc-tools-extra utilities as fallbacks.

### Phase 3: Stop Relying on Nix Sandbox Coreutils

Once posix-tools provides a complete POSIX environment, stages should
explicitly use ONLY tools from posix-tools + the stage's own compiler/binutils.
The `/bin/sh` builder should be the ONLY sandbox dependency.

To verify: temporarily restrict PATH to only posix-tools + compiler + binutils
and see what breaks.

### Phase 4: Consider a `CONFIG_SHELL` Strategy

Configure scripts need a POSIX-compliant shell. Options:
1. **bash from posix-tools** — Set `CONFIG_SHELL="${posixTools}/bin/bash"` in
   every configure invocation. This is the Guix approach.
2. **Use /bin/sh** — Continue using the sandbox's /bin/sh. This is simpler but
   less hermetic.

Recommendation: Build bash in posix-tools and use it as CONFIG_SHELL.

---

## Stage Ordering Assessment

The current ordering is **correct** for the compiler chain:

```
hex0 → mescc-tools → mes → tcc → make/sed/grep/patch → binutils → gcc 2.95
→ linux headers → glibc 2.2.5 → gcc 3.4.6 → 4.1.2 → 4.4.7 → 4.8.5
→ 8.5.0 → 11.5.0 → binutils 2.41 → glibc 2.39 → gcc 14.3.0
```

This matches the Guix/live-bootstrap proven order. No reordering needed.

However, posix-tools should be expanded BEFORE stage 4 (it already is in the
right position), and its tools should be used by all subsequent stages.

---

## Circular Dependency Analysis

**No circular dependencies exist.** The chain is strictly linear:

- Each stage depends only on outputs from earlier stages
- The only "sideways" dependency is posix-tools depending on both tinycc (stage 3) and mescc-tools (stage 1), which is fine
- GCC stages form a strict chain: 2.95 → 3.4.6 → 4.1.2 → 4.4.7 → 4.8.5 → 8.5.0 → 11.5.0 → 14.3.0
- The glibc upgrade (2.2.5 → 2.39) and binutils upgrade (2.20.1a → 2.41) happen only after GCC 11.5.0 is available

The potential circular dependency "GCC needs glibc, glibc needs GCC" is broken
by GCC 2.95.3 being freestanding (no libc needed to compile the compiler itself;
it uses Mes libc for linking). Then glibc 2.2.5 is built with GCC 2.95.3, and
subsequent GCCs link against glibc.

---

## Summary of What Needs To Be Built (In Order)

All built with TCC 0.9.27 + Mes libc, following live-bootstrap:

| Priority | Package | Version | Why Needed |
|----------|---------|---------|------------|
| 1 | coreutils | 5.0 | cat, cp, chmod, mkdir, ln, touch, echo, sort, tr, wc, head, tail, cut, basename, dirname, install, printf, true, false, test, expr, date, uname, env, sleep, rm, mv, ls, readlink |
| 2 | bash | 2.05b | Configure scripts need a real shell; CONFIG_SHELL |
| 3 | findutils | 4.2.33 | find, xargs (used in EVERY stage for permission fixups) |
| 4 | diffutils | 2.8.1 | diff, cmp (kernel headers_install, some configures) |
| 5 | gawk | 3.1.8 | awk (kernel Makefiles, some configures) |
| 6 | tar | 1.14 | GNU tar for make install targets |
| 7 | gzip | 1.2.4 | For tarball handling |
| 8 | bzip2 | 1.0.8 | For .tar.bz2 handling |

After building these, update ALL stage files (4-16) to include posixTools on
PATH and verify they work without sandbox coreutils.

---

## File Naming Issue

The `default.nix` references `./posix-tools.nix` but the file on disk is named
`stage4-posix-tools.nix`. One of these needs to be updated. Additionally, there
are duplicate files from a renaming (e.g., both `stage4-binutils220.nix` and
`stage5-binutils220.nix` exist with identical content). The numbering in
filenames does not match the logical stage numbers in `default.nix`.

Recommended naming convention: match the `default.nix` stage numbers, or drop
the stage numbers from filenames entirely since `default.nix` is the
authoritative composition.
