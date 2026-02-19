# Bootstrap & Toolchain Architecture

## Root of Trust

One opaque binary: **hex0** (229 bytes). Everything else is compiled from
auditable source. kaem is compiled from `kaem-minimal.hex0` by hex0 itself.

**No `/bin/sh` anywhere.** Zero host filesystem dependencies.

## Directory Structure

```
stdenv/
  bootstrap/                     # Stages 0-9: self-contained
    default.nix                  # Composes stages, exports clean interface
    stage0.nix                   # hex0 → kaem → stage0-posix
    stage1.nix                   # GNU Mes
    stage2.nix                   # TinyCC 0.9.27
    stage3-make382.nix           # GNU Make 3.82 (from TCC)
    stage3-sed409.nix            # sed 4.0.9 (from TCC)
    stage3-grep24.nix            # grep 2.4 (from TCC)
    stage3-patch259.nix          # patch 2.5.9 (from TCC)
    stage4-binutils220.nix       # binutils 2.20.1a (from TCC + make)
    stage5-gcc295.nix            # GCC 2.95.3 (from TCC + binutils)
    stage6-linuxHeaders414.nix   # Linux 4.14 headers (from gcc295)
    stage7-glibc225.nix          # glibc 2.2.5 (from gcc295 + headers)
    stage8-gcc346.nix            # GCC 3.4.6 (from gcc295 + glibc225)
    stage9-busybox136.nix        # BusyBox 1.36 (from gcc346 + glibc225)
    stage9-make44.nix            # GNU Make 4.4 (from gcc346 + glibc225)

  toolchain/                     # DAG, no stages
    default.nix                  # callPackage composition
    gcc412.nix                   # GCC 4.1.2
    gcc447.nix                   # GCC 4.4.7 (first C++)
    gcc485.nix                   # GCC 4.8.5
    gcc85.nix                    # GCC 8.5.0
    gcc115.nix                   # GCC 11.5.0
    binutils241.nix              # binutils 2.41 (rebuilt with gcc115)
    glibc239.nix                 # glibc 2.39 (rebuilt with gcc115)
    gcc143.nix                   # GCC 14.3.0
    bash52.nix                   # bash 5.2
    coreutils95.nix              # coreutils 9.5
    gnumake44.nix                # GNU Make 4.4 (rebuilt)
    sed49.nix                    # sed 4.9
    grep311.nix                  # grep 3.11
    findutils410.nix             # findutils 4.10
    gawk53.nix                   # gawk 5.3
    diffutils310.nix             # diffutils 3.10
    tar135.nix                   # tar 1.35
    gzip113.nix                  # gzip 1.13
    patch27.nix                  # patch 2.7

  default.nix                    # stdenv: mkDerivation, ccWrapper
  cc-wrapper.nix
  phases.nix
```

## Bootstrap Stages

### Stage 0 — stage0-posix

Builder: hex0 (229 B) compiles kaem from `kaem-minimal.hex0` source.
kaem drives the stage0-posix 3-phase build.

Output: mescc-tools + mescc-tools-extra (catm, cp, mkdir, chmod, rm,
replace, match, untar, ungz, unbz2, unxz, sha256sum, wrap) + full kaem.

### Stage 1 — GNU Mes

Builder: `${stage0}/bin/kaem`

Output: mes-m2 (Scheme interpreter), mescc (C compiler), Mes libc.

### Stage 2 — TinyCC

Builder: `${stage0}/bin/kaem`

Output: TCC 0.9.27 (5-pass bootstrap from mescc).

### Stage 3 — Build tools from TCC

Builder: `${stage0}/bin/kaem`

Separate sub-derivations, each compiling one tool directly with TCC:
- `make382` — GNU Make 3.82 (enumerate .c files, link with TCC)
- `sed409` — GNU sed 4.0.9
- `grep24` — GNU grep 2.4
- `patch259` — GNU patch 2.5.9

These are minimal, linked against Mes libc. Used only for stages 4-7.

### Stage 4 — binutils 2.20.1a

Builder: `${stage0}/bin/kaem`

Uses TCC + make382 + sed409. Manual build (kaem script, no ./configure).
Output: as, ld, ar, nm, objcopy, objdump, ranlib, readelf, strip.

### Stage 5 — GCC 2.95.3

Builder: `${stage0}/bin/kaem`

First GCC. C only, from TCC + binutils220. Linked against Mes libc.

### Stage 6 — Linux 4.14 headers

Builder: `${stage0}/bin/kaem`

Sanitized UAPI headers. Uses gcc295 to compile unifdef.

### Stage 7 — glibc 2.2.5

Builder: `${stage0}/bin/kaem`

First real C library. Built with gcc295 + binutils220 + linuxHeaders414.
Replaces Mes libc for all subsequent stages.

### Stage 8 — GCC 3.4.6

Builder: `${stage0}/bin/kaem`

Built with gcc295 + glibc225 + binutils220. Has proper libgcc.a.
This is the first **well-built** GCC — linked against real glibc.

### Stage 9 — BusyBox + Make

Builder: `${stage0}/bin/kaem`

- `busybox136` — BusyBox 1.36, built with gcc346 + glibc225. Single
  binary providing: sh, ash, cat, cp, chmod, mkdir, ln, mv, rm, touch,
  ls, find, xargs, grep, sed, awk, diff, patch, tar, gzip, sort, tr,
  wc, head, tail, cut, basename, dirname, echo, env, expr, printf,
  test, true, false, date, uname, install, readlink, sleep, nproc, ...
- `make44` — GNU Make 4.4, built with gcc346 + glibc225. Full-featured
  make for proper ./configure && make && make install builds.

## Bootstrap Boundary

### Exports from `bootstrap/default.nix`

```nix
{
  busybox136      = busybox136;      # shell + coreutils + everything
  make44          = make44;          # GNU Make 4.4
  gcc346          = gcc346;          # GCC 3.4.6 (C only)
  glibc225        = glibc225;        # glibc 2.2.5
  binutils220     = binutils220;     # binutils 2.20.1a
  linuxHeaders414 = linuxHeaders414; # Linux 4.14 headers
}
```

### What stays INTERNAL (never exported)

- hex0, kaem
- mescc-tools, mescc-tools-extra
- GNU Mes, Mes libc
- TinyCC 0.9.27
- make382, sed409, grep24, patch259 (TCC-built, Mes libc)
- gcc295 (intermediate, Mes libc)

## Builder chain (no /bin/sh)

```
Stage 0:  hex0 compiles kaem from source → kaem drives stage0-posix
Stage 1:  ${stage0}/bin/kaem
Stage 2:  ${stage0}/bin/kaem
Stage 3:  ${stage0}/bin/kaem
Stage 4:  ${stage0}/bin/kaem
Stage 5:  ${stage0}/bin/kaem
Stage 6:  ${stage0}/bin/kaem
Stage 7:  ${stage0}/bin/kaem
Stage 8:  ${stage0}/bin/kaem
Stage 9:  ${stage0}/bin/kaem  (last use of kaem as builder)

Toolchain: ${busybox136}/bin/sh  (BusyBox ash, built from source)
```

All bootstrap stages use kaem — no bash, no configure scripts, no /bin/sh.
The toolchain is the first place a real shell is used.

## Toolchain Design

### callPackage pattern

```nix
# toolchain/default.nix
{ bootstrap }:
let
  fetchurl = ...;

  callPackage = path: overrides:
    let
      fn = import path;
      auto = builtins.intersectAttrs (builtins.functionArgs fn) self;
    in fn (auto // overrides);

  self = {
    inherit fetchurl;

    # From bootstrap (versioned names — versionless aliases added later)
    inherit (bootstrap) busybox136 make44 gcc346 glibc225 binutils220
                        linuxHeaders414;

    # GCC version ladder (each depends on the previous)
    gcc412  = callPackage ./gcc412.nix {};
    gcc447  = callPackage ./gcc447.nix {};   # first C++
    gcc485  = callPackage ./gcc485.nix {};
    gcc85   = callPackage ./gcc85.nix {};
    gcc115  = callPackage ./gcc115.nix {};

    # Final toolchain (rebuilt with gcc115)
    binutils241 = callPackage ./binutils241.nix {};
    glibc239    = callPackage ./glibc239.nix {};
    gcc143      = callPackage ./gcc143.nix {};

    # Production POSIX tools (rebuilt with gcc143 + glibc239)
    bash52       = callPackage ./bash52.nix {};
    coreutils95  = callPackage ./coreutils95.nix {};
    gnumake44    = callPackage ./gnumake44.nix {};
    sed49        = callPackage ./sed49.nix {};
    grep311      = callPackage ./grep311.nix {};
    findutils410 = callPackage ./findutils410.nix {};
    gawk53       = callPackage ./gawk53.nix {};
    diffutils310 = callPackage ./diffutils310.nix {};
    tar135       = callPackage ./tar135.nix {};
    gzip113      = callPackage ./gzip113.nix {};
    patch27      = callPackage ./patch27.nix {};

    # Versionless aliases (point to production versions)
    gcc       = gcc143;
    glibc     = glibc239;
    binutils  = binutils241;
    bash      = bash52;
    coreutils = coreutils95;
    gnumake   = gnumake44;
    sed       = sed49;
    grep      = grep311;
    findutils = findutils410;
    gawk      = gawk53;
    diffutils = diffutils310;
    tar       = tar135;
    gzip      = gzip113;
    patch     = patch27;
  };
in self
```

### Architecture transition (i686 → x86_64)

All bootstrap and early toolchain builds target i686. Cross-compilation
happens in the toolchain:

```nix
gcc143cross = callPackage ./gcc143cross.nix {};
# i686 binary → x86_64 target

gcc143 = callPackage ./gcc143.nix {};
# native x86_64 (built by cross-compiler)
```

### stdenv wiring

```nix
let
  bootstrap = import ./stdenv/bootstrap {};
  toolchain = import ./stdenv/toolchain { inherit bootstrap; };
  stdenv = import ./stdenv {
    inherit (toolchain) gcc glibc binutils bash coreutils gnumake
                        sed grep findutils gawk diffutils tar gzip patch;
  };
  pkgs = import ./pkgs { inherit stdenv lib; };
in pkgs
```

## Summary

```
hex0 (229 B)
 └─ kaem (compiled from hex0 source)
     └─ stage0-posix (mescc-tools + extras)
         └─ GNU Mes (mescc, Mes libc)
             └─ TinyCC 0.9.27
                 ├─ make 3.82, sed, grep, patch
                 └─ binutils 2.20.1a
                     └─ GCC 2.95.3
                         └─ Linux 4.14 headers
                             └─ glibc 2.2.5
                                 └─ GCC 3.4.6
                                     ├─ BusyBox 1.36
                                     └─ Make 4.4
═══════════════ bootstrap boundary ═══════════════
                                     ├─ GCC 4.1.2 → 4.4.7 (C++)
                                     │  → 4.8.5 → 8.5.0 → 11.5.0
                                     ├─ binutils 2.41
                                     ├─ glibc 2.39
                                     ├─ GCC 14.3.0
                                     └─ bash 5.2, coreutils 9.5, ...
═══════════════ toolchain boundary ═══════════════
                                         └─ stdenv → all AOS packages
```
