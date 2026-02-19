# Design: Bootstrap Chain to Production stdenv Integration

## Current State

### Two Parallel Build Worlds

AOS currently has **two separate build systems** that need to converge:

1. **Production packages** (`pkgs/default.nix`): Use pre-built `bootstrap-tools.nix`
   (a nixpkgs tarball with x86_64 GCC 13.x, glibc, coreutils, etc.). Every
   package in `pkgs/` builds against these binary bootstrap tools. The ccWrapper
   in `pkgs/default.nix` wraps the pre-built gcc from this tarball.

2. **Source bootstrap chain** (`stdenv/bootstrap/default.nix`): Builds from
   hex0 (229 bytes) through 17 stages to produce GCC 14.3.0, glibc 2.39, and
   binutils 2.41 -- all from source. Currently targets **i686-linux-gnu only**.

### Production stdenv (`stdenv/default.nix`)

The production stdenv requires 14 tool packages passed as arguments:

```
gcc, glibc, binutils, bash, coreutils, gnumake, findutils,
gawk, grep, sed, tar, gzip, diffutils, patch
```

It constructs a ccWrapper (`stdenv/cc-wrapper.nix`) and an `initialPath` from
these. Nothing calls this stdenv yet -- `pkgs/default.nix` has its own inline
ccWrapper built on top of the pre-built bootstrap-tools tarball.

### The Gap

The bootstrap chain's final outputs (gcc-14.3.0, glibc-2.39, binutils-2.41)
are i686-linux-gnu and **cannot** directly serve as the production stdenv for
an x86_64-linux system. Additionally, 11 of the 14 required tools are missing
(only gcc, glibc, binutils are produced).

---

## Architecture Transition: i686 to x86_64

### Why Everything Is i686

The MesCC x86_64 code generator is broken (GNU Mes issue #470). Following
Guix's proven approach, the entire early bootstrap (stages 0-17) targets
i686-linux-gnu (32-bit). All binaries, libraries, and configure scripts use
`--build=i686-linux-gnu --host=i686-linux-gnu --target=i686-linux-gnu`.

### The Cross-Compilation Stage (NEW: Stage 18)

After the bootstrap chain produces a working GCC 14.3.0 (i686), we need a
**cross-compilation stage** to transition to x86_64:

```
Stage 18: Cross-compilation pivot
  Input:  GCC 14.3.0 (i686, from stage 17)
          binutils 2.41 (i686, from stage 15)
          glibc 2.39 (i686, from stage 16)
  Output: GCC 14.3.0 (x86_64 cross-compiler, runs on i686, targets x86_64)

Stage 19: x86_64 bootstrap
  Input:  Cross-compiler from stage 18
  Output: binutils 2.41 (native x86_64)
          glibc 2.39 (native x86_64)
          GCC 14.3.0 (native x86_64)
```

#### Stage 18 Implementation Plan

Build a **cross-compiler**: an i686 binary that generates x86_64 code.

```sh
# Configure GCC as cross-compiler
CC="i686-gcc" CXX="i686-g++" \
./configure \
  --prefix=$out \
  --build=i686-linux-gnu \
  --host=i686-linux-gnu \
  --target=x86_64-linux-gnu \
  --enable-languages=c,c++ \
  --with-sysroot=/ \
  --disable-multilib
```

This is standard GCC cross-compilation -- the resulting gcc binary runs on
i686 but emits x86_64 ELF objects. Linux x86_64 kernels run i686 binaries
natively (32-bit compatibility), so the cross-compiler can execute in the Nix
build sandbox on x86_64-linux without emulation.

#### Stage 19 Implementation Plan

Use the cross-compiler to build native x86_64 versions of the core toolchain:

1. **Linux headers** (x86_64): `make ARCH=x86_64 headers_install`
2. **binutils 2.41** (x86_64): `--build=i686 --host=x86_64 --target=x86_64`
   (built by cross-compiler, runs on x86_64)
3. **glibc 2.39** (x86_64): `--build=i686 --host=x86_64`
4. **GCC 14.3.0** (x86_64): `--build=i686 --host=x86_64 --target=x86_64`
   (built by cross-compiler, native x86_64 binary)

After stage 19, we have a fully native x86_64 toolchain built entirely from
source.

#### Alternative: Skip Cross-Compilation

If building a cross-compiler proves complex, an alternative is to use GCC's
`-m64` flag. GCC 14.3.0 built as i686 can still emit x86_64 code if it was
configured with multilib support. However, this requires building multilib
glibc which adds significant complexity. The cross-compiler approach is
cleaner and more aligned with Guix's proven methodology.

---

## Missing Packages for stdenv

The production stdenv requires 14 tools. The bootstrap chain produces 3 of them
(gcc, glibc, binutils). The bootstrap `posix-tools.nix` (stage 4) already builds
early versions of 8 tools using TCC, but these are:
- i686 only
- Linked against Mes libc (not glibc)
- Ancient versions (bash 2.05b, coreutils 5.0, etc.)

### Package Build Order for stdenv

After the x86_64 toolchain is available (stage 19), we need to build modern
versions of the 11 missing tools. This is "Stage 20: stdenv tools."

Build order (respecting dependencies):

```
Phase A: No dependencies beyond toolchain
  1. bash 5.2        (needed by configure scripts of everything below)
  2. coreutils 9.5   (needed by every Makefile)
  3. gnumake 4.4     (needed to build remaining tools)

Phase B: Depends on Phase A
  4. sed 4.9
  5. grep 3.11
  6. gawk 5.3
  7. findutils 4.10
  8. diffutils 3.10
  9. patch 2.7
  10. tar 1.35
  11. gzip 1.13

Phase C: tar/gzip needed for extracting subsequent sources (but tar/gzip from
coreutils or busybox could bootstrap this -- or use mescc-tools' untar/ungz
during these builds)
```

All of these are standard GNU autotools packages that follow the
`./configure --prefix=$out && make && make install` pattern. They should each
be implemented as a file in `stdenv/bootstrap/` (e.g., `stage20-bash.nix`).

### posix-tools.nix as Stepping Stone

The existing posix-tools (make 3.82, sed 4.0.9, grep 2.4, patch 2.5.9 from
TCC) are used during the bootstrap chain itself (stages 5-17). They are NOT
suitable for the production stdenv because:
- They are i686, linked against Mes libc
- They are very old versions missing modern features
- They don't have bash, coreutils, findutils, gawk, tar, gzip, diffutils

However, `mescc-tools` provides `untar`, `ungz`, `unbz2`, `unxz` which can
extract source archives without needing tar/gzip. These mescc-tools utilities
will remain available during stages 18-20 for source extraction.

---

## cc-wrapper.nix: Eliminating /bin/sh

### Current Problem

The wrapper scripts in `stdenv/cc-wrapper.nix` use `#!/bin/sh` shebangs:

```sh
#!/bin/sh
# AOS GCC wrapper
exec ${cc}/bin/gcc $extra_cflags "$@" $extra_ldflags
```

The user wants to eliminate `/bin/sh` dependencies. In the Nix build sandbox,
`/bin/sh` is provided by Nix itself (it's part of the sandbox contract), but
on the running AOS system there should be no `/bin/sh`.

### Solution

The production `stdenv/cc-wrapper.nix` already accepts a `shell` parameter
and is invoked with `shell = "${bash}/bin/bash"` from `stdenv/default.nix`:

```nix
ccWrapper = import ./cc-wrapper.nix {
  shell = shellPath;  # = "${bash}/bin/bash"
  ...
};
```

But the generated wrapper scripts currently hardcode `#!/bin/sh`. **Fix**: The
wrapper derivation's `builder` already uses `shell` (bash), but the generated
wrapper script shebangs need to use `#!${shell}` instead of `#!/bin/sh`.

Change in `cc-wrapper.nix`:

```nix
# Before (current):
${cat} > $out/bin/gcc << 'WRAPPER_EOF'
#!/bin/sh

# After (fixed):
${cat} > $out/bin/gcc << WRAPPER_EOF
#!${shell}
```

Note: switching from `'WRAPPER_EOF'` (no interpolation) to `WRAPPER_EOF`
(with interpolation) means `$`-signs in the wrapper body need escaping.
Alternatively, write the shebang line separately then append the body:

```nix
${echo} "#!${shell}" > $out/bin/gcc
${cat} >> $out/bin/gcc << 'WRAPPER_EOF'
# rest of wrapper (no interpolation needed)
...
WRAPPER_EOF
```

### Bootstrap chain wrappers

The wrappers in `pkgs/default.nix` (the current ccWrapper for production
packages) also use `#!/bin/sh`. These will be replaced entirely once the
production stdenv is wired. During the bootstrap chain itself (stages 0-17),
`/bin/sh` is acceptable because the Nix sandbox provides it.

---

## Wiring Diagram: Seeds to Production Packages

### Complete Path

```
STAGE 0: hex0 (229 B) + kaem (618 B)
  |
STAGE 1: mescc-tools (hex0->hex1->hex2->M0->M1->M2-Planet->kaem)
  |
STAGE 2: GNU Mes (MesCC C compiler, Scheme-based)
  |
STAGE 3: TinyCC 0.9.26/0.9.27 (Mes libc, i686 only)
  |
STAGE 4a: posix-tools (make, sed, grep, patch from TCC)
STAGE 4b: binutils 2.20.1a (from TCC)
  |
STAGE 5: GCC 2.95.3 (C only, from TCC, Mes libc)
  |
STAGE 6: Linux headers 4.14
  |
STAGE 7: glibc 2.2.5 (first real libc, replaces Mes libc)
  |
STAGES 8-12: GCC 3.4.6 -> 4.1.2 -> 4.4.7 -> 4.8.5 -> 8.5.0
  |           (RHEL version ladder, all i686, all glibc 2.2.5)
  |
STAGE 13: GCC 11.5.0 (i686, glibc 2.2.5)
  |
STAGE 14: binutils 2.41 (i686, built by GCC 11.5.0)
  |
STAGE 15: glibc 2.39 (i686, built by GCC 11.5.0 + binutils 2.41)
  |
STAGE 16: GCC 14.3.0 (i686, glibc 2.39) -- current chain endpoint
  |
  +-- ARCHITECTURE TRANSITION --
  |
STAGE 17: GCC 14.3.0 cross-compiler (i686 -> x86_64)
  |
STAGE 18: Native x86_64 toolchain
  |  binutils 2.41 (x86_64)
  |  glibc 2.39 (x86_64)
  |  GCC 14.3.0 (x86_64)
  |
STAGE 19: stdenv tools (x86_64)
  |  bash, coreutils, gnumake, sed, grep, gawk,
  |  findutils, diffutils, patch, tar, gzip
  |
  +-- STDENV COMPOSITION --
  |
stdenv/default.nix receives all 14 packages:
  gcc = stage18.gcc
  glibc = stage18.glibc
  binutils = stage18.binutils
  bash = stage19.bash
  coreutils = stage19.coreutils
  gnumake = stage19.gnumake
  ... (remaining 8 tools from stage19)
  |
  v
stdenv.mkDerivation (with ccWrapper, initialPath)
  |
  v
pkgs/default.nix — all production packages built with stdenv
```

### Top-Level Wiring Changes

The `default.nix` at the project root currently does:

```nix
pkgs = import ./pkgs { inherit lib; };
```

And `pkgs/default.nix` internally imports `bootstrap-tools.nix`. This must
change to:

```nix
# default.nix (new)
let
  bootstrap = import ./stdenv/bootstrap {};

  # Build the cross-compiler and native x86_64 toolchain
  x86_64-toolchain = import ./stdenv/bootstrap/cross-to-x86_64.nix {
    inherit bootstrap;
  };

  # Build the stdenv tools (bash, coreutils, etc.)
  stdenvTools = import ./stdenv/bootstrap/stdenv-tools.nix {
    toolchain = x86_64-toolchain;
  };

  # Compose the production stdenv
  stdenv = import ./stdenv {
    gcc = x86_64-toolchain.gcc;
    glibc = x86_64-toolchain.glibc;
    binutils = x86_64-toolchain.binutils;
    bash = stdenvTools.bash;
    coreutils = stdenvTools.coreutils;
    gnumake = stdenvTools.gnumake;
    findutils = stdenvTools.findutils;
    gawk = stdenvTools.gawk;
    grep = stdenvTools.grep;
    sed = stdenvTools.sed;
    tar = stdenvTools.tar;
    gzip = stdenvTools.gzip;
    diffutils = stdenvTools.diffutils;
    patch = stdenvTools.patch;
  };

  # pkgs/default.nix must be refactored to accept stdenv
  pkgs = import ./pkgs { inherit stdenv lib; };
in { ... }
```

### pkgs/default.nix Refactoring

The current `pkgs/default.nix` constructs its own ccWrapper from
bootstrap-tools and defines its own `mkDerivation`. This must be replaced
to use the stdenv:

```nix
# pkgs/default.nix (new shape)
{ stdenv, lib }:
let
  mkDerivation = stdenv.mkDerivation;
  fetchurl = stdenv.fetchurl;
  # callPackage uses stdenv's mkDerivation
  callPackage = path: overrides: ...;
  self = { inherit mkDerivation fetchurl lib; }
    // discoverPackages ./.
    // { ... };
in self
```

Key change: `mkDerivation` comes from `stdenv` instead of being defined
locally. The ccWrapper, PATH setup, CC/CXX/LD variables, and C_INCLUDE_PATH
injection all come from the stdenv layer.

---

## Interim Migration Strategy

The full bootstrap chain (stages 0-19 + stdenv tools) may take time to build
and debug. An interim approach:

### Phase 1: Complete the i686 Bootstrap (Current Work)
Get stages 0-17 (current 0-16 + numbering alignment) building and passing.

### Phase 2: Cross-compile to x86_64
Add stages 18-19 (cross-compiler + native x86_64 toolchain).

### Phase 3: Build stdenv Tools
Add stage 20 (bash, coreutils, etc. from the x86_64 toolchain).

### Phase 4: Wire stdenv
Refactor `default.nix` and `pkgs/default.nix` to use the source-bootstrapped
stdenv instead of bootstrap-tools.nix.

### Phase 5: Remove bootstrap-tools.nix
Delete the nixpkgs bootstrap-tools dependency entirely.

During phases 1-3, the existing `bootstrap-tools.nix` system continues
building all production packages. The two systems coexist.

---

## Open Questions

1. **Shared libraries vs static**: The current bootstrap chain builds
   everything `--disable-shared` (static only). The production stdenv needs
   shared glibc (`ld-linux-x86-64.so.2`, `libc.so.6`). At minimum, glibc
   2.39 in the x86_64 stage must enable shared libraries. GCC's libstdc++
   should also be shared for C++ packages.

2. **Linux kernel headers version**: The bootstrap chain uses headers 4.14
   (for glibc 2.2.5) and 6.12 (for glibc 2.39). The production stdenv should
   use a single, modern version. The AOS kernel package already uses 6.12.

3. **Dynamic linker path**: The cc-wrapper hardcodes
   `ld-linux-x86-64.so.2` for x86_64. The i686 chain uses `/mes/loader`.
   The x86_64 glibc needs to install to a path where the cc-wrapper can find
   the dynamic linker: `${glibc}/lib/ld-linux-x86-64.so.2`.

4. **aarch64-linux**: The current design handles only x86_64. For aarch64,
   a similar cross-compilation path from i686 is needed, or alternatively
   aarch64 seeds (which exist in bootstrap-seeds but with a different MesCC
   codegen issue). This is a separate design concern.

5. **posixTools during cross-compilation**: Stages 18-19 need make, sed, grep,
   etc. to build GCC and glibc. The i686 posix-tools (from TCC/Mes libc) can
   run on x86_64 Linux (32-bit compat). Alternatively, build modern i686
   versions of these tools using the i686 GCC 14.3.0 before cross-compiling.
   The former is simpler; the latter produces better builds.
