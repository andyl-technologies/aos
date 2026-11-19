# Toolchain ladder

The AOS compiler is built from a 501-byte `hex0` executable and checked-in
source. No prebuilt compiler, libc, or host tool enters the chain. The ladder
has two layers with different characters: a bespoke source bootstrap that
reaches a GCC 2.95.3 era toolchain, and a series of GCC version tiers that
step through each compiler generation able to build the next.

## Source bootstrap

`stdenv/bootstrap/` targets `i686-linux`, because MesCC only produces i386
code. [`seeds/README.md`](../../../stdenv/bootstrap/seeds/README.md) documents
the seed, its review procedure, and what remains in the trust base.

```text
stage 0  hex0 seed            -> kaem, mkdir, ln
stage 1  hex0 + kaem          -> M2-Planet, M1, hex2, blood-elf, full kaem
stage 2  stage 1 tools        -> GNU Mes 0.27.1 (Scheme + MesCC)
stage 3  MesCC                -> TinyCC (boot0 -> boot1 -> boot2 -> release)
stage 4  TinyCC + bash        -> sed, grep, coreutils, make, binutils, GCC, ...
stage 5  stage 4 GCC          -> linux headers, glibc, self-hosted GCC, binutils,
                                 and every POSIX tool, rebuilt with GCC
```

No TinyCC-compiled binary leaves the bootstrap: stage 5 rebuilds everything
the ladder consumes. This layer stays hand-written because MesCC, TinyCC, and
the era's autoconf scripts need workarounds that do not generalize.

## GCC tiers

`stdenv/toolchains/default.nix` chains the tiers. Each tier is built by its
predecessor and contains a complete toolchain: compiler, binutils, linux
headers, glibc, and the POSIX tools.

| Tier | GCC | glibc | Platform |
|---|---|---|---|
| `gcc3_4` | 3.4.6 | 2.3.4 | i686 |
| `gcc3_4_cross` | cross | cross | i686 -> x86_64 |
| `gcc4_1` | 4.1.2 | 2.5 | x86_64 |
| `gcc4_4` | 4.4.7 | 2.12.2 | x86_64 |
| `gcc4_8` | 4.8.5 | 2.17 | x86_64 |
| `gcc4_8_cross` | cross | cross | x86_64 -> aarch64, only for aarch64 hosts |
| `gcc8` | 8.5.0 | 2.28 | x86_64 or aarch64 |
| `gcc8_cross` | cross | cross | -> riscv64, only for riscv64 hosts |
| `gcc11` | 11.5.0 | 2.34 | final host architecture |
| `gcc16` | 16.2.0 | 2.39 | final host architecture |

The final tier is the value of `stdenv/toolchains/default.nix`; to add a tier,
create its directory, chain it after the current final tier, and return it.
Tiers after a cross transition run on the x86_64 builder through QEMU
`binfmt_misc`, while their derivations keep the build platform's `system` for
scheduling. `stdenv/default.nix` wraps the final tier into the global stdenv,
which also exposes the bootstrap chain as `stdenv.bootstrap`.

### Per-tier standard environment

The global stdenv cannot build the compiler it wraps, so each tier needs its
own build environment made from its predecessor. `stdenv/tier-stdenv.nix`
(`mkTierStdenv`) turns any completed tier into the same `mkDerivation` shape:
it instantiates `cc-wrapper.nix` from the tier's compiler, libc, and binutils,
and builds the initial `PATH` from the tier's POSIX tools. The global stdenv is
`mkTierStdenv` applied to the final tier.

Tier tools are statically linked. The wrapper's static profile
(`staticDefault`, optionally `staticNoPie`) links with `-static`, omits the
dynamic linker and rpath injection, and disables default hardening.

### Manifest-built tools

The POSIX and autotools tools of each tier (coreutils, sed, grep, make, perl,
texinfo, python3, and so on) are data. A tier's `manifest.nix` records each
tool's version, source, configure flags, patches, and any local quirk.
`toolchains/lib/mk-autotools-tool.nix` builds one record with the tier stdenv,
and `toolchains/lib/mk-manifest-tools.nix` turns a list of manifest keys into
an attribute set, so a tier's `default.nix` only states ordering. A one-off
workaround is attached to the record that needs it rather than to the shared
recipe.

Two shared phase behaviors in `stdenv/phases.nix` replace per-package
boilerplate:

- `unpackMode = "tar-pipe"` copies the source through `tar`. Tiers whose
  `coreutils` hits `ENOSYS` from `fchmodat` during `cp -r` use it; newer tiers
  use the default copy.
- `freezeAutotoolsTimestamps` stamps generated autotools outputs newer than
  their inputs and exports `AUTOCONF`, `AUTOHEADER`, `ACLOCAL`, and `AUTOMAKE`
  as `true`, so release tarballs never regenerate their build system.

GCC and glibc use shared parametrized builders, `toolchains/lib/mk-gcc.nix`
and `toolchains/lib/mk-glibc.nix`. Version-specific logic stays in those
builders or in the tier's `gcc.nix` and `glibc.nix`: in-tree GMP, MPFR, MPC,
and ISL; the target sysroot; specs scrubbing that keeps the previous tier's
glibc out of the compiler's runtime closure; and the `include-fixed/limits.h`
chain. Cross tiers keep their explicit stage sequence (binutils, stage-1 GCC,
headers, glibc, stage-2 GCC) assembled from the same pieces.

### Final compiler bootstrap

Intermediate tiers build GCC once with `--disable-bootstrap`. Each exists only
to build its successor, and a miscompiled compiler fails while building the
next tier or its checks. The code GCC emits depends on its source, not on the
compiler that built it, so rebuilding an intermediate compiler with itself
would only make a disposable binary faster.

The final tier differs because its compiler builds the whole operating system.
`gcc16` first builds a stage-1 GCC 16 with GCC 11, uses it for the tier's
binutils, headers, and glibc, then builds the shipped compiler
(`gcc-stage2.nix`) with GCC's stock `make bootstrap` (`mk-gcc.nix` with
`bootstrap = true`). GCC's own bootstrap compares its stage-2 and stage-3
objects byte for byte, a reproducibility check the tier tightens with a strict
comparison patch and records in `nix-support/gcc-bootstrap-compare-files`. Only
GCC is bootstrapped: binutils, glibc, and the POSIX tools produce identical
output from any build of the same compiler version, so they are built once.

## Producer boundary rules

A ladder output is a compiler input for every later tier. A missing or broken
tool admitted at one rung tends to surface much later as an unrelated
configure failure, such as `GCC_NO_EXECUTABLES` inside fixincludes. The
builders therefore validate their own outputs before publishing:

- Stage 5 glibc may use `make -k` for optional static-bootstrap programs, but it
  must install and verify `libc.a`, `crt1.o`, `crti.o`, and `crtn.o`. It
  honors `NIX_BUILD_CORES`.
- Stage 5 findutils must provide executable `bin/find` and `bin/xargs`. Its
  recursive Makefile can otherwise hide a failed subdirectory.
- Native GCC builders check the installed frontends they promise (for example
  `g++`, `cc1plus`, and `lto1` on GCC 8) and compile and run a test program.
  GCC 4.8 runs a static program that calls `gettimeofday` and `time`.
- Static glibc tiers enable static NSS and confirm that `libnss_files.a`
  defines `_nss_files_getpwnam_r`. Their manifest tools link through
  `staticNssWrapper`, which groups the NSS and resolver archives.

A cached downstream package is not evidence for a changed producer. Validate a
ladder change by building the changed derivation itself, not only a consumer.

## Builder environment rules

The ladder must not depend on the builder's host tools or kernel options:

- Configure scripts run through the exact store-path `CONFIG_SHELL`, which is
  also exported as `SHELL`. Setting the variable without invoking configure
  through it does not override the script's shebang, and some probes fall back
  to sandbox paths such as `/bin/sh`.
- Discovery that early shells perform with globs (GCC language fragments under
  `gcc/*/config-lang.in`, glibc's x86_64 sysdeps preconfigure fragment, and the
  glibc 2.28 dynamic-loader `stamp.os` files) is patched to explicit
  enumeration and asserted at source preparation, so an upstream change fails
  early.
- glibc 2.3.4, 2.5, and 2.12 are patched to call `gettimeofday` and `time`
  through normal system calls instead of the fixed x86_64 vsyscall page, so the
  static tools run on kernels booted without `vsyscall=emulate`.
- The gcc4_1 tier's static glibc 2.3.4 `sed` segfaults with `-i` on recent
  kernels; that tier streams edits to a sibling file and copies the result back
  over the original inode, preserving modes.
- glibc 2.17's configure appends `/usr/bin` to its `bison` and `install-info`
  searches, so the tier pins both to AOS tools.

Package-specific workarounds that do not generalize are commented next to the
code that carries them.
