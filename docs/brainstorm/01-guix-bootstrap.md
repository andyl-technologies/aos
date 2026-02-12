# 01 - Bootstrap: From 357 Bytes to a Complete Toolchain

## Overview

AOS achieves full-source bootstrap — the entire toolchain is built from source starting
from ~357 bytes of hand-auditable binary seeds. No pre-compiled compilers, no opaque
binary blobs, no trust gaps. The bootstrap chain is expressed entirely as Nix derivations,
each stage building the tools needed for the next.

This document covers:
1. **Native Nix build environment** — no Docker, no containers, just `nix-build`
2. **Full-source bootstrap chain** — hex0 through GCC 13.3.0
3. **Package set architecture** — `default.nix`, `pkgs/versions.nix`, `pkgs/sources.nix`
4. **glibc build** — a complex package expressed via `mkDerivation`
5. **Build system internals** — how `lib/derivations.nix` drives the build
6. **CLI integration** — the `aos` tool wrapping `nix-build`

---

## Table of Contents

- [1. Native Nix Build Environment](#1-native-nix-build-environment)
- [2. Full-Source Bootstrap Chain](#2-full-source-bootstrap-chain)
- [3. Package Set Architecture](#3-package-set-architecture)
- [4. Building glibc: A Complex Package Example](#4-building-glibc-a-complex-package-example)
- [5. Build System Internals](#5-build-system-internals)
- [6. CLI Integration](#6-cli-integration)
- [Summary](#summary)

---

## 1. Native Nix Build Environment

### No Docker Required

The previous Guix-based architecture required a Docker container to run `guix-daemon`.
AOS eliminates this entirely. The only prerequisite is a working Nix installation
(any recent version supporting `builtins.derivation`).

```
# Build any package
aos build coreutils

# Build the entire bootstrap chain
aos build bootstrap.glibc

# Build a system image
aos system image server
```

Under the hood, `aos build <pkg>` invokes:
```
nix-build default.nix -A pkgs.<pkg>
```

There is no container, no daemon wrapper, no cross-platform shim. The Nix daemon
manages the store (`/nix/store`), builds in sandboxed derivations, and caches results
by content hash. The build environment is fully reproducible — determined entirely by
the Git commit of this repository.

### Entry Point: `default.nix`

The entire AOS system is defined in a single `default.nix` at the repository root:

```nix
# default.nix — the entire AOS system, evaluated from standard nix-build.
# No flakes. No experimental features. Pure, stable Nix.
let
  lib = import ./lib;
  pkgs = import ./pkgs { inherit lib; };
in {
  inherit pkgs lib;

  systems = {
    base = lib.evalModules { modules = [ ./systems/base.nix ]; inherit pkgs lib; };
    server = lib.evalModules { modules = [ ./systems/server.nix ]; inherit pkgs lib; };
    k8s-worker = lib.evalModules { modules = [ ./systems/k8s-worker.nix ]; inherit pkgs lib; };
    k8s-control-plane = lib.evalModules { modules = [ ./systems/k8s-control-plane.nix ]; inherit pkgs lib; };
  };

  images = builtins.mapAttrs (name: system:
    import ./images/${name}.nix { inherit pkgs lib system; }
  ) (import ./default.nix).systems;

  checks = import ./tests { inherit pkgs lib; };
}
```

This replaces:
- The Guix channel descriptor (`.guix-channel`)
- All Guile Scheme package modules (`channel/andyl/packages/*.scm`)
- The Docker Compose configuration (`docker/docker-compose.yml`)
- The TOML configuration layer (`config/*.toml`)

Every source URL and hash is pinned in `pkgs/sources.nix`. The entire build is
determined by the Git commit — no lock file needed because there are no floating inputs.

### Why No Flakes

Flakes are deliberately not used:
- Still "experimental" after years — the RFC was withdrawn when the implementation was merged
- Copies entire repo into `/nix/store` (world-readable) on every evaluation
- Lock file format is complex and surprising
- Conflates too many concerns (versioning, composability, CLI UX, evaluation hermeticity)

Instead, `default.nix` serves as the single entry point. The `aos` CLI (a Rust binary
wrapping `nix-build`/`nix-instantiate`) provides the user-facing interface with colored
output, progress indicators, and shell completions. Reproducibility is achieved simply:
every source URL and hash is pinned in `pkgs/sources.nix`, and the entire build is
determined by the Git commit of this repository.

---

## 2. Full-Source Bootstrap Chain

### The Problem: Trusting Your Compiler

Every compiled binary was produced by some compiler. That compiler was itself a compiled
binary. This creates a "trusting trust" problem (first described by Ken Thompson in 1984)
— how do you know your compiler hasn't been backdoored to inject code into everything
it compiles?

The answer: start from something small enough to audit by hand, and build everything
else from source.

### The Seeds: hex0 + kaem (~357 bytes)

The bootstrap begins with two tiny programs — the only pre-compiled binaries in AOS:

**hex0** (~357 bytes): Reads hex pairs from stdin, writes raw bytes to stdout. This is
the simplest possible "compiler" — hand-auditable x86 assembly. Given `48 65 6c 6c 6f`,
it writes `Hello`.

**kaem**: Minimal script executor. Reads a file line-by-line and executes each line as a
command. No variables, no control flow — just sequential execution.

Together these are the ONLY pre-compiled binaries in the entire AOS build chain.
Everything else is built from source.

These seeds are fetched as a fixed-output derivation in `stdenv/bootstrap/seeds.nix`:

```nix
# stdenv/bootstrap/seeds.nix — Bootstrap seeds (hex0 + kaem)
{ system ? "x86_64-linux", storeDir ? "/nix/store" }:

let
  version = "1.0.0";

  seedsArchive = builtins.derivation {
    name = "bootstrap-seeds-source-${version}";
    inherit system;
    builder = "builtin:fetchurl";
    url = "https://github.com/oriansj/bootstrap-seeds/archive/refs/tags/${version}.tar.gz";

    # Fixed-output derivation: content is verified by hash
    outputHash = "sha256-...";  # Pinned hash
    outputHashMode = "flat";
    outputHashAlgo = "sha256";
    preferLocalBuild = true;
  };

  seeds = builtins.derivation {
    name = "aos-bootstrap-seeds-${version}";
    inherit system;
    builder = "/bin/sh";
    args = [ "-c" ''
      mkdir -p $out/bin $out/src

      tar xzf ${seedsArchive}
      cd bootstrap-seeds-${version}

      # Select architecture-specific seeds
      arch_dir="NATIVE/x86"

      install -m 755 "$arch_dir/hex0-seed" $out/bin/hex0
      [ -f "$arch_dir/kaem-optional-seed" ] && \
        install -m 755 "$arch_dir/kaem-optional-seed" $out/bin/kaem

      # Include hex0 source for auditability
      [ -f "$arch_dir/hex0_x86.hex0" ] && \
        cp "$arch_dir/hex0_x86.hex0" $out/src/
    '' ];
  };
in seeds
```

Note: this uses `builtins.derivation` directly, not `mkDerivation` — because
`mkDerivation` hasn't been built yet. The bootstrap chain bootstraps the very
build system it runs on.

### The Chain: hex0 -> GCC 13.3.0

Each stage builds the tools needed for the next, expressed as Nix derivations in
`stdenv/bootstrap/`:

```
Stage 0: seeds.nix               hex0 + kaem (~357 bytes)
                                  |  hex0 reads hex, kaem runs scripts
Stage 1: stage1-mescc-tools.nix   hex0 -> hex1 -> hex2 -> M0 -> M1 -> M2-Planet -> kaem
                                  |  (each tool compiles the next, gaining capabilities)
                                  |  M2-Planet can compile simple C
Stage 2: stage2-mes.nix           GNU Mes (Scheme interpreter + MesCC C compiler)
                                  |  MesCC can compile larger C programs
Stage 3: stage3-tinycc.nix        TinyCC 0.9.27 (compiled by MesCC)
                                  |  TinyCC is a real C compiler
Stage 4: stage4-gcc46.nix         GCC 4.6.4 (C only, compiled by TinyCC)
                                  |  GCC 4.6 supports enough C++ for the next stage
Stage 5: stage5-gcc75.nix         GCC 7.5.0 (C + C++, compiled by GCC 4.6.4)
                                  |  GCC 7.5 can build modern glibc
Stage 6: stage6-glibc.nix         glibc 2.39 (compiled by GCC 7.5.0)
                                  |  Now we have a proper C library
Production stdenv:                 GCC 13.3.0 + glibc 2.39 (final toolchain)
```

### Stage 1 — mescc-tools (`stdenv/bootstrap/stage1-mescc-tools.nix`)

The mescc-tools chain builds increasingly capable assemblers and compilers, each
building the next:

- **hex1**: Like hex0 but supports single-character labels (useful for jumps)
- **hex2**: Extends hex1 with multi-character labels and relocation
- **M0**: Macro assembler — adds named macros to hex2
- **M1**: Adds line macros, conditionals
- **M2-Planet**: Simple C-to-assembly compiler written in M1 assembly
- **kaem**: Rebuilt with M2-Planet (gaining more features than the seed version)

Each step is a separate `builtins.derivation` using the prior step's output as its
builder. The chain is inherently sequential — each stage's output is the next stage's
compiler.

### Stage 2 — GNU Mes (`stdenv/bootstrap/stage2-mes.nix`)

GNU Mes is a Scheme interpreter that includes MesCC, a C compiler written in Scheme.
MesCC is bootstrapped by M2-Planet. Mes provides enough C compilation capability to
build TinyCC.

The key properties of Mes:
- Self-hosting Scheme interpreter (reads Scheme source, interprets it)
- MesCC: a C compiler written in Scheme, runs under the Mes interpreter
- Can compile a substantial subset of C89 — enough for TinyCC
- Source is ~30,000 lines, auditable by a determined reviewer

### Stage 3 — TinyCC (`stdenv/bootstrap/stage3-tinycc.nix`)

TinyCC (Tiny C Compiler) is a small, fast C compiler. Compiled by MesCC, it becomes
the first "real" compiler in the chain — fast enough and complete enough to compile
GCC itself.

TinyCC properties:
- ~40,000 lines of C (orders of magnitude smaller than GCC)
- Compiles fast (useful for bootstrapping)
- Supports C99, enough to build GCC 4.6.4
- Produces working but unoptimized code

### Stage 4 — GCC 4.6.4 (`stdenv/bootstrap/stage4-gcc46.nix`)

The oldest GCC version that TinyCC can successfully compile. GCC 4.6.4 supports
C and minimal C++, which is enough to bootstrap later GCC versions.

### Stage 5 — GCC 7.5.0 (`stdenv/bootstrap/stage5-gcc75.nix`)

Compiled by GCC 4.6.4. GCC 7.5 has full C++ support and can build modern glibc and
the production GCC 13.3.0.

### Stage 6 — glibc 2.39 (`stdenv/bootstrap/stage6-glibc.nix`)

The GNU C Library, compiled by GCC 7.5.0. This is the C library that all production
packages link against.

### Production stdenv (`stdenv/default.nix`)

GCC 13.3.0 compiled by GCC 7.5.0, linked against the bootstrap glibc 2.39. This is
the final compiler used for all AOS packages. The production stdenv wraps GCC 13.3 +
glibc 2.39 with proper RPATH handling via `stdenv/cc-wrapper.nix`.

Supporting files:
- `stdenv/setup.sh` — Standard build environment script (sets PATH, compiler vars)
- `stdenv/phases.nix` — Build phase definitions (the structured list-of-steps engine)
- `stdenv/cc-wrapper.nix` — Compiler/linker wrapper (sets RPATH, handles library paths)

### Bootstrap Verification

```
# Build the complete bootstrap chain
aos build bootstrap.glibc

# Verify the chain produced valid outputs
nix-store --query --tree $(aos build bootstrap.glibc)

# Check the seed binary sizes
ls -la $(nix-build default.nix -A pkgs.bootstrap.seeds)/bin/

# Verify determinism: build twice, compare hashes
aos build bootstrap.seeds
aos build bootstrap.seeds  # Same hash → deterministic
```

The bootstrap chain is fully deterministic — building it twice produces bit-identical
results in `/nix/store` (verified by content hash).

---

## 3. Package Set Architecture

### Three Key Files

AOS separates package definitions into three orthogonal concerns:

**`pkgs/versions.nix`** — Every package version in one place:

```nix
{
  toolchain = {
    gcc = "13.3.0";
    glibc = "2.39";
    binutils = "2.42";
    linux-headers = "6.12.11";
  };
  core = {
    make = "4.4.1"; coreutils = "9.5"; bash = "5.2.32";
    grep = "3.11"; sed = "4.9"; gawk = "5.3.1";
    findutils = "4.10.0"; tar = "1.35"; gzip = "1.13";
    xz = "5.6.0"; diffutils = "3.10"; patch = "2.7.6";
    pkg-config = "0.29.2"; perl = "5.38.2"; bison = "3.8.2";
    texinfo = "7.1";
  };
  kernel = { linux = "6.12.11"; firmware = "20241210"; };
  security = {
    selinux-userspace = "3.7"; audit = "4.0.2";
    refpolicy = "2.20240916"; container-selinux = "2.232.1";
    setools = "4.5.1";
  };
  storage = { zfs = "2.3.0"; };
  networking = {
    iproute2 = "6.11.0"; nftables = "1.1.0"; curl = "8.10.1";
    openssh = "9.9p1"; chrony = "4.6.1";
  };
  init = {
    dbus = "1.14.10"; util-linux = "2.40.2"; kmod = "33";
    systemd = "256.9"; dracut = "103";
  };
  kubernetes = {
    kubelet = "1.31.4"; kubeadm = "1.31.4"; kubectl = "1.31.4";
    containerd = "1.7.24"; runc = "1.2.4"; cni-plugins = "1.6.1";
    helm = "3.16.4"; crictl = "1.31.1";
  };
  compression = { zlib = "1.3.1"; zstd = "1.5.6"; lz4 = "1.9.4"; };
  tls = { openssl = "3.3.2"; };
  monitoring = { node-exporter = "1.8.2"; };
  bootstrap = {
    mescc-tools = "1.3.0"; mes = "0.27"; tinycc = "0.9.27";
    gcc-464 = "4.6.4"; gcc-750 = "7.5.0";
  };
  image-tools = {
    butane = "0.21.0"; ignition = "2.19.0";
    minisign = "0.11"; sbsigntools = "0.9.5";
  };
}
```

This replaces the TOML `config/versions.toml` — now native Nix, type-checked, no parser
needed.

**`pkgs/sources.nix`** — Every source URL and hash:

```nix
{
  gcc = { url = "mirror://gnu/gcc/gcc-13.3.0/gcc-13.3.0.tar.xz"; hash = "sha256-..."; };
  glibc = { url = "mirror://gnu/glibc/glibc-2.39.tar.xz"; hash = "sha256-..."; };
  openssl = { url = "https://www.openssl.org/source/openssl-3.3.2.tar.gz"; hash = "sha256-..."; };
  linux = { url = "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.12.11.tar.xz"; hash = "sha256-..."; };
  systemd = { url = "https://github.com/systemd/systemd/archive/refs/tags/v256.9.tar.gz"; hash = "sha256-..."; };
  # ... every source in one auditable file
}
```

Sources are separated from package build logic so they can be independently verified,
cached, and mirrored. A single `grep` over `sources.nix` reveals every upstream
dependency.

**`pkgs/default.nix`** — Package set composition:

```nix
{ lib }:
let
  versions = import ./versions.nix;
  sources = import ./sources.nix;
  mkDerivation = lib.mkDerivation;
  fetchurl = lib.fetchurl;

  callPackage = path: overrides:
    let fn = import path;
    in fn (builtins.intersectAttrs (builtins.functionArgs fn) self // overrides);

  self = {
    inherit mkDerivation fetchurl versions sources;

    # Toolchain
    gcc = callPackage ./toolchain/gcc.nix {};
    binutils = callPackage ./toolchain/binutils.nix {};
    linux-headers = callPackage ./toolchain/linux-headers.nix {};

    # Core
    coreutils = callPackage ./core/coreutils.nix {};
    bash = callPackage ./core/bash.nix {};
    make = callPackage ./core/make.nix {};
    grep = callPackage ./core/grep.nix {};
    sed = callPackage ./core/sed.nix {};
    # ... all packages
  };
in self
```

### Package Structure on Disk

```
pkgs/
├── default.nix              # Package set composition
├── versions.nix             # Version pins (single source of truth)
├── sources.nix              # Source URLs + hashes
├── toolchain/
│   ├── gcc.nix              # GCC 13.3.0
│   ├── binutils.nix         # Binutils 2.42
│   └── linux-headers.nix    # Linux headers 6.12.11
├── core/                    # Base utilities
│   ├── coreutils.nix
│   ├── bash.nix
│   ├── make.nix
│   ├── grep.nix
│   ├── sed.nix
│   ├── gawk.nix
│   ├── findutils.nix
│   ├── tar.nix
│   ├── gzip.nix
│   ├── xz.nix
│   ├── diffutils.nix
│   ├── patch.nix
│   ├── pkg-config.nix
│   ├── perl.nix
│   ├── bison.nix
│   └── texinfo.nix
├── compression/
│   ├── zlib.nix
│   ├── zstd.nix
│   └── lz4.nix
├── tls/
│   └── openssl.nix          # OpenSSL 3.3.2 (TLS 1.2/1.3 only)
├── init/
│   ├── dbus.nix
│   ├── util-linux.nix
│   ├── kmod.nix
│   └── systemd.nix          # systemd 256.9
├── kernel/
│   ├── linux.nix            # Custom kernel 6.12.11
│   ├── firmware.nix         # linux-firmware
│   └── config/              # Plain kconfig fragments
│       ├── base.config
│       ├── storage.config
│       ├── networking.config
│       ├── virtualization.config
│       ├── security.config
│       ├── drivers-vm.config
│       ├── drivers-cloud.config
│       └── drivers-baremetal.config
├── storage/
│   └── zfs.nix              # ZFS 2.3.0
├── security/
│   ├── audit.nix
│   ├── libsepol.nix
│   ├── libselinux.nix
│   ├── libsemanage.nix
│   ├── policycoreutils.nix
│   ├── setools.nix
│   ├── refpolicy.nix        # SELinux targeted policy
│   └── container-selinux.nix
├── networking/
│   ├── iproute2.nix
│   ├── iptables.nix
│   ├── nftables.nix
│   ├── curl.nix
│   ├── openssh.nix
│   ├── chrony.nix
│   └── ca-certificates.nix
├── containers/
│   ├── containerd.nix       # containerd 1.7.24
│   └── runc.nix             # runc 1.2.4
├── kubernetes/
│   ├── kubelet.nix          # 1.31.4
│   ├── kubeadm.nix
│   ├── kubectl.nix
│   ├── crictl.nix
│   ├── cni-plugins.nix
│   ├── helm.nix
│   ├── nerdctl.nix
│   ├── ethtool.nix
│   ├── socat.nix
│   ├── conntrack-tools.nix
│   └── ipvsadm.nix
├── monitoring/
│   └── node-exporter.nix    # 1.8.2
├── boot/
│   ├── dracut.nix
│   ├── ignition.nix
│   └── butane.nix
└── tools/
    ├── minisign.nix         # Bundle signing
    ├── sbsigntools.nix      # Secure Boot signing
    └── update-tool.nix      # AOS update agent
```

### Contrast with the Previous Guix Approach

| Concern | Guix (old) | Nix (new) |
|---------|-----------|-----------|
| Package definitions | Guile Scheme records in `channel/andyl/packages/*.scm` | Nix expressions in `pkgs/**/*.nix` |
| Version tracking | TOML file parsed by Scheme code | Native Nix attrset in `pkgs/versions.nix` |
| Source URLs | Embedded in package definitions | Separated to `pkgs/sources.nix` |
| Channel metadata | `.guix-channel` + `channel/andyl/` tree | `default.nix` at repo root |
| Build daemon | `guix-daemon` in Docker container | Standard `nix-daemon` (native) |
| Store path | `/gnu/store` | `/nix/store` (configurable via `storeDir`) |
| Package set composition | `(specifications->manifest ...)` | `callPackage` pattern |

---

## 4. Building glibc: A Complex Package Example

glibc is one of the most complex packages to build — it has extensive configure flags,
requires specific kernel headers, and produces multiple outputs (libraries, headers,
locale data). Here is how it looks as an AOS Nix derivation:

```nix
# pkgs/toolchain/glibc.nix
{ mkDerivation, fetchurl, versions, sources, gcc, linux-headers, bison, perl, python3 }:

mkDerivation {
  pname = "glibc";
  version = versions.toolchain.glibc;  # "2.39"
  src = fetchurl sources.glibc;

  # Build-only dependencies -- not in runtime closure
  buildDeps = [
    gcc
    bison     # Generates parser files
    perl      # Build scripts
    python3   # Test infrastructure
  ];

  # Runtime dependencies -- present in the final closure
  runtimeDeps = [
    linux-headers  # Kernel headers needed by glibc headers
  ];

  # Dependencies that propagate to anything depending on glibc
  propagatedDeps = [
    linux-headers
  ];

  # Structured build phases
  phases = [
    { name = "unpack"; script = "tar xf $src"; }
    {
      name = "configure";
      script = ''
        mkdir build && cd build
        ../configure \
          --prefix=$out \
          --with-headers=${linux-headers}/include \
          --enable-kernel=6.1 \
          --enable-stack-protector=strong \
          --enable-static-pie \
          --disable-profile \
          --disable-werror \
          libc_cv_slibdir=$out/lib
      '';
    }
    {
      name = "build";
      script = "cd build && make -j$NIX_BUILD_CORES";
    }
    {
      name = "install";
      script = "cd build && make install";
    }
    {
      name = "fixup-locales";
      script = ''
        # Install minimal locale data
        mkdir -p $out/lib/locale
        cd build
        make localedata/install-locales
      '';
    }
  ];

  meta = {
    description = "GNU C Library";
    homepage = "https://www.gnu.org/software/libc/";
    license = "LGPL-2.1-or-later";
  };
}
```

### Key points about this definition

**Clean dependency categories.** `buildDeps` (build-time only: gcc, bison, perl)
vs `runtimeDeps` (needed at runtime: linux-headers) vs `propagatedDeps` (inherited
by downstream packages). This replaces Guix's `native-inputs`/`inputs`/`propagated-inputs`
naming.

**Structured phases.** Each phase is a `{ name; script; }` record. The phase list can be
inspected, extended, or modified by name — unlike Guix's `modify-phases` or nixpkgs's
`preConfigure`/`postInstall` string concatenation.

**Central version and source references.** The version comes from `versions.toolchain.glibc`
(defined in `pkgs/versions.nix`), the source from `sources.glibc` (defined in
`pkgs/sources.nix`). The package definition contains only build logic.

**Out-of-tree build.** glibc requires building in a separate directory (`mkdir build && cd build`).
The phase structure makes this explicit.

### Contrast with the Previous Guile Definition

```scheme
;; Old Guix approach (channel/andyl/packages/glibc.scm)
(define-public glibc
  (package
    (name "glibc")
    (version (assoc-ref %versions "glibc"))
    (source (origin
              (method url-fetch)
              (uri (string-append "mirror://gnu/glibc/glibc-" version ".tar.xz"))
              (sha256 (base32 "..."))))
    (build-system gnu-build-system)
    (native-inputs (list bison perl python))
    (propagated-inputs (list linux-libre-headers))
    (arguments
      (list #:configure-flags ...
            #:phases (modify-phases %standard-phases ...)))))
```

The Nix version is more explicit: dependency categories are named for their intent,
phases are data structures, and source/version are referenced from central registries.

---

## 5. Build System Internals

### How `mkDerivation` Works

The core of the AOS build system is `lib/derivations.nix`, which defines `mkDerivation`.
This is AOS's own implementation — not nixpkgs's `stdenv.mkDerivation`.

Key design decisions:

**Default phases.** If no `phases` attribute is provided, four standard phases run:
unpack, configure, build, install. Packages only override what's different.

```nix
# Default phases (from lib/derivations.nix)
defaultPhases = [
  { name = "unpack"; script = "tar xf $src"; }
  { name = "configure"; script = "./configure --prefix=$out"; }
  { name = "build"; script = "make -j$NIX_BUILD_CORES"; }
  { name = "install"; script = "make install"; }
];
```

**Phase script generation.** The phase list is transformed into a single build script:

```nix
phaseScript = lib.concatMapStrings (phase:
  ''
    echo "==> Phase: ${phase.name}"
    ${phase.script}
  ''
) phases;
```

**Final derivation.** The `mkDerivation` function calls `builtins.derivation` with the
computed build script, declared dependencies, and environment:

```nix
builtins.derivation {
  name = "${attrs.pname}-${attrs.version}";
  system = attrs.system or "x86_64-linux";
  builder = "${bash}/bin/bash";
  args = [ "-c" phaseScript ];
  inherit (attrs) src;
  # ... dependency and environment setup
};
```

### Phase Manipulation

Phases are structured data, enabling precise manipulation:

```nix
# Replace a specific phase by name
lib.replacePhase phases "configure" {
  name = "configure";
  script = "cmake -B build -DCMAKE_INSTALL_PREFIX=$out";
};

# Add a phase after an existing one
lib.addPhaseAfter phases "install" {
  name = "post-install-fixup";
  script = "rm -rf $out/share/doc";
};

# Add a phase before an existing one
lib.addPhaseBefore phases "configure" {
  name = "patch-sources";
  script = "patch -p1 < ${./fix-build.patch}";
};

# Remove a phase entirely
lib.removePhase phases "configure";
```

This replaces both Guix's `modify-phases` mechanism and nixpkgs's string concatenation
approach (`preConfigure`, `postInstall`, etc.).

### Single Override Mechanism

Every package supports `.override` — one mechanism, not three:

```nix
# Override attributes directly
openssl.override { version = "3.4.0"; }

# Override with access to old values
openssl.override (old: {
  runtimeDeps = old.runtimeDeps ++ [ zlib ];
  phases = lib.addPhaseAfter old.phases "install" {
    name = "fixup-certs";
    script = "ln -s ${ca-certificates}/etc/ssl/certs $out/etc/ssl/certs";
  };
})
```

This replaces:
- Guix's `package/inherit` (package inheritance with field overrides)
- nixpkgs's `.override` (change function arguments)
- nixpkgs's `.overrideAttrs` (change derivation attributes)
- nixpkgs's `.overrideDerivation` (change the final derivation)

One mechanism, one mental model.

### The Nix Store

All build outputs live in `/nix/store` (configurable via the `storeDir` parameter
in `lib/derivations.nix`). Each derivation produces a store path:

```
/nix/store/abc123...-glibc-2.39/
```

The hash prefix is computed from all inputs to the derivation — source code,
dependencies, build script, environment variables. If any input changes, the hash
changes, and a new store path is produced. This is the foundation of Nix's
reproducibility guarantee.

Key store properties:
- **Content-addressed**: the hash encodes all build inputs
- **Immutable**: store paths are never modified after creation
- **Garbage-collected**: unused paths can be removed via `aos gc`
- **Shareable**: identical derivations on different machines produce the same store path

### Build Isolation

Every `mkDerivation` build runs in the Nix sandbox:
- Network access is disabled (except for fixed-output derivations like `fetchurl`)
- Only declared dependencies are visible
- The build directory is a fresh tmpdir
- No access to the host filesystem outside `/nix/store`
- Timestamps are normalized (all files dated 1970-01-01)
- Build environment variables are controlled

This ensures builds are reproducible regardless of the host system's configuration.

---

## 6. CLI Integration

### The `aos` Tool

The `aos` CLI is a Rust binary built with `clap`. It wraps standard `nix-build` and
`nix-instantiate` with proper error handling, colored output, and progress indication.

**Architecture** (`cli/`):

```
cli/
├── Cargo.toml
├── Cargo.lock
└── src/
    ├── main.rs              # Entry point, clap App setup
    ├── cli.rs               # Clap derive structs (Cli, Commands, SystemCmd, TestCmd, etc.)
    ├── nix.rs               # Nix subprocess wrapper (nix-build, nix-instantiate, nix-store)
    ├── output.rs            # Colored output, progress spinners, structured logging
    ├── error.rs             # Error types (thiserror)
    └── commands/
        ├── mod.rs
        ├── build.rs         # `aos build`
        ├── system.rs        # `aos system {build,image,eval}`
        ├── show.rs          # `aos show`
        ├── graph.rs         # `aos graph`
        ├── lint.rs          # `aos lint`
        ├── test.rs          # `aos test {eval,build,vm,fleet}`
        ├── gc.rs            # `aos gc`
        ├── why_depends.rs   # `aos why-depends`
        ├── describe.rs      # `aos describe`
        ├── shell.rs         # `aos shell`
        └── repl.rs          # `aos repl`
```

**Command mapping:**

| Command | Underlying Nix Invocation |
|---------|--------------------------|
| `aos build <pkg>` | `nix-build default.nix -A pkgs.<pkg>` |
| `aos build --all` | `nix-build default.nix -A pkgs` |
| `aos system build <v>` | `nix-build default.nix -A systems.<v>.toplevel` |
| `aos system image <v>` | `nix-build default.nix -A images.<v>` |
| `aos system eval <v>` | `nix-instantiate --eval --strict --json -A systems.<v>` |
| `aos show <pkg>` | `nix-instantiate --eval --strict --json -A pkgs.<pkg>.meta` |
| `aos graph <pkg>` | `nix-build ... && nix-store --query --graph` |
| `aos lint [pkg]` | `nix-build default.nix -A checks.lint[.<pkg>]` |
| `aos test [layer] [suite]` | `nix-build default.nix -A checks[.<layer>[.<suite>]]` |
| `aos gc` | `nix-collect-garbage --delete-older-than 7d` |
| `aos gc --list-generations` | `nix-env --list-generations` |
| `aos why-depends <p> <d>` | `nix-store --query --referrers-closure / --graph` |
| `aos shell` | `nix-shell shell.nix` |
| `aos repl` | `nix repl default.nix` |
| `aos describe` | `git rev-parse + nix-instantiate --eval` |
| `aos completions <sh>` | `clap_complete` generation |

**Key features:**
- `--json` flag on all commands for CI/scripting
- `--verbose` / `--quiet` for controlling output detail
- Shell completions for bash, zsh, fish via `aos completions <shell>`
- Exit codes: 0 = success, 1 = build/test failure, 2 = user error, 3 = nix not found
- Progress spinners during long builds via `indicatif`
- Streaming output from Nix subprocesses (not buffered)

The CLI self-bootstraps: even before the full package set builds, it works because it
only needs Nix installed on the host. The binary is built once via `cargo build --release`
and placed at the repo root.

### Convenience justfile

The `justfile` is a thin wrapper over `aos` commands:

```makefile
# justfile -- convenience targets wrapping `aos` commands

build pkg:
    aos build {{pkg}}

build-all:
    aos build --all

image variant:
    aos system image {{variant}}

test *args:
    aos test {{args}}

eval variant:
    aos system eval {{variant}}

shell:
    aos shell

lint:
    aos lint

gc:
    aos gc
```

---

## Summary

| Aspect | Previous (Guix) | Current (Nix) |
|--------|-----------------|---------------|
| Build environment | Docker container + guix-daemon | Native nix-build |
| Language | Guile Scheme | Nix expression language |
| Entry point | `.guix-channel` + channel tree | `default.nix` |
| Package defs | Scheme records | `mkDerivation` with structured phases |
| Dep naming | `native-inputs` / `inputs` / `propagated-inputs` | `buildDeps` / `runtimeDeps` / `propagatedDeps` |
| Versions | TOML parsed by Scheme | Native Nix attrset (`pkgs/versions.nix`) |
| Sources | Embedded in packages | Separated (`pkgs/sources.nix`) |
| Store | `/gnu/store` | `/nix/store` (configurable) |
| Override | `package/inherit` | Single `.override` |
| Phases | `modify-phases` on Scheme records | Ordered `[{name; script;}]` list |
| CLI | `guix build`, `guix system image` | `aos build`, `aos system image` |
| Bootstrap | Same chain (hex0 -> GCC), Scheme expressions | Same chain, Nix derivations |
