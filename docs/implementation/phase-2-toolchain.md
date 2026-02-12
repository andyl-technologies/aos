# Phase 2: Production Stdenv and Core Packages

**Plan Phase:** 3 (Production Stdenv + Core Packages)

## Objective

Build the production standard environment (`stdenv/`) and all core packages (`pkgs/toolchain/`, `pkgs/core/`, `pkgs/compression/`, `pkgs/tls/`) using the bootstrap glibc and GCC from Phase 1. This establishes the production toolchain (GCC 13.3.0 + glibc 2.39) and the base utilities every AOS system needs.

## Prerequisites

- Phase 1 complete: `lib/` evaluates correctly, bootstrap chain builds through glibc 2.39
- `pkgs/versions.nix` and `pkgs/sources.nix` defined with all version pins and source hashes
- Understanding of the `mkDerivation` API from `lib/derivations.nix`

## Deliverables

### Production Stdenv (`stdenv/`)

- `stdenv/default.nix` -- Production stdenv (GCC 13.3 + glibc 2.39)
- `stdenv/cc-wrapper.nix` -- Compiler/linker wrapper (sets RPATH, search paths)
- `stdenv/setup.sh` -- Standard build environment setup script
- `stdenv/phases.nix` -- Default build phase definitions (list-of-steps, not strings)

### Package Infrastructure (`pkgs/`)

- `pkgs/default.nix` -- Package set composition (single entry point for all packages)
- `pkgs/versions.nix` -- Single source of truth for all package versions
- `pkgs/sources.nix` -- All source fetchers with pinned SHA-256 hashes

### Toolchain Packages (`pkgs/toolchain/`)

- `pkgs/toolchain/gcc.nix` -- GCC 13.3.0 (production compiler)
- `pkgs/toolchain/binutils.nix` -- Binutils 2.42
- `pkgs/toolchain/linux-headers.nix` -- Linux headers 6.12.11

### Core Packages (`pkgs/core/`)

- `pkgs/core/coreutils.nix`, `bash.nix`, `make.nix`, `grep.nix`, `sed.nix`, `gawk.nix`
- `pkgs/core/findutils.nix`, `tar.nix`, `gzip.nix`, `xz.nix`, `diffutils.nix`, `patch.nix`
- `pkgs/core/pkg-config.nix`, `perl.nix`, `bison.nix`, `texinfo.nix`

### Compression Libraries (`pkgs/compression/`)

- `pkgs/compression/zlib.nix` -- zlib 1.3.1
- `pkgs/compression/zstd.nix` -- zstd 1.5.6
- `pkgs/compression/lz4.nix` -- lz4 1.9.4

### TLS (`pkgs/tls/`)

- `pkgs/tls/openssl.nix` -- OpenSSL 3.3.2 (TLS 1.2/1.3 only, server-hardened)

## Detailed Task Checklist

### 2.1 Package Infrastructure

- [ ] Write `pkgs/versions.nix` containing all package versions as a structured Nix attrset:
  - [ ] `toolchain = { gcc = "13.3.0"; glibc = "2.39"; binutils = "2.42"; linux-headers = "6.12.11"; };`
  - [ ] `core = { make = "4.4.1"; coreutils = "9.5"; bash = "5.2.32"; ... };`
  - [ ] All version sections: toolchain, core, kernel, security, storage, networking, init, kubernetes, compression, tls, monitoring, bootstrap, image-tools, update
- [ ] Write `pkgs/sources.nix` containing all source URLs and SHA-256 hashes:
  - [ ] One entry per upstream source: `{ url = "mirror://gnu/..."; hash = "sha256-..."; }`
  - [ ] Single auditable file for all external inputs (no lock file needed)
- [ ] Write `pkgs/default.nix` composing the full package set:
  - [ ] Import each package file, passing `{ mkDerivation, sources, versions, ... }` as arguments
  - [ ] Wire up inter-package dependencies
  - [ ] Expose as a flat attrset accessible via `nix-build -A pkgs.<name>`

### 2.2 Production Stdenv

- [ ] Write `stdenv/default.nix`:
  - [ ] Build production GCC 13.3.0 using bootstrap GCC 7.5.0 + bootstrap glibc
  - [ ] Build final glibc 2.39 using production GCC 13.3.0
  - [ ] Compose the production stdenv wrapping GCC 13.3 + glibc 2.39
- [ ] Write `stdenv/cc-wrapper.nix`:
  - [ ] Wrapper script that sets `-rpath` for all linked binaries
  - [ ] Sets include and library search paths from `runtimeDeps`
  - [ ] Propagates `propagatedDeps` to downstream packages
- [ ] Write `stdenv/setup.sh`:
  - [ ] Standard environment variables (`PATH`, `C_INCLUDE_PATH`, `LIBRARY_PATH`, etc.)
  - [ ] Phase execution engine that iterates over the structured phase list
  - [ ] Default phase implementations (unpack, configure, build, install)
- [ ] Write `stdenv/phases.nix`:
  - [ ] Default phase list: `[ unpack configure build install ]`
  - [ ] Each phase: `{ name = "configure"; script = "./configure --prefix=$out"; }`
  - [ ] Helpers: `lib.replacePhase`, `lib.addPhaseAfter`, `lib.addPhaseBefore`

### 2.3 Toolchain Packages

- [ ] Write `pkgs/toolchain/gcc.nix` (GCC 13.3.0):
  - [ ] Source referenced from `sources.gcc`
  - [ ] Configure: `--enable-languages=c,c++`, `--disable-multilib`, `--disable-bootstrap`, `--with-system-zlib`
  - [ ] `buildDeps`: bootstrap GCC, bootstrap binutils
  - [ ] `runtimeDeps`: glibc, linux-headers
- [ ] Write `pkgs/toolchain/binutils.nix` (Binutils 2.42):
  - [ ] Standard autoconf build
  - [ ] `--enable-deterministic-archives`, `--enable-gold`
- [ ] Write `pkgs/toolchain/linux-headers.nix` (Linux headers 6.12.11):
  - [ ] `make headers`, `make headers_install`
  - [ ] Handle architecture detection (`ARCH=x86` for x86_64)
  - [ ] Remove `.install` files from output

### 2.4 Core Packages

Each package follows the same pattern -- a function taking `{ mkDerivation, sources, versions, ... }` and returning a derivation using `mkDerivation`:

- [ ] `coreutils.nix` -- GNU Coreutils 9.5
- [ ] `bash.nix` -- Bash 5.2.32
- [ ] `make.nix` -- GNU Make 4.4.1
- [ ] `grep.nix` -- GNU Grep 3.11
- [ ] `sed.nix` -- GNU Sed 4.9
- [ ] `gawk.nix` -- GNU Gawk 5.3.1
- [ ] `findutils.nix` -- GNU Findutils 4.10.0
- [ ] `tar.nix` -- GNU Tar 1.35
- [ ] `gzip.nix` -- Gzip 1.13
- [ ] `xz.nix` -- XZ Utils 5.6.0
- [ ] `diffutils.nix` -- GNU Diffutils 3.10
- [ ] `patch.nix` -- GNU Patch 2.7.6
- [ ] `pkg-config.nix` -- pkg-config 0.29.2
- [ ] `perl.nix` -- Perl 5.38.2 (needed for building other packages)
- [ ] `bison.nix` -- GNU Bison 3.8.2
- [ ] `texinfo.nix` -- GNU Texinfo 7.1

### 2.5 Compression Libraries

- [ ] `pkgs/compression/zlib.nix` -- zlib 1.3.1 (non-autoconf configure)
- [ ] `pkgs/compression/zstd.nix` -- zstd 1.5.6 (CMake or make-based build)
- [ ] `pkgs/compression/lz4.nix` -- lz4 1.9.4

### 2.6 TLS

- [ ] `pkgs/tls/openssl.nix` -- OpenSSL 3.3.2:
  - [ ] Server-hardened build: TLS 1.2/1.3 only, modern cipher suites
  - [ ] `buildDeps`: perl (for Configure script)
  - [ ] `runtimeDeps`: zlib

### 2.7 Toolchain Validation

- [ ] Build a complex package (e.g., curl) that exercises the full toolchain (GCC, glibc, zlib, OpenSSL)
- [ ] Verify no references to bootstrap or upstream Nix packages in final package closures
- [ ] Inspect dependency graph: `aos graph coreutils`
- [ ] Verify `.override` mechanism works for customizing packages
- [ ] Verify structured phases can be replaced by downstream packages

## Acceptance Criteria

1. Production stdenv (GCC 13.3.0 + glibc 2.39) builds successfully from the bootstrap chain
2. All 16 core packages build and produce functional binaries
3. Compression libraries (zlib, zstd, lz4) build and are linkable
4. OpenSSL 3.3.2 builds with server-hardened configuration
5. `pkgs/default.nix` composes the full package set: `nix-build -A pkgs.coreutils` works
6. `pkgs/versions.nix` is the single source of truth for all version strings
7. `pkgs/sources.nix` is the single source of truth for all source URLs and hashes
8. `.override` works for customizing any package
9. Package dependency graph has no references to bootstrap-only packages
10. `aos build coreutils` succeeds end-to-end

## Key Design Decisions

### Sources Separated from Package Logic

Unlike nixpkgs where source URLs and hashes are inline in each package file, AOS keeps all sources in `pkgs/sources.nix`. This means:
- All external inputs are auditable in a single file
- Source mirroring and caching can be done independently of package logic
- Version bumps touch `pkgs/versions.nix` + `pkgs/sources.nix`, not the package definition

### Clean Input Naming

AOS replaces nixpkgs's confusing input names:
- `nativeBuildInputs` -> `buildDeps` (tools needed at build time, not in runtime closure)
- `buildInputs` -> `runtimeDeps` (libraries needed at runtime)
- `propagatedBuildInputs` -> `propagatedDeps` (propagate to downstream dependents)

### Structured Phases

Build phases are an ordered list of `{ name; script; }` records, not string concatenation. This allows:
- Inspection: list a package's phases to see exactly what runs
- Selective replacement: `lib.replacePhase "configure" { ... }`
- Insertion: `lib.addPhaseAfter "install" { name = "fixup-certs"; script = "..."; }`

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| GCC 13.3.0 build fails with bootstrap GCC 7.5.0 | Medium | Blocks production stdenv | The version chain (7.5 -> 13.3) is well-tested; match upstream configure flags |
| cc-wrapper RPATH handling breaks packages | Medium | Binaries can't find libraries | Test with several packages; inspect with `ldd` and `patchelf --print-rpath` |
| Some packages need custom phases | Low | Minor per-package work | The structured phase model supports full replacement; zlib already needs custom configure |
| Source hashes change upstream | Low | Build failures | All hashes are pinned; use content-addressed mirrors where possible |
| Circular dependency between packages | Medium | Nix evaluation fails | Map the full dependency graph before coding; use explicit build stages |
