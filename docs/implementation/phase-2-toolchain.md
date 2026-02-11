# Phase 2: Full Bootstrap Toolchain

**Phase Number:** 2

## Objective

Implement the complete bootstrap chain from binary seeds (hex0) through to a modern GCC, glibc, and full toolchain, entirely defined in the ANDYL channel with no dependency on upstream Guix packages or binary substitutes.

## Prerequisites

- Phase 1 complete: Docker environment running, `guix-daemon` operational, channel skeleton in place
- Understanding of Guix `(gnu packages commencement)` module structure
- Familiarity with the Guix full-source bootstrap (Mes, TinyCC, GCC chain)

## Deliverables

- `channel/andyl/packages/bootstrap.scm` -- Bootstrap seeds package (hex0, kaem)
- `channel/andyl/packages/commencement.scm` -- Complete bootstrap chain (Stages 0-6)
- `channel/andyl/packages/gcc.scm` -- Production GCC package
- `channel/andyl/packages/glibc.scm` -- Production glibc with server hardening flags
- `channel/andyl/packages/base.scm` -- Core toolchain packages (binutils, make, coreutils, bash, etc.)
- `channel/andyl/packages/linux.scm` -- Linux kernel headers package
- `channel/andyl/packages/compression.scm` -- zlib, xz, zstd, lz4
- `channel/andyl/packages/tls.scm` -- OpenSSL/LibreSSL
- Successfully built full toolchain stored in `/gnu/store/`

## Detailed Task Checklist

### 2.1 Study Upstream Commencement Module

- [ ] Read and annotate `(gnu packages commencement)` from Guix source (hundreds of package definitions)
- [ ] Map the complete dependency graph: hex0 -> hex1 -> hex2 -> M0 -> M1 -> M2-Planet -> kaem -> Mes -> MesCC -> TinyCC -> GCC 4.6.4 -> GCC 7.x -> GCC 10.x/13.x
- [ ] Identify the `%boot0-inputs` through `%final-inputs` input sets
- [ ] Document which packages use `trivial-build-system` vs. `gnu-build-system`
- [ ] Identify all intermediate packages (bootstrap-glibc, bootstrap-binutils, etc.)

### 2.2 Stage 0: Bootstrap Seeds

- [ ] Create `channel/andyl/packages/bootstrap.scm`
- [ ] Define `andyl-bootstrap-seeds` package
- [ ] Source: `bootstrap-seeds` repository from GitHub (oriansj/bootstrap-seeds)
- [ ] Pin version and verify sha256 hash
- [ ] Use `trivial-build-system` to extract and install architecture-specific seed binaries (hex0, kaem)
- [ ] Target x86_64 seeds (or aarch64 if building for ARM)
- [ ] Build and verify: `guix build andyl-bootstrap-seeds`

### 2.3 Stage 1: MesCC-Tools

- [ ] Define `andyl-mescc-tools` package in `commencement.scm`
- [ ] Source: mescc-tools repository (oriansj/mescc-tools), pinned version
- [ ] Build with `trivial-build-system` using only `andyl-bootstrap-seeds` as native input
- [ ] Implement the kaem.run build script that chains: hex0 -> hex1 -> hex2 -> M0 -> M1
- [ ] Define `andyl-mescc-tools-extra` for M2-Planet and additional tools
- [ ] Build and verify both packages

### 2.4 Stage 2: GNU Mes and TinyCC

- [ ] Define `andyl-mes` package (version 0.27)
- [ ] Source: GNU Mes tarball from ftp.gnu.org
- [ ] Build with `trivial-build-system`, using `andyl-mescc-tools` (M2-Planet compiles mes.c)
- [ ] Verify Mes can interpret Scheme and compile C via MesCC
- [ ] Define `andyl-tinycc-mescc` package (TinyCC 0.9.27)
- [ ] Source: TinyCC tarball from savannah.gnu.org
- [ ] Build with `trivial-build-system`, using `andyl-mes` (MesCC compiles tcc)
- [ ] Verify TinyCC can compile simple C programs
- [ ] Build and verify both packages

### 2.5 Stage 3: GCC 4.x from TinyCC

- [ ] Define `andyl-gcc-core-mesboot` package (GCC 4.6.4)
- [ ] Source: GCC 4.6.4 tarball from mirror://gnu/gcc/
- [ ] Build with `trivial-build-system`, using `andyl-tinycc-mescc` and `andyl-mescc-tools`
- [ ] Include a bootstrap glibc as input (define `andyl-bootstrap-glibc` -- minimal libc)
- [ ] Configure: C-only, no C++, no Fortran
- [ ] Verify GCC 4.6.4 can compile a "hello world" program
- [ ] Build and verify

### 2.6 Stage 3-4: Intermediate GCC (7.x)

- [ ] Define `andyl-gcc-mesboot` package (GCC 7.5.0)
- [ ] Source: GCC 7.5.0 tarball from mirror://gnu/gcc/
- [ ] Build with `gnu-build-system`, using `andyl-gcc-core-mesboot`
- [ ] Configure: `--enable-languages=c,c++`, `--disable-multilib`
- [ ] Verify GCC 7.5 can compile C and C++ programs
- [ ] Build and verify

### 2.7 Stage 4: Modern GCC (13.x)

- [ ] Create `channel/andyl/packages/gcc.scm`
- [ ] Define `andyl-gcc` package (GCC 13.3.0)
- [ ] Source: GCC 13.3.0 tarball from mirror://gnu/gcc/
- [ ] Build with `gnu-build-system`, using `andyl-gcc-mesboot` (GCC 7.x)
- [ ] Configure flags: `--enable-languages=c,c++`, `--disable-multilib`, `--disable-bootstrap`, `--with-system-zlib`
- [ ] Verify GCC 13.3 compilation of complex C/C++ code
- [ ] Build and verify

### 2.8 Linux Kernel Headers

- [ ] Create `channel/andyl/packages/linux.scm`
- [ ] Define `andyl-linux-headers` package (version 6.12.x LTS)
- [ ] Source: kernel.org tarball
- [ ] Build phases: skip configure, run `make headers`, install with `make headers_install`
- [ ] Handle architecture detection (x86_64 -> `ARCH=x86`, aarch64 -> `ARCH=arm64`)
- [ ] Remove `.install` files from output
- [ ] Build and verify headers install correctly

### 2.9 Stage 5: glibc

- [ ] Create `channel/andyl/packages/glibc.scm`
- [ ] Define `andyl-glibc` package (version 2.39)
- [ ] Source: glibc tarball from mirror://gnu/glibc/
- [ ] Build out-of-tree (`#:out-of-source? #t`)
- [ ] Configure flags for server hardening:
  - [ ] `--enable-kernel=5.15` (minimum kernel version)
  - [ ] `--enable-stack-protector=strong`
  - [ ] `--enable-bind-now` (full RELRO)
  - [ ] `--enable-static-nss`
  - [ ] `--enable-cet` (Control-flow Enforcement)
  - [ ] `--disable-werror`
  - [ ] `--with-headers=` pointing to `andyl-linux-headers`
- [ ] Add phase: set SHELL and CONFIG_SHELL environment variables
- [ ] Add phase: install UTF-8 locales (en_US.UTF-8, C.UTF-8)
- [ ] Add phase: remove unnecessary static libraries (keep libc.a, libpthread.a, libm.a, libdl.a, librt.a)
- [ ] Native inputs: `andyl-gcc`, `andyl-binutils`, `andyl-make`, `andyl-perl`, `andyl-bison`, `andyl-texinfo`
- [ ] Propagated inputs: `andyl-linux-headers`
- [ ] Build and verify libc.so exists and is functional
- [ ] Verify locale generation succeeded

### 2.10 Stage 6: Full Toolchain Packages

- [ ] Create `channel/andyl/packages/base.scm`
- [ ] Define `andyl-binutils` package (binutils 2.42+)
- [ ] Define `andyl-make` package (GNU Make 4.4+)
- [ ] Define `andyl-coreutils` package (coreutils 9.x)
- [ ] Define `andyl-bash` package (bash 5.2+)
- [ ] Define `andyl-findutils` package
- [ ] Define `andyl-gawk` package
- [ ] Define `andyl-grep` package
- [ ] Define `andyl-sed` package
- [ ] Define `andyl-tar` package
- [ ] Define `andyl-gzip` package
- [ ] Define `andyl-xz` package
- [ ] Define `andyl-diffutils` package
- [ ] Define `andyl-patch` package
- [ ] Define `andyl-pkg-config` package
- [ ] Build each package individually, then build all together
- [ ] Verify that the complete toolchain can build a non-trivial package (e.g., zlib)

### 2.11 Essential Library Packages

- [ ] Create `channel/andyl/packages/compression.scm`
- [ ] Define `andyl-zlib` package (with custom configure phase for non-autoconf build)
- [ ] Define `andyl-xz-utils` package (for xz/lzma compression)
- [ ] Define `andyl-zstd` package (for zstd compression)
- [ ] Define `andyl-lz4` package
- [ ] Create `channel/andyl/packages/tls.scm`
- [ ] Define `andyl-openssl` package (OpenSSL 3.x) with server-hardened build flags
- [ ] Build and verify all library packages

### 2.12 Toolchain Validation

- [ ] Build a complex package (e.g., curl) that exercises the full toolchain (GCC, glibc, zlib, OpenSSL)
- [ ] Run `guix build --check andyl-zlib` to verify build reproducibility
- [ ] Generate and inspect the dependency graph: `guix graph andyl-gcc`
- [ ] Verify no references to upstream Guix packages exist in any store path
- [ ] Document the complete DAG of bootstrap stages

### 2.13 justfile Targets

- [ ] Add `bootstrap` target: builds the full chain from seeds to final toolchain
- [ ] Add `bootstrap-toolchain` target: builds just GCC + glibc + binutils (assumes earlier stages cached)
- [ ] Add `build PACKAGE` target: builds a single specified package
- [ ] Add `build-all` target: builds all packages
- [ ] Add `graph PACKAGE` target: generates DOT dependency graph
- [ ] Add `lint PACKAGE` target: runs `guix lint`
- [ ] Add `show PACKAGE` target: runs `guix show`

## Acceptance Criteria

1. All bootstrap stages (0-6) build successfully from source with `--no-substitutes`
2. The final GCC (13.x) can compile C and C++ programs
3. The final glibc includes server hardening flags (stack protector, RELRO, CET)
4. All core toolchain packages (binutils, make, coreutils, bash, etc.) build and are functional
5. `guix build --check` confirms reproducibility for at least 3 key packages (zlib, openssl, bash)
6. No upstream Guix packages are referenced (only our channel's packages)
7. The full bootstrap chain completes in under 8 hours on the recommended hardware

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Bootstrap stage failure (obscure build error in early stages) | High | Blocks all progress | Study upstream commencement.scm carefully; start with exact copies before customizing |
| Full bootstrap takes too long (>12 hours) | Medium | Slow iteration | Cache intermediate results in Docker volume; only rebuild changed stages |
| glibc build complexity (many dependencies, edge cases) | High | Time-consuming debugging | Mirror upstream Guix glibc recipe closely; deviate only for hardening flags |
| GCC version incompatibility during stage transitions | Medium | Build failures | Use the exact version chain proven by upstream Guix (4.6.4 -> 7.5 -> 13.x) |
| Source tarball hash mismatches | Low | Blocks package definition | Download and compute hashes manually; verify against upstream |
| Circular dependencies in package definitions | Medium | guix errors | Map the full DAG before coding; use explicit stage numbering |

## Estimated Complexity

**XL (Extra Large)**

This is the single most complex phase of the project. The bootstrap chain involves dozens of carefully-ordered package definitions, many with custom build phases. The commencement module in upstream Guix is over 2000 lines of meticulously crafted Scheme. Debugging bootstrap failures requires deep understanding of compilers, linkers, and libc internals. Plan for significant iteration time.
