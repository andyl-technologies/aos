# Phase 1: JDK Foundation

**Dependency:** None (uses existing AOS packages only)

## Objective

Build OpenJDK 21 from source and the small utility packages (zip, unzip,
which) that Bazel requires. The JDK is the foundation of the entire chain:
Bazel needs it to run, and Bazel is needed to build Envoy.

## Prerequisites

- Working AOS package set with: gcc (via ccWrapper), make, autoconf, bash,
  coreutils, gawk, tar, grep, gzip, findutils, zlib, python3
- Remote builder with sufficient resources (~4 GB RAM, ~4 GB disk)

## Deliverables

- `pkgs/compression/zip.nix` -- InfoZIP zip 3.0
- `pkgs/compression/unzip.nix` -- InfoZIP unzip 6.0
- `pkgs/core/which.nix` -- GNU which
- `pkgs/toolchain/openjdk21-bootstrap.nix` -- Adoptium Temurin 21 binary
- `pkgs/toolchain/openjdk21.nix` -- OpenJDK 21 headless, built from source

## Detailed Task Checklist

### 1.1 Supporting Utilities

- [ ] Write `pkgs/compression/zip.nix` (InfoZIP zip 3.0):
  - [ ] Source: `https://downloads.sourceforge.net/infozip/zip30.tar.gz`
  - [ ] Build: `make -f unix/Makefile generic_gcc`
  - [ ] Install: `make -f unix/Makefile prefix=$out install`
  - [ ] Verify: `zip --version`

- [ ] Write `pkgs/compression/unzip.nix` (InfoZIP unzip 6.0):
  - [ ] Source: `https://downloads.sourceforge.net/infozip/unzip60.tar.gz`
  - [ ] Build: `make -f unix/Makefile generic_gcc`
  - [ ] Check nixpkgs for security patches (CVE fixes)
  - [ ] Verify: `unzip --version`

- [ ] Write `pkgs/core/which.nix` (GNU which):
  - [ ] Standard autoconf build (`./configure && make && make install`)
  - [ ] Trivial package (~20 KB)
  - [ ] Verify: `which --version`

### 1.2 OpenJDK 21 Bootstrap (Binary)

- [ ] Write `pkgs/toolchain/openjdk21-bootstrap.nix`:
  - [ ] Download Adoptium Temurin 21 prebuilt binary
  - [ ] URL: `https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.6+7/OpenJDK21U-jdk_x64_linux_hotspot_21.0.6_7.tar.gz`
  - [ ] Use `aos prefetch` to compute hash
  - [ ] Patch ELF interpreter to `${bootstrapTools}/lib/ld-linux-x86-64.so.2`
  - [ ] Patch RPATH to `$out/lib:$out/lib/server:${bootstrapTools}/lib`
  - [ ] Use `find` + `patchelf` loop on all ELF executables
  - [ ] Verify: `$out/bin/java -version`
  - [ ] Note: This is a build dependency only, never in the final image

### 1.3 OpenJDK 21 Headless (From Source)

- [ ] Write `pkgs/toolchain/openjdk21.nix`:
  - [ ] Source: `https://github.com/openjdk/jdk21u/archive/refs/tags/jdk-21.0.6+7.tar.gz`
  - [ ] Configure with `--with-boot-jdk=${openjdk21-bootstrap}`
  - [ ] Use `--enable-headless-only` (eliminates X11/AWT/Swing deps)
  - [ ] Use `--with-native-debug-symbols=none` (reduces size)
  - [ ] Use `--with-zlib=system` (link against AOS zlib)
  - [ ] Use `--disable-warnings-as-errors`
  - [ ] Pass `--with-extra-cflags="$NIX_CFLAGS_COMPILE"` and
    `--with-extra-ldflags="$NIX_LDFLAGS"`
  - [ ] Build with `make images JOBS=$NIX_BUILD_CORES`
  - [ ] Install from `build/*/images/jdk/*`
  - [ ] Review nixpkgs patches from `pkgs/development/compilers/openjdk/21/`:
    - [ ] `fix-java-home.patch`
    - [ ] `read-truststore-from-env-var.patch`
    - [ ] Any other applicable patches
  - [ ] Verify: `java -version`, `javac HelloWorld.java && java HelloWorld`
  - [ ] Expected output size: ~150 MB (headless)

## Nixpkgs Reference

The OpenJDK build follows `pkgs/development/compilers/openjdk/21/default.nix`.
Key configure flags and patches are documented inline. The binary bootstrap
pattern matches nixpkgs practice -- bootstrap binaries are build deps only.

## Notes

- The builder shell is dash. The OpenJDK `configure` script is a bash script;
  invoke it explicitly with `bash configure ...` or use `$CONFIG_SHELL`.
- OpenJDK's build system uses its own make infrastructure; do not expect
  standard autoconf behavior.
- Headless mode eliminates the need for X11, freetype, fontconfig, and
  alsa-lib, significantly reducing the dependency surface.
