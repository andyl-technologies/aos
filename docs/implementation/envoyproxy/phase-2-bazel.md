# Phase 2: Bazel Build System

**Dependency:** Phase 1 (OpenJDK 21 headless, zip, unzip, which)

## Objective

Build Bazel 7 from source using a three-stage approach: binary bootstrap,
fixed-output derivation (FOD) for vendored dependencies, and a from-source
build with `--repository_disable_download`. This matches the nixpkgs pattern
and ensures full hermeticity.

## Prerequisites

- Phase 1 complete: openjdk21-headless, zip, unzip, which
- Remote builder with ~20 GB free disk (bazel-deps FOD is ~16 GB)
- Existing AOS packages: bash, coreutils, gawk, sed, tar, grep, gzip,
  findutils, python3, make

## Deliverables

- `pkgs/build-systems/bazel-bootstrap.nix` -- Prebuilt Bazel binary (build-time only)
- `pkgs/build-systems/bazel-deps.nix` -- Vendored deps FOD (~16 GB)
- `pkgs/build-systems/bazel.nix` -- Bazel 7 built from source
- `pkgs/tools/lndir.nix` -- lndir utility (for symlinking vendored deps)

## Detailed Task Checklist

### 2.1 lndir Utility

- [ ] Write `pkgs/tools/lndir.nix`:
  - [ ] Symlink directory tree utility, used to set up vendored deps
  - [ ] Can be built from xorg-lndir source or implemented as a small C program
  - [ ] Alternative: shell script wrapper (`for f in "$1"/*; do ln -s ...`)
  - [ ] Verify: creates correct symlink trees

### 2.2 Bazel Bootstrap (Binary)

- [ ] Write `pkgs/build-systems/bazel-bootstrap.nix`:
  - [ ] Download `bazel_nojdk-7.6.0-linux-x86_64` from GitHub releases
  - [ ] Patch ELF interpreter with patchelf
  - [ ] Create wrapper script that sets PATH and JAVA_HOME:
    ```
    PATH includes: bash, coreutils, which, gawk, sed, tar, grep, gzip,
    findutils, python3, zip, unzip
    JAVA_HOME = openjdk21-headless
    ```
  - [ ] Wrapper must be POSIX sh (dash-compatible), not bash
  - [ ] Verify: `bazel version`
  - [ ] Note: build dependency only, never in final image

### 2.3 Bazel Dependencies (Fixed-Output Derivation)

This is the critical piece. Bazel downloads hundreds of external dependencies
at build time. The FOD pattern:

1. FODs are allowed network access by Nix (content-addressed)
2. Run `bazel vendor` to download all deps
3. Clean non-reproducible artifacts (`.pyc`, Go cache, etc.)
4. The output hash is committed to the package definition

- [ ] Write `pkgs/build-systems/bazel-deps.nix`:
  - [ ] Use `builtins.derivation` directly with FOD attributes:
    - `outputHashMode = "recursive"`
    - `outputHashAlgo = "sha256"`
  - [ ] Source: `bazel-7.6.0-dist.zip`
  - [ ] Run `bazel vendor` with `--tool_java_runtime_version=local_jdk_21`
  - [ ] Clean non-reproducible artifacts:
    - Remove Go repository cache (`gocache/`)
    - Remove `versions.json` from Go SDK
    - Delete all `.pyc` files
    - Remove `bazel-external` symlink
  - [ ] To get the hash: build with a dummy hash, Nix reports the actual hash
  - [ ] Or copy from nixpkgs for the matching Bazel version/platform
  - [ ] Expected size: ~16 GB

### 2.4 Bazel From Source

- [ ] Write `pkgs/build-systems/bazel.nix`:
  - [ ] Source: `bazel-7.6.0-dist.zip` (same as deps)
  - [ ] Apply patches (pull from nixpkgs `pkgs/by-name/ba/bazel_7/`):
    - [ ] `java_toolchain.patch` -- non-prebuilt local JDK toolchain
    - [ ] `strict_action_env.patch` -- replace `/bin:/usr/bin` with Nix paths
    - [ ] `bazel_rc.patch` -- system bazelrc pointing to local JDK
    - [ ] `trim-last-argument-to-gcc-if-empty.patch` -- GCC arg fix
  - [ ] Replace hardcoded `/bin/` paths with Nix store paths:
    - `/bin/bash` -> `${bash}/bin/bash`
    - `/usr/bin/env` -> `${coreutils}/bin/env`
    - `/bin/true` -> `${coreutils}/bin/true`
  - [ ] Modify `compile.sh` to use vendored deps:
    - Add `--vendor_dir=../vendor_dir`
    - Add `--repository_disable_download`
    - Add `--tool_java_runtime_version=local_jdk_21`
    - Add `--java_runtime_version=local_jdk_21`
  - [ ] Symlink vendored deps from FOD using lndir
  - [ ] Generate `VENDOR.bazel` manifest
  - [ ] Build with `bash ./compile.sh`
  - [ ] Install `output/bazel` and create POSIX sh wrapper with PATH
  - [ ] Verify: `bazel version`, build a simple C++ hello world project
  - [ ] Expected build time: 30-60 min, 8 GB RAM peak

## Upstream Notes

The three-stage approach (bootstrap binary -> FOD deps -> from-source build)
directly mirrors nixpkgs `pkgs/by-name/ba/bazel_7/package.nix` which defines
`bazelBootstrap`, `bazelDeps`, and the main `bazel` derivation.

**Key difference from nixpkgs:** AOS wraps gcc via `ccWrapper` rather than
nixpkgs' `stdenv.cc`. The Bazel patches that rewrite action env PATH must
reference AOS package paths, not nixpkgs store paths.

**Known issue:** The FOD hash is platform-specific (x86_64 vs aarch64). When
adding aarch64 support later, a separate hash will be needed.
