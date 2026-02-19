# Phase 3: Envoy Build

**Dependency:** Phase 2 (Bazel 7)

## Objective

Build Envoy from source using the `buildBazelPackage` two-phase pattern: a
fixed-output derivation fetches all external deps, then a hermetic build
compiles the static binary with `--repository_disable_download`.

## Prerequisites

- Phase 2 complete: Bazel 7 from source
- Phase 1 complete: OpenJDK 21 headless
- Existing AOS packages: cmake, ninja, python3, cargo, rustc, patchelf
- Remote builder with ~13 GB free disk, 16 GB RAM

## Deliverables

- `pkgs/toolchain/openjdk11.nix` -- OpenJDK 11 headless (Envoy's Java codegen)
- `pkgs/build-systems/gn.nix` -- GN (Generate Ninja), used by boringssl
- `pkgs/networking/envoy-deps.nix` -- Envoy dependency fetch FOD
- `pkgs/networking/envoy.nix` -- Envoy static binary
- `pkgs/networking/envoy-patches/` -- Adapted nixpkgs patches

## Detailed Task Checklist

### 3.1 Supporting Packages

- [ ] Write `pkgs/toolchain/openjdk11.nix` (OpenJDK 11 headless):
  - [ ] Same pattern as openjdk21 but for JDK 11
  - [ ] Use `openjdk21-headless` as boot JDK (JDK N+1 boots JDK N)
  - [ ] Nixpkgs ref: `pkgs/development/compilers/openjdk/11/`
  - [ ] Headless-only, same configure flags
  - [ ] Verify: `java -version` shows 11.x

- [ ] Write `pkgs/build-systems/gn.nix` (Generate Ninja):
  - [ ] Used by boringssl (Envoy dependency)
  - [ ] Build with: `python3 build/gen.py && ninja -C out`
  - [ ] Install `out/gn` to `$out/bin/gn`
  - [ ] Nixpkgs ref: `pkgs/by-name/gn/gn/package.nix`
  - [ ] Verify: `gn --version`

### 3.2 Envoy Patches

Nixpkgs applies critical patches to make Envoy build with system toolchains
instead of downloading its own. These must be adapted for AOS.

- [ ] Pull patches from nixpkgs `pkgs/by-name/en/envoy/`:
  - [ ] `0001-nixpkgs-use-system-Python.patch`:
    - Removes `python_register_toolchains()` calls
    - Configures `pip_parse()` to use system Python
    - Eliminates Python version hardcoding
  - [ ] `0003-nixpkgs-use-system-C-C++-toolchains.patch`:
    - Sets `register_default_tools=False, register_built_tools=False,
      register_preinstalled_tools=True`
    - Forces system GCC via Bazel flags
  - [ ] `0004-nixpkgs-bump-rules_rust-to-0.60.0.patch`:
    - Updates rules_rust for compatibility with system cargo/rustc
- [ ] Place adapted patches in `pkgs/networking/envoy-patches/`
- [ ] Create `bazel_nix.BUILD.bazel` defining:
  - Rust toolchain filegroups (x86_64, aarch64)
  - Shell toolchain pointing to AOS bash
  - System rustc/cargo/rustdoc paths

### 3.3 Envoy Dependency Fetch (FOD)

- [ ] Write `pkgs/networking/envoy-deps.nix`:
  - [ ] Use `builtins.derivation` with FOD attributes
  - [ ] Source: `https://github.com/envoyproxy/envoy/archive/v1.36.2.tar.gz`
  - [ ] Apply patches before fetching (system Python, system toolchains)
  - [ ] Set up Rust toolchain symlinks in `bazel/nix/`
  - [ ] Run `bazel build --nobuild //source/exe:envoy-static`
  - [ ] Run `bazel sync --noenable_bzlmod` to populate repository cache
  - [ ] Clean non-reproducible artifacts:
    - Remove `remotejdk*`, `android_tools`
    - Remove built-in workspaces (`bazel_tools`, `embedded_jdk`)
  - [ ] Tar the result with deterministic flags (`--sort=name --mtime='@1'`)
  - [ ] Compute hash (build with dummy hash, Nix reports actual)
  - [ ] Expected size: ~8 GB

**Known upstream issues:**
- Maven/coursier can fail to fetch JARs with hash mismatches (nixpkgs
  [#438433](https://github.com/NixOS/nixpkgs/issues/438433)). If this
  happens, check if the upstream envoy version has moved. Pin exact
  versions in MODULE.bazel if needed.
- WASM runtimes: default wasmtime works; v8/wavm may need extra
  source pre-fetching. Use `--define=wasm=wasmtime` (default).

### 3.4 Envoy Build

- [ ] Write `pkgs/networking/envoy.nix`:
  - [ ] Source: same tarball as envoy-deps
  - [ ] Unpack pre-fetched deps from FOD into `$NIX_BUILD_TOP/output`
  - [ ] Configure `.bazelrc` with:
    - `--repository_cache` pointing to unpacked deps
    - `--repository_disable_download`
  - [ ] Set up Rust toolchain symlinks in `bazel/nix/`
  - [ ] Build with Bazel flags:
    ```
    -c opt
    --spawn_strategy=standalone
    --config=gcc
    --verbose_failures
    --extra_toolchains=@local_jdk//:all
    --java_runtime_version=local_jdk
    --tool_java_runtime_version=local_jdk
    --jobs $NIX_BUILD_CORES
    //source/exe:envoy-static
    ```
  - [ ] Convert AOS env vars to Bazel flags:
    - `NIX_CFLAGS_COMPILE` -> `--copt` flags
    - `NIX_LDFLAGS` -> `--linkopt` flags
  - [ ] aarch64 note: add `--define=disable_tcmalloc=true` (memory alignment)
  - [ ] Install `bazel-bin/source/exe/envoy-static` as `$out/bin/envoy`
  - [ ] Patch RPATH with patchelf
  - [ ] Mark with `requiredSystemFeatures = [ "big-parallel" ]`
  - [ ] Verify: `envoy --version`
  - [ ] Expected build time: 60-120 min, 16 GB RAM peak

### 3.5 Fallback Strategy

If the from-source build proves too fragile for initial bring-up:

- [ ] Consider `pkgs/networking/envoy-bin.nix` as a temporary fallback:
  - Download pre-built static binary from Envoy releases
  - Patch ELF interpreter and RPATH
  - Mark as TODO for replacement with from-source build
  - This matches nixpkgs' `envoy-bin` package as a pragmatic fallback

## Upstream Comparison

The nixpkgs envoy package uses `buildBazelPackage` which abstracts the
two-phase pattern. Key differences for AOS:

| Aspect | Nixpkgs | AOS |
|--------|---------|-----|
| Bazel sandbox | Nix sandbox wraps Bazel sandbox | Same |
| CC toolchain | `stdenv.cc` (nixpkgs wrapper) | `ccWrapper` (AOS bootstrap) |
| Flag injection | `NIX_CFLAGS_COMPILE` -> `--copt` | Same pattern needed |
| Rust toolchain | Nixpkgs rustc | AOS cargo/rustc |
| JDK | `jdk11_headless` from nixpkgs | `openjdk11` built from source |
| FOD pattern | `buildBazelPackage` helper | `builtins.derivation` directly |

The approach is architecturally identical. The main adaptation work is
replacing nixpkgs store paths with AOS package paths in patches and
wrapper scripts.
