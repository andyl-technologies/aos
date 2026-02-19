# Envoy Proxy: Phased Implementation Plan

> **Status:** Planned
>
> Build Envoy from source in AOS, including the full JDK and Bazel
> dependency chain. This is a standalone workstream extracted from the
> [Golden Image design](../../design/golden-image/README.md) so it can
> be executed independently.

## Why Envoy

Cilium uses Envoy for L7 policy enforcement, rate limiting, and mTLS.
The golden image includes Cilium; a from-source Envoy is needed to
avoid pulling pre-built binaries into the hermetic AOS package set.

## Dependency Chain

```
envoy 1.36.x (C++, ~100 MB static binary)
  |
  +-- bazel 7.x (Java + native, ~200 MB)
  |     +-- openjdk21-headless (from source, ~150 MB)
  |     |     +-- openjdk21-bootstrap (prebuilt Adoptium binary, build-time only)
  |     +-- bazel-deps FOD (~16 GB vendored deps)
  |     +-- zip, unzip, which, lndir
  |
  +-- envoy-deps FOD (~8 GB vendored deps)
  +-- openjdk11-headless (Envoy's Java codegen)
  +-- gn (Generate Ninja, for boringssl)
  +-- cmake, ninja, python3, cargo, rustc (already in AOS)
```

## Implementation Phases

| Phase | Document | Scope | New Packages |
|-------|----------|-------|-------------|
| 1 | [JDK Foundation](phase-1-jdk-foundation.md) | OpenJDK bootstrap and build from source, supporting utilities | openjdk21-bootstrap, openjdk21-headless, zip, unzip, which |
| 2 | [Bazel Build System](phase-2-bazel.md) | Three-stage Bazel build (bootstrap, deps FOD, from source) | bazel-bootstrap, bazel-deps, bazel, lndir |
| 3 | [Envoy Build](phase-3-envoy.md) | Envoy dep fetch FOD, from-source build, patches | openjdk11-headless, gn, envoy-deps, envoy |
| 4 | [Integration](phase-4-integration.md) | Golden image integration, buildBazelPackage helper, testing | (infrastructure only) |

## Build Resources

| Package | Disk | RAM | CPU Time |
|---------|------|-----|----------|
| openjdk21-headless | ~2 GB | 4 GB | 20-40 min |
| openjdk11-headless | ~2 GB | 4 GB | 20-40 min |
| bazel-deps (FOD) | ~16 GB | 4 GB | 10-20 min |
| bazel (from source) | ~4 GB | 8 GB | 30-60 min |
| envoy-deps (FOD) | ~8 GB | 4 GB | 10-20 min |
| envoy (from source) | ~5 GB | 16 GB | 60-120 min |
| **Total** | **~37 GB** | **16 GB peak** | **~3-5 hours** |

## Upstream Comparison (nixpkgs)

This plan is informed by the nixpkgs envoy package (`pkgs/by-name/en/envoy/`)
and Bazel infrastructure (`build-support/build-bazel-package/`). Key findings
from upstream:

**What works well in nixpkgs:**
- `buildBazelPackage` two-phase pattern (FOD fetch + hermetic build)
- System toolchain injection via patches and `--copt`/`--linkopt` flags
- Binary bootstrap for JDK and Bazel (same approach we use)

**Known upstream issues to watch for:**
- Maven/coursier hash mismatches during dependency fetch (nixpkgs issues
  [#438433](https://github.com/NixOS/nixpkgs/issues/438433),
  [#475686](https://github.com/NixOS/nixpkgs/issues/475686))
- WASM runtime fetches can fail -- only `wamr` works reliably; `v8` and
  `wasmtime` need extra source pre-fetching
- Patches break across Bazel major versions (rules_rust, rules_jvm coupling)
- `envoy-bin` exists as a fallback in nixpkgs for when source builds break

**AOS-specific considerations:**
- Builder shell is `/bin/sh` (dash) -- wrapper scripts must be POSIX
- `ccWrapper` injects flags differently than nixpkgs -- Bazel needs explicit
  `--copt`/`--linkopt` conversion of `NIX_CFLAGS_COMPILE` / `NIX_LDFLAGS`
- FODs use `builtins.derivation` directly (same pattern as AOS `fetchurl`)
- All bootstrap binaries (JDK, Bazel) are build-time only, never in the image

## Nixpkgs Reference Map

| AOS Package | Nixpkgs Path | What to Reference |
|------------|-------------|-------------------|
| openjdk21-bootstrap | `pkgs/by-name/ba/bazel_7/package.nix` | Binary fetch + patchelf |
| openjdk21-headless | `pkgs/development/compilers/openjdk/21/` | Configure flags, patches |
| openjdk11-headless | `pkgs/development/compilers/openjdk/11/` | Configure flags, patches |
| bazel-bootstrap | `pkgs/by-name/ba/bazel_7/package.nix` | Binary download, wrapper |
| bazel-deps | `pkgs/by-name/ba/bazel_7/package.nix` | Vendor mode, FOD hash |
| bazel | `pkgs/by-name/ba/bazel_7/package.nix` | Patches, compile.sh mods |
| envoy-deps | `pkgs/by-name/en/envoy/package.nix` | FOD build, repository cache |
| envoy | `pkgs/by-name/en/envoy/package.nix` | Build flags, patches |
| gn | `pkgs/by-name/gn/gn/package.nix` | Python bootstrap build |
| zip / unzip | `pkgs/by-name/zi/zip/`, `pkgs/by-name/un/unzip/` | Makefile |
