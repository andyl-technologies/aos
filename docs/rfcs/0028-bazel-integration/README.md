# RFC-0028: Bazel builds for the Rust workspace and native code

- **Status:** Proposed; design only. The functions, targets, and commands in
  this RFC describe the intended interface and are not implemented by this PR.
- **Date:** 2026-10-21
- **Scope:** Replace Cargo as the build system and first-party build definition
  for AOS Rust code; build first-party C, C++, and assembly in the same Bazel
  workspace; retain Nix for the source bootstrap, dependencies, packages,
  system composition, and distribution.
- **Relationship:** Successor proposal to the first-party portions of
  [RFC-0015](../0015-hermetic-cargo-artifacts.md). RFC-0015 remains the
  implemented contract until each consumer migrates.

## Problem and outcome

The Rust workspace has shared dependencies, native libraries, generated APIs,
multiple execution platforms, and distinct application, guest, Worker, and
QEMU-side configurations. Today Cargo, Nix workspace slicing, Cargo artifact
families, test wrappers, and compiler caches each describe parts of that
build. Introducing first-party native code adds another compilation graph.

This proposal makes Bazel the authoritative compilation and test graph for
first-party Rust and native code. Package recipes select Bazel package targets
through shared Nix functions. Bazel consumes source-built AOS toolchains and
immutable dependency repositories supplied by Nix. Developers reuse individual
actions across edits and compatible worktrees; release packaging remains a
hermetic Nix build with the existing qualification and publication boundaries.

The migration ends with no first-party `Cargo.toml`, workspace `Cargo.lock`,
Cargo compilation, or manually synchronized Cargo/Bazel dependency graphs.
Third-party Rust source retains its upstream metadata. Source-built Cargo may
still be used by the dependency-update tool and by upstream packages and the
compiler bootstrap. That tooling role does not make Cargo a build driver for
the migrated workspace.

## Design documents

| Document | Owns |
| --- | --- |
| [Build definitions](01-build-definitions.md) | Repository layout, Rust targets and features, native code, code generation, tests, editor integration |
| [Nix integration](02-nix-integration.md) | Shared compilation functions, source selection, offline dependencies, toolchains, package outputs, development interface |
| [Caching](03-caching.md) | Cache layers, action identity, accache interaction, worktrees, qualification, cache trust and diagnostics |
| [Migration and evidence](04-migration-and-evidence.md) | Rust-first rollout, Cargo removal, performance experiments, acceptance gates, alternatives, references |

## Decisions

1. Use one root `MODULE.bazel` and package-local `BUILD.bazel` files. Keep the
   ownership structure under `crates/`; introduce `native/` for C/C++/assembly.
2. Use pinned `rules_rust` and `rules_cc`, with small shared AOS policy rules.
   Rust compile actions invoke `rustc` directly. A `genrule` invoking
   `cargo build` is not a migrated target.
3. Keep first-party dependency edges, features, generated inputs, tests, and
   compiler settings in Bazel. Generate the metadata needed by Nix, editors,
   inventories, and packaging from that graph.
4. Use AOS-built execution and target toolchains, libraries, shells, and
   generators. Preserve the audited source-bootstrap chain and introduce no
   host-tool, nixpkgs, rustup, or prebuilt compiler dependency.
5. Resolve external dependencies in an explicit update operation. Ordinary
   builds consume pinned, source-only repositories offline and cannot repin.
6. Share one Nix compilation interface across Rust and native targets. Keep
   installation, runtime closures, platform support, and qualification in the
   Nix package model.
7. Require shared local Bazel action-cache reuse across fresh Nix derivation
   executions. Retain accache for other build systems; reuse its Bazel-format
   storage knowledge and invalidation contracts. Enable double caching only
   after measurements establish a benefit and equivalent correctness.
8. Preserve feature, platform, and licensing boundaries. Shared infrastructure
   does not create a global Rust feature union or a combined host/plugin
   binary.
9. Treat build performance and generated-program performance as separate
   measurements. Hardware-specific code generation is an explicit target
   configuration, and benchmark execution is always fresh.

## Current infrastructure to reuse

At the proposal baseline, AOS already has:

- A [source-built Bazel package](../../../pkgs/toolchain/bazel.nix), selecting
  Bazel 9, and source-built rule dependencies in the bootstrap chain.
- [`mkBazelPackage` and `fetchBazelDeps`](../../../pkgs/default.nix), with
  [offline build phases](../../../stdenv/phases.nix).
- [`aos-dev` cache controls](../../../tools/dev/lib/cache.bash) and a shared
  Bazel disk action cache.
- A Workerd-specific [Rust toolchain repository](../../../pkgs/tools/workerd/_rust-repository.nix)
  and [source-built dependency generator](../../../pkgs/tools/workerd/_cargo-bazel.nix).
- [accache](../../../tools/accache/README.md), including explicit compiler
  closure identity and extensive invalidation fixtures.
- [Cargo workspace source selection](../../../pkgs/tools/aos/_workspace-slice.nix),
  [artifact families](../0015-hermetic-cargo-artifacts.md), and established
  [workspace ownership](../../architecture/crate-workspace.md).

These are implementation references, not a claim that the common interface
already exists. In particular, the current upstream Bazel phases restore and
patch external repositories and inherit some build environment settings. The
first-party interface needs the explicit toolchain, source, environment, and
output contracts below rather than copying those phases into each package.

## Scope boundaries

The primary migration is the Rust workspace, with shared infrastructure for
first-party native code. Standalone first-party tools such as `tools/accache/`
join after their bootstrap dependencies have been checked.

Upstream packages may keep Cargo, Make, CMake, Meson, or their existing Bazel
definitions. This RFC does not translate the whole distribution into Bazel,
replace Nix system evaluation, or deploy a remote build service. It defines
interfaces that can accommodate a remote action cache later without making
one a prerequisite.
