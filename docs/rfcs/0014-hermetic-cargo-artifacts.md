# RFC-0014: Hermetic Cargo artifact graphs and parallel Rust testing

- Status: Implemented
- Date: 2026-08-21

## Summary

AOS builds Cargo dependencies into reusable Nix derivations whose identity is
based on the Cargo manifests, lockfile, target layout, toolchain, target,
profile, features, native inputs, and declared build environment. Ordinary
Rust implementation edits therefore rebuild first-party units without
rebuilding the unchanged third-party dependency graph. Rust test derivations
use cargo-nextest to schedule test processes across builder cores.

This is an AOS-native implementation. It uses only the source-built AOS Rust
toolchain and packages, and introduces no nixpkgs or host-tool dependency.

## Artifact model

`mkCargoDummySource` retains Cargo metadata and the names of Rust targets while
replacing target contents with minimal Rust. `mkCargoArtifacts` compiles that
workspace with `CARGO_INCREMENTAL=0` and publishes the complete Cargo target
directory plus Cargo JSON messages and a versioned compatibility contract.
`mkCargoPackage` restores a compatible target directory before building the
real source.

The contract fails closed when the producer and consumer differ. Its baseline
keys are:

- Rust toolchain and build system;
- host/target system;
- build and check profiles;
- default-feature policy and explicit features;
- structured Cargo environment;
- native build and runtime inputs;
- a caller-owned family discriminator for additional policy.

Callers may strengthen the contract with panic, LTO, codegen, target-feature,
or family-specific fields. They must not weaken keys that affect Cargo unit
identity. Artifact outputs are not stripped, patched, or reference-scrubbed:
mutating files behind Cargo fingerprints would make reuse unsound.

Cargo emits JSON messages for every package build. Installation consumes only
the executable and library paths reported by the current real-source build, so
dummy or inherited final artifacts cannot leak into a package output.

## Workspace families

Artifact families follow build compatibility rather than a global union:

- AOS native release and test;
- Hub native dialect and Worker WebAssembly;
- Crucible Apache host release and test-double test;
- Crucible GPL plugin and debug gateway;
- Crucible static guest;
- standalone third-party Cargo tools.

The Crucible families preserve the RFC-0010 process and licensing boundary.
No artifact family crosses from Apache host components into a QEMU-linked or
GPL-side component. Target triples, Rust flags, native headers, and libraries
are contract inputs.

`cargo-hakari` is available for measuring and maintaining family-local feature
unification. A workspace-hack crate is adopted only when measurements show a
net win; AOS does not create a global feature union across incompatible
families.

## Parallel tests

`cargo-nextest` is built hermetically from source and is available in the dev
shell. `.config/nextest.toml` defines the repository defaults. Nix checks use
`mkCargoNextestCheck`, and `aos test rust [suite]` maps to `checks.rust`.
Nextest gives each test its own process and schedules those processes in
parallel. Tests that share exclusive external state must be assigned to a
bounded nextest test group rather than forcing the entire workspace serial.

Doctests remain explicit `cargo test --doc` gates because nextest does not run
them. Clippy, rustdoc, ABI conformance, license-boundary, VM, fleet, and release
checks remain separate derivations with their existing policy.

## Validation

The artifact fixture proves that:

- an implementation-only edit retains the dummy-source identity;
- a manifest edit changes it;
- a consumer can relocate the restored target directory;
- registry dependencies are fresh in the real-source Cargo build;
- only artifacts emitted by the real build are installed.

Local evaluation, artifact fixtures, package builds, nextest suites, doctests,
formatting, and boundary gates are the required evidence. The repository has
no remote CI, so pull requests record the exact local commands and results.
