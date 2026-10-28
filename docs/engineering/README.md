# AOS engineering

This section explains how AOS is built: implementation details, design
rationale, architecture, and the internal contracts between components. It is
for people changing the source tree. Running AOS is covered in the
[user documentation](../users/README.md), and managing installation media,
releases, and forks is covered in the [maintainer documentation](../maintainers/README.md).

Pages are organized by component or feature. Each page describes the code as it
is; when the code changes, the page changes with it.

## Repository-wide

- [Code style](code-style.md) covers Rust APIs and implementation, Dendritic Nix
  modules, package expressions, comments, tests, and embedded shell.
- [Rust workspace](rust-workspace.md) covers crate naming, ownership, directory
  groups, dependency direction, and the inventory of workspace packages.

## Build system

- [Build system](build/README.md) maps the bootstrap, toolchain tiers, stdenv,
  and language builders.
- [Toolchain ladder](build/toolchain-ladder.md) covers the source bootstrap,
  GCC tiers, per-tier stdenv, and producer validation rules.
- [Rust builds](build/rust-builds.md) covers reusable Cargo dependency
  artifacts, their compatibility contract, development caches, and nextest.

## OCI containers

- [OCI containers](oci-containers/README.md) gives the build and distribution
  pipeline, code map, and container checks.
- [Image build](oci-containers/image-build.md) covers container definitions,
  closure layers, the layer archive ABI, and runtime initialization.
- [Distribution and publication](oci-containers/distribution.md) covers the
  shared OCI contract, Hub's Distribution data plane, verified publication, and
  garbage collection.

## Packages

- [Package documentation](package-documentation.md) covers generation of
  package reference documents, their signed publication, Hub verification and
  search projections, and the shared readers.
- [Package maintenance](package-maintenance/README.md) covers the
  `aos maintain` update model, components, workflow states, confinement, and
  repair boundary.
- [Update contract](package-maintenance/update-contract.md) describes the
  `mkUpstream` declaration that update tooling reads and edits.
