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
