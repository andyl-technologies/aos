# Maintainer reference: Use the AOS command-line tools

This reference covers the repository and release-engineering command surface.
Host users normally use [`apm`](packages.md) for package and generation
operations and do not need a source checkout or Nix.

The AOS package installs one multicall binary under three names. The name used
to invoke it selects the command surface.

| Command | Equivalent long form | Scope |
| --- | --- | --- |
| `aos` | — | Source tree, builds, checks, generated reference, Hub client |
| `apm` | `aos package` | Package consumption and installed generations |
| `apr` | `aos package registry` | Registry authoring and publication |

On AOS, all three commands are installed in the base system. From a repository
checkout, run `aos` through the flake:

```sh
nix run . -- describe
nix run . -- test eval
```

The current repository CLI and bootable-image workflow is supported on
`x86_64-linux`.

## Work in a repository checkout

Most `aos` development commands need `nix-build` and an AOS source root with a
`default.nix`. Root discovery checks, in order:

1. `AOS_ROOT`;
2. the current directory and its parents;
3. the binary directory and its parent.

Package, cache, Hub, metadata, server, token, and completion commands dispatch
before repository discovery and can run without a source checkout when their
own inputs are available.

## Build and inspect source

Common repository workflows are:

```sh
# Build one package or every package.
aos build zlib
aos build --all

# Inspect package metadata and dependency structure.
aos show zlib
aos graph zlib
aos graph zlib --dot > zlib.dot
aos why-depends curl openssl

# Inspect closures and references.
aos profile closure systems.server.build.toplevel
aos profile refs curl openssl

# Enter a repository-aware Nix REPL or browse generated reference data.
aos repl
aos doc
```

`aos build zlib` builds `pkgs.zlib`; it does not install a package on the
running host. Use `apm install zlib` for that operation.

System image production currently uses Nix directly. See
[Build and customize release images](../../maintainers/system-images.md). Do
not use `aos system build`, `aos system image`, or `aos system eval` with the
current tree; those commands still target an older attribute layout and are
not covered by the current system tests.

## Run checks and maintenance commands

```sh
# Formatting and static checks.
aos fmt --check
aos fmt
aos lint
aos lint zlib

# Test layers.
aos test eval
aos test build
aos test vm
aos test fleet

# Source hashes.
aos prefetch
aos prefetch --package zlib
aos prefetch --all
```

`aos test` with no layer runs evaluation, build, VM, and fleet tests in order.
VM and fleet layers need a Linux host with KVM. `aos prefetch --update` edits
package source hashes; inspect its diff before committing.

`aos fmt` uses its embedded Alejandra formatter.

## Choose output for people or automation

Global output modes are explicit:

| Flag | Behavior |
| --- | --- |
| none | Human-readable normal output |
| `--json` | Compact JSON on standard output |
| `--quiet` | Suppress non-error printer output |
| `-v` | Verbose output |
| `-vv` | Also stream Nix subprocess standard error |
| `-vvv` | Also print the Nix command line |

Use `--json` for scripts:

```sh
aos --json show zlib
apm --json list --installed
apm --json update --system
```

The normal printer writes human-facing messages to standard error, while JSON
uses standard output. The CLI does not generally switch formats when output is
piped. Exceptions with intentional standard output include completion scripts,
DOT graphs, and parts of `aos doc`. `aos doc` itself opens its interactive view
only when standard output is a terminal; a pipe receives a summary.

## Generate completions

Write a completion script to the location expected by the shell:

```sh
aos completions bash > aos.bash
aos completions zsh > _aos
aos completions fish > aos.fish
```

The generated script covers the `aos` command tree. `apm` and `apr` do not
currently expose their own completion generators.

## Understand command results

Most successful commands exit `0`. Invalid syntax normally exits `2`, and
build, evaluation, download, hash, and package errors use nonzero codes suited
to their command surface. A declined package-operation confirmation exits
`100`.

OS generation activation can fail after the new generation is live. See
[Upgrade and roll back a host](upgrades.md#interpret-activation-results) before
automating system upgrades.

Continue with [Manage packages](packages.md) for `apm`, or
[Operate an AOS package registry](../registry/) for producer-side `apr`
workflows.
