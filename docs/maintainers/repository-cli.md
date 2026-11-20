# Use the repository CLI

These sections cover the `aos` commands that need an AOS source checkout:
building and inspecting packages, and running checks and maintenance commands.
The commands that work without a checkout, such as image download, local VMs,
output modes, and attestation verification, are in
[Use the AOS command-line tools](../users/aos/cli.md).

## Work in a repository checkout

Most `aos` development commands need `nix-build` and an AOS source root with a
`default.nix`. Root discovery checks, in order:

1. `AOS_ROOT`;
2. the current directory and its parents;
3. the binary directory and its parent.

Cache, Hub, metadata, server, token, and completion commands dispatch before
repository discovery and can run without a source checkout when their own
inputs are available. Package operations belong to `apm` and registry
authoring belongs to `apr`; neither requires an AOS source checkout.

## Build and inspect source

`aos show` includes the native deployment envelope and generated module
documentation in JSON, with payload, dependency, option, and operation summaries
in text. These are local evaluated declarations; they do not authenticate a
release or prove that a handler ran. `aos graph` shows the built payload closure.

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
running host. Use `apm install --system zlib` for a machine-wide install.

`aos ability` inspects and compares checked portable plans, previews typed
reverse-use removal effects, builds bounded private deployment views, and reads
retained native execution or realized artifact-consumption evidence. It does
not activate a plan or authenticate a deployment connection.
See [Inspect ability plans and retained execution](../users/aos/ability-inspection.md) for
the current commands, provenance limits, and disclosure rules.

The flake output `packages.<system>.all` is the remote-build equivalent of
`aos build --all`: build it when one submitted derivation must realize every
individual `pkg-*` output for that system. For example, submit
`packages.x86_64-linux.all` to an x86_64 Linux builder. Git-backed package
sources use pinned fixed-output archives so restricted remote evaluators create
ordinary fetch derivations instead of requiring evaluation-time network access.
The aggregate remains one remote build session and does not shard its package
plan across a worker fleet. Submit independent `pkg-*` outputs as separate
builds when you want package-level cluster parallelism; their successful store
outputs remain reusable by a later `all` build.
Individual `pkg-*` outputs remain lazy: evaluating `pkg-openjdk-24`, for
example, does not inspect or realize Crucible merely to enumerate the package
set. Add new package files through `pkgs/default.nix` filesystem discovery, and
add explicit package aliases to its `packageNames` inventory, so this property
remains true.

System image production currently uses Nix directly. See
[Build and customize release images](system-images.md). Do
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
aos test rust
aos test build
aos test vm
aos test fleet

# Source hashes.
aos prefetch
aos prefetch --package zlib
aos prefetch --all
```

`aos test` with no layer runs evaluation, Rust, build, VM, and fleet tests in
order.
VM and fleet layers need a Linux host with KVM. `aos prefetch --update` edits
package source hashes; inspect its diff before committing.

`aos fmt` uses its embedded Alejandra formatter.
