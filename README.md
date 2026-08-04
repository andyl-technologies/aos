# `AOS // ANDYL OS`

**EARLY PREVIEW**

AOS is an immutable Linux distribution for headless servers and edge systems.
Its bootstrap toolchain, userspace, packages, system images, and tests are built
from source in this repository without nixpkgs dependencies.

AOS uses read-only system images, systemd, and a Nix module system.
Machine-specific policy is supplied as literal `host.nix`.

## Build a server image

Building AOS requires Nix with flakes enabled and a Linux builder.

```sh
nix build .#server-image-qcow2
```

The result is available at `result/aos-aos.qcow2`. The flake also exposes
`server-image-raw`, `server-image-vmdk`, and `server-image-vhd` for other
deployment targets.

Build an individual package with its `pkg-` attribute:

```sh
nix build .#pkg-zlib
```

## Use the repository CLI

The `aos` command builds packages, inspects the package graph, runs checks, and
browses the repository's generated reference. Run the packaged command through
the flake:

```sh
nix run . -- describe
nix run . -- show zlib
nix run . -- test eval
```

Use `nix run . -- --help` for the complete command list.

## Work on the Rust code

For an incremental build, compile in the development environment and run the
resulting binary directly:

```sh
nix develop -c cargo build --manifest-path crates/Cargo.toml --bin aos
crates/target/debug/aos --help
```

The development environment supplies the AOS-built dependencies and embeds the
required OpenSSL runtime path. Build the `apm` or `apr` binary instead when
working on the package-manager or registry command surface.

Useful checks include:

```sh
nix-build -A checks.eval
crates/target/debug/aos fmt --check
crates/target/debug/aos test eval
```

VM and fleet checks require a Linux builder with KVM.

## Source map

| Path | Contents |
| --- | --- |
| [`stdenv/`](stdenv/) and [`pkgs/`](pkgs/) | Bootstrap chain, toolchain, and package graph |
| [`lib/`](lib/), [`modules/`](modules/), and [`systems/`](systems/) | Module framework and image variants |
| [`crates/`](crates/) | AOS tools, registry services, and Crucible |
| [`tests/`](tests/) | Evaluation, build, VM, fleet, and integration coverage |

## Documentation

- [User guides](docs/users/), including the [Crucible operations guide](docs/users/crucible/)
- [Package registry reference](docs/registry/)
- [RFCs and design history](docs/rfcs/)

AOS is licensed under the [Apache License 2.0](LICENSE).
