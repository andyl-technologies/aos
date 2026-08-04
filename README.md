# `AOS // ANDYL OS`

**EARLY PREVIEW**

AOS is an immutable Linux distribution for headless servers and edge systems.
Its bootstrap toolchain, userspace, packages, system images, and tests are built
from source in this repository without nixpkgs dependencies.

AOS uses read-only system images, systemd, and a Nix module system.
System policy is built from modules in `systems/`. A literal `host.nix`
supplies first-boot storage policy; broader runtime activation is still under
development.

## Projects

- **AOS** builds the operating system, package graph, system images, and the
  `aos` repository CLI.
- **[AOS Hub](docs/users/aos-hub/)** hosts package registries and binary caches.
  It runs as a native service or as a Cloudflare Worker and exposes a web
  console, HTTP API, and the registry and cache protocols used by `apr`, `apm`,
  Git, and Nix.
- **[Crucible](docs/users/crucible/)** runs repeatable black-box network tests
  against unmodified guests using QEMU-backed execution.

## Build a server image

Building AOS images requires Nix with flakes enabled and an `x86_64-linux`
caller or remote builder. On an x86 Linux host:

```sh
nix build .#server-image-qcow2
```

From another system using an x86 Linux remote builder, select that package set
explicitly:

```sh
nix build .#packages.x86_64-linux.server-image-qcow2
```

The result is available at `result/aos-aos.qcow2`. The flake also exposes
`server-image-raw`, `server-image-vmdk`, and `server-image-vhd` for other
deployment targets.

Build an individual package with its `pkg-` attribute:

```sh
nix build .#pkg-zlib
nix build .#pkg-aos-hub
nix build .#pkg-crucible
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

- [Install and operate AOS](docs/users/aos/), including a
  [first-boot tutorial](docs/users/aos/quickstart.md) and the
  [`host.nix` guide](docs/users/aos/host-nix.md)
- [AOS Hub operations](docs/users/aos-hub/), including a
  [local quickstart](docs/users/aos-hub/quickstart.md)
- [Package registry operations](docs/users/registry/), including a
  [signed local quickstart](docs/users/registry/quickstart.md), hosting,
  staged rollouts, and key rotation
- [Crucible operations](docs/users/crucible/), including the
  [Nginx and Curl quickstart](docs/users/crucible/quickstart.md)
- [Registry architecture and implementation notes](docs/registry/)

AOS is licensed under the [Apache License 2.0](LICENSE).
