# `AOS // ANDYL OS`

[![Status: early preview](https://img.shields.io/badge/status-early%20preview-orange)](#project-status)
[![License: multi-license](https://img.shields.io/badge/license-multi--license-blue)](LICENSING.md)

AOS is an immutable Linux distribution for headless servers and edge systems. Its bootstrap toolchain, userspace, packages, system images, and tests are built from source in this repository without nixpkgs dependencies.

## Get started

1. [Install the AOS image](docs/users/aos/installation.md) on a machine or
   import it into a hypervisor.
2. [Configure the host](docs/users/aos/host-nix.md) with first-boot
   `host.nix` policy.
3. [Install and manage packages](docs/users/aos/packages.md) with `apm`.
4. [Operate the host](docs/users/aos/operations.md), apply
   [upgrades](docs/users/aos/upgrades.md), and use the
   [recovery guide](docs/users/aos/recovery.md) when needed.

Check the [support-status matrix](docs/users/aos/support-status.md) before planning a deployment.

## Projects

- **[AOS](https://github.com/andyl-technologies/aos/blob/master/docs/users/aos/README.md)**
  is the operating system, package manager, and host operating model.
- **[AOS Hub](docs/users/aos-hub/)** hosts package registries and binary caches.
  It runs as a native service or as a Cloudflare Worker and exposes a web
  console, HTTP API, and the registry and cache protocols used by `apr`, `apm`,
  Git, and Nix. It is also the planned distribution point for AOS system
  images.
- **[Crucible](docs/users/crucible/)** provides deterministic state-space
  exploration and debugging for unmodified QEMU guests.

## Documentation

- [AOS user documentation](docs/users/aos/) covers installation,
  configuration, packages, security, upgrades, operations, and recovery.
- [AOS Hub documentation](docs/users/aos-hub/) covers its web, API, CLI,
  native, and Cloudflare deployments.
- [Registry operator documentation](docs/users/registry/) covers hosting,
  signing, publishing, staged rollouts, and incident response.
- [Crucible documentation](docs/users/crucible/) covers deterministic
  exploration, reproduction, debugging, and CI.
- [Maintainer documentation](docs/maintainers/) covers source builds, image
  production, repository development, and tests.

## Contributing

Bug reports and feature proposals are welcome in
[GitHub Issues](https://github.com/andyl-technologies/aos/issues). Before
changing packages, images, or build tooling, read the
[contribution requirements](CONTRIBUTING.md) and
[maintainer guide](docs/maintainers/). The contribution requirements document
the CLA/DCO checks and license boundaries that apply before a change is merged.
AOS is built hermetically from source;
new dependencies must be added to the AOS package graph rather than imported
from nixpkgs.

## Project status

AOS is under active development. Interfaces and disk formats may change before
the first stable release. Public installation images, a production
external-signing workflow, durable kernel updates, and complete runtime
`host.nix` activation are not available yet.

Original AOS code is generally licensed under the
[Apache License 2.0](LICENSE). The repository and its distributions also contain
separately licensed components, including QEMU and its Crucible integration.
See the authoritative [license map](LICENSING.md) and complete license texts in
[`LICENSES/`](LICENSES/).
