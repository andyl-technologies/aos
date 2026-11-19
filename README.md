# `AOS // ANDYL OS`

[![Status: early preview](https://img.shields.io/badge/status-early%20preview-orange)](#project-status)
[![License: multi-license](https://img.shields.io/badge/license-multi--license-blue)](docs/legal/licensing.md)

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
- [AOS Hub documentation](docs/users/aos-hub/) covers its trust model, web,
  API, CLI, native, and Cloudflare deployments.
- [Registry release stages](docs/engineering/registry/release-stages.md) explains unpublished
  candidate uploads and revision checks. Registry maintainers use `apr release`;
  AOS qualification and destination orchestration use `aos maintain release`.
- [Registry operator documentation](docs/users/registry/) covers hosting,
  signing, publishing, staged rollouts, and incident response.
- [Crucible documentation](docs/users/crucible/) covers deterministic
  exploration, reproduction, debugging, and CI.
- [Downstream flake guide](docs/engineering/downstream/quickstart.md) shows how
  another repository builds with AOS as its only flake input, under the
  versioned [downstream flake API](docs/engineering/downstream/flake-api.md).
- [Maintainer documentation](docs/maintainers/) covers source builds, trust and
  package security, image production, repository development, and tests.

## Contributing

Bug reports and feature proposals are welcome in
[GitHub Issues](https://github.com/andyl-technologies/aos/issues). Report
undisclosed vulnerabilities privately under the [security policy](SECURITY.md).
External contributions are currently disabled, and only project contributors
may open pull requests. Before changing packages, images, or build tooling,
read the
[contribution requirements](CONTRIBUTING.md) and
[maintainer guide](docs/maintainers/). The contribution requirements document
the employee authorization, external CLA, DCO, and license-boundary checks that
apply before a change is merged.
AOS is built hermetically from source;
new dependencies must be added to the AOS package graph rather than imported
from nixpkgs.

Load the development shell through direnv or `nix develop --accept-flake-config`.
It puts `aos-dev` and the ordinary packaged `aos` CLI in PATH:

```sh
aos --help
aos-dev run apm --help
aos-dev run apr --help
aos-dev cache init
aos-dev build package crucible --no-out-link
```

Tool-running commands fetch or build ordinary packaged binaries on demand.
Explicit development builds use shared compiler caches. The shell and script
use the production testing binary cache with signature verification and source
fallback; an empty cache still permits source builds. See
[the development instructions](AGENTS.md#the-aos-dev-development-entry-point)
for cache setup and incremental Rust builds.

Development VM and kernel-boot fleet tests materialize large images into the
local `images` cache, retaining only small, closure-pinning recipes in the Nix
store. Each launch verifies the base and creates a private reflink or sparse
copy. Assembly scratch and the cache both require disk-backed storage; only
completed images enter shared publication staging. Changing assertions reuses
the base; changing closures, tools, assembly,
layout, or baked configuration selects another base. Missing or corrupt bases
rebuild automatically. Image boot/integrity fixtures and interactive fleet
launchers keep ordinary immutable images.

```sh
aos-dev cache images status
aos-dev cache images prune --days 7 --max-gib 50
aos-dev --no-image-cache build check fleet.vm-artifact-reuse --no-out-link
```

Images use `$AOS_DEV_CACHE_DIR/images` on disk-backed storage, mounted at
`/aos-build-cache/images` by default (`AOS_DEV_IMAGE_CACHE_DIR` selects the
sandbox path). Automatic maintenance retains at most 100 GiB of allocated
idle bases for 14 days, oldest use first; active leases can temporarily exceed
the bound. Pruning skips active assembly/copy operations, reclaims abandoned
staging, and keeps lock files. It never removes source closures or private run
disks. Builders must trust cache writers: the local integrity manifest detects
incomplete or corrupt entries, but cannot authenticate a writer able to replace
both images and manifests. For qualification, `--release` and `--no-cache` select ordinary derivations and
bypass it even alongside enabling cache flags. Existing realized test results
still follow Nix reuse; changing assertions or explicitly rerunning a check is
necessary to execute its VMs again.

Shared ext4 root builders, headless assertion volumes, and fleet GPT assembly
normalize staged timestamps and ownership and derive filesystem UUIDs, directory
hash seeds, and partition GUIDs from content and partition roles. Independent cold
ordinary builds and runtime recipe reconstructions are compared byte for byte by
`aos-dev --release build check build.image-reproducibility --no-out-link`, including
ext4 shrink/grow and the shared EROFS root builder. Normalization preserves modes,
symlinks, extended attributes, and deliberate staging hardlinks without modifying
store inputs. Nix input copies discard hardlinks introduced by store optimization,
which NAR does not encode.
Different payloads receive different filesystem UUIDs; identical image clones
retain their UUID and should not be mounted together by UUID. This guarantee does
not cover the separate production ESP/GPT assembly or guest runtime provisioning,
which continues to allocate fresh machine identities.

Rust code uses one Cargo workspace under `crates/`, grouped into shared libraries,
AOS subsystems, Hub, and Crucible. See the
[Rust workspace guide](docs/engineering/rust-workspace.md) for package
ownership, reusable boundaries, and the crate inventory.

## Project status

AOS is under active development. Interfaces and disk formats may change before
the first stable release. Public installation images, a production
external-signing workflow, durable kernel updates, and complete runtime
`host.nix` activation are not available yet.

## License

Original AOS code is generally licensed under the
[Apache License 2.0](LICENSE). The repository and its distributions also contain
separately licensed components, including QEMU and its Crucible integration.
GitHub's Apache-2.0 label describes that default; it does not describe every
component in this multi-license repository. The
[licensing guide](docs/legal/README.md) points to the authoritative component
map, contribution agreement, and complete license texts.
