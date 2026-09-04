# Use AOS

AOS is an immutable Linux distribution for headless servers and edge systems.
These guides are for developers installing, configuring, and operating AOS on
their own machines.

AOS is an early preview. The public golden image is not published yet.
First-boot storage provisioning, runtime `host.nix` activation, package
profiles, durable A/B image and configuration generations, and a guarded
encrypted-ZFS bare-metal installer are present in the tree. They remain
early-preview interfaces that must be qualified on the exact image and
platform. The checked-in verified-boot variants still use public test keys;
production deployments must supply their own trust material.

## The operating model

| Layer | How it is managed | Persistence |
| --- | --- | --- |
| System image | Installed from the AOS golden image | Immutable root and UEFI image |
| First-boot storage | Literal `host.nix` supplied through metadata | Committed once; later changes are drift |
| Host configuration | Pure `host.nix` evaluation and authenticated package configuration | Numbered configuration generations under `/var/lib/profiles/system` |
| User packages | `apm install`, `upgrade`, `remove`, and `rollback` after account storage is provisioned | Per-user profile generations under `/var/lib/profiles/per-user` |
| Runtime system packages | `apm install --system --from DESIRED.toml` | Machine-wide package generations under `/var/lib/profiles/system-packages` |
| OS image | `apm upgrade --system` and `apm rollback --system --image` | A/B image generations under `/var/lib/profiles/image` |

Three command names cover different jobs in the AOS toolchain:

| Command | Use it for |
| --- | --- |
| `apm` | Consuming packages and switching configuration or image generations |
| `apr` | Creating, signing, and publishing package registries from a maintainer host |
| `aos` | Repository and AOS Hub tooling from a development or operations host |

All three are independent programs backed by shared Rust libraries. `aos` has
no package-management subcommand, `apm` cannot publish registries, and `apr`
cannot install packages. Private activation and evaluation operations run
through `aos-package-runtime`; that executable is reserved for AOS services
and is not an operator CLI.

The base image installs `apm`, while AOS units reference the private runtime by
an absolute store path. It does not put `aos` or `apr` on the image `PATH`.
This keeps source construction, registry-authoring authority, package
consumption, and on-host activation as distinct installed capabilities.

## Install and configure

- [Install an image](installation.md) covers image formats, disk sizing,
  metadata transports, and deployment checks.
- [Understand and operate `host.nix`](host-nix.md) covers first-boot policy,
  trust, storage, drift, and diagnostics.
- [Configure an AOS host](configuration.md) explains what `host.nix` and `apm`
  can change today and what still belongs to the release image.
- [Configure networking](networking.md) covers DHCP, static addressing, DNS,
  diagnostics, and current advanced-networking limits.

## Operate the host

- [Manage packages](packages.md) covers user packages, declarative machine-wide
  packages, profiles, and package rollback.
- [Configure package registries](registries.md) covers the built-in registry,
  other public and internal registries, priorities, credentials, and trust.
- [Understand the package sandbox](package-sandbox.md) explains the runtime
  boundary for exposed services and how to inspect its effective policy.
- [Operate an AOS host](operations.md) covers services, logs, storage,
  packages, monitoring, and maintenance.
- [Upgrade and roll back a host](upgrades.md) covers the independent image and
  configuration generation axes, A/B boot counting, and failure semantics.
- [Use Secure Boot and verify package trust](secure-boot.md) follows the chain
  from firmware through the immutable root to signed package content.
- [Control access](access-control.md) covers accounts, SSH, privilege, and
  break-glass access.
- [Harden an AOS host](security-hardening.md) covers security presets, kernel
  policy, service isolation, and production qualification.
- [Audit an AOS host](auditing.md) covers audit policy, logs, evidence, and
  verification limits.
- [Manage certificates and CA trust](certificates.md) covers TLS identities,
  internal CAs, rotation, and compromise response.
- [Manage secrets on AOS](secrets.md) defines safe build-time and runtime
  handling, rotation, and incident response.
- [Recover an AOS host](recovery.md) covers first boot, activation, packages,
  disk pressure, Hub state, and reimaging decisions.
- [Troubleshoot a host](troubleshooting.md) maps boot, provisioning, package,
  and generation failures to the relevant state and logs.
- [AOS support status](support-status.md) lists implemented and incomplete
  operational surfaces.

## Develop and maintain AOS

- [Package an application for AOS](package-authoring.md) follows a service from
  its derivation through image inclusion, registry publication, and upgrade.
- Package and service configuration is generated from each package's Nix
  interface and signed runtime contract. Use `apm docs`, `apm options`, the
  offline `apm docs serve` browser, or the package documentation workspace in
  AOS Hub. The generated reference covers nginx, Envoy, k3s and add-ons,
  registry services, containerd, databases and storage, identity services,
  network daemons, and KubeEdge without maintaining a second Markdown schema.
- [Deploy AOS in production](deployment.md) covers golden-image qualification,
  platform import, bare metal, and fleet promotion.
- [Maintain the source tree](../../maintainers/) covers Nix builds, image
  production, the repository CLI, and tests.
- [Build and boot from source](../../maintainers/source-build-quickstart.md) is
  the maintainer integration tutorial; it is not the normal installation path.

Registry producers should continue with
[Operate an AOS package registry](../registry/). Hub operators should use the
[AOS Hub guide](../aos-hub/).
