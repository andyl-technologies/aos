# Use AOS

AOS is an immutable Linux distribution for headless servers and edge systems.
These guides are for developers installing, configuring, and operating AOS on
their own machines.

AOS is an early preview. The public golden image is not published yet.
First-boot storage provisioning, runtime `host.nix` activation, package
profiles, and durable A/B image and configuration generations are present in
the tree. They remain early-preview interfaces that must be qualified on the
exact image and platform. The checked-in verified-boot variants still use
public test keys, and public image distribution and a production key-custody
workflow remain separate work.

## The operating model

| Layer | How it is managed | Persistence |
| --- | --- | --- |
| System image | Installed from the AOS golden image | Immutable root and UEFI image |
| First-boot storage | Literal `host.nix` supplied through metadata | Committed once; later changes are drift |
| Host configuration | Pure `host.nix` evaluation and authenticated package configuration | Numbered configuration generations under `/var/lib/profiles/system` |
| User packages | `apm install`, `upgrade`, `remove`, and `rollback` after account storage is provisioned | Per-user profile generations under `/var/lib/profiles/per-user` |
| Runtime system packages | `apm install --system --from DESIRED.toml` | Machine-wide package generations under `/var/lib/profiles/system-packages` |
| OS image | `apm upgrade --system` and `apm rollback --system --image` | A/B image generations under `/var/lib/profiles/image` |

Three command names cover different jobs on an AOS system:

| Command | Use it for |
| --- | --- |
| `apm` | Consuming packages and switching configuration or image generations |
| `apr` | Creating, signing, and publishing package registries |
| `aos` | Repository and AOS Hub tooling; most host package operations use `apm` |

All three names are installed in an AOS image. They are also links to one
multicall binary, so `aos package` is equivalent to `apm` and
`aos package registry` is equivalent to `apr`.

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

- [Manage packages](packages.md) covers registry trust, user packages,
  declarative machine-wide packages, profiles, and package rollback.
- [Operate an AOS host](operations.md) covers services, logs, storage,
  packages, monitoring, and maintenance.
- [Upgrade and roll back a host](upgrades.md) covers the independent image and
  configuration generation axes, A/B boot counting, and failure semantics.
- [Secure an AOS host](security.md) covers security presets, remote access,
  firewall, audit policy, trust roots, and the verified-boot boundary.
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
- [Deploy AOS in production](deployment.md) covers golden-image qualification,
  platform import, bare metal, and fleet promotion.
- [Maintain the source tree](../../maintainers/) covers Nix builds, image
  production, the repository CLI, and tests.
- [Build and boot from source](../../maintainers/source-build-quickstart.md) is
  the maintainer integration tutorial; it is not the normal installation path.

Registry producers should continue with
[Operate an AOS package registry](../registry/). Hub operators should use the
[AOS Hub guide](../aos-hub/).
