# Operate AOS

AOS is an immutable Linux distribution for headless servers and edge systems.
The repository builds the toolchain, package graph, operating-system closure,
disk images, and the tools used to operate them.

AOS is an early preview. The image build, first-boot storage provisioning,
package profiles, and userspace system-generation switch are implemented and
tested. Runtime activation of general `host.nix` settings and durable kernel
updates are not complete. These guides call out that boundary where it matters.

## The operating model

| Layer | How it is managed | Persistence |
| --- | --- | --- |
| System image | Modules under `systems/`, built with Nix | Immutable root and UEFI image |
| First-boot storage | Literal `host.nix` supplied through metadata | Committed once; later changes are drift |
| User packages | `apm install`, `upgrade`, `remove`, and `rollback` after account storage is provisioned | Per-user profile generations under `/var/lib/profiles/per-user` |
| Runtime system packages | `apm install --system --from DESIRED.toml` | Machine-wide package generations under `/var/lib/profiles/system-packages` |
| OS userspace | `apm upgrade --system` and `apm rollback --system` | Sysroot generations under `/var/lib/profiles/system` |

Three command names cover different jobs:

| Command | Use it for |
| --- | --- |
| `aos` | Building and inspecting this source tree, running checks, and administering AOS Hub |
| `apm` | Consuming packages and switching package or OS generations |
| `apr` | Creating, signing, and publishing package registries |

All three names are installed in an AOS image. They are also links to one
multicall binary, so `aos package` is equivalent to `apm` and
`aos package registry` is equivalent to `apr`.

## Start here

- [Build and boot a server](quickstart.md) takes a custom image from source to
  a real UEFI/KVM guest with SSH access and first-boot storage provisioning.
- [Install an image](installation.md) covers image formats, disk sizing,
  metadata transports, and deployment checks.
- [Customize AOS](configuration.md) separates build-time system modules from
  the narrower `host.nix` surface that is active today.
- [Understand and operate `host.nix`](host-nix.md) covers its complete
  lifecycle, trust policy, storage schema, examples, drift, and diagnostics.
- [Use the repository CLI](cli.md) covers the `aos` development command,
  output modes, and working-tree discovery.
- [Manage packages](packages.md) covers registry trust, user packages,
  declarative machine-wide packages, profiles, and package rollback.
- [Upgrade and roll back a host](upgrades.md) covers userspace OS generations,
  activation modes, and failure semantics.
- [Troubleshoot a host](troubleshooting.md) maps boot, provisioning, package,
  and generation failures to the relevant state and logs.

Registry producers should continue with
[Operate an AOS package registry](../registry/). Hub operators should use the
[AOS Hub guide](../aos-hub/).
