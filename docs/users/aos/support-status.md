# AOS support status

AOS is an early preview. This page records the operational boundary reflected
by the current implementation and tests. It is not a long-term compatibility
promise.

| Area | Status |
| --- | --- |
| Hermetic package and system builds | Implemented |
| Bootable images | `x86_64-linux` workflow implemented |
| UEFI boot | Required |
| Raw, QCOW2, VMDK, dynamic VHD output | Implemented |
| Build-time system modules | Implemented |
| Runtime `host.nix` storage provisioning | Implemented, first boot only |
| ext4 state on repart partitions | Stable; the default for every image (see [filesystem tiers](#filesystem-support-tiers)) |
| xfs data volumes | Supported on partitions and arrays, plain or TPM-sealed; `/var` remains ext4 |
| MD RAID arrays for `/var` and data volumes | Implemented; raid1 fleet-tested, raid0/10/5/6 validated and assembled by the same path |
| TPM-sealed LUKS2 data volumes | Implemented on measured-boot images; fleet-tested on an MD mirror |
| Recovery maintenance of a mirrored `/var` | Not implemented; the recovery console supports only the root-disk `var` partition |
| Other runtime `host.nix` settings | Early-preview configuration generations implemented |
| Platform-trusted metadata | Implemented for documented transports |
| Native AWS, GCP, Azure, DigitalOcean, OpenStack metadata | Implemented |
| Other native cloud metadata APIs | Unsupported |
| Signed metadata on GCP, Azure, DigitalOcean, native OpenStack | No detached-signature channel |
| DHCP and single-address static networking | Implemented |
| MTU, VLAN, and bond high-level options | Incomplete rendering |
| APM machine-wide packages | Add/remove reconciliation implemented; upgrade and rollback incomplete |
| [Typed package runtime policy](package-sandbox.md) | Implemented through native ability providers |
| Stock unprivileged user package profile | Not provisioned |
| Persistent home directories | `/root` always on the state volume; `/home` opt-in through `aos.homes` |
| Configuration generation rollback | Implemented |
| Durable image, kernel, and UKI upgrade | Early-preview A/B path implemented with boot counting and redundant ESP synchronization |
| Image rollback | Early-preview path implemented |
| Opaque runtime credential references | Implemented for system credentials, desired credentials, and TPM2 credstore |
| System-package/configuration generation pruning | Implemented |
| A/B image-generation pruning | Not implemented |
| [Secure Boot, lockdown, measured boot, dm-verity](secure-boot.md) | Fleet-test fixtures implemented |
| Package supply-chain attestation | Fleet-test implementation for signed system packages |
| SELinux module | Present, not enabled by presets |
| Audit, firewall, kernel hardening | Implemented in server baseline |
| Encrypted ZFS bare-metal storage | Supported when configured, at the lowest stability tier (see [filesystem tiers](#filesystem-support-tiers)) |
| [ZFS memory bounding and dataset policy](storage-zfs.md) | Implemented; does not bound every OpenZFS structure |
| ZFS pool lifecycle (event daemon, scrub, trim, health, metrics) | Implemented |
| ZFS pool creation outside the installer | Not implemented; the installer is the only path that creates a pool |
| NVIDIA GPU support | Open kernel modules and matching GSP firmware implemented |
| In-band IPMI | Kernel interfaces and `ipmitool` module implemented |
| Hardware watchdog and SMART monitoring | Opt-in |
| Remote log shipping | No complete module |

## Filesystem support tiers

AOS ranks persistent-state filesystems by maturity. Each tier is opt-in from
`host.nix` (or, for ZFS, from the image definition); nothing below the first
tier is selected by default.

| Tier | Filesystem | What it means |
| --- | --- | --- |
| Stable, default | ext4 | The only filesystem for `/var` and the default for data volumes. On the boot, sealing, growth, and recovery paths; qualified by every fleet test. |
| Supported | xfs | Data volumes on partitions or MD arrays, plain or TPM-sealed, with tool defaults. Exercised by the provisioning fleet test. In-tree kernel code. |
| Supported with caveats | ZFS | The `aos.profiles.bareMetalZfs` installer and dataset modules. OpenZFS is an out-of-tree module; qualify it on the exact host and kernel before relying on it, and expect its stability tier to stay below the in-tree filesystems. |

The ZFS caveat is not theoretical. On large hosts, the OpenZFS Linux
integration has shown failure classes that AOS cannot bound from
configuration: kernel memory retained far above the configured ARC ceiling
under metadata pressure, multi-minute write stalls with idle disk queues while
time is spent inside ZFS code paths, and kernel panics in the write and
encryption paths. Public reports of the same classes include
[openzfs/zfs#18893](https://github.com/openzfs/zfs/issues/18893) and
[openzfs/zfs#17516](https://github.com/openzfs/zfs/issues/17516). AOS keeps
the ZFS modules and installer maintained and tested, but the release
qualification bar is the ext4 and xfs paths.

For redundant or encrypted state without ZFS, declare MD arrays and TPM-sealed
volumes through [`host.nix`](host-nix.md#mirror-the-system-state).
