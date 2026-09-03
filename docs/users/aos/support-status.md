# AOS support status

AOS is an early preview. This page records the operational boundary reflected
by the current implementation and tests. It is not a long-term compatibility
promise.

| Area | Status | Operator guidance |
| --- | --- | --- |
| Hermetic package and system builds | Implemented | Build through the repository's AOS package set; do not use nixpkgs or host tools |
| Bootable images | `x86_64-linux` workflow implemented | Use an x86 Linux host or remote builder |
| UEFI boot | Required | Select UEFI firmware; legacy BIOS is not a supported image path |
| Raw, QCOW2, VMDK, dynamic VHD output | Implemented | Provider import requirements remain platform-specific |
| Build-time system modules | Implemented | Keep boot-critical substrate and image trust policy in the release image |
| Runtime `host.nix` storage provisioning | Implemented, first boot only | Treat the committed plan as immutable; later differences are drift |
| Other runtime `host.nix` settings | Early-preview configuration generations implemented | Preview, activate, and verify the transaction-bound activation record on the exact image |
| Platform-trusted metadata | Implemented for documented transports | Use signed mode when the metadata channel is not trusted |
| Native AWS, GCP, Azure, DigitalOcean, OpenStack metadata | Implemented | User-data and normalized facts feed the same pure evaluation transaction |
| Other native cloud metadata APIs | Unsupported | Use an offline metadata or config drive; AOS does not guess provider protocols |
| Signed metadata on GCP, Azure, DigitalOcean, native OpenStack | No detached-signature channel | Use an offline drive or config-drive transport |
| DHCP and single-address static networking | Implemented | Verify the target interface name before deployment |
| MTU, VLAN, and bond high-level options | Incomplete rendering | Supply and test complete networkd units if required |
| APM machine-wide packages | Add/remove reconciliation implemented; upgrade and rollback incomplete | Use `apm install --system --from`; do not confuse sysroot upgrade/rollback with runtime-package operations |
| Exposed APM service confinement | Implemented, early preview | Applies to services activated through `expose`; inspect signed permissions because broad grants can weaken or remove the boundary, and treat registry trust separately |
| Stock unprivileged user package profile | Not provisioned | Do not assume user-scope package mutation is available on a stock host |
| Configuration generation rollback | Implemented | Same-ABI rollback is direct; cross-ABI rollback re-evaluates retained inputs |
| Durable image, kernel, and UKI upgrade | Early-preview A/B path implemented with boot counting and redundant ESP synchronization | Qualify inactive-slot staging, reboot, replica failover, and image/config generation binding on the target firmware |
| Image rollback | Early-preview path implemented | Select the image axis explicitly and qualify configuration rebind after boot |
| Opaque runtime credential references | Implemented for system credentials, desired credentials, and TPM2 credstore | Keep bytes outside Nix; external Vault/cloud-secret backends are separate |
| System-package/configuration generation pruning | Implemented | `apm clean --system --generations --keep N`, then `apm gc` |
| A/B image-generation pruning | Not implemented | Preserve rollback capacity; size `/var` and reimage rather than deleting image generations manually |
| Secure Boot, lockdown, measured boot, dm-verity | Fleet-test fixtures implemented | Checked-in variants use public test keys; no complete production key-custody workflow is shipped |
| SELinux module | Present, not enabled by presets | No production policy package is wired into `standard` or `hardened` |
| Audit, firewall, kernel hardening | Implemented in server baseline | Verify active rules and service state on the deployed host |
| Encrypted ZFS bare-metal storage | Early-preview installer and boot path implemented | Supply deployment trust keys; qualify TPM unlock, recovery, pool import, zvol slots, disk failure, and replacement on target hardware |
| NVIDIA GPU support | Open kernel modules and matching GSP firmware implemented | Proprietary compute and graphics userspace is outside the source-only image; qualify module binding and supply version-matched userspace separately |
| In-band IPMI | Kernel interfaces and `ipmitool` module implemented | Enable the server-management profile and qualify the BMC interface, watchdog policy, and credentials on target hardware |
| Hardware watchdog and SMART monitoring | Opt-in | Qualify devices and alert delivery on real hardware |
| Remote log shipping | No complete module | Journald can forward to syslog, but the receiver must be separately provided |

## Use the matrix in release reviews

For every deployment, record which incomplete or unsupported areas the design
touches. An unsupported feature may be reasonable in a development
environment, but it must not become an implicit production dependency.

When implementation changes one of these boundaries, update this page in the
same change or the immediately following documentation change. Prefer a small,
explicit limitation over an example that suggests an untested path works.
