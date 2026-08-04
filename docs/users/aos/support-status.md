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
| Build-time system modules | Implemented | Bake networking, users, access, services, firewall, and required packages into the image |
| Runtime `host.nix` storage provisioning | Implemented, first boot only | Treat the committed plan as immutable; later differences are drift |
| Other runtime `host.nix` settings | Evaluated but not activated end to end | Do not rely on metadata for live networking, users, SSH keys, services, or package changes |
| Platform-trusted metadata | Implemented for documented transports | Use signed mode when the metadata channel is not trusted |
| Native Hetzner, Vultr, Scaleway, Oracle metadata | Detection only | Use an offline metadata drive |
| Signed metadata on GCP, Azure, DigitalOcean, native OpenStack | No detached-signature channel | Use an offline drive or config-drive transport |
| DHCP and single-address static networking | Implemented | Verify the target interface name before deployment |
| MTU, VLAN, and bond high-level options | Incomplete rendering | Supply and test complete networkd units if required |
| APM machine-wide packages | Add/remove reconciliation implemented; upgrade and rollback incomplete | Use `apm install --system --from`; do not confuse sysroot upgrade/rollback with runtime-package operations |
| Stock unprivileged user package profile | Not provisioned | Do not assume user-scope package mutation is available on a stock host |
| Userspace sysroot upgrade and rollback | Implemented for unchanged kernel/UKI | Dry-run, stage, and verify activation |
| Durable kernel and UKI upgrade | Incomplete | Reimage releases that change boot artifacts |
| System-package/sysroot generation pruning | Not implemented | Size `/var` and reimage instead of deleting generations manually |
| Secure Boot, lockdown, measured boot, dm-verity | Fleet-test fixtures implemented | Checked-in variants use public test keys; no complete production key-custody workflow is shipped |
| SELinux module | Present, not enabled by presets | No production policy package is wired into `standard` or `hardened` |
| Audit, firewall, kernel hardening | Implemented in server baseline | Verify active rules and service state on the deployed host |
| ZFS in the server path | Disabled for this iteration | Use the supported `/var` layout unless separately qualifying ZFS |
| Hardware watchdog and SMART monitoring | Opt-in | Qualify devices and alert delivery on real hardware |
| Remote log shipping | No complete module | Journald can forward to syslog, but the receiver must be separately provided |

## Use the matrix in release reviews

For every deployment, record which incomplete areas the design touches. An
unsupported feature may be reasonable in a development environment, but it
must not become an implicit production dependency.

When implementation changes one of these boundaries, update this page in the
same change or the immediately following documentation change. Prefer a small,
explicit limitation over an example that suggests an untested path works.
