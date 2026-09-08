# AOS support status

AOS is an early preview. This page records the operational boundary reflected
by the current implementation and tests. It is not a long-term compatibility
promise.

| Area | Status | Operator guidance |
| --- | --- | --- |
| Hermetic package and system builds | Implemented | Build packages and systems through the AOS package set. Avoid dependencies on nixpkgs or tools installed on the build host. |
| Bootable images | `x86_64-linux` workflow implemented | Build on an x86 Linux host, or configure an x86 Linux remote builder. |
| UEFI boot | Required | Configure the target to boot with UEFI firmware. AOS images do not support legacy BIOS boot. |
| Raw, QCOW2, VMDK, dynamic VHD output | Implemented | Choose the format accepted by the target platform and validate that platform's import settings before rollout. |
| Build-time system modules | Implemented | Include boot-critical components and image trust policy in the release image; do not defer them to runtime configuration. |
| Runtime `host.nix` storage provisioning | Implemented, first boot only | Finalize and review the storage plan before first boot. After it is committed, treat any difference in later configuration as drift to resolve manually. |
| Other runtime `host.nix` settings | Early-preview configuration generations implemented | Preview the change, activate it on the intended image, and confirm that the activation record identifies the expected transaction. |
| Platform-trusted metadata | Implemented for documented transports | Use unsigned metadata only on a channel the platform authenticates. Require signed metadata on any other channel. |
| Native AWS, GCP, Azure, DigitalOcean, OpenStack metadata | Implemented | Validate both user-data and discovered platform facts before activation because AOS evaluates them together. |
| Other native cloud metadata APIs | Unsupported | Provide configuration through an offline metadata or config drive instead of relying on an unrecognized provider API. |
| Signed metadata on GCP, Azure, DigitalOcean, native OpenStack | No detached-signature channel | Use an offline drive or config drive when the deployment requires signed metadata. |
| DHCP and single-address static networking | Implemented | Confirm the target interface name and test connectivity with the deployed network configuration before rollout. |
| MTU, VLAN, and bond high-level options | Incomplete rendering | Provide complete systemd-networkd units for these features and test them on the target network. |
| APM machine-wide packages | Add/remove reconciliation implemented; upgrade and rollback incomplete | Install the desired set with `apm install --system --from`. Plan upgrades and rollbacks separately; sysroot operations do not manage runtime packages. |
| [Exposed APM service confinement](package-sandbox.md) | Implemented, early preview | Review the signed permissions of every service activated through `expose`; broad grants can weaken or eliminate confinement. Assess registry trust separately. |
| Stock unprivileged user package profile | Not provisioned | Provision a user package profile separately if users need to install or remove packages without administrator access. |
| Configuration generation rollback | Implemented | Roll back directly when the old and current generations share an ABI. For a cross-ABI rollback, retain the original inputs so AOS can re-evaluate them. |
| Durable image, kernel, and UKI upgrade | Early-preview A/B path implemented with boot counting and redundant ESP synchronization | Before production use, test inactive-slot staging, reboot recovery, ESP replica failover, and image-to-configuration binding with the target firmware. |
| Image rollback | Early-preview path implemented | Explicitly select an image rollback, then verify after boot that the intended configuration generation is bound to that image. |
| Opaque runtime credential references | Implemented for system credentials, desired credentials, and TPM2 credstore | Keep credential contents out of Nix configuration. Integrate Vault or cloud secret managers separately if required. |
| System-package/configuration generation pruning | Implemented | Retain the required rollback generations with `apm clean --system --generations --keep N`, then reclaim unreferenced storage with `apm gc`. |
| A/B image-generation pruning | Not implemented | Size `/var` to retain the required rollback images. Reimage the host when cleanup is necessary; do not delete image generations by hand. |
| [Secure Boot, lockdown, measured boot, dm-verity](secure-boot.md) | Fleet-test fixtures implemented | Replace the public test keys in the checked-in variants and establish a production key custody process before deployment. |
| Package supply-chain and runtime attestation | Fleet-test implementation for exposed system packages | Use signed registry graphs to authenticate package closures and PCR 15 to attest activated exposed roots and manifests. Require signed dm-verity `RootImage=` workloads where block-level runtime integrity is needed. |
| SELinux module | Present, not enabled by presets | Supply and validate a production SELinux policy package; the `standard` and `hardened` presets do not enable one. |
| Audit, firewall, kernel hardening | Implemented in server baseline | After deployment, confirm that the expected audit rules, firewall rules, kernel settings, and services are active. |
| Encrypted ZFS bare-metal storage | Early-preview installer and boot path implemented | Supply deployment trust keys and test TPM unlock, recovery, pool import, zvol slot handling, disk failure, and disk replacement on the target hardware. |
| NVIDIA GPU support | Open kernel modules and matching GSP firmware implemented | Provide version-matched compute or graphics userspace separately, then verify that the open kernel module binds to each target GPU. |
| In-band IPMI | Kernel interfaces and `ipmitool` module implemented | Enable the server-management profile, secure the BMC credentials, and test the interface and watchdog policy on the target hardware. |
| Hardware watchdog and SMART monitoring | Opt-in | Enable both features explicitly, then test device compatibility and end-to-end alert delivery on the target hardware. |
| Remote log shipping | No complete module | Configure journald's syslog forwarding and operate a compatible remote receiver separately. |

## Use the matrix in release reviews

For every deployment, record which incomplete or unsupported areas the design
touches. An unsupported feature may be reasonable in a development
environment, but it must not become an implicit production dependency.

When implementation changes one of these boundaries, update this page in the
same change or the immediately following documentation change. Prefer a small,
explicit limitation over an example that suggests an untested path works.
