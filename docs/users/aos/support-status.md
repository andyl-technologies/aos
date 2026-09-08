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
| Other runtime `host.nix` settings | Early-preview configuration generations implemented |
| Platform-trusted metadata | Implemented for documented transports |
| Native AWS, GCP, Azure, DigitalOcean, OpenStack metadata | Implemented |
| Other native cloud metadata APIs | Unsupported |
| Signed metadata on GCP, Azure, DigitalOcean, native OpenStack | No detached-signature channel |
| DHCP and single-address static networking | Implemented |
| MTU, VLAN, and bond high-level options | Incomplete rendering |
| APM machine-wide packages | Add/remove reconciliation implemented; upgrade and rollback incomplete |
| [Exposed APM service confinement](package-sandbox.md) | Implemented, early preview |
| Stock unprivileged user package profile | Not provisioned |
| Configuration generation rollback | Implemented |
| Durable image, kernel, and UKI upgrade | Early-preview A/B path implemented with boot counting and redundant ESP synchronization |
| Image rollback | Early-preview path implemented |
| Opaque runtime credential references | Implemented for system credentials, desired credentials, and TPM2 credstore |
| System-package/configuration generation pruning | Implemented |
| A/B image-generation pruning | Not implemented |
| [Secure Boot, lockdown, measured boot, dm-verity](secure-boot.md) | Fleet-test fixtures implemented |
| Package supply-chain and runtime attestation | Fleet-test implementation for exposed system packages |
| SELinux module | Present, not enabled by presets |
| Audit, firewall, kernel hardening | Implemented in server baseline |
| Encrypted ZFS bare-metal storage | Early-preview installer and boot path implemented |
| NVIDIA GPU support | Open kernel modules and matching GSP firmware implemented |
| In-band IPMI | Kernel interfaces and `ipmitool` module implemented |
| Hardware watchdog and SMART monitoring | Opt-in |
| Remote log shipping | No complete module |
