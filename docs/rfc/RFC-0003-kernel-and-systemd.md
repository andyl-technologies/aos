# RFC-0003: Kernel Configuration and systemd Integration

- **Status**: Draft
- **Authors**: ANDYL OS Architecture Team
- **Date**: 2026-02-10
- **Supersedes**: None

## Abstract

ANDYL OS uses a custom-built upstream Linux kernel (6.12.x LTS series) with a fragment-based configuration management strategy. The kernel is configured for server workloads with support for KVM, eBPF, namespaces, cgroups v2, and SELinux mandatory access control. The root filesystem is an immutable ext4 golden image; ZFS is used for mutable data (`/var`, etc.) and is provisioned by Ignition on first boot. systemd replaces Guix's default Shepherd as PID 1, with systemd-boot as the boot loader, Unified Kernel Images (UKIs) for boot management, and dracut for initrd generation.

## Motivation

A server-oriented OS requires precise control over kernel features: container isolation (namespaces, cgroups v2), storage (ext4 for immutable root, ZFS for mutable data, NVMe, dm-verity), networking (eBPF for Cilium CNI), virtualization (KVM), and security (SELinux for mandatory access control). The upstream kernel (not linux-libre) is necessary because linux-libre strips firmware loading support and proprietary driver stubs needed for server hardware. A fragment-based configuration approach keeps kernel configs reviewable, composable, and version-controllable rather than maintaining an opaque monolithic `.config` file.

## Design

### 1. LTS Kernel Series Selection

**Selected: Linux 6.12.x LTS**

| Series | EOL | Status | Rationale |
|--------|-----|--------|-----------|
| 6.6.x | Dec 2026 | Mature LTS | Proven stability; shorter support runway |
| 6.12.x | ~2028 | Fresh LTS | **Selected.** Longer support runway, improved eBPF (BPF arena, kfuncs), better io_uring, cgroup v2 improvements, newer cloud drivers |

Fallback: If OpenZFS or a critical driver lags on 6.12, start with 6.6.x and upgrade once compatibility is confirmed. OpenZFS 2.3.x is required for 6.12 kernel support.

### 2. Kernel Config Fragment Management

We use a **defconfig + fragment overlay** approach. Config fragments are stored in separate files organized by subsystem:

```
kernel/
  base.config              Core options (cgroups, namespaces, security)
  storage.config           ZFS deps, NVMe, virtio-blk, dm-verity
  networking.config        Netfilter, eBPF, virtio-net, cloud NICs
  virtualization.config    KVM, vhost
  security.config          SELinux, IMA, seccomp
  drivers-vm.config        Virtio drivers (built-in for boot)
  drivers-cloud.config     AWS/GCP/Azure specific drivers
  drivers-baremetal.config Server NIC and storage controllers
  Makefile                 Merges fragments into final .config
```

Fragment merge uses `scripts/kconfig/merge_config.sh` from the kernel tree:

```bash
cd linux-6.12.x
make defconfig
./scripts/kconfig/merge_config.sh .config \
  ../kernel/base.config \
  ../kernel/storage.config \
  ../kernel/networking.config \
  ../kernel/virtualization.config \
  ../kernel/security.config \
  ../kernel/drivers-vm.config
```

Conflicts are resolved last-writer-wins (later fragments override earlier ones).

### 3. Required Kernel Features

#### 3.1 ZFS Prerequisites

OpenZFS is built out-of-tree but the kernel must enable features it depends on:

```kconfig
CONFIG_TMPFS_POSIX_ACL=y
CONFIG_CRYPTO=y
CONFIG_CRYPTO_DEFLATE=y
CONFIG_CRYPTO_LZ4=y
CONFIG_CRYPTO_LZ4HC=y
CONFIG_CRYPTO_ZSTD=y
CONFIG_CRYPTO_SHA256=y
CONFIG_CRYPTO_SHA512=y
CONFIG_CRYPTO_AES=y
CONFIG_BLOCK=y
CONFIG_BLK_DEV_LOOP=y
CONFIG_BLK_DEV_DM=y
CONFIG_DM_SNAPSHOT=y
CONFIG_DM_CRYPT=m
CONFIG_UNICODE=y
# CONFIG_ZFS is not set    (OpenZFS is built separately)
```

#### 3.2 KVM (Virtualization Host)

```kconfig
CONFIG_VIRTUALIZATION=y
CONFIG_KVM=m
CONFIG_KVM_INTEL=m
CONFIG_KVM_AMD=m
CONFIG_VHOST=m
CONFIG_VHOST_NET=m
CONFIG_VHOST_VSOCK=m
CONFIG_IOMMU_SUPPORT=y
CONFIG_INTEL_IOMMU=y
CONFIG_AMD_IOMMU=y
CONFIG_VFIO=m
CONFIG_VFIO_PCI=m
CONFIG_HUGETLBFS=y
CONFIG_TRANSPARENT_HUGEPAGE=y
```

#### 3.3 eBPF (Observability, Networking, Security)

```kconfig
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_BPF_JIT_ALWAYS_ON=y
CONFIG_BPF_UNPRIV_DEFAULT_OFF=y
CONFIG_BPF_LSM=y
CONFIG_DEBUG_INFO_BTF=y          # BTF for CO-RE
CONFIG_DEBUG_INFO_BTF_MODULES=y
CONFIG_BPF_STREAM_PARSER=y
CONFIG_LWTUNNEL_BPF=y
CONFIG_NET_ACT_BPF=m
CONFIG_NET_CLS_BPF=m
CONFIG_CGROUP_BPF=y
CONFIG_KPROBES=y
CONFIG_KPROBE_EVENTS=y
CONFIG_UPROBE_EVENTS=y
CONFIG_FTRACE=y
CONFIG_FUNCTION_TRACER=y
CONFIG_DYNAMIC_FTRACE=y
CONFIG_FPROBE=y
```

#### 3.4 Namespaces (Containers / Kubernetes)

```kconfig
CONFIG_NAMESPACES=y
CONFIG_UTS_NS=y
CONFIG_IPC_NS=y
CONFIG_USER_NS=y
CONFIG_PID_NS=y
CONFIG_NET_NS=y
CONFIG_CGROUP_NS=y
CONFIG_TIME_NS=y
```

#### 3.5 Cgroups v2

```kconfig
CONFIG_CGROUPS=y
CONFIG_CGROUP_V2=y
CONFIG_MEMCG=y
CONFIG_CGROUP_SCHED=y
CONFIG_CGROUP_PIDS=y
CONFIG_CGROUP_FREEZER=y
CONFIG_CGROUP_HUGETLB=y
CONFIG_CGROUP_DEVICE=y
CONFIG_CGROUP_CPUACCT=y
CONFIG_CGROUP_PERF=y
CONFIG_CGROUP_BPF=y
CONFIG_PSI=y                     # Pressure Stall Information (systemd-oomd)
CONFIG_BLK_CGROUP=y
CONFIG_BLK_CGROUP_IOLATENCY=y
CONFIG_BLK_CGROUP_IOCOST=y
```

Boot parameter to enforce unified hierarchy: `systemd.unified_cgroup_hierarchy=1`

#### 3.6 OverlayFS (Container Runtime)

```kconfig
CONFIG_OVERLAY_FS=y
CONFIG_OVERLAY_FS_REDIRECT_DIR=y
CONFIG_OVERLAY_FS_METACOPY=y
CONFIG_OVERLAY_FS_INDEX=y
CONFIG_OVERLAY_FS_XINO_AUTO=y
```

#### 3.7 Security Modules

```kconfig
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_SECURITY_NETWORK=y
CONFIG_SECURITY_SELINUX=y         # Mandatory access control (label-based)
CONFIG_DEFAULT_SECURITY_SELINUX=y
CONFIG_SECURITY_SELINUX_BOOTPARAM=y
CONFIG_SECURITY_SELINUX_DEVELOP=y
CONFIG_SECURITY_SELINUX_AVC_STATS=y
CONFIG_SECURITY_SELINUX_CHECKREQPROT_VALUE=0
CONFIG_AUDIT=y                    # Required by SELinux
CONFIG_AUDITSYSCALL=y
CONFIG_SECURITY_YAMA=y            # ptrace restrictions
CONFIG_SECCOMP=y
CONFIG_SECCOMP_FILTER=y
CONFIG_SECURITY_LANDLOCK=y        # Unprivileged sandboxing
CONFIG_IMA=y                      # Integrity measurement
CONFIG_EVM=y
CONFIG_SECURITY_LOCKDOWN_LSM=y
CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY=y
CONFIG_STACKPROTECTOR=y
CONFIG_STACKPROTECTOR_STRONG=y
```

**SELinux is the definitive MAC system for ANDYL OS.** The decision to use SELinux (rather than AppArmor or other LSMs) is based on the following rationale:

- **Fine-grained mandatory access control:** SELinux's label-based model provides type enforcement (TE), role-based access control (RBAC), and optional multi-level security (MLS). Labels travel with objects rather than being tied to filesystem paths, which is critical for confining container workloads where mount namespaces make paths dynamic and unpredictable. This is fundamentally more expressive than AppArmor's path-based model.
- **Container and Kubernetes integration:** SELinux is the default MAC system for Kubernetes, CRI-O, and containerd. The `container-selinux` policy module provides well-tested contexts (`container_t`, `container_file_t`, `container_runtime_t`) that are assumed by Pod SecurityContexts and RuntimeDefault profiles. Kubernetes SecurityContext fields (`seLinuxOptions`) map directly to SELinux contexts.
- **RHEL ecosystem alignment:** The majority of production Kubernetes and container tooling is developed and tested against SELinux (RHEL, Fedora CoreOS, OpenShift). Choosing SELinux avoids translation friction with upstream documentation, policies, and troubleshooting guides. Most container runtime SELinux bugs are found and fixed in this ecosystem first.
- **Audit integration:** SELinux's tight coupling with the Linux audit subsystem (`CONFIG_AUDIT=y`, `CONFIG_AUDITSYSCALL=y`) provides comprehensive, structured access logging. Every policy decision (allow or deny) can be logged with full context (source, target, class, permission), which is essential for compliance reporting, incident response, and iterative policy development via `audit2allow`.
- **Immutable root compatibility:** SELinux labels are stored as `security.selinux` xattrs on the filesystem. The ext4 golden image is fully labeled at build time. OverlayFS for `/etc` supports reading xattrs from the lower layer and writing them in the upper layer, which is compatible with our architecture.

Boot parameters: `security=selinux selinux=1`

Policy: Targeted policy (default). MLS policy available for compliance workloads (government, finance, defense). The `container-selinux` policy module is required for container runtime support.

### 4. Kernel as a Guix Package

The kernel is defined as a Guix package that fetches the upstream kernel.org tarball (NOT linux-libre):

```scheme
(define-public andyl-kernel
  (package
    (name "andyl-kernel")
    (version "6.12.10")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://cdn.kernel.org/pub/linux/kernel/v6.x/"
             "linux-" version ".tar.xz"))
       (sha256 (base32 "HASH_HERE"))))
    (build-system gnu-build-system)
    (arguments
     (list
      #:tests? #f
      #:phases
      #~(modify-phases %standard-phases
          (replace 'configure
            (lambda* (#:key inputs #:allow-other-keys)
              (copy-file #$%andyl-kernel-config ".config")
              (invoke "make" "olddefconfig")))
          (replace 'build
            (lambda _
              (invoke "make" "-j" (number->string (parallel-job-count))
                      "bzImage" "modules")))
          (replace 'install
            (lambda* (#:key outputs #:allow-other-keys)
              (let ((out (assoc-ref outputs "out")))
                (invoke "make"
                        (string-append "INSTALL_MOD_PATH=" out)
                        "modules_install")
                (install-file "arch/x86/boot/bzImage"
                              (string-append out "/boot"))
                (install-file "System.map"
                              (string-append out "/boot"))
                (invoke "make"
                        (string-append "INSTALL_HDR_PATH=" out "/usr")
                        "headers_install")))))))
    (native-inputs (list perl flex bison elfutils bc openssl kmod))
    ...))
```

### 5. Kernel Module Handling on Immutable OS

Traditional `dkms` (which writes to `/lib/modules/` at runtime) cannot work on an immutable root. Instead:

- All in-tree modules are built during the kernel package build.
- Out-of-tree modules (OpenZFS) are built as separate Guix packages that depend on the kernel package.
- At image assembly time, kernel modules and ZFS modules are union-merged into a single read-only `/lib/modules/<version>/`.
- `depmod` runs at build time to generate `modules.dep`.
- No runtime module compilation is ever needed.

```
andyl-kernel --------+
                     +---> merge /lib/modules/<ver>/ --> depmod --> image
andyl-zfs-modules ---+
```

### 6. Driver Strategy

**Built-in (`=y`) for boot-critical drivers:**
- NVMe (`CONFIG_BLK_DEV_NVME=y`)
- AHCI (`CONFIG_AHCI=y`)
- Virtio block (`CONFIG_VIRTIO_BLK=y`)
- Virtio net (`CONFIG_VIRTIO_NET=y`)
- Virtio PCI (`CONFIG_VIRTIO_PCI=y`)
- Serial console (`CONFIG_SERIAL_8250=y`)

**Module (`=m`) for everything else:**
- Cloud drivers (ENA, gVNIC, Hyper-V)
- Bare metal NICs (Intel ice/i40e/ixgbe, Mellanox mlx5, Broadcom bnxt)
- RAID controllers (MegaRAID, SmartPQI)
- KVM/VFIO
- Non-boot filesystems

**Image strategy:** Start with a universal image containing all drivers as modules. Split into per-environment images (vm, cloud, baremetal) if image size or attack surface becomes critical.

### 7. Firmware Management

The upstream `linux-firmware` repository is ~862 MB. We strip it to ~20 MB of server-relevant firmware:

```scheme
(define-public andyl-firmware
  (package
    (name "andyl-firmware")
    (version "20250110")
    (source (origin (method git-fetch) ...))
    (build-system copy-build-system)
    (arguments
     (list #:install-plan
      #~'(("intel-ucode" "lib/firmware/intel-ucode")
          ("amd-ucode" "lib/firmware/amd-ucode")
          ("intel/ice" "lib/firmware/intel/ice")
          ("mellanox" "lib/firmware/mellanox")
          ("bnxt" "lib/firmware/bnxt")
          ("bnx2x" "lib/firmware/bnx2x")
          ("qed" "lib/firmware/qed"))))
    ...))
```

CPU microcode is loaded as an early initrd (uncompressed cpio prepended to the main initrd) for UEFI systems or embedded in the UKI.

### 8. systemd Integration (Replacing Shepherd)

ANDYL OS uses systemd as PID 1 instead of Guix's default Shepherd. The kernel `init=` parameter points to `/usr/lib/systemd/systemd`.

**systemd unit packaging:** Since we cannot use Guix's `(service ...)` abstractions (which target Shepherd), systemd units are packaged as Guix packages:

```scheme
(define-public andyl-base-services
  (package
    (name "andyl-base-services")
    (version "1.0")
    (source (local-file "./units" #:recursive? #t))
    (build-system copy-build-system)
    (arguments
     '(#:install-plan
       '(("." "lib/systemd/system/"
          #:include-regexp (".*\\.service$"
                            ".*\\.timer$"
                            ".*\\.socket$"
                            ".*\\.target$"
                            ".*\\.mount$")))))
    ...))
```

**Key systemd features for immutable OS:**

- `tmpfiles.d`: Creates volatile directories on every boot:
  ```ini
  d /var/log 0755 root root -
  d /var/lib 0755 root root -
  d /var/cache 0755 root root -
  d /var/tmp 1777 root root 30d
  d /run/andyl 0755 root root -
  ```

- `sysusers.d`: Ensures system users exist on boot:
  ```ini
  u root 0 "Super User" /root /bin/bash
  u nobody 65534 "Nobody" / /sbin/nologin
  u systemd-network 192 "systemd Network Management" / /sbin/nologin
  u systemd-resolve 193 "systemd Resolver" / /sbin/nologin
  ```

- `networkd`: Predictable network management for servers:
  ```ini
  [Match]
  Type=ether
  Name=en* eth*

  [Network]
  DHCP=yes
  IPv6AcceptRA=yes
  ```

### 9. systemd-boot as Bootloader

systemd-boot is a simple UEFI boot manager on the ESP. Each generation gets a boot loader entry.

**Type #1 entries:**

```ini
# /boot/loader/entries/andyl-os-gen-42.conf
title      ANDYL OS (gen 42)
version    42
linux      /andyl-os/42/vmlinuz
initrd     /andyl-os/42/intel-ucode.img
initrd     /andyl-os/42/initramfs.img
options    root=/dev/disk/by-label/ANDYL-ROOT ro quiet
```

### 10. Unified Kernel Images (UKIs)

UKIs bundle kernel + initrd + cmdline + os-release into a single PE/COFF binary that systemd-boot can boot directly.

```bash
/usr/lib/systemd/ukify build \
  --linux=vmlinuz-6.12.10 \
  --initrd=intel-ucode.img \
  --initrd=initramfs-6.12.10.img \
  --cmdline="root=/dev/disk/by-label/ANDYL-ROOT ro quiet" \
  --os-release=@os-release \
  --output=andyl-os-gen-42.efi
```

UKIs simplify boot management and enable Secure Boot signing of the entire boot chain as a single artifact. The UKI is placed on the ESP at `/boot/EFI/Linux/andyl-os_42+3-0.efi` (with boot counting suffix).

### 11. dracut for Initrd Generation

dracut generates the systemd-based initrd at **image build time** (not at runtime):

```bash
dracut \
  --force \
  --kver 6.12.10 \
  --add "systemd" \
  --fstab \
  --no-hostonly \
  --no-early-microcode \
  /boot/initramfs-6.12.10.img
```

`--no-hostonly` is critical: we build a generic initrd, not one tailored to the build host.

The systemd-based initrd provides:
- Consistent logging (journald in initrd)
- Device management via systemd-udevd
- ext4 root mount (standard systemd root mount)
- Ignition first-boot provisioning (creates ZFS data pool if needed)
- Clean handoff from initrd to real root via `switch-root`

**Root mount in initrd:**

The kernel command line `root=/dev/disk/by-label/ANDYL-ROOT ro` triggers the standard systemd root mount. ZFS is NOT needed in the initrd because the root filesystem is ext4. The ZFS kernel module is loaded after boot by systemd to import the data pool and mount `/var`, `/var/lib`, and `/var/log`.

### 12. Boot Counting Protocol

systemd-boot implements automatic boot assessment via filename-based counting:

```
andyl-os_42+3-0.efi    Fresh deploy, 3 tries remaining
andyl-os_42+2-1.efi    After 1st boot attempt
andyl-os_42+1-2.efi    After 2nd failed boot
andyl-os_42+0-3.efi    After 3rd failed boot -> fallback on next boot
andyl-os_42.efi        Verified good (counter removed by systemd-bless-boot)
```

The `systemd-bless-boot.service` marks a boot as successful after the health check passes:

```ini
[Unit]
Description=Mark Boot as Successful
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/lib/systemd/systemd-bless-boot good

[Install]
WantedBy=multi-user.target
```

## Alternatives Considered

**linux-libre:** Rejected because it strips firmware loading support and proprietary driver stubs needed for server NICs, storage controllers, and cloud environments.

**Shepherd init system:** Rejected because it lacks the ecosystem integration needed: boot counting, sysext, networkd, comprehensive container runtime support, and tmpfiles.d/sysusers.d for immutable OS patterns.

**GRUB bootloader:** Rejected in favor of systemd-boot for its simplicity, native boot counting support, and UKI compatibility. GRUB's complexity is unnecessary for UEFI-only systems.

**mkinitcpio / custom CPIO assembly:** dracut was chosen over alternatives for its first-class systemd-in-initrd support, ZFS module, and UKI generation capability.

**AppArmor (instead of SELinux):** Rejected. While AppArmor has a simpler path-based policy model that is easier to learn initially, SELinux is the definitive choice for ANDYL OS because: (1) SELinux's label-based mandatory access control provides fine-grained type enforcement that follows objects across mount namespaces, which is critical for container workloads; (2) Kubernetes, CRI-O, containerd, and the `container-selinux` policy module are developed and tested against SELinux in the RHEL/Fedora ecosystem; (3) SELinux's tight integration with the Linux audit subsystem provides structured, comprehensive access logging for compliance and incident response; (4) RBAC and optional MLS provide security tiers that AppArmor cannot match.

## Security Considerations

- **SELinux MAC:** SELinux is the definitive mandatory access control system for ANDYL OS. Targeted policy confines daemons and container workloads with type enforcement and RBAC. The audit subsystem (`CONFIG_AUDIT=y`, `CONFIG_AUDITSYSCALL=y`) logs all access decisions for compliance and forensics. The ext4 golden image is fully labeled at build time using `setfiles`/`restorecon`; the OverlayFS `/etc` upper layer and ZFS mutable data are labeled on first boot via Ignition. Container workloads receive `container_t` contexts via the `container-selinux` policy module.
- **Kernel hardening flags:** Stack protector (strong), lockdown mode (integrity), YAMA ptrace restrictions, seccomp filters, and Landlock are all enabled.
- **eBPF restrictions:** `CONFIG_BPF_UNPRIV_DEFAULT_OFF=y` prevents unprivileged eBPF program loading.
- **Firmware stripping:** Only server-relevant firmware is included, reducing the attack surface from 862 MB to ~20 MB.
- **UKI signing:** UKIs can be signed for UEFI Secure Boot, creating a verified chain from firmware to kernel to initrd.
- **Immutable ext4 root:** The root filesystem is an ext4 golden image mounted read-only. Kernel modules and system binaries are part of this read-only root and cannot be tampered with at runtime. dm-verity can be layered on top for cryptographic integrity verification.
- **Boot counting:** Automatic rollback after 3 failed boots prevents a bad kernel update from leaving the system unbootable.

## Compatibility

- **OpenZFS 2.3.x** is required for 6.12 kernel compatibility (used for mutable data pool, not root). If using 6.6 LTS, OpenZFS 2.2.x is sufficient.
- **Kubernetes:** All required kernel features (namespaces, cgroups v2, eBPF, overlayfs, netfilter) are enabled. SELinux is the default MAC for Kubernetes SecurityContexts; the `container-selinux` policy module is included.
- **Container runtimes:** containerd and runc are fully supported with systemd cgroup driver. SELinux container contexts (`container_t`, `container_file_t`) are enforced via the `container-selinux` policy module. SELinux `seLinuxOptions` in Kubernetes PodSecurityContext are fully supported.
- **Cloud providers:** Drivers for AWS (ENA, NVMe), GCP (gVNIC, virtio), and Azure (Hyper-V) are included as modules.
- **UEFI required:** systemd-boot requires UEFI firmware. Legacy BIOS is not supported.

## Open Questions

1. **Kernel series finalization:** OpenZFS 2.3.x compatibility with 6.12 needs validation testing before committing.
2. **SELinux policy scope:** Determine whether MLS policy is needed for any initial deployment targets, or if targeted policy is sufficient across the board.
3. **UKI signing and Secure Boot:** Should we implement Secure Boot from day one? This requires key management infrastructure.
4. **Per-environment images:** When should we split the universal image into vm/cloud/baremetal variants?
5. **initrd generator:** Should we evaluate `mkosi-initrd` as an alternative to dracut?

## References

- Linux Kernel Configuration: https://docs.kernel.org/admin-guide/README.html
- systemd-boot: https://www.freedesktop.org/software/systemd/man/systemd-boot.html
- Unified Kernel Image: https://uapi-group.org/specifications/specs/unified_kernel_image/
- dracut: https://github.com/dracut-ng/dracut-ng
- OpenZFS: https://openzfs.github.io/openzfs-docs/
- Boot Counting: https://systemd.io/AUTOMATIC_BOOT_ASSESSMENT/
- SELinux Project: https://selinuxproject.org/
- container-selinux: https://github.com/containers/container-selinux
- eBPF: https://ebpf.io/
