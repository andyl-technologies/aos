# 02 - Kernel, systemd, and System Architecture

This document covers the low-level system architecture of ANDYL OS: the custom
kernel build, driver and firmware management, systemd integration, ZFS support
(for mutable data), SELinux mandatory access control, and the immutable base
image design (ext4 golden image with read-only root).

---

## Table of Contents

1. [Custom Kernel Build](#1-custom-kernel-build)
2. [Driver Management](#2-driver-management)
3. [Firmware Stripping](#3-firmware-stripping)
4. [systemd as Init System](#4-systemd-as-init-system)
5. [ZFS Support (Mutable Data Only)](#5-zfs-support-mutable-data-only)
6. [Immutable Base Image Architecture](#6-immutable-base-image-architecture)

---

## 1. Custom Kernel Build

### 1.1 LTS Kernel Series Selection

As of early 2025, two viable upstream LTS kernel series exist:

| Series | EOL        | Status        | Notes |
|--------|------------|---------------|-------|
| 6.6.x  | Dec 2026   | Mature LTS    | Proven stability, wide driver support |
| 6.12.x | ~2028      | Fresh LTS     | Newest features, longer support runway |

**Recommendation: 6.12.x LTS**

Rationale:
- Longer support runway avoids a forced migration within the first 1-2 years of
  ANDYL OS deployment.
- 6.12 includes improved eBPF features (BPF arena, kfuncs), better io_uring
  support, and cgroup v2 improvements that benefit our server workloads.
- OpenZFS 2.3.x supports 6.12 kernels.
- Newer cloud driver support (AWS ENA improvements, GCP gvnic) is better in 6.12.

Fallback: If OpenZFS or a critical driver lags on 6.12, start with 6.6.x and
upgrade once compatibility is confirmed. Both are valid choices.

### 1.2 Kernel Config Management Strategy

We use a **defconfig + fragment overlay** approach rather than maintaining a
monolithic `.config` file. This makes configs reviewable, composable, and
version-controllable.

```
kernel/
  base.config           # Core options (cgroups, namespaces, security)
  storage.config        # ZFS deps, NVMe, virtio-blk, dm-verity
  networking.config     # Netfilter, eBPF, virtio-net, cloud NICs
  virtualization.config # KVM, vhost
  security.config       # SELinux, IMA, seccomp
  drivers-vm.config     # Virtio drivers
  drivers-cloud.config  # AWS/GCP/Azure drivers
  drivers-baremetal.config  # Server NIC and storage drivers
  Makefile              # Merges fragments → .config
```

Fragment merge process using `scripts/kconfig/merge_config.sh` from the kernel
tree:

```bash
# Start from a minimal defconfig, then layer fragments
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

This produces a final `.config` that is the merge of all fragments. Conflicts
are resolved last-writer-wins (later fragments override earlier ones).

### 1.3 Required Kernel Config Options

#### 1.3.1 ZFS Prerequisites

OpenZFS is built out-of-tree, but the kernel must enable features it depends on:

```kconfig
# ZFS requires POSIX ACLs
CONFIG_TMPFS_POSIX_ACL=y

# Required: SIMD / crypto acceleration for ZFS checksums
CONFIG_CRYPTO=y
CONFIG_CRYPTO_DEFLATE=y
CONFIG_CRYPTO_LZ4=y
CONFIG_CRYPTO_LZ4HC=y
CONFIG_CRYPTO_ZSTD=y
CONFIG_CRYPTO_SHA256=y
CONFIG_CRYPTO_SHA512=y
CONFIG_CRYPTO_AES=y
CONFIG_CRYPTO_SKCIPHER=y

# Required: block layer
CONFIG_BLOCK=y
CONFIG_BLK_DEV_LOOP=y
CONFIG_BLK_DEV_ZRAM=m

# Do NOT enable in-tree ZFS — we build OpenZFS separately
# CONFIG_ZFS is not set

# Required for zvol and device-mapper integration
CONFIG_BLK_DEV_DM=y
CONFIG_DM_SNAPSHOT=y
CONFIG_DM_CRYPT=m

# Unicode support for ZFS datasets
CONFIG_UNICODE=y
```

#### 1.3.2 KVM (Virtualization Host Support)

```kconfig
CONFIG_VIRTUALIZATION=y
CONFIG_KVM=m
CONFIG_KVM_INTEL=m
CONFIG_KVM_AMD=m

# vhost for accelerated guest I/O
CONFIG_VHOST=m
CONFIG_VHOST_NET=m
CONFIG_VHOST_SCSI=m
CONFIG_VHOST_VSOCK=m

# IOMMU for device passthrough
CONFIG_IOMMU_SUPPORT=y
CONFIG_INTEL_IOMMU=y
CONFIG_AMD_IOMMU=y
CONFIG_VFIO=m
CONFIG_VFIO_PCI=m
CONFIG_VFIO_IOMMU_TYPE1=m

# Huge pages for VM memory
CONFIG_HUGETLBFS=y
CONFIG_HUGETLB_PAGE=y
CONFIG_TRANSPARENT_HUGEPAGE=y
```

#### 1.3.3 eBPF (Observability, Networking, Security)

```kconfig
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_BPF_JIT_ALWAYS_ON=y
CONFIG_BPF_UNPRIV_DEFAULT_OFF=y

# BPF LSM for security policies
CONFIG_BPF_LSM=y

# BTF for CO-RE (Compile Once, Run Everywhere)
CONFIG_DEBUG_INFO_BTF=y
CONFIG_DEBUG_INFO_BTF_MODULES=y

# BPF-based networking
CONFIG_BPF_STREAM_PARSER=y
CONFIG_LWTUNNEL_BPF=y
CONFIG_NET_ACT_BPF=m
CONFIG_NET_CLS_BPF=m

# cgroup BPF hooks
CONFIG_CGROUP_BPF=y

# Kprobes/uprobes for tracing
CONFIG_KPROBES=y
CONFIG_KPROBE_EVENTS=y
CONFIG_UPROBE_EVENTS=y
CONFIG_FTRACE=y
CONFIG_FUNCTION_TRACER=y
CONFIG_DYNAMIC_FTRACE=y
CONFIG_FPROBE=y
```

#### 1.3.4 Namespaces (Containers / Kubernetes)

```kconfig
CONFIG_NAMESPACES=y
CONFIG_UTS_NS=y
CONFIG_IPC_NS=y
CONFIG_USER_NS=y
CONFIG_PID_NS=y
CONFIG_NET_NS=y
CONFIG_CGROUP_NS=y   # cgroup namespace (added 4.6+)
CONFIG_TIME_NS=y     # time namespace (added 5.6+)

# Unprivileged user namespaces — needed for rootless containers
CONFIG_USER_NS=y
```

#### 1.3.5 OverlayFS

```kconfig
CONFIG_OVERLAY_FS=y

# Needed for container runtimes (metacopy, redirect_dir)
CONFIG_OVERLAY_FS_REDIRECT_DIR=y
CONFIG_OVERLAY_FS_METACOPY=y
CONFIG_OVERLAY_FS_INDEX=y
CONFIG_OVERLAY_FS_NFS_EXPORT=y
CONFIG_OVERLAY_FS_XINO_AUTO=y
```

#### 1.3.6 Cgroups v2

```kconfig
CONFIG_CGROUPS=y
CONFIG_CGROUP_V2=y

# Individual controllers
CONFIG_MEMCG=y
CONFIG_CGROUP_SCHED=y
CONFIG_CGROUP_PIDS=y
CONFIG_CGROUP_RDMA=y
CONFIG_CGROUP_FREEZER=y
CONFIG_CGROUP_HUGETLB=y
CONFIG_CGROUP_DEVICE=y
CONFIG_CGROUP_CPUACCT=y
CONFIG_CGROUP_PERF=y
CONFIG_CGROUP_BPF=y
CONFIG_CGROUP_MISC=y

# PSI (Pressure Stall Information) — useful for systemd-oomd
CONFIG_PSI=y
CONFIG_PSI_DEFAULT_DISABLED=n

# io controller
CONFIG_BLK_CGROUP=y
CONFIG_BLK_CGROUP_IOLATENCY=y
CONFIG_BLK_CGROUP_IOCOST=y
CONFIG_BLK_CGROUP_IOPRIO=y
```

Boot parameter to enforce cgroup v2 unified hierarchy:

```
systemd.unified_cgroup_hierarchy=1
```

#### 1.3.7 Security Modules

```kconfig
CONFIG_SECURITY=y
CONFIG_SECURITYFS=y
CONFIG_SECURITY_NETWORK=y

# SELinux — mandatory access control with label-based policy
CONFIG_SECURITY_SELINUX=y
CONFIG_DEFAULT_SECURITY_SELINUX=y
CONFIG_SECURITY_SELINUX_BOOTPARAM=y
CONFIG_SECURITY_SELINUX_DEVELOP=y
CONFIG_SECURITY_SELINUX_AVC_STATS=y
CONFIG_SECURITY_SELINUX_CHECKREQPROT_VALUE=0
CONFIG_AUDIT=y                  # Required by SELinux for access logging
CONFIG_AUDITSYSCALL=y
CONFIG_AUDIT_ARCH=y
CONFIG_NET_KEY=y                # Required for SELinux labeled networking

# Additional LSMs:
CONFIG_SECURITY_YAMA=y          # ptrace restrictions
CONFIG_SECCOMP=y                # syscall filtering
CONFIG_SECCOMP_FILTER=y
CONFIG_SECURITY_LANDLOCK=y      # unprivileged sandboxing

# IMA/EVM for integrity measurement (optional, for measured boot)
CONFIG_IMA=y
CONFIG_EVM=y

# Lockdown mode (optional, restricts even root from modifying kernel)
CONFIG_SECURITY_LOCKDOWN_LSM=y
CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY=y

# Stack protector
CONFIG_STACKPROTECTOR=y
CONFIG_STACKPROTECTOR_STRONG=y
```

**LSM boot parameter:**

```
security=selinux selinux=1
```

**SELinux Policy Notes:**

- **Policy type:** Targeted policy (confines specific daemons while leaving
  unconfined domains for general use). MLS (Multi-Level Security) can be layered
  on top if required for compliance (e.g., government / defense workloads).
- **Immutable root + OverlayFS /etc labeling:** The read-only ext4 root
  filesystem (golden image) must be fully labeled at image build time using
  `setfiles` / `restorecon`. The OverlayFS upper layer for `/etc` inherits
  labels from the lower layer by default; new files created in the upper
  layer receive labels from the parent directory's context or via SELinux
  transition rules. Relabeling of the upper layer should be performed on
  first boot via Ignition or a one-shot systemd unit. ZFS mutable datasets
  (`/var`, `/var/lib`, `/var/log`) must also carry correct file contexts;
  these are labeled during first-boot provisioning by Ignition.
- **Container / Kubernetes SELinux contexts:** Container runtimes (CRI-O,
  containerd) assign SELinux contexts to container processes
  (`container_t`, `container_file_t`). The targeted policy must include
  the `container-selinux` policy module. Kubernetes uses SELinux contexts
  in SecurityContext / PodSecurityPolicy to enforce per-pod MAC.
- **SELinux userspace tools:** The image must include `policycoreutils`
  (sestatus, semanage, restorecon, audit2allow), `selinux-policy-targeted`,
  and `libselinux-utils` (getenforce, setenforce).
- **OverlayFS xattr support:** SELinux labels are stored as `security.selinux`
  xattrs. OverlayFS supports reading xattrs from the lower layer and writing
  them in the upper layer, which is compatible with our /etc overlay design.

### 1.4 Defining the Kernel as a Guix Package

Guix normally uses its own kernel package definition (based on `make-linux-libre`).
We need to define a custom package that:
- Fetches the upstream kernel.org tarball (not linux-libre)
- Applies our config fragment merge
- Includes non-libre firmware support (CONFIG_FW_LOADER)

```scheme
(define-module (andyl packages kernel)
  #:use-module (guix packages)
  #:use-module (guix download)
  #:use-module (guix build-system gnu)
  #:use-module (guix gexp)
  #:use-module (gnu packages linux))

(define %kernel-version "6.12.10")
(define %kernel-hash
  (base32 "0000000000000000000000000000000000000000000000000000"))

(define %andyl-kernel-config
  ;; Our config fragments, merged at build time
  (local-file "../kernel/merged.config"))

(define-public andyl-kernel
  (package
    (name "andyl-kernel")
    (version %kernel-version)
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://cdn.kernel.org/pub/linux/kernel/v6.x/"
             "linux-" version ".tar.xz"))
       (sha256 %kernel-hash)))
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
                ;; Install headers for out-of-tree module builds (ZFS)
                (invoke "make"
                        (string-append "INSTALL_HDR_PATH=" out "/usr")
                        "headers_install")))))))
    (native-inputs
     (list perl flex bison elfutils bc openssl kmod))
    (home-page "https://kernel.org")
    (synopsis "ANDYL OS custom Linux kernel")
    (description "Upstream Linux kernel built with ANDYL OS config fragments.")
    (license license:gpl2)))
```

**Key considerations:**

- We use `url-fetch` to the kernel.org CDN, NOT `linux-libre` sources. This is
  critical because linux-libre strips firmware loading support and proprietary
  driver stubs we need.
- We must install kernel headers so OpenZFS can build against them.
- The `build` directory (with Module.symvers, full source) should be preserved
  for out-of-tree module builds. Consider a separate `-headers` output.

### 1.5 Kernel Module Handling in Immutable OS Context

In an immutable root filesystem, we cannot use traditional `dkms` (which writes
to `/lib/modules/` at runtime). Instead:

**Strategy: Pre-build all modules at image build time.**

- All in-tree modules are built and installed during the kernel package build.
- Out-of-tree modules (OpenZFS) are built as separate Guix packages that depend
  on the kernel package and install into the same `/lib/modules/<version>/`
  directory in the Guix store.
- At image assembly time, we union-merge the kernel modules directory with ZFS
  modules, creating a single read-only `/lib/modules/<version>/`.
- `depmod` runs at build time to generate `modules.dep` and friends.
- No runtime module compilation is ever needed.

```
Image build pipeline:

  andyl-kernel ─────────┐
                        ├──> merge /lib/modules/<ver>/ ──> depmod ──> image
  andyl-zfs-modules ────┘
```

---

## 2. Driver Management

### 2.1 VM Environment (KVM/QEMU)

These are the essential virtio drivers for running ANDYL OS as a guest:

```kconfig
# Virtio core
CONFIG_VIRTIO=y
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_PCI_MODERN=y
CONFIG_VIRTIO_MMIO=y

# Virtio block
CONFIG_VIRTIO_BLK=y

# Virtio SCSI
CONFIG_SCSI_VIRTIO=y

# Virtio network
CONFIG_VIRTIO_NET=y

# Virtio console
CONFIG_VIRTIO_CONSOLE=y

# Virtio balloon (memory management)
CONFIG_VIRTIO_BALLOON=y

# Virtio RNG
CONFIG_HW_RANDOM_VIRTIO=y

# Virtio filesystem (for host-guest sharing)
CONFIG_VIRTIO_FS=m

# Virtio GPU (for console, not 3D)
CONFIG_DRM_VIRTIO_GPU=m

# Virtio input
CONFIG_VIRTIO_INPUT=y

# Virtio vsock (host-guest communication)
CONFIG_VIRTIO_VSOCK=m
CONFIG_VHOST_VSOCK=m

# QEMU guest agent support
CONFIG_VIRTIO_TRANSPORT_COMMON=y
```

**Build as built-in (`=y`) for boot-critical drivers** (virtio-blk, virtio-net,
virtio-pci) so they are available in initrd without module loading. Build
non-boot-critical drivers (virtio-gpu, virtio-fs) as modules.

### 2.2 Cloud Environment Drivers

#### AWS (EC2)

```kconfig
# ENA (Elastic Network Adapter) — required for most instance types
CONFIG_ENA_ETHERNET=m

# NVMe — required for EBS and instance store
CONFIG_BLK_DEV_NVME=y
CONFIG_NVME_CORE=y

# Xen — needed for older instance types (not needed for Nitro)
CONFIG_XEN=y
CONFIG_XEN_PV=y
CONFIG_XEN_PVHVM=y
CONFIG_XEN_BLKDEV_FRONTEND=m
CONFIG_XEN_NETDEV_FRONTEND=m

# EFA (Elastic Fabric Adapter) — for HPC workloads
CONFIG_EFA=m

# Serial console (required for EC2 serial console feature)
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_CONSOLE=y
```

#### GCP (Compute Engine)

```kconfig
# GCP uses virtio for most I/O — covered by virtio section above

# gVNIC (Google Virtual NIC) — high-performance networking
CONFIG_GVE=m

# Google guest environment support
CONFIG_ACPI=y
CONFIG_ACPI_BUTTON=y
```

#### Azure

```kconfig
# Hyper-V core
CONFIG_HYPERV=y
CONFIG_HYPERV_UTILS=y

# Hyper-V VMBus
CONFIG_HYPERV_VMBUS=y

# Hyper-V network
CONFIG_HYPERV_NET=y

# Hyper-V storage
CONFIG_HYPERV_STORAGE=y

# Hyper-V keyboard (for console)
CONFIG_HYPERV_KEYBOARD=m

# Hyper-V balloon
CONFIG_HYPERV_BALLOON=m

# Hyper-V framebuffer
CONFIG_DRM_HYPERV=m
```

### 2.3 Bare Metal Server Drivers

```kconfig
# Intel NICs
CONFIG_E1000E=m          # 1GbE (common in older servers)
CONFIG_IGB=m             # 1GbE (server-grade)
CONFIG_IXGBE=m           # 10GbE
CONFIG_I40E=m            # 10/25/40GbE
CONFIG_ICE=m             # 25/50/100GbE (Intel E800 series)

# Mellanox/NVIDIA NICs
CONFIG_MLX4_CORE=m       # ConnectX-3
CONFIG_MLX4_EN=m
CONFIG_MLX5_CORE=m       # ConnectX-4/5/6/7
CONFIG_MLX5_CORE_EN=m
CONFIG_MLX5_EN_IPSEC=y

# Broadcom NICs
CONFIG_BNXT=m            # NetXtreme-E/C (common in HPE/Dell)
CONFIG_BNX2X=m           # Older NetXtreme II

# Storage controllers
CONFIG_MEGARAID_SAS=m        # LSI/Broadcom MegaRAID
CONFIG_MPTBASE=m             # LSI Fusion MPT
CONFIG_SCSI_MPT3SAS=m        # LSI SAS3 controllers
CONFIG_SCSI_SMARTPQI=m       # Microsemi SmartPQI (HPE)
CONFIG_SCSI_HPSA=m           # HP Smart Array (legacy)
CONFIG_ATA_PIIX=m            # Common SATA controller
CONFIG_AHCI=y                # AHCI SATA (built-in for boot)

# NVMe (common in modern servers)
CONFIG_BLK_DEV_NVME=y
CONFIG_NVME_CORE=y
CONFIG_NVME_MULTIPATH=y
CONFIG_NVME_HWMON=y

# IPMI (server management)
CONFIG_IPMI_HANDLER=m
CONFIG_IPMI_DEVICE_INTERFACE=m
CONFIG_IPMI_SI=m
CONFIG_IPMI_SSIF=m
```

### 2.4 Strategy: Universal Image vs. Per-Environment Images

**Two viable approaches:**

| Approach | Pros | Cons |
|----------|------|------|
| Universal image (all drivers as modules) | Single image to build/test/deploy; simpler CI | Larger initrd if many drivers loaded; more firmware needed; slightly larger attack surface |
| Per-environment images | Minimal attack surface; smaller images; less firmware | N images to build and test; more complex CI; environment detection needed |

**Recommendation: Start with a universal image, then split if needed.**

Rationale:
- Driver modules loaded but unused consume negligible memory.
- Build complexity of N images is significant early on.
- We can still strip firmware per-role (see Section 3).
- Boot-critical drivers (NVMe, virtio-blk, AHCI) are built-in. All others are
  modules — loaded on demand via udev/systemd.

If image size or security hardening becomes critical, we can introduce image
flavors later:
- `andyl-os-vm.img` (virtio only)
- `andyl-os-aws.img` (ENA + NVMe)
- `andyl-os-baremetal.img` (all server drivers)

### 2.5 Built-in vs. Module Decision Framework

```
Boot-critical → must be =y (built into kernel)
  - Root disk driver (NVMe, virtio-blk, AHCI)
  - Root filesystem (ext4 for immutable root; ZFS loaded post-boot for mutable data)
  - Console (serial 8250 for cloud)

Available at boot but not root-critical → =y or in initrd
  - Network drivers for PXE/netboot scenarios
  - DM/LVM if used for root

Everything else → =m (module)
  - Cloud-specific drivers
  - Bare metal NIC drivers
  - RAID controllers
  - Virtualization (KVM, VFIO)
  - Non-boot filesystems
```

---

## 3. Firmware Stripping

### 3.1 The Problem

The upstream `linux-firmware` repository is enormous:

```
$ du -sh linux-firmware/
862M    linux-firmware/
```

Most of this is GPU firmware (amdgpu, i915), WiFi drivers (iwlwifi, ath11k),
and Bluetooth firmware — none of which are needed on a headless server.

### 3.2 Identifying Required Firmware

Required firmware blobs, by driver:

| Driver | Firmware path | Approx size |
|--------|--------------|-------------|
| Intel ice (100GbE) | `intel/ice/` | ~5 MB |
| Intel i40e (40GbE) | (no firmware needed) | 0 |
| Intel ixgbe (10GbE) | (no firmware needed) | 0 |
| Mellanox mlx5 | `mellanox/` | ~3 MB |
| Broadcom bnxt | `bnxt/` | ~1 MB |
| Broadcom bnx2x | `bnx2x/` | ~2 MB |
| QLogic/Marvell | `qed/` | ~3 MB |
| AWS ENA | (no firmware needed) | 0 |
| Hyper-V | (no firmware needed) | 0 |
| CPU microcode (Intel) | `intel-ucode/` | ~5 MB |
| CPU microcode (AMD) | `amd-ucode/` | ~1 MB |

**Estimated stripped firmware: ~20 MB** (vs. 862 MB original)

### 3.3 Build-Time Firmware Selection

We define a Guix package that installs only the firmware we need:

```scheme
(define-public andyl-firmware
  (package
    (name "andyl-firmware")
    (version "20250110")
    (source
     (origin
       (method git-fetch)
       (uri (git-reference
             (url "https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git")
             (commit version)))
       (sha256 (base32 "..."))))
    (build-system copy-build-system)
    (arguments
     (list
      #:install-plan
      #~'(;; CPU microcode
          ("intel-ucode" "lib/firmware/intel-ucode")
          ("amd-ucode" "lib/firmware/amd-ucode")
          ;; NIC firmware
          ("intel/ice" "lib/firmware/intel/ice")
          ("mellanox" "lib/firmware/mellanox")
          ("bnxt" "lib/firmware/bnxt")
          ("bnx2x" "lib/firmware/bnx2x")
          ;; QLogic
          ("qed" "lib/firmware/qed"))))
    (synopsis "Stripped firmware for ANDYL OS server hardware")
    (description "Minimal firmware blobs for server NICs and CPU microcode.")
    (license license:nonfree)))  ;; firmware is non-free
```

### 3.4 Per-Role Firmware Sets

If we adopt per-environment images:

```scheme
(define %firmware-vm
  ;; VMs need no firmware at all (virtio is firmware-free)
  '())

(define %firmware-cloud
  '("intel-ucode" "amd-ucode"))  ;; Just CPU microcode

(define %firmware-baremetal
  '("intel-ucode" "amd-ucode"
    "intel/ice" "mellanox" "bnxt" "bnx2x" "qed"))
```

### 3.5 Firmware Loading: initrd vs. Root Filesystem

Firmware needed during early boot must be in the initrd:

| Firmware | When needed | Location |
|----------|-------------|----------|
| CPU microcode | Very early boot (before initrd in some cases) | Bundled as early initrd cpio |
| Root disk driver firmware | initrd (to mount root) | In initrd |
| NIC firmware | After root mount (unless netboot) | Root filesystem |
| All other firmware | After root mount | Root filesystem |

**CPU microcode** is special: it should be loaded as an **early initrd** (a
separate uncompressed cpio archive prepended to the main initrd). systemd-boot
supports this natively when using Unified Kernel Images (UKIs) or via the
`initrd` key in boot loader entries.

```
# Boot entry structure with early microcode
/boot/loader/entries/andyl-os.conf:
  title    ANDYL OS
  linux    /vmlinuz-6.12.10
  initrd   /intel-ucode.img    # early microcode (prepended)
  initrd   /initramfs-6.12.10.img
  options  root=/dev/disk/by-label/ANDYL-ROOT ro ...
```

Or with UKI (preferred, see Section 4), microcode is embedded in the UKI itself.

---

## 4. systemd as Init System

ANDYL OS uses systemd instead of Guix's default Shepherd init system. This is a
significant departure from standard Guix System but gives us access to the full
systemd ecosystem.

### 4.1 systemd as PID 1 (Replacing Shepherd)

Guix System normally generates a Shepherd configuration from `operating-system`
declarations. We bypass this entirely:

- Our system image includes systemd and its unit files, NOT Shepherd.
- The kernel `init=` parameter points to `/usr/lib/systemd/systemd` (or we
  symlink `/sbin/init` to it).
- We package all systemd units as Guix packages installed into the system
  profile.

**Implication:** We cannot use Guix's `(service ...)` abstractions directly
for service management. Instead, we define our own service layer that generates
systemd unit files and installs them as Guix packages. (This is a significant
engineering effort but gives us full systemd compatibility.)

```scheme
;; Conceptual: Define a systemd service as a Guix package
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
    (synopsis "ANDYL OS base systemd units")
    (description "Core systemd unit files for ANDYL OS.")
    (license license:asl2.0)))
```

### 4.2 systemd in initrd (systemd-based initramfs)

We use a **systemd-based initrd** (as opposed to busybox-based). This gives us:
- Consistent logging (journald available in initrd)
- Device management via systemd-udevd
- ZFS root mount via a custom generator
- Cleaner handoff from initrd to real root

#### 4.2.1 Initrd Generator Approach

**Options:**

| Approach | Pros | Cons |
|----------|------|------|
| dracut | Mature, widely used, good ZFS support | Complex, many dependencies, designed for mutable systems |
| mkinitcpio | Simpler than dracut, Arch-style | Less systemd-native |
| ukify / custom build | Full control, minimal | More engineering work |
| Manual CPIO assembly | Maximum control | Significant effort |

**Recommendation: dracut** (packaged as a Guix build tool)

dracut has first-class support for:
- systemd in initrd (`--add systemd`)
- systemd-boot integration
- UKI generation (`--uefi`)

We run dracut at **image build time** (not at runtime on the target machine),
since the target has an immutable root.

```bash
dracut \
  --force \
  --kver 6.12.10 \
  --add "systemd" \
  --fstab \
  --no-hostonly \
  --no-early-microcode \       # We prepend microcode separately
  /boot/initramfs-6.12.10.img
```

`--no-hostonly` is critical: we are building a generic initrd, not one tailored
to the build host.

Note: ZFS is NOT needed in the initrd because the root filesystem is ext4.
The ZFS kernel module is loaded after boot by systemd to mount the mutable
data pool (`/var`, `/var/lib`, `/var/log`). See Section 5 for details.

#### 4.2.2 ext4 Root Mount from initrd

The initrd mounts the immutable ext4 root filesystem. The kernel command line
specifies the root device:

```
root=/dev/disk/by-label/ANDYL-ROOT ro
```

The `ro` flag ensures the root filesystem is mounted read-only from the start.
For systemd-based initrd, this translates to a standard root mount unit.

### 4.3 systemd-boot as Bootloader

systemd-boot (formerly gummiboot) is a simple UEFI boot manager. It lives on
the EFI System Partition (ESP) and reads boot entries from
`/loader/entries/*.conf`.

#### 4.3.1 Boot Loader Entry Types

**Type #1 entries** (individual files in `/loader/entries/`):

```ini
# /boot/loader/entries/andyl-os-gen-42.conf
title      ANDYL OS (gen 42)
version    42
linux      /andyl-os/42/vmlinuz
initrd     /andyl-os/42/intel-ucode.img
initrd     /andyl-os/42/initramfs.img
options    root=/dev/disk/by-label/ANDYL-ROOT ro quiet
```

**Type #2 entries** (Unified Kernel Images, UKIs):

A UKI bundles kernel + initrd + cmdline + os-release + optional splash into a
single PE/COFF binary that systemd-boot can directly boot:

```
/boot/EFI/Linux/andyl-os-gen-42.efi
```

#### 4.3.2 Unified Kernel Image (UKI) Approach

**Recommendation: Use UKIs.**

UKIs simplify boot management and enable Secure Boot signing of the entire
boot chain as a single artifact.

Building a UKI with `ukify` (part of systemd):

```bash
/usr/lib/systemd/ukify build \
  --linux=vmlinuz-6.12.10 \
  --initrd=intel-ucode.img \
  --initrd=initramfs-6.12.10.img \
  --cmdline="root=/dev/disk/by-label/ANDYL-ROOT ro quiet" \
  --os-release=@os-release \
  --output=andyl-os-gen-42.efi
```

The resulting `.efi` file is placed on the ESP:

```
/boot/EFI/Linux/andyl-os_42+3-0.efi
```

The filename encodes the generation and boot count (see below).

#### 4.3.3 Boot Counting for Automatic Rollback

systemd-boot's boot counting protocol enables automatic rollback if a new
generation fails to boot:

Filename format: `andyl-os_<sort-key>+<tries-left>-<tries-done>.efi`

Example boot flow:
```
1. Deploy gen-42 (new ext4 golden image written to root partition):
   andyl-os_42+3-0.efi (3 tries left, 0 done)

2. First boot attempt: andyl-os_42+2-1.efi
   (renamed by boot loader: 2 left, 1 done)

3. If boot succeeds, systemd marks it good:
   andyl-os_42.efi (no count = known good)

4. If all 3 attempts fail:
   andyl-os_42+0-3.efi (0 left, 3 done)
   systemd-boot falls back to previous entry
```

The `systemd-bless-boot.service` unit marks a boot as successful:

```ini
# Runs after successful boot, removes the +N-M suffix
[Unit]
Description=Mark Boot as Successful
ConditionPathExists=/boot/loader/entries/
After=multi-user.target

[Service]
Type=oneshot
ExecStart=/usr/lib/systemd/systemd-bless-boot good

[Install]
WantedBy=multi-user.target
```

### 4.4 Key systemd Components

| Component | Purpose | Notes |
|-----------|---------|-------|
| **journald** | Structured logging | Binary logs in `/var/log/journal/`; forward to remote syslog or Loki |
| **networkd** | Network management | Simpler than NetworkManager; good for servers with predictable interfaces |
| **resolved** | DNS resolution | Supports DNSSEC, DNS-over-TLS; manages `/etc/resolv.conf` |
| **timesyncd** | NTP client | Lightweight; for servers consider chrony instead for higher accuracy |
| **tmpfiles.d** | Volatile file management | Critical for immutable OS: creates/cleans dirs on boot |
| **sysusers.d** | System user management | Creates system users/groups on boot from declarative config |
| **systemd-cryptsetup** | LUKS volumes | If encrypted root/data is needed |
| **systemd-repart** | Partition management | Can grow/create partitions on first boot; useful for data partitions |
| **systemd-sysext** | System extensions | Overlays on `/usr`; potentially useful for role-specific extensions |
| **systemd-oomd** | OOM killer | Uses PSI; better than kernel OOM killer for containers |
| **systemd-homed** | Home directory management | Probably not needed for servers |
| **systemd-machined** | Container/VM management | Useful if we run systemd-nspawn containers |

#### 4.4.1 networkd Configuration Example

```ini
# /etc/systemd/network/10-ethernet.network
[Match]
Type=ether
Name=en* eth*

[Network]
DHCP=yes
IPv6AcceptRA=yes

[DHCPv4]
UseDNS=yes
UseNTP=yes
UseHostname=yes
```

#### 4.4.2 tmpfiles.d for Volatile State

Critical for immutable root — tmpfiles.d creates necessary directories and files
on every boot:

```ini
# /usr/lib/tmpfiles.d/andyl-os.conf

# Ensure /var structure exists
d /var/log 0755 root root -
d /var/lib 0755 root root -
d /var/cache 0755 root root -
d /var/tmp 1777 root root 30d
d /var/spool 0755 root root -

# Runtime directories
d /run/andyl 0755 root root -

# Create machine-id if not present
C /etc/machine-id - - - - /usr/share/factory/etc/machine-id
```

#### 4.4.3 sysusers.d for System Users

```ini
# /usr/lib/sysusers.d/andyl-os.conf

# Core system users
u root 0 "Super User" /root /bin/bash
u nobody 65534 "Nobody" / /sbin/nologin
g wheel 10
g systemd-journal 190

# Service users
u systemd-network 192 "systemd Network Management" / /sbin/nologin
u systemd-resolve 193 "systemd Resolver" / /sbin/nologin
u systemd-timesync 194 "systemd Time Sync" / /sbin/nologin
```

### 4.5 systemd-sysext (System Extensions)

`systemd-sysext` overlays extension images onto `/usr` (and optionally `/opt`).
This is potentially powerful for our model:

```
Base image (immutable):
  /usr/lib/systemd/system/base-*.service
  /usr/bin/core-tools

Extension "k8s" (overlaid):
  /usr/lib/systemd/system/kubelet.service
  /usr/bin/kubelet
  /usr/bin/kubectl

Extension "monitoring" (overlaid):
  /usr/lib/systemd/system/node-exporter.service
  /usr/bin/node_exporter
```

Extensions are stored as disk images (squashfs, erofs, or raw) in
`/var/lib/extensions/` and activated via:

```bash
systemd-sysext merge
```

**This complements our generational model**: the base image is one generation,
and role-specific extensions are layered on top. The base image can be updated
independently of extensions.

### 4.6 Packaging systemd Units in Guix

Since we cannot use Guix's native service abstraction (which targets Shepherd),
we create a parallel mechanism:

```scheme
;; A macro for defining systemd service packages
(define-syntax define-systemd-service
  (syntax-rules ()
    ((_ name unit-files ...)
     (package
       (name name)
       (version "1.0")
       (source #f)
       (build-system trivial-build-system)
       (arguments
        (list
         #:builder
         #~(begin
             (let ((unitdir (string-append #$output "/lib/systemd/system")))
               (mkdir-p unitdir)
               ;; Install each unit file
               ...))))
       (synopsis (string-append name " systemd units"))
       (description "")
       (license license:asl2.0)))))
```

The system profile then collects all service packages and their unit files
are visible under `/gnu/store/...-profile/lib/systemd/system/`. We symlink
or bind-mount this into `/usr/lib/systemd/system/` on the running system.

---

## 5. ZFS Support (Mutable Data Only)

The root filesystem is an immutable ext4 golden image (see Section 6). ZFS is
used exclusively for **mutable data** (`/var`, `/var/lib`, `/var/log`, etc.).
The ZFS pool is not part of the golden image; it is created by Ignition on
first boot, allowing hardware-specific pool configuration (device paths,
mirror/stripe layout, SLOG/L2ARC if available).

### 5.1 OpenZFS Version Compatibility

| OpenZFS Version | Kernel Support | Status |
|----------------|----------------|--------|
| 2.2.x          | Up to 6.11     | Stable |
| 2.3.x          | Up to 6.12+    | Current |

**We need OpenZFS 2.3.x** to match our 6.12 LTS kernel.

If we choose 6.6 LTS, OpenZFS 2.2.x is sufficient.

### 5.2 Building OpenZFS as a Guix Package

OpenZFS builds against the kernel headers and produces kernel modules + userspace
tools. Both are included in the immutable golden image so they are available at
boot, but no ZFS pool exists until Ignition provisions one on first boot.

```scheme
(define-public andyl-zfs
  (package
    (name "andyl-zfs")
    (version "2.3.0")
    (source
     (origin
       (method url-fetch)
       (uri (string-append
             "https://github.com/openzfs/zfs/releases/download/zfs-"
             version "/zfs-" version ".tar.gz"))
       (sha256 (base32 "..."))))
    (build-system gnu-build-system)
    (arguments
     (list
      #:configure-flags
      #~(list
         (string-append "--with-linux=" #$andyl-kernel "/lib/modules/build")
         (string-append "--with-linux-obj=" #$andyl-kernel "/lib/modules/build")
         "--with-config=kernel"   ;; Build kernel modules only
         )))
    (inputs (list andyl-kernel))
    (native-inputs (list which pkg-config))
    (synopsis "OpenZFS kernel modules for ANDYL OS")
    (description "ZFS kernel modules built against the ANDYL OS kernel.")
    (license license:cddl1.0)))

(define-public andyl-zfs-tools
  (package
    (inherit andyl-zfs)
    (name "andyl-zfs-tools")
    (arguments
     (list
      #:configure-flags
      #~(list "--with-config=user")))   ;; Userspace tools only
    (synopsis "OpenZFS userspace tools")
    (description "zpool, zfs, and related userspace utilities.")
    (license license:cddl1.0)))
```

We split kernel modules and userspace tools into separate packages because:
- Kernel modules go into the immutable image alongside the kernel.
- Userspace tools go into the system profile.

### 5.3 ZFS for Mutable Data (Not Root)

The root filesystem is ext4 (immutable golden image, see Section 6). ZFS is
used for all mutable, persistent data. The ZFS pool is created by Ignition on
first boot, not at image build time.

#### 5.3.1 Pool Layout

```
datapool                        # Data pool (dedicated partition or disk)
  datapool/var                  # /var (base writable area)
  datapool/var-lib              # /var/lib (container data, DBs, kubelet)
  datapool/var-log              # /var/log (persistent logs, journal)
  datapool/RESERVED             # Reserved space (keep pool < 80% full)
```

#### 5.3.2 First-Boot Pool Creation via Ignition

Ignition creates the ZFS pool and datasets on first boot. This allows the
pool configuration to adapt to the target hardware (device paths, mirror vs.
stripe, optional SLOG/L2ARC devices):

```json
{
  "ignition": { "version": "3.4.0" },
  "systemd": {
    "units": [
      {
        "name": "zfs-pool-create.service",
        "enabled": true,
        "contents": "[Unit]\nDescription=Create ZFS data pool\nConditionPathExists=!/var/.zfs-pool-created\nBefore=var.mount var-lib.mount var-log.mount\n\n[Service]\nType=oneshot\nExecStart=/usr/bin/zpool create -o ashift=12 -O compression=zstd -O atime=off -O xattr=sa -O acltype=posixacl datapool /dev/disk/by-id/DATA_DISK\nExecStart=/usr/bin/zfs create -o mountpoint=/var datapool/var\nExecStart=/usr/bin/zfs create -o mountpoint=/var/lib datapool/var-lib\nExecStart=/usr/bin/zfs create -o mountpoint=/var/log datapool/var-log\nExecStart=/usr/bin/zfs create -o quota=10G -o mountpoint=none datapool/RESERVED\nExecStart=/usr/bin/touch /var/.zfs-pool-created\n\n[Install]\nWantedBy=local-fs.target"
      }
    ]
  }
}
```

The `ConditionPathExists=!/var/.zfs-pool-created` guard ensures the pool is
only created on first boot.

#### 5.3.3 Datasets and Mountpoints

```
Dataset                  Mountpoint   Notes
------------------------------------------------------
(ext4, read-only)        /            Immutable golden image (not ZFS)
datapool/var             /var         Base writable area
datapool/var-lib         /var/lib     Persistent (containers, state)
datapool/var-log         /var/log     Persistent (journal, app logs)
(tmpfs)                  /tmp         Volatile
(tmpfs)                  /run         Volatile
(overlay)                /etc         See Section 6
```

#### 5.3.4 ZFS Mount Ordering with systemd

Since the root filesystem is ext4, ZFS datasets mount after systemd starts
on the real root. systemd units for ZFS mounts must be ordered correctly:

```ini
# /usr/lib/systemd/system/var.mount
[Unit]
Description=ZFS mount for /var
Requires=zfs-import.target
After=zfs-import.target

[Mount]
What=datapool/var
Where=/var
Type=zfs

[Install]
WantedBy=local-fs.target
```

The `zfs-import-cache.service` and `zfs-mount.service` (provided by OpenZFS's
systemd integration) handle pool import and dataset mounting automatically.

### 5.4 ZFS Features for Our Use Case

#### 5.4.1 Snapshots for Data Protection

ZFS snapshots protect mutable data (not the immutable root, which is managed
via ext4 golden image versioning):

```bash
# Snapshot persistent data before an upgrade
zfs snapshot -r datapool@pre-upgrade-42

# Rollback if the upgrade corrupts data
zfs rollback -r datapool@pre-upgrade-42
```

#### 5.4.2 Compression

```bash
# zstd gives best ratio for general data; lz4 for highest throughput
zfs set compression=zstd datapool

# Compression ratios on typical server data:
# zstd:   ~2.5x compression
# lz4:    ~1.8x compression (but faster)
# off:    1x (no compression)
```

#### 5.4.3 Checksumming

ZFS checksums every block by default (fletcher4 or sha256). This provides
end-to-end data integrity, which is critical for server workloads.

```bash
# Use sha256 for high-security datasets
zfs set checksum=sha256 datapool/var-lib
```

### 5.5 Relationship Between ext4 Root and ZFS Data

```
ext4 root (immutable golden image):
  /gnu/store/    Immutable content-addressed store (Guix manages packages)
  /usr/          System binaries and libraries (read-only)
  /etc/          Base config (lower layer of OverlayFS)

ZFS data pool (mutable, created by Ignition on first boot):
  /var/          All mutable persistent state
  /var/lib/      Container data, databases, kubelet state
  /var/log/      Journal and application logs

Generation model:
  - New OS generations are deployed as new ext4 golden images.
  - The ZFS data pool persists across OS generation upgrades.
  - systemd-boot entry points to the ext4 root partition.
  - Boot counting handles automatic rollback of failed OS upgrades.
  - ZFS snapshots protect mutable data independently of OS generations.
```

---

## 6. Immutable Base Image Architecture

### 6.1 Read-Only Root Filesystem

**Options for immutable root:**

| Approach | Pros | Cons |
|----------|------|------|
| squashfs | Compressed, read-only, simple | No random write, needs overlay for all writes |
| erofs | Newer, better random read perf | Less tooling support |
| dm-verity + ext4 | Integrity verification, standard fs | Requires dm-verity setup, slightly more complex boot |
| ext4 mounted `ro` | Standard fs, wide tooling support, simple boot | Can theoretically be remounted rw by root |
| Bind-mount + `ro` | Simple, works with any fs | Can be remounted rw by root |

**Decision: ext4 golden image mounted read-only**

The root filesystem is an ext4 partition mounted read-only. This provides a
simple, well-understood immutable root with broad tooling support. The golden
image is built offline and written to the root partition as a complete,
pre-labeled filesystem image.

```
root=/dev/disk/by-label/ANDYL-ROOT ro
```

The `ro` kernel parameter ensures the root is mounted read-only from boot.
Even root cannot remount it rw without passing `rw` on the kernel command
line (which is embedded in the signed UKI).

ZFS is used for mutable data (`/var`, `/var/lib`, `/var/log`) and is set up
by Ignition on first boot (see Section 5).

For higher integrity guarantees (e.g., Secure Boot scenarios), dm-verity can
be layered on top of the ext4 root partition.

### 6.2 Required Writable Areas

```
Filesystem layout:

/                           ext4: /dev/disk/by-label/ANDYL-ROOT (read-only golden image)
  /gnu/store/               Part of ext4 root (read-only)
  /usr/                     Part of root (read-only); systemd-sysext can overlay
  /etc/                     OverlayFS (lower=root /etc, upper=persistent or tmpfs)
  /var/                     ZFS: datapool/var (writable, created by Ignition)
    /var/lib/               ZFS: datapool/var-lib (writable, persistent)
    /var/log/               ZFS: datapool/var-log (writable, persistent)
    /var/tmp/               tmpfs or ZFS (volatile)
    /var/cache/             tmpfs or ZFS (volatile)
  /tmp/                     tmpfs
  /run/                     tmpfs
  /home/                    ZFS: datapool/home (writable, if needed)
```

### 6.3 /etc Management

`/etc` is the most complex writable area because systemd, PAM, NSS, and many
tools expect to read and sometimes write to `/etc`.

**Approach: OverlayFS on /etc**

```
                       ┌─────────────┐
                       │  merged /etc │  ← processes see this
                       └──────┬──────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
      ┌───────┴───────┐ ┌────┴────┐  ┌───────┴───────┐
      │ lower (ro)     │ │ upper   │  │ work dir      │
      │ /sysroot/etc   │ │ /var/   │  │ /var/         │
      │ from image     │ │ etc-    │  │ etc-overlay-  │
      │                │ │ overlay │  │ work          │
      └───────────────┘ └─────────┘  └───────────────┘
```

systemd mount unit:

```ini
# /usr/lib/systemd/system/etc.mount
[Unit]
Description=Overlay for /etc
DefaultDependencies=no
Before=local-fs.target
After=var.mount

[Mount]
What=overlay
Where=/etc
Type=overlay
Options=lowerdir=/sysroot/etc,upperdir=/var/etc-overlay,workdir=/var/etc-overlay-work

[Install]
WantedBy=local-fs.target
```

**Alternative: tmpfiles.d + factory reset model**

Instead of overlaying, we can use systemd's `factory reset` approach:
- Ship a complete `/etc` in `/usr/share/factory/etc/`
- Use `tmpfiles.d` with `C` (copy) directives to populate `/etc` on boot
- `/etc` is a tmpfs or writable ZFS dataset on the data pool
- On "factory reset," just clear the `/etc` dataset

```ini
# /usr/lib/tmpfiles.d/etc-factory.conf
C /etc/passwd - - - - /usr/share/factory/etc/passwd
C /etc/group - - - - /usr/share/factory/etc/group
C /etc/shadow 0600 root root - /usr/share/factory/etc/shadow
C /etc/nsswitch.conf - - - - /usr/share/factory/etc/nsswitch.conf
C /etc/pam.d - - - - /usr/share/factory/etc/pam.d
```

**Decision: Use OverlayFS for /etc.**

Rationale: OverlayFS preserves the full base `/etc` from the image while
allowing Ignition and runtime services to make targeted modifications. The
`upperdir` captures only delta changes, making it easy to see what has been
modified from the base image.

### 6.4 /gnu/store as Read-Only

The Guix store (`/gnu/store`) is naturally content-addressed and should be
read-only on the running system. In our model:

- `/gnu/store` is part of the ext4 root filesystem, which is mounted `ro`.
- The Guix daemon is NOT running on the target machine (builds happen on a
  build server; the target is a deployment target).
- No `guix` commands modify the store on the target. All updates come via
  new generations (new ext4 golden images written to the root partition).

If we ever need to run Guix on the target (for development or emergency repairs):
```bash
# Temporarily allow writes (remount root rw)
mount -o remount,rw /
# Do work...
mount -o remount,ro /
```

### 6.5 systemd Interaction with Immutable Root

systemd has first-class support for immutable/read-only root filesystems.

#### 6.5.1 ConditionPathIsReadWrite

Units that require a writable filesystem can be conditioned:

```ini
[Unit]
Description=Service That Writes to Disk
ConditionPathIsReadWrite=/var/lib/myservice

[Service]
ExecStart=/usr/bin/myservice --data-dir=/var/lib/myservice
```

#### 6.5.2 ProtectSystem in Service Units

For services that should NOT be able to modify the system:

```ini
[Service]
ProtectSystem=strict    # /usr and /boot are read-only (already are)
ProtectHome=yes         # /home, /root, /run/user are inaccessible
ReadWritePaths=/var/lib/myservice  # Explicit writable paths
PrivateTmp=yes          # Isolated /tmp
```

#### 6.5.3 systemd Volatile Mode

systemd can boot with a fully volatile `/etc` and `/var`:

```
systemd.volatile=state   # /etc from image (ro), /var is tmpfs
systemd.volatile=yes     # Both /etc and /var are tmpfs
systemd.volatile=overlay # /etc is overlayfs over image /etc
```

`systemd.volatile=overlay` is closest to our desired model. However, we may
prefer explicit mount units for more control.

### 6.6 /var Structure and Persistence

`/var` is the primary writable, persistent area. Its structure:

```
/var/
  lib/                    Persistent application state
    containers/           Container storage (Podman/Docker)
    kubelet/              Kubernetes node state
    systemd/              systemd persistent state
    machines/             systemd-machined
    extensions/           systemd-sysext images
  log/                    Persistent logs
    journal/              systemd journal
  cache/                  Caches (can be tmpfs if desired)
  spool/                  Mail, cron (if needed)
  tmp/                    Persistent temp (30-day cleanup via tmpfiles.d)
```

ZFS datasets for `/var` subtrees (created by Ignition on first boot):

```bash
zfs create -o mountpoint=/var/lib datapool/var-lib
zfs create -o mountpoint=/var/log datapool/var-log
# /var/cache and /var/tmp can be tmpfs or ZFS with no-persist
```

### 6.7 Ignition for First-Boot Configuration

Ignition (from Fedora CoreOS / Flatcar) performs one-shot configuration on
first boot. It writes to the `/etc` overlay and `/var`:

Ignition writes:
- `/etc/hostname`
- `/etc/systemd/network/` (network config)
- SSH authorized keys
- Custom systemd units (enabled via symlinks)
- Users and groups (via `/etc/passwd`, `/etc/shadow`)
- TLS certificates

```json
{
  "ignition": { "version": "3.4.0" },
  "storage": {
    "files": [
      {
        "path": "/etc/hostname",
        "contents": { "inline": "andyl-node-01" },
        "mode": 420
      }
    ]
  },
  "systemd": {
    "units": [
      {
        "name": "custom-app.service",
        "enabled": true,
        "contents": "[Unit]\nDescription=Custom App\n[Service]\nExecStart=/usr/bin/app\n[Install]\nWantedBy=multi-user.target"
      }
    ]
  }
}
```

Ignition runs from the initrd, before systemd in the real root takes over.
This means it can write to `/etc` before the overlay is mounted, seeding the
upper layer.

### 6.8 systemd-sysext for Role-Based Extensions

System extensions are particularly interesting for our model. The base image
contains the OS essentials, and role-specific software is delivered as
extensions:

```
Base image (ext4 golden image):
  - kernel, systemd, coreutils, networking, ZFS kernel module + userspace tools
  - ~500 MB

Extensions:
  k8s.raw          → kubelet, kubectl, cri-o, CNI plugins   (~200 MB)
  monitoring.raw   → prometheus, node_exporter, alertmanager (~100 MB)
  database.raw     → postgresql, pgbouncer                   (~150 MB)
```

Extensions are stored in `/var/lib/extensions/` and activated on boot via:

```ini
# /usr/lib/systemd/system/systemd-sysext.service
# (ships with systemd; just needs to be enabled)
```

Extension images are built as squashfs with `/usr/` structure:

```bash
# Build a sysext image
mkdir -p k8s-ext/usr/bin k8s-ext/usr/lib/systemd/system
cp kubelet kubectl k8s-ext/usr/bin/
cp kubelet.service k8s-ext/usr/lib/systemd/system/

# Must include extension-release file
mkdir -p k8s-ext/usr/lib/extension-release.d
cat > k8s-ext/usr/lib/extension-release.d/extension-release.k8s <<EOF
ID=andyl-os
VERSION_ID=1.0
EOF

mksquashfs k8s-ext k8s.raw -comp zstd
```

### 6.9 Complete Partition Layout

```
Disk layout (GPT):

+-------------------------+
| ESP (512 MB)            |  FAT32, mounted at /boot
| - systemd-boot          |
| - UKIs (*.efi)          |
| - loader.conf           |
+-------------------------+
| ANDYL-ROOT (8-16 GB)    |  ext4, mounted at / (read-only golden image)
| - /gnu/store/           |  Guix store (immutable)
| - /usr/, /etc/ (base)   |  System binaries and base config
+-------------------------+
| ZFS partition            |  Remainder of disk
| - datapool               |  Created by Ignition on first boot
|   - var                  |  /var (writable)
|   - var-lib              |  /var/lib (persistent data)
|   - var-log              |  /var/log (persistent logs)
|   - home                 |  /home (if needed)
+-------------------------+
```

Alternative with swap:

```
+-------------------------+
| ESP (512 MB)            |
+-------------------------+
| ANDYL-ROOT (8-16 GB)    |  ext4, read-only
+-------------------------+
| Swap (2-8 GB)           |  Or use ZRAM for swap
+-------------------------+
| ZFS partition            |
+-------------------------+
```

Note: ZFS supports ZVOL-based swap, but it is not recommended due to deadlock
risks. Use a dedicated swap partition or ZRAM instead.

### 6.10 Boot Flow Summary

```
Power on
  │
  ▼
UEFI firmware
  │
  ▼
systemd-boot (from ESP)
  │  Reads /loader/entries/ or /EFI/Linux/*.efi
  │  Selects entry (boot counting: tries left > 0)
  │
  ▼
Load UKI (kernel + initrd + cmdline)
  │
  ▼
Linux kernel boots
  │  Early: CPU microcode applied
  │  Init: systemd (PID 1 in initrd)
  │
  ▼
systemd in initrd
  │  udevd starts → devices enumerated
  │  ext4 root mounted read-only on /sysroot
  │  Ignition runs (first boot only):
  │    - Creates ZFS data pool if not present
  │    - Writes /etc overlay upper layer config
  │    - Triggers SELinux relabeling of new files
  │
  ▼
switch-root to /sysroot
  │
  ▼
systemd (PID 1 on real root)
  │  ZFS module loaded → datapool imported
  │  Mounts: /var (ZFS datapool), /etc (overlay), /tmp (tmpfs), /run (tmpfs)
  │  tmpfiles.d: creates volatile dirs/files
  │  sysusers.d: ensures system users exist
  │  SELinux: policy loaded, enforcing mode active
  │  networkd: configures networking
  │  resolved: DNS
  │  journald: logging to /var/log/journal/ (on ZFS)
  │  systemd-sysext: merges extensions into /usr
  │
  ▼
multi-user.target
  │  Application services start
  │  systemd-bless-boot marks boot as good
  │
  ▼
System ready
```

---

## Open Questions and Decisions Needed

1. **Kernel series**: 6.6 vs. 6.12 — depends on OpenZFS compatibility testing.
   Recommend 6.12 but need to validate.

2. **SELinux policy scope**: Targeted policy covers the core use case. Evaluate
   MLS policy for compliance-sensitive deployments (government, finance).

3. **Universal vs. per-environment images**: Start universal. When/if to split?

4. **UKI vs. Type #1 boot entries**: UKI is cleaner and supports Secure Boot
   signing. Any reason to prefer Type #1 entries?

5. **/etc strategy**: OverlayFS vs. tmpfiles.d factory reset. OverlayFS
   recommended but adds complexity to the boot chain.

6. **systemd-sysext adoption**: Use from day one for role-based software, or
   start with everything in the base image and split later?

7. **Golden image deployment**: What is the primary mechanism for deploying new
   ext4 golden images? dd-style raw image writes, A/B partition scheme, or
   filesystem-level copy? ZFS send/receive remains relevant for migrating
   mutable data between nodes.

8. **Secure Boot**: Do we sign UKIs? This requires key management infrastructure.
   Important for compliance but adds complexity.

9. **initrd generator**: dracut is recommended, but should we evaluate
   `mkosi-initrd` or a fully custom approach?

10. **Guix service layer**: How much of Guix's service abstraction do we
    replicate for systemd? Full declarative model, or just package unit files
    manually?
