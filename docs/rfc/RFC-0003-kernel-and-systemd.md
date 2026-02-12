# RFC-0003: Kernel Configuration and systemd Integration

- **Status**: Draft
- **Authors**: ANDYL OS Architecture Team
- **Date**: 2026-02-10
- **Supersedes**: None

## Abstract

ANDYL OS uses a custom-built upstream Linux kernel (6.12.x LTS series) with a fragment-based configuration management strategy, defined as a Nix derivation in `pkgs/kernel/linux.nix`. The kernel is configured for server workloads with support for KVM, eBPF, namespaces, cgroups v2, and SELinux mandatory access control. The root filesystem is an immutable ext4 golden image; ZFS is used for mutable data (`/var`, etc.) and is provisioned by Ignition on first boot. systemd (built from `pkgs/init/systemd.nix`) is PID 1, with systemd-boot as the boot loader and dracut for initrd generation. Boot configuration is managed by the `modules/base/boot.nix` module.

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

Config fragments are stored in `pkgs/kernel/config/` organized by subsystem:

```
pkgs/kernel/config/
  base.config              Core options (cgroups, namespaces, security)
  storage.config           ZFS deps, NVMe, virtio-blk, dm-verity
  networking.config        Netfilter, eBPF, virtio-net, cloud NICs
  virtualization.config    KVM, vhost
  security.config          SELinux, IMA, seccomp
  drivers-vm.config        Virtio drivers (built-in for boot)
  drivers-cloud.config     AWS/GCP/Azure specific drivers
  drivers-baremetal.config Server NIC and storage controllers
```

Fragment merge uses `scripts/kconfig/merge_config.sh` from the kernel tree, as implemented in the kernel derivation (`pkgs/kernel/linux.nix`):

```nix
# From pkgs/kernel/linux.nix — configure phase
{ name = "configure";
  script = ''
    make defconfig ARCH=x86_64
    for frag in $configDir/*.config; do
      scripts/kconfig/merge_config.sh -m .config "$frag"
    done
    make olddefconfig ARCH=x86_64
  '';
}
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
CONFIG_SECURITY_SELINUX=y
CONFIG_DEFAULT_SECURITY_SELINUX=y
CONFIG_SECURITY_SELINUX_BOOTPARAM=y
CONFIG_SECURITY_SELINUX_DEVELOP=y
CONFIG_SECURITY_SELINUX_AVC_STATS=y
CONFIG_SECURITY_SELINUX_CHECKREQPROT_VALUE=0
CONFIG_AUDIT=y
CONFIG_AUDITSYSCALL=y
CONFIG_SECURITY_YAMA=y
CONFIG_SECCOMP=y
CONFIG_SECCOMP_FILTER=y
CONFIG_SECURITY_LANDLOCK=y
CONFIG_IMA=y
CONFIG_EVM=y
CONFIG_SECURITY_LOCKDOWN_LSM=y
CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY=y
CONFIG_STACKPROTECTOR=y
CONFIG_STACKPROTECTOR_STRONG=y
```

**SELinux is the definitive MAC system for ANDYL OS.** The decision rationale:

- **Fine-grained mandatory access control:** SELinux's label-based model provides type enforcement (TE), role-based access control (RBAC), and optional multi-level security (MLS). Labels travel with objects rather than being tied to filesystem paths, which is critical for confining container workloads.
- **Container and Kubernetes integration:** SELinux is the default MAC system for Kubernetes, CRI-O, and containerd. The `container-selinux` policy module provides well-tested contexts (`container_t`, `container_file_t`, `container_runtime_t`).
- **RHEL ecosystem alignment:** The majority of production Kubernetes and container tooling is developed and tested against SELinux.
- **Audit integration:** SELinux's tight coupling with the Linux audit subsystem provides comprehensive, structured access logging for compliance and incident response.
- **Immutable root compatibility:** SELinux labels are stored as `security.selinux` xattrs. The ext4 golden image is fully labeled at build time.

Boot parameters: `security=selinux selinux=1` (configured as defaults in `modules/base/boot.nix`).

### 4. Kernel as a Nix Derivation

The kernel is defined as a Nix derivation in `pkgs/kernel/linux.nix` using `mkDerivation`:

```nix
# pkgs/kernel/linux.nix
{ mkDerivation, fetchurl, sources, versions, make, perl, bash,
  bison, gawk, openssl, kmod }:

mkDerivation {
  name = "linux-${versions.kernel.linux}";
  version = versions.kernel.linux;

  src = fetchurl {
    inherit (sources.linux) url hash;
  };

  buildDeps = [ make perl bash bison gawk openssl ];
  runtimeDeps = [ kmod ];

  configDir = ./config;

  phases = [
    { name = "unpack"; script = "tar xf $src; cd linux-${versions.kernel.linux}"; }
    { name = "configure"; script = ''
        make defconfig ARCH=x86_64
        for frag in $configDir/*.config; do
          scripts/kconfig/merge_config.sh -m .config "$frag"
        done
        make olddefconfig ARCH=x86_64
      '';
    }
    { name = "build"; script = "make -j$NIX_BUILD_CORES ARCH=x86_64 bzImage modules"; }
    { name = "install"; script = ''
        mkdir -p $out/boot $out/lib/modules
        cp arch/x86/boot/bzImage $out/boot/vmlinuz-${versions.kernel.linux}
        make modules_install INSTALL_MOD_PATH=$out ARCH=x86_64
        rm -f $out/lib/modules/*/build $out/lib/modules/*/source
      '';
    }
  ];
}
```

### 5. Kernel Module Handling on Immutable OS

Traditional `dkms` (which writes to `/lib/modules/` at runtime) cannot work on an immutable root. Instead:

- All in-tree modules are built during the kernel package build.
- Out-of-tree modules (OpenZFS, built from `pkgs/storage/zfs.nix`) are built as separate Nix derivations that depend on the kernel package.
- At image assembly time, kernel modules and ZFS modules are union-merged into a single read-only `/lib/modules/<version>/`.
- `depmod` runs at build time to generate `modules.dep`.
- No runtime module compilation is ever needed.

### 6. Driver Strategy

**Built-in (`=y`) for boot-critical drivers:**
- NVMe, AHCI, Virtio block/net/PCI, Serial console

**Module (`=m`) for everything else:**
- Cloud drivers (ENA, gVNIC, Hyper-V)
- Bare metal NICs (Intel ice/i40e/ixgbe, Mellanox mlx5, Broadcom bnxt)
- KVM/VFIO

### 7. Firmware Management

The upstream `linux-firmware` repository is ~862 MB. The firmware derivation (`pkgs/kernel/firmware.nix`) strips it to ~20 MB of server-relevant firmware: CPU microcode (Intel + AMD) and server NIC firmware.

### 8. systemd Integration

ANDYL OS uses systemd as PID 1. The systemd package is built from `pkgs/init/systemd.nix` with meson, configured for server use:

```nix
# Key meson options from pkgs/init/systemd.nix
-Dnetworkd=true
-Dtmpfiles=true
-Dsysusers=true
-Dselinux=enabled
-Daudit=enabled
-Dlogind=true
-Dhostnamed=true
# Disabled: hibernate, coredump, homed, machined, portabled, sysext, etc.
```

**systemd unit generation:** The AOS module system generates systemd units declaratively. For example, `modules/base/boot.nix` generates boot loader entries and dracut configuration; `modules/services/update.nix` generates the update agent timer and service units.

Key systemd features for immutable OS:

- `tmpfiles.d`: Creates volatile directories on every boot
- `sysusers.d`: Ensures system users exist on boot
- `networkd`: Predictable network management for servers

### 9. systemd-boot as Bootloader

systemd-boot is a simple UEFI boot manager on the ESP. Boot entries are generated by the `modules/base/boot.nix` module.

### 10. dracut for Initrd Generation

dracut generates the systemd-based initrd at **image build time** (not at runtime), configured via `modules/base/boot.nix`:

```nix
# From modules/base/boot.nix
aos.boot.initrd.modules = [
  "virtio_blk"
  "virtio_pci"
  "ext4"
  "overlay"
];
```

The systemd-based initrd provides consistent logging, device management via udevd, ext4 root mount, Ignition first-boot provisioning, and clean handoff via switch-root.

### 11. Boot Counting Protocol

systemd-boot implements automatic boot assessment via filename-based counting. The boot tries count is configured via `aos.update.bootTries` (default: 3) in `modules/services/update.nix`.

```
andyl-os_42+3-0.efi    Fresh deploy, 3 tries remaining
andyl-os_42+2-1.efi    After 1st boot attempt
andyl-os_42+1-2.efi    After 2nd failed boot
andyl-os_42+0-3.efi    After 3rd failed boot -> fallback on next boot
andyl-os_42.efi        Verified good (counter removed by systemd-bless-boot)
```

## Alternatives Considered

**linux-libre:** Rejected because it strips firmware loading support and proprietary driver stubs needed for server NICs, storage controllers, and cloud environments.

**GRUB bootloader:** Rejected in favor of systemd-boot for its simplicity and native boot counting support.

**mkinitcpio / custom CPIO assembly:** dracut was chosen for its first-class systemd-in-initrd support.

**AppArmor (instead of SELinux):** Rejected. SELinux's label-based mandatory access control provides fine-grained type enforcement that follows objects across mount namespaces, which is critical for container workloads. Kubernetes, containerd, and the `container-selinux` policy module are developed and tested against SELinux.

## Security Considerations

- **SELinux MAC:** Targeted policy confines daemons and container workloads with type enforcement and RBAC. The ext4 golden image is fully labeled at build time.
- **Kernel hardening flags:** Stack protector (strong), lockdown mode (integrity), YAMA ptrace restrictions, seccomp filters, and Landlock are all enabled.
- **eBPF restrictions:** `CONFIG_BPF_UNPRIV_DEFAULT_OFF=y` prevents unprivileged eBPF program loading.
- **Firmware stripping:** Only server-relevant firmware is included (~20 MB vs 862 MB).
- **Secure Boot:** Kernel and boot artifacts can be signed for UEFI Secure Boot.
- **Immutable ext4 root:** Kernel modules and system binaries are part of the read-only root and cannot be tampered with at runtime.
- **Boot counting:** Automatic rollback after failed boots prevents bad kernel updates from leaving the system unbootable.

## Compatibility

- **OpenZFS 2.3.x** is required for 6.12 kernel compatibility (built from `pkgs/storage/zfs.nix`).
- **Kubernetes:** All required kernel features are enabled. SELinux is the default MAC for Kubernetes SecurityContexts.
- **Container runtimes:** containerd and runc are fully supported with systemd cgroup driver.
- **Cloud providers:** Drivers for AWS (ENA), GCP (gVNIC), and Azure (Hyper-V) are included as modules.
- **UEFI required:** systemd-boot requires UEFI firmware. Legacy BIOS is not supported.

## Open Questions

1. **Kernel series finalization:** OpenZFS 2.3.x compatibility with 6.12 needs validation testing before committing.
2. **SELinux policy scope:** Determine whether MLS policy is needed for any initial deployment targets.
3. **Secure Boot:** Should we implement Secure Boot from day one?

## References

- Linux Kernel Configuration: https://docs.kernel.org/admin-guide/README.html
- systemd-boot: https://www.freedesktop.org/software/systemd/man/systemd-boot.html
- dracut: https://github.com/dracut-ng/dracut-ng
- OpenZFS: https://openzfs.github.io/openzfs-docs/
- Boot Counting: https://systemd.io/AUTOMATIC_BOOT_ASSESSMENT/
- SELinux Project: https://selinuxproject.org/
- container-selinux: https://github.com/containers/container-selinux
- eBPF: https://ebpf.io/
