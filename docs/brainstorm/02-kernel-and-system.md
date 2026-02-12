# 02 - Kernel, systemd, and System Architecture

This document covers the low-level system architecture of AOS: the custom kernel build,
driver and firmware management, systemd integration, ZFS support (for mutable data),
SELinux mandatory access control, and the immutable base image design (ext4 golden image
with read-only root).

---

## Table of Contents

- [1. Custom Kernel (6.12.x LTS)](#1-custom-kernel-612x-lts)
- [2. Driver and Module Management](#2-driver-and-module-management)
- [3. Firmware](#3-firmware)
- [4. systemd Integration](#4-systemd-integration)
- [5. ZFS for Mutable Data](#5-zfs-for-mutable-data)
- [6. SELinux Mandatory Access Control](#6-selinux-mandatory-access-control)
- [7. Immutable Base Image Architecture](#7-immutable-base-image-architecture)
- [8. Boot Flow](#8-boot-flow)

---

## 1. Custom Kernel (6.12.x LTS)

### Why a Custom Kernel

AOS uses a custom-compiled Linux kernel rather than a distribution kernel. This enables:
- **Minimal attack surface**: only required subsystems are enabled
- **Server-optimized tuning**: no desktop/multimedia/graphics subsystems
- **Hardened configuration**: lockdown mode, module signature verification
- **Exact version control**: pinned in `pkgs/versions.nix`, built from source
- **ZFS compatibility**: kernel version matched to ZFS module requirements

### Package Definition

The kernel is defined as a standard AOS package in `pkgs/kernel/linux.nix`:

```nix
# pkgs/kernel/linux.nix
{ mkDerivation, fetchurl, versions, sources, gcc, flex, bison, perl,
  bc, openssl, elfutils, kmod }:

mkDerivation {
  pname = "linux";
  version = versions.kernel.linux;  # "6.12.11"
  src = fetchurl sources.linux;

  buildDeps = [
    gcc flex bison perl bc openssl elfutils kmod
  ];

  phases = [
    { name = "unpack"; script = "tar xf $src"; }
    {
      name = "configure";
      script = ''
        # Start from a minimal defconfig
        make defconfig

        # Apply AOS config fragments
        scripts/kconfig/merge_config.sh -m .config \
          ${./config/base.config} \
          ${./config/storage.config} \
          ${./config/networking.config} \
          ${./config/virtualization.config} \
          ${./config/security.config} \
          ${./config/drivers-vm.config}

        make olddefconfig
      '';
    }
    {
      name = "build";
      script = "make -j$NIX_BUILD_CORES bzImage modules";
    }
    {
      name = "install";
      script = ''
        mkdir -p $out/boot $out/lib/modules/${versions.kernel.linux}

        cp arch/x86/boot/bzImage $out/boot/vmlinuz
        cp System.map $out/boot/System.map
        cp .config $out/boot/config

        make INSTALL_MOD_PATH=$out modules_install
        # Remove build/source symlinks (point outside the store)
        rm -f $out/lib/modules/*/build $out/lib/modules/*/source
      '';
    }
  ];

  meta = {
    description = "Linux kernel (AOS server configuration)";
    homepage = "https://www.kernel.org/";
    license = "GPL-2.0-only";
  };
}
```

### Kernel Configuration Fragments

Instead of maintaining a monolithic `.config` file, AOS uses modular kconfig fragments
that are merged at build time. These live in `pkgs/kernel/config/`:

```
pkgs/kernel/config/
├── base.config              # Core: namespaces, cgroups v2, BPF, audit, modules
├── storage.config           # Block devices, NVMe, virtio-blk, ext4, ZFS deps
├── networking.config        # TCP/IP, netfilter/nftables, bridging, vxlan
├── virtualization.config    # KVM, virtio, PCI passthrough
├── security.config          # SELinux, integrity, lockdown, seccomp
├── drivers-vm.config        # Virtio drivers (VM environments)
├── drivers-cloud.config     # Cloud platform drivers (AWS, GCP, Azure)
└── drivers-baremetal.config # Physical server hardware (megaraid, mpt3sas, etc.)
```

**`base.config`** includes the core server subsystems:

```kconfig
# Namespaces and cgroups (required for containers)
CONFIG_NAMESPACES=y
CONFIG_UTS_NS=y
CONFIG_IPC_NS=y
CONFIG_USER_NS=y
CONFIG_PID_NS=y
CONFIG_NET_NS=y
CONFIG_CGROUP_V2=y
CONFIG_CGROUP_BPF=y

# Audit (required for SELinux)
CONFIG_AUDIT=y
CONFIG_AUDITSYSCALL=y

# Module loading
CONFIG_MODULES=y
CONFIG_MODULE_SIG=y
CONFIG_MODULE_SIG_SHA256=y

# Disable desktop subsystems
# CONFIG_SOUND is not set
# CONFIG_DRM is not set
# CONFIG_FB is not set
# CONFIG_VGA_CONSOLE is not set
```

**`security.config`** enables mandatory access control:

```kconfig
# SELinux
CONFIG_SECURITY_SELINUX=y
CONFIG_SECURITY_SELINUX_BOOTPARAM=y
CONFIG_SECURITY_SELINUX_DEVELOP=y
CONFIG_DEFAULT_SECURITY_SELINUX=y

# Lockdown
CONFIG_SECURITY_LOCKDOWN_LSM=y
CONFIG_SECURITY_LOCKDOWN_LSM_EARLY=y
CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY=y

# Integrity
CONFIG_INTEGRITY=y
CONFIG_IMA=y
CONFIG_EVM=y
```

### Variant-Specific Config

Different deployment targets use different driver fragments. The image builder selects
the appropriate fragment based on the system variant:

- **VM images**: `drivers-vm.config` (virtio-blk, virtio-net, virtio-serial, etc.)
- **Cloud images**: `drivers-cloud.config` (ENA, nvme, xen-blkfront, etc.)
- **Bare metal**: `drivers-baremetal.config` (megaraid_sas, mpt3sas, ixgbe, etc.)

---

## 2. Driver and Module Management

### Built-in vs. Module Loading

AOS takes a conservative approach to kernel modules:
- **Critical subsystems are built-in** (compiled into vmlinuz): namespaces, cgroups,
  networking core, ext4, device mapper
- **Hardware drivers are loadable modules**: storage controllers, NICs, platform-specific
- **ZFS is a loadable module**: built out-of-tree against the AOS kernel

### Module Loading

systemd's `modules-load.d` mechanism loads required modules at boot:

```nix
# modules/kubernetes/network.nix (excerpt)
config = lib.mkIf config.aos.kubernetes.enable {
  aos.boot.kernelModules = [
    "overlay"        # Required by containerd
    "br_netfilter"   # Required by kube-proxy/CNI
    "ip_vs"          # Required by kube-proxy IPVS mode
    "ip_vs_rr"
    "ip_vs_wrr"
    "ip_vs_sh"
    "nf_conntrack"
  ];
};
```

The module system collects all `aos.boot.kernelModules` values and generates the
appropriate `modules-load.d` configuration files.

### Module Signing

When `CONFIG_MODULE_SIG=y` is enabled, the kernel verifies module signatures at load
time. Modules built as part of the kernel derivation are automatically signed. ZFS
modules (built out-of-tree) are signed using a build-time key embedded in the kernel.

---

## 3. Firmware

### linux-firmware Package

The firmware package (`pkgs/kernel/firmware.nix`) bundles binary firmware blobs
required by hardware drivers:

```nix
# pkgs/kernel/firmware.nix
{ mkDerivation, fetchurl, versions, sources }:

mkDerivation {
  pname = "linux-firmware";
  version = versions.kernel.firmware;  # "20241210"
  src = fetchurl sources.linux-firmware;

  phases = [
    { name = "unpack"; script = "tar xf $src"; }
    {
      name = "install";
      script = ''
        mkdir -p $out/lib/firmware

        # Install only firmware for hardware we support
        for dir in amdgpu i915 iwlwifi mellanox intel; do
          [ -d "$dir" ] && cp -r "$dir" $out/lib/firmware/
        done

        # Always include CPU microcode
        cp -r amd-ucode intel-ucode $out/lib/firmware/ 2>/dev/null || true
      '';
    }
  ];

  meta = {
    description = "Linux firmware collection (server subset)";
    license = "redistributable";
  };
}
```

### Firmware Stripping

AOS includes only firmware for supported hardware classes (server NICs, storage
controllers, CPU microcode). Desktop hardware firmware (wifi, bluetooth, webcam, GPU
display) is excluded. This reduces the firmware install from ~800 MB to ~50 MB.

### initrd Firmware

Critical firmware (NVMe controller, boot NIC) is included in the initrd so it's
available during early boot before the root filesystem is mounted. The dracut module
configuration handles this:

```nix
# modules/base/boot.nix (excerpt)
config.aos.boot.initrdFirmware = [
  "intel/ice"        # Intel E800 series NICs
  "mellanox"         # Mellanox ConnectX NICs
  "amd-ucode"       # AMD CPU microcode
  "intel-ucode"     # Intel CPU microcode
];
```

---

## 4. systemd Integration

### systemd as PID 1

AOS uses systemd 256.9 as its init system. systemd provides:
- **Service management**: starting, stopping, dependency ordering
- **Journal logging**: structured, indexed binary logs
- **Network management**: systemd-networkd, systemd-resolved
- **Boot management**: systemd-boot (EFI bootloader)
- **Timer units**: replacing cron for scheduled tasks
- **tmpfiles**: declarative temporary file management
- **Hardening**: sandboxing options for services (namespaces, seccomp, capabilities)

### systemd Package

```nix
# pkgs/init/systemd.nix (simplified)
{ mkDerivation, fetchurl, versions, sources, meson, ninja, pkg-config,
  glibc, util-linux, kmod, dbus, libcap, libseccomp, openssl,
  audit, libselinux, zstd, lz4, xz, curl }:

mkDerivation {
  pname = "systemd";
  version = versions.init.systemd;  # "256.9"
  src = fetchurl sources.systemd;

  buildDeps = [
    meson ninja pkg-config
  ];

  runtimeDeps = [
    glibc util-linux kmod dbus libcap libseccomp openssl
    audit libselinux zstd lz4 xz curl
  ];

  phases = [
    { name = "unpack"; script = "tar xf $src"; }
    {
      name = "configure";
      script = ''
        meson setup build \
          --prefix=$out \
          -Dmode=release \
          -Drootprefix=$out \
          -Dsysvinit-path="" \
          -Dselinux=true \
          -Daudit=true \
          -Dkmod=true \
          -Dpam=false \
          -Dpolkit=false \
          -Dmachined=false \
          -Dhomed=false \
          -Duserdb=false \
          -Dportabled=false \
          -Dremote=false \
          -Dgnu-efi=true \
          -Dblkid=true \
          -Dfdisk=false \
          -Dman=false \
          -Dtests=false
      '';
    }
    { name = "build"; script = "ninja -C build -j$NIX_BUILD_CORES"; }
    { name = "install"; script = "DESTDIR=/ ninja -C build install"; }
  ];
}
```

Note the meson configuration: server features enabled (SELinux, audit, kmod, EFI boot),
desktop features disabled (machined, homed, polkit, PAM).

### No Activation Scripts

A key design difference from NixOS: AOS has no activation scripts. NixOS runs imperative
Bash scripts at system switch time that can take 8+ minutes and introduce race conditions.

In AOS, everything is declarative:
- System services are expressed as systemd units generated by modules
- The disk image contains the complete filesystem — no imperative setup at switch time
- First-boot provisioning is handled by Ignition (runs once in initrd, not every boot)
- Configuration files are generated at build time by Nix, not at boot time by scripts

### systemd Units from Modules

Each AOS module generates systemd units as part of its configuration output:

```nix
# modules/services/chrony.nix (example)
{ config, pkgs, lib, ... }:
{
  options.aos.chrony = {
    enable = lib.mkOption { type = lib.types.bool; default = false; };
    servers = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "time.cloudflare.com" "time.google.com" ];
    };
  };

  config = lib.mkIf config.aos.chrony.enable {
    systemd.services.chronyd = {
      description = "NTP client/server";
      after = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        ExecStart = "${pkgs.chrony}/bin/chronyd -f /etc/chrony.conf -d";
        Type = "simple";
        Restart = "on-failure";
        # Hardening
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        NoNewPrivileges = true;
        CapabilityBoundingSet = [ "CAP_SYS_TIME" "CAP_NET_BIND_SERVICE" ];
      };
    };

    # Generate chrony.conf from option values
    environment.etc."chrony.conf".text = ''
      ${lib.concatMapStrings (s: "server ${s} iburst\n") config.aos.chrony.servers}
      driftfile /var/lib/chrony/drift
      makestep 1.0 3
      rtcsync
      logdir /var/log/chrony
    '';
  };
}
```

---

## 5. ZFS for Mutable Data

### Architecture: Immutable Root + ZFS Data

AOS uses a split filesystem architecture:
- **Root (`/`)**: Read-only ext4 from the golden image. Contains the Nix store,
  system binaries, and base configuration.
- **`/var`**: Writable ZFS dataset. Contains logs, container images, Kubernetes state,
  and all runtime-generated data.
- **`/etc`**: Overlay filesystem. Lower layer from the image (read-only), upper layer
  on ZFS (writable for machine-specific config like hostname, SSH keys).
- **`/tmp`**: tmpfs (RAM-backed, cleared on reboot).

### Why ZFS for `/var`

- **Snapshots**: Automatic periodic snapshots of `/var` enable data recovery
- **Compression**: zstd compression saves disk space (especially for container layers)
- **Integrity**: Checksumming prevents silent data corruption
- **Copy-on-write**: Efficient snapshotting without performance penalty
- **Quotas**: Dataset-level quotas prevent individual services from filling disk

### ZFS Package

ZFS is built as an out-of-tree kernel module plus userspace tools:

```nix
# pkgs/storage/zfs.nix
{ mkDerivation, fetchurl, versions, sources, linux, gcc, util-linux,
  openssl, zlib, libuuid }:

mkDerivation {
  pname = "zfs";
  version = versions.storage.zfs;  # "2.3.0"
  src = fetchurl sources.zfs;

  buildDeps = [ gcc ];
  runtimeDeps = [ util-linux openssl zlib libuuid ];

  phases = [
    { name = "unpack"; script = "tar xf $src"; }
    {
      name = "configure";
      script = ''
        ./configure \
          --prefix=$out \
          --with-linux=${linux.dev}/lib/modules/${versions.kernel.linux}/build \
          --with-linux-obj=${linux.dev}/lib/modules/${versions.kernel.linux}/build \
          --enable-systemd \
          --with-systemdunitdir=$out/lib/systemd/system \
          --with-systemdpresetdir=$out/lib/systemd/system-preset \
          --disable-pyzfs
      '';
    }
    { name = "build"; script = "make -j$NIX_BUILD_CORES"; }
    { name = "install"; script = "make install"; }
  ];
}
```

### ZFS Pool Layout

Created by Ignition on first boot:

```
tank                         # Root pool on unpartitioned space
├── tank/var                 # /var mount point
│   ├── tank/var/log         # System and service logs
│   ├── tank/var/lib         # Persistent state
│   │   ├── tank/var/lib/containerd  # Container runtime state
│   │   ├── tank/var/lib/kubelet     # Kubernetes node state
│   │   └── tank/var/lib/etcd        # etcd data (control-plane only)
│   └── tank/var/tmp         # Persistent temp (survives reboot)
├── tank/etc-upper           # /etc overlay upper layer
└── tank/containers          # Container image storage
```

Pool properties:
```
ashift=12           # 4K sector alignment
compression=zstd    # Transparent compression
atime=off           # No access time updates (performance)
xattr=sa            # Extended attributes in system area
```

### ZFS Module Integration

```nix
# modules/base/filesystems.nix (ZFS section)
config = lib.mkIf config.aos.filesystems.zfs.enable {
  aos.boot.kernelModules = [ "zfs" ];

  systemd.services.zfs-import = {
    description = "Import ZFS pool";
    before = [ "local-fs.target" ];
    wantedBy = [ "local-fs.target" ];
    serviceConfig = {
      Type = "oneshot";
      ExecStart = "${pkgs.zfs}/bin/zpool import -a -f";
      RemainAfterExit = true;
    };
  };

  systemd.timers.zfs-snapshot = {
    description = "Periodic ZFS snapshots";
    timerConfig = {
      OnCalendar = "hourly";
      Persistent = true;
    };
    wantedBy = [ "timers.target" ];
  };
};
```

---

## 6. SELinux Mandatory Access Control

### Why SELinux

AOS uses SELinux for mandatory access control (MAC). Even if a service is compromised,
SELinux confines it to its declared security context, preventing lateral movement.

Key benefits for AOS:
- Containers run in confined domains (`container_t`)
- kubelet has its own policy with minimal privileges
- Network services cannot access arbitrary files
- The Nix store is labeled as system content (immutable)

### SELinux Package Stack

The SELinux stack is built as a series of packages, each depending on the previous:

```
libsepol       Low-level policy manipulation library
    |
libselinux     User-space interface library
    |
libsemanage    Policy management library
    |
policycoreutils  Core policy tools (semodule, restorecon, etc.)
    |
setools        Policy analysis tools (sesearch, seinfo)
    |
refpolicy      Reference policy (targeted mode)
    |
container-selinux  Container-specific policy modules
```

Each is a Nix derivation in `pkgs/security/`:

```nix
# pkgs/security/libselinux.nix
{ mkDerivation, fetchurl, versions, sources, libsepol, pcre2, python3 }:

mkDerivation {
  pname = "libselinux";
  version = versions.security.selinux-userspace;  # "3.7"
  src = fetchurl sources.libselinux;

  buildDeps = [ python3 ];
  runtimeDeps = [ libsepol pcre2 ];
  propagatedDeps = [ libsepol ];

  phases = [
    { name = "unpack"; script = "tar xf $src"; }
    {
      name = "build";
      script = "make -j$NIX_BUILD_CORES PREFIX=$out LIBSEPOL=${libsepol}";
    }
    { name = "install"; script = "make install PREFIX=$out"; }
  ];
}
```

### SELinux Module

```nix
# modules/security/selinux.nix
{ config, pkgs, lib, ... }:
{
  options.aos.selinux = {
    enable = lib.mkOption { type = lib.types.bool; default = false; };
    mode = lib.mkOption {
      type = lib.types.enum [ "enforcing" "permissive" "disabled" ];
      default = "enforcing";
    };
  };

  config = lib.mkIf config.aos.selinux.enable {
    # Kernel command line
    aos.boot.kernelParams = [
      "security=selinux"
      "selinux=1"
    ];

    # SELinux configuration
    environment.etc."selinux/config".text = ''
      SELINUX=${config.aos.selinux.mode}
      SELINUXTYPE=targeted
    '';

    # Initial policy load at boot
    systemd.services.selinux-policy-load = {
      description = "Load SELinux policy";
      before = [ "sysinit.target" ];
      wantedBy = [ "sysinit.target" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${pkgs.policycoreutils}/sbin/load_policy";
        RemainAfterExit = true;
      };
    };

    # Relabel filesystem on first boot (after Ignition)
    systemd.services.selinux-relabel = {
      description = "SELinux filesystem relabel";
      after = [ "selinux-policy-load.service" "local-fs.target" ];
      wantedBy = [ "sysinit.target" ];
      unitConfig.ConditionPathExists = "!/.autorelabel-done";
      serviceConfig = {
        Type = "oneshot";
        ExecStart = "${pkgs.policycoreutils}/sbin/restorecon -R /";
        ExecStartPost = "/bin/touch /.autorelabel-done";
      };
    };
  };
}
```

### SELinux Policy for Containers

The `container-selinux` package provides policy modules for containerd and runc:

```
container_t           # Container process domain
container_file_t      # Container filesystem labels
container_runtime_t   # containerd/runc process domain
container_log_t       # Container log files
container_var_lib_t   # /var/lib/containerd
```

These are loaded as policy modules by `semodule` at boot.

---

## 7. Immutable Base Image Architecture

### Filesystem Layout

```
/                      ext4, read-only (from golden image)
├── nix/store/         All packages, kernel, systemd, etc.
├── sbin/init          -> /nix/store/.../systemd (PID 1)
├── etc/               Overlay (lower=image, upper=ZFS)
├── var/               ZFS dataset (writable)
├── tmp/               tmpfs
├── proc/              procfs
├── sys/               sysfs
├── dev/               devtmpfs
└── run/               tmpfs
    └── current-system -> /nix/store/.../system-toplevel
```

### Immutability Guarantees

1. **Root is read-only**: The ext4 root partition is mounted with `ro` flag. No process
   can modify system files, even as root.
2. **Store is immutable**: `/nix/store` paths are never modified after creation. The
   entire store is on the read-only root.
3. **`/etc` is overlay**: Base configuration from the image (read-only layer) plus
   machine-specific overrides (writable upper layer on ZFS). New files can be created,
   but the base layer cannot be changed.
4. **`/var` is the only persistent writable area**: All mutable state lives here on ZFS.
5. **`/tmp` and `/run` are tmpfs**: Cleared on every reboot.

### Why ext4 Read-Only (Not SquashFS, Not dm-verity)

- **ext4 read-only** is simple and well-tested. No extra kernel modules needed.
- **SquashFS** would provide compression but adds complexity. The image is only built
  once and transferred once — compression at the filesystem level provides minimal benefit
  vs. zstd compression during transfer.
- **dm-verity** provides runtime integrity verification (every block read is hash-checked).
  This is a future consideration but adds latency to every I/O operation.

### Update Mechanism

Updates replace the entire root filesystem atomically:
1. New image is downloaded as an update bundle (delta-compressed)
2. New store paths are extracted to a staging area
3. Boot entry is updated to point to the new system toplevel
4. On next reboot, the new system is active
5. Boot counting provides automatic rollback if the new system fails to boot

The running system is never modified in place. This is the immutable infrastructure model.

---

## 8. Boot Flow

### UEFI Boot Sequence

```
1. UEFI firmware
   └── Loads systemd-boot from ESP (EFI System Partition)

2. systemd-boot
   ├── Reads /loader/loader.conf (timeout, default entry)
   ├── Reads /loader/entries/aos.conf (kernel, initrd, options)
   └── Loads vmlinuz + initrd from ESP

3. Linux kernel
   ├── Decompresses and initializes
   ├── Mounts initrd as temporary root
   └── Runs /init from initrd (dracut)

4. initrd (dracut)
   ├── Loads storage drivers (NVMe, virtio-blk)
   ├── Loads firmware (CPU microcode, NIC firmware)
   ├── Finds root partition (by label: aos-root)
   ├── Mounts root partition read-only
   ├── Runs Ignition (first boot only: creates ZFS pool, datasets)
   └── Switches to real root, exec's systemd

5. systemd (PID 1)
   ├── /sbin/init -> /nix/store/.../systemd
   ├── Imports ZFS pool, mounts /var
   ├── Sets up /etc overlay
   ├── Mounts tmpfs for /tmp, /run
   ├── Loads SELinux policy
   ├── Starts network (systemd-networkd, systemd-resolved)
   ├── Starts services (sshd, chronyd, containerd, kubelet, ...)
   └── Reaches multi-user.target

6. System operational
   ├── Read-only root: /
   ├── Writable data: /var (ZFS)
   ├── Overlay config: /etc
   └── Services running under systemd
```

### Kernel Command Line

Generated by the boot module from evaluated configuration:

```nix
# modules/base/boot.nix (excerpt)
options.aos.boot.kernelParams = lib.mkOption {
  type = lib.types.listOf lib.types.str;
  default = [
    "root=LABEL=aos-root"
    "rootfstype=ext4"
    "ro"                    # Read-only root
    "quiet"
    "loglevel=4"
    "systemd.show_status=auto"
  ];
};
```

SELinux, ZFS, and other modules append to this list via the module system:
```nix
# From modules/security/selinux.nix
config.aos.boot.kernelParams = [ "security=selinux" "selinux=1" ];

# From modules/base/filesystems.nix
config.aos.boot.kernelParams = [ "zfs.zfs_arc_max=1073741824" ];
```

The final kernel command line is the concatenation of all contributed parameters,
written into the boot entry by the image builder.

### Boot Counting and Automatic Rollback

systemd-boot supports boot counting for automatic rollback:

```
/loader/entries/aos.conf          # Current generation
/loader/entries/aos-previous.conf # Previous generation (fallback)
```

Each entry has a `tries-left` counter. If the system fails to reach a healthy state
(defined by the health-check service), the counter decrements. When it reaches zero,
systemd-boot automatically falls back to the previous generation.

```nix
# modules/services/update.nix (boot counting)
config.aos.update.bootTries = lib.mkOption {
  type = lib.types.int;
  default = 3;
  description = "Number of boot attempts before automatic rollback";
};
```

The health check service (`systemd-bless-boot.service`) marks the current boot as
successful once all critical services are running. This resets the tries counter,
confirming the system is healthy.

---

## Summary

| Component | Implementation |
|-----------|---------------|
| Kernel | `pkgs/kernel/linux.nix` — custom 6.12.11 LTS with modular kconfig fragments |
| Firmware | `pkgs/kernel/firmware.nix` — stripped to server-relevant hardware only |
| systemd | `pkgs/init/systemd.nix` — 256.9, meson build, server features only |
| ZFS | `pkgs/storage/zfs.nix` — 2.3.0, out-of-tree kernel module + userspace |
| SELinux | `pkgs/security/lib{sepol,selinux,semanage}.nix` + `refpolicy.nix` |
| Init system | systemd as PID 1, no activation scripts, declarative unit generation |
| Root filesystem | ext4 read-only, immutable |
| Mutable data | ZFS datasets under /var |
| Config layer | /etc overlay (image base + ZFS upper) |
| Boot | systemd-boot + boot counting + automatic rollback |
| Module system | Nix modules generate systemd units, no imperative scripts |
