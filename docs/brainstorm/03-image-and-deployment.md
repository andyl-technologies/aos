# 03 - Image Generation, Deployment, and Rollback

## Overview

This document covers the full lifecycle of an AOS machine: how golden images are built
from Nix derivations, how they are deployed to bare metal or VMs, how updates are
delivered as delta-compressed bundles, how system generations provide atomic rollback,
how garbage collection reclaims disk space, how CoreOS Ignition configures machines on
first boot, and how Kubernetes workloads run on the immutable base.

---

## Table of Contents

- [1. Image Generation](#1-image-generation)
- [2. The Nix Store and Content Addressing](#2-the-nix-store-and-content-addressing)
- [3. System Generations and Rollback](#3-system-generations-and-rollback)
- [4. Update Bundles](#4-update-bundles)
- [5. Garbage Collection](#5-garbage-collection)
- [6. Ignition: First-Boot Provisioning](#6-ignition-first-boot-provisioning)
- [7. Kubernetes on Immutable AOS](#7-kubernetes-on-immutable-aos)

---

## 1. Image Generation

### How `aos system image` Works

Building a disk image is a single command:

```
aos system image server
```

Under the hood, this invokes:
```
nix-build default.nix -A images.server
```

The image builder (`images/builder.nix`) is a Nix derivation that produces a bootable
GPT disk image from an evaluated system configuration.

### Image Builder Architecture

```nix
# images/builder.nix — AOS disk image builder
{ pkgs, lib, system, name, diskSize ? "16G", espSize ? "1G", rootSize ? "8G" }:

let
  # Compute the Nix store closure of the system toplevel
  closureInfo = pkgs.mkDerivation {
    name = "${name}-closure-info";
    # ... enumerates every store path in the transitive closure
  };

  kernelParams = lib.concatStringsSep " " system.config.aos.boot.kernelParams;

in pkgs.mkDerivation {
  name = "aos-image-${name}";

  nativeBuildInputs = [
    pkgs.util-linux    # losetup, sfdisk, partprobe
    pkgs.dosfstools    # mkfs.fat
    pkgs.e2fsprogs     # mkfs.ext4
    pkgs.coreutils     # truncate, cp, mkdir
  ];

  buildPhase = ''
    # 1. Create empty raw image
    truncate -s ${diskSize} image.raw

    # 2. Create GPT partition table
    sfdisk image.raw <<PTABLE
    label: gpt
    size=${espSize}, type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, name="ESP"
    size=${rootSize}, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="Root"
    PTABLE

    # 3. Attach loop device with partition scanning
    LOOP=$(losetup --find --show --partscan image.raw)

    # 4. Format partitions
    mkfs.fat -F 32 -n ESP "''${LOOP}p1"
    mkfs.ext4 -L aos-root -O ^has_journal -q "''${LOOP}p2"

    # 5. Mount and populate
    mount "''${LOOP}p2" /mnt/aos-root
    mount "''${LOOP}p1" /mnt/aos-esp

    # 6. Copy entire Nix store closure to root filesystem
    while IFS= read -r storePath; do
      cp -a "$storePath" /mnt/aos-root"$storePath"
    done < ${closureInfo}/store-paths

    # 7. Set up system directories and symlinks
    ln -sfn ${system.config.system.build.toplevel} \
      /mnt/aos-root/run/current-system
    ln -sfn ${pkgs.systemd}/lib/systemd/systemd /mnt/aos-root/sbin/init

    # 8. Install systemd-boot on ESP
    cp ${systemdBootEfi} /mnt/aos-esp/EFI/systemd/systemd-bootx64.efi
    cp ${systemdBootEfi} /mnt/aos-esp/EFI/BOOT/BOOTX64.EFI

    # 9. Write boot entry
    cat > /mnt/aos-esp/loader/entries/aos.conf <<ENTRY
    title   AOS ${variant} ${version}
    linux   /vmlinuz
    initrd  /initrd.img
    options ${kernelParams}
    ENTRY

    # 10. Copy kernel and initrd to ESP
    cp ${system.config.system.build.kernel}/bzImage /mnt/aos-esp/vmlinuz
    cp ${system.config.system.build.initrd}/initrd.img /mnt/aos-esp/initrd.img

    # 11. Unmount
    umount /mnt/aos-esp /mnt/aos-root
    losetup -d "$LOOP"
  '';

  installPhase = ''
    mkdir -p $out
    mv image.raw $out/aos-${name}.img
  '';

  requiredSystemFeatures = [ "kvm" ];
}
```

### Disk Layout

```
+-------------------------------------------------------------------+
| GPT Partition Table                                                |
+-------------------------------------------------------------------+
| Partition 1: ESP (FAT32)                | 1 GiB                   |
|   /EFI/systemd/systemd-bootx64.efi     |                         |
|   /EFI/BOOT/BOOTX64.EFI                |                         |
|   /loader/loader.conf                   |                         |
|   /loader/entries/aos.conf              |                         |
|   /vmlinuz                              |                         |
|   /initrd.img                           |                         |
+-----------------------------------------+-------------------------+
| Partition 2: Root (ext4, read-only)     | 8-12 GiB                |
|   /nix/store/...                        | (entire system closure)  |
|   /sbin/init -> /nix/store/.../systemd  |                         |
|   /etc/ (base layer for overlay)        |                         |
+-----------------------------------------+-------------------------+
| Unpartitioned space                     | Remaining (for ZFS)     |
|   (ZFS pool created by Ignition on      |                         |
|    first boot)                          |                         |
+-------------------------------------------------------------------+
```

### Image Variants

Different system variants produce different images with appropriate sizing:

| Variant | Disk Size | ESP | Root | ZFS Reserved |
|---------|-----------|-----|------|-------------|
| `base` | 16 GiB | 1 GiB | 8 GiB | 7 GiB |
| `server` | 16 GiB | 1 GiB | 8 GiB | 7 GiB |
| `k8s-worker` | 32 GiB | 1 GiB | 12 GiB | 19 GiB |
| `k8s-control-plane` | 32 GiB | 1 GiB | 12 GiB | 19 GiB |

K8s variants need more root space (containerd, kubelet, CNI plugins) and more ZFS
space (container images, etcd data).

### Image Metadata

Each image includes machine-readable metadata:

```json
{
  "name": "server",
  "variant": "server",
  "version": "0.1.0",
  "diskSize": "16G",
  "espSize": "1G",
  "rootSize": "8G",
  "format": "raw",
  "partitionTable": "gpt",
  "partitions": [
    { "number": 1, "label": "ESP",  "type": "esp",   "filesystem": "fat32", "size": "1G" },
    { "number": 2, "label": "Root", "type": "linux", "filesystem": "ext4",  "size": "8G" }
  ]
}
```

---

## 2. The Nix Store and Content Addressing

### Store Path Structure

Every build output lives in `/nix/store` with a content-derived hash prefix:

```
/nix/store/abc123...-glibc-2.39/
/nix/store/def456...-systemd-256.9/
/nix/store/ghi789...-linux-6.12.11/
/nix/store/jkl012...-aos-server-toplevel/
```

The hash is computed from all build inputs (source, dependencies, build script,
environment). Changing any input produces a different hash and a new store path.

### System Toplevel

The "system toplevel" is a store path that represents the complete system configuration:

```
/nix/store/...-aos-server-toplevel/
├── activate              # (not used in AOS — no activation scripts)
├── init -> /nix/store/.../systemd
├── kernel -> /nix/store/.../linux-6.12.11/boot/vmlinuz
├── initrd -> /nix/store/.../initrd.img
├── system-units/ -> /nix/store/.../systemd-units/
└── etc/ -> /nix/store/.../etc-static/
```

The image builder uses the toplevel to:
1. Compute the store closure (all transitively referenced paths)
2. Copy the closure to the root partition
3. Set up `/run/current-system` symlink
4. Extract kernel + initrd for the ESP

### Closure Computation

A "closure" is the set of all store paths transitively referenced by a given path.
If the system toplevel references systemd, and systemd references glibc, then glibc
is in the closure even though the toplevel doesn't reference it directly.

```
# Show the full closure of the server system
nix-store --query --requisites $(nix-build default.nix -A systems.server.config.system.build.toplevel)

# Count paths in the closure
nix-store --query --requisites ... | wc -l

# Show the closure as a tree
nix-store --query --tree $(nix-build ...)
```

The image builder copies the entire closure to the root filesystem, ensuring the
system can run without a Nix daemon.

---

## 3. System Generations and Rollback

### Generation Model

Each successful update produces a new "generation" — a new system toplevel store path
with a new boot entry. Previous generations remain in the store (until garbage collected).

```
/loader/entries/
├── aos.conf              # Current generation (default boot)
└── aos-previous.conf     # Previous generation (fallback)
```

### Atomic Switching

Switching to a new generation is atomic:
1. New store paths are extracted from the update bundle
2. A new boot entry is written pointing to the new toplevel
3. The `default` in `loader.conf` is updated
4. Reboot activates the new generation

The previous generation's files remain on disk. If the new generation fails, the
boot counting mechanism automatically reverts to the previous generation.

### Boot Counting

systemd-boot's boot counting protocol provides automatic rollback:

```
# Boot entry with counting
title   AOS server 0.2.0
linux   /vmlinuz-0.2.0
initrd  /initrd-0.2.0.img
options root=LABEL=aos-root ro ...
```

On each boot:
1. systemd-boot decrements `tries-left` counter
2. The system boots and starts services
3. If the health check passes, `systemd-bless-boot.service` marks the boot successful
4. If `tries-left` reaches 0 without a successful mark, the bootloader falls back

```nix
# modules/services/update.nix
options.aos.update = {
  bootTries = lib.mkOption {
    type = lib.types.int;
    default = 3;
    description = "Boot attempts before automatic rollback";
  };
};

config = lib.mkIf config.aos.update.enable {
  # Health check: all critical services must be running
  systemd.services.aos-health-check = {
    description = "AOS system health check";
    after = [ "multi-user.target" ];
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      Type = "oneshot";
      ExecStart = pkgs.writeScript "health-check" ''
        #!/bin/sh
        set -eu
        # Verify critical services
        systemctl is-active systemd-networkd || exit 1
        systemctl is-active sshd || exit 1
        ${lib.optionalString config.aos.kubernetes.enable
          "systemctl is-active kubelet || exit 1"}
        # Mark boot as successful
        bootctl set-oneshot ""
      '';
    };
  };
};
```

### Manual Rollback

Operators can also roll back manually:

```
# List available generations
aos gc --list-generations

# The previous generation is always available as the fallback boot entry
# To manually rollback: reboot and select the previous entry in systemd-boot
# Or set it as default:
bootctl set-default aos-previous.conf
reboot
```

---

## 4. Update Bundles

### Delta Compression

Updates are delivered as delta bundles — only store paths present in the new system
but absent from the old system are included. This minimizes transfer size.

The bundle builder (`deploy/bundle.nix`) computes the delta:

```nix
# deploy/bundle.nix — AOS update bundle builder
{ pkgs, lib, oldSystem, newSystem, version }:

let
  oldToplevel = oldSystem.config.system.build.toplevel;
  newToplevel = newSystem.config.system.build.toplevel;

in pkgs.mkDerivation {
  name = "aos-bundle-${version}";

  buildPhase = ''
    # 1. Compute store closures
    nix-store --query --requisites ${oldToplevel} | sort > old-paths
    nix-store --query --requisites ${newToplevel} | sort > new-paths

    # 2. Compute delta (paths in new but not in old)
    comm -13 old-paths new-paths > delta-paths

    # 3. Compress each delta path with zstd
    while IFS= read -r storePath; do
      basename=$(basename "$storePath")
      tar -cf - -C / "$storePath" | zstd -15 -T0 -q > "store/''${basename}.tar.zst"
    done < delta-paths

    # 4. Write manifest
    cat > manifest.json <<MANIFEST
    {
      "version": "${version}",
      "format": 1,
      "oldToplevel": "${oldToplevel}",
      "newToplevel": "${newToplevel}",
      "pathCount": $(wc -l < delta-paths),
      "paths": [...]
    }
    MANIFEST

    # 5. Create final tarball
    tar -cf bundle.tar manifest.json store/
  '';

  installPhase = ''
    mkdir -p $out
    mv bundle.tar $out/aos-update-${version}.tar
    tar -xf $out/aos-update-${version}.tar -C $out manifest.json
  '';
}
```

### Bundle Structure

```
aos-update-0.2.0.tar
├── manifest.json                    # Version metadata, path list, sizes, hashes
└── store/
    ├── abc123...-systemd-256.10.tar.zst
    ├── def456...-linux-6.12.12.tar.zst
    └── ...                          # Only changed paths
```

### Manifest Format

```json
{
  "version": "0.2.0",
  "format": 1,
  "timestamp": "2025-01-15T10:30:00Z",
  "oldToplevel": "/nix/store/...-aos-server-0.1.0",
  "newToplevel": "/nix/store/...-aos-server-0.2.0",
  "deltaHash": "sha256:abcdef...",
  "totalSize": 524288000,
  "compressedSize": 157286400,
  "pathCount": 42,
  "paths": [
    {
      "path": "/nix/store/abc123...-systemd-256.10",
      "hash": "sha256:...",
      "size": 12345678,
      "compressedSize": 4567890,
      "archive": "store/abc123...-systemd-256.10.tar.zst"
    }
  ]
}
```

### Bundle Signing

Bundles are signed with minisign for authenticity verification:

```nix
# deploy/sign.nix — Sign an update bundle with minisign
{ pkgs, bundle, signingKey }:

pkgs.mkDerivation {
  name = "aos-signed-bundle";

  buildPhase = ''
    ${pkgs.minisign}/bin/minisign -S \
      -s ${signingKey} \
      -m ${bundle}/aos-update-*.tar
  '';

  installPhase = ''
    mkdir -p $out
    cp ${bundle}/aos-update-*.tar $out/
    cp ${bundle}/aos-update-*.tar.minisig $out/
  '';
}
```

### Update Application Flow

On the target machine, the update agent:

1. **Downloads** the bundle from the update server
2. **Verifies** the minisign signature against the trusted public key
3. **Reads** the manifest to determine required store paths
4. **Extracts** each compressed store path to `/nix/store`
5. **Writes** a new boot entry pointing to the new toplevel
6. **Reboots** (if auto-update is enabled, or waits for operator confirmation)

```nix
# modules/services/update.nix (update check)
options.aos.update = {
  enable = lib.mkOption { type = lib.types.bool; default = true; };
  server = lib.mkOption { type = lib.types.str; default = "https://update.aos.internal"; };
  channel = lib.mkOption { type = lib.types.str; default = "stable"; };
  checkInterval = lib.mkOption { type = lib.types.int; default = 3600; };
  autoUpdate = lib.mkOption { type = lib.types.bool; default = false; };
  maxRetries = lib.mkOption { type = lib.types.int; default = 3; };
  retryDelay = lib.mkOption { type = lib.types.int; default = 300; };
  signingKeyPath = lib.mkOption {
    type = lib.types.str;
    default = "/etc/aos/update-signing-key.pub";
  };
};
```

---

## 5. Garbage Collection

### The Problem

Over time, old generations accumulate store paths that are no longer referenced by the
current system. These consume disk space on the root partition.

### GC Strategy

AOS garbage collection is conservative:
1. Keep the current generation and at least one previous generation (for rollback)
2. Keep generations newer than a configurable age (default: 7 days)
3. Remove store paths not referenced by any kept generation

```nix
# modules/services/gc.nix
options.aos.update.gc = {
  schedule = lib.mkOption { type = lib.types.str; default = "weekly"; };
  keepGenerations = lib.mkOption { type = lib.types.int; default = 5; };
  minAgeHours = lib.mkOption { type = lib.types.int; default = 168; }; # 7 days
};

config = lib.mkIf config.aos.update.enable {
  systemd.timers.aos-gc = {
    description = "AOS store garbage collection";
    timerConfig = {
      OnCalendar = config.aos.update.gc.schedule;
      Persistent = true;
    };
    wantedBy = [ "timers.target" ];
  };

  systemd.services.aos-gc = {
    description = "AOS store garbage collection";
    serviceConfig = {
      Type = "oneshot";
      ExecStart = pkgs.writeScript "aos-gc" ''
        #!/bin/sh
        set -eu
        # Remove old generations beyond the keep threshold
        nix-collect-garbage \
          --delete-older-than ${toString config.aos.update.gc.minAgeHours}h
      '';
    };
  };
};
```

### Manual GC

```
# Run garbage collection
aos gc

# List current generations
aos gc --list-generations

# Inspect what would be deleted
nix-store --gc --print-dead
```

### Store Path Sizes

The `aos test build` layer includes closure size checks to prevent accidental bloat:

```nix
# tests/build.nix (excerpt)
closureSizeCheck = system: maxSize:
  pkgs.mkDerivation {
    name = "closure-size-check";
    buildPhase = ''
      size=$(nix-store --query --requisites ${system.config.system.build.toplevel} \
        | xargs du -sb | tail -1 | cut -f1)
      if [ "$size" -gt "${toString maxSize}" ]; then
        echo "FAIL: closure size $size exceeds maximum ${toString maxSize}"
        exit 1
      fi
      echo "PASS: closure size $size within limit"
    '';
  };
```

---

## 6. Ignition: First-Boot Provisioning

### What Ignition Does

CoreOS Ignition runs exactly once, during the first boot, in the initrd before systemd
starts. It performs machine-specific provisioning that cannot be baked into the
golden image:

1. **ZFS pool creation** — creates the `tank` pool on unpartitioned disk space
2. **ZFS datasets** — creates `/var`, `/var/log`, `/var/lib/containerd`, etc.
3. **`/etc` overlay** — sets up the overlay mount with ZFS upper layer
4. **Hostname** — sets the machine's hostname
5. **SSH authorized keys** — installs operator SSH keys
6. **Network configuration** — machine-specific IP addresses (if static)
7. **Kubernetes bootstrap** — kubeadm join token, control-plane init

### Butane Configuration

Operators write Butane YAML, which compiles to Ignition JSON:

```yaml
# butane config for a k8s worker node
variant: fcos
version: "1.5.0"

storage:
  filesystems:
    - path: /var
      device: /dev/disk/by-label/tank-var
      format: zfs
      wipe_filesystem: false

  files:
    - path: /etc/hostname
      mode: 0644
      contents:
        inline: worker-01

    - path: /etc/kubernetes/kubeadm-join.yaml
      mode: 0600
      contents:
        inline: |
          apiVersion: kubeadm.k8s.io/v1beta3
          kind: JoinConfiguration
          discovery:
            bootstrapToken:
              apiServerEndpoint: "control-plane:6443"
              token: "abcdef.0123456789abcdef"

passwd:
  users:
    - name: core
      ssh_authorized_keys:
        - "ssh-ed25519 AAAA... ops@example.com"
```

### Ignition in the Boot Flow

```
initrd (dracut)
  ├── Load storage drivers
  ├── Find root partition (LABEL=aos-root)
  ├── Mount root read-only
  ├── Check for /etc/ignition-done marker
  │   ├── If exists: skip Ignition (not first boot)
  │   └── If not: run Ignition
  │       ├── Read Ignition config from:
  │       │   ├── QEMU fw_cfg (VMs)
  │       │   ├── Cloud instance metadata (cloud)
  │       │   └── Disk label (bare metal)
  │       ├── Create ZFS pool and datasets
  │       ├── Set up /etc overlay
  │       ├── Write hostname, SSH keys, network config
  │       ├── Write /etc/ignition-done marker
  │       └── Continue boot
  └── Switch to real root, exec systemd
```

### Ignition Module

```nix
# modules/services/ignition.nix
{ config, pkgs, lib, ... }:
{
  options.aos.ignition = {
    enable = lib.mkOption { type = lib.types.bool; default = true; };
    zfsPoolName = lib.mkOption { type = lib.types.str; default = "tank"; };
    datasets = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [
        "var"
        "var/log"
        "var/lib"
        "var/lib/containerd"
        "var/tmp"
        "etc-upper"
      ];
    };
  };

  config = lib.mkIf config.aos.ignition.enable {
    # Ignition binary included in initrd
    aos.boot.initrdPackages = [ pkgs.ignition ];

    # Dracut module to run Ignition during initrd
    aos.boot.dracutModules = [ "ignition" ];
  };
}
```

### Ignition Package

```nix
# pkgs/boot/ignition.nix
{ mkDerivation, fetchurl, versions, sources, go }:

mkDerivation {
  pname = "ignition";
  version = versions.image-tools.ignition;  # "2.19.0"
  src = fetchurl sources.ignition;

  buildDeps = [ go ];

  phases = [
    { name = "unpack"; script = "tar xf $src"; }
    {
      name = "build";
      script = ''
        export GOPATH=$TMPDIR/go
        go build -o ignition ./internal
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out/bin $out/lib/dracut/modules.d/30ignition
        install -m 755 ignition $out/bin/
      '';
    }
  ];
}
```

---

## 7. Kubernetes on Immutable AOS

### Architecture Overview

AOS is designed as a Kubernetes node OS. The immutable base provides a stable,
predictable platform for container workloads:

```
+----------------------------------------------------------+
| AOS Immutable Base                                        |
|                                                           |
|  /nix/store/...   (read-only)                             |
|    ├── systemd                                            |
|    ├── containerd                                         |
|    ├── kubelet                                            |
|    ├── CNI plugins                                        |
|    └── ... (all system packages)                          |
|                                                           |
|  /var/ (ZFS, writable)                                    |
|    ├── lib/containerd/  (container images + layers)        |
|    ├── lib/kubelet/     (pod manifests, volumes)           |
|    ├── lib/etcd/        (control-plane only)               |
|    ├── log/             (system + container logs)          |
|    └── run/             (runtime sockets)                  |
|                                                           |
+----------------------------------------------------------+
```

### System Variants

K8s nodes are built from layered system variants:

```
base.nix
  └── server.nix (adds: SELinux, firewall, SSH, chrony, audit)
      └── k8s-worker.nix (adds: containerd, kubelet, CNI)
          └── k8s-control-plane.nix (adds: kubeadm, extra firewall rules)
```

```nix
# systems/k8s-worker.nix
{ config, pkgs, lib, ... }:
{
  imports = [ ./server.nix ];

  aos.kubernetes.enable = true;
  aos.kubernetes.role = "worker";
  aos.containerd.enable = true;
  aos.monitoring.nodeExporter.enable = true;
}
```

### containerd Configuration

```nix
# modules/kubernetes/containerd.nix
{ config, pkgs, lib, ... }:
{
  options.aos.containerd = {
    enable = lib.mkOption { type = lib.types.bool; default = false; };
    stateDir = lib.mkOption { type = lib.types.str; default = "/var/lib/containerd"; };
  };

  config = lib.mkIf config.aos.containerd.enable {
    systemd.services.containerd = {
      description = "containerd container runtime";
      after = [ "network.target" "local-fs.target" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        ExecStart = "${pkgs.containerd}/bin/containerd --config /etc/containerd/config.toml";
        Type = "notify";
        Restart = "always";
        RestartSec = "5s";
        LimitNOFILE = 1048576;
        LimitNPROC = "infinity";
        LimitCORE = "infinity";
        Delegate = true;
        KillMode = "process";
      };
    };

    environment.etc."containerd/config.toml".text = ''
      version = 2
      [plugins."io.containerd.grpc.v1.cri"]
        sandbox_image = "registry.k8s.io/pause:3.10"
        [plugins."io.containerd.grpc.v1.cri".containerd]
          default_runtime_name = "runc"
          [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
            runtime_type = "io.containerd.runc.v2"
            [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
              SystemdCgroup = true
    '';
  };
}
```

### kubelet Configuration

```nix
# modules/kubernetes/kubelet.nix
{ config, pkgs, lib, ... }:
{
  options.aos.kubernetes = {
    enable = lib.mkOption { type = lib.types.bool; default = false; };
    role = lib.mkOption {
      type = lib.types.enum [ "worker" "control-plane" ];
      default = "worker";
    };
    clusterDNS = lib.mkOption { type = lib.types.str; default = "10.96.0.10"; };
    clusterDomain = lib.mkOption { type = lib.types.str; default = "cluster.local"; };
  };

  config = lib.mkIf config.aos.kubernetes.enable {
    systemd.services.kubelet = {
      description = "Kubernetes node agent";
      after = [ "containerd.service" "network-online.target" ];
      requires = [ "containerd.service" ];
      wantedBy = [ "multi-user.target" ];
      serviceConfig = {
        ExecStart = lib.concatStringsSep " " [
          "${pkgs.kubelet}/bin/kubelet"
          "--container-runtime-endpoint=unix:///run/containerd/containerd.sock"
          "--kubeconfig=/etc/kubernetes/kubelet.conf"
          "--config=/etc/kubernetes/kubelet-config.yaml"
        ];
        Restart = "always";
        RestartSec = "10s";
      };
    };
  };
}
```

### Network Configuration for Kubernetes

```nix
# modules/kubernetes/network.nix
{ config, pkgs, lib, ... }:
{
  config = lib.mkIf config.aos.kubernetes.enable {
    # Required kernel modules
    aos.boot.kernelModules = [
      "overlay"         # containerd overlay filesystem
      "br_netfilter"    # Bridge netfilter for CNI
      "ip_vs"           # IPVS load balancing
      "ip_vs_rr"        # Round-robin scheduler
      "ip_vs_wrr"       # Weighted round-robin
      "ip_vs_sh"        # Source hash
      "nf_conntrack"    # Connection tracking
    ];

    # Required sysctl settings
    aos.boot.sysctls = {
      "net.bridge.bridge-nf-call-iptables" = 1;
      "net.bridge.bridge-nf-call-ip6tables" = 1;
      "net.ipv4.ip_forward" = 1;
      "net.ipv4.conf.all.forwarding" = 1;
      "net.ipv6.conf.all.forwarding" = 1;
    };

    # Firewall rules for K8s traffic
    aos.firewall.allowedTCP = [
      10250  # kubelet API
      10256  # kube-proxy health
    ] ++ lib.optionals (config.aos.kubernetes.role == "control-plane") [
      6443   # Kubernetes API server
      2379   # etcd client
      2380   # etcd peer
      10257  # kube-controller-manager
      10259  # kube-scheduler
    ];

    # NodePort range
    aos.firewall.allowedTCP = lib.mkIf (config.aos.kubernetes.role == "worker")
      (lib.range 30000 32767);

    # VXLAN for overlay networking (Flannel/Cilium)
    aos.firewall.allowedUDP = [ 8472 ];
  };
}
```

### CNI Plugins

```nix
# pkgs/kubernetes/cni-plugins.nix
{ mkDerivation, fetchurl, versions, sources, go }:

mkDerivation {
  pname = "cni-plugins";
  version = versions.kubernetes.cni-plugins;  # "1.6.1"
  src = fetchurl sources.cni-plugins;

  buildDeps = [ go ];

  phases = [
    { name = "unpack"; script = "tar xf $src"; }
    {
      name = "build";
      script = ''
        export GOPATH=$TMPDIR/go
        ./build_linux.sh
      '';
    }
    {
      name = "install";
      script = ''
        mkdir -p $out/bin
        cp bin/* $out/bin/
      '';
    }
  ];
}
```

CNI plugins are installed to `/nix/store/.../bin/` and referenced by containerd's
configuration. The CNI config directory (`/etc/cni/net.d/`) is on the `/etc` overlay
and configured by kubeadm or the CNI provider.

### Fleet Updates for Kubernetes

Rolling updates across a K8s fleet follow a careful sequence:

1. **Cordon** the node (prevent new pod scheduling)
2. **Drain** existing pods (with grace period)
3. **Apply** the update bundle
4. **Reboot** into the new generation
5. **Health check** passes (kubelet rejoins, node becomes Ready)
6. **Uncordon** the node (resume pod scheduling)
7. **Repeat** for the next node

```bash
# deploy/scripts/fleet-update.sh (simplified)
for node in $(kubectl get nodes -o name); do
  echo "==> Updating $node"

  kubectl cordon "$node"
  kubectl drain "$node" --ignore-daemonsets --delete-emptydir-data --timeout=300s

  # Apply update via SSH
  ssh "$node" "aos-update apply /tmp/aos-update-${VERSION}.tar && reboot"

  # Wait for node to rejoin
  until kubectl get node "$node" | grep -q "Ready"; do
    sleep 10
  done

  kubectl uncordon "$node"
  echo "==> $node updated successfully"
done
```

---

## Summary

| Aspect | Implementation |
|--------|---------------|
| Image generation | `images/builder.nix` — GPT disk with ESP + ext4 root + ZFS space |
| Image command | `aos system image <variant>` |
| Store model | Content-addressed `/nix/store` with hash-derived paths |
| Generations | Boot entries in `/loader/entries/`, previous always available |
| Rollback | Automatic via boot counting, manual via `bootctl set-default` |
| Update bundles | `deploy/bundle.nix` — delta-compressed zstd archives with manifest |
| Bundle signing | `deploy/sign.nix` — minisign ed25519 signatures |
| Garbage collection | `modules/services/gc.nix` — keep N generations, delete unreferenced |
| First-boot | Ignition in initrd — ZFS pool, datasets, hostname, SSH keys |
| K8s integration | Layered modules: containerd, kubelet, CNI, network, control-plane |
| Fleet updates | Cordon/drain/update/reboot/health-check/uncordon per node |
