# Phase 4: Disk Image Builder

**Plan Phase:** 8 (Disk Image Builder)

## Objective

Build the disk image assembly pipeline (`images/`) that takes an evaluated AOS system configuration and produces a bootable raw disk image. The `buildAndylImage` derivation computes the store closure, creates a GPT-partitioned disk (ESP + read-only ext4 root + reserved ZFS space), installs systemd-boot, bakes SELinux file contexts into the golden image, and outputs a raw disk image that boots in QEMU or on bare metal.

## Prerequisites

- Phase 1-3 complete: All packages build, system modules evaluate
- System variants (`systems/`) compose modules into complete configurations (covered in Plan Phase 7)
- Module system produces a system closure with all required packages, systemd units, config files
- SELinux targeted policy and file contexts validated

## Deliverables

- `images/builder.nix` -- `buildAndylImage` derivation (the core image builder)
- `images/base.nix` -- Base image definition (16 GiB)
- `images/server.nix` -- Server image definition (16 GiB)
- `images/k8s-worker.nix` -- K8s worker image definition (32 GiB)
- `images/k8s-control-plane.nix` -- K8s control plane image definition (32 GiB)
- Bootable raw disk images (`.raw`) for each variant
- systemd-boot installed on ESP with Type #1 boot entries
- Read-only ext4 root with functional `/etc` overlay and writable `/var` (ZFS, created by Ignition)
- SELinux file contexts baked into the golden image at build time

## Detailed Task Checklist

### 4.1 Image Builder Derivation

- [ ] Write `images/builder.nix` defining `buildAndylImage`:
  - [ ] Input: evaluated system config (from `lib.evalModules`)
  - [ ] Compute store closure via Nix's native `closureInfo`
  - [ ] Run in a VM (`builtins.derivation` with `requiredSystemFeatures = ["kvm"]`) for privileged access to loop devices
  - [ ] Create GPT disk layout:
    - [ ] Partition 1: ESP (1 GiB, FAT32, label=ESP)
    - [ ] Partition 2: ANDYL-ROOT (ext4, read-only, sized per variant)
    - [ ] Partition 3: Reserved for ZFS data (remainder of disk, left empty)
  - [ ] Populate root partition from store closure
  - [ ] Install systemd-boot on ESP
  - [ ] Generate Type #1 boot entry
  - [ ] Write `loader.conf` (`default`, `timeout 3`, `editor no`)
  - [ ] Run `setfiles` / `restorecon -R /` to bake SELinux labels into the image
  - [ ] Output: raw disk image

### 4.2 Partition Layout

- [ ] ESP (1 GiB FAT32):
  - [ ] systemd-boot EFI binary at `/EFI/systemd/systemd-bootx64.efi` and `/EFI/BOOT/BOOTX64.EFI`
  - [ ] Type #1 boot entry
  - [ ] `loader.conf` with boot counting disabled by default
- [ ] ANDYL-ROOT (ext4, mounted read-only at `/`):
  - [ ] Complete system closure in `/nix/store/`
  - [ ] System profile symlinks
  - [ ] Base `/etc` (lower layer for overlay)
  - [ ] SELinux policy and compiled file contexts
  - [ ] ZFS kernel modules + userspace tools (for post-boot data pool setup)
- [ ] ZFS data partition (remainder):
  - [ ] Left empty at image build time
  - [ ] Ignition creates ZFS pool (`datapool`) on first boot
  - [ ] Datasets: `datapool/var`, `datapool/var-lib`, `datapool/var-log`
  - [ ] ZFS properties: compression=zstd, atime=off, xattr=sa, acltype=posixacl

### 4.3 Boot Configuration

- [ ] Kernel cmdline: `root=/dev/disk/by-label/ANDYL-ROOT ro quiet console=ttyS0,115200n8 security=selinux selinux=1`
- [ ] Boot counting protocol: entry format `andyl-os-<N>+<tries_left>-<tries_done>.efi`

### 4.4 os-release File

- [ ] Generate `/usr/lib/os-release`:
  - [ ] `NAME="ANDYL OS"`
  - [ ] `ID=andyl-os`
  - [ ] `VERSION="0.1.0"` (from system config)
  - [ ] `BUILD_ID=gen-1`
  - [ ] `PRETTY_NAME="ANDYL OS 0.1.0 (Generation 1)"`
  - [ ] `HOME_URL`, `BUG_REPORT_URL`

### 4.5 Read-Only Root and Filesystem Layout

- [ ] ext4 root mounted read-only via kernel cmdline (`ro` flag)
- [ ] `/nix/store` is read-only (part of ext4 root)
- [ ] `/etc` is an OverlayFS (lower=profile/etc from ext4, upper=/var/etc-overlay on ZFS)
- [ ] `/var` is writable on ZFS (created by Ignition on first boot)
- [ ] `/tmp` and `/run` are tmpfs
- [ ] Create bind mounts from store profile to expected system paths

### 4.6 /etc OverlayFS Setup

- [ ] systemd mount unit for `/etc` overlay:
  - [ ] Lower: `/nix/store/<hash>-system/etc` (from profile, read-only)
  - [ ] Upper: `/var/etc-overlay` (writable, on ZFS)
  - [ ] Work: `/var/etc-overlay-work`
  - [ ] Ordered: before `local-fs.target`, after `var.mount`
- [ ] tmpfiles.d entries to ensure upper/work directories exist
- [ ] Changes to `/etc` persist across reboots (upper layer on ZFS)

### 4.7 SELinux Labels in Golden Image

- [ ] Run `setfiles` / `restorecon -R /` on the ext4 root at build time:
  - [ ] `/nix/store` paths labeled as `usr_t` (or custom `nix_store_t`)
  - [ ] `/etc` base layer labeled with standard contexts
  - [ ] systemd units labeled as `systemd_unit_file_t`
  - [ ] Kernel modules labeled as `modules_object_t`
- [ ] Verify no `unlabeled_t` contexts exist in the image
- [ ] First-boot relabeling service for Ignition-created files:
  - [ ] Runs after Ignition and ZFS mount
  - [ ] `restorecon -R /etc /var`
  - [ ] Conditioned on marker file (runs only once)

### 4.8 Image Variant Definitions

- [ ] Write `images/base.nix`: 16 GiB (1 GiB ESP + 8 GiB root + 7 GiB ZFS)
- [ ] Write `images/server.nix`: 16 GiB (same layout, server system config)
- [ ] Write `images/k8s-worker.nix`: 32 GiB (1 GiB ESP + 12 GiB root + 19 GiB ZFS)
- [ ] Write `images/k8s-control-plane.nix`: 32 GiB (same layout, control plane config)

### 4.9 System Profile and Symlinks

- [ ] System profile directory: `bin/`, `etc/`, `lib/`, `share/`, `boot/`, `manifest`
- [ ] Generation symlink: `/nix/var/nix/profiles/system-1` -> `/nix/store/<hash>-system`
- [ ] Current symlink: `/nix/var/nix/profiles/system` -> `system-1`

### 4.10 Image Signing

- [ ] Sign disk images with minisign (Ed25519)
- [ ] Embed the public key in the image (for update verification)
- [ ] Verify: `minisign -Vm image.raw -p andyl-os-sign.pub`

### 4.11 Boot Verification

- [ ] Boot each variant in QEMU:
  - [ ] UEFI firmware (OVMF), serial console, 4 GB RAM, 2 CPUs
  - [ ] UEFI finds systemd-boot on ESP
  - [ ] systemd-boot loads kernel + initrd
  - [ ] systemd in initrd starts
  - [ ] ext4 root mounted read-only
  - [ ] Ignition runs on first boot (creates ZFS pool, writes /etc overlay)
  - [ ] switch-root to real root
  - [ ] ZFS module loads, datapool imported, `/var` datasets mounted
  - [ ] `/etc` overlay mounts correctly
  - [ ] `multi-user.target` reached
  - [ ] SSH accessible, network configured (DHCP via systemd-networkd)
  - [ ] SELinux active (`getenforce` reports mode)
  - [ ] `os-release` shows correct info
- [ ] Verify: `aos system image server` produces `output/aos-server.raw`

## Acceptance Criteria

1. `buildAndylImage` produces a bootable raw disk image from an evaluated system config
2. Image boots in QEMU with UEFI firmware to a functional systemd-managed system
3. Root filesystem is ext4 mounted read-only
4. `/etc` overlay is functional (base from ext4, changes persist in ZFS upper layer)
5. `/var` is writable on ZFS (created by Ignition on first boot)
6. `/nix/store` is read-only
7. SSH access works after boot
8. SELinux is active and all files have correct labels
9. All four image variants (base, server, k8s-worker, k8s-control-plane) build successfully
10. Images are signed and signature verification works
11. `aos system image server` is the primary build command

## Key Design Decisions

### Image Builder Runs in a VM

The image builder uses `requiredSystemFeatures = ["kvm"]` because creating partitions and filesystems requires privileged access to loop devices. This is a standard Nix pattern -- the build VM is hermetic and its output is deterministic.

### No Activation Scripts

Unlike NixOS, AOS has no imperative "activation scripts" that run at switch time. The system image contains the complete filesystem. First-boot provisioning (ZFS pool creation, /etc seeding) is handled by Ignition, which runs once in the initrd. Subsequent boots find everything already set up.

### ZFS Created at Runtime, Not Build Time

The ZFS data partition is left empty in the image. Ignition creates the pool and datasets on first boot, setting per-dataset properties (compression, recordsize) based on the machine's role. This avoids baking machine-specific state into the golden image.

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Image builder requires KVM, not available on all build machines | Medium | Can't build images without KVM | Require KVM on build machines; document hardware requirements |
| ext4 root + ZFS data boot flow is complex | Medium | Boot failures | Test each stage independently; capture serial logs |
| ZFS pool creation fails on first boot | Medium | No writable /var | Ignition must handle errors; include fallback tmpfs /var |
| OverlayFS /etc interacts poorly with systemd | Medium | Services fail to start | Test thoroughly; fall back to tmpfiles.d factory model if needed |
| SELinux labeling at build time is slow | Low | Build time increases | Labels are only applied once during image build; cached by Nix |
| Image size too large for deployment | Low | Slow deployment | Monitor closure sizes; `aos test build` checks closure bounds |
