# Phase 4: Immutable Base Image Assembly

**Phase Number:** 4

## Objective

Assemble a bootable, immutable base image from the kernel, systemd, ZFS, and toolchain packages. The root filesystem is an ext4 golden image mounted read-only; ZFS is used for mutable data (`/var`, `/var/lib`, `/var/log`) and is created by Ignition on first boot. Define the partition layout (ESP + ext4 root + ZFS data), configure systemd-boot, generate UKIs, set up the read-only root filesystem with writable `/var` and `/etc` overlay, bake SELinux file contexts into the golden image, and produce the image via `guix system image`.

## Prerequisites

- Phase 3 complete: Kernel, systemd, ZFS modules, firmware, dracut/initrd, SELinux policy all building and verified
- Partition layout decided: ESP + ext4 root (immutable golden image) + ZFS data partition (mutable, created by Ignition)
- `/etc` management strategy decided (OverlayFS recommended)
- SELinux targeted policy and file contexts validated in Phase 3

## Deliverables

- `channel/andyl/system/base.scm` -- Base operating-system definition for Guix
- `channel/andyl/system/server.scm` -- Server-specific system configuration
- `channel/andyl/images/base.scm` -- Image definition with partition layout
- `channel/andyl/packages/image-tools.scm` -- UKI generation and image assembly tools
- Bootable raw disk image (`.img` or `.qcow2`) that boots in QEMU
- systemd-boot installed on ESP with UKI or Type #1 boot entries
- Read-only root filesystem with functional `/etc` overlay and writable `/var`
- Image manifest (JSON) listing all store paths and their hashes

## Detailed Task Checklist

### 4.1 Partition Layout Definition

The root filesystem is an ext4 golden image (immutable, mounted read-only).
ZFS is used for mutable data and is created by Ignition on first boot, not
at image build time.

- [ ] Partition 1: ESP (1 GiB, FAT32, label=ESP)
  - [ ] systemd-boot EFI binary
  - [ ] UKIs or Type #1 boot entries
  - [ ] `loader.conf`
- [ ] Partition 2: ANDYL-ROOT (8-16 GiB, ext4, mounted read-only at /)
  - [ ] Complete system closure: `/gnu/store`, `/usr`, `/etc` (base layer), kernel, systemd
  - [ ] SELinux file contexts baked in at build time (all files labeled)
  - [ ] SELinux policy package installed (`selinux-policy-targeted`, `container-selinux`)
  - [ ] ZFS kernel modules and userspace tools included (for post-boot data pool setup)
- [ ] Partition 3: ZFS data partition (remainder of disk)
  - [ ] Left empty at image build time
  - [ ] Ignition creates ZFS pool (`datapool`) on first boot with datasets:
    - [ ] `datapool/var` -- /var (writable)
    - [ ] `datapool/var-lib` -- /var/lib (persistent, writable)
    - [ ] `datapool/var-log` -- /var/log (persistent, writable)
    - [ ] `datapool/RESERVED` -- reserved space to prevent pool from filling
  - [ ] ZFS properties set by Ignition: compression=zstd, atime=off, xattr=sa, acltype=posixacl
- [ ] Optional: Swap partition (2-8 GiB) or use ZRAM for swap
- [ ] Document the chosen layout in a design decision record

### 4.2 Guix Operating System Definition

- [ ] Create `channel/andyl/system/base.scm`
- [ ] Define the `andyl-os-base` operating-system record:
  - [ ] Hostname: `andyl-os` (overridden by Ignition at deploy time)
  - [ ] Kernel: `andyl-kernel`
  - [ ] Initrd: custom initrd with systemd (no ZFS in initrd; root is ext4)
  - [ ] Init system: point to systemd (`/gnu/store/...-systemd/lib/systemd/systemd`)
  - [ ] Boot loader: systemd-boot on ESP
  - [ ] Firmware: `andyl-firmware` (stripped)
- [ ] Define base package list:
  - [ ] systemd (journald, networkd, resolved, timesyncd, udevd)
  - [ ] coreutils, bash, grep, sed, findutils, gawk
  - [ ] openssh-server
  - [ ] chrony (NTP)
  - [ ] node_exporter (Prometheus metrics)
  - [ ] ca-certificates
  - [ ] curl
  - [ ] ZFS kernel modules and userspace tools (zpool, zfs -- for mutable data pool)
  - [ ] SELinux userspace tools (policycoreutils, libselinux-utils, selinux-policy-targeted)
  - [ ] container-selinux policy module
  - [ ] andyl-selinux-policy (custom ANDYL OS policy package)
  - [ ] audit userspace tools (auditd, ausearch, aureport)
  - [ ] andyl-os-agent (placeholder -- update/health-check daemon)
  - [ ] Ignition binary (first-boot configuration: creates ZFS pool, seeds /etc, triggers relabeling)
- [ ] Define filesystem mount points:
  - [ ] Root: ext4 partition (ANDYL-ROOT, mounted read-only)
  - [ ] `/boot/efi` or `/boot`: ESP
  - [ ] `/var`: ZFS dataset (datapool/var, created by Ignition on first boot)
  - [ ] `/var/lib`: ZFS dataset (datapool/var-lib)
  - [ ] `/var/log`: ZFS dataset (datapool/var-log)
  - [ ] `/tmp`: tmpfs
  - [ ] `/run`: tmpfs
  - [ ] `/etc`: OverlayFS (lower=profile/etc from ext4 root, upper=/var/etc-overlay on ZFS)

### 4.3 /etc OverlayFS Setup

- [ ] Create a systemd mount unit for `/etc` overlay:
  - [ ] Lower directory: `/gnu/store/<hash>-andyl-os-system/etc` (read-only from profile)
  - [ ] Upper directory: `/var/etc-overlay` (writable, persistent)
  - [ ] Work directory: `/var/etc-overlay-work`
  - [ ] Mount unit ordered before `local-fs.target`, after `var.mount`
- [ ] Create tmpfiles.d entries to ensure upper/work directories exist
- [ ] Verify the overlay mounts correctly and changes to `/etc` persist across reboots
- [ ] Verify base files from profile are visible through the overlay

### 4.4 systemd-boot Installation

- [ ] Package systemd-boot EFI binary for installation on ESP
- [ ] Create `loader.conf` with:
  - [ ] `default andyl-os-*.conf` (wildcard for latest generation)
  - [ ] `timeout 3`
  - [ ] `editor no` (prevent boot-time parameter editing)
  - [ ] `console-mode max`
- [ ] Write initial boot loader entry for generation 1
- [ ] Install systemd-boot EFI binary to ESP `/EFI/systemd/systemd-bootx64.efi` and `/EFI/BOOT/BOOTX64.EFI`

### 4.5 UKI (Unified Kernel Image) Generation

- [ ] Package `ukify` tool (part of systemd)
- [ ] Create a build script that generates UKIs:
  - [ ] Bundle: kernel (vmlinuz) + early microcode (intel-ucode.img) + initramfs + kernel cmdline + os-release
  - [ ] Kernel cmdline: `root=/dev/disk/by-label/ANDYL-ROOT ro quiet console=ttyS0,115200n8 security=selinux selinux=1`
  - [ ] Output: `andyl-os-gen-1.efi`
- [ ] Place UKI on ESP at `/EFI/Linux/andyl-os-gen-1.efi`
- [ ] Alternatively, if not using UKIs, create Type #1 boot entries:
  - [ ] Copy vmlinuz and initrd to ESP
  - [ ] Write entry file with linux, initrd, and options fields

### 4.6 os-release File

- [ ] Create `/usr/lib/os-release` (or `/etc/os-release`) with:
  - [ ] `NAME="ANDYL OS"`
  - [ ] `ID=andyl-os`
  - [ ] `VERSION="0.1.0"` (parameterized)
  - [ ] `VERSION_ID=0.1.0`
  - [ ] `BUILD_ID=gen-1` (parameterized)
  - [ ] `PRETTY_NAME="ANDYL OS 0.1.0 (Generation 1)"`
  - [ ] `HOME_URL`, `BUG_REPORT_URL`

### 4.7 Read-Only Root Filesystem

- [ ] ext4 root partition is mounted read-only via kernel cmdline (`ro` flag)
- [ ] Verify `/gnu/store` is read-only at runtime
- [ ] Verify `/usr` is read-only (or served from store profile)
- [ ] Verify root cannot be remounted rw without modifying the UKI cmdline
- [ ] Create bind mounts from store profile directories to expected system paths:
  - [ ] `/gnu/store/<hash>-system/bin` accessible as system PATH entries
  - [ ] `/gnu/store/<hash>-system/lib/systemd/system` accessible to systemd

### 4.8 SELinux File Contexts and Labeling

SELinux file contexts must be baked into the ext4 golden image at build time.
The image ships fully labeled so no full-filesystem relabel is needed on first
boot. Only files created at runtime (by Ignition, ZFS dataset provisioning)
need targeted relabeling.

#### 4.8.1 SELinux Policy Package Inclusion

- [ ] Install SELinux targeted policy and file_contexts into the golden image:
  - [ ] `selinux-policy-targeted` package installed in system profile
  - [ ] `container-selinux` policy module installed
  - [ ] `andyl-selinux-policy` (custom ANDYL OS policy) installed
  - [ ] Policy files placed at `/etc/selinux/targeted/` (in the ext4 image, lower layer of /etc overlay)
  - [ ] Compiled policy binary (`policy.<version>`) present and loadable
- [ ] Package SELinux policy as a separate Guix package (`andyl-selinux-policy`) so it can be updated independently of the base image

#### 4.8.2 File Context Definitions for ANDYL OS Paths

- [ ] Define custom file context rules for ANDYL OS paths:
  - [ ] `/gnu/store(/.*)?` -- labeled as `usr_t` (or custom `guix_store_t` type)
  - [ ] `/var/lib/containers(/.*)?` -- labeled as `container_var_lib_t`
  - [ ] `/var/lib/kubelet(/.*)?` -- labeled as `container_var_lib_t`
  - [ ] `/var/etc-overlay(/.*)?` -- labeled to match corresponding `/etc` contexts
  - [ ] `/var/log/journal(/.*)?` -- labeled as `systemd_journal_t`
- [ ] Compile file_contexts into the binary format used by `setfiles` and `restorecon`
- [ ] Include compiled file_contexts in the golden image at `/etc/selinux/targeted/contexts/files/`

#### 4.8.3 restorecon During Image Build

- [ ] Run `setfiles` / `restorecon -R /` on the ext4 root filesystem at image build time:
  - [ ] All files in the ext4 golden image receive correct SELinux labels before the image is finalized
  - [ ] `/gnu/store` paths labeled as `usr_t` or `guix_store_t`
  - [ ] `/etc` (base layer) labeled with standard `etc_t` and service-specific contexts
  - [ ] `/usr` labeled with standard `usr_t`, `bin_t`, `lib_t` contexts
  - [ ] systemd units labeled as `systemd_unit_file_t`
  - [ ] Kernel modules labeled as `modules_object_t`
- [ ] Verify no unlabeled files exist: `restorecon -n -v -R /` should report no changes needed
- [ ] Verify no `unlabeled_t` contexts: `find / -context '*unlabeled_t*'` returns empty

#### 4.8.4 SELinux Mode Configuration

- [ ] Configure SELinux mode in the golden image:
  - [ ] `/etc/selinux/config`: `SELINUX=enforcing`, `SELINUXTYPE=targeted`
  - [ ] Initial images may ship with `SELINUX=permissive` until policy is fully validated
  - [ ] Kernel cmdline includes `security=selinux selinux=1` (in UKI)
  - [ ] Kernel cmdline includes `enforcing=0` for initial testing images, `enforcing=1` for production

#### 4.8.5 First-Boot Relabeling via Ignition

- [ ] Create Ignition-triggered relabeling on first boot:
  - [ ] Ignition writes files to `/etc` overlay upper layer; these need SELinux labels
  - [ ] Ignition creates ZFS datasets for `/var`, `/var/lib`, `/var/log`; new files need labels
  - [ ] Add a one-shot systemd unit (`andyl-os-relabel.service`) that runs:
    - [ ] `restorecon -R /etc` (relabel /etc overlay upper layer after Ignition writes)
    - [ ] `restorecon -R /var` (relabel ZFS mutable data after pool creation)
  - [ ] The unit should only run on first boot (conditioned on a flag file, e.g., `/var/.selinux-relabel-done`)
  - [ ] The unit must run after Ignition completes and after ZFS datasets are mounted
  - [ ] The unit must run before application services start (`Before=multi-user.target`)
- [ ] Verify: after first boot, `restorecon -n -v -R /var /etc` reports no changes needed

### 4.9 Profile and Symlink Structure

- [ ] Create the system profile directory structure:
  - [ ] `bin/` -- symlinks to all package binaries
  - [ ] `etc/` -- base configuration files
  - [ ] `lib/` -- libraries, kernel modules, firmware
  - [ ] `share/` -- shared data
  - [ ] `boot/` -- kernel and initrd symlinks
  - [ ] `manifest` -- JSON manifest of all paths
- [ ] Create generation symlink: `/var/guix/profiles/system-1` -> `/gnu/store/<hash>-andyl-os-system`
- [ ] Create "current" symlink: `/var/guix/profiles/system` -> `system-1`

### 4.10 Image Assembly with `guix system image`

- [ ] Create `channel/andyl/images/base.scm` with image definition
- [ ] Define partitions matching the chosen layout
- [ ] Configure partition initializers:
  - [ ] ESP initializer: install systemd-boot, UKI, loader.conf
  - [ ] Root initializer: populate from store closure with references-graphs
- [ ] Set image format: `disk-image` (raw) or convert to qcow2 post-build
- [ ] Set image size (8 GB initial, or `guess` for dynamic sizing)
- [ ] Build the image: `guix system image --image-type=disk-image andyl/images/base.scm`
- [ ] Convert to qcow2 if needed: `qemu-img convert -f raw -O qcow2`

### 4.11 Image Manifest Generation

- [ ] Generate a JSON manifest for the image:
  - [ ] `image_id`: unique identifier
  - [ ] `build_timestamp`: ISO 8601
  - [ ] `guix_commit`: channel commit hash
  - [ ] `system_profile`: store path of the system profile
  - [ ] `store_paths`: array of all store paths with nar_hash, nar_size, and references
  - [ ] `total_store_size` and `total_paths`
- [ ] Sign the manifest with the project signing key (minisign or signify)

### 4.12 Image Signing

- [ ] Generate Ed25519 signing keypair (if not already done)
- [ ] Sign the disk image with minisign: `minisign -Sm image.img -s andyl-os-sign.key`
- [ ] Embed the public key in the image (for update verification)
- [ ] Verify signature: `minisign -Vm image.img -p andyl-os-sign.pub`

### 4.13 Boot Verification in QEMU

- [ ] Boot the raw image in QEMU:
  - [ ] UEFI firmware (OVMF)
  - [ ] Serial console output
  - [ ] 4 GB RAM, 2 CPUs
- [ ] Verify:
  - [ ] UEFI firmware finds systemd-boot on ESP
  - [ ] systemd-boot loads the kernel + initrd (UKI)
  - [ ] Kernel boots, microcode applied
  - [ ] systemd in initrd starts
  - [ ] ext4 root partition mounted read-only
  - [ ] Ignition runs on first boot (creates ZFS data pool, writes /etc overlay, triggers relabeling)
  - [ ] switch-root to real root
  - [ ] systemd on real root starts
  - [ ] ZFS kernel module loads, datapool imported, `/var` datasets mounted
  - [ ] `/etc` overlay mounts correctly (lower=ext4 root /etc, upper=/var/etc-overlay on ZFS)
  - [ ] `/var` is writable (ZFS datapool)
  - [ ] `/gnu/store` is read-only (ext4 root)
  - [ ] `multi-user.target` reached
  - [ ] SSH is accessible
  - [ ] Network is configured (DHCP via networkd)
  - [ ] Journal is writing to `/var/log/journal/` (on ZFS)
  - [ ] `os-release` shows correct ANDYL OS info
  - [ ] `getenforce` reports `Permissive` or `Enforcing` (SELinux is active)
  - [ ] `sestatus` shows loaded policy (`targeted`) and correct mode
  - [ ] No critical AVC denials in `ausearch -m avc` output that block core services
  - [ ] SELinux file contexts are present on `/gnu/store` (from golden image), `/etc`, `/var` (from first-boot relabeling)
  - [ ] `restorecon -n -v -R /` reports no changes needed (all files correctly labeled)

### 4.14 justfile Targets

- [ ] Add `build-image` target: builds the raw disk image
- [ ] Add `build-vm` target: builds a QEMU-compatible image
- [ ] Add `boot-vm` target: boots the image in QEMU with serial console
- [ ] Add `image-manifest` target: generates the JSON manifest
- [ ] Add `image-sign` target: signs the image

## Acceptance Criteria

1. A bootable disk image is produced by `guix system image`
2. The image boots in QEMU with UEFI firmware to a functional systemd-managed system
3. Root filesystem is ext4 mounted read-only (immutable golden image)
4. `/etc` overlay is functional -- base config visible from ext4 root, changes persist in ZFS upper layer
5. `/var` is writable on ZFS datapool (created by Ignition on first boot) and persists across reboots
6. `/gnu/store` is read-only (part of ext4 root) and contains the full system closure
7. SSH access works after boot
8. systemd journal writes to `/var/log/journal/` (on ZFS datapool)
9. Image manifest accurately lists all store paths with correct hashes
10. Image signature verifies correctly
11. SELinux is active on boot (`getenforce` returns `Permissive` or `Enforcing`)
12. All files in the ext4 golden image have correct SELinux labels baked in at build time (no `unlabeled_t` contexts)
13. SELinux targeted policy and `container-selinux` module are installed and loadable in the golden image
14. First-boot relabeling service (`andyl-os-relabel.service`) runs successfully after Ignition provisions ZFS datasets and writes to `/etc` overlay
15. After first-boot relabeling, `restorecon -n -v -R /var /etc` reports no changes needed

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| `guix system image` doesn't support our custom init (systemd) | High | Must work around Guix's Shepherd assumption | May need to bypass `guix system image` and assemble the image manually using `guix system build` + custom assembly script |
| ext4 root boot fails | Low | Image won't boot | ext4 is well-supported; use `by-label` device references for portability |
| ZFS data pool creation fails on first boot | Medium | /var not available | Ignition must handle errors gracefully; include fallback tmpfs /var |
| OverlayFS on /etc interacts poorly with systemd expectations | Medium | Services fail to start | Test thoroughly; fall back to tmpfiles.d factory model if needed |
| ESP sizing miscalculation | Low | Boot failure after multiple generations | Use 1 GiB ESP (generous); monitor usage |
| OVMF (UEFI firmware) not available in Docker build env | Medium | Can't test boot flow during build | Install OVMF as a build-time dependency; test only in QEMU on host |
| Image size too large for practical deployment | Low | Slow deployment | Monitor store closure size; run GC before image assembly |
| SELinux labeling fails on Guix store paths | Medium | AVC denials on boot | Define custom file_contexts for /gnu/store; run setfiles at image build time; validate with restorecon -n |
| SELinux + OverlayFS /etc interaction causes denials | Medium | Services fail to read /etc | Test overlay xattr inheritance thoroughly; add policy exceptions for overlay-specific transitions |
| SELinux labels missing on ZFS mutable data after first boot | Medium | AVC denials on /var paths | First-boot relabeling service must run after Ignition and ZFS mount; validate with restorecon -n |

## Estimated Complexity

**L (Large)**

Image assembly integrates all previous phases into a single bootable artifact. The complexity lies in the boot flow (UEFI -> systemd-boot -> kernel -> systemd initrd -> ext4 root mount -> Ignition -> switch-root -> systemd -> ZFS data pool import), the filesystem layout (read-only ext4 root, overlay /etc, writable /var on ZFS), SELinux labeling (baked into golden image at build time, first-boot relabeling for Ignition-created files), and the interaction between Guix's image tooling and our custom systemd-based system. Debugging boot failures requires understanding every layer of the stack.
