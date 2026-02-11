# Phase 3: Custom Kernel Build, systemd Packaging, and ZFS Module Build

**Phase Number:** 3

## Objective

Build a custom Linux kernel (6.12 LTS) with server-optimized configuration fragments, package systemd as the init system (replacing Guix's Shepherd), and build OpenZFS kernel modules and userspace tools as Guix packages.

## Prerequisites

- Phase 2 complete: Full toolchain (GCC, glibc, binutils, make, coreutils) available in the ANDYL channel
- Kernel config fragment strategy decided (defconfig + overlay)
- LTS kernel series selected (6.12.x recommended)
- OpenZFS version confirmed compatible with chosen kernel (2.3.x for 6.12)

## Deliverables

- `kernel/base.config` -- Core kernel config fragment (cgroups, namespaces, security)
- `kernel/storage.config` -- Storage fragment (ZFS deps, NVMe, virtio-blk, dm-verity)
- `kernel/networking.config` -- Networking fragment (netfilter, eBPF, virtio-net)
- `kernel/virtualization.config` -- KVM and vhost fragment
- `kernel/security.config` -- SELinux, IMA, seccomp fragment
- `kernel/drivers-vm.config` -- Virtio driver fragment
- `kernel/drivers-cloud.config` -- AWS/GCP/Azure driver fragment
- `kernel/drivers-baremetal.config` -- Server NIC/storage controller fragment
- `kernel/Makefile` -- Fragment merge script
- `channel/andyl/packages/kernel.scm` -- Kernel package definition
- `channel/andyl/packages/systemd.scm` -- systemd package definition and unit files
- `channel/andyl/packages/zfs.scm` -- OpenZFS kernel modules and userspace tools
- `channel/andyl/packages/firmware.scm` -- Stripped firmware package
- `channel/andyl/packages/dracut.scm` -- dracut initrd generator package
- Working kernel that boots in QEMU with systemd as PID 1

## Detailed Task Checklist

### 3.1 Kernel Config Fragment System

- [ ] Create `kernel/` directory at project root
- [ ] Write `kernel/base.config` with core options:
  - [ ] Cgroups v2 unified hierarchy (`CONFIG_CGROUPS=y`, `CONFIG_CGROUP_V2=y`, all controllers)
  - [ ] All namespace types (UTS, IPC, USER, PID, NET, CGROUP, TIME)
  - [ ] PSI (Pressure Stall Information) enabled
  - [ ] OverlayFS with all extensions (redirect_dir, metacopy, index, nfs_export, xino_auto)
  - [ ] Block layer essentials (loop, zram, device-mapper)
- [ ] Write `kernel/storage.config`:
  - [ ] ZFS prerequisites: POSIX ACLs, crypto modules (deflate, lz4, lz4hc, zstd, sha256, sha512, aes, skcipher)
  - [ ] NVMe support (built-in: `CONFIG_BLK_DEV_NVME=y`)
  - [ ] AHCI SATA (built-in)
  - [ ] dm-crypt, dm-snapshot
  - [ ] Unicode support for ZFS datasets
- [ ] Write `kernel/networking.config`:
  - [ ] eBPF full stack: `BPF=y`, `BPF_SYSCALL=y`, `BPF_JIT=y`, `BPF_JIT_ALWAYS_ON=y`, `BPF_LSM=y`
  - [ ] BTF for CO-RE: `DEBUG_INFO_BTF=y`, `DEBUG_INFO_BTF_MODULES=y`
  - [ ] BPF networking: stream parser, lwtunnel, net_act, net_cls
  - [ ] Kprobes/uprobes/ftrace for tracing
  - [ ] Bridge, VXLAN, IP_VS (for k8s networking)
  - [ ] Netfilter conntrack and comment matching
- [ ] Write `kernel/virtualization.config`:
  - [ ] KVM: Intel and AMD modules
  - [ ] vhost: net, scsi, vsock
  - [ ] IOMMU: Intel and AMD
  - [ ] VFIO for device passthrough
  - [ ] Huge pages: hugetlbfs, transparent hugepages
- [ ] Write `kernel/security.config`:
  - [ ] SELinux as default LSM (`CONFIG_SECURITY_SELINUX=y`, `CONFIG_DEFAULT_SECURITY_SELINUX=y`)
  - [ ] SELinux boot param support (`CONFIG_SECURITY_SELINUX_BOOTPARAM=y`)
  - [ ] SELinux development mode (`CONFIG_SECURITY_SELINUX_DEVELOP=y`)
  - [ ] SELinux AVC stats (`CONFIG_SECURITY_SELINUX_AVC_STATS=y`)
  - [ ] Audit subsystem (`CONFIG_AUDIT=y`, `CONFIG_AUDITSYSCALL=y`)
  - [ ] Yama (ptrace restrictions)
  - [ ] Seccomp and seccomp filter
  - [ ] Landlock
  - [ ] IMA/EVM for integrity measurement
  - [ ] Lockdown LSM with integrity enforcement
  - [ ] Stack protector strong
  - [ ] BPF_UNPRIV_DEFAULT_OFF
- [ ] Write `kernel/drivers-vm.config`:
  - [ ] All virtio drivers: PCI, BLK, SCSI, NET, console, balloon, RNG, FS, GPU, input, vsock
  - [ ] Boot-critical drivers as built-in (`=y`): virtio-blk, virtio-net, virtio-pci
  - [ ] Non-boot-critical as modules (`=m`): virtio-gpu, virtio-fs
- [ ] Write `kernel/drivers-cloud.config`:
  - [ ] AWS: ENA ethernet, NVMe, Xen (PV, PVHVM, blkdev, netdev), EFA, serial 8250
  - [ ] GCP: gVNIC (GVE), ACPI support
  - [ ] Azure: Hyper-V core, VMBus, network, storage, keyboard, balloon, framebuffer
- [ ] Write `kernel/drivers-baremetal.config`:
  - [ ] Intel NICs: e1000e, igb, ixgbe, i40e, ice (as modules)
  - [ ] Mellanox NICs: mlx4, mlx5 (as modules)
  - [ ] Broadcom NICs: bnxt, bnx2x (as modules)
  - [ ] Storage controllers: MegaRAID, MPT3SAS, SmartPQI, HPSA (as modules)
  - [ ] IPMI handler and interfaces (as modules)
- [ ] Write `kernel/Makefile` to merge all fragments:
  - [ ] Start from `make defconfig`
  - [ ] Use `scripts/kconfig/merge_config.sh` to overlay each fragment
  - [ ] Output final `.config` file

### 3.2 Kernel Package Definition

- [ ] Create/update `channel/andyl/packages/kernel.scm`
- [ ] Define `andyl-kernel` package (version 6.12.x LTS)
- [ ] Source: kernel.org CDN (NOT linux-libre -- we need firmware loading support)
- [ ] Pin sha256 hash
- [ ] Build with `gnu-build-system`
- [ ] Replace `configure` phase: copy merged config, run `make olddefconfig`
- [ ] Replace `build` phase: `make -j$(nproc) bzImage modules`
- [ ] Replace `install` phase:
  - [ ] Install modules with `make modules_install INSTALL_MOD_PATH=$out`
  - [ ] Install bzImage to `$out/boot/`
  - [ ] Install System.map to `$out/boot/`
  - [ ] Install kernel headers for out-of-tree module builds (`make headers_install`)
- [ ] Preserve build directory (Module.symvers, full source) in a separate output for ZFS builds
- [ ] Native inputs: perl, flex, bison, elfutils, bc, openssl, kmod
- [ ] Set `#:tests? #f`
- [ ] Build and verify: kernel image and modules produced

### 3.3 systemd Package Definition

- [ ] Create `channel/andyl/packages/systemd.scm`
- [ ] Define `andyl-systemd` package (systemd 255+)
- [ ] Source: systemd GitHub release tarball
- [ ] Build with `meson-build-system`
- [ ] Configure essential components:
  - [ ] journald, networkd, resolved, timesyncd
  - [ ] tmpfiles.d, sysusers.d
  - [ ] systemd-boot, ukify
  - [ ] systemd-repart, systemd-sysext
  - [ ] systemd-oomd, systemd-cryptsetup
  - [ ] systemd-bless-boot
  - [ ] udevd
- [ ] Disable unnecessary components:
  - [ ] systemd-homed (not needed for servers)
  - [ ] GUI-related features
- [ ] Inputs: `andyl-glibc`, `andyl-linux-headers`, `andyl-openssl`, `andyl-zstd`, `andyl-lz4`, `andyl-xz-utils`, libcap, util-linux, kmod
- [ ] Build and verify: `systemctl --version` outputs correctly

### 3.4 systemd Unit Files Package

- [ ] Create `channel/andyl/packages/systemd-units.scm` or extend `systemd.scm`
- [ ] Define `andyl-base-services` package containing base systemd unit files:
  - [ ] `systemd-networkd.service` configuration
  - [ ] `systemd-resolved.service` configuration
  - [ ] `systemd-timesyncd.service` configuration
  - [ ] `systemd-journald.service` configuration
  - [ ] `andyl-os-health-check.service` (post-boot health check)
  - [ ] `systemd-bless-boot.service` (boot counting integration)
- [ ] Create tmpfiles.d configuration (`andyl-os.conf`):
  - [ ] `/var/log`, `/var/lib`, `/var/cache`, `/var/tmp`, `/var/spool` directories
  - [ ] `/run/andyl` runtime directory
  - [ ] machine-id factory default
- [ ] Create sysusers.d configuration:
  - [ ] root, nobody system users
  - [ ] wheel, systemd-journal groups
  - [ ] systemd-network, systemd-resolve, systemd-timesync service users
- [ ] Create networkd default configuration (DHCP on ethernet interfaces)
- [ ] Install all units using `copy-build-system` to `lib/systemd/system/`

### 3.5 OpenZFS Kernel Modules

- [ ] Create `channel/andyl/packages/zfs.scm`
- [ ] Define `andyl-zfs-modules` package (OpenZFS 2.3.x)
- [ ] Source: OpenZFS GitHub release tarball
- [ ] Build with `gnu-build-system`
- [ ] Configure flags: `--with-linux=` and `--with-linux-obj=` pointing to `andyl-kernel`, `--with-config=kernel`
- [ ] Inputs: `andyl-kernel` (with build directory available)
- [ ] Native inputs: which, pkg-config
- [ ] Install kernel modules to output path
- [ ] Build and verify: `zfs.ko` and related modules exist in output

### 3.6 OpenZFS Userspace Tools

- [ ] Define `andyl-zfs-tools` package (inheriting from `andyl-zfs-modules`)
- [ ] Override configure: `--with-config=user` (userspace tools only)
- [ ] Produce `zpool`, `zfs`, `mount.zfs`, `zdb`, `zed`, and related utilities
- [ ] Build and verify: `zpool --version` works

### 3.7 Module Merge and depmod

- [ ] Create a package or build script that merges kernel modules with ZFS modules:
  - [ ] Union-merge `andyl-kernel/lib/modules/<version>/` with `andyl-zfs-modules/lib/modules/<version>/`
  - [ ] Run `depmod` at build time to generate `modules.dep`, `modules.alias`, etc.
- [ ] Verify: `modinfo zfs` resolves correctly from the merged module tree

### 3.8 Firmware Package

- [ ] Create `channel/andyl/packages/firmware.scm`
- [ ] Define `andyl-firmware` package
- [ ] Source: linux-firmware.git from kernel.org, pinned commit
- [ ] Use `copy-build-system` with selective install plan:
  - [ ] `intel-ucode/` -- Intel CPU microcode
  - [ ] `amd-ucode/` -- AMD CPU microcode
  - [ ] `intel/ice/` -- Intel 100GbE NIC firmware
  - [ ] `mellanox/` -- Mellanox NIC firmware
  - [ ] `bnxt/` -- Broadcom NIC firmware
  - [ ] `bnx2x/` -- Broadcom legacy NIC firmware
  - [ ] `qed/` -- QLogic/Marvell firmware
- [ ] Verify stripped firmware is ~20 MB (vs. 862 MB full)
- [ ] Build and verify

### 3.9 dracut Initrd Generator

- [ ] Create `channel/andyl/packages/dracut.scm`
- [ ] Define `andyl-dracut` package
- [ ] Source: dracut GitHub release tarball
- [ ] Configure with systemd support and ZFS module
- [ ] This package is used at image build time, not installed on target machines
- [ ] Build and verify

### 3.10 Initrd Generation Script

- [ ] Create a build script/package that generates the initramfs using dracut:
  - [ ] `--add "systemd"` for systemd-based initrd (ZFS is NOT needed in initrd; root is ext4)
  - [ ] `--no-hostonly` for generic initrd (not tailored to build host)
  - [ ] `--no-early-microcode` (microcode prepended separately)
  - [ ] Include systemd-udevd for device enumeration
  - [ ] Include Ignition binary for first-boot provisioning (creates ZFS data pool)
- [ ] Create separate early microcode initrd for CPU microcode
- [ ] Verify: initrd contains systemd, udevd, and Ignition; boots ext4 root correctly

### 3.11 Integration Verification

- [ ] Assemble a minimal boot test: kernel + initrd + systemd
- [ ] Boot in QEMU with serial console
- [ ] Verify kernel boots and hands off to systemd in initrd
- [ ] Verify systemd reaches default target
- [ ] Verify ZFS module loads successfully
- [ ] Verify no kernel panics or critical errors in dmesg

### 3.12 SELinux Policy Development and Userspace

SELinux is the definitive mandatory access control system for ANDYL OS. This
section covers packaging the SELinux userspace stack, developing targeted
policy, generating file contexts, and verifying enforcement.

#### 3.12.1 SELinux Userspace Packaging

- [ ] Package `libselinux` as a Guix package (required by SELinux-aware userspace tools)
- [ ] Package `libsepol` and `libsemanage` as Guix packages
- [ ] Package `policycoreutils` (sestatus, semanage, restorecon, audit2allow, semodule)
- [ ] Package `checkpolicy` (SELinux policy compiler)
- [ ] Package `selinux-policy-targeted` (reference targeted policy from Fedora/RHEL)
- [ ] Package `container-selinux` policy module (required for CRI-O / containerd)
- [ ] Package `setools` (sesearch, seinfo -- for policy analysis and debugging)
- [ ] Package `audit` userspace tools (auditd, ausearch, aureport -- required for SELinux audit logging)

#### 3.12.2 SELinux Policy Development

- [ ] Develop or adapt targeted policy for ANDYL OS:
  - [ ] Base policy modules for systemd services (journald, networkd, resolved, timesyncd)
  - [ ] Policy module for ZFS tools (zpool, zfs, zed) -- needed for mutable data pool operations
  - [ ] Policy module for Ignition first-boot service (creates ZFS pool, writes /etc overlay, triggers relabeling)
  - [ ] Policy module for sysext overlay operations
  - [ ] Policy module for the ANDYL OS update agent
  - [ ] Unconfined domain for interactive admin sessions
  - [ ] Container runtime policy: ensure `container-selinux` module integrates with CRI-O and containerd
  - [ ] Kubernetes-specific contexts: `kubelet_t`, integration with Pod SecurityContext `seLinuxOptions`
- [ ] Define ANDYL OS-specific SELinux types:
  - [ ] `guix_store_t` for `/gnu/store` content (or map to `usr_t` if sufficient)
  - [ ] `andyl_etc_overlay_t` for `/var/etc-overlay` upper layer
  - [ ] `andyl_zfs_data_t` for ZFS mutable data datasets

#### 3.12.3 File Context Generation

- [ ] Create file_contexts entries for ANDYL OS-specific paths:
  - [ ] `/gnu/store(/.*)?` -- labeled as `usr_t` or custom `guix_store_t`
  - [ ] `/var/etc-overlay(/.*)?` -- labeled to match corresponding `/etc` contexts
  - [ ] `/var/lib/containers(/.*)?` -- labeled as `container_var_lib_t`
  - [ ] `/var/lib/kubelet(/.*)?` -- labeled as `container_var_lib_t`
  - [ ] `/var/log/journal(/.*)?` -- labeled as `systemd_journal_t`
- [ ] Generate compiled file_contexts for use by `setfiles` and `restorecon`
- [ ] Verify file_contexts cover all paths in the ext4 golden image and ZFS mutable data

#### 3.12.4 Labeling Verification

- [ ] Verify SELinux labels on the immutable ext4 root filesystem:
  - [ ] Run `setfiles` / `restorecon -R /` against the built image at image build time
  - [ ] Verify `/gnu/store` paths carry appropriate labels (e.g., `usr_t` or custom `guix_store_t`)
  - [ ] Verify `/etc` overlay lower layer (in the ext4 image) is labeled correctly
  - [ ] Verify no unlabeled files exist: `find / -context '*unlabeled_t*'` returns empty
- [ ] Verify labeling of ZFS mutable data:
  - [ ] First-boot Ignition provisioning must apply correct labels to newly created ZFS datasets
  - [ ] `/var`, `/var/lib`, `/var/log` must carry correct context after Ignition runs
- [ ] Verify OverlayFS `/etc` labeling:
  - [ ] Lower layer (ext4 image) xattrs are readable through the overlay
  - [ ] New files in upper layer receive correct labels via transition rules or `restorecon`
  - [ ] SELinux `security.selinux` xattrs work correctly with OverlayFS

#### 3.12.5 Permissive-to-Enforcing Transition Testing

- [ ] Phase 1 -- Permissive mode testing:
  - [ ] Add boot parameters: `security=selinux selinux=1 enforcing=0`
  - [ ] Boot the system and collect all AVC denials with `ausearch -m avc`
  - [ ] Categorize denials: legitimate policy gaps vs. application bugs
  - [ ] Use `audit2allow` to generate candidate policy modules for legitimate gaps
  - [ ] Review and refine generated modules (do NOT blindly apply audit2allow output)
- [ ] Phase 2 -- Targeted enforcing:
  - [ ] Enable enforcing mode: change boot parameter to `enforcing=1`
  - [ ] Verify core services start without AVC denials:
    - [ ] systemd (PID 1), journald, networkd, resolved, timesyncd
    - [ ] ZFS pool import and dataset mount
    - [ ] SSH daemon
    - [ ] `/etc` overlay mount
  - [ ] Verify container workloads receive `container_t` context and run without denials
  - [ ] Run full system test suite in enforcing mode
- [ ] Phase 3 -- Production hardening:
  - [ ] Remove `CONFIG_SECURITY_SELINUX_DEVELOP=y` from kernel config (prevents runtime disable)
  - [ ] Set `SELINUX=enforcing` in `/etc/selinux/config` as the image default
  - [ ] Ensure no `permissive` domain exceptions remain in production policy
  - [ ] Document any `dontaudit` rules and their rationale

### 3.13 justfile Targets

- [ ] Add `build-kernel` target: builds the kernel package
- [ ] Add `build-systemd` target: builds systemd and unit files
- [ ] Add `build-zfs` target: builds ZFS modules and tools
- [ ] Add `build-initrd` target: generates initramfs
- [ ] Add `kernel-config` target: merges config fragments and outputs final `.config`

## Acceptance Criteria

1. Kernel builds successfully from kernel.org source with custom config fragments
2. All kernel config requirements are met (cgroups v2, namespaces, eBPF, overlayfs, ZFS prerequisites, SELinux, audit subsystem)
3. systemd builds and all essential components are functional (journald, networkd, resolved, timesyncd, udevd)
4. OpenZFS kernel modules build against the custom kernel and `modinfo zfs` reports correct version
5. OpenZFS userspace tools (`zpool`, `zfs`) are functional
6. dracut generates a systemd-based initrd that boots ext4 root (ZFS not required in initrd)
7. A minimal boot test in QEMU shows kernel + systemd reaching the default target with ext4 root
8. Firmware package is stripped to ~20 MB containing only server-relevant blobs
9. SELinux userspace tools are packaged and functional (sestatus, getenforce report correct mode)
10. Targeted SELinux policy loads successfully and the system boots in permissive mode without critical AVC denials
11. SELinux file contexts are defined for all ANDYL OS-specific paths (/gnu/store, /var/etc-overlay, container paths)
12. Permissive-to-enforcing transition plan is documented with clear criteria for each phase

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| OpenZFS 2.3.x incompatible with chosen kernel 6.12.x | Medium | Must use different kernel or ZFS version | Test compatibility early; have 6.6 LTS as fallback |
| systemd build requires many dependencies not yet packaged | High | Delays this phase | Identify and package all systemd dependencies first (libcap, util-linux, etc.) |
| Kernel config fragment merge produces invalid config | Medium | Kernel build failure | Run `make olddefconfig` after merge to resolve conflicts; validate with `make menuconfig` |
| dracut integration with custom Guix paths is non-trivial | High | initrd generation fails | Study dracut's module system; may need custom dracut modules for Guix store paths |
| Kernel module ABI mismatch between kernel build and ZFS build | Medium | ZFS module fails to load | Ensure ZFS builds against the exact kernel build output (headers + Module.symvers) |
| Firmware licensing concerns (non-free blobs) | Low | Governance issue | Document firmware license status; keep firmware in separate package with clear labeling |
| SELinux policy development is labor-intensive | High | Delays enforcing mode | Start in permissive mode; use audit2allow to iteratively build policy; base policy on Fedora's targeted policy |
| SELinux labeling conflicts with Guix store paths | Medium | AVC denials on /gnu/store | Define custom SELinux file context rules for /gnu/store; run restorecon at image build time |

## Estimated Complexity

**XL (Extra Large)**

This phase involves building three major, complex software components (Linux kernel, systemd, OpenZFS) and integrating them together. Each has extensive build dependencies and configuration requirements. The systemd packaging is particularly challenging because it replaces Guix's native init system. The initrd generation requires deep understanding of the boot process.
