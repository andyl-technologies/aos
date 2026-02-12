# Phase 3: System Packages -- Kernel, systemd, Security, Networking, Storage

**Plan Phase:** 4 (System Packages)

## Objective

Build all server infrastructure packages using the production stdenv from Phase 2: a custom Linux kernel (6.12.11 LTS) with server-optimized config fragments, systemd 256.9 as the init system, OpenZFS 2.3.0 (kernel modules + userspace), the full SELinux stack with targeted policy, networking tools, the audit framework, dracut for initrd generation, and boot-time provisioning tools (Ignition, Butane).

## Prerequisites

- Phase 2 complete: Production stdenv (GCC 13.3 + glibc 2.39) and all core packages building
- Kernel config fragment strategy decided (defconfig + overlaid fragments)
- LTS kernel series selected: 6.12.11
- OpenZFS 2.3.0 confirmed compatible with kernel 6.12

## Deliverables

### Kernel (`pkgs/kernel/`)

- `pkgs/kernel/linux.nix` -- Custom kernel 6.12.11 with config fragments
- `pkgs/kernel/firmware.nix` -- Stripped linux-firmware (~20 MB server-relevant blobs)
- `pkgs/kernel/config/` -- Plain kconfig fragments:
  - `base.config` -- cgroups v2, namespaces, PSI, OverlayFS, block essentials
  - `storage.config` -- ZFS prerequisites, NVMe, AHCI, dm-crypt
  - `networking.config` -- eBPF full stack, BTF, bridge, VXLAN, IP_VS, netfilter
  - `virtualization.config` -- KVM, vhost, IOMMU, VFIO, hugepages
  - `security.config` -- SELinux (default LSM), audit, Yama, seccomp, Landlock, IMA/EVM, lockdown
  - `drivers-vm.config` -- Virtio drivers (boot-critical as built-in, others as modules)
  - `drivers-cloud.config` -- AWS (ENA, NVMe, Xen), GCP (gVNIC), Azure (Hyper-V)
  - `drivers-baremetal.config` -- Intel/Mellanox/Broadcom NICs, storage controllers, IPMI

### Init System (`pkgs/init/`)

- `pkgs/init/systemd.nix` -- systemd 256.9 (journald, networkd, resolved, tmpfiles, sysusers, systemd-boot, udevd)
- `pkgs/init/dbus.nix` -- D-Bus 1.14.10
- `pkgs/init/util-linux.nix` -- util-linux 2.40.2
- `pkgs/init/kmod.nix` -- kmod 33

### Security (`pkgs/security/`)

- `pkgs/security/libsepol.nix` -- SELinux policy library
- `pkgs/security/libselinux.nix` -- SELinux userspace library
- `pkgs/security/libsemanage.nix` -- SELinux management library
- `pkgs/security/policycoreutils.nix` -- sestatus, restorecon, semanage, audit2allow
- `pkgs/security/setools.nix` -- sesearch, seinfo (policy analysis) 4.5.1
- `pkgs/security/refpolicy.nix` -- SELinux reference targeted policy 2.20240916
- `pkgs/security/container-selinux.nix` -- Container runtime SELinux policy 2.232.1
- `pkgs/security/audit.nix` -- Audit framework 4.0.2 (auditd, ausearch, aureport)

### Networking (`pkgs/networking/`)

- `pkgs/networking/iproute2.nix` -- iproute2 6.11.0
- `pkgs/networking/iptables.nix` -- iptables 1.8.10 (with nftables backend)
- `pkgs/networking/nftables.nix` -- nftables 1.1.0
- `pkgs/networking/libmnl.nix`, `libnftnl.nix` -- netfilter libraries
- `pkgs/networking/curl.nix` -- curl 8.10.1
- `pkgs/networking/openssh.nix` -- OpenSSH 9.9p1
- `pkgs/networking/chrony.nix` -- chrony 4.6.1
- `pkgs/networking/ca-certificates.nix` -- CA certificate bundle

### Storage (`pkgs/storage/`)

- `pkgs/storage/zfs.nix` -- OpenZFS 2.3.0 (kernel modules built against custom kernel + userspace tools)

### Boot (`pkgs/boot/`)

- `pkgs/boot/dracut.nix` -- dracut 103 (initrd generator)
- `pkgs/boot/ignition.nix` -- Ignition 2.19.0 (first-boot provisioning)
- `pkgs/boot/butane.nix` -- Butane 0.21.0 (config compiler)

### Monitoring (`pkgs/monitoring/`)

- `pkgs/monitoring/node-exporter.nix` -- Prometheus node exporter 1.8.2

### Tools (`pkgs/tools/`)

- `pkgs/tools/minisign.nix` -- Bundle signing
- `pkgs/tools/sbsigntools.nix` -- Secure Boot signing
- `pkgs/tools/update-tool.nix` -- AOS update agent

## Detailed Task Checklist

### 3.1 Kernel Config Fragments

- [ ] Write `pkgs/kernel/config/base.config`:
  - [ ] Cgroups v2 unified hierarchy (all controllers)
  - [ ] All namespace types (UTS, IPC, USER, PID, NET, CGROUP, TIME)
  - [ ] PSI (Pressure Stall Information)
  - [ ] OverlayFS with all extensions
  - [ ] Block layer essentials (loop, zram, device-mapper)
- [ ] Write `pkgs/kernel/config/storage.config`:
  - [ ] ZFS prerequisites: POSIX ACLs, crypto modules
  - [ ] NVMe, AHCI SATA (built-in), dm-crypt, dm-snapshot
- [ ] Write `pkgs/kernel/config/networking.config`:
  - [ ] eBPF full stack: BPF_SYSCALL, BPF_JIT, BPF_JIT_ALWAYS_ON, BPF_LSM
  - [ ] BTF for CO-RE: DEBUG_INFO_BTF, DEBUG_INFO_BTF_MODULES
  - [ ] Bridge, VXLAN, IP_VS (for k8s networking)
  - [ ] Netfilter conntrack and comment matching
- [ ] Write `pkgs/kernel/config/virtualization.config`: KVM, vhost, IOMMU, VFIO, hugepages
- [ ] Write `pkgs/kernel/config/security.config`:
  - [ ] SELinux as default LSM, boot param support, develop mode, AVC stats
  - [ ] Audit subsystem, Yama, seccomp, Landlock, IMA/EVM, lockdown
  - [ ] Stack protector strong, BPF_UNPRIV_DEFAULT_OFF
- [ ] Write `pkgs/kernel/config/drivers-vm.config`: all virtio drivers
- [ ] Write `pkgs/kernel/config/drivers-cloud.config`: AWS, GCP, Azure drivers
- [ ] Write `pkgs/kernel/config/drivers-baremetal.config`: server NIC/storage controllers, IPMI

### 3.2 Kernel Package

- [ ] Write `pkgs/kernel/linux.nix`:
  - [ ] Source: kernel.org CDN (NOT linux-libre -- firmware loading required)
  - [ ] Merge config fragments, run `make olddefconfig`
  - [ ] Build: `make -j$NIX_BUILD_CORES bzImage modules`
  - [ ] Install: modules, bzImage, System.map, headers for out-of-tree builds
  - [ ] `buildDeps`: perl, flex, bison, elfutils, bc, openssl, kmod
  - [ ] Preserve build directory (Module.symvers) for ZFS module builds

### 3.3 systemd Package

- [ ] Write `pkgs/init/systemd.nix` (systemd 256.9):
  - [ ] Build with meson
  - [ ] Enable: journald, networkd, resolved, tmpfiles.d, sysusers.d, systemd-boot, udevd, systemd-bless-boot, systemd-repart, systemd-oomd
  - [ ] Disable: systemd-homed, GUI features
  - [ ] `runtimeDeps`: glibc, linux-headers, openssl, zstd, lz4, xz, util-linux, kmod, dbus

### 3.4 OpenZFS

- [ ] Write `pkgs/storage/zfs.nix`:
  - [ ] ZFS kernel modules: configure with `--with-linux=` pointing to the kernel build, `--with-config=kernel`
  - [ ] ZFS userspace tools: configure with `--with-config=user`
  - [ ] Both from the same OpenZFS 2.3.0 source
  - [ ] Produce `zpool`, `zfs`, `mount.zfs`, `zdb`, `zed`
  - [ ] Run `depmod` to generate module dependency files

### 3.5 SELinux Stack

- [ ] Build the SELinux stack in dependency order:
  - [ ] `libsepol.nix` -- policy library (no deps beyond core)
  - [ ] `libselinux.nix` -- userspace library (depends on libsepol)
  - [ ] `libsemanage.nix` -- management library (depends on libselinux, libsepol)
  - [ ] `policycoreutils.nix` -- CLI tools (depends on all above)
  - [ ] `setools.nix` -- policy analysis tools 4.5.1
  - [ ] `refpolicy.nix` -- targeted reference policy
  - [ ] `container-selinux.nix` -- container runtime policy module

### 3.6 Networking Packages

- [ ] Build networking packages:
  - [ ] `libmnl.nix`, `libnftnl.nix` -- netfilter libraries
  - [ ] `iproute2.nix` -- IP routing and network config
  - [ ] `iptables.nix` -- iptables with nftables backend
  - [ ] `nftables.nix` -- nftables rule management
  - [ ] `curl.nix` -- HTTP client (exercises full toolchain: GCC + glibc + zlib + OpenSSL)
  - [ ] `openssh.nix` -- SSH server and client (hardened defaults)
  - [ ] `chrony.nix` -- NTP time sync
  - [ ] `ca-certificates.nix` -- CA certificate bundle

### 3.7 Boot and Provisioning Tools

- [ ] `pkgs/boot/dracut.nix` -- initrd generator with systemd support
- [ ] `pkgs/boot/ignition.nix` -- Ignition 2.19.0 (Go binary, first-boot provisioning)
- [ ] `pkgs/boot/butane.nix` -- Butane 0.21.0 (config compiler)

### 3.8 Remaining Packages

- [ ] `pkgs/security/audit.nix` -- audit framework 4.0.2
- [ ] `pkgs/monitoring/node-exporter.nix` -- Prometheus node exporter 1.8.2
- [ ] `pkgs/tools/minisign.nix` -- Ed25519 signing tool
- [ ] `pkgs/tools/sbsigntools.nix` -- Secure Boot signing
- [ ] `pkgs/tools/update-tool.nix` -- AOS update agent

### 3.9 Integration Verification

- [ ] `aos build linux` -- kernel builds with all config fragments merged
- [ ] `aos build systemd` -- systemd builds with all server features
- [ ] `aos build zfs` -- ZFS modules build against the custom kernel and tools work
- [ ] `aos build openssh` -- SSH builds with hardened configuration
- [ ] Verify all SELinux tools: `sestatus`, `getenforce`, `restorecon` produce output
- [ ] Verify audit tools: `auditd`, `ausearch`, `aureport` are functional
- [ ] Verify no package has references to bootstrap-only tools in its runtime closure

## Acceptance Criteria

1. Kernel builds from kernel.org source with all config fragments merged
2. All kernel config requirements are met (cgroups v2, namespaces, eBPF, OverlayFS, ZFS prerequisites, SELinux, audit)
3. systemd 256.9 builds with all server components functional
4. OpenZFS kernel modules build against the custom kernel; `zpool` and `zfs` commands work
5. Full SELinux userspace stack is functional (sestatus, getenforce report correct mode)
6. SELinux targeted policy and container-selinux modules are packaged
7. Networking tools (iproute2, nftables, curl, openssh, chrony) build and work
8. Firmware package is stripped to ~20 MB server-relevant blobs
9. dracut generates a systemd-based initrd
10. All packages use `mkDerivation` with clean inputs and structured phases

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| OpenZFS 2.3.0 incompatible with kernel 6.12 | Medium | Must use different kernel or ZFS version | Test compatibility early; have kernel 6.6 LTS as fallback |
| systemd build requires many dependencies not yet packaged | High | Delays this phase | Dependency chain is: dbus -> util-linux -> kmod -> systemd; build in order |
| Kernel config fragment merge produces invalid config | Medium | Kernel build failure | Run `make olddefconfig` after merge; validate in CI |
| ZFS module ABI mismatch | Medium | ZFS fails to load | Build ZFS against exact kernel build output (Module.symvers) |
| SELinux policy development is labor-intensive | High | Delays enforcing mode | Start with permissive mode; use reference policy; iteratively refine |
| Go-based packages (Ignition, Butane, node-exporter) need special build handling | Medium | Build failures | May need Go bootstrap or pre-built binaries wrapped in derivations |
