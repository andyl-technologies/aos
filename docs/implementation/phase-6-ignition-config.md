# Phase 6: NixOS-Style Modules

**Plan Phase:** 6 (Modules)

## Objective

Create the NixOS-style module hierarchy (`modules/`) that absorbs all configuration values from the original TOML/Scheme files into typed Nix option defaults. Each module defines options, generates systemd units, config files, and tmpfiles rules. The Ignition first-boot provisioning module is the centerpiece, handling ZFS pool creation, /etc overlay seeding, and per-machine configuration.

## Prerequisites

- Phase 1 complete: `lib/modules.nix` provides the module evaluation engine (`evalModules`)
- Phase 3 complete: All system packages available (systemd, kernel, ZFS, SELinux, networking, etc.)
- Understanding of the module contract: `{ config, pkgs, lib, ... }: { options = {...}; config = {...}; }`

## Deliverables

### Module Registry

- `modules/module-list.nix` -- List of all module paths (explicit, no auto-discovery)

### Base Modules (`modules/base/`)

- `modules/base/system.nix` -- Core system identity, os-release, locale
- `modules/base/boot.nix` -- systemd-boot, kernel args
- `modules/base/filesystems.nix` -- Immutable root, ZFS /var, overlay /etc, tmpfs
- `modules/base/networking.nix` -- systemd-networkd, systemd-resolved
- `modules/base/users.nix` -- System users and groups

### Security Modules (`modules/security/`)

- `modules/security/selinux.nix` -- Policy loading, relabeling, enforcement mode
- `modules/security/audit.nix` -- auditd configuration and rules
- `modules/security/hardening.nix` -- sysctl, kernel lockdown, systemd service hardening
- `modules/security/firewall.nix` -- nftables rule generation from option values
- `modules/security/ssh.nix` -- sshd hardened configuration

### Service Modules (`modules/services/`)

- `modules/services/ignition.nix` -- First-boot: ZFS pool, datasets, hostname, SSH keys, /etc overlay
- `modules/services/update.nix` -- Update agent, health check, rollback, boot counting
- `modules/services/gc.nix` -- Store garbage collection timer
- `modules/services/chrony.nix` -- NTP time sync

### Kubernetes Modules (`modules/kubernetes/`)

- `modules/kubernetes/containerd.nix` -- Container runtime + config generation
- `modules/kubernetes/kubelet.nix` -- Node agent + config generation
- `modules/kubernetes/network.nix` -- K8s sysctl, kernel modules, firewall rules
- `modules/kubernetes/control-plane.nix` -- kubeadm, static pod manifests, etcd firewall

### Monitoring Modules (`modules/monitoring/`)

- `modules/monitoring/node-exporter.nix` -- Prometheus node exporter

### System Variants (`systems/`)

- `systems/base.nix` -- Minimal bootable system
- `systems/server.nix` -- + SSH, firewall, chrony, SELinux enforcing
- `systems/k8s-worker.nix` -- + containerd, kubelet, CNI
- `systems/k8s-control-plane.nix` -- + kubeadm, static pods

## Detailed Task Checklist

### 6.1 Module List Registry

- [ ] Write `modules/module-list.nix`:
  - [ ] Explicit list of all module file paths
  - [ ] No auto-discovery (prevents evaluation of unused modules)
  - [ ] ~20 module paths total

### 6.2 Base Modules

- [ ] `modules/base/system.nix`:
  - [ ] `options.aos.system.name` -- OS name (default: "ANDYL OS")
  - [ ] `options.aos.system.version` -- version string
  - [ ] `options.aos.system.hostname` -- machine hostname
  - [ ] `config`: generate `/usr/lib/os-release`, locale settings
- [ ] `modules/base/boot.nix`:
  - [ ] `options.aos.boot.loader` -- boot loader (default: systemd-boot)
  - [ ] `options.aos.boot.kernelParams` -- kernel command line parameters
  - [ ] `config`: systemd-boot installation, boot entry management
- [ ] `modules/base/filesystems.nix`:
  - [ ] `options.aos.filesystems.rootDevice` -- root partition label
  - [ ] `options.aos.filesystems.zfsPool` -- ZFS pool name (default: "datapool")
  - [ ] `config`: mount units for root (ro), /var (ZFS), /etc (overlay), /tmp (tmpfs), /run (tmpfs)
- [ ] `modules/base/networking.nix`:
  - [ ] `options.aos.networking.useDHCP` -- enable DHCP (default: true)
  - [ ] `options.aos.networking.nameservers` -- DNS servers
  - [ ] `config`: systemd-networkd units, resolved configuration
- [ ] `modules/base/users.nix`:
  - [ ] `options.aos.users.sshAuthorizedKeys` -- SSH keys for the admin user
  - [ ] `config`: system users (root, nobody), groups (wheel, systemd-journal, etc.)

### 6.3 Security Modules

- [ ] `modules/security/selinux.nix`:
  - [ ] `options.aos.selinux.enable` (default: true)
  - [ ] `options.aos.selinux.mode` -- "enforcing" or "permissive" (default: "enforcing")
  - [ ] `options.aos.selinux.type` -- policy type (default: "targeted")
  - [ ] `config`: SELinux config file, kernel cmdline args, first-boot relabeling service
- [ ] `modules/security/audit.nix`:
  - [ ] `options.aos.audit.enable` (default: true)
  - [ ] `options.aos.audit.rules` -- list of audit rules
  - [ ] `config`: auditd service, audit rule loading
- [ ] `modules/security/hardening.nix`:
  - [ ] `options.aos.hardening.enable` (default: true)
  - [ ] `config`: sysctl settings (kernel.kptr_restrict, dmesg_restrict, ptrace_scope, etc.), systemd service hardening defaults, kernel boot parameters (slab_nomerge, init_on_alloc, lockdown=integrity)
- [ ] `modules/security/firewall.nix`:
  - [ ] `options.aos.firewall.enable` (default: true)
  - [ ] `options.aos.firewall.defaultPolicy` (default: "drop")
  - [ ] `options.aos.firewall.allowedTCP` (default: [22])
  - [ ] `options.aos.firewall.allowedUDP` (default: [])
  - [ ] `options.aos.firewall.kubernetes.workerTCP`, `controlPlaneTCP`, etc.
  - [ ] `config`: nftables service, generated ruleset from option values
- [ ] `modules/security/ssh.nix`:
  - [ ] `options.aos.ssh.enable` (default: true)
  - [ ] `options.aos.ssh.permitRootLogin` (default: "prohibit-password")
  - [ ] `options.aos.ssh.passwordAuthentication` (default: false)
  - [ ] `config`: sshd service, hardened config (key-only auth, modern ciphers, restricted forwarding)

### 6.4 Service Modules

- [ ] `modules/services/ignition.nix` -- the centerpiece first-boot module:
  - [ ] `options.aos.ignition.enable` (default: true)
  - [ ] `config`:
    - [ ] ZFS pool creation: `zpool create -f -o ashift=12 -o autotrim=on ...`
    - [ ] Core datasets: `datapool/var`, `datapool/var-lib`, `datapool/var-log`, `datapool/etc-overlay`
    - [ ] Role-specific datasets: `datapool/var-lib-containerd` (recordsize=128K), `datapool/var-lib-etcd` (recordsize=4K)
    - [ ] Completion marker: `/var/lib/andyl-os/zfs-setup-complete`
    - [ ] `ConditionPathExists=!/var/lib/andyl-os/zfs-setup-complete` (runs only once)
    - [ ] /etc overlay seeding, hostname setting, SSH key installation
    - [ ] First-boot SELinux relabeling for Ignition-created files
  - [ ] Config delivery: QEMU fw_cfg, cloud metadata, HTTP server, USB drive
- [ ] `modules/services/update.nix`:
  - [ ] `options.aos.update.enable` (default: true)
  - [ ] `options.aos.update.server` (default: "https://update.aos.internal")
  - [ ] `options.aos.update.channel` (default: "stable")
  - [ ] `options.aos.update.checkInterval` (default: 3600)
  - [ ] `options.aos.update.autoUpdate` (default: false)
  - [ ] `options.aos.update.bootTries` (default: 3)
  - [ ] `options.aos.update.gc.schedule` (default: "weekly")
  - [ ] `options.aos.update.gc.keepGenerations` (default: 5)
  - [ ] `config`: update-check.timer, update-check.service, health-check.service, rollback.service, systemd-bless-boot integration
- [ ] `modules/services/gc.nix`:
  - [ ] `options.aos.gc.enable` (default: true)
  - [ ] `options.aos.gc.schedule` (default: "weekly")
  - [ ] `options.aos.gc.keepGenerations` (default: 5)
  - [ ] `config`: gc.timer, gc.service (IOSchedulingClass=idle, Nice=19)
- [ ] `modules/services/chrony.nix`:
  - [ ] `options.aos.chrony.enable` (default: true)
  - [ ] `options.aos.chrony.servers` -- NTP server list
  - [ ] `config`: chronyd service, chrony.conf

### 6.5 Kubernetes Modules

- [ ] `modules/kubernetes/containerd.nix`:
  - [ ] `options.aos.kubernetes.containerd.enable` (default: false)
  - [ ] `options.aos.kubernetes.containerd.snapshotter` (default: "overlayfs")
  - [ ] `config`: containerd.service, config.toml (gRPC socket, sandbox image, SystemdCgroup=true, CNI paths)
- [ ] `modules/kubernetes/kubelet.nix`:
  - [ ] `options.aos.kubernetes.kubelet.enable` (default: false)
  - [ ] `options.aos.kubernetes.kubelet.clusterDNS`, `clusterDomain`, resource reservations, eviction thresholds
  - [ ] `config`: kubelet.service (After=containerd, Requires=containerd), kubelet config.yaml
- [ ] `modules/kubernetes/network.nix`:
  - [ ] `options.aos.kubernetes.network.enable` (default: false)
  - [ ] `config`: sysctl (net.bridge.bridge-nf-call-iptables, net.ipv4.ip_forward), kernel module loading (overlay, br_netfilter), firewall rule extensions
- [ ] `modules/kubernetes/control-plane.nix`:
  - [ ] `options.aos.kubernetes.controlPlane.enable` (default: false)
  - [ ] `config`: kubeadm config, static pod manifest directory, extra firewall rules (6443, 2379-2380)

### 6.6 Monitoring Module

- [ ] `modules/monitoring/node-exporter.nix`:
  - [ ] `options.aos.monitoring.nodeExporter.enable` (default: false)
  - [ ] `options.aos.monitoring.nodeExporter.port` (default: 9100)
  - [ ] `config`: node-exporter.service with collector config, custom AOS textfile collectors (generation, boot status, update status)

### 6.7 System Variant Compositions

- [ ] `systems/base.nix`: enables system, boot, filesystems, networking, users, ignition
- [ ] `systems/server.nix`: imports base + enables SELinux enforcing, hardening, firewall, SSH, chrony, audit, update, gc
- [ ] `systems/k8s-worker.nix`: imports server + enables containerd, kubelet, K8s network, node-exporter
- [ ] `systems/k8s-control-plane.nix`: imports worker + enables control-plane (kubeadm, extra firewall rules)

The hierarchy (base -> server -> k8s-worker -> k8s-control-plane) uses module imports. Each level enables more modules and overrides options as needed -- later modules override earlier ones, no `mkForce` required.

### 6.8 Verification

- [ ] `aos system eval server` succeeds and produces a complete system configuration
- [ ] `aos system eval k8s-control-plane` evaluates all four variants
- [ ] All options have valid types and defaults
- [ ] No undefined references or infinite recursion
- [ ] `aos test eval` passes all evaluation checks in <1 second

## Acceptance Criteria

1. All modules evaluate correctly via `lib.evalModules`
2. Every option has a type, default, and description
3. No `mkDefault` / `mkForce` / `mkOverride` anywhere -- later modules simply override
4. `lib.mkIf` conditional config works for enable/disable patterns
5. All four system variants (base, server, k8s-worker, k8s-control-plane) evaluate without error
6. Security options (firewall, SSH, sysctl) generate correct systemd units and config files
7. Ignition module generates complete first-boot provisioning logic (ZFS pool, datasets, /etc, relabeling)
8. Update module generates health check, boot counting, and GC services
9. Kubernetes modules generate containerd and kubelet configs matching the original TOML values
10. Module evaluation completes in <1 second (10 modules, not 1500)

## Key Design Decisions

### TOML Values Absorbed Into Module Defaults

The original design used TOML config files (`config/security/firewall.toml`, `config/kubernetes/kubelet.toml`, etc.) parsed by a Guile TOML library. In the Nix architecture, these values become typed option defaults directly in the module. No config format translation layer needed -- the Nix language is the config language.

### Explicit Module List

`modules/module-list.nix` is a hand-maintained list of module paths. This prevents:
- Auto-discovery scanning (which evaluates unused modules)
- Accidental inclusion of work-in-progress modules
- Import ordering surprises

### Variant Hierarchy via Imports

System variants form a hierarchy: `base -> server -> k8s-worker -> k8s-control-plane`. Each level imports its parent and enables additional modules. This is a standard Nix import pattern -- no special inheritance mechanism needed.

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Module evaluation engine bugs cause subtle config errors | Medium | Incorrect system configs | Comprehensive eval tests check all option types and merging behavior |
| Ignition + /etc overlay interaction is fragile | High | Files not visible after boot | Test both Ignition write strategies; pick the working one |
| Firewall rules block legitimate traffic | Medium | Service outage | Test rules in VM; include health check ports; log before enforcing |
| Kubernetes module option defaults don't match production requirements | Low | kubelet misconfigured | Defaults match the original TOML values; documented and overridable |
| Module count grows beyond ~20 | Low | Evaluation performance degrades | Keep modules coarse-grained; audit additions |
