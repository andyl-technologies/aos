# ANDYL-OS Expert Analysis: Unified Synthesis Report

> 8-domain expert analysis comparing andyl-os against NixOS best practices
> and the nix-host reference implementation. Prioritized recommendations
> for building a world-class, minimal, Kubernetes-focused server OS.

## Executive Summary

andyl-os has a strong foundation: immutable root, systemd-boot, systemd-networkd,
nftables, containerd/kubelet with kubeadm, and signed updates with boot counting.
However, significant gaps exist between the current state and production-grade
infrastructure. The top priorities are: **replacing dracut with systemd-initrd**,
**adopting A/B root partitions with systemd-sysupdate**, **adding enterprise
services (SSSD, Vault, Alloy)**, and **hardening the kernel/security stack**.

---

## P0 — CRITICAL: Must-Have for Production

### 1. Replace Dracut with systemd-initrd

**Current**: `boot.nix` uses dracut for initrd with `add_dracutmodules+=" systemd systemd-initrd "`.
**Problem**: Dracut is a separate initrd framework. For a pure systemd stack, use systemd's
own initrd generator (`systemd-initrd`), which provides a unified boot chain from UEFI
through initrd to rootfs.

**What NixOS does**: `nixos/modules/system/boot/systemd/initrd.nix` — full systemd-in-initrd
with systemd-cryptsetup, systemd-veritysetup, systemd-fstab-generator, and proper
unit ordering. No dracut dependency.

**Action**:
- `modules/base/boot.nix` — Remove dracut configuration, switch to systemd-initrd
- `pkgs/boot/dracut.nix` — Deprecate, replace with systemd initrd build tooling
- New: `modules/base/initrd.nix` — systemd-initrd configuration module
- Kernel modules loaded via `modules-load.d/` instead of dracut `add_drivers`
- Root device discovery via systemd generators (not dracut hooks)

### 2. A/B Root Partition Scheme + systemd-sysupdate

**Current**: Single root partition (ext4), custom `aos-update` tool for updates.
**Problem**: No atomic root updates, no safe rollback to a known-good partition.

**What NixOS provides**: `systemd-sysupdate` + `systemd-repart` modules for
declarative A/B partition management with automatic boot counting.

**Action**:
- Adopt this partition layout:
  ```
  Part 1: ESP          512M   FAT32     systemd-boot + UKIs
  Part 2: Root-A       4G     ext4      Active rootfs (read-only)
  Part 3: Root-B       4G     ext4      Standby rootfs
  Part 4: Persistent   rest   ZFS       All mutable state (/var, /etc overlay)
  ```
- New: `modules/base/sysupdate.nix` — systemd-sysupdate transfer definitions
- New: `modules/base/repart.nix` — systemd-repart partition definitions
- Modify: `modules/services/update.nix` — integrate with systemd-sysupdate
  instead of custom `aos-update` tool (keep health-check + bless-boot)
- Modify: `images/builder.nix` — generate A/B layout

### 3. dm-verity for Root Integrity

**Current**: Root is read-only ext4 but no integrity verification.
**Problem**: Without verity, a compromised disk can modify the root filesystem
without detection, breaking the trust chain.

**What NixOS provides**: `boot.initrd.systemd.dmVerity.enable` and
`boot.initrd.nix-store-veritysetup` for cryptographic root verification.

**Action**:
- New: `modules/security/verity.nix` — dm-verity for root partitions
- Integrate with UKI (verity hash embedded in kernel cmdline or signed)
- Requires systemd-initrd (P0 #1 above)
- Add kernel modules: `dm_mod`, `dm_verity` to initrd

### 4. Audit Framework — Enable by Default

**Current**: `audit.nix` exists but `enable = false` by default.
**Problem**: CIS compliance and security monitoring require auditing.

**Action**:
- Change `modules/security/audit.nix` default: `enable = true`
- Add CIS Level 1 rules as the base set (current rules are good, already CIS-aligned)
- The nix-host reference also enables auditd (`security.auditd.enable = true`)

### 5. Unified Kernel Image (UKI) — Enable by Default

**Current**: UKI support exists in `boot.nix` but `enable = false`.
**Problem**: Without UKI, the kernel, initrd, and cmdline are separate files on ESP,
making the Secure Boot chain incomplete.

**Action**:
- Change `aos.boot.uki.enable = true` as default for production images
- Use `systemd-ukify` or `objcopy` to build UKI during image generation
- Embed verity hash in UKI cmdline for full trust chain:
  `ESP (signed UKI) -> kernel+initrd+cmdline -> verity-verified rootfs`
- Sign UKI with Secure Boot keys (sbsign)

---

## P1 — HIGH: Required for Enterprise Kubernetes

### 6. Kernel Configuration Module

**Current**: No dedicated kernel configuration module. Kernel params scattered across
`boot.nix` and `hardening.nix`.
**Problem**: Missing critical kernel features for production k8s.

**What nix-host does**: Explicit kernel package selection (`linuxPackages_6_12`),
TCP BBR, NMI watchdog panic, softlockup panic.

**Action** — New: `modules/base/kernel.nix`:
```nix
# Key settings to include:
- Kernel version: linux 6.12+ LTS (stable, well-tested for k8s)
- TCP congestion: BBR ("net.ipv4.tcp_congestion_control" = "bbr")
- Watchdog: nmi_watchdog=panic, softlockup_panic=1
- cgroup v2: already set via kernel cmdline (good)
- eBPF: required for Cilium (CONFIG_BPF, CONFIG_BPF_SYSCALL, etc.)
- CPU microcode: load AMD/Intel microcode at boot
- io_uring: enabled by default in modern kernels
- Huge pages: configurable transparent hugepages
- K8s sysctls: vm.overcommit_memory=1, vm.panic_on_oom=0,
  net.core.somaxconn=32768, net.ipv4.ip_local_port_range,
  fs.inotify.max_user_watches=1048576, fs.inotify.max_user_instances=8192,
  net.core.netdev_max_backlog=5000, net.ipv4.tcp_max_syn_backlog=8096
```

### 7. SSSD — Enterprise Identity Integration

**Current**: Not present in andyl-os.
**Problem**: Enterprise environments need LDAP/AD authentication for SSH access.

**What nix-host does**: Full SSSD with Google Secure LDAP, nscd, PAM integration,
automated user cleanup timer.

**Action** — New: `modules/services/sssd.nix`:
- SSSD service with configurable LDAP provider
- NSS/PAM integration
- nscd configuration (cache hosts only, disable passwd/group cache for SSSD)
- PAM session hook for `loginctl enable-linger`
- Cleanup timer for removed LDAP users
- Age/sops-based secret management for LDAP certificates

### 8. Vault Agent — Secret Management

**Current**: Not present in andyl-os.
**Problem**: Kubernetes nodes need secrets (TLS certs, tokens, credentials) delivered
securely without baking them into images.

**What nix-host does**: Sophisticated vault-agent with proxy socket, per-service
template rendering, mTLS auth, systemd-notify integration.

**Action** — New: `modules/services/vault-agent.nix`:
- Vault proxy with Unix socket
- Per-service template rendering
- mTLS or AppRole authentication
- Systemd service with `Type=notify` and reload propagation
- Log rotation (24h, 7 files)
- Integration point for other modules (SSSD certs, k8s tokens, etc.)

### 9. Grafana Alloy — Observability Agent

**Current**: Only `node-exporter.nix` for metrics.
**Problem**: Need unified metrics/logs/traces forwarding to central monitoring.

**What nix-host does**: Alloy with unix self-exporter, smartctl exporter,
custom scrape configs, remote write to Prometheus.

**Action** — New: `modules/monitoring/alloy.nix`:
- Grafana Alloy service with configurable scrape targets
- Built-in prometheus.exporter.unix (replaces standalone node-exporter)
- Journal log forwarding (Loki)
- Configurable remote write endpoints
- smartctl exporter integration (conditional on non-virtualized)
- Systemd unit filtering

### 10. Kubelet Production Hardening

**Current**: Good foundation but missing production settings.
**Problem**: No resource reservations, eviction thresholds, or image GC.

**Action** — Modify: `modules/kubernetes/kubelet.nix`, add:
```yaml
# Add to KubeletConfiguration:
systemReserved:
  cpu: "500m"
  memory: "1Gi"
  ephemeral-storage: "1Gi"
kubeReserved:
  cpu: "500m"
  memory: "512Mi"
evictionHard:
  memory.available: "200Mi"
  nodefs.available: "10%"
  imagefs.available: "15%"
evictionSoft:
  memory.available: "500Mi"
  nodefs.available: "15%"
evictionSoftGracePeriod:
  memory.available: "30s"
  nodefs.available: "1m"
imageGCHighThresholdPercent: 85
imageGCLowThresholdPercent: 80
containerLogMaxSize: "50Mi"
containerLogMaxFiles: 5
featureGates:
  GracefulNodeShutdown: true
  TopologyManager: true
topologyManagerPolicy: "best-effort"
```

### 11. Containerd Hardening

**Current**: Basic containerd config. Using CRI v1 API paths (deprecated).
**Problem**: Registry config uses old `plugins."io.containerd.grpc.v1.cri".registry`
which is deprecated in containerd 2.x.

**Action** — Modify: `modules/kubernetes/containerd.nix`:
- Update to containerd 2.x config format:
  - Use `[plugins."io.containerd.cri.v1.images".registry]` for registry config
  - Or use `/etc/containerd/certs.d/` host-based registry config (preferred)
- Add `max_concurrent_downloads = 10` for faster image pulls
- Add `discard_unpacked_layers = true` to save disk space
- Add runtime classes for sandboxed workloads (gVisor/kata as optional)
- Consider `native` ZFS snapshotter when rootfs is ZFS

### 12. Fail2ban

**Current**: Not present.
**Problem**: SSH brute-force protection. nix-host uses `services.fail2ban.enable = true`.

**Action** — New: `modules/security/fail2ban.nix`:
- fail2ban with sshd jail
- Configurable ban time, find time, max retries
- Journald backend (no syslog dependency)
- nftables action (not iptables)

---

## P2 — MEDIUM: Quality and Robustness

### 13. Networking Improvements

**Current**: Good systemd-networkd base. Missing advanced features.

**Action** — Modify: `modules/base/networking.nix`:
- Add VLAN support (submodule for VLANs with VLAN ID + parent interface)
- Add bonding/teaming support for NIC redundancy
- Add `[DHCPv4] RouteMetric=` for multi-interface priority
- Add `LinkLocalAddressing=no` option for server interfaces
- Add `IPv6AcceptRA=` configuration
- Add configurable MTU (jumbo frames: 9000 for internal networks)
- Add network performance sysctls:
  ```
  net.core.rmem_max = 16777216
  net.core.wmem_max = 16777216
  net.ipv4.tcp_rmem = 4096 87380 16777216
  net.ipv4.tcp_wmem = 4096 65536 16777216
  net.core.somaxconn = 32768
  net.netfilter.nf_conntrack_max = 1048576
  ```

### 14. Journald Configuration Module

**Current**: No journald configuration.
**Problem**: Default journald can fill disk with logs, no forwarding configured.

**Action** — New: `modules/base/journald.nix`:
```nix
# Key settings:
SystemMaxUse=500M
SystemKeepFree=1G
SystemMaxFileSize=50M
RuntimeMaxUse=100M
MaxRetentionSec=1month
ForwardToSyslog=no
Compress=yes
Storage=persistent  # store in /var/log/journal
```

### 15. ZFS Tuning

**Current**: Good ZFS dataset layout in ignition.nix.

**Action** — Modify: `modules/base/filesystems.nix` / `modules/services/ignition.nix`:
- Add `/var/lib/kubelet` dataset (recordsize=128K, quota)
- Add `/var/log/journal` dataset with quota (prevent log floods)
- Enable auto-trim and auto-scrub
- Add `special_small_blocks=32K` for metadata vdev on SSD

### 16. Swap/OOM Strategy

**Current**: No swap. systemd-oomd not configured.
**Problem**: OOM kills can affect k8s node stability.

**Action** — New: `modules/base/swap.nix`:
- zram-based compressed swap (in-memory, no disk I/O)
- systemd-oomd for proactive OOM prevention
- Configure `DefaultMemoryPressureThresholdPercent`, `DefaultMemoryPressureDurationUSec`

### 17. Encryption at Rest

**Current**: No encryption.
**Problem**: Compliance requirements for data at rest.

**Action** — New: `modules/security/encryption.nix`:
- ZFS native encryption (aes-256-gcm) for persistent pool
- TPM2-sealed key for automatic unlock (NixOS has `systemd/tpm2.nix`)
- Swap with random encryption (`randomEncryption=true`)

### 18. Hardware Monitoring

**Current**: No hardware monitoring.

**Action** — New: `modules/monitoring/hardware.nix`:
- smartmontools for disk health (smartd service + smartctl exporter)
- IPMI/BMC monitoring (ipmitool, freeipmi)
- Hardware watchdog (systemd RuntimeWatchdogSec=30s, RebootWatchdogSec=10min)
- Thermal monitoring (lm_sensors)
- mcelog or rasdaemon for hardware error detection

### 19. systemd-coredump Integration

**Current**: Core dump handled in `hardening.nix` with custom sysctl.
**Problem**: When enabled, should use systemd-coredump properly.

**Action** — Improve: `modules/security/hardening.nix`:
- When `coreDump.enable = true`, use `systemd-coredump` with
  `Storage=journal`, `Compress=yes`, `MaxUse=1G`, `ProcessSizeMax=2G`
- Add `systemd.coredump.extraConfig` option
- Current implementation is good for disabled case

---

## P3 — LOWER: Advanced Features and Polish

### 20. Nix Module Architecture Improvements

**Current**: Modules use `environment.etc` for config file generation and
`systemd.services` for service definitions. No assertions or warnings.

**Recommendations**:
- Add assertions for cross-module constraints, e.g.:
  ```nix
  assertions = [
    { assertion = cfg.kubelet.cgroupDriver == cfg.containerd.cgroupDriver;
      message = "kubelet and containerd cgroup drivers must match"; }
    { assertion = cfg.controlPlane.enable -> cfg.network.enable;
      message = "control plane requires kubernetes networking"; }
  ];
  ```
- Add `mkDefault` for values that should be overridable by role/variant modules
- Consider `mkMerge` for combining firewall rules from multiple modules
  (currently each module sets `allowedTCP` which may overwrite)
- Fix the firewall port accumulation: currently multiple modules set
  `aos.firewall.allowedTCP = [...]` — these should merge, not override.
  Use `lib.mkOption { type = lib.types.listOf lib.types.port; }` and ensure
  the merging behavior works correctly.

### 21. Role/Variant Layering

**Current**: Image variants in `images/` (base, server, k8s-worker, k8s-control-plane).
**Better pattern from nix-host**: role/sku/zone/region layering.

**Action**: Consider adopting a layering system:
```
modules/base/     — always included
modules/roles/    — server, k8s-worker, k8s-control-plane, builder
modules/profiles/ — minimal, hardened, debug
```

### 22. Cilium-Specific Optimizations

**Current**: `network.nix` includes Cilium interface trust rules and IPVS modules.
**Enhancement**: Add Cilium-specific kernel requirements:
- eBPF kernel config verification
- `ip_vs_*` modules for kube-proxy replacement mode
- `vxlan` module if using VXLAN mode
- `wireguard` module if using WireGuard encryption
- BPF filesystem mount (`/sys/fs/bpf`)

### 23. Tailscale/WireGuard VPN

SKIP

### 24. Node Problem Detector

**Current**: Not present.
**Action** — New: `modules/kubernetes/node-problem-detector.nix`:
- Detect kernel oops, OOM, filesystem corruption, network issues
- Report as Kubernetes node conditions
- Run as systemd service (not DaemonSet for OS-level issues)

### 25. kdump / Crash Dump

**Current**: Not present.
**What nix-host does**: `nixos/boot/kdump.nix`.

**Action** — New: `modules/base/kdump.nix`:
- Reserve crashkernel memory (`crashkernel=256M` kernel param)
- Configure makedumpfile for compressed dumps
- Ship dumps to remote server or local ZFS dataset

---

## Module File Inventory

### New modules to create (19):

| Priority | File | Description |
|----------|------|-------------|
| P0 | `modules/base/initrd.nix` | systemd-initrd configuration |
| P0 | `modules/base/sysupdate.nix` | systemd-sysupdate A/B updates |
| P0 | `modules/base/repart.nix` | systemd-repart partition mgmt |
| P0 | `modules/security/verity.nix` | dm-verity root integrity |
| P1 | `modules/base/kernel.nix` | Kernel config, version, tuning |
| P1 | `modules/services/sssd.nix` | SSSD LDAP/AD integration |
| P1 | `modules/services/vault-agent.nix` | Vault secret management |
| P1 | `modules/monitoring/alloy.nix` | Grafana Alloy observability |
| P1 | `modules/security/fail2ban.nix` | SSH brute-force protection |
| P2 | `modules/base/journald.nix` | Journald configuration |
| P2 | `modules/base/swap.nix` | zram + systemd-oomd |
| P2 | `modules/security/encryption.nix` | Encryption at rest |
| P2 | `modules/monitoring/hardware.nix` | Disk/IPMI/thermal monitoring |
| P3 | `modules/services/tailscale.nix` | Tailscale VPN overlay |
| P3 | `modules/kubernetes/node-problem-detector.nix` | NPD |
| P3 | `modules/base/kdump.nix` | Crash dump support |
| P3 | `modules/profiles/hardened.nix` | Hardened profile (combined) |
| P3 | `modules/profiles/debug.nix` | Debug profile |
| P3 | `modules/profiles/minimal.nix` | Minimal profile |

### Existing modules to modify (10):

| Priority | File | Changes |
|----------|------|---------|
| P0 | `modules/base/boot.nix` | Remove dracut, enable UKI by default |
| P0 | `modules/security/audit.nix` | Enable by default |
| P1 | `modules/kubernetes/kubelet.nix` | Add reservations, eviction, GC |
| P1 | `modules/kubernetes/containerd.nix` | Update to v2 config format |
| P2 | `modules/base/networking.nix` | VLANs, bonding, perf sysctls |
| P2 | `modules/base/filesystems.nix` | Additional ZFS datasets, tuning |
| P2 | `modules/security/hardening.nix` | Better coredump integration |
| P2 | `modules/services/ignition.nix` | ZFS datasets for kubelet, journal |
| P2 | `modules/kubernetes/network.nix` | Cilium eBPF/BPF mount, WireGuard |
| P3 | `modules/module-list.nix` | Add all new modules |

### Files to deprecate/remove (1):

| File | Reason |
|------|--------|
| `pkgs/boot/dracut.nix` | Replaced by systemd-initrd |

---

## Key Architectural Decisions

### 1. k3s vs kubeadm
**Recommendation: Keep kubeadm** (already in andyl-os). The nix-host reference
uses k3s, but for a custom OS where you control the entire stack, kubeadm
gives more control. k3s bundles containerd+flannel+traefik which conflicts
with the "compose-your-own-stack" philosophy of andyl-os.

### 2. SELinux vs AppArmor
**Current**: andyl-os uses SELinux (`selinux=1 security=selinux` in kernel params).
**Recommendation**: Stick with SELinux for CIS/STIG compliance, but note that
NixOS ecosystem has better AppArmor support. Ensure SELinux policy is properly
configured for containerd/kubelet, which is the hardest part.

### 3. ZFS vs ext4 for persistent data
**Recommendation: Keep ZFS** (already in andyl-os). The dataset-per-service model
(etcd@4K recordsize, containerd@128K, logs with quotas) is excellent. Consider
erofs for the read-only root partitions for better compression.

### 4. Containerd snapshotter
**Current**: overlayfs. **Recommendation**: Keep overlayfs for now (works on ZFS-backed
dirs). Evaluate `native` ZFS snapshotter if container image storage becomes a concern.

### 5. Firewall: nftables (keep current)
The nftables approach is correct. Kubernetes ecosystem is moving from iptables
to nftables. Cilium in eBPF mode bypasses iptables/nftables entirely for pod traffic.

---

## Implementation Order

```
Phase 1 (P0): Boot chain modernization
  1. Replace dracut with systemd-initrd
  2. Enable UKI by default
  3. Enable audit by default
  4. dm-verity for root integrity

Phase 2 (P0): Update system
  5. A/B root partitions (systemd-repart)
  6. systemd-sysupdate integration

Phase 3 (P1): Enterprise services
  7. Kernel configuration module
  8. SSSD module
  9. Vault agent module
  10. Grafana Alloy module
  11. Fail2ban module

Phase 4 (P1): K8s hardening
  12. Kubelet production settings
  13. Containerd v2 config update

Phase 5 (P2): Robustness
  14. Networking improvements
  15. Journald configuration
  16. ZFS tuning
  17. Swap/OOM strategy
  18. Encryption at rest
  19. Hardware monitoring

Phase 6 (P3): Polish
  20. Module architecture (assertions, merging)
  21. Role layering system
  22. Cilium optimizations
  23. Tailscale/WireGuard
  24. Node Problem Detector
  25. kdump
```

---

## NixOS Module References

Key upstream modules to study and adapt patterns from:

| Module Path | Relevance |
|-------------|-----------|
| `nixos/modules/system/boot/systemd/initrd.nix` | systemd-initrd |
| `nixos/modules/system/boot/systemd/sysupdate.nix` | A/B updates |
| `nixos/modules/system/boot/systemd/repart.nix` | Partition mgmt |
| `nixos/modules/system/boot/systemd/dm-verity.nix` | Root integrity |
| `nixos/modules/system/boot/loader/systemd-boot/` | Boot loader |
| `nixos/modules/profiles/hardened.nix` | Security hardening |
| `nixos/modules/services/security/fail2ban.nix` | Brute-force |
| `nixos/modules/services/misc/sssd.nix` | LDAP/AD |
| `nixos/modules/services/monitoring/prometheus/exporters/` | Metrics |
| `nixos/modules/services/monitoring/alloy.nix` | Observability |
| `nixos/modules/tasks/network-interfaces-systemd.nix` | Network mgmt |
| `nixos/modules/services/networking/firewall-nftables.nix` | Firewall |
