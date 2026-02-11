# Phase 9: Production Hardening, Monitoring, Security, and Fleet Management

**Phase Number:** 9

## Objective

Harden ANDYL OS for production deployment: implement security baselines, integrate monitoring and observability, set up fleet-wide update orchestration with canary deployments, create operational runbooks, and produce comprehensive documentation for operators and contributors.

## Prerequisites

- Phase 4 complete: Base image boots with immutable root, systemd-boot, /etc overlay
- Phase 5 complete: Update agent, boot counting, health checks, GC all functional
- Phase 6 complete: Ignition provisioning for per-machine configuration
- Phase 7 complete: Kubernetes node images validated
- Phase 8 complete: CI pipeline and test suite passing for all roles

## Deliverables

- `channel/andyl/packages/monitoring.scm` -- Prometheus node_exporter, promtail packages
- `channel/andyl/packages/security.scm` -- SELinux policy, audit tools, fail2ban
- `channel/andyl/system/hardened.scm` -- Hardened system configuration (inherits base)
- `tools/fleet-update.py` -- Fleet-wide rolling update orchestrator
- `tools/fleet-inventory.py` -- Fleet inventory and status dashboard
- Monitoring stack integration (Prometheus, Grafana, Loki) configuration templates
- SELinux policy modules for all ANDYL OS services
- Secure Boot signing workflow (optional, documented)
- `docs/operator-guide.md` -- Operational runbook and troubleshooting guide
- `docs/architecture.md` -- System architecture reference
- `docs/contributing.md` -- Contributor guide for package and image development
- Alerting rules for node health, update failures, and security events
- Fleet update strategy with canary and rolling deployment support

## Detailed Task Checklist

### 9.1 Kernel Hardening

- [ ] Review and finalize kernel security config fragment (`kernel/security.config`):
  - [ ] `CONFIG_STACKPROTECTOR=y`, `CONFIG_STACKPROTECTOR_STRONG=y`
  - [ ] `CONFIG_FORTIFY_SOURCE=y`
  - [ ] `CONFIG_STRICT_KERNEL_RWX=y`
  - [ ] `CONFIG_STRICT_MODULE_RWX=y`
  - [ ] `CONFIG_RANDOMIZE_BASE=y` (KASLR)
  - [ ] `CONFIG_RANDOMIZE_MEMORY=y`
  - [ ] `CONFIG_PAGE_TABLE_ISOLATION=y` (KPTI)
  - [ ] `CONFIG_INIT_ON_ALLOC_DEFAULT_ON=y`
  - [ ] `CONFIG_INIT_ON_FREE_DEFAULT_ON=y`
  - [ ] `CONFIG_HARDENED_USERCOPY=y`
  - [ ] `CONFIG_SLAB_FREELIST_RANDOM=y`
  - [ ] `CONFIG_SLAB_FREELIST_HARDENED=y`
  - [ ] `CONFIG_MODULE_SIG=y` (require signed kernel modules)
  - [ ] `CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY=y`
- [ ] Add kernel boot parameters for hardening:
  - [ ] `slab_nomerge` -- prevent slab merging for isolation
  - [ ] `init_on_alloc=1` -- zero pages on allocation
  - [ ] `page_alloc.shuffle=1` -- randomize page allocator
  - [ ] `lockdown=integrity` -- integrity mode lockdown
  - [ ] `vsyscall=none` -- disable vsyscall emulation
- [ ] Disable kernel module loading after boot (optional, strict mode):
  - [ ] `sysctl kernel.modules_disabled=1` after all required modules load
- [ ] Verify hardening with `checksec` or equivalent on the running kernel

### 9.2 Userspace Security Hardening

- [ ] Disable password-based root login (SSH key only):
  - [ ] `/etc/ssh/sshd_config`: `PermitRootLogin prohibit-password`
  - [ ] Ensure root account has no password hash in `/etc/shadow`
- [ ] Harden SSH daemon configuration:
  - [ ] `PasswordAuthentication no`
  - [ ] `KbdInteractiveAuthentication no`
  - [ ] `MaxAuthTries 3`
  - [ ] `LoginGraceTime 30`
  - [ ] `X11Forwarding no`
  - [ ] `AllowTcpForwarding no` (unless required by role)
  - [ ] `ClientAliveInterval 300`, `ClientAliveCountMax 2`
  - [ ] `AllowUsers core` (restrict to provisioned user)
  - [ ] `HostKeyAlgorithms ssh-ed25519,ecdsa-sha2-nistp256`
  - [ ] `KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org`
- [ ] Configure systemd service hardening defaults:
  - [ ] `ProtectSystem=strict` for non-critical services
  - [ ] `ProtectHome=yes`
  - [ ] `PrivateTmp=yes`
  - [ ] `NoNewPrivileges=yes`
  - [ ] `ProtectKernelTunables=yes`
  - [ ] `ProtectKernelModules=yes`
  - [ ] `ProtectControlGroups=yes`
  - [ ] `RestrictSUIDSGID=yes`
  - [ ] `RestrictNamespaces=yes` (where applicable)
  - [ ] `SystemCallFilter=@system-service` (where applicable)
- [ ] Configure `sysctl` hardening via `/etc/sysctl.d/90-andyl-hardening.conf`:
  - [ ] `kernel.kptr_restrict=2` -- hide kernel pointers
  - [ ] `kernel.dmesg_restrict=1` -- restrict dmesg access
  - [ ] `kernel.perf_event_paranoid=3` -- restrict perf events
  - [ ] `kernel.yama.ptrace_scope=1` -- restrict ptrace
  - [ ] `net.ipv4.conf.all.rp_filter=1` -- reverse path filtering
  - [ ] `net.ipv4.conf.all.accept_redirects=0`
  - [ ] `net.ipv6.conf.all.accept_redirects=0`
  - [ ] `net.ipv4.conf.all.send_redirects=0`
  - [ ] `net.ipv4.conf.all.log_martians=1`
  - [ ] `net.ipv4.tcp_syncookies=1`
  - [ ] `fs.protected_symlinks=1`
  - [ ] `fs.protected_hardlinks=1`
  - [ ] `fs.suid_dumpable=0`
- [ ] Disable unnecessary services:
  - [ ] Verify no unexpected listening ports (`ss -tlnp`)
  - [ ] Remove or disable debug shells (`debug-shell.service`)
  - [ ] Disable `ctrl-alt-del.target` reboot shortcut

### 9.3 SELinux Policy

- [ ] Create SELinux policy modules for ANDYL OS services:
  - [ ] Install `selinux-policy-targeted` and `container-selinux` base policies
  - [ ] `containerd` policy module: restrict filesystem access, network, capabilities
  - [ ] `kubelet` policy module: allow necessary k8s paths, restrict others
  - [ ] `andyl-os-agent` policy module: restrict to update paths and network
  - [ ] `sshd` policy module: standard SSH confinement
  - [ ] `node_exporter` policy module: read-only access to /proc, /sys
  - [ ] Custom ANDYL OS policy module combining all service policies
- [ ] Package policy modules as `andyl-selinux-policy`:
  - [ ] Install to `/etc/selinux/targeted/`
  - [ ] Include type enforcement (.te), file context (.fc), and interface (.if) files
- [ ] Enable SELinux enforcement at boot:
  - [ ] Kernel parameter: `security=selinux selinux=1`
  - [ ] SELinux loads targeted policy on boot
- [ ] Test that SELinux is in `enforcing` mode: `sestatus` / `getenforce`
- [ ] Test that confined services still function correctly

### 9.4 Secure Boot (Optional)

- [ ] Document Secure Boot signing workflow:
  - [ ] Generate Machine Owner Key (MOK) pair
  - [ ] Sign UKIs with `sbsign` or `ukify --sign`
  - [ ] Enroll MOK in UEFI firmware or via `mokutil`
- [ ] Create signing automation in CI:
  - [ ] Store signing key in CI secrets manager
  - [ ] Sign UKIs as part of the image build pipeline
  - [ ] Verify signature before publishing
- [ ] Test Secure Boot chain in QEMU with OVMF + enrolled keys
- [ ] Document key rotation procedure
- [ ] Document recovery procedure if MOK is lost

### 9.5 Monitoring: Prometheus Node Exporter

- [ ] Package `node_exporter` as `andyl-node-exporter`:
  - [ ] Version 1.8.x
  - [ ] Enable collectors: cpu, diskstats, filesystem, loadavg, meminfo, netdev, netstat, os, systemd, textfile, uname, zfs
  - [ ] Disable unnecessary collectors: wifi, nfs, mdadm, infiniband
- [ ] Create systemd service unit:
  - [ ] Listen on `0.0.0.0:9100` (or restrict to management network)
  - [ ] `--web.disable-exporter-metrics` for cleaner output
  - [ ] `--collector.textfile.directory=/var/lib/node_exporter/textfile_collector`
  - [ ] Service hardening: `ProtectSystem=strict`, `CapabilityBoundingSet=`
- [ ] Create custom textfile collectors:
  - [ ] `andyl_os_generation` -- current generation number and version
  - [ ] `andyl_os_boot_verified` -- whether current boot is verified
  - [ ] `andyl_os_update_available` -- whether an update is pending
  - [ ] `andyl_os_gc_last_run` -- timestamp of last GC run
  - [ ] `andyl_os_store_paths_count` -- number of paths in /gnu/store
  - [ ] `andyl_os_store_size_bytes` -- total store size
- [ ] Timer to refresh textfile metrics every 5 minutes

### 9.6 Monitoring: Log Aggregation

- [ ] Package `promtail` (or `alloy`) as `andyl-promtail`:
  - [ ] Configure to scrape systemd journal
  - [ ] Ship logs to Grafana Loki endpoint
  - [ ] Label logs with hostname, role, generation, zone metadata
- [ ] Create promtail systemd service:
  - [ ] `After=systemd-journald.service`
  - [ ] Read from `/var/log/journal/`
  - [ ] Include pipeline stages for parsing structured journal fields
- [ ] Define Loki log retention policy (30 days default)
- [ ] Create Grafana dashboard templates for ANDYL OS logs:
  - [ ] Service log viewer filtered by role and node
  - [ ] Error rate dashboard
  - [ ] Boot event timeline

### 9.7 Alerting Rules

- [ ] Create Prometheus alerting rules (`alerts/andyl-os.rules.yml`):
  - [ ] **Node health**:
    - [ ] `AndylOSNodeDown` -- node_exporter unreachable for >5 minutes
    - [ ] `AndylOSSystemDegraded` -- `systemctl is-system-running` not `running`
    - [ ] `AndylOSHighCPU` -- CPU usage >90% for >10 minutes
    - [ ] `AndylOSHighMemory` -- memory usage >90% for >5 minutes
    - [ ] `AndylOSDiskSpaceLow` -- /var usage >85%
    - [ ] `AndylOSStoreFull` -- /gnu/store partition >90%
  - [ ] **Update and deployment**:
    - [ ] `AndylOSBootNotVerified` -- boot not verified within 10 minutes of reboot
    - [ ] `AndylOSUpdateFailed` -- update agent reported failure
    - [ ] `AndylOSRollbackOccurred` -- generation changed to a lower number (rollback detected)
    - [ ] `AndylOSGCFailed` -- garbage collection service failed
    - [ ] `AndylOSStaleGeneration` -- node running a generation >7 days behind latest
  - [ ] **Kubernetes (role-specific)**:
    - [ ] `AndylOSKubeletDown` -- kubelet not active for >2 minutes
    - [ ] `AndylOSContainerdDown` -- containerd not active for >2 minutes
    - [ ] `AndylOSNodeNotReady` -- k8s node not Ready for >5 minutes
  - [ ] **Security**:
    - [ ] `AndylOSSSHBruteForce` -- >10 failed SSH auth attempts in 5 minutes
    - [ ] `AndylOSStoreWritable` -- /gnu/store mounted read-write outside of update/GC window
    - [ ] `AndylOSSELinuxViolation` -- SELinux AVC denial logged
- [ ] Test alerting rules with unit tests (`promtool test rules`)
- [ ] Document escalation procedures for each alert

### 9.8 Fleet Update Orchestration

- [ ] Create `tools/fleet-update.py`:
  - [ ] Load fleet inventory from `inventory/hosts.yaml`
  - [ ] Group nodes by role and zone for rolling updates
  - [ ] Implement update strategies:
    - [ ] **Rolling**: update N nodes at a time, wait for health check, proceed
    - [ ] **Canary**: update 1 node per role, monitor for configurable soak period, then roll out
    - [ ] **Blue-green**: bring up new nodes, drain old nodes, remove old nodes
  - [ ] Pre-update checks:
    - [ ] Verify target node is reachable via SSH
    - [ ] Verify current generation and health status
    - [ ] For k8s nodes: cordon and drain before update
  - [ ] Update execution:
    - [ ] SSH to each node: `andyl-os-agent update --now`
    - [ ] Wait for reboot and SSH availability
    - [ ] Wait for health check to mark boot as verified
    - [ ] For k8s nodes: uncordon after health check passes
  - [ ] Post-update validation:
    - [ ] Verify new generation is running
    - [ ] Check monitoring for error rate spikes
    - [ ] Abort rollout if error rate exceeds threshold
  - [ ] Rollback capability:
    - [ ] `--rollback` flag to roll back the entire fleet to previous generation
    - [ ] Respect the same rolling strategy for rollbacks
- [ ] Add configurable parallelism (`--parallel=N`)
- [ ] Add `--dry-run` mode (show what would happen without executing)
- [ ] Add logging and progress reporting

### 9.9 Fleet Inventory and Status

- [ ] Create `tools/fleet-inventory.py`:
  - [ ] Query all nodes for current status:
    - [ ] Current generation number and version
    - [ ] Boot verification status
    - [ ] System health (running/degraded/failed)
    - [ ] Role and zone metadata
    - [ ] Uptime
    - [ ] Disk usage (/var, /gnu/store, ESP)
  - [ ] Output formats: table, JSON, CSV
  - [ ] Filter by role, zone, generation, health status
  - [ ] Show fleet-wide summary: total nodes, generation distribution, health overview
- [ ] Create `tools/fleet-status-dashboard.py`:
  - [ ] Simple terminal-based dashboard showing fleet health at a glance
  - [ ] Refresh periodically (default every 30 seconds)
  - [ ] Highlight nodes with issues (failed health, stale generation, degraded)

### 9.10 Operational Runbooks

- [ ] Create `docs/operator-guide.md`:
  - [ ] **Day-1 operations**:
    - [ ] Provisioning a new node (image write, Ignition, first boot)
    - [ ] Adding a node to the fleet inventory
    - [ ] Generating Ignition configs for new nodes
  - [ ] **Day-2 operations**:
    - [ ] Performing a fleet update (canary + rolling)
    - [ ] Monitoring update progress
    - [ ] Manual rollback procedure
    - [ ] Emergency rollback from boot menu
    - [ ] Running garbage collection manually
    - [ ] Checking node health and generation status
  - [ ] **Troubleshooting**:
    - [ ] Node fails to boot after update (boot counting, serial console access)
    - [ ] Health check fails (how to investigate, common causes)
    - [ ] Store corruption (ZFS scrub, integrity checks)
    - [ ] Disk space issues (GC, store cleanup)
    - [ ] Network issues (networkd, resolved troubleshooting)
    - [ ] SSH access lost (serial console, rescue USB)
    - [ ] kubelet/containerd issues (logs, restart, drain)
  - [ ] **Disaster recovery**:
    - [ ] ESP corruption recovery
    - [ ] Full node reimaging
    - [ ] etcd backup and restore (control plane)
    - [ ] Certificate rotation

### 9.11 Architecture Documentation

- [ ] Create `docs/architecture.md`:
  - [ ] System overview diagram (boot flow, filesystem layout, update flow)
  - [ ] Package and channel structure
  - [ ] Image build pipeline
  - [ ] Generational deployment model explanation
  - [ ] Security model (immutable root, boot counting, signature verification)
  - [ ] Networking model (systemd-networkd, Ignition, CNI)
  - [ ] Monitoring and observability stack
  - [ ] Fleet management model

### 9.12 Contributor Guide

- [ ] Create `docs/contributing.md`:
  - [ ] Development environment setup (Docker, Guix, macOS)
  - [ ] Channel and package structure
  - [ ] How to add a new package to the channel
  - [ ] How to create a new role-based image variant
  - [ ] How to write and run integration tests
  - [ ] CI pipeline overview
  - [ ] Code review and merge process
  - [ ] Release process (tagging, promotion, fleet deployment)

### 9.13 Certificate Rotation

- [ ] Implement certificate rotation mechanism for post-first-boot changes:
  - [ ] `tools/rotate-certs.sh` -- generate new certificates, distribute via SSH
  - [ ] Alternatively: integrate with cert-manager for Kubernetes TLS
  - [ ] Create systemd timer for automatic rotation before expiry
  - [ ] Test rotation without node reboot (service reload)
- [ ] Document certificate lifecycle:
  - [ ] CA certificate validity: 5 years
  - [ ] Node certificates: 1 year
  - [ ] Auto-rotation threshold: 30 days before expiry
  - [ ] Manual rotation procedure for emergency

### 9.14 Audit Logging

- [ ] Configure systemd-journald for audit trail:
  - [ ] `Storage=persistent`
  - [ ] `Compress=yes`
  - [ ] `SystemMaxUse=2G`
  - [ ] `MaxRetentionSec=90day`
- [ ] Enable Linux audit subsystem (`auditd` or systemd-journald audit integration):
  - [ ] Audit rules for security-relevant events:
    - [ ] File access to `/etc/shadow`, `/etc/ssh/`
    - [ ] Changes to `/gnu/store` (remount events)
    - [ ] Privileged command execution
    - [ ] User login/logout events
    - [ ] Module loading events
- [ ] Forward audit logs to central log aggregation (Loki via promtail)
- [ ] Create audit log review procedure in operator guide

### 9.15 Network Security

- [ ] Configure nftables firewall baseline:
  - [ ] Default deny inbound
  - [ ] Allow SSH (port 22) from management network only
  - [ ] Allow node_exporter (port 9100) from monitoring network
  - [ ] Allow kubelet (port 10250) from control plane network (k8s roles)
  - [ ] Allow container networking (pod CIDR, service CIDR)
  - [ ] Allow ICMP echo (for monitoring)
  - [ ] Log dropped packets
- [ ] Create role-specific firewall extensions:
  - [ ] k8s-control: allow 6443 (API server), 2379-2380 (etcd)
  - [ ] edge: allow 80, 443 (public)
  - [ ] database: allow 5432 from application network
- [ ] Create nftables systemd service:
  - [ ] Load rules at boot before network services start
  - [ ] Persist rules in `/etc/nftables.conf` (via Ignition or image)
- [ ] Configure DNS security:
  - [ ] `DNSSEC=allow-downgrade` in resolved configuration
  - [ ] Restrict DNS queries to known upstream resolvers

### 9.16 Image Promotion Pipeline

- [ ] Define promotion workflow:
  - [ ] `dev` -- every merge to main, automatic after CI passes
  - [ ] `staging` -- manual promotion or automatic after 3-day soak
  - [ ] `production` -- manual approval after staging validation
- [ ] Create `tools/promote.sh`:
  - [ ] Copy image artifacts between environment buckets
  - [ ] Update environment manifest
  - [ ] Trigger fleet update for the target environment
- [ ] Create canary deployment logic in `fleet-update.py`:
  - [ ] Deploy to 1 node per role
  - [ ] Monitor error rates and resource usage for soak period (default 1 hour)
  - [ ] Auto-promote if no anomalies, or alert and halt if issues detected
- [ ] Add promotion notifications:
  - [ ] Slack/webhook notification on promotion events
  - [ ] Notification on canary failures
  - [ ] Notification on fleet-wide rollout completion

### 9.17 Backup Strategy

- [ ] Document backup requirements by role:
  - [ ] k8s-control: etcd snapshots (every 30 minutes)
  - [ ] database: PostgreSQL WAL archiving + base backups
  - [ ] All roles: `/var/lib` for persistent state
- [ ] Create etcd backup automation:
  - [ ] `etcdctl snapshot save` via systemd timer
  - [ ] Upload snapshots to S3/MinIO
  - [ ] Retention: 30 snapshots (15 hours at 30-minute intervals)
  - [ ] Test restore procedure
- [ ] Document restore procedures for each role in operator guide

### 9.18 Performance Tuning

- [ ] Configure kernel parameters for server workloads:
  - [ ] `vm.swappiness=10` (prefer keeping data in RAM)
  - [ ] `vm.dirty_ratio=10`, `vm.dirty_background_ratio=5`
  - [ ] `net.core.somaxconn=65535`
  - [ ] `net.ipv4.tcp_max_syn_backlog=65535`
  - [ ] `net.core.netdev_max_backlog=16384`
  - [ ] `net.core.rmem_max=16777216`, `net.core.wmem_max=16777216`
  - [ ] `fs.file-max=2097152`
  - [ ] `fs.inotify.max_user_watches=524288`
- [ ] Configure systemd resource limits:
  - [ ] `DefaultLimitNOFILE=1048576` in system.conf
  - [ ] `DefaultLimitNPROC=65535`
- [ ] Configure ZFS tuning (if ZFS layout):
  - [ ] `zfs_arc_max` -- limit ARC to 25% of RAM on k8s nodes
  - [ ] `zfs_prefetch_disable=1` for database workloads
- [ ] Document role-specific tuning recommendations

### 9.19 justfile Targets

- [ ] Add `fleet-status` target: show fleet health summary
- [ ] Add `fleet-update ENVIRONMENT` target: trigger fleet update for an environment
- [ ] Add `fleet-rollback ENVIRONMENT` target: roll back fleet to previous generation
- [ ] Add `promote FROM TO VERSION` target: promote images between environments
- [ ] Add `certs-rotate` target: rotate TLS certificates for the fleet
- [ ] Add `security-audit` target: run security checks against a running image
- [ ] Update `docs` target: build all documentation

## Acceptance Criteria

1. All services run under SELinux targeted policy in enforcing mode
2. SSH is hardened: key-only auth, restricted users, modern ciphers
3. Kernel hardening flags are active and verified by automated tests
4. node_exporter serves system and ANDYL-OS-specific metrics on every node
5. Alerting rules fire correctly for simulated failure scenarios
6. Fleet update orchestrator performs rolling updates without downtime
7. Canary deployment detects simulated failures and halts rollout
8. Operator guide covers all day-1, day-2, and troubleshooting scenarios
9. Architecture and contributor documentation are complete and accurate
10. nftables firewall is active with role-appropriate rules
11. Audit logging captures security-relevant events
12. Certificate rotation works without node reboot

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| SELinux policy too restrictive, breaks services | High | Services fail to start | Develop policy in permissive mode first, test thoroughly, then switch to enforcing |
| Fleet update orchestrator has race conditions | Medium | Partial fleet update, inconsistent state | Extensive testing with multi-node QEMU clusters; use locks and state machines |
| Monitoring stack adds resource overhead | Low | Reduced capacity for workloads | node_exporter and promtail are lightweight; set resource limits; monitor their resource usage |
| Secure Boot key management complexity | Medium | Lost keys = cannot update boot chain | Document key backup and rotation; test recovery procedure |
| Firewall rules block legitimate traffic | Medium | Service outage | Test rules in development; include health check ports; use logging before enforcement |
| Documentation becomes stale | High | Operators follow outdated procedures | Link docs to CI (fail on broken links); review docs quarterly; treat docs as code |
| Canary deployment window too short | Medium | Bad release reaches production | Default soak period of 1 hour minimum; monitor error rates and latency, not just health checks |
| Certificate rotation disrupts running connections | Low | Brief connection drops | Use graceful reload (SIGHUP) for services; test rotation under load |

## Estimated Complexity

**XL (Extra Large)**

This phase spans security hardening, monitoring integration, fleet orchestration tooling, and comprehensive documentation. Each area is individually manageable, but the breadth of work and the need for thorough testing across all roles makes this the largest single-phase effort. Security hardening and SELinux policy require careful iterative testing to avoid breaking functionality. Fleet update orchestration must handle failure scenarios gracefully. Documentation requires deep understanding of all previous phases.
