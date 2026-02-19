# 5. Security Architecture

## 5.1 Default Security Posture (No Cloud-Init Required)

The golden image boots fully hardened with no external input:

**Kernel command line** (embedded in per-generation signed UKI, immutable):

```
console=ttyS0,115200 console=tty0 systemd.unified_cgroup_hierarchy=1
selinux=1 security=selinux lockdown=integrity
root=/var/lib/store/<hash>-aos-system
```

Each generation has its own UKI with its own kernel command line. The
`root=` parameter points to the generation's store path. systemd-boot
presents all available generations in its menu.

**Filesystem hardening**:

| Mount        | Type    | Mode     | Options                        |
|--------------|---------|----------|--------------------------------|
| `/`          | ext4    | `ro`     | dm-verity verified             |
| `/boot`      | vfat    | `ro`     | `fmask=0077,dmask=0077`        |
| `/etc`       | overlay | rw       | tmpfs upper, ro lower          |
| `/tmp`       | tmpfs   | rw       | `nosuid,nodev,noexec,mode=1777`|
| `/run`       | tmpfs   | rw       | `nosuid,nodev,noexec,mode=755` |
| `/var`       | ZFS     | rw       | Persistent state               |
| `/nix/store` | ext4    | `ro`     | Part of dm-verity root         |

**Sysctl hardening** (`/etc/sysctl.d/80-aos-hardening.conf`):

```ini
kernel.randomize_va_space = 2          # Full ASLR
kernel.kptr_restrict = 2               # Hide kernel pointers
kernel.dmesg_restrict = 1              # dmesg requires CAP_SYSLOG
kernel.perf_event_paranoid = 3         # Deny perf for unprivileged
kernel.yama.ptrace_scope = 2           # ptrace requires CAP_SYS_PTRACE
net.ipv4.conf.all.rp_filter = 1        # Strict reverse path
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.tcp_syncookies = 1            # SYN flood protection
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0                   # No SUID core dumps
```

**User accounts**: All passwords locked (`!*` in shadow). Root has no
password hash. Service accounts use `/sbin/nologin`.

**SELinux**: Enforcing mode, targeted policy. Policy loaded before
`sysinit.target`.

**Core dumps**: Disabled at sysctl, systemd, and ulimit levels.

**Audit**: CIS-compliant ruleset: execve, module load/unload,
mount/umount, user/group changes, SELinux policy changes.

## 5.2 Secure Boot Chain

```
UEFI Platform Key (PK) -> KEK -> db
  -> systemd-boot (signed EFI binary, verified against db)
    -> Per-generation UKI (kernel + initrd + cmdline, signed PE)
      -> lockdown=integrity (blocks unsigned modules, /dev/mem)
      -> selinux=1 (MAC before any userspace)
      -> Store paths verified by content-addressing (hash in path)
        -> LUKS unsealing bound to TPM PCRs 0+4+7
```

Each generation produces a signed UKI installed to the ESP as
`aos-<short-hash>.efi`. systemd-boot selects between generations at boot.
Old UKIs are removed when their generation is garbage collected.

TPM PCR measurements:

| PCR | Content                            |
|-----|------------------------------------|
| 0   | UEFI firmware code                 |
| 4   | Boot manager (systemd-boot)        |
| 7   | Secure Boot policy (db, KEK)       |
| 11  | UKI image (kernel+initrd+cmdline)  |
| 14  | SELinux policy (measured by IMA)    |

**Multi-generation TPM considerations**: PCR 11 changes with each
generation since each has a different UKI. LUKS unsealing should NOT
bind to PCR 11, or must use `systemd-pcrlock` to pre-authorize expected
PCR values for known generations. The recommended policy binds to PCRs
0+4+7 (firmware + bootloader + Secure Boot policy) which are stable
across generation switches.

## 5.3 Security Boundaries

**Cloud-init CAN** (via overlay /etc and ZFS /var):
- Add SSH authorized keys
- Open additional firewall ports (additive only)
- Relax SELinux to permissive (cannot disable -- kernel param is immutable)
- Add users and groups
- Set hostname, configure networking
- Enable fail2ban, tighten audit rules

**Cloud-init CANNOT** (enforced by immutable layers):
- Modify `/nix/store` (read-only, dm-verity)
- Replace kernel or initrd (Secure Boot + UKI signature)
- Alter kernel command line (embedded in signed UKI)
- Change dm-verity root hash
- Disable kernel lockdown at runtime (one-way switch)
- Load unsigned kernel modules
- Write to root filesystem directly
- Remove base audit rules (additive only)
- Modify unit files in `/usr/lib/systemd/` (read-only rootfs)

## 5.4 Cloud-Init Security

**Sandboxed systemd unit** for cloud-init itself:

```ini
[Service]
SystemCallFilter=~@reboot @swap @raw-io @clock @module @debug
ProtectKernelModules=yes
ProtectKernelTunables=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ReadOnlyPaths=/nix/store /boot /usr
ReadWritePaths=/etc /run /var/lib/cloud /var/log
CapabilityBoundingSet=CAP_CHOWN CAP_FOWNER CAP_DAC_OVERRIDE
  CAP_NET_ADMIN CAP_SETUID CAP_SETGID
NoNewPrivileges=yes
MemoryMax=512M
CPUQuota=50%
TasksMax=64
TimeoutStartSec=300
```

**SELinux policy** (`cloud_init_t`):
- Allowed: write to overlay `/etc`, `/run/secrets`, `/var/lib/cloud`
- Denied: write to `nix_store_t`, `boot_t`, `usr_t`; network listen; module loading

**Input validation**:
- Payload size limit: 64 KB
- YAML safe_load only (no Python object instantiation)
- `runcmd` module disabled by default
- `write_files` path allowlist (SSH keys, systemd network, nftables.d)

**Config signing** (optional, recommended for bare-metal):
- Ed25519 signature envelope around userdata
- Public key baked into dm-verity rootfs at `/etc/cloud/signing-key.pub`

## 5.5 Hardening Knobs via Cloud-Init

| Knob | Default (no cloud-init) | Cloud-init key | Constraints |
|------|------------------------|----------------|-------------|
| SELinux mode | `enforcing` | `aos.selinux.mode` | Cannot set `disabled` |
| Kernel lockdown | `integrity` | N/A | Can only escalate to `confidentiality` |
| SSH root login | `prohibit-password` | `aos.ssh.permit_root_login` | Cannot set `yes` |
| SSH ciphers | Mozilla Modern | `aos.ssh.ciphers` | Subset only |
| Firewall TCP | `[22]` | `aos.firewall.extra_tcp` | Additive only |
| Forward policy | `drop` | `aos.firewall.forward_policy` | `drop` or `accept` |
| Fail2ban | disabled | `aos.fail2ban.enable` | `true`/`false` |
| Audit extra rules | CIS baseline | `aos.audit.extra_rules` | Additive only |
| ptrace_scope | `2` | `aos.hardening.ptrace_scope` | Can tighten to `3` |

## 5.6 Credential Management

**SSH keys**: Written to overlay `/etc/ssh/authorized_keys/<user>`.
Ephemeral by design (tmpfs). Re-applied from datasource on every boot.
SSH **host keys** stored on ZFS at `/var/lib/ssh/host_keys/` and symlinked
into `/etc/ssh/` by cloud-init.

**Kubernetes tokens**: k3s token written to `/run/secrets/k3s-token`
(tmpfs). Referenced by `/etc/rancher/k3s/config.yaml` via `token-file`.
Token is re-applied from datasource on every boot.

**TLS certificates**: k3s auto-generates and rotates serving certificates.
Additional CA certs for private registries delivered via cloud-init to
`/run/secrets/` (tmpfs, never on disk).

## 5.7 Threat Model Summary

| Threat | Mitigation |
|--------|------------|
| Supply chain (image tamper) | UEFI Secure Boot + dm-verity (every block verified) |
| Cloud-init injection | Signature verification, runcmd disabled, path allowlist |
| Lateral movement (service -> kernel) | SELinux, lockdown=integrity, ptrace_scope=2 |
| Credential theft via core dumps | Disabled at sysctl + systemd + ulimit |
| Persistence after compromise | ro root, /etc resets on reboot, rollback to known-good generation |
| Generation store tampering | Store paths are content-addressed (hash in path name); UKIs are signed |
| Network attack on listening services | Default-deny nftables, SYN cookies, fail2ban |
| Firmware tampering (Evil Maid) | TPM PCR binding, LUKS unsealing fails on firmware change |
| Container escape to IMDS | nftables blocks pod-to-169.254.169.254 on K8s nodes |
| Pod-to-pod lateral movement | Cilium network policies (eBPF-enforced, L3-L7) |
