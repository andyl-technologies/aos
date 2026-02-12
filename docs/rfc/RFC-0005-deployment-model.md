# RFC-0005: Generational Deployment Model

- **Status**: Draft
- **Authors**: ANDYL OS Architecture Team
- **Date**: 2026-02-10
- **Supersedes**: None

## Abstract

ANDYL OS uses a generational deployment model where each system update produces a new numbered generation backed by content-addressed store paths in `/nix/store`. Updates are delivered as delta bundles (built by `deploy/bundle.nix`) containing only new store paths, compressed with zstd and signed with minisign (via `deploy/sign.nix`). Generations are applied atomically via rename operations. systemd-boot's boot counting protocol provides automatic rollback after failed boots (configurable via `aos.update.bootTries`, default 3). A health check service validates new generations before marking them as good. Mark-and-sweep garbage collection (configured via `modules/services/gc.nix`) reclaims disk space from old generations.

## Motivation

Traditional server updates modify the system in place, creating partial-update failure modes, configuration drift, and difficult rollback scenarios. The generational model treats each system state as an immutable, numbered snapshot. Switching between generations is an atomic symlink swap, making upgrades instant and rollbacks trivial. Content-addressed store paths enable deduplication across generations (unchanged packages are shared), and delta bundle updates minimize network transfer. Boot counting provides a hardware-level safety net: if a new generation cannot boot successfully, the boot loader automatically falls back to the previous known-good generation.

## Design

### 1. Core Concepts

- **Store path:** An immutable, content-addressed directory under `/nix/store`. Example: `/nix/store/abc123...-bash-5.2`. The hash is derived from all build inputs.
- **System profile:** A store path containing a directory tree that references all packages, services, and configuration for a complete system. Example: `/nix/store/xyz789...-aos-system`.
- **Generation:** A numbered symlink pointing to a system profile. Example: `/var/lib/aos/generations/system-42` -> `/nix/store/xyz789...-aos-system`.
- **Current generation:** The active generation, indicated by `/var/lib/aos/generations/system` -> `system-42`.

### 2. Content-Addressed Store Paths Shared Across Versions

When two generations share the same version of a package (e.g., both use bash-5.2 built with the same inputs), they reference the same store path. The store path exists once on disk but is referenced by multiple generations.

```
Generation 41 profile:
  bin/bash -> /nix/store/abc123...-bash-5.2/bin/bash     (shared)
  bin/nginx -> /nix/store/old111...-nginx-1.25.3/bin/nginx

Generation 42 profile:
  bin/bash -> /nix/store/abc123...-bash-5.2/bin/bash     (shared)
  bin/nginx -> /nix/store/new222...-nginx-1.25.4/bin/nginx
```

In this example, bash is shared (same store path in both generations) while nginx differs (different store paths because the version changed). This deduplication means a typical update that changes a few packages adds only the new store paths to disk, not a complete copy of the system.

### 3. Filesystem Layout

The runtime filesystem combines the ext4 golden image partition (read-only)
with ZFS datasets (created by Ignition on first boot) for all mutable state.
Generations are managed on the ext4 root; all writable data lives on ZFS.

```
/                                     ext4: ANDYL-ROOT (read-only at runtime)
  nix/
    store/                            Read-only, on ext4 root partition
      abc123...-bash-5.2/
      def456...-linux-6.12.11/
      ghi789...-aos-system/           Generation 41 system profile
      xyz789...-aos-system/           Generation 42 system profile
      ...                            (thousands of store paths)

  var/                                ZFS: aos-pool/var (writable, created by Ignition)
    lib/
      aos/
        generations/
          system -> system-42         Current generation (symlink)
          system-41 -> /nix/store/ghi789...-aos-system
          system-41.meta              Generation 41 metadata
          system-42 -> /nix/store/xyz789...-aos-system
          system-42.meta              Generation 42 metadata
        updates/                      Staged update bundles
      containerd/                     ZFS: aos-pool/var/lib/containerd
    log/                              ZFS: aos-pool/var/log (persistent logs)

  etc/                                OverlayFS: base from profile + upper on ZFS
  boot/
    efi/                              ESP mount point
      loader/
        loader.conf
        entries/
          andyl-os-41.conf
          andyl-os-42.conf            (or andyl-os-42+3.conf during assessment)
```

**Storage split:** The ext4 root partition holds the immutable store and
generation profiles. ZFS datasets (created by Ignition on first boot)
hold all mutable state: `/var`, logs, container data, databases, etc.
This hybrid approach keeps the golden image simple and portable while
giving runtime data the benefits of ZFS (checksumming, compression,
snapshots, dynamic allocation).

### 4. Generation Metadata

Each generation has an associated metadata file:

```json
{
  "generation": 42,
  "profile": "/nix/store/xyz789...-aos-system",
  "timestamp": "2026-01-15T14:30:00Z",
  "git_commit": "a1b2c3d4e5f6...",
  "andyl_os_version": "0.3.1",
  "role": "k8s-worker",
  "changelog": "Updated containerd 1.7.23 -> 1.7.24, kernel 6.12.10 -> 6.12.11",
  "manifest_hash": "sha256:aabbccdd...",
  "previous_generation": 41
}
```

### 5. Delta Update Bundles

Updates are delivered as delta bundles built by `deploy/bundle.nix`. The bundle builder computes the store closure diff between old and new system toplevels, compresses each new store path with zstd, and packages them with a manifest.

**Update flow:**

```
Build Server              Update Server         Target Machine
                          (HTTPS/CDN)           (ANDYL OS)

nix-build -A bundle
  (deploy/bundle.nix)
       |
compute diff:
  nix-store --query
  --requisites (old/new)
       |
compress with zstd-15
       |
sign bundle
  (deploy/sign.nix,
   minisign Ed25519)
       |
upload to update ------> serves via HTTPS
  server                       |
                               +---------> aos-update agent
                                            1. polls for update (timer)
                                            2. downloads manifest
                                            3. computes local diff
                                            4. downloads bundle
                                            5. verifies signature
                                            6. verifies store path hashes
                                            7. unpacks store paths
                                            8. creates generation symlink
                                            9. installs boot entry
                                            10. reboots
```

**Bundle building with `deploy/bundle.nix`:**

The bundle builder is a Nix derivation that takes the old and new system toplevels as inputs:

```nix
# From deploy/bundle.nix
{ pkgs, lib, oldSystem, newSystem, version }:

# 1. Compute store closures
nix-store --query --requisites ${oldToplevel} | sort > old-paths
nix-store --query --requisites ${newToplevel} | sort > new-paths

# 2. Compute delta (paths in new but not in old)
comm -13 old-paths new-paths > delta-paths

# 3. Compress each delta path with zstd
tar -cf - -C / "$storePath" | zstd -15 -T0 -q > store/${basename}.tar.zst

# 4. Write manifest.json with path list, hashes, sizes

# 5. Create final tarball
tar -cf aos-update-${version}.tar manifest.json store/
```

**Bundle signing with `deploy/sign.nix`:**

The signing derivation produces a minisign (Ed25519) detached signature and a verification receipt:

```nix
# From deploy/sign.nix
{ pkgs, lib, bundle, signingKey, comment ? null }:

# Sign with minisign
minisign -S -s "${signingKey}" -m "${bundleName}" -t "${trustedComment}"

# Self-verify if public key is available
minisign -V -p "${signingKey}.pub" -m "${bundleName}"

# Write signing receipt (JSON: bundle name, algorithm, SHA-256)
```

**Update bundle contents:**
- `manifest.json` -- version metadata, path list with hashes and sizes
- `store/` -- zstd-compressed store path archives (one per new store path)

**Transport model:** Pull-based HTTPS. Machines poll the update server on their own schedule (configurable via `aos.update.checkInterval`, default 3600 seconds). For urgent patches, a push trigger via SSH initiates an immediate check:

```bash
ssh root@target aos-update check --now
```

### 6. Atomic Store Path Installation

Unpacking new store paths into `/nix/store` uses a temp-then-rename strategy for atomicity:

```bash
install_store_path() {
    archive=$1
    target_path=$2   # e.g., /nix/store/abc123...-bash-5.2

    # Check if path already exists (idempotent)
    if [ -d "$target_path" ]; then return 0; fi

    # Unpack to temporary location (same filesystem for atomic rename)
    temp_path="/nix/store/.tmp-$(basename $target_path)-$$"
    mkdir -p "$temp_path"
    zstd -d < "$archive" | tar -xf - -C "$temp_path"

    # Atomic rename into final location
    mv "$temp_path" "$target_path"

    # Make read-only
    chmod -R a-w "$target_path"
}
```

`mv` (rename) on the same filesystem is atomic in Linux. Each store path either fully exists or does not.

**Generation registration (also atomic):**

```bash
register_generation() {
    gen_num=$1
    profile_path=$2

    # Create generation symlink atomically (create temp, rename)
    ln -sf "$profile_path" "/var/lib/aos/generations/system-${gen_num}.tmp"
    mv -T "/var/lib/aos/generations/system-${gen_num}.tmp" \
          "/var/lib/aos/generations/system-${gen_num}"

    # Update "current" symlink
    ln -sf "system-${gen_num}" "/var/lib/aos/generations/system.tmp"
    mv -T "/var/lib/aos/generations/system.tmp" "/var/lib/aos/generations/system"
}
```

### 7. systemd-boot Boot Counting Protocol

systemd-boot implements automatic boot assessment through filename-based counting. The boot tries count is configured via `aos.update.bootTries` (default: 3) in `modules/services/update.nix`.

**Boot entry with counting:**

```ini
# /boot/efi/loader/entries/andyl-os-42+3.conf
title   ANDYL OS Generation 42
linux   /andyl-os/<hash>-vmlinuz
initrd  /andyl-os/<hash>-initrd.cpio.zst
options root=LABEL=ANDYL-ROOT rw init=/nix/store/xyz789...-aos-system/boot/init \
        andyl.generation=42
```

**Boot counting lifecycle:**

```
Step 1: Deploy gen-42
  File: andyl-os-42+3.conf (3 tries remaining)

Step 2: First boot attempt
  systemd-boot renames: andyl-os-42+2.conf (2 remaining)

Step 3: If boot succeeds + health check passes:
  systemd-bless-boot renames: andyl-os-42.conf (no counter = verified good)

Step 4: If all 3 attempts fail:
  File becomes: andyl-os-42+0.conf (0 remaining)
  systemd-boot automatically selects previous entry on next boot
```

### 8. Automatic Rollback After Failed Boots

The automatic rollback sequence:

1. New generation boots, health check fails or system crashes.
2. System reboots (via watchdog, panic, or manual).
3. systemd-boot decrements the counter in the filename.
4. After exhausting all tries (counter reaches +0), systemd-boot boots the previous generation (which has no counter suffix, meaning it is verified good).
5. Previous generation's health check passes.
6. System is stable on the old generation.
7. Alert sent to monitoring system.

No human intervention is required. The boot loader handles rollback at the firmware level.

### 9. Health Check Service

The health check is configured by `modules/services/update.nix`. After every boot of a new (unverified) generation, the `aos-health-check` service runs:

```nix
# From modules/services/update.nix
systemd.services."aos-health-check" = {
  description = "AOS Boot Health Check";
  wantedBy = [ "multi-user.target" ];
  after = [ "multi-user.target" ];
  serviceConfig = {
    Type = "oneshot";
    RemainAfterExit = true;
    ExecStart = "/usr/bin/aos-update health-check";
    # If healthy, bless this boot so the counter stops.
    ExecStartPost = "/usr/bin/systemd-bless-boot good";
  };
};
```

**Health check script:**

```bash
#!/usr/bin/env bash
set -euo pipefail

CHECKS_PASSED=0
CHECKS_TOTAL=0

check() {
    local name=$1; shift
    CHECKS_TOTAL=$((CHECKS_TOTAL + 1))
    if "$@"; then
        CHECKS_PASSED=$((CHECKS_PASSED + 1))
    else
        log "FAIL: $name"
    fi
}

# Core system checks
check "systemd running"        systemctl is-system-running --quiet
check "networkd online"        networkctl status --no-pager
check "DNS resolution"         getent hosts update.aos.internal
check "NTP synchronized"       timedatectl show -p NTPSynchronized --value | grep -q yes
check "store mount read-only"  mount | grep '/nix/store' | grep -q 'ro,'
check "journal healthy"        journalctl --verify --quiet 2>/dev/null

# Role-specific checks
ROLE=$(cat /etc/aos/role 2>/dev/null || echo "base")
case "$ROLE" in
    k8s-worker|k8s-control-plane)
        check "containerd running"  systemctl is-active --quiet containerd
        check "kubelet running"     systemctl is-active --quiet kubelet
        check "kubelet healthz"     curl -sf http://localhost:10248/healthz
        ;;
esac

# Verdict
[ "$CHECKS_PASSED" -eq "$CHECKS_TOTAL" ]
```

### 10. Garbage Collection

Over time, `/nix/store` accumulates store paths from old generations. Garbage collection is configured by `modules/services/gc.nix`:

```nix
# From modules/services/gc.nix
options.aos.gc = {
  enable = lib.mkOption { default = true; };
  schedule = lib.mkOption { default = "weekly"; };
  keepGenerations = lib.mkOption { default = 5; };
  olderThan = lib.mkOption { default = "7d"; };
};
```

**Algorithm:**

```
Phase 1: Determine GC Roots
  roots = {all kept generation symlinks}
        + {store paths referenced by running processes via /proc}

Phase 2: Mark (compute reachable set via BFS)
  reachable = transitive_closure(roots, reference_graph)

Phase 3: Sweep (delete unreachable paths)
  for each path in /nix/store:
    if path not in reachable:
      delete(path)

Phase 4: Clean up old generation symlinks and boot entries
```

**Reference graph:** Store paths reference other store paths (e.g., bash references glibc). These references are recorded in the generation manifest. The GC agent loads reference data from all kept generations' manifests and computes the transitive closure.

The GC runs at low priority (`IOSchedulingClass=idle`, `Nice=19`, `CPUSchedulingPolicy=idle`) to minimize impact on running workloads. It is implemented as a systemd timer:

```nix
# From modules/services/gc.nix
systemd.timers."aos-gc" = {
  wantedBy = [ "timers.target" ];
  timerConfig = {
    OnCalendar = cfg.schedule;
    RandomizedDelaySec = "1h";
    Persistent = true;
  };
};
```

### 11. /proc Scanning for Safety

The GC scans `/proc` to prevent deleting store paths that are currently in use by running processes:

- `/proc/*/maps` -- memory-mapped files (shared libraries)
- `/proc/*/exe` -- the executable binary
- `/proc/*/fd/*` -- open file descriptors

```bash
# Scan /proc/*/maps for store path references
for maps_file in /proc/[0-9]*/maps; do
    while IFS= read -r line; do
        if [[ "$line" =~ /nix/store/([a-z0-9]{32}-[^/[:space:]]+) ]]; then
            store_path="/nix/store/${BASH_REMATCH[1]}"
            roots["$store_path"]=1
        fi
    done < "$maps_file" 2>/dev/null
done
```

This prevents the scenario where:
1. Process A runs from generation 40.
2. Generation 40 is GC'd (only keeping last 5, current is 45).
3. Process A crashes because its shared libraries are deleted.

The `/proc` scan keeps those store paths alive as GC roots.

### 12. GC Locking

The GC must not run concurrently with updates. Both use a shared lock file:

- **GC:** Acquires exclusive lock. If update is in progress, GC skips.
- **Update agent:** Acquires shared lock during store path installation. If GC is running, update waits.

```bash
exec 9>"/var/lock/aos-gc.lock"
flock -n 9 || { echo "GC already running or update in progress"; exit 1; }
```

### 13. Update Agent Configuration

The update agent is fully configurable via `modules/services/update.nix`:

```nix
# From modules/services/update.nix — key options
aos.update = {
  enable = true;              # Enable update agent
  server = "https://update.aos.internal";
  channel = "stable";         # stable, testing, unstable
  checkInterval = 3600;       # seconds between checks
  autoUpdate = false;         # stage only, or auto-apply
  maxRetries = 3;
  retryDelay = 300;           # seconds between retries
  bootTries = 3;              # boot counting attempts
  signingKeyPath = "/etc/aos/update-signing-key.pub";
  gc = {
    schedule = "weekly";
    keepGenerations = 5;
    minAgeHours = 168;        # 7 days
  };
};
```

The module generates:
- `/etc/aos/update.conf` -- configuration file consumed by the update agent
- `aos-update-check.timer` -- periodic timer for update polling
- `aos-update-check.service` -- downloads and verifies update bundles
- `aos-update-apply.service` -- applies staged updates
- `aos-health-check.service` -- post-boot health validation
- `aos-rollback.service` -- emergency rollback to previous generation

### 14. Manual Rollback

```bash
# List available generations
aos-update generations list
# Generation 42 (current, FAILED)
# Generation 41 (verified)
# Generation 40 (verified)

# Roll back to generation 41
aos-update rollback --to=41
# Sets generation 41 as default boot entry, reboots
```

**Emergency rollback from boot menu:**
1. Reboot the machine.
2. systemd-boot menu appears (3-second timeout).
3. Select the desired generation entry.
4. System boots into that generation.

### 15. Failure Scenarios and Recovery

| Scenario | Effect | Recovery |
|----------|--------|----------|
| Download failure | Incomplete bundle on disk | Agent retries. No store paths modified. |
| Signature verification failure | Agent rejects update | Alert sent. No changes applied. |
| Store path unpacking failure (disk full) | Some paths installed, some not | Agent deletes partially-installed paths. Temp-then-rename ensures no partial store paths exist. |
| Health check failure (post-boot) | Boot counting decrements | After exhausting boot tries, automatic rollback to previous generation. Alert sent. |
| ESP corruption (power loss during write) | Unbootable system | Boot from USB rescue image. Regenerate boot entries from `/var/lib/aos/generations`. |

## Alternatives Considered

**A/B partition scheme:** Rejected because it wastes 50% of disk space and limits rollback to a single previous version. Nix generations can keep N previous versions with shared store paths.

**Container-based updates (like CoreOS rpm-ostree):** Rejected because rpm-ostree uses RPM packages internally, losing the content-addressing and reproducibility benefits of Nix store paths.

**ZFS as the root filesystem:** Considered but rejected for the golden image. ZFS adds complexity to image generation, requires ZFS kernel modules at imaging time, and is less portable across deployment targets (bare metal, VMs, cloud). Instead, ANDYL OS uses ext4 for the immutable root (simple, portable, works everywhere) and ZFS for mutable runtime data only (`/var`, container storage, logs). ZFS datasets are created by Ignition on first boot from unpartitioned disk space.

**ZFS send/receive as the update mechanism:** Considered as a complement to NAR-based updates. ZFS send/receive operates at the block level and can be more efficient for large changes but requires ZFS on both build and target machines. Since the store lives on ext4 (not ZFS), NAR-based updates are the natural fit. ZFS send/receive could still be used for `/var` data migration between machines.

**Push-based update model:** Rejected as the primary model because pull-based is more resilient (works behind NAT/firewalls, no inbound ports needed). Push is supported as an optional trigger for urgent patches.

## Security Considerations

- **Signed update bundles** (minisign Ed25519 via `deploy/sign.nix`) prevent unauthorized or tampered updates from being installed.
- **Store path hash verification** ensures each store path matches its manifest entry.
- **Atomic store path installation** (temp-then-rename) prevents partial updates from corrupting the store.
- **Read-only `/nix/store`** at runtime prevents modification of installed software.
- **Boot counting** at the firmware level ensures a bad update cannot permanently brick the system.
- **GC locking** prevents race conditions between garbage collection and update installation.
- **`/proc` scanning** prevents the GC from deleting store paths in active use.

## Compatibility

- **systemd-boot:** Required for boot counting protocol. UEFI firmware required.
- **NAR format:** Standard Nix archive format. Well-tested in production.
- **Existing monitoring:** The health check service integrates with standard monitoring via exit codes and systemd unit status.
- **Nix store:** The deployment model uses standard `/nix/store` content-addressed paths. No experimental Nix features are required.

## Open Questions

1. **Delta updates:** Should we support binary delta compression (casync, zchunk) for large store paths that changed slightly (e.g., kernel rebuild with a single config change)?
2. **GC during active workloads:** Should GC be restricted to maintenance windows, or is the `IOSchedulingClass=idle` + `Nice=19` approach sufficient?

## References

- systemd Boot Counting: https://systemd.io/AUTOMATIC_BOOT_ASSESSMENT/
- NAR Archive Format: https://nixos.org/guides/nix-pills/nix-store-paths.html
- systemd-bless-boot: https://www.freedesktop.org/software/systemd/man/systemd-bless-boot.service.html
- Boot Loader Specification: https://systemd.io/BOOT_LOADER_SPECIFICATION/
- minisign: https://jedisct1.github.io/minisign/
