# Phase 5: Generational Deployment Model

**Phase Number:** 5

## Objective

Implement the generational deployment system: the update agent (`andyl-os-agent`), NAR-based content transport, atomic store path registration, boot entry management with boot counting, health check integration, automatic rollback, and garbage collection of old generations.

## Prerequisites

- Phase 4 complete: Bootable base image with systemd-boot, ext4 read-only root, writable /var on ZFS
- Image manifest format defined
- Signing keys generated and deployed
- Understanding of Guix NAR archive format and narinfo structure
- ZFS kernel modules included in initrd (for mounting datapool on boot)

## Deliverables

- `andyl-os-agent` binary (or script) -- update agent running on target machines
- Update server API specification (HTTPS endpoints for manifest, bundle, signature)
- NAR archive generation tooling (build server side)
- Atomic store path unpacking and registration logic
- Boot entry management with systemd-boot boot counting protocol
- Health check service (`andyl-os-health-check.service`)
- `systemd-bless-boot` integration for marking successful boots
- Garbage collection tool (`andyl-os-gc`)
- GC systemd timer and service
- Locking mechanism between update agent and GC
- Complete update sequence tested end-to-end

## Detailed Task Checklist

### 5.1 Update Server Design

- [ ] Define the update server API:
  - [ ] `GET /api/v1/updates/latest` -- returns JSON with latest generation number, manifest URL, bundle URL, signature URL
  - [ ] `GET /updates/gen-<N>/manifest.json` -- generation manifest
  - [ ] `GET /updates/gen-<N>/bundle.tar` -- NAR archive bundle
  - [ ] `GET /updates/gen-<N>/bundle.tar.sig` -- bundle signature
- [ ] Choose update server implementation: static HTTPS file server (nginx) or CDN
- [ ] Set up TLS with the project's CA certificate
- [ ] Configure caching headers:
  - [ ] Manifest: `Cache-Control: public, max-age=300` (5 min)
  - [ ] Bundle: `Cache-Control: public, max-age=86400` (1 day)
- [ ] Test server with sample manifests and bundles

### 5.2 NAR Archive Generation (Build Server)

- [ ] Create a build script that generates update bundles:
  - [ ] Build the new system profile: `guix system build`
  - [ ] Compute the store closure of the new profile: `guix gc --references --recursive`
  - [ ] Fetch the current manifest from the target (or from the update server)
  - [ ] Compute the diff: new store paths = new_closure - current_closure
  - [ ] Export new store paths as NAR archives: `guix archive --export <path>`
  - [ ] Compress each NAR with zstd: `zstd --ultra -22`
  - [ ] If kernel/initrd changed, include new kernel and initrd
  - [ ] Generate new manifest JSON
  - [ ] Create the update bundle (tar of NARs, manifest, boot files)
  - [ ] Sign the bundle with minisign
- [ ] Test: generate a bundle for a known diff between two generations
- [ ] Verify bundle contains only the delta (not the full closure)

### 5.3 andyl-os-agent: Core Update Logic

- [ ] Create the `andyl-os-agent` project (shell script initially, consider Go/Rust later)
- [ ] Implement `update check` subcommand:
  - [ ] Read update server URL from `/etc/andyl-os/update.conf`
  - [ ] Query `GET /api/v1/updates/latest`
  - [ ] Compare latest generation with current generation
  - [ ] Report: "up to date" or "update available: gen N -> gen M"
- [ ] Implement `update download` subcommand:
  - [ ] Download manifest and bundle from update server
  - [ ] Support HTTP range requests for resume on interrupted downloads
  - [ ] Store downloads in `/var/cache/andyl-os/updates/`
  - [ ] Show download progress
- [ ] Implement `update verify` subcommand:
  - [ ] Verify bundle signature with embedded public key (`/etc/andyl-os/update-signing-key.pub`)
  - [ ] Extract manifest from bundle
  - [ ] Verify each NAR hash matches manifest
- [ ] Implement `update apply` subcommand:
  - [ ] Acquire exclusive lock (`/var/lock/andyl-os-gc.lock`)
  - [ ] Remount ext4 root (`/gnu/store`) as read-write
  - [ ] For each NAR in bundle:
    - [ ] Check if store path already exists (idempotent)
    - [ ] Unpack to temp directory on same ext4 filesystem (`/gnu/store/.tmp-<name>-$$`)
    - [ ] Atomic rename (`mv`) to final location (same filesystem = atomic)
    - [ ] Set read-only permissions
  - [ ] Create generation symlink atomically (on ZFS `/var`):
    - [ ] `ln -sf <profile> /var/guix/profiles/system-<N>.tmp`
    - [ ] `mv -T system-<N>.tmp system-<N>`
  - [ ] Update "current" symlink:
    - [ ] `ln -sf system-<N> /var/guix/profiles/system.tmp`
    - [ ] `mv -T system.tmp system`
  - [ ] Write generation metadata file (`system-<N>.meta`) to ZFS `/var`
  - [ ] Remount ext4 root (`/gnu/store`) as read-only
  - [ ] Release lock
- [ ] Implement `update now` subcommand (combines check + download + verify + apply + reboot)

### 5.4 Boot Entry Management

- [ ] Implement boot entry creation in the agent:
  - [ ] Copy kernel image to ESP with content-addressed name
  - [ ] Copy initrd to ESP with content-addressed name
  - [ ] Write boot loader entry with boot counting suffix (`+3`):
    ```
    /boot/efi/loader/entries/andyl-os-<N>+3.conf
    ```
  - [ ] Set as default: `bootctl set-default andyl-os-<N>+3.conf`
- [ ] If using UKIs:
  - [ ] Generate UKI with ukify (kernel + initrd + cmdline + os-release)
  - [ ] Place on ESP: `/boot/EFI/Linux/andyl-os_<N>+3-0.efi`
  - [ ] Filename format follows systemd-boot boot counting protocol
- [ ] Implement `generations list` subcommand:
  - [ ] List all generations with number, timestamp, status (current, verified, failed)
  - [ ] Show boot entry status (boot counting state)

### 5.5 Boot Counting Integration

- [ ] Create `systemd-bless-boot.service` integration:
  - [ ] After successful boot and health check, run `systemd-bless-boot good`
  - [ ] This removes the `+N-M` suffix from the boot entry, marking it as verified
- [ ] Configure systemd-boot to recognize boot counting protocol:
  - [ ] Entry format: `andyl-os-<N>+<tries_left>-<tries_done>.conf`
  - [ ] On each boot, systemd-boot decrements tries_left and increments tries_done
  - [ ] When tries_left reaches 0, entry is skipped; fallback to previous verified entry
- [ ] Set default boot tries to 3 (configurable)

### 5.6 Health Check Service

- [ ] Create `/usr/bin/andyl-os-health-check` script
- [ ] Implement core system checks:
  - [ ] `systemctl is-system-running` returns `running` or `degraded`
  - [ ] networkd is online (`networkctl status`)
  - [ ] DNS resolution works (`getent hosts`)
  - [ ] NTP synchronized (`timedatectl show -p NTPSynchronized`)
  - [ ] `/gnu/store` mounted read-only
  - [ ] Journal is healthy (`journalctl --verify`)
- [ ] Implement role-specific checks (detected from `/etc/andyl-os/role`):
  - [ ] k8s-worker: containerd running, kubelet running, CNI plugins exist, kubelet healthz
  - [ ] database: postgresql running, pg_isready
  - [ ] edge: envoy running, envoy admin ready
- [ ] Create systemd service unit:
  - [ ] `After=multi-user.target`
  - [ ] `ConditionPathExists` on boot counting entry files
  - [ ] On success: `systemctl start boot-complete.target`
  - [ ] On failure: log, let boot counting handle rollback
- [ ] Create `boot-complete.target` that `systemd-bless-boot.service` depends on

### 5.7 Rollback Procedures

- [ ] Implement `rollback` subcommand in agent:
  - [ ] `andyl-os-agent rollback --to=<gen>` -- set specified generation as default, reboot
  - [ ] `andyl-os-agent rollback` -- roll back to previous verified generation
- [ ] Document automatic rollback flow:
  - [ ] New generation boots -> health check fails -> reboot
  - [ ] Boot counting decrements -> after 3 failures -> fallback to previous
  - [ ] Previous generation boots -> health check passes (already verified)
  - [ ] Alert sent to monitoring
- [ ] Document manual rollback via boot menu:
  - [ ] Reboot -> systemd-boot menu (3-second timeout) -> select desired generation
- [ ] Document emergency rollback from rescue USB

### 5.8 Garbage Collection

- [ ] Create `/usr/bin/andyl-os-gc` script
- [ ] Implement Phase 0 -- Determine generations to keep:
  - [ ] Read retention policy from `/etc/andyl-os/gc.conf` (default: keep 5 generations)
  - [ ] List all generations, sort by number
  - [ ] Identify generations to remove (oldest beyond retention count)
  - [ ] Never remove the currently booted generation
  - [ ] Respect minimum age (default: 24 hours)
- [ ] Implement Phase 1 -- Compute GC roots:
  - [ ] GC roots = kept generation symlinks
  - [ ] Add running process roots: scan `/proc/*/maps`, `/proc/*/exe`, `/proc/*/fd/*` for `/gnu/store/` references
- [ ] Implement Phase 2 -- Mark (compute reachable set):
  - [ ] Load reference database from kept generations' manifests
  - [ ] BFS/DFS traversal from roots through reference graph
  - [ ] Result: set of all reachable store paths
- [ ] Implement Phase 3 -- Sweep:
  - [ ] Enumerate all store paths in `/gnu/store/`
  - [ ] Delete store paths not in reachable set
  - [ ] Track bytes freed and paths deleted
  - [ ] Support dry-run mode
- [ ] Implement Phase 4 -- Cleanup:
  - [ ] Remove old generation symlinks and metadata files
  - [ ] Remove old boot entries from ESP
  - [ ] Remove orphaned kernel/initrd images from ESP
- [ ] Add exclusive locking: acquire `/var/lock/andyl-os-gc.lock` (shared with update agent)
- [ ] Create systemd timer (`andyl-os-gc.timer`):
  - [ ] `OnCalendar=weekly`, `RandomizedDelaySec=3600`, `Persistent=true`
- [ ] Create systemd service (`andyl-os-gc.service`):
  - [ ] Remount ext4 root store read-write before GC, read-only after
  - [ ] `IOSchedulingClass=idle`, `Nice=19` for low priority
  - [ ] `TimeoutSec=3600`

### 5.9 GC Configuration

- [ ] Create `/etc/andyl-os/gc.conf`:
  - [ ] `keep_generations = 5`
  - [ ] `min_age_hours = 24`
  - [ ] `schedule = weekly`
  - [ ] `low_space_threshold_percent = 15`
  - [ ] `dry_run = false`
  - [ ] `timeout_minutes = 60`

### 5.10 Update Agent Configuration

- [ ] Create `/etc/andyl-os/update.conf`:
  - [ ] `server = https://update.andyl-os.internal`
  - [ ] `channel = stable`
  - [ ] `check_interval = 3600` (seconds)
  - [ ] `auto_update = false` (require manual trigger by default)
  - [ ] `max_retries = 3`
  - [ ] `retry_delay = 300` (seconds)
- [ ] Create systemd timer for periodic update checks (optional, for auto-update mode)

### 5.11 Push-Based Update Trigger

- [ ] Implement SSH-triggered update: `ssh root@target andyl-os-agent update --now`
- [ ] Create a fleet update script:
  - [ ] Iterate over fleet inventory
  - [ ] SSH to each machine and trigger update
  - [ ] Support rolling updates (update N machines at a time)
  - [ ] Wait for health check pass before proceeding to next batch

### 5.12 End-to-End Update Test

- [ ] Boot generation 1 in QEMU (with Ignition config for ZFS setup)
- [ ] Verify first boot: ext4 root mounted read-only, ZFS datapool created, `/var` on ZFS
- [ ] Create generation 2 (with a minor package change)
- [ ] Generate update bundle (gen 1 -> gen 2)
- [ ] Host bundle on a local HTTP server
- [ ] Run `andyl-os-agent update --now` on the VM
- [ ] Verify: download, verify, unpack to ext4 store, reboot
- [ ] Verify: gen 2 boots, health check passes, boot entry marked verified
- [ ] Verify: gen 1 boot entry still exists
- [ ] Verify: generation metadata persists on ZFS `/var/guix/profiles/`
- [ ] Run garbage collection with keep=1
- [ ] Verify: gen 1 store paths cleaned up from ext4 root
- [ ] Verify: gen 2 still functional, ZFS datasets intact

### 5.13 justfile Targets

- [ ] Add `update-bundle` target: generates an update bundle from build server
- [ ] Add `update-serve` target: starts a local update server (for testing)
- [ ] Add `gc` target: runs GC inside the build environment
- [ ] Add `generations` target: lists generations

## Acceptance Criteria

1. `andyl-os-agent update --now` downloads, verifies, installs, and reboots to a new generation
2. Boot counting works: failed boots automatically fall back to previous generation after 3 attempts
3. Health check runs after each boot and correctly marks successful boots
4. Manual rollback via `andyl-os-agent rollback` works
5. Garbage collection correctly identifies and deletes unreferenced store paths
6. GC respects running processes (does not delete memory-mapped store paths)
7. GC and update agent are mutually exclusive (locking works)
8. Update bundles contain only delta store paths (not full closure)
9. All NAR signatures are verified before unpacking
10. End-to-end update test passes in QEMU

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| Atomic rename fails across filesystem boundaries | Medium | Partial store path installation | Ensure temp directory is on same filesystem as `/gnu/store` |
| Boot counting not supported by all UEFI firmware | Low | Rollback doesn't work automatically | Test with OVMF; document firmware requirements; manual rollback always available |
| GC deletes store path still needed by running process | Low | Running process crashes | `/proc/*/maps` scanning catches this; add extensive testing |
| Update download interrupted, leaving corrupt state | Medium | Failed update | All store paths are atomic (temp-then-rename); interrupted download can be resumed |
| Health check false positive (marks bad generation as good) | Low | Bad generation persists | Make health checks comprehensive; include role-specific checks |
| GC race with update (concurrent modification) | Medium | Corruption | Exclusive locking via flock; both agents use shared lock file |

## Estimated Complexity

**XL (Extra Large)**

This phase implements the core deployment infrastructure. The update agent, NAR transport, atomic installation, boot counting, health checks, rollback, and garbage collection are all tightly coupled and must work correctly in failure scenarios. The GC algorithm (mark-and-sweep with process scanning) is particularly delicate. Extensive testing in QEMU is required for each failure scenario.
