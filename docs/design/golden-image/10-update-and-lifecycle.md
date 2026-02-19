# 10. Update and Lifecycle

## 10.1 Generation Model

AOS is a generation-based OS. Each generation is a complete system closure
identified by the hash of its `system.build.toplevel` derivation. Multiple
generations coexist in the store partition. The active generation is
determined by a profile symlink chain:

```
/var/lib/profiles/system -> system-N-link -> /var/lib/store/<hash>-aos-system
```

Generation numbers are monotonically increasing integers. The `system`
symlink always points to the currently active generation.

### Update Flow

```
1. APM checks registry for new system generation (timer or manual)
2. Downloads delta store paths (only new/changed paths, not full image)
3. Imports NARs into /var/lib/store/, verifies hashes
4. Creates new profile link: system-(N+1)-link -> new store path
5. Builds and signs a UKI for the new generation, installs to ESP
6. Sets new generation as default boot entry
7. Switch:
   a. Reboot: systemd-boot loads new generation's UKI
   b. Live: `aos system switch --now` triggers systemd soft-reboot
8. Cloud-init re-applies same role config from same datasource
9. Old generations retained per retention policy (default: keep 5)
10. `aos gc --generations` removes old generations + frees store paths
```

### Rollback

Rollback is instantaneous — a single symlink swap to a previous generation
plus a boot entry update. No downloads or store changes needed:

```
aos system rollback           # Set previous generation for next boot
aos system rollback --now     # Live rollback via soft-reboot
```

On boot failure (3 consecutive failed boots), systemd-boot's boot counting
mechanism automatically falls back to the previous generation.

## 10.2 Generation Switching

### Reboot Switch (Default)

The safest mode. `aos system switch <gen>` updates the default boot entry
and the profile symlink. On next reboot, systemd-boot loads the new
generation's UKI, which boots into the new root.

### Live Switch (systemd soft-reboot)

`aos system switch --now <gen>` performs a userspace-only restart:

1. Mounts the new generation's root at `/run/nextroot/`
2. Runs `systemctl soft-reboot`
3. systemd sends SIGTERM to all userspace processes, then SIGKILL
4. `switch_root` to `/run/nextroot/`
5. systemd re-executes PID 1 from the new root
6. All services start fresh from the new generation
7. Cloud-init re-applies role config

The kernel stays running — no firmware, BIOS, or bootloader
initialization. A live switch completes in seconds rather than the
minutes a full reboot takes.

**Compared to NixOS switch-to-configuration**: NixOS diffs systemd units
and surgically restarts only changed services. This is more granular but
complex and can leak state from unchanged services. AOS uses the simpler
soft-reboot approach for a clean slate on every switch.

## 10.3 Version Compatibility

Each generation carries metadata at `aos-version` in its store path:

```yaml
generation_id: "sha256-abc123..."
built_from: "systems/golden.nix"
build_time: "2026-02-16T12:00:00Z"
min_userdata_version: "1"
max_userdata_version: "2"
```

Userdata includes `aos_userdata_version: "1"`. Cloud-init checks
compatibility before applying. Incompatible versions fall back to base
role.

## 10.4 Generation Retention Policy

Old generations are retained until explicitly removed. Defaults:

| Policy | Default | Flag |
|--------|---------|------|
| Keep N most recent | 5 | `aos gc --generations --keep 5` |
| Delete older than | 30 days | `aos gc --generations --older-than 30d` |
| Pin specific generation | indefinite | `aos system pin <gen>` |
| Dry run | — | `aos gc --generations --dry-run` |

Pinned generations are never removed by `aos gc --generations`. Use
`aos system unpin <gen>` to allow GC.

When a generation is removed:
1. Its profile link (`system-N-link`) is deleted
2. Its UKI is removed from the ESP
3. Its boot entry is removed from systemd-boot
4. Store paths unique to that generation become GC candidates
5. `aos gc --collect` (or the next periodic GC) frees the store paths

## 10.5 APM Integration

System generations are published to APM registries as store closures —
the same mechanism used for packages. A system generation is a "package"
whose store path is a toplevel derivation.

```
apm update                         # Fetch latest registry metadata
apm upgrade --system               # Download + install new system generation
```

APM downloads only the delta (new/changed store paths), not the full
system image. Packages shared between the old and new generation are
already in the local store and are not re-downloaded.

After APM installs a new generation, `aos system switch` activates it.
This separation ensures that downloading a generation does not
automatically activate it — the operator controls when the switch happens.

## 10.6 Rolling Update Strategy (Kubernetes Clusters)

```
Phase 1: Canary (1 worker)
  - apm upgrade --system + aos system switch --now
  - Verify health for 30 min
  - Rollback on failure: aos system rollback --now

Phase 2: Workers (10% batches)
  - Cordon + drain + switch generation (reboot or --now) + uncordon
  - 5 min between batches, halt on failure

Phase 3: Control plane (one at a time)
  - Maintain etcd quorum
  - k3s handles version upgrade on restart
  - Verify API server health before proceeding to next CP node
```
