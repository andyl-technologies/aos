# Container Orchestration

Jobs create one of two container types, determined by the `ContainerSpec` in the
`JobSpec`. Both types run under systemd-nspawn with UID isolation and separate
mount namespaces. They differ in init process, network access, store mounting,
and lifecycle.

## Profile Container

A profile container runs a long-lived workload based on a `ProfileSpec` — a
store hash registered in the DHT at `aos:profile:{peer_ident}`. The profile's
store object (fetched via the chunk store like any other content) contains
binaries, libraries, configs, systemd units, and an activation script.

### Profile Structure

The profile is a store object identified by its hash. When fetched and
reconstructed via FUSE, it contains:

```
{store_hash}/
  activate              # activation script
  bin/                  # binaries
  lib/                  # libraries
  etc/
    systemd/system/     # systemd units (kubelet.service, etc.)
    config/             # application configs
  share/
```

The daemon resolves the profile's `store_hash` from the `ProfileContainer`
field in the `JobSpec`, fetches it via `get_providers` → `/aos/store/manifest`
→ `/aos/store/chunk` (same as any store object), and mounts it via FUSE.

### Activation Types

The `ActivationType` field in the `ProfileSpec` determines boot behavior:

**ACTIVATION_TYPE_NONE** -- mount the profile via FUSE, run a shell or
specified entrypoint. No special activation. Useful for interactive shells or
simple one-off commands.

**ACTIVATION_TYPE_SYSTEMD_V1** -- run systemd as PID 1. The activation script
installs units, configs, and binaries into the container filesystem. systemd
discovers the units and starts services.

### SYSTEMD_V1 Activation Flow

1. Daemon fetches the profile store object (if not already local).
2. Daemon creates a FUSE view projecting the profile's closure.
3. Daemon creates an nspawn container with systemd as init (PID 1).
4. Activation script runs early in boot:
   - Symlinks units from the profile into `/etc/systemd/system/`.
   - Symlinks configs into `/etc/`.
   - Symlinks binaries into `/usr/local/bin/`.
   - Creates required state directories.
5. systemd starts, picks up the installed units, launches services.
6. Container runs until job cancel or service exit.

As an example, a Kubernetes worker profile would contain kubelet, containerd,
and kube-proxy along with their configs and systemd units. Activation links
everything in; systemd starts the services.

### Network and Identity

Profile containers use `NETWORK_HOST` (host NAT) -- they typically need network
access for the services they run.

Job identity is injected via systemd credentials (`LoadCredential`). Services
inside the container can read the credential to obtain the job's `PeerId` for
libp2p participation (metrics reporting, heartbeat, etc.).

## Build Container

A build container executes a single Nix derivation and produces new store
objects. It uses a host-level build rootfs and a minimal init process (not
systemd).

### Build Rootfs

The build rootfs is a store object configured at the daemon level by its hash:

```toml
[jobs]
build_rootfs = "{store_hash}"    # hash of the minimal build rootfs store object
```

The rootfs store object is fetched and reconstructed via the chunk store like
any other content. Its contents are intentionally sparse:

```
{build_rootfs_hash}/
  bin/sh -> bash
  usr/bin/env
  build-init            # minimal init process
  etc/
    passwd              # minimal (root:x:0:0:...)
    group
```

Everything else — gcc, make, python, libraries — comes from the FUSE view of
the derivation's input closure.

### Container Setup

1. **Fetch and parse the derivation.** The daemon resolves the derivation
   store hash from `JobSpec.container.builder.derivation`, fetches it via the
   store protocol (`get_providers` → `/aos/store/manifest` →
   `/aos/store/chunk`), and parses the `.drv` to extract:
   - Builder executable (store hash + relative path)
   - Args
   - Environment variables (including `$out` — the output store hash/path)
   - Input closure (store hashes of all build-time dependencies)

2. **Fetch the input closure.** For each store hash in the input closure, the
   daemon fetches via the store protocol. Inputs may come from the job creator
   (who `start_providing`'d them), from other peers, or from local cache.

3. **Create FUSE view.** The daemon creates a FUSE view in eager mode with
   projection set to the input closure. All inputs must be fully local before
   the build starts. See [fuse.md](fuse.md).

4. **Set up OverlayFS.**
   - Lower layer: FUSE mount (read-only, input closure only)
   - Upper layer: tmpfs or ZFS dataset (writable, for build output)
   - Merged: what the container sees as its store directory

5. **Spawn nspawn container:**
   - `--directory=<build_rootfs>` (reconstructed from chunk store)
   - `--bind=<merged>:<store_dir>`
   - `--private-network` (`NETWORK_NONE` mandatory)
   - `--private-users=pick` (UID isolation mandatory)
   - init = `build-init` (minimal, not systemd)

6. **build-init runs:**
   a. Sets environment variables from the `.drv` (out, src, PATH, etc.)
   b. Execs the builder specified in the `.drv`
   c. Builder reads inputs from the FUSE lower layer
   d. Builder writes output to `$out` (OverlayFS upper layer)
   e. On exit: returns exit code to daemon

### Exit Handling

**Exit 0 (success):**

1. Daemon reads the output directory from the OverlayFS upper layer.
2. Chunks output files (FastCDC: 64KB min, 256KB avg, 1MB max).
3. Generates manifest, computes NAR hash (SHA-256, for Nix compatibility).
4. Writes manifest to `chunks/index.mdb` (`manifests_db`).
5. Writes chunk references to `chunk_refs_db` (reverse index for GC).
6. Calls `start_providing(output_store_hash)` on DHT.
7. Publishes `JobPost{delta: exit(JobExit{outputs: [out_hash]})}`.
8. Cleanup: unmount overlay, unmount FUSE, remove upper layer.

**Non-zero exit (failure):**

1. Daemon captures error info (exit code, last log lines).
2. Publishes `JobPost{delta: error(JobError{exit_code, message, ...})}`.
3. Optionally: ZFS snapshot of upper layer for post-mortem inspection.
4. Cleanup (or retain for a configurable inspection period).

### Network and Identity

Build containers use `NETWORK_NONE` -- mandatory. No network access, same
isolation as the Nix sandbox. All inputs come from the FUSE view.

Job identity is available but rarely used. The daemon handles log streaming and
store registration from outside the container. The build process itself does not
need libp2p access.

## Security Isolation

Both container types share a common security baseline:

- **`--private-users=pick`**: container UID 0 maps to an unprivileged host UID.
  Prevents privilege escalation via `SO_PEERCRED` or host filesystem access.
- **Separate mount namespace**: the container sees only its FUSE/overlay mounts.

Build containers add further restrictions:

- **No network**: `--private-network` drops all interfaces.
- **Whitelist store access**: only declared inputs are visible via FUSE.
  Everything else returns `ENOENT`.

## Init Process Comparison

| | Profile Container | Build Container |
|---|---|---|
| Init (PID 1) | systemd | build-init (minimal) |
| Activation | Profile's activate script | None (exec builder directly) |
| Services | Multiple (from systemd units) | Single (the builder process) |
| Lifecycle | Long-lived (until cancel) | One-shot (exits when build completes) |
| Network | NETWORK_HOST | NETWORK_NONE |
| Store mount | FUSE (profile closure from chunk store) | FUSE + OverlayFS (input closure + writable output) |
| Output | None (services run in-place) | Store objects from overlay upper layer |
| systemd overhead | Required (manages services) | Not needed (single process) |

## Output Registration

When a build container exits successfully, the daemon makes the output available
on the mesh. The full sequence:

1. Walk the output directory (the OverlayFS upper layer).
2. Chunk each file using FastCDC (64KB min, 256KB avg, 1MB max).
3. Write chunks to local pack files (dedup: skip if chunk hash exists).
4. Generate manifest (file tree with per-file chunk references).
5. Compute NAR hash on-the-fly (SHA-256, for Nix compatibility).
6. Write manifest to `chunks/index.mdb` (`manifests_db`).
7. Update `chunk_refs_db` (reverse index for GC).
8. Publish DHT provider record: `start_providing(output_store_hash)`.
9. Publish `JobPost{delta: exit(JobExit{outputs: [store_hash, ...]})}`.

The output is now discoverable via `get_providers` and fetchable via
`/aos/store/manifest` and `/aos/store/chunk`. See
[chunk-store.md](chunk-store.md) and [store.md](store.md).

## Crash Cleanup

On daemon restart, stale containers from a previous run must be cleaned up:

1. List all nspawn machines matching `build-*` or `job-*` prefix.
2. Terminate orphaned containers (`machinectl terminate`).
3. Unmount stale OverlayFS mounts.
4. Unmount stale FUSE views.
5. Remove tmpfs upper layer directories.

For builds that were in progress: the `JobPost` CRDT will show them as `RUNNING`
but the DHT heartbeat will expire, triggering crash recovery. See
[jobs.md](jobs.md).

## Relationship to Other Docs

- [jobs.md](jobs.md) -- job lifecycle (create, claim, exec, start, exit). This
  document covers what happens at the start and exit phases inside the container.
- [fuse.md](fuse.md) -- FUSE view creation and modes. Build containers use eager
  mode; profile containers use async or lazy.
- [chunk-store.md](chunk-store.md) -- output registration writes to the chunk
  store.
- [store.md](store.md) -- output becomes available on the mesh via provider
  records and manifest/chunk protocols.
- [protocol.md](protocol.md) -- `ContainerSpec` protobuf (`BuilderSpec` vs
  `ProfileContainer`).
- [auth.md](auth.md) -- job identity (`PeerId`) injected into containers.
