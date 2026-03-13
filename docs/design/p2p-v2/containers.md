# Container Orchestration

Jobs create containers determined by the `ContainerSpec` in the `JobSpec`. All
containers run under systemd-nspawn with UID isolation and separate mount
namespaces. The `ActivationType` determines init process, activation behavior,
and lifecycle. The `ViewSpec` defines the FUSE view mounted into the container.

## Activation Types

### ACTIVATION_NONE

Mount the view via FUSE, run a shell or specified entrypoint. No special
activation. Useful for interactive shells or simple one-off commands.

### ACTIVATION_SYSTEMD_V1

Run systemd as PID 1. The view's store objects include an activation script
that installs units, configs, and binaries into the container filesystem.
systemd discovers the units and starts services.

**Activation flow:**

1. Daemon computes the transitive closure from the `ViewSpec` and creates a
   FUSE view. All manifests and chunks are fetched before the mount is
   available.
2. Daemon creates an nspawn container with systemd as init (PID 1).
3. Activation script runs early in boot:
   - Symlinks units into `/etc/systemd/system/`.
   - Symlinks configs into `/etc/`.
   - Symlinks binaries into `/usr/local/bin/`.
   - Creates required state directories.
4. systemd starts, picks up the installed units, launches services.
5. Container runs until job cancel or service exit.

As an example, a Kubernetes worker container would include kubelet, containerd,
and kube-proxy along with their configs and systemd units in its `ViewSpec`.
Activation links everything in; systemd starts the services.

**Network:** Typically `NETWORK_HOST` (host NAT) — services need network access.

**Identity:** Job identity is injected via systemd credentials
(`LoadCredential`). Services inside the container can read the credential to
obtain the job's `PeerId` for libp2p participation.

### ACTIVATION_DERIVATION

Execute a single Nix derivation and produce new store objects. Uses a
host-level build rootfs and a minimal init process (not systemd). The
`ContainerSpec.derivation` field specifies the `.drv` store hash, and
`ContainerSpec.overlay` is true to enable the writable OverlayFS layer.

#### Build Rootfs

The build rootfs is a store object configured at the daemon level:

```toml
[jobs]
build_rootfs = "{store_hash}"
```

Its contents are intentionally sparse:

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
the derivation's input closure (defined in the `ViewSpec`).

#### Container Setup

1. **Fetch and parse the derivation.** The daemon fetches the `.drv` store
   object from `ContainerSpec.derivation` and parses it to extract:
   - Builder executable (store hash + relative path)
   - Args
   - Environment variables (including `$out` — the output store hash/path)
   - Input closure (store hashes of all build-time dependencies)

2. **Create view.** The daemon creates a FUSE view from the `ViewSpec`
   (which lists the input closure). All manifests and chunks are fetched
   before the mount is available. See [view.md](view.md).

3. **Set up OverlayFS.**
   - Lower layer: FUSE mount (read-only, input closure only)
   - Upper layer: tmpfs or ZFS dataset (writable, for build output)
   - Merged: what the container sees as its store directory

4. **Spawn nspawn container:**
   - `--directory=<build_rootfs>` (reconstructed from chunk store)
   - `--bind=<merged>:<store_dir>`
   - `--private-network` (`NETWORK_NONE` mandatory)
   - `--private-users=pick` (UID isolation mandatory)
   - init = `build-init` (minimal, not systemd)

5. **build-init runs:**
   a. Sets environment variables from the `.drv` (out, src, PATH, etc.)
   b. Execs the builder specified in the `.drv`
   c. Builder reads inputs from the FUSE lower layer
   d. Builder writes output to `$out` (OverlayFS upper layer)
   e. On exit: returns exit code to daemon

#### Exit Handling

**Exit 0 (success):**

1. Daemon reads the output directory from the OverlayFS upper layer.
2. Chunks output files (FastCDC: 64KB min, 256KB avg, 1MB max).
3. Generates manifest, computes NAR hash (SHA-256, for Nix compatibility).
4. Writes manifest to `db/chunks.mdb` (`manifests_db`).
5. Writes chunk references to `chunk_refs_db` (reverse index for GC).
6. Calls `start_providing(output_store_hash)` on DHT.
7. Publishes `StorePublish` to the `store/publish` GossipSub topic.
8. Publishes `JobPost{delta: exit(JobExit{outputs: [out_hash]})}`.
9. Cleanup: unmount overlay, unmount FUSE, remove upper layer.

**Non-zero exit (failure):**

1. Daemon captures error info (exit code, last log lines).
2. Publishes `JobPost{delta: error(JobError{exit_code, message, ...})}`.
3. Optionally: ZFS snapshot of upper layer for post-mortem inspection.
4. Cleanup (or retain for a configurable inspection period).

**Network:** `NETWORK_NONE` — mandatory. No network access, same isolation as
the Nix sandbox. All inputs come from the FUSE view.

**Identity:** Available but rarely used. The daemon handles log streaming and
store registration from outside the container.

## Security Isolation

All containers share a common security baseline:

- **`--private-users=pick`**: container UID 0 maps to an unprivileged host UID.
  Prevents privilege escalation via `SO_PEERCRED` or host filesystem access.
- **Separate mount namespace**: the container sees only its FUSE/overlay mounts.

`ACTIVATION_DERIVATION` containers add further restrictions:

- **No network**: `--private-network` drops all interfaces.
- **Whitelist store access**: only declared inputs are visible via FUSE.
  Everything else returns `ENOENT`.

## Activation Comparison

| | ACTIVATION_NONE | ACTIVATION_SYSTEMD_V1 | ACTIVATION_DERIVATION |
|---|---|---|---|
| Init (PID 1) | shell/entrypoint | systemd | build-init (minimal) |
| Activation | None | activate script | None (exec builder) |
| Services | Single process | Multiple (systemd units) | Single (builder) |
| Lifecycle | Until cancel/exit | Until cancel/exit | One-shot |
| Network | Configurable | Typically NETWORK_HOST | NETWORK_NONE |
| Store mount | FUSE (view closure) | FUSE (view closure) | FUSE + OverlayFS |
| Output | None | None (services run in-place) | Store objects from overlay |

## Output Registration

When an `ACTIVATION_DERIVATION` container exits successfully, the daemon makes
the output available on the mesh:

1. Walk the output directory (the OverlayFS upper layer).
2. Chunk each file using FastCDC (64KB min, 256KB avg, 1MB max).
3. Write chunks to local pack files (dedup: skip if chunk hash exists).
4. Generate manifest (file tree with per-file chunk references).
5. Compute NAR hash on-the-fly (SHA-256, for Nix compatibility).
6. Write manifest to `db/chunks.mdb` (`manifests_db`).
7. Update `chunk_refs_db` (reverse index for GC).
8. Publish DHT provider record: `start_providing(output_store_hash)`.
9. Publish `StorePublish` to the `store/publish` GossipSub topic.
10. Publish `JobPost{delta: exit(JobExit{outputs: [store_hash, ...]})}`.

The output is now discoverable via `get_providers` and fetchable via
`/aos/store/manifest` and `/aos/store/chunk`. See
[storage.md](storage.md) and [store.md](store.md).

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

- [jobs.md](jobs.md) -- job lifecycle (create, claim, start, exit).
- [view.md](view.md) -- view model (ViewSpec, transitive closure, OverlayFS).
- [fuse.md](fuse.md) -- FUSE filesystem implementation.
- [storage.md](storage.md) -- chunk store, pack files, output registration.
- [store.md](store.md) -- output becomes available on the mesh via provider
  records and manifest/chunk protocols.
- [protocol.md](protocol.md) -- `ContainerSpec`, `ActivationType`, `ViewSpec`
  protobuf definitions.
- [auth.md](auth.md) -- job identity (`PeerId`) injected into containers.
