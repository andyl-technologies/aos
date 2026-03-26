# Volumes

A volume is a named, typed storage mount declared by a job. All job storage
comes from volumes -- there is no implicit storage allocation. Every container
filesystem mount traces back to an explicit volume request in the job spec.

Three volume types exist:

- **StoreVolume** -- read-only FUSE mount of store closure sets. Replaces the
  `ViewSpec` model.
- **LocalPersistentVolume** -- persistent node-pinned ZFS dataset. Survives job
  restarts.
- **LocalVolume** -- ephemeral ZFS dataset scoped to a single job. Destroyed on
  job exit.

---

## StoreVolume

A StoreVolume is a read-only FUSE mount of one or more store object closures.
It replaces the `ViewSpec` from the current model. The daemon resolves
transitive closures, resolves NixObjects and fetches chunks, and mounts the FUSE
filesystem -- identical to the current view construction pipeline described in
[view.md](view.md) and [fuse.md](fuse.md).

Multiple StoreVolumes per job are allowed. A build container might have a single
StoreVolume for its input closure mounted at the store directory. A service
container might mount separate closures at different paths -- one for the base
system and another for a plugin set.

The StoreVolume ID is deterministic: the sorted `store_hashes` list is
concatenated and hashed. Two volume requests with the same store hashes produce
the same ID, enabling deduplication of FUSE mounts across concurrent jobs.

GC pins the entire transitive closure while the StoreVolume is active (mounted).
When the volume is destroyed, the pin is released and the closure becomes
eligible for LRU eviction. This is the same mechanism as the current view-based
pinning described in [gc.md](gc.md).

All content must be local before the StoreVolume becomes available. There is no
lazy or partial fetching -- the volume blocks during job startup until every
object and chunk in the closure is present in the local chunk store.

---

## LocalPersistentVolume

A LocalPersistentVolume is a ZFS dataset with a stable ID that persists across
job restarts. It is created on first use (or via the daemon API) and survives
until explicitly deleted or expired by TTL.

### Node Pinning

Persistent volumes are node-pinned. A job referencing an existing persistent
volume by ID is hard-pinned to the node holding that dataset. During scheduling,
only that node passes eligibility filtering -- all other peers reject the job
immediately. This is a hard constraint, not a soft affinity bonus.

A job referencing a persistent volume ID that does not yet exist on any node
behaves differently: the volume will be created on whichever node claims the
job. In this case the volume exerts soft affinity based on available local space
(see [Volume Affinity and Scheduling](#volume-affinity-and-scheduling)).

### Metadata via ZFS User Properties

Persistent volume metadata is tracked entirely via ZFS user properties. No LMDB
database or Statute coordination is needed -- the ZFS dataset itself is the
source of truth.

Properties set on each persistent volume dataset:

| Property | Example | Description |
|---|---|---|
| `user:aos:volume_id` | `vol-abc123` | Stable volume identifier |
| `user:aos:cluster_id` | `cluster-prod` | Owning cluster |
| `user:aos:created_at` | `1710000000` | Unix timestamp of creation |
| `user:aos:last_used_at` | `1710086400` | Unix timestamp of last job mount |

The daemon updates `last_used_at` each time a job mounts the volume.

### Quota and Properties

Size enforcement uses the ZFS `quota` property, set at creation time from the
volume request's `size` field. The dataset also gets `compression=zstd` and
`atime=off` by default.

### Dataset Path

```
{pool}/aos/volumes/persistent/{volume_id}
```

### Cleanup

Two cleanup mechanisms:

1. **TTL expiry.** The daemon periodically scans persistent volume datasets and
   compares `user:aos:last_used_at` against a configurable TTL (default: 7
   days). Expired volumes are destroyed. The scan interval is configurable
   (default: 1 hour).

2. **Explicit delete.** The daemon API accepts a `VolumeDelete` request that
   immediately destroys a persistent volume by ID.

### Snapshots

Persistent volumes can be ZFS-snapshotted for backup or read-only sharing. A
snapshot of a persistent volume can be cloned to create a new volume with the
same initial contents. Snapshot management is exposed via the daemon API but is
not coordinated across the cluster -- snapshots are local operations.

---

## LocalVolume

A LocalVolume is an ephemeral ZFS dataset created by the daemon during job
startup and destroyed when the job exits. It is used for transient writable
storage: build OverlayFS upper layers, container root writable layers, and
scratch space.

### Dataset Path

```
{pool}/aos/volumes/ephemeral/{cluster_id}/{job_id}/{volume_id}
```

The hierarchy encodes ownership. On job exit, the daemon destroys all datasets
under `{pool}/aos/volumes/ephemeral/{cluster_id}/{job_id}/`.

### Properties

Same defaults as persistent volumes: `quota` from the request's `size` field,
`compression=zstd`, `atime=off`.

### Orphan Cleanup

On daemon restart, the daemon scans for ephemeral datasets that have no
corresponding running job. Any dataset under
`{pool}/aos/volumes/ephemeral/{cluster_id}/{job_id}/` where `job_id` does not
match a running container is destroyed. This handles crash recovery -- ephemeral
volumes from jobs that were interrupted by a daemon crash are cleaned up on
restart.

---

## Volume Requests in Job Specs

Jobs declare volumes via `repeated VolumeRequest volumes` in the `JobSpec`. The
volume request list defines every filesystem mount the container will receive.
Every job must have at least one volume request.

### BuildSpec

For build jobs, the daemon generates volume requests automatically from the
`.drv` parse. The creator does not specify volumes -- the daemon derives them:

1. **StoreVolume** -- input closure from the derivation's `inputDrvs` and
   `inputSrcs`. Mounted read-only as the FUSE lower layer.
2. **LocalVolume (upper)** -- OverlayFS upper layer where the builder writes
   `$out`. Size derived from `ResourceLimits.disk_bytes` in the job spec (or a
   daemon default).
3. **LocalVolume (work)** -- OverlayFS work directory. Minimal size (OverlayFS
   requires a separate work dir on the same filesystem as upper).

### RunSpec

For run jobs, the creator specifies volumes explicitly. A minimal RunSpec
requires:

1. **StoreVolume** -- the container's `/nix/store` content. Without this, the
   container has no store objects.
2. **LocalVolume** -- writable root layer. The container's root filesystem is an
   OverlayFS merge of the StoreVolume (lower) and this LocalVolume (upper).

Additional volumes are optional: persistent volumes for databases, local volumes
for caches, additional store volumes for supplementary closures.

### FetchSpec

Fetch jobs have no volumes. Fetches run in the daemon process, not in
containers. The daemon downloads content, verifies hashes, chunks the result,
and publishes it to the store directly.

---

## Volume Affinity and Scheduling

Volume types interact with the scheduling model described in
[scheduling.md](scheduling.md) at both the eligibility (hard filter) and
claim delay (soft ranking) stages.

### StoreVolume -- Soft Affinity

Same as the current closure locality bonus. A peer with more of the
StoreVolume's closure cached locally computes a lower claim delay (higher
`affinity_bonus`). This is a scheduling optimization, not a constraint -- any
eligible peer can serve the job.

### LocalPersistentVolume (Existing) -- Hard Affinity

If the job references a persistent volume ID that exists on a specific node,
that node is the only eligible peer. All other peers fail the eligibility check
and reject the job immediately. This is enforced during the hard filter phase
before claim delay computation.

The peer discovers whether it holds a persistent volume by checking for the ZFS
dataset `{pool}/aos/volumes/persistent/{volume_id}` and reading its
`user:aos:volume_id` property.

### LocalPersistentVolume (New, First Use) -- Soft Affinity

If the persistent volume ID does not exist on any node, the volume will be
created on whichever node claims the job. In this case, the volume contributes
soft affinity based on available local space -- peers with more free ZFS pool
space compute a slightly lower claim delay.

### LocalVolume -- No Affinity

Ephemeral volumes are created fresh on whatever node runs the job. They
contribute no affinity signal.

### Local Space as a Resource Dimension

Available ZFS pool space is a new resource dimension in the scheduling model,
alongside CPU, memory, and disk. Peers report available local space in
LoadReports (see [load-reports.md](load-reports.md)). The four-state model
applies:

- **Reserved**: ZFS overhead, metadata, snapshots.
- **Free**: available for new volume allocations.
- **Claimed**: allocated to claimed-but-not-started jobs.
- **Active**: consumed by running job volumes.

During eligibility filtering, the peer sums the `size` fields of all volume
requests in the job spec and checks against free local space:

```rust
fn has_local_space_for(&self, volumes: &[VolumeRequest]) -> bool {
    let required: u64 = volumes.iter()
        .filter_map(|v| match &v.volume {
            Volume::Local(l) => Some(parse_quantity(&l.size)),
            Volume::Persistent(p) => {
                // Only count if we'd need to create it
                if !self.has_persistent_volume(&p.id) {
                    Some(parse_quantity(&p.size))
                } else {
                    None // already exists, no additional space needed
                }
            }
            Volume::Store(_) => None, // no local space needed
        })
        .sum();
    self.local_space_state.free >= required
}
```

---

## ZFS Integration

Both local volume types (persistent and ephemeral) use ZFS datasets. ZFS
provides quota enforcement, compression, snapshots, and efficient dataset
creation/destruction.

### Pool Configuration

The ZFS pool is configured at the daemon level:

```toml
[volumes]
zfs_pool = "aos"
default_compression = "zstd"
```

Per-cluster local space budgets limit how much of the pool a single cluster can
consume:

```toml
[clusters.prod.volumes]
local_space_budget = "500Gi"

[clusters.staging.volumes]
local_space_budget = "100Gi"
```

### Dataset Hierarchy

```
{pool}/aos/
  volumes/
    persistent/
      {volume_id}/
    ephemeral/
      {cluster_id}/
        {job_id}/
          {volume_id}/
```

The `{pool}/aos/volumes/` parent dataset is created by the daemon on first
startup if it does not exist. Compression and atime defaults are set on this
parent and inherited by children.

### Default Properties

| Property | Value | Notes |
|---|---|---|
| `quota` | From volume request `size` | Hard limit, ZFS enforced |
| `compression` | `zstd` | Inherited from parent, overridable |
| `atime` | `off` | No access time updates |

### Persistent Volume Metadata

All persistent volume metadata lives in ZFS user properties on the dataset
itself. The daemon discovers persistent volumes by scanning datasets under
`{pool}/aos/volumes/persistent/` and reading their `user:aos:*` properties. No
separate database is needed.

### Provisioning

ZFS pool creation is handled during node provisioning, not by the daemon. See
[cloud-init.md](cloud-init.md) for pool setup during first boot.

---

## Container Mount Assembly

The daemon assembles the container's mount namespace from its volume requests
during the job start phase. The assembly order depends on the job spec type.

### General Assembly

For each volume in the job's volume request list:

1. **StoreVolume**: resolve the transitive closure from `store_hashes`, fetch
   all NixObjects and chunks, mount a FUSE filesystem at a daemon-managed path
   (e.g., `/run/aos/volumes/store/{volume_id}/`). The FUSE mount blocks until
   all content is local.

2. **LocalPersistentVolume**: check if the ZFS dataset exists at
   `{pool}/aos/volumes/persistent/{volume_id}`. If not, create it with the
   requested quota. Update `user:aos:last_used_at`. The dataset's mountpoint is
   used directly.

3. **LocalVolume**: create a ZFS dataset at
   `{pool}/aos/volumes/ephemeral/{cluster_id}/{job_id}/{volume_id}` with the
   requested quota. The dataset's mountpoint is used directly.

### BuildSpec Assembly

Build containers use OverlayFS to provide a writable store directory over the
read-only FUSE view:

1. Mount StoreVolume (FUSE) at `/run/aos/volumes/store/{volume_id}/`.
2. Create LocalVolume (upper) -- ZFS dataset for the OverlayFS upper layer.
3. Create LocalVolume (work) -- ZFS dataset for the OverlayFS work directory.
4. Mount OverlayFS:
   - `lowerdir` = FUSE mount (read-only input closure)
   - `upperdir` = upper LocalVolume mount
   - `workdir` = work LocalVolume mount
   - `merged` = `/run/aos/builds/{job_id}/merged`
5. Bind the merged directory into the nspawn container via `--bind`.

### RunSpec Assembly

Run containers mount volumes at their declared paths:

1. Mount StoreVolume(s) via FUSE. Typically one StoreVolume at the store
   directory path.
2. Create or attach LocalVolume(s) and LocalPersistentVolume(s).
3. For containers needing a writable root: OverlayFS with the StoreVolume as
   lower and a LocalVolume as upper, same as build containers.
4. Bind-mount each volume at its declared `mount_path` into the nspawn
   container.

### nspawn Integration

All volume mounts are passed to systemd-nspawn as `--bind` or
`--bind-ro` flags:

```
systemd-nspawn \
  --bind-ro=/run/aos/volumes/store/{sv_id}:/nix/store \
  --bind=/path/to/local/{lv_id}:/var/data \
  --bind=/path/to/persistent/{pv_id}:/var/db \
  ...
```

Read-only volumes (StoreVolume, or LocalPersistentVolume with `read_only=true`)
use `--bind-ro`. Writable volumes use `--bind`.

---

## Volume Lifecycle

### StoreVolume

1. **Create**: daemon resolves closure, fetches content, mounts FUSE.
2. **Active**: reads served from local chunk store. Closure pinned against GC.
3. **Destroy**: FUSE unmounted, GC pin released.

Same lifecycle as current views. Multiple jobs sharing the same StoreVolume ID
share the same FUSE mount (refcounted). The mount is destroyed when the last
referencing job exits.

### LocalVolume

1. **Create**: daemon creates ZFS dataset with quota during job start.
2. **Active**: container reads/writes to the dataset.
3. **Destroy**: daemon destroys the ZFS dataset during job exit cleanup.

On daemon crash, orphaned ephemeral datasets are cleaned up on restart (see
[Orphan Cleanup](#orphan-cleanup) above).

### LocalPersistentVolume

1. **Create**: daemon creates ZFS dataset on first reference (or via API).
2. **Active**: container reads/writes. `last_used_at` updated on mount.
3. **Persist**: dataset survives job exit. Remains on the node.
4. **Destroy**: TTL expiry or explicit delete via daemon API.

Persistent volumes survive daemon crashes. On restart, the daemon rediscovers
them by scanning ZFS datasets and reading user properties.

---

## Protocol

```protobuf
// Volume request within a JobSpec.
// Each request defines a single volume mount for the container.
message VolumeRequest {
    oneof volume {
        StoreVolume store = 1;
        LocalPersistentVolume persistent = 2;
        LocalVolume local = 3;
    }
}

// Read-only FUSE mount of store closure sets.
// Replaces ViewSpec. The daemon resolves transitive closures,
// resolves NixObjects, fetches chunks, and mounts FUSE.
// ID is deterministic: hash of sorted store_hashes.
message StoreVolume {
    string id = 1;                    // deterministic from sorted store_hashes
    repeated string store_hashes = 2; // root store hashes (transitive closure resolved by daemon)
    string mount_path = 3;            // mount point in container (e.g. "/nix/store")
}

// Persistent node-pinned ZFS dataset.
// Survives job restarts. Jobs referencing an existing persistent
// volume are hard-pinned to the node holding it.
message LocalPersistentVolume {
    string id = 1;                    // stable volume ID (user-defined or generated)
    string size = 2;                  // quota, k8s Quantity format (e.g. "10Gi")
    string mount_path = 3;            // mount point in container
    bool read_only = 4;               // mount as read-only (e.g. shared snapshot)
}

// Ephemeral ZFS dataset scoped to a single job.
// Created during job startup, destroyed on job exit.
message LocalVolume {
    string id = 1;                    // ephemeral, generated per volume request
    string size = 2;                  // quota, k8s Quantity format (e.g. "10Gi")
    string mount_path = 3;            // mount point in container
}

// Daemon API: delete a persistent volume by ID.
message VolumeDeleteRequest {
    string volume_id = 1;
    string cluster_id = 2;
}

message VolumeDeleteResponse {
    bool deleted = 1;
    string error = 2;                 // non-empty on failure (e.g. volume in use)
}

// LoadFull extension: local space reporting.
// Added to LoadFull alongside existing cpu/memory/disk fields.
// Uses the same four-state ResourceState model.
//
//   ResourceCapacity local_space_capacity = 13;
//   ResourceState local_space = 14;
//
// LoadDelta extension:
//   optional ResourceState local_space = 8;
```

---

## Relationship to Other Docs

- [view.md](view.md) -- StoreVolume implementation (FUSE mount, path resolution,
  chunk reads). StoreVolume replaces ViewSpec.
- [fuse.md](fuse.md) -- FUSE filesystem backing StoreVolumes.
- [containers.md](containers.md) -- container mount assembly using volumes,
  OverlayFS setup, nspawn integration.
- [jobs.md](jobs.md) -- `VolumeRequest` in `JobSpec`, per-spec volume generation
  rules.
- [scheduling.md](scheduling.md) -- `local_space` resource dimension, persistent
  volume hard pinning in eligibility filtering.
- [load-reports.md](load-reports.md) -- `local_space` reporting in
  `LoadFull`/`LoadDelta`.
- [daemon.md](daemon.md) -- ZFS pool configuration (`[volumes]`), volume
  lifecycle management, orphan cleanup on restart.
- [gc.md](gc.md) -- StoreVolume as GC pin, ephemeral volume cleanup.
- [storage.md](storage.md) -- ZFS dataset layout under the pool.
- [cloud-init.md](cloud-init.md) -- ZFS pool provisioning during node setup.
