# Daemon Architecture

The AOS daemon (`aos daemon`) is a single binary that participates in a
libp2p network, manages local storage, executes jobs, and serves content to
peers. A single daemon instance joins one network and may participate in
multiple clusters on that network simultaneously. Each cluster gets its own
systemd slice for resource isolation.

## Responsibilities

A running daemon:

- Joins the libp2p network (QUIC transport, mDNS + Kademlia discovery)
- Subscribes to per-cluster GossipSub topics (`jobs/announce`, `load/announce`)
  for each configured cluster
- Subscribes to network-wide GossipSub topics (`aos/store/publish`,
  `aos/store/replicate`, `aos/store/purge`, `aos/workflows/announce`,
  `aos/auth/token/revoke`, `aos/auth/token/issue`)
- Serves stream protocols (`/aos/store/object/1.0.0`,
  `/aos/store/chunk/1.0.0`, `/aos/store/upload/1.0.0`,
  `/aos/store/fetch/1.0.0`, `/aos/job/create/1.0.0`, `/aos/job/start/1.0.0`,
  `/aos/job/log/1.0.0`, `/aos/job/exec/1.0.0`, `/aos/job/run/1.0.0`,
  `/aos/workflow/run/1.0.0`, `/aos/workflow/info/1.0.0`,
  `/aos/workflow/log/1.0.0`, `/aos/workflow/list/1.0.0`)
- Manages the local chunk store (shared across all clusters; see
  [storage.md](storage.md))
- Manages FUSE view mounts (created on-demand by jobs)
- Publishes DHT records (provider records, job heartbeats)
- Participates in store replication protocol (if `[store.replication]`
  configured)
- Accepts remote store uploads (if `store.upload.accept_remote` configured)
- Accepts remote store fetch requests (if `store.fetch.accept_remote` configured)
- Executes workflow steps (if `/aos/workflow/execute` permission held)
- Participates in Statute consensus (if `statute.role = validator`) or follows the chain (if `follower`)
- Manages local volume ZFS datasets (creation, quota enforcement, cleanup)
- Publishes periodic LoadReport per cluster

## Main Event Loop

The daemon runs a single tokio `select!` loop over:

- **Swarm events** -- GossipSub messages, stream requests, DHT queries
- **Job execution** -- per-cluster container lifecycle (load-staggered claim,
  reservation-based start, announce; see [jobs.md](jobs.md) and
  [containers.md](containers.md))
- **Load reporting** -- periodic LoadReport publish per cluster
- **GC** -- periodic garbage collection of unreferenced chunks

---

## Configuration

Single TOML file with network-wide and per-cluster sections.

### Network-Wide Configuration

These sections apply to the daemon as a whole, regardless of cluster
membership. There is one libp2p identity, one network, one store, and one
workflow engine per daemon.

```toml
# --- Daemon identity (one keypair per daemon) ---
[identity]
key_file = "/etc/aos/peer.key"

# --- Network (one libp2p swarm, may host multiple clusters) ---
[network]
seed_peers = ["/ip4/.../p2p/QmSeed1", "/ip4/.../p2p/QmSeed2"]

# --- Store (shared across all clusters, content-addressed) ---
[store]
db_dir = "/var/lib/aos/db"
chunk_dir = "/var/lib/aos/chunks"

[store.gc]
budget = "500Gi"
target = 0.8                       # target utilization ratio (GC runs when usage exceeds this fraction of budget)

[store.replication]
reserved = "100Gi"

[store.upload]
accept_remote = false              # accept /aos/store/upload/1.0.0
max_object_size = "10Gi"           # max NAR size per upload

[store.fetch]
accept_remote = false              # accept /aos/store/fetch/1.0.0
max_download_size = "10Gi"
pin_ttl_min = "1h"                 # minimum pin TTL (clamp floor)
pin_ttl_max = "7d"                 # maximum pin TTL (clamp ceiling)
pin_ttl_default = "24h"            # TTL when client requests 0

# --- Workflow engine (network-wide) ---
[workflows]
max_steps = 10000
max_depth = 500
max_concurrent = 100
sync_window = 60                   # state snapshot interval (seconds)
accept_remote = false              # accept /aos/workflow/run/1.0.0

# --- Volume storage (ZFS-backed) ---
[volumes]
zfs_pool = "aos"                       # ZFS pool name for volume datasets
compression = "zstd"                   # default compression for volume datasets

# --- Statute BFT KV store ---
[statute]
chain_id = "aos-main"
role = "follower"                  # validator, follower, or none
genesis_file = "/etc/aos/statute-genesis.json"

[statute.reconfiguration]
suspicion_rounds = 10              # rounds missed before suspected
halt_timeout = "5m"                # chain halt time before auto-kick
auto_rejoin = true                 # automatically accept rejoin requests
min_validators = 4                 # floor for auto-kick (below = manual only)
```

**Network-wide rationale:**

- **Identity:** one keypair = one PeerId on the network. All clusters see
  the same peer identity.
- **Store:** content-addressed objects are the same regardless of which cluster
  produced them. Sharing the store across clusters enables cross-cluster
  deduplication.
- **Workflows:** workflows can reference store objects from any cluster and
  coordinate across cluster boundaries.

### Per-Cluster Configuration

Each cluster the daemon joins gets its own section under `[clusters.<name>]`.
A daemon can participate in any number of clusters on the same network.

```toml
# --- Production cluster ---
[clusters.prod]
ucan_file = "/etc/aos/prod.ucan"   # cluster-specific UCAN chain

# What this node advertises to the "prod" cluster for scheduling
[clusters.prod.node]
system = "x86_64-linux"
features = ["kvm", "big-parallel"]

[clusters.prod.node.labels]
rack = "r1"
gpu = "a100"

[[clusters.prod.node.taints]]
key = "dedicated"
value = "ci"
effect = "NoSchedule"

# Job execution for this cluster
[clusters.prod.jobs]
max_concurrent = 8
accept_remote = false              # accept /aos/job/create/1.0.0

# Systemd slice resource allocation
[clusters.prod.slice]
cpu_weight = 100
memory_max = "32Gi"
memory_high = "30Gi"
io_weight = 100

[clusters.prod.volumes]
local_space_budget = "500Gi"           # total local volume space for this cluster
persistent_ttl = "7d"                  # TTL for unused persistent volumes

[clusters.prod.fetch]
max_concurrent = 8
max_connections_per_domain = 6

[[clusters.prod.fetch.bandwidth_limits]]
limit = "1Gi"
window = "1s"

[[clusters.prod.fetch.bandwidth_limits]]
limit = "100Mi"
window = "1m"

# --- Staging cluster (same network, different resources) ---
[clusters.staging]
ucan_file = "/etc/aos/staging.ucan"

[clusters.staging.node]
system = "x86_64-linux"
features = ["kvm"]

[clusters.staging.jobs]
max_concurrent = 4
accept_remote = true

[clusters.staging.slice]
cpu_weight = 50
memory_max = "16Gi"
memory_high = "14Gi"
io_weight = 50
```

### Node Identity (per-cluster)

The `[clusters.X.node]` section declares what this peer advertises to
cluster X. These fields are published in `LoadFull` reports and used by the
scheduling system:

- **system** -- architecture string matched against `NodeSelector.system`.
- **features** -- capability strings matched against `NodeSelector.features`.
- **labels** -- arbitrary key-value pairs for topology-aware scheduling.

A node may advertise different features or labels to different clusters (e.g.,
offer GPU to prod but not staging).

### Taints and Tolerations (per-cluster)

Taints are per-cluster. A node may be tainted as `dedicated=ci` in one cluster
but untainted in another.

Each taint has:
- **key** + **value** -- identifies the taint.
- **effect** -- `NoSchedule`, `PreferNoSchedule`, or `NoExecute`.

See [scheduling.md](scheduling.md) for how taints interact with eligibility
filtering.

### Effective Role (per-cluster)

Each cluster has its own UCAN chain (`ucan_file`). The daemon's role in a
cluster is determined by the capabilities in that cluster's UCAN:

| Has `/aos/job/claim` | Has `/aos/store/read` | Effective behavior |
|---|---|---|
| yes | yes | Builder. Claims and executes jobs, serves content. |
| no | yes | Cache node. Serves content, does not build. |
| yes | no | Builder without cache (unusual). |
| no | no | Relay. Mesh routing only. |

A daemon can be a builder in the prod cluster and a cache node in staging —
the UCAN determines what it's authorized to do in each cluster.

---

## Systemd Slice Hierarchy

Each cluster's workloads run in a dedicated systemd slice, providing resource
isolation between clusters on the same host.

```
-.slice (root)
  ├── aos-daemon.service                 (the daemon process itself)
  └── aos-clusters.slice                 (aggregate: ALL cluster workloads)
      ├── aos-cluster-prod.slice         (prod cluster workloads)
      │   ├── aos-cluster-prod-job-abc123.scope (nspawn container)
      │   └── aos-cluster-prod-job-def456.scope
      └── aos-cluster-staging.slice      (staging cluster workloads)
          └── aos-cluster-staging-job-ghi789.scope
```

The daemon process and cluster workloads are in separate cgroup subtrees. The
daemon is a system service that must always be responsive (mesh communication,
DHT, GossipSub). Cluster workloads are batch compute that can tolerate
contention. Separating them ensures the daemon is never starved by jobs.

The `aos-clusters.slice` provides an aggregate cap on ALL jobs across all
clusters (e.g., 75% CPU). Individual cluster slices subdivide within that cap.
See [cloud-init.md](cloud-init.md) for the full resource flow model and
systemd configuration.

### Resource Model

The `[clusters.X.slice]` section maps directly to systemd cgroup controls:

| Config field | systemd property | Meaning |
|---|---|---|
| `cpu_weight` | `CPUWeight` | Relative CPU share (1-10000) |
| `memory_max` | `MemoryMax` | Hard memory limit |
| `memory_high` | `MemoryHigh` | Memory pressure threshold |
| `io_weight` | `IOWeight` | Relative I/O share (1-10000) |

The daemon reads actual cgroup limits at runtime to populate LoadReport fields:

- **`ResourceCapacity.total`** = the cluster slice's allocated resources (from
  cgroup limits).
- **`ResourceCapacity.reserved`** = resources consumed outside the cluster's
  slice (other clusters, kernel, system services). Computed as: parent slice
  usage minus this cluster's slice allocation.
- **`ResourceState.active/claimed/free`** = usage within this cluster's slice.

Resources used by the staging cluster are invisible to prod's LoadReport and
vice versa. Each cluster sees only its own slice's resources.

### Slice Lifecycle

1. **Startup:** the daemon creates `aos-{cluster_id}.slice` for each configured
   cluster, applying the resource controls from `[clusters.X.slice]`.
2. **Job execution:** each nspawn container is started within its cluster's
   slice as a transient scope unit (`aos-{cluster_id}-job-{job_id}.scope`).
3. **Shutdown:** running jobs are drained, containers stopped, and the cluster
   slices are removed.

---

## Module Listing

```
aos-daemon/src/
  main.rs           -- CLI entry, config loading, tokio runtime setup
  mesh.rs           -- libp2p swarm setup, AosBehaviour (Kademlia + GossipSub + request-response)
  cluster.rs        -- per-cluster state management, topic subscriptions, LoadReport
  jobs.rs           -- JobPost handling, load-staggered claiming, reservation exec, container lifecycle
  store.rs          -- chunk store management (pack files + LMDB), NixObject resolve/chunk serving
  fuse.rs           -- FUSE view management, mount/unmount lifecycle
  load.rs           -- LoadReport computation and publishing (per-cluster, from cgroup stats)
  view.rs           -- view construction (ViewSpec closure resolution, FUSE mount lifecycle)
  containers.rs     -- container orchestration (nspawn setup, slice placement, output registration)
  exec.rs           -- container exec handling (nsenter, PTY allocation, ExecFrame multiplexing)
  workflow.rs       -- workflow engine (step claiming, transition log, speculative execution)
  statute.rs        -- Statute BFT chain (HotStuff consensus, state trie, transaction validation)
  gc.rs             -- garbage collection (unreferenced chunks, expired DHT records)
  volumes.rs        -- volume lifecycle management (ZFS dataset create/destroy, quota, persistent volume tracking)
  slices.rs         -- systemd slice management (create, configure, destroy, cgroup stats)
  config.rs         -- TOML config parsing and validation
```

## Startup Sequence

1. Load config and identity (generate keypair on first run)
2. Open databases (store.mdb, objects.mdb, chunk.mdb, gc.mdb, access.mdb, workflow.mdb + pack files; see
   [storage.md](storage.md))
3. Verify ZFS pool exists and is healthy. Scan for orphaned ephemeral volume
   datasets and destroy them. Rebuild persistent volume index from ZFS dataset
   listing.
4. Build swarm (QUIC transport, mDNS, Kademlia, GossipSub)
5. Subscribe to network-wide topics (`aos/store/publish`,
   `aos/store/replicate`, `aos/store/purge`, `aos/workflows/announce`,
   `aos/auth/token/revoke`, `aos/auth/token/issue`)
6. Register stream protocol handlers (`/aos/store/object/1.0.0`,
   `/aos/store/chunk/1.0.0`, `/aos/store/upload/1.0.0`,
   `/aos/store/fetch/1.0.0`, `/aos/job/create/1.0.0`, `/aos/job/start/1.0.0`,
   `/aos/job/log/1.0.0`, `/aos/job/exec/1.0.0`, `/aos/job/run/1.0.0`,
   `/aos/workflow/run/1.0.0`, `/aos/workflow/info/1.0.0`,
   `/aos/workflow/log/1.0.0`, `/aos/workflow/list/1.0.0`)
   Disconnect-cancellation: if the requester disconnects during
   `/aos/job/create/1.0.0`, `/aos/job/start/1.0.0`, or
   `/aos/workflow/run/1.0.0`, the daemon cancels the operation globally.
7. For each configured cluster:
   a. Create systemd slice `aos-{cluster_id}.slice` with resource controls
   b. Subscribe to cluster topics (`{cluster_id}/jobs/announce`,
      `{cluster_id}/load/announce`)
   c. Publish provider record on `aos:cluster:{cluster_id}:members` (membership)
   d. If `clusters.X.jobs.accept_remote`, publish provider record on
      `aos:cluster:{cluster_id}:job`
   e. Publish initial `LoadFull` report for this cluster
8. If `statute.role != none`, join the Statute chain (load genesis, sync blocks,
   advertise on `aos:statute:validators` if validator)
9. If `workflows.accept_remote`, publish provider record on `aos:workflow:runners`
10. If `store.replication` configured, publish provider record on `aos:store:replica`
11. If `store.upload.accept_remote`, publish provider record on `aos:store:upload`
12. If `store.fetch.accept_remote`, publish provider record on `aos:store:fetch`
13. Enter main event loop

## Shutdown Sequence

1. For each cluster: stop accepting new jobs (unsubscribe from `jobs/announce`)
2. Wait for in-flight jobs to complete (with configurable timeout)
3. Destroy ephemeral LocalVolume ZFS datasets for all exiting jobs.
4. Unmount any active FUSE views
5. Remove cluster systemd slices
6. Disconnect from mesh

---

## Relationship to Other Docs

- [volumes.md](volumes.md) -- volume types, ZFS dataset management, persistent volume lifecycle.
- [../../tla/Network.tla](../../tla/Network.tla) -- TLA+ formal specification: libp2p network model (GossipSub, DHT, partitions).
