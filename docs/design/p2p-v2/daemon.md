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
- Subscribes to network-wide GossipSub topics (`aos/workflows/announce`,
  `aos/auth/token/revoke`)
- Serves stream protocols (`/aos/store/object/1.0.0`,
  `/aos/store/chunk/1.0.0`, `/aos/store/upload/1.0.0`,
  `/aos/job/create/1.0.0`, `/aos/job/start/1.0.0`,
  `/aos/job/log/1.0.0`, `/aos/job/exec/1.0.0`, `/aos/job/run/1.0.0`,
  `/aos/workflow/state/1.0.0`,
  `/aos/workflow/log/1.0.0`)
- Manages the local chunk store (shared across all clusters; see
  [storage.md](storage.md))
- Manages FUSE view mounts (created on-demand by jobs)
- Publishes DHT records (provider records, job heartbeats)
- Fetches and pins store objects matching mount affinities from Statute state
- Accepts remote store uploads (if `node.labels.store-upload = "true"`)
- Executes workflow steps (if `/aos/workflow/execute` permission held)
- Participates in Statute consensus (if `node.labels.statute = "validator"`) or follows the chain (if `"follower"`)
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
membership. There is one node descriptor, one libp2p swarm, one store, and one
workflow engine per daemon.

```toml
# --- Node descriptor (one keypair, one label set per daemon) ---
[node]
system = "x86_64-linux"
key_file = "/etc/aos/peer.key"
seed_peers = ["/ip4/.../p2p/QmSeed1", "/ip4/.../p2p/QmSeed2"]

[node.labels]
rack = "r1"
statute = "validator"              # "validator", "follower", or absent (no Statute participation)
store-upload = "true"              # accepts /aos/store/upload/1.0.0

[node.features]
kvm = true
big-parallel = true

[node.limits]
max_jobs = 8                       # aggregate across all clusters

# --- Store (shared across all clusters, content-addressed) ---
[store]
db_dir = "/var/lib/aos/db"

[[store.tiers]]
name = "nvme"
chunk_dir = "/var/lib/aos/chunks/nvme"
budget = "500Gi"
labels = { media = "nvme", speed = "fast" }

[[store.tiers]]
name = "hdd"
chunk_dir = "/mnt/hdd/aos/chunks"
budget = "10Ti"
labels = { media = "hdd", speed = "slow" }

[store.gc]
budget = "500Gi"
target = 0.8                       # target utilization ratio (GC runs when usage exceeds this fraction of budget)

[store.upload]
max_upload_size = "10Gi"           # max NAR size per upload
pin_ttl_min = "1h"
pin_ttl_max = "7d"
pin_ttl_default = "24h"
network_query_height = 2

# --- Workflow engine (network-wide) ---
[workflows]
max_steps = 10000
max_depth = 500
max_concurrent = 100
sync_window = 60                   # state snapshot interval (seconds)
# accept_remote removed — use node/cluster labels (workflows = "true")

# --- Volume storage (ZFS-backed) ---
[volumes]
zfs_pool = "aos"                       # ZFS pool name for volume datasets
compression = "zstd"                   # default compression for volume datasets

# --- Statute BFT KV store (chain-specific config only; role comes from node.labels.statute) ---
[statute]
chain_id = "aos-main"
genesis_file = "/etc/aos/statute-genesis.json"

[statute.reconfiguration]
suspicion_rounds = 10              # rounds missed before suspected
halt_timeout = "5m"                # chain halt time before auto-kick
auto_rejoin = true                 # automatically accept rejoin requests
min_validators = 4                 # floor for auto-kick (below = manual only)
```

**Network-wide rationale:**

- **Node:** one keypair = one PeerId on the network. All clusters see the same
  peer identity. The node's flat label set (`[node.labels]`) describes
  hardware, location, storage capabilities, and participation flags. Labels
  are the universal vocabulary — there are no separate boolean flags or role
  enums. Statute participation is determined by `node.labels.statute`, store
  upload acceptance by `node.labels.store-upload`, etc. The `[node.features]`
  section declares Nix-style system features (kvm, big-parallel). The
  `[node.limits]` section caps aggregate resource consumption.
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

# Cluster-specific labels (merged with node.labels; cluster wins on conflict)
[clusters.prod.labels]
jobs = "true"                      # accepts job claims in this cluster
workflows = "true"                 # accepts workflow submissions
gpu = "a100"

# Cluster-specific limits
[clusters.prod.limits]
max_jobs = 6
local_space = "500Gi"

# Taints are per-cluster (a node may be tainted differently in different clusters)
[[clusters.prod.taints]]
key = "dedicated"
value = "ci"
effect = "NoSchedule"

# Systemd slice resource allocation
[clusters.prod.slice]
cpu_weight = 100
memory_max = "32Gi"
memory_high = "30Gi"
io_weight = 100

[clusters.prod.volumes]
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

[clusters.staging.labels]
jobs = "true"

[clusters.staging.limits]
max_jobs = 4

[clusters.staging.slice]
cpu_weight = 50
memory_max = "16Gi"
memory_high = "14Gi"
io_weight = 50
```

**Edge/observer node example** — a minimal node that follows the Statute chain
and observes a cluster without building anything:

```toml
[node]
system = "aarch64-linux"
key_file = "/etc/aos/peer.key"
seed_peers = ["/ip4/.../p2p/QmSeed1"]

[node.labels]
statute = "follower"

[[store.tiers]]
name = "flash"
chunk_dir = "/var/lib/aos/chunks"
budget = "64Gi"
labels = { media = "flash" }

[statute]
chain_id = "aos-main"
genesis_file = "/etc/aos/statute-genesis.json"

[clusters.prod]
ucan_file = "/etc/aos/prod.ucan"
# no cluster labels — just observes
```

### Node Descriptor and Effective Labels

A node has ONE flat label set that describes everything — hardware, location,
storage, capabilities. There are no scattered boolean flags or role enums.
Labels are the universal vocabulary.

- **Node-wide labels** (`[node.labels]`) describe the node itself: rack
  placement, Statute participation, store upload acceptance, etc.
- **Node-wide features** (`[node.features]`) declare Nix-style system features
  (kvm, big-parallel) matched against `NodeSelector.features`.
- **Node-wide system** (`node.system`) is the architecture string matched
  against `NodeSelector.system`.
- **Per-cluster labels** (`[clusters.X.labels]`) add cluster-specific
  capabilities: whether the node accepts jobs, workflows, GPU availability, etc.
- **Effective labels** for a cluster = `node.labels | clusters.X.labels`
  (cluster labels override node labels on conflict).

Labels determine behavior: `jobs = "true"` means accept job claims in that
cluster, `statute = "validator"` means participate in consensus,
`store-upload = "true"` means accept remote store uploads. UCAN capabilities
gate authorization; labels gate configuration. Both must be present for a
capability to be active.

A node may advertise different labels to different clusters (e.g., offer GPU
to prod but not staging) by setting cluster-specific labels.

### Taints and Tolerations (per-cluster)

Taints are per-cluster. A node may be tainted as `dedicated=ci` in one cluster
but untainted in another.

Each taint has:
- **key** + **value** -- identifies the taint.
- **effect** -- `NoSchedule`, `PreferNoSchedule`, or `NoExecute`.

See [scheduling.md](scheduling.md) for how taints interact with eligibility
filtering.

### Effective Role (per-cluster)

Each cluster has its own UCAN chain (`ucan_file`). The daemon's effective
behavior in a cluster is determined by BOTH the labels (configuration) and the
UCAN capabilities (authorization):

| Has `jobs = "true"` label | Has `/aos/job/claim` UCAN | Behavior |
|---|---|---|
| yes | yes | Builder. Claims and executes jobs. |
| yes | no | Misconfigured. Label advertises but UCAN blocks. |
| no | yes | Authorized but not configured. Won't claim. |
| no | no | Not a builder. |

| Has `store-upload = "true"` label | Has `/aos/store/write` UCAN | Behavior |
|---|---|---|
| yes | yes | Accepts remote store uploads. |
| yes | no | Misconfigured. |
| no | yes | Authorized but not configured. |
| no | no | Does not accept uploads. |

| `node.labels.statute` value | Behavior |
|---|---|
| `"validator"` | Participates in HotStuff consensus, votes on blocks. |
| `"follower"` | Syncs blocks from validators, does not vote. |
| absent | No Statute participation. |

A daemon can be a builder in the prod cluster and a pure observer in staging —
the combination of labels and UCANs determines what it does in each cluster.

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

The `[clusters.X.slice]` section maps directly to systemd cgroup controls.
Resource limits from `[clusters.X.limits]` cap job counts and storage; the
slice section handles cgroup-level controls:

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
  store.rs          -- chunk store management (tiered storage, pack files + LMDB), NixObject resolve/chunk serving
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

1. Load config and node descriptor (generate keypair on first run)
2. Open databases (store.mdb, objects.mdb, chunk.mdb, gc.mdb, access.mdb, workflow.mdb + pack files; see
   [storage.md](storage.md))
3. Verify ZFS pool exists and is healthy. Scan for orphaned ephemeral volume
   datasets and destroy them. Rebuild persistent volume index from ZFS dataset
   listing.
4. Build swarm (QUIC transport, mDNS, Kademlia, GossipSub)
5. Subscribe to network-wide topics (`aos/workflows/announce`,
   `aos/auth/token/revoke`)
6. Register stream protocol handlers (`/aos/store/object/1.0.0`,
   `/aos/store/chunk/1.0.0`, `/aos/store/upload/1.0.0`,
   `/aos/job/create/1.0.0`, `/aos/job/start/1.0.0`,
   `/aos/job/log/1.0.0`, `/aos/job/exec/1.0.0`, `/aos/job/run/1.0.0`,
   `/aos/workflow/state/1.0.0`,
   `/aos/workflow/log/1.0.0`)
   Disconnect-cancellation: if the requester disconnects during
   `/aos/job/create/1.0.0` or `/aos/job/start/1.0.0`, the daemon cancels
   the operation globally.
7. For each configured cluster:
   a. Create systemd slice `aos-{cluster_id}.slice` with resource controls
   b. Subscribe to cluster topics (`{cluster_id}/jobs/announce`,
      `{cluster_id}/load/announce`)
   c. Publish provider record on `aos:cluster:{cluster_id}:members` (membership)
   d. If effective labels include `jobs = "true"`, publish provider record on
      `aos:cluster:{cluster_id}:job`
   e. Publish initial `LoadFull` report for this cluster (includes effective
      labels = `node.labels | clusters.X.labels`)
8. If `node.labels.statute` is set, join the Statute chain (load genesis, sync
   blocks, advertise on `aos:statute:validators` if `statute = "validator"`)
9. Walk Statute state, compute effective affinities, queue fetch-on-pin for matching objects not yet local
10. If `node.labels.store-upload = "true"`, publish provider record on `aos:store:upload`
11. Enter main event loop

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
