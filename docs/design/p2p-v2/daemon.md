# Daemon Architecture

The AOS daemon (`aos daemon`) is a single binary that participates in the
libp2p mesh, manages local storage, executes jobs, and serves content to peers.
Every node runs the same binary; configuration determines what each node does.

## Responsibilities

A running daemon:

- Joins the libp2p mesh (QUIC transport, mDNS + Kademlia discovery)
- Subscribes to cluster GossipSub topics (`jobs/announce`, `load/announce`)
- Subscribes to global GossipSub topics (`aos/store/publish`, `aos/store/replicate`, `aos/store/purge`, `aos/workflows/announce`)
- Serves stream protocols (`/aos/store/manifest/1.0.0`,
  `/aos/store/chunk/1.0.0`, `/aos/job/start/1.0.0`, `/aos/job/log/1.0.0`,
  `/aos/job/exec/1.0.0`)
- Manages the local chunk store (pack files + LMDB indexes; see
  [storage.md](storage.md))
- Manages FUSE view mounts (created on-demand by jobs)
- Publishes DHT records (provider records, job heartbeats)
- Participates in store replication protocol (if `[store.replication]` configured)
- Executes workflow steps (if `/aos/workflow/execute` permission held)
- Accepts remote workflow starts (if `workflow.accept_remote_starts` configured)
- Publishes periodic LoadReport

## Main Event Loop

The daemon runs a single tokio `select!` loop over:

- **Swarm events** -- GossipSub messages, stream requests, DHT queries
- **Job execution** -- container lifecycle (load-staggered claim, reservation-based start, announce; see [jobs.md](jobs.md) and [containers.md](containers.md))
- **Load reporting** -- periodic LoadReport publish to cluster topic
- **GC** -- periodic garbage collection of unreferenced chunks

## Configuration

Single TOML file:

```toml
[cluster]
id = "my-cluster"
seed_peers = ["/ip4/.../p2p/QmSeed1"]

[identity]
key_file = "/etc/aos/peer.key"
ucan_file = "/etc/aos/peer.ucan"

[store]
db_dir = "/var/lib/aos/db"
chunk_dir = "/var/lib/aos/chunks"

[store.replication]
reserved_bytes = 107_374_182_400   # 100 GB reserved for replication pool

[workflow]
max_steps = 10000              # max total steps per workflow
max_depth = 500                # max steps through longest path (bounds log size)
max_active_workflows = 100     # max concurrent active workflows tracked
sync_window = 60               # seconds; periodic state snapshot interval
accept_remote_starts = false   # set to true to accept /aos/workflow/start/1.0.0

[node]
system = "x86_64-linux"
features = ["kvm", "big-parallel"]
max_jobs = 8

[node.labels]
rack = "r1"
gpu = "a100"
region = "us-east"

[node.capacity]
cpu_cores = 16
memory_bytes = 68_719_476_736    # 64 GB
disk_bytes = 1_099_511_627_776   # 1 TB scratch

[node.reserved]
cpu_cores = 2                    # reserved for host OS
memory_bytes = 4_294_967_296     # 4 GB reserved
disk_bytes = 107_374_182_400     # 100 GB reserved

# Taints prevent jobs from scheduling here unless they tolerate the taint.
[[node.taints]]
key = "dedicated"
value = "ci"
effect = "NoSchedule"           # NoSchedule | PreferNoSchedule | NoExecute
```

### Node Identity

The `[node]` section declares what this peer advertises to the cluster. These
fields are published in `LoadFull` reports and used by the scheduling system:

- **system** -- architecture string matched against `NodeSelector.system` in
  job specs. Required.
- **features** -- capability strings matched against `NodeSelector.features`.
  A job requires a subset; the peer must have all of them.
- **labels** -- arbitrary key-value pairs matched against
  `NodeSelector.labels`. Used for topology-aware scheduling (rack, region, GPU
  type, etc.).
- **max_jobs** -- maximum concurrent jobs this peer will claim. Checked during
  eligibility filtering.

### Resource Capacity

`[node.capacity]` declares the total physical resources available.
`[node.reserved]` declares resources reserved for the host OS and not
allocatable to jobs. The allocatable capacity is `capacity - reserved`, which
feeds into the `ResourceCapacity` fields in LoadReport.

See [load-reports.md](load-reports.md) for how these are published and
[scheduling.md](scheduling.md) for how they influence claim delay.

### Taints and Tolerations

Taints are the peer-side complement to the job-side `NodeSelector`. A taint
marks a peer as unsuitable for general scheduling unless a job explicitly
tolerates it.

Each taint has:
- **key** + **value** -- identifies the taint (e.g. `dedicated=ci`,
  `hardware=gpu`, `maintenance=true`).
- **effect** -- what happens to jobs that don't tolerate this taint:
  - `NoSchedule` -- do not schedule new jobs here.
  - `PreferNoSchedule` -- avoid scheduling here, but allow if no other peer is
    available.
  - `NoExecute` -- do not schedule, and evict running jobs that don't tolerate
    the taint (used for draining).

A job tolerates a taint if its `NodeSelector` includes a matching toleration
(same key/value, compatible effect). See [scheduling.md](scheduling.md) for
how taints interact with eligibility filtering.

### Effective Role

The daemon's effective role is determined by its capabilities, not by a role
field:

| Has `/aos/job/claim` | Has `/aos/store/read` | Effective behavior |
|---|---|---|
| yes | yes | Builder. Claims and executes jobs, serves content. |
| no | yes | Cache node. Serves content, does not build. |
| yes | no | Builder without cache (unusual). |
| no | no | Relay. Mesh routing only. |

UCAN capabilities (from the peer's certificate chain) determine what the daemon
is authorized to do. The `[node]` configuration determines what it advertises
as available.

## Module Listing

```
aos-daemon/src/
  main.rs           -- CLI entry, config loading, tokio runtime setup
  mesh.rs           -- libp2p swarm setup, AosBehaviour (Kademlia + GossipSub + request-response)
  jobs.rs           -- JobPost handling, load-staggered claiming, reservation exec, container lifecycle
  store.rs          -- chunk store management (pack files + LMDB), manifest/chunk serving
  fuse.rs           -- FUSE view management, mount/unmount lifecycle
  load.rs           -- LoadReport computation and publishing
  view.rs           -- view construction (ViewSpec closure resolution, FUSE mount lifecycle)
  containers.rs     -- container orchestration (nspawn setup, activation types, output registration)
  exec.rs           -- container exec handling (nsenter, PTY allocation, ExecFrame multiplexing)
  workflow.rs       -- workflow engine (step claiming, transition log, speculative execution)
  gc.rs             -- garbage collection (unreferenced chunks, expired DHT records)
  config.rs         -- TOML config parsing and validation
```

## Startup Sequence

1. Load config and identity (generate keypair on first run)
2. Open chunk store (ChunkDB, AccessDB, StoreDB + pack files; see
   [storage.md](storage.md))
3. Build swarm (QUIC transport, mDNS, Kademlia, GossipSub)
4. Subscribe to cluster topics (`jobs/announce`, `load/announce`)
   Subscribe to global topics (`aos/store/publish`, `aos/store/replicate`, `aos/store/purge`, `aos/workflows/announce`)
5. Register stream protocol handlers (`/aos/store/manifest/1.0.0`,
   `/aos/store/chunk/1.0.0`, `/aos/job/start/1.0.0`, `/aos/job/log/1.0.0`,
   `/aos/job/exec/1.0.0`, `/aos/workflow/info/1.0.0`,
   `/aos/workflow/log/1.0.0`, `/aos/workflow/list/1.0.0`,
   `/aos/workflow/start/1.0.0`)
6. Publish provider record on `aos:cluster:{cluster_id}` (cluster membership advertisement)
7. If `workflow.accept_remote_starts`, publish provider record on `aos:workflow`
8. Publish initial `LoadFull` report (advertising system, features, labels,
   capacity)
9. Enter main event loop

## Shutdown Sequence

1. Stop accepting new jobs (unsubscribe from `jobs/announce`)
2. Wait for in-flight jobs to complete (with configurable timeout)
3. Unmount any active FUSE views
4. Disconnect from mesh
