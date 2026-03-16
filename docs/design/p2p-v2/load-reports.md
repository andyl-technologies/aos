# LoadReport

LoadReport is a periodic metric broadcast published on
`aos/cluster/{cluster_ident}/load/announce`, authorized by `/aos/load/announce
WHERE .cluster == {cluster_ident}`.

---

## 1. Wire Format

LoadReport uses a full/delta oneof. The first report from a peer (and periodic
refreshes) is a `LoadFull` containing static metadata (system, features,
capacity) and a complete resource snapshot. Subsequent reports are `LoadDelta`
messages containing only fields that have changed since the last full report.

See [protocol.md](protocol.md) for the complete protobuf definitions:
`LoadReport`, `LoadFull`, `LoadDelta`, `ResourceCapacity`, `ResourceState`,
`SmoothedTrend`.

## 2. Resource State Model

Each resource (CPU, memory, disk, local_space) uses a four-state model via
`ResourceState`:

- **Active**: currently consumed by running workloads.
- **Claimed**: allocated to a job but not actively consumed (could spike).
- **Free**: available for new jobs.

The total allocatable capacity is `total - reserved` (from `ResourceCapacity`),
which equals `active + claimed + free`.

The `local_space` resource represents available ZFS pool space for
`LocalVolume` and `LocalPersistentVolume` allocations. It follows the same
four-state model as other resources.

## 3. EWMA Smoothing

Raw resource measurements are noisy. Each peer smooths its local measurements
using an exponentially weighted moving average (EWMA) before publishing:

| Resource | Alpha | Rationale |
|---|---|---|
| CPU | 0.3 | CPU fluctuates rapidly; higher alpha tracks changes quickly. |
| Memory | 0.1 | Memory changes more gradually; lower alpha reduces noise. |
| Disk | 0.05 | Disk changes are slow and monotonic during builds. |
| Local space | 0.05 | ZFS pool space changes slowly, similar to disk. |

The EWMA value and its slope (rate of change) are published in the
`SmoothedTrend` fields. Receivers use these for extrapolation when reports are
stale (see [scheduling.md](scheduling.md#decay-estimation) for the decay
estimation model).

## 4. Adaptive Submission Rate

LoadReports are not sent at a fixed interval. The submission rate adapts to the
rate of change:

| Condition | Delay | Rationale |
|---|---|---|
| Job state change (claim, start, exit) | Immediate | Other peers need to know capacity changed. |
| Moderate resource change (>10% delta) | 2-5s | Meaningful change worth communicating soon. |
| Small resource change (<10% delta) | 15s | Minor fluctuation; no urgency. |
| No change | 60s (heartbeat) | Liveness signal; confirms peer is still alive. |

A `LoadDelta` is sent only when at least one field differs from the previously
sent report. If nothing has changed, the peer waits for the heartbeat interval.

## 5. Delta Encoding

After sending a `LoadFull`, subsequent reports use `LoadDelta` containing only
fields that have changed. The receiver applies deltas on top of the last known
full state. If a delta arrives for a peer with no known full state, it is
discarded (the receiver waits for the next `LoadFull`).

The `sequence` field in `LoadReport` is a monotonically increasing counter.
Receivers discard reports with a sequence number less than or equal to the last
seen sequence for that peer.

## 6. Staggered Heartbeats

To prevent thundering-herd spikes where all peers send heartbeats
simultaneously, each peer offsets its heartbeat timer:

```
offset = hash(peer_id) % heartbeat_interval
```

This spreads heartbeat traffic evenly across the interval.

## 7. Scheduling Use

LoadReports are **not** a CRDT -- they are ephemeral observations. Each peer
maintains a table of the most recent LoadReport per peer (keyed by `peer_id`,
overwritten on each receive).

LoadReports serve scheduling decisions:

- **Job claiming**: when a job is posted, eligible peers compute a claim delay
  based on their relative load position, chunk store affinity, and confidence
  in load estimates. See [scheduling.md](scheduling.md) for the full claim
  delay computation including load ranking, affinity bonus, confidence penalty,
  urgency factor, and failure avoidance.

If a peer's LoadReport is older than `peer_liveness_timeout` (from
ClusterConfig, or a built-in default), that peer is considered offline and
excluded from scheduling decisions.

## Protocol

```protobuf
// GossipSub topic: aos/cluster/{id}/load/announce
// Periodic resource utilization report published by each peer.
// Uses full/delta encoding: first report is LoadFull, subsequent
// reports are LoadDelta containing only changed fields.
message LoadReport {
    string peer_id = 1;             // reporting peer
    uint64 timestamp = 2;           // epoch microseconds
    uint64 sequence = 3;            // monotonic counter for ordering/dedup

    oneof report {
        LoadFull full = 4;          // complete state (first report + periodic refresh)
        LoadDelta delta = 5;        // incremental changes since last full
    }

    bytes signature = 6;            // peer signs the report
}

// Complete resource snapshot including static metadata.
// Published on first report and periodically as a refresh.
message LoadFull {
    string system = 1;              // architecture (e.g. "x86_64-linux")
    repeated string features = 2;   // node features (e.g. ["kvm", "big-parallel"])
    ResourceCapacity capacity = 3;  // total allocatable resources (from cgroup limits)
    ResourceState cpu = 4;          // current CPU utilization
    ResourceState memory = 5;       // current memory utilization
    ResourceState disk = 6;         // current disk utilization
    uint32 jobs_running = 7;        // number of running job containers
    uint32 jobs_claimed = 8;        // number of claimed but not yet started jobs
    SmoothedTrend cpu_trend = 9;    // EWMA-smoothed CPU trend
    SmoothedTrend memory_trend = 10; // EWMA-smoothed memory trend
    uint32 fetch_jobs_active = 11;  // active FetchSpec jobs
    uint32 fetch_jobs_max = 12;     // max concurrent fetch jobs (from config)
    ResourceState local_space = 13;      // ZFS pool space for volume allocations
    SmoothedTrend local_space_trend = 14; // EWMA trend for local space usage
}

// Incremental update containing only fields that changed since
// the last report. Receivers apply deltas on top of the last
// known full state. Deltas for unknown peers are discarded.
message LoadDelta {
    optional ResourceState cpu = 1;
    optional ResourceState memory = 2;
    optional ResourceState disk = 3;
    optional uint32 jobs_running = 4;
    optional uint32 jobs_claimed = 5;
    optional SmoothedTrend cpu_trend = 6;
    optional SmoothedTrend memory_trend = 7;
    optional ResourceState local_space = 8;
    optional SmoothedTrend local_space_trend = 9;
}

// Total and reserved capacity for a resource type.
// Allocatable = total - reserved.
message ResourceCapacity {
    uint64 total = 1;               // total capacity (bytes or millicores)
    uint64 reserved = 2;            // host/OS overhead, not allocatable to jobs
}

// Four-state resource utilization model.
// total allocatable = active + claimed + free.
message ResourceState {
    uint64 active = 1;              // currently consumed by running workloads
    uint64 claimed = 2;             // allocated to a job but not actively consumed
    uint64 free = 3;                // available for new jobs
}

// EWMA-smoothed trend for a resource metric.
// Published for receivers to extrapolate when reports are stale.
message SmoothedTrend {
    double ewma = 1;                // exponentially weighted moving average
    double slope = 2;               // rate of change (for linear extrapolation)
}
```

## Relationship to Other Docs

- [volumes.md](volumes.md) -- volume types that consume local_space, persistent volume lifecycle.
- [../../tla/Network.tla](../../tla/Network.tla) -- TLA+ formal specification: GossipSub message delivery model for load reports.
