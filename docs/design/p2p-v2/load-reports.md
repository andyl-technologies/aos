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

Each resource (CPU, memory, disk) uses a four-state model via `ResourceState`:

- **Active**: currently consumed by running workloads.
- **Claimed**: allocated to a job but not actively consumed (could spike).
- **Free**: available for new jobs.

The total allocatable capacity is `total - reserved` (from `ResourceCapacity`),
which equals `active + claimed + free`.

## 3. EWMA Smoothing

Raw resource measurements are noisy. Each peer smooths its local measurements
using an exponentially weighted moving average (EWMA) before publishing:

| Resource | Alpha | Rationale |
|---|---|---|
| CPU | 0.3 | CPU fluctuates rapidly; higher alpha tracks changes quickly. |
| Memory | 0.1 | Memory changes more gradually; lower alpha reduces noise. |
| Disk | 0.05 | Disk changes are slow and monotonic during builds. |

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
