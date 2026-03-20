# Scheduling

Scheduling is fully decentralized. There is no central scheduler. Each peer
independently decides whether and when to claim a job based on its local state
and its view of the cluster's load (from LoadReports). Scheduling quality
degrades gracefully with incomplete information.

## Eligibility (Hard Filters)

Before computing claim delay, a peer checks hard filters. If any filter fails,
the job is instantly rejected:

1. **System match**: `job.node_selector.system == node.system` (from `[node]`).
2. **Features match**: `job.node_selector.features` is a subset of `node.features`
   (from `[node.features]`).
3. **Label match**: `job.node_selector.labels` satisfied by effective labels
   (`node.labels ∪ clusters.X.labels`).
4. **Taint toleration**: for each of my `NoSchedule` taints (from
   `[[clusters.X.taints]]`), the job's `node_selector.tolerations` must include
   a matching toleration (same key and value, or value-wildcard).
   `PreferNoSchedule` taints are checked during soft ranking, not here.
   `NoExecute` taints reject scheduling AND evict running jobs that lack a
   toleration.
5. **Capacity**: `jobs_running + jobs_claimed < clusters.X.limits.max_jobs`.
6. **Failure avoidance**: the derivation has not failed on this builder recently
   (checked against local failure history).
7. **Resource headroom**: enough free resources for the job's `ResourceLimits`.
8. **Local volume space**: the sum of `LocalVolume.size` and new
   `LocalPersistentVolume.size` in the job's volume requests must fit within
   `local_space_state.free`.
9. **Persistent volume pinning**: if any `LocalPersistentVolume` in the job's
   volume requests references an existing volume ID, this peer must be the node
   holding that volume.

## Claim Delay (Soft Ranking)

The claim delay determines priority. Lower delay means the peer claims first
and wins the job. The delay is computed as:

```
claim_delay = (load_rank_delay - affinity_bonus + confidence_penalty + taint_penalty) * urgency_factor + failure_penalty
```

### Taint Penalty (0 or 200ms)

If the peer has `PreferNoSchedule` taints that the job tolerates, a 200ms
penalty is added. This makes tainted peers claim later, so untainted peers win
when available. If no untainted peer claims within the delay window, the
tainted peer proceeds.

### Load Rank Delay (50-500ms)

Based on relative load position among eligible peers. Uses LoadReport data with
confidence bounds.

The peer estimates its own load conservatively (upper bound of confidence
interval) and compares against other peers' estimated loads optimistically
(lower bound). Rank = fraction of peers confidently less loaded than me.

```rust
fn load_rank_delay(&self, job: &JobSpec, load_table: &LoadTable) -> Duration {
    let now = Instant::now();
    let my_estimate = load_table.get(&self.peer_id).estimated_utilization(Resource::Cpu, now);
    let my_load = my_estimate.upper;  // conservative for self

    let mut peer_loads: Vec<(f64, f64)> = load_table.iter()
        .filter(|(pid, est)| {
            *pid != &self.peer_id
            && est.is_alive(now, self.liveness_timeout)
            && est.matches_job(job)
        })
        .map(|(_, est)| {
            let e = est.estimated_utilization(Resource::Cpu, now);
            (e.lower, e.confidence)  // optimistic about peers
        })
        .collect();

    let better_than_me = peer_loads.iter()
        .filter(|(load, confidence)| *load < my_load && *confidence > 0.5)
        .count();

    let my_rank = better_than_me as f64 / (peer_loads.len() + 1).max(1) as f64;
    Duration::from_millis((50.0 + my_rank * 450.0) as u64)
}
```

### Affinity Bonus (0-200ms reduction)

Based on fraction of the job's input closure that exists in the local chunk
store. The peer walks the job spec store object's closure (via `store_db`)
and checks which store hashes have local NixObjects.

```rust
fn affinity_bonus(&self, job_spec_hash: &StoreHash) -> Duration {
    let closure = self.store_db.transitive_closure(job_spec_hash);
    if closure.is_empty() { return Duration::ZERO; }
    let local_hits = closure.iter()
        .filter(|h| self.chunk_db.has_object(h))
        .count();
    let fraction = local_hits as f64 / closure.len() as f64;
    Duration::from_millis((fraction * 200.0) as u64)
}
```

> **Note:** StoreVolume locality replaces the previous "input closure" language
> for affinity computation. Additionally, if this node holds a
> `LocalPersistentVolume` referenced by the job, the maximum affinity bonus
> (200ms) is applied unconditionally.

### Confidence Penalty (0-200ms)

If the peer's own load estimate is uncertain (just joined, or stale
self-measurement), a penalty is added. If peers' estimates are uncertain (many
peers at max uncertainty), a penalty is also added (the peer cannot make good
relative comparisons).

```rust
fn confidence_penalty(&self, load_table: &LoadTable) -> Duration {
    let my_confidence = load_table.get(&self.peer_id)
        .map(|e| e.confidence())
        .unwrap_or(0.5);

    let avg_peer_confidence = load_table.iter()
        .filter(|(pid, _)| *pid != &self.peer_id)
        .map(|(_, e)| e.confidence())
        .sum::<f64>() / load_table.len().max(1) as f64;

    let penalty = (1.0 - my_confidence) * 100.0 + (1.0 - avg_peer_confidence) * 100.0;
    Duration::from_millis(penalty as u64)
}
```

### Urgency Factor (0.3-1.0 multiplier)

Jobs near their deadline claim faster:

```rust
fn urgency_factor(&self, job: &JobSpec) -> f64 {
    let remaining = job.deadline.saturating_sub(now_micros());
    let remaining_secs = remaining as f64 / 1_000_000.0;

    if remaining_secs < 300.0 { 0.3 }       // < 5 min
    else if remaining_secs < 3600.0 { 0.7 }  // < 1 hour
    else { 1.0 }
}
```

### Failure Penalty (0-300s)

Exponential backoff for derivations that have previously failed on this
builder:

```rust
fn failure_penalty(&self, drv_hash: &str) -> Duration {
    match self.failure_history.get(drv_hash) {
        Some((count, _)) if *count >= 2 => Duration::from_secs(5u64.pow((*count).min(4))),
        _ => Duration::ZERO,
    }
}
```

After 2+ failures: 25s. After 3: 125s. After 4+: 625s (effectively "don't
claim").

## Claim Execution

After the delay fires:

1. Re-check capacity (may have filled since the timer was set).
2. Re-check if someone else claimed (from GossipSub).
3. If still valid: publish `JobPost{claim}`.
4. Immediately publish `LoadDelta` with updated `jobs_claimed`.
5. The immediate delta tells other peers within ~100ms (GossipSub propagation).

## Claim Count Limiting

When many jobs arrive simultaneously, a peer limits pending claim timers:

```rust
fn max_pending_claims(&self) -> usize {
    // Don't set more pending timers than free job slots
    self.max_jobs.saturating_sub(self.jobs_running + self.jobs_claimed)
}
```

This prevents a peer from trying to claim 100 jobs when it can only run 8.
Extra jobs are left for other peers.

## New Joiner Behavior

A new joiner has no LoadReport data for existing peers. All peers are at max
uncertainty (confidence=0.0). The joiner:

- Knows its own load (just started, very low).
- Cannot confidently compare against any peer (all uncertain).
- Gets `confidence_penalty` from low `avg_peer_confidence`.
- Result: moderate delay (~150-250ms), not the fastest, not the slowest.
- As heartbeats arrive over the next 60s, confidence improves and delays
  normalize.
- No special protocol needed -- self-correcting.

## Reservation Tokens (Follow-up Jobs)

After a build completes, the builder offers a `ReservationToken` to the
creator. The creator can skip the entire claiming phase for the next job in the
DAG. Benefits:

- ~0.8s overhead instead of ~1.6s.
- Chunk store locality (previous job's inputs are warm).
- Same builder for sequential DAG levels.

See [jobs.md](jobs.md#slot-reservation) for the full reservation flow.

## Label Model

A node's effective labels for scheduling are `node.labels ∪ clusters.X.labels`.
Labels defined in `[node.labels]` apply globally across all clusters the node
participates in. Per-cluster overrides in `[clusters.X.labels]` add or shadow
node-level labels for that cluster only. The merged effective label set is the
same set used by mount `_affinity` matching and by `job.node_selector.labels`
evaluation.

Boolean flags that were previously separate config fields (e.g.
`accept_remote`, `statute.role`) are now expressed as labels. For example,
`clusters.X.labels.jobs = "true"` replaces `clusters.X.jobs.accept_remote`.

## Resource Model

Four resource dimensions: CPU, memory, disk, and `local_space`. Each uses a
four-state model. Resource capacity and limits come from `[clusters.X.limits]`
and `[clusters.X.slice]`.

- **Reserved**: host overhead, non-allocatable.
- **Free**: available for new jobs.
- **Claimed**: allocated to a job but not actively consumed (could spike).
- **Active**: currently consumed by running workloads.

Allocatable = total - reserved = free + claimed + active.

For scheduling, peers evaluate FREE resources against the job's
`ResourceLimits`:

```rust
fn has_capacity_for(&self, limits: &ResourceLimits, volume_space_needed: u64) -> bool {
    let cpu_free = self.cpu_state.free;
    let mem_free = self.memory_state.free;
    let disk_free = self.disk_state.free;
    let local_space_free = self.local_space_state.free;

    (limits.cpu_cores == 0 || cpu_free >= limits.cpu_cores as u64 * 1_000_000)
    && (limits.memory_bytes == 0 || mem_free >= limits.memory_bytes)
    && (limits.disk_bytes == 0 || disk_free >= limits.disk_bytes)
    && (volume_space_needed == 0 || local_space_free >= volume_space_needed)
}
```

## Decay Estimation

When a receiver has not heard from a peer recently, it extrapolates from the
last known state plus trend:

```rust
fn estimated_utilization(&self, now: Instant) -> EstimatedValue {
    let elapsed = (now - self.last_report_time).as_secs_f64();
    let projected = (self.trend.ewma + self.trend.slope * elapsed).clamp(0.0, 1.0);
    let uncertainty = (BASE_UNCERTAINTY + DECAY_RATE * elapsed).min(MAX_UNCERTAINTY);

    EstimatedValue {
        point: projected,
        lower: (projected - uncertainty).max(0.0),
        upper: (projected + uncertainty).min(1.0),
        confidence: 1.0 - (uncertainty / MAX_UNCERTAINTY),
    }
}
```

Constants: `BASE_UNCERTAINTY=0.02`, `DECAY_RATE=0.005/s`, `MAX_UNCERTAINTY=0.5`.

| Time since report | Uncertainty | Confidence |
|---|---|---|
| 0s (at report time) | +/-2% | 96% |
| 10s | +/-7% | 86% |
| 30s | +/-17% | 66% |
| 60s | +/-32% | 36% |
| 100s | +/-50% (max) | 0% (effectively unknown) |

Scheduling uses confidence bounds:

- **For self**: use UPPER bound (conservative -- assume my load is higher than
  estimated).
- **For peers**: use LOWER bound (optimistic -- assume they are less loaded than
  estimated).

This biases toward letting other peers claim when uncertain.

Where `volume_space_needed` is the sum of all `LocalVolume` and
`LocalPersistentVolume` sizes in the job's volume requests.

## Relationship to Other Docs

- [jobs.md](jobs.md) -- job lifecycle, claiming protocol, reservation tokens.
- [load-reports.md](load-reports.md) -- LoadReport format and submission.
- [permissions.md](permissions.md) -- `/aos/job/claim` capability required.
- [protocol.md](protocol.md) -- LoadReport, LoadFull, LoadDelta, ResourceState
  protobuf definitions.
- [volumes.md](volumes.md) -- volume requests, local space resource, persistent volume pinning.
- [../../tla/Jobs.tla](../../tla/Jobs.tla) -- TLA+ formal specification: load-staggered claiming, affinity bonus.
