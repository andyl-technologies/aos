# Failure Modes, Recovery, and Partition Tolerance

## Design Philosophy

The system favors **availability and partition tolerance** over strong
consistency (AP in CAP terms). This is possible because:

- Nix builds are deterministic -- duplicate work produces identical results
- Store paths are content-addressed -- duplicate provider announcements are harmless
- Build results are immutable -- once complete, they never change

Duplicate work is wasted compute but never produces incorrect results.

## Failure Mode Matrix

| Failure | Detection | Recovery | Data Loss Risk |
|---------|-----------|----------|----------------|
| Daemon crashes mid-build | DHT record TTL expires (30 min). Peers notice via GossipSub (no heartbeats from daemon). Ephemeral views (build sandboxes) are cleaned up on restart. Provider records for paths held by the crashed daemon expire via TTL (this is the only scenario with a stale window -- normal GC actively removes provider records). | Job is re-announced on `build/wanted/{universe}/{system}` by the submitting daemon (or any peer that noticed the stale claim). A new daemon claims and rebuilds. | Outputs are lost if the crashed daemon was the only provider. Other peers that previously fetched some paths still serve them. Worst case: rebuild from source. |
| Daemon network partition | Daemon can't publish to GossipSub (no peers receive logs). DHT record stops being refreshed. | **Daemon side**: continues building (work is useful). Buffers logs locally. On reconnection, announces as provider and re-publishes result. **Cluster side**: DHT record expires after TTL. Another daemon may claim and rebuild. If both complete, results are identical -- DHT provider records are additive (multiple providers for the same path is fine). | Duplicate work possible. No data loss. |
| Observing daemon crashes | Clients lose their connection. | Clients reconnect to another daemon. The new daemon looks up the builder via DHT, requests log replay from the builder peer. Zero state lost -- the observing layer is stateless. | None. |
| Duplicate build claims (race) | Two daemons both write DHT records for the same drv_hash. | Both build. Both produce identical outputs (deterministic). Both announce as providers in the DHT (provider records are additive). Both announce on `build/result`. Clients receive the first result and ignore duplicates. | None. Wasted compute only. |
| All providers for a store path go offline | Provider records are actively removed from the DHT during GC (zero stale window). For daemon crashes, DHT provider records expire via TTL. Either way, peers requesting the path find no providers. | Path must be rebuilt from source. Any peer can re-derive the path because all builds in the system are reproducible. Once rebuilt, the new daemon announces as provider. | None. The source derivation is always available. Rebuilding produces identical output. |
| Poison message (unbuildable derivation) | Build fails on every daemon that tries. | Track retry count in DHT record. After N failures (e.g., 3), mark as "permanently failed" in DHT. The submitting daemon reports error to client. Daemons skip jobs with "permanently failed" status. | None. |
| GossipSub message loss | Message doesn't reach some peers (normal in gossip protocols). | Job announcements (`build/wanted/{universe}/{system}`): submitting daemon re-announces after timeout if no `build/claimed/{universe}/{system}` seen. Log lines: late joiners use replay protocol to fill gaps. Results: submitting daemon polls DHT for build status as fallback. | None -- all critical paths have fallback mechanisms. |
| DHT record loss (all K replicas crash) | K closest peers to a key all go down simultaneously. | Build claim records: build completes or times out regardless. Daemon capability records: daemon re-publishes on next heartbeat interval. Build result records: daemons that completed the build re-announce as providers on their next DHT refresh. | Rare (K=20 replicas). Temporary loss of metadata only -- actual data (NARs) remains in daemon stores. |
| Mesh partition (cluster splits in two) | Peers in each partition can still discover each other. GossipSub mesh reforms within each partition. | Both partitions continue operating independently. Builds may be duplicated across partitions. Both sides announce as providers -- peers in each partition can fetch from their local provider. When partition heals, DHT records merge, GossipSub meshes reconnect. Multiple providers for the same path coexist cleanly. | Duplicate work during partition. Results merge cleanly after healing. |
| Slow daemon (build takes hours) | DHT claim record has TTL. | Daemon periodically refreshes its DHT claim record to prevent expiry. If daemon is truly stuck (hung process), the build times out after a configurable max build duration (e.g., 4 hours). Claim expires, job re-announced. | None. |

## Detailed Scenarios

### Daemon Crash Recovery

```
Timeline:
  T=0    Daemon A claims build for drv_hash=abc123
         DHT record: {peer: A, status: "building", ttl: 30min}
  T=5    Daemon A crashes
  T=5    GossipSub notices A is gone (no more log messages)
  T=30   DHT claim record expires (TTL)
  T=31   Submitting daemon (or monitoring peer) notices no result for abc123
         Re-publishes job to build/wanted/{universe}/{system}
  T=32   Daemon B picks up the job
         B checks DHT: claim expired -> claims it
         B starts building from scratch
  T=45   Daemon B completes, announces as provider, publishes result
```

**Ephemeral view cleanup**: When a daemon crashes mid-build, any ephemeral
views (FUSE mounts for build sandboxes) are orphaned. On restart, the daemon
scans for stale ephemeral views and unmounts/removes them before accepting new
work. This prevents resource leaks from accumulated crash debris.

**Optimization**: The submitting daemon can detect builder crash earlier than DHT TTL by:
- Noticing GossipSub log stream went silent for >60 seconds
- Attempting direct stream connection to builder -- fails
- Immediately re-announcing the job (don't wait for DHT TTL)

### Network Partition Recovery

```
Timeline:
  T=0    Cluster: [A, B, C] -- [D, E, F]
         Partition occurs between the two groups
  T=1    Build request arrives at Daemon A (HTTP) for drv=foo
         Daemon A claims and starts building
  T=2    Build request arrives at Daemon D (HTTP) for drv=foo (same build)
         Daemon D can't see A's claim (DHT partitioned)
         Daemon D claims and starts building
  T=10   Both A and D complete the build
         Both announce as providers in their respective partitions
  T=15   Partition heals
         DHT records merge: both A and D are providers for foo
         Peers can now fetch from either provider
         No inconsistency -- outputs are identical
```

### Graceful Shutdown

Daemons support graceful shutdown:

```rust
async fn shutdown(swarm: &mut Swarm<AosBehaviour>) {
    // Stop accepting new jobs (unsubscribe from all universe-scoped wanted topics)
    for topic in &builds_wanted_topics {
        swarm.behaviour_mut().gossipsub.unsubscribe(topic);
    }

    // Wait for in-flight builds to complete (with timeout)
    let deadline = Instant::now() + Duration::from_secs(300);
    while active_builds.load() > 0 && Instant::now() < deadline {
        sleep(Duration::from_secs(1)).await;
    }

    // If builds still running after timeout, let them be re-claimed
    // (DHT records will expire, jobs will be re-announced)

    // Remove capability record from DHT
    swarm.behaviour_mut().kademlia.remove_record(&daemon_key);

    // Disconnect from mesh
    swarm.close().await;
}
```

## Consistency Guarantees

What the system guarantees:

- **Build results are correct**: deterministic builds + content-addressed storage
- **No lost builds**: failed builds are re-tried via job re-announcement
- **No corrupted outputs**: content-addressed paths are immutable; DHT provider records are additive
- **Eventual log availability**: live via GossipSub, replay via daemon stream
- **Recoverable from total provider loss**: all builds are reproducible from source, so any lost path can be rebuilt

What the system does NOT guarantee:

- **No duplicate work**: rare but possible during races and partitions
- **Strong ordering of job execution**: jobs may be claimed out of priority order
- **Immediate failure detection**: up to 30 minutes (DHT TTL) for undetected failures in worst case (optimized to ~60s with active monitoring)

## Monitoring and Observability

Each peer exposes metrics:

- Active builds count
- Build success/failure rate
- GossipSub message rates
- DHT record counts
- Connected peer count
- Store size and available disk space

Daemons can aggregate these for dashboards. No central monitoring server
needed -- any daemon can query any other daemon's metrics via libp2p
request/response.
