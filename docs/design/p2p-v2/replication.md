# Store Replication

Store replication ensures that important store objects are available from
multiple peers, surviving individual node failures and improving download
performance. Replication is opt-in per node and configured at the cluster
level.

## Overview

When a new store object is published (via `aos/store/publish`), a subset of
peers called **replicators** independently determine whether they should
replicate it. Assignment is based on hash distance: the N replicators whose
peer IDs are closest (by XOR distance) to the store hash are responsible for
replicating that object. This is deterministic — every replicator computes the
same assignment from the same inputs.

The replication factor N is an "at least" count. The original builder also
holds the object, so a newly published object has at least N+1 providers (N
replicators + the builder). Replicated objects are managed separately from the
builder's copy — the builder's copy is subject to normal GC, while replicated
copies live in a dedicated replication pool excluded from GC.

## Cluster Configuration

Two fields in `ClusterConfig` govern replication:

- **`replication_factor`** (uint32, default 3): minimum number of replicator
  copies for each store object. The builder's own copy does not count toward
  this — it may be GC'd independently.
- **`min_hold_duration`** (uint64, microseconds, default 1 hour): minimum time
  a newly published store object must be retained by the publisher before
  becoming eligible for GC. This ensures replicators have time to download the
  object before the original provider disappears.

## Daemon Configuration

Nodes opt into replication via the `[store.replication]` section:

```toml
[store.replication]
reserved = "100Gi"                 # 100 GB reserved for replication pool
```

Only the `reserved` field is needed. The replication factor comes from
the cluster config. If `[store.replication]` is absent, the node does not
participate in replication.

The replication pool is a logical reservation within the local chunk store.
Replicated objects that are unpinned (not in any active FUSE view) count
toward `reserved`. Pinned objects do not count — they are already
retained by the view and would exist regardless of replication.

## Replicator Advertisement

### DHT Provider Record

Each active replicator publishes a provider record on the DHT key
`aos:store:replica` with a short TTL (1 minute). This record is periodically
refreshed. Non-replicator nodes can query this key to discover how many
replicators are active in the network.

When a replicator's pool is full (`free = 0`), it stops refreshing
this DHT record, causing it to expire. After a purge frees space, the
replicator re-publishes.

### GossipSub Advertisement

Replicators also publish `ReplicateAdvertise` messages on the
`aos/store/replicate` GossipSub topic. These carry capacity state:

```
ReplicateAdvertise {
    peer_id
    reserved_bytes       // total pool size
    used_bytes           // used by unpinned replicated objects
    free_bytes           // available for new replications
    ttl                  // advertisement validity (default 5 min)
}
```

Other replicators track these advertisements to maintain a live view of all
active replicators and their capacity. This is the primary coordination
mechanism — the DHT record is a secondary discovery path for non-replicators
and new joiners.

A `ReplicateRescind` message cancels an advertisement before its TTL expires
(e.g., when a replicator is shutting down or its pool fills up):

```
ReplicateRescind {
    peer_id
}
```

## Replication Protocol

### New Object Flow

When a replicator receives a `StorePublish` message:

1. **Compute assignment.** Sort all known active replicators (from
   advertisements) by XOR distance from the store hash. The closest N peer IDs
   are the assigned replicators for this object.

2. **Check self.** If the local peer is not in the closest N, ignore the
   object.

3. **Check capacity.** If `free_bytes < nar_size` (from the `StorePublish`
   message), submit a `ReplicateNack` and stop. The next-nearest replicator
   will take over.

4. **Claim.** Publish a `ReplicateClaim` to `aos/store/replicate`:

   ```
   ReplicateClaim {
       store_hash
       peer_id
       lease_duration      // scaled by nar_size: base_timeout + nar_size / expected_bandwidth
   }
   ```

   In case of XOR distance ties between replicators, the tie-break is
   lexicographic comparison of peer IDs. This ensures all replicators compute
   the same deterministic assignment from the same inputs.

   Other replicators in the nearest-N see this claim and wait rather than
   starting their own download.

5. **Download.** Fetch the NixObject via `/aos/store/object/1.0.0` and fetch
   chunks via `/aos/store/chunk/1.0.0`. The NixObject's `refs` enable walking
   and parallel fetching of the full closure.

6. **Renew lease.** For large objects, periodically publish
   `ReplicateLeaseRenew` messages to extend the claim before it expires:

   ```
   ReplicateLeaseRenew {
       store_hash
       peer_id
       lease_duration
   }
   ```

7. **Success.** Once the object is fully local, publish `ReplicateSuccess`:

   ```
   ReplicateSuccess {
       store_hash
       peer_id
   }
   ```

   The replicator also calls `start_providing` on `aos:store:object:{store_hash}` so
   the object becomes discoverable for normal fetches. The replicator does NOT
   publish to `aos/store/publish` — only newly created objects use that topic.

8. **Failure.** If the download fails (network error, timeout, internal error),
   publish `ReplicateNack`:

   ```
   ReplicateNack {
       store_hash
       peer_id
       reason              // POOL_FULL, NETWORK_ERROR, TIMEOUT, OBJECT_TOO_LARGE
   }
   ```

   The next replicator in the distance-sorted list (N+1, N+2, ...) sees the
   nack and takes over by starting at step 3.

### Nack Rate Limiting

A replicator that nacks the same object repeatedly is removed from the
assignment pool for that object. After 3 nacks for the same
`(replicator, store_hash)` pair within a configurable window (default 1
hour), the replicator is excluded from that object's nearest-N set. Other
replicators see the repeated nacks and skip to the next-nearest peer.

This prevents a malicious replicator from blocking replication by
indefinitely nacking objects it's assigned to.

### Claim Lease Timeout

The claim lease duration scales with object size:

```
lease_duration = base_timeout + nar_size / expected_bandwidth
```

Default `base_timeout` is 30 seconds. Default `expected_bandwidth` is
10 MB/s. A 1 GB object gets a ~130s lease; a 10 MB object gets a ~31s lease.

If a claim's lease expires without a success or renewal, other nearest-N
replicators treat it as an implicit nack and the next-nearest proceeds.

### Lease Cancellation

A replicator may cancel its own lease if it decides to abort:

```
ReplicateLeaseCancel {
    store_hash
    peer_id
}
```

This is equivalent to a nack but explicitly signals "I gave up" rather than
waiting for the lease to expire.

## Rebalancing

Each replicator periodically checks whether its replicated objects have
sufficient providers. The check interval is the cluster-config-defined TTL
period (e.g., 1 day), with per-object splay to spread queries:

```
check_time = epoch_start + hash(store_hash ⊕ peer_id) % ttl_period
```

This ensures that checks for the same object by different replicators are
spread across the TTL period, and checks for different objects by the same
replicator are also spread.

At check time, the replicator queries `get_providers` for
`aos:store:object:{store_hash}`. If the total provider count (including non-replicator
providers like the original builder) falls below the replication factor, the
replicator publishes a `ReplicateRebalance` message to `aos/store/replicate`:

```
ReplicateRebalance {
    store_hash
    peer_id              // replicator that detected the shortfall
    current_providers    // observed provider count
}
```

A rebalance message triggers the same nearest-N assignment as a new
`StorePublish`, with one difference: replicators that already hold the object
respond immediately with `ReplicateSuccess` (skipping the claim/download flow).
Only replicators that are in the nearest-N but don't have the object proceed
with the claim/download sequence.

## Store Purge

The `aos/store/purge` GossipSub topic carries explicit deletion requests:

```
StorePurge {
    store_hash
    peer_id              // requester
    reason               // human-readable
    ucan                 // /aos/store/purge authorization
}
```

On receiving a purge:

- **Pinned objects** (in an active FUSE view or in `gc.mdb`): silently
  ignored. The object cannot be removed while pinned.
- **Replicated objects** (in the replication pool, unpinned): removed from
  the replication pool. The replicator stops refreshing the
  `aos:store:object:{store_hash}` provider record, letting it expire.
- **Normal objects** (not replicated, not pinned): removed from the local
  store and provider records.

After a purge frees replication pool space, the replicator updates its
`ReplicateAdvertise` with the new `free_bytes` and resumes accepting new
replication assignments if it was previously full.

## DHT Provider TTL

Provider record TTLs for `aos:store:object:{store_hash}` are tiered:

| Object State | TTL | Rationale |
|---|---|---|
| Pinned (FUSE view or gc.mdb) | Cluster-config interval (e.g., 1 day) | Stable, long-lived. |
| Replicated (in replication pool) | Cluster-config interval (e.g., 1 day) | Managed by replication protocol. |
| Unpinned, unreplicated | Estimated time to GC (capped at cluster-config interval) | May be evicted soon; TTL reflects expected lifetime. |

The estimated time to GC is derived from the object's LRU position and the
store's budget headroom. See [gc.md](gc.md) for the LRU eviction model.

Provider records are refreshed at `TTL * 2/3` intervals, standard for DHT
record maintenance.

### Min Hold Duration

Newly published objects (by the original builder) are subject to a minimum hold
duration from `ClusterConfig.min_hold_duration` (default 1 hour). During this
period, the object is not eligible for GC regardless of LRU position. This
ensures replicators have time to download the object before the original
provider disappears.

The min hold duration is enforced locally by the publisher — it sets the
object's `last_access` in AccessDB to `now`, and GC skips objects younger than
`min_hold_duration`.

## Protocol

```protobuf
// GossipSub topic: aos/store/replicate
// Envelope for all replicator coordination messages.
message ReplicateMessage {
    oneof message {
        ReplicateAdvertise advertise = 1;   // "I'm an active replicator with this capacity"
        ReplicateRescind rescind = 2;       // "I'm leaving / pool full"
        ReplicateClaim claim = 3;           // "I'm downloading this object" (lease)
        ReplicateLeaseRenew renew = 4;      // "Still downloading, extend my lease"
        ReplicateLeaseCancel cancel = 5;    // "I gave up on this download"
        ReplicateSuccess success = 6;       // "I now have this object"
        ReplicateNack nack = 7;             // "I can't replicate this object"
        ReplicateRebalance rebalance = 8;   // "This object is under-replicated"
    }
}

// Periodic advertisement of replicator capacity.
// Other replicators track these to maintain a live view of all
// active replicators and their available space.
message ReplicateAdvertise {
    string peer_id = 1;             // advertising replicator
    uint64 reserved_bytes = 2;      // total replication pool size
    uint64 used_bytes = 3;          // used by unpinned replicated objects
    uint64 free_bytes = 4;          // available for new replications
    uint64 ttl = 5;                 // advertisement validity (microseconds)
}

// Cancel an advertisement before its TTL expires.
// Used when a replicator shuts down or its pool fills.
message ReplicateRescind {
    string peer_id = 1;
}

// Claim a store object for replication. Other replicators in the
// nearest-N see this and wait rather than starting their own download.
// The lease expires if no success/renewal arrives within lease_duration.
message ReplicateClaim {
    string store_hash = 1;          // object being replicated
    string peer_id = 2;             // claiming replicator
    uint64 lease_duration = 3;      // lease time (microseconds, scaled by nar_size)
}

// Extend a replication lease for large objects that take
// longer to download than the initial lease duration.
message ReplicateLeaseRenew {
    string store_hash = 1;
    string peer_id = 2;
    uint64 lease_duration = 3;
}

// Explicitly cancel a replication lease (abort download).
// Equivalent to letting the lease expire, but faster.
message ReplicateLeaseCancel {
    string store_hash = 1;
    string peer_id = 2;
}

// Confirm successful replication. The replicator now holds the
// object and has called start_providing on the DHT.
message ReplicateSuccess {
    string store_hash = 1;
    string peer_id = 2;
}

// Report a replication failure. The next replicator in the
// distance-sorted list sees this and takes over.
message ReplicateNack {
    string store_hash = 1;
    string peer_id = 2;
    NackReason reason = 3;
}

enum NackReason {
    NACK_POOL_FULL = 0;             // no space in replication pool
    NACK_NETWORK_ERROR = 1;         // download failed
    NACK_TIMEOUT = 2;               // download timed out
    NACK_OBJECT_TOO_LARGE = 3;      // object exceeds pool capacity
}

// Trigger re-replication of an under-replicated object.
// Functions like a new StorePublish for replication purposes:
// existing holders respond immediately, new assignees claim and download.
message ReplicateRebalance {
    string store_hash = 1;          // under-replicated object
    string peer_id = 2;             // replicator that detected the shortfall
    uint32 current_providers = 3;   // observed provider count
}

// GossipSub topic: aos/store/purge
// Best-effort request to remove a store object from peers.
// Pinned objects are silently ignored. Replicated unpinned objects
// are removed from the replication pool.
message StorePurge {
    string store_hash = 1;          // object to purge
    string peer_id = 2;             // requester
    string reason = 3;              // human-readable reason
    string ucan = 4;                // /aos/store/purge authorization
}
```

## Relationship to Other Docs

- [protocol.md](protocol.md) -- protobuf definitions for replication messages.
- [store.md](store.md) -- store transfer protocol used by replicators to
  download objects.
- [storage.md](storage.md) -- on-disk layout, replication pool accounting.
- [gc.md](gc.md) -- replication pool excluded from normal GC, min hold
  duration, provider TTL.
- [permissions.md](permissions.md) -- `/aos/store/replicate` and
  `/aos/store/purge` UCAN capabilities.
- [daemon.md](daemon.md) -- `[store.replication]` configuration.
- [overview.md](overview.md) -- GossipSub topic listing.
- [../../tla/Store.tla](../../tla/Store.tla) -- TLA+ formal specification: nearest-N assignment, claim/nack/rebalance, nack rate limiting.
