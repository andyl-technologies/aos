# Garbage Collection

GC determines what to keep and what to discard in the local chunk store. It
operates in three phases: store object eviction, orphaned chunk cleanup, and
pack compaction. GC is always local -- a peer GC'ing a store path does not
affect other peers.

## GC Roots

The pin set is the union of two sources:

- **Active FUSE views:** every store hash in any mounted FUSE view is pinned.
  The daemon tracks mounted views in memory -- no LMDB needed for this. This
  covers all job containers (input closures, service views) and any other
  active views.
- **Manual pins (StoreDB (roots_db)):** store hashes pinned by the operator via the
  `store.mdb` database. Used for keeping specific store objects that should not
  be evicted regardless of LRU age.
- **Active workflow specs:** the store hash of each non-terminated workflow's
  spec is pinned. Since the spec protobuf contains store hashes as literal
  strings (output hashes, derivation hashes, source hashes, dependent workflow
  IDs), reference scanning records all of them in `closure_db`. The standard
  closure-based pinning transitively protects everything the workflow references.
  Cross-workflow pinning is automatic: if W2's spec references W1's workflow_id
  (a store hash), W1's spec and its entire closure are transitively pinned.
  Pins are released when the workflow terminates. See
  [workflow-spec.md](workflow-spec.md) for the full model.

Everything else is LRU-evictable based on `last_access` in the AccessDB.

## Replication Pool and Hold Duration

Objects managed by the replication protocol receive special GC treatment:

- **Replication pool objects** (unpinned objects held for replication) are
  excluded from normal LRU eviction. They are managed by the replication
  protocol -- removed via explicit purge messages or pool eviction when the
  replication budget (`[store.replication] reserved_bytes`) is exceeded.
- **Newly published objects** are subject to `ClusterConfig.min_hold_duration`
  -- GC skips objects younger than this threshold to allow replicators time to
  discover and download the object before the publisher evicts it.

Archive/storage nodes are just peers with very high max_size thresholds (and may
not participate in job execution).

```toml
# Normal builder
[gc]
policy = "budget"
max_size = "100GB"

# Archive/storage node
[gc]
policy = "budget"
max_size = "50TB"
```

## GC Algorithm -- Three Phases

### Phase 1: Store Object Eviction

Input: AccessDB (LRU data) + active FUSE views (daemon memory) + StoreDB (roots_db)
(manual pins) + budget
Output: evicted manifests from ChunkDB, removed entries from AccessDB

```rust
fn gc_store_objects(
    access_db: &AccessDb,
    active_views: &HashSet<String>,  // from daemon's FUSE mount state
    roots_db: &RootsDb,              // manual pins
    chunk_db: &ChunkDb,
    max_size: u64,
) {
    let total_size = access_db.total_nar_size();
    if total_size <= max_size { return; }

    let pinned: HashSet<String> = active_views
        .union(&roots_db.all_roots())
        .cloned()
        .collect();

    let mut candidates: Vec<AccessRecord> = access_db.iter()
        .filter(|r| !pinned.contains(&r.store_hash))
        .collect();
    candidates.sort_by_key(|r| r.last_access);  // coldest first

    let target = (max_size as f64 * 0.8) as u64;  // 80% to avoid churn
    let mut freed = 0;

    for candidate in candidates {
        if total_size - freed <= target { break; }
        access_db.delete(&candidate.store_hash);
        chunk_db.delete_manifest(&candidate.store_hash);
        freed += candidate.nar_size;
    }
}
```

### Phase 2: Orphaned Chunk Cleanup (Mark and Sweep)

Input: all remaining manifests in ChunkDB
Output: removed orphaned chunk location entries

Why mark-and-sweep instead of reference counting:
- Zero writes during normal operation (no ref counts to maintain on ingest/eviction)
- Bulk read during GC (LMDB readers don't block writers)
- Simpler (no ref count bugs, no stale counts after crashes)
- Runs infrequently (only after Phase 1, during idle time)

Tradeoff: mark phase scans all manifests O(total chunk references). For 100K
store objects, ~80 seconds at LMDB read speeds. Acceptable for periodic GC.

```rust
fn gc_orphaned_chunks(chunk_db) {
    // MARK: all chunk hashes referenced by any surviving manifest
    let referenced: HashSet<[u8; 16]> = chunk_db.all_manifests()
        .flat_map(|m| m.file_chunk_hashes())
        .collect();

    // SWEEP: remove unreferenced chunk locations
    for (hash, _loc) in chunk_db.all_chunk_locations() {
        if !referenced.contains(&hash) {
            chunk_db.delete_chunk_location(&hash);
            // Data stays as dead space in pack file until compaction
        }
    }
}
```

### Phase 3: Pack Compaction (Optional, Idle Time)

After chunk index entries are removed, pack files have dead space.

**Option A (cheap):** Delete fully-dead packs. If ALL chunks in a pack are dead,
delete the file. Common case because FastCDC chunks are written sequentially per
store object during ingest -- a store object's chunks cluster in 1-3 packs.

**Option B (expensive):** Rewrite partially-dead packs with >30% dead space.
Copy live chunks to new pack, update location entries, delete old pack. Only
during idle time.

## Provider TTL Coordination

DHT provider records should expire around when the path might be GC'd.

For budget-based GC:
```
provider_ttl = f(lru_rank, disk_headroom, growth_rate)

Hot paths (top of LRU): long TTL (hours)
Cold paths (bottom, near eviction): short TTL (minutes)
Pinned paths (active containers): max TTL
```

Self-correcting: `last_access = max(creation_time, last_manifest_serve)`.
Content being actively served to remote peers stays advertised. FUSE reads do
not affect provider TTL -- objects in active FUSE views are pinned and get max
TTL regardless.

After GC runs: re-advertise surviving store objects with updated TTLs. Evicted
objects are NOT re-advertised -- their provider records expire naturally via DHT
TTL.

## Configuration

```toml
[gc]
policy = "budget"          # only budget-based LRU for now
max_size = "100GB"
interval = "1h"            # how often GC runs
target_free = 0.2          # GC until 20% free (avoid constant churn)

[gc.compaction]
dead_ratio = 0.3           # compact packs with >30% dead space
idle_only = true           # only compact when no active jobs
```

## Relationship to Other Docs

- [storage.md](storage.md) -- on-disk layout and database specs (AccessDB,
  ChunkDB, StoreDB (roots_db))
- [storage.md](storage.md) -- pack file format, FastCDC chunking,
  read/write operations
- [fuse.md](fuse.md) -- FUSE filesystem views (read-only, no access tracking)
- [store.md](store.md) -- provider TTL on DHT records
- [containers.md](containers.md) -- container lifecycle pins roots on start,
  unpins on exit
- [jobs.md](jobs.md) -- job lifecycle determines when roots are pinned/unpinned
