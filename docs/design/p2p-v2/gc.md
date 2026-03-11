# Garbage Collection

GC determines what to keep and what to discard in the local chunk store. It
operates at two layers:

- **Store path GC** decides which store paths (manifests) to retain based on
  roots and eviction policies.
- **Chunk GC** removes unreferenced chunks after store paths are removed.

GC is always local. A peer GC'ing a store path does not affect other peers --
they retain their own copies independently. There is no distributed GC protocol
and no coordination required.

## GC Roots

A store path is a GC root if any of the following hold:

**Active jobs.** Inputs and outputs of running jobs are roots. Protected from
the moment the job is claimed until its `JobPost` CRDT transitions to a
terminal state (complete or failed). Both the derivation's input closure and
any produced outputs are included.

**FUSE views.** Every store hash in a mounted view's `allowed` set is a root.
This includes build views (eager mode, short-lived), profile views, and
explicit views. A store path remains rooted for the lifetime of the view.

**DHT provider records.** Paths we are actively providing to the mesh are
roots. To GC a provided path: stop refreshing the provider record, wait for
its TTL to expire, then proceed with eviction. Peers that request chunks
during the TTL wind-down receive `DONT_HAVE` and retry with another provider.

**Profiles.** The peer's current `ProfileSpec` `store_hash` and its transitive
closure. The profile itself references packages, and those packages reference
their runtime dependencies recursively.

**ReplicaSet templates.** Store paths referenced by active `ControlSignal`
`ReplicaSet` definitions. These are paths the control plane has declared should
be available on this peer.

**Pinned paths.** Explicitly pinned by the operator via `aos pin {store_hash}`.
Pins persist across daemon restarts (stored in the chunk store LMDB).

```rust
fn compute_roots(
    jobs: &JobStore,
    views: &[View],
    profile: &ProfileSpec,
    replica_sets: &[ReplicaSet],
    pins: &PinDb,
    manifests_db: &lmdb::Database,
) -> HashSet<StoreHash> {
    let mut roots = HashSet::new();

    // Active job inputs and outputs.
    for job in jobs.active() {
        roots.extend(job.input_closure.iter().copied());
        if let Some(output) = &job.output {
            roots.insert(output.store_hash);
        }
    }

    // FUSE view contents.
    for view in views {
        roots.extend(view.allowed.iter().copied());
    }

    // Current profile closure.
    roots.extend(transitive_closure(&profile.store_hash, manifests_db));

    // ReplicaSet template closures.
    for rs in replica_sets {
        for store_hash in &rs.template_paths {
            roots.extend(transitive_closure(store_hash, manifests_db));
        }
    }

    // Pinned paths.
    roots.extend(pins.all());

    // Expand to transitive closure of all roots.
    let direct_roots: Vec<StoreHash> = roots.iter().copied().collect();
    for root in direct_roots {
        roots.extend(transitive_closure(&root, manifests_db));
    }

    roots
}

fn transitive_closure(
    store_hash: &StoreHash,
    manifests_db: &lmdb::Database,
) -> Vec<StoreHash> {
    let mut result = Vec::new();
    let mut stack = vec![*store_hash];
    let mut seen = HashSet::new();

    while let Some(hash) = stack.pop() {
        if !seen.insert(hash) {
            continue;
        }
        result.push(hash);

        if let Some(manifest) = get_manifest(manifests_db, &hash) {
            for dep in &manifest.references {
                stack.push(*dep);
            }
        }
    }

    result
}
```

## Eviction Policies

Three policies, configured per daemon. Only one policy is active at a time.

### TTL-based

Paths not accessed within a configurable TTL are eligible for eviction. Simple
time-based expiry with no size awareness.

```toml
[gc]
policy = "ttl"
ttl = "7d"
```

Access tracking: per-view `access.mdb` records last access time per store hash.
Every FUSE `read()` updates the timestamp. Serving a chunk via
`/aos/store/chunk` or a manifest via `/aos/store/manifest` also counts as an
access.

### Budget-based (LRU)

When total chunk store size exceeds a budget, evict the least-recently-used
paths first. A `target_free` ratio prevents constant GC churn -- eviction
continues until usage drops below `max_size * (1 - target_free)`.

```toml
[gc]
policy = "budget"
max_size = "100GB"
target_free = 0.2
```

When disk usage exceeds `max_size`, sort all non-root paths by last access
time (from `access.mdb`), evict coldest first until usage drops below
`max_size * 0.8`.

### Manual

No automatic eviction. Paths are only removed via explicit `aos gc` command.
Suitable for builder peers with large disks that want full operator control.

```toml
[gc]
policy = "manual"
```

## GC Algorithm

The GC loop runs periodically (configurable interval, default 1 hour) or
on-demand via `aos gc`. Each cycle:

```rust
fn gc_cycle(
    store: &ChunkStore,
    views: &[View],
    jobs: &JobStore,
    profile: &ProfileSpec,
    replica_sets: &[ReplicaSet],
    pins: &PinDb,
    config: &GcConfig,
) -> GcStats {
    let mut stats = GcStats::default();

    // 1. Compute root set (with transitive closure).
    let roots = compute_roots(jobs, views, profile, replica_sets, pins, &store.manifests_db);

    // 2. Compute eviction candidates: all manifests not in root set.
    let all_manifests = store.list_manifests();
    let non_root: Vec<StoreHash> = all_manifests
        .into_iter()
        .filter(|h| !roots.contains(h))
        .collect();

    // 3. Filter by policy.
    let to_evict = match config.policy {
        Policy::Ttl => {
            let cutoff = SystemTime::now() - config.ttl;
            non_root.into_iter()
                .filter(|h| last_access(views, h) < cutoff)
                .collect::<Vec<_>>()
        }
        Policy::Budget => {
            let current_size = store.total_pack_size();
            if current_size <= config.max_size {
                return stats; // under budget, nothing to do
            }
            let target = (config.max_size as f64 * (1.0 - config.target_free)) as u64;

            let mut ranked: Vec<(StoreHash, SystemTime)> = non_root.iter()
                .map(|h| (*h, last_access(views, h)))
                .collect();
            ranked.sort_by_key(|(_, t)| *t); // coldest first

            let mut freed = 0u64;
            ranked.into_iter()
                .take_while(|_| {
                    let still_over = (current_size - freed) > target;
                    still_over
                })
                .map(|(h, _)| {
                    freed += store.manifest_disk_usage(&h);
                    h
                })
                .collect::<Vec<_>>()
        }
        Policy::Manual => {
            // Manual: evict all non-root paths, but only when operator triggered.
            non_root
        }
    };

    // 4. Evict each store path.
    for store_hash in &to_evict {
        // Stop advertising: don't refresh DHT provider record.
        store.stop_providing(store_hash);

        // Remove manifest and update chunk references.
        match store.gc_store_path(store_hash) {
            Ok(path_stats) => {
                stats.paths_evicted += 1;
                stats.chunks_freed += path_stats.chunks_freed;
                stats.bytes_freed += path_stats.bytes_freed;
            }
            Err(e) => {
                log::warn!("gc failed for {}: {}", hex::encode(store_hash), e);
            }
        }
    }

    stats
}
```

The per-path eviction (`gc_store_path`) is the same function defined in
[chunk-store.md](chunk-store.md): remove the manifest from `manifests_db`,
update `chunk_refs_db` for each chunk, and delete `locations_db` entries for
chunks with zero remaining references. Chunk data in pack files becomes dead
space until compaction.

### Aggregate Last Access

A store hash may appear in multiple views. The aggregate last access time is
the maximum across all views:

```rust
fn last_access(views: &[View], store_hash: &StoreHash) -> SystemTime {
    views.iter()
        .filter_map(|v| v.access_db.get(store_hash))
        .map(|record| record.last_access)
        .max()
        .unwrap_or(SystemTime::UNIX_EPOCH)
}
```

## Provider TTL and GC Coordination

DHT provider records have a TTL. A path nearing eviction should have a short
provider TTL so the DHT stops directing peers to us shortly before we delete
the data. A path that will be retained indefinitely should have a long TTL.

**TTL-based GC:**

```
provider_ttl = gc_ttl - time_since_last_access
```

A path last accessed 1 hour ago with a 7-day GC TTL gets a ~7 day provider
TTL. A path last accessed 6.5 days ago gets a ~12 hour provider TTL.

**Budget-based GC:**

```
provider_ttl = f(lru_rank, disk_headroom, growth_rate)
```

Hot paths (top of LRU) get long TTLs. Cold paths (bottom of LRU, near the
eviction boundary) get short TTLs. The function estimates when eviction
pressure will reach each path based on the current growth rate and remaining
headroom.

**Rooted paths (active jobs, profiles, pins):**

```
provider_ttl = max_ttl  // e.g. 24h, re-advertised on access
```

These will not be GC'd, so advertise them with the maximum TTL and
re-advertise before expiry.

**Self-correcting property.** Every access -- FUSE `read()`, chunk serving,
manifest serving -- bumps the path up the LRU and extends its provider TTL.
Content that is actively being served stays advertised. Content that nobody is
fetching naturally expires from both the DHT and the local store.

```rust
fn compute_provider_ttl(
    store_hash: &StoreHash,
    config: &GcConfig,
    roots: &HashSet<StoreHash>,
    views: &[View],
    store: &ChunkStore,
) -> Duration {
    const MAX_TTL: Duration = Duration::from_secs(24 * 3600);
    const MIN_TTL: Duration = Duration::from_secs(3600);

    if roots.contains(store_hash) {
        return MAX_TTL;
    }

    match config.policy {
        Policy::Ttl => {
            let age = SystemTime::now()
                .duration_since(last_access(views, store_hash))
                .unwrap_or_default();
            let remaining = config.ttl.saturating_sub(age);
            remaining.clamp(MIN_TTL, MAX_TTL)
        }
        Policy::Budget => {
            let usage_ratio = store.total_pack_size() as f64 / config.max_size as f64;
            let access_time = last_access(views, store_hash);

            // Cold paths near eviction boundary get short TTLs.
            // Hot paths with headroom get long TTLs.
            let recency = SystemTime::now()
                .duration_since(access_time)
                .unwrap_or_default();

            if usage_ratio > 0.9 && recency > Duration::from_secs(3600) {
                MIN_TTL
            } else if usage_ratio > 0.7 {
                Duration::from_secs(6 * 3600)
            } else {
                MAX_TTL
            }
        }
        Policy::Manual => MAX_TTL,
    }
}
```

## Access Tracking

Per-view LMDB at `/var/lib/aos/views/{view_name}/access.mdb`:

```rust
struct AccessRecord {
    last_access: u64,     // microseconds since epoch
    access_count: u64,    // total accesses (for analytics)
    first_access: u64,    // when this path was first accessed in this view
}
```

Key: store hash (32 bytes). Value: `AccessRecord` (24 bytes, fixed-size).

Updated on:

- FUSE `read()` for any file in this store path.
- Serving a chunk from this store path via `/aos/store/chunk`.
- Serving a manifest for this store path via `/aos/store/manifest`.

Access tracking writes are batched to reduce LMDB write pressure. The daemon
accumulates updates in a `HashMap<StoreHash, SystemTime>` and flushes to LMDB
every 1000 accesses or every 10 seconds, whichever comes first.

```rust
struct AccessBatcher {
    pending: HashMap<StoreHash, SystemTime>,
    flush_threshold: usize,
    last_flush: Instant,
}

impl AccessBatcher {
    fn touch(&mut self, hash: StoreHash, now: SystemTime) {
        self.pending.insert(hash, now);
        if self.pending.len() >= self.flush_threshold
            || self.last_flush.elapsed() > Duration::from_secs(10)
        {
            self.flush();
        }
    }

    fn flush(&mut self) {
        let mut txn = self.env.begin_rw_txn().unwrap();
        for (hash, time) in self.pending.drain() {
            let micros = time
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_micros() as u64;

            match txn.get(self.db, hash.as_bytes()) {
                Ok(existing) => {
                    let mut record: AccessRecord = decode(existing);
                    record.last_access = micros;
                    record.access_count += 1;
                    txn.put(self.db, hash.as_bytes(), &encode(&record), Default::default())
                        .unwrap();
                }
                Err(_) => {
                    let record = AccessRecord {
                        last_access: micros,
                        access_count: 1,
                        first_access: micros,
                    };
                    txn.put(self.db, hash.as_bytes(), &encode(&record), Default::default())
                        .unwrap();
                }
            }
        }
        txn.commit().unwrap();
        self.last_flush = Instant::now();
    }
}
```

Per-view LMDB isolation means access tracking for one view does not contend
with another view's writes. Each view has its own `access.mdb` file and its own
write lock.

## Chunk Reference Counting

The `chunk_refs_db` in the chunk store LMDB tracks which store paths reference
each chunk:

```
key: chunk_hash (16 bytes, xxh3-128)
value: concatenated store_hash values (N * 32 bytes)
```

When a store path is GC'd:

1. Load the manifest to get all chunk hashes.
2. For each chunk: remove this store hash from `chunk_refs_db`.
3. If the chunk's reference list is now empty: remove from `locations_db`.
4. The chunk data in the pack file becomes dead space.

When a new store path is ingested:

1. For each chunk: add this store hash to `chunk_refs_db`.
2. If the chunk already exists (dedup hit): add only the back-reference, do not
   write chunk data again.

The encoding is a flat byte array. Adding a reference appends 32 bytes.
Removing a reference filters it out and rewrites. The number of store objects
referencing any single chunk is typically small (single digits for most chunks,
low hundreds for widely-shared library chunks like libc), so the linear scan is
not a bottleneck.

## Pack Compaction

Dead space accumulates in sealed pack files as chunks are GC'd. Compaction
reclaims this space. Two strategies:

**Full-pack deletion.** If all chunks in a pack are dead (no `locations_db`
entries point to it), delete the entire pack file. Zero I/O cost beyond the
`unlink`. This happens naturally when an entire store path's chunks were in the
same pack -- common, since chunks are written sequentially during ingest.

**Rewrite compaction.** For packs with dead space exceeding a configurable
threshold (default 30%) but some live chunks, copy live chunks to a new pack,
update `locations_db` entries in a single LMDB transaction, then delete the old
pack. See `compact_pack()` in [chunk-store.md](chunk-store.md) for the full
implementation.

Compaction is opportunistic -- it runs when the daemon is idle (no active
builds, no in-flight chunk transfers). Pack files being actively read (FUSE
operations, chunk serving) are not compacted until readers finish. At most one
pack is compacted at a time to limit I/O impact.

```rust
fn maybe_compact(
    store: &ChunkStore,
    config: &CompactionConfig,
    active_jobs: &JobStore,
) {
    if !config.idle_only || active_jobs.active().is_empty() {
        let dead_space = store.compute_dead_space();
        for (pack_id, dead_bytes) in &dead_space {
            let pack_size = store.pack_size(*pack_id);
            let dead_ratio = *dead_bytes as f64 / pack_size as f64;

            if dead_ratio >= 1.0 {
                // All chunks dead -- delete the entire pack.
                store.delete_pack(*pack_id);
            } else if dead_ratio >= config.dead_ratio {
                // Partial dead space -- rewrite with only live chunks.
                let new_id = store.next_pack_id();
                store.compact_pack(*pack_id, new_id);
                break; // one at a time
            }
        }
    }
}
```

## Configuration

```toml
[gc]
policy = "budget"          # ttl, budget, or manual
max_size = "100GB"         # budget policy: evict when store exceeds this
ttl = "7d"                 # ttl policy: evict paths unused for this long
interval = "1h"            # how often GC runs automatically
target_free = 0.2          # budget policy: GC until 20% free (avoid churn)

[gc.compaction]
dead_ratio = 0.3           # compact packs with >30% dead space
idle_only = true           # only compact when no active jobs
```

## Relationship to Other Docs

- **[chunk-store.md](chunk-store.md):** GC removes manifests and chunk
  references from the chunk store LMDB. Pack compaction reclaims dead space
  in pack files. The `gc_store_path()` and `compact_pack()` functions are
  defined there.
- **[fuse.md](fuse.md):** FUSE view contents are GC roots. Access tracking in
  per-view `access.mdb` feeds GC eviction decisions.
- **[store.md](store.md):** Provider TTL on DHT records is coordinated with
  GC -- paths near eviction get short TTLs so the DHT stops routing to us
  before we delete the data.
- **[jobs.md](jobs.md):** Active job inputs and outputs are GC roots while the
  job runs.
- **[containers.md](containers.md):** Build output registration adds new
  manifests and chunks to the store; GC is the inverse operation.
- **[control.md](control.md):** ReplicaSet template closures are GC roots.
