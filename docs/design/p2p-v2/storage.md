# Local Storage

The chunk store is the local content-addressed storage engine. It holds chunks
in append-only pack files, indexes them via LMDB, and serves content for
`/aos/store/manifest/1.0.0` and `/aos/store/chunk/1.0.0` requests. Each daemon
has exactly one chunk store instance. The store is local — replication happens
at the protocol layer.

## On-Disk Layout

```
/var/lib/aos/
  db/
    chunks.mdb                # ChunkDB: manifests, chunk locations
    access.mdb                # AccessDB: manifest serve + object creation times
    store.mdb                 # StoreDB: closure refs, manual pins
    workflow.mdb               # WorkflowDB: workflow state, transitions, cross-workflow deps
  chunks/
    packs/                    # append-only pack files (~1GB each)
      pack-0001.pack
      pack-0002.pack
```

---

## ChunkDB (db/chunks.mdb)

Two named LMDB databases:

- `manifests_db`: store_hash -> ManifestEntry (file tree with per-file chunk lists)
- `locations_db`: chunk_hash (16 bytes) -> PackLocation {pack_id, offset, length, compressed_length}

Readers: FUSE layer (hot path, every file read)
Writers: chunk ingest (bursty, on build completion or content fetch)

No reference counting. Orphaned chunks are cleaned up via mark-and-sweep during
GC. See [gc.md](gc.md).

## AccessDB (db/access.mdb)

Single LMDB database:

- Key: store_hash (string)
- Value: AccessRecord {last_access: u64, nar_size: u64}

Updated on only two events:
- **Object creation:** when a new store object is ingested (build output
  completion or chunk fetch from mesh), the creation time is recorded.
- **Remote manifest serve:** when a remote peer requests the manifest via
  `/aos/store/manifest/1.0.0`, `last_access` is updated ("someone else still
  needs this").

FUSE reads do NOT update access tracking. Objects in an active FUSE view are
pinned by the view itself — GC cannot evict them while mounted.

Per-store-object, NOT per-chunk. Chunks don't have independent access times.

Write rate is ~1-10/sec (manifest serves + object creation), so LMDB handles
this easily with single-writer semantics.

## StoreDB (db/store.mdb)

Two named LMDB databases:

- `closure_db`: store_hash → repeated store_hash (immediate references found by reference scanning)
- `roots_db`: store_hash → RootEntry {pinned_at: u64, reason: string}

`closure_db` records the immediate store dependencies of each object, discovered
via reference scanning during ingest (same as Nix: find store hashes embedded
in file content). This enables fast transitive closure computation — walk the
DAG by following references in LMDB. Used when serving manifests (to build
closure hints) and during job start (to resolve the full input closure).
`closure_db` is also populated during replication — when a replicator downloads
an object, it performs the same reference scan and records the object's
dependencies. No additional sub-database is needed for replication.

`roots_db` holds manual pins, operator-managed. Used for keeping specific store
objects that should not be evicted regardless of LRU age. Active FUSE views are
tracked in memory by the daemon, not in LMDB.

The full GC pin set is: all store hashes in any mounted FUSE view (tracked in
daemon memory) + all entries in `roots_db` (manual pins) + all store hashes
referenced by active workflows (tracked in WorkflowDB). Everything else is
LRU-evictable.

Readers: manifest serving (closure walk), job start (closure resolution), GC (roots scan)
Writers: object ingest (closure refs), operator pin/unpin

## WorkflowDB (db/workflow.mdb)

Four named LMDB databases:

- `workflows_db`: workflow_id (store hash) → WorkflowRecord {spec_hash, status, creator, created_at, deadline, expiration}
- `steps_db`: (workflow_id, step_id) → StepState {status, executor, claimed_at, result, timeout}
- `transitions_db`: (workflow_id, sequence) → WorkflowTransition (serialized protobuf)
- `workflow_deps_db`: workflow_id → [awaited_workflow_ids] (cross-workflow dependency edges)

`workflow_deps_db` enables cycle detection: on workflow announcement, the daemon
inserts edges for any `await_workflow` steps and runs a topological sort on the
full cross-workflow graph. Circular dependencies are rejected immediately.

Readers: workflow engine (step evaluation, state queries), stream protocol handlers (info/log/list)
Writers: workflow engine (state transitions), announcement handler (new workflows)

## Database Separation Rationale

Three separate LMDB environments:

| Database | Sub-databases | Hot path | Writers |
|---|---|---|---|
| `chunks.mdb` | `manifests_db`, `locations_db` | FUSE reads | Chunk ingest (bursty) |
| `access.mdb` | single db | GC | Manifest serve + object creation |
| `store.mdb` | `closure_db`, `roots_db` | Manifest serve, job start | Object ingest, operator pin/unpin |
| `workflow.mdb` | `workflows_db`, `steps_db`, `transitions_db`, `workflow_deps_db` | Workflow engine, stream handlers | Workflow transitions |

LMDB has single-writer semantics. Separating `chunks.mdb` from the other
databases means chunk ingest (bursty) never blocks FUSE chunk reads
(latency-sensitive). `store.mdb` combines closure references and manual pins
since both are per-store-object and have low write frequency. `access.mdb` is
separate because GC reads compete with manifest-serve writes — keeping them in
their own environment avoids lock contention with the store DB. `workflow.mdb`
is separate because workflow transitions are high-frequency during active
execution and should not contend with store or chunk operations.

---

## Content-Defined Chunking

Files are split using the FastCDC algorithm applied per-file (not per-NAR).
Chunking operates on the raw file content, not the NAR serialization. This
means that two store objects containing the same file produce identical chunks
for that file regardless of its position in the directory tree.

| Parameter | Value | Rationale |
|---|---|---|
| Minimum chunk size | 64 KB | Avoids pathologically small chunks on repetitive data. |
| Average chunk size | 256 KB | Balances dedup ratio against manifest size. |
| Maximum chunk size | 1 MB | Bounds worst-case chunk size for memory and transfer. |
| Hash function | xxh3-128 | 16-byte digest, non-cryptographic, >10 GB/s on modern CPUs. |

Chunk identity is the xxh3-128 digest of the chunk's raw (uncompressed) bytes.
Store path integrity uses SHA-256 (Nix native): after reconstruction, the
daemon hashes the reassembled content as a NAR and verifies it against the
manifest's `nar_hash`.

```rust
use fastcdc::v2020::FastCDC;

const MIN_CHUNK: u32 = 64 * 1024;
const AVG_CHUNK: u32 = 256 * 1024;
const MAX_CHUNK: u32 = 1024 * 1024;

fn chunk_file(data: &[u8]) -> Vec<ChunkRef> {
    let chunker = FastCDC::new(data, MIN_CHUNK, AVG_CHUNK, MAX_CHUNK);
    chunker
        .map(|chunk| {
            let hash = xxh3_128(&data[chunk.offset..chunk.offset + chunk.length]);
            ChunkRef {
                hash: hash.to_be_bytes(),
                size: chunk.length as u32,
            }
        })
        .collect()
}
```

Deduplication is implicit: if the chunk hash already exists in `locations_db`,
the write is skipped. This produces cross-version dedup — when a new version
of a package shares most of its files with the previous version, the shared
chunks are already present and only the changed chunks are written.

---

## Pack Files

Chunks are stored in append-only pack files, similar in concept to git
packfiles. Each pack file holds raw chunk data sequentially. Once a pack reaches
its target size (~1 GB), it is sealed and a new pack is opened.

### Format

```
+------------------------------------------+
| Magic: "AOSP" (4 bytes)                  |
| Version: u32 (1)                         |
+------------------------------------------+
| Chunk data (variable length)             |
| Chunk data (variable length)             |
| ...                                      |
+------------------------------------------+
| Trailing checksum: xxh3-128 (16 bytes)   |
+------------------------------------------+
```

Each chunk's data is written directly to the pack file at the current write
offset. The chunk's position and length are recorded in the LMDB index. There
are no per-chunk headers in the pack file itself — the index provides all
addressing.

### Compression

Chunks above 4 KB are compressed with zstd (level 3) before writing to the pack
file. Chunks at or below 4 KB are stored uncompressed — the compression
overhead is not worthwhile at small sizes. The LMDB index records both the
compressed length and the original length, so the reader knows whether
decompression is needed.

```rust
const COMPRESSION_THRESHOLD: usize = 4096;
const ZSTD_LEVEL: i32 = 3;

fn maybe_compress(data: &[u8]) -> (Vec<u8>, bool) {
    if data.len() <= COMPRESSION_THRESHOLD {
        return (data.to_vec(), false);
    }
    let compressed = zstd::encode_all(data, ZSTD_LEVEL).unwrap();
    if compressed.len() < data.len() {
        (compressed, true)
    } else {
        (data.to_vec(), false)
    }
}
```

### Sealed Packs

A sealed pack is immutable. Once sealed, it is never appended to. Sealing
writes the trailing xxh3-128 checksum over the entire pack contents (excluding
the checksum itself). The checksum is verified during compaction and on startup
integrity checks.

Only one pack file is open for writing at a time (the "active pack"). All other
packs are sealed.

---

## Reading Chunks

Serving a `/aos/store/chunk/1.0.0` request:

```rust
fn read_chunk(
    env: &lmdb::Environment,
    pack_dir: &Path,
    chunk_hash: &[u8; 16],
) -> io::Result<Vec<u8>> {
    // 1. Look up location in LMDB.
    let txn = env.begin_ro_txn()?;
    let db = env.open_db(Some("locations"))?;
    let loc_bytes = txn.get(db, chunk_hash)
        .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "chunk not found"))?;
    let loc: PackLocation = unsafe { std::ptr::read(loc_bytes.as_ptr() as *const _) };

    // 2. pread from the pack file.
    let pack_path = pack_dir.join(format!("pack-{:04}.pack", loc.pack_id));
    let file = File::open(&pack_path)?;
    let read_len = if loc.compressed_length > 0 {
        loc.compressed_length as usize
    } else {
        loc.length as usize
    };
    let mut buf = vec![0u8; read_len];
    file.read_exact_at(&mut buf, loc.offset)?;

    // 3. Decompress if needed.
    if loc.compressed_length > 0 {
        buf = zstd::decode_all(&buf[..])?;
    }

    Ok(buf)
}
```

Multiple concurrent reads proceed without contention: LMDB supports concurrent
read transactions, and `pread` on sealed (immutable) pack files does not require
locking.

## Writing Chunks

When ingesting a new store object (after a build or after fetching from a peer),
the daemon chunks each file and writes new chunks to the store. The creation
time is recorded in AccessDB at this point.

```rust
fn write_chunks(
    env: &lmdb::Environment,
    active_pack: &mut ActivePack,
    chunks: &[(Vec<u8>, [u8; 16])], // (data, hash) pairs
) -> io::Result<()> {
    let mut txn = env.begin_rw_txn()?;
    let loc_db = env.open_db(Some("locations"))?;

    for (data, hash) in chunks {
        // Deduplicate: skip if chunk already exists.
        if txn.get(loc_db, hash).is_ok() {
            continue;
        }

        // Compress and write to the active pack file.
        let (encoded, compressed) = maybe_compress(data);
        let offset = active_pack.append(&encoded)?;

        // Record location in LMDB.
        let loc = PackLocation {
            pack_id: active_pack.id(),
            offset,
            length: data.len() as u32,
            compressed_length: if compressed { encoded.len() as u32 } else { 0 },
        };
        txn.put(loc_db, hash, &encode_location(&loc), lmdb::WriteFlags::NO_OVERWRITE)?;

        // Seal and rotate if the pack is full.
        if active_pack.size() >= PACK_TARGET_SIZE {
            active_pack.seal()?;
            *active_pack = ActivePack::create_next(active_pack.id() + 1)?;
        }
    }

    txn.commit()?;
    Ok(())
}

const PACK_TARGET_SIZE: u64 = 1_073_741_824; // 1 GB
```

---

## Manifest Generation

When a build output or fetched store path needs to be registered in the store,
the daemon walks the directory tree, chunks each file, and produces a manifest.
Build output registration (see [containers.md](containers.md)) is the primary
source of new manifests and chunks.

```rust
fn generate_manifest(
    root: &Path,
    store_hash: [u8; 32],
    name: &str,
) -> io::Result<(Manifest, Vec<(Vec<u8>, [u8; 16])>)> {
    let mut entries = Vec::new();
    let mut all_chunks = Vec::new();
    let mut nar_hasher = Sha256::new();

    for entry in walkdir::WalkDir::new(root).sort_by_file_name() {
        let entry = entry?;
        let rel_path = entry.path().strip_prefix(root).unwrap();
        let metadata = entry.metadata()?;

        if metadata.is_dir() {
            nar_hasher.update_dir(rel_path, metadata.permissions().mode());
            entries.push(Entry::dir(rel_path, metadata.permissions().mode()));
        } else if metadata.is_symlink() {
            let target = std::fs::read_link(entry.path())?;
            nar_hasher.update_symlink(rel_path, &target);
            entries.push(Entry::symlink(rel_path, target));
        } else {
            let data = std::fs::read(entry.path())?;
            nar_hasher.update_file(rel_path, &data, metadata.permissions().mode());

            let chunk_refs = chunk_file(&data);
            let chunker = FastCDC::new(&data, MIN_CHUNK, AVG_CHUNK, MAX_CHUNK);
            for (chunk, cref) in chunker.zip(chunk_refs.iter()) {
                let chunk_data = data[chunk.offset..chunk.offset + chunk.length].to_vec();
                all_chunks.push((chunk_data, cref.hash));
            }

            entries.push(Entry::file(
                rel_path,
                data.len() as u64,
                metadata.permissions().mode() & 0o111 != 0,
                chunk_refs,
            ));
        }
    }

    let manifest = Manifest {
        store_hash,
        name: name.to_string(),
        nar_hash: nar_hasher.finalize(),
        nar_size: nar_hasher.byte_count(),
        entries,
    };

    Ok((manifest, all_chunks))
}
```

The NAR hash is computed on-the-fly during the walk, producing the same hash
that `nix-store --dump` would produce. This avoids materializing the full NAR
serialization in memory.

---

## Chunk Garbage Collection

Orphaned chunks (those no longer referenced by any manifest) are cleaned up by
a mark-and-sweep pass during GC. There is no reference counting — the GC
scans all surviving manifests to build the set of live chunk hashes, then
removes any `locations_db` entries not in that set. Chunk data in pack files
becomes dead space until compaction.

See [gc.md](gc.md) for the full three-phase GC algorithm (store object
eviction, orphaned chunk cleanup, pack compaction).

---

## Pack Compaction

Sealed packs accumulate dead space as chunks are GC'd. Compaction reclaims
this space by rewriting packs, keeping only live chunks.

### When Compaction Runs

Compaction is a background maintenance task triggered when:

1. **Dead space threshold**: a sealed pack has >30% dead space (tracked in
   memory, reconstructed from `locations_db` vs pack file sizes on startup).
2. **Idle condition**: no active builds and no in-flight chunk transfers.

At most one pack is compacted at a time. The daemon checks for compaction
candidates after each GC cycle completes.

### Compaction Sequence

1. **Identify live chunks.** Scan `locations_db` for all entries where
   `pack_id` matches the target pack.
2. **Write new pack.** Create a new pack file with the next available ID. Copy
   live chunks sequentially from the old pack via `pread`, preserving their
   existing compression.
3. **Atomic index update.** In a single LMDB write transaction, update every
   relocated chunk's `PackLocation` in `locations_db` to point to the new pack
   ID and offset. The transaction is all-or-nothing — readers see either all
   old locations or all new locations, never a mix.
4. **Delete old pack.** Remove the old pack file from disk. In-flight `pread`
   calls that opened the old file descriptor before deletion complete normally
   (POSIX unlink semantics).
5. **Seal new pack.** Write the trailing xxh3-128 checksum.

```rust
fn compact_pack(
    env: &lmdb::Environment,
    pack_dir: &Path,
    target_pack_id: u32,
    new_pack_id: u32,
) -> io::Result<CompactStats> {
    // Collect all live chunk locations pointing to this pack.
    let live_chunks = {
        let txn = env.begin_ro_txn()?;
        let loc_db = env.open_db(Some("locations"))?;
        let mut live = Vec::new();
        let mut cursor = txn.open_ro_cursor(loc_db)?;
        for (key, val) in cursor.iter() {
            let loc: PackLocation = decode_location(val);
            if loc.pack_id == target_pack_id {
                let mut hash = [0u8; 16];
                hash.copy_from_slice(key);
                live.push((hash, loc));
            }
        }
        live
    };

    // Create new pack, copy live chunks, collect new locations.
    let mut new_pack = ActivePack::create(pack_dir, new_pack_id)?;
    let mut updates: Vec<([u8; 16], PackLocation)> = Vec::with_capacity(live_chunks.len());

    let old_path = pack_dir.join(format!("pack-{:04}.pack", target_pack_id));
    let old_file = File::open(&old_path)?;

    for (hash, old_loc) in &live_chunks {
        let read_len = if old_loc.compressed_length > 0 {
            old_loc.compressed_length as usize
        } else {
            old_loc.length as usize
        };
        let mut buf = vec![0u8; read_len];
        old_file.read_exact_at(&mut buf, old_loc.offset)?;

        let new_offset = new_pack.append(&buf)?;
        updates.push((*hash, PackLocation {
            pack_id: new_pack_id,
            offset: new_offset,
            length: old_loc.length,
            compressed_length: old_loc.compressed_length,
        }));
    }

    new_pack.seal()?;

    // Atomic index update.
    let mut txn = env.begin_rw_txn()?;
    let loc_db = env.open_db(Some("locations"))?;
    for (hash, new_loc) in &updates {
        txn.put(loc_db, hash, &encode_location(new_loc), lmdb::WriteFlags::empty())?;
    }
    txn.commit()?;

    // Remove old pack file.
    std::fs::remove_file(&old_path)?;

    Ok(CompactStats {
        chunks_copied: updates.len() as u64,
        new_size: new_pack.size(),
    })
}
```

### Crash Safety

- **Before LMDB commit (step 3):** the new pack file exists but no index
  entries point to it. On restart, orphaned pack files (no `locations_db`
  references) are deleted.
- **After LMDB commit, before old pack delete (step 4):** both packs exist but
  `locations_db` points to the new one. The old pack is orphaned and cleaned up
  on restart.
- **After completion:** clean state.

No write-ahead log or journal is needed — LMDB's transactional semantics and
POSIX file deletion provide the necessary atomicity.

### FUSE Read Consistency

FUSE reads use `pread` with the pack ID and offset from `locations_db`. During
compaction, reads that resolved the old location before the LMDB commit hold an
open file descriptor to the old pack and complete normally. Reads after the
commit see the new pack. LMDB MVCC ensures readers always see a consistent
snapshot. No locking is needed.

### Fully Dead Packs

If a pack has zero live chunks, it can be deleted outright without writing a
new pack — skip steps 2-3 and go directly to deletion.

### Dead Space Tracking

Dead space per pack is tracked as a counter in memory, incremented when a chunk
is GC'd. On daemon startup, the counter is reconstructed by scanning
`locations_db` and comparing against pack file sizes:

```rust
fn compute_dead_space(env: &lmdb::Environment, pack_dir: &Path) -> HashMap<u32, u64> {
    let mut live_bytes: HashMap<u32, u64> = HashMap::new();

    let txn = env.begin_ro_txn().unwrap();
    let loc_db = env.open_db(Some("locations")).unwrap();
    let mut cursor = txn.open_ro_cursor(loc_db).unwrap();
    for (_key, val) in cursor.iter() {
        let loc: PackLocation = decode_location(val);
        let on_disk = if loc.compressed_length > 0 {
            loc.compressed_length as u64
        } else {
            loc.length as u64
        };
        *live_bytes.entry(loc.pack_id).or_default() += on_disk;
    }

    let mut dead_space = HashMap::new();
    for entry in std::fs::read_dir(pack_dir).unwrap() {
        let entry = entry.unwrap();
        if let Some(pack_id) = parse_pack_id(&entry.file_name()) {
            let file_size = entry.metadata().unwrap().len();
            let header_size = 8u64; // magic + version
            let checksum_size = 16u64;
            let data_size = file_size - header_size - checksum_size;
            let live = live_bytes.get(&pack_id).copied().unwrap_or(0);
            dead_space.insert(pack_id, data_size.saturating_sub(live));
        }
    }

    dead_space
}
```

---

## Sizing Estimates

Typical numbers for a moderately-sized Nix store (10,000 store paths, ~100 GB
total content):

| Metric | Estimate | Notes |
|---|---|---|
| Chunks per store path | ~100 (avg) | 25 MB avg store path / 256 KB avg chunk |
| Total chunks (before dedup) | ~1,000,000 | 10,000 paths * 100 chunks |
| Total chunks (after dedup) | ~600,000 | ~40% dedup ratio across package versions |
| LMDB `locations_db` size | ~14 MB | 600K entries * 24 bytes value |
| LMDB `manifests_db` size | ~50 MB | 10K manifests, ~5 KB avg |
| Total ChunkDB index size | ~64 MB | Both databases |
| Pack files | ~60 GB | After compression (~60% of raw) |
| Pack file count | ~60 | At 1 GB per sealed pack |

For a large store (100,000 paths, ~1 TB total content), multiply accordingly.
The LMDB index stays under 1 GB. Pack file count reaches ~600.

LMDB's memory-mapped I/O means the index performs well even when it exceeds
available RAM — the OS page cache handles hot-path caching transparently.

---

## Relationship to Other Docs

- [gc.md](gc.md) -- eviction algorithm using AccessDB and RootsDB
- [fuse.md](fuse.md) -- FUSE filesystem (read-only, no access tracking)
- [view.md](view.md) -- view model (views pin store objects against GC)
- [containers.md](containers.md) -- build output registration (primary source of new manifests)
- [store.md](store.md) -- mesh-level store protocol (transfer, discovery)
