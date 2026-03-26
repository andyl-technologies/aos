# Local Storage

The chunk store is the local content-addressed storage engine. It holds chunks
in append-only pack files, indexes them via LMDB, and serves content for
`/aos/store/object/1.0.0` and `/aos/store/chunk/1.0.0` requests. Each daemon
has exactly one chunk store instance. The store is local — retention across
peers is driven by Statute mount affinities (see [mounts.md](mounts.md)).

## On-Disk Layout

```
/var/lib/aos/
  db/
    store.mdb                 # store index (store_hash → meta_hash)
    objects.mdb               # merkle tree nodes (tree_db, blob_db, meta_db)
    chunk.mdb                 # chunk locations (chunk_hash → tier + pack location)
    hash.mdb                  # hash translation (sha256_db, sha1_db, blake3_to_chunk_db)
    gc.mdb                    # GC roots / pins
    access.mdb                # access tracking for LRU eviction
    workflow.mdb              # workflow state and transitions
  chunks/
    nvme/                     # tier: NVMe storage
      packs/
        pack-0001.pack
    hdd/                      # tier: HDD storage
      packs/
        pack-0001.pack
    tmpfs/                    # tier: tmpfs (ephemeral, fast)
      packs/
        pack-0001.pack
```

---

## StoreDB (store.mdb)

Single default database (no named sub-databases):

- Key: `store_hash` (string)
- Value: `meta_hash` (blake3, 32 bytes)

A simple index from Nix store path hash to the blake3 hash of the
corresponding NixObject MetaObject in ObjectsDB's `meta_db`. One entry per
Nix store path. All store path metadata (name, root_tree, nar_hash,
nar_size, refs) lives in the NixObject itself — the store_db is purely an
index.

Multiple store hashes can map to the same `root_tree` within their
NixObjects (content dedup — two different input-addressed paths with
identical content share one merkle tree).

Readers: FUSE (first hop: store_hash → meta_hash → NixObject → root_tree), resolve serving, GC
Writers: store object ingest (bursty)

## ObjectsDB (objects.mdb)

Three named databases:

- `tree_db`: tree_hash (blake3, 32 bytes) → TreeObject (serialized protobuf)
- `blob_db`: blob_hash (blake3, 32 bytes) → BlobObject { size: u64, executable: bool, root_chunk: xxh128 (16 bytes), root_height: u32 }
- `meta_db`: meta_hash (blake3, 32 bytes) → MetaObject (serialized protobuf)

One blob maps to one chunk tree root. The `root_chunk` and `root_height`
fields locate the chunk tree in ChunkDB. For single-chunk files (the common
case), `root_height = 0` and `root_chunk` is the sole data chunk's xxh128.
See [git-store.md](git-store.md) for the full chunk tree model.

Meta objects are structured metadata that reference other objects. Each field
is either a string value (metadata), a numeric value, or an object reference
(blake3 hash forming a DAG edge). Concrete MetaObject types:
- **NixObject** — store path metadata (store_hash, name, root_tree, nar_hash, nar_size, refs). Replaces the old StoreRecord.
- **GitCommit** — git commits (tree ref, parent refs, author, message)
- **StatuteBlock** — consensus blocks (parent block, state root, transaction refs, QC ref)
- **StatuteTransaction** — state mutations (key, value ref, prev value ref, UCAN, signature)
- **StatuteQC** — quorum certificates (block ref, vote refs, validator signatures)

The GC closure walker follows all `Ref` fields in meta objects recursively,
ensuring that pinning a NixObject, git commit, or Statute block protects
its entire dependency tree.

The git-compatible merkle tree. Tree and blob hashes use blake3 (not SHA-256
or SHA-1). External hash systems (git, Nix) use the translation indexes in
HashDB.

Subtree dedup: if two store objects share an identical `lib/` directory,
the tree_db entry for that subtree is stored exactly once. Blob entries
for shared files are also stored once.

Readers: FUSE path resolution (tree traversal: one read per path component)
Writers: store object ingest (bursty, but skips existing entries)

## ChunkDB (chunk.mdb)

Single default database:

- Key: chunk_hash (xxh128, 16 bytes) — `xxh128(le32(height) || data)`
- Value: PackLocation { tier_id: u8, pack_id: u32, offset: u64, length: u32, compressed_length: u32, height: u32 }

The key includes the height in its hash preimage: `xxh128(le32(height) || data)`.
Height 0 chunks contain raw data bytes. Height N chunks (N > 0) contain a
serialized list of ChunkRef entries pointing to height N-1 chunks. See
[git-store.md](git-store.md) for the chunk tree model.

`tier_id` identifies which tier's pack files contain this chunk. A chunk
exists in exactly one tier at a time — one ChunkDB entry per chunk. The
lookup is still one LMDB read + one pread.

Maps chunk hashes to their location in pack files. This is the FUSE hot
path — every `read()` call looks up chunk locations here.

Readers: FUSE (every file read)
Writers: chunk ingest (bursty, on build completion or content fetch)

## HashDB (hash.mdb)

Three named databases:

- `sha256_db`: sha256_hash (32 bytes) → blake3_hash (32 bytes)
- `sha1_db`: sha1_hash (20 bytes) → blake3_hash (32 bytes)
- `blake3_to_chunk_db`: blake3_hash (32 bytes) → xxh128_hash (16 bytes)

The first two are translation indexes from external hash systems to internal
blake3 hashes. Populated during ingest (when tree/blob hashes are computed,
the SHA-256 and SHA-1 equivalents are also computed and indexed). Used for:

- Git tooling compatibility (`git cat-file -p <sha256>` → look up blake3 → read from tree_db/blob_db)
- Nix compatibility (NAR hash verification uses SHA-256)
- Interoperability with systems that use SHA-1 or SHA-256 identifiers

The third database (`blake3_to_chunk_db`) maps blake3 identity hashes to
xxh128 chunk hashes. When structural objects (trees, blobs, meta objects)
are also stored as chunks for network transfer, this index allows lookup of
their chunk hash from their identity hash.

Readers: git tools, Nix verification, external API queries, chunk transfer resolution
Writers: store object ingest (alongside tree_db/blob_db writes)

## GcDB (gc.mdb)

Single default database:

- Key: store_hash (string)
- Value: RootEntry { pinned_at: u64, reason: string, ttl: u64 }

GC roots (pins). Objects pinned here are excluded from LRU eviction. Pins
are created by:
- Store upload protocol (time-limited pin from `requested_ttl`)
- Store fetch protocol (time-limited pin)
- Active workflow specs (closure-based pinning)
- Operator manual pins (`aos store pin <hash>`)

Active StoreVolumes are tracked in daemon memory (not in LMDB) and also serve
as GC roots.

Readers: GC (periodic scan)
Writers: pin/unpin operations (low frequency)

## AccessDB (access.mdb)

Single default database:

- Key: store_hash (string)
- Value: AccessRecord { last_access: u64, nar_size: u64 }

Updated on only two events:
- **Object creation:** when a new store object is ingested, the creation time
  is recorded.
- **Remote object serve:** when a remote peer requests the store object via
  `/aos/store/object/1.0.0`, `last_access` is updated.

FUSE reads do NOT update access tracking. Objects in an active FUSE view are
pinned by the view itself.

Per-store-object, NOT per-chunk or per-tree-node.

Readers: GC (periodic scan for LRU eviction)
Writers: object serve + object creation (~1-10/sec)

## WorkflowDB (workflow.mdb)

Four named databases:

- `workflows_db`: workflow_id → WorkflowRecord { spec_hash, status, creator, created_at, deadline, expiration }
- `steps_db`: (workflow_id, step_id) → StepState { status, executor, claimed_at, result, timeout }
- `transitions_db`: (workflow_id, sequence) → WorkflowTransition (serialized protobuf)
- `workflow_deps_db`: workflow_id → [awaited_workflow_ids] (cross-workflow dependency edges)

Readers: workflow engine, stream protocol handlers
Writers: workflow transitions (high-frequency during active execution)

## Database Separation Rationale

Seven LMDB environments, each with one concern:

| Database | Sub-databases | Hot path | Writers |
|---|---|---|---|
| `store.mdb` | (default) | Store lookups, FUSE first hop | Ingest |
| `objects.mdb` | `tree_db`, `blob_db`, `meta_db` | FUSE path resolution | Ingest |
| `chunk.mdb` | (default) | FUSE reads (every `read()`) | Ingest |
| `hash.mdb` | `sha256_db`, `sha1_db`, `blake3_to_chunk_db` | Git/Nix compat lookups, chunk transfer | Ingest |
| `gc.mdb` | (default) | GC scans | Pin/unpin |
| `access.mdb` | (default) | GC scans | Object serve |
| `workflow.mdb` | 4 sub-databases | Workflow engine | Transitions |

LMDB has single-writer semantics per environment. The separation ensures:
- FUSE chunk reads (chunk.mdb) are never blocked by tree/blob ingest (objects.mdb)
- GC pin operations (gc.mdb) don't block store ingest (store.mdb)
- Workflow transitions (workflow.mdb) don't block any store operation
- Hash index writes (hash.mdb) don't block FUSE path resolution (objects.mdb)

The ingest path writes to store.mdb + objects.mdb + chunk.mdb + hash.mdb
sequentially. There is no atomic cross-environment transaction. Crash
recovery: on startup, scan objects.mdb for tree/blob entries not reachable
from any store.mdb root. Orphans are cleaned up (same pattern as orphaned
chunks after failed pack compaction).

---

## Content-Defined Chunking

The storage layer uses content-defined chunking (CDC) for deduplication and
transfer. This is the lower layer of the two-layer store model — see
[git-store.md](git-store.md) for the upper git-compatible merkle tree layer
that provides structural verification. Files are identified by blake3 blob
hash (git layer) and stored as xxh128 CDC chunks (storage layer).

Files are split using the FastCDC algorithm applied per-file (not per-NAR).
Chunking operates on the raw file content, not the NAR serialization. This
means that two store objects containing the same file produce identical chunks
for that file regardless of its position in the directory tree.

| Parameter | Value | Rationale |
|---|---|---|
| Minimum chunk size | 64 KB | Avoids pathologically small chunks on repetitive data. |
| Average chunk size | 256 KB | Balances dedup ratio against index size. |
| Maximum chunk size | 1 MB | Bounds worst-case chunk size for memory and transfer. |
| Hash function | xxh128 | 16-byte digest, non-cryptographic, >10 GB/s on modern CPUs. |

Chunk identity is `xxh128(le32(height) || raw_bytes)` where height is 0 for
data chunks. Store path integrity uses SHA-256 (Nix native): after
reconstruction, the daemon hashes the reassembled content as a NAR and
verifies it against the NixObject's `nar_hash`.

```rust
use fastcdc::v2020::FastCDC;

const MIN_CHUNK: u32 = 64 * 1024;
const AVG_CHUNK: u32 = 256 * 1024;
const MAX_CHUNK: u32 = 1024 * 1024;

fn chunk_file(data: &[u8]) -> Vec<ChunkRef> {
    let chunker = FastCDC::new(data, MIN_CHUNK, AVG_CHUNK, MAX_CHUNK);
    chunker
        .map(|chunk| {
            let chunk_data = &data[chunk.offset..chunk.offset + chunk.length];
            // Height 0: xxh128(le32(0) || chunk_data)
            let hash = xxh128_with_height(0, chunk_data);
            ChunkRef {
                hash: hash.to_be_bytes(),
                size: chunk.length as u32,
            }
        })
        .collect()
}
```

Deduplication is implicit: if the chunk hash already exists in `chunk_db`,
the write is skipped. This produces cross-version dedup — when a new version
of a package shares most of its files with the previous version, the shared
chunks are already present and only the changed chunks are written.

### Chunk Tree Nodes (height > 0)

The FastCDC parameters above apply to height-0 (leaf/data) chunks. For blobs
with many data chunks, the ChunkRef list is itself split using FastCDC with
separate parameters to produce interior (height > 0) chunk tree nodes:

| Parameter | Value | Rationale |
|---|---|---|
| Minimum entries per node | 512 | ~10 KB min node size (20 bytes/entry) |
| Average entries per node | 1024 | ~20 KB avg node size |
| Maximum entries per node | 2048 | ~40 KB max node size |

Interior nodes are hashed as `xxh128(le32(height) || serialized_refs)` and
stored in ChunkDB like any other chunk. See [git-store.md](git-store.md) for
the full chunk tree construction algorithm.

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

## Storage Tiers

A daemon can have multiple storage tiers, each backed by different media
(NVMe, HDD, tmpfs). Each tier has its own pack file directory, capacity
budget, and labels. The LMDB indexes (ChunkDB, ObjectsDB, etc.) are shared
— only the pack file storage is per-tier.

### Configuration

```toml
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

[[store.tiers]]
name = "tmpfs"
chunk_dir = "/run/aos/chunks-tmpfs"
budget = "32Gi"
labels = { media = "tmpfs", persistent = "false" }
```

### Tier Selection

When ingesting new chunks (build output, fetch, peer transfer):

- If the ingest is driven by an affinity-pinned Statute reference with
  `tier` labels, place chunks in the matching tier.
- Otherwise, place in the default tier (first configured tier, or the tier
  with the most free space).
- Active pack file rotation is per-tier: each tier has its own active pack.

### Migration

Objects can move between tiers without changing identity (same xxh128 hash):

1. Copy chunk data from source tier pack file to destination tier pack file.
2. Atomic ChunkDB update: change `tier_id` in PackLocation.
3. Source tier reclaims space during compaction.

Migration triggers:

- **Promotion**: cold tier -> hot tier when access frequency increases.
- **Demotion**: hot tier -> cold tier under LRU pressure on the hot tier.
  Demotion is preferred over eviction — demote to a colder tier before
  evicting entirely.
- **Affinity-driven**: when a mount's `_affinity.tier` changes, affected
  objects migrate to the correct tier.

### Single-Tier Compatibility

A daemon with one `[[store.tiers]]` entry behaves identically to the
current model. The `tier_id` is always 0 and can be ignored.

---

## Reading Chunks

Serving a `/aos/store/chunk/1.0.0` request:

```rust
fn read_chunk(
    env: &lmdb::Environment,
    tiers: &[TierConfig],
    chunk_hash: &[u8; 16],
) -> io::Result<Vec<u8>> {
    // 1. Look up location in LMDB.
    let txn = env.begin_ro_txn()?;
    let db = env.open_db(None)?;
    let loc_bytes = txn.get(db, chunk_hash)
        .map_err(|_| io::Error::new(io::ErrorKind::NotFound, "chunk not found"))?;
    let loc: PackLocation = decode_location(loc_bytes);

    // 2. Select the tier's pack directory and pread from the pack file.
    let tier = &tiers[loc.tier_id as usize];
    let pack_path = tier.chunk_dir.join(format!("pack-{:04}.pack", loc.pack_id));
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
    tier: &mut TierState,      // target tier
    chunks: &[(Vec<u8>, [u8; 16], u32)], // (data, hash, height) triples
) -> io::Result<()> {
    let mut txn = env.begin_rw_txn()?;
    let loc_db = env.open_db(None)?;

    for (data, hash, chunk_height) in chunks {
        // Deduplicate: skip if chunk already exists.
        if txn.get(loc_db, hash).is_ok() {
            continue;
        }

        // Compress and write to the tier's active pack file.
        let (encoded, compressed) = maybe_compress(data);
        let offset = tier.active_pack.append(&encoded)?;

        // Record location in LMDB (includes tier_id).
        let loc = PackLocation {
            tier_id: tier.id,
            pack_id: tier.active_pack.id(),
            offset,
            length: data.len() as u32,
            compressed_length: if compressed { encoded.len() as u32 } else { 0 },
            height: chunk_height,
        };
        txn.put(loc_db, hash, &encode_location(&loc), lmdb::WriteFlags::NO_OVERWRITE)?;

        // Seal and rotate if the pack is full.
        if tier.active_pack.size() >= PACK_TARGET_SIZE {
            tier.active_pack.seal()?;
            tier.active_pack = ActivePack::create_next(tier.active_pack.id() + 1)?;
        }
    }

    txn.commit()?;
    Ok(())
}

const PACK_TARGET_SIZE: u64 = 1_073_741_824; // 1 GB
```

---

## Object Ingest Pipeline

When a build output or fetched store path needs to be registered in the store,
the daemon walks the directory tree, chunks each file, builds chunk trees, and
produces a NixObject MetaObject. Build output registration (see
[containers.md](containers.md)) is the primary source of new objects and chunks.

The pipeline produces:
1. Height-0 data chunks from FastCDC on file content
2. Chunk tree (height 1+) for files with many chunks
3. BlobObject entries in `blob_db` (root_chunk + root_height per file)
4. TreeObject entries in `tree_db` (unchanged git-format merkle trees)
5. NixObject MetaObject in `meta_db`
6. Store index entry in `store_db` (store_hash -> meta_hash)

```rust
fn ingest_store_object(
    root: &Path,
    store_hash: &str,
    name: &str,
    refs: &[Blake3Hash],
) -> io::Result<Blake3Hash> {
    let mut nar_hasher = Sha256::new();
    let mut tree_builder = TreeBuilder::new();

    for entry in walkdir::WalkDir::new(root).sort_by_file_name() {
        let entry = entry?;
        let rel_path = entry.path().strip_prefix(root).unwrap();
        let metadata = entry.metadata()?;

        if metadata.is_dir() {
            nar_hasher.update_dir(rel_path, metadata.permissions().mode());
            tree_builder.add_dir(rel_path, metadata.permissions().mode());
        } else if metadata.is_symlink() {
            let target = std::fs::read_link(entry.path())?;
            nar_hasher.update_symlink(rel_path, &target);
            // Symlink stored as blob containing target path
            let blob_hash = blake3_blob(target.as_bytes());
            let chunk = store_data_chunk(target.as_bytes())?;
            blob_db.put(blob_hash, BlobObject {
                size: target.as_bytes().len() as u64,
                executable: false,
                root_chunk: chunk.hash,
                root_height: 0,
            });
            tree_builder.add_symlink(rel_path, blob_hash);
        } else {
            let data = std::fs::read(entry.path())?;
            let executable = metadata.permissions().mode() & 0o111 != 0;
            nar_hasher.update_file(rel_path, &data, metadata.permissions().mode());

            // 1. FastCDC → height-0 data chunks
            let data_chunks = chunk_file(&data);
            for chunk_ref in &data_chunks {
                store_data_chunk_if_new(chunk_ref)?;
            }

            // 2. Build chunk tree (height 1+ if many chunks)
            let (root_chunk, root_height) = build_chunk_tree(&data_chunks);

            // 3. BlobObject in blob_db
            let blob_hash = blake3_blob(&data);
            blob_db.put(blob_hash, BlobObject {
                size: data.len() as u64,
                executable,
                root_chunk,
                root_height,
            });

            tree_builder.add_file(rel_path, blob_hash, executable);
        }
    }

    // 4. TreeObjects in tree_db (bottom-up)
    let root_tree = tree_builder.finalize(&tree_db)?;

    // 5. NixObject MetaObject in meta_db
    let nix_object = MetaObject::nix_object(
        store_hash,
        name,
        root_tree,
        nar_hasher.finalize(),
        nar_hasher.byte_count(),
        refs,
    );
    let meta_hash = blake3(&nix_object.serialize());
    meta_db.put(meta_hash, nix_object);

    // 6. Store index: store_hash → meta_hash
    store_db.put(store_hash, meta_hash);

    Ok(meta_hash)
}
```

The NAR hash is computed on-the-fly during the walk, producing the same hash
that `nix-store --dump` would produce. This avoids materializing the full NAR
serialization in memory. The function returns the NixObject's `meta_hash`,
which is the canonical identity for lookups via `store_db`.

---

## Chunk Garbage Collection

Orphaned chunks (those not reachable from any BlobObject's chunk tree) are
cleaned up by a mark-and-sweep pass during GC. There is no reference
counting — the mark phase walks NixObject -> tree_db -> blob_db -> chunk
trees (height > 0 refs) -> height-0 data chunks to build the set of live
chunk hashes, then removes any `chunk_db` entries not in that set. Chunk data in pack files
becomes dead space until compaction.

See [gc.md](gc.md) for the full three-phase GC algorithm (store object
eviction, orphaned chunk cleanup, pack compaction).

---

## Pack Compaction

Sealed packs accumulate dead space as chunks are GC'd. Compaction reclaims
this space by rewriting packs, keeping only live chunks. Compaction is
per-tier — dead space tracking and the compaction trigger (>30% dead space)
apply within each tier independently.

### When Compaction Runs

Compaction is a background maintenance task triggered when:

1. **Dead space threshold**: a sealed pack has >30% dead space (tracked in
   memory, reconstructed from `chunk_db` vs pack file sizes on startup).
2. **Idle condition**: no active builds and no in-flight chunk transfers.

At most one pack is compacted at a time. The daemon checks for compaction
candidates after each GC cycle completes.

### Compaction Sequence

1. **Identify live chunks.** Scan `chunk_db` for all entries where
   `pack_id` matches the target pack.
2. **Write new pack.** Create a new pack file with the next available ID. Copy
   live chunks sequentially from the old pack via `pread`, preserving their
   existing compression.
3. **Atomic index update.** In a single LMDB write transaction, update every
   relocated chunk's `PackLocation` in `chunk_db` to point to the new pack
   ID and offset. The transaction is all-or-nothing — readers see either all
   old locations or all new locations, never a mix.
4. **Delete old pack.** Remove the old pack file from disk. In-flight `pread`
   calls that opened the old file descriptor before deletion complete normally
   (POSIX unlink semantics).
5. **Seal new pack.** Write the trailing xxh3-128 checksum.

```rust
fn compact_pack(
    env: &lmdb::Environment,
    tier: &TierConfig,
    target_pack_id: u32,
    new_pack_id: u32,
) -> io::Result<CompactStats> {
    let pack_dir = &tier.chunk_dir;
    // Collect all live chunk locations pointing to this pack.
    let live_chunks = {
        let txn = env.begin_ro_txn()?;
        let loc_db = env.open_db(None)?;
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
            tier_id: tier.id,
            pack_id: new_pack_id,
            offset: new_offset,
            length: old_loc.length,
            compressed_length: old_loc.compressed_length,
            height: old_loc.height,
        }));
    }

    new_pack.seal()?;

    // Atomic index update.
    let mut txn = env.begin_rw_txn()?;
    let loc_db = env.open_db(None)?;
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
  entries point to it. On restart, orphaned pack files (no `chunk_db`
  references) are deleted.
- **After LMDB commit, before old pack delete (step 4):** both packs exist but
  `chunk_db` points to the new one. The old pack is orphaned and cleaned up
  on restart.
- **After completion:** clean state.

No write-ahead log or journal is needed — LMDB's transactional semantics and
POSIX file deletion provide the necessary atomicity.

### FUSE Read Consistency

FUSE reads use `pread` with the pack ID and offset from `chunk_db`. During
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
`chunk_db` and comparing against pack file sizes:

```rust
fn compute_dead_space(env: &lmdb::Environment, pack_dir: &Path) -> HashMap<u32, u64> {
    let mut live_bytes: HashMap<u32, u64> = HashMap::new();

    let txn = env.begin_ro_txn().unwrap();
    let loc_db = env.open_db(None).unwrap();
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
| LMDB `chunk_db` size | ~14 MB | 600K entries * 24 bytes value |
| LMDB `store_db` size | ~1 MB | 10K entries, ~64 bytes avg (hash → 32-byte blake3) |
| Total index size | ~15 MB | chunk_db + store_db |
| Pack files | ~60 GB | After compression (~60% of raw) |
| Pack file count | ~60 | At 1 GB per sealed pack |

Interior chunk tree nodes add negligible overhead for typical Nix store
objects. Most store paths are < 256 MB, meaning files produce either a single
data chunk (height 0) or a small number of chunks with a single height-1 root
node. Only very large files (> ~256 MB) produce height-1 interior nodes, and
height-2 nodes only appear above ~256 GB. The interior node chunks are small
(~20 KB each) and are stored in the same pack files as data chunks.

For a large store (100,000 paths, ~1 TB total content), multiply accordingly.
The LMDB index stays under 1 GB. Pack file count reaches ~600.

With multiple tiers, the total storage capacity is the sum of all tier
budgets. Hot data lives on fast tiers, cold data on slow tiers. The LMDB
indexes remain shared and small relative to pack file data.

LMDB's memory-mapped I/O means the index performs well even when it exceeds
available RAM — the OS page cache handles hot-path caching transparently.

---

## ZFS Volume Layout

Local volumes (both persistent and ephemeral) use ZFS datasets, separate from
the content-addressed chunk store. The chunk store uses LMDB + pack files under
`/var/lib/aos/`; volumes use ZFS datasets under the configured ZFS pool.

```
{pool}/aos/
  volumes/
    persistent/
      {volume_id}/              # ZFS dataset with quota, survives job restarts
    ephemeral/
      {cluster_id}/
        {job_id}/
          {volume_id}/          # ZFS dataset, destroyed on job exit
```

ZFS properties for volume datasets:

| Property | Value | Purpose |
|---|---|---|
| `quota` | from `VolumeRequest.size` | Disk space enforcement |
| `compression` | `zstd` (default) | Transparent compression |
| `atime` | `off` | Performance |
| `user:aos:volume_id` | volume ID | Identity (persistent only) |
| `user:aos:cluster_id` | cluster ID | Cluster association |
| `user:aos:created_at` | epoch micros | Creation timestamp |
| `user:aos:last_used_at` | epoch micros | Last job attachment (persistent only) |

Persistent volume metadata is stored entirely in ZFS user properties. The daemon
rebuilds its in-memory persistent volume index by scanning ZFS datasets on startup.
No additional LMDB database is needed.

See [volumes.md](volumes.md) for the full volume model and lifecycle.

## Relationship to Other Docs

- [gc.md](gc.md) -- eviction algorithm using AccessDB and gc.mdb; per-tier LRU eviction, demotion before eviction
- [fuse.md](fuse.md) -- FUSE filesystem (read-only, no access tracking)
- [view.md](view.md) -- view model (StoreVolumes pin store objects against GC)
- [containers.md](containers.md) -- build output registration (primary source of new objects and chunks)
- [store.md](store.md) -- mesh-level store protocol (resolve, chunk transfer)
- [git-store.md](git-store.md) -- content-addressed object model (TreeObject, BlobObject, chunk tree, MetaObject)
- [store-upload.md](store-upload.md) -- upload verification uses blob hashes and tree hashes
- [volumes.md](volumes.md) -- volume model, ZFS dataset lifecycle
- mounts.md -- `_affinity` tier labels drive tier selection
