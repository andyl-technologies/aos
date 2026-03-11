# Local Chunk Store

The chunk store is the local content-addressed storage engine backing the wire
protocol defined in [store.md](store.md) and [protocol.md](protocol.md). It
holds chunks in append-only pack files and indexes them via LMDB. It serves
chunks for `/aos/store/chunk/1.0.0` requests and manifests for
`/aos/store/manifest/1.0.0` requests.

Each daemon has exactly one chunk store instance. The store is local -- it has
no awareness of the mesh. The daemon's protocol handlers read from and write to
it; replication happens at the protocol layer.

## On-Disk Layout

```
/var/lib/aos/
  chunks/
    packs/
      pack-0001.pack
      pack-0002.pack
      ...
    index.mdb
    index.mdb-lock
```

- `packs/` contains append-only pack files, each ~1 GB.
- `index.mdb` is an LMDB database with three named databases (see below).
- The LMDB lock file is managed by LMDB; no application-level locking.

## Content-Defined Chunking

Files are split using the FastCDC algorithm applied per-file (not per-NAR).
Chunking operates on the raw file content, not the NAR serialization. This
means that two store objects containing the same file produce identical chunks
for that file regardless of its position in the directory tree.

Parameters:

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

## Pack File Storage

Chunks are stored in append-only pack files, similar in concept to git
packfiles. Each pack file holds raw chunk data sequentially. Once a pack reaches
its target size (~1 GB), it is sealed and a new pack is opened.

### Pack File Format

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
are no per-chunk headers in the pack file itself -- the index provides all
addressing.

### Compression

Chunks above 4 KB are compressed with zstd (level 3) before writing to the pack
file. Chunks at or below 4 KB are stored uncompressed -- the compression
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
    // Only use compression if it actually shrinks the data.
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

## LMDB Index

The chunk store maintains a single LMDB environment (`chunks/index.mdb`) with
three named databases:

### `manifests_db`

Maps store hashes to serialized manifests.

- **Key:** `store_hash` (32 bytes, SHA-256)
- **Value:** protobuf-encoded `Manifest` (as defined in protocol.md)

```rust
fn get_manifest(env: &lmdb::Environment, store_hash: &[u8; 32]) -> Option<Manifest> {
    let txn = env.begin_ro_txn().ok()?;
    let db = env.open_db(Some("manifests")).ok()?;
    let bytes = txn.get(db, store_hash).ok()?;
    Manifest::decode(bytes).ok()
}
```

### `locations_db`

Maps chunk hashes to their physical location in a pack file.

- **Key:** `chunk_hash` (16 bytes, xxh3-128)
- **Value:** `PackLocation` (fixed-size, 24 bytes)

```rust
#[repr(C, packed)]
struct PackLocation {
    pack_id: u32,          // which pack file (e.g. 1 for pack-0001.pack)
    offset: u64,           // byte offset within the pack file
    length: u32,           // uncompressed chunk size
    compressed_length: u32, // compressed size on disk (0 = not compressed)
}
```

When `compressed_length` is 0, the chunk is stored uncompressed and `length`
bytes are read from the pack file. When `compressed_length` > 0, that many bytes
are read and then decompressed to yield the original `length` bytes.

### `chunk_refs_db`

Reverse index mapping chunk hashes to the set of store hashes that reference
them. Used exclusively by GC to determine when a chunk is unreferenced.

- **Key:** `chunk_hash` (16 bytes, xxh3-128)
- **Value:** concatenated `store_hash` values (N * 32 bytes)

The value is a flat byte array of 32-byte store hashes. Adding a reference
appends 32 bytes; removing one filters it out and rewrites. This is a simple
encoding -- the number of store objects referencing any single chunk is typically
small (single digits for most chunks, low hundreds for shared library chunks).

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
the daemon chunks each file and writes new chunks to the store:

```rust
fn write_chunks(
    env: &lmdb::Environment,
    active_pack: &mut ActivePack,
    store_hash: &[u8; 32],
    chunks: &[(Vec<u8>, [u8; 16])], // (data, hash) pairs
) -> io::Result<()> {
    let mut txn = env.begin_rw_txn()?;
    let loc_db = env.open_db(Some("locations"))?;
    let ref_db = env.open_db(Some("chunk_refs"))?;

    for (data, hash) in chunks {
        // Deduplicate: skip if chunk already exists.
        if txn.get(loc_db, hash).is_ok() {
            // Chunk exists -- just add the back-reference.
            append_ref(&mut txn, ref_db, hash, store_hash)?;
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
        let loc_bytes = unsafe {
            std::slice::from_raw_parts(&loc as *const _ as *const u8, std::mem::size_of::<PackLocation>())
        };
        txn.put(loc_db, hash, loc_bytes, lmdb::WriteFlags::NO_OVERWRITE)?;
        append_ref(&mut txn, ref_db, hash, store_hash)?;

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

Deduplication is implicit: if the chunk hash already exists in `locations_db`,
the write is skipped and only the reverse reference is added. This is the
mechanism that produces cross-version dedup -- when a new version of a package
shares most of its files with the previous version, the shared chunks are
already present and only the changed chunks are written.

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
    let mut nar_hasher = Sha256::new(); // for NAR hash computation

    for entry in walkdir::WalkDir::new(root).sort_by_file_name() {
        let entry = entry?;
        let rel_path = entry.path().strip_prefix(root).unwrap();
        let metadata = entry.metadata()?;

        if metadata.is_dir() {
            // Feed directory entry to NAR hasher.
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
            // Collect raw chunk data for writing.
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

## Chunk Garbage Collection

Chunk GC is triggered when a store path is removed from all views (no remaining
GC roots reference it). The sequence:

1. **Remove manifest.** Delete the manifest entry from `manifests_db`.
2. **Update reverse references.** For each chunk hash in the manifest's entries,
   remove this `store_hash` from the chunk's entry in `chunk_refs_db`.
3. **Mark dead chunks.** If a chunk's `chunk_refs_db` entry becomes empty (zero
   remaining references), delete both its `chunk_refs_db` entry and its
   `locations_db` entry.

```rust
fn gc_store_path(
    env: &lmdb::Environment,
    store_hash: &[u8; 32],
) -> lmdb::Result<GcStats> {
    let mut txn = env.begin_rw_txn()?;
    let manifest_db = env.open_db(Some("manifests"))?;
    let loc_db = env.open_db(Some("locations"))?;
    let ref_db = env.open_db(Some("chunk_refs"))?;

    // Load manifest to find all referenced chunks.
    let manifest_bytes = txn.get(manifest_db, store_hash)?;
    let manifest = Manifest::decode(manifest_bytes)?;

    let mut chunks_freed = 0u64;
    let mut bytes_freed = 0u64;

    for entry in &manifest.entries {
        if let EntryKind::File(file_entry) = &entry.kind {
            for chunk_ref in &file_entry.chunks {
                // Remove this store_hash from the chunk's reference set.
                let remaining = remove_ref(&mut txn, ref_db, &chunk_ref.hash, store_hash)?;
                if remaining == 0 {
                    // Chunk is unreferenced -- remove from locations index.
                    // The actual bytes in the pack file become dead space.
                    if let Ok(loc_bytes) = txn.get(loc_db, &chunk_ref.hash) {
                        let loc: PackLocation = decode_location(loc_bytes);
                        let on_disk = if loc.compressed_length > 0 {
                            loc.compressed_length as u64
                        } else {
                            loc.length as u64
                        };
                        bytes_freed += on_disk;
                    }
                    txn.del(loc_db, &chunk_ref.hash, None)?;
                    txn.del(ref_db, &chunk_ref.hash, None)?;
                    chunks_freed += 1;
                }
            }
        }
    }

    txn.del(manifest_db, store_hash, None)?;
    txn.commit()?;

    Ok(GcStats { chunks_freed, bytes_freed })
}
```

Deleting from `locations_db` does not reclaim the bytes in the pack file. The
chunk data remains as dead space until pack compaction runs.

## Pack Compaction

Sealed packs accumulate dead space as chunks are GC'd. When a sealed pack's
dead space exceeds 30% of its total size, it is eligible for compaction.

Compaction rewrites a pack file, copying only live chunks:

1. **Scan the LMDB index** for all `PackLocation` entries pointing to the target
   pack. These are the live chunks.
2. **Create a new pack file** with the next available pack ID.
3. **Copy live chunks** sequentially into the new pack, recording the new
   offsets.
4. **Update `locations_db`** in a single LMDB transaction: for each copied
   chunk, update `pack_id` and `offset` to point to the new pack.
5. **Delete the old pack file.**
6. **Seal the new pack** with a trailing checksum.

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
        let loc_bytes = encode_location(new_loc);
        txn.put(loc_db, hash, &loc_bytes, lmdb::WriteFlags::empty())?;
    }
    txn.commit()?;

    // Remove old pack file.
    std::fs::remove_file(&old_path)?;

    Ok(CompactStats {
        chunks_copied: updates.len() as u64,
        old_size: std::fs::metadata(&old_path).map(|m| m.len()).unwrap_or(0),
        new_size: new_pack.size(),
    })
}
```

Compaction is scheduled during idle time (no active builds, no in-flight chunk
transfers). It runs at most one pack at a time to limit I/O impact.

### Dead Space Tracking

Dead space per pack is tracked as a counter in memory, incremented when a chunk
is GC'd. On daemon startup, the counter is reconstructed by scanning
`locations_db` and comparing against the pack file sizes:

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

## Sizing Estimates

Typical numbers for a moderately-sized Nix store (10,000 store paths, ~100 GB
total content):

| Metric | Estimate | Notes |
|---|---|---|
| Chunks per store path | ~100 (avg) | 25 MB avg store path / 256 KB avg chunk |
| Total chunks (before dedup) | ~1,000,000 | 10,000 paths * 100 chunks |
| Total chunks (after dedup) | ~600,000 | ~40% dedup ratio across package versions |
| LMDB `locations_db` size | ~14 MB | 600K entries * 24 bytes value |
| LMDB `chunk_refs_db` size | ~21 MB | 600K entries * ~36 bytes avg value |
| LMDB `manifests_db` size | ~50 MB | 10K manifests, ~5 KB avg |
| Total LMDB index size | ~85 MB | All three databases |
| Pack files | ~60 GB | After compression (~60% of raw) |
| Pack file count | ~60 | At 1 GB per sealed pack |

For a large store (100,000 paths, ~1 TB total content), multiply accordingly.
The LMDB index stays under 1 GB. Pack file count reaches ~600.

LMDB's memory-mapped I/O means the index performs well even when it exceeds
available RAM -- the OS page cache handles hot-path caching transparently.
