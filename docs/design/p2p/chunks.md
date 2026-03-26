# Content-Defined Chunking and Transfer Protocol

This documents the content-defined chunking, pack file storage, and
transfer protocol for the AOS distributed build system. The chunk store
is the source of truth for all view content.

## Overview

The host's `/nix/store` is immutable (baked into the base image with
only boot essentials). All mutable package content lives in the **chunk
store** -- a set of append-only pack files containing content-defined
chunks. FUSE views reconstruct files on-the-fly from chunks.

Individual files are chunked using FastCDC (content-defined chunking
with a rolling hash). Each chunk is identified by its xxh3-128 hash
(xxHash, non-cryptographic, 10+ GB/s). Integrity is verified at the
store-path level using SHA-256 (Nix's native hash) after
reconstruction. This enables:

- **Cross-version dedup**: rebuilding LLVM with a one-line patch reuses ~95% of file chunks
- **Cross-package dedup**: packages sharing libraries/data reuse chunks
- **Parallel transfer**: fetch missing chunks from multiple peers simultaneously
- **Minimal transfer**: only chunks you don't already have need to be fetched
- **True dedup at rest**: each unique chunk stored once in pack files, referenced by any number of views

The manifest is a file tree (directory structure plus per-file chunk
lists), not a flat chunk list over a serialized archive.

## Architecture

```
Chunk Store (source of truth for all view content)
  +-- packs/              append-only pack files (concatenated chunks)
  +-- index.mdb           LMDB index (manifests, chunk locations, reverse refs)

FUSE ViewFs (reconstructs files from chunks)
  +-- on file read -> look up manifest -> read chunks from packs -> return data
  +-- on first access -> trigger chunk indexing (lazy)
  +-- LRU tracking via ViewDb

Transfer Protocol (directed point-to-point, DHT-discovered providers)
  +-- get_providers(store_hash) -> discover providers via Kademlia DHT
  +-- WANT_MANIFEST -> file tree manifest (directed, universe-scoped)
  +-- WANT_CHUNK -> chunk data from pack files (directed, universe-agnostic)

Host /nix/store (immutable, boot essentials only)
  +-- kernel, systemd, aos-daemon, bash (frozen base image)
```

The chunk store holds all package data in pack files. The LMDB index
maps manifests to file trees and chunk hashes to pack locations. FUSE
views reconstruct files by reading chunks from packs via pread. The
host `/nix/store` is frozen and not used for view content.

## Content-Defined Chunking (FastCDC)

### Why content-defined, not fixed-size

Fixed-size chunks (e.g., 256KB blocks) shift ALL boundaries when a byte
is inserted near the beginning. Content-defined chunking uses a rolling
hash to find boundaries based on content patterns. An insertion only
affects 1-2 chunks around the change -- everything else stays identical.

```
Fixed-size (BAD for dedup):
  Original:  [block1][block2][block3][block4]
  +1 byte:   [block1'][block2'][block3'][block4']  <- ALL blocks change

Content-defined (GOOD for dedup):
  Original:  [chunk_a ][chunk_b  ][chunk_c][chunk_d   ]
  +1 byte:   [chunk_a ][chunk_b' ][chunk_c][chunk_d   ]  <- only 1 chunk changes
              ^^^^^^^^              ^^^^^^^^  ^^^^^^^^^^
              identical             identical  identical
```

### FastCDC parameters

```rust
use fastcdc::v2020::FastCDC;

const MIN_CHUNK: u32 = 64 * 1024;     // 64 KB minimum
const AVG_CHUNK: u32 = 256 * 1024;    // 256 KB average
const MAX_CHUNK: u32 = 1024 * 1024;   // 1 MB maximum

fn chunk_file(file_data: &[u8]) -> Vec<ChunkInfo> {
    FastCDC::new(file_data, MIN_CHUNK, AVG_CHUNK, MAX_CHUNK)
        .map(|entry| ChunkInfo {
            hash: xxhash_rust::xxh3::xxh3_128(&file_data[entry.offset..entry.offset + entry.length]),
            offset: entry.offset,
            length: entry.length,
        })
        .collect()
}
```

The algorithm is applied to individual files, not NAR byte streams.
Small files (below min_chunk_size) become a single chunk. Symlinks and
directories carry no chunk data -- they are metadata entries in the
manifest.

Use the `fastcdc` crate (v2020 implementation, 64-bit hashes). It
supports `AsyncStreamCDC` with tokio for streaming chunking without
buffering the entire file in memory.

### Chunk size tradeoffs

| Avg chunk | Dedup ratio | Chunks per 2GB binary | Manifest size | Round-trips |
|-----------|-------------|----------------------|--------------:|-------------|
| 64 KB     | ~98%        | ~32K                  | ~1 MB         | Many        |
| 256 KB    | ~95%        | ~8K                   | ~256 KB       | Moderate    |
| 1 MB      | ~85%        | ~2K                   | ~64 KB        | Few         |

256 KB average is the sweet spot (same as IPFS default).

## Manifest Format

The manifest describes a store path as a file tree. Each entry is a
directory, a file with its chunk list, or a symlink.

```json
{
  "store_hash": "abc123",
  "store_path": "/nix/store/abc123-llvm-18.0",
  "entries": [
    {"type": "dir", "name": "bin", "mode": 493},
    {"type": "file", "name": "bin/clang", "size": 83886080, "executable": true,
     "chunks": [{"hash": "aaa...", "size": 262144}, {"hash": "bbb...", "size": 319488}]},
    {"type": "symlink", "name": "bin/clang++", "target": "clang"},
    {"type": "file", "name": "lib/libLLVM-18.so", "size": 209715200, "executable": false,
     "chunks": [{"hash": "ddd...", "size": 262144}]},
    {"type": "file", "name": "include/llvm/IR.h", "size": 12288, "executable": false,
     "chunks": [{"hash": "ggg...", "size": 12288}]}
  ]
}
```

Directories carry their permission mode. Files carry their size, an
executable flag, and an ordered list of chunk references. Symlinks carry
their target path. The receiver can reconstruct the full store path from
this information plus the chunk data.

## Chunk Store

### On-disk layout

```
/var/lib/aos/chunks/
  packs/
    pack-0001.pack          # append-only pack files (concatenated chunks)
    pack-0002.pack
    ...
  index.mdb                 # LMDB (heed3) -- chunk index only
    manifests_db:   store_hash -> ManifestEntry (file tree)
    locations_db:   chunk_hash -> PackLocation  # {pack_id, offset, length}
    chunk_refs_db:  chunk_hash -> Vec<(store_hash, file_path)>  # reverse index
```

The chunk store's `index.mdb` is a separate LMDB environment from the view
state databases. It contains only chunk-related metadata (manifests, pack
locations, reverse refs) -- not view roots, access tracking, or sync state.
This isolation means bursty chunk ingestion (e.g. after a build completes)
doesn't contend with the hot FUSE access tracking path in per-view
`access.mdb` or the sync writes in `state/sync.mdb`.

There is no NAR cache. LMDB stores index metadata -- chunk content is
read from pack files via pread. Pack files are the single source of
truth for all view content.

### ChunkStore implementation

```rust
/// The ChunkStore manages chunks/index.mdb -- a dedicated LMDB environment
/// for chunk metadata only. View roots live in state/roots.mdb; access
/// tracking lives in per-view access.mdb. This separation ensures chunk
/// ingestion doesn't contend with FUSE access tracking or sync writes.
struct ChunkStore {
    env: heed3::Env,           // /var/lib/aos/chunks/index.mdb
    // chunk_hash -> pack file location
    locations_db: Database<Str, SerdeBincode<PackLocation>>,
    // store_hash -> file tree manifest
    manifests_db: Database<Str, SerdeBincode<ManifestEntry>>,
    // chunk_hash -> which store paths reference this chunk (reverse index)
    chunk_refs_db: Database<Str, SerdeBincode<Vec<ChunkLocation>>>,
    // Pack file management
    packs_dir: PathBuf,
    current_pack: Mutex<PackWriter>,
}

struct ManifestEntry {
    store_path: String,
    entries: Vec<FsEntry>,
}

enum FsEntry {
    Dir { name: String, mode: u32 },
    File { name: String, size: u64, executable: bool, chunks: Vec<ChunkRef> },
    Symlink { name: String, target: String },
}

struct ChunkRef {
    hash: String,    // xxh3-128 hash of chunk data
    size: u32,       // chunk size in bytes
}

struct PackLocation {
    pack_id: u32,              // which pack file
    offset: u64,               // byte offset within pack
    length: u32,               // uncompressed chunk size
    compressed_length: u32,    // 0 = not compressed
}

struct ChunkLocation {
    store_hash: String,
    file_path: String,
}
```

### Serving chunks -- pread from pack files

Chunks are served by looking up the pack location in LMDB and reading
the byte range from the pack file via pread.

```rust
fn serve_chunk(&self, chunk_hash: &str) -> Result<Vec<u8>> {
    let loc = self.locations_db.get(chunk_hash)?
        .ok_or_else(|| anyhow!("chunk not found: {chunk_hash}"))?;

    let pack_path = self.pack_path(loc.pack_id);
    let file = File::open(&pack_path)?;

    if loc.compressed_length > 0 {
        let mut compressed = vec![0u8; loc.compressed_length as usize];
        file.read_exact_at(&mut compressed, loc.offset)?;
        Ok(zstd::decode_all(&compressed[..])?)
    } else {
        let mut buf = vec![0u8; loc.length as usize];
        file.read_exact_at(&mut buf, loc.offset)?;
        Ok(buf)
    }
}
```

Pack files are the chunk storage. Each unique chunk is stored once and
can be served to any peer.

## Chunk Indexing Strategy

### Lazy indexing driven by FUSE

There is no background indexer. Chunking happens on first access through
the FUSE view layer. When a file is first written to the chunk store
(after a build or a transfer), the daemon chunks the file, writes the
chunks to pack files, and updates the LMDB index.

```rust
// In ViewStore or FUSE handler
fn on_file_ingest(&self, store_hash: &str, file_path: &str, data: &[u8]) {
    // Check if this file's chunks are already in the chunk store
    if self.chunk_store.manifests_db.contains(store_hash)? {
        return; // already indexed
    }

    // Chunk the file and write chunks to pack files
    let chunks = FastCDC::new(data, MIN_CHUNK, AVG_CHUNK, MAX_CHUNK);
    for entry in chunks {
        let chunk_data = &data[entry.offset..entry.offset + entry.length];
        let hash = xxhash_rust::xxh3::xxh3_128(chunk_data).to_hex();
        // write_chunk deduplicates: skips if hash already in locations_db
        self.chunk_store.write_chunk(&hash, chunk_data)?;
        self.chunk_store.add_chunk_ref(&hash, store_hash, file_path)?;
    }
}
```

For manifest generation on WANT_MANIFEST:

1. Look up the manifest in LMDB (it was built when the store path was ingested)
2. If not yet indexed, walk the reconstructed store path and chunk each file
3. Build the manifest from the tree structure plus chunk info
4. Cache the manifest in LMDB

### Indexing on build completion

When a build completes, the daemon eagerly chunks the output files and
writes them to pack files while they are fresh in the page cache. This
ensures every build output is immediately available for FUSE views and
P2P transfer. The daemon also calls `kademlia.start_providing(store_hash)`
with a per-path GC-aware TTL (see Transfer Protocol section) to advertise
the new store path to the DHT.

### Indexing performance

FastCDC processes data at ~1 GB/s on modern hardware. A 2GB binary takes
~2 seconds to chunk. xxh3 hashing runs at 10+ GB/s. The bottleneck is
CPU time for hashing plus sequential writes to the current pack file
and a small LMDB write for the index entries.

For a store with 100K paths averaging 10MB each (1TB total), full
indexing takes ~17 minutes of CPU time. With lazy indexing, only
accessed files pay this cost.

## Transfer Protocol

### Provider Discovery via DHT

Before any transfer, the requesting daemon discovers providers through
Kademlia DHT provider records -- not broadcast or GossipSub:

```
kademlia.get_providers(store_hash) → [PeerA, PeerC, PeerF]
```

This returns a bounded set of PeerIds (up to Kademlia's K, typically 20).
All subsequent WANT_MANIFEST and WANT_CHUNK requests are **directed
point-to-point** to these discovered providers.

#### Provider advertisement with GC-aware TTL

When a daemon builds or fetches a store path, it advertises itself as a
provider with a TTL that reflects the path's estimated survival time in
the local store. The TTL varies per path based on GC policy, LRU rank,
and pin/CRDT state -- cold paths that are likely to be evicted soon get
short TTLs, while hot or pinned paths get long TTLs.

**TTL-based GC views** (paths expire after N days of no access):

The `access.mdb` tracks last access time per path. The provider TTL is
simply the remaining time before the path ages out:

```
provider_ttl = max_age - time_since_last_access

Path last accessed 1 hour ago, max_age = 7d  → provider TTL ≈ 7 days
Path last accessed 6.5 days ago, max_age = 7d → provider TTL ≈ 12 hours
```

**Budget-based GC views** (evict coldest paths when disk pressure hits):

The TTL depends on the path's LRU rank relative to the eviction frontier.
Paths near the bottom of the LRU (coldest, evicted first) get short TTLs.
Paths near the top (hottest, evicted last) get long TTLs:

```
Inputs:
  - Current disk usage vs budget (e.g., 75% of 50GB)
  - Average disk growth rate (e.g., 2GB/day from builds)
  - Path's LRU rank (e.g., 3000th of 10000 paths)

time_to_pressure = headroom_bytes / growth_rate
rank_ratio       = path_rank / total_paths       (0 = coldest, 1 = hottest)
provider_ttl     = time_to_pressure * rank_ratio

Coldest paths (near bottom of LRU)  → short TTL (minutes)
Warmest paths (near top of LRU)     → long TTL (hours/days)
```

**Pinned/profile/CRDT paths:**

```
In active profile generation → TTL = profile retention window
Explicitly pinned            → TTL = pin duration or max TTL
In sync CRDT as alive        → TTL = max TTL (won't be locally GC'd while CRDT says it should exist)
```

```rust
fn provider_ttl_for(&self, store_hash: &str, view: &View) -> Duration {
    // Pinned or in CRDT desired state → long TTL
    if view.is_pinned(store_hash) || view.in_sync_crdt(store_hash) {
        return Duration::from_secs(86400); // 24h, re-advertised on access
    }

    match &view.gc_policy {
        GcPolicy::Ttl { max_age } => {
            let last_access = view.last_access(store_hash);
            let remaining = max_age.saturating_sub(last_access.elapsed());
            remaining.max(Duration::from_secs(60)) // floor of 1 min
        }
        GcPolicy::Budget { max_size } => {
            let rank = view.lru_rank(store_hash);     // 0 = coldest
            let total = view.path_count();
            let usage_ratio = view.disk_usage() as f64 / *max_size as f64;
            let growth_rate = view.avg_growth_rate();  // bytes/sec

            // How long until disk pressure reaches this path's rank?
            let headroom_bytes = max_size - view.disk_usage();
            let time_to_pressure = headroom_bytes as f64 / growth_rate;
            let rank_ratio = rank as f64 / total as f64;

            // Coldest paths (rank_ratio near 0) get short TTL
            // Hottest paths (rank_ratio near 1) get long TTL
            let ttl_secs = (time_to_pressure * rank_ratio) as u64;
            Duration::from_secs(ttl_secs.clamp(60, 86400))
        }
        GcPolicy::Manual => Duration::from_secs(86400), // manual GC, assume safe
    }
}

fn advertise_store_path(&self, store_hash: &str, view: &View) -> Result<()> {
    let ttl = self.provider_ttl_for(store_hash, view);
    self.kademlia.start_providing(
        store_hash_to_kad_key(store_hash),
        ttl,
    )?;
    Ok(())
}

// After GC completes, re-advertise surviving paths with per-path TTLs
fn post_gc_readvertise(&self, view: &View) -> Result<()> {
    for store_hash in self.surviving_store_hashes() {
        let ttl = self.provider_ttl_for(&store_hash, view);
        self.kademlia.start_providing(
            store_hash_to_kad_key(&store_hash),
            ttl,
        )?;
    }
    Ok(())
}
```

**Self-correcting properties:**

- Every access bumps LRU position, which extends provider TTL automatically.
- Serving content via WANT_CHUNK counts as an access, so serving keeps
  provider records alive.
- Hot paths get long TTLs, so they require fewer DHT re-advertisements
  and produce less overhead.
- Cold paths get short TTLs, so their provider records expire before
  the path is GC'd -- no stale providers.

### Two-level WANT protocol

The transfer protocol has two levels. Both are **directed** -- sent
point-to-point to DHT-discovered providers, never broadcast.

**Level 1: Manifest request (directed, universe-scoped, auth checked)**

```
WANT_MANIFEST({universe}, {store_hash}) → directed to one DHT-discovered provider
  Auth: provider checks requester's UCAN for {universe}
  Response: ManifestEntry { store_path, entries: [FsEntry...] }
  Or: DONT_HAVE (path not in this universe)
```

The requester picks one provider from `get_providers` results and sends a
point-to-point WANT_MANIFEST. This is the auth boundary. You cannot get a
manifest for a universe you don't have access to. The manifest reveals the
file tree and chunk hashes, but individual chunks are meaningless without
the manifest.

**Level 2: Chunk request (directed, universe-AGNOSTIC, no auth check)**

```
WANT_CHUNK({chunk_hash}) → directed to DHT-discovered providers (round-robin)
  Auth: NONE (mesh membership is sufficient)
  Response: raw chunk bytes (pread from pack file)
  Or: DONT_HAVE
```

Chunks are just bytes. They have no universe association. Any mesh peer can
serve any chunk. Chunk requests are distributed round-robin across the
providers returned by `get_providers`, enabling parallel fetching from
multiple peers. This also enables cross-universe dedup automatically -- a
daemon that has the chunk from any universe can serve it.

### Why chunks are universe-agnostic

A single 256KB chunk is meaningless without the manifest. You cannot:

- Determine which package it belongs to
- Reconstruct a file from a single chunk
- Learn anything about another tenant's packages

The manifest is the gate. Once you have it (proving universe access), the
chunks are just content-addressed bytes that can come from anywhere. This
is like having an encrypted filesystem where the directory structure is
protected but the raw disk blocks are freely readable -- the blocks
reveal nothing without the metadata.

A tenant cannot even guess chunk hashes -- they would need the manifest
to know which chunks to request. Brute-forcing xxh3-128 hashes is
infeasible.

### Transfer flow example

```
Daemon B needs LLVM 18.0 in universe "staging":

1. Discovery (DHT provider records, no broadcast):
   kademlia.get_providers(abc123) → [PeerA, PeerC, PeerF]

2. Manifest (directed, one peer):
   WANT_MANIFEST(staging, abc123) → PeerA
   -> PeerA checks: is abc123 in staging? Is B's UCAN valid for staging?
   -> YES: sends file tree manifest (directory structure + per-file chunk lists)

3. B scans manifest, checks local chunk index for each chunk hash:
   -> Cross-version dedup: chunks from previous LLVM version match
   -> Cross-package dedup: chunks from shared libraries match
   -> 7800 chunks already present locally
   -> 391 chunks missing

4. Chunks (directed, all providers in parallel, round-robin):
   WANT_CHUNK(chunk_847_hash) → PeerA   responds with bytes (pread from pack)
   WANT_CHUNK(chunk_848_hash) → PeerC   responds with bytes
   WANT_CHUNK(chunk_849_hash) → PeerF   responds with bytes
   WANT_CHUNK(chunk_850_hash) → PeerA   responds with bytes
   ... (391 requests, round-robin across discovered providers)

5. B reconstructs the store path:
   -> mkdir tree from dir entries
   -> Write files from ordered chunk data
   -> Create symlinks from symlink entries
   -> Set permissions (executable bits, directory modes)

6. Write chunks to local pack files, update LMDB index
7. Advertise as provider: kademlia.start_providing(abc123, ttl=provider_ttl_for(abc123))
8. Root in local view (chunks are now available for FUSE views and serving to others)

Transfer: ~100MB instead of 2.1GB (95% dedup from previous version)
```

### Reconstruction on the receiving side

The receiver builds the store path from the manifest plus fetched
chunks:

```rust
fn reconstruct_store_path(manifest: &ManifestEntry, chunk_store: &ChunkStore) -> Result<PathBuf> {
    let store_path = Path::new("/nix/store").join(&manifest.store_path);

    for entry in &manifest.entries {
        match entry {
            FsEntry::Dir { name, mode } => {
                let dir = store_path.join(name);
                std::fs::create_dir_all(&dir)?;
                std::fs::set_permissions(&dir, Permissions::from_mode(*mode))?;
            }
            FsEntry::File { name, chunks, executable, .. } => {
                let file_path = store_path.join(name);
                let mut file = File::create(&file_path)?;
                for chunk_ref in chunks {
                    let data = chunk_store.read_chunk(&chunk_ref.hash)?;
                    file.write_all(&data)?;
                }
                if *executable {
                    set_executable(&file_path)?;
                }
            }
            FsEntry::Symlink { name, target } => {
                let link_path = store_path.join(name);
                std::os::unix::fs::symlink(target, &link_path)?;
            }
        }
    }

    Ok(store_path)
}
```

No nix-store --import is needed. Files are written directly -- the
daemon is the store manager.

### Inbound chunk handling

When receiving chunks from a peer, each chunk is written to the current
pack file and indexed in LMDB. After all chunks for a store path arrive,
the manifest is stored and the path is available for FUSE views. Chunks
are deduplicated on write -- if a chunk hash already exists in the
locations_db, it is not written again.

### Parallel fetching from multiple peers

Unlike whole-file transfer, chunking enables fetching from multiple peers
simultaneously:

```rust
async fn fetch_missing_chunks(
    manifest: &ManifestEntry,
    local_chunks: &ChunkStore,
    peers: &[PeerId],
) -> Result<()> {
    let missing: Vec<&ChunkRef> = manifest.entries.iter()
        .filter_map(|e| match e {
            FsEntry::File { chunks, .. } => Some(chunks.iter()),
            _ => None,
        })
        .flatten()
        .filter(|c| !local_chunks.has_chunk(&c.hash))
        .collect();

    // Fetch in parallel, distributing across peers
    let semaphore = Arc::new(Semaphore::new(32)); // max 32 concurrent fetches
    let tasks: Vec<_> = missing.iter().enumerate().map(|(i, chunk)| {
        let peer = peers[i % peers.len()]; // round-robin across peers
        let sem = semaphore.clone();
        async move {
            let _permit = sem.acquire().await;
            let data = fetch_chunk_from_peer(peer, &chunk.hash).await?;
            verify_chunk(&data, &chunk.hash)?;
            local_chunks.store_chunk(&chunk.hash, &data)?;
            Ok(())
        }
    }).collect();

    futures::future::try_join_all(tasks).await?;
    Ok(())
}
```

## NAR Hash Computation (Nix Compatibility)

### Two-Level Hashing Strategy

Chunk hashing and store path integrity use different algorithms optimized
for their respective roles:

| Level | Algorithm | Speed | Purpose |
|-------|-----------|-------|---------|
| Chunk identity | xxh3-128 | 10+ GB/s | Dedup matching, chunk lookup |
| Store path integrity | SHA-256 | ~500 MB/s | Nix compatibility, tamper detection |

Chunk identity uses xxh3 (non-cryptographic) because it's the hot path --
every file read through FUSE triggers chunk boundary detection and hash
computation. Collisions are astronomically unlikely for real data
(128-bit output). Store-path integrity uses SHA-256 (Nix's native hash)
and is verified once after reconstruction -- not per-chunk.

If a malicious peer serves a chunk with the correct xxh3 but wrong
content (crafted collision), the reconstructed store path's SHA-256 will
fail. On mismatch: re-fetch chunks and verify individually. This slow
path only triggers under active attack.

For narinfo signing and content-addressed path verification, the NAR
hash is computed on-the-fly from the file tree without generating a NAR
file:

```rust
fn compute_nar_hash(store_path: &Path) -> sha2::Sha256Hash {
    let mut hasher = sha2::Sha256::new();
    nar_walk(store_path, |event| {
        // Write NAR format bytes to hasher without materializing
        hasher.update(&nar_bytes_for(event));
    });
    hasher.finalize()
}
```

The NAR format is a deterministic serialization of a directory tree. By
walking the tree and feeding NAR-format bytes into the hasher, we get a
NAR hash without ever creating a NAR file. This maintains compatibility
with the Nix store's content-addressing scheme.

## Chunk GC

When a store path is removed from all views, GC removes the manifest
and updates the reverse index. Chunks whose reference count drops to
zero are removed from the LMDB index, leaving dead space in the pack
files. Pack compaction (see below) reclaims this space during idle time.

After GC completes, the daemon re-advertises all surviving store paths
as DHT provider records with per-path TTLs computed from `provider_ttl_for`.
Paths that were garbage-collected are not re-advertised, so their
provider records naturally expire from the DHT without requiring explicit
removal. See the Provider Discovery section above for the TTL estimation
model.

```rust
fn gc_store_path_chunks(&self, store_hash: &str) -> Result<()> {
    let manifest = self.manifests_db.get(store_hash)?;

    let mut wtxn = self.env.write_txn()?;

    for entry in &manifest.entries {
        if let FsEntry::File { chunks, .. } = entry {
            for chunk_ref in chunks {
                // Remove this store path from the chunk's reverse index
                let mut refs = self.chunk_refs_db.get(&wtxn, &chunk_ref.hash)?
                    .unwrap_or_default();
                refs.retain(|loc| loc.store_hash != store_hash);

                if refs.is_empty() {
                    self.chunk_refs_db.delete(&mut wtxn, &chunk_ref.hash)?;
                    self.locations_db.delete(&mut wtxn, &chunk_ref.hash)?;
                    // Chunk data remains as dead space in its pack file
                    // until pack compaction reclaims it
                } else {
                    self.chunk_refs_db.put(&mut wtxn, &chunk_ref.hash, &refs)?;
                }
            }
        }
    }

    self.manifests_db.delete(&mut wtxn, store_hash)?;
    wtxn.commit()?;
    Ok(())
}
```

Chunks are reference-counted via the reverse index. When the last store
path referencing a chunk is removed, both the locations_db and
chunk_refs_db entries are deleted. The chunk data remains as dead space
in the pack file until pack compaction rewrites the pack to reclaim it.

## Dedup Examples

### Cross-version dedup

```
LLVM 18.0 -> LLVM 18.0+patch:
  bin/clang (80MB): most chunks of the same binary are identical
  -> 8189 file chunks identical, 2 chunks differ
  -> Transfer: ~512KB instead of 2.1GB (99.97% dedup)
```

### Cross-package dedup

```
lib/libLLVM-18.so shared between llvm and clang packages:
  -> Exact same file = exact same chunks
  -> If you have llvm, fetching clang needs zero new chunks for libLLVM

include/ headers unchanged across patch versions:
  -> Same files = same chunks
  -> Header-only changes transfer just the modified files
```

### Cross-bootstrap dedup

```
Rebuild entire package set with new GCC:
  -> Source code, scripts, docs, data files: file chunks unchanged
  -> Object code, libraries: file chunks differ
  -> Typically 40-60% chunk reuse across a full GCC version bump
```

## Universe Scoping with Chunks

### Manifests are universe-scoped (auth boundary)

WANT_MANIFEST is a directed request to a DHT-discovered provider, not a
broadcast:

```
kademlia.get_providers(abc123) → [PeerA, PeerC, PeerF]

WANT_MANIFEST(staging, abc123) → PeerA (directed, point-to-point)
  -> PeerA checks: is (staging, abc123) in state/roots.mdb?
  -> PeerA checks: does requester UCAN include staging?
  -> If both yes: serve manifest
  -> If either no: DONT_HAVE
```

### Chunks are universe-agnostic (content layer)

WANT_CHUNK requests are directed to providers from the same
`get_providers` call, distributed round-robin for parallelism:

```
WANT_CHUNK(chunk_hash) → PeerA (directed, point-to-point)
  -> PeerA checks: is this chunk_hash in the locations_db?
  -> Yes: pread from the pack file and serve it (regardless of which universe)
  -> No: DONT_HAVE (requester tries next provider)
```

### Cross-view local sharing

When a daemon receives WANT_MANIFEST(staging, abc123) and has abc123 in its
production view but not staging:

```rust
fn handle_want_manifest(&self, universe: &str, store_hash: &str) -> ManifestResponse {
    // Direct hit: path is in the requested view (mapped from universe)
    let view = self.universe_to_view(universe);
    // Roots are in the global state/roots.mdb, keyed by (view, store_hash)
    if self.roots_db.contains(&(view, store_hash)) {
        let manifest = self.chunk_store.get_manifest(store_hash);
        return ManifestResponse::Have(manifest);
    }

    // Cross-view local sharing: path is in another local view
    if self.store_has_path(store_hash) {
        // Root it in the requested view too (local operation)
        self.roots_db.insert(&(view, store_hash));
        let manifest = self.chunk_store.get_manifest(store_hash);
        return ManifestResponse::Have(manifest);
    }

    ManifestResponse::DontHave
}
```

### Tenancy isolation is preserved

Tenant A (universe "acme") cannot:

- Request manifests from universe "globex" (UCAN check fails)
- Discover chunk hashes belonging to "globex" files (needs the manifest first)
- Learn which packages "globex" has (manifest is the discovery mechanism)

Tenant A CAN accidentally receive chunks that were originally produced
by "globex" -- but the chunks are meaningless without the manifest, and
the content is identical to what "acme" would produce from the same
source.

The timing side channel (an "instant build" reveals the output already
existed) is acknowledged and accepted.

## Configuration

```toml
[chunks]
avg_size = "256KB"
min_size = "64KB"
max_size = "1MB"
max_pack_size = "1GB"            # seal and rotate at this size
compaction_dead_ratio = 0.3      # compact packs with >30% dead space
min_compress_size = "4KB"        # don't compress chunks smaller than this
```

Chunk content lives in pack files under `/var/lib/aos/chunks/packs/`.

## Immutable Host Store

The host's `/nix/store` is immutable — baked into the golden/base image. It contains only boot essentials and the AOS daemon. All mutable package content lives in views, constructed from the chunk store via FUSE.

```
/nix/store/              -- immutable, baked into base image
  {hash}-linux-kernel/
  {hash}-systemd/
  {hash}-aos-daemon/
  {hash}-bash/
  ... (minimal boot set)

/var/lib/aos/
  chunks/                -- chunk store (source of truth for all view content)
    packs/               -- pack files (append-only, content-addressed chunks)
    index.mdb            -- LMDB index (manifests, chunk locations, reverse refs)
  views/
    staging/
      access.mdb         -- per-view LRU tracking
    production/
      access.mdb
  state/
    roots.mdb            -- view roots across all views
    sync.mdb             -- CRDT sync state
    config.mdb           -- view/universe config
    history.mdb          -- build history (append-only)
```

This means:
- The host store is NOT used for dedup with views (frozen, separate layer)
- ALL view content comes from the chunk store
- FUSE views reconstruct files on-the-fly from chunks in pack files
- True dedup: each unique chunk stored once, referenced by any number of views

## Pack File Storage

Instead of storing each chunk as an individual file (millions of small files, inode exhaustion), use pack files (like git packfiles or Restic packs).

### Why not individual chunk files

With 1M chunks at 256KB average:
- 1M files = 1M inodes, 1M directory entries
- Filesystem metadata overhead is significant
- ext4 struggles with >100K entries per directory (even with dir_index)
- Backup/sync of millions of small files is slow

### Pack file design

```
/var/lib/aos/chunks/
  packs/
    pack-0001.pack    -- concatenated chunks (~1GB per pack)
    pack-0002.pack
    pack-0003.pack
    ...
  index.mdb           -- LMDB: chunk locations + manifests
```

Chunks are appended to the current pack file. When a pack reaches MAX_PACK_SIZE (e.g., 1GB), it's sealed (becomes read-only) and a new pack starts. Sealed packs are immutable.

### Pack file format

```
[magic: "AOSP" (4 bytes)]
[version: u32 (4 bytes)]
[chunk 0 data: N bytes]
[chunk 1 data: N bytes]
...
[chunk M data: N bytes]
[checksum: xxh3-128 of entire file (16 bytes)]
```

No per-chunk headers in the pack file itself -- the index (LMDB) tracks where each chunk lives.

### LMDB Index

The LMDB index is part of the `ChunkStore` struct defined above. The
three databases are:

- `locations_db`: chunk_hash -> `PackLocation` (which pack file, byte offset, length)
- `manifests_db`: store_hash -> `ManifestEntry` (file tree for a store path)
- `chunk_refs_db`: chunk_hash -> `Vec<ChunkLocation>` (reverse index: which store paths reference this chunk)

### Reading a chunk (pread from pack)

This is the same `read_chunk` / `serve_chunk` implementation shown in
the ChunkStore section above -- look up the `PackLocation` in LMDB,
then pread from the pack file.

### Writing a chunk (append to current pack)

```rust
fn write_chunk(&self, hash: &str, data: &[u8]) -> Result<()> {
    // Dedup: already have it?
    if self.locations_db.contains(hash)? {
        return Ok(());
    }

    let mut current = self.current_pack.lock();

    // Rotate if current pack is full
    if current.size + data.len() as u64 > MAX_PACK_SIZE {
        current.seal()?;   // write checksum trailer, mark read-only
        *current = self.new_pack()?;
    }

    // Optional: compress
    let (write_data, compressed_len) = if data.len() > MIN_COMPRESS_SIZE {
        let compressed = zstd::encode_all(data, 3)?;
        if compressed.len() < data.len() {
            (compressed, compressed.len() as u32)
        } else {
            (data.to_vec(), 0)  // compression didn't help
        }
    } else {
        (data.to_vec(), 0)
    };

    let offset = current.size;
    current.file.write_all(&write_data)?;
    current.size += write_data.len() as u64;

    // Update index
    self.locations_db.put(hash, &PackLocation {
        pack_id: current.id,
        offset,
        length: data.len() as u32,
        compressed_length: compressed_len,
    })?;

    Ok(())
}
```

### FUSE reads from pack files

When a FUSE view needs to read a file, it looks up the file's chunks in the
manifest, then reads each chunk from its pack file. The behavior depends on
the view's FUSE operation mode (see [views.md](views.md) for full details):

- **eager**: All chunks are already local. `read_chunk` always hits the local
  pack file via pread. No network I/O.
- **async**: Chunks may or may not be local. If a chunk is missing, the read
  promotes it to `Urgent` priority in the background fetch queue and blocks
  until the chunk arrives. Once fetched, the chunk is written to the local pack
  file and indexed in LMDB, so subsequent reads are instant.
- **lazy**: No chunks are pre-fetched. The first `read()` for each file
  triggers an on-demand fetch of its chunks from DHT-discovered providers. Each
  fetched chunk is written to the current pack file and its location is recorded
  in `locations_db`, making it available for all subsequent reads (including
  reads from other views that reference the same chunk). This is the only mode
  where a FUSE `read()` can trigger a full network round-trip.

```rust
fn fuse_read_file(&self, manifest: &ManifestEntry, file_path: &str) -> Result<Vec<u8>> {
    let file_entry = manifest.find_file(file_path)?;

    let mut data = Vec::with_capacity(file_entry.size as usize);
    for chunk_ref in &file_entry.chunks {
        let chunk_data = self.read_chunk(&chunk_ref.hash)?;
        data.extend_from_slice(&chunk_data);
    }

    Ok(data)
}

/// In lazy/async mode, read_chunk may trigger a remote fetch.
/// The fetched chunk is always persisted to the local pack file
/// and indexed in LMDB before being returned.
fn read_chunk(&self, chunk_hash: &str) -> Result<Vec<u8>> {
    // Fast path: chunk is in local pack files
    if let Some(loc) = self.locations_db.get(chunk_hash)? {
        return self.read_chunk_from_pack(&loc);
    }

    // Slow path (lazy/async): fetch from peers, store locally
    let data = self.fetch_chunk_from_peers(chunk_hash)?;
    self.write_chunk(chunk_hash, &data)?;  // persist to pack + update LMDB index
    Ok(data)
}
```

In all three modes, manifests are always local (fetched eagerly on view sync
or path addition). This means `readdir`, `stat`, and `getattr` never touch the
network -- only `read()` may do so, and only in async or lazy mode.

With FUSE passthrough (Linux 6.9+), the kernel caches the result and subsequent
reads bypass FUSE. Cold reads pay the pack-seek cost once.

### Pack compaction (GC)

Sealed packs are immutable. When chunks are removed (via manifest GC), the pack has dead space. Compaction rewrites packs to reclaim space:

```rust
fn compact_pack(&self, pack_id: u32) -> Result<()> {
    let pack_path = self.pack_path(pack_id);

    // Find all live chunks in this pack
    let live_chunks: Vec<(String, PackLocation)> = self.locations_db.iter()?
        .filter(|(_, loc)| loc.pack_id == pack_id)
        .collect();

    if live_chunks.is_empty() {
        // Pack is entirely dead -- just delete it
        std::fs::remove_file(&pack_path)?;
        return Ok(());
    }

    let dead_ratio = 1.0 - (live_bytes as f64 / pack_size as f64);
    if dead_ratio < 0.3 {
        return Ok(()); // not worth compacting yet
    }

    // Write live chunks to a new pack
    let new_pack = self.new_pack()?;
    for (hash, old_loc) in &live_chunks {
        let data = self.read_chunk_raw(old_loc)?;
        let new_offset = new_pack.size;
        new_pack.file.write_all(&data)?;
        new_pack.size += data.len() as u64;

        // Update index to point to new location
        self.locations_db.put(hash, &PackLocation {
            pack_id: new_pack.id,
            offset: new_offset,
            ..old_loc.clone()
        })?;
    }

    new_pack.seal()?;
    std::fs::remove_file(&pack_path)?; // delete old pack

    Ok(())
}
```

Compaction runs during idle time. Packs with >30% dead space are candidates.

### Sizing

| Store content | Chunks (256KB avg) | Pack files (1GB each) | Index (LMDB) |
|---|---|---|---|
| 10 GB | ~40K chunks | ~10 packs | ~5 MB |
| 100 GB | ~400K chunks | ~100 packs | ~50 MB |
| 1 TB | ~4M chunks | ~1000 packs | ~500 MB |

### Compression

ZSTD compression within packs typically achieves:
- Compiled binaries: 30-40% reduction
- Source code/scripts: 60-70% reduction
- Already-compressed data (images, archives): ~0% reduction

Only compress chunks above MIN_COMPRESS_SIZE (e.g., 4KB). Small chunks have poor compression ratios and the overhead isn't worth it.

## Relationship to Other Docs

- **store.md**: The transfer protocol uses file-tree manifests. WANT_MANIFEST returns a directory structure with per-file chunk lists, not a flat NAR chunk list.
- **views.md**: Chunk GC runs after store path GC. GC removes index entries from LMDB; dead space in pack files is reclaimed by pack compaction during idle time.
- **daemon.md**: Chunk indexing on build completion indexes the output files directly. No NAR serialization needed.
- **builds.md**: Build outputs are files, not NARs. The chunk layer operates on the files as they exist on disk.
