# Content-Addressed Object Model

The AOS store has four object types in two hash spaces. **blake3** (cryptographic,
32-byte digest) provides integrity verification for trees, blobs, and metadata.
**xxh128** (non-cryptographic, 16-byte digest, >10 GB/s) provides fast storage
identity for chunks. The two spaces compose: MetaObject references trees, trees
reference blobs, blobs reference chunk tree roots, and chunk trees reference raw
data.

## Design Overview

```
NixObject (MetaObject, blake3)
  │
  ├── root_tree: Ref → TreeObject (blake3)
  │     ├── entry "bin/" → TreeObject (blake3)
  │     │     ├── entry "gcc" → BlobObject (blake3)
  │     │     │     └── root_chunk → Chunk tree (xxh128)
  │     │     │           ├── height-1 manifest chunk → [ref, ref, ref, ...]
  │     │     │           └── height-0 data chunks → raw file bytes
  │     │     └── entry "g++" → BlobObject (blake3)
  │     ├── entry "lib/" → TreeObject (blake3)
  │     └── entry "include/" → TreeObject (blake3)
  │
  ├── nar_hash: Bytes (SHA-256, Nix compat)
  └── refs: [Ref] → other NixObject meta_hashes
```

The four object types:

- **TreeObject** — directory: sorted entries of `(mode, name, blake3_hash)`.
  Hashed with blake3, stored in `tree_db`.
- **BlobObject** — file: `blob_hash = blake3("blob <size>\0<full content>")`,
  plus a root chunk reference and height for storage. Stored in `blob_db`.
- **Chunk** — raw bytes at a given height.
  `chunk_hash = xxh128(le32(height) || data)`. Stored in `chunk_db`.
- **MetaObject** — structured metadata with typed fields: string, uint, bytes,
  and ref (blake3 hash). Stored in `meta_db`.

## Git Object Format

### Blob

A blob represents the raw content of a single file. The blob hash is:

```
blob_hash = blake3("blob <size>\0<content>")
```

Where `<size>` is the decimal byte count and `<content>` is the **full assembled
byte stream** — all data chunks concatenated in order. This is NOT the hash of
the chunk tree root. The blob hash is computed over the complete file content,
providing end-to-end integrity regardless of how the file is chunked or stored.

This uses git's blob serialization format but with blake3 as the hash function.
AOS blob hashes are not directly comparable to git blob hashes (see
[Hash Functions](#hash-functions)).

### Tree

A tree is a sorted list of directory entries. Each entry is:

```
<mode> <name>\0<32-byte-blake3-hash>
```

The tree hash is:

```
tree_hash = blake3("tree <size>\0<entries>")
```

Where entries are concatenated in sorted order by name. Modes follow git
conventions:

| Mode | Meaning |
|---|---|
| `040000` | Directory (subtree) |
| `100644` | Regular file |
| `100755` | Executable file |
| `120000` | Symbolic link |

Symlinks are stored as blobs containing the target path.

### Root Tree Hash

The root tree hash of a store object is the blake3 hash of the root tree object.
This is the content-addressed merkle root of the entire directory tree. Two store
objects with identical file trees have identical root tree hashes.

## Chunk Model

Chunks are the unit of storage and transfer. Each chunk has a **height** that
determines its role in the chunk tree:

```
chunk_hash = xxh128(le32(height) || data)
```

**Height 0** — raw data bytes. File content, symlink targets, etc. These are
the leaf nodes of the chunk tree, produced by FastCDC splitting of file content.

**Height N (N > 0)** — a serialized list of `ChunkRef` entries pointing to
height N-1 chunks. Each entry is 20 bytes:

```
ChunkRef: [xxh128 hash (16 bytes) | u32 size (4 bytes)]
```

The height is included in the hash input for type safety: a height-0 chunk
containing bytes that happen to look like a ChunkRef list will hash differently
than a height-1 chunk with the same bytes. This prevents a malicious peer from
substituting a data chunk for a manifest node or vice versa.

```protobuf
// A chunk reference: the unit of storage addressing.
// Used within height-N chunks to reference height-(N-1) children,
// and in BlobObject to reference the chunk tree root.
message ChunkRef {
    bytes hash = 1;                 // xxh128 content hash (16 bytes)
    uint32 size = 2;                // data size in bytes (uncompressed)
}
```

## BlobObject

A BlobObject maps a file's blake3 identity to its chunk tree storage:

```protobuf
// Maps a git blob (whole file) to its chunk tree in the storage layer.
// blob_hash = blake3("blob <size>\0<full assembled content>").
// To verify: traverse chunk tree, concatenate all height-0 data,
// compute blake3, compare against blob_hash.
message BlobObject {
    bytes blob_hash = 1;            // blake3 of the complete file content
    uint64 size = 2;                // file size in bytes
    bool executable = 3;            // true if mode is 100755
    bytes root_chunk = 4;           // xxh128 of the chunk tree root (16 bytes)
    uint32 root_height = 5;         // height of the root chunk
}
```

**Single-chunk files** (the common case for files < 1 MB): `root_height = 0`,
`root_chunk` is the xxh128 of the sole height-0 data chunk. No manifest nodes
exist.

**Multi-chunk files**: `root_height > 0`, `root_chunk` points to the root of a
chunk tree. Traversing the tree from root to leaves yields all data chunks in
order.

The blob hash provides end-to-end integrity: fetch all data chunks via the chunk
tree, concatenate in order, compute `blake3("blob <size>\0<data>")`, verify
against `blob_hash`. The chunk hashes (xxh128) provide fast storage-level
identity and dedup but are not cryptographic — integrity flows from the blake3
blob hash.

Storage: `blob_db` maps `blob_hash (blake3, 32 bytes)` →
`{ size, executable, root_chunk, root_height }`.

## Chunk Tree Construction

The chunk tree is built bottom-up from a file's data chunks. The algorithm uses
FastCDC at two levels: first to split file content into data chunks, then to
group chunk references into balanced tree nodes.

### Algorithm

1. FastCDC splits file content into height-0 data chunks (64 KB min, 256 KB avg,
   1 MB max). Each chunk is hashed: `xxh128(le32(0) || chunk_data)`.

2. If the file produces a single data chunk: `root_height = 0`,
   `root_chunk = chunk_hash`. Done.

3. If multiple data chunks: serialize the ChunkRef list (20 bytes per entry).
   If the serialized list fits in one FastCDC segment: store it as a single
   height-1 chunk. `root_height = 1`, `root_chunk = xxh128(le32(1) || refs)`.

4. If the ref list is too large for one segment: FastCDC over the serialized
   refs (avg ~1024 entries per segment). Each segment becomes a height-1 chunk.
   The resulting height-1 ChunkRefs are collected. If they fit in one segment:
   store as a height-2 root. Otherwise, repeat at height 2, 3, etc.

5. Terminates when the root ref list fits in a single FastCDC segment.

```rust
fn build_chunk_tree(data_chunks: &[ChunkRef]) -> (xxh128, u32) {
    if data_chunks.len() == 1 {
        return (data_chunks[0].hash, 0);  // single data chunk, height 0
    }

    let refs = serialize_refs(data_chunks);
    let segments = fastcdc(&refs, MIN_REFS, AVG_REFS, MAX_REFS);

    if segments.len() == 1 {
        // Fits in one node
        let chunk_data = serialize_refs(data_chunks);
        let hash = xxh128(le32(1) || chunk_data);
        store_chunk(hash, chunk_data, 1);
        return (hash, 1);
    }

    // Multiple segments — each becomes a height-1 child
    let children: Vec<ChunkRef> = segments.map(|seg| {
        let chunk_data = serialize_refs(&seg);
        let hash = xxh128(le32(1) || chunk_data);
        store_chunk(hash, chunk_data, 1);
        ChunkRef { hash, size: chunk_data.len() }
    });

    promote(children, 2)
}

fn promote(refs: Vec<ChunkRef>, height: u32) -> (xxh128, u32) {
    let serialized = serialize_refs(&refs);
    let segments = fastcdc(&serialized, MIN_REFS, AVG_REFS, MAX_REFS);

    if segments.len() == 1 {
        let hash = xxh128(le32(height) || serialized);
        store_chunk(hash, serialized, height);
        return (hash, height);
    }

    let children: Vec<ChunkRef> = segments.map(|seg| {
        let chunk_data = serialize_refs(&seg);
        let hash = xxh128(le32(height) || chunk_data);
        store_chunk(hash, chunk_data, height);
        ChunkRef { hash, size: chunk_data.len() }
    });

    promote(children, height + 1)
}

const MIN_REFS: usize = 512;    // ~10 KB per node min
const AVG_REFS: usize = 1024;   // ~20 KB per node avg
const MAX_REFS: usize = 2048;   // ~40 KB per node max
```

### Scaling

| Object size | Data chunks | Tree height | Root node size | Manifest overhead |
|---|---|---|---|---|
| 25 MB (typical Nix pkg) | ~100 | 0 (single chunk) | 0 | 0 |
| 1 GB | ~4K | 1 | ~80 KB | ~80 KB |
| 50 GB | ~400K | 1 | ~8 KB | ~8 MB |
| 1 TiB | ~8M | 2 | ~1.5 KB | ~160 MB |
| 10 TiB | ~80M | 3 | ~1.5 KB | ~1.6 GB |

For the 25 MB case (~100 chunks), the serialized ref list is ~2 KB — well under
the FastCDC minimum segment size. This collapses to a single height-1 root node
or, for very small files, a single height-0 data chunk with no manifest overhead
at all.

The tree grows logarithmically. Even at 10 TiB, the tree is only 3 levels deep.
Manifest overhead is ~0.016% of the data size.

## MetaObject

A MetaObject is structured metadata with typed fields. Each field is one of:

- **String** — UTF-8 text (names, identifiers)
- **Uint** — unsigned 64-bit integer (sizes, timestamps)
- **Bytes** — raw byte sequence (hashes from external systems)
- **Ref** — blake3 hash pointing to another object (tree, blob, or meta)

The meta hash is computed over the canonical serialization:

```
meta_hash = blake3(serialized_meta_object)
```

GC follows all Ref fields recursively. Pinning a MetaObject protects its entire
transitive dependency graph.

```protobuf
message MetaObject {
    string type = 1;                // type discriminator (e.g. "NixObject", "GitCommit")
    repeated MetaField fields = 2;  // typed fields
}

message MetaField {
    string name = 1;
    oneof value {
        string string_val = 2;
        uint64 uint_val = 3;
        bytes bytes_val = 4;
        bytes ref_val = 5;          // blake3 hash (32 bytes), forms DAG edge
    }
}

// For repeated Ref fields (e.g. NixObject.refs, GitCommit.parents):
message MetaRefList {
    repeated bytes refs = 1;        // blake3 hashes (32 bytes each)
}
```

### NixObject

Replaces the old `StoreRecord`. Represents a Nix store path.

```
NixObject {
    store_hash: String,        // Nix store path hash (identity)
    name: String,              // human-readable (e.g. "gcc-14.2.0")
    root_tree: Ref,            // blake3 → tree_db (root directory)
    nar_hash: Bytes,           // SHA-256 NAR hash (Nix compat)
    nar_size: Uint,
    refs: [Ref],               // immediate store deps → other NixObject meta_hashes
}
```

`store_db` is now a simple index: `store_hash (string)` → `meta_hash (blake3)`.
Multiple store hashes can map to the same `root_tree` — two different
input-addressed paths with identical content share one merkle tree and one set
of chunks.

### GitCommit

```
GitCommit {
    tree: Ref,                 // root tree
    parents: [Ref],            // parent commit meta_hashes
    author: String,
    author_time: Uint,
    committer: String,
    commit_time: Uint,
    message: String,
}
```

### StatuteBlock, StatuteTransaction, StatuteQC

These are MetaObjects in `meta_db` following the same pattern. StatuteBlock
references a parent block, state root, transaction refs, and QC ref.
StatuteTransaction carries key, value ref, previous value ref, UCAN, and
signature. StatuteQC references the block and aggregated validator signatures.
See [statute.md](statute.md) for the full field definitions.

## Two-Hash Model

Each object in the store is addressed by one of two hash functions depending on
its role:

| Hash | Algorithm | Derived from | Purpose |
|---|---|---|---|
| `root_tree` | blake3 | Git-format merkle tree | Structure verification, subtree dedup |
| `blob_hash` | blake3 | `"blob <size>\0<full assembled content>"` | File integrity verification |
| `chunk_hash` | xxh128 | `le32(height) \|\| chunk_data` | Storage identity, chunk tree structure |
| `nar_hash` | SHA-256 | NAR serialization | Nix compatibility |
| `store_hash` | Nix algorithm | Input or content addressed | Store path identity, DHT key |
| `meta_hash` | blake3 | Serialized MetaObject | MetaObject identity |

The `root_tree`, `blob_hash`, and `meta_hash` are blake3 — cryptographic,
providing tamper detection. The `chunk_hash` is xxh128 — fast,
non-cryptographic, sufficient for storage identity because integrity is
guaranteed by blake3 at the blob level. A corrupted or substituted chunk is
detected when the reconstructed blob fails blake3 verification.

The `nar_hash` uses SHA-256 for Nix compatibility. It covers the same content
as `root_tree` but uses NAR serialization format. Both are computed during
ingest.

## Subtree Deduplication

If two store objects share identical subtrees (same files, same permissions,
same structure), the tree hash for that subtree is identical in both
NixObjects. This enables:

1. **Transfer optimization.** When fetching a store object, check which tree
   hashes already exist locally. If `lib/` has the same tree hash as another
   object you already have, all blobs under `lib/` are already local.

2. **Storage dedup.** Shared blobs (same blake3) map to the same chunk trees
   (same xxh128 chunks). No redundant storage.

3. **Structural diffing.** Comparing two NixObjects: identical tree hashes mean
   "this entire subtree is identical" — skip it. Only differing subtrees need
   inspection.

### Example: Package Version Update

```
gcc-14.1.0/                     gcc-14.2.0/
  tree root: blake3(A)            tree root: blake3(B)   ← different
    bin/: blake3(X)                 bin/: blake3(Y)       ← different (gcc binary changed)
    lib/: blake3(Z)                 lib/: blake3(Z)       ← SAME (no lib changes)
    include/: blake3(W)             include/: blake3(W)   ← SAME
```

Fetching gcc-14.2.0 when you already have 14.1.0: only `bin/` subtree needs
transfer. `lib/` and `include/` are skipped (matching tree hashes).

## Verification

### Full Verification (on ingest)

When ingesting a store object (build output, fetch, or upload):

1. For each blob: traverse chunk tree from `root_chunk` at `root_height` down
   to height-0 data chunks. At each level, verify
   `chunk_hash == xxh128(le32(height) || data)`. Concatenate height-0 data
   chunks in order. Compute `blake3("blob <size>\0<content>")`. Verify against
   `blob_hash`.

2. For each tree: serialize entries in git format → blake3 → verify tree hash.

3. Verify root tree hash matches `NixObject.root_tree`.

4. Compute NAR hash from the file tree → verify against `NixObject.nar_hash`.

Steps 1-3 verify the merkle tree and chunk tree integrity. Step 4 verifies Nix
compatibility.

### Incremental Verification

A receiver can verify any subtree independently without downloading the full
object:

1. Pick a path (e.g., `lib/libgcc.so`)
2. Fetch the blob's chunk tree → verify chunk hashes at each level
3. Reconstruct blob → verify blob blake3 hash
4. Verify blob hash appears in the `lib/` tree entry
5. Verify `lib/` tree hash appears in the root tree entry
6. Verify root tree hash matches `NixObject.root_tree`

## Ingest Pipeline

When a store object is produced (build output or fetch), the full pipeline:

```
Directory tree walk (depth-first, sorted)
  │
  ├── For each file:
  │   ├── Read content
  │   ├── Compute blob_hash = blake3("blob <size>\0<content>")
  │   ├── FastCDC → height-0 data chunks, xxh128(le32(0) || chunk_data) each
  │   ├── Build chunk tree (if many chunks): recursive FastCDC over ref list
  │   └── Write BlobObject { size, executable, root_chunk, root_height } to blob_db
  │
  ├── For each symlink:
  │   └── Same as file (blob_hash of target path, single tiny chunk)
  │
  ├── For each directory (bottom-up):
  │   └── Compute tree_hash = blake3("tree <size>\0<entries>")
  │
  ├── Compute root_tree = tree_hash of "/"
  ├── Compute nar_hash = SHA-256(NAR serialization) in parallel
  │
  └── Create NixObject MetaObject:
      { store_hash, name, root_tree, nar_hash, nar_size, refs }
      Write to meta_db. Write store_hash → meta_hash to store_db.
```

The NAR hash is computed in a separate pass (or tee'd during the walk) because
NAR serialization order differs from git tree order. NAR uses a specific
depth-first format; git trees use sorted entries.

## FUSE Read Path

The FUSE layer resolves paths via tree traversal (unchanged — the tree structure
is the same). The read function navigates the chunk tree:

```rust
fn read_blob(&self, blob: &BlobObject, offset: u64, size: u32) -> Result<Vec<u8>> {
    if blob.root_height == 0 {
        // Fast path: single data chunk
        let data = self.chunk_store.read_chunk(blob.root_chunk)?;
        return Ok(data[offset as usize..(offset + size as u64) as usize].to_vec());
    }

    // Navigate chunk tree to find covering leaf nodes
    let leaves = self.resolve_leaves(blob.root_chunk, blob.root_height, offset, size)?;
    let mut buf = Vec::with_capacity(size as usize);
    for (leaf_offset, leaf_chunk) in leaves {
        let data = self.chunk_store.read_chunk(leaf_chunk)?;
        // slice to relevant portion, append to buf
        let start = if leaf_offset < offset { (offset - leaf_offset) as usize } else { 0 };
        let end = std::cmp::min(data.len(), start + (size as usize - buf.len()));
        buf.extend_from_slice(&data[start..end]);
    }
    Ok(buf)
}
```

For `root_height > 0` reads: navigate the chunk tree from root to leaves. A
height-N chunk contains a list of ChunkRef entries, each with a `size` field.
For height-1 children, `size` is the data chunk size. For height-N children
(N > 1), `size` is the total assembled data size covered by that subtree.

Walk the tree to find which children overlap the requested byte range. At each
level, accumulate byte offsets from the `size` fields to locate the correct
children. Cache resolved tree structure in memory for repeated reads — the
manifest chunks are small and change infrequently.

### Performance

For single-chunk files (the common case: files < 1 MB), the read path is a
single `chunk_db` lookup and `pread` — identical to the current flat model.

For multi-chunk files, the overhead is one additional chunk read per tree level.
A 1 GB file has height 1 — one manifest chunk read to find the data chunk, then
one data chunk read. A 1 TiB file has height 2 — two manifest chunk reads.
Manifest chunks are ~20 KB and cache well.

## Hash Functions

### blake3

AOS uses blake3 for all tree, blob, and meta hashing:

- Cryptographically secure
- ~10x faster than SHA-256, ~50x faster than SHA-1
- 32-byte digest (same size as SHA-256)
- Has a tree hashing mode designed for merkle trees (enables parallel
  per-subtree hashing)

The git tree/blob serialization format is preserved (same `"blob <size>\0"` and
`"tree <size>\0"` prefixes), but the hash function is blake3 instead of git's
SHA-256. AOS hashes are NOT directly comparable to git hashes — they use the
same structure but a different hash function.

### xxh128

Chunks use xxh128 for storage identity:

- Non-cryptographic, >10 GB/s on modern CPUs
- 16-byte digest
- Used for chunk dedup, pack file indexing, and chunk tree structure

xxh128 is not security-critical here. Integrity is guaranteed by blake3 at the
blob level: a corrupted chunk produces incorrect assembled content, which fails
the blake3 verification. xxh128 provides fast identity for the storage layer
without the overhead of cryptographic hashing on every chunk read.

### External Hash Compatibility

Git uses SHA-256 (or SHA-1 historically). Nix uses SHA-256 for NAR hashes. To
interoperate, the daemon maintains translation indexes in `hash.mdb`:

- `sha256_db`: SHA-256 hash → blake3 hash
- `sha1_db`: SHA-1 hash → blake3 hash

These are populated during ingest. Git tooling uses the SHA-256 hash, which is
translated to blake3 for internal lookup.

## Relationship to Other Docs

- [store.md](store.md) — object protocol, chunk transfer.
- [storage.md](storage.md) — on-disk layout (chunk_db, blob_db, meta_db, store_db).
- [fuse.md](fuse.md) — read path, chunk tree traversal.
- [statute.md](statute.md) — StatuteBlock/Transaction/QC as MetaObjects.
- [containers.md](containers.md) — build output registration produces
  NixObject MetaObjects.
- [store-upload.md](store-upload.md) — upload verification uses blob hashes
  and tree hashes.
