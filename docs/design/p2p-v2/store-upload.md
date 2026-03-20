# Store Upload

The `/aos/store/upload/1.0.0` stream protocol uploads objects (MetaObjects,
TreeObjects, BlobObjects) and their chunk graphs to a remote peer. The
protocol minimizes both latency (few round-trips) and bandwidth (skip chunks
the server already has, locally or from the network).

## Upload Model

An upload is a set of objects identified by blake3 hash, plus the chunk trees
backing any blobs in the set. The client provides the full transitive closure
— the server does not need to chase references.

Objects are opaque: the protocol transfers blake3-keyed bytes. The server
deserializes and indexes after ingest. Any object type (NixObject, GitCommit,
TreeObject, BlobObject, or any future MetaObject type) can be uploaded.

### Content-Addressed Restriction (NixObjects)

NixObjects have an additional restriction: the upload protocol **only accepts
content-addressed NixObjects** (FODs — fixed-output derivations). The server
verifies the NAR hash of the reconstructed content matches the declared hash.
Input-addressed NixObjects (build outputs) cannot be verified by content alone
and are produced exclusively by hermetic build jobs (`BuildSpec`).

Other object types (GitCommit, TreeObject, BlobObject) have no such
restriction — they are self-verifying by their blake3 hash.

### Hash Namespace Safety

Content-addressed and input-addressed NixObjects naturally occupy different
hash namespaces. Nix's store path computation uses different hash prefixes for
the two types, making collisions impossible by construction. This is an
existing security property inherited from the Nix store model.

### Trust Boundaries

| Source | Verification | Trust |
|---|---|---|
| Upload protocol | blake3 hash verified, NixObject NAR hash verified | Trustless (math) |
| Hermetic build (job system) | Builder ran derivation in isolation | Trusted builder |
| Store transfer (object + chunk protocols) | blake3 and chunk hashes verified | Content-verified |

---

## Protocol Flow

Three phases: negotiate, stream, verify.

```
Client                                 Server
  │                                      │
  │  UploadNegotiate                     │
  │  (objects, chunk bloom, heights)     │
  │─────────────────────────────────────>│
  │                                      │── local: check ChunkDB vs bloom
  │                                      │── network: DHT query for high-height chunks
  │                                      │
  │                   UploadPlan         │
  │  (have_local bloom, network chunks)  │
  │<─────────────────────────────────────│
  │                                      │
  │  Client computes:                    │
  │  skip = have_local ∪ network         │
  │  send = closure \ skip               │
  │                                      │
  │  UploadData (stream)                 │
  │  objects first, then chunks          │
  │─────────────────────────────────────>│
  │─────────────────────────────────────>│── server ingests as data arrives
  │─────────────────────────────────────>│
  │                                      │
  │                                      │── fetch network_chunks from mesh
  │                                      │── verify everything
  │                                      │
  │                   UploadResult       │
  │<─────────────────────────────────────│
  │                                      │
  │  (if UploadMissing: send tail)       │
  │─────────────────────────────────────>│
  │                   UploadResult       │
  │<─────────────────────────────────────│
```

### Phase 1: Negotiate

The client describes what it wants to upload. The server determines what it
already has (locally and on the network) and responds with a plan.

**Client sends `UploadNegotiate`:**

- `objects` — blake3 hashes of all objects in the upload set.
- `chunk_filter` — Bloom filter of all chunk xxh128 hashes in the closure
  (data chunks and interior nodes). Lets the server check set membership
  without enumerating every hash.
- `chunk_heights` — chunks with height >= 1. These are candidates for network
  queries because they represent large subtrees.

**Server processes (in parallel):**

1. **Local dedup.** Check the server's ChunkDB against the client's Bloom
   filter. Build a response Bloom filter of chunks the server has locally.
2. **Network dedup (high-height chunks).** For each chunk in `chunk_heights`,
   estimate the subtree size as `N^height` leaf chunks (where N is the
   average FastCDC branching factor, ~1024). If the estimated size exceeds a
   threshold, query the DHT (`get_providers(xxh128)`) to check if any peer
   holds the chunk. Chunks available on the network are marked — the server
   will fetch them from the mesh after the upload completes.

Height is an exponential size proxy. Since the chunk tree uses the same
FastCDC branching factor N at every level, a height-H chunk represents
approximately N^H leaf chunks:

| Height | Estimated subtree (N=1024) | Network query? |
|---|---|---|
| 0 | 1 chunk (~256 KB) | No — query latency > transfer time |
| 1 | ~1K chunks (~256 MB) | Configurable |
| 2 | ~1M chunks (~256 GB) | Yes |
| 3 | ~1B chunks (~256 TB) | Absolutely |

**Server responds with `UploadPlan`:**

- `have_objects` — blake3 hashes the server already has (exact).
- `have_chunk_filter` — Bloom filter of the server's local chunks.
- `network_chunks` — xxh128 hashes of high-height chunks available from other
  peers. The server commits to fetching these from the mesh.
- `upload_id` — session token for the stream phase.

The client computes what to send: everything not in `have_chunk_filter` and
not in `network_chunks`. Bloom false positives mean the client might skip a
few chunks the server doesn't have — this is resolved in phase 3.

### Phase 2: Stream

The client streams objects and chunks the server needs. Objects are sent
first (small, needed for structural verification), then chunks in any order.
The server writes chunks to pack files as they arrive.

### Phase 3: Verify

After all data is received, the server:

1. Fetches any `network_chunks` from the mesh (parallel with client stream).
2. Verifies all ingested data:
   - **Chunk hashes:** recompute `xxh128(le32(height) || data)` for each chunk.
   - **Chunk trees:** verify height-N chunks reference valid height N-1 chunks.
   - **Blob hashes:** reconstruct blobs from chunk trees, compute
     `blake3("blob <size>\0<content>")`, verify against declared blob_hash.
   - **Tree hashes:** re-serialize tree entries in git format, compute blake3,
     verify against declared tree_hash.
   - **NixObject NAR hash (if applicable):** compute NAR hash from the
     reconstructed file tree, verify against nar_hash. Verify store_hash is
     correctly content-derived.
   - **Other MetaObjects:** verify meta_hash = blake3 of serialized content.
3. Responds with `UploadResult`:
   - `UploadSuccess` — all objects ingested. Server publishes DHT provider
     records and creates GC pins.
   - `UploadMissing` — Bloom filter false positives. Lists specific chunk
     xxh128 hashes the server still needs. Client sends the missing chunks
     and server verifies again. At most one extra round-trip.
   - `UploadError` — validation failure, quota exceeded, or authorization error.

### Round-trip Count

| Case | RTTs | Description |
|---|---|---|
| Hot (server has everything) | 1 | Negotiate → plan says "have all" |
| Best (no Bloom misses) | 2 | Negotiate → stream → verify |
| Typical (few Bloom misses) | 3 | Negotiate → stream → missing → stream tail → verify |
| Cold (server has nothing) | 2 | Bloom is empty on server side, client sends everything |

### Bloom Filter Sizing

The Bloom false positive rate determines how often phase 3 requires a tail
transfer. Recommended sizing:

| Chunk count | Filter size | FPR (k=10) |
|---|---|---|
| 1,000 | 1 KB | < 0.1% |
| 100,000 | 120 KB | < 0.1% |
| 1,000,000 | 1.2 MB | < 0.1% |

The server's `have_chunk_filter` covers its entire ChunkDB. For a server with
600K chunks, a 100 KB filter gives ~0.01% FPR. This filter can be cached and
maintained incrementally (rebuild on GC, update on ingest).

---

## Pin Lifetime

Uploaded NixObjects are pinned in `gc.mdb` with a TTL:

```
requested_ttl = 0      → pin_ttl_default (e.g., 24h)
requested_ttl < min    → pin_ttl_min (e.g., 1h)
requested_ttl > max    → pin_ttl_max (e.g., 7d)
otherwise              → requested_ttl
```

The pin prevents the object and its closure from GC for the pin duration.
After expiry, the object becomes LRU-eligible.

Other object types (GitCommit, TreeObject) are not pinned by the upload
protocol. They are retained by Statute mount affinities if referenced from
Statute state, or LRU-evicted otherwise.

## Discovery

Nodes accepting uploads advertise on the DHT key `aos:store:upload` as a
provider record with a short TTL (1 min). Clients call `get_providers` to
discover upload-capable nodes.

## Daemon Configuration

```toml
[store.upload]
# Store upload acceptance is controlled by node.labels.store-upload = "true"
max_upload_size = "10Gi"           # max total upload size per session
pin_ttl_min = "1h"                 # minimum pin TTL (clamp floor)
pin_ttl_max = "7d"                 # maximum pin TTL (clamp ceiling)
pin_ttl_default = "24h"            # TTL when client requests 0
network_query_height = 2           # min chunk height for DHT network queries during negotiate
```

## Permissions

The `/aos/store/upload` UCAN capability gates access to the upload protocol.
See [permissions.md](permissions.md) for the full capability model.

---

## Protocol

```protobuf
// Stream protocol: /aos/store/upload/1.0.0
// Upload objects and their chunk graphs to a remote peer.
// Three-phase: negotiate → stream → verify.
//
// Flow:
//   Client → Server:  UploadNegotiate
//   Server → Client:  UploadPlan
//   Client → Server:  stream of UploadData
//   Server → Client:  UploadResult
//   (if UploadMissing: Client sends tail chunks, Server sends final UploadResult)

// Phase 1: Client describes the upload set.
message UploadNegotiate {
    repeated bytes objects = 1;        // blake3 hashes of all objects to upload
    bytes chunk_filter = 2;            // Bloom filter of all chunk xxh128 hashes
    uint32 chunk_filter_k = 3;         // Bloom filter hash function count
    repeated ChunkHeight chunk_heights = 4; // chunks with height >= 1 (network query candidates)
    uint64 total_size = 5;             // total uncompressed bytes (admission control hint)
    uint64 requested_ttl = 6;          // pin duration for NixObjects (microseconds, 0 = default)
    string ucan = 7;                   // authorization chain
}

// Chunk with its height, for network query decisions.
// N^height estimates the subtree leaf count (N = FastCDC branching factor).
message ChunkHeight {
    bytes hash = 1;                    // xxh128
    uint32 height = 2;
}

// Phase 1 response: Server says what it needs.
message UploadPlan {
    bytes upload_id = 1;               // session token
    bool accept = 2;
    string reject_reason = 3;          // non-empty if accept = false

    repeated bytes have_objects = 4;   // blake3 hashes server already has
    bytes have_chunk_filter = 5;       // Bloom filter of server's local chunks
    uint32 have_chunk_filter_k = 6;    // Bloom filter hash function count
    repeated bytes network_chunks = 7; // xxh128 of high-height chunks server will fetch from mesh
    uint64 actual_ttl = 8;             // server-clamped pin TTL (microseconds)
}

// Phase 2: Client streams objects and chunks.
message UploadData {
    bytes upload_id = 1;
    oneof payload {
        UploadObject object = 2;
        UploadChunk chunk = 3;
    }
}

// An object (opaque blake3-keyed bytes).
message UploadObject {
    bytes hash = 1;                    // blake3
    bytes data = 2;                    // serialized object
}

// A chunk (data or interior node).
message UploadChunk {
    bytes hash = 1;                    // xxh128 (height baked into hash)
    uint32 height = 2;                 // 0 = data, N = tree of height N-1 refs
    bytes data = 3;                    // chunk content
}

// Phase 3: Server reports result.
message UploadResult {
    oneof result {
        UploadSuccess success = 1;
        UploadMissing missing = 2;
        UploadError error = 3;
    }
}

message UploadSuccess {
    repeated bytes ingested = 1;       // blake3 hashes of successfully ingested objects
    uint64 pin_expires_at = 2;         // epoch microseconds (for pinned NixObjects)
}

// Bloom filter false positives: chunks the server still needs.
message UploadMissing {
    repeated bytes chunks = 1;         // xxh128 hashes
}

message UploadError {
    uint32 code = 1;                   // 400=invalid, 403=forbidden, 413=too large, 507=no space
    string message = 2;
}
```

---

## Relationship to Other Docs

- [store.md](store.md) -- store transfer protocol (download path: object + chunk protocols).
- [git-store.md](git-store.md) -- content-addressed object model (tree/blob/chunk verification).
- [storage.md](storage.md) -- chunk store, pack files, ChunkDB, tiered storage.
- [containers.md](containers.md) -- hermetic builds produce input-addressed NixObjects
  (the only source of input-addressed objects).
- [gc.md](gc.md) -- pin TTL, orphaned chunk cleanup, affinity-scoped pinning.
- [daemon.md](daemon.md) -- `[store.upload]` configuration.
- [mounts.md](mounts.md) -- `_affinity` controls long-term retention beyond pin TTL.
