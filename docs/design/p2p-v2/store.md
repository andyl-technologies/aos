# Content-Addressed Store and Transfer Protocol

The AOS P2P v2 store is a content-addressed object store distributed across
peers. Store objects are identified by their content hash -- the same hash
always refers to the same content, regardless of which peer or cluster produced
it. The store is global: there is no cluster-scoping on store objects
themselves. Authorization is handled at the protocol level via UCANs.

The store is global -- all clusters on the same network share the same
content-addressed store. A peer with `/aos/store/read` from any cluster can
read store objects produced by any other cluster. This is by design:
content-addressed objects are identical regardless of which cluster produced
them, and cross-cluster deduplication is a key benefit. If cluster-level
store isolation is needed, use separate networks.

## Content-Addressed Store Model

Every build output in AOS is a **store object** identified by a **store hash**.
A store object is represented by a **NixObject** MetaObject (see
[git-store.md](git-store.md) for the full MetaObject model). The NixObject
carries:

- **`store_hash`** — the content address of the object. This is the primary
  identifier used in DHT records, object requests, and dependency references.
- **`name`** — human-readable name (e.g. `gcc-14.2.0`).
- **`root_tree`** — a Ref (blake3 hash) pointing to the root TreeObject in
  `tree_db`, representing the directory structure.
- **`nar_hash`** — SHA-256 hash of the object serialized in NAR format, used
  for integrity verification of the complete object.
- **`nar_size`** — size of the NAR serialization in bytes.
- **`refs`** — a list of Refs pointing to other NixObject `meta_hash`es,
  representing immediate store dependencies.

Content addressing means that if two builds produce byte-identical outputs, they
share the same store hash and are fungible. Any peer providing a given store
hash serves the same content.

## Provider Discovery

Peers advertise which store objects they hold via DHT provider records.

### Publishing

When a peer holds a store object, it calls `start_providing` on the DHT with
the key `aos:store:object:{object_id}`. This creates a `ProviderRecord` that maps the
object ID to the peer's address. No signature validation is performed on
provider records -- any peer can advertise itself as a provider.

### Lookup

To find providers for a store object, a peer calls `get_providers` on the DHT
with the same key pattern. The DHT returns a set of provider records, each
identifying a peer that claims to hold the object. The requesting peer can then
open stream protocols to any of the returned providers to retrieve the content.

Discovery is pull-based: peers query for specific objects they need. There is no
broadcast announcement of available store objects.

## Provider TTL and Eviction

Provider record TTLs for `aos:store:object:{store_hash}` are tiered based on object
state:

| Object State | TTL | Rationale |
|---|---|---|
| Pinned (active FUSE view or gc.mdb) | Cluster-config interval (default 1 day) | Stable, long-lived. |
| Replicated (in replication pool) | Cluster-config interval (default 1 day) | Managed by replication protocol. |
| Unpinned, unreplicated | Estimated time to GC (capped at cluster-config interval) | May be evicted soon; TTL reflects expected lifetime. |

Provider records are refreshed at `TTL * 2/3` intervals.

Newly published objects are subject to `ClusterConfig.min_hold_duration`
(default 1 hour) — the publisher retains the object for at least this period
regardless of LRU position, ensuring replicators have time to download it. See
[replication.md](replication.md) for the full replication protocol.

## NixObject

A NixObject is a MetaObject that describes a store object. It contains the root
tree reference (blake3 → `tree_db`), NAR hash (SHA-256), and dependency refs
(blake3 → other NixObject `meta_hash`es). The tree and blob objects provide
directory structure and chunk mappings. See [git-store.md](git-store.md) for
all type definitions (MetaObject, TreeObject, BlobObject, ChunkRef).

## Transfer Flow

Retrieving a store object follows a six-step sequence:

1. **Discover providers.** Query the DHT with `get_providers` for key
   `aos:store:object:{object_id}`. Select one or more providers from the results.

2. **Fetch store object metadata.** The receiver looks up the NixObject's
   `meta_hash` (carried in the DHT provider record), then fetches it via
   `/aos/store/object/1.0.0`. The NixObject contains `root_tree`, `nar_hash`,
   and `refs`. This step requires a valid `/aos/store/read` UCAN.

3. **Fetch structural objects.** The receiver batches tree blake3 hashes from
   the NixObject and fetches them in one `ObjectRequest`. Then batches blob
   blake3 hashes and fetches those. All graph walking is done locally — the
   receiver reads the NixObject's `refs` to discover immediate dependencies,
   then fetches their NixObjects in turn to walk the closure.

4. **Check local state.** Walk the resolved closure and check which NixObjects,
   trees, blobs, and chunks already exist in the local store. Chunks shared
   with previously-fetched objects will already be present.

5. **Fetch missing content.** For each missing store object in the closure,
   fetch its NixObject and structural objects. Fetch all missing chunks (data
   chunks AND chunk tree interior nodes) via `/aos/store/chunk/1.0.0`. For
   blobs with `root_height > 0`, fetch the chunk tree level by level starting
   from the root — or pipeline by fetching interior nodes and starting data
   chunk fetches as leaves are discovered. The requesting peer may contact
   multiple providers simultaneously, requesting different subsets of missing
   chunks from each.

6. **Reconstruct and verify.** Navigate chunk trees to assemble file content.
   Verify each chunk hash (xxh128 with height prefix). Verify each blob hash
   (blake3 of assembled content). Verify tree hashes. Verify the NixObject's
   `nar_hash` against the reconstructed NAR serialization.

## Chunk Deduplication

Files are split using content-defined chunking, which determines chunk
boundaries based on the data content rather than fixed offsets. This means that
when two store objects contain similar files (or identical files), their chunk
decompositions will share chunks at the boundaries where content is the same.

The practical effect is significant deduplication:

- Successive versions of a package that change only a few files will share the
  vast majority of chunks with the previous version.
- Common files across packages (e.g., shared libraries, license files) produce
  identical chunks.
- A peer that already has one version of a package will typically need to
  transfer only a small number of new chunks to obtain the next version.

Deduplication is implicit -- it falls out of content addressing. There is no
explicit deduplication index or coordination between peers.

## Auth Boundary

Both store protocols require the `/aos/store/read` UCAN capability:

- **`/aos/store/object/1.0.0`** requires the caller to present a valid
  `/aos/store/read` UCAN. The object response reveals the structure of a store
  object: its name, file tree layout, and the chunk hashes needed to
  reconstruct it.

- **`/aos/store/chunk/1.0.0`** also requires `/aos/store/read`. While chunks
  are content-addressed and self-verifying by hash, gating access prevents
  unauthorized peers from exfiltrating store data even if they learn chunk
  hashes through other means.

### DHT Provider Record Trust

Provider records for `aos:store:object:{store_hash}` have no signature
validation — any peer can advertise itself as a provider. This is an accepted
tradeoff: the verification happens at the content layer, not the discovery
layer. When a peer fetches content from an advertised provider, it verifies
the NAR hash against the NixObject. A provider that serves incorrect content
is detected immediately and blacklisted via GossipSub peer scoring.

False provider advertisements waste bandwidth (connecting to a peer that
doesn't have the content) but cannot corrupt the store. The cost is
proportional to the number of malicious peers and is mitigated by trying
multiple providers in parallel.

The `/aos/store/upload/1.0.0` protocol requires `/aos/store/upload` and only
accepts content-addressed objects (FODs). The server reconstructs the object
from uploaded chunks, computes its NAR hash, and verifies it matches the
NixObject's declared hash and that the store hash is correctly content-derived.
Input-addressed objects (build outputs) cannot be uploaded — they are produced
exclusively by hermetic build containers via the job system. See
[store-upload.md](store-upload.md) for the full upload protocol and security
model.

## Build Output Publishing

When a build job completes, the executing daemon publishes the output to the
store network:

1. **Chunk the output.** The daemon applies content-defined chunking to every
   file in the build output, producing a set of chunks with xxh3-128 hashes.

2. **Create store objects.** The daemon creates the NixObject MetaObject, tree
   objects, blob objects, and chunk trees. BlobObjects are written to `blob_db`,
   TreeObjects to `tree_db`, the NixObject to `meta_db`, and the store index
   (`store_hash` → `meta_hash`) to `store_db`.

3. **Scan references.** The daemon scans the output for embedded store hashes
   (reference scanning, same as Nix). The discovered references are recorded
   as the NixObject's `refs` field (immediate deps). When serving this object
   via the object protocol later, the daemon walks `store_db` refs
   transitively to populate the `closure` hints.

4. **Start providing.** The daemon calls `start_providing` on the DHT for
   `aos:store:object:{object_id}`, registering itself as a provider of the new store
   object.

5. **Announce on GossipSub.** The daemon publishes a `StorePublish` message to
   the `aos/store/publish` topic, notifying peers
   that a new store object is available. This allows peers to proactively
   discover new objects without polling the DHT.

From this point, other peers can discover the object via the DHT (or learn
about it immediately via the GossipSub announcement) and retrieve it using the
object and chunk transfer protocols. As other peers fetch and retain the
object, they also become providers, increasing the object's availability across
the network.

---

## Protocol

```protobuf
// GossipSub topic: aos/store/publish
// Announces a new store object is available. Published after the peer
// has written the provider record to the DHT via start_providing.
message StorePublish {
    string store_hash = 1;          // content address of the new store object
    string name = 2;                // human-readable name (e.g. package name)
    uint64 nar_size = 3;            // NAR-serialized size in bytes
    string peer_id = 4;             // PeerId of the publishing peer
    string ucan = 5;                // authorization chain
}

// Stream protocol: /aos/store/object/1.0.0
// Batch fetch objects by blake3 hash. Serves MetaObjects, TreeObjects,
// and BlobObjects — any object in the blake3 address space.
// Symmetric with /aos/store/chunk/1.0.0 (which serves the xxh128 space).
message ObjectRequest {
    repeated bytes hashes = 1;       // blake3 hashes to fetch
}

message ObjectResponse {
    bytes hash = 1;                  // blake3 hash
    bytes data = 2;                  // serialized object (empty = not found)
}

// Tree, blob, chunk definitions: see git-store.md
// (TreeObject, TreeEntry, ChunkRef are defined there)

// Stream protocol: /aos/store/chunk/1.0.0
// Batch fetch chunks by hash. The server responds with a stream of Chunk
// messages. If a requested hash is not found, a Chunk with empty data
// is returned so the client can identify missing chunks.
message ChunkRequest {
    repeated bytes hashes = 1;      // xxh3-128 hashes to fetch
}

message Chunk {
    bytes hash = 1;                 // xxh3-128 content hash
    bytes chunk = 2;                // chunk data (empty = not found)
}

// Common error type used by stream protocol responses.
message StreamError {
    uint32 code = 1;                // HTTP-style: 404=not found, 403=forbidden, 500=internal
    string message = 2;             // human-readable error description
}
```

---

## Relationship to Other Docs

- [git-store.md](git-store.md) -- content-addressed object model (NixObject, TreeObject, BlobObject, ChunkRef), verification.
- [storage.md](storage.md) -- local storage engine (pack files, LMDB indexes, CDC chunking)
- [gc.md](gc.md) -- eviction algorithm using AccessDB and RootsDB
- [replication.md](replication.md) -- replication protocol
- [store-upload.md](store-upload.md) -- upload protocol for FODs
- [../../tla/Store.tla](../../tla/Store.tla) -- TLA+ formal specification: replication protocol, GC pinning safety, pack compaction, nack termination.
