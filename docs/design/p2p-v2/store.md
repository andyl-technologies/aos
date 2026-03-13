# Content-Addressed Store and Transfer Protocol

The AOS P2P v2 store is a content-addressed object store distributed across
peers. Store objects are identified by their content hash -- the same hash
always refers to the same content, regardless of which peer or cluster produced
it. The store is global: there is no cluster-scoping on store objects
themselves. Authorization is handled at the protocol level via UCANs.

## Content-Addressed Store Model

Every build output in AOS is a **store object** identified by a **store hash**.
A store object represents a file tree (the output of a build derivation) and
carries two hashes:

- **Store hash** (`store_hash`): the content address of the object. This is the
  primary identifier used in DHT records, manifest requests, and dependency
  references.
- **NAR hash** (`nar_hash`): the hash of the object serialized in NAR (Nix
  Archive) format, used for integrity verification of the complete object.

Content addressing means that if two builds produce byte-identical outputs, they
share the same store hash and are fungible. Any peer providing a given store
hash serves the same content.

## Provider Discovery

Peers advertise which store objects they hold via DHT provider records.

### Publishing

When a peer holds a store object, it calls `start_providing` on the DHT with
the key `aos:store:{object_id}`. This creates a `ProviderRecord` that maps the
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

Provider record TTLs for `aos:store:{store_hash}` are tiered based on object
state:

| Object State | TTL | Rationale |
|---|---|---|
| Pinned (active FUSE view or roots_db) | Cluster-config interval (default 1 day) | Stable, long-lived. |
| Replicated (in replication pool) | Cluster-config interval (default 1 day) | Managed by replication protocol. |
| Unpinned, unreplicated | Estimated time to GC (capped at cluster-config interval) | May be evicted soon; TTL reflects expected lifetime. |

Provider records are refreshed at `TTL * 2/3` intervals.

Newly published objects are subject to `ClusterConfig.min_hold_duration`
(default 1 hour) — the publisher retains the object for at least this period
regardless of LRU position, ensuring replicators have time to download it. See
[replication.md](replication.md) for the full replication protocol.

## Manifest Format

A **Manifest** describes the file tree structure of a store object. It contains
metadata about the object and a list of entries representing every path in the
tree.

```
Manifest {
    store_hash    // content address of this store object
    name          // human-readable name (e.g. package name)
    nar_hash      // hash of the full NAR serialization
    nar_size      // size of the NAR serialization in bytes
    entries[]     // ordered list of file tree entries
}
```

### Entries

Each entry has a `path` and one of three types:

| Type | Fields | Description |
|---|---|---|
| **DirEntry** | `mode` | A directory with the given permission mode. |
| **FileEntry** | `size`, `executable`, `chunks[]` | A regular file, possibly executable, composed of one or more chunks. |
| **SymlinkEntry** | `target` | A symbolic link pointing to `target`. |

### Chunk References

Each `FileEntry` contains an ordered list of `ChunkRef` values that, when
concatenated, reconstruct the file contents:

```
ChunkRef {
    hash    // xxh3-128 digest, 16 bytes
    size    // size of this chunk in bytes
}
```

The xxh3-128 hash is a non-cryptographic hash used for chunk identification and
deduplication. Chunks are self-verifying: the recipient hashes the received data
and confirms it matches the expected hash.

## Transfer Flow

Retrieving a store object follows a six-step sequence:

1. **Discover providers.** Query the DHT with `get_providers` for key
   `aos:store:{object_id}`. Select one or more providers from the results.

2. **Request manifest.** Open the `/aos/store/manifest/1.0.0` stream to a
   provider and send a `ManifestRequest{store_hash}`. The provider responds
   with a `ManifestResponse` containing the `Manifest` (including `references`
   and `closure` hints) or a `StreamError`. This step requires a valid
   `/aos/store/read` UCAN.

3. **Resolve closure.** The manifest's `references` field lists the object's
   immediate store dependencies (authoritative). The `closure` field provides
   best-effort transitive dependency hints — each `ClosureHint` names a
   dependency and its own immediate references (if the serving peer has it
   locally). This lets the fetcher discover the full closure without
   sequentially walking the DAG.

4. **Check local state.** Walk the resolved closure and check which manifests
   and chunks already exist in the local store. Chunks shared with
   previously-fetched objects will already be present.

5. **Fetch missing content in parallel.** For each missing store object in the
   closure, fetch its manifest (which may reveal additional deps at the
   frontier where closure hints were incomplete). Fetch all missing chunks
   across multiple providers in parallel. The requesting peer may contact
   multiple providers simultaneously, requesting different subsets of missing
   chunks from each.

6. **Reconstruct.** Reassemble each file by concatenating its chunks in order
   (as specified by the manifest entries). Verify each chunk's hash on receipt.
   Verify the reconstructed object's NAR hash against the manifest's
   `nar_hash`.

The closure hints in step 3 collapse what would otherwise be a depth-sequential
DAG walk into a single parallel fetch wave. For objects where the serving peer
has the full transitive closure locally, the fetcher learns every dependency
from a single manifest response.

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

- **`/aos/store/manifest/1.0.0`** requires the caller to present a valid
  `/aos/store/read` UCAN. The manifest reveals the structure of a store object:
  its name, file tree layout, and the chunk hashes needed to reconstruct it.

- **`/aos/store/chunk/1.0.0`** also requires `/aos/store/read`. While chunks
  are content-addressed and self-verifying by hash, gating access prevents
  unauthorized peers from exfiltrating store data even if they learn chunk
  hashes through other means.

In practice, a peer that has authenticated once for the manifest can reuse the
same UCAN for chunk requests. Chunk transfer can still be parallelized across
multiple providers -- each provider independently verifies the UCAN.

## Build Output Publishing

When a build job completes, the executing daemon publishes the output to the
store network:

1. **Chunk the output.** The daemon applies content-defined chunking to every
   file in the build output, producing a set of chunks with xxh3-128 hashes.

2. **Generate the manifest.** The daemon constructs a `Manifest` containing the
   file tree structure and chunk references for the build output. The manifest
   includes the store hash, NAR hash, and NAR size.

3. **Scan references.** The daemon scans the output for embedded store hashes
   (reference scanning, same as Nix). The discovered references are recorded
   in `closure_db` (StoreDB) and included in the manifest's `references`
   field. When serving this manifest later, the daemon walks `closure_db`
   transitively to populate the `closure` hints.

4. **Start providing.** The daemon calls `start_providing` on the DHT for
   `aos:store:{object_id}`, registering itself as a provider of the new store
   object.

5. **Announce on GossipSub.** The daemon publishes a `StorePublish` message to
   the `aos/store/publish` topic, notifying peers
   that a new store object is available. This allows peers to proactively
   discover new objects without polling the DHT.

From this point, other peers can discover the object via the DHT (or learn
about it immediately via the GossipSub announcement) and retrieve it using the
manifest and chunk transfer protocols. As other peers fetch and retain the
object, they also become providers, increasing the object's availability across
the network.
