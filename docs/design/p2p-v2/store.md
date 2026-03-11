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

Provider records have a TTL that is not fixed but derived from a **GC LRU
eviction function**. Each peer manages its local store with a
least-recently-used policy. When a store object is evicted from a peer's local
store (because the peer needs to reclaim space and the object has not been
accessed recently), the peer stops re-publishing the corresponding provider
record. The record then expires from the DHT naturally when its TTL lapses.

This means that popular, frequently-accessed objects remain well-replicated
across the network, while cold objects gradually lose providers and may
eventually become unavailable unless at least one peer retains them.

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

Retrieving a store object follows a five-step sequence:

1. **Discover providers.** Query the DHT with `get_providers` for key
   `aos:store:{object_id}`. Select one or more providers from the results.

2. **Request manifest.** Open the `/aos/store/manifest/1.0.0` stream to a
   provider and send a `ManifestRequest{store_hash}`. The provider responds
   with a `ManifestResponse` containing either the full `Manifest` or a
   `StreamError` (e.g., code 404 if the store hash is not found). This step
   requires a valid `/aos/store/read` UCAN.

3. **Check local chunks.** Walk the manifest entries and collect all `ChunkRef`
   hashes. Check which chunks already exist in the local store. Chunks shared
   with previously-fetched objects will already be present.

4. **Batch request missing chunks.** Open the `/aos/store/chunk/1.0.0` stream
   to a provider and send a `ChunkRequest` containing all missing chunk hashes
   in a single batch (repeated `bytes` hashes). The provider responds with a
   stream of `Chunk{hash, chunk}` messages. If a requested hash is not found,
   the provider sends a `Chunk` with the requested hash and empty `chunk` bytes,
   allowing the requester to identify missing chunks and try other providers.
   No authentication is required for chunk transfer.

5. **Reconstruct.** Reassemble each file by concatenating its chunks in order
   (as specified by the manifest entries). Verify each chunk's hash on receipt.
   Verify the reconstructed object's NAR hash against the manifest's
   `nar_hash`.

The requesting peer may contact multiple providers in parallel to increase
throughput, requesting different subsets of missing chunks from each.

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

The store protocol draws a deliberate authorization boundary between manifests
and chunks:

- **Manifests are gated.** The `/aos/store/manifest/1.0.0` protocol requires
  the caller to present a valid `/aos/store/read` UCAN. The manifest reveals
  the structure of a store object: its name, file tree layout, and the chunk
  hashes needed to reconstruct it.

- **Chunks are ungated.** The `/aos/store/chunk/1.0.0` protocol requires no
  authentication. Chunks are opaque blobs identified by their xxh3-128 hash. A
  chunk hash alone reveals nothing about which store object it belongs to or
  what role it plays in the file tree. Without the manifest, a set of chunks is
  meaningless.

This design means that chunk transfer can be freely parallelized across any
available peer without credential exchange, while the manifest -- which gives
meaning to the chunks -- remains access-controlled.

## Build Output Publishing

When a build job completes, the executing daemon publishes the output to the
store network:

1. **Chunk the output.** The daemon applies content-defined chunking to every
   file in the build output, producing a set of chunks with xxh3-128 hashes.

2. **Generate the manifest.** The daemon constructs a `Manifest` containing the
   file tree structure and chunk references for the build output. The manifest
   includes the store hash, NAR hash, and NAR size.

3. **Start providing.** The daemon calls `start_providing` on the DHT for
   `aos:store:{object_id}`, registering itself as a provider of the new store
   object.

From this point, other peers can discover the object via the DHT and retrieve
it using the manifest and chunk transfer protocols. As other peers fetch and
retain the object, they also become providers, increasing the object's
availability across the network.
