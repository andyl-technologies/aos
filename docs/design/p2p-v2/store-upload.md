# Store Upload

The `/aos/store/upload/1.0.0` stream protocol allows clients to upload
content-addressed store objects (FODs — fixed-output derivations) to the
network. Input-addressed objects (build outputs) cannot be uploaded — they
can only be produced by hermetic build containers via the job system.

## Security Model

### Content-Addressed vs Input-Addressed

The AOS store follows Nix's store ID system. Store objects have two hash
types:

- **Content-addressed (FODs):** `store_hash` is derived from the content
  itself (the NAR hash). Used for source tarballs, flake inputs, and any
  object whose hash is declared in a Nix expression via `outputHash`. The
  content uniquely determines the hash — uploading the same content always
  produces the same hash.

- **Input-addressed (build outputs):** `store_hash` is derived from the
  derivation's inputs (builder, args, env, input derivation hashes). The hash
  is known before the build runs, but the content is only known after. Two
  builds of the same derivation produce the same store hash and (for
  deterministic builds) the same content.

### Upload Restriction

The upload protocol **only accepts content-addressed objects**. The server
verifies the uploaded content matches the declared hash — if the NAR hash
of the reconstructed content does not match, the upload is rejected.

Input-addressed objects cannot be verified by content alone (the server would
need to re-run the build). They are produced exclusively by hermetic build jobs
(`BuildSpec` in the job system), where the
builder is trusted and the output is captured from the OverlayFS upper layer.

### Hash Namespace Safety

Since the store is hash-based, content-addressed and input-addressed objects
naturally occupy different hash namespaces. Nix's store path computation uses
different hash prefixes for content-addressed vs input-addressed paths,
making collisions between the two types impossible by construction. This is
an existing security property inherited from the Nix store model.

### Trust Boundaries

| Source | Hash Type | Verification | Trust |
|---|---|---|---|
| Upload protocol | Content-addressed only | NAR hash verified against content | Trustless (math) |
| Hermetic build (job system) | Input-addressed | Builder ran the derivation in isolation | Trusted builder |
| Store transfer (resolve + chunks) | Either | NAR hash verified on reconstruction | Content-verified |

## Protocol Flow

```
Client → Server:  StoreUploadRequest { nix_object, trees, blobs, requested_ttl }
Server → Client:  StoreUploadResponse { needed_chunks[], actual_ttl } (or error)
Client → Server:  stream of Chunk { hash, data } (only needed chunks)
Server → Client:  StoreUploadComplete { store_hash, pin_expires_at } (or error)
```

### Step by Step

1. **Client sends NixObject metadata.** The request includes the NixObject
   (store_hash, name, root_tree, nar_hash, nar_size), inlined tree objects, and
   blob objects. The client also specifies a requested pin TTL (how long the
   object should be retained before becoming GC-eligible).

2. **Server validates.** The server checks:
   - The requester's UCAN includes `/aos/store/upload`.
   - The NixObject's `nar_size` does not exceed `store.upload.max_object_size`.
   - The server is accepting uploads (`store.upload.accept_remote = true`).
   - The server clamps the requested TTL to `[pin_ttl_min, pin_ttl_max]`
     (or uses `pin_ttl_default` if the client sent 0).

3. **Server responds with needed chunks.** The server checks which chunks from
   the blob objects already exist locally (cross-object deduplication). It responds
   with the list of chunk hashes it still needs. If all chunks are already
   local (the object was previously uploaded or fetched), the needed list is
   empty and the server proceeds directly to validation.

4. **Client streams chunks.** Only the chunks listed in `needed_chunks` are
   sent. Each chunk is a `Chunk{hash, data}` message (same format as the
   download protocol). Chunks are written to the local pack files as they
   arrive.

5. **Server validates content.** After all chunks are received, the server
   verifies the upload at both layers:
   1. **CDC layer:** verify each chunk's xxh3-128 hash matches the declared hash.
   2. **Git layer:** reconstruct each blob from its chunks, compute blake3,
      verify it matches the BlobRef's `blob_hash`. Then verify each tree
      object's hash by re-serializing entries in git format and computing blake3.
      Verify the root tree hash matches the NixObject's `root_tree`.
   3. **NAR layer:** compute the NAR hash from the reconstructed file tree
      and verify it matches the NixObject's `nar_hash`.

   It also verifies the `store_hash` is correctly derived from the content
   (content-addressed check).

   - **If validation passes:** the server writes the NixObject metadata to
     `store.mdb` (`store_db`), scans references into `store_db` refs,
     creates a time-limited pin in `gc.mdb` (clamped to configured bounds),
     calls `start_providing` on `aos:store:object:{store_hash}`, and publishes
     `StorePublish` to the `store/publish` gossipsub topic.
   - **If validation fails:** the server responds with an error
     (`400 hash mismatch`). The orphaned chunks remain in the pack files
     and will be cleaned up by the next GC cycle (mark-and-sweep removes
     chunks not referenced by any NixObject).

6. **Server responds.** On success: `StoreUploadSuccess{store_hash,
   pin_expires_at}`. On failure: `StreamError` with error code and message.

### Deduplication

The `needed_chunks` mechanism provides upload-time deduplication. If the
server already has some of the object's chunks (from a previous upload, a
build output, or a fetch from another peer), the client skips sending them.
For objects that share content with existing store objects (e.g., a new
version of a source tarball that differs by a few files), only the changed
chunks are uploaded.

### Pin Lifetime

The uploaded object is pinned in `gc.mdb` with a TTL:

```
requested_ttl = 0      → pin_ttl_default (e.g., 24h)
requested_ttl < min    → pin_ttl_min (e.g., 1h)
requested_ttl > max    → pin_ttl_max (e.g., 7d)
otherwise              → requested_ttl
```

The pin prevents the object (and its closure via `store_db` refs) from being
GC'd for the pin duration. After the pin expires, the object becomes
LRU-eligible like any other unpinned object.

The pin covers the object's **closure** — all transitively-referenced store
objects are also protected. This ensures that a FOD and its dependencies
remain available for the pin duration.

## Discovery

Nodes accepting uploads advertise themselves on the DHT key `aos:store:upload`
as a provider record with a short TTL (1 min). Clients call `get_providers`
on this key to discover upload-capable nodes.

## Daemon Configuration

```toml
[store.upload]
accept_remote = false              # accept /aos/store/upload/1.0.0
max_object_size = "10GB"           # max NAR size per upload
pin_ttl_min = "1h"                 # minimum pin TTL (clamp floor)
pin_ttl_max = "7d"                 # maximum pin TTL (clamp ceiling)
pin_ttl_default = "24h"            # TTL when client requests 0
```

## Permissions

The `/aos/store/upload` UCAN capability gates access to the upload protocol.
See [permissions.md](permissions.md) for the full capability model.

---

## Protocol

```protobuf
// Stream protocol: /aos/store/upload/1.0.0
// Upload a content-addressed store object (FOD). The server syncs all
// chunks, then validates that the NAR hash matches the content.
// Input-addressed objects (build outputs) cannot be uploaded — they
// are produced only by hermetic BuildSpec jobs.
//
// Flow:
//   Client -> Server:  StoreUploadRequest { nix_object, trees, blobs, requested_ttl }
//   Server -> Client:  StoreUploadResponse { needed_chunks[], actual_ttl }
//   Client -> Server:  stream of Chunk { hash, data } (only needed chunks)
//   Server -> Client:  StoreUploadComplete { store_hash, pin_expires_at }
message StoreUploadRequest {
    NixObject nix_object = 1;       // NixObject metadata (store_hash, name, root_tree, nar_hash, nar_size)
    repeated TreeObject trees = 2;  // inlined tree objects
    repeated BlobObject blobs = 3;  // inlined blob objects (with chunk refs)
    uint64 requested_ttl = 4;      // requested pin duration (microseconds, 0 = server default)
}

message StoreUploadResponse {
    oneof result {
        StoreUploadAccepted accepted = 1;
        StreamError error = 2;      // 403=forbidden, 413=too large, 503=not accepting
    }
}

// Server accepts the upload and lists which chunks it still needs.
// Chunks already in the local store (cross-object dedup) are omitted.
message StoreUploadAccepted {
    repeated bytes needed_chunks = 1; // chunk hashes the server needs
    uint64 actual_ttl = 2;          // server-clamped TTL (microseconds)
}

// Final status after all chunks have been received and validated.
message StoreUploadComplete {
    oneof result {
        StoreUploadSuccess success = 1;
        StreamError error = 2;      // 400=hash mismatch, 500=internal
    }
}

message StoreUploadSuccess {
    string store_hash = 1;          // content address of the uploaded object
    uint64 pin_expires_at = 2;      // epoch microseconds when the pin expires
}
```

## Relationship to Other Docs

- [protocol.md](protocol.md) -- `StoreUploadRequest`, `StoreUploadResponse`,
  `StoreUploadAccepted`, `StoreUploadComplete` protobuf definitions.
- [store.md](store.md) -- store transfer protocol (download path).
- [storage.md](storage.md) -- chunk store, pack files, store_db, gc.mdb.
- [containers.md](containers.md) -- hermetic containers produce input-addressed
  build outputs (the only source of input-addressed objects).
- [gc.md](gc.md) -- pin TTL, orphaned chunk cleanup.
- [daemon.md](daemon.md) -- `[store.upload]` configuration.
- [git-store.md](git-store.md) -- git-compatible two-layer model (tree/blob
  objects over CDC chunks) verified during upload validation.
