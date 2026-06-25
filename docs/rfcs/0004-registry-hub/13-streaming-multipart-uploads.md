# Streaming + multipart uploads (bounded-memory, >100 MB NARs)

- **Status:** Design (2026-06-25). Validated against the current upload stack;
  not yet implemented. Motivated by live e2e testing of `aos cache push`
  against the Cloudflare Worker hub (`aos.andyl.org`), where uploads 413 once a
  NAR exceeds the worker's buffered-body limit.

## The problem

`aos cache push` uploads each compressed NAR as a single `PUT`. Over the
Cloudflare Worker that fails for large objects:

- The worker bridge buffers the **entire** request body in isolate memory
  (`crates/aos-hub-worker/src/bridge.rs` `to_axum` → `req.bytes()`), then hands
  a `&[u8]` through `put_machine_path`/`put_cache_path`
  (`crates/aos-hub-core/src/service.rs`) to `SurfaceWrite::write(path, &[u8])`
  (`crates/aos-hub-core/src/surface_write.rs`). A large NAR exceeds the buffer
  and returns `413 "Failed to buffer the request body: length limit exceeded"`.
- Even ignoring memory, Cloudflare caps a **single request body** (~100 MB on
  most plans). NARs in the full AOS package set exceed that. So no
  single-request scheme — buffered *or* streamed — can carry them over the
  Worker.

Two requirements follow:

1. **Bounded memory** — the hub must never hold a whole NAR in memory.
2. **>100 MB objects** — a NAR larger than the platform request-body cap must
   upload as several sub-cap parts.

Both are satisfied by **multipart upload that passes through to each storage
backend's native multipart**, with each part a small, independent request.
Single-body streaming is at best an optimization for sub-cap objects on the
native server; it cannot carry >100 MB over the Worker, so multipart is the
load-bearing mechanism.

## Non-goal / correction

An earlier sketch buffered each part in a server-side `DashMap<upload_id,
Vec<u8>>` and assembled at `complete`. That is wrong here: it reintroduces the
whole-object memory cost, and a Worker **cannot** keep that map across requests
(each request is a fresh isolate). The server must be **stateless**: the
backend holds the multipart state, and the wire protocol carries the backend's
`upload_id` on every part/complete call.

## Wire protocol (client ↔ hub)

Three operations under the cache/registry slug. The `upload_id` is the
*backend's* multipart id (R2/S3) or a hub-minted id (local disk); the client
treats it as opaque and echoes it back.

```text
POST /{slug}/{path}?uploads
  Auth: Bearer <jwt>            # authorized ONCE here (publish / cache-admin)
  -> 200 { "upload_id": "...", "part_size": 16777216 }   # suggested part size

PUT  /{slug}/{path}?uploadId=<id>&partNumber=<n>
  Auth: Bearer <jwt>
  body: one part (< part_size, < platform cap)
  -> 200 { "part_number": n, "etag": "..." }             # etag opaque to client

POST /{slug}/{path}?uploadId=<id>   (action=complete)
  Auth: Bearer <jwt>
  body: { "parts": [ { "part_number": n, "etag": "..." }, ... ] }
  -> 200 { "path": "...", "size": N }

DELETE /{slug}/{path}?uploadId=<id>  (abort; best-effort cleanup)
```

`partNumber` is 1-based and contiguous; parts must be ≥ the backend minimum
(R2/S3: 5 MiB except the last). The narinfo and other small objects keep using
the existing single `PUT` (they are tiny and, for a key-bearing cache, are
*signed* server-side — multipart is NAR-only, and NARs are never signed).

Authorization happens at **initiate** (the same `authorize_publish` /
`require_cache_admin` checks as the single-PUT path); part/complete re-verify
the JWT and that the `upload_id` belongs to the same `(slug, path)`.

## `SurfaceWrite` port additions

```rust
/// Opaque multipart handle: the backend upload id plus the resolved key.
pub struct MultipartUpload { pub upload_id: String /* + backend key, internal */ }
pub struct PartTag { pub part_number: u32, pub etag: String }

pub trait SurfaceWrite: BackendBounds {
    async fn write(&self, path: &str, bytes: &[u8]) -> Result<()>;   // unchanged
    async fn delete(&self, path: &str) -> Result<()>;               // unchanged

    /// Begin a multipart upload for `path`; returns the backend upload id.
    async fn create_multipart(&self, path: &str) -> Result<String>;
    /// Upload one part of an in-progress multipart upload; returns its etag.
    async fn upload_part(&self, path: &str, upload_id: &str, part_number: u32, bytes: &[u8])
        -> Result<PartTag>;
    /// Finalize, assembling the parts into the object at `path`.
    async fn complete_multipart(&self, path: &str, upload_id: &str, parts: &[PartTag])
        -> Result<()>;
    /// Abort and free any backend state (best-effort).
    async fn abort_multipart(&self, path: &str, upload_id: &str) -> Result<()>;
}
```

Every method is stateless across calls — `upload_id` + `path` reconstruct the
backend handle each request, which is exactly what a Worker isolate needs.

### Backend mappings

- **R2 (worker, `surface.rs`)** — `bucket.createMultipartUpload(key)` →
  `{uploadId}`; `bucket.resumeMultipartUpload(key, uploadId).uploadPart(n, bytes)`
  → `{etag}`; `.complete([{partNumber, etag}])`. worker-rs 0.8.5's multipart
  builders share the option-serialization bug already bypassed for
  `get`/`put`, so call these via `js_sys` (Reflect) with no options object, the
  same pattern as `r2_get` and the `R2Write::write` put-bypass.
- **S3 (native `coreports.rs` + worker `surface.rs`)** — `POST {key}?uploads`
  (CreateMultipartUpload) → `UploadId`; `PUT {key}?partNumber=n&uploadId=…`
  (UploadPart) → `ETag` response header; `POST {key}?uploadId=…`
  (CompleteMultipartUpload) with the parts XML. Each request SigV4-signed via
  the existing `s3surface`/`sigv4` signer (extend `object_url` to take query
  params).
- **Local disk (native `coreports.rs`)** — `create_multipart` makes a temp dir
  `…/.uploads/<uuid>/`; `upload_part` writes `part-<n>`; `complete` concatenates
  parts in order into the temp file, then atomic-renames into place (reusing
  `write_atomic`). `upload_id` = the uuid; `etag` = the part's sha256 (or
  empty). `abort` removes the temp dir.

## Server: stateless handlers

Add to `RpcService` (shared, single-sourced native + worker):

```rust
async fn initiate_upload(&self, auth, slug, path) -> InitiateResult     // authorize + create_multipart
async fn upload_part(&self, auth, slug, path, upload_id, n, body) -> PartResult  // reauth + upload_part
async fn complete_upload(&self, auth, slug, path, upload_id, parts) -> WriteResult  // reauth + complete + index
```

`complete_upload` runs the same post-write steps as the single-PUT path
(narinfo is not multipart, so for a NAR there is no signing; the cache/registry
index update keys off the narinfo upload, unchanged).

Routes (`connect.rs`): the facade `/{slug}/{*path}` handler branches on the
`?uploads` / `?uploadId=&partNumber=` / `?uploadId=` query (so it composes with
the existing wildcard, no new top-level paths). Part `PUT`s still flow through
the worker bridge, but each body is one sub-cap part — bounded memory.

## Client: chunked uploader

In `crates/aos-cache` (`backend/mod.rs` + `backend/http.rs` + `push.rs`):

- Add `CacheBackend` multipart methods (`initiate_multipart`, `upload_part`,
  `complete_multipart`, `supports_multipart`).
- In `run_push`, when a compressed NAR exceeds a threshold (e.g. the part size,
  default 16 MiB) **and** the backend supports multipart, drive
  initiate → N× upload_part (streaming each chunk from the compressor, never
  holding the whole NAR) → complete. Otherwise keep the single `PUT`.
- The HTTP backend issues the protocol above with `Authorization: Bearer`.
  (`aos-net` already has `TransferBody::Stream`; parts can be fed without a full
  buffer.)

## Files (ordered, smallest blast radius first)

1. `crates/aos-hub-core/src/surface_write.rs` — port methods + `MultipartUpload`/`PartTag`.
2. `crates/aos-hub-worker/src/surface.rs` — R2 multipart via js_sys; S3 multipart.
3. `crates/aos-hub/src/coreports.rs` — local-fs temp-part multipart; native S3 multipart.
4. `crates/aos-hub-core/src/service.rs` — `initiate/upload_part/complete_upload` (+ auth reuse).
5. `crates/aos-hub-core/src/connect.rs` — facade query-param branch for the three ops.
6. `crates/aos-cache/src/backend/mod.rs` + `backend/http.rs` — client multipart methods.
7. `crates/aos-cache/src/push.rs` — size-threshold routing to multipart.

The single-PUT path and `bridge.rs` are unchanged; small objects (narinfo, info/refs,
sub-threshold NARs) keep working exactly as today.

## Testing

- Unit: local-fs multipart round-trip (parts → concatenated object == single write).
- Worker e2e: push a >100 MB synthetic NAR through `aos.andyl.org`, assert the
  object reads back byte-identical and substitutes.
- Memory: confirm the worker isolate peak stays ~one part, not the whole NAR.
