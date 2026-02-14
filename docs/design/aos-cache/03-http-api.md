# HTTP API

> Part of the [AOS Cache Design](README.md)

All endpoints are prefixed with `/:view/`. A request to `/ci/abc123.narinfo`
looks up the `ci` view's auth and serves from the shared store.

## 4.1 Cache Info

```
GET /:view/nix-cache-info

Response 200:
StoreDir: /var/lib/aos/store
WantMassQuery: 1
Priority: 30
```

## 4.2 NARInfo Lookup

```
GET /:view/{hash}.narinfo

Response 200 (Content-Type: text/x-nix-narinfo):
StorePath: /var/lib/aos/store/{hash}-{name}
URL: nar/{narhash}.nar.zst
Compression: zstd
FileHash: sha256:{base32}
FileSize: {bytes}
NarHash: sha256:{base32}
NarSize: {bytes}
References: {space-separated store-path basenames}
Deriver: {basename}.drv
Sig: {key-name}:{base64-signature}

Response 404: path not in this view (no GC root symlink) or not in store
Response 401: missing/invalid auth token (if view requires auth for reads)
```

**Implementation**:
1. Check namespaces for a GC root symlink: try
   `readlink /var/lib/aos/gcroots/{view}/bin/{hash}`, then
   `readlink /var/lib/aos/gcroots/{view}/src/{hash}` -- if neither exists,
   return 404 (path not in this view's projection)
2. Resolve the symlink to get the full store path
3. Query SQLite for metadata (narHash, narSize, references, deriver, sigs)
4. Format narinfo using `nix_compat::narinfo`
5. Sign with the server's ed25519 key

## 4.3 NAR Download

```
GET /:view/nar/{store-hash}-{narhash}.nar
GET /:view/nar/{store-hash}-{narhash}.nar.zst
GET /:view/nar/{store-hash}-{narhash}.nar.xz

Response 200 (Content-Type: application/x-nix-nar):
<binary NAR stream>

Response 404: path not in this view or not in store
```

**Implementation**: The URL encodes both the store path hash and the NAR hash
(nix-serve pattern). The store hash is used to verify the path exists in this
view (check GC root symlink), then resolve to the full store path. Stream
`nix store dump-path /var/lib/aos/store/{path}` through a zstd/xz compressor to the
HTTP response. No temp files -- pipe directly from the subprocess stdout to
the HTTP body using `tokio::process::Command` with `AsyncRead`.

## 4.4 Remote Builds Over HTTP

### 4.4.0 Why HTTP Instead of SSH

Nix already supports remote builds via `ssh-ng://`, using the daemon's
worker protocol over SSH. The protocol does three things:

```
1. IsValidPath (batch) — "which of these paths do you have?"
2. AddToStore  (serial) — upload each missing path as NAR, one by one
3. BuildPaths            — "realise this .drv"
```

SSH is a poor transport for this:

| Problem | SSH | HTTP |
|---------|-----|------|
| Transfer parallelism | One NAR at a time through a single pipe | **Parallel** uploads over multiple connections |
| Resume on failure | Restart entire closure copy from scratch | **Retry** just the failed path; range requests for large files |
| Connection lifetime | Must stay alive for entire build (hours) | Build request returns SSE stream; reconnectable |
| Timeout handling | `connect-timeout` **ignored** on SSH (nix #7459) | Standard HTTP timeouts, well-understood |
| Binary data safety | TTY escape sequences can **corrupt** NAR data | Binary-safe by design |
| Error granularity | Pipe error = opaque failure | HTTP status codes per operation |

We implement the same three operations over HTTP, with better transport
properties. This is not a new protocol -- it's the same semantics as
`ssh-ng://` remote builds, just with HTTP as the wire format.

### 4.4.1 What a Derivation Closure Contains

A derivation closure has **only two kinds of paths** -- no intermediate
build outputs:

```
nix-store -qR /var/lib/aos/store/{hash}-foo.drv
  │
  ├── .drv files (text build recipes, ~KB each)
  │   /var/lib/aos/store/aaa-foo.drv
  │   /var/lib/aos/store/bbb-gcc.drv
  │   /var/lib/aos/store/ccc-make.drv
  │   /var/lib/aos/store/ddd-glibc.drv
  │   ... (possibly hundreds, but total ~5-10 MB)
  │
  └── fixed-output sources (fetchurl tarballs, hash-verified)
      /var/lib/aos/store/eee-gcc-14.1.0.tar.xz     (120 MB)
      /var/lib/aos/store/fff-glibc-2.39.tar.xz      (18 MB)
      /var/lib/aos/store/ggg-foo-src.tar.gz          (2 MB)
      ... (bulk of the transfer)
```

When `nix-store --realise foo.drv` runs on the server, it builds the
**entire dependency graph** from these inputs: gcc from source, make
from source, etc. No pre-built intermediate outputs cross the wire.

**Two safe categories**:
- `.drv` files: just text (ATerm format). Cannot execute. Safe to accept.
- Fixed-output paths: content-addressed. Nix verifies `outputHash` on
  import -- a tampered tarball is rejected. Safe to accept.

The server **rejects** any path that isn't `.drv` or fixed-output.

### 4.4.2 Query Missing Paths (IsValidPath over HTTP)

Before uploading, the client asks what the server already has:

```
POST /:view/query-missing
Authorization: Bearer {build-token}
Content-Type: application/json

{
  "paths": [
    "/var/lib/aos/store/aaa-foo.drv",
    "/var/lib/aos/store/bbb-gcc.drv",
    "/var/lib/aos/store/eee-gcc-14.1.0.tar.xz",
    ...
  ]
}

Response 200:
{
  "missing": [
    "/var/lib/aos/store/bbb-gcc.drv",
    "/var/lib/aos/store/eee-gcc-14.1.0.tar.xz"
  ],
  "fetchable": [
    "/var/lib/aos/store/eee-gcc-14.1.0.tar.xz"
  ]
}
```

The `fetchable` field lists fixed-output paths that the server can download
from the internet itself (it inspects the `.drv` to find the URL). The
client can skip uploading these -- the server fetches them during build.

This is the HTTP equivalent of the daemon's `IsValidPath` batch query.

### 4.4.3 Upload Missing Inputs (AddToStore over HTTP)

Upload each missing path the server can't fetch itself. Paths are uploaded
**in parallel** over independent HTTP connections -- unlike SSH's serial
pipe.

```
PUT /:view/store/{hash}
Authorization: Bearer {build-token}
Content-Type: application/x-nix-nar
Content-Length: {bytes}
Body: NAR of the store path

Response 200: {"path": "/var/lib/aos/store/{hash}-{name}"}
Response 409: already exists (idempotent, ok)
Response 400: rejected (not .drv, not fixed-output)
Response 401: unauthorized
```

**Validation**: the server inspects each uploaded path:
- Ends in `.drv` -> accept (text build recipe)
- Has `ca` field in narinfo (fixed-output derivation) -> accept after
  verifying the content hash matches the declared `outputHash`
- Anything else -> **reject with 400**

**Large source uploads** support resume via `Content-Range`:
```
PUT /:view/store/{hash}
Content-Range: bytes 104857600-209715199/209715200
Body: <remaining bytes of NAR>
```

If the connection drops during a 200MB source tarball, the client retries
from where it left off -- not from the beginning.

**Upload concurrency**: the client uploads multiple paths simultaneously
(e.g., 8 parallel connections). Each upload is independent; a failure in
one doesn't affect others. This is the fundamental improvement over SSH's
serial `AddToStore`.

### 4.4.4 Request Build (BuildPaths over HTTP)

```
POST /:view/build?drv=/var/lib/aos/store/{hash}-{name}.drv&priority=0
Authorization: Bearer {access-token}

Response 200 (Content-Type: text/event-stream):
  Server-Sent Events stream of build progress (see §4.4.5)

Response 400: derivation not found on server
Response 401: unauthorized
Response 409: outputs already built (idempotent — creates GC roots, returns paths)
```

Query parameters for build requests (and all endpoints with scalar arguments)
instead of JSON bodies. Easier to debug (`curl`), log, and cache. JSON bodies
are reserved for endpoints with complex/large payloads (`query-missing`,
`upload-pack`).

**Build workflow on the server**:
1. Authenticate token for build access to the view
2. Verify the `.drv` exists in the local store
3. Check if outputs are already built -> if so, skip to step 7
4. Invoke `nix-store --realise /var/lib/aos/store/{hash}.drv` in a subprocess
   - The Nix daemon handles: fetching sources, building input derivations,
     sandboxed build execution, output hash verification, signing
5. Stream build logs to the client via SSE (see §4.4.5)
6. On failure: send error event with log tail, respond with failure status
7. On success: create GC root symlinks for all output paths AND their
   transitive runtime closure in this view
8. Write metadata JSON (pushed_at, expires_at) for each root
9. Send completion event with output store paths

### 4.4.5 Build Log Streaming & Deduplication

**The Problem**: When multiple clients request a build for the same `.drv`
simultaneously, we must NOT start duplicate builds. Instead, all clients
should see the same build log -- including clients that join late (after
the build has already started). This is explicitly better than Nix's current
behavior where "the build is already in progress somewhere else, but we
won't tell you what's happening."

**SSE Event Format**:

```
id: 0
event: status
data: {"phase": "queued", "drv": "/var/lib/aos/store/xxx.drv"}

id: 1
event: status
data: {"phase": "building", "drv": "/var/lib/aos/store/yyy-dep.drv"}

id: 2
event: log
data: configuring...

id: 15
event: complete
data: {"success": true, "outputs": ["/var/lib/aos/store/zzz-pkg"], "duration_secs": 142}

--- or on failure ---

id: 15
event: error
data: {"success": false, "drv": "/var/lib/aos/store/xxx.drv", "exit_code": 1, "log_tail": "...last 50 lines..."}
```

Every event has a monotonic `id` field for SSE reconnection (`Last-Event-ID`).

**Build Deduplication via BuildManager**:

The server maintains an in-memory `BuildManager` that maps `drv_path` to a
shared `BuildHandle`. When a build is requested:

1. Check if a `BuildHandle` already exists for this `.drv` -- if yes, return
   the existing handle (deduplication)
2. If not, create a new handle and start `nix-store --realise` as a subprocess
3. All clients sharing a handle receive the same event stream

```rust
struct BuildManager {
    /// drv_path → active build handle (shared across all clients for same drv)
    builds: RwLock<HashMap<String, BuildHandle>>,
    /// per-view build semaphore (max_concurrent_builds)
    semaphores: HashMap<String, Semaphore>,
}

struct BuildHandle {
    drv_path: String,
    tx: broadcast::Sender<BuildEvent>,  // live events to all subscribers
    log_buffer: Arc<LogBuffer>,         // ring buffer for replay
    result: Arc<Mutex<Option<BuildResult>>>,
    done: Arc<Notify>,
}
```

**Log Replay for Late Joiners**:

A `LogBuffer` (append-only ring buffer, ~100K events) stores every event
from the build start. When a new client connects (or reconnects):

1. **Replay**: read events from `log_buffer[start_idx..current]` and send
   as SSE events immediately
2. **Subscribe**: attach to the `broadcast::Sender` for live events going
   forward
3. Events from replay and live subscription are merged into a single stream

This means a client joining at event #50 instantly receives events 0-49
(catchup) then continues with live events 50+.

**SSE Reconnection**: If a client's connection drops, the browser/client
sends `Last-Event-ID: 42` on reconnect. The server replays from event 43
onward. No duplicate events, no missed events.

**Concurrency Flow**:

```
Client A: POST /:view/build?drv=foo.drv
  → BuildManager creates BuildHandle, starts nix-store --realise
  → Client A subscribes to broadcast channel, receives events live

Client B: POST /:view/build?drv=foo.drv (same drv, 30s later)
  → BuildManager returns EXISTING BuildHandle (no new build!)
  → Client B replays events 0..N from LogBuffer (instant catchup)
  → Client B subscribes to broadcast for live events N+1..

Client C reconnects with Last-Event-ID: 10:
  → Server replays events 11..N from LogBuffer
  → Client C subscribes to broadcast for live events N+1..

Build completes:
  → All clients receive "complete" event simultaneously
  → BuildHandle kept in memory for 5 minutes (late reconnectors)
  → Then removed from BuildManager map
```

**Implementation**: `nix-store --realise` subprocess with piped stderr.
Each stderr line becomes a `BuildEvent` written to both the `LogBuffer`
(for replay) and the `broadcast::Sender` (for live subscribers):

```rust
let mut child = Command::new("nix-store")
    .args(["--realise", drv_path])
    .stderr(Stdio::piped())
    .spawn()?;

let stderr = BufReader::new(child.stderr.take().unwrap());
let mut lines = stderr.lines();
while let Some(line) = lines.next_line().await? {
    let event = BuildEvent { id: next_id(), kind: Log { line } };
    handle.log_buffer.append(event.clone());
    let _ = handle.tx.send(event);  // broadcast to all live subscribers
}
```

After completion, Nix also persists the log to
`/var/lib/aos/var/log/nix/drvs/{hash1}/{hash2}-{name}.drv.bz2`. This serves as
a durable backup -- if the server restarts, completed build logs can be
recovered from Nix's log storage.

### 4.4.6 Batch Build

For building a closure (e.g., a system configuration with many derivations):

```
POST /:view/build-closure?drv=/var/lib/aos/store/{hash}-toplevel.drv&max_jobs=4
Authorization: Bearer {access-token}

Response 200 (text/event-stream): same SSE format, but with multiple
  "building" phases as the dependency graph is traversed
```

`nix-store --realise` already handles building the full dependency graph.
The `--max-jobs` flag controls parallelism. Logs for all dependencies
are interleaved in the SSE stream with `drv` identifiers for each event.

### 4.4.7 Cross-Architecture Builds

For building `aarch64-linux` derivations on an `x86_64-linux` host:

1. The host must have QEMU user-mode emulation registered via `binfmt_misc`
2. The Nix daemon must be configured with `extra-platforms = aarch64-linux`
3. No special handling needed in `aos serve` -- `nix-store --realise` uses
   the binfmt interpreter transparently

Configuration on the host (NixOS):
```nix
boot.binfmt.emulatedSystems = [ "aarch64-linux" ];
# This registers QEMU interpreters for the target architecture
```

The cache server reports supported platforms:
```
GET /nix-cache-info  →  System: x86_64-linux
GET /platforms       →  {"platforms": ["x86_64-linux", "aarch64-linux"]}
```

### 4.4.8 Pack Upload (Git-Inspired)

`.drv` files are tiny (~1-5 KB each) but closures contain hundreds of them.
Uploading each as a separate `PUT` means hundreds of HTTP round-trips, each
with TLS overhead, for a few KB of payload. Git solves this with **packfiles**
-- a single stream containing multiple objects. We borrow the concept.

**Problem**: 300 .drv files x 1 HTTP PUT each = 300 round-trips (~2-3s on
a 10ms link, dominated by TLS handshakes and TCP slow-start). A single POST
with all 300 .drv NARs concatenated = 1 round-trip (~50ms + transfer time
for ~1-2 MB total).

```
POST /:view/upload-pack
Authorization: Bearer {build-token}
Content-Type: application/x-aos-pack

Wire format:
┌──────────────────────────────────────┐
│ [4 bytes] magic: "AOSP"             │
│ [4 bytes] version: 1 (u32 BE)       │
│ [4 bytes] entry count: N (u32 BE)   │
├──────────────────────────────────────┤
│ Entry 1:                             │
│   [32 bytes] store path hash (hex)  │
│   [8 bytes] NAR size (u64 BE)       │
│   [NAR size bytes] NAR data         │
│ Entry 2:                             │
│   ...                                │
│ Entry N:                             │
│   ...                                │
├──────────────────────────────────────┤
│ [32 bytes] SHA-256 of all above     │
└──────────────────────────────────────┘

Response 200:
{
  "accepted": 300,
  "rejected": 0,
  "paths": ["/var/lib/aos/store/aaa-foo.drv", ...]
}
Response 400: validation failure (non-.drv, non-fixed-output in pack)
```

**What goes in a pack vs. individual uploads**:

| Path type | Size | Upload method |
|-----------|------|--------------|
| `.drv` files | ~1-5 KB | **Pack** (hundreds in one POST) |
| Small sources | < 10 MB | **Pack** (if total pack < 50 MB) |
| Large sources | > 10 MB | **Individual PUT** (parallel, resumable) |

This mirrors git's approach: small objects are packed together, large blobs
are transferred individually (git's `packfile-uris` capability in protocol v2
redirects large objects to separate URLs).

**Validation**: same as individual uploads -- each entry must be `.drv` or
fixed-output. The server unpacks entries, validates each, and imports via
`nix-store --import`. A single invalid entry rejects the entire pack (atomic).

**Client-side implementation** (`aos build --remote`):

```rust
// Partition missing paths into pack-eligible and individual uploads
let (packable, individual): (Vec<_>, Vec<_>) = missing.iter()
    .partition(|p| p.nar_size < PACK_THRESHOLD);

// Upload pack in one POST (all .drv files + small sources)
if !packable.is_empty() {
    upload_pack(&client, &packable).await?;
}

// Upload large sources in parallel PUTs (with resume)
futures::future::join_all(
    individual.iter().map(|p| upload_path(&client, p))
).await;
```

### 4.4.9 Capability Negotiation

Borrowing from git protocol v2, client and server advertise supported features
during the initial handshake. This enables forward-compatible protocol evolution.

```
GET /:view/nix-cache-info

StoreDir: /var/lib/aos/store
WantMassQuery: 1
Priority: 30
Capabilities: pack-upload query-missing sse-logs content-range
```

**Defined capabilities**:

| Capability | Description |
|------------|-------------|
| `query-missing` | Server supports `POST /:view/query-missing` batch endpoint |
| `pack-upload` | Server accepts `POST /:view/upload-pack` bundled uploads |
| `content-range` | Server supports `Content-Range` for resumable uploads |
| `sse-logs` | Server streams build logs via Server-Sent Events |
| `zstd` | Server accepts/serves zstd-compressed NARs |
| `xz` | Server accepts/serves xz-compressed NARs |

**Client behavior**: the `aos build --remote` client reads capabilities from
`nix-cache-info` before choosing its upload strategy. If `pack-upload` is
absent, fall back to individual PUTs. If `content-range` is absent, don't
attempt resume. This allows older servers to work with newer clients.

**Future capabilities** (not implemented in v1):
- `delta-drv`: server accepts delta-compressed .drv packs (like git's
  `OFS_DELTA` -- .drv files that differ by one input hash can be expressed
  as a delta from a base .drv, saving ~80% of .drv transfer size)
- `negotiate-v2`: multi-round negotiation for large closures (like git's
  multi_ack -- client sends "have" batches starting from top-level .drv,
  server ACKs common ancestors, client stops expanding already-common subtrees)

These are listed as future because .drv files are already small (a few KB each)
