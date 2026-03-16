# Store Fetch

The `/aos/store/fetch/1.0.0` stream protocol requests a daemon to download a
content-addressed store object from upstream URLs (mirrors). This is how FODs
(fixed-output derivations) — source tarballs, flake inputs — enter the
network. The client provides URLs and an expected content hash; the daemon
downloads, verifies, chunks, and publishes the object.

## Stream Protocol

```
Client → Server:  StoreFetchRequest { urls, hash, requested_ttl }
Server → Client:  stream of StoreFetchStatus { progress or complete or error }
```

The daemon streams progress updates back to the client as the download
proceeds (bytes downloaded, current speed, current mirror). The final message
is either success (with the store hash and pin expiry) or failure.

### Discovery

Nodes accepting fetch requests advertise themselves on the DHT key
`aos:store:fetch` as a provider record with a short TTL (1 min). Clients call
`get_providers` on this key to discover fetch-capable nodes.

### Daemon Configuration

Fetch configuration is per-cluster under `clusters.<name>.fetch`:

```toml
[clusters.prod.fetch]
accept_remote = false              # accept /aos/store/fetch/1.0.0
max_download_size = "10Gi"         # max download size per fetch
pin_ttl_min = "1h"
pin_ttl_max = "7d"
pin_ttl_default = "24h"

# Connection limits
max_connections_global = 64        # max concurrent HTTP connections total
max_connections_per_domain = 6     # max concurrent connections per domain
connection_timeout = "10s"
request_timeout = "5m"             # per request ("0s" = no limit)

# Bandwidth limits (multiple windows supported)
[[clusters.prod.fetch.bandwidth_limits]]
limit = "1Gi"
window = "1s"

[[clusters.prod.fetch.bandwidth_limits]]
limit = "100Mi"
window = "1m"

# Domain filtering
allowed_domains = []               # empty = allow all
blocked_domains = []               # blocked even if in allowed

# Retries
max_retries_per_mirror = 3
max_mirror_failures = 0            # 0 = try all mirrors before giving up
```

## FetchSpec Jobs

Fetches are now job types (`FetchSpec`) that go through the normal job
claim/start/exit lifecycle defined in [jobs.md](jobs.md). A `FetchSpec` job
contains the URLs, expected content hash, and fetch parameters. The daemon that
claims the job executes it using the fetch engine described below. This means
fetch operations benefit from the same load-staggered claiming, liveness
tracking, and crash recovery as build and run jobs.

## Fetch Engine Architecture

The fetch engine is the daemon-internal component that executes `FetchSpec`
jobs. It is also shared by:
- `/aos/store/fetch/1.0.0` stream protocol (remote fetch requests)
- Workflow `fetch` steps
- Any internal operation that needs to download from upstream

### Connection Manager

The connection manager maintains a pool of HTTP connections with:

- **Per-domain connection limits** (default 6, like browsers). Prevents
  overwhelming a single mirror.
- **Global connection limit** (default 64). Prevents file descriptor
  exhaustion.
- **Connection pooling with keep-alive.** HTTP/1.1 and HTTP/2 connections are
  reused across requests to the same domain. HTTP/3 (QUIC) connections are
  also pooled where supported.
- **Protocol negotiation.** The engine supports HTTP/1.1, HTTP/2, and HTTP/3.
  ALPN negotiation selects the best protocol. HTTP/2 and HTTP/3 enable
  multiplexing (multiple requests on one connection).

### Parallel Downloads

For servers that support HTTP Range requests, the engine splits large
downloads into parallel chunks:

```
File: 1 GB
  ├── Range: bytes=0-67108863          (64 MB, connection 1)
  ├── Range: bytes=67108864-134217727  (64 MB, connection 2)
  ├── Range: bytes=134217728-...       (64 MB, connection 3)
  └── ...
```

The engine probes Range support with a HEAD request. If the server responds
with `Accept-Ranges: bytes`, the download is parallelized. Otherwise, a single
sequential download is used.

Parallel range chunk size is adaptive: starts at 64 MB, adjusts based on
connection throughput (larger chunks for fast connections, smaller for slow).

### Mirror Failover

The fetch request includes a prioritized list of mirror URLs. The engine:

1. Starts with the first URL.
2. If the connection fails, times out, or the download is too slow (below
   `min_speed` threshold for `slow_timeout` seconds), fails over to the next
   URL.
3. For Range-capable servers, different ranges can be fetched from different
   mirrors simultaneously (multi-source download).
4. If a mirror returns data that doesn't match the expected hash (detected at
   the end of download), the mirror is blacklisted for this request and the
   next mirror is tried.
5. If all mirrors fail, the fetch fails with an error listing each mirror's
   failure reason.

```toml
[clusters.prod.fetch]
min_speed = "10Ki"                 # bytes/s below this = slow connection
slow_timeout = "30s"               # duration below min_speed before failover
```

### Slow Connection Detection

The engine monitors per-connection throughput using a sliding window (last 10
seconds). If throughput drops below `min_speed` for `slow_timeout` seconds:

1. The connection is marked as slow.
2. A new connection to the next mirror is opened.
3. Both connections continue (the slow one may recover).
4. Whichever finishes first wins; the other is cancelled.

This provides automatic failover without abandoning connections that may
recover (e.g., temporary network congestion).

### Request Deduplication

If two concurrent requests target the same content hash, the engine
deduplicates:

1. First request proceeds normally.
2. Second request is queued and waits for the first to complete.
3. When the first completes successfully, the second returns immediately
   (the object is already in the store).
4. If the first fails, the second retries independently.

Deduplication is keyed by the expected content hash, not the URL. Two
different URLs that produce the same content are deduplicated.

### Fetch Queue

When many fetch requests arrive simultaneously (e.g., a workflow with 100 FOD
steps), the engine queues them and processes up to `max_connections_global`
concurrently. The queue is priority-ordered:

1. Requests from active workflow steps (have a workflow_id).
2. Requests from stream protocol clients.
3. Background replication fetches.

Within each priority level, requests are ordered by submission time (FIFO).

### Progress Monitoring

Each active download reports progress to its caller:

```
StoreFetchProgress {
    bytes_total: uint64          // from Content-Length (0 if unknown)
    bytes_downloaded: uint64
    speed_bytes_per_sec: uint64  // current throughput
    current_mirror: string       // URL being downloaded from
    phase: FetchPhase            // CONNECTING, DOWNLOADING, CHUNKING, VERIFYING
}
```

For the stream protocol, these are sent as status messages. For workflow
steps, they feed into the step's progress tracking.

## Download-to-Store Pipeline

The download bytes flow through a streaming pipeline with no intermediate
temp file:

```
HTTP response stream
  → tee: SHA-256 hasher (computes NAR hash in parallel)
  → FastCDC chunker (64KB min, 256KB avg, 1MB max)
    → for each chunk:
        → xxh3-128 hash
        → zstd compress (if > 4KB)
        → dedup check against chunk_db
        → write to active pack file (if new)
        → record in chunk_db
```

### Why Stream Chunking

The download is chunked as bytes arrive, not after writing to a temp file:

- **No temp file.** A 10 GB download doesn't need 10 GB of scratch space.
  Data flows directly from the HTTP stream to pack files.
- **Memory-bounded.** Only the FastCDC sliding window (~1 MB) and compression
  buffers are in memory.
- **Immediate dedup.** Chunks are deduplicated as they're produced. If 80%
  of the content is already in the store (common for new versions of large
  tarballs), only 20% is written.
- **Progressive.** Chunks are available in the store as soon as they're
  written, even before the download completes.

### Hash Verification

The SHA-256 hasher runs in parallel with chunking (tee'd from the download
stream). After the final byte is received:

1. The hasher produces the content hash.
2. The content hash is compared against the expected hash from the request.
3. **If match:** the NixObject, tree/blob objects, and chunk trees are created,
   written to `store_db`, references scanned into `store_db` refs, provider record
   published to DHT, `StorePublish` sent to gossipsub. A time-limited pin
   is created in `gc.mdb`.
4. **If mismatch:** the chunks are orphaned (no NixObject references them).
   They'll be cleaned up by the next GC mark-and-sweep cycle. An error is
   returned to the client with the expected vs actual hash.

The orphaned-chunk approach avoids needing a rollback mechanism. The chunks
are harmless dead space until GC runs.

## Domain Filtering and Authentication

### Domain Filtering

The fetch engine can restrict which domains are accessible:

```toml
[clusters.prod.fetch]
allowed_domains = ["ftp.gnu.org", "*.kernel.org", "github.com"]
blocked_domains = ["malicious.example.com"]
```

If `allowed_domains` is non-empty, only URLs matching an allowed domain are
fetched. `blocked_domains` overrides `allowed_domains` (a domain in both
lists is blocked). Glob patterns are supported.

### Authentication

Some mirrors require authentication (e.g., GitHub release assets for private
repos, S3 buckets). The fetch engine integrates with the daemon's identity
manager for credentials:

```toml
[[clusters.prod.fetch.credentials]]
domain = "github.com"
type = "bearer"                    # bearer, basic, aws-sigv4
source = "keystore"                # keystore, env, file, instance-metadata
key = "github-token"               # key name in the identity manager
```

The identity manager is a shared component used by both the fetch engine and
the enrollment system. It supports multiple credential sources:

| Source | Description |
|---|---|
| `keystore` | From the daemon's key store (see [enrollment.md](enrollment.md)) |
| `env` | Environment variable |
| `file` | File on disk (e.g., `/etc/aos/tokens/github`) |
| `instance-metadata` | Cloud provider instance metadata / IAM role |

See [identity.md](identity.md) for the unified identity management model.

---

## Protocol

```protobuf
// Stream protocol: /aos/store/fetch/1.0.0
// Request a daemon to download a FOD from upstream URLs. The daemon
// creates a FetchSpec job internally, downloads the content, verifies
// the hash, chunks it, and publishes the store object. Content-addressed
// only. Client disconnect = cancel the fetch job.
message StoreFetchRequest {
    repeated string urls = 1;       // mirror URLs (priority order)
    string hash = 2;                // expected content hash (SRI format)
    uint64 requested_ttl = 3;      // pin TTL (microseconds, 0 = server default)
}

// Streamed back to the client during the fetch. Multiple progress
// messages followed by a terminal success or failure.
message StoreFetchStatus {
    oneof status {
        StoreFetchProgress progress = 1; // intermediate download progress
        StoreFetchSuccess success = 2;   // terminal: object stored and published
        StreamError failed = 3;          // terminal: fetch failed
    }
}

// Download progress update.
message StoreFetchProgress {
    StoreFetchPhase phase = 1;      // current phase of the fetch
    uint64 bytes_total = 2;         // from Content-Length (0 if unknown)
    uint64 bytes_downloaded = 3;    // bytes received so far
    uint64 speed_bytes_per_sec = 4; // current download throughput
    string current_mirror = 5;      // URL currently being downloaded from
    string message = 6;             // human-readable status
}

enum StoreFetchPhase {
    FETCH_CONNECTING = 0;           // establishing connection to mirror
    FETCH_DOWNLOADING = 1;          // downloading content
    FETCH_CHUNKING = 2;             // applying FastCDC and writing to pack files
    FETCH_VERIFYING = 3;            // verifying content hash
}

message StoreFetchSuccess {
    string store_hash = 1;          // content address of the fetched object
    uint64 pin_expires_at = 2;      // epoch microseconds when the pin expires
}
```

## Relationship to Other Docs

- [protocol.md](protocol.md) -- `StoreFetchRequest`, `StoreFetchStatus`
  protobuf definitions.
- [store-upload.md](store-upload.md) -- upload protocol (client pushes content).
- [store.md](store.md) -- store transfer protocol (peer-to-peer resolve + chunk
  fetch).
- [storage.md](storage.md) -- pack files, chunking, store_db.
- [workflow-spec.md](workflow-spec.md) -- workflow `fetch` source type uses the
  fetch engine.
- [daemon.md](daemon.md) -- `[clusters.<name>.fetch]` configuration.
- [jobs.md](jobs.md) -- `FetchSpec` job lifecycle (claim, start, exit).
- [identity.md](identity.md) -- unified credential management.
