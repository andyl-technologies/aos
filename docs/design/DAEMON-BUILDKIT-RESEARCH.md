# BuildKit LLB Internals Research

Research report for the `aos daemon` architecture design. Covers BuildKit's LLB
graph format, gRPC APIs, solver mechanics, MergeOp/DiffOp, worker configuration,
progress streaming, cancellation, and existing Rust ecosystem.

---

## 1. LLB Protobuf Definitions

The LLB (Low-Level Build) format is BuildKit's intermediate representation — a
content-addressable DAG of filesystem operations serialized as Protocol Buffer
messages. The canonical definition lives in
[`solver/pb/ops.proto`](https://github.com/moby/buildkit/blob/master/solver/pb/ops.proto).

### Core Messages

**`Op`** — a single vertex in the LLB DAG:
```protobuf
message Op {
  repeated Input inputs = 1;
  oneof op {
    ExecOp   exec   = 2;
    SourceOp source = 3;
    FileOp   file   = 4;
    BuildOp  build  = 5;
    MergeOp  merge  = 6;
    DiffOp   diff   = 7;
  }
  Platform          platform    = 10;
  WorkerConstraints constraints = 11;
}
```

**`Input`** — an edge connecting two ops:
```protobuf
message Input {
  string digest = 1;  // marshaled digest of the input Op
  int64  index  = 2;  // output index of the input Op
}
```

**`Definition`** — the complete serialized graph:
```protobuf
message Definition {
  repeated bytes                  def      = 1;  // marshaled Op messages
  map<string, OpMetadata>         metadata = 2;
  Source                          Source   = 3;
}
```

The `def` field is a list of protobuf-marshaled `Op` messages. Each Op is
identified by the content-hash (digest) of its marshaled bytes. The graph is
implicit: each `Input.digest` references the digest of another Op in the list.
The *last* entry is the terminal (root) vertex.

### Operation Types

| Op | Purpose | Key Fields |
|----|---------|-----------|
| `SourceOp` | Pull images, git repos, local context, HTTP URLs | `identifier` (e.g. `docker-image://alpine`), `attrs` map |
| `ExecOp` | Run a command in a container | `Meta` (args, env, cwd, user), `mounts[]`, `network`, `security` |
| `FileOp` | Copy, mkdir, mkfile, rm, symlink | `actions[]` — each a `FileAction` with `oneof` |
| `MergeOp` | Layer multiple filesystem states | `inputs[]` — `MergeInput` messages |
| `DiffOp` | Extract changes between two states | `lower`, `upper` |
| `BuildOp` | Nested sub-build (experimental) | `def`, `inputs`, `attrs` |

**`Mount`** (used by ExecOp):
```protobuf
message Mount {
  int64       input    = 1;  // input index (-1 = scratch)
  string      selector = 2;  // sub-path within input
  string      dest     = 3;  // mount point in container
  int64       output   = 4;  // output index (-1 = no output)
  bool        readonly = 5;
  MountType   mountType = 6; // BIND, SECRET, SSH, CACHE, TMPFS
  TmpfsOpt    tmpfsOpt  = 19;
  CacheOpt    cacheOpt  = 20;
  SecretOpt   secretOpt = 21;
  SSHOpt      sshOpt    = 22;
}
```

**`Platform`**:
```protobuf
message Platform {
  string Architecture = 1;
  string OS           = 2;
  string Variant      = 3;
  string OSVersion    = 4;
  repeated string OSFeatures = 5;
}
```

### How to Construct LLB from Non-Go Languages

Since LLB is just protobuf, any language with protobuf support can construct and
serialize LLB graphs:

1. **Generate code** from `solver/pb/ops.proto` (and dependencies like
   `github.com/opencontainers/go-digest`)
2. **Build Op messages** programmatically — each Op becomes a vertex
3. **Marshal each Op** to bytes and compute its SHA256 digest
4. **Wire inputs** by setting `Input.digest` to the digest of referenced Ops
5. **Collect all marshaled bytes** into a `Definition.def` list (terminal Op last)
6. **Submit** the Definition via the Control.Solve gRPC RPC

The Go `client/llb` package provides a high-level chainable `State` API that
does all of this under the hood, but the wire format is language-agnostic.

---

## 2. The Control gRPC API (Control Service)

The buildkitd daemon exposes a gRPC service at
[`api/services/control/control.proto`](https://github.com/moby/buildkit/blob/master/api/services/control/control.proto).

### Service Definition

```protobuf
service Control {
  rpc DiskUsage(DiskUsageRequest)         returns (DiskUsageResponse);
  rpc Prune(PruneRequest)                 returns (stream UsageRecord);
  rpc Solve(SolveRequest)                 returns (SolveResponse);
  rpc Status(StatusRequest)               returns (stream StatusResponse);
  rpc Session(stream BytesMessage)        returns (stream BytesMessage);
  rpc ListWorkers(ListWorkersRequest)     returns (ListWorkersResponse);
  rpc Info(InfoRequest)                   returns (InfoResponse);
  rpc ListenBuildHistory(BuildHistoryRequest) returns (stream BuildHistoryEvent);
  rpc UpdateBuildHistory(UpdateBuildHistoryRequest) returns (UpdateBuildHistoryResponse);
}
```

### Solve RPC

**`SolveRequest`**:
```
Ref             string              // unique build reference (for Status queries)
Definition      pb.Definition       // the LLB graph (nil if Frontend is set)
Exporter        string              // deprecated, use Exporters[]
ExporterAttrs   map<string,string>  // deprecated
Session         string              // session ID for file sync/auth
Frontend        string              // e.g. "dockerfile.v0", "gateway.v0"
FrontendAttrs   map<string,string>  // frontend-specific config
FrontendInputs  map<string,pb.Definition>  // named input definitions
Cache           CacheOptions        // import/export cache config
Entitlements    []string            // security entitlements
Internal        bool                // if true, not recorded in history
SourcePolicy    *SourcePolicy       // source access policy
Exporters       []Exporter          // output destinations
```

When `Definition` is set, the daemon solves the LLB graph directly. When
`Frontend` is set instead, the daemon invokes that frontend (e.g. the Dockerfile
parser) which internally produces LLB and calls the gateway's Solve.

**`SolveResponse`**:
```
ExporterResponse  map<string,string>  // exporter-specific outputs
```

### Submitting a Build (Go Client Flow)

In Go, the `Client.Solve()` method orchestrates:

```go
func (c *Client) Solve(
    ctx context.Context,
    def *llb.Definition,
    opt SolveOpt,
    statusChan chan *SolveStatus,
) (*SolveResponse, error)
```

**SolveOpt** fields:
- `Exports` — output destinations (image push, local tar, etc.)
- `LocalDirs` / `LocalMounts` — filesystem access for Local() sources
- `Frontend` / `FrontendAttrs` / `FrontendInputs` — frontend config
- `CacheExports` / `CacheImports` — cache management
- `Session` — attachable session handlers (file sync, auth, secrets)
- `AllowedEntitlements` — security permissions

The client spawns three concurrent goroutines:
1. **Solve request** — sends the SolveRequest to `Control.Solve`
2. **Status stream** — reads from `Control.Status` and forwards to `statusChan`
3. **Gateway callback** — optional, for frontend-mode builds

Validation: either `Definition` or `Frontend` must be set, never both.

---

## 3. How Solve() Works Internally

When buildkitd receives a Solve request:

1. **Deserialization** — The `Definition.def` bytes are unmarshaled into Op messages
2. **DAG reconstruction** — Ops are wired into a vertex graph by matching digest references
3. **Vertex merging** — Duplicate sub-graphs (same digest) are deduplicated
4. **Cache lookup** — Each vertex is checked against the content-addressable cache
5. **Scheduling** — Uncached vertices are scheduled for execution respecting dependency order
6. **Parallel execution** — Independent vertices execute concurrently on workers
7. **Snapshotting** — Results are stored as snapshotter snapshots (overlay, native, etc.)
8. **Export** — Terminal vertex result is exported per the Exporter config

The solver uses a **pull-based** model: it starts at the terminal vertex and
recursively resolves dependencies, caching intermediate results.

---

## 4. MergeOp — Merging Multiple Inputs

### Semantics

`MergeOp` takes N input states and layers them sequentially:
- Files from later inputs override files from earlier inputs
- When both inputs have a directory at the same path, contents are merged recursively
- Non-directory conflicts are resolved in favor of the later input

Properties:
- **Associative**: `Merge(A, B, C) == Merge(Merge(A, B), C)`
- **Not commutative**: order matters
- **Layer-independent**: cache invalidation of one input doesn't cascade to others

### Image Export

When exported as a container image, MergeOp's result consists of all layers
from each input concatenated in order. This is a key optimization: if some
layers are already pushed to a registry, they don't need re-upload.

### Implementation Details

On **overlay-based snapshotters** (the common case):
- MergeOp joins the `lowerdir` entries from each input's snapshot into a single
  overlay mount — no data copy needed
- Hardlinks from underlying lowerdirs are used instead of copies
- This is a metadata-only operation, making it extremely fast

On **native snapshotters** (no overlay):
- Files are hardlinked from source snapshots into the merged snapshot
- Falls back to copy if hardlinking fails (cross-device)

### LLB Construction

```go
// Go API
merged := llb.Merge([]llb.State{base, overlay1, overlay2})
```

In protobuf:
```protobuf
message MergeOp {
  repeated MergeInput inputs = 1;
}
message MergeInput {
  int64 input = 1;  // index into parent Op.inputs[]
}
```

### Use Cases for AOS

MergeOp is directly relevant for combining multiple Nix store paths into a
single filesystem. Each derivation output could be a separate LLB state, and
MergeOp can combine them without copying — matching how Nix store paths are
composed in the final system.

---

## 5. DiffOp — Extracting Changes

`DiffOp` computes the difference between two states:

```
Diff(lower, upper) = the changes needed to go from lower to upper
```

If you apply `Diff(A, B)` on top of `A`, you get `B`.

Changes are detected by comparing content, permissions, and mtime (not
atime/ctime). When `lower` is in `upper`'s history chain, DiffOp can reuse
intermediate layers directly rather than computing a full diff.

Together, Merge + Diff enable:
- **Rebasing**: apply changes from one build on top of a different base
- **DESTDIR-free packaging**: build in one state, diff against empty to extract
  just the installed files
- **Efficient layer reuse**: break apart and recombine image layers

---

## 6. The Gateway / Frontend Protocol

The gateway protocol is defined in
[`frontend/gateway/pb/gateway.proto`](https://github.com/moby/buildkit/blob/master/frontend/gateway/pb/gateway.proto).

### LLBBridge Service

```protobuf
service LLBBridge {
  rpc ResolveImageConfig(...)  returns (ResolveImageConfigResponse);
  rpc ResolveSourceMeta(...)   returns (ResolveSourceMetaResponse);
  rpc Solve(SolveRequest)      returns (SolveResponse);
  rpc ReadFile(...)            returns (ReadFileResponse);
  rpc ReadDir(...)             returns (ReadDirResponse);
  rpc StatFile(...)            returns (StatFileResponse);
  rpc Evaluate(...)            returns (EvaluateResponse);
  rpc Ping(...)                returns (PongResponse);
  rpc Return(...)              returns (ReturnResponse);
  rpc Inputs(...)              returns (InputsResponse);
  rpc NewContainer(...)        returns (NewContainerResponse);
  rpc ReleaseContainer(...)    returns (ReleaseContainerResponse);
  rpc ExecProcess(...)         returns (stream ExecMessage);
  rpc Warn(...)                returns (WarnResponse);
}
```

Frontends run *inside* buildkitd and communicate via this bridge. A frontend:
1. Receives the build context (Dockerfile, local files) via `Inputs()`
2. Constructs an LLB Definition
3. Calls `Solve()` to execute it
4. Returns the result via `Return()`

The `gateway.v0` frontend allows using any container image as a frontend.

For AOS, we would **not** use the gateway/frontend protocol — we'd construct LLB
directly and submit via `Control.Solve`.

---

## 7. Worker Configuration

### Worker Types

BuildKit supports two worker backends:

| Worker | Runtime | Default |
|--------|---------|---------|
| OCI worker | runc (or compatible) | Yes |
| containerd worker | containerd daemon | No |

### Configuration (buildkitd.toml)

```toml
[worker.oci]
  enabled = true
  platforms = ["linux/amd64", "linux/arm64"]
  max-parallelism = 4
  snapshotter = "auto"     # overlay, native, stargz
  gc = true

  [[worker.oci.gcpolicy]]
    keepBytes = 10737418240   # 10 GB
    keepDuration = 604800     # 7 days

[worker.containerd]
  enabled = false
  namespace = "buildkit"
```

### Remote Workers

Remote buildkitd instances are accessed via:
- **Unix socket**: `unix:///run/buildkit/buildkitd.sock` (default)
- **TCP**: `tcp://host:1234` (requires TLS in production)
- **Docker container**: `docker-container://container-name`
- **Kubernetes pod**: `kube-pod://pod-name`

Docker buildx manages remote workers:
```bash
docker buildx create --name mybuilder --driver remote tcp://build-host:1234 \
  --driver-opt cacert=/path/ca.pem,cert=/path/cert.pem,key=/path/key.pem
```

Multiple workers can be added to a single builder for multi-platform builds,
where buildx routes platform-specific builds to the appropriate worker.

### WorkerRecord (from ListWorkers)

```protobuf
message WorkerRecord {
  string                   ID        = 1;
  map<string, string>      Labels    = 2;
  repeated Platform        platforms = 3;
  repeated GCPolicy        GCPolicy  = 4;
  BuildkitVersion          BuildkitVersion = 5;
}
```

---

## 8. StatusResponse — Progress Streaming

The `Control.Status` RPC is a **server-streaming** call that delivers real-time
build progress.

### Request/Response

```protobuf
rpc Status(StatusRequest) returns (stream StatusResponse);

message StatusRequest {
  string Ref = 1;  // build reference from SolveRequest.Ref
}

message StatusResponse {
  repeated Vertex       vertexes = 1;
  repeated VertexStatus statuses = 2;
  repeated VertexLog    logs     = 3;
  repeated VertexWarning warnings = 4;
}
```

### Vertex (build step state)

```go
type Vertex struct {
    Digest        digest.Digest   // unique Op identifier
    Inputs        []digest.Digest // dependencies
    Name          string          // human-readable label
    Started       *time.Time
    Completed     *time.Time
    Cached        bool
    Error         string
    ProgressGroup *pb.ProgressGroup
}
```

### VertexStatus (progress within a step)

```go
type VertexStatus struct {
    ID        string          // unique status ID
    Vertex    digest.Digest   // parent vertex
    Name      string          // what's happening (e.g. "downloading layer")
    Total     int64           // total work units
    Current   int64           // completed work units
    Timestamp time.Time
    Started   *time.Time
    Completed *time.Time
}
```

### VertexLog (output from a step)

```go
type VertexLog struct {
    Vertex    digest.Digest
    Stream    int       // 1=stdout, 2=stderr
    Data      []byte    // log content
    Timestamp time.Time
}
```

### Streaming Pattern

The client opens a Status stream with the build's `Ref` and receives a
continuous stream of StatusResponse messages. Each message contains incremental
updates — new vertices appearing, vertices starting/completing, progress ticks,
and log lines.

The Go client uses a 5-second inactivity timeout after the Solve completes to
drain final status messages before closing the stream.

For a Rust client, this maps to a `tonic::Streaming<StatusResponse>` that yields
items until the server closes the stream or the client drops it.

---

## 9. Build Cancellation

### Mechanism

BuildKit uses **gRPC context cancellation** — the standard gRPC pattern:

1. Client cancels the gRPC call context (in Go: `cancel()` on the context;
   in Rust/tonic: drop the response future or cancel the tokio task)
2. The gRPC framework sends a `RST_STREAM` or `GOAWAY` to the server
3. Server detects context cancellation and propagates it through the solver
4. Running operations receive cancellation and clean up

### Important Details

- Canceling the **Solve** RPC cancels the build
- The **Status** stream should NOT be wired to the same cancellation context as
  the build — it needs to outlive the build to drain final status messages
  ([moby/moby#37597](https://github.com/moby/moby/pull/37597))
- Some long-running operations (git clone, large downloads) may not respond
  immediately to cancellation ([moby/buildkit#740](https://github.com/moby/buildkit/issues/740))
- The error code returned is `codes.Canceled`

### In Rust/tonic

```rust
// Start the build
let response = client.solve(request).await?;

// Cancel by dropping or aborting the task
task_handle.abort(); // sends cancellation to server
```

Or use `tokio_util::sync::CancellationToken` for structured cancellation across
the Solve call and Status stream.

---

## 10. Docker buildx LLB Construction

### Architecture

Docker buildx is a CLI plugin that:
1. Parses the Dockerfile using the `dockerfile.v0` frontend
2. Manages buildkitd instances (local, remote, docker-container, kubernetes)
3. Submits builds via the BuildKit client library
4. Handles multi-platform builds by routing to platform-specific workers

### LLB Construction Flow

```
Dockerfile -> buildx -> buildkitd -> Dockerfile frontend -> LLB DAG -> Solver -> Image
```

Specifically:
1. `buildx build` connects to a buildkitd instance
2. Sends the build context + Dockerfile via the Session protocol
3. Specifies `Frontend: "dockerfile.v0"` in the SolveRequest
4. The frontend (running inside buildkitd) parses the Dockerfile:
   - `FROM` → `SourceOp` (docker-image://)
   - `RUN` → `ExecOp` with mounts
   - `COPY` → `FileOp` (copy action)
   - `WORKDIR` → `FileOp` (mkdir action)
   - Multi-stage: separate DAG branches merged at the end
5. Frontend returns the LLB Definition to the solver
6. Solver executes the DAG and exports the result

### Alternative: Direct LLB Submission

buildx can also submit pre-built LLB directly (without a frontend):

```bash
# Generate LLB from a custom tool
my-llb-generator | buildctl build --no-cache
```

This is the pattern AOS would use: construct LLB programmatically in Rust and
submit via `Control.Solve` with a Definition (no frontend).

---

## 11. Existing Rust Ecosystem

### buildkit-client (crates.io)

- **Version**: 0.1.4 (Nov 2025)
- **Features**: Complete gRPC client, session protocol, progress streaming,
  auth, cache management
- **Dependencies**: tonic 0.12, prost 0.13, tokio, h2
- **Maturity**: Actively maintained, implements full session protocol
- **Relevance**: Could be used directly or as reference for the AOS daemon

### rust-buildkit (denzp)

Three crates:
- **buildkit-llb** (0.2.0) — high-level LLB construction API
- **buildkit-frontend** — utilities for writing BuildKit frontends in Rust
- **buildkit-proto** (0.2.0) — generated protobuf types from BuildKit protos
- **Maturity**: Older (prost 0.6), but demonstrates the pattern
- **Relevance**: Shows how to construct LLB graphs in idiomatic Rust

### buildkit-rs (cicadahq)

- Newer crate from the Cicada CI project
- Modules: `llb` (exec, state, platform), `op_metadata`
- 100% documented
- Uses tonic for gRPC

### Key Protobuf Files to Generate From

For a Rust client, generate tonic/prost code from:
1. `solver/pb/ops.proto` — LLB operations (Op, ExecOp, MergeOp, etc.)
2. `api/services/control/control.proto` — Control service (Solve, Status, etc.)
3. `api/types/worker.proto` — Worker types
4. `frontend/gateway/pb/gateway.proto` — (only if implementing a frontend)

---

## 12. Implications for AOS Daemon

### LLB as Build Representation

Each Nix derivation can map to an LLB subgraph:
- **Fetch source** → `SourceOp` (HTTP source with content hash)
- **Build phases** → `ExecOp` (configure, make, install in sequence)
- **Combine outputs** → `MergeOp` (merge multiple store paths)
- **Extract artifacts** → `DiffOp` (extract installed files from build root)

### Submitting to Remote buildkitd

The AOS daemon would:
1. Evaluate Nix derivations to extract build instructions
2. Construct an LLB Definition (protobuf)
3. Connect to a remote buildkitd via gRPC (TCP + mTLS)
4. Call `Control.Solve` with the Definition
5. Stream progress via `Control.Status`
6. Handle cancellation by dropping the gRPC context

### Key Design Decisions

1. **Direct LLB vs Frontend**: Use direct LLB (no frontend) since we construct
   the graph ourselves from Nix derivations
2. **Session protocol**: Need it for sending local source files to buildkitd
   (Nix sources, patches, etc.)
3. **MergeOp for store paths**: Compose multiple derivation outputs into a
   system image using MergeOp
4. **Worker selection**: Use `ListWorkers` to discover available workers;
   platform constraints in `Op.constraints`
5. **Caching**: Content-addressable caching aligns well with Nix's
   content-addressed derivations
6. **Rust implementation**: Use tonic + prost, generate from upstream protos.
   Reference `buildkit-client` crate for session protocol implementation.

---

## Sources

- [ops.proto — LLB operations](https://github.com/moby/buildkit/blob/master/solver/pb/ops.proto)
- [control.proto — Control service](https://github.com/moby/buildkit/blob/master/api/services/control/control.proto)
- [gateway.proto — Frontend/Gateway service](https://github.com/moby/buildkit/blob/master/frontend/gateway/pb/gateway.proto)
- [merge-diff.md — MergeOp/DiffOp design doc](https://github.com/moby/buildkit/blob/master/docs/dev/merge-diff.md)
- [MergeOp PR #2335](https://github.com/moby/buildkit/pull/2335)
- [DiffOp PR #2434](https://github.com/moby/buildkit/pull/2434)
- [MergeOp issue #1431](https://github.com/moby/buildkit/issues/1431)
- [Merge+Diff blog post](https://www.docker.com/blog/mergediff-building-dags-more-efficiently-and-elegantly/)
- [BuildKit in depth (Depot)](https://depot.dev/blog/buildkit-in-depth)
- [client/llb Go package](https://pkg.go.dev/github.com/moby/buildkit/client/llb)
- [client/solve.go](https://github.com/moby/buildkit/blob/master/client/solve.go)
- [client/graph.go — Vertex types](https://github.com/moby/buildkit/blob/master/client/graph.go)
- [buildkit-client Rust crate](https://crates.io/crates/buildkit-client)
- [rust-buildkit (denzp)](https://github.com/denzp/rust-buildkit)
- [buildkit-rs (cicadahq)](https://github.com/cicadahq/buildkit-rs)
- [Remote driver docs](https://docs.docker.com/build/builders/drivers/remote/)
- [gRPC cancellation docs](https://grpc.io/docs/guides/cancellation/)
- [moby/moby#37597 — Status stream cancellation fix](https://github.com/moby/moby/pull/37597)
- [moby/buildkit#740 — Git operation cancellation](https://github.com/moby/buildkit/issues/740)
