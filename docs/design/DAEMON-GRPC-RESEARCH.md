# gRPC Server/Client Patterns in Rust with Tonic

Research for the `aos` daemon architecture. Covers tonic crate patterns, proto
design for a build service, streaming, cancellation, UDS/TCP transport, and
reference proto designs from BuildKit and containerd.

---

## Table of Contents

1. [Tonic Crate Overview](#1-tonic-crate-overview)
2. [Server and Client Implementation Patterns](#2-server-and-client-implementation-patterns)
3. [Proto File Design for a Build Service](#3-proto-file-design-for-a-build-service)
4. [Server-Streaming RPC for Build Progress](#4-server-streaming-rpc-for-build-progress)
5. [Detecting Client Disconnection and Cancelling Work](#5-detecting-client-disconnection-and-cancelling-work)
6. [Unix Domain Socket Support](#6-unix-domain-socket-support)
7. [TCP Listeners with Optional TLS/mTLS](#7-tcp-listeners-with-optional-tlsmtls)
8. [Tokio Integration](#8-tokio-integration)
9. [Proto Message Design for Build Service](#9-proto-message-design-for-build-service)
10. [Reference Proto Designs](#10-reference-proto-designs)
11. [Proto File Organization and Build Setup](#11-proto-file-organization-and-build-setup)
12. [Recommended Architecture for aos Daemon](#12-recommended-architecture-for-aos-daemon)

---

## 1. Tonic Crate Overview

Tonic is the de facto gRPC library for Rust. It provides a native async gRPC
implementation built on top of three components:

- **hyper** -- HTTP/2 transport layer
- **tower** -- middleware/service abstraction layer
- **prost** -- Protocol Buffers code generation

### Key Crates

| Crate              | Purpose                                      |
|--------------------|----------------------------------------------|
| `tonic`            | Core gRPC server and client runtime          |
| `tonic-build`      | Code generation from `.proto` files           |
| `tonic-health`     | Standard gRPC health checking service         |
| `tonic-reflection` | gRPC reflection for service discovery         |
| `tonic-web`        | gRPC-Web support (browser clients)            |
| `prost`            | Protobuf message serialization               |
| `prost-types`      | Well-known protobuf types (Timestamp, etc.)   |

### Feature Flags

Tonic requires feature flags to enable transport:
- `transport` -- enables the built-in HTTP/2 transport (Server, Channel)
- `tls` -- enables TLS via rustls
- `channel` -- client transport
- `server` -- server transport

### Version Compatibility

As of early 2026, tonic 0.12+ is the current stable line. It targets
hyper 1.x and tower 0.4+. The `tonic-build` version should match the
`tonic` version.

---

## 2. Server and Client Implementation Patterns

### Server Pattern

Tonic generates a trait from each `service` definition in a `.proto` file.
The server implements this trait:

```rust
// Generated trait (simplified)
#[tonic::async_trait]
pub trait BuildService: Send + Sync + 'static {
    type BuildStream: Stream<Item = Result<BuildEvent, Status>> + Send + 'static;

    async fn build(
        &self,
        request: Request<BuildRequest>,
    ) -> Result<Response<Self::BuildStream>, Status>;
}
```

Implementation:

```rust
pub struct BuildServer {
    // Internal state: build queue, store connection, etc.
    build_queue: Arc<BuildQueue>,
}

#[tonic::async_trait]
impl BuildService for BuildServer {
    type BuildStream = Pin<Box<dyn Stream<Item = Result<BuildEvent, Status>> + Send>>;

    async fn build(
        &self,
        request: Request<BuildRequest>,
    ) -> Result<Response<Self::BuildStream>, Status> {
        let req = request.into_inner();
        let (tx, rx) = mpsc::channel(32);

        // Spawn the actual build work
        let queue = self.build_queue.clone();
        tokio::spawn(async move {
            queue.execute(req, tx).await;
        });

        let stream = ReceiverStream::new(rx);
        Ok(Response::new(Box::pin(stream) as Self::BuildStream))
    }
}
```

Server startup:

```rust
Server::builder()
    .add_service(BuildServiceServer::new(build_server))
    .add_service(tonic_health::server::health_reporter().0)
    .add_service(tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
        .build()?)
    .serve(addr)
    .await?;
```

### Client Pattern

```rust
let channel = Channel::from_static("http://[::1]:50051")
    .connect()
    .await?;

let mut client = BuildServiceClient::new(channel);

let request = tonic::Request::new(BuildRequest {
    derivation_path: "/nix/store/abc-foo.drv".into(),
    ..Default::default()
});

let mut stream = client.build(request).await?.into_inner();

while let Some(event) = stream.next().await {
    match event? {
        // Handle build events...
    }
}
```

### Interceptors (Middleware)

Tonic supports lightweight interceptors for auth, logging, tracing:

```rust
fn auth_interceptor(req: Request<()>) -> Result<Request<()>, Status> {
    let token = req.metadata()
        .get("authorization")
        .ok_or_else(|| Status::unauthenticated("No token"))?;
    // validate token...
    Ok(req)
}

// Apply to service
let svc = BuildServiceServer::with_interceptor(build_server, auth_interceptor);
```

### Tower Layers

For more sophisticated middleware, use tower layers:

```rust
Server::builder()
    .layer(tower::timeout::TimeoutLayer::new(Duration::from_secs(300)))
    .layer(tower::limit::ConcurrencyLimitLayer::new(64))
    .add_service(svc)
    .serve(addr)
    .await?;
```

---

## 3. Proto File Design for a Build Service

### Design Principles

1. **Use server-streaming for long-running builds** -- The client sends a
   single `BuildRequest` and receives a stream of `BuildEvent` messages.

2. **Envelope pattern for events** -- Use a `oneof` inside `BuildEvent` to
   multiplex different event types (progress, log, error, complete) over a
   single stream.

3. **Enum zero values** -- Every enum should have an `UNKNOWN = 0` sentinel.
   Prefix enum values with the enum name (e.g., `STATUS_UNKNOWN`).

4. **Timestamps** -- Use `google.protobuf.Timestamp` for all time fields.

5. **Opaque IDs** -- Use string IDs for build references, derivation paths,
   etc. Avoid embedding structured data in IDs.

6. **Error detail in messages, not just Status** -- Transport errors use gRPC
   `Status`, but build-level errors should be part of the event stream so
   clients can distinguish "the build failed" from "the RPC failed".

### Recommended Proto Structure

```
proto/
  aos/
    v1/
      build.proto      -- BuildService, BuildRequest, BuildEvent
      store.proto       -- StoreService (query store, GC)
      daemon.proto      -- DaemonService (health, info, shutdown)
      types.proto       -- Shared types (Derivation, StorePath, etc.)
```

---

## 4. Server-Streaming RPC for Build Progress

### The Pattern

```protobuf
service BuildService {
  // Start a build and stream progress events until completion.
  rpc Build(BuildRequest) returns (stream BuildEvent);
}
```

### Server Implementation with mpsc Channel

The canonical pattern uses a `tokio::sync::mpsc` channel to bridge between
the build execution logic and the gRPC stream:

```rust
type BuildStream = Pin<Box<dyn Stream<Item = Result<BuildEvent, Status>> + Send>>;

async fn build(
    &self,
    request: Request<BuildRequest>,
) -> Result<Response<Self::BuildStream>, Status> {
    let req = request.into_inner();
    let (tx, rx) = mpsc::channel(64);

    // Spawn build task
    tokio::spawn(async move {
        // Send progress events through tx
        for step in build_steps {
            let event = BuildEvent { /* ... */ };
            if tx.send(Ok(event)).await.is_err() {
                // Client disconnected
                break;
            }
        }
        // Send final completion event
        let _ = tx.send(Ok(BuildEvent::completed(result))).await;
    });

    let stream = ReceiverStream::new(rx);
    Ok(Response::new(Box::pin(stream)))
}
```

### Client Receiving Pattern

```rust
let mut stream = client.build(request).await?.into_inner();

while let Some(event) = stream.message().await? {
    match event.event {
        Some(Event::Progress(p)) => {
            println!("[{}/{}] {}", p.current, p.total, p.message);
        }
        Some(Event::Log(log)) => {
            print!("{}", log.output);
        }
        Some(Event::Completed(result)) => {
            println!("Build complete: {}", result.output_path);
            break;
        }
        Some(Event::Error(err)) => {
            eprintln!("Build error: {}", err.message);
            break;
        }
        None => {}
    }
}
```

### Key Considerations

- **Buffer size**: The mpsc channel buffer (e.g., 64) provides backpressure.
  If the client is slow to consume, the sender blocks when the buffer is full.
- **Completion signaling**: The stream ends naturally when `tx` is dropped
  (all senders gone). Send an explicit completion event before dropping.
- **Error propagation**: Build errors should be sent as `BuildEvent::Error`
  messages, not as gRPC `Status` errors. Reserve `Status` for transport and
  protocol errors.

---

## 5. Detecting Client Disconnection and Cancelling Work

This is critical for a build daemon -- if the client disconnects, we should
be able to cancel the in-flight build to free resources.

### Pattern 1: mpsc::Sender::send() Returns Err

When the client disconnects, the gRPC stream (and its underlying receiver)
is dropped. The `mpsc::Sender::send()` will return `Err`, which the build
task can use to detect disconnection:

```rust
tokio::spawn(async move {
    for step in build_steps {
        let event = BuildEvent { /* ... */ };
        if tx.send(Ok(event)).await.is_err() {
            // Client disconnected -- cancel build
            cancel_token.cancel();
            break;
        }
    }
});
```

### Pattern 2: CancellationToken + tokio::select!

The recommended approach uses `tokio_util::sync::CancellationToken` to
propagate cancellation to all child tasks:

```rust
use tokio_util::sync::CancellationToken;

async fn build(
    &self,
    request: Request<BuildRequest>,
) -> Result<Response<Self::BuildStream>, Status> {
    let cancel_token = CancellationToken::new();
    let (tx, rx) = mpsc::channel(64);

    // The drop guard cancels the token when the stream is dropped
    // (i.e., when the client disconnects)
    let _guard = cancel_token.clone().drop_guard();

    let child_token = cancel_token.child_token();
    tokio::spawn(async move {
        tokio::select! {
            _ = child_token.cancelled() => {
                // Client disconnected, clean up
                tracing::info!("Build cancelled by client");
            }
            result = execute_build(req, tx.clone()) => {
                match result {
                    Ok(output) => {
                        let _ = tx.send(Ok(BuildEvent::completed(output))).await;
                    }
                    Err(e) => {
                        let _ = tx.send(Ok(BuildEvent::error(e))).await;
                    }
                }
            }
        }
    });

    let stream = ReceiverStream::new(rx);
    Ok(Response::new(Box::pin(stream)))
}
```

### Pattern 3: Custom Drop-Detecting Stream Wrapper

For fine-grained control, wrap the receiver in a custom `Stream` that
detects when it's dropped:

```rust
pub struct DropDetectStream<T> {
    inner: mpsc::Receiver<T>,
    cancel_signal: oneshot::Sender<()>,
}

impl<T> Stream for DropDetectStream<T> {
    type Item = T;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(cx)
    }
}

impl<T> Drop for DropDetectStream<T> {
    fn drop(&mut self) {
        // Signal the build task that the client is gone
        // (oneshot::Sender::send consumed self, use take pattern)
    }
}
```

### Hierarchical Cancellation with child_token()

CancellationToken supports parent-child relationships. Cancelling a parent
cancels all children, but cancelling a child does not affect the parent.
This is ideal for a build daemon that runs multiple concurrent builds:

```rust
let daemon_token = CancellationToken::new();  // top-level

// Per-build tokens
let build_token = daemon_token.child_token();

// Per-step tokens within a build
let step_token = build_token.child_token();
```

When the daemon shuts down, `daemon_token.cancel()` cascades to all builds.
When a single client disconnects, only its `build_token` is cancelled.

---

## 6. Unix Domain Socket Support

UDS is the primary transport for a local build daemon (like Docker/BuildKit).

### Server Side

Tonic's `Server::builder()` can accept any `Stream` of connections via
`serve_with_incoming`:

```rust
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;

let sock_path = "/run/aos/aosd.sock";

// Clean up stale socket
let _ = std::fs::remove_file(sock_path);
std::fs::create_dir_all(Path::new(sock_path).parent().unwrap())?;

let uds = UnixListener::bind(sock_path)?;
let uds_stream = UnixListenerStream::new(uds);

Server::builder()
    .add_service(BuildServiceServer::new(build_server))
    .serve_with_incoming(uds_stream)
    .await?;
```

### Client Side

Clients connect using the `unix://` URI scheme:

```rust
// Standard approach (tonic 0.12+)
let channel = Endpoint::try_from("http://[::]:50051")?  // dummy URI
    .connect_with_connector(tower::service_fn(|_: Uri| {
        tokio::net::UnixStream::connect("/run/aos/aosd.sock")
    }))
    .await?;

// Or more simply with the unix:// scheme (if supported by version):
let channel = Channel::from_static("unix:///run/aos/aosd.sock")
    .connect()
    .await?;
```

### Connection Info

On Unix, tonic provides `UdsConnectInfo` for extracting peer credentials:

```rust
use tonic::transport::server::UdsConnectInfo;

async fn build(&self, request: Request<BuildRequest>) -> Result<...> {
    if let Some(info) = request.extensions().get::<UdsConnectInfo>() {
        // info.peer_cred -- uid, gid, pid of the caller
        // Useful for authorization decisions
    }
}
```

### Socket Permissions

For a build daemon, the socket should be:
- Owned by root or a `builders` group
- Mode 0660 or 0770
- Created after `serve_with_incoming` binds (or pre-created with correct perms)

---

## 7. TCP Listeners with Optional TLS/mTLS

For remote builder scenarios, the daemon should also support TCP with TLS.

### Plain TCP

```rust
let addr = "[::]:50051".parse()?;
Server::builder()
    .add_service(svc)
    .serve(addr)
    .await?;
```

### TLS (Server Authentication)

Tonic uses rustls for TLS:

```rust
use tonic::transport::{Identity, ServerTlsConfig};

let cert = std::fs::read_to_string("server.pem")?;
let key = std::fs::read_to_string("server.key")?;

let tls = ServerTlsConfig::new()
    .identity(Identity::from_pem(cert, key));

Server::builder()
    .tls_config(tls)?
    .add_service(svc)
    .serve(addr)
    .await?;
```

### mTLS (Mutual Authentication)

For mutual TLS, both server and client present certificates:

Server:
```rust
let ca_cert = Certificate::from_pem(std::fs::read_to_string("ca.pem")?);

let tls = ServerTlsConfig::new()
    .identity(Identity::from_pem(server_cert, server_key))
    .client_ca_root(ca_cert);  // Require client certificates
```

Client:
```rust
use tonic::transport::{Certificate, ClientTlsConfig, Identity};

let tls = ClientTlsConfig::new()
    .ca_certificate(Certificate::from_pem(ca_cert))
    .identity(Identity::from_pem(client_cert, client_key))
    .domain_name("aosd.example.com");

let channel = Channel::from_static("https://builder:50051")
    .tls_config(tls)?
    .connect()
    .await?;
```

### Dual Listener (UDS + TCP)

A production daemon should listen on both UDS (local) and TCP (remote):

```rust
let uds_server = Server::builder()
    .add_service(svc.clone())
    .serve_with_incoming(uds_stream);

let tcp_server = Server::builder()
    .tls_config(tls)?
    .add_service(svc)
    .serve(tcp_addr);

// Run both concurrently
tokio::select! {
    r = uds_server => r?,
    r = tcp_server => r?,
}
```

---

## 8. Tokio Integration

### Runtime Setup

The daemon should use a multi-threaded tokio runtime:

```rust
#[tokio::main]
async fn main() -> Result<()> {
    // Or for more control:
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(num_cpus::get())
        .enable_all()
        .build()?;

    runtime.block_on(async { run_daemon().await })
}
```

### Spawning Build Tasks

Each build should be a spawned task with its own cancellation scope:

```rust
let handle = tokio::spawn(async move {
    tokio::select! {
        result = execute_build(&drv, &progress_tx) => result,
        _ = cancel_token.cancelled() => {
            Err(BuildError::Cancelled)
        }
    }
});
```

### Graceful Shutdown

Use `tokio::signal` with `CancellationToken` for clean shutdown:

```rust
use tokio::signal;

let shutdown_token = CancellationToken::new();
let token = shutdown_token.clone();

tokio::spawn(async move {
    let ctrl_c = signal::ctrl_c();
    let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;

    tokio::select! {
        _ = ctrl_c => {}
        _ = sigterm.recv() => {}
    }

    tracing::info!("Shutdown signal received");
    token.cancel();
    Ok::<_, std::io::Error>(())
});

// In the server loop:
tokio::select! {
    r = server.serve_with_incoming(uds_stream) => r?,
    _ = shutdown_token.cancelled() => {
        tracing::info!("Shutting down gracefully");
        // Wait for in-flight builds to complete (with timeout)
        tokio::time::timeout(
            Duration::from_secs(30),
            wait_for_builds(&build_tracker),
        ).await.ok();
    }
}
```

### Concurrency Control

Limit concurrent builds with a `tokio::sync::Semaphore`:

```rust
let build_semaphore = Arc::new(Semaphore::new(max_concurrent_builds));

async fn build(&self, request: Request<BuildRequest>) -> Result<...> {
    let permit = self.build_semaphore.clone()
        .acquire_owned()
        .await
        .map_err(|_| Status::unavailable("Server shutting down"))?;

    tokio::spawn(async move {
        let _permit = permit;  // Released on drop
        execute_build(req).await
    });
}
```

---

## 9. Proto Message Design for Build Service

### Recommended Proto Messages

```protobuf
syntax = "proto3";

package aos.v1;

import "google/protobuf/timestamp.proto";

// ============================================================
// Build Service
// ============================================================

service BuildService {
  // Build a derivation and stream progress events.
  rpc Build(BuildRequest) returns (stream BuildEvent);

  // Query the status of a running or completed build.
  rpc GetBuild(GetBuildRequest) returns (BuildStatus);

  // List recent builds.
  rpc ListBuilds(ListBuildsRequest) returns (ListBuildsResponse);

  // Cancel a running build.
  rpc CancelBuild(CancelBuildRequest) returns (CancelBuildResponse);
}

// ============================================================
// Request / Response Messages
// ============================================================

message BuildRequest {
  // Nix expression or attribute path to build (e.g., "pkgs.hello")
  string target = 1;

  // Optional: pre-evaluated derivation store path
  string derivation_path = 2;

  // Build options
  BuildOptions options = 3;
}

message BuildOptions {
  // Maximum number of parallel build jobs
  int32 max_jobs = 1;

  // Keep going on build failures
  bool keep_going = 2;

  // Substituters to check before building
  repeated string substituters = 3;

  // Extra features required (e.g., "kvm")
  repeated string required_features = 4;
}

message GetBuildRequest {
  string build_id = 1;
}

message ListBuildsRequest {
  int32 limit = 1;
  string page_token = 2;
  BuildStateFilter state_filter = 3;
}

enum BuildStateFilter {
  BUILD_STATE_FILTER_UNKNOWN = 0;
  BUILD_STATE_FILTER_RUNNING = 1;
  BUILD_STATE_FILTER_COMPLETED = 2;
  BUILD_STATE_FILTER_FAILED = 3;
  BUILD_STATE_FILTER_ALL = 4;
}

message ListBuildsResponse {
  repeated BuildStatus builds = 1;
  string next_page_token = 2;
}

message CancelBuildRequest {
  string build_id = 1;
}

message CancelBuildResponse {}

// ============================================================
// Build Event (streamed from server)
// ============================================================

message BuildEvent {
  google.protobuf.Timestamp timestamp = 1;

  oneof event {
    BuildStarted started = 10;
    VertexStarted vertex_started = 11;
    VertexProgress vertex_progress = 12;
    VertexCompleted vertex_completed = 13;
    VertexLog vertex_log = 14;
    BuildCompleted completed = 15;
    BuildError error = 16;
  }
}

// Sent once at the beginning of a build.
message BuildStarted {
  string build_id = 1;
  // Total number of derivations to build
  int32 total_vertices = 2;
  // Human-readable description
  string description = 3;
}

// A single derivation/step has started building.
message VertexStarted {
  // Unique vertex ID (derivation hash)
  string vertex_id = 1;
  // Human-readable name (e.g., "gcc-13.2.0")
  string name = 2;
  // Inputs (vertex IDs this depends on)
  repeated string inputs = 3;
  // Whether this was fetched from a cache/substituter
  bool cached = 4;
}

// Progress update for a vertex (download progress, compile steps, etc.)
message VertexProgress {
  string vertex_id = 1;
  // Human-readable status message
  string message = 2;
  // Numeric progress (bytes downloaded, steps completed, etc.)
  int64 current = 3;
  int64 total = 4;
}

// A vertex has completed.
message VertexCompleted {
  string vertex_id = 1;
  // Output store paths
  repeated string output_paths = 2;
  // Build duration
  google.protobuf.Timestamp started = 3;
  google.protobuf.Timestamp completed = 4;
  // Error message if failed (empty if success)
  string error = 5;
  // Whether this was a cache hit
  bool cached = 6;
}

// Log output from a vertex.
message VertexLog {
  string vertex_id = 1;
  // 1 = stdout, 2 = stderr
  int32 stream = 2;
  bytes data = 3;
  google.protobuf.Timestamp timestamp = 4;
}

// The entire build completed successfully.
message BuildCompleted {
  string build_id = 1;
  // Final output store paths
  repeated string output_paths = 2;
  // Total build time
  google.protobuf.Timestamp started = 3;
  google.protobuf.Timestamp completed = 4;
}

// The build failed.
message BuildError {
  string build_id = 1;
  // Which vertex failed (if applicable)
  string vertex_id = 2;
  // Error code
  BuildErrorCode code = 3;
  // Human-readable error message
  string message = 4;
  // Detailed error output (build log tail)
  string detail = 5;
}

enum BuildErrorCode {
  BUILD_ERROR_CODE_UNKNOWN = 0;
  BUILD_ERROR_CODE_EVAL_FAILED = 1;      // Nix evaluation error
  BUILD_ERROR_CODE_BUILD_FAILED = 2;     // Builder process failed
  BUILD_ERROR_CODE_FETCH_FAILED = 3;     // Source fetch failed
  BUILD_ERROR_CODE_HASH_MISMATCH = 4;    // Fixed-output hash mismatch
  BUILD_ERROR_CODE_TIMEOUT = 5;          // Build timeout
  BUILD_ERROR_CODE_CANCELLED = 6;        // Cancelled by client
  BUILD_ERROR_CODE_DEPENDENCY_FAILED = 7; // A dependency failed
  BUILD_ERROR_CODE_STORE_ERROR = 8;      // Nix store error
}

// ============================================================
// Build Status (for query RPCs)
// ============================================================

message BuildStatus {
  string build_id = 1;
  string target = 2;
  BuildState state = 3;
  google.protobuf.Timestamp created = 4;
  google.protobuf.Timestamp completed = 5;
  repeated string output_paths = 6;
  string error_message = 7;
  // Progress summary
  int32 vertices_total = 8;
  int32 vertices_completed = 9;
  int32 vertices_cached = 10;
}

enum BuildState {
  BUILD_STATE_UNKNOWN = 0;
  BUILD_STATE_QUEUED = 1;
  BUILD_STATE_EVALUATING = 2;
  BUILD_STATE_BUILDING = 3;
  BUILD_STATE_COMPLETED = 4;
  BUILD_STATE_FAILED = 5;
  BUILD_STATE_CANCELLED = 6;
}
```

### Design Rationale

1. **`oneof event` envelope** -- Multiplexes all event types over a single
   stream. The client uses a match/switch on the variant. This is the same
   pattern BuildKit uses.

2. **Vertex = Derivation** -- Maps directly to Nix's derivation graph. Each
   vertex is a store derivation that needs to be built or substituted.

3. **Separate `BuildError` from `VertexCompleted.error`** -- A single vertex
   failure may or may not fail the entire build (depends on `keep_going`).
   `BuildError` is the final fatal error.

4. **VertexLog with raw bytes** -- Build logs can contain arbitrary binary
   output. Using `bytes` instead of `string` avoids UTF-8 validation issues.

5. **Timestamps everywhere** -- Enables precise timing analysis on the client
   side. Uses well-known `google.protobuf.Timestamp`.

---

## 10. Reference Proto Designs

### BuildKit control.proto

BuildKit's Control service is the primary reference:

```protobuf
service Control {
    rpc DiskUsage(DiskUsageRequest) returns (DiskUsageResponse);
    rpc Prune(PruneRequest) returns (stream UsageRecord);
    rpc Solve(SolveRequest) returns (SolveResponse);
    rpc Status(StatusRequest) returns (stream StatusResponse);
    rpc Session(stream BytesMessage) returns (stream BytesMessage);
    rpc ListWorkers(ListWorkersRequest) returns (ListWorkersResponse);
    rpc Info(InfoRequest) returns (InfoResponse);
    rpc ListenBuildHistory(BuildHistoryRequest) returns (stream BuildHistoryEvent);
    rpc UpdateBuildHistory(UpdateBuildHistoryRequest) returns (UpdateBuildHistoryResponse);
}
```

Key design aspects:

- **`Solve` is unary, `Status` is streaming** -- The build is started with
  `Solve()` (returns a reference), then progress is streamed separately via
  `Status()`. This decouples build initiation from progress monitoring.

- **`StatusResponse`** contains three arrays:
  - `repeated Vertex vertexes` -- build graph nodes (name, cached, started, completed, error)
  - `repeated VertexStatus statuses` -- progress for a vertex (current/total)
  - `repeated VertexLog logs` -- log output (vertex ID, stream ID, data)

- **`Session` is bidirectional** -- Used for auth forwarding, local content
  sharing, etc. The client and server exchange opaque `BytesMessage` frames.

- **`ListenBuildHistory`** -- Server-streaming for observing past and
  in-progress builds. Good pattern for a "dashboard" view.

**Applicability to AOS**: We can simplify by combining `Solve` + `Status`
into a single server-streaming `Build` RPC (since we don't need the
decoupled pattern for our use case). The `Vertex`/`VertexStatus`/`VertexLog`
decomposition maps well to Nix derivations.

### containerd content.proto

Containerd's Content service demonstrates patterns for content-addressable storage:

```protobuf
service Content {
    rpc Info(InfoRequest) returns (InfoResponse);
    rpc Update(UpdateRequest) returns (UpdateResponse);
    rpc List(ListContentRequest) returns (stream ListContentResponse);
    rpc Delete(DeleteContentRequest) returns (empty);
    rpc Read(ReadContentRequest) returns (stream ReadContentResponse);
    rpc Write(stream WriteContentRequest) returns (stream WriteContentResponse);
    rpc Abort(AbortRequest) returns (empty);
    rpc Status(StatusRequest) returns (StatusResponse);
    rpc ListStatuses(ListStatusesRequest) returns (ListStatusesResponse);
}
```

Key design aspects:

- **Streaming for list/read operations** -- `List` and `Read` use
  server-streaming. Efficient for large result sets.
- **Bidirectional streaming for writes** -- `Write` uses bidi streaming.
  Client streams data chunks, server streams acknowledgments (with offset).
- **`WriteAction` enum** -- `STAT`, `WRITE`, `COMMIT` control the write
  lifecycle within a single stream.
- **Separate types vs services** -- containerd splits proto definitions
  into `types/` (shared messages) and `services/` (RPC definitions).

**Applicability to AOS**: The content store pattern could inform a future
binary cache push/pull API, where NAR files are streamed to/from the daemon.

---

## 11. Proto File Organization and Build Setup

### Recommended Directory Structure

```
cli/
  proto/
    aos/
      v1/
        build.proto        # BuildService
        store.proto         # StoreService (GC, query)
        daemon.proto        # DaemonService (info, shutdown)
        types.proto         # Shared message types
    buf.yaml               # Optional: buf linting config
  build.rs                 # tonic-build compilation
  src/
    daemon/
      server.rs
      service/
        build.rs
        store.rs
        daemon.rs
      proto.rs             # Re-export generated types
```

### build.rs Configuration

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile proto files
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?);

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .file_descriptor_set_path(out_dir.join("aos_descriptor.bin"))
        .compile_protos(
            &[
                "proto/aos/v1/build.proto",
                "proto/aos/v1/store.proto",
                "proto/aos/v1/daemon.proto",
            ],
            &["proto"],  // Include path for resolving imports
        )?;

    Ok(())
}
```

### Including Generated Code

```rust
// src/daemon/proto.rs

pub mod aos {
    pub mod v1 {
        tonic::include_proto!("aos.v1");

        // For gRPC reflection
        pub const FILE_DESCRIPTOR_SET: &[u8] =
            tonic::include_file_descriptor_set!("aos_descriptor");
    }
}
```

### Cargo.toml Dependencies

```toml
[dependencies]
tonic = { version = "0.12", features = ["transport", "tls"] }
tonic-health = "0.12"
tonic-reflection = "0.12"
prost = "0.13"
prost-types = "0.13"
tokio = { version = "1", features = ["full"] }
tokio-util = { version = "0.7", features = ["sync"] }  # CancellationToken
tokio-stream = { version = "0.1", features = ["net"] }  # UnixListenerStream
tower = { version = "0.4", features = ["timeout", "limit"] }
tracing = "0.1"

[build-dependencies]
tonic-build = "0.12"
```

### NixOS / AOS Build Consideration

On NixOS (and in the AOS build environment), `protoc` may not be in PATH.
Set the `PROTOC` environment variable in the Nix derivation:

```nix
buildPhase = ''
  export PROTOC=${protobuf}/bin/protoc
  export PROTOC_INCLUDE=${protobuf}/include
  cargo build --release
'';
```

---

## 12. Recommended Architecture for aos Daemon

Based on the research above, here is the recommended gRPC architecture:

### Transport Layer

```
                    +------------------+
                    |   aos CLI        |
                    +--------+---------+
                             |
              +--------------+--------------+
              |                             |
     unix:///run/aos/aosd.sock    https://builder:50051
              |                             |
     +--------v---------+        +---------v--------+
     |  UDS Listener     |        |  TCP+TLS Listener |
     +--------+----------+        +---------+---------+
              |                             |
              +-------------+---------------+
                            |
                   +--------v--------+
                   |  tonic::Server   |
                   +--------+---------+
                            |
              +-------------+-------------+
              |             |             |
     +--------v--+  +-------v---+  +------v------+
     |BuildService|  |StoreService|  |DaemonService|
     +------------+  +-----------+  +-------------+
```

### Key Design Decisions

1. **UDS for local, TCP+mTLS for remote** -- Local builds use the Unix
   socket (fast, no auth overhead). Remote builders use TCP with mutual
   TLS for authentication.

2. **Server-streaming for builds** -- A single `Build()` RPC returns a
   stream of events. No need for BuildKit's decoupled Solve+Status pattern
   since our client always wants to watch the build it started.

3. **CancellationToken hierarchy** -- Daemon token > per-build token >
   per-step token. Client disconnect cancels only its build.

4. **Concurrency via Semaphore** -- Limit concurrent builds. Queued builds
   wait on the semaphore.

5. **Health + Reflection** -- Standard gRPC health checking and reflection
   for debuggability with grpcurl/grpcui.

6. **Event envelope with oneof** -- All build events flow through a single
   `BuildEvent` message with a `oneof event` discriminator. This is
   type-safe, extensible, and matches the BuildKit pattern.

### Crate Dependencies Summary

| Crate              | Version | Purpose                           |
|--------------------|---------|-----------------------------------|
| `tonic`            | 0.12    | gRPC server + client              |
| `tonic-build`      | 0.12    | Proto codegen (build dep)         |
| `tonic-health`     | 0.12    | Health checking service           |
| `tonic-reflection` | 0.12    | Reflection service                |
| `prost`            | 0.13    | Protobuf serialization            |
| `prost-types`      | 0.13    | Timestamp, Duration, etc.         |
| `tokio`            | 1.x     | Async runtime (full features)     |
| `tokio-util`       | 0.7     | CancellationToken                 |
| `tokio-stream`     | 0.1     | Stream utilities, UnixListenerStream |
| `tower`            | 0.4     | Middleware layers                 |
| `tracing`          | 0.1     | Structured logging                |

---

## Sources

- [tonic repository](https://github.com/hyperium/tonic)
- [tonic docs](https://docs.rs/tonic/latest/tonic/)
- [tonic-build docs](https://docs.rs/tonic-build/latest/tonic_build/)
- [tonic transport module](https://docs.rs/tonic/latest/tonic/transport/index.html)
- [BuildKit control.proto on Buf](https://buf.build/depot/buildkit/file/3952d181d6124b64b96a478079dcdbf2:moby/buildkit/v1/control.proto)
- [BuildKit repository](https://github.com/moby/buildkit)
- [containerd content.proto](https://github.com/containerd/containerd/blob/main/api/services/content/v1/content.proto)
- [containerd tasks.proto](https://github.com/containerd/containerd/blob/main/api/services/tasks/v1/tasks.proto)
- [gRPC streaming with Rust](https://ciao-systems.com/blog/grpc-streaming-with-rust)
- [Bidirectional gRPC streaming with tonic](https://oneuptime.com/blog/post/2026-01-25-bidirectional-grpc-streaming-tonic-rust/view)
- [Cancellation in Tonic/Tokio](https://users.rust-lang.org/t/cancellation-in-tonic-tokio-how-does-it-work/109625)
- [Detecting client disconnection (tonic #377)](https://github.com/hyperium/tonic/issues/377)
- [Tokio task cancellation patterns](https://cybernetist.com/2024/04/19/rust-tokio-task-cancellation-patterns/)
- [Tokio graceful shutdown](https://tokio.rs/tokio/topics/shutdown)
- [CancellationToken docs](https://docs.rs/tokio-util/latest/tokio_util/sync/struct.CancellationToken.html)
- [tonic UDS issue #826](https://github.com/hyperium/tonic/issues/826)
- [gRPC basics for Rust developers](https://dockyard.com/blog/2025/04/08/grpc-basics-for-rust-developers)
- [Proto3 language guide](https://protobuf.dev/programming-guides/proto3/)
