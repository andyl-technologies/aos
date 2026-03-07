# aos daemon — Architecture Design

## Overview

The `aos daemon` replaces Nix's build infrastructure (nix-daemon, remote builds,
substitution) with a BuildKit-backed distributed build system. It evaluates Nix
expressions into derivation graphs, translates them to BuildKit LLB, distributes
builds across local/remote BuildKit workers, and imports results back into the
Nix store — providing Docker-grade build UX (parallel progress, streaming logs,
cancellation) for Nix builds.

```
  aos build pkgs.hello
        |
        v
  +------------------+
  |   aos CLI         |  gRPC client
  +--------+---------+
           |
    unix:///run/aos/aosd.sock  (or tcp+mTLS for remote)
           |
  +--------v---------+
  |   aos daemon      |  gRPC server (tonic)
  |                    |
  |  1. nix-instantiate → .drv files
  |  2. parse .drv → dependency DAG
  |  3. check binary caches (narinfo)
  |  4. check local nix store
  |  5. translate uncached drvs → LLB graph
  |  6. submit LLB → buildkit workers
  |  7. stream progress → client
  |  8. import results → nix store
  +----+----------+---+
       |          |
       v          v
  +--------+  +--------+
  |buildkitd|  |buildkitd|   (local + remote workers)
  +--------+  +--------+
```

---

## 1. Core Pipeline

### Phase 1: Evaluation

```
nix expression → nix-instantiate → .drv files in /nix/store
```

- Run `nix-instantiate -A <attr> <flake-or-file>` to produce `.drv` paths
- Parse each `.drv` (ATerm format) to extract: `inputDrvs`, `inputSrcs`,
  `outputs`, `builder`, `args`, `env`
- Use Tvix's `nix_compat::derivation` crate for Rust-native .drv parsing
  (avoids shelling out to `nix derivation show`)

### Phase 2: Graph Construction

```
.drv files → dependency DAG (topologically sorted)
```

- Walk `inputDrvs` recursively from the target `.drv` to build the full closure
- Each node is a derivation with its output paths
- Edges represent build-time dependencies (inputDrvs) and source inputs (inputSrcs)
- Classify each derivation:
  - **Fixed-output (FOD)**: has `outputHash` in env → network-accessing fetch
  - **Input-addressed**: normal build → deterministic output from inputs

### Phase 3: Cache Resolution

For each derivation output path in the graph:

1. **Check local store**: `nix-store --check-validity <output-path>`
2. **Check binary caches**: HTTP GET `<cache-url>/<hash>.narinfo`
3. Mark nodes as: `cached-local`, `cached-remote`, or `needs-build`

Prune the graph: remove all `cached-local` subtrees. For `cached-remote` nodes,
generate substitution tasks instead of build tasks.

### Phase 4: LLB Translation

Translate the pruned derivation graph into a BuildKit LLB `Definition`:

```
For each derivation (bottom-up, topological order):

  FOD (fetchurl/fetchgit):
    → SourceOp(identifier="https-<url>", attrs={hash, hashAlgo})
    or
    → ExecOp with network=HOST running curl/wget in a minimal container

  Regular derivation:
    → deps = MergeOp([...input store paths as layers...])
    → build = ExecOp(
        mount[0] = deps (readonly, at /nix/store)
        mount[1] = scratch (rw, at /build — the build sandbox)
        mount[2] = scratch (rw, at $out — the output)
        args = [builder] + builder_args
        env = drv.env
      )
    → result = DiffOp(scratch, build_output)
      or just capture mount[2] (the $out directory)
```

### Phase 5: Build Execution

Submit the LLB `Definition` to BuildKit via `Control.Solve` gRPC:

- Connect to buildkitd (local unix socket or remote TCP+TLS)
- Submit the LLB graph as a `SolveRequest` with a unique `Ref`
- Stream progress via `Control.Status(Ref)` in parallel
- Forward `Vertex`, `VertexStatus`, `VertexLog` events to the client

### Phase 6: Result Import

After BuildKit completes each derivation:

1. Export the build result from BuildKit (as a tar/directory)
2. NAR-serialize the output
3. Copy to the expected Nix store path
4. Register with `nix-store --register-validity --hash-given`
5. Process in topological order (dependencies before dependents)

For binary cache substitutions:
1. Fetch `.narinfo` from cache
2. Download and decompress `.nar`
3. `nix-store --restore <store-path> < path.nar`
4. Register validity with references

---

## 2. LLB Graph Design — Nix Store Path Composition

The key insight: each Nix store path becomes an independent LLB layer, and
`MergeOp` composes them into build environments.

### Store Path as Layer

```
/nix/store/abc...-glibc-2.38/     → LLB layer A
/nix/store/def...-gcc-13.2.0/     → LLB layer B
/nix/store/ghi...-coreutils-9.4/  → LLB layer C
```

Each layer contains files only under its `/nix/store/<hash>-<name>/` prefix.
Layers are non-overlapping by construction (unique store path hashes).

### Build Environment via MergeOp

To build a derivation that depends on glibc + gcc + coreutils:

```
MergeOp([layer_A, layer_B, layer_C])
  → unified /nix/store/ with all three packages
```

On overlay-backed snapshotters, this is metadata-only (no file copying).
This is the critical performance advantage over Nix's approach of copying
or bind-mounting individual store paths.

### ExecOp for Build Phases

```
ExecOp:
  mounts:
    - input=merged_deps, dest="/nix/store", readonly=true
    - input=sources, dest="/build/src", readonly=true
    - type=SCRATCH, dest="/build/out"  (will become $out)
    - type=TMPFS, dest="/tmp"
  meta:
    args: ["/nix/store/...-bash/bin/bash", "-e", "/nix/store/...-builder.sh"]
    env:
      out: "/build/out"
      src: "/build/src"
      PATH: "/nix/store/...-coreutils/bin:..."
      # ... all env vars from .drv
    cwd: "/build"
  network: NONE  (sandbox — no network for regular derivations)
  security: SANDBOX
```

After the ExecOp, the content at `/build/out` is the derivation output.

### Fixed-Output Derivations (Fetches)

FODs need network access. Two strategies:

**Strategy A: HTTP SourceOp** (preferred for simple URL fetches)
```
SourceOp:
  identifier: "https://example.com/foo-1.0.tar.gz"
  attrs:
    http.checksum: "sha256:abc123..."
    http.filename: "foo-1.0.tar.gz"
```
BuildKit's HTTP source has built-in content-addressed caching and ETag support.

**Strategy B: ExecOp with network=HOST** (for complex fetchers like fetchgit)
```
ExecOp:
  network: HOST
  meta:
    args: [bash, "-c", "curl -L -o $out <url> && sha256sum --check ..."]
```

### Result Extraction

After build, extract the output and create the store path layer:

```
FileOp(copy):
  src: build_exec output mount (index 2)
  dest: "/nix/store/<hash>-<name>/"
```

This creates a new layer containing only the derivation output at its correct
store path. This layer can then be used as input to downstream MergeOps.

---

## 3. BuildKit Integration

### Connection to buildkitd

The daemon connects to one or more buildkitd instances via gRPC:

```toml
# aosd.toml
[[builders]]
name = "local"
endpoint = "unix:///run/buildkit/buildkitd.sock"
platforms = ["linux/amd64"]
max_parallelism = 8

[[builders]]
name = "arm-builder"
endpoint = "tcp://arm-host:1234"
platforms = ["linux/arm64"]
tls.ca = "/etc/aos/ca.pem"
tls.cert = "/etc/aos/client.pem"
tls.key = "/etc/aos/client-key.pem"
```

### Existing Rust Crates

| Crate | Version | Use |
|-------|---------|-----|
| `buildkit-client` | 0.1.4 | Full gRPC client with session protocol |
| `buildkit-llb` | 0.2.0 | High-level LLB construction API |
| `buildkit-proto` | 0.2.0 | Generated protobuf types |

Recommended: use `buildkit-client` for the buildkitd gRPC client, or vendor
the proto files and generate with tonic-build for tighter control.

### LLB Submission Flow

```rust
// Pseudocode
let definition = translate_drv_graph_to_llb(&drv_graph, &cache_status);

let solve_request = SolveRequest {
    r#ref: build_id.clone(),
    definition: Some(definition),
    // No frontend — we provide pre-built LLB
    ..Default::default()
};

// Start solve and status stream concurrently
let (solve_result, _) = tokio::join!(
    buildkit_client.solve(solve_request),
    stream_status(buildkit_client, &build_id, &progress_tx),
);
```

### Content-Addressed Caching

BuildKit caches by content hash of each Op. Since our LLB ops are derived from
Nix derivation hashes, a derivation that hasn't changed will hit BuildKit's cache
automatically — no rebuild needed even across daemon restarts.

---

## 4. Binary Cache Integration

### Transparent Substitution

When the daemon finds a store path in a remote binary cache:

1. Skip LLB generation for that derivation
2. Instead, create a `SourceOp` that fetches the NAR directly:

```
SourceOp:
  identifier: "https://cache.nixos.org/nar/<hash>.nar.zst"
  attrs:
    http.checksum: "sha256:<nar-file-hash>"
```

Or handle substitution outside BuildKit entirely:

```
1. HTTP GET <cache>/<hash>.narinfo  → parse NarHash, URL, References, Sig
2. Verify Ed25519 signature
3. HTTP GET <cache>/<nar-url>       → download compressed NAR
4. Decompress (xz/zstd/bzip2)
5. nix-store --restore <store-path> < uncompressed.nar
6. nix-store --register-validity --hash-given <<EOF
   <store-path>
   <nar-hash-hex>
   <nar-size>
   <deriver-or-empty>
   <num-references>
   <ref1>
   <ref2>
   EOF
```

### Cache Priority

```toml
# aosd.toml
[[binary_caches]]
url = "https://cache.nixos.org"
public_key = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
priority = 40

[[binary_caches]]
url = "https://aos-cache.example.com"
public_key = "aos-cache:..."
priority = 10   # checked first
```

---

## 5. gRPC Service Design

### Proto Definition

```
proto/aos/v1/
  build.proto    — BuildService (the main build RPC)
  store.proto    — StoreService (query/GC operations)
  daemon.proto   — DaemonService (health, info, config)
  types.proto    — shared types (StorePath, Derivation, etc.)
```

### BuildService

```protobuf
service BuildService {
  // Start a build, stream progress until completion or failure.
  // Client disconnect cancels the build.
  rpc Build(BuildRequest) returns (stream BuildEvent);

  // Query status of a running or recent build.
  rpc GetBuild(GetBuildRequest) returns (BuildStatus);

  // List recent builds.
  rpc ListBuilds(ListBuildsRequest) returns (ListBuildsResponse);

  // Cancel a running build by ID.
  rpc CancelBuild(CancelBuildRequest) returns (CancelBuildResponse);
}
```

### BuildEvent Stream

```protobuf
message BuildEvent {
  google.protobuf.Timestamp timestamp = 1;
  oneof event {
    BuildStarted      started          = 10;
    VertexStarted     vertex_started   = 11;
    VertexProgress    vertex_progress  = 12;
    VertexCompleted   vertex_completed = 13;
    VertexLog         vertex_log       = 14;
    BuildCompleted    completed        = 15;
    BuildError        error            = 16;
  }
}
```

**Vertex = Nix Derivation**. Each derivation in the build graph is a vertex.
The client sees: "building gcc-13.2.0 [3/47]", progress bars for downloads,
streaming build logs — exactly like `docker build` output.

### Transport

- **Local**: Unix domain socket at `/run/aos/aosd.sock`
  - Peer credential auth (uid/gid from SO_PEERCRED)
  - Zero-copy, lowest latency
- **Remote**: TCP with mTLS at configurable port
  - Client certificate for authentication
  - Suitable for remote `aos build --remote`

Both listeners run concurrently via `tokio::select!`.

### Cancellation

```
daemon_token (top-level)
  └── build_token (per-build, cancelled on client disconnect)
       └── step_token (per-derivation, cancelled when build cancelled)
```

Client disconnect → tonic drops the response stream → `mpsc::Sender::send()`
returns `Err` → build task cancels its `CancellationToken` → all child tasks
(BuildKit Solve RPCs) are cancelled via gRPC context cancellation.

---

## 6. Configuration

### aosd.toml

```toml
[daemon]
socket = "/run/aos/aosd.sock"
# tcp_listen = "0.0.0.0:50051"  # optional TCP listener
max_concurrent_builds = 4
log_level = "info"

[store]
# Path to the Nix store
store_dir = "/nix/store"
# State directory for daemon metadata
state_dir = "/var/lib/aos"

[eval]
# Path to nix-instantiate
nix_instantiate = "nix-instantiate"
# Extra args passed to nix-instantiate
extra_args = []

[[builders]]
name = "local"
endpoint = "unix:///run/buildkit/buildkitd.sock"
platforms = ["linux/amd64"]
max_parallelism = 8

[[builders]]
name = "arm-farm"
endpoint = "tcp://arm-builder.internal:1234"
platforms = ["linux/arm64"]
max_parallelism = 16
[builders.tls]
ca = "/etc/aos/ca.pem"
cert = "/etc/aos/client.pem"
key = "/etc/aos/client-key.pem"

[[binary_caches]]
url = "https://cache.nixos.org"
public_key = "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY="
priority = 40

[[binary_caches]]
url = "https://my-cache.example.com"
public_key = "my-cache:..."
priority = 10
auth_token_env = "AOS_CACHE_TOKEN"

[tls]
# For TCP listener
cert = "/etc/aos/server.pem"
key = "/etc/aos/server-key.pem"
client_ca = "/etc/aos/ca.pem"  # enables mTLS
```

### CLI Flag Overrides

```
aos daemon --socket /tmp/aosd.sock --max-jobs 2 --builder local
aos daemon --config /etc/aos/aosd.toml
```

---

## 7. Rust Module Structure

```
cli/src/daemon/
  mod.rs              — pub mod exports, daemon entry point (run fn)
  config.rs           — TOML config parsing, CLI flag merge
  server.rs           — tonic Server setup (UDS + TCP listeners)
  proto.rs            — re-export generated protobuf types

  service/
    mod.rs            — service module exports
    build.rs          — BuildService trait impl (Build, GetBuild, etc.)
    store.rs          — StoreService trait impl (query, GC)
    daemon.rs         — DaemonService trait impl (info, shutdown)

  eval/
    mod.rs            — Nix evaluation orchestration
    instantiate.rs    — nix-instantiate wrapper
    drv_parser.rs     — .drv ATerm parser (or nix_compat wrapper)
    graph.rs          — dependency graph construction + topological sort

  cache/
    mod.rs            — cache resolution orchestration
    narinfo.rs        — .narinfo fetch + parse
    substitute.rs     — NAR download, decompress, restore, register
    verify.rs         — Ed25519 signature verification

  llb/
    mod.rs            — LLB graph construction orchestration
    translate.rs      — derivation → LLB Op translation
    merge.rs          — MergeOp construction for store path composition
    exec.rs           — ExecOp construction for build phases
    source.rs         — SourceOp construction for fetches
    definition.rs     — final Definition assembly (marshal, digest, wire)

  build/
    mod.rs            — build orchestration (the main pipeline)
    scheduler.rs      — build scheduling, worker selection
    executor.rs       — BuildKit Solve submission + status streaming
    importer.rs       — result import back to Nix store
    progress.rs       — progress aggregation + client event generation

cli/proto/
  aos/v1/
    build.proto
    store.proto
    daemon.proto
    types.proto
```

### lib.rs Addition

```rust
// cli/src/lib.rs
pub mod daemon;  // add to existing exports
```

### commands/daemon.rs (thin CLI adapter)

```rust
// cli/src/commands/daemon.rs
pub async fn run(config_path: Option<&str>, overrides: DaemonOverrides) -> Result<()> {
    let config = daemon::config::load(config_path, overrides)?;
    daemon::run(config).await
}
```

### cli.rs Addition

```rust
// In the Commands enum:
Daemon {
    /// Path to config file
    #[arg(long, short)]
    config: Option<String>,

    /// Socket path override
    #[arg(long)]
    socket: Option<String>,

    /// Max concurrent builds override
    #[arg(long)]
    max_jobs: Option<u32>,

    /// Run in foreground (don't daemonize)
    #[arg(long)]
    foreground: bool,
},
```

---

## 8. Key Design Decisions

### Why BuildKit over Nix builders?

| Aspect | Nix daemon | aos daemon + BuildKit |
|--------|-----------|----------------------|
| **Progress** | Per-derivation start/end only | Per-step progress bars, streaming logs |
| **Parallelism** | Configurable but opaque | Visual parallel build tree (like docker) |
| **Remote builds** | SSH + nix-copy-closure (slow) | BuildKit gRPC + content-addressed layers |
| **Cancellation** | Kill signal, unclean | gRPC context cancel, graceful |
| **Caching** | Binary cache OR local | Both + BuildKit layer cache |
| **Distribution** | One remote at a time | Multiple concurrent workers |
| **File sync** | Full closure copy | Content-addressed, diff-based |

### Why MergeOp for store paths?

Nix store paths are non-overlapping by construction. MergeOp on overlay
snapshotters is metadata-only — it just adds lowerdir entries. This means
composing 100 store paths into a build environment is nearly free, compared
to Nix's approach of bind-mounting each path individually.

### Why not use BuildKit frontends?

We construct LLB directly because:
1. Nix evaluation is complex and Nix-specific — no benefit to running it inside BuildKit
2. Direct LLB gives us full control over caching and layer composition
3. No container image overhead for the frontend itself
4. Simpler architecture (no gateway protocol)

### Why keep nix-instantiate?

Nix expression evaluation is deeply integrated with the Nix language runtime.
Reimplementing it would be massive (see: Tvix, which is years of work). Using
`nix-instantiate` as a subprocess is pragmatic — it does one thing well (eval)
and produces .drv files that we can parse independently.

### Why not use the experimental `nix` command?

Per project requirements, we use stable `nix-*` commands (`nix-instantiate`,
`nix-store`) which have well-defined behavior and are available everywhere.
The experimental `nix` CLI changes frequently.

---

## 9. Build Pipeline Sequence Diagram

```
Client                     Daemon                    BuildKit            Nix Store       Binary Cache
  |                          |                          |                   |                |
  |--- Build(target) ------->|                          |                   |                |
  |                          |                          |                   |                |
  |                          |-- nix-instantiate ------>|                   |                |
  |                          |<-- .drv paths -----------|                   |                |
  |                          |                          |                   |                |
  |                          |-- parse .drv files ----->|                   |                |
  |                          |-- build dep graph ------>|                   |                |
  |                          |                          |                   |                |
  |<-- BuildStarted ---------|                          |                   |                |
  |                          |                          |                   |                |
  |                          |-- check validity ------->|------------------>|                |
  |                          |-- check narinfo -------->|                   |--------------->|
  |                          |<-- cache hits -----------|                   |                |
  |                          |                          |                   |                |
  |                          |-- translate to LLB ----->|                   |                |
  |                          |                          |                   |                |
  |                          |-- Solve(Definition) ---->|                   |                |
  |                          |-- Status(Ref) ---------->|                   |                |
  |                          |                          |                   |                |
  |<-- VertexStarted --------|<-- Vertex(started) ------|                   |                |
  |<-- VertexLog ------------|<-- VertexLog ------------|                   |                |
  |<-- VertexProgress -------|<-- VertexStatus ---------|                   |                |
  |<-- VertexCompleted ------|<-- Vertex(completed) ----|                   |                |
  |                          |                          |                   |                |
  |                          |<-- SolveResponse --------|                   |                |
  |                          |                          |                   |                |
  |                          |-- export result -------->|                   |                |
  |                          |-- nix-store --restore -->|------------------>|                |
  |                          |-- register-validity ---->|------------------>|                |
  |                          |                          |                   |                |
  |<-- BuildCompleted -------|                          |                   |                |
  |                          |                          |                   |                |

  [Client disconnect at any point]
  |--- TCP RST / stream drop |                          |                   |                |
  |                          |-- cancel token --------->|                   |                |
  |                          |                          |-- cancel Solve -->|                |
  |                          |                          |                   |                |
```

---

## 10. Dependency Summary

### New Cargo.toml Dependencies

```toml
# gRPC
tonic = { version = "0.12", features = ["transport", "tls"] }
tonic-health = "0.12"
tonic-reflection = "0.12"
prost = "0.13"
prost-types = "0.13"

# BuildKit client (or vendor protos)
# buildkit-client = "0.1"

# Nix derivation parsing
# nix_compat = { git = "https://github.com/tvlfyi/tvix" }  # for .drv parsing

# Existing deps already in Cargo.toml that we reuse:
# tokio, tokio-util, tokio-stream, serde, toml, sha2, ed25519-dalek, reqwest, zstd

[build-dependencies]
tonic-build = "0.12"
```

### Build Dependencies

- `protoc` (Protocol Buffers compiler) — needed for tonic-build
- Must be available in the Nix dev shell

---

## 11. Open Questions and Future Work

1. **Sandbox fidelity**: Nix sandbox uses Linux namespaces with specific
   bind-mount patterns. BuildKit's runc-based sandbox is similar but not
   identical. Need to verify that build environment differences don't cause
   reproducibility issues.

2. **Store path relocation**: BuildKit builds happen in a container filesystem.
   The output needs to end up at the correct `/nix/store/<hash>-<name>` path.
   We need to ensure the container's `/nix/store` mount is correctly configured.

3. **Content-addressed derivations (CA-derivations)**: Nix's experimental
   CA derivation support could simplify the import step, since output paths
   would be determined by content rather than input hashes.

4. **Build log persistence**: BuildKit stores logs ephemerally. The daemon
   should persist build logs for debugging (could use the existing SQLite
   infrastructure from the server module).

5. **Garbage collection coordination**: The daemon should coordinate with
   `nix-collect-garbage` to avoid collecting store paths that are in-flight
   builds.

6. **Multi-output derivations**: Derivations with multiple outputs (out, dev,
   lib) need each output extracted and imported separately.

7. **IFD (Import From Derivation)**: Nix expressions that depend on build
   results (`import (pkgs.runCommand ...)`) require building during evaluation.
   The daemon would need to handle recursive build requests from
   nix-instantiate.
