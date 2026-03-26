# AOS Distributed Build System -- Rust Crate Structure

This documents the Rust crate structure and implementation plan for the AOS distributed build system.

## Crate Structure

```
crates/
  aos-p2p/              # Shared libp2p networking layer + auth protocol
  aos-daemon/            # Unified daemon binary (builds, joins mesh, Unix socket control)

  # Existing crates (modified):
  aos-core/              # Shared types, Nix runner (already exists)
  aos/                   # CLI binary (already exists) -- the `-i` flag activates P2P client mode
```

Note: there is no separate client binary. The `aos` binary handles both daemon
socket mode (default) and P2P client mode (activated by `-i <identity>`). The
P2P transport layer from `aos-p2p` is linked into the `aos` binary and used
when `-i` is provided.

## aos-p2p -- Shared Networking Layer

The core libp2p integration crate. Both `aos-daemon` and the `aos` binary (for P2P client mode) depend on this.

```
aos-p2p/
  src/
    lib.rs               # Public API
    behaviour.rs          # Combined NetworkBehaviour definition
    config.rs             # P2P configuration types
    discovery.rs          # Peer discovery (mDNS + Kademlia bootstrap)
    gossipsub.rs          # Topic management, message types, publish/subscribe helpers
    dht.rs                # DHT record types, put/get with serialization, TTL management
    auth.rs               # /aos/auth/1.0.0 handshake protocol, UCAN verification
    ucan.rs               # UCAN token parsing, chain verification, capability checking
    protocols/
      mod.rs
      log_replay.rs       # /aos/log-replay/1.0.0 protocol codec
      content_transfer.rs # WANT_MANIFEST and WANT_CHUNK protocol codecs
      sync.rs             # /aos/sync/1.0.0 anti-entropy protocol codec
    types.rs              # Shared message types (BuildJob, BuildClaim, LogEvent, BuildResult)
    sync.rs               # CRDT sync state management (LWW-Map, merge logic)
    merkle.rs             # Merkle tree construction and anti-entropy protocol
    bloom.rs              # Bloom filter for store affinity
    node.rs               # P2pNode wrapper -- manages Swarm lifecycle, event loop
```

### Auth Protocol (`auth.rs`, `ucan.rs`)

Every libp2p connection performs a `/aos/auth/1.0.0` handshake immediately after
the noise/TLS transport is established. The connecting peer presents a UCAN
token chain; the receiving peer verifies it before allowing any application
protocols to proceed.

```rust
// auth.rs -- /aos/auth/1.0.0 handshake
pub struct AuthProtocol;

pub struct AuthRequest {
    pub ucan_chain: Vec<String>,   // UCAN token chain (innermost first)
}

pub struct AuthResponse {
    pub ok: bool,
    pub capabilities: Vec<Capability>,  // Granted capabilities
    pub error: Option<String>,
}

// ucan.rs -- UCAN verification
pub struct UcanVerifier {
    pub root_keys: Vec<PublicKey>,  // Trusted root issuer keys
}

pub enum Capability {
    Build,          // Submit build jobs
    Watch,          // Observe build logs
    Fetch,          // Fetch NARs
    Delegate,       // Issue sub-UCANs
    Admin,          // Full control
}

impl UcanVerifier {
    pub fn verify_chain(&self, chain: &[String]) -> Result<Vec<Capability>>;
    pub fn check_capability(&self, chain: &[String], required: Capability) -> Result<bool>;
}
```

### Key Types

```rust
// behaviour.rs
#[derive(NetworkBehaviour)]
pub struct AosBehaviour {
    pub mdns: mdns::tokio::Behaviour,
    pub kademlia: kad::Behaviour<MemoryStore>,
    pub gossipsub: gossipsub::Behaviour,
    pub stream: libp2p_stream::Behaviour,
    pub autonat: autonat::Behaviour,
    pub relay_client: relay::client::Behaviour,
    pub identify: identify::Behaviour,
}

// Sync protocol integration:
// - Sync deltas ride on the existing GossipSub behaviour (topic: `sync/{universe}`)
// - Anti-entropy uses the `libp2p_stream::Behaviour` for the `/aos/sync/1.0.0` protocol

// types.rs
pub struct BuildJob {
    pub job_id: String,
    pub drv_path: String,
    pub drv_hash: String,
    pub universe: String,
    pub arch: String,
    pub features: Vec<String>,
    pub priority: i32,
    pub input_hashes: Vec<String>,
    pub submitted_at: u64,
    pub submitter_peer_id: String,
}

pub struct BuildClaim {
    pub peer_id: String,
    pub status: String,      // "building"
    pub started_at: u64,
}

pub struct BuildResult {
    pub status: String,      // "complete" or "failed"
    pub outputs: Vec<String>,
    pub completed_at: u64,
    pub error: Option<String>,
}

pub struct LogEvent {
    pub seq: u64,
    pub kind: String,        // "status", "log", "complete", "error"
    pub line: String,
    pub timestamp: u64,
}
```

### Dependencies

```toml
[dependencies]
libp2p = { version = "0.54", features = [
    "tokio",
    "quic",
    "mdns",
    "kad",
    "gossipsub",
    "autonat",
    "relay",
    "identify",
    "macros",
    "noise",
] }
libp2p-stream = "0.2"
ucan = "0.4"
fastcdc = "3"
xxhash-rust = { version = "0.8", features = ["xxh3"] }
sha2 = "0.10"
blake3 = "1"           # Merkle tree hashing (alternative to sha2; sha2 also sufficient)
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", features = ["full"] }
bloomfilter = "1"
```

## aos-daemon -- Unified Daemon Binary

The single daemon binary. Manages the local Nix store, performs builds, and joins
the mesh. Local clients communicate via a Unix socket control protocol. Auth
policy maps local uid/gid to capabilities (no HTTP, no JWT).

The daemon also supports a **forwarding mode** for containers and VMs: it binds
a control socket inside the container and forwards requests to an upstream
daemon socket on the host, narrowing capabilities at each level. The forwarding
mode is extremely lightweight (~200 lines) -- no mesh participation, no store
management, just socket-to-socket proxying. See [sockets.md](sockets.md).

```
aos-daemon/
  src/
    main.rs               # CLI entry, config loading, daemon startup
    config.rs             # Daemon configuration (TOML)
    worker.rs             # Main event loop, job listening, claiming
    executor.rs           # Build execution (nspawn + ephemeral FUSE view, see builds.md)
    logs.rs               # Log buffer, GossipSub publishing, replay handler
    store.rs              # Local store queries, bloom filter, input fetching
    provider.rs           # DHT provider announcement for build outputs
    heartbeat.rs          # Capability advertisement, DHT refresh
    shutdown.rs           # Graceful shutdown handling
    control.rs            # Unix socket control protocol (local CLI <-> daemon)
    policy.rs             # Local auth policy (uid/gid -> capabilities)
    viewdb.rs             # ViewDb trait: view (persistent) and ephemeral view lifecycle
    sync_handler.rs       # Handles incoming sync deltas, triggers content fetch, manages local CRDT state
    chunk_store.rs        # Content-defined chunk storage, manifest management, chunk GC
```

### Unix Socket Control Protocol (`control.rs`)

Local clients (the `aos` CLI) connect to the daemon over a Unix domain socket
rather than HTTP. The control protocol is a simple newline-delimited JSON
request/response protocol.

```rust
// control.rs
pub struct ControlServer {
    pub socket_path: PathBuf,    // e.g. /run/aos/daemon.sock
}

pub enum ControlRequest {
    Build { drv_path: String, universe: String },
    SubscribeLogs { job_id: String },
    Status,
    Gc { older_than: Option<Duration> },
}

pub enum ControlResponse {
    BuildStarted { job_id: String },
    LogLine(LogEvent),
    Status { peers: usize, jobs_active: usize },
    GcComplete { freed_bytes: u64 },
    Error { message: String },
}
```

### Local Auth Policy (`policy.rs`)

The daemon checks the connecting process's uid/gid (via `SO_PEERCRED`) and maps
it to a set of capabilities. No tokens are needed for local communication.

```rust
// policy.rs
pub struct PolicyConfig {
    pub admin_groups: Vec<String>,    // gids that get Admin capability
    pub build_groups: Vec<String>,    // gids that get Build capability
    pub allow_all_users: bool,        // if true, any local user can submit builds
}

impl PolicyConfig {
    pub fn capabilities_for(&self, uid: u32, gid: u32) -> Vec<Capability>;
}
```

### Dependencies

```toml
[dependencies]
aos-p2p = { path = "../aos-p2p" }
aos-core = { path = "../aos-core" }
tokio = { version = "1", features = ["full"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
toml = "0.8"
anyhow = "1"
clap = { version = "4", features = ["derive"] }
tracing = "0.1"
tracing-subscriber = "0.3"
lru = "0.12"
```

## Modifications to Existing Crates

### aos-core

Add shared types if not already present:
- NAR pack/unpack utilities
- Store path hash extraction
- Nix derivation parsing (input closure extraction)

### aos (CLI binary)

Subcommands:
- `aos daemon` -- run the daemon (manages local Nix store, performs builds, joins mesh; local CLI talks to it via Unix socket)
- `aos build` -- build a package (via daemon socket by default; with `-i <identity>`, joins the P2P mesh directly as a client peer)
- `aos net` -- network observability (peers, builds, topology, bandwidth, logs); with `-i <identity>`, observes via P2P mesh instead of daemon socket
  - `aos net peers` -- list connected mesh peers
  - `aos net builds` -- list active/recent builds
  - `aos net topology` -- show mesh topology
  - `aos net bandwidth` -- show bandwidth stats
  - `aos net logs` -- stream build logs
- `aos auth init` -- generate the cluster root keypair
- `aos auth enroll` -- issue UCANs from root key (generates initial UCAN for a peer)
- `aos auth delegate` -- daemon delegates sub-UCANs (attenuated capabilities to downstream peers)
- `aos auth revoke` -- revoke a UCAN
- `aos auth rotate-root` -- rotate the cluster root key
- `aos auth list` -- list issued tokens/UCANs

## Implementation Phases

### Phase 1: aos-p2p foundation
- [ ] NetworkBehaviour definition with all protocols
- [ ] Peer discovery (mDNS + Kademlia)
- [ ] GossipSub topic management
- [ ] DHT record helpers (typed put/get with serde)
- [ ] Bloom filter implementation
- [ ] P2pNode wrapper with event loop

### Phase 2: Auth protocol (aos-p2p)
- [ ] `/aos/auth/1.0.0` handshake protocol implementation
- [ ] UCAN token parsing and chain verification
- [ ] Capability model (Build, Watch, Fetch, Delegate, Admin)
- [ ] Root key management and UCAN issuance (`aos auth enroll`)
- [ ] Sub-UCAN delegation (`aos auth delegate`)

### Phase 3: aos-daemon MVP
- [ ] Unix socket control server (`control.rs`)
- [ ] Local auth policy -- uid/gid to capabilities (`policy.rs`)
- [ ] Main loop: listen for jobs on GossipSub
- [ ] Job claiming via DHT
- [ ] Build execution (nspawn + ephemeral FUSE view)
- [ ] Log streaming via GossipSub
- [ ] Log replay handler (/aos/log-replay/1.0.0)
- [ ] Output announcement via DHT provider records
- [ ] Capability advertisement
- [ ] CRDT sync state (LWW-Map) and delta propagation via GossipSub (`sync/{universe}` topic)
- [ ] Merkle tree anti-entropy protocol (`/aos/sync/1.0.0`) for state reconciliation
- [ ] Sync handler -- incoming delta processing, content fetch triggers, local CRDT merge

### Phase 4: P2P client mode in `aos` binary
- [ ] Identity loading from `~/.aos/identities/{name}/`
- [ ] `-i <identity>` flag on `aos build` (P2P build submission)
- [ ] `-i <identity>` flag on `aos net` (P2P network observability)
- [ ] P2P mesh join with UCAN authentication
- [ ] NAR fetching for archivers

### Phase 5: Robustness
- [ ] Affinity-based delayed claiming
- [ ] Graceful shutdown
- [ ] Reconnect retry logic
- [ ] Builder crash detection and job re-announcement
- [ ] Daemon log cache (fallback for late joiners)
- [ ] Content transfer protocols (WANT_MANIFEST/WANT_CHUNK) for P2P mode
- [ ] Monitoring metrics

### Phase 6: Production hardening
- [ ] UCAN revocation lists
- [ ] Rate limiting
- [ ] GC integration
- [ ] Multi-arch support (cross-platform scheduling)
- [ ] Integration tests with multiple daemons

## Build and Test

```sh
# Build all crates
cargo build --workspace

# Run daemon locally
cargo run -p aos-daemon -- --config daemon.toml

# Integration test: start 3 daemons, submit a build via aos build -i
cargo test -p aos-p2p --test integration
```

## Relationship to Existing Code

The existing `aos-server` crate contains valuable code that will be refactored into `aos-daemon`:

| Existing module | Destination | Notes |
|----------------|-------------|-------|
| `build.rs` | `aos-daemon/src/executor.rs` | BuildManager -> local execution in daemon |
| `narinfo.rs` | `aos-daemon/src/store.rs` | Narinfo generation for P2P serving |
| `compress.rs` | `aos-daemon/src/store.rs` | NAR compression |
| `sign.rs` | `aos-daemon` | Daemon signs outputs, may re-sign when proxying |
| `drain.rs` | `aos-daemon` | Graceful shutdown |
| `views.rs` | `aos-daemon/src/viewdb.rs` | View (persistent) and ephemeral view management |
| `config.rs` | `aos-daemon/src/config.rs` | Unified daemon config |
| `store.rs` | `aos-daemon/src/store.rs` | Local store queries |
| `pack.rs` | `aos-daemon/src/store.rs` | NAR pack handling |
| `evict.rs` | `aos-daemon` | GC/eviction |

The `aos-remote` crate (old client) is removed. P2P client functionality is now
part of the `aos` binary, activated by the `-i <identity>` flag.
