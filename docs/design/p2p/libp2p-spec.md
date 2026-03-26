# AOS P2P Quick-Reference Spec

Single reference for all networking primitives in the AOS distributed build system.

---

## 1. Transport

| Type | Port | Encryption | Multiplexing | Notes |
|------|------|------------|--------------|-------|
| QUIC (primary) | UDP 4001 | TLS 1.3 (peer Ed25519 key) | Native QUIC streams | NAT-friendly, 0-RTT |
| Relay (fallback) | Via relay peer | Noise XX + Yamux | Yamux over TCP | For NATed peers; upgraded via DCUtR |

Listen addresses:
- `/ip4/0.0.0.0/udp/4001/quic-v1`
- `/ip6/::/udp/4001/quic-v1`

Peer identity: Ed25519 keypair. PeerId = multihash(pubkey). No CA/PKI.

---

## 2. GossipSub Topics

**Mesh parameters:** D=6, D_lo=4, D_hi=12, D_lazy=6, heartbeat=5s, max_transmit_size=256 KiB, duplicate_cache=60s.

| Topic Pattern | Scope | Payload | Publisher | Subscribers | Auth | Ref Doc |
|---|---|---|---|---|---|---|
| `build/wanted/{universe}/{system}` | Universe+system | `BuildJob` | Submitting daemon | Daemons for that universe+arch | `build/submit` UCAN | jobs.md |
| `build/claimed/{universe}/{system}` | Universe+system | `BuildClaim` (GossipSub) | Claiming daemon | Daemons for that universe+arch | `build/claim` UCAN | jobs.md |
| `build/result/{universe}/{system}` | Universe+system | `BuildResult` | Building daemon | Daemons for that universe+arch | `build/claim` UCAN | jobs.md |
| `build/logs/{drv_hash}` | Per-derivation | `LogEvent` | Building daemon | Any authorized peer (on-demand subscribe) | `build/observe` UCAN | logs.md |
| `sync/{universe}` | Universe | `SyncMessage::Delta` | Any peer with `sync/write` | All peers in universe | `sync/write` UCAN (path-scoped) | sync.md |
| `sync/{universe}/announce` | Universe | `StateAnnounce` | All syncing peers (periodic) | All peers in universe | `sync/read` UCAN | sync.md |

**Note:** `build/wanted`, `build/claimed`, and `build/result` are being replaced by sync namespace graph entries. `build/logs/{drv_hash}` remains.

All messages carry an Ed25519 signature (libp2p message signing) plus a UCAN in the envelope. The validation callback rejects messages with invalid/expired/insufficient UCANs; rejection feeds peer scoring (`invalid_message_deliveries_weight = -10.0`).

---

## 3. Stream Protocols

| Protocol ID | Purpose | Request Format | Response Format | Auth | Ref Doc |
|---|---|---|---|---|---|
| `/aos/auth/1.0.0` | Peer authentication handshake | `AuthRequest { ucan_chain: Vec<String> }` | `AuthResponse { ok, capabilities, error }` | Transport PeerId verified; UCAN chain checked to root key | auth.md |
| `/aos/sync/1.0.0` | Merkle-CRDT anti-entropy | `MerkleRequest { prefix, depth }` | `MerkleResponse { nodes: Vec<(String, Hash)> }` | Peer must be authenticated | sync.md |
| `/aos/log-replay/1.0.0` | Log replay for late joiners | `ReplayRequest { drv_hash, from_seq }` | Stream of `LogEvent` (replay + live tail) | `build/observe` UCAN | logs.md |
| WANT_MANIFEST | Fetch file-tree manifest | `WantManifestRequest { store_hash, universe }` | `ManifestResponse::Have(ManifestEntry)` or `DontHave` or `Denied` | `store/fetch` UCAN for universe | chunks.md, store.md |
| WANT_CHUNK | Fetch chunk data | `WantChunkRequest { chunk_hash }` | `ChunkResponse::Have(bytes)` or `DontHave` | None (mesh membership sufficient) | chunks.md |
| `/aos/shell/1.0.0` | Interactive remote shell | Shell create/resume/exec requests | Terminal stream (interactive) | `shell/create` UCAN | testing.md |
| `/aos/metrics/1.0.0` | Query remote peer metrics | `{ categories: [latency, bandwidth, topology, builds] }` | JSON metrics blob | Peer must be authenticated | net.md |
| `/aos/store-search/1.0.0` | Search store paths by name | Name pattern string | Matching manifest entries | Peer must be authenticated | net.md |
| `/aos/id/1.0.0` (Identify) | Address exchange | Automatic (libp2p Identify) | PeerId, listen addrs, observed addr, protocols | Transport layer | mesh.md |
| `/aos/kad/1.0.0` (Kademlia) | DHT routing | Standard Kademlia RPCs | Standard Kademlia responses | Transport layer | mesh.md |
| `/ipfs/ping/1.0.0` | Connectivity test | 32-byte random payload | Echo response | Transport layer | net.md |

---

## 4. DHT Records

| Key Pattern | Value Format | TTL | Publisher | Purpose | Ref Doc |
|---|---|---|---|---|---|
| `build:{drv_hash}` | `{ peer_id, status, started_at, outputs?, completed_at?, error? }` | 30 min (building), 24h (complete), 1h (failed) | Claiming/building daemon | Build claim and result tracking | jobs.md |
| `daemon:{peer_id}` | `{ arch, features, max_jobs, active_jobs, store_bloom (base64), last_updated }` | 5 min (re-published every 2 min) | Each daemon | Capability advertisement, scheduling hints | jobs.md |
| Provider records: `store_hash` | PeerId set (Kademlia native) | **LRU-aware per-path**: TTL-GC = `max_age - time_since_last_access`; Budget-GC = `time_to_pressure * rank_ratio`; Pinned/CRDT = 24h max | Daemon holding the path | Content provider discovery for WANT_MANIFEST/WANT_CHUNK | chunks.md, store.md |
| `revocations` | `{ revoked: [did:key:...], updated_at }` | Long-lived | Admin daemon | UCAN revocation list | auth.md |
| `pin:{universe}:{hash}` | Pin metadata | Long-lived | Pinning daemon | Pinned closure tracking | views.md |

Kademlia config: replication_factor=20, record_ttl=3600s, publication_interval=600s, mode=Server.

---

## 5. Sync Namespace Paths

All entries are LWW-CRDT closure roots in `sync/{universe}/`.

| Path Pattern | Content | Publisher | UCAN Scope | Ref Doc |
|---|---|---|---|---|
| `graph/{store_hash}` | Build result closure root (replaces build/wanted, build/claimed, build/result) | Building daemon | `aos://{universe}/sync/graph/*` | sync.md, overview.md |
| `profiles/{user}` | User profile derivation (packages + config + activation scripts) | User's daemon or client | `aos://{universe}/sync/profiles/{user}/*` | sync.md, package.md |
| `registries/{name}` | Registry store path (symlink tree to packages + .drv files) | Registry maintainer | `aos://{universe}/sync/registries/*` | sync.md, package.md |
| `registries/{name}/{platform}` | Platform-specific registry pointer | Registry maintainer | `aos://{universe}/sync/registries/{name}/*` | package.md |
| `shells/{name}` | Container state ref (host, ZFS, status) | Shell creator | `aos://{universe}/sync/shells/*` | sync.md, testing.md |
| `config` | Universe config derivation (registry list, trusted builders, policies) | Admin | `aos://{universe}/sync/config` | sync.md |
| `pins/{name}` | Pinned closure root (any store path to retain across universe) | Admin or pinning user | `aos://{universe}/sync/pins/*` | sync.md |
| `packages/{name}` | Named package set roots | Admin | `aos://{universe}/sync/packages/*` | sync.md |
| `deploy/{env}` | System configuration derivation | Admin | `aos://{universe}/sync/deploy/*` | sync.md |

Entry structure:

```rust
struct SyncEntry {
    store_hash: String,       // closure root
    timestamp: u64,           // LWW ordering
    alive: bool,              // false = tombstone
    author: PeerId,
}
```

Merge: highest timestamp wins. On tie, `alive=true` wins (add bias). CRDT properties: commutative, associative, idempotent.

Merkle tree: path hierarchy IS the tree. `leaf = H(path || store_hash || timestamp || alive || author)`. Anti-entropy via `/aos/sync/1.0.0` stream; real-time via `sync/{universe}` GossipSub.

---

## 6. Unix Socket Protocol

### Socket Types

| Socket | Path | Auth | Scope | Capabilities |
|---|---|---|---|---|
| Control | `/run/aos/control.sock` | SO_PEERCRED (uid/gid) | All views | Per uid/gid local policy |
| View | `/run/aos/sockets/view-{name}.sock` | Socket-as-credential | One view | submit, observe, path-info |
| Build | `/run/aos/sockets/build-{drv-hash}.sock` | Socket-as-credential | One ephemeral view | path-info, register-output |

### Control Commands (JSON-lines protocol)

| Command | Action | Required Capability | Response |
|---|---|---|---|
| `{"cmd": "build", "drv_path": "...", "view": "..."}` | Submit build | `submit` | Stream of `LogEvent` lines |
| `{"cmd": "watch", "drv_hash": "...", "from_seq": N}` | Tail build logs | `observe` | Stream of `LogEvent` lines |
| `{"cmd": "status", "drv_hash": "..."}` | Query build status | `observe` | JSON status object |
| `{"cmd": "status"}` | Query daemon status | `observe` | JSON (peers, active builds, uptime) |
| `{"cmd": "gc", "view": "..."}` | Trigger GC | `manage` | `{ freed_bytes }` |
| `{"cmd": "peers"}` | List mesh peers | `observe` | JSON peer list |
| `{"cmd": "delegate", "peer_id": "...", "capabilities": [...], "lifetime_secs": N}` | Mint child UCAN | `manage` | UCAN token string |
| `{"action": "fetch", "hash": "..."}` | Fetch store path from upstream | `fetch` | NAR data stream |
| `{"action": "has-path", "hash": "..."}` | Query upstream for path | `observe` | `{ exists: bool }` |
| `{"action": "metrics"}` | Query daemon metrics | `observe` | JSON metrics blob |
| `{"action": "net-status"}` | Cluster status | `observe` | JSON summary |
| `{"action": "net-peers", "view": "...", "verbose": bool}` | List peers | `observe` | JSON peer list |
| `{"action": "net-builds", "view": "...", "active_only": bool}` | List builds | `observe` | JSON build list |
| `{"action": "net-events", "follow": bool, "filter": "..."}` | Event stream | `observe` | NDJSON event stream |

### Daemon Modes

| Mode | Mesh | Store | Sockets | Auto-detection |
|---|---|---|---|---|
| Full | Yes | Yes | control + view + build | No upstream socket at `/run/aos/upstream.sock` |
| Forward | No | No | control (proxies to upstream) | Upstream socket exists |
| Nested-full | Optional | Yes (own) | control + view + build | Explicit `mode = "full"` with upstream |

Capability intersection at each nesting level: `effective = upstream_scope INTERSECT local_user_policy`.

---

## 7. UCAN Capabilities

| Capability | Description | Typical Holder | Path-scoped? |
|---|---|---|---|
| `build/submit` | Publish jobs to `build/wanted/{universe}/{system}` | Daemons, dev clients, CI clients | Universe-scoped (`aos://{universe}/*`) |
| `build/claim` | Claim jobs and execute builds | Daemons only | Universe-scoped |
| `build/observe` | Subscribe to build logs, query status | All peers | Universe-scoped |
| `store/serve` | Serve NARs/chunks to requesting peers | Daemons | Universe-scoped |
| `store/fetch` | Fetch NARs/chunks from peers | Daemons, archiver clients | Universe-scoped |
| `admin/manage` | GC, view management, peer administration | Admin daemons | Universe-scoped |
| `sync/write` | Publish CRDT mutations to sync namespace | Daemons, dev clients | Path-scoped (`aos://{universe}/sync/profiles/dylan/*`) |
| `sync/read` | Receive CRDT state from universe | Daemons, clients | Path-scoped |
| `shell/create` | Create login shells on hosts | Daemons, dev clients | Universe-scoped |

UCAN structure: `{ iss, aud, exp, att: [{ with: "aos://{universe}/*", can: "..." }], prf: [parent-UCANs], fct }`.

Delegation: monotonically narrowing. Child cannot exceed parent. Path prefix matching for sync permissions.

Verification: signature chain back to root public key. Root pubkey is the only trust anchor distributed to all nodes.

---

## 8. Message Formats

### GossipSub Messages

```rust
struct BuildJob {
    job_id: String,                 // UUID v4
    drv_path: String,               // /nix/store/{hash}-foo.drv
    drv_hash: String,               // hash portion
    universe: String,
    arch: String,                   // e.g. "x86_64-linux"
    features: Vec<String>,          // e.g. ["kvm"]
    priority: i32,                  // 0 = normal, higher = more urgent
    input_hashes: Vec<String>,      // build closure hashes (for bloom affinity)
    submitted_at: u64,              // unix timestamp
    submitter_peer_id: String,
}

struct BuildClaim {
    drv_hash: String,
    peer_id: String,
    status: String,                 // "building"
    started_at: u64,
}

struct BuildResult {
    drv_hash: String,
    status: String,                 // "complete" or "failed"
    outputs: Vec<String>,           // output store paths
    completed_at: u64,
    error: Option<String>,
}

struct LogEvent {
    seq: u64,                       // monotonically increasing per build
    kind: String,                   // "status" | "log" | "complete" | "error"
    line: String,
    timestamp: u64,
}
```

### Sync Messages

```rust
enum SyncMessage {
    Delta {
        path: String,               // e.g. "profiles/dylan"
        entry: SyncEntry,
        ucan: String,
    },
    MerkleRequest {
        prefix: String,             // subtree to compare
        depth: u32,
    },
    MerkleResponse {
        nodes: Vec<(String, Hash)>,
    },
    StateAnnounce {
        root_hash: Hash,
        vector_clock: VectorClock,
        entry_count: u64,
    },
}

struct SyncEntry {
    store_hash: String,
    timestamp: u64,
    alive: bool,
    author: PeerId,
}
```

### Stream Protocol Types

```rust
// /aos/auth/1.0.0
struct AuthRequest { ucan_chain: Vec<String> }
struct AuthResponse { ok: bool, capabilities: Vec<Capability>, error: Option<String> }

// /aos/log-replay/1.0.0
struct ReplayRequest { drv_hash: String, from_seq: u64 }
// Response: stream of LogEvent

// WANT_MANIFEST
struct WantManifestRequest { store_hash: String, universe: String }
enum ManifestResponse { Have(ManifestEntry), DontHave, Denied }

// WANT_CHUNK
struct WantChunkRequest { chunk_hash: String }
enum ChunkResponse { Have(Vec<u8>), DontHave }

// Manifest entry
struct ManifestEntry {
    store_hash: String,
    store_path: String,
    entries: Vec<FsEntry>,
}
enum FsEntry {
    Dir { name: String, mode: u32 },
    File { name: String, size: u64, executable: bool, chunks: Vec<ChunkRef> },
    Symlink { name: String, target: String },
}
struct ChunkRef { hash: String, size: u32 }   // xxh3-128 hash

// Pack file location (LMDB value)
struct PackLocation {
    pack_id: u32,
    offset: u64,
    length: u32,
    compressed_length: u32,        // 0 = uncompressed
}
```

---

## 9. NetworkBehaviour

```rust
#[derive(NetworkBehaviour)]
struct AosBehaviour {
    mdns: mdns::tokio::Behaviour,                              // LAN discovery
    kademlia: kad::Behaviour<kad::store::MemoryStore>,         // WAN discovery + DHT
    gossipsub: gossipsub::Behaviour,                           // Pub/sub
    stream: libp2p_stream::Behaviour,                          // Direct streams
    autonat: autonat::Behaviour,                               // NAT detection
    relay_client: relay::client::Behaviour,                    // Relay for NATed peers
    identify: identify::Behaviour,                             // Address exchange
    allow_block_list: libp2p::allow_block_list::Behaviour<BlockedPeers>, // Emergency revocation
}
```

Publicly reachable peers additionally include `relay::Behaviour` (server side) with: max_reservations=128, max_circuits=64, max_circuits_per_peer=4, reservation_duration=3600s, max_circuit_duration=300s, max_circuit_bytes=1 MiB.

Connection limits: max_established_incoming=50, max_established_outgoing=50, max_per_peer=5, max_pending_incoming=20, max_pending_outgoing=20. Idle timeout: 60s (GossipSub heartbeats keep mesh peers alive).

---

## 10. NAT Traversal

4-layer strategy, each handling progressively harder NAT scenarios:

| Layer | Protocol | Mechanism | Outcome |
|---|---|---|---|
| 1. QUIC Transport | UDP | UDP hole punching more reliable than TCP; NAT mappings held longer | Handles many NAT scenarios with no extra protocol |
| 2. AutoNAT | Reachability probes | Peer asks others to dial back; retry_interval=60s, timeout=30s, boot_delay=15s | Determines Public vs Private status |
| 3. Circuit Relay | Relay reservation | NATed peer reserves on up to 3 relay peers; advertises relay address in DHT | Indirect connectivity (higher latency, bandwidth-limited) |
| 4. DCUtR | Coordinated hole punch | After relay connection: exchange addresses, simultaneous UDP packets | Upgrades relay to direct connection; fails only for symmetric NATs |

Decision flow:

```
Startup -> Listen QUIC :4001 -> Bootstrap Kademlia -> AutoNAT probes
  |
  +-> Public:  advertise direct addrs, enable relay server
  +-> Private: reserve on 3 relays, advertise relay addrs
               -> on each inbound relay connection: DCUtR attempt
               -> success: drop relay, use direct
               -> failure: keep relay
```

---

## 11. Content Addressing

### Hash Algorithms

| Level | Algorithm | Speed | Purpose |
|---|---|---|---|
| Chunk identity | xxh3-128 (xxHash) | 10+ GB/s | Dedup matching, chunk lookup, pack index key |
| Store path integrity | SHA-256 | ~500 MB/s | Nix compatibility, NAR hash, tamper detection |
| Merkle tree nodes | BLAKE3 (or SHA-256) | ~6 GB/s | Sync anti-entropy tree hashing |
| Peer identity | Ed25519 (multihash) | N/A | PeerId derivation |

### FastCDC Parameters

| Parameter | Value |
|---|---|
| Min chunk size | 64 KB |
| Average chunk size | 256 KB |
| Max chunk size | 1 MB |
| Algorithm | FastCDC v2020 (rolling hash) |
| Scope | Per-file (not per-NAR stream) |

Small files (< min_chunk_size) become a single chunk. Symlinks and directories carry no chunk data.

### Pack File Format

```
[magic: "AOSP" (4 bytes)]
[version: u32 (4 bytes)]
[chunk 0 data: N bytes]
[chunk 1 data: N bytes]
...
[chunk M data: N bytes]
[checksum: xxh3-128 of entire file (16 bytes)]
```

No per-chunk headers in pack file -- LMDB index tracks locations. Max pack size: 1 GB (configurable). Sealed packs are immutable. Compaction rewrites packs with >30% dead space.

ZSTD compression within packs: 30-40% for binaries, 60-70% for source code, skipped for chunks < 4 KB.

### LMDB Databases (chunk store: `chunks/index.mdb`)

| Database | Key | Value |
|---|---|---|
| `manifests_db` | store_hash | `ManifestEntry` (file tree) |
| `locations_db` | chunk_hash | `PackLocation` (pack_id, offset, length, compressed_length) |
| `chunk_refs_db` | chunk_hash | `Vec<ChunkLocation>` (reverse index: store_hash + file_path) |

### Dedup Examples

| Scenario | Typical dedup ratio |
|---|---|
| Same package, 1-byte patch | ~99.97% (2 chunks differ out of ~8K) |
| Shared library across packages | 100% (exact same file = same chunks) |
| Full rebuild with new GCC | 40-60% chunk reuse |
| Registry update (5/1000 pkgs changed) | Only 5 package closures transferred |

---

## Source Documents

| Document | Covers |
|---|---|
| [overview.md](overview.md) | Architecture, design principles, protocol summary, mesh scoping |
| [mesh.md](mesh.md) | Peer discovery, mesh formation, NAT traversal, GossipSub config |
| [auth.md](auth.md) | UCAN, peer identity, Unix socket auth, cluster bootstrapping |
| [jobs.md](jobs.md) | Job submission, claiming, affinity scheduling, DAG awareness |
| [logs.md](logs.md) | Log streaming, replay, reconnection, durability |
| [store.md](store.md) | NAR transfer, provider discovery, output publishing, GC |
| [chunks.md](chunks.md) | FastCDC, pack files, chunk store, FUSE reads, dedup |
| [daemon.md](daemon.md) | Daemon modes, config, lifecycle, build execution, control protocol |
| [builds.md](builds.md) | nspawn isolation, ephemeral views, OverlayFS, output verification |
| [sockets.md](sockets.md) | Socket types, forwarding, multi-level nesting |
| [sync.md](sync.md) | CRDT sync, merkle anti-entropy, path-namespaced state |
| [views.md](views.md) | View projections, GC policies, FUSE modes, access tracking |
| [net.md](net.md) | `aos net` observability CLI, metrics, data sources |
| [package.md](package.md) | APM, registries, profiles, P2P package distribution |
| [crates.md](crates.md) | Rust crate structure, implementation plan |
| [testing.md](testing.md) | Acceptance criteria, test harnesses |
