# P2P Build System Architecture Overview

A fully distributed Nix build system using libp2p. No single coordinator --
every node is a peer in a self-organizing mesh. Two peer types participate:
daemons (full nodes with Nix stores) and clients (lightweight peers for remote
interaction).

## Terminology

- **Universe** -- The wire-protocol identity of a trust domain. Universes scope
  GossipSub topics (`build/wanted/{universe}/{system}`, `sync/{universe}`), UCAN
  capabilities (`aos://{universe}/*`), WANT_MANIFEST requests, and enrollment. A universe is
  the unit of mesh-level isolation: peers subscribe to universes, UCANs grant
  capabilities within universes, and manifests are served per-universe.

- **View** -- A local, persistent (or ephemeral) projection of the chunk store,
  defined by a projection function over a universe. Views are path-namespaced
  (e.g., `profiles/dylan`, `staging`, `builds/{drv-hash}`). Each view has its
  own FUSE mount, access tracking (LMDB), GC policy, sync mode, and FUSE
  operation mode. A view always represents some subset of a universe's content.
  CLI flags like `--view`, FUSE paths (`/run/aos/views/{name}/`), and GC
  commands operate on views. The view namespace mirrors the sync namespace:

  ```
  views/
    profiles/
      dylan              → view projecting sync/universe/profiles/dylan
      alice              → view projecting sync/universe/profiles/alice
    staging              → full universe projection
    prod                 → receive-only full projection
    builds/
      {drv-hash}         → ephemeral build closure projection
  ```

- **Registry** -- A metadata source that maps package names and versions to
  store hashes and derivation paths. Registries do not host NARs; the mesh
  handles content distribution.

- **Sync** -- The sync layer provides CRDT-based state synchronization across
  all peers in a universe, using a path-namespaced merkle-CRDT. Profiles,
  registries, shell references, and configuration are all sync entries --
  closure roots at different paths in the `sync/{universe}/` namespace. The
  merkle tree provides consistency validation; anti-entropy repairs divergence.

A daemon's configuration binds each view to a universe. Multiple views on
different daemons can belong to the same universe, forming a shared trust and
content domain across the mesh.

## High-Level Architecture

The mesh consists of two types of peers:

1. **Daemon** -- A full node that owns a Nix store, builds derivations, and
   holds a machine-level identity. Each daemon runs as `aos daemon` and
   participates in peer discovery (mDNS/Kademlia), pub/sub (GossipSub), and
   distributed state (DHT). Daemons subscribe to job announcements via
   GossipSub, claim builds via DHT, execute builds inside nspawn containers
   with ephemeral FUSE views exposing only the declared input closure, stream
   logs back via GossipSub and direct streams, and share outputs to the mesh
   via content-defined chunking (FastCDC) with a two-level transfer protocol:
   universe-scoped manifest requests and universe-agnostic chunk exchange. Local users
   interact with the daemon through a Unix socket control
   interface. The daemon runs in one of three modes: **full** (mesh + store +
   sockets), **forward** (no mesh, forwards requests to an upstream daemon
   socket), or **auto-detect** (checks for an upstream socket at startup and
   picks full or forward accordingly). See [sockets.md](sockets.md) for the
   socket architecture. Daemons are stateless and ephemeral -- they can be
   preempted, restarted, or scaled without coordination.

2. **Client** -- A lightweight peer with its own identity and UCAN
   capabilities, but no Nix store. Clients connect to the mesh to submit
   remote builds (`aos build -i <identity>`), observe build progress, archive
   results, and serve web UIs. Clients authenticate to daemons by presenting
   UCAN chains over the `/aos/auth/1.0.0` protocol. A client can be a
   developer laptop, a CI runner, a monitoring dashboard, or any process that
   needs to interact with the build mesh without running a full daemon.

**No external dependencies.** The mesh IS the infrastructure. There is no
separate gateway, coordinator, or HTTP API server. NAR transfer is purely
peer-to-peer: NARs are split into content-defined chunks (FastCDC), referenced
by per-NAR manifests, and exchanged directly between peers. Manifests are
universe-scoped (auth boundary); chunks are universe-agnostic (content layer),
enabling cross-version deduplication. There is no S3 bucket, no MinIO cluster,
no external storage service of any kind.

```
    Daemons are full nodes (Nix store, builds, machine identity).
    Clients are lightweight peers (own identity + UCAN, no store).

    ┌──────────┐   ┌──────────┐   ┌──────────┐
    │ Daemon   │◄─►│ Daemon   │◄─►│ Daemon   │
    │ [nix]    │   │ [nix]    │   │ [nix]    │
    └────┬─────┘   └────┬─────┘   └────┬─────┘
         │    GossipSub  │  Kademlia    │
         │    mesh       │  DHT         │
    ┌────▼─────┐   ┌────▼─────┐   ┌────▼─────┐
    │ Daemon   │◄─►│ Client   │◄─►│ Client   │
    │ [nix]    │   │ (remote) │   │ (web UI) │
    └──────────┘   └──────────┘   └──────────┘

    No external dependencies -- the mesh IS the infrastructure
```

All arrows are bidirectional libp2p connections over QUIC. Daemons and clients
differ in capability: daemons hold Nix stores and execute builds; clients hold
UCAN tokens and delegate work to daemons. Both are first-class mesh
participants with their own libp2p identities.

## Why libp2p Over NATS/Kafka/etcd

### Problems with centralized message brokers

- **Cluster management overhead.** NATS requires a JetStream cluster with Raft
  consensus. Kafka requires ZooKeeper or KRaft for leader election and partition
  assignment. etcd requires a Raft quorum. Each of these is a stateful service
  that must be deployed, monitored, backed up, and upgraded independently of the
  build system itself.

- **Single dependency.** Even with replication, the broker cluster is a single
  logical dependency. If the NATS cluster loses quorum, all job dispatch stops.
  If Kafka loses its controller, partition leadership freezes. The build system
  inherits the failure modes of a system it does not control.

- **Configuration coupling.** Every node must be configured with broker
  addresses. Adding or moving brokers requires reconfiguring all clients.
  Service discovery (Consul, DNS SRV) can help but adds yet another dependency.

- **Scaling friction.** Adding broker capacity means adding broker nodes,
  rebalancing partitions, and waiting for replication to catch up. This is a
  fundamentally different scaling model from "start another builder."

### libp2p advantages

- **Zero-config peer discovery.** mDNS finds peers on the local network with no
  configuration. Kademlia DHT finds peers across WANs using bootstrap nodes
  (which are themselves just peers, not special infrastructure).

- **No leader election.** Every peer is equal. There is no quorum to maintain,
  no leader to elect, no split-brain to resolve. The DHT provides eventual
  consistency, which is sufficient because Nix builds are deterministic.

- **Embedded in each process.** The libp2p host runs inside the daemon binary.
  There is no external service to deploy. The mesh exists because the daemon
  processes exist.

- **Automatic NAT traversal.** AutoNAT detects whether a peer is behind NAT.
  Relay nodes provide fallback connectivity. DCUtR (Direct Connection Upgrade
  through Relay) upgrades relayed connections to direct connections via UDP hole
  punching. Daemons behind NAT can participate without manual port forwarding.

- **Elastic mesh.** The mesh grows when peers join and shrinks when peers leave.
  No rebalancing, no partition reassignment, no quorum recalculation. A mesh of
  3 peers and a mesh of 300 peers work identically.

- **Battle-tested at scale.** libp2p is the networking layer for IPFS (millions
  of nodes), Ethereum 2.0 (hundreds of thousands of validators), and Filecoin
  (thousands of storage providers). Its peer discovery, NAT traversal, and
  pub/sub have been hardened in adversarial production environments.

## Design Principles

1. **No coordinator.** Scheduling is emergent from local decisions. Each daemon
   independently evaluates announced jobs, computes an affinity score (based on
   warm cache hits, system match, current load), and delays its claim
   proportionally. High-affinity daemons claim first. There is no central
   scheduler to bottleneck, fail, or require consensus.

2. **Idempotency over consistency.** Nix builds are deterministic -- the same
   derivation always produces the same output hash. This means duplicate work
   (two daemons racing to claim the same job) wastes compute but never produces
   incorrect results. This property lets us use eventual consistency (Kademlia
   DHT) instead of strong consistency (Raft/Paxos), eliminating an entire class
   of distributed systems complexity.

3. **Three-layer auth.** libp2p identity secures transport (every peer has a
   cryptographic identity verified at connection time). UCAN tokens encode mesh
   capabilities scoped to universes (what a peer is allowed to do within a given
   universe -- e.g., `aos://staging/submit`, `aos://prod/read`). Unix sockets gate
   local control (only users with filesystem
   access to the daemon socket can issue local commands like `aos build`).

4. **Delegation without escalation.** Capabilities flow downward through UCAN
   chains, never upward. A daemon operator enrolls a client via `aos auth enroll`,
   issuing a root UCAN. That client can delegate a subset of its capabilities
   to another client via `aos auth delegate`, but can never grant more than it holds.
   Revocation propagates through the chain.

5. **The daemon is the authority.** For an in-progress build, the daemon peer
   that claimed it is the canonical source of truth for logs and status. Late
   joiners (a user opening a web UI after a build started) request log replay
   directly from the daemon via a point-to-point libp2p stream. There is no
   log aggregation service to query.

6. **Content-addressed everything.** Nix store paths are content-addressed.
   NARs are content-addressed. narinfo files reference content hashes. This
   makes deduplication trivial (same hash = same content), caching natural
   (immutable objects can be cached forever), and peer-to-peer transfer safe
   (fetch from any peer, verify by hash).

7. **Views as persistent projections.** A view is a named, persistent (or
   ephemeral) projection of the chunk store -- a GC root collection, a
   permission boundary, and a logical isolation layer. Views are path-namespaced
   (e.g., `profiles/dylan`, `staging`, `builds/{drv-hash}`). The same store
   path can exist in multiple views. GC is per-view; actual store cleanup
   happens when paths have no remaining roots in any view.

8. **Build isolation.** Builds run in nspawn containers with ephemeral views
   (short-lived FUSE mounts) containing only the declared input closure.
   Whitelist isolation (only declared deps exist) rather than blacklist (try to
   hide everything else). Ephemeral views are destroyed when the build completes
   or the daemon crashes.

9. **Structural auth on sockets.** Socket path is the credential for
   containers. `SO_PEERCRED` for host users. No tokens on sockets.
   Capabilities narrow through nesting levels.

10. **Generic sync primitive.** One CRDT sync protocol handles all distributed
    state -- profiles, registries, containers, configuration -- using
    path-namespaced entries under `sync/{universe}/` with merkle tree
    consistency validation. Rather than building separate replication mechanisms
    for each state type, all mutable distributed state flows through the same
    anti-entropy protocol.

11. **Graceful degradation.** Network partitions do not stop work. A daemon
   that loses connectivity to the mesh continues building. It cannot announce
   completion or stream logs, but the build output is still correct. When
   connectivity returns, results are shared to the mesh via the manifest/chunk
   protocol and the DHT is updated. Duplicate builds across partitions reconcile
   automatically because outputs are content-addressed.

## libp2p Protocols Used

| Protocol | Purpose |
|---|---|
| mDNS | LAN peer discovery. Finds peers on the local network without any configuration or bootstrap nodes. |
| Kademlia DHT | WAN peer discovery, build claim records, daemon capability advertisements, build result announcements (routing + value records). The DHT is the distributed key-value store that replaces etcd/Consul. |
| GossipSub | Pub/sub for job announcements, live log streaming, and build completion notifications (events). Messages fan out across the mesh with logarithmic overhead. |
| `/aos/auth/1.0.0` | Peer authentication handshake. On connection, peers present UCAN chains to prove their capabilities. Daemons verify the chain against their trust root before granting access to mesh resources. |
| WANT_MANIFEST / WANT_CHUNK | Two-level content transfer. WANT_MANIFEST requests are universe-scoped (auth boundary); WANT_CHUNK requests are universe-agnostic (content layer). See [chunks.md](chunks.md). |
| `/aos/sync/1.0.0` | Merkle-CRDT anti-entropy and consistency milestones. Peers exchange merkle tree roots and deltas to converge on shared state. See [sync.md](sync.md). |
| Stream (libp2p-stream) | Point-to-point streams for log replay (late joiners requesting historical output) and direct data exchange between specific peers. |
| AutoNAT | NAT detection. Peers behind NAT discover their reachability status by asking other peers to dial them back. |
| Relay + DCUtR | NAT traversal. Relay nodes forward traffic for unreachable peers. DCUtR upgrades relayed connections to direct connections via UDP hole punching, eliminating the relay hop. |
| QUIC transport | UDP-based transport with built-in TLS 1.3, multiplexed streams, and 0-RTT connection establishment. NAT-friendly because UDP hole punching is more reliable than TCP. |

## Mesh Scoping Model

Different mesh primitives operate at different scopes:

| Primitive | Scope | Key/Topic Pattern | Rationale |
|-----------|-------|-------------------|-----------|
| GossipSub: job submission | Universe+system-scoped | `build/wanted/{universe}/{system}` | Daemons subscribe only to universes and architectures they serve. |
| GossipSub: log streaming | Drv-scoped | `build/logs/{drv_hash}` | Logs are per-derivation, not per-universe. Any authorized peer can tail. |
| GossipSub: build claimed | Universe+system-scoped | `build/claimed/{universe}/{system}` | Claim announcements follow the same universe+system scope as job submission. |
| GossipSub: build result | Universe+system-scoped | `build/result/{universe}/{system}` | Result announcements follow the same universe+system scope as job submission. |
| DHT: build claims | Universe-agnostic | `build:{drv_hash}` | Derivations are content-addressed; the same drv can appear in multiple universes. Claiming is global. |
| DHT: daemon capabilities | Universe-agnostic | `daemon:{peer_id}` | Capability advertisements are per-daemon, not per-universe. |
| UCAN | Universe-scoped | `aos://{universe}/*` | Permissions are granted per-universe. A peer may have `submit` in `staging` but not `prod`. |
| WANT_MANIFEST | Universe-scoped (with auth) | per-NAR manifest | Request includes universe name; serving daemon checks UCAN + local view membership before serving the manifest. |
| WANT_CHUNK | Universe-agnostic | by chunk hash | Chunks are content-addressed and shared across all universes. No auth required -- possession of a manifest (obtained via authenticated WANT_MANIFEST) implies authorization to fetch the referenced chunks. |
| GossipSub: sync deltas | Universe-scoped | `sync/{universe}` | CRDT deltas for path-namespaced state (profiles, registries, config). Peers subscribe to universes they serve. |
| GossipSub: sync announce | Universe-scoped | `sync/{universe}/announce` | Consistency milestone announcements -- merkle tree roots that peers use to detect divergence and trigger anti-entropy. |

## CLI Commands

| Command | Description |
|---|---|
| `aos daemon` | Start a full daemon node (Nix store, builds, mesh participation, Unix socket control) |
| `aos build` | Build a package (via daemon socket, or P2P with `-i`) |
| `aos net` | Network observability -- peers, builds, topology, bandwidth, logs |
| `aos auth init` | Generate the cluster root keypair |
| `aos auth enroll` | Enroll a new peer, issuing it a UCAN from the root key or this daemon |
| `aos auth delegate` | Delegate a subset of capabilities to another peer via UCAN |
| `aos auth revoke` | Revoke a UCAN |
| `aos auth rotate-root` | Rotate the cluster root key |
| `aos auth list` | List issued tokens/UCANs |

### The `-i` / `--identity` flag

The `-i <identity>` flag on `aos build` and `aos net` selects a P2P client
transport instead of the default daemon socket. Identity files live at
`~/.aos/identities/{name}/` and contain:

- `key.ed25519` -- the peer's ed25519 keypair
- `token.ucan` -- the UCAN token for mesh authentication
- `seed_peers` -- bootstrap peers for mesh discovery

When `-i` is omitted, commands talk to the local daemon via Unix socket.
When `-i <identity>` is provided, commands join the P2P mesh directly as a
lightweight client peer using the named identity.

## Document Index

- [mesh.md](mesh.md) -- Peer discovery, mesh formation, NAT traversal, bootstrap nodes
- [auth.md](auth.md) -- Authentication, authorization, UCAN capabilities, Unix socket control, cluster bootstrapping
- [jobs.md](jobs.md) -- Job submission, claiming protocol, scheduling via affinity scores
- [logs.md](logs.md) -- Log streaming via GossipSub, log replay via direct streams, durability
- [store.md](store.md) -- P2P NAR transfer, content-addressed storage, mesh replication
- [chunks.md](chunks.md) -- Content-defined chunking, Bitswap transfer, cross-version dedup, chunk store
- [failures.md](failures.md) -- Failure modes, recovery strategies, partition tolerance analysis
- [daemon.md](daemon.md) -- Daemon design, Unix socket control, build execution, store management, log replay
- [views.md](views.md) -- Views (persistent projections), garbage collection, per-view permissions, eviction policies, cross-view deduplication
- [builds.md](builds.md) -- Build isolation, ephemeral views (build sandboxes), nspawn containers, sandbox comparison
- [sockets.md](sockets.md) -- Unix socket architecture, three socket types, forwarding mode, multi-level nesting
- [net.md](net.md) -- Network observability CLI (`aos net`)
- [package.md](package.md) -- Package manager (APM) integration with views, profiles, P2P fetch chain
- [sync.md](sync.md) -- Generic CRDT sync protocol, merkle tree anti-entropy, path-namespaced state, consistency milestones
- [crates.md](crates.md) -- Crate structure, dependency graph, implementation plan
