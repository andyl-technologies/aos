# P2P Build System Architecture Overview

A fully distributed Nix build system using libp2p. No single coordinator --
every node is a peer in a self-organizing mesh. Two peer types participate:
daemons (full nodes with Nix stores) and clients (lightweight peers for remote
interaction).

## High-Level Architecture

The mesh consists of two types of peers:

1. **Daemon** -- A full node that owns a Nix store, builds derivations, and
   holds a machine-level identity. Each daemon runs as `aos daemon` and
   participates in peer discovery (mDNS/Kademlia), pub/sub (GossipSub), and
   distributed state (DHT). Daemons subscribe to job announcements via
   GossipSub, claim builds via DHT, run `nix-store --realise`, stream logs
   back via GossipSub and direct streams, and share outputs to the mesh via
   Bitswap. Local users interact with the daemon through a Unix socket control
   interface. Daemons are stateless and ephemeral -- they can be preempted,
   restarted, or scaled without coordination.

2. **Client** -- A lightweight peer with its own identity and UCAN
   capabilities, but no Nix store. Clients connect to the mesh to submit
   remote builds (`aos remote build`), observe build progress, archive
   results, and serve web UIs. Clients authenticate to daemons by presenting
   UCAN chains over the `/aos/auth/1.0.0` protocol. A client can be a
   developer laptop, a CI runner, a monitoring dashboard, or any process that
   needs to interact with the build mesh without running a full daemon.

**No external dependencies.** The mesh IS the infrastructure. There is no
separate gateway, coordinator, or HTTP API server. NAR transfer is purely
peer-to-peer via Bitswap-style libp2p protocols. NARs and narinfo metadata are
stored across the mesh using content-addressed blocks, replicated by the peers
that need them. There is no S3 bucket, no MinIO cluster, no external storage
service of any kind.

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
   capabilities (what a peer is allowed to do -- submit builds, read logs,
   delegate access). Unix sockets gate local control (only users with filesystem
   access to the daemon socket can issue local commands like `aos build`).

4. **Delegation without escalation.** Capabilities flow downward through UCAN
   chains, never upward. A daemon operator enrolls a client via `aos enroll`,
   issuing a root UCAN. That client can delegate a subset of its capabilities
   to another client via `aos delegate`, but can never grant more than it holds.
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

7. **Graceful degradation.** Network partitions do not stop work. A daemon
   that loses connectivity to the mesh continues building. It cannot announce
   completion or stream logs, but the build output is still correct. When
   connectivity returns, results are shared to the mesh via Bitswap and the
   DHT is updated. Duplicate builds across partitions reconcile automatically
   because outputs are content-addressed.

## libp2p Protocols Used

| Protocol | Purpose |
|---|---|
| mDNS | LAN peer discovery. Finds peers on the local network without any configuration or bootstrap nodes. |
| Kademlia DHT | WAN peer discovery, build claim records, daemon capability advertisements, build result announcements. The DHT is the distributed key-value store that replaces etcd/Consul. |
| GossipSub | Pub/sub for job announcements, live log streaming, and build completion notifications. Messages fan out across the mesh with logarithmic overhead. |
| `/aos/auth/1.0.0` | Peer authentication handshake. On connection, peers present UCAN chains to prove their capabilities. Daemons verify the chain against their trust root before granting access to mesh resources. |
| Stream (libp2p-stream) | Point-to-point streams for log replay (late joiners requesting historical output), NAR fetch (peer-to-peer binary transfer), and direct data exchange between specific peers. |
| AutoNAT | NAT detection. Peers behind NAT discover their reachability status by asking other peers to dial them back. |
| Relay + DCUtR | NAT traversal. Relay nodes forward traffic for unreachable peers. DCUtR upgrades relayed connections to direct connections via UDP hole punching, eliminating the relay hop. |
| QUIC transport | UDP-based transport with built-in TLS 1.3, multiplexed streams, and 0-RTT connection establishment. NAT-friendly because UDP hole punching is more reliable than TCP. |

## CLI Commands

| Command | Description |
|---|---|
| `aos daemon` | Start a full daemon node (Nix store, builds, mesh participation, Unix socket control) |
| `aos build` | Submit a local build to the daemon via Unix socket |
| `aos remote build` | Submit a remote build as a P2P client peer (UCAN-authenticated) |
| `aos remote status` | Query build status from the mesh as a P2P client peer |
| `aos enroll` | Enroll a new client peer, issuing it a root UCAN from this daemon |
| `aos delegate` | Delegate a subset of capabilities to another peer via UCAN |

## Document Index

- [mesh.md](mesh.md) -- Peer discovery, mesh formation, NAT traversal, bootstrap nodes
- [auth.md](auth.md) -- Authentication, authorization, UCAN capabilities, Unix socket control, cluster bootstrapping
- [jobs.md](jobs.md) -- Job submission, claiming protocol, scheduling via affinity scores
- [logs.md](logs.md) -- Log streaming via GossipSub, log replay via direct streams, durability
- [store.md](store.md) -- P2P NAR transfer via Bitswap, content-addressed storage, mesh replication
- [failures.md](failures.md) -- Failure modes, recovery strategies, partition tolerance analysis
- [daemon.md](daemon.md) -- Daemon design, Unix socket control, build execution, store management, log replay
- [crates.md](crates.md) -- Crate structure, dependency graph, implementation plan
