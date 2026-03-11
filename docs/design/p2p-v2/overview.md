# AOS P2P v2 Protocol Overview

AOS P2P v2 is a peer-to-peer protocol for distributed package builds, content
storage, and job execution. It runs on libp2p and organizes peers into
clusters -- trust domains that scope communication, authorization, and
membership.

## Identity Model

The protocol defines three identity types, each backed by a libp2p keypair:

| Identity | Scope | Purpose |
|---|---|---|
| **PeerIdentity** | Daemon | Long-lived identity of a running AOS daemon. Signs profile records. |
| **JobIdentity** | Per-job | Ephemeral identity created for each job. Jobs are full libp2p participants. Signs job state records. |
| **ClusterIdentity** | Cluster | Root identity for a cluster. Signs cluster configuration records. Issues UCAN capability delegations. |

## Clusters

A cluster is the fundamental trust domain. It determines:

- Which GossipSub topics a peer subscribes to.
- Which UCAN capabilities are valid (capabilities are scoped to a cluster).
- Which peers are members and what roles they hold.

Cluster configuration is published to the DHT as a signed record.

## Jobs

A job is a unit of work executed by a peer within a cluster. Jobs encompass
builds, login shells, and any other containerized task:

- **Build jobs** use a `BuilderSpec` container type with a writable store
  overlay and network access disabled.
- **Login shells** use a `ProfileContainer` container type.

Each job gets its own `JobIdentity` (keypair and PeerId) and participates in
libp2p independently.

### Two-Phase Execution

Job execution follows a two-phase protocol:

1. **Post**: The creator publishes a `JobPost` to the cluster's jobs GossipSub
   topic.
2. **Claim + Exec**: A claimant claims the job (providing an `exec_ucan` in the
   claim). The creator then calls `/aos/job/exec/1.0.0` on the claimant to
   initiate execution.

The client is responsible for managing build DAGs and submitting jobs in
dependency order.

## Content Storage

Content is identified by object ID and transferred in two steps:

1. **Discovery**: DHT provider records (`aos:store:{object_id}`) advertise which
   peers hold an object. TTL is based on GC LRU eviction; no signature
   validation is required.
2. **Transfer**: The `/aos/store/manifest/1.0.0` stream protocol retrieves the
   file tree structure. The `/aos/store/chunk/1.0.0` stream protocol transfers
   raw data chunks.

## Protocol Summary

### DHT Records

| Key Pattern | Value Type | Lifetime | Signed By |
|---|---|---|---|
| `aos:store:{object_id}` | ProviderRecord | TTL (GC LRU eviction) | None (no signature validation) |
| `aos:profile:{peer_ident}` | ProfileSpec | Long-lived | PeerIdentity |
| `aos:job:{job_ident}` | JobState | Short-lived (liveness check) | JobIdentity |
| `aos:cluster:{cluster_ident}` | ClusterConfig | Long-lived | ClusterIdentity |

### GossipSub Topics (per cluster)

| Topic | Message Type | Notes |
|---|---|---|
| `aos/cluster/{cluster_ident}/jobs/announce` | JobPost | CRDT |
| `aos/cluster/{cluster_ident}/load/announce` | LoadReport | |
| `aos/cluster/{cluster_ident}/control/announce` | ControlSignal | CRDT |

### Stream Protocols

| Protocol | Request/Response | Auth Requirement |
|---|---|---|
| `/aos/store/manifest/1.0.0` | ManifestRequest / ManifestResponse | `/aos/store/read` |
| `/aos/store/chunk/1.0.0` | ChunkRequest / Chunk (stream) | None |
| `/aos/job/exec/1.0.0` | ExecRequest / ExecResult | `/aos/job/exec` WHERE `.job == {job_ident}` |
| `/aos/job/log/1.0.0` | LogRequest / LogResponse | `/aos/job/read` WHERE `.cluster == {cluster_ident}` OR `.job == {job_ident}` |

## Document Index

| Document | Description |
|---|---|
| [overview.md](overview.md) | This document. Protocol summary and key concepts. |
| [identity.md](identity.md) | Identity types, keypairs, and signing. |
| [clusters.md](clusters.md) | Cluster configuration, membership, and trust domains. |
| [dht.md](dht.md) | DHT record types, lifetimes, and validation rules. |
| [gossipsub.md](gossipsub.md) | GossipSub topics, message types, and CRDT semantics. |
| [streams.md](streams.md) | Stream protocols, request/response formats, and auth. |
| [jobs.md](jobs.md) | Job lifecycle, two-phase execution, and container types. |
| [store.md](store.md) | Content storage, provider records, manifest and chunk transfer. |
| [auth.md](auth.md) | UCAN capabilities, delegation, and per-protocol authorization. |
| [containers.md](containers.md) | Container orchestration: profile containers (systemd activation) and build containers (derivation execution, store output). |
