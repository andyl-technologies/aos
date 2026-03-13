# AOS P2P v2 Protocol Overview

AOS P2P v2 is a peer-to-peer protocol for distributed package builds, content
storage, and job execution. It runs on libp2p and organizes peers into
clusters -- trust domains that scope communication, authorization, and
membership.

## Identity Model

The protocol uses a certificate tree hierarchy with four identity tiers:

| Identity | Scope | Purpose |
|---|---|---|
| **Root Identity** | Cluster | Offline key (vault/HSM). Signs intermediate certificates and ClusterConfig. Never used for day-to-day operations. |
| **Intermediate Identity** | Admin domain | Online key held by ops teams / CI / team leads. Issues UCANs to peers and jobs. Scoped capabilities, explicit expiry. |
| **PeerIdentity** | Daemon | Long-lived identity of a running AOS daemon. Identifies the daemon in all libp2p interactions. Receives UCANs from an intermediate. |
| **JobIdentity** | Per-job | Ephemeral identity created for each job. Jobs are full libp2p participants. Signs job state records. Receives UCANs from an intermediate. |

UCAN verification walks the cert chain: UCAN -> intermediate cert -> root
public key. See [auth.md](auth.md#8-cluster-bootstrapping) for the full
verification algorithm.

## Clusters

A cluster is the fundamental trust domain. It determines:

- Which GossipSub topics a peer subscribes to.
- Which UCAN capabilities are valid (capabilities are scoped to a cluster).
- Which peers are members and what roles they hold.

Cluster configuration is published to the DHT as a signed record.

## Jobs

A job is a unit of work executed by a peer within a cluster. Jobs encompass
builds, login shells, and any other containerized task:

- **Build jobs** use `ACTIVATION_DERIVATION` with a writable store overlay
  and network access disabled.
- **Service containers** use `ACTIVATION_SYSTEMD_V1` with systemd as PID 1.
- **Login shells** use `ACTIVATION_NONE` with a simple entrypoint.

Each job gets its own `JobIdentity` (keypair and PeerId) and participates in
libp2p independently.

### Two-Phase Execution

Job execution follows a two-phase protocol:

1. **Post**: The creator publishes a `JobPost` to the cluster's jobs GossipSub
   topic.
2. **Claim + Start**: A claimant claims the job (providing a `start_ucan` in the
   claim). The creator then calls `/aos/job/start/1.0.0` on the claimant to
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
| `aos:cluster:{cluster_ident}:job:{job_ident}` | ProviderRecord | Short (heartbeat) | None |
| `aos:cluster:{cluster_ident}:job:{job_ident}:state` | JobState | Short-lived (liveness check) | JobIdentity |
| `aos:cluster:{cluster_ident}` | ProviderRecord | Short (heartbeat) | None |
| `aos:cluster:{cluster_ident}:config` | ClusterConfig | Long-lived | Root Identity |
| `aos:auth:token:{token_hash}:revoke` | RevocationRecord | Mirrors token expiry | Token issuer key |
| `aos:store` | ProviderRecord | Short (1 min) | None |
| `aos:workflow` | ProviderRecord | Short (1 min) | None |
| `aos:workflow:{workflow_id}` | ProviderRecord | Workflow lifetime | None |

### GossipSub Topics (per cluster)

| Topic | Message Type | Notes |
|---|---|---|
| `aos/cluster/{cluster_ident}/jobs/announce` | JobPost | CRDT |
| `aos/cluster/{cluster_ident}/load/announce` | LoadReport | |
| `aos/auth/token/revoke` | RevocationNotice | Global (not cluster-scoped); peers fetch full record from DHT |
| `aos/auth/token/issue` | IssuanceNotice | Global (not cluster-scoped); optional issuance notification |
| `aos/store/publish` | StorePublish | Global (not cluster-scoped) |
| `aos/store/replicate` | ReplicateMessage | Global (not cluster-scoped) |
| `aos/store/purge` | StorePurge | Global (not cluster-scoped) |
| `aos/workflows/announce` | WorkflowPost | Global |
| `aos/workflows/active/{id}/state` | WorkflowStateMessage | Per-workflow |

### Stream Protocols

| Protocol | Request/Response | Auth Requirement |
|---|---|---|
| `/aos/store/manifest/1.0.0` | ManifestRequest / ManifestResponse | `/aos/store/read` |
| `/aos/store/chunk/1.0.0` | ChunkRequest / Chunk (stream) | `/aos/store/read` |
| `/aos/job/start/1.0.0` | JobStartRequest / JobStartResult | `/aos/job/start` WHERE `.job == {job_ident}` |
| `/aos/job/log/1.0.0` | LogRequest / LogResponse | `/aos/job/read` WHERE `.cluster == {cluster_ident}` OR `.job == {job_ident}` |
| `/aos/job/exec/1.0.0` | JobExecRequest / ExecFrame (bidirectional stream) | `/aos/job/exec` |
| `/aos/workflow/info/1.0.0` | WorkflowInfoRequest / WorkflowInfoResponse | `/aos/workflow/read` |
| `/aos/workflow/log/1.0.0` | WorkflowLogRequest / WorkflowTransition (stream) | `/aos/workflow/read` |
| `/aos/workflow/list/1.0.0` | WorkflowListRequest / WorkflowListResponse | `/aos/workflow/read` |
| `/aos/workflow/start/1.0.0` | WorkflowStartRequest / WorkflowStartResponse | `/aos/workflow/start` |

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
| [storage.md](storage.md) | Local chunk store: on-disk layout, LMDB databases, FastCDC chunking, pack files, compaction. |
| [auth.md](auth.md) | UCAN capabilities, delegation, and per-protocol authorization. |
| [permissions.md](permissions.md) | Resource/verb matrix, policy restrictions, and role definitions. |
| [scheduling.md](scheduling.md) | Decentralized job scheduling: eligibility filters, claim delay computation, resource model, and decay estimation. |
| [view.md](view.md) | View model: ViewSpec, transitive closure, OverlayFS, GC pinning. |
| [fuse.md](fuse.md) | FUSE filesystem implementation: path resolution, chunk reads, operations. |
| [containers.md](containers.md) | Container orchestration: activation types (none, systemd, derivation), container setup, output registration. |
| [replication.md](replication.md) | Store replication: hash-distance assignment, replicator coordination, purge, rebalancing. |
| [workflow.md](workflow.md) | Distributed workflows: reactive DAGs, step execution, transition ordering, inter-workflow signaling. |
| [workflow-spec.md](workflow-spec.md) | Workflow specification format: step types, idempotency model, GC pinning, Nix build example. |
