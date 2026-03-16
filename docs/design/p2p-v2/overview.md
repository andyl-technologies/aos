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

- **Build jobs** use `BuildSpec` with a `.drv` reference, writable store overlay, and network disabled.
- **Service containers** use `RunSpec` with `INIT_SYSTEMD` and systemd as PID 1.
- **Login shells** use `RunSpec` with `INIT_DIRECT` and a simple entrypoint.

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

1. **Discovery**: DHT provider records (`aos:store:object:{object_id}`) advertise which
   peers hold an object. TTL is based on GC LRU eviction; no signature
   validation is required.
2. **Transfer**: The `/aos/store/object/1.0.0` stream protocol fetches store
   objects (NixObjects, trees, blobs) by blake3 hash. The
   `/aos/store/chunk/1.0.0` stream protocol transfers raw data chunks.

## Protocol Summary

### DHT Records

| Key Pattern | Value Type | Lifetime | Signed By |
|---|---|---|---|
| `aos:store:object:{object_id}` | ProviderRecord | TTL (GC LRU eviction) | None (no signature validation) |
| `aos:cluster:{cluster_ident}:job:{job_ident}` | ProviderRecord | Short (heartbeat) | None |
| `aos:cluster:{cluster_ident}:job:{job_ident}:state` | JobState | Short-lived (liveness check) | JobIdentity |
| `aos:cluster:{cluster_ident}:members` | ProviderRecord | Short (heartbeat) | None |
| `aos:cluster:{cluster_ident}:config` | ClusterConfig | Long-lived | Root Identity |
| `aos:auth:token:{token_hash}:revoke` | RevocationRecord | Mirrors token expiry | Token issuer key |
| `aos:store:replica` | ProviderRecord | Short (1 min) | None |
| `aos:store:upload` | ProviderRecord | Short (1 min) | None |
| `aos:store:fetch` | ProviderRecord | Short (1 min) | None |
| `aos:workflow:runners` | ProviderRecord | Short (1 min) | None |
| `aos:cluster:{cluster_ident}:job` | ProviderRecord | Short (1 min) | None |
| `aos:workflow:run:{workflow_id}` | ProviderRecord | Workflow lifetime | None |
| `aos:statute:validators` | ProviderRecord | Short (heartbeat) | None |
| `aos:statute:head` | Block hash | Short | None |

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
| `aos/statute/transactions` | Transaction | Global |

### Stream Protocols

| Protocol | Request/Response | Auth Requirement |
|---|---|---|
| `/aos/store/object/1.0.0` | ObjectRequest / ObjectResponse | `/aos/store/read` |
| `/aos/store/chunk/1.0.0` | ChunkRequest / Chunk (stream) | `/aos/store/read` |
| `/aos/job/start/1.0.0` | JobStartRequest / JobStartStatus (stream) | `/aos/job/start` WHERE `.job == {job_ident}` |
| `/aos/job/log/1.0.0` | LogRequest / LogResponse | `/aos/job/read` WHERE `.cluster == {cluster_ident}` OR `.job == {job_ident}` |
| `/aos/job/exec/1.0.0` | JobExecRequest / ExecFrame (bidirectional stream) | `/aos/job/exec` |
| `/aos/workflow/info/1.0.0` | WorkflowInfoRequest / WorkflowInfoResponse | `/aos/workflow/read` |
| `/aos/workflow/log/1.0.0` | WorkflowLogRequest / WorkflowTransition (stream) | `/aos/workflow/read` |
| `/aos/workflow/list/1.0.0` | WorkflowListRequest / WorkflowListResponse | `/aos/workflow/read` |
| `/aos/workflow/run/1.0.0` | WorkflowRunRequest / WorkflowRunStatus (stream) | `/aos/workflow/run` |
| `/aos/job/run/1.0.0` | JobRunRequest / JobRunStatus (stream) | `/aos/job/create` |
| `/aos/job/create/1.0.0` | JobCreateRequest / JobCreateStatus (stream) | `/aos/job/create` |
| `/aos/store/upload/1.0.0` | StoreUploadRequest / StoreUploadComplete | `/aos/store/upload` |
| `/aos/store/fetch/1.0.0` | StoreFetchRequest / StoreFetchStatus (stream) | `/aos/store/fetch` |
| `/aos/auth/enroll/1.0.0` | EnrollRequest / EnrollResponse | Network key (or delegate) |
| `/aos/statute/consensus/1.0.0` | HotStuff messages | Statute validator |
| `/aos/statute/sync/1.0.0` | BlockSyncRequest / Block (stream) | Statute validator/follower |
| `/aos/statute/read/1.0.0` | StatuteReadRequest / StatuteReadResponse | Statute follower |
| `/aos/statute/write/1.0.0` | Transaction / StatuteWriteResponse (stream) | Statute validator |

## Document Index

| Document | Description |
|---|---|
| [overview.md](overview.md) | This document. Protocol summary and key concepts. |
| [identity.md](identity.md) | Identity types, keypairs, and signing. |
| [daemon.md](daemon.md) | Daemon architecture, configuration, and startup. |
| [jobs.md](jobs.md) | Job lifecycle, two-phase execution, and container types. |
| [store.md](store.md) | Content storage, provider records, resolve and chunk transfer. |
| [store-upload.md](store-upload.md) | Store upload protocol: content-addressed uploads, security model, pin TTL, deduplication. |
| [fetch.md](fetch.md) | Store fetch engine: connection management, parallel downloads, mirror failover, chunking pipeline. |
| [identity.md](identity.md) | Identity management: credential sources, key store, resolution, integration. |
| [workflow-validation.md](workflow-validation.md) | Workflow validation: structural, graph, input, fetch, cross-workflow, and capacity checks. |
| [storage.md](storage.md) | Local chunk store: on-disk layout, LMDB databases, FastCDC chunking, pack files, compaction. |
| [auth.md](auth.md) | UCAN capabilities, delegation, and per-protocol authorization. |
| [permissions.md](permissions.md) | Resource/verb matrix, policy restrictions, and role definitions. |
| [scheduling.md](scheduling.md) | Decentralized job scheduling: eligibility filters, claim delay computation, resource model, and decay estimation. |
| [volumes.md](volumes.md) | Volume model: StoreVolume, LocalPersistentVolume, LocalVolume. ZFS integration, scheduling interaction. |
| [view.md](view.md) | View model: ViewSpec, transitive closure, OverlayFS, GC pinning. |
| [fuse.md](fuse.md) | FUSE filesystem implementation: path resolution, chunk reads, operations. |
| [containers.md](containers.md) | Container orchestration: activation types (none, systemd, derivation), container setup, output registration. |
| [replication.md](replication.md) | Store replication: hash-distance assignment, replicator coordination, purge, rebalancing. |
| [workflow.md](workflow.md) | Distributed workflows: reactive DAGs, step execution, transition ordering, inter-workflow signaling. |
| [workflow-spec.md](workflow-spec.md) | Workflow specification format: step types, idempotency model, GC pinning, Nix build example. |
| [cloud-init.md](cloud-init.md) | Cloud-init integration: native module, systemd slice hierarchy, auto-detection, secrets. |
| [enrollment.md](enrollment.md) | Network enrollment: node states, manual enrollment, key management, enrollment protocol. |
| [git.md](git.md) | Git repositories: refs in Statute, content in store, meta objects, auto-pinning. |
| [git-store.md](git-store.md) | Git-compatible store model: merkle tree structure, blob/tree hashing, subtree dedup, CDC chunk mapping. |
| [mounts.md](mounts.md) | Statute mounts: protocol handlers in the KV namespace, capabilities, sandboxing. |
| [statute.md](statute.md) | Statute BFT KV store: consensus, UCAN authorization, CUE schema validation, merkle-trie state. |
| [workflow-templates.md](workflow-templates.md) | Workflow templates: parameterized CUE definitions, template composition, instance tracking. |
| [system.md](system.md) | System architecture: four building blocks (store, statute, jobs, workflows) and composition patterns. |
