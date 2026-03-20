# Wire Protocol Index

Index of all protobuf message definitions, DHT records, GossipSub topics, and
stream protocols in the AOS P2P v2 protocol. Each message is defined with full
documentation in its corresponding doc file.

---

## DHT Records

| Key | Value | TTL | Signature | Description | Defined in |
|---|---|---|---|---|---|
| `aos:cluster:{id}:members` | Provider record | Short (heartbeat) | None | Cluster membership advertisement | [daemon.md](daemon.md) |
| `aos:cluster:{id}:config` | `ClusterConfig` | Long | Root key | Cluster configuration and certificate tree | [auth.md](auth.md#protocol) |
| `aos:cluster:{id}:job` | Provider record | Short (1 min) | None | Job creation acceptor advertisement | [jobs.md](jobs.md) |
| `aos:cluster:{id}:job:{job_id}` | Provider record | Short (heartbeat) | None | Job executor advertisement | [jobs.md](jobs.md#protocol) |
| `aos:cluster:{id}:job:{job_id}:state` | `JobState` | Short (heartbeat) | Job key | Job liveness heartbeat | [jobs.md](jobs.md#protocol) |
| `aos:store:object:{store_hash}` | Provider record | GC LRU eviction | None | Store object provider | [store.md](store.md#protocol) |
| `aos:store:upload` | Provider record | Short (1 min) | None | Upload acceptor | [store-upload.md](store-upload.md) |
| `aos:auth:token:{hash}:revoke` | `RevocationRecord` | Mirrors token expiry | Issuer key | UCAN revocation | [auth.md](auth.md#protocol) |
| `aos:workflow:run:{workflow_id}` | Provider record | Workflow lifetime | None | Workflow tracker | [workflow.md](workflow.md) |
| `aos:statute:validators` | Provider record | Short (heartbeat) | None | Active Statute validator | [statute.md](statute.md) |
| `aos:statute:head` | Block hash | Short | None | Latest finalized block hint | [statute.md](statute.md) |

## GossipSub Topics

| Topic | Message | Description | Defined in |
|---|---|---|---|
| `aos/cluster/{id}/jobs/announce` | `JobPost` | Job lifecycle CRDT | [jobs.md](jobs.md#protocol) |
| `aos/cluster/{id}/load/announce` | `LoadReport` | Peer resource reports | [load-reports.md](load-reports.md#protocol) |
| `aos/auth/token/revoke` | `RevocationNotice` | UCAN revocation | [auth.md](auth.md#protocol) |
| `aos/workflows/announce` | `WorkflowPost` | Workflow creation/cancel | [workflow.md](workflow.md#protocol) |
| `aos/workflows/active/{id}/state` | `WorkflowStateMessage` | Per-workflow state | [workflow.md](workflow.md#protocol) |
| `aos/statute/transactions` | `Transaction` | Statute transaction submission | [statute.md](statute.md) |

## Stream Protocols

| Protocol | Request | Response | Description | Defined in |
|---|---|---|---|---|
| `/aos/store/object/1.0.0` | `ObjectRequest` | `ObjectResponse` | Fetch store objects by blake3 hash | [store.md](store.md#protocol) |
| `/aos/store/chunk/1.0.0` | `ChunkRequest` | stream of `Chunk` | Batch fetch chunks | [store.md](store.md#protocol), [git-store.md](git-store.md) |
| `/aos/store/upload/1.0.0` | `StoreUploadRequest` | `StoreUploadComplete` | Upload content-addressed object | [store-upload.md](store-upload.md#protocol) |
| `/aos/job/create/1.0.0` | `JobCreateRequest` | stream of `JobCreateStatus` | Submit job, wait until running | [jobs.md](jobs.md#protocol) |
| `/aos/job/run/1.0.0` | `JobRunRequest` | stream of `JobRunStatus` | Submit job, wait until exit | [jobs.md](jobs.md#protocol) |
| `/aos/job/start/1.0.0` | `JobStartRequest` | stream of `JobStartStatus` | Start claimed job on builder | [jobs.md](jobs.md#protocol) |
| `/aos/job/log/1.0.0` | `LogRequest` | stream of `LogResponse` | Stream container logs | [jobs.md](jobs.md#protocol) |
| `/aos/job/exec/1.0.0` | `JobExecRequest` | `ExecFrame` (bidirectional) | Exec command in container | [jobs.md](jobs.md#protocol) |
| `/aos/workflow/state/1.0.0` | `WorkflowInfoRequest` | `WorkflowInfoResponse` | Fetch point-in-time workflow state snapshot | [workflow.md](workflow.md#protocol) |
| `/aos/workflow/log/1.0.0` | `WorkflowLogRequest` | stream of `WorkflowTransition` | Fetch/tail transition history | [workflow.md](workflow.md#protocol) |
| `/aos/auth/enroll/1.0.0` | `EnrollRequest` | `EnrollResponse` | Enroll a pending node | [enrollment.md](enrollment.md#protocol-messages) |
| `/aos/statute/consensus/1.0.0` | HotStuff messages | HotStuff messages | BFT consensus (validators only) | [statute.md](statute.md) |
| `/aos/statute/sync/1.0.0` | `BlockSyncRequest` | stream of `Block` | Block sync for catching-up nodes | [statute.md](statute.md) |
| `/aos/statute/read/1.0.0` | `StatuteReadRequest` | `StatuteReadResponse` | State query with merkle proofs | [statute.md](statute.md) |
| `/aos/statute/write/1.0.0` | `Transaction` | stream of `StatuteWriteResponse` | Submit transaction, stream status updates | [statute.md](statute.md) |

## Volume Types

| Type | Description | Defined in |
|---|---|---|
| `VolumeRequest` | Union type: one of StoreVolume, LocalPersistentVolume, LocalVolume | [volumes.md](volumes.md#protocol) |
| `StoreVolume` | Read-only bind mount of a store object's content | [volumes.md](volumes.md#protocol) |
| `LocalPersistentVolume` | Persistent writable ZFS dataset that survives job restarts | [volumes.md](volumes.md#protocol) |
| `LocalVolume` | Ephemeral writable ZFS dataset destroyed on job teardown | [volumes.md](volumes.md#protocol) |
| `VolumeDelete` | Explicit deletion request for a persistent volume | [volumes.md](volumes.md#protocol) |

## Common Types

The unified data model types — `NixObject`, `BlobObject`,
`MetaObject`, and `ChunkRef` — are defined in [git-store.md](git-store.md).

```protobuf
// Used by all stream protocol responses for error reporting.
message StreamError {
    uint32 code = 1;              // HTTP-style: 400, 403, 404, 409, 413, 500, 503
    string message = 2;           // human-readable error description
}
```
