# Permissions

The AOS P2P v2 authorization model has two distinct layers. They serve
different purposes and never overlap.

**Layer 1: DHT record auth.** Signature-based, per-record-type, no UCAN.
Each DHT record type defines which key must sign the record. Validators reject
records with invalid or missing signatures. This layer protects the integrity
of DHT state.

**Layer 2: Protocol auth.** UCAN-based, gates GossipSub publishing/subscribing
and stream protocol access. Each protocol operation maps to a capability in the
`/aos/{resource}/{verb}` namespace. This layer controls what peers are allowed
to do within the cluster.

---

## 1. DHT Auth (Layer 1)

DHT record authorization uses cryptographic signatures to ensure only the
correct identity can write each record type. No UCANs are involved.

| DHT Key | Signer | Validation |
|---|---|---|
| `aos:store:object:{hash}` | None | Provider records. Self-verifying via content hash. No signature required. |
| `aos:cluster:{cluster_id}:job:{job_id}:state` | JobIdentity | Job's keypair signs. Only the running job writes its heartbeat. |
| `aos:cluster:{cluster}:config` | Root Identity | Only root signs cluster config. |
| `aos:auth:token:{token}:revoke` | Token Issuer | Signature must match the key that issued the revoked token. |

Store records require no signature because the content hash is the key --
anyone can verify correctness by recomputing the hash. Job, cluster, and
revocation records are identity-addressed and require the corresponding
identity's signature to prevent impersonation. See
[auth.md](auth.md#2-dht-record-signing) for the full signing model.

---

## 2. Protocol Auth (Layer 2)

Protocol authorization uses UCAN capabilities. Every capability follows the
format:

```
Resource:  /aos/{resource}/{verb}
Scope:     UCAN `with` field (cluster URI, e.g., "aos://prod/*")
Caveats:   UCAN `nb` field (sub-resource constraints)
```

The `with` field scopes the capability to a cluster. The `nb` field contains
policy restrictions that constrain the capability to specific sub-resources
(activation types, architectures, etc.).

---

### /aos/job/create

Gates publishing `JobPost{create}` and `JobPost{cancel}` deltas to GossipSub.
Also gates the `/aos/job/create/1.0.0` and `/aos/job/run/1.0.0` stream
protocols for remote job creation and execution.

**Checked:** GossipSub validation callback on the `jobs/announce` topic.
Stream open validation on `/aos/job/create/1.0.0`.

**Policy restrictions (`nb` caveats):**

| Caveat | Type | Meaning |
|---|---|---|
| `activation` | string[] | Allowed activation types (`"none"`, `"systemd_v1"`, `"derivation"`). |
| `system` | string[] | Allowed target architectures (`"x86_64-linux"`, `"aarch64-linux"`). |
| `network` | string[] | Allowed network modes (`"none"`, `"host"`). |

A CI token restricted to `{"activation": ["derivation"], "network": ["none"]}`
can only submit isolated build jobs -- it cannot create service containers or
jobs with host network access.

**Example UCAN capability:**

```json
{
  "can": "/aos/job/create",
  "with": "aos://prod/*",
  "nb": {
    "activation": ["derivation"],
    "network": ["none"]
  }
}
```

---

### /aos/job/claim

Gates publishing `JobPost{claim}`, `JobPost{start}`, `JobPost{exit}`, and
`JobPost{error}` deltas to GossipSub. Also gates accepting
`/aos/job/start/1.0.0` stream requests (builder side).

**Checked:** GossipSub validation for claim/start/exit/error deltas. Builder
self-checks before accepting a start stream.

**Policy restrictions (`nb` caveats):**

| Caveat | Type | Meaning |
|---|---|---|
| `activation` | string[] | Which activation types this builder accepts. |
| `system` | string[] | Must match builder's actual architecture. |

**Implicit volume operations:** A peer with `/aos/job/claim` may create
LocalVolume and LocalPersistentVolume ZFS datasets as part of container setup,
and destroy LocalVolume datasets on container teardown. Volume creation and
destruction are implicit in job execution -- no separate capability is required.
(If standalone volume management outside of jobs is needed in the future, it
would require a new `/aos/volume/manage` capability.)

**Example UCAN capability:**

```json
{
  "can": "/aos/job/claim",
  "with": "aos://prod/*",
  "nb": {
    "activation": ["derivation"],
    "system": ["x86_64-linux"]
  }
}
```

---

### /aos/job/read

Gates subscribing to the `jobs/announce` GossipSub topic (receiving JobPost
deltas) and opening `/aos/job/log/1.0.0` streams.

**Checked:** Connection-time topic admission. Stream open validation.

**Policy restrictions (`nb` caveats):**

| Caveat | Type | Meaning |
|---|---|---|
| `job_creator` | string[] | Can only read jobs created by these PeerIds. |
| `activation` | string[] | Can only read jobs of these activation types. |

No restrictions means the peer can read all jobs in the cluster.

---

### /aos/job/exec

Gates opening `/aos/job/exec/1.0.0` streams to execute a command inside a
running job's container. Like `docker exec` -- runs a process in the
container's namespaces with PTY support.

**Checked:** Builder (hosting the container) verifies requester's UCAN before
spawning the process.

**Policy restrictions (`nb` caveats):**

| Caveat | Type | Meaning |
|---|---|---|
| `job_id` | string[] | Restrict to specific job IDs. |
| `job_creator` | string[] | Can only exec into jobs created by these PeerIds. |
| `activation` | string[] | Can only exec into these activation types. |

**Example UCAN capability:**

```json
{
  "can": "/aos/job/exec",
  "with": "aos://prod/*",
  "nb": {
    "job_creator": ["QmCiSystem"]
  }
}
```

---

### /aos/store/read

Gates opening `/aos/store/object/1.0.0` and `/aos/store/chunk/1.0.0` streams.

**Checked:** Serving peer verifies requester's UCAN before responding.

**No sub-resource restrictions.** Store access is global -- it is not scoped to
a cluster. The store is shared across all clusters, and any valid
`/aos/store/read` UCAN grants access regardless of which cluster issued it.

---

### /aos/store/write

Gates publishing `StorePublish` messages to the `store/publish` GossipSub topic.

**Checked:** GossipSub validation callback. PeerId in StorePublish must match sender.

**No sub-resource restrictions.** Store write access is global (not cluster-scoped) -- the `StorePublish` message is published to the `aos/store/publish` topic.

---

### /aos/store/replicate

Gates publishing and subscribing to the `aos/store/replicate` GossipSub topic.
Required for participation in the store replication protocol.

**Checked:** GossipSub validation callback and connection-time topic admission.

**No sub-resource restrictions.** Store replication is global (not cluster-scoped).

---

### /aos/store/purge

Gates publishing `StorePurge` messages to the `aos/store/purge` GossipSub
topic. Purge is a privileged operation — typically restricted to ops-admin
roles.

**Checked:** GossipSub validation callback.

**No sub-resource restrictions.**

---

### /aos/store/upload

Gates opening `/aos/store/upload/1.0.0` streams to upload store objects.

**Checked:** Serving node verifies requester's UCAN before accepting the upload.

**No sub-resource restrictions.** Store upload is global — it is not scoped to
a cluster.

---

### /aos/store/fetch

Gates opening `/aos/store/fetch/1.0.0` streams to request a daemon to fetch
FODs from upstream URLs.

**Checked:** Serving node verifies requester's UCAN before accepting the fetch.

**No sub-resource restrictions.** Store fetch is global — it is not scoped to
a cluster.

---

### /aos/load/read

Gates subscribing to the `load/announce` GossipSub topic.

**Checked:** Connection-time topic admission.

**No sub-resource restrictions.**

---

### /aos/load/write

Gates publishing `LoadReport` to `load/announce`.

**Checked:** GossipSub validation. PeerId in LoadReport must match sender.

**No sub-resource restrictions.** A peer can only report its own load -- the
PeerId in the LoadReport is verified against the sender's identity.

---

### /aos/auth/token/revoke

Gates publishing `RevocationNotice` to the `auth/token/revoke` GossipSub topic.

**Checked:** GossipSub validation.

Note: the DHT revocation record uses issuer signature validation (Layer 1),
not UCAN. This capability gates the GossipSub notification only.

---

### /aos/auth/token/issue

Gates publishing `IssuanceNotice` to the `auth/token/issue` GossipSub topic.
Optional — the system functions without issuance notifications. Enables
proactive topic admission, audit logging, and revocation cache warming.

**Checked:** GossipSub validation. Issuer in the notice must match the sender.

**No sub-resource restrictions.**

**Policy restrictions (`nb` caveats):**

| Caveat | Type | Meaning |
|---|---|---|
| `scope` | string | `"subtree"` -- can only revoke tokens issued by this intermediate or its children. |

---

### /aos/auth/read

Gates subscribing to the `auth/revoke` GossipSub topic.

**Checked:** Connection-time topic admission.

**No restrictions.** All cluster members should receive revocation
notifications.

---

### /aos/workflow/create

Gates publishing `WorkflowPost{create}` and `WorkflowPost{cancel}` to the
`aos/workflows/announce` topic.

**Checked:** GossipSub validation callback.

**No sub-resource restrictions.**

---

### /aos/workflow/execute

Gates claiming and advancing workflow steps. Required to publish transitions
to `aos/workflows/active/{id}/state` topics.

**Checked:** GossipSub validation callback on per-workflow state topics.

**No sub-resource restrictions.**

---

### /aos/workflow/read

Gates subscribing to workflow topics and opening `/aos/workflow/info/1.0.0`,
`/aos/workflow/log/1.0.0`, and `/aos/workflow/list/1.0.0` streams.

**Checked:** Connection-time topic admission. Stream open validation.

**No sub-resource restrictions.**

---

### /aos/workflow/cancel

Gates publishing `WorkflowPost{cancel}` to `aos/workflows/announce`. Typically
restricted to workflow creators or admin roles.

**Checked:** GossipSub validation callback.

**No sub-resource restrictions.**

---

### /aos/workflow/run

Gates opening `/aos/workflow/run/1.0.0` streams to submit workflows to
bootstrap nodes.

**Checked:** Bootstrap node verifies requester's UCAN before ingesting the
workflow.

**No sub-resource restrictions.**

---

## 3. Capability Dependencies

Some capabilities are only useful when combined with others. The daemon
validates its own capability set on startup and logs warnings for incomplete
sets. Peers with missing dependencies will fail at runtime when the dependent
operation is attempted.

| Capability | Requires | Reason |
|---|---|---|
| `/aos/job/claim` | `/aos/store/read` | Builder must resolve NixObject metadata and fetch chunks to create views for job containers. |
| `/aos/job/claim` | `/aos/job/read` | Builder must receive `JobPost` messages to see jobs available for claiming. |
| `/aos/job/claim` | `/aos/load/write` | Builder must publish LoadReports for scheduling to function. |
| `/aos/job/claim` | `/aos/load/read` | Builder must receive LoadReports to compute claim delay. |
| `/aos/job/create` | `/aos/job/read` | Creator must receive claim/start/exit/error deltas for its jobs. |
| `/aos/job/create` | `/aos/store/read` | Creator must fetch build outputs. |
| `/aos/job/exec` | `/aos/job/read` | Must be able to discover which peer is running the target job. |
| `/aos/store/write` | `/aos/store/read` | A peer publishing store objects must also be able to serve them. |
| `/aos/store/replicate` | `/aos/store/read` | Replicators must resolve NixObject metadata and fetch chunks to replicate objects. |
| `/aos/store/purge` | `/aos/store/read` | Must be able to identify the objects being purged. |
| `/aos/store/upload` | `/aos/store/read` | Uploader should also be able to read store objects. |
| `/aos/store/fetch` | `/aos/store/read` | Fetched objects should be readable by the requester. |
| `/aos/load/write` | `/aos/load/read` | A peer reporting load must also receive others' reports for scheduling. |
| `/aos/workflow/execute` | `/aos/job/create` | Workflow executors submit build jobs. |
| `/aos/workflow/execute` | `/aos/store/read` | Workflow executors fetch store objects. |
| `/aos/workflow/execute` | `/aos/workflow/read` | Must observe workflow state to advance steps. |
| `/aos/workflow/create` | `/aos/workflow/read` | Creator must monitor workflow progress. |
| `/aos/workflow/run` | `/aos/workflow/read` | Submitter must be able to monitor workflow progress. |

A capability set that violates a dependency is **not rejected** — the UCAN is
still valid. But the peer will encounter authorization failures at runtime. For
example, a peer with `/aos/job/claim` but without `/aos/store/read` can publish
a claim, but when the job starts and the daemon tries to fetch the input
closure, the object request will be rejected by the serving peer.

The daemon logs a warning on startup for each unsatisfied dependency so
operators can fix the UCAN delegation before the peer attempts to use the
incomplete capability.

---

## 4. Start Stream Authorization

The `/aos/job/start/1.0.0` stream does not have a standalone capability. It is
authorized by the mutual handshake between job/create and job/claim, mediated
through a UCAN exchange.

The two capabilities compose:

1. **Creator has /aos/job/create** -- proved when posting the job to GossipSub.
2. **Builder has /aos/job/claim** -- proved when posting the claim to GossipSub.

The start stream is authorized by the claim handshake:

- Builder's claim includes `start_ucan`: "I authorize the job identity holder
  to start on me."
- Creator's exec request includes `job_ucan`: "I delegate the job identity to
  you."

With a reservation token:

- Builder signed the reservation: "I offer this slot to you."
- Creator presents the reservation.
- Builder verifies its own signature and creator match.

Authorization emerges from the intersection of job/create + job/claim mediated
by the UCAN exchange. There is no separate `/aos/job/start` capability. See
[auth.md](auth.md#7-two-phase-start-authorization) for the full handshake
protocol and [jobs.md](jobs.md#two-phase-start-handshake) for the lifecycle
integration.

---

## 5. GossipSub Topic Mapping

Each GossipSub topic maps to specific capabilities for publishing and
subscribing.

| Topic | Publish requires | Subscribe requires |
|---|---|---|
| `jobs/announce` | `/aos/job/create` (for create, cancel) or `/aos/job/claim` (for claim, start, exit, error) | `/aos/job/read` |
| `store/publish` | `/aos/store/write` | `/aos/store/read` |
| `store/replicate` | `/aos/store/replicate` | `/aos/store/replicate` |
| `store/purge` | `/aos/store/purge` | `/aos/store/read` |
| `load/announce` | `/aos/load/write` | `/aos/load/read` |
| `auth/token/revoke` | `/aos/auth/token/revoke` | `/aos/auth/read` |
| `auth/token/issue` | `/aos/auth/token/issue` | `/aos/auth/read` |
| `workflows/announce` | `/aos/workflow/create` | `/aos/workflow/read` |
| `workflows/active/{id}/state` | `/aos/workflow/execute` | `/aos/workflow/read` |

The `jobs/announce` topic is split by delta type: create and cancel deltas
require `/aos/job/create`, while claim, start, exit, and error deltas require
`/aos/job/claim`. The validation callback inspects the delta's `oneof` variant
to determine which capability is needed.

---

## 6. Stream Protocol Mapping

Each stream protocol maps to specific capabilities for the requester and
responder.

| Protocol | Requester needs | Responder needs |
|---|---|---|
| `/aos/store/object/1.0.0` | `/aos/store/read` | (serves if has content) |
| `/aos/store/chunk/1.0.0` | `/aos/store/read` | (serves if has content) |
| `/aos/job/start/1.0.0` | job/create (implicit from job posting) | `/aos/job/claim` |
| `/aos/job/log/1.0.0` | `/aos/job/read` | `/aos/job/claim` (builder serves logs) |
| `/aos/job/exec/1.0.0` | `/aos/job/exec` | `/aos/job/claim` (builder hosts the container) |
| `/aos/workflow/info/1.0.0` | `/aos/workflow/read` | (serves if tracking workflow) |
| `/aos/workflow/log/1.0.0` | `/aos/workflow/read` | (serves if tracking workflow) |
| `/aos/workflow/list/1.0.0` | `/aos/workflow/read` | (serves if tracking workflow) |
| `/aos/workflow/run/1.0.0` | `/aos/workflow/run` | (accepts if configured) |
| `/aos/store/upload/1.0.0` | `/aos/store/upload` | (accepts if configured) |
| `/aos/store/fetch/1.0.0` | `/aos/store/fetch` | (accepts if configured) |
| `/aos/job/run/1.0.0` | `/aos/job/create` | (accepts if configured) |
| `/aos/job/create/1.0.0` | `/aos/job/create` | (accepts if configured) |

Both resolve and chunk transfer require `/aos/store/read`. This ensures that
only authorized cluster members can retrieve store content. Chunks are
self-verifying by hash, but access is still gated to prevent unauthorized data
exfiltration.

`/aos/job/create/1.0.0` waits until the job is **running** (terminal =
`JobStart`). `/aos/job/run/1.0.0` waits until the job **exits** (terminal =
`JobExit`). Both require `/aos/job/create` capability and cancel the job on
client disconnect.

---

## 7. Role Examples

Concrete UCAN capability sets for common peer roles.

### Builder Node

A peer that claims and executes jobs.

```
/aos/job/claim
/aos/job/read
/aos/store/read
/aos/store/write
/aos/store/replicate
/aos/load/write
/aos/load/read
/aos/auth/read
/aos/workflow/execute
/aos/workflow/read
```

### CI Submitter

A peer that creates build jobs and monitors results.

```
/aos/job/create    (nb: activation=["derivation"], network=["none"])
/aos/job/read
/aos/job/exec      (nb: job_creator=["{self}"])
/aos/store/read
/aos/store/upload
/aos/store/fetch
/aos/load/read
/aos/auth/read
/aos/workflow/create
/aos/workflow/run
/aos/workflow/read
```

### Ops Admin

Full access including token revocation.

```
/aos/job/create
/aos/job/claim
/aos/job/read
/aos/job/exec
/aos/store/read
/aos/store/write
/aos/store/upload
/aos/store/fetch
/aos/store/replicate
/aos/store/purge
/aos/load/write
/aos/load/read
/aos/auth/token/revoke
/aos/auth/read
/aos/workflow/create
/aos/workflow/run
/aos/workflow/execute
/aos/workflow/read
/aos/workflow/cancel
```

### Observer

Read-only access to all cluster state. Cannot create jobs or claim work.

```
/aos/job/read
/aos/store/read
/aos/load/read
/aos/auth/read
/aos/workflow/read
```

### Cache Node

Serves store content and reports load, but does not participate in job
scheduling.

```
/aos/store/read
/aos/load/write
/aos/load/read
/aos/auth/read
```

---

## 8. Connection-Time Capability Enforcement

During the `/aos/auth/1.0.0` handshake, the peer presents its UCAN chain.
The receiving peer extracts capabilities and determines which GossipSub topics
to admit the peer to.

- Peers without read capability for a topic are pruned from that topic's mesh.
- Peers without write capability for a topic have their published messages
  rejected by the validation callback.
- Peers without any valid capabilities for the cluster are disconnected.

Topic admission is evaluated at connection time. If a peer's UCAN is later
revoked (see [auth.md](auth.md#9-revocation)), the revocation notification
triggers re-evaluation and the peer is pruned from all affected topics.

---

## 9. Limits and Enforcement

Distributed limits (max_concurrent, max_replicas) are advisory, not strictly
enforceable in a decentralized system. A peer can self-enforce its own limits,
but the cluster cannot prevent a misbehaving peer from exceeding them.

Misbehavior is detected through two mechanisms:

- **LoadReport anomalies**: a peer reporting low load while running many jobs
  (or vice versa) accumulates negative peer score.
- **GossipSub peer scoring**: a peer consistently exceeding its declared limits,
  publishing unauthorized messages, or exhibiting other protocol violations
  accumulates negative GossipSub peer score. Peers with sufficiently negative
  scores are disconnected and temporarily blacklisted by the mesh.

Hard enforcement (preventing all violations) would require a consensus
protocol, which conflicts with the decentralized, coordination-free design.
The advisory model with peer scoring provides adequate protection for
cooperative clusters while maintaining the system's availability properties.
