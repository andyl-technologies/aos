# AOS P2P v2 Authentication and Authorization

## 1. Identity Types

Three identity types underpin all authentication in AOS P2P v2. Each is an
ed25519 keypair managed by a different actor and scoped to a different lifetime.

### PeerIdentity

A per-daemon ed25519 keypair generated when an AOS daemon first starts. The
PeerId is the hash of the public key.

- **Scope**: One per running daemon instance.
- **Lifetime**: Long-lived, persisted across daemon restarts.
- **Purpose**: Signs `ProfileSpec` records published to the DHT under
  `aos:profile:{peer_ident}`. Identifies the daemon in all libp2p interactions.

### JobIdentity

A per-job ed25519 keypair created each time a job is scheduled.

- **Scope**: One per job.
- **Lifetime**: Ephemeral. Created when the job is posted, destroyed when the
  job exits or is cancelled.
- **Purpose**: Signs `JobState` records published to the DHT under
  `aos:job:{job_ident}`. The job process receives the private key via systemd
  credential injection (`LoadCredential`), allowing it to participate in libp2p
  as a first-class peer with its own identity.

### ClusterIdentity

A per-cluster ed25519 keypair created when the cluster is bootstrapped.

- **Scope**: One per cluster.
- **Lifetime**: Long-lived. Held by the cluster administrator.
- **Purpose**: Signs `ClusterConfig` records published to the DHT under
  `aos:cluster:{cluster_ident}`. Acts as the root of trust for the cluster by
  issuing UCAN capability delegations to peers and jobs.

## 2. DHT Record Signing

Every DHT record type has a defined signature requirement. Validators reject
records that fail signature verification.

| Key Format | Signed By | Validation Rule |
|---|---|---|
| `aos:store:{object_id}` | None | Provider records are self-verifying via content hash. No signature required. |
| `aos:profile:{peer_ident}` | PeerIdentity | Public key extracted from `{peer_ident}`, signature verified against record payload. |
| `aos:job:{job_ident}` | JobIdentity | Public key extracted from `{job_ident}`, signature verified against record payload. |
| `aos:cluster:{cluster_ident}` | ClusterIdentity | Public key extracted from `{cluster_ident}`, signature verified against record payload. |

Store records require no signature because the object ID is itself a
content-addressed hash. Any peer can verify a store object by recomputing its
hash. Profile, job, and cluster records are identity-addressed and require the
corresponding identity's signature to prevent impersonation.

## 3. UCAN Capability Model

Authorization for GossipSub messages and stream protocol requests uses UCAN
(User Controlled Authorization Networks). A UCAN is a signed JWT-like token that
encodes a capability delegation chain.

### Capability Structure

Each UCAN capability specifies:

- **Resource path**: A hierarchical namespace (e.g., `/aos/job/announce`).
- **WHERE clauses**: Conditions that scope the capability to specific clusters,
  jobs, or operations. The verifier evaluates each clause against the message
  or request being authorized.

A capability matches a request when:

1. The resource path in the UCAN matches the resource path required by the
   protocol.
2. All WHERE clauses evaluate to true against the request's fields.

### Delegation

The ClusterIdentity is the root issuer. It delegates capabilities to peers,
which may further delegate subsets of those capabilities (attenuation). Each
link in the chain is signed by the delegator. Verification walks the chain from
the presented UCAN back to a trusted ClusterIdentity root.

## 4. GossipSub Message Authorization

Every message published to a GossipSub topic must carry a UCAN in the message
envelope. Subscribers validate the UCAN before accepting the message. Messages
that fail validation are dropped silently.

| Topic | Required UCAN Capability |
|---|---|
| `aos/cluster/{cluster_ident}/jobs/announce` | `/aos/job/announce` WHERE `.cluster == {cluster_ident}` AND `.operation HAS {post_op}` |
| `aos/cluster/{cluster_ident}/load/announce` | `/aos/load/announce` WHERE `.cluster == {cluster_ident}` |
| `aos/cluster/{cluster_ident}/control/announce` | `/aos/control/announce` WHERE `.cluster == {cluster_ident}` AND `.operation HAS {control_op}` |

The WHERE clauses enforce that:

- **Cluster scoping**: A UCAN issued for cluster A cannot authorize messages on
  cluster B's topics.
- **Operation scoping**: Job announcement capabilities can be restricted to
  specific operations (e.g., only `create` and `cancel`, but not `claim`).
  Control signal capabilities can similarly be restricted to specific control
  operations.

## 5. Stream Protocol Authorization

Stream protocol requests carry a UCAN in the request header. The serving peer
validates the UCAN before processing the request.

| Protocol | Required UCAN Capability |
|---|---|
| `/aos/store/manifest/1.0.0` | `/aos/store/read` |
| `/aos/store/chunk/1.0.0` | None |
| `/aos/job/exec/1.0.0` | `/aos/job/exec` WHERE `.job == {job_ident}` |
| `/aos/job/log/1.0.0` | `/aos/job/read` WHERE `.cluster == {cluster_ident}` OR `.job == {job_ident}` |

Notable design choices:

- **Chunk transfer is unauthenticated.** Chunks are content-addressed by
  xxh3-128 hash. Knowing a chunk hash is sufficient to request it, and the
  response is self-verifying. The manifest request (which reveals which chunks
  compose an object) is the authorization boundary.
- **Log access has two scopes.** A cluster-scoped UCAN grants access to logs
  for all jobs in the cluster. A job-scoped UCAN grants access only to that
  specific job's logs.
- **Exec authorization is job-scoped.** The UCAN must name the specific job
  identity being executed.

## 6. Two-Phase Exec Authorization

Job execution requires mutual authorization between the job creator and the
claiming peer. Neither party can unilaterally start a job on the other's
machine. This is enforced through two UCANs that cross in opposite directions.

### Phase 1: Claim

When a peer claims a job, it includes an `exec_ucan` in the `JobClaim` message:

```protobuf
message JobClaim {
    string peer_id = 1;
    string exec_ucan = 2;  // Claimant authorizes the creator to exec on their machine.
}
```

The `exec_ucan` is issued by the claimant and grants the job identity holder
(i.e., the creator) the `/aos/job/exec` capability scoped to this specific job.
This proves: **the claimant consents to run this job on their machine.**

### Phase 2: Exec

The creator calls `/aos/job/exec/1.0.0` on the claimant with an `ExecRequest`:

```protobuf
message ExecRequest {
    string job_ucan = 1;   // Creator delegates the job identity to the claimant.
    string exec_ucan = 2;  // The exec_ucan from the JobClaim.
}
```

The `ExecRequest` carries two UCANs:

- **`job_ucan`**: Issued by the creator, delegating the JobIdentity (private
  key access via systemd secrets) to the claimant. This proves: **the creator
  authorizes this specific peer to act as the job.**
- **`exec_ucan`**: The same UCAN from the claim, echoed back. This proves:
  **the claimant previously consented to execute this job.**

The claimant verifies both UCANs before starting the job container. The job
process receives the JobIdentity private key through systemd credential
injection so it can join libp2p and sign its own DHT records.

### Why Mutual Authorization

Neither UCAN alone is sufficient:

- Without `exec_ucan`, a creator could force arbitrary peers to run jobs they
  never agreed to.
- Without `job_ucan`, a claimant could impersonate a job identity it was never
  granted, or a creator could bait-and-switch the job after claiming.

Both sides must independently prove their intent for execution to proceed.

## 7. Cluster Bootstrapping

When a new cluster is created, the administrator generates a ClusterIdentity
keypair and publishes a signed `ClusterConfig` record to the DHT. The
bootstrapping sequence is:

1. **Generate ClusterIdentity.** The administrator creates the ed25519 keypair.
   The public key hash becomes the `{cluster_ident}`.
2. **Publish ClusterConfig.** The initial cluster configuration is signed and
   published to `aos:cluster:{cluster_ident}`.
3. **Issue initial UCANs.** The ClusterIdentity issues UCAN delegations to the
   first set of peers, granting them capabilities to announce jobs, report load,
   and publish control signals on the cluster's GossipSub topics. This is
   analogous to creating initial service accounts and RBAC bindings in
   Kubernetes.
4. **Peers join.** Each peer receives its UCAN delegation (out of band or via a
   registration protocol) and begins participating in the cluster's topics and
   protocols.

The ClusterIdentity private key does not need to remain online after
bootstrapping. It is only required when issuing new UCAN delegations or updating
the `ClusterConfig`.

## 8. Job Identity Lifecycle

Job identities are ephemeral and tightly scoped to a single job execution.

1. **Creation.** When a job is posted, the creator generates a fresh ed25519
   keypair. The public key hash becomes the `{job_ident}`.
2. **Publication.** The creator publishes the initial `JobPost` (with a `create`
   delta) to the cluster's jobs GossipSub topic. The `{job_ident}` is included
   in the message.
3. **Delegation.** When execution begins (Phase 2), the creator delegates the
   JobIdentity to the claimant via the `job_ucan` in the `ExecRequest`.
4. **Injection.** The claimant's daemon injects the JobIdentity private key into
   the job's systemd unit via `LoadCredential`. The job process reads the key
   from the credential path at startup.
5. **Participation.** The running job uses its JobIdentity to join libp2p, sign
   `JobState` DHT records under `aos:job:{job_ident}`, and authenticate to any
   protocols that accept job-scoped UCANs.
6. **Destruction.** When the job exits (normally or via cancellation), the
   JobIdentity is discarded. The DHT record expires via its short TTL liveness
   check. The keypair is never reused.

## 9. Revocation

UCAN revocation uses a combination of short-lived tokens and emergency signals
to ensure that compromised or decommissioned peers lose access promptly.

### Short-Lived UCANs

UCANs are issued with short expiry windows (hours to days). Non-renewal is
implicit revocation: when a UCAN expires, the peer can no longer authorize
messages or requests with it. The ClusterIdentity holder simply stops issuing
new delegations to revoke a peer's access. This is the normal revocation path
and requires no broadcast.

### Emergency Revocation

For immediate revocation (e.g., a compromised peer key), the ClusterIdentity
publishes a `ControlSignal` with a `PeerSet` signal marking the target peer as
`EVICTED`. All peers that receive the signal:

1. Stop accepting GossipSub messages from the evicted peer.
2. Reject stream protocol requests from the evicted peer.
3. Remove the evicted peer from scheduling consideration.

This takes effect as fast as GossipSub propagation (typically sub-second within
a cluster).

### Per-Message Validation

Every GossipSub message carries a UCAN in its envelope. On receipt, peers
validate the UCAN before processing the message:

1. **Expiry check**: if the UCAN's `exp` claim is in the past, the message is
   rejected.
2. **Revocation check**: if the message author's PeerId matches an `EVICTED`
   peer in the local ControlSignal state, the message is rejected.
3. **Peer score penalty**: rejected messages incur a GossipSub peer score
   penalty. Repeated violations cause the peer to be disconnected and
   blacklisted by the mesh.
