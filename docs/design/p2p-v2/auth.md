# AOS P2P v2 Authentication and Authorization

## 1. Identity Types

The identity model uses a certificate tree hierarchy with three tiers. Each
identity is an ed25519 keypair. The hierarchy enables offline root keys,
scoped delegation through intermediates, and subtree revocation.

```
Root (offline, vault/HSM)
  ├── Intermediate "ops-admin" (online, 1yr expiry)
  │     ├── PeerIdentity: daemon-1
  │     ├── PeerIdentity: daemon-2
  │     └── PeerIdentity: daemon-3
  ├── Intermediate "ci-admin" (online, 90d expiry)
  │     ├── JobIdentity: build-job-1
  │     └── JobIdentity: build-job-2
  └── Intermediate "dev-admin" (online, 6mo expiry)
        ├── PeerIdentity: dev-laptop-alice
        └── PeerIdentity: dev-laptop-bob
```

### Root Identity

An offline ed25519 keypair stored in a vault or HSM. The root public key is
embedded in `ClusterConfig` and never changes for the lifetime of the cluster.

- **Scope**: One per cluster.
- **Lifetime**: Permanent. Never rotated unless the cluster is re-bootstrapped.
- **Purpose**: Signs `IntermediateCert` records. Signs `ClusterConfig` records
  published to the DHT under `aos:cluster:{cluster_ident}:config`. Acts as the
  ultimate root of trust for the cluster.
- **Operational constraint**: The root private key is **never used for
  day-to-day operations**. It is only brought online to sign new intermediate
  certificates or update `ClusterConfig`.

### Intermediate Identities

Online ed25519 keypairs held by ops teams, CI systems, or team leads. Each
intermediate has a certificate (`IntermediateCert`) signed by the root or by a
parent intermediate.

- **Scope**: One per administrative domain (e.g., ops team, CI pipeline, dev
  team).
- **Lifetime**: Medium-lived with explicit expiry (days to years). Must be
  renewed by the parent before expiry.
- **Purpose**: Issues UCAN capability delegations to peers and jobs. An
  intermediate can only delegate capabilities that it was itself granted.
  Capabilities are scoped — an intermediate with only `/aos/job/announce`
  cannot issue UCANs beyond its granted scope.
- **Certificate format**: See `IntermediateCert` in
  [protocol.md](protocol.md#41-dht-messages).

### PeerIdentity

A per-daemon ed25519 keypair generated when an AOS daemon first starts. The
PeerId is the hash of the public key.

- **Scope**: One per running daemon instance.
- **Lifetime**: Long-lived, persisted across daemon restarts.
- **Purpose**: Identifies the daemon in all libp2p interactions. Participates
  in mesh routing, GossipSub, and stream protocols.

### JobIdentity

A per-job ed25519 keypair created each time a job is scheduled.

- **Scope**: One per job.
- **Lifetime**: Ephemeral. Created when the job is posted, destroyed when the
  job exits or is cancelled.
- **Purpose**: Signs `JobState` records published to the DHT under
  `aos:cluster:{cluster_ident}:job:{job_ident}:state`. The job process receives the private key via systemd
  credential injection (`LoadCredential`), allowing it to participate in libp2p
  as a first-class peer with its own identity.

## 2. Two-Layer Authorization Model

The protocol uses two distinct authorization mechanisms:

- **DHT record signing**: Identity-based signatures that prove a record was
  written by the correct identity (sections 2 and following).
- **UCAN protocol authorization**: Capability-based tokens that authorize
  GossipSub messages and stream protocol requests (sections 3--5).

See [permissions.md](permissions.md) for the detailed breakdown of which
capabilities map to which protocol operations and how roles compose them.

## 3. DHT Record Signing

Every DHT record type has a defined signature requirement. Validators reject
records that fail signature verification.

| Key Format | Signed By | Validation Rule |
|---|---|---|
| `aos:store:{object_id}` | None | Provider records are self-verifying via content hash. No signature required. |
| `aos:cluster:{cluster_ident}:job:{job_ident}:state` | JobIdentity | Public key extracted from `{job_ident}`, signature verified against record payload. |
| `aos:cluster:{cluster_ident}:config` | Root Identity | Public key extracted from `{cluster_ident}`, signature verified against record payload. |
| `aos:auth:token:{token_hash}:revoke` | Token Issuer | Signature verified against the issuer's public key. TTL mirrors the revoked token's expiry. See [Revocation](#10-revocation). |

Store records require no signature because the object ID is itself a
content-addressed hash. Any peer can verify a store object by recomputing its
hash. Job, cluster, and revocation records are identity-addressed and require the
corresponding identity's signature to prevent impersonation.

## 4. UCAN Capability Model

Authorization for GossipSub messages and stream protocol requests uses UCAN
(User Controlled Authorization Networks). A UCAN is a signed JWT-like token that
encodes a capability delegation chain.

### Capability Structure

Each UCAN capability specifies a resource path and WHERE clauses that scope it
to specific clusters, jobs, or operations. See
[permissions.md](permissions.md) for the complete resource/verb matrix, policy
restrictions, and role definitions.

A capability matches a request when:

1. The resource path in the UCAN matches the resource path required by the
   protocol.
2. All WHERE clauses evaluate to true against the request's fields.

### Delegation

Intermediate identities are the primary issuers of UCANs to leaf identities
(peers and jobs). An intermediate can only delegate capabilities it was itself
granted in its `IntermediateCert`. Peers may further delegate subsets of those
capabilities (attenuation). Each link in the chain is signed by the delegator.

Verification walks the full cert chain: UCAN signature -> intermediate
certificate -> root public key. See [UCAN Verification](#ucan-verification)
for the detailed algorithm.

## 5. GossipSub Message Authorization

Every message published to a GossipSub topic must carry a UCAN in the message
envelope. Subscribers validate the UCAN before accepting the message. Messages
that fail validation are dropped silently. See
[permissions.md](permissions.md) for the full publish/subscribe capability
mapping per topic.

| Topic | Required UCAN Capability |
|---|---|
| `aos/cluster/{cluster_ident}/jobs/announce` | `/aos/job/create`, `/aos/job/claim`, `/aos/job/cancel` (depends on delta type) |
| `aos/cluster/{cluster_ident}/load/announce` | `/aos/load/announce` WHERE `.cluster == {cluster_ident}` |
| `aos/store/publish` | `/aos/store/write` |
| `aos/auth/token/revoke` | Authorized by the token issuer (see [Revocation](#10-revocation)) |
| `aos/auth/token/issue` | Authorized by the token issuer |
| `aos/store/replicate` | `/aos/store/replicate` |
| `aos/store/purge` | `/aos/store/purge` |

The WHERE clauses enforce that:

- **Cluster scoping**: A UCAN issued for cluster A cannot authorize messages on
  cluster B's topics.
- **Operation scoping**: Job announcement capabilities can be restricted to
  specific operations (e.g., only `create` and `cancel`, but not `claim`).

## 6. Stream Protocol Authorization

Stream protocol requests carry a UCAN in the request header. The serving peer
validates the UCAN before processing the request.

| Protocol | Required UCAN Capability |
|---|---|
| `/aos/store/manifest/1.0.0` | `/aos/store/read` |
| `/aos/store/chunk/1.0.0` | `/aos/store/read` |
| `/aos/job/start/1.0.0` | `/aos/job/start` WHERE `.job == {job_ident}` |
| `/aos/job/log/1.0.0` | `/aos/job/read` WHERE `.cluster == {cluster_ident}` OR `.job == {job_ident}` |

Notable design choices:

- **Both manifest and chunk transfer require `/aos/store/read`.** While chunks
  are content-addressed and self-verifying by hash, gating access prevents
  unauthorized peers from exfiltrating store data even if they learn chunk
  hashes through other means.
- **Log access has two scopes.** A cluster-scoped UCAN grants access to logs
  for all jobs in the cluster. A job-scoped UCAN grants access only to that
  specific job's logs.
- **Exec authorization is job-scoped.** The UCAN must name the specific job
  identity being executed.

## 7. Two-Phase Start Authorization

Job execution requires mutual authorization between the job creator and the
claiming peer. Neither party can unilaterally start a job on the other's
machine. This is enforced through two UCANs that cross in opposite directions.

### Phase 1: Claim

When a peer claims a job, it includes a `start_ucan` in the `JobClaim` message:

```protobuf
message JobClaim {
    string peer_id = 1;
    string start_ucan = 2;  // Claimant authorizes the creator to start on their machine.
}
```

The `start_ucan` is issued by the claimant and grants the job identity holder
(i.e., the creator) the `/aos/job/start` capability scoped to this specific job.
This proves: **the claimant consents to run this job on their machine.**

### Phase 2: Start

The creator calls `/aos/job/start/1.0.0` on the claimant with a `JobStartRequest`:

```protobuf
message JobStartRequest {
    string job_ucan = 1;   // Creator delegates the job identity to the claimant.
    string start_ucan = 2;  // The start_ucan from the JobClaim.
}
```

The `JobStartRequest` carries two UCANs:

- **`job_ucan`**: Issued by the creator, delegating the JobIdentity (private
  key access via systemd secrets) to the claimant. This proves: **the creator
  authorizes this specific peer to act as the job.**
- **`start_ucan`**: The same UCAN from the claim, echoed back. This proves:
  **the claimant previously consented to execute this job.**

The claimant verifies both UCANs before starting the job container. The job
process receives the JobIdentity private key through systemd credential
injection so it can join libp2p and sign its own DHT records.

### Why Mutual Authorization

Neither UCAN alone is sufficient:

- Without `start_ucan`, a creator could force arbitrary peers to run jobs they
  never agreed to.
- Without `job_ucan`, a claimant could impersonate a job identity it was never
  granted, or a creator could bait-and-switch the job after claiming.

Both sides must independently prove their intent for execution to proceed.

## 8. Cluster Bootstrapping

When a new cluster is created, the administrator generates a root ed25519
keypair and publishes a signed `ClusterConfig` record to the DHT. The
`ClusterConfig` carries the root public key and a list of active intermediate
certificates.

The bootstrapping sequence is:

1. **Generate Root Identity.** The administrator creates the ed25519 keypair
   offline (vault or HSM). The public key hash becomes the `{cluster_ident}`.
2. **Create Intermediate Certificates.** The root signs one or more
   `IntermediateCert` records, each scoped to a set of capabilities and an
   expiry window. For example: `ops-admin` (1yr, full capabilities),
   `ci-admin` (90d, job announce + start only), `dev-admin` (6mo, job announce
   + log read only).
3. **Publish ClusterConfig.** The initial cluster configuration — including
   `root_public_key` and the list of `IntermediateCert` records — is signed by
   the root and published to `aos:cluster:{cluster_ident}:config`.
4. **Issue initial UCANs.** Each intermediate issues UCAN delegations to its
   assigned peers and jobs, granting them capabilities to announce jobs, report
   load on the cluster's GossipSub topics.
5. **Peers join.** Each peer receives its UCAN delegation (out of band or via a
   registration protocol) and begins participating in the cluster's topics and
   protocols.

The root private key does not need to remain online after bootstrapping. It is
only required when signing new intermediate certificates or updating the
`ClusterConfig`. Intermediate keys remain online to issue and renew UCANs.

### UCAN Verification

When verifying a UCAN presented by a peer or job, the verifier walks the
certificate chain from the UCAN back to the root:

```
Verify UCAN:
  1. UCAN says iss=intermediate-X, aud=peer-Y
  2. Look up intermediate-X in ClusterConfig.intermediates
  3. Verify intermediate's cert signature chains to root (or parent intermediate)
  4. Check intermediate not expired (not_before <= now <= not_after)
  5. Check intermediate not revoked (DHT lookup or cache hit)
  6. Verify UCAN signature by intermediate's key
  7. Verify UCAN capabilities are subset of intermediate's capabilities
```

For chained intermediates (where `parent_cert_id` is non-empty), step 3
recurses: verify the parent intermediate's cert, then the grandparent's, until
reaching a cert signed directly by the root.

## 9. Job Identity Lifecycle

Job identities are ephemeral and tightly scoped to a single job execution.

1. **Creation.** When a job is posted, the creator generates a fresh ed25519
   keypair. The public key hash becomes the `{job_ident}`.
2. **Publication.** The creator publishes the initial `JobPost` (with a `create`
   delta) to the cluster's jobs GossipSub topic. The `{job_ident}` is included
   in the message.
3. **Delegation.** When execution begins (Phase 2), the creator delegates the
   JobIdentity to the claimant via the `job_ucan` in the `JobStartRequest`.
4. **Injection.** The claimant's daemon injects the JobIdentity private key into
   the job's systemd unit via `LoadCredential`. The job process reads the key
   from the credential path at startup.
5. **Participation.** The running job uses its JobIdentity to join libp2p, sign
   `JobState` DHT records under `aos:cluster:{cluster_ident}:job:{job_ident}:state`, and authenticate to any
   protocols that accept job-scoped UCANs.
6. **Destruction.** When the job exits (normally or via cancellation), the
   JobIdentity is discarded. The DHT record expires via its short TTL liveness
   check. The keypair is never reused.

## 10. Revocation

UCAN and intermediate certificate revocation uses a DHT-based model with
GossipSub notifications for protocol propagation. This replaces the previous
approach of relying solely on short-lived tokens and emergency eviction signals.

### Revocation Records

Revocation records are stored in the DHT at `aos:auth:token:{token_hash}:revoke`.

- **Value**: `RevocationRecord` — see [protocol.md](protocol.md#41-dht-messages)
  for the protobuf definition.
- **Signature**: Must be signed by the same key that issued the token being
  revoked. This prevents unauthorized revocation — only the issuer of a UCAN
  or the signer of an intermediate cert can revoke it.
- **TTL**: Mirrors the revoked token's expiry time. When the token would have
  expired anyway, the revocation record is garbage-collected automatically.

### GossipSub Notification

When a token is revoked, the issuer publishes a `RevocationNotice` to the
GossipSub topic `aos/auth/token/revoke`. The notice carries only
the `token_hash` — it is lightweight by design. Peers that receive the
notification fetch the full `RevocationRecord` from the DHT if they do not
already have it cached.

### Local Revocation Cache

Each peer maintains a local revocation cache with two layers:

- **Positive cache**: Known-revoked tokens. Populated from DHT lookups and
  GossipSub notifications. Entries persist until the token's original expiry
  time (matching the DHT TTL).
- **Negative cache**: Known-NOT-revoked tokens with a short TTL (default 60s).
  Prevents repeated DHT lookups for high-frequency operations. Entries are
  invalidated immediately when a GossipSub revocation notice arrives for the
  token.

### Tiered Validation

Different operations have different risk profiles and volume characteristics.
The revocation check strategy is tiered accordingly:

| Operation | Revocation Check | Rationale |
|---|---|---|
| Chunk fetch | Cache only (no DHT lookup on miss) | High volume, low risk. Chunks are content-addressed and self-verifying. |
| GossipSub messages | Cache + negative cache (60s TTL) | Medium volume, medium risk. Stale-by-60s is acceptable. |
| Job exec | Cache + synchronous DHT lookup on miss | Low volume, high risk. No negative caching — always verify against DHT if not positively cached. |

### Intermediate Subtree Revocation

Revoking an intermediate certificate implicitly revokes its entire subtree.
There is no need to individually revoke each child UCAN issued by that
intermediate. During UCAN verification (see [UCAN Verification](#ucan-verification)),
the cert chain walk encounters the revoked intermediate at step 5 and rejects
the entire chain. All UCANs issued by the revoked intermediate — and any
sub-intermediates chained below it — become invalid immediately.

### Per-Message Validation

Every GossipSub message carries a UCAN in its envelope. On receipt, peers
validate the UCAN before processing the message:

1. **Chain walk**: Verify the UCAN's delegation chain through intermediates to
   the root (see [UCAN Verification](#ucan-verification)).
2. **Expiry check**: If the UCAN's `exp` claim is in the past, the message is
   rejected.
3. **Revocation check**: Check the revocation cache (and optionally DHT) for
   the UCAN and each intermediate in the chain, per the tiered validation
   policy.
4. **Peer score penalty**: Rejected messages incur a GossipSub peer score
   penalty. Repeated violations cause the peer to be disconnected and
   blacklisted by the mesh.
