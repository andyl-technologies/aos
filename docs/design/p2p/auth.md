# Authentication and Authorization

The AOS distributed build system uses three complementary mechanisms to
authenticate peers and authorize actions:

1. **libp2p peer identity** -- transport-layer authentication
2. **UCAN tokens** -- capability-based authorization on the mesh
3. **Unix sockets with SO_PEERCRED** -- local user authentication to the daemon

Each mechanism operates at a different boundary and addresses a distinct
concern. Together they provide end-to-end security from a local user typing
`aos build foo` through to a remote daemon claiming and executing that build.

---

## Mesh Participants

Two types of peers participate in the mesh:

**Daemon** -- A full node with a Nix store. Can evaluate derivations, claim
jobs, execute builds, serve NARs, and manage its local store. Long-lived,
machine-level identity. Local users on the same machine delegate through Unix
sockets; they never join the mesh directly.

**Client** -- A lightweight peer with no Nix store and no build execution
capability. Joins the mesh with its own keypair and UCAN. May be ephemeral
(CI container that submits a build and exits) or long-lived (observability
dashboard). Examples:

- Developer laptops running `aos build -i <identity>`
- CI containers that submit builds and stream logs
- Web UIs and dashboards (`aos net -i <identity>`)
- Archivers that fetch NARs for cold storage
- Monitoring and alerting systems

Same mesh, same auth model (UCAN), different capabilities. A daemon is just a
client that additionally holds `claim` + `serve` capabilities and has a Nix
store.

---

## Auth Boundaries

Three boundaries, each handled by a different mechanism:

| Boundary | Mechanism | Question answered |
|----------|-----------|-------------------|
| Transport | libp2p TLS 1.3 / Noise | Who is this peer? |
| Mesh authorization | UCAN | What can this peer do? |
| Local control | Unix socket + SO_PEERCRED | What can this user do on this daemon? |

---

## Peer Identity (Transport Layer)

Every peer -- daemon or client -- has an ed25519 keypair. The PeerId is the
multihash of the public key. All connections are encrypted and mutually
authenticated via TLS 1.3 (over QUIC) or the Noise protocol.

This is non-optional. libp2p enforces it at the transport layer. Every
connection is authenticated: you always know WHO you are talking to. But
transport-layer identity says nothing about WHAT a peer is allowed to do.
That is UCAN's job.

Key properties:

- Keypair generated once per peer (daemon or client) and stored locally
- PeerId is deterministic: same keypair always produces the same PeerId
- No certificates, no CA, no PKI -- identity is purely key-based
- libp2p rejects connections from peers that cannot prove possession of
  the private key corresponding to their claimed PeerId

---

## UCAN: Capability-Based Authorization

### What is UCAN

UCAN (User Controlled Authorization Networks) is a decentralized
capability-based authorization scheme built on JWT. Key properties:

- **Self-contained**: tokens are verifiable offline by checking the signature
  chain. No network call to an auth server required.
- **Delegable**: capabilities can be passed from one peer to another, but only
  narrowed (attenuated), never escalated. A peer cannot grant capabilities it
  does not itself possess.
- **No auth server**: verification is purely cryptographic. Check signatures
  back to the root public key.
- **Expiring**: tokens carry an `exp` field for natural rotation and bounded
  exposure windows.

### Capability Vocabulary

| Capability | What it grants | Typical holder |
|------------|----------------|----------------|
| `build/submit` | Publish jobs to `build/wanted/{universe}/{system}` | Daemons, dev clients, CI clients |
| `build/claim` | Claim jobs from `build/wanted/{universe}/{system}` and execute builds | Daemons only |
| `build/observe` | Subscribe to build logs, query build status | All |
| `store/serve` | Serve NARs/chunks to peers requesting store paths | Daemons |
| `store/fetch` | Fetch NARs/chunks from peers | Daemons, archiver clients |
| `admin/manage` | GC, view management, peer administration | Admin daemons |
| `sync/write` | Publish CRDT mutations to `sync/{universe}/` namespace. Path-scoped: `aos://{universe}/sync/profiles/dylan/*` grants write only to that subtree. | Daemons, dev clients |
| `sync/read` | Receive CRDT state from universe. Path-scoped similarly. | Daemons, clients |
| `shell/create` | Create login shells on hosts with login capability. | Daemons, dev clients |

### UCAN Structure

```json
{
  "iss": "did:key:z6Mk...",
  "aud": "did:key:z6Mk...",
  "exp": 1735689600,
  "att": [
    {"with": "aos://default/*", "can": "build/submit"},
    {"with": "aos://default/*", "can": "build/observe"},
    {"with": "aos://staging/*", "can": "build/submit"}
    // "with" uses universe-scoped URIs: aos://{universe}/*
  ],
  "prf": ["<parent-UCAN>"],
  "fct": [
    {"hostname": "builder-01", "arch": "x86_64-linux"}
  ]
}
```

Path-scoped sync capabilities use the same URI scheme with path prefixes to
restrict write access to specific subtrees within the sync namespace:

```json
{
  "att": [
    {"with": "aos://staging/sync/profiles/dylan/*", "can": "sync/write"},
    {"with": "aos://staging/sync/*", "can": "sync/read"},
    {"with": "aos://staging/*", "can": "shell/create"}
  ]
}
```

Here the peer can write CRDT mutations only under `sync/profiles/dylan/` in the
`staging` universe, read all sync state in that universe, and create login
shells on any host in `staging`.

Fields:

- `iss` (issuer): the DID of the peer that signed this token. For root-issued
  tokens this is the root key. For delegated tokens this is the delegating
  peer.
- `aud` (audience): the DID of the peer this token is issued to. The peer
  presenting the token must prove it controls this key (via the libp2p
  transport handshake).
- `exp` (expiry): Unix timestamp after which the token is no longer valid.
- `att` (attenuations): the list of capabilities granted. Each entry has a
  `with` field scoping to a resource (view) and a `can` field naming the
  capability.
- `prf` (proofs): parent UCAN tokens forming the delegation chain. Empty for
  root-issued tokens.
- `fct` (facts): optional metadata. Not used for authorization decisions but
  useful for debugging and observability.

The `with` field scopes capabilities to universes: `aos://default/*` means "the
universe named `default`, all resources within it." This enables fine-grained
scoping. A CI client might only have `submit` for the `staging` universe and
nothing else.

### Delegation Chain

A concrete example showing how capabilities flow from the root key through
daemons to clients:

```
Root Key (offline after initial setup)
  |
  | UCAN #1: root -> Daemon A
  |   cap: [build/submit, build/claim, store/serve, store/fetch, build/observe, admin/manage]
  |   universes: [*]  (all universes)
  |   exp: 2027-01-01
  |
  +---> Daemon A stores UCAN #1
  |
  | UCAN #2: root -> Daemon B
  |   cap: [build/claim, store/serve, store/fetch, build/observe]
  |   universes: [default]
  |   exp: 2027-01-01
  |
  +---> Daemon B: build-only worker, cannot submit jobs
  |
  | UCAN #3: Daemon A -> Client C (delegated, not root-signed)
  |   iss: PeerId-A
  |   aud: PeerId-C
  |   cap: [build/submit, build/observe]  <-- attenuated from A's full set
  |   universes: [staging]         <-- further restricted
  |   exp: 7 days from now
  |   prf: [UCAN #1]          <-- proof: A got these caps from root
  |
  +---> Client C: developer laptop, can submit to staging only
        Verification: any peer checks root -> A -> C
        Capabilities only narrow at each delegation step
```

Note that Daemon A can delegate `build/submit` and `build/observe` (which it holds) but
cannot delegate `admin/manage` to Client C unless it also restricts its own future
use (UCAN attenuation is monotonically narrowing).

Sync capabilities follow the same delegation pattern with path scoping:

```
Root Key
  |
  | UCAN #S1: root -> Daemon A
  |   cap: [sync/write, sync/read]
  |   with: aos://*/sync/*        (all paths, all universes)
  |   exp: 2027-01-01
  |
  +---> Daemon A: full sync read/write for all paths
  |
  | UCAN #S2: Daemon A -> Developer Client D (delegated)
  |   iss: PeerId-A
  |   aud: PeerId-D
  |   cap: [sync/write]           <-- attenuated: write only
  |   with: aos://default/sync/profiles/dylan/*  <-- path-scoped
  |   cap: [sync/read]
  |   with: aos://default/sync/*  <-- can read all sync state
  |   exp: 7 days from now
  |   prf: [UCAN #S1]
  |
  +---> Client D: can write only to their own profile subtree
  |
  | UCAN #S3: Daemon A -> CI Client E (delegated)
  |   iss: PeerId-A
  |   aud: PeerId-E
  |   cap: [sync/write]
  |   with: aos://staging/sync/shells/ci-*  <-- scoped to CI shells
  |   cap: [sync/read]
  |   with: aos://staging/sync/*
  |   exp: 24 hours from now
  |   prf: [UCAN #S1]
  |
  +---> Client E: CI can only write shell state under ci-* prefix
```

Path scoping ensures that delegated sync capabilities cannot exceed the
subtree granted by the parent UCAN. Daemon A has `sync/*` (all paths) and
can narrow to `sync/profiles/dylan/*` or `sync/shells/ci-*` for specific
clients.

### Verification

When a peer receives a GossipSub message (e.g., a job submission on
`build/wanted/{universe}/{system}`), it validates the attached UCAN before accepting the message:

```rust
fn validate_gossipsub_message(
    msg: &gossipsub::Message,
    root_pubkey: &PublicKey,
) -> MessageAcceptance {
    let job: BuildJob = match serde_json::from_slice(&msg.data) {
        Ok(j) => j,
        Err(_) => return MessageAcceptance::Reject,
    };

    // Verify the UCAN chain back to the root key
    let chain = match ucan::ProofChain::from_token_string(&job.ucan) {
        Ok(c) => c,
        Err(_) => return MessageAcceptance::Reject,
    };

    // Check: chain roots at our trusted root key
    if chain.root_issuer() != root_pubkey {
        return MessageAcceptance::Reject;
    }

    // Check: the sender PeerId matches the UCAN audience
    if chain.audience() != msg.source {
        return MessageAcceptance::Reject;
    }

    // Check: token has the required capability for this message type
    let required_cap = match job.message_type {
        t if t.starts_with("build/wanted/") => "build/submit",
        t if t.starts_with("build/claimed/") => "build/claim",
        _ => return MessageAcceptance::Reject,
    };

    if !chain.has_capability(required_cap, &format!("aos://{}/*", job.universe)) {
        return MessageAcceptance::Reject;
    }

    // Sync deltas on the sync/{universe} GossipSub topic are validated the
    // same way: check UCAN chain, verify the `with` path covers the delta's
    // target path, and check expiry.  For example, a delta targeting
    // sync/profiles/dylan/status requires a UCAN whose `with` field is a
    // prefix match (e.g. aos://default/sync/profiles/dylan/*).
    // See validate_sync_delta() below.

    // Check: not expired
    if chain.is_expired() {
        return MessageAcceptance::Reject;
    }

    MessageAcceptance::Accept
}
```

Sync deltas published to `sync/{universe}` GossipSub topics are validated
identically:

```rust
fn validate_sync_delta(
    msg: &gossipsub::Message,
    root_pubkey: &PublicKey,
) -> MessageAcceptance {
    let delta: SyncDelta = match serde_json::from_slice(&msg.data) {
        Ok(d) => d,
        Err(_) => return MessageAcceptance::Reject,
    };

    let chain = match ucan::ProofChain::from_token_string(&delta.ucan) {
        Ok(c) => c,
        Err(_) => return MessageAcceptance::Reject,
    };

    if chain.root_issuer() != root_pubkey {
        return MessageAcceptance::Reject;
    }

    if chain.audience() != msg.source {
        return MessageAcceptance::Reject;
    }

    // Path-scoped check: the UCAN's `with` field must be a prefix of
    // the delta's target path.  e.g. "aos://default/sync/profiles/dylan/*"
    // covers "aos://default/sync/profiles/dylan/status".
    let delta_resource = format!("aos://{}/sync/{}", delta.universe, delta.path);
    if !chain.has_capability("sync/write", &delta_resource) {
        return MessageAcceptance::Reject;
    }

    if chain.is_expired() {
        return MessageAcceptance::Reject;
    }

    MessageAcceptance::Accept
}
```

Rejected messages penalize the sender's GossipSub peer score. Persistent
offenders accumulate negative scores and are eventually graylisted -- their
messages are ignored and their connections deprioritized. This provides
automatic protection against both misconfigured peers and active attackers.

---

## Auth Domain Separation

UCAN is for mesh (peer-to-peer). Unix sockets are for local (same
machine/container). They never mix. A UCAN token is never sent over a Unix
socket; `SO_PEERCRED` is never used on the mesh. The two auth systems operate
at different boundaries and serve different purposes:

- **Mesh auth (UCAN)**: identifies peers across the network, encodes
  capabilities, supports delegation chains. Used for all libp2p communication.
- **Local auth (Unix sockets)**: identifies users/processes on the same
  machine via kernel-provided credentials. Socket path is the credential for
  containers (if you can connect, you are authorized at that level).
  `SO_PEERCRED` provides uid/gid for host users.

For multi-user containers and VMs, the daemon runs in **forwarding mode**:
it binds a control socket inside the container and forwards requests to an
upstream daemon socket on the host. Capabilities narrow at each nesting level.
See [sockets.md](sockets.md) for the full socket architecture, socket types,
and multi-level nesting.

## Unix Socket Control Protocol

### How local users interact with their daemon

Users on a machine do not join the mesh directly. They communicate with their
local daemon via a Unix domain socket. The daemon authenticates the user via
`SO_PEERCRED` (which the kernel populates with the connecting process's uid,
gid, and pid) and then acts on the user's behalf on the mesh.

```
User runs: aos build foo
  |
  | Connect to /run/aos/control.sock
  | SO_PEERCRED -> uid=1000, gid=100
  |
  v
Daemon checks local policy:
  | uid 1000 is in group "aos-build"
  | group "aos-build" has capabilities: [submit, observe]
  |
  v
Daemon performs the action on the mesh:
  - Evaluates derivation
  - Submits job to GossipSub (using daemon's PeerId + UCAN)
  - Streams logs back to user via the socket
```

The mesh never sees user identities. The daemon is the trust boundary. From the
mesh's perspective, all actions from a machine come from that machine's daemon
PeerId.

### Local auth policy

The daemon's configuration maps Unix groups to capability sets:

```toml
[control]
socket = "/run/aos/control.sock"
socket_group = "aos"              # Unix group that can connect

[control.groups]
# Short forms for local auth policy -- these map to the qualified UCAN
# capability names internally (e.g. "submit" -> "build/submit",
# "fetch" -> "store/fetch", "manage" -> "admin/manage").
aos-admin = ["submit", "observe", "manage", "fetch"]
aos-build = ["submit", "observe"]
aos-read  = ["observe"]
```

When a connection arrives on the Unix socket, the daemon:

1. Reads `SO_PEERCRED` to obtain the connecting process's uid and gid
2. Resolves the uid's group memberships
3. Looks up the highest-privilege matching group in `[control.groups]`
4. Allows or denies the requested action based on the group's capability set

If the user's groups do not appear in the policy, the connection is rejected.

### Control protocol messages

The Unix socket uses a JSON-lines protocol. Each line is a self-contained JSON
object. The daemon responds with one or more JSON lines (streaming for logs).

```json
// Submit a build
{"action": "build", "attr": "pkgs.foo"}

// Watch build logs (streams until build completes)
{"action": "watch", "drv_hash": "abc123"}

// Query build status
{"action": "status", "drv_hash": "abc123"}

// Trigger garbage collection
{"action": "gc", "view": "default", "dry_run": true}

// List connected peers
{"action": "peers"}

// Delegate a UCAN to a client
{"action": "delegate", "cap": ["build/submit", "build/observe"], "universes": ["staging"], "expires": "7d"}
```

The `delegate` action is how a daemon issues UCAN tokens to client peers. The
daemon creates a sub-UCAN attenuated from its own capabilities, signs it with
its own key, and returns the token string. The user can then pass this token to
a client peer (e.g., their laptop running `aos build -i <identity>`).

---

## Client Peers

### What is a client peer

A client is a lightweight libp2p peer that joins the mesh with its own identity
and UCAN. It has no Nix store and cannot execute builds. Clients are created
by passing the `-i <identity>` flag to `aos build` or `aos net`, which
activates P2P mode in the main `aos` binary instead of talking to the local
daemon socket. Clients are used for:

- `aos build -i myident foo` -- developer laptop submitting builds without
  running a local daemon
- CI containers -- submit builds, watch results, exit
- Web UIs and dashboards -- `aos net -i myident` to observe build activity
- Archiving tools -- fetch NARs from the mesh for backup or cold storage
- Monitoring and alerting -- observe peer health, build failure rates

### How `aos build -i` works

```
$ aos build -i myident foo
```

Identity files live at `~/.aos/identities/myident/` and contain `key.ed25519`,
`token.ucan`, and `seed_peers`.

The steps:

1. Read the identity from `~/.aos/identities/myident/`
2. Load the ed25519 keypair from `key.ed25519`
3. Read the UCAN token from `token.ucan`
4. Read bootstrap peers from `seed_peers`
5. Start a lightweight libp2p peer (no Kademlia server mode, no NAR serving)
6. Connect to the mesh via the seed peers
7. Present UCAN during the `/aos/auth/1.0.0` handshake -- peers verify the
   chain back to the root key
8. Evaluate the derivation locally (requires Nix on the local machine, but
   not a daemon)
9. Publish the job to `build/wanted/{universe}/{system}` via GossipSub (UCAN must include
   `build/submit` capability)
10. Subscribe to `build/logs/{drv_hash}` via GossipSub
11. Stream logs to the terminal as they arrive
12. On completion: print the result and exit

For long-lived observation:

```
$ aos net logs -i myident
# Subscribes to all build activity, streams to stdout or a dashboard
```

### Client vs daemon: capability comparison

| | Daemon | Client |
|---|--------|--------|
| Nix store | Yes | No |
| Build execution | Yes (if `[build]` configured) | No |
| Unix socket control | Yes | No |
| NAR serving | Yes | No |
| GossipSub subscribe | All topics | Selective (logs, results) |
| GossipSub publish | Jobs, claims, results, logs | Jobs only (if `submit` cap) |
| Persistence | Long-lived, stores state on disk | Ephemeral or long-lived, minimal state |
| Identity | Persistent keypair (machine-level) | Persistent or ephemeral keypair |

Both daemon and client modes use `aos-p2p` for the libp2p layer. The daemon
additionally links `aos-core` for Nix store operations and build execution.

---

## Cluster Bootstrapping

### Step 1: Create the cluster root key

```
$ aos auth init
```

This command:

- Generates an ed25519 root keypair
- Stores the private key at `~/.aos/root.key`
- Stores the public key at `~/.aos/root.pub`
- Prints the root PeerId (the cluster identity)
- Prints the root public key in `did:key` format

The root public key is the ONLY thing every node needs to verify UCAN tokens.
It functions like a CA root certificate. Distribute it however you want:
config management, container images, `scp`, checked into the repo, baked into
a NixOS module. It is a public key -- there is no secret to protect.

The root private key should be stored securely and kept offline after initial
enrollment. It is only needed to issue top-level UCANs.

### Step 2: Start the first daemon

If the root key is on the same machine as the first daemon:

```
$ aos daemon --root-pubkey <root-public-key>
```

The daemon detects that `root.key` is present locally, auto-issues a
full-capability UCAN to itself, and starts the mesh (a mesh of one).

Alternatively, issue the UCAN explicitly:

```
$ aos auth enroll daemon \
    --root-key ~/.aos/root.key \
    --cap build/submit,build/claim,store/serve,store/fetch,build/observe,admin/manage \
    --universes '*' \
    --expires 1y
# Prints UCAN token

$ aos daemon --token <UCAN-token> --root-pubkey <root-public-key>
```

### Step 3: Enroll additional daemons

On the admin machine (which holds the root key):

```
$ aos auth enroll daemon \
    --root-key ~/.aos/root.key \
    --peer-id QmDaemonB \
    --cap build/claim,store/serve,store/fetch,build/observe \
    --universes default \
    --expires 1y
# Prints UCAN token
```

On the new machine:

```
$ aos daemon \
    --token <UCAN-token> \
    --root-pubkey <root-public-key> \
    --seed seed1.example.com
```

The new daemon connects to the seed peer, presents its UCAN during the
`/aos/auth/1.0.0` handshake, the seed peer verifies the chain back to the root
key, and the new daemon is admitted to the mesh.

### Step 4: Issue client credentials

Root-issued client token:

```
$ aos auth enroll client \
    --root-key ~/.aos/root.key \
    --cap build/submit,build/observe \
    --universes staging \
    --expires 30d
# Prints UCAN token (not bound to a specific PeerId -- bearer token)
```

Daemon-delegated client token (no root key needed):

```
$ aos auth delegate \
    --cap build/submit,build/observe \
    --universes staging \
    --expires 7d
# Daemon issues a sub-UCAN from its own capabilities
# Prints delegated token
```

The difference: root-issued tokens have a one-link chain (root -> client).
Daemon-delegated tokens have a two-link chain (root -> daemon -> client). Both
verify the same way -- check signatures back to the root public key.

Bearer tokens (no `aud` binding) are usable by any peer that possesses them.
For higher security, bind the token to a specific PeerId by setting `aud`.

### Step 5: Ongoing operations

- **Daemon tokens**: long-lived (months to a year). Re-issue before expiry
  using the root key, or set up auto-renewal where a daemon requests a fresh
  UCAN from a peer that holds a longer-lived parent UCAN.
- **Client tokens**: short-lived (hours to days) for CI. Long-lived (weeks to
  months) for developer laptops and dashboards.
- **Rotation**: issue new tokens before old ones expire. Old tokens continue
  to work until their `exp` passes. No coordinated cutover required.

---

## Revocation

### The problem

UCANs are self-contained. A revoked-but-unexpired token still verifies
cryptographically. This is inherent to any bearer token scheme. Three
mitigation strategies address this, and the recommended approach combines
all three.

### Strategy 1: Short-lived tokens

Issue UCANs with short expiry (e.g., 24 hours for CI clients, 7 days for
developer clients, 30 days for daemons). Revocation amounts to not renewing
the token. The window of exposure is bounded by the expiry.

Daemons can auto-renew by requesting a fresh UCAN from a peer that holds a
longer-lived parent UCAN. This is analogous to short-lived TLS certificates
with automatic renewal via ACME.

### Strategy 2: Revocation list in the DHT

Publish revoked UCAN IDs (or revoked PeerIds) to a well-known DHT key:

```
DHT key: "revocations"
Value: { "revoked": ["did:key:z6Mk...", ...], "updated_at": ... }
```

Peers check the revocation list during UCAN verification. This is eventually
consistent -- there is a window where a revoked token is still accepted by
peers that have not yet seen the update. The window depends on DHT propagation
speed (typically seconds to low minutes).

### Strategy 3: Connection gating

Use `libp2p-allow-block-list` to immediately disconnect and block a revoked
PeerId at the transport layer. Faster than waiting for DHT propagation.

The admin daemon publishes a `peers/blocked` GossipSub message containing the
PeerId to block. All daemons that receive this message update their local block
lists and immediately sever connections to the blocked peer.

This is the "kill this peer NOW" mechanism for emergencies (compromised key,
active attack).

### Recommended approach

Combine all three:

1. **Short-lived tokens** as the baseline. Limits the exposure window even if
   no active revocation is performed. This handles the common case (employee
   leaves, CI token no longer needed).
2. **DHT revocation list** for active revocation when a token must be
   invalidated before its natural expiry. Handles the uncommon case
   (compromised key discovered).
3. **Connection gating** for emergency scenarios where a peer must be severed
   immediately. Handles the rare case (active attack in progress).

---

## Root Key Management

### Single root key (simple)

One ed25519 keypair. Store securely: hardware security key, encrypted file on
an air-gapped machine, or a secrets vault (e.g., HashiCorp Vault, AWS KMS).
Keep offline after initial enrollment.

Risk: if the root private key is compromised, an attacker can issue arbitrary
UCANs with any capabilities. Mitigation: rotate the root key and re-enroll all
nodes (see below).

### Root key set (multi-sig, future)

Multiple root keys with M-of-N threshold signatures required to issue UCANs.
More complex but more resilient to single-key compromise. This can be
implemented later since UCAN supports multiple proofs -- a token could require
signatures from M of N root keys.

This is not planned for the initial implementation.

### Root key rotation

```
$ aos auth rotate-root \
    --old-key ~/.aos/root.key \
    --new-key ~/.aos/root-new.key
```

This command:

1. Generates a new root keypair (or uses a provided one)
2. Issues a "key rotation" UCAN signed by the old key, containing the new
   public key in its `fct` field
3. Publishes the rotation UCAN to the DHT and via GossipSub
4. All peers learn the new root public key and begin accepting tokens signed
   by either key during a transition period
5. Re-issue daemon and client UCANs signed by the new key
6. After all tokens have been re-issued, the old key can be destroyed

During the transition period, peers accept tokens rooted at either the old or
new root key. This allows rolling updates without coordinated downtime.

---

## Mesh Membership Enforcement

### How peers are admitted to the mesh

When a new peer connects to any existing peer via libp2p:

1. libp2p authenticates the PeerId via the TLS 1.3 or Noise handshake
   (transport layer -- automatic)
2. The existing peer initiates a custom `/aos/auth/1.0.0` protocol exchange:
   - The new peer sends its UCAN token
   - The existing peer verifies the chain back to the root public key
   - If valid: the peer is accepted and added to the GossipSub mesh,
     Kademlia DHT, etc.
   - If invalid: the connection is closed and the PeerId is added to the
     local block list

```rust
async fn handle_auth_handshake(
    mut stream: libp2p::Stream,
    root_pubkey: &PublicKey,
) -> Result<bool> {
    // Read UCAN from new peer
    let token: String = read_framed(&mut stream).await?;

    // Verify the delegation chain
    let chain = ucan::ProofChain::from_token_string(&token)?;

    if chain.root_issuer() != root_pubkey {
        write_framed(&mut stream, &AuthResponse::Rejected("unknown root")).await?;
        return Ok(false);
    }

    if chain.is_expired() {
        write_framed(&mut stream, &AuthResponse::Rejected("expired")).await?;
        return Ok(false);
    }

    // Extract capabilities for this peer and store them
    let caps = chain.capabilities();
    write_framed(&mut stream, &AuthResponse::Accepted { caps }).await?;
    Ok(true)
}
```

After admission, the peer's capabilities are cached locally. Subsequent
GossipSub messages from this peer are validated against both the cached
capabilities and the UCAN attached to each message (belt and suspenders).

### Open mesh mode (development and testing)

For development or fully trusted networks, UCAN verification can be disabled:

```toml
[auth]
mode = "open"  # accept all peers (default: "ucan")
```

In open mode, any peer that can complete the libp2p transport handshake is
admitted with full capabilities. This should never be used in production.

---

## Security Properties

| Property | Mechanism |
|----------|-----------|
| Peer identity | ed25519 keypair, PeerId = multihash of public key |
| Connection encryption | TLS 1.3 (QUIC) or Noise protocol |
| Peer authentication | libp2p transport-layer handshake (mutual) |
| Capability authorization | UCAN token chain verification back to root key |
| Capability delegation | UCAN attenuation chains (monotonically narrowing) |
| Local user authentication | Unix socket SO_PEERCRED (kernel-provided uid/gid) |
| Message integrity | GossipSub signed messages (libp2p message signing) |
| Spam prevention | GossipSub peer scoring + UCAN validation on every message |
| Revocation | Short-lived tokens + DHT revocation list + connection gating |
| Root trust | Single root public key distributed to all nodes |
| Replay prevention | UCAN `exp` field + GossipSub message deduplication |
| Path-scoped sync permissions | UCAN path prefix matching on sync namespace |
| Privilege escalation prevention | UCAN attenuation: delegated tokens can only narrow, never widen |
