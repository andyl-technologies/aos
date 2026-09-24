# Protocols and portable data formats

## Compatibility domains

The design has four independent compatibility domains:

1. public sandbox control API;
2. coordinator-to-node reconciliation protocol;
3. node-local privileged broker protocols; and
4. portable policy, tree, delta, view, environment, snapshot, and signature
   formats.

An API package version does not imply a kernel capability or data-format
version. Every domain negotiates or identifies its own compatibility.

## Public API

The public API uses protobuf service definitions in `aos.sandbox.v1` and AOS's
existing Connect transport and ProtoJSON conventions. It includes services for:

- sandbox lifecycle and ancestry;
- execution authorization and operation status;
- filesystem views and attachments;
- snapshots and forks;
- capability delegation and revocation;
- policy planning and explanation; and
- paginated events and observations.

Resource responses contain stable UIDs, opaque resource versions, desired
specification, observed status, effective policy digest, and conditions. They
never include host paths, unit names, cgroup paths, PIDs as identity, namespace
paths, FUSE IDs, mount IDs, ZFS dataset names, or backend command lines.

The additive public observation model makes that status explicit.
`SandboxObservedState` carries phase, optional active incarnation and placement,
desired generation, monotone observation sequence, conditions, ownership lease
generation and expiry, Guardian state and generation, capability generation,
realized-root and ownership-transaction state, environment generation, typed
attachment health and generations, active executions, pinned references,
cache/disclosure domain observations, logical usage, an audit-event cursor, and
the last successful reconciliation time. Conditions bind their desired
generation and observation sequence and use closed reason and freshness values.
Operations and the other reconciled resources likewise carry a current
observation sequence and reconciliation time.

Source-only checked projections validate the complete established protobuf
resource, phase and placement legality, condition correlation, bounds, and
public/operator redaction before a service or CLI may return it. The pure Get
and watch handler is deliberately not registered with the production Connect
router. These models define no second public schema, grant no read authority,
and activate no point-read, watch, audit, or mutation route.

### Runtime and guest-agent source status

The portable runtime-backend module defines capability negotiation, move-only
lifecycle states, durable execution admission and effect records, bounded
codecs, and authenticated recovery inputs. A dormant Host 1.0 projection maps
an already validated request into that model without invoking an effect. A
concrete dormant `RuntimeBackend` composition now binds that projection to the
fixed-root protected runtime owner and real readiness evidence. No active Host
service call site, listener, readiness advertisement, or production activation
consumes it.

The source-only guest-agent contract uses `AOSAGE01` frames for one exact
incarnation handshake and a bounded stop-and-wait execution/quiesce stream.
Protected reducer, sequence reservation, checkpoint, terminal commit, and cold
recovery authority live under `aos-sandbox::runtime_execution`, not in the
portable agent crate. A dormant protected guest adapter and process supervisor
cover credential, process, PTY, resize, and signal effects without accepting
caller-forged observations; the protected owner separately reconciles signed
restart readback. There is still no public execution data plane, nspawn
activation, listener, readiness advertisement, or production service route in
this source tranche.

The initial method registry is explicit:

- sandbox: create, get, list, list-children, plan/update policy, start, stop,
  suspend, resume, and delete;
- execution: create, get, cancel, and list;
- snapshot: create, get, list, restore, fork, and delete;
- filesystem view: create, get, list, attach, replace, detach, and release;
- capability: attenuate, inspect, renew, and revoke; and
- operations/observations: get operation, cancel operation, watch, and get node
  semantic capabilities.

Create uses expected absence plus the expected parent/project resource
versions. Idempotent delete of an absent resource does not require a resource
version; destructive deletion of an existing object does. Multi-object
mutations name the version of every authority or dependency they consume.

Tree APIs do not recursively embed unbounded descendants. They expose paginated
adjacency:

```text
GetSandbox
ListChildren(parent, page)
ListAncestors(sandbox, bounded_depth, page)
ListDescendants(sandbox, maximum_depth, page)
```

Every mutation carries an idempotency key and expected resource version.
Incarnation- or placement-specific mutations also carry the expected
incarnation. Destructive multi-resource changes support plan/apply; ordinary
low-latency sandbox creation remains one idempotent operation with a separate
pure planning call.

Idempotency is scoped to authenticated principal, method, and project. The
service stores a digest of the normalized request with the result; reusing a
key with different input fails rather than returning or starting an unrelated
operation. Accepted operations retain enough result state for clients to
resolve transport ambiguity after reconnect.

The record is retained longer than the maximum operation lifetime plus the
published client retry window. Validation or compare-and-swap rejection before
acceptance does not consume the key; every accepted terminal success or failure
does. A retry rechecks current authority before revealing the stored result but
never repeats effects. If authority was revoked, the response follows the same
concealment rules as an ordinary read of the operation.

Execution control returns an `OpenSshAccessEndpoint` in v1: an OpenSSH route
with a holder-bound short-lived certificate and forced policy. The endpoint
binds execution UID, sandbox incarnation, principal, allowed stream features,
certificate expiry, and audit UID. Host/port/socket routing is ephemeral and never
resource identity. Admission takes a client public key and proof of possession;
the endpoint contains the signed certificate and server identity, never the
client private key. The execution resource remains the source of final exit
status. Forwarding, file transfer, and agent forwarding are independent
feature grants rather than incidental SSH properties. The guest agent's local
control channel is node-internal and is not a second public execution data
plane. A future alternative requires a separately versioned protocol and RFC.

For v1 attach, `client_public_key` is the canonical UTF-8 OpenSSH `ssh-ed25519`
public line without a comment or trailing newline. `proof_of_possession` is an
OpenSSH SSHSIG PEM signature using SHA-256, an empty reserved field, and the
namespace `aos.sandbox.execution.attach-holder-proof.v1`. Its signed message
is the v1 deterministic protobuf encoding of the complete
`ExecutionControlRequest` with only `proof_of_possession` cleared. Unknown
fields in that request or its mutation, duration, and features are rejected;
known fields use ascending field-number order and minimal varints. The
execution ID, optimistic version,
incarnation fence, idempotency key, required features, and exact public key are
therefore signed together. The controller independently authenticates the TLS
peer and authorizes the execution; this signature alone grants no access. A
route can be issued only for the proven key and must still be short-lived.

Attach requests require `aos.sandbox.execution.attach-holder-proof, 1, 0` in
`MutationContext.required_features`; resize and signal requests carry no holder
key or proof. CreateExecution uses the same canonical Ed25519 OpenSSH key and
SSHSIG PEM profile, but signs the complete `CreateExecutionRequest` with only
`proof_of_possession` cleared under the distinct namespace
`aos.sandbox.execution.create-holder-proof.v1`. Its command, sandbox ID,
optimistic mutation fence, required features, and key are bound together;
unknown fields in the request, command, nested environment, timeout, mutation,
or features are rejected. Create requests require
`aos.sandbox.execution.create-holder-proof, 1, 0` in
`MutationContext.required_features`. The controller verifies the proof before
admission, independently of TLS peer authorization. Cache pin and unpin requests require
`aos.sandbox.cache.consumer-pin, 1, 0` so an older peer cannot ignore the
consumer identity and reinterpret them as object-only retention.

Detached `CreateExecution` requests also require
`aos.sandbox.execution.detached-capture-stream-ceilings, 1, 0` in both
`MutationContext.required_features` and `Command.stream_features`. The command
must carry both present `maximum_stdout_bytes` and `maximum_stderr_bytes`; an
explicit zero permits a stream to retain no bytes. Their checked sum must be
positive and equal `detached_capture_bytes`, the aggregate output reservation.
The controller rejects aggregate-only requests and mismatched or overflowing
ceilings. Stream and PTY commands omit both per-stream fields.

Client absolute deadlines are advisory because clocks differ. When accepting
an operation, the server records its own wall timestamp for audit and a bounded
monotonic duration for admission/cancellation behavior. Node sub-deadlines are
durations relative to receipt and can never extend the assignment lease.

Production Create policy binding, execution authorization, opaque capability
handles, and Host readiness also follow the
[authority closure amendment](17-production-authority-closure.md). A valid wire
shape alone does not establish those independent authorities.

## Operations and events

Long-running requests return an operation resource. The operation contains
accepted generation, progress, typed conditions, terminal result, and retry
classification. Transport success means the operation was accepted, not that
all node effects completed.

Watching has two explicit modes. A bootstrap request supplies no cursor: the
server produces bounded snapshot chunks or pages all pinned to watermark `W`,
emits `snapshot_complete(W)`, and only then sends events strictly after `W`.
The client does not apply later events as a complete baseline until it has
every chunk and the completion marker. A resume request supplies the last fully
applied cursor: the server sends only events strictly after that cursor and
does not send a list snapshot.

The cursor is opaque but the server binds it to stream epoch, normalized query
and filters, authenticated principal, authorization scope and revision, and
negotiated observation schema/features. Reuse under a different binding returns
`resync_required` rather than broadening or silently changing the stream.

Each event has an increasing sequence and stable event UID. Delivery is at
least once, so clients deduplicate event UIDs. An expired or unknown cursor,
epoch change, authorization revision that cannot be replayed, compaction, or
slow-consumer eviction returns `resync_required`; the client must perform a new
bootstrap. A server never silently substitutes a current snapshot for a
resume cursor or combines events on opposite sides of different watermarks.

Pagination tokens bind query, authorization scope, and an immutable list
revision. A server that cannot retain that revision fails with
`resync_required`; it never silently mixes pages from different revisions.
Authorization is checked on every page and event. If it narrows, the stream
ends with a non-disclosing authorization-change status rather than emitting
newly concealed resources.

Canceling an RPC deadline does not cancel an accepted operation. An explicit
`CancelOperation` is effective only before the semantic commit point. Progress
uses portable milestones rather than backend step names, and terminal results
distinguish pre-commit failure/cancel from committed desired state with
residual cleanup.

### Protected-domain journal adapters (source-only, inert)

The dormant domain adapters share a canonical reducer envelope and materialized
transaction-member wrapper:

```text
AOSRDP01 | version:u16 | family:u8 | kind:u8 | phase:u8 | reserved:u8 |
companions:u16 | body-length:u32 | sorted-companion-digests |
canonical-body | digest

AOSDTX01 | version:u16 | reserved:u16 | transaction-id[16] |
member-index:u16 | member-count:u16 | set-digest[32] |
envelope-length:u32 | canonical-envelope | member-digest[32]
```

Closed schemas bind record kind, fixed journal namespace, transaction order,
state/publication/effect role, reducer phase, canonical payload bound, replay,
and postcommit capability. Current domain envelopes are hierarchy `AOSHTJ01`,
environment `AOSEPJ01`, Git `AOSGPJ01`, lifecycle `AOSLPJ01`, cache residency
`AOSCRJ01`, policy compilation `AOSPCJ01`, and publisher admission `AOSPAJ01`.
The adapters cannot select arbitrary namespaces or manufacture postcommit
authority. They remain source-only: no production route, backend, publisher,
cache, Git, environment, or lifecycle effect is activated by their presence.

## Errors

Transport status has stable meaning:

| Status | Meaning |
| --- | --- |
| `invalid_argument` | Malformed input or invalid closed-policy value |
| `unauthenticated` | Missing or invalid caller authentication |
| `permission_denied` | Authenticated caller lacks authority |
| `not_found` | Absent or policy-concealed resource |
| `aborted` | Resource-version, generation, or assignment conflict |
| `failed_precondition` | Invalid lifecycle transition or unmet dependency |
| `resource_exhausted` | Quota, reservation, mount, FD, memory, or capacity admission failure |
| `unavailable` | Transient node or backend loss |
| `unimplemented` | Server lacks a requested API feature |
| `internal` | Sanitized unexpected implementation failure |

Typed Connect error details describe field violations, stale versions,
unsatisfied enforcement, quota dimension, required feature, retry advice, and
safe policy diagnostics. Backend-private diagnostics remain in protected node
logs.

Concealed and absent objects have indistinguishable status, safe detail set,
retry hints, and bounded timing behavior. No response says that concealment was
the reason. Quota details reveal only the caller's effective dimension and
limit, never another tenant's use. Error details come from a closed registry;
unknown or backend-private details are not reflected through the public API.

## Coordinator-to-node protocol

The node protocol uses a distinct protobuf package and mutual node identity. An
assignment binds:

- sandbox UID and incarnation;
- assignment epoch and desired generation;
- effective policy and source commitments;
- node capability requirements;
- resource reservations;
- operation deadline; and
- a node-audience authorization proof.

Nodes reconcile desired state and return observations. They never receive the
user's general bearer credential. Every mutation rejects an older assignment
epoch even if its other fields are valid.

The coordinator grants one node mutation authority for an assignment epoch.
Desired updates carry a monotone generation and complete references needed to
reconcile that generation; delivery may repeat or arrive after reconnect. A
node persists its highest accepted epoch/generation before effects and cannot
adopt a lower one after local state loss. Reassignment requires fencing the old
node through the storage/runtime mechanism or proving it cannot mutate shared
state; network reachability loss alone is not proof.

The protocol supports a bounded rolling-upgrade window through feature IDs and
minimum semantic versions. Unknown required features fail the assignment.

Feature IDs come from a checked-in, ownership-namespaced registry. Each entry
defines its semantic version rules, required request/observation fields,
incompatible combinations, and conformance fixture digest. Backends cannot
invent strings that silently widen a known feature. A requirement names an
exact major and permitted minor range; negotiation selects one tested version.

Assignments and updates are ordered by `(assignment epoch, desired generation,
assignment digest)`. The digest covers immutable assignment semantics and
explicitly excludes lease issue time, expiry, nonce, and lease generation. An
exact semantic tuple replay is idempotent. A different assignment digest at
the same epoch/generation is a protocol violation; a lower tuple is rejected.
The node durably records acceptance before effects. Observations carry the
semantic tuple, current lease generation, and a monotone observation sequence
and compare-and-swap the controller's prior observation version. Delayed
reports from an old epoch are retained only as audit evidence and cannot change
current status.

Capability drift during preparation aborts before publication and reports the
observed capability generation. Reconnect starts with an inventory digest and
full desired-state resync before incremental updates. Expiry of an operation
deadline stops new effect admission but does not erase already committed
intent; the operation moves to its defined compensation or residual state.

### Exclusive ownership lease

An epoch number alone cannot fence a partitioned prior owner. Every active
assignment therefore carries an `OwnershipLease` signed directly by a strongly
consistent ownership authority. It contains sandbox UID, incarnation, node
identity, assignment epoch and digest, monotonically increasing lease
generation, authority-issued start/expiry, maximum clock skew, and renewal
nonce. Equal lease generations with different digests fail; a renewal must
increase the lease generation while retaining the same assignment semantics.
A controller signature alone cannot extend ownership time.

On receipt, a node validates the authority signature and converts the remaining
duration into a local `CLOCK_BOOTTIME` fail-stop deadline after subtracting
maximum skew and a fixed safety margin. Host suspend therefore consumes lease
time. The node persists authority expiry, lease generation and digest, and host
boot ID; a different boot ID or unverifiable clock provenance invalidates the
deadline and requires current authority before effects. Renewal advances only
the lease record, not assignment semantics.

Before acknowledging the lease or starting the payload, the host arms the
per-assignment guardian described by the runtime contract. If renewal fails,
the guardian independently closes new admission, default-drops networking,
requests an early freeze, and stops the payload at the local deadline.
Guardian death also stops the systemd-bound payload. This path does not require
the unprivileged node daemon to be live or cooperative. Fixed ingress and
egress host-veth tc-BPF lease gates check the same epoch and
`CLOCK_BOOTTIME` deadline through `bpf_ktime_get_boot_ns()` on every packet, so
expiry is fail-closed even during daemon death or immediately after host
resume.

Every mutable shared storage, cache-publication, Git receive, network lease,
and external service endpoint used during multi-node operation validates the
assignment fencing token. A destination may take ownership only after the old
lease has expired beyond the skew bound and all shared endpoints have accepted
the newer fence, or after an authoritative mechanism proves and records that
the old node/runtime is stopped. Loss of network reachability is not proof.

The single-node implementation still records epochs but does not claim live
reassignment. Multi-node enablement requires the ownership authority and
endpoint fencing tests; the exact consensus implementation is replaceable,
not optional semantics.

The transport-neutral ownership-authority protocol has the exact 1.0 baseline.
`Begin` durably admits one
exact canonical acquire, renew, or same-owner advance claim;
`CompleteOrResume` explicitly drives or resumes the admitted operation; and
`Query` observes the exact request-ID/claim-digest binding. Query reports
`Absent`, `Pending`, or `Completed`; Begin and CompleteOrResume never report
`Absent`. Completed carries the exact ownership lease, lease signature,
transaction receipt, and receipt signature. Replays and recovered completions
are authenticated historical artifacts, not present effect authority.

The distinct `Advance` action compare-and-swaps the exact
prior lease generation and digest while keeping node, sandbox, incarnation,
and assignment epoch unchanged. Desired generation must strictly increase and
assignment digest must change. The resulting signed receipt binds the new
desired generation, and the lease generation must advance. Renewal continues
to require identical assignment semantics, including the receipt-authenticated
desired generation. Admission, post-issuance checks, and historical chain
recovery enforce the same transition rules.

Same-owner advancement does not transfer ownership and need not wait for the
prior lease to expire: the exclusive node remains unchanged. It does not
invalidate old broker grants by itself. Publication, broker fence installation,
guardian update, and effect-time authority checks remain mandatory before
claiming the new generation is observed. Node, incarnation, or epoch changes
require a separate fenced ownership transition; `Advance` cannot authorize
migration or satisfy its endpoint-fencing obligations.

The fixed V1 claim uses action code `3` for advancement. Every receipt action
binds the exact protocol 1.0 baseline, and every 1.0 session admits all three
actions.

Negotiation pins the exact ownership-authority key generation, canonical
method set, request/response bounds, and maximum lease duration. Each client
hello and server selection adds an independent nonzero 32-byte CSPRNG nonce.
The domain-separated SHA-256 transcript over both nonces and every negotiated
field is echoed in requests and responses, so reconnect and authority-epoch
substitution fail correlation checks. The transcript is not authentication:
local transports correlate kernel-nominated credentials with configured
service identity but still require application session authentication, while
remote transports require an authenticated, integrity-protected channel.
Paths, file descriptors, local credentials, and `CLOCK_BOOTTIME` values are
not portable protocol fields.

The authority signs the fixed binary
`OwnershipTransactionReceipt` with its ownership-lease key and trust policy.
The receipt binds protocol version, exact authority key generation, immutable
Acquire/Renew/Advance action, request ID, complete canonical claim digest, and exact
lease descriptor. It deliberately does not bind the observation method or
session transcript, allowing the same durable receipt to be returned by Begin,
CompleteOrResume, and Query. A caller-supplied clock sample can authenticate
artifacts but is not a protected clock capability; privileged effect admission
must independently verify current time and all broker fences.

The ownership journal uses one V1 authority-state schema for transaction
receipts, pending intents, completed responses, and current pointers. Unknown
namespaces, key shapes, magic, versions, and malformed cross-links are corrupt
state rather than alternate formats.

Controller publication uses one V1 format in its own `AuthorityPublication`
journal namespace. V1 retains a permanent prepared
record by publication digest and a sandbox-keyed current pointer whose embedded
sandbox and complete prepared bytes must cross-link exactly. The namespace is
closed: unknown key shapes, malformed or substituted values, missing permanent
records, digest collisions, wrong magic, and non-V1 versions are corruption.

Ownership-gated admission atomically records desired state, the operation,
every planned effect, idempotency, and a self-contained, lease-independent
publication draft. The operation remains `OwnershipPending`; ordinary
reconciliation cannot execute its effects and cannot contact the ownership
authority. Only an explicit resume path may obtain and verify the exact signed
lease and receipt for the gate's canonical claim. The controller uses a local
paired-clock observation to reject artifacts that are not live at publication
time, but that caller-supplied observation is not a sealed clock capability.
Publication and gate release remain non-authorizing: every privileged broker
independently verifies protected current time, assignment authority, and all
fences immediately before an effect. Release atomically publishes the permanent
prepared record and current pointer, changes the operation to `Accepted`, and
records the activated gate. Recovery requires the permanent record and either
that exact current publication or a valid successor. Renewal may change only
the lease-bound artifacts for the same authority and source draft at an
unchanged assignment epoch and desired generation.

The effect ledger writes V2 records for generic and authority-bound effects.
Its fourth header byte remains a closed flags field: zero selects the
byte-exact generic body and `AUTHORITY_BOUND=1` selects the authority body. V2
adds the exact closed broker-method tag after the fixed length fields, and the
tag must belong to the record's fixed domain. The decoder retains V1 records
for recovery compatibility. An authority-bound V1 record recovers its method
from its authenticated binding; an opaque generic V1 record has no such method
and is permanently blocked before executor I/O rather than reinterpreted.
Unknown versions, methods, flags, cross-domain methods, and a record variant
that does not match its operation provenance are corrupt state.

An ownership-gated operation requires an authority-bound record for every
step. Its binding is constructed only from a template in the gate's exact
publication draft; it records and recomputes the source-draft digest, broker
audience and method, template digest, deadline-free request body digest, and
portable semantic-identity commitment. The outer V2 method and bound method
must match. The binding digest also commits the operation ID and ordered step,
preventing valid values from being exchanged between journal keys. Callers
cannot provide those fields independently. The binding currently admits only
descriptor-free Host `ApplyRuntime`; Mount, Storage, Network, Guardian, Guest,
other methods, and every descriptor-bearing template are rejected before
journal admission. Recovery rejects a missing or extra effect, a template
absent from the gate draft, and any substituted body or semantic commitment.

Before the first external broker call, the sole journal-owning reconciler
selects the current publication. It accepts the activated publication or a
valid successor only when the source draft and exact effect template remain
unchanged. It then injects a bounded deadline and durably changes the effect
from `Planned` to `Applying` together with the selected publication digest,
lease generation and digest, the wall-seconds/boottime scalar projection used
for deadline attenuation, the paired host boot ID, exact deadline-bearing body,
and exact encoded authorization packet. Raw clock-source provenance remains
unpersisted advisory input. The boot ID is an exact replay fence: an Applying
attempt must match a fresh executor timing sample before any observation or
Apply I/O. The executor receives that owned recovered attempt and never opens
the controller journal.
After a crash it queries the broker with the byte-exact original Apply request
and signed quartet. Validated `Pending` and indeterminate transport results
retain that exact attempt. Only validated `Absent` permits reselection: the
reconciler consults current authority, constructs a fresh attenuated attempt,
and durably replaces the dispatch record before issuing its Apply. A crash at
that boundary therefore recovers by querying the replacement rather than
replaying an unrecorded request.

The authority-bound variant carries the complete binding and a fixed
dispatch slot. A `Planned` record has no dispatch and requires every byte of
that slot to be zero. `Applying`, `Applied`, and `PermanentlyBlocked` records
require a dispatch with a nonzero preparation Host boot ID in addition to the
selected publication, lease, attenuation scalars, body, and packet. Completed
V1 history remains valid across a reboot because it is receipt history, while
an ambiguous `Applying` V1 attempt must still name the current boot. Generic V1
bytes remain golden-stable in all four states. The authority body and binding
digests use their sole V1 domains.

Each durable dispatch also commits the Effect V1 binding digest. Recovery
reconstructs the selected publication relative to the gate's permanent
activated publication, not relative to whichever publication is current at
query time; a same-draft lease renewal may therefore leave historical attempts
queryable. Current is consulted only for initial selection and validated
`Absent` replacement. A first completion may return any canonical Host
`RuntimeObservation` whose fence and derived runtime handle match the exact
persisted Apply; mutable observation fields are not implied to have been
precommitted by the request. The `Applied` record retains the exact accepted
bytes. Recovery deterministically decodes those stored bytes and rechecks the
same fence and handle invariant. The in-memory validation token is additionally
bound to the effect binding and exact attempt packet, so a valid observation
from another attempt cannot cross the commit boundary. Any substitution that
changes the reconstructed packet, lease, publication, binding, or body fails
before executor I/O. Stored attenuation scalars are rechecked for consistency,
and stored receipt bytes are revalidated for the fence/handle invariant.
Descriptor-bearing attempts remain disabled until a
durable, deterministic FD-reacquisition contract is defined; descriptor
integers are never persisted as capabilities.

The V1 decoder has no predecessor-format or migration branch. It rejects any
non-V1 version before interpreting the body and never treats malformed or
variant-mismatched bytes as historical authority.

The protocol error code is the single source of truth for recovery behavior.
Wrong authority epoch, already-owned acquisition, and stale renewal fences
require refresh and replan; unavailable, deadline, and internal indeterminacy
require an exact query before retry; resource exhaustion awaits an explicit
state transition; integrity failure quarantines; and correctable request or
identity failures do not become automatic retries.

The first service adapter is transport-neutral. It dispatches an already
negotiated and validated envelope onto the protected durable authority. Query
only observes the exact request-ID/claim-digest binding; Begin only commits an
unsigned intent; and CompleteOrResume queries that binding under the same
exclusive authority borrow before contacting the issuer. An absent completion
returns NotFound, a completed transaction replays its exact four artifacts, and
only a still-pending transaction may reach the issuer and protected authority
clock. Journal recovery, Query, and completed replay never contact the issuer;
explicit completion of a recovered pending intent may do so idempotently.

An in-process adapter composes controller and service only when they share one
trusted computing base; it is not a security boundary and conveys no synthetic
peer-authentication token. A Unix carrier must correlate kernel-nominated
credentials with configured service identity, separately authenticate and
authorize its application session, enforce the negotiated frame ceiling before
allocation, and validate hostile request parts before dispatch. A future
authenticated remote carrier supplies its own principal and channel security
to the same semantic handler. Socket paths, credentials, framing, and remote
identity therefore remain outside the portable ownership protocol.

## Record-subject local ingress

Producer-output and publisher admission use a distinct local carrier from the
descriptor-passing broker protocols below. Each accepted record must include
exactly one kernel-checked `SCM_CREDENTIALS` nomination and one correlated
kernel-generated `SCM_PIDFD`; `SCM_RIGHTS` is forbidden. The receiver bounds the complete packet
before allocating its payload. Connection-establisher identity from
`SO_PEERCRED`/`SO_PEERPIDFD` remains separate from the subject nominated for each
record. Neither identity alone proves application provenance or a portable
principal, and forwarded channel-binding bytes are not authentication.

Listener adoption requires Unix `SOCK_SEQPACKET`, listening state, and both
`SO_PASSCRED` and `SO_PASSPIDFD` already enabled. Every accepted child must
independently have both options enabled before any record is read. The adapter
must reject and close an incorrectly configured child, never repair its options
after acceptance. It retains the listener so subsequent correctly configured
connections can proceed. Exclusive socket-configuration ownership is part of
this contract; a duplicate descriptor that changes options breaks that premise.

This reuses systemd socket activation with `Accept=no`, `PassCredentials=yes`,
and `PassPIDFD=yes`, but does not trust configuration text as runtime proof.
[Systemd 259.8](https://github.com/systemd/systemd/blob/v259.8/src/core/socket.c)
applies these options after creating the listening socket and treats failures as
nonfatal. An early queued connection can therefore lack them. Linux 6.18.33's
`net/unix/af_unix.c` copies the listener's credential-receive flags during
`unix_stream_connect`, which also serves sequenced packets, before publishing
the connected peer; acceptance does not refresh those flags. Inspecting the
child closes this setup race without patching systemd. `Accept=yes` is not an
equivalent carrier: systemd can apply options to the accepted child itself, so
current option values would no longer establish inheritance at connection time.
First-party socket creation must enable the options before bind/listen.

The kernel permits credential nominations within the sender's kernel authority;
this is not necessarily the writer's effective UID/GID. A service must map the
retained kernel subject to its protected principal registration, check the
required live service/sandbox identity, and bind the actual session before
evaluating release or publication policy. Numeric PIDs, persisted inode numbers,
and supplied principal IDs cannot reconstruct that authority after restart.
Authenticated remote carriers must establish equivalent semantic principal and
channel bindings through their own authentication, not serialize local pidfds.

Local cgroup scope uses a retained, filesystem-validated cgroup-v2 directory,
not an arbitrary directory whose inode happens to match a reported number.
The supported 64-bit profile preserves the complete kernfs cgroup identifier.
Fresh opens of the fixed `cgroup.procs` file observe active kernfs state;
directory link counts do not establish it. Exact service membership compares
fresh PIDFD information with the retained directory. Descendant membership
resolves a bounded, untrusted relative hint beneath that anchor with
`RESOLVE_BENEATH`, `RESOLVE_NO_XDEV`, `RESOLVE_NO_SYMLINKS`, and
`RESOLVE_NO_MAGICLINKS`, then matches the resolved candidate's complete ID to
the PIDFD. The hint only locates a candidate. It neither authenticates a subject
nor causes a numeric PID to be reopened. Cgroup-v2's no-reparent rule preserves
the retained candidate's ancestry; a same-filesystem bind-mount graft is still
rejected by `NO_XDEV`. Repeated active and membership observations remain
snapshots, not a lock against privileged migration or a later effect.

The first producer session must be provisioned by the controller for an explicit
holder/capability/project/sandbox/incarnation/assignment tuple and a retained
payload-cgroup anchor. Neither shifted UID allocation nor host/guest UID zero
selects that principal. A fresh, unpredictable, role-separated channel binding
belongs to the controller's live session table, and each record must independently
match the provisioned cgroup scope. The publisher uses its separate configured
service principal and a fresh registered execution identity. Restart discards
live session authority; durable challenge records cannot resurrect sockets,
cgroup anchors, or publisher instances. This provisioning and principal/session
table remain implementation requirements, not properties granted by the Linux
observation types.

## Node-local broker protocols

Privileged brokers listen only on protected Unix `SOCK_SEQPACKET` sockets. The
protocol has:

- a handshake that selects one exact local version and advertised closed
  operation/feature set before privileged requests;
- one bounded message per packet;
- a closed operation tag;
- request ID, operation digest, sandbox UID, incarnation, assignment epoch,
  desired generation, assignment/plan digests, ownership lease generation and
  digest, and payload namespace generation;
- an exact FD-role table matching SCM_RIGHTS ancillary descriptors;
- maximum body and FD counts checked before allocation; and
- peer-credential and service-unit verification.

Host and mount brokers pin the connection establisher using `SO_PEERPIDFD`
rather than reopening the numeric PID reported by `SO_PEERCRED`. Verification
reads fresh cgroup and liveness information through that retained descriptor.
The legacy channel is delegable: this authenticates its establisher, not every
later writer. A dead or unresolvable accepted peer is a per-connection rejection,
not a fatal listener error. Publisher/producer record-subject admission must not
reuse this connection-only proof as holder authentication.

The protocol passes real descriptors or broker-minted handles. It never
serializes descriptor integers as reusable references. Extra, missing,
duplicated, wrong-type, writable, or unexpectedly mounted descriptors are
rejected.

### Storage workspace root-pin repair

Storage root-pin repair is a resource-targeted Storage 1.0 operation. Its
public node-local request carries only the canonical repair request and the
standard signed plan, plan signature, ownership lease, and lease signature.
The caller does not supply a dataset name or GUID, creation catalog, attempt
ordinal, mount observation, host scope, or root-pin proof. Those values come
only from authenticated retained Storage state and freshly inspected
descriptors. Exact replay of an already durable repair is observation-only and
must be resolved before starting a new pre-admission observation.

Before committing a new repair, the broker selects one of two authenticated
predecessor shapes. `ExistingAttempt` binds the exact globally latest workspace
attempt, which must be an Ensure, and its optional predecessor repair intent.
`MissingInitial` instead requires an active committed `CreateWorkspace` or
`Clone` with no workspace-pin attempt. Ordinary committed same-handle history
does not substitute for or make the creation ambiguous.

The broker then sends a distinct non-authorizing version-2 `AOSZRPA1` request to
the fixed observer. Version 2 is a hard cut and its probe uses a distinct v2
domain. It binds a fresh challenge; the prospective repair request, assignment,
and workspace identities; the exact creation operation, result catalog and
digest; the creation publication and canonical catalog; the dataset GUID and
root policy; the physical catalog head; and either authenticated latest-attempt
bytes or an empty value for `MissingInitial`. The optional predecessor repair
intent is separately authenticated. The observer independently authenticates
the records it receives after entering the retained mount namespace and returns
the exact dataset with an absent root pin in `AOSZRPS1`. A validated payload is
not admission authority: the broker may consume it only after authenticating
the observer process, proving natural child exit, and proving complete service-
cgroup quiescence.

The broker then reopens the raw request and signed artifacts under a fresh
protected clock while holding the sole Storage journal lock. It authenticates
the exact committed creation and publication, current physical catalog head,
current assignment and plan, ownership, node, lease, and Clone source identity;
rechecks the predecessor shape and exact absence observation; and performs the
final before-effect check. Admission atomically replaces the sandbox current
fence and writes the Pending Effect, operation fence, immutable repair intent,
and new Ambiguous Ensure attempt. Capacity for the later atomic completion must
be reserved before this five-record transaction commits. No mutating provider
action occurs before this authenticated durable admission. Once committed, the
repair authorization is consumed: uncertain admission returns
`ReopenRequired`, and restart can observe but cannot reissue its worker
authority.

The mutating worker accepts only the repair-specific `AOSZRPW1` envelope. It
independently authenticates the Pending repair Effect, equal current and
operation fences, repair intent, attempt receipt, committed creation result,
creation publication, and canonical creation catalog. An ordinal-one Ensure is
valid only when the tagged repair intent proves `MissingInitial`; an
`ExistingAttempt` repair is exactly adjacent to its predecessor and therefore
has ordinal two or greater. The worker binds the attempt root policy to both the
portable publication and catalog root policies. For Clone it additionally
binds the exact source dataset, snapshot, version handle, active hold, and
source root policy. It proves the exact destination dataset and an absent pin
before mutation, checks the protected current fence and clock immediately
before and after its durable exactly-once claim, materializes only the fixed
handle-derived pin, and returns exact postcondition evidence.

Successful completion is one two-record journal transaction: the attempt
becomes Satisfied with its observed pin proof and the live Effect becomes
Complete with a deterministic receipt bound to the attempt's stable authority
digest. Exact transaction readback is mandatory. Reopen accepts only the phase
pairs Ambiguous/Pending and Satisfied/Complete, and a Complete record must carry
the exact deterministic receipt. A one-sided transition or an otherwise valid
Complete Effect with an arbitrary receipt is corruption or authority failure.

Post-commit recovery continues to use the non-authorizing
`AOSZRPO1`/`AOSZRPR1` observer protocol. Exact presence may finish the same
two-record completion; exact absence remains `AwaitFreshRepair` without a
journal write. Recovery never converts that observer envelope into fresh
mutation authority.

Host-broker protocol 1.0 defines a generic request-envelope carrier for the
exact canonical broker plan, detached plan signature, ownership lease, and
detached lease signature. Host negotiates the carrier with
`aos.sandbox.authorization.signed-plan-lease, 1, 0` and requires it on effect
methods. Observation and inventory methods reject the carrier. Every Host
request uses exact protocol 1.0; unknown minor or major versions fail closed.

Mount instead uses exact protocol 2.0. Version 2.0 is a preproduction hard cut:
1.0 peers and persisted source-path recipes are not migration inputs, and 2.1
or any other unknown version fails closed. Mount negotiates the same
signed-plan/lease feature and requires the carrier on every effect method,
while its observation and inventory methods reject the carrier. CREATE and its
catalog preparation additionally require
`aos.sandbox.mount.source-acquisition, 1, 0`; production does not advertise
that capability until an authenticated provider protocol is installed.
Existing-resource INSTALL, REPLACE, DETACH, inventory, and catalog preparation
remain available without source acquisition, and RELEASE remains catalogless.
Fresh source admission additionally requires authoritative PID 1 confirmation
that the canonical realization-handle name owns the exact source descriptor.
The systemd 259 `sd_notify` processing barrier is not that confirmation: it
does not expose an exact post-mutation descriptor-store snapshot. A backend
limited to that interface must report fresh store and present-name removal as
unconfirmed, must not publish `Active` or `Released` from its local bookkeeping,
and may complete `Reaping` only when a complete subsequent socket-activation
inventory proves the name absent. Until a manager-query backend can provide
exact positive and negative evidence, production CREATE remains closed and an
acknowledged removal can remain durably `Reaping` across the running service.
The transport validator applies
independent and aggregate byte limits, fully decodes each canonical object, and
preserves the received bytes exactly; that structural validation grants no
authority. Trust anchors, public keys, trusted clock samples, revocation state,
and node-local records never cross in the request. The same portable artifact
quartet can later be placed in a distinct authenticated remote wrapper, but the
local `SOCK_SEQPACKET` framing, peer credentials, and descriptor table are not
a remote protocol.

SourceProvider protocol 1.0 is an independent exact local process protocol
between RootMount and a protected source authority. It does not change Mount
protocol 2.0. Its canonical `AOSSPV01` outer frame fixes `Hello`, `Acquire`,
`Release`, and `Inventory` methods; the sole required signed-lease-receipts
feature; and the sole `SourceRoot` descriptor role. Unknown versions, methods,
features, roles, proof classes, flags, reserved bytes, trailing bytes, and
oversized records fail closed. The typed decoder binds method, request/response
phase, signed status envelope, signed body kind, and descriptor contract rather than
returning an arbitrary frame body. Inventory is capped at 2,048 sorted entries,
and the decoder checks the complete fixed entry area before allocation.
Signed subjects use the repository-unique `AOSSPX01` envelope magic, exact
format version 1, closed purpose and method codes, four zero reserved header
bytes, the exact 120-byte signer reference with seven zero reserved bytes, a
bounded big-endian subject length, canonical subject bytes, and one 64-byte
Ed25519 signature. Purpose codes 1 through 7 are export lease, Acquire receipt,
Release receipt, Inventory snapshot, RootMount operation request, endpoint
hello, and provider response status respectively. Purposes 1 through 4 use a
zero method byte; hello and operation records bind their exact closed method.
The unrelated sandbox-spec state magic `AOSSPS01` is never
accepted as a SourceProvider signed envelope.

Before any operation, RootMount sends a signed client hello with a nonzero
32-byte nonce, its boot and process instance, its exact query key,
the exact expected provider receipt key and protected route, and its requested
capabilities. The provider returns a signed server hello with an independent
nonzero nonce, boot/process/key/route, the digest of the complete signed client
hello, and advertised capabilities. Advertised capabilities must be a subset
of both the client request and protected route/trust policy. A session binding
commits the complete signed hello envelopes. Strict verification of both
signatures, exact configured keys and route, expected client nonce, common boot,
capabilities, and shape-checked supplied confinement fields constructs the
verified signed Stage 2A session model; an unsigned hello grants no session.
Those public confinement fields do not establish kernel provenance. A future
branded adapter must supply that evidence from retained kernel objects, and
production integration must freshly generate each nonce from process-exclusive
CSPRNG state.
Every operation re-verifies both stored signed hellos against current RootMount
and provider trust, requires the complete supplied route snapshot - including
resource namespace - to equal current protected routing, and binds
both hello boot IDs to the current verification boot. Rekey, authority-state or
route replacement, and a new boot invalidate the session before any status is
accepted or nested result is interpreted.

Acquire requests contain that nonzero session binding, an exact expected
client-to-provider sequence, exact canonical logical-binding bytes and digest and
the complete deadline-free canonical Mount `AOSMSEM1` field envelope. For the
Mount source-acquisition feature this is specifically the pre-catalog Create
template: exact fields 1 through 27, Create action, canonical empty field 13,
and every other field final. Ordinary final Create semantics still require a
nonzero verified catalog commitment. Before final Create admission, Mount must
reproduce the pre-catalog template by projecting only final field 13 back to
empty; accepting an arbitrary structurally decodable `AOSMSEM1` envelope is not
sufficient. The
prospective template digest is SHA-256 over
`aos-source-provider-prospective-mount-template-v1\0 || AOSMSEM1-bytes`; the
SourceProvider decoder checks exact fields 1 through 27, magic, and format
version, while RootMount remains responsible for producing Mount-canonical
field values. Request digests are SHA-256 over a separate request domain, the
closed method code, body length, and canonical request body. Provider
idempotency is scoped by `(holder signing authority/key, method, request-id)`;
reusing an ID across methods is a distinct operation because the method is in
both the digest and signature. Requests never contain a provider endpoint,
pathname, descriptor integer, verification key, protected route, or
caller-selected provider identity.

Acquire success carries exactly one `SourceRoot` descriptor by `SCM_RIGHTS`;
an exact completed replay may redeliver that same realized selection. Every
other result, every request, Release, and Inventory carries zero descriptors.
The generic carrier supplies a kernel-authorized nominated record subject, not
proof of the actual writer: a privileged sender may nominate another subject
within its kernel authority. Safe use additionally requires a strict signature
under protected trust, fixed UID/GID/TGID/start-time/cgroup, pidfd liveness,
hello/process-instance continuity, and capability confinement to the selected
protected route. Stage 2A shape-checks supplied connection-peer and nominated-
subject fields for equality and accepts modeled provider-process confinement
fields as verification inputs. It does not establish their kernel provenance or
install the kernel observation or routing backend. Provider ingress must apply
the same signed transcript and independently establish RootMount connection
peer/record-subject/pidfd/cgroup continuity before executing a request; that
production adapter is also unavailable in Stage 2A.

Protected trust pins signer authority ID/generation/digest, exact Ed25519 key
and fingerprint, signature use, active key generation and revocation state,
proof-class set, provider route, and minimum catalog/resource/selection
generations. At the exact resource-floor generation, protected trust also pins
the complete 32-byte resource ID and resource-state digest; different identity
or equal-generation equivocation fails closed. Verification uses strict Ed25519
verification and rejects weak keys. The provider chooses a concrete resource only inside the protected
route's resource namespace; selection generation/digest commits that routing
decision independently of resource and catalog generations. Resource IDs are
exactly 32 bytes. The provider resource commitment is SHA-256 over its versioned
domain followed by resource-namespace digest, resource ID/generation/digest,
selection generation/digest, and complete proof digest. The current `AOSMSA02` maps
that value into the Stage-1 `provider_resource_digest` input before Mount mints
the realization handle; neither caller nor provider chooses that handle.

Every Acquire, Release, and Inventory disposition, including `Pending`,
`Rejected`, and `Unavailable`, is carried in a provider-signed outer status.
It binds the method, request ID, digest of the complete signed request envelope,
status, provider process instance, session binding, exact provider-to-client
sequence, and commitment to the exact nested-result bytes and descriptor set.
Transport close is not an authoritative `Unavailable`. A completed Acquire
descriptor commitment covers the `SourceRoot` role and the supplied modeled
boot/device/inode/unique-mount-ID/`O_PATH`/directory/read-only observation;
the future branded adapter must derive those fields from the received
descriptor. All zero-descriptor statuses commit the canonical empty set. Request and
response sequences are verified against caller-supplied exact expected values,
and opaque verified sequencing evidence is returned for external monotonic
state advancement. A production integration must atomically compare-and-swap
and durably consume both direction-local sequence values before using a returned
descriptor; returning opaque evidence does not itself advance replay state.
Client and server nonces must come from process-exclusive CSPRNG state with
freshness preserved across restart and fork. Reuse across a session, restart,
boot, method, key, request, nonce, or sequence therefore fails closed.

Provider receipts bind stable authority, key, catalog, resource, and selection
generations and digests separately from the ephemeral provider process
instance. The signed lease digest commits the exact signed lease envelope,
including signer reference and signature, not only its unsigned subject. The
closed proof union explicitly carries ZFS storage/version handles, dataset and
snapshot GUIDs and hold state; local assignment/owner/incarnation/export,
consumer, workspace, revocation, lease and kernel grant; immutable
tree/view/publication/catalog/cache/disclosure/materialization/fs-verity and
writer closure; or best-effort reconstructibility/replica/cutoff/checkpoint,
lag/access/degraded state. Every class has an orthogonal bounded recursive
topology/count authority. When covered by the verified signed lease, these are
authenticated provider claims; the raw proof model and codec do not establish
backend truth. Hello, protected trust, route, request,
and proof capabilities must intersect, observed topology may not exceed the
request, and kernel-coupled live exports require an explicit request and route.
Topology counts include the root: submount count cannot exceed entries minus
one, depth cannot exceed either entries or submounts plus one, and depth is
nonzero. A local-live proof's consumer authority and generation must equal the
signed request and lease holder.

Composite Acquire verification requires the verified signed Stage 2A session and outer
status before interpreting any disposition. It requires `issued <= now < expires`, expiry no
later than the Acquire deadline or current ownership bound, and nonzero duration
no greater than the requested duration or 86,400 seconds. It checks every
request/holder/revocation/boot/process/provider/resource/selection/proof and
descriptor-observation cross-link before returning an opaque verified result.
The provider receipt, supplied modeled descriptor observation, signed request,
and caller-supplied current context must name one boot. Production must source
that context from protected state. The kernel adapter must establish
that `SourceRoot` is an actual read-only directory opened with `O_PATH`; an
ordinary directory descriptor is rejected. Stage 2A models this observation but
does not implement that kernel adapter. Public scalar observation constructors
validate shape only; the future adapter must issue non-forgeable, adapter-branded
evidence derived from the received descriptor before production integration.
Release and Inventory have equivalent signed, holder-scoped composite entry
points and never transfer descriptors.

Mount 2.0 predeclares the additive
`aos.sandbox.mount.source-acquisition,1.0` profile. It contains exactly three
methods: numeric tags 22 `MOUNT_ACQUIRE_SOURCE`, 23
`MOUNT_RELEASE_SOURCE_ACQUISITION`, and 24
`MOUNT_INVENTORY_SOURCE_ACQUISITIONS`. Acquire and Release are effects and use
the exact signed-plan/ownership-lease carrier; Inventory is an observation and
rejects authorization. All three directions carry zero controller-to-Mount or
Mount-to-controller descriptors. The provider `SourceRoot` terminates at Mount
and PID 1 custody; it is never returned to or nominated by the controller.

Advertisement is feature-conditioned as well as feature-gated. A Mount server
must strip all three methods from the effective server hello unless the client
hello required the exact source-acquisition feature. If the feature is
required and negotiated, the server must advertise all three methods. A client
rejects any server hello that advertises one of the methods without the feature
or only a partial method group. This preserves exact-2.0 legacy clients, which
validate every server-advertised method rather than only their required subset.

`AcquireMountSourceRequest` has exact fields: header 1, assignment fence 2,
pre-catalog template bytes and digest 3 and 4, canonical logical binding bytes
and digest 5 and 6, requested lease seconds 7, requested maximum submounts 8,
and kernel-coupled flag 9. It accepts no provider identity, route, key,
acquisition ID, revocation state, node, boot, holder, session, provider request
ID, or sequence from the controller. Mount derives recursive authority from
the canonical attributes; the six Boolean attribute bytes are closed, no-suid
and no-device are true, read-only is equivalent to immutable mutation class,
and kernel-coupled is equivalent to local-live consistency. A nonrecursive
request has a zero maximum-submount count. The outer Mount request ID is the
Acquire operation identity and is distinct from the later Create request ID.
Live admission and durable recovery use one time-independent exact decoder for
the canonical Acquire body, NodeController header shape, logical binding, and
all 27 pre-catalog Create fields; live peer authentication and deadline
currentness remain additional admission gates. Provider proof class must equal
the binding consistency mapping: immutable revision to ImmutableTree, local
live to LocalLive, and best-effort replica to BestEffortReplica.

New LocalLive acquisition requires the version-2 logical source binding. It
extends the exact View/source/incarnation tuple with the digest of a separately
authenticated current assignment for the source sandbox; the destination
assignment cannot stand in for that source authority. The same digest is bound
through the Mount request semantics, durable source recipe, inventory, and
provider export proof. The provider must independently establish the current
storage export and kernel grant before supplying a physical source. Version-1
LocalLive records remain decodable for historical inventory and teardown, but
cannot authorize a new Acquire or Present. The logical assignment binding alone
does not establish a physical export or enable a provider backend.

`ReleaseMountSourceAcquisitionRequest` has header 1, assignment fence 2,
acquisition ID 3, expected revision 4, and expected record digest 5. The caller
cannot replace provider or lease identity. Release must remain in the same
sandbox/incarnation lineage under current or dominating teardown authority.
An equal assignment epoch and desired generation requires the exact Acquire
assignment digest; a higher desired generation dominates only within the same
epoch; and a higher epoch dominates with its own nonzero generation and
digest. A lower epoch never dominates, even with a larger desired generation.
Mount durably retains and canonically reproduces the exact Release body,
teardown fence, acquisition ID, operation/request identity, and predecessor
revision/record-digest CAS. Release response correlation applies this same
dominance relation to the immutable Acquire assignment projected by the row.
`InventoryMountSourceAcquisitionsRequest` contains only header 1. Acquire and
Release each return one shared acquisition record; Inventory returns kernel
boot ID 1, journal sequence 2, at most 1,024 acquisition-ID-sorted records 3,
and broker process instance 4. Records retain exact Acquire and optional
Release correlations, assignment, provider route/authority/key/resource,
catalog and selection generations and digests, lease/proof/descriptor and
physical-source commitments, disposition digests, release/inventory evidence,
fault origin, revision, phase, and corruption-detecting record digest. They are
an authenticated public projection of the durable row, not a raw provider
envelope or a claim that scalar kernel fields prove provenance.

Mount mints
`SHA256("aos.sandbox.mount.source-acquisition-id.v1\0" ||
acquire-operation-id[16] || SHA256(exact Mount Acquire body))` as the 32-byte
acquisition ID. Namespace 40's normal decoder accepts only canonical
`AOSMSA02`, version 2, with five closed record families:

- acquisition:
  `"aos.mount.source-acquisition.v2\0" || acquisition-id[32]`, digest domain
  `"aos.sandbox.mount.source-acquisition-record.v2\0"`;
- provider head:
  `"aos.mount.source-provider-head.v2\0" || holder-id[16] || provider-id[16]`,
  digest domain `"aos.sandbox.mount.source-provider-head-record.v2\0"`;
- holder sequence:
  `"aos.mount.source-holder-sequence.v2\0" || holder-id[16]`, digest domain
  `"aos.sandbox.mount.source-holder-sequence-record.v2\0"`;
- immutable provider session:
  `"aos.mount.source-provider-session.v2\0" || session-id[32]`, digest domain
  `"aos.sandbox.mount.source-provider-session-record.v2\0"`; and
- immutable provider query attempt:
  `"aos.mount.source-provider-query-attempt.v2\0" || attempt-id[32]`, digest
  domain `"aos.sandbox.mount.source-provider-query-attempt-record.v2\0"`.

Each canonical JSON value, including its envelope and hex-encoded retained
bytes, is bounded at four MiB; the complete materialized graph is bounded at
512 MiB before cloning or allocation. A version-1 key is never recognized by
the normal decoder. `AOSMSA01` remains available only to the explicit, pure,
bounded hard-cut migration planner. That planner validates the complete legacy
graph and requires a complete supplemental `AOSMSA02` provenance graph for
four-key trust, executions, normalized intents, floors, attempts, and holder
sequences. Retained legacy authority that cannot supply those facts returns
`NeedsProvenance`; no ordinary open, implicit upgrade, installer, or authority
is created by the migration decoder.

The acquisition row retains the closed lifecycle `PendingQuery`,
`DescriptorCustodied`, `Active`,
`Consumed`, `Releasing`, `Released`, and `Faulted`. A first PendingQuery is
durable before provider I/O and binds exact Mount request and semantic identity,
plan and lease digests, pre-catalog template and binding bytes/digests,
protected holder/node/boot/route/trust/session snapshots, signed provider
request bytes, and sequence reservation. Each stable holder/provider pair also
has a provider-head control row; holder-sequence rows make acquisition identity
nonreuse explicit, immutable session rows retain the authenticated execution
and trust transcript, and immutable query-attempt rows own each signed request,
sequence reservation, outcome, and recovery state. The provider head owns the
current session and direction heads, one pending attempt, and the stable
inventory and catalog floor. The client-to-provider sequence is reserved
atomically before I/O; a verified signed disposition consumes the attempt
reservation and advances the response head atomically with its acquisition row
or inventory reconciliation. Multiple acquisition rows never infer or share a
sequence by scanning lifecycle state. A Complete inventory's exact signed
bytes are retained by its attempt while the stable floor retains the correlated
disposition commitment without duplicating the large result.
The head also advances a checked durable inventory-observation ordinal for
every newly consumed Complete response, including a fresh authenticated query
whose provider generation and stable content equal the preceding floor. Exact
redelivery of an already committed checkpoint does not advance the ordinal.
The canonical maximum SourceProvider inventory therefore remains below the
four-MiB AOSMSA02 value ceiling. Reconciliation commits that one provider-head
record and its aggregate residual/conflict result; it does not rewrite every
matching acquisition row in the same transaction. When a terminal inventory
later authorizes manager-confirmed release, that row records the exact current
floor digest and observation ordinal in its own bounded lifecycle transaction.
Release admission captures the preceding observation ordinal, so an omission
or exact Released entry must come from a strictly later Complete Inventory;
an older floor cannot prove terminality. Thus maximum-cardinality reconciliation
never scales one journal transaction with retained row history. Before the
Inventory reservation is committed, Mount preflights that reservation followed
by one maximum four-MiB provider-head replacement against the exclusively held
journal's transaction, file, and materialized-state limits. Production wiring
must preserve that exclusive no-unmodeled-commit interval through completion.

Transport close records no provider outcome and leaves the exact reservation
ambiguous. Signed Pending, Rejected, and Unavailable dispositions consume their
sequences and retain exact bytes without inventing Complete. Bounded retry
history preserves those dispositions before a new sequence is reserved. Exact
controller replay returns the current row or tombstone; request-ID reuse with
different body or authority is equivocation. Exact provider response redelivery
is a no-write replay, while a different response at a consumed sequence fails
closed. Session replacement cannot erase an outstanding reservation or rewrite
a PendingQuery into a new session. Such an attempt must first be resolved or
faulted; retry after fault requires a new controller operation and acquisition
ID. Stable inventory floors survive permitted session, boot, route, and key
replacement. The stable route ID and resource-namespace digest may not change
through ordinary session replacement; changing either scope requires a
distinct authenticated migration contract and old-head tombstone, which Stage
2B does not yet expose.

For Complete Acquire, Mount first verifies and adapter-brands the received
descriptor, then atomically records the complete signed graph and sequence CAS
while the phase remains PendingQuery. It may attempt PID 1 handoff only after
that commit. `DescriptorCustodied` requires an authoritative handoff
acknowledgement and remains unusable. `Active` requires authoritative positive
PID 1 readback; neither a local mutex nor `BARRIER=1` is evidence. Mount maps
only the SourceProvider resource/proof commitment into the existing AOSMSP01
`provider_resource_digest`, maps provider proof classes explicitly rather than
by numeric cast, and mints the realization handle. `Active` becomes `Consumed`
only in one transaction with the exact AOSMSP01 activation and one final Create
effect/operation admission whose field-13 projection equals the prospective
template. AOSMSP01 itself is not folded into or silently changed by AOSMSA02.

Release retains the original signed lease and derives its provider request from
the row and current protected session. It retains that release-time protected
holder/route/authority/key/session snapshot separately from immutable Acquire
evidence, so authenticated cleanup survives provider rekey and restart without
accepting an old-key response. `Releasing` and the exact signed request are
durable before provider I/O. `Released` requires either an exact signed
terminal release receipt or reconciled terminal inventory plus authoritative
negative PID 1 custody evidence. Complete-but-not-yet-custodied and custodied
failures remain eligible for cleanup. Released is terminal. Faulted retains its
source phase and sanitized failure commitment; it cannot erase preceding
provider, descriptor, or custody evidence.

Signed provider inventory currentness is durable per stable holder/provider
pair. Lower generation is rollback; equal generation with changed canonical
inventory, provider/key/route/catalog tuple, or entries is equivocation; equal
stable content under a fresh authenticated query legitimately consumes the new
request/response sequences and advances the observation ordinal; higher
generation advances atomically with full reconciliation. Stored residual and
conflict booleans are diagnostics for the row projection at observation time,
not current authority after later row mutations. Consumers recompute the exact
current reconciliation from the retained signed floor and current rows.
Unknown provider leases are untracked residuals and are never adopted. Missing
locally Active or Consumed leases, a nonterminal reappearance of a Released
local tombstone, and resource/proof changes are authority conflicts recorded
without wedging the authenticated response reservation. Releasing/Reaping
remains pending; a post-Release omission or exact matching Released entry may
establish provider terminality but cannot substitute for manager-negative
custody.

On reopen, canonical validation method-decodes every retained Complete provider
result. It reproduces Acquire lease/resource/proof/physical-realization
evidence, Release lease/provider/generation evidence, and the complete
Inventory request/result/floor graph. Recovery also rechecks global operation-ID
and session-sequence uniqueness, direction-head reachability,
provider-history partial ordering, and bidirectional pending-owner integrity
before exposing any row.

Controller inventory currentness follows the same fail-closed observation
rules as other Mount inventories: exact query/response bytes and complete
controller-state commitment, current boot/process pairing, monotonic journal
sequence, identical bytes at an equal sequence, unique query ID, live-row boot
agreement, physical-alias exclusion, and equal-generation anti-equivocation
across provider route/authority/key/resource/catalog/selection facts. This is a
kernel-nominated, broker-returned observation, not authenticated broker-writer
proof. Production consumption requires `SBX-BPROTO-05` session authentication,
MAC/confinement, protected key custody, and branded kernel evidence.

This Stage 2B contract remains deliberately inert. The dormant fixed-root
composition performs authenticated SourceProvider session establishment,
durable-before-I/O Acquire and Release reservation, exact response and
descriptor verification, postcommit readback recovery, and cold recovery of a
durably pending provider attempt without rebuilding or redispatching its
request. A fixed Mount-manager control session drives fresh descriptor handoff,
positive presence readback, Release removal, negative absence readback, and the
exact transition to Released. Fresh Release authority is derived only from
retained or startup-recovered SourceRoot custody, and every precommit or
ambiguous postcommit path retains its move-only retry evidence. No production
feature advertisement, listener, provider route registration, controller
Create enablement, or readiness change is installed. SourceProvider 1.0 and
AOSMSP01 retain their exact wire and durable formats.

### SourceProvider ledger and Mount-manager startup state (source-only, inert)

Namespace 41's current canonical SourceProvider owner format is `AOSSPL01`,
version 4. It has exactly seven closed bodies: authority head, catalog head,
current holder-session head, immutable session history, provider attempt,
provider acquisition, and release lineage. Fixed per-artifact ceilings, a
bounded record count, and a 512-MiB aggregate recovered-graph ceiling apply
before graph allocation. Version 4 durably binds the protected response
completion time into terminal attempts. A normal open rejects older records
before materializing the graph; they are not alternate accepted wire shapes.

The separate pure legacy migration planner first validates the complete,
sorted canonical version-2 graph and requires externally authenticated
supplemental projections for every identity, sequence, trust-history, and floor
fact that version 2 omitted, plus a complete canonical current-format
replacement graph. The security layer authenticates the fixed
`AOSSPMG1` manifest against the exact current namespace-41 snapshot plus current
trust, revocation, catalog, and protected-configuration heads. The provider
layer then applies the whole replacement under one snapshot/CAS boundary and
returns an opaque recovery token if append durability is ambiguous. This is an
offline migration path, not an in-place upgrade, listener, provider backend, or
advertised production feature.

Namespace 45 stores one monotone `AOSMMSTA1` Mount-manager startup-policy head
and immutable `AOSMMCAP1` per-execution captures. Its purpose-limited protected
authority may read namespace 40 acquisition state, namespace 39 SourcePin
state, namespace 2 Mount resource lifecycle, and namespace 45 itself, and may
append exactly one capture. It cannot mutate source lifecycle or grant general
journal authority.

Namespace 46 stores global capacity reservations for only two closed purposes:
`PublisherCompletion`, whose owner is namespace 7 and whose allowed companion
records are namespaces 6, 3, and 46, and `RuntimeExecution`, whose owner is
namespace 3 and whose only companion namespace is 46. Each admission reserves
exact successful-terminal and poison-terminal record and byte budgets in the
same transaction; settlement consumes that reservation in the terminal
transaction. This is neither generic cross-namespace capacity authority nor
SourceProvider's internal `AOSSPL01` capacity accounting.

Namespace 62 is reserved for a Storage-owned, protected retained-execution-output
ledger. Its records bind the exact accepted Create, execution, assignment, v2
output-claim record digest, and admitted bytes. A zero-byte stream still has a
record. Authenticated deletion leaves a tombstone and releases only the logical
ledger charge. Storage accepts only the runtime execution owner's v2-only
protected accepted-Create readback witness; a caller-supplied legacy claim and
currentness pair cannot enter this ledger. This ledger does not attest physical
capture backing or authorize Host Apply: the capture dataset, live ZFS
quota/reservation observation, and cross-owner currentness barrier remain
required before production use.

For nonzero capture, the Storage backing contract selects one dedicated direct
child named `aos-output-<execution-id-hex>` beneath a configured managed root.
The physical catalog must retain the exact creating Storage operation, dataset
GUID, domains, and `refquota` plus `reservation` both equal to an allocation at
least as large as the admitted capture ceiling. The allocation includes a
protected, measured metadata allowance. The dataset has no clone origin,
descendants, or snapshots, and the capture writer has exclusive access to its
mounted content. The Storage ledger binds this verified dataset before capture.
Logical release requires an authenticated later catalog tombstone for that
same name, GUID, and deleting Storage operation; it retains the original
dataset binding, name, GUID, and creation generation so a restart between ZFS
destroy and logical settlement can recheck the later tombstone. It also retains
the distinct authorized execution Delete operation, Storage Destroy operation,
and deletion catalog head on replay. ZFS reservations are not
sufficient while a pool checkpoint can consume them, so admission must also
prove that condition absent at the effect barrier. These are requirements for
future service wiring, not authority supplied by the current dormant producer.

### Linux connection-bound record origins (source-only)

The sequence-packet carrier now privately retains each connected endpoint's
nonzero Linux `SO_COOKIE` and stamps that already-retained binding into a record
only after its payload, nominated credentials, pidfd, and optional descriptor
table are completely received and validated. Legacy receive performs no new
socket query and retains its existing error taxonomy and syscall behavior. A
socket-owned binding operation then consumes the record, queries the live
endpoint cookie, and requires both that observation and the private origin to
name the exact retained socket object. A duplicate descriptor for the same
socket is accepted; the opposite endpoint and an independent connection are
rejected. Any binding error or mismatch closes the receiving socket and drops
the complete record and every transferred descriptor.

The public connection-bound wrappers have no arbitrary constructor or rebinding
operation. They own the record while borrowing the exact retained connection
peer, so mutable I/O through that socket owner cannot compete until the wrapper
or its preserved peer borrow is released. Legacy receive, payload, subject,
descriptor, and consuming `into_parts` APIs remain available and unchanged.
Binding failures use a separate nonconstructible, non-exhaustive error whose
closed/current-socket/origin categories and text disclose no cookie, descriptor,
kernel error, or peer. The existing public socket-cookie observation also
remains non-authorizing.
Neither the private origin nor the wrapper proves the syscall writer,
authenticates an application or channel, equates the nominated record subject
with the connection establisher, or authorizes use of a transferred descriptor.

This is an additive source foundation only. No Host, Storage, Mount, Network,
controller, or service call site consumes the wrapper, and no protocol, wire,
feature advertisement, readiness, journal, Nix, or deployment behavior changes.
Production use still requires the authenticated broker-session composite,
protected route/key custody, exact subject/peer/process/cgroup continuity,
descriptor-role semantics, atomic owner transactions, and enforcing MAC and
delegated-writer confinement. `SBX-BPROTO-04`, `SBX-BPROTO-05`, and
`SBX-P0-10` remain open.

### Broker Session Authentication 1.0 source foundations (inert)

The exact client-required feature is
`aos.sandbox.authentication.broker-session,1.0`. It has no alias and is never
selected opportunistically. The generic unauthenticated broker-session API
rejects it even when locally advertised. No Host, Storage, Mount, Network, or
controller production path advertises or requires it. Four additive bytes
fields reserve the carrier without changing a protocol or method version:
ClientHello field 7, BrokerHello field 8, request field 5, and response field 7.
Legacy decoders reject every nonempty carrier; empty legacy encodings remain
byte-identical.

The source-only `aos-sandbox-broker-session-protocol` crate defines exact
`AOSBSA01 || u16be(1) || purpose || method || reserved[4]=0 || signer[120] ||
u32be(subject length) || subject || Ed25519 signature[64]` artifacts. The signer
is authority ID 16, authority generation `u64be`, authority digest 32, key ID
16, key generation `u64be`, SHA-256 of the raw public key 32, key use, and seven
zero reserved bytes. Sentinel values, unknown codes, weak keys, trailing or
noncanonical bytes, and failed strict verification are rejected. Pairwise
distinct signer references, key IDs, and physical keys are ordered
ClientHello=1, BrokerHello=2, ClientRecord=3, BrokerOutcome=4. The signer-set
digest commits the four exact references in that order.

ClientHello's 150-byte subject commits node/boot IDs, broker code (Host=1,
Storage=2, Mount=3, Network=4), exact version/audience, client process, nonce,
protected-context digest, and cleared ClientHello digest. BrokerHello's
182-byte subject adds the analogous broker process/nonce and complete signed
ClientHello digest while committing the same protected-context digest.
ClientRecord's 104-byte subject commits session binding, client process,
C-to-B sequence, request ID, and cleared request digest. BrokerOutcome's
136-byte subject commits session binding, broker process, B-to-C sequence,
request ID, complete signed request digest, and cleared response digest. Total
artifact sizes are 354, 386, 308, and 340 bytes. Hello method is zero; request
and outcome use the same exact existing BrokerMethod.

Independent terminal-NUL domains cover all four signatures, cleared protobuf
projections, complete signed hello/request links, signer set, protected
context, and session binding; variable bytes are `u32be` length-prefixed.
Projection clears only the containing auth field and requires the received
protobuf to equal canonical re-encoding with that field restored, closing
unknown, reordered, duplicate, non-minimal, and trailing fields. Request
projection commits body, ordered
contiguous descriptor `(index,role)` entries, and all authorization-quartet
bytes/presence. Outcome projection commits request ID/method/body, ordered
response descriptors, complete BrokerError including exact missing-feature
triple, and ordered dispositions. It adds no sender-claimed kernel-object
digest; actual SCM identity remains future receiver-derived branded evidence.

Authenticated negotiation accepts only Host/Storage/Network 1.0 and Mount
2.0. The client-required and broker-advertised feature sets each contain exact
Broker Session Authentication 1.0 once, the required sets are subsets of the
advertised sets, and methods remain canonical, protocol/role scoped, and
feature-conditioned under the existing broker rules. BrokerHello cannot carry
an error. Response ceilings are 4,096 through 15 MiB and the broker cannot
exceed the client offer; BrokerHello's nonzero request ceiling cannot exceed
the protocol maximum. The transcript retains the exact protocol/version,
audience, required and advertised features/methods, and both negotiated packet
ceilings. No received feature, digest, or signer reference selects local trust.

Nonces are nonzero and unequal, all identity/protocol/process continuity is
exact, BrokerHello cross-links the complete ClientHello, and session binding
commits both complete artifacts client-first. The verified transcript stays
Provisional until a valid sequence-1 ClientRecord proves possession of the
separate traffic key. Shape-only local context pins route/domain/protocol/
version/audience/node/boot, both processes, all four references/raw keys, and
caller-supplied trust/route/revocation/currentness floors. Its independent
digest commits that entire fixed context plus the ordered signer-set digest;
both hellos sign it. All four keys must be active at handshake, and every
request/outcome classification, including exact replay, first recomputes and
compares the currently supplied context before selecting the role key. A
change, revocation, or supersession therefore invalidates live traffic. The
context is shape/crypto input only and explicitly proves neither protected
provenance nor authority.

Traffic is direction-local nonzero `u64` stop-and-wait starting at one. Exact
replay of only the retained outstanding/latest-completed record yields
no-write evidence; it is not unbounded history. The latest completed request
and byte-identical complete response remain replayable while the next request
is outstanding, and each response is checked against its own retained bound.
A response with an unchanged signed carrier but changed body, error,
descriptor table, disposition table, or outer request ID is equivocation, not
exact replay. `u64::MAX` is reserved for exhaustion, making `u64::MAX - 1` the
last admissible sequence. Changed equal sequence/request ID is equivocation.
Gaps, rollback, a second outstanding request, and cross-session/protocol/route/
method/direction transplant fail closed. Every
authenticated success/error is a signed outcome. Pre-auth malformed input may
close silently; transport close is not signed Unavailable. Pure verification
does not persist or advance authority. A method outside the retained negotiated
protocol set, or missing its client-required traffic feature, fails before
replay classification.

Authenticated response total is 15 MiB (15,728,640), cleared maximum
15,728,297. Existing 65,536-byte hello totals leave cleared maxima 65,179 and
65,147. Ordinary/Host-query/Mount-PrepareCatalog totals are
1,048,576/1,048,640/1,081,408 and leave cleared maxima
1,048,265/1,048,329/1,081,097. Auth carrier contributions are respectively
357, 389, 311, and 343 bytes. Raw requests are capped at the largest legal
total before protobuf allocation and then at the method-specific and signed
negotiated ceiling. Each request's response ceiling must be at least 4,096 and
no greater than the negotiated response ceiling; responses are raw-bounded
before decode by the minimum of that request bound, the negotiated bound, and
15 MiB. Where both the latest completed record and a new outstanding request
exist, the receive adapter may preallocate only through the greater applicable
retained bound, then must identify the authenticated target and apply that
record's own bound before semantic use.

The dormant all-method adapter performs canonical traffic admission and complete
established request/outcome semantic validation for the closed 22-method
profile: seven Host methods, eight Mount methods, four Storage methods, and
three Network methods. It uses the existing method decoders, method-separated
semantic commitments, required catalog bindings, exact header/request/budget
cross-links, descriptor-role tables, errors, dispositions, and both endpoint
directions. The adopted-socket owner derives method-specific bindings and
descriptor cardinality from the protected request and received `SCM_RIGHTS`,
durably reserves the request, issues a move-only domain handoff, records the
exact domain observation, commits the signed terminal outcome, and only then
sends it. Host, Storage, Mount, and Network implementations cover every closed
method, including observation and inventory. Ambiguous transport, effect, and
commit boundaries retain exact recovery custody and never authorize blind
redispatch.

`AOSBSD01` is the method-neutral durable record for that complete profile. A
request record and its terminal successor bind the endpoint, revision and
predecessor, session and peer, protected context/publication/catalog, request
ID, direction-local sequences, response ceiling, method profile, request and
outcome semantics, fixed companions, and byte-exact signed packets. Bounded
`AOSBSH01` full histories retain every canonical revision, enforce a gap-free
CAS chain and exact request-to-terminal progression, and preserve the sole
current head instead of accepting a caller-selected checkpoint. These formats
are journal-neutral and allocate no namespace or write authority.

The sealed recovery layer accepts history only through the protected
namespace-47 `AOSBSJ01` owner, sandwiches derivation or reopen with another
protected read, replays every retained signature and method semantic through
the traffic machine, and alone mints move-only resend or outstanding-outcome
state. Public dormant all-role custody internally selects fixed controller
client or Host/Storage/Mount/Network broker endpoint roots, the fixed
`session.journal` basename, role-owned protected opening, and closed replay limits.
Broker journals remain root-owned; client journals use the pinned service
execution's UID so the unprivileged controller can own its state. Both paths
retain strict root-to-owner ancestor, no-symlink, exact-mode, and exact-owner
checks, and reopen reuses the captured owner after endpoint revalidation. Raw
endpoint loaders, journal openers, paths, basenames, and limits are not public
authority inputs.
Only completion of the adopted-socket handshake opens the protected journal.
The resulting co-owner supplies its retained transcript and live socket peer to
every initialization, replay, commit, recovery, and effect-handoff operation;
there is no public raw journal owner plus detached peer path. It creates no
listener, route, dispatcher, or background task, so production use remains dormant.

The same fixed custody can instead consume an already-connected ordinary
sequenced-packet socket and enter the existing three-flight protected handshake.
One explicit call advances one bounded flight or returns the complete state for
retry. Completion opens the matching fixed journal and co-owns it with the
socket, verified transcript, and retained kernel peer; narrow methods on that
co-owned object are the only authority path. No descriptor-subject carrier is exported.

The version-2 protected journal record stores a stable endpoint identity derived
from protocol, role, and protected manifest separately from the process-specific
endpoint publication. Reopen validates the stable identity across process
restart. A fresh authenticated initial request may replace only a terminal
old-process history under an exact generation/head/publication CAS; ambiguous
replacement retains its exact recovery target, while nonterminal old-process
state fails closed for operator reconciliation. This preserves current-session
anti-replay without making every prior process identity permanently unopenable.

The dormant FUSE operations adapter separately owns one fixed root-owned
`registrations.journal` in namespace 50. Its canonical record commits the exact
connection and reducer bindings, registration bytes and digest, monotone
generation, and predecessor head/digest. OPEN/CLOSE broker admission and final
worker cleanup consume one-shot exact-readback tokens that retain the fixed
owner borrow. A rejected OPEN exposes only an opaque close-pending holder; its
operation and selector become available solely through a fresh token minted
after exact readback of the resulting `Closing` snapshot. Ambiguous protected
CAS is reopened against its retained exact target before any such token exists,
while an ambiguous broker effect consumes the token and faults the connection
instead of authorizing a duplicate close. No caller-implementable byte store
can mint these tokens.

The broker-side gate admits new or byte-exact replay requests for all 22 closed
methods. It derives actual descriptor identity and method bindings at receive,
commits the authorized request before effect, and seals the domain observation
before terminal signing. Host catalog publication additionally retains the
request, descriptor, intended digest, byte count, and generation across an
ambiguous rename/fsync boundary; fixed-root fsync and double readback classify
the publication as exact, absent, or conflicting before terminalization or a
safe retry. No generic caller-built success can bypass the domain handoff.

Descriptor-bearing Host scope outcomes add a protected post-CAS receipt
boundary. The Host authority, rather than the scope caller, pins the sole
BrokerOutcome verifier from `broker-outcome-verifier-v1` in its protected
credential directory. That file is a root-owned, single-link, mode-0400 regular
file retained and repeatedly revalidated through its original descriptor. Its
canonical `AOSBROKEROUTV001` record is exactly 160 bytes:

```text
magic[16] = "AOSBROKEROUTV001" ||
authority-id[16] || authority-generation:u64be || authority-digest[32] ||
key-id[16] || key-generation:u64be || public-key-digest[32] ||
broker-outcome-ed25519-public-key[32]
```

The signer reference must select BrokerOutcome use, every identifier,
generation, and digest must be nonzero, the public-key digest must match the
raw strong Ed25519 key, and the credential must remain byte- and
metadata-identical. A missing credential disables these dormant Host scope
paths. A caller cannot substitute a verifier through the Host call surface.
Before a live physical scope operation, the authenticated BSA endpoint's
protected BrokerOutcome verifier commitment must equal this fixed Host pin.

After the exact signed terminal outcome is durably committed and read back,
the BSA owner signs a terminal-commit receipt with that protected
BrokerOutcome key. The receipt binds the Host reservation locator, method,
request ID, complete signed-request digest, session binding, domain-separated
digest of the complete signed outcome artifact, committed journal generation,
and committed history head. The signing API consumes or borrows the opaque
committed advancement or protected replay evidence; it does not accept those
fields as a caller-built binding. Host verifies the receipt against its fixed
pin before converting the reservation into a finalized replay record. Only
then may the already-committed response and its inseparable descriptor bundle
enter transport.

The Host replay index authenticates both stages. A reservation records the
request, authorization artifacts, peer/policy, boot, response digest, and fixed
verifier commitment with zero terminal fields. Its finalized successor adds
the exact predecessor reservation locator, signed-outcome digest, protected
generation, and protected head. The predecessor locator must recompute from
the successor after clearing those terminal fields. If atomic rename persisted
the successor but directory fsync reported failure, recovery reloads protected
Host state and accepts only one authenticated successor whose predecessor and
receipt match exactly. That classification performs no physical scope effect,
does not reopen or replace the BSA-held descriptor bundle, and does not write
the already-finalized record again. An absent, conflicting, multiply matching,
or unauthenticated successor retains recovery custody and fails closed.

These source paths include complete dormant effect and inventory dispatch, but
add no listener, service registration, production advertisement/readiness,
orchestration, Nix, or VM activation. Request reservation, effect handoff,
protected observation, signed-outcome commit, and send remain explicitly
ordered. Reconnect or session replacement cannot erase or renumber outstanding
or indeterminate effects: the protected journal resolves or replays exact
custody first. Allocation is capped before protobuf decode, and the full body,
error, descriptor, and disposition contract validates before any outcome head
advances.

The initial specialized source-only layer composes this cryptographic state
with the complete existing Network 1.0 `InventoryResources` semantics in
`aos-sandbox-protocol::authenticated_session`. Its opaque state can be created
only from canonical mutual hellos and exact provisional transcript
verification. Raw receive bounds come from that state. Request admission
requires the exact body-derived request ID, deadline, response ceiling,
Network version/audience, empty authorization quartet, empty signed descriptor
table, and zero actual descriptors before a candidate state exists. Outcome
admission correlates the retained request and validates the complete success
inventory or closed BrokerError plus exact empty descriptor/disposition
contract before exposing a candidate next state. A signed but semantically
invalid outcome therefore cannot consume its sequence; a corrected outcome at
the same sequence remains admissible. Exact latest-record replay and the
retained N/N+1 bound behavior remain those of the pure cryptographic state.
Authenticated traffic and the protected retained request classify an exact
outstanding or latest-completed replay before live request semantics and
deadline freshness run. Exact replay therefore remains valid at and after its
original deadline, but only for the byte-identical retained request and its
protected in-flight recovery or terminal response. Fresh protected-context,
peer-policy, kernel-execution, journal-head, generation, and outcome checks
still apply. Only `New` traffic enters live semantic and deadline admission.
Inventory need only be in the broker's signed advertised/negotiated method set;
it is not required to be in the client's required-method subset.

The retained Network request evidence is deliberately non-authorizing. It
contains the exact canonical envelope packet, exact signed and semantically
validated nested body bytes, independently domain-separated packet digest,
session binding, request ID, response bound, deadline, sequence, complete
signed ClientRecord bytes/digest, and the exact empty role table. The nested
Network protobuf is not independently canonical-reencoded. The
correlated outcome retains that complete request evidence, its own canonical
packet/digest, complete signed BrokerOutcome bytes, sequence, and either the
fully validated inventory or error. The Network inventory request defines no
portable semantic, catalog, effect, or durable-owner digest, so none is
fabricated. These records neither open/commit a journal nor install a catalog.
Private staged Network service/controller seams use the real kernel record
subject carriers and existing execution rechecks both before semantic admission
and immediately before catalog/snapshot observation, but are unreachable from
`serve_once` and `ResourceInventoryClient::query`.

This remains production-inert. Host and Mount authenticated receive/allocation,
protected key loaders and CSPRNG integration, Linux authority/provenance,
caller-owned atomic companions, every service/controller production branch,
MAC policy, readiness, Nix, and VM qualification remain open under
`SBX-BPROTO-04`, `SBX-BPROTO-05`, and `SBX-P0-10`.

### Broker-session protected manifest, custody, and entropy foundation (inert)

The source-only `aos-sandbox-broker-session-security` crate defines one exact
protected configuration format without activating Broker Session
Authentication. `AOSBSC01` is exactly 920 bytes: its fixed 184-byte prefix
contains version 1, closed broker protocol and protobuf audience codes, the
exact Host/Storage/Network 1.0 or Mount 2.0 version, domain and route IDs,
route/trust/revocation generations and digests, and node ID. Four ordered
184-byte pins then name ClientHello, BrokerHello, ClientRecord, and
BrokerOutcome. Each pin contains the exact 120-byte signer reference, raw
Ed25519 public key, nonzero authority/key generation floors, closed revoked
and superseded-presence bytes, six zero reserved bytes, and the optional
strictly advancing superseding key generation. The decoder rejects wrong
lengths, trailing bytes, sentinels, unknown codes, weak or mismatched keys,
role reordering, repeated signer/key/physical-key identities, inconsistent
floors, and noncanonical currentness. The non-authorizing manifest binding is
`SHA-256("aos-sandbox-broker-session-manifest-v1\0" || u32be(920) || exact
manifest)`.

A client directory has fixed `broker-session-manifest`,
`client-hello-signing-key`, and `client-record-signing-key` names; a broker
directory analogously has broker-hello and broker-outcome keys. Secret files
are exactly `stable-key-id[16] || Ed25519-seed[32]`. The loader captures its
effective UID, PID, and current kernel boot ID rather than accepting identity
scalars. It retains no-follow descriptors for the exact-mode owner-only
directory and three exact-mode, single-link regular files; reads them
positionally between metadata snapshots; holds a nonblocking exclusive flock
on the manifest; and rejects either known opposite-role secret name by
metadata lookup without opening its contents. Local seeds must reproduce the
matching manifest IDs, raw public keys, and fingerprints, and all four pins
must be active when either role loads.

Before opening protected configuration, the custody loader opens one pidfd for
itself and retains it for the object's lifetime. A capture sandwiches complete
pidfd information and pidfd-bound procfs identity between boot ID, current PID,
effective UID, and effective GID observations. It requires a live thread-group
leader, nonzero cgroup-v2 ID, stable start-time ticks, all eight credential IDs,
and exact agreement among the scalar, pidfd, and identity views. Revalidation
repeats that observation through the retained pidfd and compares every baseline
field except PPID; PPID may change between calls but must remain stable within
each observation. After capture the guard never creates or replaces its retained
pidfd from the numeric PID. The pidfd-bound identity helper opens numeric
`/proc/PID/stat` only inside the retained-pidfd information and liveness
sandwich.

Every protected custody-object output revalidates both the retained descriptors
and a fresh opening of the captured absolute path before and after producing the
value, with retained-self execution checks bracketing each file revalidation.
Path-bound device/inode/security metadata, complete file contents, the manifest
digest, opposite-role absence, and the retained execution baseline must remain
exact. Any in-place edit, chmod/chown/link/truncation, child or directory
replacement, execution change, entropy failure, or nonce exhaustion permanently
poisons the endpoint; restoring bytes does not revive it. Rotation is whole-directory
publication followed by process restart. Errors and Debug output expose only
stable redacted labels.

Role-specific, non-cloneable custody objects expose only a revalidated
manifest binding, an opaque random nonzero process-execution ID, and an opaque
role-specific fresh hello nonce. They expose no seed, signing key, descriptor,
generic signer, raw-sign callback, caller-selected UID/RNG, peer process
scalar, full verification context, or session binding. Process IDs and nonces
come directly from blocking `getrandom(2)` with empty flags, exact partial-fill
handling, at most eight interrupted-call retries, a hard zero-progress rule,
and at most eight complete all-zero retries. Each nonce privately retains the
process ID, manifest binding, and checked nonzero issuance counter.
Purpose-specific ClientHello and BrokerHello finalizers consume those private
values. They are reachable only through the fixed-role adopted-socket handshake
owner; no finalizer, nonce bytes, process bytes, key, generic signer, or outbound
signature API is independently public.

Host, Storage, Mount, Network, and controller production registration does not
consume this foundation. The dormant source composition implements the complete
closed-method authenticated exchange: protected request reservation, exact
descriptor count and semantic bindings, move-only domain dispatch, signed
terminal outcomes, ordered replay, and ambiguity recovery for every broker
status. Fixed controller and Host/Storage/Mount/Network roots own the
`AOSBSJ01` namespace-47 sessions. Real fork continuation, cgroup/procfs
mutation, cross-process flock contention, cross-UID ownership, MAC policy,
listener registration, readiness, and Nix activation are separate `SBX-P0-10`
deployment gates; this source contract grants no production descriptor-use
permit.

### Broker endpoint publication and sealed hello flights (source-only, inert)

The protocol crate additionally freezes the untrusted broker-only `AOSBSE01`
publication as exactly 64 bytes: magic `AOSBSE01`, `u16be(1)`, role Broker=2,
five zero reserved bytes, nonzero broker process-execution ID 16, and nonzero
manifest binding 32. There is no client form, extension, signature, boot ID,
nonce, descriptor, protocol, or audience field. Exact 63/64/65-byte bounds,
every closed header byte, both sentinels, and trailing bytes are tested.
Decoded values are explicitly untrusted: the binding must equal current local
protected configuration and the process value becomes meaningful only when the
later signed BrokerHello repeats it.

ClientHello verification now has an explicit pure stage boundary. A broker
first compares the received signer reference with its locally pinned active
ClientHello key and performs strict Ed25519 verification. Only the resulting
authenticated client process value may populate that dynamic field in a full
locally constructed context; route, domain, trust, revocation, protocol,
audience, node, boot, and all four keys/currentness states remain local. Full
context and hello semantics then run, and the existing pair verifier delegates
through those same checks. The signed subjects, artifacts, protected-context
digest, session binding, protobuf carriers, and golden vectors are unchanged.

The security crate contains a sealed typestate for exactly three flights on one
retained sequenced-packet endpoint: broker publication, ClientHello, and
BrokerHello. A public dormant owner can adopt an already-connected ordinary
socket from any fixed controller-client or service-broker role and drive one
bounded flight per explicit call. It creates no listener, route, service, or
background task. Both ordinary and internal descriptor-subject carriers
immediately consume and socket-bind each received record; the descriptor form
requires exactly zero transferred descriptors. The state retains the
connection peer and each record's independent nominated subject, including
pidfd-backed PID/TGID/start-time/cgroup/full-credential/liveness evidence.
Each capture and transition recheck uses `info-before -> process identity ->
info-after -> final liveness`, requires the two complete information snapshots
equal (and the carrier's initial snapshot equal at capture), and therefore
closes PPID or credential drift inside one observation. PPID alone is omitted
from the retained cross-transition comparison; all other fields remain exact.
Publication and BrokerHello broker subjects must name the same execution, while
the ClientHello subject is retained for a future ClientRecord comparison. This
does not equate peer and nominated subject, identify the actual writer, or
grant channel authority under descriptor delegation.

Only the role-local hello key and one fresh role-local nonce can finalize each
hello. BrokerHello also commits the exact signed ClientHello. Protected files
and retained-self execution are checked around finalization, send, receive,
and verification; retained peer/subject pidfds are rechecked at each transition.
Prepared exact packets remain state-owned across nonblocking retry and are not
re-signed or re-nonced. Invalid, duplicate, reordered, cross-channel, partial,
or descriptor-bearing flights close the private handshake; local custody
failure poisons custody. Completion retains the verified transcript inside a
non-extractable wrapper with the same adopted socket and fixed protected
journal; a scoped callback is the only access to that co-owned state.

The initial sealed bootstrap path requires the first traffic exchange to
be Network 1.0 `InventoryResources`, NodeController, ClientRecord sequence 1,
with no authorization quartet or descriptors. The protected client creates the
request ID from blocking kernel entropy, selects an exclusive `CLOCK_BOOTTIME`
deadline, signs only with the ClientRecord key, and locally admits the exact
packet before its first send. The broker authenticates and semantically admits
the same socket-bound record before any outcome exists. A first-seen expired
request is retained only by the purpose-specific sealed traffic-proof seam and
can produce only the fixed retryable `DeadlineExpired` outcome. The ordinary
public authenticated Network admission remains fail-closed with
`DeadlineExpired`; malformed or unauthenticated input produces no signed
oracle. Fresh work may produce a fully validated inventory, fixed
`ResourceExhausted`, or fixed unavailable-integrity outcome. Each outcome is
signed only with the BrokerOutcome key and locally admitted before send.
The request's response ceiling covers the complete authenticated packet; the
cleared response encoder reserves the exact 343-byte BrokerOutcome field, and
packet attachment rechecks that the resulting total does not exceed the
retained ceiling. An otherwise-valid success that exceeds this cleared budget
deterministically becomes the fixed bounded `ResourceExhausted` outcome.
Either a valid success or closed signed error completes the private traffic
proof with both sequence heads at 2, no outstanding request, and the latest
complete pair retained. Retry keeps the exact packet, signature, request ID,
deadline, and candidate state. Exact replay does not re-expire, while changed
equal sequence or request ID remains equivocation.

There is deliberately no public constructor, carrier trait, socket extractor,
raw process/nonce/context/session accessor, generic signer, or production
entrypoint. The private peer expectation has only a test constructor and never
derives policy from received credentials. Protected peer/MAC policy,
delegated-writer confinement, production receive allocation and resend, durable
atomic companions, all service/controller wiring, readiness, Nix, and VM
qualification remain open. `SBX-BPROTO-04`, `SBX-BPROTO-05`, and `SBX-P0-10`
stay unchecked.

Host protocol 1.0 includes `QueryRuntimeEffect`. The query carries a fresh
1.0 header, zero descriptors, the same exact signed authorization quartet, and
the byte-exact original protocol 1.0 `ApplyRuntimeRequest`; its outer request
ID must equal the embedded Apply request ID. Apply's portable signed semantic
authorization is also exact protocol 1.0. The
query returns `Absent`, `Pending`, or
`Complete`, with `Complete` carrying the byte-exact durable response receipt.
The Host-query packet ceiling is 64 bytes above the generic ceiling, which is
greater than the maximum protobuf growth from the additional query header and
nested-body framing. Packets in the additive band must decode specifically as
`QueryRuntimeEffect`; every other method retains the generic ceiling. Query
responses reject unknown status values and fields;
`Absent` and `Pending` require an empty receipt, while `Complete` requires a
bounded, structurally valid `RuntimeObservation` whose fence exactly matches
the original Apply.
The broker revalidates the original request digest, semantic authorization,
assignment fence, and authority artifacts against durable state. Existing
effects are checked at their authenticated admission clock only to establish
historical identity, never to grant new authority; an absent request must still
be live at the current protected clock. The operation is strictly read-only:
it does not admit or refresh a fence, write state, resolve a catalog handle, or
invoke a worker.

Host 1.0 also defines `ObservePayloadScope`, a live authority-bearing query
with zero request descriptors. Its exact signed plan must already grant the
query semantic operation for the installed runtime; the complete admitted
plan/lease fence must equal the installed durable fence. Unlike effect receipt
queries, this operation always checks current protected time and requires live
launch-retained payload pins. It never installs a newer lease or advances
durable state. A receipt alone is never authority to reconstruct kernel pins
after restart. For a Guardian-backed runtime, before accepting either retained
or rebuilt volatile pins, the Host requires the unique authenticated
completed-Launch lineage for the current sandbox incarnation and assignment
epoch, including its exact saved Guardian binding, both service-manager
invocation identities, and durable runtime proof, followed by a fresh live
proof that matches every saved manager and kernel identity. Completed Freeze
and Thaw successors in that same epoch preserve the lineage while permitting
desired-generation and assignment-digest advancement. A pending transition,
Stop or Kill history, replacement epoch or incarnation, missing or ambiguous
launch, or any proof mismatch fails closed without starting, stopping, or
adopting a process.

A successful response echoes the exact assignment fence and runtime handle,
adds a nonzero process-local opaque scope handle, and transfers exactly two
descriptors in order: the retained payload leader pidfd and the retained
payload-subtree cgroup `O_PATH` descriptor. Bodies are bounded at 8 KiB and the
raw leader-cgroup hint at 4 KiB. The hint is only an empty exact-membership or
strict descendant locator; it is not membership proof. Error responses carry
no descriptors. Live admission checks the absolute query deadline before the
Host effect. The Host then transfers the exact prepared descriptor bundle into
opaque BSA custody before signed-outcome preparation/reservation, terminal CAS,
Host receipt finalization, or transport; errors and ambiguity at those later
boundaries retain that same inseparable bundle rather than reconstructing or
substituting descriptors. Protected endpoint, journal-head, peer, and kernel
evidence are revalidated around the later steps, but the live deadline is not
renewed or reinterpreted immediately before send. A protected byte-exact
terminal replay deliberately does not reapply that historical live deadline.
It instead revalidates the fixed verifier, terminal head and receipt, current
boot and fence, and fresh physical scope readback before reopening the exact
role-ordered descriptors for the retained signed response.

The controller checks the kernel-authorized nominated subject of the hello
response against trusted host-service credentials and a retained service cgroup.
Subsequent response records must nominate that same live execution. This SCM
metadata does not prove the actual syscall writer. Application-authenticated
signed session/results plus deployment MAC and capability confinement remain a
required behavioral integration. Listener creator credentials alone do not
authenticate the responder under socket activation. The controller validates
descriptor roles, pidfd liveness, cgroup-v2 identity, and leader membership
using the received objects. Payload PID-1, root, and namespace verification
remain validated Host observations, not facts inferred from descriptor types.
This observation does not itself grant
holder mapping, current assignment authority, or permission to deliver a local
channel; those remain separate controller admission requirements.

The controller records observed runtime executions and signed namespace targets
in separate protected journal namespaces. The first live observation for an
incarnation seeds its target from the current signed assignment manifest. A
later observed generation allocates a target advanced by the same positive
delta. Each immutable target record names the exact runtime-generation audit
digest, and each per-incarnation head names the latest observed generation,
target, and allocation digest. Replay validates both complete bounded histories
and their cross-references before controller effects.

Allocation is not authority. When a new observed execution still has an older
signed target, the controller returns only a copyable advancement proposal. The
caller must publish an authorized assignment successor, reacquire and retrack
the live Host proof, and bind it again. Only exact agreement between the current
signed manifest, current runtime-generation head, current allocation head, and
retained live proof yields a `CurrentNamespaceTarget`. Restart cannot recreate
that value, and it does not by itself prove attachment replay or readiness.
The proposal includes the non-authorizing opaque payload-scope handle so the
successor Host plan can grant that exact retained execution; it contains no
descriptor, lease, or reconstructed kernel authority.

Host 1.0 includes `ObserveMountScope` for the privileged Mount broker. This keeps
payload root and namespace descriptors out of the node controller. The Host
accepts the method only from a root peer in the fixed Mount service cgroup;
that peer cannot negotiate controller methods. The controller query and its
two-descriptor response remain unchanged.

The request binds the assignment, deterministic runtime handle, and exact
opaque payload-scope handle. A distinct canonical argument commitment binds
the RootMount audience and five response roles. The installed signed Host
plan must already grant this exact query, and the supplied plan/lease fence
must equal the installed fence. Querying cannot install or renew authority.
A replacement payload scope, including after reboot, requires new authority
for its new handle; the query cannot silently select the replacement.
Controller verification and Host admission require the signed plan, query
header, and negotiated carrier to use exact Host protocol 1.0.

Success transfers the payload pidfd, payload-subtree cgroup, root directory,
mount namespace, and user namespace in that order. Errors transfer none.
The Mount client checks the Host response's kernel-nominated subject and retains
that subject with the payload descriptors; SCM metadata does not prove the
actual syscall writer. Application-authenticated signed session/results and
deployment MAC/capability confinement remain required. It checks exact response bindings,
descriptor types, live membership, and deadlines. These observations do not
authorize a mount effect or continuously prove the payload's root/namespace
selection: Mount admission and the worker's exact-resource checks remain
mandatory before use.

Host 1.0 requires a separately signed Guardian plan on every live
`Launch`. The deadline-free Host dispatch template must not contain that plan.
Only after selecting the current ownership lease and sampling the current host
boot may the controller derive the fixed Guardian arm commitment and request a
signature. The Guardian plan must use Guardian 1.0, name the exact Host
assignment, node, and ownership signer, and contain only the assignment-target
`GuardianArm` grant covering the 160-byte boot-and-lease binding with zero
actual descriptors. The controller reselects current publication state after
signing, so a lease renewal or publication change during that interval cannot
silently enter the attempt.

The live `ApplyRuntimeRequest` carries only the exact canonical Guardian plan
and detached signature in its launch-only companion. The enclosing Host
authorization quartet supplies the one exact ownership lease and signature;
the companion cannot duplicate or replace them. Its Host deadline must remain
positive and no later than both the conservative lease deadline and the
Guardian plan expiry projected onto `CLOCK_BOOTTIME`, with one whole wall-clock
tick reserved for the Guardian's sample ordering. The expanded Host body is
matched again against the Host grant and the complete encoded packet remains
bounded before it becomes durable.

The companion is forbidden in templates and non-Launch actions. A live Host
1.0 Launch without it is invalid. Unknown Host versions are rejected rather
than decoded as compatibility formats. Structural companion decoding does not
establish trust: the Host and Guardian execution paths still perform their
protected signature, lease, clock, descriptor, and before-effect checks.

The controller exposes Guardian-plan preparation as a narrow executor hook
whose input is already bound to the selected lease and boot. The default hook
returns no plan, so Host Launch remains disabled unless a concrete trusted
signing adapter is installed. The hook starts no units and performs no external
effect; the exact composite attempt must be committed first. A validated
`Absent` result repeats current selection, Guardian signing, validation, and
durable replacement before a new Apply. Transport ambiguity or `Pending` never
authorizes construction of a different packet.

Mount-broker protocol 2.0 includes `PrepareMountCatalog`. The node controller
sends no descriptors and no outer Mount authorization. Its bounded
body contains a complete prospective `ApplyMountRequest` plus a complete
authorized Host 1.0 `ObserveMountScope` envelope. The outer request, prospective
Apply, and Host query must use the same request ID, deadline, and assignment
fence; the Host query remains separately bound to the RootMount audience,
runtime handle, and opaque payload-scope handle. A release action cannot be
sent to `PrepareMountCatalog` because it requires no catalog resolution. The
controller prepares release locally from the current namespace target and still
requires its exact catalogless semantics in a separately signed Mount plan.

Mount performs the Host exchange itself and retains the returned scope in a
bounded, memory-only registry. For the exact assignment and namespace
generation, refresh may replace an observation only when its runtime, scope
handle, root, mount namespace, and user namespace are unchanged. A different
scope requires a new namespace generation. Restart loses this registry, so
reconciliation repeats preparation before replay rather than reconstructing
descriptor authority from journal metadata.

The protected file catalog still selects the immutable source and destination
slot. Mount resolves the destination beneath the Host-supplied root and requires
its device/inode identity to equal the separately pinned root-owned catalog
slot. The resulting commitment binds the catalog generation, complete Mount
tuple, Host runtime and scope handles, kernel identities, and relative slot.
The response returns only that nonzero digest and the exclusive Host-query
BOOTTIME deadline. Preparation writes no durable fence, allocates no mount
resource, invokes no helper, and performs no namespace mutation. The controller
places the returned digest in the portable semantics for a separately signed
Mount Apply grant. It verifies that plan under the pinned controller trust
anchor, current assignment and ownership authority, and retains the live
namespace target beside the deadline-free Apply template. Apply still resolves
and rechecks the same live scope and catalog facts before effect.

The controller accepts only a fence-free prospective Mount body: callers cannot
supply its assignment, namespace generation, request identity, or deadline. It
derives those fields and the Host runtime/scope handles from
`CurrentNamespaceTarget`, requires one request ID and deadline across all three
layers, and checks the Mount response's kernel-nominated subject against the
pinned service cgroup. That SCM metadata does not prove the actual syscall
writer; signed session/result authentication and deployment MAC/capability
confinement remain required. The resulting preparation remains memory-only. Controller
attempt admission consumes and rechecks it, re-verifies the current ownership
lease, attenuates a local deadline, and commits the exact deadline-free template
body, deadline-bearing Apply body, authorization packet, catalog commitment,
and immutable namespace-allocation reference before returning a dispatch token.
The token retains the live proof and cannot be cloned or recreated from journal
bytes. On restart, validated inventory must first report the exact local
request as pending. Catalog-backed actions then reacquire their catalog, and a
durable packet or catalog digest alone is never descriptor authority.

Pending resumption loads the immutable `AOSMTA01` record by request ID and exact
current namespace-allocation reference, matches the Mount handle observed in
inventory, and reconstructs preparation from the original deadline-free body.
The reacquired catalog commitment must equal the durable commitment; release is
reconstructed through the catalogless path. The exact original signed plan and
signature must still verify under current controller trust and assignment state.
An equal assignment generation cannot substitute another plan digest. A current
ownership lease may replay exactly or advance monotonically, but it cannot roll
back or equivocate. The controller injects only the original exclusive BOOTTIME
deadline, requires the resulting Apply body to equal the durable bytes, leaves
the original attempt record immutable, and emits a volatile envelope containing
the reverified plan and current lease. An expired original deadline or plan,
changed catalog or namespace state, missing durable attempt, or any semantic or
body mismatch fails closed without issuing a new operation.

For attachment reconciliation, the caller does not supply even that fence-free
body. The controller consumes one closed action with its current desired record,
complete validated inventory snapshot, and live target. It derives CREATE
from desired state, derives INSTALL and REPLACE from the addressed inventory
recipe, and reproduces an older inventoried recipe for DETACH and RELEASE while
carrying the current desired generation and lease. These inputs are rechecked
through preparation and signed-plan binding and once more immediately before
admission. The admitted record invalidates the pre-attempt inventory snapshot;
the live dispatch token retains the exact desired generation, lease mode, and
namespace target instead.

Mount attempts use digest-protected `AOSMTA01` records. Flag bit zero marks a
present 32-byte catalog commitment. It is set for CREATE, INSTALL, REPLACE, and
DETACH; RELEASE clears it and requires the catalog field to be all zeroes.
Validation requires catalog absence if and only if the exact Apply action is
RELEASE and reconstructs portable semantics with the corresponding optional
binding. A catalogless release remains durable-before-I/O and receipt-bound;
only descriptor acquisition is omitted.

The controller's Apply client negotiates exact Mount 2.0 with the
signed-plan/lease feature and checks both hello and result kernel-nominated
subjects against configured Mount subject policy. That SCM correlation does
not prove the actual syscall writers; application-authenticated signed results
and deployment confinement remain required. First issue sends the packet durably admitted above;
pending resumption sends the same body and deadline under the exact plan with a
current lease. Mount admits by request ID plus request digest, refreshes only
permitted authority on a matching pending effect, resumes its worker without
allocating a second resource, and returns an already completed receipt exactly.
A successful `MountResult` must reproduce the attachment ID, current desired
and addressed resource generations, logical source-view identity, optional
local-live source incarnation, source consistency and generation, attachment
lease ID and interval, view, action-specific state, and broker handle derived
from or supplied by the exact Apply body. The controller commits that receipt
against the original attempt in the versioned `AOSMTC01` Mount-completion record
before returning it.
A transport failure or broker error is not evidence of absence: Mount may retain
a durable intermediate resource, so authoritative inventory still decides
retry, adoption, or cleanup.

The controller queries `InventoryMountResources` over a separate one-shot
Mount 2.0 session with no effect authorization. It requires each hello and
response's kernel-nominated subject to match configured Mount subject policy,
but that SCM correlation does not identify the actual syscall writer. It
accepts no descriptors and applies the complete resource-table validator before
committing the exact query and response in a bounded `AOSMTI01` latest-snapshot
record. The record also commits the complete
validated namespace-target, Mount-attempt, and completion set that the query
postdates. Successive snapshots may advance the Mount journal sequence or
refresh an unchanged sequence from a new broker process; sequence rollback,
same-sequence resource changes, request-ID reuse, and one broker process
spanning kernel boots fail closed.

Current-target comparison consumes a fresh snapshot and a live namespace
proof. It rejects any resource whose fence, namespace generation, recipe, or
replacement predecessor contradicts the exact durable attempt. The immutable
recipe includes its resource attachment generation, source-view identity,
optional live incarnation, source consistency and generation, view descriptor,
recursive and security mount attributes, canonical logical binding digest,
Mount-minted realization handle, physical proof digest and class, source boot,
device, inode and unique mount ID, and stable provider authority, resource, and
catalog identities, generations, and digests. The validator reproduces the
physical proof and realization handle, rejects physical aliases, and requires
every repeated handle and provider generation to carry one exact tuple.
Creation and publication require the desired and resource generations to agree.
Teardown may carry newer desired
authority while naming an older resource generation, but it must reproduce that
older recipe exactly. Replacement inventory requires both its assignment and
resource attachment generations to advance strictly. Each attempt is
then classified as unobserved, pending, faulted, successful without a retained
reply, superseded, or completed with a durable reply. Current-bound resources
with no local attempt are reported separately as untracked residuals. These are
planning observations, not permission to retry, adopt, detach, or clean up;
every effect still requires fresh catalog and signed authority.

Current attachment planning then rechecks one exact durable desired generation,
the fresh inventory commitment that includes the complete desired-state
namespace, and the retained live namespace target. It compares every physical
recipe field and separates the desired generation authorizing teardown from the
older resource generation being drained. The closed result selects at most one
prepare, install, replace, post-attach verify, detach, or release step, or
reports an exact pending operation, Mount fault, lease wait/expiry, residual
conflict, or completed release. A same-slot resource owned by another
attachment, a stale namespace, a non-advancing replacement fence, an untracked
intermediate transition, or a recipe substitution stops planning. The result
retains evidence for the next recheck but carries no catalog descriptor, signed
plan, or broker effect authority.

Post-attach verification consumes only the closed `Verify` result. The
controller persists an immutable `AOSATV01` record keyed by attachment and
desired generation. It binds the desired-record digest, exact historical
namespace-allocation reference, current assignment tuple, source inventory
snapshot and query, stable Mount handle and resource revision, resource boot
ID, complete installed kernel observation, and canonical digests of both the
desired recipe and complete installed resource. The observation retains the
non-recycled mount ID, parent and mount-namespace IDs, device and superblock
identity, VFS attributes and propagation, root and mount-point bytes, and the
complete identity-map commitment.

Verification records are append-only and bounded. Replay validates every
desired-generation and namespace-allocation cross-reference and recomputes the
recipe commitment from historical desired state. A verification commit enters
journal namespace 17 and advances the Mount inventory controller-state
commitment under its sole v1 domain, deliberately making its source snapshot
stale. Only a later validated complete inventory that reproduces the exact
verified installed resource under the same current desired state and live
target yields `Ready`. A missing resource or changed recipe, assignment,
revision, boot identity, kernel observation, operation correlation, or other
durable resource field is a verification conflict, not permission to reinstall
or reverify the same generation. Release and lease-expiry drains remain
available under newer desired authority and do not mistake historical readiness
for effect authority.

Caller role derives from peer credentials, socket activation, and the expected
service-unit identity; a serialized role is descriptive only. Unknown
operations, features, or FD roles fail before effects. An exact request replay
returns the persisted result. Reuse of an operation ID or equal fences with a
different digest is rejected. Responses state which descriptors were consumed,
returned, or closed so ownership is unambiguous across every error path.

The controller also signs an audience-specific broker authorization plan for
each host, mount, storage, and network broker. The immutable semantic plan
binds the assignment tuple and digest, exact semantic verbs, opaque resource
handles, argument bounds, policy commitment, and revocation scope. It commits
to the ownership-authority key and assignment identity; every use also carries
the current `OwnershipLease`, whose node, epoch, assignment digest, and validity
must match. The plan can attenuate that lease but cannot extend it.
It contains no arbitrary systemd property, mount option, host path, command, or
backend expression. Delivery through the unprivileged node daemon does not add
authority: a broker verifies the controller signature and its own audience.

Host, Storage, Network, and Guardian each admit only their exact 1.0 broker
protocol, while Mount admits only exact 2.0. They do not negotiate earlier or
later minor versions, and an unknown major or minor fails closed. Ownership
remains an independently versioned protocol and does not lend its version range
to a broker domain.

Before acknowledging or performing an effect, each broker durably records its
highest accepted semantic assignment tuple and plan digest, plus highest lease
generation/digest, authority expiry, and host boot ID. It rejects
caller-invented tuples, plans for another broker, an equal counter with
different bytes, older leases, expired authority, and every request not exactly
authorized by both plan and lease. A lease renewal may advance the lease
generation for an unchanged plan; it cannot change verbs, handles, or bounds.

The node-local lease record uses the fixed-width 234-byte `AOSLLR` version 1
codec. In network byte order it carries magic and version, sandbox and
incarnation IDs, assignment epoch and digest, node ID, lease generation and
digest, renewal nonce, authority expiry, raw clock-source provenance, host boot
ID, the derived `CLOCK_BOOTTIME` fail-stop deadline, and a domain-separated
SHA-256 corruption digest. Wrong length, magic, version, trailing bytes,
sentinel authority fields, or digest mismatch fail closed. The digest is not a
MAC: this is a non-authorizing local recovery format, and an adversarial-storage
threat model requires the broker journal to authenticate it with a node-local
key. It is not a portable media type or evidence that the containing journal
transaction reached stable storage.

At expiry a broker denies new effects. The stale plan permits only local
containment that cannot harm a later owner: network default-drop, cgroup
freeze/kill, namespace-local detach after stop, and removal of proven
node-private ephemeral objects. Shared hold release, storage mutation or
destroy, publication rollback, and external endpoint removal require a fresh
controller cleanup plan subordinate to current ownership plus compare-and-swap
at the authoritative resource endpoint. Thus compromise or rollback of the
unprivileged node daemon cannot retain or resurrect broker authority that each
broker and the guardian have rejected.

This protocol is deliberately not stable for remote callers. Distributed
standardization belongs at the public resource and portable-format layers.

## Portable policy format

The normative encoding, scalar, metadata, digest, media-type, feature,
signature, and distribution rules are defined in the
[portable format profile](09-portable-format-profile.md). This document
summarizes the resource roles and protocol relationship.

The resolved policy has its own media type and schema version. It is canonical,
strictly decoded, size bounded, and signed or bound by digest. Unknown fields,
enum values, and required features in authority-bearing policy fail closed.

Canonical policy uses the deterministic CBOR profile and domain-separated
object digest. Golden encoded-byte and semantic fixtures pin the result.

## Portable tree format

The tree format is a Merkle graph of bounded directory and node objects. Each
object carries:

- media type and schema version;
- algorithm-tagged digest and exact size;
- canonical sorted entries;
- metadata and feature flags;
- regular-file content or extent descriptors;
- hard-link identity where present; and
- child object commitments.

The commitment is stable across node-local mmap index versions. NAR, Git, OCI,
and native snapshots are adapters; their source digest and provenance can be
retained without making their representation universal.

## Portable view format

The canonical view schema commits source revision or live export generation,
ordered namespace presentation, consistency and mutation modes, identity
presentation, disclosure domain, and required features. Attachments separately
name destination slots and may narrow mutation. The closed descriptor-role and
feature registries in the portable profile prevent implementations from
substituting an arbitrary tree, profile, checkpoint, or trust object whose
digest happens to parse.

## Delta format

A portable writable delta commits to an exact base tree, exact result tree,
the result-graph objects not reachable from the base, and required features.
It is not a syscall log: rename order, whiteouts, overlayfs private xattrs, and
ZFS internal object identifiers are extraction details, not public semantics.

Applying a delta verifies its declared base and every immutable object, then
resolves exactly one result tree or fails. The conformance suite compares
native clone, overlayfs, and pure model extraction. Optional change hints live
outside the signed canonical delta and cannot change identity or authority.

## Snapshot envelope

A portable sandbox snapshot envelope contains:

- sandbox specification and effective policy commitment;
- ancestry and source snapshot references;
- private filesystem tree/delta commitments;
- package environment and attachment view revisions;
- execution-independent configuration;
- network and service dependency declarations;
- secret retention/redaction declarations;
- consistency level and quiesce evidence;
- required backend capabilities; and
- provenance and signatures.

Cache residency and operational retention tokens are excluded. The canonical
object commits typed receipt digests and dependency claims while the controller
ledger holds usable storage/content/service/secret authority. Base v1 has no
backend-local process or VM checkpoint field; adding one requires a new
snapshot media type with exact backend, version, architecture, CPU, device,
kernel, and compatibility semantics. It is never mislabeled portable.

V1 uses AOS content-addressed descriptor graphs for distribution. OCI may gain
a later transport mapping, but it does not define the sandbox's tree, policy,
or restore semantics. The snapshot format remains independently versioned.

## Compatibility rules

- Public `aos.sandbox.v1` evolves additively; breaking semantics use a new API
  package.
- Binary observational responses may add ordinary protobuf fields. ProtoJSON
  responses are projected to the client's negotiated schema because current
  AOS generated decoders reject unknown fields.
- Additive fields that change admission, authority, resource selection, or
  effects are legal only when the base request carries a required semantic
  feature understood before the method body is acted upon. An older server
  rejects the unknown required feature. A change that cannot obey that rule
  uses a new API package rather than relying on an absent-field default.
- Extensible observations use a v1 `ObservationExtension` envelope with a
  registered type URL, schema version, required-feature flag, bounded bytes,
  and opaque-display policy. Authority-bearing requests never use this escape
  hatch.
- Authority-bearing documents reject unknown semantics rather than ignoring
  them.
- Removed protobuf tags and names are reserved permanently.
- Unspecified enum zero is never assigned a rolling security default.
- Canonical format versions coexist with explicit readers and writers.
- Node-helper major mismatches fail loudly before privileged effects.
- Runtime capability probes are observations, not inferred from protocol
  versions.

The existing difference between strict canonical document decoding and
extensible RPC projection decoding must be tested explicitly rather than
hidden behind one global JSON policy.
