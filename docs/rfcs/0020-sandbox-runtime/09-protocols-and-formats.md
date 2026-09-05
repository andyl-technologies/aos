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

Client absolute deadlines are advisory because clocks differ. When accepting
an operation, the server records its own wall timestamp for audit and a bounded
monotonic duration for admission/cancellation behavior. Node sub-deadlines are
durations relative to receipt and can never extend the assignment lease.

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

The transport-neutral ownership-authority protocol is independently versioned
as 1.1, retaining 1.0 sessions for acquire and renew. `Begin` durably admits one
exact canonical acquire, renew, or same-owner advance claim;
`CompleteOrResume` explicitly drives or resumes the admitted operation; and
`Query` observes the exact request-ID/claim-digest binding. Query reports
`Absent`, `Pending`, or `Completed`; Begin and CompleteOrResume never report
`Absent`. Completed carries the exact ownership lease, lease signature,
transaction receipt, and receipt signature. Replays and recovered completions
are authenticated historical artifacts, not present effect authority.

Protocol 1.1 adds the distinct `Advance` action. It compare-and-swaps the exact
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

The fixed claim retains its V1 framing with action code `3` for advancement;
old readers reject that unknown action. Advance receipts bind protocol 1.1;
acquire and renew receipts retain their exact 1.0 encoding, even in a 1.1
session. A 1.0 session rejects advance Begin requests and cannot query or
complete retained advance transactions. Existing V2 ownership journals retain
their encoding; older programs fail closed on entries containing the new
action rather than reinterpret or discard them.

Negotiation pins the exact ownership-authority key generation, canonical
method set, request/response bounds, and maximum lease duration. Each client
hello and server selection adds an independent nonzero 32-byte CSPRNG nonce.
The domain-separated SHA-256 transcript over both nonces and every negotiated
field is echoed in requests and responses, so reconnect and authority-epoch
substitution fail correlation checks. The transcript is not authentication:
local transports still authenticate peer credentials and service identity,
while remote transports require an authenticated, integrity-protected channel.
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

The first implementation that retains transaction receipts uses the V2
ownership journal. It does not reinterpret the previously committed V1 bytes.
Finding any V1 ownership entry or current pointer fails with
`MigrationRequired`; an explicit authenticated migration must move that state
before V2 reads or writes proceed.

Controller publication uses an independently versioned V3 format in its own
`AuthorityPublication` journal namespace. V3 retains a permanent prepared
record by publication digest and a sandbox-keyed current pointer whose embedded
sandbox and complete prepared bytes must cross-link exactly. The namespace is
closed: unknown key shapes, malformed or substituted values, missing permanent
records, and digest collisions are corruption. V1 or V2 publication keys or
magic require explicit authenticated migration rather than reinterpretation.

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

The generic effect ledger retains its exact V1 encoding for ungated effects.
An ownership-gated operation instead requires an Effect V2 record for every
step. A V2 plan is constructed only from a template in the gate's exact
publication draft; it records and recomputes the source-draft digest, broker
audience and method, template digest, deadline-free request body digest, and
portable semantic-identity commitment. Its binding digest also commits the
operation ID and ordered step, preventing valid values from being exchanged
between journal keys. Callers cannot provide those fields independently. V2
currently admits only descriptor-free Host `ApplyRuntime`; Mount, Storage,
Network, Guardian, Guest, other methods, and every descriptor-bearing template
are rejected before journal admission. Recovery reports legacy V1 records under
ownership-gated operation provenance as migration-required rather than silently
reinterpreting them. It rejects a missing or extra
effect, a template absent from the gate draft, and any substituted body or
semantic commitment.

Before the first external broker call, the sole journal-owning reconciler
selects the current publication. It accepts the activated publication or a
valid successor only when the source draft and exact effect template remain
unchanged. It then injects a bounded deadline and durably changes the effect
from `Planned` to `Applying` together with the selected publication digest,
lease generation and digest, only the wall-seconds/boottime scalar projection
used for deadline attenuation, exact deadline-bearing body, and exact encoded
authorization packet. Raw clock provenance and boot identity are deliberately
not persisted: they are unauthenticated advisory input and are not part of the
reconstruction theorem. The executor
receives that owned recovered attempt and never opens the controller journal.
After a crash it queries the broker with the byte-exact original Apply request
and signed quartet. Authenticated `Pending` and indeterminate transport results
retain that exact attempt. Only authenticated `Absent` permits reselection: the
reconciler consults current authority, constructs a fresh attenuated attempt,
and durably replaces the dispatch record before issuing its Apply. A crash at
that boundary therefore recovers by querying the replacement rather than
replaying an unrecorded request.

Each durable dispatch also commits the Effect V2 binding digest. Recovery
reconstructs the selected publication relative to the gate's permanent
activated publication, not relative to whichever publication is current at
query time; a same-draft lease renewal may therefore leave historical attempts
queryable. Current is consulted only for initial selection and authenticated
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

The Effect V2 layout is not yet released and therefore has no compatibility
decoder for earlier experimental bytes. Its current canonical layout omits raw
clock provenance and boot ID. Legacy Effect V1 golden encodings remain frozen
for all four states; finding V1 under gated provenance requires explicit
migration.

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
peer-authentication token. A Unix carrier must authenticate and authorize peer
credentials and service identity, enforce the negotiated frame ceiling before
allocation, and validate hostile request parts before dispatch. A future
authenticated remote carrier supplies its own principal and channel security
to the same semantic handler. Socket paths, credentials, framing, and remote
identity therefore remain outside the portable ownership protocol.

## Record-subject local ingress

Producer-output and publisher admission use a distinct local carrier from the
descriptor-passing broker protocols below. Each accepted record must include
exactly one kernel-validated `SCM_CREDENTIALS` and one kernel-generated
`SCM_PIDFD`; `SCM_RIGHTS` is forbidden. The receiver bounds the complete packet
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

Host- and mount-broker protocol 1.1 defines a generic request-envelope carrier
for the exact canonical broker plan, detached plan signature, ownership lease,
and detached lease signature. The carrier is negotiated with
`aos.sandbox.authorization.signed-plan-lease, 1, 0` and is mandatory on effect
methods. Legacy 1.0 is observation/inventory-only; it rejects effect methods
and the carrier. Protocol 1.1 observation and inventory methods also reject the
carrier. The transport validator applies independent and aggregate byte limits,
fully decodes each canonical object, and preserves the received bytes exactly;
that structural validation grants no authority. Trust anchors, public keys,
trusted clock samples, revocation state, and node-local records never cross in
the request. The same portable artifact quartet can later be placed in a
distinct authenticated remote wrapper, but the local `SOCK_SEQPACKET` framing,
peer credentials, and descriptor table are not a remote protocol.

Host-broker protocol 1.2 adds `QueryRuntimeEffect`. The query carries a fresh
1.2 header, zero descriptors, the same exact signed authorization quartet, and
the byte-exact original protocol 1.1 or 1.2 `ApplyRuntimeRequest`; its outer
request ID must equal the embedded Apply request ID. Apply's portable signed
semantic authorization remains version 1.1 under either carrier version. The
query returns `Absent`, `Pending`, or
`Complete`, with `Complete` carrying the byte-exact durable response receipt.
Protocol 1.2 negotiates a Host-query packet ceiling 64 bytes above the legacy
generic ceiling, which is greater than the maximum protobuf growth from the
additional query header and nested-body framing. Protocol 1.1 Apply retains its
original full packet ceiling, while every accepted Apply and its unchanged
quartet therefore fit in a later 1.2 query packet. Packets in the additive band
must decode specifically as `QueryRuntimeEffect`; every other method retains
the legacy ceiling. Query responses reject unknown status values and fields;
`Absent` and `Pending` require an empty receipt, while `Complete` requires a
bounded, structurally valid `RuntimeObservation` whose fence exactly matches
the original Apply.
The broker revalidates the original request digest, semantic authorization,
assignment fence, and authority artifacts against durable state. Existing
effects are checked at their authenticated admission clock only to establish
historical identity, never to grant new authority; an absent request must still
be live at the current protected clock. The operation is strictly read-only:
it does not admit or refresh a fence, write state, resolve a catalog handle, or
invoke a worker. Protocol 1.0 and 1.1 do not advertise, negotiate, or accept the
query method.

Host 1.2 also defines `ObservePayloadScope`, a live authority-bearing query
with zero request descriptors. Its exact signed plan must already grant the
query semantic operation for the installed runtime; the complete admitted
plan/lease fence must equal the installed durable fence. Unlike effect receipt
queries, this operation always checks current protected time and requires live
launch-retained payload pins. It never installs a newer lease, advances durable
state, or reconstructs kernel authority from a receipt after restart.

A successful response echoes the exact assignment fence and runtime handle,
adds a nonzero process-local opaque scope handle, and transfers exactly two
descriptors in order: the retained payload leader pidfd and the retained
payload-subtree cgroup `O_PATH` descriptor. Bodies are bounded at 8 KiB and the
raw leader-cgroup hint at 4 KiB. The hint is only an empty exact-membership or
strict descendant locator; it is not membership proof. Error responses carry
no descriptors. The broker retains its proof through the atomic response send
and rechecks kernel identity and the live query deadline immediately before it.

The controller authenticates the kernel-authorized subject of the actual hello
response against trusted host-service credentials and a retained service cgroup.
Subsequent response records must identify that same live execution. Listener
creator credentials alone do not authenticate the responder under socket
activation. The controller validates descriptor roles, pidfd liveness, cgroup-v2
identity, and leader membership using the received objects. Payload PID-1,
root, and namespace verification remain an authenticated host attestation, not
facts inferred from descriptor types. This observation does not itself grant
holder mapping, current assignment authority, or permission to deliver a local
channel; those remain separate controller admission requirements.

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
