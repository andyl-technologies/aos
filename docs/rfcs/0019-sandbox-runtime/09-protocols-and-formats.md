# Protocols and portable data formats

## Compatibility domains

The design has four independent compatibility domains:

1. public sandbox control API;
2. coordinator-to-node reconciliation protocol;
3. node-local privileged broker protocols; and
4. portable policy, tree, delta, and snapshot formats.

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
- execution: create, get, attach, cancel, and list;
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
reattach expiry, and audit UID. Host/port/socket routing is ephemeral and never
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
server produces one bounded list snapshot as of watermark `W`, then sends only
events strictly after `W`. A resume request supplies the last fully applied
cursor: the server sends only events strictly after that cursor and does not
send a list snapshot. The cursor is opaque and monotonically ordered within
one stream identity and epoch.

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
assignment digest)`. An exact tuple replay is idempotent. A different digest at
the same epoch/generation is a protocol violation; a lower tuple is rejected.
The node durably records acceptance before effects. Observations carry the
tuple plus a monotone observation sequence and compare-and-swap the
controller's prior observation version. Delayed reports from an old epoch are
retained only as audit evidence and cannot change current status.

Capability drift during preparation aborts before publication and reports the
observed capability generation. Reconnect starts with an inventory digest and
full desired-state resync before incremental updates. Expiry of an operation
deadline stops new effect admission but does not erase already committed
intent; the operation moves to its defined compensation or residual state.

### Exclusive ownership lease

An epoch number alone cannot fence a partitioned prior owner. Every active
assignment therefore carries an exclusive lease issued by a strongly
consistent ownership authority. The grant contains sandbox UID, incarnation,
epoch, assignment digest, authority-issued start/expiry, maximum clock skew,
and renewal nonce.

On receipt, a node converts the remaining authority duration into a local
monotonic fail-stop deadline after subtracting the maximum skew and a fixed
safety margin. It renews before that margin. If renewal fails, it closes new
execution/publication/mount admission, freezes the payload before the local
deadline, and then stops it if contact is not restored. Wall-clock movement
cannot extend the local deadline.

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

## Node-local broker protocols

Privileged brokers listen only on protected Unix `SOCK_SEQPACKET` sockets. The
protocol has:

- a handshake that selects one exact local version and advertised closed
  operation/feature set before privileged requests;
- one bounded message per packet;
- a closed operation tag;
- request ID, operation digest, sandbox UID, incarnation, assignment epoch,
  desired generation, and payload namespace generation;
- an exact FD-role table matching SCM_RIGHTS ancillary descriptors;
- maximum body and FD counts checked before allocation; and
- peer-credential and service-unit verification.

The protocol passes real descriptors or broker-minted handles. It never
serializes descriptor integers as reusable references. Extra, missing,
duplicated, wrong-type, writable, or unexpectedly mounted descriptors are
rejected.

Caller role derives from peer credentials, socket activation, and the expected
service-unit identity; a serialized role is descriptive only. Unknown
operations, features, or FD roles fail before effects. An exact request replay
returns the persisted result. Reuse of an operation ID or equal fences with a
different digest is rejected. Responses state which descriptors were consumed,
returned, or closed so ownership is unambiguous across every error path.

The controller also signs an audience-specific broker authorization plan for
each host, mount, storage, and network broker. The plan binds the assignment
tuple and digest, exact semantic verbs, opaque resource handles, argument
bounds, policy commitment, lease interval, maximum skew, and revocation scope.
It contains no arbitrary systemd property, mount option, host path, command, or
backend expression. Delivery through the unprivileged node daemon does not add
authority: a broker verifies the controller signature and its own audience.

Before acknowledging or performing an effect, each broker durably records its
highest accepted assignment tuple, plan digest, and monotonic fail-stop
deadline. It rejects caller-invented tuples, plans for another broker, expired
plans, an equal tuple with different bytes, and every request not exactly
authorized by the current plan. Renewals are newly signed plans and cannot
extend the deadline merely by replay. At expiry a broker denies new effects
and permits only the plan's closed fail-stop verbs needed to freeze, detach,
revoke, or remove that assignment. Thus compromise or rollback of the
unprivileged node daemon cannot resurrect broker authority that the broker's
own durable fence has rejected.

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

Cache residency is excluded. A backend-local process or VM checkpoint is an
optional descriptor with exact backend, version, architecture, CPU, device,
and compatibility identity. It is never mislabeled portable.

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
