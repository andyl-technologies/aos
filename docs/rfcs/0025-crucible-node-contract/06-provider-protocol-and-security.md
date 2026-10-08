# 06 — Provider protocol, compatibility, and security

This chapter specifies the Crucible Node Protocol, **CNP/1**. It is a
language-neutral local process contract between the coordinator's trusted
provider broker and a node implementation. A provider can implement compute,
storage, links, clocks, or an external-device adapter. Scheduling, capabilities,
and preservation semantics come from the other chapters of this RFC; this
chapter specifies their transport, correlation, admission, and failure rules.

CNP/1 and QEMU's native QMP/control/shared-memory protocols have distinct
encodings and authority. A broker MAY translate the contract into those
mechanisms, but MUST preserve their authenticated ownership and completion
obligations. Receipt of a CNP message does not manufacture a native QEMU receipt,
and a broker MUST NOT report stronger semantics than its adapter implements.

## 6.1 Scope and parties

The **controller** is the trusted coordinator-side endpoint. The **provider** is
the implementation-side endpoint. A **session** identifies one controlled world
realization. An **incarnation** identifies one continuously surviving provider
instance. Restarting or replacing a provider creates a new incarnation even
when its executable and restored model state are identical.

The protocol distinguishes semantic `NodeId`, scheduling role,
`ExecutionOwnerId`, and `CaptureOwnerId`. One provider can expose several nodes
and owners. Several public nodes can share an indivisible native execution or
capture owner. CNP MUST NOT require a process, thread, socket, or native snapshot
per public node.

- **[CN-IPC-1]** A conforming provider MUST implement the baseline transport,
  envelope, negotiation, lifecycle, operation journal, and content transfer
  specified here. It MUST implement every advertised facet and reject an
  unadvertised facet before causing its effects.
- **[CN-IPC-2]** Execution and capture requests MUST identify their complete
  owner membership. An owner-scoped operation MUST NOT be decomposed into
  independently executed child requests unless the admitted descriptor
  explicitly declares that decomposition safe.
- **[CN-IPC-3]** Only the controller grants progress or releases visible input.
  A provider MUST NOT infer a grant from a socket becoming writable, a polling
  request, a host deadline, or another node's observed wall-clock progress.

Native host traits are an implementation technique. They are neither a stable
Rust ABI nor the portable extension interface. A vendor implementation written
in C++, Rust, another language, or an external hardware service implements the
same CNP messages and semantic obligations through its process adapter.

## 6.2 Baseline transport and limits

The baseline is a connected local Unix-domain `SOCK_STREAM` socket. The
controller launches or explicitly admits its peer and lends the connected
endpoint. Listening sockets are an optional deployment mechanism; accepting a
connection alone never admits a provider. Network transports are outside the
CNP/1 baseline and require a separately specified authenticated transport
profile.

Each frame consists of a four-octet unsigned big-endian length followed by that
many octets of UTF-8 JSON. The length excludes its own four octets. There is no
terminating newline, implicit padding, compression, or magic prefix. Stream
reads can split a length or body, and one read can contain several frames.

| Limit | Baseline value | Negotiation rule |
| --- | --- | --- |
| Frame JSON length | `16777216` octets | Peer selects the smaller advertised limit; never exceeds this hard cap |
| JSON container nesting | 64 | Smaller values MAY be negotiated |
| Outstanding request IDs | 256 | Smaller values MAY be negotiated |
| Retained journal entries per request origin | 4096 | Smaller values MAY be negotiated |
| Concurrent operations per execution owner | 1 | No increase in CNP/1 |
| Concurrent operations per capture owner | 1 | No increase in CNP/1 |
| Decoded inline blob chunk | `1048576` octets | Smaller limits follow frame and memory limits |
| Identifier length | 128 ASCII octets | No increase in CNP/1 |
| Pre-negotiation hello exchanges | 1 | One request and its one response |

- **[CN-IPC-4]** A receiver MUST validate the length before allocating body
  storage. Length zero, a length over its current limit, truncated framing, or
  invalid UTF-8 is a fatal connection error. It MUST close the stream and
  quarantine unresolved effectful operations; it MUST NOT resynchronize by
  searching arbitrary bytes for JSON.
- **[CN-IPC-5]** Implementations MUST enforce bounded parsing, request, journal,
  payload, and observation storage. A negotiated limit MUST be positive and no
  larger than the baseline hard limit. Receiving a limit does not authorize a
  corresponding unbounded allocation.
- **[CN-IPC-6]** Socket backpressure MUST NOT alter modeled timestamps, discard
  effects, advance the simulation, or convert an incomplete operation into a
  completed one. Providers MUST retain bounded pending effects or stop before
  producing more; exhaustion is reported as `RESOURCE_EXHAUSTED` with effect
  certainty.

The baseline does not place arbitrary binary frames on the control stream.
Binary data uses the blob transfer operations in Section 6.10. Optional shared
memory and descriptor transfer use a separately negotiated facet and preserve
the same correlation and visibility rules.

## 6.3 Portable value vocabulary

JSON follows [RFC 8259](https://www.rfc-editor.org/rfc/rfc8259). Duplicate
object keys, invalid Unicode, lone surrogates, and non-finite numeric values
are rejected. Identity-bearing JSON is canonicalized using
[RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785). Implementations MUST
preserve string values rather than normalize their Unicode representation.

| Type | Wire representation | Validation |
| --- | --- | --- |
| `Id` | JSON string | `[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}` |
| `U64` | JSON string | `0` or `[1-9][0-9]*`; parsed value at most `18446744073709551615` |
| `I64` | JSON string | `0` or `-?[1-9][0-9]*`; signed 64-bit range; `-0` forbidden |
| `Tick` | `U64` | Picoseconds on the admitted coordinator timeline |
| `Version` | JSON number | Integer from 0 through 65535; zero only where explicitly allowed |
| `HashRef` | JSON object | `algorithm`, `domain`, `digest` as defined below |
| `ContentRef` | JSON object | `hash`, `length`, `media_type` as defined below |
| `Bytes` | JSON string | RFC 4648 URL-safe base64 alphabet, no padding or whitespace; canonical unused bits |
| `IdSet` | JSON array of `Id` | Strict ascending ASCII order; no duplicate members |
| `Extensions` | JSON object | Negotiated namespaced fields; empty object in the baseline |

Counts, timestamps, byte lengths, offsets, ordinal values, quantum indices,
and sequence numbers use `U64`, even when a sample value is small. Signed
clock offsets use `I64`; arbitrary-precision values require an explicitly
versioned facet. JSON numbers MUST NOT carry time or these counters.

- **[CN-IPC-7]** Timing arithmetic MUST use checked integer operations. A value
  outside its declared range, noncanonical decimal string, overflow, or
  conversion to floating-point time is rejected with `INVALID_ARGUMENT`.
  The receiver MUST NOT round a ceiling, silently saturate a value, or infer a
  50-ps instruction cost from the use of picosecond units.
- **[CN-IPC-8]** Schema fields defined here are required unless their table
  explicitly says optional. Unknown unnamespaced fields are rejected. Optional
  extensions appear only under `extensions`; their features MUST be negotiated
  before use. Null is not interchangeable with omission.

### 6.3.1 Content identity

`HashRef` contains exactly these fields:

```json
{
  "algorithm": "blake3-256",
  "domain": "cnp.node-descriptor.v1",
  "digest": "0000000000000000000000000000000000000000000000000000000000000000"
}
```

The digest above illustrates syntax, not a valid descriptor identity. `domain`
is an ASCII string of 1 through 128 octets; `digest` is exactly 64 lowercase
hexadecimal characters. The algorithm is ordinary unkeyed BLAKE3 with a 32-byte
output, not BLAKE3 keyed mode or `derive_key`. BLAKE3's algorithm is specified
by its [upstream specification](https://github.com/BLAKE3-team/BLAKE3-specs).

The CNP domain-separated digest is defined without implicit native widths:

```text
Hash(domain, payload) = BLAKE3_256(
    ASCII("CNP/1") || 0x00 ||
    U32_BE(octet_length(ASCII(domain))) || ASCII(domain) ||
    U64_BE(octet_length(payload)) || payload
)

JsonHash(domain, value) = Hash(domain, UTF8(JCS(value)))
```

| Object | Domain | Payload |
| --- | --- | --- |
| Immutable node descriptor | `cnp.node-descriptor.v1` | Complete descriptor JSON, excluding its external `descriptor_hash` wrapper |
| Admitted node binding | `cnp.node-binding.v1` | Durable `compatibility` projection of `NodeBinding`; live authority is excluded |
| Complete owner binding | `cnp.owner-binding.v1` | Complete `OwnerBinding` covering owner roster and node binding hashes |
| Complete world binding | `cnp.world-binding.v1` | Complete world binding JSON, excluding its external `world_binding_hash` wrapper |
| Operation request identity | `cnp.request.v1` | Request projection defined in Section 6.6 |
| Opaque content blob | `cnp.blob.v1` | Exact raw octets |
| Ordered observation batch | `cnp.observation-batch.v1` | Complete observation batch JSON |
| Ordered input batch | `cnp.input-batch.v1` | Complete input batch JSON |

`ContentRef` has `hash: HashRef`, `length: U64`, and `media_type: string`.
Its hash domain is always `cnp.blob.v1` over the exact stored octets. Typed
object identities such as descriptor/binding hashes are separate `HashRef`
values recomputed after decoding those stored octets. Identity-bearing JSON
objects are stored as their UTF-8 JCS bytes before creating a `ContentRef`.
The media type is bounded to 128 printable ASCII octets and describes the
content; it does not alter the opaque blob hash. A receiver validates length,
media type, and the applicable schema in addition to the digest. A reference is
not a URL, filesystem path, permission grant, or proof the receiver possesses
the content.

- **[CN-IPC-9]** Providers and controllers MUST compute these identities from
  canonical bytes with the stated domain and length prefixes. Native struct
  layout, JSON insertion order, process paths, pretty-print whitespace, and
  accidental envelope fields MUST NOT enter an object's identity.
- **[CN-IPC-10]** Extensions inside an immutable descriptor or binding are
  included in its identity. Runtime-only authentication receipts and host
  admission decisions are separate records; implementations MUST NOT erase
  them from identity-bearing data by guessing that a field is observational.

The normative core object tables are in
[cnp-v1-core-types.md](reference/cnp-v1-core-types.md). The primitive expectations
in [cnp-v1-vectors.json](reference/cnp-v1-vectors.json) are normative hash,
canonicalization, and scalar vectors; they do not represent complete manifests.

## 6.4 Envelope and correlation

Every frame carries this envelope. Nullable fields are present with JSON null
when their scope does not apply.

| Field | Type | Meaning |
| --- | --- | --- |
| `protocol` | string | Exactly `CNP/1` |
| `message` | string | `request`, `response`, or `event` |
| `session_id` | `Id` or null | Admitted world session; null only for initial `hello` |
| `incarnation_id` | `Id` or null | Surviving provider instance; null only in initial `hello` request |
| `node_id` | `Id` or null | Specific semantic node; null for provider, world, or multi-node owner scope |
| `execution_owner_id` | `Id` or null | Owner of a progress operation |
| `capture_owner_id` | `Id` or null | Owner of preservation state |
| `request_id` | `Id` or null | Request-origin-generated correlation ID; null only for unsolicited events |
| `operation_id` | `Id` or null | Controller-generated long-lived operation identity |
| `sequence` | `U64` | Sender's monotonically increasing frame sequence on this connection |
| `method` | string | Operation name in Section 6.7 |
| `body` | object | Method-specific request, result, or event |
| `extensions` | `Extensions` | Negotiated envelope extensions |

Each direction starts sequence at `"1"` and increments by one for each frame.
Sequences detect stream-level duplication and gaps; they are not node time,
event order, or authorization. A response echoes the request's IDs, method,
node/owner scope, and admitted session/incarnation; its sequence belongs to
the response sender. Responses can arrive in a different order from requests.

Request IDs are scoped by origin (`controller` or `provider`), session, and
incarnation. The request's direction determines origin; a response echoes that
origin implicitly by being sent in the opposite direction. Execution and
preservation operation IDs are controller-generated. Blob transfer IDs are
origin-scoped. Neither endpoint can retire the other origin's journal.

```json
{
  "protocol": "CNP/1",
  "message": "request",
  "session_id": "session-1",
  "incarnation_id": "provider-1",
  "node_id": null,
  "execution_owner_id": "machine-owner-1",
  "capture_owner_id": null,
  "request_id": "request-17",
  "operation_id": "operation-9",
  "sequence": "17",
  "method": "poll",
  "body": {"after_observation_sequence": "0"},
  "extensions": {}
}
```

- **[CN-IPC-11]** Peers MUST reject a stale session, incarnation, binding,
  owner, request correlation, or out-of-sequence frame before applying effects.
  A malformed correlation that cannot be answered safely closes the stream.
  Correctly framed semantic mismatches return the errors in Section 6.11.
- **[CN-IPC-12]** Owner-scoped messages MUST carry the owner ID and complete
  admitted participant set in their operation arguments. A child `node_id`
  does not authorize progress of its enclosing owner or peers.

A response body has one of these shapes:

```text
{ "status": "accepted", "operation_state": "running",
  "result": { ...method-specific fields... }, "extensions": {} }

{ "status": "completed", "operation_state": "completed",
  "result": { ...method-specific fields... }, "extensions": {} }

{ "status": "error", "operation_state": "not_started|running|completed|unknown",
  "error": { "code": "...", "message": "...",
             "effect": "not_started|in_progress|completed|unknown",
             "retryable": false, "details": {} }, "extensions": {} }
```

Immediate read-only requests return `completed`. `accepted` proves durable
registration in the live incarnation's bounded journal, not execution,
delivery, capture, visibility, or successful completion. `completed` has the
method-specific meaning below and MUST include the corresponding evidence.

## 6.5 Negotiation, realization, and admission

The controller sends `hello` before other methods. Its body contains:

| Field | Type | Meaning |
| --- | --- | --- |
| `versions` | array of strings | Supported protocol versions; includes `CNP/1` |
| `session_id` | `Id` | Intended world session |
| `controller_nonce` | `Bytes` | Exactly 32 unpredictable octets |
| `required_features` | `IdSet` | Features without which the controller refuses the connection |
| `optional_features` | `IdSet` | Offered extensions |
| `limits` | object | `frame_bytes`, `nesting`, `requests`, `journal_entries`, `blob_chunk_bytes`, all `U64` |
| `admission_token` | `Bytes` | Exactly 32 octets from the host's private launch/admission channel |
| `extensions` | object | Negotiated hello extensions |

The successful reply returns `version`, `session_id`, `incarnation_id`,
`controller_nonce`, `provider_nonce` (32 octets), `selected_features`,
`limits`, `resume_token: Bytes or null`, and `provider_identity`. A selected
`cnp.resume/1` returns a 32-octet unpredictable resume token; otherwise it is null.
`provider_identity` is the provider's
implementation manifest, not a trusted assertion of its executable measurement.
The initial hello response has envelope `session_id: null` and the returned
`incarnation_id`. Later messages use the admitted session/incarnation.

The required baseline feature is `cnp.core/1`. Additional facet identifiers are
negotiated by exact versioned name; port protocols such as `core.block/1` are
negotiated separately through the realized node descriptors.

Both endpoints MUST offer `cnp.core/1`, and the controller MUST require it.
Journal and outstanding-request credit are finite in both request directions.
Each receiver advertises its positive receiving limits within the hard caps.

- **[CN-IPC-13]** The selected protocol version MUST be common to both peers;
  selected features MUST be offered by both; every required feature MUST be
  selected. No mutual version, unknown required feature, or unsupported port
  schema is a fail-closed error. A vendor MUST NOT silently downgrade exact
  timing, preservation, or visibility requirements.
- **[CN-IPC-14]** `discover` returns bounded provider-supported profiles and
  facet schemas. `realize` validates configuration and returns complete
  immutable realized descriptors. Neither call grants execution, external
  input consumption, or visible output. Profile descriptions are not
  substitutes for capabilities of the particular realized nodes.
- **[CN-IPC-15]** `admit` installs the controller's binding after host evidence
  and qualification checks. The provider MUST verify that the supplied binding
  names its realized descriptor, implementation, owners, ports, timing policy,
  and selected guarantees. A discrepancy is rejected before activation.

### Realization state machine

```text
connected -> negotiated -> realized -> admitted -> staged -> active
                                      |           |          |
                                      +------ abort ---------+
                                                           stopped
                                                              |
                                               shutdown -> released
```

`active` authorizes participation only through later grants, not free-running
execution. An exact owner is stopped between grants. A quantized owner has only
the physical activity allowed by its admitted policy. A stopped world may
capture or stage a restore without activating its replacement.

The protocol states above describe connection/admission staging. The public
node lifecycle remains `Unrealized`, `Prepared`, `Stopped`, `Executing`,
`FailedContained`, `Quarantined`, and `Released` as defined in Chapter 01.
Successful realization creates `Prepared` nodes; global activation establishes
`Stopped` nodes; a grant creates `Executing` nodes. Disconnection does not itself
establish a public node stop.

Descriptor changes require a new realization and binding. An admitted node
cannot gain a device, mutable shared mapping, new clock behavior, capture owner,
or timing mode through an observational update.

## 6.6 Idempotency, retry, and reconnect

A request ID identifies one logical request in an origin/session/incarnation. An
operation ID identifies the registered effectful operation, including its
terminal result. The controller supplies both before the effect can begin.

The request hash is `JsonHash("cnp.request.v1", projection)`, where projection
contains exactly `protocol`, `session_id`, `incarnation_id`, `node_id`,
`execution_owner_id`, `capture_owner_id`, `request_id`, `operation_id`, `method`,
`body`, `extensions`, and an additional `request_origin` field set to
`controller` or `provider`. `message` and connection `sequence` are excluded so
the same request can be queried or retransmitted on a resumed connection.

- **[CN-IPC-16]** Before an effectful request can change state, the provider
  MUST reserve its journal record containing request hash, operation ID, owner
  binding, status, and retained outcome. Repetition of the same request ID and
  hash returns the recorded result or current operation state without applying
  the effect again. Reuse with different material returns `CONFLICT`.
- **[CN-IPC-17]** There MUST be at most one effectful execution operation per
  execution owner and one preservation operation per capture owner. A capture
  and execution operation MUST NOT overlap when their state domains intersect.
  The provider rejects conflicts before beginning another effect.
- **[CN-IPC-18]** Timeout, EOF, interrupted polling, and cancellation request
  delivery do not prove an operation stopped. The controller MUST query the
  same operation or quarantine it. It MUST NOT create a replacement operation
  ID and re-execute an ambiguous run, input, close, capture, or activation.

`poll` is read-only and returns `operation_state`, the retained result/error,
and bounded observation references after the supplied cursor. `cancel` requests
a stop; its acceptance does not prove that stop. Completion requires a later
terminal operation record with stop boundary and pending-effect inventory.
Already completed operations retain their original result when canceled.

`retire` identifies a sorted set of request and operation IDs whose outcomes
the requesting origin has durably consumed. Its reply acknowledges journal eviction.
IDs MUST NOT be reused within the session. A retired operation is
`OPERATION_RETIRED`, not a new operation eligible for execution. Providers
retain compact tombstone/range state or terminate the session before they
cannot reject reuse within negotiated resource limits.

`disposition` is `consumed` or `abandoned_inert_transfer`. Consumed retirement
requires a nonnull receipt proving durable outcome/content acceptance or
transferred custody. Inert abandonment requires null receipt and identifies
only blob-transfer requests that never authorized model effects. It cannot
retire an ambiguous execution operation. A receiver validates the originating
IDs and pin ownership before releasing journal/content records.

Reconnect uses a new `hello` body with the additional negotiated
`resume_session` object: `session_id`, `incarnation_id`, `resume_token`, and
`unresolved_operation_ids`. The token is issued over the admitted connection,
is 32 unpredictable octets, and is not included in persisted world identity.
Connection sequences restart; operation/request identities do not. Initial
negotiation issues the token; every successful resume atomically rotates it and
fences the previous control connection before acknowledging the replacement.
The old connection can no longer register requests or grant effects. Deferred
workers recheck connection authority before registering new work; previously
journaled operations remain queryable rather than being re-executed. Only one
controller connection may hold mutation authority for an incarnation.
If token rotation acknowledgment is lost and authority cannot be recovered,
the controller contains the incarnation; it never guesses a new operation.
Successful resume returns `resumed_operations: array` with exactly the requested
operation IDs and their retained states, in sorted ID order. Each record has
`operation_id`, `operation_state`, and `outcome: object or null`; terminal
outcome is the original response body. A fresh hello returns an empty array.

- **[CN-IPC-19]** `cnp.resume/1` MAY resume only the same surviving incarnation
  with the same journal and owner custody. The response MUST enumerate every
  requested unresolved operation and its retained state. Lost journal entries,
  a new process incarnation, or uncertain native custody yield
  `OUTCOME_UNKNOWN`; the controller MUST quarantine affected owners.
- **[CN-IPC-20]** Provider restart is not reconnect. Recovery into a fresh
  provider requires explicit restore preparation with authenticated preserved
  state and a new incarnation. The controller MUST NOT replay ambiguous
  requests into that new incarnation to infer what happened previously.

## 6.7 Method registry and minimum bodies

Every method carries `extensions: {}` in its body unless negotiated otherwise.
Objects named `NodeDescriptor`, `NodeBinding`, `WorldBinding`, `Event`, and
`CaptureManifest` have the immutable schema and semantics defined by Chapters
02, 04, and 05. These are structured objects, not vendor-chosen opaque strings.
Their language-neutral field schemas are in the normative
[core types](reference/cnp-v1-core-types.md). The operation-specific fields in
this chapter are mandatory minimum fields;
an advertised facet can add only its explicitly versioned requirements.

| Method | Request fields beyond `extensions` | Successful result | Permitted state |
| --- | --- | --- | --- |
| `hello` | Section 6.5 fields | Negotiated version, identities, limits, features | Connected or resumable |
| `discover` | `profile_ids: IdSet`; empty means all bounded advertised profiles; optional `cursor: Id` | `provider_manifest: ProviderManifest`, `profiles: array<NodeManifest>`, `facet_schemas: array<SchemaRef>`, `complete: bool`, `next_cursor: Id or null` | Negotiated onward |
| `realize` | `realization_id: Id`, `configuration: ContentRef`, `requested_node_ids: IdSet`, `resource_limits: ResourceLimits` | `realization_manifest: RealizationManifest`, `prepared_token: Id`, `closed_gate_receipt: ContentRef` | Negotiated; repeated ID is idempotent |
| `admit` | `bindings: array<NodeBinding>`, `world_binding_hash: HashRef`, `admission_receipt: ContentRef` | `accepted_binding_hashes: array<HashRef>`, `admission_id: Id` | Realized |
| `activate` | `admission_id: Id`, `activation_id: Id`, `world_generation: U64`, `prepared_token: Id`, `world_binding_hash: HashRef`, `gate_id: Id` | `staged: true`, `gate_id: Id`, `staged_owner_ids: IdSet`, `activation_receipt: ContentRef` | Admitted; does not open execution gate |
| `input` | `binding_hash: HashRef`, `owner_generation: U64`, `batch_id: Id`, `batch_sequence: U64`, `input_epoch: Id`, `events: array<Event>`, `batch_hash: HashRef` | `accepted_event_ids: IdSet`, `input_watermark: U64`, `custody_receipt: ContentRef`, `inventory_hash: HashRef` | Stopped or admitted running-input facet |
| `observe` | `binding_hash: HashRef`, `owner_generation: U64`, `after_observation_sequence: U64`, `maximum_items: U64` | `observations: array<ObservationBatch>`, `next_sequence: U64`, `complete: bool`, `inventory_hash: HashRef` | Admitted onward |
| `begin` | `kind: string`, `binding_hash: HashRef`, `owner_generation: U64`, `activation_id: Id or null`, `world_generation: U64`, `arguments: object` | Registered operation state and operation-specific immediate result | According to kind below |
| `poll` | `after_observation_sequence: U64` | `operation_id: Id`, `operation_state: string`, `outcome: object or null`, `observations: array<ObservationBatch>`, `next_observation_sequence: U64` | Existing operation |
| `cancel` | `reason: Id` | `cancel_requested: bool`, `operation_state: string`; eventual terminal result via `poll` | Existing operation |
| `quantum_close` | Section 6.8 fields | Accepted cut, stop receipt, inventory and observation commitments | A stopped quantized round |
| `world_activate` | Section 6.9 fields | Armed activation receipt, never an implicit run grant | Staged world/restore |
| `abort` | `transaction_id: Id`, `reason: Id` | `transaction_id`, `owner_ids: IdSet`, `cleanup_receipt: ContentRef`, `effect: string` | Unactivated staging |
| `retire` | `request_ids: IdSet`, `operation_ids: IdSet`, `disposition: string`, `custody_receipt: ContentRef or null` | `retired_request_ids: IdSet`, `retired_operation_ids: IdSet` | Terminal consumed outcomes |
| `blob_begin` | Section 6.10 fields | Registered transfer ID and accepted limit | Negotiated onward |
| `blob_chunk` | Section 6.10 fields | Accepted offset/length | Registered transfer |
| `blob_finish` | `transfer_id: Id` | Verified `ContentRef` | Complete transfer |
| `release` | `realization_id: Id` | `realization_id`, `owner_ids: IdSet`, `cleanup_receipt: ContentRef`, `released: bool` | Reaped/shut down owners only |

Pagination uses `discover` with optional `cursor: Id` returned by a prior page;
the provider MUST keep the page's immutable discovery generation fixed. A
controller MUST NOT infer absence from an incomplete page. The pagination
cursor is operational and does not enter a descriptor's identity.

An `observe` result can report transport custody, pending deadlines, stop
evidence, and effects already admitted by the node contract. It does not release
uncommitted effects. `complete` indicates complete enumeration through the
returned cursor, not that an owner has no pending work. Absence, unknown, and
an empty known inventory MUST remain distinguishable.

Accepted binding hashes sort by `(domain,digest)`. Owner-scoped `binding_hash`
uses `cnp.owner-binding.v1`; node-only observation uses `cnp.node-binding.v1`.
`begin` acceptance returns `operation_id: Id` and `kind: string`. Poll's
`operation_state` is `not_started`, `running`, `completed`, or `unknown`.
Its `outcome` is null until terminal; otherwise it is the original terminal
`begin` response body, including either `result` or `error`. Observations never
replace that retained outcome or its custody evidence. Observe/poll cursors use
the admitted owner observation stream, are captured, and cannot be reset by
opening another connection. `complete` with an empty array proves enumeration
only for the explicitly requested cursor range.

### Begin operation kinds

| `kind` | Required `arguments` | Terminal result |
| --- | --- | --- |
| `exact_run` | `GrantContext`, `start: Position`, `limit: Position`, `boundary_policy: string`, `input_authorization: ContentRef`, `input_watermark: U64` | `grant_id`, `reached: Position`, `stop_reason`, `stop_receipt`, `observation_batch`, `pending_inventory`, `next_attention: Bound` |
| `boundary_settle` | Same fields as `exact_run`; start and limit share one physical tick | Same terminal fields as `exact_run`, with completed phased input/output closure |
| `quantum_begin` | `GrantContext`, `quantum_index: U64`, `from_ps: Tick`, `until_ps: Tick`, `input_batch: ContentRef`, `input_watermark: U64`, `policy_hash: HashRef`, `wall_budget_ns: U64` | A physically acknowledged round stop, staged observations, pending inventory, and measured budget outcome; visibility commits only through close |
| `pause` | `participant_ids: IdSet`, `reason: Id` | `stop_receipt: ContentRef`, `physical_paused: bool`, `reached: Position or null`, `pending_inventory: ContentRef` |
| `capture` | `capture_id: Id`, `participant_ids: IdSet`, `cut_id: Id`, `cut: Position`, `event_ordinal: U64`, `ordering_profile: string`, `preservation_contract: Id` | `capture_manifest: ContentRef`, `owner_state_refs: array<ContentRef>`, `unchanged_cut_receipt: ContentRef` |
| `prepare_restore` | `transaction_id: Id`, `capture_manifest: ContentRef`, `expected_world_binding_hash: HashRef`, `expected_owner_binding_hash: HashRef`, `destination_owner_ids: IdSet` | Prepared restore token, complete validated binding inventory, state refs, closed-gate receipt |
| `shutdown` | `participant_ids: IdSet`, `reason: Id` | `observation_batch: ContentRef`, `pending_inventory: ContentRef`, `stopped: bool`, `reaped: bool`, `cleanup_receipt: ContentRef` |

`GrantContext` expands into `grant_id: Id`, `participant_ids: IdSet`,
`realization_id: Id`, `activation_id: Id`, `world_generation: U64`,
`owner_generation: U64`, `input_epoch: Id`, and `mode: string` (`exact` or
`quantized`), plus `ordering_profile: string` (`superdense-v1`). The provider
checks these against admitted live authority before progress. `boundary_policy`
is `ordinary_stop` or `input_blocked_park`; the
latter requires a qualified advertised facet. Grants cover `[from_ps,
until_ps)` for quantized execution and `[start, limit)` for exact execution;
stop coordinates do not implicitly prove inclusive input closure. Position
uses `(time_ps,microstep,phase)`. A physical ceiling H is represented by
`(H,0,0)`. Exact grants exclude every transition at or beyond their limit;
an administrative park at the limit executes no semantic work. Atomic native
work straddling a limit requires a preservable split or refusal before effects.
`boundary_settle` explicitly grants same-tick phase work after complete due
input authorization; ordinary parking is not such a grant.

Quantized terminal results contain `grant_id`, `quantum_index`,
`stop_receipt: ContentRef`, `observation_batch: ContentRef`,
`pending_inventory: ContentRef`, `budget_outcome: string` (`within_budget`,
`stall`, `timeout`, `fail`), and `physical_measurement_ref: ContentRef`.
Its stop receipt distinguishes physical pause from an observation window closed
while hardware continues, including actual budget overshoot and uncertainty.
Pause completion with `physical_paused: false` cannot satisfy a requested
physical-pause facet; unsupported physical pause is refused before acceptance.

`stop_receipt`, `observation_batch`, and `pending_inventory` are `ContentRef`
values with the schemas of the applicable node facet. Each includes its owner,
binding, operation/grant identity, and coordinate/cursor. A content ref to an
unknown receipt schema cannot establish exact stopping or input custody.
`stop_reason` is one of `ceiling`, `attention`, `input_required`, `output`,
`idle`, `canceled`, or `failed`; the receipt carries the more specific facet
reason. `next_attention` has the explicitly tagged `Bound` schema; unknown and
qualified no-output-until-activation claims are distinct.

The input watermark is the highest contiguous controller input batch sequence
accepted into the relevant owner custody. It does not authorize arrival of
events beyond a grant's boundary. The descriptor's input facet defines whether
delivery to a running owner exists; providers without that facet accept input
only at acknowledged stopped boundaries.

Input batches use a controller-origin stream scoped to execution owner and
`input_epoch`. Sequence begins at `"1"`; watermark `"0"` means no batch has
been accepted. A provider accepts only the next contiguous sequence or an
identical retry of a retained sequence. A gap is `INVALID_STATE`; a changed
batch at an existing sequence is `CONFLICT`. Capture preserves the complete
stream/custody state. A fresh incarnation or restored stream requires explicit
epoch rebinding and custody receipt; neither connection sequences nor a reset
to zero can discard previously accepted input.

- **[CN-IPC-21]** Baseline requests and terminal results MUST contain the
  fields above, the immutable semantic schemas they reference, and complete
  owner coverage. Missing required evidence is a protocol failure, not an
  invitation to substitute an approximate receipt.
- **[CN-IPC-22]** `input` completion proves retained input custody, not guest
  consumption. A repeated batch MUST NOT inject its events twice. Conflicting
  event IDs or batch hash reuse is rejected before further visibility.
- **[CN-IPC-23]** `exact_run` completion MUST establish a frontier no later
  than its ceiling and stop before any earlier possible input according to the
  admitted exact contract. Host timer expiration and a copied requested
  timestamp are not sufficient stop evidence.

## 6.8 Quantized operations and observation visibility

A quantized provider executes the closed policy selected for the world. It
does not relabel uncontrolled physical execution as exact stepping. Its
operation distinguishes authorized logical progress, actual physical activity,
and the publication boundary of staged effects.

`quantum_close` carries:

| Field | Type | Meaning |
| --- | --- | --- |
| `grant_id` | `Id` | Original quantum grant |
| `activation_id` | `Id` | Original admitted activation |
| `world_generation` | `U64` | Same committed generation as begin |
| `owner_generation` | `U64` | Same owner generation as begin |
| `input_epoch` | `Id` | Same input-custody epoch as begin |
| `quantum_index` | `U64` | Admitted quantum index |
| `participant_ids` | `IdSet` | Complete owner membership |
| `cut` | `Position` | Policy-authorized publication cut including phase/microstep |
| `policy_hash` | `HashRef` | Same quantization policy as begin |
| `observation_batch_hash` | `HashRef` | Exact staged batch controller accepts |
| `input_watermark` | `U64` | Input custody required at this close |
| `deadline_disposition` | string | `within_budget`, `stall`, `timeout`, or `fail` |

The result includes the same typed grant/index/cut/policy fields,
`activation_id: Id`, `world_generation: U64`, `owner_generation: U64`,
`input_epoch: Id`, a `stop_receipt: ContentRef`,
`committed_batch: ContentRef`, `pending_inventory: ContentRef`, and
`next_allowed_quantum: U64 or null`. The controller's world commit determines
when that batch becomes visible to peers. A provider cannot choose a later
boundary merely because it missed its wall budget.

- **[CN-IPC-24]** A provider MUST retain every staged observation with its
  original order and declared physical measurement limits until the controller
  commits or explicitly rejects the round. Polling transport data MUST NOT
  itself make a staged effect visible to other nodes.
- **[CN-IPC-25]** Close MUST reject a changed policy, grant, observation batch,
  cut, input watermark, or incomplete owner stop. The controller MUST NOT
  grant another round before the previous close outcome is known.
- **[CN-IPC-26]** A nonpausable physical device MUST report the admitted
  ongoing-activity policy and observation limitations. A stopped adapter is not
  evidence the hardware stopped. Such a provider cannot satisfy a preservation
  or execution guarantee that requires pausing the actual device.
- **[CN-IPC-27]** Missed budgets MUST follow the admitted stall/timeout/failure
  policy. CNP never permits retroactive input, silently shifted deadlines,
  dropped staged output, or speculative coordinator commitment followed by
  unsupported physical rollback.

## 6.9 Capture, restore, and global activation

Capture is owner-scoped and records the complete state domains once. Its
manifest binds implementation, model configuration, preservation contract,
cut/event ordinal, external ownership, and all content. An exact capture MUST
not drain, flush, warm up, replay, or execute extra model events merely to
obtain serializable state. Providers advertise weaker capture contracts
separately.

`prepare_restore` verifies all state content and compatibility before touching
the active world's state. It stages a destination behind a closed gate. Its
result contains `transaction_id`, `prepared_token: Id`,
`world_binding_hash`, `owner_binding_hash`, `staged_owner_ids: IdSet`,
`closed_gate_receipt: ContentRef`, and `validated_manifest: ContentRef`.
A preparation may allocate private inactive resources; failure must report
cleanup or quarantine custody without activating them.

`world_activate` contains `transaction_id: Id`, `activation_id: Id`,
`world_generation: U64`, `prepared_token: Id`, `world_binding_hash: HashRef`,
`gate_id: Id`, and `activation_manifest: ContentRef`.
The activation manifest lists the complete world transaction and prepared
tokens/owner bindings. Each provider verifies its membership and pre-arms its
staged owners, returning `armed_owner_ids: IdSet`, `gate_id: Id`, and
`activation_receipt: ContentRef`.

Fresh worlds obtain their prepared token from `realize`; restored worlds obtain
it from `prepare_restore`. `activate` stages fresh owners under their admission;
`world_activate` pre-arms the complete owner set for either path. The controller
commits the generation only after collecting every required receipt.
Its durable activation record includes the exact ready owner roster and gate
identity. An ordinary grant names that committed activation/generation; an
uncommitted, older, or revoked activation is `INVALID_STATE` or `STALE_SESSION`.

- **[CN-IPC-28]** A foreign implementation, state schema, model profile,
  capture contract, port binding, or owner coverage MUST fail preparation with
  `STATE_BINDING_MISMATCH` before destination state activation. Cross-provider
  conversion is a separate explicitly versioned operation creating a new root;
  CNP/1 restore MUST NOT perform it implicitly.
- **[CN-IPC-29]** Global activation is a controller transaction, not an atomic
  RPC spanning independent processes. The controller MUST validate every
  prepare and armed receipt, install the complete coordinator state, and only
  then open its global execution/input gate. Providers MUST NOT execute from
  `world_activate`; later grants reference the committed activation ID.
- **[CN-IPC-30]** Partial preparation, ambiguous activation, or cleanup failure
  MUST leave the replacement gated and affected resources quarantined. No
  surviving provider may resume a partially activated world. Abort is legal
  only before global activation commitment; afterward recovery requires a new
  controlled world transaction.

Exact capture and restore receipts are meaningful only with the qualification
and preservation contracts in Chapters 04, 05, and 08. A provider-generated
hash does not prove that hidden pipeline, queue, timer, PRNG, or physical device
state was included.

## 6.10 Content transfer and optional shared memory

Every CNP/1 implementation supports bounded inline content transfer. Transfers
are session/incarnation scoped and inert until the content is verified.

| Method | Required request fields | Result fields |
| --- | --- | --- |
| `blob_begin` | `transfer_id: Id`, `content: ContentRef` | `transfer_id`, `next_offset: U64`, `maximum_chunk_bytes: U64` |
| `blob_chunk` | `transfer_id`, `offset: U64`, `bytes: Bytes` | `transfer_id`, `next_offset: U64` |
| `blob_finish` | `transfer_id` | `transfer_id`, `content: ContentRef` |

The sender sends chunks in ascending contiguous offset order. An exact retry
at an already accepted offset is accepted only if its length and octets match;
conflicting retries return `CONFLICT`. A chunk beyond the declared content
length or negotiated maximum is rejected before writing. The receiver checks
the complete raw-octet digest and length at finish. Zero-length blobs have no
chunks. Baseline transfers permit controller-to-provider and provider-to-
controller exchange; the receiving endpoint exposes these methods in either
direction using IDs generated by the sender. The receiver owns the sender's
origin-scoped journal; responses echo transfer ID. Request and journal limits
apply independently in each direction. Provider-origin requests are restricted
to blob methods and `retire`; other baseline requests originate at the
controller.

Verified transfer bytes are pinned to their receiver-owned transfer record.
Finishing proves verified local possession, not durable publication or
permission to reclaim referenced state. An operation consuming the content
retains an explicit content pin. Retiring a transfer releases its transfer pin
only after custody has moved to a consuming operation or a durable admitted
store, or the sender explicitly abandons the inert transfer. Operation-result
content remains pinned until outcome retirement authenticates durable receipt
or transferred custody. `abort` releases only its transaction's staged pins;
unknown outcome pins remain quarantined. Repeated finish/abort/retire uses the
same identity and cannot release another owner's live pin. Quota failure cannot
silently evict pinned content.

- **[CN-IPC-31]** Content MUST NOT affect model state before finish verifies
  length, hash, and its consuming schema. Invalid or truncated content is
  discarded or quarantined as inert storage. A content hash never authorizes
  reading a host path or contacting a URL supplied by an untrusted provider.
- **[CN-IPC-32]** Transfer memory and disk usage MUST fit negotiated resource
  ceilings. A receiver MAY spool bounded content into a private admitted
  store; it MUST NOT allocate the declared complete length without quota.

The optional `cnp.local-fd/1` feature transfers file descriptors using
`SCM_RIGHTS` on the same Unix stream. An ancillary-bearing send begins at the
first byte of exactly one complete JSON frame. Its body contains a
`handle_manifest` listing indices, declared object type, access mode, byte
length, expected seals, content/region identity, and purpose. Receivers use
`recvmsg` for framing and retain the ancillary descriptors until the complete
matching frame is validated. Unexpected count, duplicate index, ancillary
truncation, or a descriptor on a frame without a handle manifest is fatal.

The handle manifest appears under
`body.extensions["cnp.local-fd/1"].handle_manifest`, never as an unknown
unnamespaced baseline field. It is an array sorted by descriptor index, with
`index: U64`, `object_type: Id`, `access: string` (`read_only` or `read_write`),
`length: U64`, `expected_seals: IdSet`, `identity: HashRef`, and `purpose: Id`.
Its negotiated object schema defines region/handle-specific proof requirements.

`cnp.local-fd/1` is an optimization, not baseline interoperability. A transfer
of a descriptor that cannot be independently authenticated does not qualify a
capture or native owner. Optional mapped memory additionally negotiates its
exact region schema/version, byte order, atomics, alignment, capacities,
offset arithmetic, initialization, publication, and restart rules.

- **[CN-IPC-33]** Receivers MUST validate descriptor object type, ownership,
  access mode, length, seals, and admitted purpose before use, set close-on-exec,
  and close all descriptors on refusal. They MUST NOT infer custody from a
  numerical descriptor value or accept arbitrary sockets/device handles as
  substitutes for a declared region.
- **[CN-IPC-34]** Shared memory MUST contain only the public versioned format:
  fixed-width fields, explicit tags, and checked offsets. Native pointers,
  function tables, QEMU structures, Rust enum/trait layouts, and process-private
  object references are forbidden. Every extent calculation MUST be checked
  against its declared region before access.
- **[CN-IPC-35]** Buffer/ring publication MUST preserve the admitted event
  key, input custody, output visibility, and backpressure semantics. A producer
  MUST NOT overwrite an unread slot or reinterpret a slot after changing its
  epoch. Restoring a region requires explicit epoch/owner rebinding and cannot
  silently reuse a live peer's old mutable mapping.

## 6.11 Error registry and events

Errors carry a bounded human-readable message (at most 4096 UTF-8 octets) and
machine-readable details. `effect` states what is known about the operation;
`retryable` permits retry of the **same identity**, never replacement execution.

| Code | Meaning |
| --- | --- |
| `INVALID_ARGUMENT` | Invalid field, integer range, schema, or arithmetic |
| `UNSUPPORTED_VERSION` | No admitted protocol/state schema version |
| `UNSUPPORTED_FEATURE` | Required facet or port protocol unavailable |
| `UNAUTHORIZED` | Missing or wrong authority, token, peer, or launch receipt |
| `STALE_SESSION` | Wrong session, provider incarnation, or revoked epoch |
| `UNKNOWN_NODE` | Node absent from admitted realization |
| `OWNER_MISMATCH` | Wrong owner or incomplete owner membership |
| `BINDING_MISMATCH` | Realized immutable binding differs |
| `STATE_BINDING_MISMATCH` | Capture cannot be restored into supplied implementation/profile |
| `INVALID_STATE` | Method violates lifecycle or physical stop prerequisites |
| `CONFLICT` | ID reuse, overlapping operation, or contradictory retained request |
| `RESOURCE_EXHAUSTED` | Admitted queue, byte, process, or journal limit exhausted |
| `DEADLINE_EXCEEDED` | Operational host deadline or admitted quantum budget expired |
| `CANCELED` | Authenticated terminal cancellation, with retained stop result |
| `OPERATION_RETIRED` | Previously consumed identity; cannot execute again |
| `OUTCOME_UNKNOWN` | Effect/completion cannot be established; quarantine required |
| `CONTENT_MISMATCH` | Content hash or length invalid |
| `PROTOCOL_ERROR` | Framed message violates CNP contract |
| `IMPLEMENTATION_FAILURE` | Provider/model failure with reported effect certainty |

Unknown codes are treated as `IMPLEMENTATION_FAILURE` with `effect: unknown`
unless their negotiated feature defines stronger handling. A syntactic error
that prevents trustworthy correlation closes the stream instead of issuing an
uncorrelated response.

Unsolicited events use `request_id: null`, the associated operation ID when
known, and `method: operation_update`, `observation_ready`, or
`provider_fault`. They contain only bounded notification metadata:
`operation_state`, `last_observation_sequence`, and `details`. `poll`/`observe`
retrieves the authoritative result. Event transport ordering is not modeled
event ordering. No unsolicited event can grant time or open a global gate.

- **[CN-IPC-36]** A provider MUST disclose ambiguous effects explicitly.
  Errors MUST NOT imply rollback unless all changed state and external effects
  are known undone under the admitted contract. The controller MUST fail closed
  when required exact evidence, event inventory, or cleanup custody is absent.

## 6.12 Trust, qualification, and resource security

The threat model includes malformed provider data, mistaken capability claims,
stale/incarnation-crossed requests, malicious guest-originated payloads,
resource exhaustion, unsafe host path/descriptor use, and external physical
activity beyond adapter control. The controller/broker, launch measurement,
qualification registry, and admission policy are trusted components.

- **[CN-SEC-1]** Local peer credentials MUST be checked against the admitted
  launch identity using the platform's trusted peer-credential interface. The
  launch token and nonce exchange MUST bind the connection to that admission.
  Tokens MUST NOT appear in logs, descriptors, content hashes, or scenario
  artifacts. A same-user socket peer alone is insufficient admission.
- **[CN-SEC-2]** Provider implementation claims, authenticated host launch
  receipts, and qualification evidence MUST remain distinguishable. Hashing or
  signing a claim authenticates its bytes/origin; it does not establish exact
  stopping, determinism, complete state capture, device parity, or accurate
  physical timestamp measurement.
- **[CN-SEC-3]** The broker MUST bind admitted capabilities to measured
  implementation/profile and applicable qualification. Self-advertised
  unsupported guarantees are refused. A nondeterministic provider MUST NOT be
  admitted to a mode requiring repeatable continuation merely because its
  messages are canonically ordered.
- **[CN-SEC-4]** A provider MUST run with admitted CPU, memory, writable
  storage, process, descriptor, observation, and operation limits before
  activation. Resource ownership MUST survive cancellation, failed reap, and
  quarantine until the responsible supervisor proves release safe.
- **[CN-SEC-5]** Host deadlines MUST remain operational measurements. They
  MUST NOT be inserted into exact event timestamps or interpreted as evidence
  of bounded simulated execution. Deadline failure follows the selected
  execution-mode policy and preserves effect ambiguity.
- **[CN-SEC-6]** The controller MUST treat provider/guest-supplied paths,
  filenames, media types, diagnostic strings, and content as untrusted. Host
  artifacts are resolved through admitted content stores or pinned handles;
  path traversal, unexpected devices, executable substitution, and implicit
  network fetches MUST be refused.
- **[CN-SEC-7]** External hardware access MUST be explicit in the descriptor
  and host admission, including nonpausable activity, shared physical state,
  timestamp uncertainty, irreversible effects, and unavailable restore.
  An adapter MUST NOT hide those limitations behind a modeled-node name.
- **[CN-SEC-8]** Diagnostics SHOULD redact secrets and bound disclosure.
  Private host paths, authentication material, guest memory, packets, and
  device data MUST NOT be published merely because an operation failed.
  Evidence retention and publication follow separately authorized policy.

## 6.13 License and implementation boundary

CNP is a public process protocol. Host-side semantic models, scheduling,
assertion evaluation, and campaign state remain outside QEMU's GPL process.
Implementation-specific code linked into or loaded by QEMU remains in its
applicable GPL-compatible scope. Integration uses the process boundary specified
by [RFC-0010](../0010-crucible/37-licensing-process-boundary.md).

- **[CN-SEC-9]** Apache-only host crates MUST NOT include QEMU headers, link
  QEMU, expose its callback entry points, or load QEMU implementation libraries.
  Neutral protocol and shared-memory components MUST remain usable without a
  QEMU implementation dependency.
- **[CN-SEC-10]** A broker translating CNP into QMP, control, or shared-memory
  protocols MUST preserve version/compatibility checks and license-boundary
  gates. Native host trait objects or pointers MUST NOT cross into a provider
  process as an alleged protocol optimization.
- **[CN-SEC-11]** Distribution of patched QEMU MUST retain the matching
  complete corresponding source and enforced suite publication policy. Adding
  a generic provider package or wrapper MUST NOT create a bypass. Each other
  provider's source/distribution obligations are reviewed independently.

- **[CN-SEC-12]** Before realization or restoration preparation, host policy
  MUST install explicit filesystem, network, and physical-device allowlists,
  minimize provider credentials and inherited descriptors, and confine writes
  to admitted private storage. Preparation MUST refuse external effects beyond
  that policy, including implicit network attachment or unadmitted device
  activation. Deployment can choose namespaces, sandboxing, or another
  enforceable mechanism; declaring an allowlist without enforcement is
  insufficient. Permitted preparation effects remain journaled and bounded.

The licensing and distribution requirements are specified by
[RFC-0010's process boundary](../0010-crucible/37-licensing-process-boundary.md).

## 6.14 Version evolution and conformance

`CNP/1` fixes this baseline envelope and transport. A breaking framing,
correlation, value representation, or baseline lifecycle change requires a new
major protocol. Compatible additional optional facets require exact versioned
feature negotiation. State formats and port formats version independently and
are bound in descriptor/binding identities.

- **[CN-IPC-37]** Unknown required fields/features or incompatible versions
  MUST fail before activation or destination mutation. A provider MUST NOT
  discard an unknown identity-bearing extension, reinterpret a foreign state
  blob, or infer compatibility from matching filenames or public node IDs.
- **[CN-IPC-38]** Implementations MUST pass protocol conformance vectors and
  adversarial cases in Chapter 08: partial frames, duplicate keys, integer
  boundaries, JCS identity, domain separation, retry conflicts, canceled but
  running operations, provider restart, incomplete inventories, descriptor
  misuse, content corruption, and partial world activation.

CNP conformance establishes interoperability and faithful reporting of the
declared interface. Qualification establishes the actual semantics of a
particular implementation/profile. Both are required before a provider can
satisfy the executor's stronger timing or state-preservation modes.
