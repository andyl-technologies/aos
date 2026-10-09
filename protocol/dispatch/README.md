# Dispatch language-neutral protocols

`worker.proto` is the private process contract between a supervising Rust runner
and a native solver. It is not a public remote session API. Cargo builds use
checked-in matching Prost derives; native builds generate C++ bindings from this
schema using their declared source-built Protobuf dependency.

Allocation semantics have version major one, minor zero. The independently
versioned worker protocol is also one, zero. Exact JSON schemas are published
for `Problem`, `Assignment`, `Evaluation`, `SolveRequest`, `SolveResult`, and
`BoundReport`. Structural JSON-schema validation
does not replace Dispatch's semantic model validation or independent evaluation.
`canonical.md` defines the complete commitment mapping. `vectors.json` provides
interoperability vectors.

## Worker channel

A frame is a four-byte unsigned big-endian length and that many bytes of
`WorkerEnvelope`. The initial maximum is 65,536 bytes. Both endpoints negotiate
finite frame and decoded-model limits. Zero, oversized, and truncated frames
fail the channel. JSON input is independently bounded for wire size, decoded
storage, nesting, string lengths, and entity collections before semantic
construction. A frame has at most 8,192 Protobuf fields and depth 32.

Protobuf serialization must use its canonical known-field encoding as produced
by the published bindings. Unknown fields, duplicate singular fields, multiple
oneof bodies, overlong varints, unknown enum alternatives, and alternate scalar
encodings are rejected. This intentionally prevents ordinary Protobuf
unknown-field skipping from weakening semantic requirements. Logs travel
separately from binary frames.

The supervisor issues a nonzero session generation and a worker generation
unique within that session. Replacement increments the worker generation.
Request identifiers are nonzero and strictly increase within the worker
generation. Replies echo all three identifiers. Generations and model
commitments bind prepared handles; a replacement makes its old handles stale.

The first request is `Hello`; the response is `Capabilities` or `ProtocolError`.
After successful negotiation, clients may prepare immutable input, solve
inline or prepared input, and release idle prepared handles. At most one solve
is active in a worker, including materialization and verification. Optional
progress and candidate events precede at most one terminal `Finished` response.
Any channel failure is an execution failure, never an infeasibility claim.

`SolveOptions` contains the original requested budget. An optional remaining
wall duration on `Solve` carries the reduced submission budget and is excluded
from request identity. The solver returns effective options separately.
Cancellation is externally enforced by terminating the worker tree. A native
backend may additionally advertise graceful cancellation, candidate streaming,
or incremental updates. Unsupported optional features must remain disabled.

All worker candidates are untrusted. A Rust runner independently evaluates
assignment JSON against the committed validated model before setting a
verification classification. Imported verification labels confer no authority
and must be checked again. Allocation observations do not become reservations,
execution permissions, or freshness proofs.

## JSON interoperability

All exact integers use canonical decimal strings, including small values.
Canonical rationals are reduced numerator/positive-denominator decimal strings;
zero has denominator one. Quantity parsing enforces the complete unsigned
64-bit range. Model input rational numerators fit signed 64 bits and denominators
fit unsigned 64 bits; evaluation arithmetic may produce wider exact results.
Schemas use patterns and range annotations; semantic decoders enforce exact
numeric maxima and references.

Duplicate object keys, including escaped aliases, unknown semantic fields,
floating-point representations of exact quantities, noncanonical integers, and
unreduced rationals are errors. Dicts carry opaque IDs and cannot acquire
semantics through a key's spelling. Fields may not silently disappear during
language translation.

`Evaluation.repair_debt` is sparse: an omitted valid repair component with both
zero debt and zero baseline means exact zero. Unknown components do not acquire
that meaning. Nonzero debt/baseline, selected objective components, and all
violations are explicit. This permits topology reports without an item-by-zone
zero matrix while preserving the full componentwise verifier semantics.

The optional public remote-session protocol is a separate contract. No worker
framing artifact advertises an available daemon, authenticated remote service,
durable retention, or exactly-once execution.

## Optional remote-session service

`session.proto` defines a separately versioned public service contract. A
deployment may implement it over authenticated RPC transport while consumers
continue to use application-owned sessions. Its publishing does not mean that
an installed worker listens on a network endpoint. The service does not import
or expose the private worker schema.

Initialization negotiates public and model versions, authenticates the caller,
and returns a finite resource grant and lease. Server policy selects authorized
profiles; clients cannot supply privileged process identities or cgroup paths.
Every reference is checked against authenticated caller ownership. Session,
prepared-input, and result retention are finite and ephemeral unless the server
explicitly grants durability.

Submitting a solve is asynchronous. The server admits it before retaining its
payload beyond negotiated limits, and returns immutable model/request digests.
The accepted wall duration bounds server execution without assuming synchronized
clocks; clients independently bound submission and waiting. Watching reports
ordered lifecycle events. Losing a watcher does not cancel the job. Clients can
retrieve its terminal result even after intermediate progress is discarded.

Cancellation may lose to completion. Exactly one terminal state is committed
per retained job; transport retries do not guarantee exactly-once execution.
When enabled, idempotency binds caller, session generation, token, and request
digest for the advertised retention interval. Matching retry returns the same
job; conflicting reuse fails. Expired tokens carry no deduplication promise.

RPC failures carry bounded `SessionError` Protobuf details in
`dispatch-error-bin` metadata. Invalid input maps to `INVALID_ARGUMENT`, version
or model incompatibility to `FAILED_PRECONDITION`, limits to
`RESOURCE_EXHAUSTED`, authorization to `PERMISSION_DENIED`, unavailable execution
to `UNAVAILABLE`, and absent references to `NOT_FOUND`. Stale/expired references
use `FAILED_PRECONDITION` with their specific typed code, after ownership checks.
Servers must not disclose whether another caller's protected reference exists.
