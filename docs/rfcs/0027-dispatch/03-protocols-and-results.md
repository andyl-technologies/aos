# 7. Protocols and results

Dispatch exposes a language-neutral model and result contract. The Rust API,
command-line interchange, native backend workers, and optional remote execution
MUST preserve its semantics. Transport compatibility alone does not establish
model compatibility. The requirement words in this chapter have their
[BCP 14 interpretation](https://www.rfc-editor.org/rfc/rfc8174.html) when written
in uppercase.

## 7.1. Independent version domains

Three contracts MUST be versioned independently: the allocation model, the
private backend-worker protocol, and any public remote-session protocol.
`modelVersion` identifies the meaning of constraints, accounting, objectives,
and candidate classifications. Worker versions identify process communication.
Public versions identify authentication, grants, session operations, and result
retrieval. A compatible worker transport MUST NOT imply support for every model
version or backend feature.

Each version has unsigned 32-bit major and minor components. Major changes
MUST require explicit agreement; peers MUST NOT reinterpret an unknown major.
Minor additions MUST preserve established semantics and identify any newly
required capability. Unknown required fields, enum alternatives, constraints,
and objective types MUST cause rejection before solving. Receivers MAY ignore
only fields explicitly designated nonsemantic by the negotiated schema.

Before an interoperable version is released, Dispatch MUST publish complete
Protobuf schemas, the JSON mapping, canonical commitment mapping, capability
definitions, error registry, and cross-language test vectors. Schemas MUST
define field numbers, presence, defaults, identifier types, numeric ranges,
collection ordering, and extension handling. Removed field numbers MUST NOT be
reused. This chapter defines requirements for those artifacts; its message names
are not a substitute for their complete typed definitions.

## 7.2. Exact interchange and model commitments

The CLI MUST support typed JSON imports and exports for problems, assignments,
requests, evaluations, and results. Exact integers, including aggregate values
wider than 64 bits, MUST be encoded as canonical decimal strings, including
values small enough for JavaScript
numbers. Such strings contain no leading plus, exponent, whitespace, leading
zeros, or negative zero. Unsigned fields prohibit a minus sign. Exact rational
values MUST encode a signed numerator and positive denominator as decimal
strings, reduced to lowest terms; zero has denominator one. Consumers MUST NOT
convert these fields through binary floating point. Duplicate JSON object keys
and unknown semantic fields MUST be rejected.

Model identity MUST be calculated from the validated semantic representation,
not raw JSON, Protobuf serialization, or native memory. Canonical bytes MUST
use [RFC 8949 core deterministic CBOR](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1)
with definite lengths and shortest integer encodings. Dispatch additionally
prohibits floats, tags, indefinite-length values, duplicate map keys, and
undefined values. Schema-defined records use unsigned integer field keys;
arbitrary application maps MUST be converted to ordered entry collections.
Strings retain their exact valid UTF-8 bytes without Unicode normalization.
Rational fields use pairs of the canonical decimal strings defined above.

The published mapping MUST assign every field a unique representation.
Defaults MUST be materialized; absent optional fields MUST map to explicit
null. Semantically unordered collections MUST be sorted by their published
canonical keys, with duplicates rejected. Ordered objective tiers MUST retain
order. The mapping MUST NOT depend on host endianness, hash-table iteration,
locale, or the order of equivalent JSON members.

The model commitment is exactly:

```text
SHA256(ASCII("dispatch:model") || 0x00
       || U32BE(modelVersion.major) || U32BE(modelVersion.minor)
       || canonicalModelBytes)
```

It MUST include identifiers, quantities, eligibility, topology, constraints,
objectives, observation basis, observed assignment, and declared concurrent
occupancy. It MUST exclude display labels, tracing metadata, submission tokens,
search hints, and execution options. Excluded annotations MUST NOT affect
evaluation or compilation. Including an observation reference binds the answer
to that supplied reference; it does not authenticate its source or freshness.

Request identity is separately committed:

```text
SHA256(ASCII("dispatch:request") || 0x00 || canonicalRequestBytes)
```

The published request mapping MUST include the model commitment, request-schema
version, operation, backend selection policy, hint, seed policy, requested
limits, and semantic options. Submission tokens and transport correlation IDs
MUST be excluded. Results MUST record the resolved backend and effective limits
separately when authorization or negotiation changes requested values.

## 7.3. Private worker framing and bounds

The private worker channel MUST carry Protobuf envelopes over a supervised
Unix-domain stream or inherited pipes. Each frame consists of a fixed four-byte
unsigned big-endian payload length followed by exactly that many bytes. Zero
length, a length exceeding the negotiated maximum, truncated frames, invalid
envelopes, and illegal state transitions MUST fail the channel. Logs MUST use a
separate bounded channel and MUST NOT be mixed into protocol output.

Before negotiation completes, the maximum frame payload is 65,536 bytes.
Negotiation MAY select a different finite limit no greater than either peer's
advertised bound or the framing range. A receiver MUST check lengths before
allocating a payload buffer. Compression is not part of the base framing.

Limits MUST separately bound decoded bytes, string lengths, items, targets,
dimensions, group memberships, candidate-domain entries, sparse overrides,
constraints, objectives, nesting depth, prepared inputs, and diagnostic output.
Compact input MUST NOT authorize unbounded expansion. Receivers MUST enforce
these limits during decoding and construction, not only after materialization.
Limit exhaustion MUST return an explicit resource or unsupported-model error
where the channel remains usable; it MUST NOT imply infeasibility.

An optional incremental-upload capability MAY carry bounded ordered data frames
with a declared total size, upload identity, and final commitment. The receiver
MUST bound concurrent uploads and their retained bytes, reject discontinuities,
and discard incomplete input on expiry. Solving MUST await complete validation.
Worker messages MUST NOT name arbitrary temporary files or contain native
pointers, function references, process-private handles, or executable callbacks.

## 7.4. Negotiation and correlation

`Hello` MUST be the first exchange. It identifies the owning session generation,
supported worker versions, model versions, resource bounds, and requested
optional capabilities.
`Capabilities` MUST confirm the selected versions and limits, backend identity,
backend build identity, the owning session generation, and a new worker
generation. A backend build identity MUST identify the compiler adapter and
native solver build, not merely a
human-readable release name.

Capabilities MUST describe supported constraint and objective combinations,
numeric envelopes, optional candidate streaming, graceful cancellation,
incremental updates, and preparation behavior. Provider guarantees such as hard
termination and memory containment MUST be negotiated independently of backend
search features. Negotiation MUST reject required capabilities it cannot meet.

Each subsequent envelope MUST carry the selected worker version, session and
worker generations, and request correlation identifier. Correlation identifiers
MUST be unique within the worker generation. Responses and events MUST echo the
relevant identifier. A peer MUST reject stale generations and mismatched responses.
Local process identity or a reused socket path MUST NOT substitute for this
generation binding.

## 7.5. Preparation, solving, and release

The worker protocol MUST provide these operations:

| Message | Required meaning |
|---|---|
| `Prepare` | Validate and retain bounded immutable problem input |
| `Solve` | Execute against inline or prepared input with explicit options |
| `Progress` | Optional bounded execution observations |
| `Candidate` | Optional untrusted intermediate assignment |
| `Finished` | Terminal backend outcome and optional candidate |
| `Release` | Release an idle prepared input |

Preparation responses MUST include the model commitment and an opaque handle
bound to session and worker generations and negotiated semantics. A prepared
handle promises retained input, not a native expression graph or resumed search
state. A worker
MUST execute at most one active solve, including input materialization. The
provider MUST retain that worker slot through result verification. Preparation
and release MUST NOT mutate input used by an active solve.

Worker-local handles MUST NOT outlive the worker generation. Session-input
handles are a runtime facility and MUST be materialized or uploaded into a
fresh worker before that worker can use them; they are not interchangeable with
private backend handles.

`Solve` MUST bind the model and request commitments and specify remaining
execution limits. It MUST identify whether a seed is explicit, selected by the
backend, or unsupported. Effective options MUST be returned in provenance.
Supplying a seed MUST NOT promise bit-identical replay: parallel search,
wall-time budgets, native builds, and host scheduling can change results.

Optional incremental updates MUST create a new immutable model revision and
commitment. They MUST NOT alter an in-flight problem. Unsupported streaming,
updates, or cooperative cancellation MUST NOT be simulated by weakening the
public contract. `Progress` is observational; `Candidate` remains untrusted
until independent verification. Neither message confers application authority.

## 7.6. Deadlines and cancellation

The supervising runtime MUST own hard cancellation by default. It MUST enforce
the provider's deadline outside the native solver and terminate the worker tree
when the advertised guarantee requires it. A killed worker MUST NOT be reused.
Its worker generation and worker-local prepared handles MUST be invalidated;
session-input handles retain the lifetime defined in Section 6.7.

A negotiated graceful-cancellation capability MAY add a cancellation message.
Cooperative acknowledgement MUST NOT disable the external hard deadline.
Providers unable to terminate embedded or remote work MUST report that
limitation in their grant and reject profiles requiring hard termination.

A worker MUST emit at most one `Finished` for an accepted solve and MUST emit
no later solve events for that request. The supervising runtime MUST arbitrate
one terminal decision across completion, cancellation, deadline, and failure.
Channel loss caused by an intentional cancellation or deadline termination
MUST retain that cause; unexpected channel loss MUST become execution failure.
Later observations MUST NOT replace a committed terminal decision. Event
buffering MUST remain bounded; lost optional progress MUST NOT prevent terminal
delivery during the granted retention interval.

Remote deadline propagation MUST use remaining durations rather than assume
synchronized clocks. Transfer, queueing, startup, search, verification, and
result construction MUST consume the submission budget. A remote server MUST
report its accepted duration; the client MUST independently bound its waiting.
Verification MUST NOT silently extend an expired deadline. A candidate already
verified before the terminal decision MAY accompany a limit or cancellation
outcome.

## 7.7. Lifecycle, candidate classification, and evidence

A solve has lifecycle states `Queued`, `Running`, `Verifying`, and `Terminal`.
Admission rejection creates no queued entitlement. A terminal record MUST
separate three axes:

| Axis | Values or required distinction |
|---|---|
| Termination | Completed, limit reached, cancelled, rejected, execution failed |
| Candidate | Absent, rejected, verified fully feasible, verified repair proposal |
| Search evidence | None, local search exhausted, backend-reported bound, backend-reported infeasibility, backend-reported optimality |

Verification MUST use the exact committed validated problem and independently
recompute constraints, repair envelopes, resource accounting, deltas, and exact
objective values. A worker-provided `verified` flag MUST NOT be trusted.
Serialized artifacts MUST be re-evaluated before becoming locally verified
plans. Explicit trust in an authenticated remote verifier MAY produce a
separately classified trusted-remote result under Section 12.1; importing data
MUST NOT establish that trust policy. A backend answer
that violates Dispatch semantics MUST be rejected even if native tolerances
accept it.

Timeout, OOM, crash, startup failure, malformed output, cancellation, and
failure to find a candidate MUST NOT become infeasibility. Repair proposals
MUST NOT be classified as fully feasible. Backend bounds and gaps MUST identify
objective tier, units, candidate-domain restrictions, transformation or
quantization, effective tolerance, and build provenance. A scalar gap MUST NOT
be presented as a bound on an entire lexicographic objective unless that
interpretation is established.

Independent assignment checking establishes feasibility, not optimality or
infeasibility. A stronger evidence classification requires a separately defined
certificate format and checker. Explanations MUST distinguish evaluated
violations from search heuristics and backend claims.

## 7.8. Result binding and provenance

Every admitted job's terminal result MUST carry its job identity, session
generation, termination, candidate classification, and search evidence. It MUST
report model and request commitments, observation basis, worker generation,
backend build identity, effective options, seed policy, and resource grant when
those facts have been established. Fields unavailable because execution ended
earlier MUST have typed unavailability reasons; they MUST NOT be invented,
encoded as zero, or confused with successfully negotiated defaults. A validated
model MUST have its commitment, and a verified candidate MUST additionally bind
its complete assignment, evaluation, movement delta, repair debt, and evaluator
version.

A submission rejected before admission MUST return a structured rejection
without implying a queued job or resource entitlement. Malformed model input
MUST NOT acquire a semantic model commitment. A caller-provided claimed digest
MUST NOT be reported as validated provenance until checked.

Timing and resource reports SHOULD distinguish queueing, startup, transfer,
construction, search, verification, CPU time, and wall time. Missing measurements
MUST be explicit rather than encoded as zero. Bounded diagnostic truncation
MUST be marked. Provenance MUST identify restrictions introduced by candidate
pruning or backend compilation.

A verified answer describes the supplied observation basis. It MUST NOT claim
reservation, execution permission, transition safety, current membership, or
distributed ownership. Importing, retaining, or caching a result MUST NOT
refresh that basis. Re-evaluation against a changed problem creates a new
verification binding.

## 7.9. Optional public remote sessions

A remote provider MAY expose a separately versioned Protobuf service over
authenticated transport. Its public API MUST cover initialization and grants,
validation, evaluation, bounded preparation, solve submission, state inspection,
watching, cancellation, result retrieval, release, and explicit session close.
It MUST NOT expose the private worker socket as an unauthenticated public API.
Local library and CLI execution MUST remain usable without this service.

Caller authorization MUST scope sessions, jobs, prepared handles, and results.
Identifiers are references, not bearer authority. Limits and leases MUST be
server-issued. Session expiry MUST stop admission and initiate bounded cleanup.
Prepared handles and results MUST advertise expiry and retention; retention
MUST NOT imply durability across restart unless separately granted. Stale,
expired, unauthorized, and unavailable references MUST have distinct documented
handling without exposing another caller's protected data.

Dropping a watcher MUST NOT cancel work. Close and cancellation races MUST
publish at most one terminal state per job. Transport retries MUST NOT be
described as exactly-once execution. Optional idempotency MUST bind authenticated
caller, session generation, token, and request commitment for an advertised
finite retention interval. Matching retries MUST retrieve the same job;
conflicting token reuse MUST be rejected. After expiry, callers MUST NOT assume
deduplication. Public streaming MUST preserve event order and provide terminal
retrieval even when intermediate progress was lost.
