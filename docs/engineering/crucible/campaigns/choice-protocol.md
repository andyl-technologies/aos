# Typed selectables and the choice protocol

Environment models, guest applications, the scheduler, and workloads expose
different effects but one exploration concept: a stable opportunity offers a
typed set of legal values, and the run records one selection. This page
describes that shared model. The campaign types live in
`crucible_campaign::choice`; the guest wire codec lives in
`crucible_qemu_protocol::selectable`, its deferred transport in
`crucible_qemu_protocol::selectable_transport`, and guest helpers in
`crucible-guest`.

## Declaration, offer, selection, application

1. A **selectable declaration** names a reusable schema, legal domain, default,
   units, and semantic tags.
2. A **choice opportunity** instantiates a declaration at one stable runtime
   coordinate and may narrow its domain.
3. A **selection** records the chosen value, the domain digest, and its
   origin.
4. A **typed consumer** applies the value: a network adapter changes frame
   treatment, a storage adapter changes an I/O outcome, or a guest receives a
   reply.

```text
environment adapter ----\
guest application -------+-> ChoiceOpportunity -> Selection -> typed consumer
scheduler / workload ----/
```

The selection engine knows the domain and campaign metadata, never how to
mutate QEMU or device state. It returns only a `ChoiceValue`: it never
receives a callback, pointer, QEMU object, guest address, or executable code.
Consumers validate the selection and apply it transactionally at the declared
opportunity phase.

`ChoiceSource` identifies the producer class:

| Source | Fields |
| --- | --- |
| `Environment` | Adapter implementation identity and typed effect target |
| `Guest` | Scenario node and guest choice protocol version |
| `Scheduler` | An explicitly explorable deterministic scheduler decision class |
| `Workload` | A scenario-declared workload input class |

A producer may only expose alternatives whose application respects the
deterministic scheduler, the adapter capability manifest, causal lookahead,
and scenario bounds. Ordinary deterministic event ordering does not become a
choice merely because a campaign would like to vary it. Guidance and candidate
generation treat all sources uniformly while preserving source identity in
evidence.

## Domains

```rust,ignore
pub enum ChoiceDomain {
    Boolean,
    Discrete(DiscreteDomain),       // stable AlternativeId -> label/description
    Integer(IntegerDomain),         // representation, min, max, step, unit,
                                    // scale, landmarks
    Group(Box<ChoiceGroup>),        // atomic tuple of member selections
}

pub enum ChoiceValue {
    Boolean(bool),
    Discrete(AlternativeId),
    Integer(IntegerValue),
    Group(ChoiceGroupValue),
}
```

- Integers are signed or unsigned 64-bit stored values computed with checked
  128-bit intermediates. Physical fixed-point quantities are integers plus a
  unit and an exact rational scale. Native floating point is not admitted.
- A value is legal when it lies within the inclusive bounds and
  `(value - minimum)` is divisible by `step`. Range cardinality is computed with
  checked arithmetic and is never enumerated.
- Landmarks are legal values suggested by the producer (defaults, timeouts,
  protocol thresholds, powers of two). They guide candidate generation but do
  not change legality or the semantic domain ID; they do change the exact
  stored `ChoiceDomainId`.
- A discrete alternative has a stable ID independent of display order or
  label. Reordering alternatives does not change meaning; changing an ID or the
  alternative set does.
- Defaults and landmarks must validate. Duplicate alternative IDs or
  landmarks, empty discrete domains, inverted ranges, and zero steps fail
  admission.

### Groups

Some selections must apply atomically, for example latency, loss, and duration
forming one network profile. A `ChoiceGroup` is a set of member declarations
with either an explicit finite tuple set or a Cartesian product of member
domains filtered by a finite list of typed relational constraints. It does not
execute arbitrary constraint code. Group canonical order is member selectable
ID order, every member domain must be a legal narrowing of its referenced
declaration, and an application either commits every member or none. Lazily
sampled tuples are validated against the complete constraints before
proposal publication.

## Opportunity identity

```rust,ignore
pub struct ChoiceOpportunity {
    scenario: ScenarioDefId,
    class: ChoiceClassId,
    source: ChoiceSource,
    declaration: SelectableId,
    declaration_semantics: SelectableSemanticId,
    domain: ChoiceDomainId,
    domain_semantics: ChoiceDomainSemanticId,
    coordinate: ChoiceCoordinate,
    instance: String,
    default: ChoiceValue,
    model_prior: Option<ProbabilityModelId>,
}
```

Replay reconstructs the identical exact opportunity ID and domain digest before
accepting a recorded selection. The guest-supplied instance key is a semantic
key such as a routing epoch or request ID. A process-global occurrence counter
is not acceptable because inserting an unrelated choice would shift every later
ID. When one declaration may be offered more than once at an otherwise
identical coordinate, the producer must supply a distinguishing instance key;
ambiguity fails closed. Adding an unrelated selectable, node, binding, or RNG
stream never perturbs the identity or sampling sequence of an existing
opportunity.

`ChoiceClassId` lets guidance statistics be shared across semantically
equivalent repeated opportunities. It derives from the declaration and stable
context tags, not from the runtime coordinate.

Discovering an opportunity does not imply that the parent configuration is
checkpointed or hot-fork eligible. Campaign projection pairs the opportunity
with its parent to form a branch point; realization capability is recorded
separately.

## Selection record

```rust,ignore
pub struct Selection {
    opportunity: ChoiceOpportunityId,
    domain: ChoiceDomainId,
    value: ChoiceValue,
    origin: SelectionOrigin,
}

pub enum SelectionOrigin {
    Default,
    ModelSample { model, stream, draw },
    CampaignBranch { branch_point, edge },
    LockedReplay,
}
```

A recorded selection contains everything needed to replay without consulting
campaign state or drawing randomness. Operator, planner, debugger, and
exhaustive provenance belongs to campaign facts (branch requests and
proposals), not to the modeled selection, which keeps two requests for one
value on one edge. The branch point is stored beside the edge so a closure
audit can recompute the edge without a planner object. Structural decoding
alone does not produce an executable selection: the opportunity and domain are
resolved and the origin-specific evidence is checked first.

The schedule codec records fault firing, RNG draws, overrides, preemption, and
typed selections in one canonical grammar. One configuration resolves at most
4,096 selection decisions. Repository resolution of selection, opportunity,
declaration, and domain bodies is one bounded batch (at most 128 MiB of unique
bodies), and a conservative 256 MiB bound on schedule-prefix work prevents
repeated deep clones of large schedules.

## Scenario declarations and runtime offers

Scenario authors declare environment selectables and expected guest
selectables. Environment adapters register their declarations during scenario
validation. A white-box guest registers its declarations during setup and
freezes its catalog at `setup_complete`; the host compares the registered
catalog with the scenario. Required declarations must match exactly. Optional
ones must still match the declared namespace, type, cardinality, and size
limits. A required mismatch stops the run before the ready point.

A runtime opportunity may narrow its declared domain (for example to the
recovery policies legal in the current protocol state), and the narrowed domain
is hashed into the opportunity. It may never broaden the declaration and must
still contain the scenario default.

For a node-qualified guest request the host derives two coordinates, where
`LP(s) = u64be(len(utf8(s))) || utf8(s)`:

```text
scheduler_coordinate = H("crucible.guest-selectable.scheduler-coordinate.v1",
                         LP(node) || u64be(trap_icount) || u32be(vcpu_index))
producer_coordinate  = H("crucible.guest-selectable.producer-coordinate.v1",
                         selectable_semantic_id || u32be(guest_protocol_version))
```

The transport sequence and guest reply address are operational continuation
data and never enter opportunity identity. A discovery attempt that stops at
`NextChoice` does not reply to or resume the guest. Deterministic
continuation replies with the scenario default. Thin replay consumes an
authenticated default, locked, or campaign-branch selection only at the
reconstructed exact opportunity.

## Guest wire protocol

The guest-host ABI has three version-1 messages. Integers are little-endian.
A `range` is `start:u32` followed by `len:u32`, relative to byte zero of the
message. Every message begins with:

```text
offset  size  field
     0     2  protocol_version : u16 = 1
     2     2  kind             : u16; 1 register, 2 request, 3 reply
     4     2  header_len       : u16; exact kind-specific size
     6     2  flags            : u16; closed per kind
     8     4  total_len        : u32
    12     8  sequence         : u64; registration order or request/reply ID
```

`SelectableRegisterV1` (56-byte header) carries dense ranges for the
selectable ID, canonical domain bytes, canonical default value, and
concatenated length-prefixed semantic tags, plus a tag count.

`SelectionRequestV1` (48-byte header) carries the selectable ID, instance key,
an optional narrowed domain (flag bit 0), and `request_end`. Bytes from
`request_end` to `total_len` are the reply reservation and must initially be
zero; `total_len` is the lent buffer capacity and is at least 96 bytes so a
typed rejection always fits.

`SelectionReplyV1` (96-byte header) carries a status, the 32-byte opportunity
digest, the 32-byte domain digest, and a selected-value range. Status values
are `0 Selected`, `1 UnknownSelectable`, `2 InvalidInstance`,
`3 InvalidNarrowedDomain`, `4 NoAdmissibleValue`, and `5 Unavailable`. The host
overwrites the request buffer with the reply and zeroes the unused tail. The
guest accepts it only when the reply sequence equals the request sequence.

Limits: every message is at most 4,608 bytes; identifiers, instance keys, and
tags are 1 to 128 bytes of ASCII alphanumerics plus `._-/:`; at most 32 tags,
strictly ordered and unique. Decoders reject unknown versions, kinds, flags,
or statuses, nonzero reserved data, non-dense, overlapping, or trailing
ranges, a dirty reply reservation, and any aggregate violation before
allocating. Golden vectors and truncation tests are part of
`gate:abi-conformance`.

Within one node generation, registration and completed-request sequences each
strictly increase, and at most one guest request owns a pending reply at a
time. A failed admission does not advance a sequence watermark.

### Deferred replies

A request is reply-bearing: the guest blocks at the doorbell until it receives
a value or a typed rejection. When the plugin cannot answer immediately it
records the request and trap coordinate, leaves the reservation zeroed, and
requests a VM stop at the following one-instruction boundary before another
guest instruction runs. It then publishes a `crucible.guest-selectable.pending-request`
record (magic `CRUCSPQ2`) on the lossless plugin-to-host white-box marker ring.
The host returns the authorized reply on a single-entry host-to-plugin ring;
the plugin checks the exact catalog incarnation, sequence, vCPU, trap, and stop
boundary, writes the reply into guest memory, and only then charges completion.
A queued but unconsumed reply is not checkpoint-ready.

This boundary is also a legal hot-fork point when the whole world supports it:
the world can be paused just before the reply, cloned, and given different
replies in sibling children. It remains a branch point when only exact restore
or thin replay is available.

Guest choice handling is side-effect-free except for the recorded request and
returned value until the guest resumes. A checkpoint at a pending choice
preserves the complete request, sequence watermarks, reply ownership, and ring
cursors so a fresh-process restore delivers exactly one reply.

### Catalog and setup plans

The launch-authenticated node catalog and its checkpoint continuation use the
`crucible.guest-selectable.catalog-plan` descriptor (magic `CRUCSCP4`,
big-endian). It records the frozen expected declarations, registered
identifiers, completed request counters, both sequence watermarks, and any
pending request with its icount, vCPU, guest virtual reply address, and
pre-instruction tick. The plan is at most 32 MiB; one node catalog holds at
most 4,096 declarations and one node run at most 1,000,000 completed requests.

The plugin `Setup` control message carries a sealed memfd containing the
`crucible.qemu-plugin.setup-plan` (magic `CRUCSUP2`), which concatenates the
application-random branch plan (at most 4 MiB) and the selectable catalog plan.
Byte layouts are documented on `crucible_qemu_protocol::selectable_catalog_plan`
and `crucible_qemu_protocol::plugin_setup_plan`.

No Rust-native layout, pointer, callback, or QEMU-private object crosses this
boundary.

### Guest helpers

`crucible-guest` provides `build_selectable_registration`,
`emit_selectable_registration`, `request_selection`, and
`request_typed_selection` over the architecture-specific doorbell transport,
plus group helpers. Black-box guests remain supported and expose no
selectables.

## Environment producers

Signal-fault bindings expose Boolean outcomes, finite transitions, and typed
parameters as choice domains at stable opportunities. Network latency and
loss, storage latency and errors, memory corruption, interrupt behavior, and
node lifecycle effects all use the same proposal interface, while their typed
adapters keep authority over target validity, phase, composition, and effect
application. The standardized search adapter is
`crucible.signal-fault-search.v1`; see
[hierarchical fault exploration](exploration.md#hierarchical-fault-exploration).

## Application randomness

Application-controlled randomness is an unsigned integer selectable with an
explicit uniform model, not a raw byte width. The QEMU plugin emits untrusted
`BackendRngEvidence`, because it holds no scenario or seed authority. The host
accepts it only when the scenario-seeded draw reproduces the served value, then
records the canonical `RngDraw` followed by a typed `Selection`.

The normalization contract (with `H` the campaign hash) is:

```text
choice_stream = H("crucible.app-random.choice-rng-stream.v1",
                  LP(engine_stream_domain) || LP(engine_stream_name))
model         = H("crucible.app-random.uniform-model.v1", u8(width_bits))
domain        = unsigned64 [0, 2^width_bits - 1], step 1
default       = 0
instance      = "request-" || lower_hex16(request_id)
sample        = raw_seeded_draw & (2^width_bits - 1)
```

Width is `1..=64`. The coordinates deliberately exclude schedule position and
occurrence counts. Branch generation is lazy: from one parent selection it
produces at most a configured 64 alternatives using a keyed hash
(`"crucible.app-random.branch.v3"`), omitting the observed value and
duplicates. There is no raw-width branch API.

## Admission limits

Scenarios declare nonzero ceilings, no greater than the hard maxima above, for
selectables per node and world, identifier and tag bytes, discrete
alternatives, landmarks and constraints, requests per selectable and per run,
message sizes, pending guest requests, and proposals per opportunity. Guest
declarations and requests are untrusted: every bound is checked before
allocation or iteration, and violations produce localized protocol evidence.
