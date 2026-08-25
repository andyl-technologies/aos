# 02 — Typed selectables and the shared choice protocol

Environmental models and guest applications expose different effects but the
same exploration concept: a stable opportunity offers a typed set of legal
values, and the scheduler records one selection. This file defines that common
model.

## 02.1 Declaration, offer, selection, and application

The protocol separates four steps:

1. A **selectable declaration** names a reusable schema, legal domain, default,
   units, and semantic tags.
2. A **choice opportunity** instantiates that declaration at one stable runtime
   coordinate and may narrow its legal domain.
3. A **selection** records the chosen value, domain digest, policy provenance,
   and any model-sampling evidence.
4. A **typed consumer** applies the value: a network adapter changes frame
   treatment, a storage adapter changes an I/O outcome, or a guest receives a
   reply.

```text
environment adapter ----\
guest application -------+-> ChoiceOpportunity -> Selection -> typed consumer
scheduler/workload ------/
```

The selection engine knows the domain and campaign metadata. It does not know
how to mutate QEMU or device state. Domain-specific application remains in the
validated adapter defined by RFC-0014.

- **[SEL-1]** Every explorable degree of freedom MUST be representable as a
  `ChoiceOpportunity` with a stable ID, versioned domain, default value, source,
  class, and semantic tags.
- **[SEL-2]** A selection engine MUST return only a `ChoiceValue`; it MUST NOT
  receive a callback, native pointer, QEMU object, guest address, or arbitrary
  executable code.
- **[SEL-3]** Typed effect consumers MUST validate the selection and apply it
  transactionally at the declared opportunity phase.

## 02.2 Choice domains

```rust,illustrative
pub enum ChoiceDomain {
    Boolean,
    Discrete {
        alternatives: Vec<DiscreteAlternative>,
    },
    Integer {
        representation: IntegerRepresentation,
        minimum: IntegerValue,
        maximum: IntegerValue,
        step: NonZeroIntegerMagnitude,
        unit: Option<UnitId>,
        landmarks: Vec<IntegerValue>,
    },
}

pub struct DiscreteAlternative {
    pub id: AlternativeId,
    pub label: String,
    pub description: Option<String>,
}

pub enum ChoiceValue {
    Boolean(bool),
    Discrete(AlternativeId),
    Integer(IntegerValue),
}
```

`IntegerRepresentation` declares signedness and canonical width. The first
implementation supports signed and unsigned 64-bit stored values with checked
128-bit intermediates. Physical fixed-point values are integers plus a unit and
scale declared by the schema. Native floating-point values are not admitted.

An integer value is legal exactly when it is within the inclusive bounds and
`(value - minimum)` is divisible by `step`. Landmarks are legal values suggested
by the producer because they correspond to defaults, timeouts, protocol
thresholds, powers of two, physical transitions, or other semantic boundaries.
They guide candidate generation but do not alter the legal domain or its
`ChoiceDomainSemanticId`; they do alter the exact stored `ChoiceDomainId` so
the generator input remains auditable.

A discrete alternative has a stable ID independent of display order or label.
Labels are user-facing annotations. Reordering alternatives does not change
meaning; changing an ID or adding/removing an alternative changes the domain
digest.

- **[SEL-4]** Choice-domain identity MUST be the digest of canonical type,
  bounds or alternatives, step, unit, and semantic version. Display-only text
  MAY be excluded only when the schema explicitly marks it non-semantic.
- **[SEL-5]** Integer range cardinality MUST be computed with checked arithmetic
  and need not fit in memory or be enumerable.
- **[SEL-6]** Every default and landmark MUST validate against the domain.
  Duplicate alternative IDs, duplicate landmarks, empty discrete domains,
  inverted ranges, and zero steps MUST fail admission.

## 02.3 Choice groups and constraints

Some selections must be applied atomically, such as latency, loss, and burst
duration forming one network profile. The model uses a `ChoiceGroup`, not a
general expression evaluator:

```rust,illustrative
pub struct ChoiceGroup {
    pub id: ChoiceGroupId,
    pub members: Vec<SelectableId>,
    pub admitted_tuples: ChoiceTupleDomain,
    pub application: GroupApplicationPolicy,
}
```

The initial implementation supports either an explicit finite set of tuples or
a Cartesian product of independent member domains with a finite list of typed
relational constraints (`equal`, ordered comparison, membership, and implication
over discrete tags). It does not execute arbitrary constraint code. A selected
group is recorded as an ordered set of member selections and applied in one
adapter transaction.

- **[SEL-7]** Group canonical order MUST be member selectable ID order, not
  authoring order. Every member domain MUST be validated as a legal narrowing
  of the exact referenced `SelectableDeclaration`; caller-supplied IDs and
  unrelated domains are not a valid group. A group application either commits
  every member or none.
- **[SEL-8]** Candidate generation MAY sample a large product lazily, but every
  yielded tuple MUST be validated against the complete declared constraints
  before proposal publication.

## 02.4 Stable choice-opportunity identity

```rust,illustrative
pub struct ChoiceOpportunity {
    pub id: ChoiceOpportunityId,
    pub semantic_id: ChoiceOpportunitySemanticId,
    pub class: ChoiceClassId,
    pub source: ChoiceSource,
    pub declaration: SelectableId,
    pub domain: ChoiceDomainId,
    pub coordinate: ChoiceCoordinate,
    pub instance: ChoiceInstanceKey,
    pub default: ChoiceValue,
    pub model_prior: Option<ProbabilityModelId>,
}
```

`ChoiceOpportunityId` is the exact stored record identity and retains the exact
declaration and offered-domain content IDs. `ChoiceOpportunitySemanticId`
replaces those fields with `SelectableSemanticId` and
`ChoiceDomainSemanticId`. Thus label, description, display ordering, or integer
landmark changes remain visible in storage/provenance without changing the
semantic branch point, edge, or resulting configuration.

Environment-originated opportunities use RFC-0014's stable
`FaultOpportunity` identity and typed target/operation/phase coordinate.
Guest-originated opportunities use:

```text
H(
  scenario,
  node,
  selectable declaration,
  guest-supplied logical instance key,
  scheduler coordinate,
  domain digest
)
```

The guest-supplied instance key is a semantic key such as routing epoch,
transaction ID, request ID, or algorithm phase. A process-global occurrence
counter is not sufficient because inserting an unrelated choice would shift all
future IDs.

`ChoiceClassId` allows guidance statistics to be shared across semantically
equivalent repeated opportunities without conflating unrelated choices. It is
derived from the declaration and stable context tags, not from the specific
runtime coordinate.

- **[SEL-9]** Replaying a schedule MUST reconstruct an identical
  exact choice-opportunity ID and domain digest before accepting the recorded
  selection. Semantic branch identity is separately reconstructed from the
  opportunity and domain semantic IDs.
- **[SEL-10]** A producer MUST supply an explicit stable instance key when the
  same declaration can be offered more than once at an otherwise identical
  coordinate. Ambiguity fails closed.
- **[SEL-11]** Adding an unrelated selectable, node, binding, or RNG stream MUST
  NOT perturb the keyed candidate or model-sampling sequence of an existing
  choice opportunity.

## 02.5 Selection record

```rust,illustrative
pub struct Selection {
    pub opportunity: ChoiceOpportunityId,
    pub domain: ChoiceDomainId,
    pub value: ChoiceValue,
    pub origin: SelectionOrigin,
}

pub enum SelectionOrigin {
    Default,
    ModelSample {
        model: ProbabilityModelId,
        stream: RngStreamId,
        draw: u64,
    },
    CampaignBranch {
        branch_point: BranchPointId,
        edge: BranchEdgeId,
    },
    LockedReplay,
}
```

The branch point is stored beside the edge so a repository closure audit can
recompute the edge from `(branch point, semantic domain, value)` without an
ambient planner object. Structural decoding alone does not return a validated
public `Selection`: resolving the exact opportunity and domain and checking
origin-specific evidence is the conversion boundary to an executable
selection. Model samples additionally require the named pure model verifier.

Operator, planner, debugger, and exhaustive provenance belongs to the
`BranchRequestCause` and `Proposal` facts in campaign knowledge, not to the
modeled selection. This keeps two requests for the same value on the same
semantic branch edge. A valid debugger selection override uses a debugger-
caused branch request; an arbitrary register or memory write remains a non-
canonical debug session and is not encoded as a `SelectionOrigin`.

Schedule V2 adds one canonical selection-decision envelope. Existing
fault-firing, RNG-draw, override, preemption, and application-random decision
variants remain readable and are not silently reclassified as selections;
producer-by-producer normalization remains implementation work. New campaign
configuration payloads write Schedule V2 and reject nested Schedule V1 at the
executor boundary. The general execution-model reader retains selection-free
Schedule V1 for older reproduction artifacts and scheduler continuations, but
rejects a selection tag under V1. Checkpoint V4 carries the expanded decision
grammar while selection-free Checkpoint V3 remains readable. Domain-specific
applied-effect evidence remains in the event log and adapter checkpoint state.
Campaign execution resolves no more than 4,096 selection decisions in one
configuration and permits at most 256 MiB of conservative aggregate
schedule-prefix byte work across campaign-branch provenance checks. The latter
is computed as encoded schedule bytes times campaign-branch selection count, so
it bounds repeated deep clones and hashes even when an early decision contains
a maximum-sized variable-length value. The resolver preflights both bounds in
one linear scan before repository reads; selection-free schedules therefore
remain linear in schedule length. Repository resolution is one bounded batch:
at most 128 MiB of unique canonical selection, opportunity, declaration, and
domain bodies are admitted, and repeated dependencies are decoded once and
shared across resolved selections.

- **[SEL-12]** A recorded selection MUST contain enough information to replay
  without consulting campaign state or drawing randomness.
- **[SEL-13]** Selection origin identifies the modeled delivery mechanism. Two
  selections of the same value at the same opportunity denote the same modeled
  branch even if different branch requests proposed them; request and proposal
  records remain distinct campaign facts while the branch edge and temporal-
  graph configuration deduplicate.

## 02.6 Scenario declaration and runtime offers

Scenario authors may declare environment and expected guest selectables:

```toml
[[selectable]]
id = "product.network.recovery-policy"
source = { guest = "router-a" }
type = "discrete"
default = "failover"
alternatives = ["hold", "withdraw", "failover"]
required = true

[[selectable]]
id = "environment.network.loss-bps"
source = { fault_binding = "uplink-disruption" }
type = "integer"
minimum = 0
maximum = 10000
step = 1
unit = "basis_points"
default = 0
landmarks = [1, 100, 1000, 5000, 10000]
```

Environment adapters register their declarations during scenario validation.
A white-box guest registers declarations during setup and freezes its catalog at
`setup_complete`. The host compares the registered catalog with the scenario.
Required declarations must exist exactly; unexpected declarations are rejected
unless an explicit scenario wildcard admits bounded dynamic selectables.

Dynamic choice opportunities may narrow a declared domain, for example to the
recovery policies legal in the current protocol state. The narrowed domain is
hashed into the opportunity. It may never broaden beyond the scenario
declaration.

- **[SEL-14]** Scenario admission MUST resolve all statically declared
  environment selectables and validate policy selectors before guest start.
- **[SEL-15]** A required guest selectable mismatch MUST stop the run before the
  ready point. Optional inline selectables MUST still match scenario-declared
  namespace, type, cardinality, and byte ceilings.

## 02.7 Guest protocol

The guest-host ABI adds three independently dispatchable version-1 messages.
Every multi-byte integer is little-endian. A `range` is two `u32` values,
`start` followed by `len`, relative to byte zero of the complete message. All
messages begin with this common prefix:

```text
offset  size  field
------  ----  ----------------------------------------------------------
  0      2   protocol_version : u16 = 1
  2      2   kind             : u16; 1 register, 2 request, 3 reply
  4      2   header_len       : u16; exact kind-specific fixed size
  6      2   flags            : u16; closed per kind
  8      4   total_len        : u32; complete message/buffer bytes
 12      8   sequence         : u64; registration order or request/reply ID
```

`SelectableRegisterV1` has a 56-byte header:

```text
offset  size  field
------  ----  ----------------------------------------------------------
 20      8   selectable_id : range
 28      8   domain        : range; canonical ChoiceDomain bytes
 36      8   default_value : range; canonical ChoiceValue bytes
 44      8   semantic_tags : range; concatenated u16-length UTF-8 tags
 52      2   tag_count     : u16
 54      2   reserved      : u16 = 0
```

Register flags are zero. The four body ranges are dense, in the listed order,
and end exactly at `total_len`.

`SelectionRequestV1` has a 48-byte header:

```text
offset  size  field
------  ----  ----------------------------------------------------------
 20      8   selectable_id  : range
 28      8   instance_key   : range
 36      8   narrowed_domain: range, or zero range when absent
 44      4   request_end    : u32
```

Request flag bit zero means a narrowed domain is present; every other bit is
reserved and zero. Present request ranges are dense, in the listed order, and
end at `request_end`. Bytes `[request_end, total_len)` are one exact mutable
reply reservation and MUST initially be zero. `total_len` is therefore the
lent buffer capacity, not merely the request-body length, and is at least 96 so
the host can always encode a typed rejection.

`SelectionReplyV1` has a 96-byte header:

```text
offset  size  field
------  ----  ----------------------------------------------------------
 20      2   status                : u16; closed table below
 22      2   reserved              : u16 = 0
 24     32   choice_opportunity_id : content-derived digest bytes
 56     32   domain_id             : content-derived digest bytes
 88      8   selected_value        : range, or zero range on rejection
```

Reply flags are zero. Status values are `0 Selected`, `1 UnknownSelectable`,
`2 InvalidInstance`, `3 InvalidNarrowedDomain`, `4 NoAdmissibleValue`, and
`5 Unavailable`; every other value is invalid. `Selected` carries one nonempty
dense value range ending at `total_len`. Rejections carry the zero range and
have `total_len == header_len`. The host overwrites the beginning of the lent
request buffer with this exact reply and clears every unused byte in the
reservation. The guest accepts it only when the reply sequence equals the
request sequence.

Within one node generation, accepted registration sequences and completed
request sequences each strictly increase in their own namespace. At most one
guest request may own a pending reply range at a time. A failed registration or
request admission does not advance its sequence watermark. Checkpoint restore
retains the frozen registered identifiers, both sequence watermarks, completed
per-selectable and total request counts, and the exact pending request and trap
coordinate when one exists; it does not infer continuation state from mutable
guest bytes alone.

The complete register, request buffer, and reply are each at most 4,608 bytes.
`selectable_id`, `instance_key`, and every semantic tag are 1..=128 bytes of
ASCII alphanumeric plus `._-/:`; tags are strictly byte-ordered, unique, and
limited to 32. Domains and values are nonempty canonical opaque bytes at this
transport layer. Decoders reject an unknown version, kind, flag, or status;
nonzero reserved data; an invalid identifier; non-dense, overlapping,
out-of-bounds, or trailing ranges; a dirty reply reservation; and any aggregate
bound violation before retaining allocation-sized fields. Byte-exact golden
vectors and truncation/allocation adversarial tests are part of
`gate:abi-conformance`.

The request is reply-bearing. The guest blocks at the doorbell until the host
returns a value or a typed rejection. This opportunity may also be a legal
hot-fork boundary when the complete world satisfies the advertised capability:
the world may be paused immediately before the reply, cloned, and given
different replies in sibling children. The opportunity still defines a branch
point when only exact restore or thin replay is available.

The plugin represents that boundary explicitly. Choice authority may return an
immediate reply or a `Pending` disposition. `Pending` retains the exact request
and trap coordinate, leaves the complete reply reservation zero-filled, and
requests native VMStop before another guest instruction is admitted. Catalog
freeze occurs before `setup_complete` becomes host-observable. On an exact
restore launch, throwaway boot-barrier registrations use a separate cold
incarnation; the VMState logical-restore boundary swaps a preallocated catalog
carrying the authenticated registered set, counters, sequence watermarks, and
pending request before acknowledging restore. Immutable declarations are
shared, but pending tokens are incarnation-specific and cannot cross the swap.

The wire protocol contains no Rust-native layouts, pointers, callbacks, or
QEMU-private objects. The version-1 codec is owned by
`crucible-protocol::selectable`; `crucible-guest` exposes typed emission and
reply-validation helpers over the architecture-specific doorbell transport.

The launch-authenticated node-local catalog and checkpoint continuation use the
independent `crucible.guest-selectable.catalog-plan` version-2 descriptor body.
Every integer is big-endian. Its 104-byte header is:

```text
offset  size  field
------  ----  ----------------------------------------------------------
  0      8   magic = "CRUCSCP2"
  8      4   schema_version = 2
 12      4   header_len = 104
 16      4   total_len
 20      4   flags: bit 0 frozen, bit 1 last registration present,
                  bit 2 last completed request present, bit 3 pending
 24      4   declaration_limit
 28      4   expected_declaration_count
 32      4   registered_identifier_count
 36      4   completed_counter_count
 40      8   requests_per_selectable_limit
 48      8   total_request_limit
 56      8   total_completed_requests
 64      8   last_registration_sequence, or zero when absent
 72      8   last_completed_request_sequence, or zero when absent
 80      8   pending_trap_icount, or zero when absent
 88      4   pending_vcpu_index, or zero when absent
 92      4   pending_request_len, or zero when absent
 96      8   pending_guest_virtual_address, or zero when absent
```

The header is followed by strictly identifier-ordered expected declarations,
registered identifiers, completed counters, and then the pending request when
present. An expected entry is `presence:u8` (`0 Optional`, `1 Required`), three
zero reserved bytes, `body_len:u32`, and one canonical sequence-zero
`SelectableRegisterV1`. A registered identifier is `len:u16 | bytes`; a
completed counter is `len:u16 | bytes | count:u64`. The pending body is one
complete canonical `SelectionRequestV1`, including its zero-filled reply
reservation. The process-neutral guest virtual address is the exact reservation
target restored by VMState; native pointers and QEMU-private objects never enter
the descriptor. Version-1 selection-free plans remain readable, but a version-1
plan carrying a pending request fails closed because it cannot identify that
reply target. The encoded total and per-collection counts are exact, absent
optional header fields are zero, every continuation identifier is declared,
every completed/pending identifier is registered, required frozen declarations
are present, request counts respect the encoded ceilings, and no trailing or
alternate encoding is accepted. The complete plan is at most 32 MiB.

Control-protocol v3 retains the three-descriptor `Setup` shape but changes the
third descriptor from the v2 raw app-random body to
`crucible.qemu-plugin.setup-plan` version 2. The descriptor is a regular memfd
sealed against write, growth, shrink, and further seal changes. Every integer is
big-endian, and its fixed 28-byte header is:

```text
offset  size  field
------  ----  ----------------------------------------------------------
  0      8   magic = "CRUCSUP2"
  8      4   schema_version = 2
 12      4   header_len = 28
 16      4   total_len
 20      4   app_random_plan_len
 24      4   selectable_catalog_plan_len
 28      A   canonical AppRandomBranchPlanV1 body
 28+A    S   canonical SelectableCatalogPlanV2 body
```

The two nested lengths exactly partition the descriptor body, each nested body
must pass its independent canonical decoder, and no trailing or alternate
encoding is accepted. The app-random body remains at most 4 MiB, the selectable
body remains at most 32 MiB, and the complete composite is at most 36 MiB plus
the 28-byte header. Negotiated v2 continues to mean the raw `CRUCABP1` third
descriptor and does not accept this composite encoding.
Selection-free version-1 composites remain readable for checkpoint/tooling
compatibility; new writes always use version 2.

Guest libraries expose typed helpers:

```rust,illustrative
register_discrete("network.recovery-policy", alternatives, default)?;
register_integer("network.retry-delay-ms", 0..=30_000, 1, 1_000)?;

let policy = choose_discrete("network.recovery-policy", routing_epoch)?;
let delay = choose_integer("network.retry-delay-ms", routing_epoch)?;
```

Black-box guests remain supported and expose no guest selectables.

- **[SEL-16]** Guest choice handling MUST be side-effect-free except for the
  recorded request and returned value until the guest resumes.
- **[SEL-17]** Checkpoints at a pending guest choice MUST preserve the complete
  request, protocol sequence, reply ownership, and shared-memory ring cursors so
  a fresh process restore receives exactly one reply.

## 02.8 Environment and scheduler producers

RFC-0014 fault bindings expose Boolean outcomes, finite transitions, and typed
parameters as choice domains at stable opportunities. Network latency/loss,
storage latency/errors, memory corruption targets/values, interrupt behavior,
and node lifecycle effects all use the same proposal interface. Their typed
adapters retain authority over target validity, phase, composition, and effect
application.

Scheduler preemption and workload inputs may also expose choice opportunities
when their existing deterministic contracts admit genuine alternatives.
Ordinary deterministic event ordering does not become a choice merely because a
campaign would like to vary it.

- **[SEL-18]** A producer MUST NOT expose an alternative whose application
  violates the deterministic scheduler, adapter capability manifest, causal
  lookahead, or scenario bounds.
- **[SEL-19]** The campaign layer MUST treat guest and environment opportunity
  sources uniformly for candidate generation and guidance while preserving
  source and typed-consumer identity in evidence.

## 02.9 Randomness as a selectable

Application-controlled randomness is represented as an integer selectable with
an explicit distribution. A convenience guest `random` API may construct such a
domain, but raw byte width is not the exploration model.

For campaign-enabled execution this section supersedes RFC-0010's live-schedule
use of `Decision::AppRandom`. That variant remains a readable legacy schedule
form and the plugin-to-host transport conjecture; it is not the canonical live
campaign decision admitted by the scheduler.

```text
random_u16(stream="backoff", instance=epoch)
  domain = integer [0, 65535]
  model prior = uniform
```

Campaigns may propose alternate values using the same bounded sampling budget
as any large integer domain. Replay returns the recorded integer.

The Crucible application-random producer uses the following version-1
normalization contract. Let `LP(s) = u64be(len(utf8(s))) || utf8(s)`, and let
`H(domain, bytes)` be `CampaignHash::derive` as defined by the campaign identity
schema.

```text
choice_stream = H("crucible.app-random.choice-rng-stream.v1",
                  LP(engine_stream_domain) || LP(engine_stream_name))
model         = H("crucible.app-random.uniform-model.v1", u8(width_bits))
domain        = unsigned64 [0, 2^width_bits - 1], step 1, scale 1, version 1
default       = unsigned64(0)
instance      = "request-" || lower_hex16(request_id)
sample        = unsigned64(raw_seeded_draw & (2^width_bits - 1))
```

For width 64 the mask is `u64::MAX`. Width is restricted to `1..=64`. The
declaration source is the requesting guest node under white-box doorbell
protocol version 3. Its class context is exactly `app-random` plus the
hex-encoded `choice_stream`; its semantic tags are exactly `app-random`,
`uniform-unsigned`, and `width-N`. The scheduler coordinate is
`H("crucible.app-random.scheduler-coordinate.v1", scenario_id || LP(node))`.
The producer coordinate is
`H("crucible.app-random.producer-coordinate.v1", choice_stream || u8(width))`.
These coordinates deliberately exclude schedule position and process-global
occurrence counts, so unrelated decisions and RNG streams do not perturb an
existing opportunity.

The engine adapter constructs and applies this typed contract, and the executor
resolves the declaration, domain, and opportunity and verifies the exact
low-bit mapping before accepting a model-sampled configuration. Other
probability models remain fail-closed. At a live scheduler boundary the
doorbell's untrusted legacy `AppRandom` transport record is accepted only when
the scenario-seeded raw draw reproduces its served value. The canonical
schedule then records `RngDraw` followed by the typed `Selection`, and the
quantum outcome carries the exact declaration, domain, and opportunity as one
self-contained discovery for observation publication. Event-kind catalog
version 6 registers the causal `campaign_selection` kind with the single
`canonical_selection` byte attribute, so the unified log admits the same strict
selection bytes.

Standardized model-sample selections consume the same scenario-hashed
app-random draw cap as retained legacy `AppRandom` decisions. A campaign branch
replaces the model sample at the exact parent after its `RngDraw`, emits a
`SelectionOrigin::CampaignBranch`, and remains chargeable because the parent
draw uses the reserved, strictly length-framed app-random stream namespace.
Checkpoint relaunch derives each node's continuation from that same
authoritative named-stream cursor rather than opaque selection bytes.

Branch generation is lazy: it accepts one exact parent, the observed typed
selection, and its validated discovery records, and generates at most the
configured 64 alternatives. It never scans or eagerly expands every random
request in a retained schedule. There is no raw-width `AppRandom` branch API.
Alternative index `i` uses this exact deterministic sampler, where `CH(domain,
bytes)` is the execution model's `ContentHash::from_canonical_hex_bytes`
operation and `low_u64_le` interprets the first eight digest bytes as a
little-endian integer:

```text
material = seed_32
        || LP(node)
        || LP(engine_stream_domain)
        || LP(engine_stream_name)
        || u64be(request_id)
        || u8(width_bits)
        || u64be(i)
value = low_u64_le(CH("crucible.app-random.branch.v3", material)) & width_mask
```

Indices are considered in ascending order from zero. The producer omits the
observed value and duplicate sampled values, so the result contains at most the
configured number of alternatives and remains deterministic even for narrow
domains.
Retained legacy entries remain readable and replayable only; campaign expansion
rejects them by requiring the typed selection/discovery basis. Operators that
need to explore such an artifact must re-execute its prefix through the live
producer to retain the canonical typed discovery. The broader migration policy
for other legacy explorable decisions remains required by T-CAM-2.3.

## 02.10 Admission limits

The scenario declares ceilings for:

- registered selectables per node and per world;
- identifier, label, tag, and description bytes;
- alternatives per discrete domain;
- landmarks and constraints per integer/group domain;
- requests per selectable and total requests per run;
- maximum choice message and reply bytes;
- pending simultaneous guest requests;
- candidate proposals per opportunity and per class.

The version-1 plugin implementation additionally caps one node catalog at 4,096
declarations and one node run at 1,000,000 completed requests. Scenario ceilings
MUST be nonzero and no greater than those hard maxima, and the per-selectable
request ceiling MUST be no greater than the total request ceiling. These limits
bound catalog maps, missing-declaration diagnostics, and continuation counters;
the scenario normally selects substantially smaller values.

- **[SEL-20]** Guest-controlled declarations and requests are untrusted input.
  All allocation bounds MUST be checked before allocation or iteration, and
  violations MUST produce localized protocol evidence and terminate according
  to scenario policy.
- **[SEL-21]** Discovering a `ChoiceOpportunity` MUST NOT imply that the parent
  configuration is checkpointed or hot-fork eligible. Campaign projection pairs
  the opportunity with its parent to form a `BranchPoint`; realization
  capability is recorded separately.
