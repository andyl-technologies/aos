# 02 — Typed selectables and the shared choice protocol

Environmental models and guest applications expose different effects but the
same exploration concept: a stable point offers a typed set of legal values,
and the scheduler records one selection. This file defines that common model.

## 02.1 Declaration, offer, selection, and application

The protocol separates four steps:

1. A **selectable declaration** names a reusable schema, legal domain, default,
   units, and semantic tags.
2. A **choice offer** instantiates that declaration at one stable runtime
   coordinate and may narrow its legal domain.
3. A **selection** records the chosen value, domain digest, policy provenance,
   and any model-sampling evidence.
4. A **typed consumer** applies the value: a network adapter changes frame
   treatment, a storage adapter changes an I/O outcome, or a guest receives a
   reply.

```text
environment adapter ----\
guest application -------+-> ChoicePoint -> Selection -> typed consumer
scheduler/workload ------/
```

The selection engine knows the domain and campaign metadata. It does not know
how to mutate QEMU or device state. Domain-specific application remains in the
validated adapter defined by RFC-0014.

- **[SEL-1]** Every explorable degree of freedom MUST be representable as a
  `ChoicePoint` with a stable ID, versioned domain, default value, source,
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
They guide candidate generation but do not alter the legal domain.

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
  authoring order. A group application either commits every member or none.
- **[SEL-8]** Candidate generation MAY sample a large product lazily, but every
  yielded tuple MUST be validated against the complete declared constraints
  before proposal publication.

## 02.4 Stable choice-point identity

```rust,illustrative
pub struct ChoicePoint {
    pub id: ChoicePointId,
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

Environment-originated points use RFC-0014's stable
`FaultOpportunity` identity and typed target/operation/phase coordinate.
Guest-originated points use:

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
equivalent repeated points without conflating unrelated choices. It is derived
from the declaration and stable context tags, not from the specific runtime
coordinate.

- **[SEL-9]** Replaying a schedule MUST reconstruct an identical choice-point ID
  and domain digest before accepting the recorded selection.
- **[SEL-10]** A producer MUST supply an explicit stable instance key when the
  same declaration can be offered more than once at an otherwise identical
  coordinate. Ambiguity fails closed.
- **[SEL-11]** Adding an unrelated selectable, node, binding, or RNG stream MUST
  NOT perturb the keyed candidate or model-sampling sequence of an existing
  choice point.

## 02.5 Selection record

```rust,illustrative
pub struct Selection {
    pub point: ChoicePointId,
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
    CampaignProposal {
        proposal: ProposalId,
        policy: CampaignPolicyId,
    },
    LockedReplay,
    OperatorFork {
        command: CampaignCommandId,
    },
}
```

The implementation adds one canonical selection decision envelope to the
schedule. Existing fault-firing, RNG-draw, override, preemption, and
application-random decision paths are normalized through this envelope where
they represent a genuine selectable. Domain-specific applied-effect evidence
remains in the event log and adapter checkpoint state.

This is a schema-version change, not a parallel compatibility path. Old
artifacts are either migrated by an offline canonical converter with explicit
source provenance or rejected; the execution engine does not silently lower
two decision taxonomies at runtime.

- **[SEL-12]** A recorded selection MUST contain enough information to replay
  without consulting campaign state or drawing randomness.
- **[SEL-13]** Selection origin is provenance. Two selections of the same value
  at the same point denote the same modeled branch even if different campaign
  policies proposed them; proposal records remain distinct campaign facts while
  temporal-graph configuration identity deduplicates.

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

Dynamic choice offers may narrow a declared domain, for example to the recovery
policies legal in the current protocol state. The narrowed domain is hashed into
the point. It may never broaden beyond the scenario declaration.

- **[SEL-14]** Scenario admission MUST resolve all statically declared
  environment selectables and validate policy selectors before guest start.
- **[SEL-15]** A required guest selectable mismatch MUST stop the run before the
  ready point. Optional inline selectables MUST still match scenario-declared
  namespace, type, cardinality, and byte ceilings.

## 02.7 Guest protocol

The guest-host ABI adds three versioned messages:

```text
SelectableRegister
  protocol_version
  selectable_id
  canonical domain bytes
  default value
  semantic tags

SelectionRequest
  protocol_version
  selectable_id
  instance_key
  optional narrowed-domain bytes

SelectionReply
  protocol_version
  choice_point_id
  domain_id
  selected value
  status
```

The request is reply-bearing. The guest blocks at the doorbell until the host
returns a value or a typed rejection. This point is also a legal hot-fork
boundary: the world may be paused immediately before the reply, cloned, and
given different replies in sibling children.

The wire protocol uses fixed-width little-endian headers, checked offsets,
bounded UTF-8 identifiers normalized by the protocol, and explicit lengths. It
contains no Rust-native layouts, pointers, callbacks, or QEMU-private objects.

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

Scheduler preemption and workload inputs may also expose choice points when
their existing deterministic contracts admit genuine alternatives. Ordinary
deterministic event ordering does not become a choice merely because a campaign
would like to vary it.

- **[SEL-18]** A producer MUST NOT expose an alternative whose application
  violates the deterministic scheduler, adapter capability manifest, causal
  lookahead, or scenario bounds.
- **[SEL-19]** The campaign layer MUST treat guest and environment point sources
  uniformly for candidate generation and guidance while preserving source and
  typed-consumer identity in evidence.

## 02.9 Randomness as a selectable

Application-controlled randomness is represented as an integer selectable with
an explicit distribution. A convenience guest `random` API may construct such a
domain, but raw byte width is not the exploration model.

```text
random_u16(stream="backoff", instance=epoch)
  domain = integer [0, 65535]
  model prior = uniform
```

Campaigns may propose alternate values using the same bounded sampling budget
as any large integer domain. Replay returns the recorded integer.

## 02.10 Admission limits

The scenario declares ceilings for:

- registered selectables per node and per world;
- identifier, label, tag, and description bytes;
- alternatives per discrete domain;
- landmarks and constraints per integer/group domain;
- requests per selectable and total requests per run;
- maximum choice message and reply bytes;
- pending simultaneous guest requests;
- candidate proposals per point and per class.

- **[SEL-20]** Guest-controlled declarations and requests are untrusted input.
  All allocation bounds MUST be checked before allocation or iteration, and
  violations MUST produce localized protocol evidence and terminate according
  to scenario policy.
