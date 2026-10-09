# 5. Assignment model

Dispatch models finite resource-assignment problems. A problem describes what
may be placed, where it may be placed, the resources and policies governing
placement, and the preferences used to compare answers. Its meaning is
independent of a solver algorithm or implementation language.

The model MUST NOT contain executable callbacks, native solver objects, native
pointers, or an opaque mathematical program whose meaning only a backend can
evaluate. Domain observations MUST be projected into portable data before
submission. Dispatch does not discover membership, decide observation
freshness, acquire resources, or establish execution authority.

## 5.1. Problem identity and finite assignments

A problem contains finite collections of items, targets, dimensions, groups,
target scopes, candidate domains, constraints, and objective tiers. It also
contains an observation basis and an observed assignment. Each collection
member MUST have an opaque identifier unique within its entity kind. An
identifier MUST NOT derive meaning from its spelling, ordering, or similarity
to another identifier. All references MUST resolve within the problem.

An item is an atomic placement unit. An assignment MUST bind every item exactly
once to either a target or `Deferred`. Replicas and shards are distinct items;
an item cannot simultaneously satisfy obligations at several targets. Groups
express relationships between such items without changing their identity.

An item declares whether deferral is permitted. `Deferred` is a decision, not a
target: it consumes no placement capacity, satisfies no locality requirement,
and does not count as a distinct failure domain. A mandatory item MUST be
assigned to an eligible target. Missing bindings, duplicate bindings, and
unknown identifiers are malformed answers rather than implicit deferral.

The observed assignment uses `Unplaced` for an item with no existing placement.
For comparison purposes, `Unplaced` corresponds to candidate `Deferred`, but
does not make deferral permissible. A previously absent mandatory item still
requires placement in a fully feasible answer.

The validated problem is immutable. Any change to quantities, membership,
policies, observations, or preferences creates a new problem identity. The
canonical encoding and domain-separated digest defined by the protocol chapter
MUST identify the complete semantic problem. Search options and warm-start
hints are separate request data and MUST NOT silently alter that identity.

## 5.2. Dimensions, units, and accounting

A dimension defines a nonnegative quantity with an explicit unit and integer
quantum. Examples include bytes, thousandths of a CPU, worker slots, and units
of transfer cost. Unit names are descriptive; consumers MUST provide quantities
already expressed in the declared quantum. Evaluators MUST NOT infer conversion
rates from unit names or mix dimensions without an explicit objective
normalization.

Resource quantities, finite capacities, and individual demands MUST fit an
unsigned 64-bit integer. Aggregation and comparison MUST use exact arithmetic.
An implementation MAY use wider integers, but MUST detect overflow whenever
its representation is bounded. Wrapping, saturation, floating-point rounding,
and dropping small demands are prohibited. Numeric exhaustion MUST produce an
explicit error; it MUST NOT produce a feasibility result.

Input rational coefficients MUST have a signed 64-bit numerator and positive
unsigned 64-bit denominator, reduced to lowest terms. Aggregate loads, costs,
and objective intermediates MAY require larger representations. Their
interchange form MUST be exact decimal strings or rational pairs as specified
in Section 7.2. Implementations MUST publish their evaluation-size bounds and
distinguish numeric exhaustion from malformed input and backend incompatibility.

Every charged item-dimension pair MUST define a demand for each eligible
target. A demand can be shared across all targets or vary by target. The
representation MAY use defaults with sparse overrides, but missing demand
MUST NOT implicitly mean zero. An explicit zero demand is permitted. A target
capacity is either finite or explicitly unbounded; an omitted finite limit
MUST NOT implicitly mean infinity.

Observed source charges MUST also be defined, even when the observed target is
no longer eligible. They represent historical occupancy and MAY differ from
the proposed demand for retaining an item on that target. A source charge is
zero for `Unplaced`. Historical charges MUST NOT be erased by candidate-domain
pruning. Fixed load MUST be defined per target and dimension; the fixed load
of a target set is the exact sum over its distinct targets.

For a target set `S`, dimension `d`, and final assignment `a`, resource load is:

```text
load(S, d, a) = fixed_load(S, d)
             + retained_extra_load(S, d)
             + sum(demand(i, a(i), d) for placed i with a(i) in S)
```

Fixed load represents consumption outside the modeled placement decisions. It
MUST NOT duplicate item consumption. Retained extra load contains additional
holdings classified as retained under Section 5.5. Each item contributes once
to each applicable target set, regardless of how many labels it shares with
that set.
Overlapping sets deliberately impose separate constraints over shared demand;
their totals MUST NOT be added together as a purported physical fleet total.

Hierarchical grants, reservations, and measured use MUST be projected into a
specified accounting basis. A consumer MUST NOT charge both an inclusive
parent grant and the same child consumption as independent demand. Dispatch
checks the submitted accounting model; it cannot establish whether that model
accounts for every physical consumer.

## 5.3. Candidate domains and topology

A candidate domain is a finite set of target identifiers. Several items MAY
reference the same domain. Set operations, shared sets, and sparse demand or
cost overrides MUST have the same semantics as their finite expanded form.
Implementations SHOULD preserve these representations rather than require a
dense item-by-target matrix.

Eligibility restricts final choices, not historical observations. An observed
target MAY be ineligible for further placement. It MUST remain represented if
its identity, demand, or occupancy is needed for accounting. Removing a target
from membership MUST NOT silently erase current resource consumption.

Topology contains named target sets and scope families. A named target set MAY
overlap other sets. A scope family, such as host, rack, or zone, partitions all
targets: every target belongs to exactly one member of that family. Missing or
overlapping membership is invalid. A consumer MAY explicitly model an unknown
domain, but MUST NOT treat it as several independent domains.

Topology carries submitted relationships only. A label called `zone` is not
evidence that two targets have independent failure modes. Constraints select
the particular scope family whose separation matters; they MUST NOT implicitly
substitute target separation for host or zone separation.

## 5.4. Groups, admission, and spread

A group is a finite set of distinct item identifiers. Groups MAY overlap. A
group's admitted count is the number of its members bound to real targets.

An admission constraint provides inclusive minimum and maximum admitted
counts. An atomic admission constraint additionally requires either zero
admitted members or every member admitted. Atomic admission does not require
co-location and does not authorize coordinated execution. Combining atomic
admission with a positive minimum requires all members to be admitted.

A spread constraint identifies a group and scope family. It defines a minimum
number of distinct occupied scope members and an optional maximum number of
admitted group items per scope member. Only placed items contribute. For an
empty admitted group, the occupied-domain count is zero. A requirement that
applies only when a group is admitted MUST explicitly declare that condition,
meaning that its admitted count is greater than zero;
otherwise its minimum applies even to the empty group.

A co-location constraint requires all admitted group members to occupy one
member of a declared scope family. Zero or one admitted member satisfies this
relation. Requiring an entire group to run together therefore needs both
co-location and the appropriate admission constraints.

These definitions distinguish three commonly confused statements: all replicas
must exist, replicas must occupy distinct targets, and replicas must occupy
distinct failure domains. Each requires its own declared constraint.

## 5.5. Observations, hints, and concurrent occupancy

The observed assignment defines the baseline for movement, fixed placement,
and repair debt. The observation basis binds it to opaque consumer revisions.
Dispatch MUST preserve that basis in verified outputs, but MUST NOT interpret
the revisions as leases, freshness proofs, or consensus terms.

A warm-start hint is an optional structurally well-formed assignment used to
guide search. It MAY violate constraints. It MUST NOT replace the observed
assignment, determine repair debt, or acquire the status of a verified answer
without evaluation.

Movement accounting MUST distinguish new placement, relocation between real
targets, and retirement to `Deferred`. A movement budget or objective MUST
declare the categories it charges and their costs. It MUST NOT hide retirement
inside a relocation-only metric. Target-dependent movement costs MUST define
their value for every applicable source and destination combination, including
the applicable unplaced and deferred cases. Only the submitted observed sources
and possible candidate destinations require entries; an implementation MUST
NOT require an unrelated dense all-pairs table.

Observed concurrent occupancy describes resource holdings during in-progress
work. Every holding has an identity, target, dimension, and quantity, with an
explicit association to an item's ordinary placement charge or to additional
occupancy. An ordinary charge MUST be counted once; a simultaneous extra copy
MUST be counted separately. Ordinary holding fragments MUST occur at the
item's observed target and sum to its declared historical charge. An unplaced
item MUST NOT have an ordinary source holding. Each additional holding declares
whether it remains charged at the final boundary. All observed additional
holdings remain charged in conservative overlap accounting.

Capacity constraints select either final accounting or conservative overlap
accounting. For each item `i`, target `t`, and dimension `d`, let `O(i,t,d)` be
the historical ordinary charge, zero away from the observed target. Let
`P(i,t,d,a)` be the proposed demand if assignment `a` binds the item to `t`,
and zero otherwise. Let `E_final(t,d)` sum additional holdings retained at the
final boundary, and `E_overlap(t,d)` sum all observed additional holdings.
Then the exact per-target loads are:

```text
final(t, d, a) = fixed(t, d) + E_final(t, d) + sum_i P(i,t,d,a)
overlap(t, d, a) = fixed(t, d) + E_overlap(t, d)
                + sum_i max(O(i,t,d), P(i,t,d,a))
```

Target-set loads sum these values over distinct targets. An unchanged ordinary
placement contributes exactly the maximum of its historical and proposed
charge in overlap accounting. A relocation contributes its source charge at
the source and its proposed demand at the destination. Arbitrary conservative
excess MUST NOT be introduced by an evaluator; a consumer can submit explicit
additional occupancy or reduce usable capacity.

For observation-derived repair debt, the placement charges are `O` rather than
forecast `P`; final and overlap phases retain their respective additional
holding rules. This allows the observed baseline to differ from proposed
resource grants without changing its meaning.

Passing an overlap constraint is a resource calculation, not proof of an
executable transition. It does not establish copy completion, custody transfer,
quorum preservation, or operation ordering. An assignment with only final
capacity constraints makes no claim about temporary headroom.

## 5.6. Typed constraints and explicit repair

Every constraint has a stable identifier, typed parameters, and an enforcement
mode. The version 1 vocabulary includes eligibility, fixed placement,
capacity, admission cardinality, atomic admission, co-location, spread, and
movement budgets. Evaluators MUST implement every valid version 1 constraint.
Constraint combinations can be contradictory without being structurally
invalid; contradiction can yield an infeasible problem.

The constraint predicates are:

| Type | Required predicate |
| --- | --- |
| Eligibility | Every placed selected item belongs to its finite candidate domain, intersected with any additional declared eligibility set |
| Fixed placement | Every selected item equals its explicitly declared target or deferred binding |
| Capacity | The exact load of a declared target set, dimension, and accounting phase is at most its explicit finite limit |
| Admission | The group's admitted count lies within the declared inclusive bounds |
| Atomic admission | The group's admitted count is zero or its full membership count |
| Co-location | The admitted group members occupy at most one member of the declared scope family |
| Spread | The occupied-domain count meets the declared minimum and each domain's admitted count meets any declared maximum, subject to the explicit conditional-admission rule |
| Movement budget | The exact sum of the declared movement categories and costs over selected items is at most the declared nonnegative bound |

A freeze-observed helper MUST expand to explicit fixed bindings, translating
`Unplaced` to `Deferred`. A fixed binding MUST NOT override eligibility or
authorize deferral of a mandatory item; conflicting requirements can make the
problem infeasible. Capacity limits MUST be supplied explicitly. A consumer
helper MAY derive an aggregate limit by summing declared capacities of distinct
targets, but the derived value MUST be part of the semantic model. Overlapping
target-set capacities MUST NOT be implicitly summed. Movement budget terms
MUST use compatible declared cost units and nonnegative costs.

Hard enforcement requires every constraint component to hold. Components are
identified by the relevant item, group, target set, or scope member. A backend
MUST NOT convert a hard constraint into a preference because the observed
assignment violates it.

Repair enforcement is explicit and applies only to numeric bound obligations:
capacity, admitted cardinality, and spread counts. Upper-bound debt is
`max(0, value - limit)`; lower-bound debt is `max(0, limit - value)`. Each named
component receives its own debt value. Non-numeric eligibility, atomicity,
co-location, and fixed-placement requirements remain hard in version 1.

For every repair component `c`, Dispatch derives baseline debt `D0(c)` from the
observed assignment. A candidate MUST satisfy:

```text
debt(candidate, c) <= D0(c)
```

The test is componentwise, including components whose baseline debt is zero.
Decreasing total debt does not permit creating a new violation elsewhere.
Consumers MUST declare repair priorities as objective terms; declining to
worsen debt does not itself require strict improvement. A backend MUST NOT
derive a different baseline from its hint or internal preprocessing.

A candidate satisfying all hard constraints with zero repair debt is fully
feasible. A candidate satisfying all hard constraints and repair envelopes but
retaining debt is a repair proposal and MUST be labeled accordingly. It MUST
NOT be reported as fully feasible. No constraint can be silently relaxed to
produce either classification.

## 5.7. Objectives and exact ordering

Objectives compare candidates; they do not override hard constraints or repair
envelopes. A problem contains an ordered sequence of objective tiers. Comparison
is lexicographic: the first differing tier determines which candidate is
preferred. No improvement in a later tier compensates for regression in an
earlier tier.

Each tier contains an explicitly normalized, weighted sum of typed metrics.
Weights are nonnegative rationals; normalization divisors are strictly positive
rationals. The default weight and normalizer, when the schema permits omission,
are both one and MUST be materialized in the canonical model. Each term declares
minimization or maximization. All tiers are represented as minimized values:

```text
tier_k(a) = sum_j direction_j * weight_j * metric_j(a) / normalizer_j
direction_j = +1 for minimization, -1 for maximization
```

Exact rational comparison MUST be used for final evaluation. Objectives MUST
NOT rely on backend-specific floating-point tolerances to define equality.

Version 1 metrics include admitted counts or priority scores, assignment cost,
movement cost, used-target count, repair debt, maximum utilization, utilization
range, and total absolute deviation from a declared utilization reference.
Each metric identifies its item set, dimensions, target sets, or scope family
as applicable. The metric definitions are:

| Metric | Exact value |
| --- | --- |
| Admitted count | Number of selected items assigned to real targets |
| Admitted priority | Sum of explicit nonnegative per-item priority values for admitted selected items |
| Assignment cost | Sum of declared item-binding costs, including explicit deferred entries or a declared deferred default |
| Movement cost | Sum of costs for the selected new-placement, relocation, and retirement categories relative to the observed assignment; unchanged bindings contribute zero |
| Used-target count | Number of distinct targets receiving at least one selected item; fixed or additional occupancy alone does not count |
| Repair debt | Sum of the explicitly selected repair components in compatible units, optionally combined through separate normalized objective terms |
| Maximum utilization | Maximum of selected member utilizations |
| Utilization range | Maximum utilization minus minimum utilization over the selected members |
| Total absolute deviation | Sum over selected members of the absolute difference between utilization and an explicit member-specific or common rational reference |

Member utilization is `load(S,d,a) / capacity(S,d)` with an explicit accounting
phase, target set `S`, dimension `d`, and positive finite capacity. The denominator
is submitted semantic data, not an implicitly inferred fleet capacity. Empty
utilization selections are invalid. An objective MUST explicitly exclude
zero-capacity and unbounded members or is invalid. Empty selections for count
and sum metrics evaluate to zero. Metrics MUST NOT infer priority or unit
conversion from labels. A used-target objective does not imply that other
occupancy permits the consumer to shut a target down.

Costs MAY be integer or rational values. Negative signed preference costs MAY
be used only where the metric schema explicitly permits them. Sparse cost
tables MUST define an explicit default; missing entries MUST NOT inherit an
implementation-specific value. Objective values and contribution reports MUST
be recomputed by Dispatch from the accepted assignment.

Lexicographic semantics do not imply global optimality. A heuristic can return
a preferred feasible answer without establishing that a better answer does
not exist. Quality bounds or optimality claims MUST identify the exact
objective and model to which they apply.

## 5.8. Validation, evaluation, and verification

Validation checks entity references, quantities, units, topology partitions,
scope and group definitions, sparse expansion semantics, objective domains,
and the observation basis. It derives repair baselines and produces an
immutable validated problem. Validation MUST NOT require that a feasible
assignment already be known. Validating a problem is distinct from validating
its compatibility with a particular backend.

Evaluation accepts a validated problem and a structurally valid assignment.
It returns resource loads, named violations, repair debt, movement deltas, and
the objective vector. Evaluation MUST be available without starting a solver.

Verification independently evaluates an untrusted candidate against the exact
validated problem. It produces a verified feasible plan, a verified repair
proposal, or explicit violations. A verified result MUST bind the assignment,
problem identity, observation basis, and independently calculated values.
Serialized artifacts MUST be checked again before becoming locally verified
plans. Explicit trusted-remote verification follows Section 12.1 and MUST
remain distinguishable from local verification.

A backend MAY reject a valid model because it cannot implement a constraint,
objective, combination, or numeric range. It MUST return an unsupported-model
error identifying the limitation. Unknown semantics MUST NOT be ignored.
Extensions require a versioned schema, defined evaluation semantics, and
conformance cases; arbitrary callbacks and native backend programs are not
extensions to this contract.

Failure to find a candidate is not infeasibility evidence. Any infeasibility
claim MUST identify whether it concerns the complete problem or a restricted
candidate domain and whether independently checkable evidence is available.
Neither verified placement nor infeasibility evidence confers reservation,
execution, membership, or ownership authority.

## 5.9. Worked placement and repair example

Targets `A` and `B` each have capacity 8. Mandatory items `x`, `y`, and `z`
consume 6, 4, and 3 units respectively, with identical demand on either target.
All targets are eligible. The observed placement is `x -> A`, `y -> A`,
`z -> B`, producing loads 10 and 3. Historical ordinary charges equal these
declared demands; there is no fixed or additional occupancy.

Capacity is explicitly repairable under final accounting. Its baseline debt
vector is `(A: 2, B: 0)`. Objectives first minimize total debt, then relocation
units, then maximum utilization. Relocation units equal the moved item's
demand.

Moving `x` to `B` gives loads 4 and 9. Total debt falls from 2 to 1, but the
candidate is rejected because `B` acquires debt 1 against its baseline 0.
Moving `y` to `B` gives loads 6 and 7, debt `(0, 0)`, relocation cost 4, and
maximum utilization `7/8`. This is fully feasible. Retaining the observed
assignment is a repair proposal with debt `(2, 0)` and zero relocation cost;
its cheaper movement cannot outrank the feasible answer's earlier debt tier.

If overlap accounting retains `y` at its source during transfer, the temporary
loads are 10 and 7. The final feasible answer therefore does not satisfy a
hard overlap limit of 8 on `A`. That difference MUST remain visible to the
consumer; final feasibility MUST NOT be promoted into permission to execute
the move.
