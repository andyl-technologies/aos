# RFC-0025 — 08. Conformance and qualification

This chapter defines how a provider demonstrates the contracts in this RFC.
The words conformance and qualification have different scopes:

- **Protocol conformance** establishes that an implementation accepts,
  produces, and refuses operations according to the negotiated interface.
- **Behavioral qualification** establishes evidence for an operating contract
  on a particular realized configuration and execution environment.
- **Scientific validation** assesses whether a model represents the physical
  system of interest. Interface qualification does not establish that result.

A deterministic but inaccurate processor model can conform to an exact timing
contract. An accurate physical sensor can conform to a quantized contract
without supporting repeatability or capture. Neither is a reason to weaken the
other contract or infer a capability that has not been demonstrated.

## 8.1 Conformance units and classes

The unit of qualification is the tuple of provider implementation identity,
realized owner configuration, node descriptors, negotiated operating contracts,
port profiles, execution environment constraints, and harness revision.
An executable name, implementation family, CPU ISA, or provider version alone
is not a qualification unit.

**[CN-TEST-001]** A provider claiming conformance MUST identify this qualification
unit and the classes below that its evidence covers.

Classes are orthogonal unless their listed prerequisites require otherwise.
They do not form a ladder in which a higher class implies all lower classes.

| Class | Prerequisite | Claim and scope |
| --- | --- | --- |
| `base-provider` | None | Admission, identity, descriptors, lifecycle, errors, ownership, and protocol behavior. |
| `exact-timing` | `base-provider` | Bounded advancement at the declared resolution with truthful progress and event receipts. |
| `quantized-timing` | `base-provider` | Input admission, authorized windows, output publication, and acknowledgments under the declared boundary policy. |
| `repeatable` | `base-provider` | Equivalent continuation under identical admitted inputs and declared environment constraints. |
| `capture-architectural` | `base-provider` | Capture of the explicitly enumerated architectural and device state; no implied physical or modeled microstate equivalence. |
| `capture-modeled-live` | `base-provider` | Complete modeled-state continuation while the declared live resources remain available. |
| `capture-modeled-durable` | `base-provider` | Complete modeled-state continuation from an artifact after the source owner and its live resources have ceased to exist. |
| `branch-isolated` | A supported capture class | Independent branches with the declared state-preservation scope and no unintended shared effects. |
| `conditional-replay` | `base-provider` | Replay of a recorded boundary transcript when its declared applicability conditions hold. |
| A role/port profile | `base-provider` | The semantic operations, features, ordering, faults, and capture coverage of the named profile. |

An owner can support both timing classes through separately admitted modes.
Such support does not allow changing the mode of an active realization without
the transition procedure defined by its contract. A capture class does not
imply repeatability, a durable artifact does not imply portability, and a
repeatable node does not imply repeatability of a world with a nondeterministic
dependency.

**[CN-TEST-002]** A conformance report MUST keep timing, repeatability,
capture scope, capture lifetime, branch isolation, replay, and role-profile
results distinct.

**[CN-TEST-003]** The executor MUST refuse a scenario whose required class or
configuration is outside the accepted qualification scope before activation.

This refusal includes an exact scenario offered only quantized timing, a
complete-state scenario offered architectural capture, a durable restore
offered only a live seed process, or a role profile missing a required feature.
An unsupported facet is an ordinary admission result, not an implementation
defect. A missing feature in a promised parity profile is a failed profile.

## 8.2 Evidence identity and vendor claim manifest

A vendor claim manifest contains the following fields. This is a semantic
inventory; its encoding and identity are governed by the protocol chapter.

| Field | Purpose |
| --- | --- |
| Claim identity and superseded claim | Distinguish evidence revisions without rewriting historical results. |
| RFC, protocol, and profile revisions | Bind the specification interpreted by the test harness. |
| Implementation identities | Bind executable, adapter, patches, generated model, firmware, and relevant dependency identities. |
| Realization identity | Bind CPU, memory hierarchy, devices, port features, timing parameters, seeds, and operating modes. |
| Environment constraints | Record host ISA, kernel/hypervisor constraints, threading, memory mappings, and required live resources where relevant. |
| Claimed classes and requirement coverage | Identify exactly which obligations are supported. |
| Harness and fixture identities | Identify executable tests, reference models, scenario inputs, and oracle revisions. |
| Result inventory | Separate pass, fail, unsupported, not applicable, and not executed. |
| Observation and coverage inventory | Identify measured state domains, difficult-state coverage, event traces, and negative controls. |
| Evidence references and integrity | Locate reports and bind their contents to the qualification claim. |
| Limitations and expiry conditions | State unsupported configurations and changes that invalidate the claim. |

**[CN-TEST-004]** Evidence MUST bind the tested implementation and configuration
identities rather than an unverified marketing name or a mutable branch name.

**[CN-TEST-005]** A claim MUST distinguish model-only results from results
observed against the realized provider; a passing reference model is not a
passing live implementation.

**[CN-TEST-006]** A claim MUST retain failures, unexecuted cases, relevant
limitations, and required difficult-state coverage alongside successful cases.

**[CN-TEST-007]** A changed implementation, realization, contract, or environment
outside the claim's stated compatibility scope MUST be requalified before the
executor treats that claim as applicable.

The executor's trust policy decides which evidence authorities are accepted.
A provider's self-description alone is not accepted qualification. Signing a
report establishes provenance, not the truth of its measurements. Evidence
collection is bounded by deployment retention and confidentiality policies;
the report can contain authenticated local references or controlled-access
artifact references. Evidence access follows the deployment's retention and
confidentiality policies.

## 8.3 Harness structure and meaningful oracles

The qualification harness has three complementary layers:

1. A small reference state machine explores grants, event custody, lifecycle,
   owner locking, publication, and restore transactions under adversarial
   interleavings.
2. Independent protocol peers exercise serialization, negotiation, parser
   limits, transport failure, retries, and stale authority.
3. Realized providers execute workloads that expose internal state and
   timing effects through independently observed receipts, traces, or digests.

**[CN-TEST-008]** A behavioral qualification claim MUST include realized-provider
tests for each claimed class and declared configuration family in addition to
any model or mock tests.

**[CN-TEST-009]** Test oracles MUST observe the promised property independently
of the implementation mechanism whose correctness they assess.

For example, hashing only a serialized artifact cannot establish that its
serializer included every timing-relevant state domain. State inspection and
future event/commit observations are complementary. Two restore paths using
the same incomplete serializer are not independent references. A serial
console message is useful for boot liveness but does not establish exact
microstate continuation.

Independent observations can use native diagnostic hooks whose qualification
scope is documented. They need not expose native pointers through the public
interface. The harness records perturbation caused by instrumentation and
separates diagnostic runs from performance measurement.

## 8.4 Suite B: base, admission, and lifecycle

Suite B exercises a provider with no optional facets and providers supporting
several valid role and timing combinations. It checks:

- Descriptor stability after admission; identity binding; unknown required
  capabilities and profile revisions; explicitly unsupported optional facets.
- Duplicate node or owner identities, dangling ports, invalid schemas,
  incompatible endpoint modes, unsupported device features, and configuration
  changes between planning and realization.
- Initialize, activate, stop, failure, and disposal; repeated or out-of-order
  requests; failure during initialization before external effects escape.
- Role-specific operations presented to the wrong port or node role.
- Owner-exclusive operations when several logical nodes share one owner.
- Unknown observation versus absence of pending work. A node with no proven
  future bound contributes no invented lookahead.

**[CN-TEST-010]** Suite B MUST demonstrate refusal before activation for
incompatible contracts, identities, ownership declarations, and required
profiles, with no observable guest or external-device mutation.

Fresh-world activation fixtures stage one owner successfully and fail another
owner's preparation or readiness acknowledgment. They also lose a staging
receipt and attempt an execution grant before the global activation commit.
The oracle observes execution and event-publication gates, not merely a local
owner's ready flag. No independently ready owner can begin simulation work.

**[CN-TEST-037]** Activation qualification MUST demonstrate that prepared or
staged readiness does not authorize execution before global commitment and
that failure before commitment leaves all new-world execution gates closed.

Activation does not require physically simultaneous start of all owners.
Post-commit failure fixtures include an owner failing after another has
executed or published an admitted effect. They verify containment, explicit
uncertain outcomes, and recovery under a new authorized transaction; they do
not expect physical effects to disappear or the old world to roll back.

## 8.5 Suite E: exact timing and conservative coordination

Suite E tests each supported time resolution and stopping mechanism. Its
finite fixtures cover immediate stops, zero-length legal requests, a single
native event, multiple native events at one timestamp, early output, timer
expiry, pending input, idle skipping, and boundaries near numeric limits.

The harness varies grant partitioning while preserving admitted inputs: one
long grant, many short grants, and grants cut immediately before and after
each causal event. It compares final state and ordered observations under the
declared repeatability scope. A backend unable to reach a requested boundary
returns its actual legal stop or refusal; it does not round a receipt.

**[CN-TEST-011]** Exact timing qualification MUST demonstrate that accepted
advancement never exceeds the authorized coordinate, including earliest
possible input, externally relevant arbitration boundaries, and early-output
stops.

Provider-private pipeline, cache, and memory events can execute inside a grant
without a separate host stop for every native event. Their ordering and effects
remain governed by the admitted model and grant. The stopping obligation is
triggered by its boundary or a transition requiring external input, publication,
or coordinator arbitration, rather than by the existence of an internal event.

**[CN-TEST-035]** Exact timing qualification MUST test a private state transition
at the excluded grant limit that produces no output and a native atomic step
that would straddle the limit, proving neither executes unauthorized effects.

The first fixture changes only a register, cache state, or private counter at
the limit; the oracle detects mutation even without a port observation. The
second starts a noninterruptible modeled step before the limit whose completion
would cross it. The provider either refuses before its effects, returns an
earlier legal stop, or uses a separately qualified boundary-park mechanism
that retains the unexecuted portion. Reporting the limit after executing the
whole step fails qualification.

**[CN-TEST-012]** Exact timing qualification MUST cover equal-time ordering,
resolution mismatch, overflow, unknown lookahead, and zero-latency dependency
cycles without inventing a safe window.

**[CN-TEST-036]** Same-instant qualification MUST test a zero-delay causal chain
whose node identifiers sort opposite to causality; a policy admitting zero-delay
cycles MUST also test an admitted cycle and explicit nonconvergence handling.

For the chain, `Z` produces an event consumed by `B`, whose response reaches
`A` at the same physical instant. The harness verifies that the selected
superdense policy orders each cause before its effect; sorting only by physical
time and node name would incorrectly place `A` before `Z`. An unrelated event
at that instant exercises the policy's deterministic within-phase tie-break.
An alarm fixture executes its native reaction at `(t, 0, phase 3)` and produces
an interrupt publication at `(t, 1, phase 1)`. The interrupt belongs to the next
superdense round even though its phase number is lower. The harness captures
the pending causal relationship before publication, restores it, and checks
that neither original nor restored execution reports closure through the
pending effect before it is resolved.
Cycle fixtures include a convergent exchange and an exchange that never reaches
closure. They verify the declared iteration limit and refusal/failure policy,
without claiming same-instant closure after an arbitrary number of rounds.

Mixed exact-node cases use independently progressing producers and consumers.
One producer is deliberately slow in wall time. Its potential output bounds
the faster consumer before the output is known. Cases include both directions
of traffic, timer-driven messages, concurrent output, pending storage
completion, and a queued interrupt at capture. Serial and parallel dispatch
preserve the same admitted ordering where repeatability is claimed.

**[CN-TEST-013]** A mixed exact-world claim MUST include realized-provider
tests proving no consumer advances beyond an unexcluded input from a slower
producer, including shared-owner components and non-network ports.

QEMU-SIM and gem5 are intended examples of exact compute providers, not
qualification shortcuts. Each claimed CPU model, device configuration, and
stop implementation still supplies applicable evidence.

## 8.6 Suite Q: quantized participation and physical activity

Suite Q uses the admitted quantum policy as its oracle. It covers readiness,
window authorization, input sampling, work execution, output buffering,
closure acknowledgment, publication, and next-window admission. Observed
physical activity and wall-clock time remain separate from logical time.

**[CN-TEST-014]** Quantized timing qualification MUST demonstrate that inputs
and published outputs obey their authorized boundary assignments and that no
next window starts before its coordinator authorization.

**[CN-TEST-015]** Quantized timing qualification MUST exercise late input,
missed wall deadlines, stalled participants, cancellation races, and output
queue exhaustion according to the admitted policy, without silently
reassigning an event to a committed boundary.

Tests delay a slow exact producer while a quantized consumer waits. They vary
whether the quantized participant can pause execution, only gate interaction,
or cannot pause its physical activity. The report records which case was
tested. A counter-clock adjustment and a signal requesting a vCPU exit are
not evidence of exact stopping. Holding an adapter's publication queue is not
evidence that the physical device stopped.

**[CN-TEST-016]** Qualification MUST verify the claimed pause and containment
behavior separately from publication gating and reject undeclared externally
visible paths that bypass the admitted interaction policy.

Mixed exact/quantized tests check that fine-grained events between exact nodes
retain their admitted resolution. Coarse boundaries apply only to connections
and modes that negotiated them. A continuous physical observation can be
assigned to a future boundary only under an explicit sampling/publication
contract, not as a claim about its unmeasured physical occurrence time.

## 8.7 Suite R: repeatability and conditional replay

Repeatability cases vary host scheduling, dispatch batching, permitted thread
interleavings, and grant partitioning within the claim's environment scope.
They preserve admitted logical inputs and compare ordered event traces,
state witnesses, and final outputs. Negative controls change a seed, an input,
or a relevant configuration and establish that the harness can distinguish it.

**[CN-TEST-017]** Repeatability qualification MUST state the equivalence
relation being tested and compare more than an implementation's own claim of
success or a single application liveness marker.

Conditional replay fixtures record both outputs and the interactions on which
they depend: payloads, order, assigned boundary coordinates, requests,
completion/interrupt effects, storage effects, and relevant control actions.
They repeat the original admissible interaction and then intentionally alter
its requests or causal context.

**[CN-TEST-018]** Conditional replay qualification MUST demonstrate refusal
when the recorded transcript's applicability conditions no longer hold,
including changed requests, missing events, mismatched order, and altered
side-effect dependencies.

**[CN-TEST-019]** Mixed-world qualification MUST retain nondeterministic
provenance from an interacting participant and distinguish conditional
transcript replay from repeatability of the original physical execution.

No class in this RFC promises that a recorded transcript applies to an
arbitrary counterfactual branch or reconstructs physical timing that was
never observed.

## 8.8 Suite S: capture, restore, and branch isolation

Suite S enumerates all mutable domains in each qualified capture owner.
Coverage includes, where realized:

| Domain | Difficult state to exercise |
| --- | --- |
| CPU | Speculation, pipeline latches, microcode, outstanding loads/stores, register renaming, predictor state, and pending exceptions. |
| Cache/coherence | Dirty lines, replacement history, MSHRs, retries, write queues, transient coherence states, and in-flight messages. |
| Translation/memory | TLB state, pending walks, memory queues, open rows, refresh, scheduling history, and DMA. |
| Events/time | Pending callbacks and payloads, time anchors, timer phase, same-time native tie ordering, cancellation, and reschedule history. |
| Randomness | Every realized PRNG stream and draw position, including device and coordinator streams. |
| Devices/storage | Virtqueue state, pending completions, interrupt state, filesystem handles, private overlays, and host-side model state. |
| Protocol | Input/output custody, unpublished quantum output, grant generations, pending operations, and backpressure. |
| World | Connection queues, pending delivery, coordinator choice state, faults, publication frontiers, and owner closure. |

This inventory is not a requirement to implement a speculative CPU in every
node. It requires preserving every such domain that exists in the realized
model when complete modeled-state continuation is claimed.

**[CN-TEST-020]** Complete modeled-state qualification MUST exercise nonempty
difficult states in every realized mutable domain that can affect subsequent
contract-visible behavior.

**[CN-TEST-021]** Complete modeled-state qualification MUST establish that
capture does not advance the boundary, retire extra work, drain pending
activity, consume random draws, flush caches, or reconstruct state by warm-up.

Each applicable state fixture runs these continuations:

| Path | Reference or property |
| --- | --- |
| Original, uninterrupted | Reference future at the chosen boundary. |
| Capture, continue without restore | Detect capture perturbation. |
| Restore into the stopped owner | Detect replacement of live state. |
| Restore into a fresh owner/process | Detect hidden dependence on old allocations or queues. |
| Restore after source exit | Establish the durable lifetime claim. |
| Two branches, identical admitted inputs | Compare continuation under the qualified repeatability scope. |
| Two branches, deliberately divergent inputs | Establish isolation and independent effects. |

**[CN-TEST-022]** Qualification MUST execute every continuation path required
by its declared scope and lifetime; durable evidence includes restoration
after the source owner and required live resources have been removed.

**[CN-TEST-023]** Branch qualification MUST test isolation of memory, mutable
mappings, storage overlays, descriptors, transport queues, host services, and
external side effects included in the claim, rather than heap state alone.

**[CN-TEST-024]** Capture qualification MUST include negative controls that
omit or alter selected pending-state classes and demonstrate detection by an
independent state or continuation oracle.

Architectural capture reports enumerate the preserved state and explicitly
exclude physical caches, pipelines, or other unpreserved domains. Their
oracle tests restoration of that stated state, not exact future timing.
A weaker architectural claim cannot satisfy complete modeled-state scenarios.

Atomic world-restore tests inject failure at validation, preparation, binding,
and staged activation of every owner position before global commitment. They
include one owner serving several nodes and one mutable domain erroneously
claimed by two owners. Separate post-commit failure tests retain already
published effects and fence failed or ambiguous owners before recovery.

**[CN-TEST-025]** World-state qualification MUST prove single-owner coverage
and that partial restore failure before global activation commitment leaves
the new world inactive or quarantined, with no partial external publication or
silently usable mixed-generation state.

**[CN-TEST-038]** Post-commit failure qualification MUST verify containment and
explicit effect/uncertainty accounting without assuming automatic rollback of
published effects or physically simultaneous owner activation.

## 8.9 Suite P: protocol, identities, and fault handling

Suite P uses the normative schemas, canonical identity rules, and
[primitive vectors](reference/cnp-v1-vectors.json) in the protocol chapter.
The vectors establish byte framing, restricted JSON canonicalization examples,
domain separation, and typed-scalar refusal. Their JSON objects are not
schema-complete node manifests. Suite P checks an independently implemented
peer against valid frames and adversarial malformed input.

**[CN-TEST-026]** Protocol qualification MUST verify canonical identity
vectors, distinguish identity-relevant changes, and reject malformed
representations or noncanonical typed scalars under the selected encoding.

Permitted object-member order and whitespace variations canonicalize to the
same identity. This is distinct from accepting duplicate keys, malformed UTF-8,
or noncanonical decimal strings.

**[CN-TEST-027]** Protocol qualification MUST cover unsupported versions,
unknown required fields or extensions, duplicate identities, length and offset
limits, arithmetic overflow, stale sessions/generations, and forged or reused
operation authority.

**[CN-TEST-028]** Protocol qualification MUST test disconnect and retry at
each operation phase, duplicate delivery, cancellation races, and uncertain
outcomes without duplicate execution or fabricated successful acknowledgment.

A reconnect does not imply recovery of owner state. The harness checks that
session fencing and explicit recovery requirements prevent an old peer from
publishing into a new world. Shared-memory peers additionally test invalid
offsets, ownership transitions, lifetime reuse, and capacity exhaustion.
No native pointer or process-private object is a valid public reference.

## 8.10 Suite F: role profiles and device parity

Each role-profile suite exercises its advertised features and relevant
cross-role paths: reset, feature negotiation, queue behavior, ordering,
interrupt delivery, faults, completion timing, backpressure, and captured
pending work. Platform device profiles cover firmware and interrupt/timer
behavior required by their declared machine profile.

**[CN-TEST-029]** A provider claiming a role or parity profile MUST qualify its
complete required feature set, including pending-operation capture where
that profile requires it; a reduced feature set needs a different profile.

The public contract requires equivalent specified guest-visible semantics,
not identical native object names or internal implementations. Different
timing models remain legitimate when their contracts and scenarios admit
them. Port schemas alone do not establish device parity.

## 8.11 Performance validation

Performance is evaluated after correctness qualification. It is not a
conformance class and supplies no exemption from causal or state guarantees.
The baseline inventory includes finite protocol operations, finite modeled
work, cold boot, device-heavy workloads, and capture/restore/branch costs.
Compute tests record executed guest work where observable; event-model tests
record processed events and queue occupancy. Throughput and latency are
reported separately from logical simulation time and modeled CPU fidelity.

**[CN-TEST-030]** A performance claim MUST bind matched scenario inputs,
implementation/configuration identities, admitted contracts, completion
criteria, measurement boundaries, environment, and all measured attempts.

**[CN-TEST-031]** A comparison MUST disclose changes in guest work, device
features, modeled fidelity, clock policy, capture scope, or completion
criteria rather than attributing those changes solely to implementation speed.

**[CN-TEST-032]** Performance evidence MUST separate profiling and diagnostic
instrumentation from timing runs and preserve failed or censored attempts
under a stated treatment policy.

Alternating baseline/candidate runs, fixed affinity where applicable, warm and
cold conditions reported separately, and independent completion observations
reduce avoidable bias. Sample counts and dispersion are reported; unexplained
outliers are not discarded. Small improvements can accumulate, but the final
aggregate is measured directly against the original baseline rather than
obtained by adding percentages from unrelated workloads.

The RFC does not prescribe an arbitrary universal percentage regression
threshold. The deployment's explicit performance budget supplies acceptance
criteria. A faster run that omits pending state or publishes early is a
correctness failure, not a performance improvement.

## 8.12 Requirement traceability and acceptance record

The suite assignment below is a coverage index. The normative requirements
remain in their owning chapters; passing a suite does not waive any applicable
requirement not explicitly exercised by its fixtures.

| Requirement family | Owning chapter | Primary suites | Additional coverage |
| --- | --- | --- | --- |
| `CN-MODEL-*` | [Conventions and model](00-conventions-and-model.md) | B | F, S, P |
| `CN-NODE-*` | [Node contract](01-node-contract.md) | B | E, Q, S, F |
| `CN-PORT-*` | [Ports and admission](02-ports-capabilities-and-admission.md) | B, F | E, Q, P, S |
| `CN-CAP-*` | [Ports and admission](02-ports-capabilities-and-admission.md) | B, P | Every claimed class |
| `CN-TIME-*` | [Exact scheduling](03-time-and-scheduling.md) | E | P, S |
| `CN-QUANT-*` | [Quantized participation](04-quantized-and-physical-nodes.md) | Q | E for mixed connections; P, S |
| `CN-STATE-*` | [State and replay](05-state-and-replay.md) | S | B, P, R |
| `CN-REPLAY-*` | [State and replay](05-state-and-replay.md) | R | E, Q, S |
| `CN-IPC-*` | [Provider protocol](06-provider-protocol-and-security.md) and [core type schemas](reference/cnp-v1-core-types.md) | P | B, E, Q |
| `CN-SEC-*` | [Provider security](06-provider-protocol-and-security.md) | P, B | S, Q |
| `CN-PROFILE-*` | [Reference profiles](07-reference-profiles-and-examples.md) | F | E or Q; S where supported |
| `CN-TEST-*` | This chapter | Applicable suite and claim inspection | All evidence |
| `CN-EXT-*` | [Decisions and extensions](09-decisions-and-extensions.md) | B, P | F and affected timing/state suites |

**[CN-TEST-033]** The acceptance record MUST enumerate every applicable
normative requirement identifier in this RFC and bind it to executed cases,
inspection evidence, or an explicit not-applicable rationale.

**[CN-TEST-034]** A claimed class MUST have no unresolved failure or unexecuted
applicable requirement in the accepted record.

Vendors can add narrower qualified profiles without claiming every class.
An integration can begin with a quantized, uncapturable adapter or an exact
event-driven disk. The same base contract applies to both. Stronger scenario
requirements continue to be enforced, and later evidence expands the admitted
scope without retroactively changing the meaning of earlier executions.
