# 05 — State Preservation, Restoration, and Replay

## 1. Scope and terminology

This chapter defines the state contract for every simulation node,
execution owner, capture owner, and external adapter admitted to a Crucible
world. It applies to compute, storage, clocks, links, shared devices, and their
coordinator state.

Logical time is an unsigned 64-bit count of picoseconds. Native instruction
counts, CPU cycles, host timestamps, and device counters remain separate
coordinates. Their mappings and boundary semantics are defined in
[03 — Time and Scheduling](03-time-and-scheduling.md). Quantized and physical
execution is defined in [04 — Quantized and Physical Nodes](04-quantized-and-physical-nodes.md).
Canonical representation, authenticated operation ownership, and provider
transport are defined in [06 — Provider Protocol and Security](06-provider-protocol-and-security.md).

A **state domain** is a named collection of mutable state with one authoritative
owner. An **execution owner**, identified by `ExecutionOwnerId`, controls native
execution for one or more nodes. A **capture owner**, identified by
`CaptureOwnerId`, can freeze and preserve an explicitly enumerated set of state
domains. Several graph nodes may share either owner; graph presentation
does not imply separate native machines or independently capturable state.

A **world cut** includes a logical coordinate, a scheduling phase, and all
continuation state required at that boundary. A **snapshot artifact** is an
identity-bound closure of preserved state and its provenance. A **live template**
is an operationally retained source with a lease. Neither its process identifier
nor its lease alone is a durable snapshot artifact.

**[CN-STATE-1]** State capability claims MUST name the realized node graph,
execution owners, capture owners, state domains, and implementation/model
identities to which they apply. Support for one CPU or memory model MUST NOT
imply support for another configuration of the same provider.

**[CN-STATE-2]** A provider MUST declare capture fidelity, persistence, and
branching support independently. The executor MUST NOT infer exact capture,
durable restart, or live fork support from another of these capabilities.

| Capability dimension | Meaning |
| --- | --- |
| Exact continuation state | Preserves every state component that can affect future modeled execution or timing |
| Architectural capture | Preserves the declared architectural/device projection, with omitted state identified |
| Durable restart | Reconstructs the declared state after every original owner and live template has terminated |
| Live fork | Creates an isolated continuation using an admitted retained execution source |
| Conditional transcript replay | Repeats a captured observation sequence only when its declared request/input preconditions hold |

**[CN-STATE-3]** Exact continuation fidelity MUST be defined relative to the
admitted model, not to unmodeled properties of a physical processor. A provider
that cannot observe or preserve a future-affecting component of its declared
model MUST NOT advertise exact continuation for that realization.

Hardware-assisted execution can preserve architectural state while remaining
unable to preserve physical cache or predictor state. That distinction is not
removed by freezing a virtual clock. Exact modeled state preservation and
repeatable execution are also separate claims: exogenous future input can vary
after an otherwise complete capture.

## 2. Ownership and complete state closure

**[CN-STATE-4]** Every mutable state domain MUST have exactly one authoritative
owner within a realized world. The ownership manifest MUST include shared
domains, dependencies between owners, and any domain exposed through multiple
node views. Duplicate ownership and unowned mutable domains MUST fail admission.

**[CN-STATE-5]** The graph MUST identify which state domains each capture owner
preserves. A node-local snapshot MUST NOT claim closure over an independently
owned clock, storage service, link queue, coherence fabric, or external adapter
unless that owner's state is included in the same admitted cut.

**[CN-STATE-6]** A complete state manifest MUST classify every realized object
that can affect continuation as captured mutable state, immutable state bound
by content identity, or explicitly outside the claimed fidelity. Unknown objects
or unsupported mutable domains MUST fail exact-capture admission.

The manifest is a coverage statement, not a list inferred from fields that
happen to have serializers. A newly introduced predictor, device queue, or
memory controller invalidates a prior coverage claim until it is classified.

**[CN-STATE-7]** Exact continuation state MUST include architectural registers,
memory, exception state, and all modeled future-affecting microstate. It MUST
include state whose only observable effect is a change in future event time.
An architectural RAM/register hash alone MUST NOT certify exact continuation.

For a detailed processor, the closure includes the following when realized:

- Pipeline stages, instruction and micro-operation queues, rename maps, free
  lists, reorder buffers, speculative register state, retirement state, and
  pending precise exceptions.
- Branch prediction and recovery state, histories, speculative updates,
  replacement metadata, and instructions executing on a wrong path.
- Load/store queues, store buffers, ordering violations, fences, atomics,
  outstanding translations, TLB entries, and page-walker transactions.
- Cache data, tags, dirty state, coherence permissions, replacement history,
  miss-status entries, writeback buffers, and outstanding responses.
- Coherence directories, controller state machines, interconnect credits,
  arbitration state, memory-controller queues, and pending transactions.

**[CN-STATE-8]** The closure MUST include modeled devices and transports:
interrupt-controller state, pending interrupts, timers, DMA, negotiated device
features, descriptors, partial requests, completions, storage durability state,
link queues, backpressure, and guest-visible acknowledgements.

**[CN-STATE-9]** Pending events MUST retain their complete processing order,
including same-time priority and within-priority order, cancellation state,
recurrence state, source identity, payload, and ownership. Reconstructing a queue
from timestamps alone MUST NOT be treated as exact restoration.

**[CN-STATE-10]** The closure MUST include current PRNG state and stream position,
not merely initial seeds. It MUST also include fault runtime state, active effect
lifetimes, pending choices, assertion/trigger state, delivery ledgers, sequence
counters, and the continuation state of stateful external-input adapters.

**[CN-STATE-11]** The coordinator closure MUST include node time mappings, clock
relationships, pending topology changes, conservative bounds, unresolved inputs
and outputs, scheduler phase, committed event-log prefix, and any retained
operation that affects subsequent admission or resolution.

**[CN-STATE-12]** Snapshot closure construction MUST bind all immutable inputs
needed for reconstruction, including base images, firmware, guest binaries,
configuration artifacts, and model parameters. An external pathname or mutable
download location MUST NOT substitute for a verified content identity.

Host accounting and diagnostic timestamps may be recorded separately. Their
presence does not make them simulated state. Any operational value that does
affect modeled continuation must instead be identified and governed by the
admitted timing and provenance contract.

## 3. Capture boundaries and consistent cuts

**[CN-STATE-13]** Exact capture MUST occur at a declared native safe point with a
known logical time and scheduling phase. The safe point MUST suspend dispatch
before another state-mutating native event or guest operation can execute.
Returning from a callback is not, by itself, proof of a valid safe point.

An event-driven provider may expose boundaries between native event callbacks
while retaining partially executed guest instructions in pipeline objects.
A provider need not capture an arbitrary host stack instruction, but it must
state which requested logical boundaries it can represent without advancing.

**[CN-STATE-14]** A request for an unrepresentable exact boundary MUST be refused
or remain pending according to the admitted scheduling contract. The provider
MUST NOT silently move the cut to a later tick or replace the requested phase
with a convenient drained state.

**[CN-STATE-15]** Exact capture MUST NOT advance logical time, retire instructions,
execute pending modeled events, drain pipelines or transactions, write back or
invalidate modeled caches, redraw randomness, or re-execute a prefix to obtain
a convenient serialization state. Capture MUST preserve the reached state.

Normalizing host-only padding or replacing native references with canonical
object identifiers is permitted only when it preserves the modeled state and
future behavior. Model-visible normalization is a state transition and cannot
be hidden inside an exact capture operation.

**[CN-STATE-16]** Capturing a world MUST establish one causally consistent cut
across all admitted capture owners and coordinator-owned domains. The cut MUST
record its boundary and pending transfers; equality of selected node timestamps
alone MUST NOT establish consistency.

**[CN-STATE-17]** Every in-flight transfer at the cut MUST have exactly one
authoritative custody record, or an explicit protocol state describing its
handoff. The snapshot MUST distinguish queued, published, received, resolved,
and acknowledged states without dropping or duplicating the transfer.

**[CN-STATE-18]** Boundary capture MUST preserve the order of control operations,
fault application, inputs, device completions, observations, assertions, and
outgoing-event publication established by the scheduling chapters. Capture
MUST NOT convert uncommitted observations into committed outputs.

**[CN-STATE-19]** An owner that cannot stop, freeze relevant state, or isolate
exogenous mutation MUST declare that limitation. An exact world-capture request
that includes such an owner MUST fail capability admission; it MUST NOT report
a synthetic paused state or a complete exact world artifact.

A quantized physical observation cut can be useful without satisfying exact
world capture. Its uncertainty, external activity, and missing domains remain
part of the artifact's declared fidelity. The executor must not upgrade it to
exact capture because the modeled neighbors can be paused.

**[CN-STATE-20]** Capture inspection and microstate fingerprinting MUST be
observational. They MUST NOT consume queues, change replacement metadata,
advance streams, or invoke model-visible service work. A provider MUST identify
whether diagnostic instrumentation is included in compatibility identity.

## 4. Artifacts and implementation compatibility

**[CN-STATE-21]** Every snapshot artifact MUST bind its scenario and realized
owner graph, cut coordinate and phase, capture fidelity, timing mode, guarantee
scope, implementation compatibility identity, state schema, and full state
closure. These fields MUST be authenticated by its canonical artifact identity.

**[CN-STATE-22]** Implementation compatibility identity MUST bind the provider
implementation and patches, execution model, guest ISA/features, CPU and memory
models, cache/coherence configuration, clocks, device graph, transport features,
fault capabilities, and all parameters that affect state interpretation or
continuation. Backend family name alone MUST NOT authorize restoration.

**[CN-STATE-23]** The provider MUST declare and verify any host compatibility
constraints required for restoration, including architectural virtualization
features and native format dependencies. An executable version string without
the declared compatibility evidence MUST NOT satisfy this requirement.

**[CN-STATE-24]** Ordinary restoration MUST refuse another provider
implementation or incompatible model realization. Cross-backend restoration
MUST NOT be attempted by treating opaque state bytes as a common architectural
format or by substituting a different launch configuration.

**[CN-STATE-25]** Compatibility MUST be checked before mutating an existing
world or authorizing guest execution in a replacement world. Unsupported
schemas, missing closure objects, digest mismatches, and inconsistent ownership
references MUST fail closed and identify the incompatible component.

**[CN-STATE-26]** Snapshot bytes and owner manifests MUST use the canonical,
bounded representation defined by CNP/1. References MUST identify verified
objects or checked offsets; native pointers, borrowed process handles, and
host object addresses MUST NOT become portable artifact references.

**[CN-STATE-27]** Artifact metadata MUST distinguish live source identity from
durable compatibility identity. A PID, socket address, file descriptor, lease,
or retained process address MUST NOT be accepted as evidence that durable
reconstruction is possible.

**[CN-STATE-28]** A snapshot cache key MUST include the realized implementation
compatibility identity and capture fidelity. Cache admission MUST verify the
artifact's actual closure and provenance; an equal planned configuration hash
alone MUST NOT authorize substituting a cached native state.

Canonical content addressing may deduplicate identical verified bytes. It does
not imply that two realizations can execute those bytes, or that a cache entry
is the only state ever observed under a planned configuration.

## 5. Atomic world restoration

Restoration operates on the owner graph, including shared owners. Logical node
views do not each restore a second copy of a shared memory controller, clock,
storage service, or event queue.

**[CN-STATE-29]** Restoration MUST first admit the complete world artifact and
validate every owner, dependency, immutable object, and compatibility constraint.
The executor MUST NOT resume one node while still discovering whether another
required owner can be restored.

**[CN-STATE-30]** Each restored execution owner MUST receive a new incarnation
identity. Prepared operations, leases, receipts, channels, and outstanding
requests from the original incarnation MUST NOT authorize the replacement.
Stable logical identities and new physical identities MUST remain distinct.

**[CN-STATE-31]** The executor MUST stage replacement owners and resources in a
non-runnable state. During staging, providers MUST NOT execute guest work,
dispatch modeled events, publish outputs, or consume world inputs except the
explicit restore protocol required to establish preserved state.

**[CN-STATE-32]** Every owner MUST positively attest that its preserved domains,
pending queues, time coordinate, phase, and references are prepared. The
coordinator MUST validate cross-owner projections and input/output custody
before accepting the world as prepared.

**[CN-STATE-33]** A replacement world MUST become runnable only after all owners
are prepared and the coordinator has durably published one complete world
generation. Owner activation MUST arm readiness while withholding execution
grants until that publication is complete. Individual ready acknowledgements
MUST NOT permit guest execution or physical input publication.

The lifecycle is:

```text
admit artifact closure
    -> stage all owners and resources without execution
    -> restore each domain under a new incarnation
    -> validate all owner attestations and cross-owner projections
    -> arm all owners without execution grants
    -> durably publish the complete world generation
    -> release work through ordinary executor admission
```

**[CN-STATE-34]** Failure before world publication MUST abandon staged owners
without exposing a partially runnable replacement world. If publication status is
uncertain, the executor MUST contain the affected owners and resolve or abort
that generation before authorizing further work. An owner failure after
publication MUST quarantine the world and MUST NOT be reported as successful
partial restoration or as rollback of physical effects.

Durable publication gates execution permission; it does not promise simultaneous
host execution starts across processes. Scheduling ordinary admitted work after
publication is governed by the world's timing mode. An owner failure after
publication does not undo an externally visible operation already performed.

**[CN-STATE-35]** Failure recovery MUST NOT claim that the original world is
unchanged unless its preservation is positively established. It MUST report
whether the original remains resumable, is stopped awaiting reconciliation,
or has been terminated. Cleanup MUST NOT fabricate a restored success receipt.

**[CN-STATE-36]** Restore acknowledgement MUST identify the committed world
generation, new owner incarnations, preserved cut, verified artifact closure,
and admitted guarantee scope. Stale messages from discarded generations MUST
be rejected or retained only as explicitly non-authoritative diagnostics.

**[CN-STATE-37]** A restored operation ledger MUST preserve logical exactly-once
delivery and acknowledgement state while rebinding transport authority to new
incarnations. Retrying restoration or recovering a lost response MUST NOT
duplicate a guest-visible input, completion, fault, or output publication.

## 6. Live templates, forks, and durability

**[CN-STATE-38]** Live fork capability MUST identify the retained source, captured
cut, owner graph, lease scope, and child isolation guarantees. The executor
MUST NOT label a live-template-only continuation as durable restart.

**[CN-STATE-39]** An exact live fork MUST preserve the same complete modeled
state as exact restoration and MUST begin at the same cut and phase. Preparing
the fork MUST NOT perform modeled draining, warm-up, or re-execution prohibited
for exact capture.

**[CN-STATE-40]** Child owners MUST receive independent mutable state and fresh
incarnation-bound resources. Immutable content-addressed state MAY be shared.
Copy-on-write MAY implement isolation, but shared host file offsets, device
queues, mappings, output channels, or native authority MUST NOT leak mutations
between the parent and children.

**[CN-STATE-41]** Forking a host process MUST NOT be treated as sufficient
isolation for external kernel resources. Providers MUST recreate or safely
rebind those resources using their native APIs. In particular, inherited
hypervisor VM/vCPU handles MUST NOT be reused as independent child machines.

**[CN-STATE-42]** Leases MUST bind their source incarnation and retained
generation. Expiry, source exit, or resource revocation MUST make a live source
unavailable. The executor MUST NOT substitute a cold restart unless an admitted
durable artifact and explicit restart operation authorize that path.

**[CN-STATE-43]** Durable restart qualification MUST reconstruct state in fresh
owners after the original source and templates have terminated. Live fork
qualification MUST independently establish concurrent child isolation. Neither
experiment MUST be accepted as proof of the other capability.

**[CN-STATE-44]** Re-execution from a known root MAY be offered as an explicitly
identified reconstruction strategy. It MUST NOT be represented as preservation
of exact native state, and MUST NOT satisfy an operation requiring exact capture
or durable reconstruction of the captured microstate closure.

## 7. Determinism scope and attempt identity

**[CN-REPLAY-1]** Replay and state artifacts MUST declare whether execution is
repeatable under the admitted model, conditional on a recorded transcript, or
an observational nondeterministic attempt. Exact state fidelity MUST NOT imply
repeatability of future physical execution or external input.

**[CN-REPLAY-2]** A world containing a nondeterministic owner MUST default to a
nondeterministic world guarantee. A narrower deterministic scope MAY be claimed
only with an admitted isolation proof excluding every causal path from the
nondeterministic owner into that scope.

**[CN-REPLAY-3]** Isolation proof MUST cover shared storage, clocks, links,
devices, external adapters, fault decisions, assertions, and control actions,
as well as direct compute-to-compute traffic. A nondeterministic observation
used to decide a deterministic node's future input or fault breaks isolation.

**[CN-REPLAY-4]** Guarantee scope MUST be recomputed when topology, shared owners,
or input sources change. Snapshots and findings MUST retain the scope applicable
to their recorded prefix. A later disconnection MUST NOT erase nondeterministic
influence already present in captured state.

**[CN-REPLAY-5]** Every nondeterministic execution attempt MUST have an independent
attempt identity. Planned scenario/configuration identity MUST NOT be used as a
unique native-state identity or as proof that separate attempts are equivalent.

**[CN-REPLAY-6]** Stored observations and state MUST bind their actual attempt,
input provenance, realized owner identities, and recorded output history.
Canonical state content MAY be deduplicated after verification, but attempt
provenance and incompatible guarantees MUST NOT be merged or discarded.

**[CN-REPLAY-7]** Nondeterministic results MUST NOT satisfy byte-identity replay
gates by retrying until a matching outcome occurs. Smoke-test assertions and
success rates MUST report their declared populations and failures without
promoting observed similarity into deterministic execution evidence.

## 8. Exact replay and conditional transcripts

**[CN-REPLAY-8]** Repeatable replay MUST bind initial state, implementation/model
identity, realized graph, complete input sequence, and ordering contract. It
MUST compare execution at the same logical boundaries and phases, independent
of host scheduling and permitted execution chunk sizes.

**[CN-REPLAY-9]** Exact replay validation MUST compare future-affecting state and
event trajectories, including hidden timing state and pending queues. Matching
final architectural output while intermediate event times differ MUST NOT
satisfy exact replay.

**[CN-REPLAY-10]** A replay mismatch MUST fail at the first available validated
boundary and retain evidence for localization. The executor MUST NOT repair
the run by changing event order, resampling input, discarding divergent state,
or accepting an equivalent application result.

**[CN-REPLAY-11]** Conditional transcript replay MUST identify the recorded
boundary inputs, requests, outputs, time assignments, ordering, and declared
preconditions under which replayed responses are valid. It MUST distinguish
recorded physical observation from simulated computation.

**[CN-REPLAY-12]** Before releasing a transcript response, the adapter MUST
validate the corresponding request identity, payload, relevant context, and
boundary preconditions. An unexpected, absent, reordered, or changed request
MUST cause divergence; matching a response by ordinal alone is insufficient.

**[CN-REPLAY-13]** Transcript replay MUST NOT supply recorded outputs for an
unrecorded counterfactual branch. A changed request, fault, world input, clock
policy, or owner realization requires a new execution unless an independently
admitted model defines that behavior.

**[CN-REPLAY-14]** A transcript MUST retain original logical boundary/phase,
sequence and custody identity, raw request/response bytes needed for checking,
and declared physical timing uncertainty. Deterministic replay of assigned
timestamps MUST NOT be described as exact reproduction of physical timing.

**[CN-REPLAY-15]** Capturing complete raw output MAY be optional and subject to
explicit size, retention, and privacy policy. The executor MUST admit replay
only when the retained data is sufficient for the advertised guarantee; hashes
alone MUST NOT stand in for bytes required to reconstruct future inputs.

**[CN-REPLAY-16]** Capture limits MUST be declared before execution. Overflow,
lost records, unresolved truncation, or missing sequence ranges MUST invalidate
any replay claim requiring those records. The system MUST fail that operation
unless the admitted policy permits an explicit downgrade of the resulting
claim. It MUST NOT silently produce a complete transcript claim from incomplete
evidence, or downgrade a capability required by the scenario.

**[CN-REPLAY-17]** A transcript adapter MUST preserve its validation cursor,
pending requests, output custody, and consumed-record state in snapshots. Replay
after restore MUST NOT reissue an external physical side effect or consume the
same response twice unless the admitted protocol explicitly authorizes it.

**[CN-REPLAY-18]** Reconnecting to a live physical system MUST be a declared
external-input transition. It MUST NOT be hidden inside ordinary replay or
restoration, and MUST retain its new nondeterministic provenance and attempt
lineage.

## 9. Backend progression and qualification

A performance-to-fidelity progression can run the same image and application
through hardware-assisted smoke tests, deterministic functional simulation,
and detailed processor simulation. These runs need not share a native state.

**[CN-REPLAY-19]** A KVM-to-Sim-to-gem5 progression MUST use fresh admitted roots
for each implementation unless an explicit state-conversion operation is
selected. Passing a faster stage MUST NOT certify timing, replay, or state
preservation at a later stage.

**[CN-REPLAY-20]** State conversion MUST be a separate operation with a declared
source/target compatibility contract, transferred projection, omissions,
initialization policy, and resulting guarantee scope. It MUST establish a new
lineage and MUST NOT be presented as ordinary exact restoration.

**[CN-REPLAY-21]** Conversion from architectural hardware state to a detailed
model MUST declare how unobserved caches, predictors, pipelines, and timing state
are initialized. Warm-up or draining MAY be part of that explicit conversion
but MUST NOT be attributed to an exact snapshot capture or replay.

**[CN-REPLAY-22]** Exact state qualification MUST compare uninterrupted execution
with capture-without-restore, fresh durable restore, and live fork where claimed.
Capture points MUST contain nonempty future-affecting state, including pending
transactions and ordering ties, rather than only drained boot milestones.

**[CN-REPLAY-23]** Qualification MUST include per-domain negative controls,
identity/model incompatibility refusal, staged-restore failures, stale
incarnation messages, child isolation, chunk-size variation, and missing or
corrupt transcript records. A provider profile MUST advertise only the models
and capabilities for which these claims have executable evidence.

The reference profiles in [07 — Reference Profiles and Examples](07-reference-profiles-and-examples.md)
specialize these requirements for supported implementations. A profile name
does not supply evidence, and this chapter does not grant universal exact-state
support to any simulator, hypervisor, or physical device.
