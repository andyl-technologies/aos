# RFC-0025 — 01. Common node and provider contract

## 01.1. Contract layers

`SimulationNode` is the common public participant contract. It exposes identity,
admitted capabilities, lifecycle, scheduling observations, operations, events,
and state participation. Role interfaces specialize behavior. Providers realize
and supervise the actual owners supporting those interfaces.

The contract applies to event-driven devices as well as independently advancing
compute nodes. A disk does not emulate a CPU loop to qualify as a node. A clock
does not become an independent time authority merely because it is public.

Language-neutral operation meanings in this chapter are normative through their
requirement paragraphs. Rust examples illustrate host-side abstraction shape.
The CNP/1 mapping and cross-process schemas are specified in
[06-provider-protocol-and-security.md](06-provider-protocol-and-security.md).

**[CN-NODE-1]** Every realized public participant MUST implement the common
node contract and each advertised role or facet contract. Advertising a role
without its behavioral implementation MUST cause realization refusal.

**[CN-NODE-2]** Common node operations MUST preserve semantic node identity,
port identity, implementation identity, owner identity, and operating mode
through routing, execution, observations, and artifact publication.

## 01.2. Descriptors and immutable bindings

A node descriptor contains semantic identity, roles, port definitions,
immutable model configuration, and initialization policy. A realized binding
adds implementation/profile identity, selected mode, owner roster, supported
capabilities, guarantees, and incarnation information.

**[CN-NODE-3]** A descriptor MUST be canonical and immutable after scenario
admission. Runtime observations and process identifiers MUST NOT be inserted
into its semantic content identity.

**[CN-NODE-4]** A realized binding MUST resolve every public component to its
execution and capture owners, including components sharing an owner. Missing,
ambiguous, or duplicate authoritative ownership MUST cause refusal.

**[CN-NODE-5]** A provider MUST bind its capability claims to the actual
realized configuration and selected mode. A capability change MUST trigger
explicit readmission or termination before an affected operation executes.

**[CN-NODE-6]** A caller MUST NOT infer optional support from implementation
brand, ISA, role membership, an inherited method default, or another node's
capabilities. Unsupported operations MUST refuse before their effects begin.

Port compatibility and capability predicates are defined in
[02-ports-capabilities-and-admission.md](02-ports-capabilities-and-admission.md).

## 01.3. Host-side interface shape

The following sketch uses opaque admission objects and asynchronous operation
tokens. The supporting types stand for contracts specified elsewhere in this
RFC; the fragment is not a complete crate or a serialization schema.

```rust
trait SimulationNode {
    fn descriptor(&self) -> &NodeDescriptor;

    fn binding(&self) -> &NodeBinding;

    fn status(&mut self) -> Result<NodeStatus, NodeError>;

    fn observe_boundary(
        &mut self,
        request: ObservationRequest,
    ) -> Result<BoundaryObservation, NodeError>;

    fn begin_operation(
        &mut self,
        admission: &OperationAdmission,
    ) -> Result<OperationToken, NodeError>;

    fn poll_operation(
        &mut self,
        operation: &OperationToken,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<OperationOutcome, NodeError>>;

    fn request_cancel(
        &mut self,
        operation: &OperationToken,
    ) -> Result<CancelStatus, NodeError>;

    fn facet(&mut self, kind: FacetKind) -> Result<NodeFacet<'_>, NodeError>;
}

trait ComputeNode: SimulationNode {
    fn compute_description(&self) -> &ComputeDescription;
}

trait BlockNode: SimulationNode {
    fn block_description(&self) -> &BlockDescription;
}

trait FilesystemNode: SimulationNode {
    fn filesystem_description(&self) -> &FilesystemDescription;
}

trait NetworkLinkNode: SimulationNode {
    fn link_description(&self) -> &NetworkLinkDescription;
}

trait ClockNode: SimulationNode {
    fn clock_description(&self) -> &ClockDescription;
}

trait ExternalDeviceNode: SimulationNode {
    fn external_description(&self) -> &ExternalDeviceDescription;
}
```

The methods are object-safe: they have no generic operation methods, no
`Self` return values, and no associated result type that prevents heterogeneous
host routing. Role descriptions are immutable views; state-changing role
operations still use the common admission and completion machinery.

**[CN-NODE-7]** A host adapter MUST provide a runtime-dispatchable common
interface for heterogeneous nodes. It MUST NOT require the coordinator to
downcast to a particular simulator type to invoke common operations.

**[CN-NODE-8]** Host interface values MUST remain process-local. A provider
protocol MUST NOT transmit Rust trait objects, native pointers, callback tables,
or language-runtime layouts as its operation contract.

**[CN-NODE-9]** Optional host facets MUST be explicitly enumerated and
capability-checked. Failure to acquire a facet MUST NOT produce a synthetic
endpoint, empty successful response, or no-op success.

Possible facets include exact execution, quantized execution, preservation,
replay, fault injection, coverage, architectural introspection and debugging.
An exact-preservation facet does not imply replay or efficient process fork.
An introspection facet does not grant debugger mutation permission.

## 01.4. Lifecycle states

The lifecycle states are `Unrealized`, `Prepared`, `Stopped`, `Executing`,
`FailedContained`, `Quarantined`, and `Released`. `Prepared` means native
resources exist but are not available for semantic execution. `Stopped` means
the admitted stopped-boundary contract is established. `Executing` means an
operation is outstanding; it does not imply completed logical progress.

Typical successful paths are:

```text
Unrealized -> Prepared -> Stopped -> Executing -> Stopped
                                      |
                                      +-> FailedContained -> Released

Prepared/Stopped/Executing -> Quarantined -> Released
```

`FailedContained` retains the failed owner's resources and known effects for
inspection or controlled cleanup. `Quarantined` transfers retained supervision
to an owner that can complete containment and reclamation.

**[CN-NODE-10]** A provider MUST expose lifecycle state independently of
semantic activity such as runnable, halted, event-driven, or powered off.
An unknown process status MUST NOT imply a stopped boundary.

**[CN-NODE-11]** Activation MUST occur only after realization admission and
complete initialization or restore validation. A prepared node MUST NOT accept
an ordinary execution admission before that activation succeeds.

**[CN-NODE-12]** A stopped node MUST retain its authentic boundary and all
pending outputs, inputs, queue custody, and incomplete publications until the
coordinator completes the corresponding protocol or containment action.

**[CN-NODE-13]** Lifecycle release MUST occur only after all retained native
resource obligations are discharged or transferred to an authenticated
quarantine owner. A failed cleanup MUST NOT abandon a live process or device
authority by dropping its last owner handle.

**[CN-NODE-14]** Power-off, hotplug, reset, and process replacement MUST use
explicit admitted lifecycle operations. Their supported state transitions and
event effects MUST be included in the selected node profile.

## 01.5. Operation taxonomy and admission

Common operations comprise advancement, admitted input delivery, role-specific
mutation, boundary observation, capture preparation, restoration preparation,
activation, shutdown and resource release. An implementation can group native
suboperations while retaining their specified external effects.

The semantic operation names below align with the CNP/1 mapping. A language
binding can use descriptive method names such as `begin_operation`; the
cross-process names and encodings are those of chapter 06.

| Operation name | Meaning at the common contract boundary |
| --- | --- |
| `exact_run` | Execute within an authenticated exact permission and report the actual stop. |
| `quantum_begin` | Start an admitted quantized window, retaining its actual-progress obligation. |
| `quantum_close` | Close that original window and settle its admitted visibility/evidence policy. |
| `pause` | Establish an authenticated physical stop without inventing a completion coordinate. |
| `input` | Stage or publish one original admitted input under retained owner custody. |
| `observe` | Read an authorized boundary or operation observation without semantic mutation. |
| `capture` | Contribute exact preserved owner state to a specified capture transaction. |
| `prepare_restore` | Prepare an inactive compatible owner from a validated state contribution. |
| `world_activate` | Make the complete restored/realized capture group available after admission. |
| `shutdown` | End semantic access and initiate supervised owner shutdown. |
| `abort` | Contain an incomplete realization, restoration, or world transaction. |
| `release` | Discharge resource custody after authenticated reclamation or transfer. |

`begin`, `poll`, and `cancel` manage outstanding operations; they do not change
the semantics of the contained operation. `hello`, `discover`, `realize`,
`admit`, and `activate` establish the provider relationship and initial
realization. World activation is the atomic publication barrier when multiple
prepared owners participate in one transaction.

**[CN-NODE-15]** Every mutating operation MUST validate its admission against
the actual realization, owner incarnation, boundary generation, operation kind,
required capabilities, and resource limits before beginning an effect.

**[CN-NODE-16]** The executor MUST serialize conflicting operations sharing
an execution or capture owner. Public component handles MUST NOT provide
independent mutable aliases that bypass this serialization.

**[CN-NODE-17]** An operation token MUST identify one original operation and
its retained owner association. A token for another node, incarnation, or retry
MUST NOT authorize polling, cancellation, or publication of this operation.

**[CN-NODE-18]** Beginning an asynchronous operation MUST distinguish refusal
without effects from acceptance with an outstanding completion obligation.
Transport acknowledgement MUST NOT be interpreted as semantic completion.

**[CN-NODE-19]** Completion MUST report actual progress, stop reason, accepted
and published inputs, output/evidence batches, and any required follow-up
custody. Requested progress MUST NOT substitute for observed progress.

**[CN-NODE-20]** A retry after uncertain submission MUST recover the original
operation's status or enter explicit containment. It MUST NOT silently submit
a second mutation or renumber an already published event.

**[CN-NODE-51]** Operation kinds MUST be selected from the negotiated protocol
and admitted profile. An unknown operation or unsupported selected mode MUST
refuse before effects; it MUST NOT be translated to another operation kind.

**[CN-NODE-52]** `quantum_close` MUST refer to the original admitted window
and its retained operation. It MUST NOT create a replacement window, conceal
observed overshoot, or grant exact execution semantics to quantized progress.

**[CN-NODE-53]** `pause` MUST report the established physical stopped state
and actual-progress knowledge. `abort` MUST report containment and retained
effects. Either operation MUST NOT be reported as rollback or successful capture
solely because native execution has stopped.

## 01.6. Preconditions, postconditions, and failures

The table is an informative index into the requirements below and the referenced
chapters. The selected mode supplies the exact receipt structure.

| Operation | Entry condition | Successful result | Failure obligations |
| --- | --- | --- | --- |
| Advance | Current admitted boundary and owner permission | Actual reached boundary and ordered evidence | Retain stop/progress evidence; contain uncertain execution |
| Deliver input | Admitted target port, event key and boundary | Authenticated visibility acknowledgement | Distinguish staged, published and rejected input |
| Observe | Authorized observation scope | Bounded observation with completeness status | Preserve unknown; refuse corrupt observations |
| Capture | Stopped compatible owner roster | Immutable capture contribution | Keep source stopped; discard unpublished partial manifest |
| Restore | Compatible validated state closure | Prepared replacement owners | Keep replacements inactive; quarantine failed native owners |
| Activate | Complete world/group admission | Accessible stopped realization | Keep incomplete world inaccessible |
| Cancel | Original operation association | Cancellation status and eventual terminal receipt | Do not infer rollback or stopped state |
| Release | End of semantic access and retained custody | Reclamation or supervised transfer | Retain resource ownership through failure |

**[CN-NODE-21]** An advance MUST satisfy the selected exact or quantized
timing contract. A stopped completion MUST distinguish horizon completion,
earlier output, input boundary, guest request, idle proof, lifecycle stop,
failure, and unclassified stop where those are supported.

**[CN-NODE-22]** The coordinator MUST NOT continue through an unclassified
early stop by inventing an idle proof or advancing the committed frontier to
the requested ceiling. Such a stop MUST be resolved by the admitted policy or
contained.

**[CN-NODE-23]** Input delivery MUST authenticate the target port, original
event identity, admitted visibility coordinate, and retained native input owner.
Staging input MUST NOT imply guest visibility before its publication receipt.

**[CN-NODE-24]** After an input publication commits, a failure MUST retain the
committed prefix and its original event identities. Retrying the operation MUST
NOT republish that prefix or roll it back without an explicit state transaction.

**[CN-NODE-25]** A completed boundary MUST include every observation and
output required by its admitted inventory contract, including explicit empty
queues where completeness is claimed. Partial collection MUST retain its
original pending obligation and MUST NOT be reported as complete.

**[CN-NODE-26]** Observing a boundary MUST NOT consume an input, recompute a
device response, allocate a new semantic sequence, or independently advance
guest execution. An observation requiring such an effect MUST be an explicit
admitted operation with separate semantics.

**[CN-NODE-27]** A failure result MUST classify whether no effect occurred,
an identified prefix committed, execution may have progressed, or effect
knowledge is unavailable. Unavailable effect knowledge MUST prevent canonical
continuation until reconciliation or containment completes.

**[CN-NODE-28]** Capture and restoration MUST satisfy the selected state
contract in [05-state-and-replay.md](05-state-and-replay.md). The common
interface MUST NOT substitute drained, reconstructed, or replayed state for an
exact-preservation request.

## 01.7. Role semantics and facets

Role interfaces identify semantics rather than shared implementation code.
Several roles can be supported by one owner or exposed as distinct public
component handles.

**[CN-NODE-29]** A compute node MUST declare its architectural profile,
processor count, initialization surface, clock dependencies, and supported
execution observations. Retirement and cycle observations MUST retain their
units and completeness separately from logical time.

**[CN-NODE-30]** A block node MUST declare its request protocol, capacity,
ordering, durability, completion timing, fault surfaces, and mutable storage
state ownership. A completed write MUST satisfy its declared durability level
rather than an inferred provider default.

**[CN-NODE-31]** A filesystem node MUST declare its namespace identity,
request protocol, permission/error semantics, handle lifetime, mutation and
visibility ordering, and complete mutable continuation requirements.

**[CN-NODE-32]** A network-link node MUST declare its endpoint ports,
directionality, minimum latency, queuing/bandwidth policy, delivery ordering,
and loss/fault semantics. It MUST retain pending frames and sequence/RNG state
under its declared capture owner.

**[CN-NODE-33]** A clock node MUST declare its source coordinate, frequency,
epoch, width/wrap rules, transformation policy, and timer relationship. It MUST
retain deadline and transform state within its declared owner domain.

**[CN-NODE-34]** An external-device node MUST declare its physical input
capture, timestamp/quantization policy, containment, outstanding transaction
inventory, and reset/restore limitations. Uncontrolled physical behavior MUST
be represented in its guarantees and event provenance.

**[CN-NODE-35]** A role-specific operation MUST use the common admission,
failure-effect, ownership, and completion rules. A direct role method MUST NOT
be an alternate path around coordinator ordering or preservation controls.

An internal instruction pipeline is implementation state, not automatically a
public node. A model can expose it when that exposure has useful semantics;
its owner and preservation obligations still follow the same rules.

## 01.8. Providers and realization

The provider boundary separates immutable planning from resource allocation.
A provider can realize one owner with many components or several coordinated
owners with a declared capture group.

```rust
trait NodeProvider {
    fn describe(&self) -> &ProviderDescriptor;

    fn prepare(
        &mut self,
        request: &RealizationRequest,
    ) -> Result<PreparedRealization, RealizationError>;

    fn admit(
        &mut self,
        prepared: PreparedRealization,
        admission: &RealizationAdmission,
    ) -> Result<RealizedNodeSet, RealizationFailure>;
}
```

The prepared and realized values retain resource custody. A failure containing
live native resources is an owned failure value, not merely a diagnostic string.

**[CN-NODE-36]** Provider discovery MUST identify executable/model identities,
protocol versions, supported profiles, and qualification evidence before
realization. Discovery MUST NOT automatically select a weaker mode to satisfy
an incompatible scenario.

**[CN-NODE-37]** Preparation MUST validate requested roles, ports, modes,
guarantees, owner composition and resource ceilings before activating execution.
Prepared native resources MUST remain contained and inaccessible to ordinary
scenario execution.

**[CN-NODE-38]** Realization admission MUST bind the complete actual owner
roster and every public component to the requested immutable descriptors.
An incomplete or incompatible roster MUST remain unpublished.

**[CN-NODE-39]** A provider MUST keep each failed prepared or realized owner
under supervised cleanup or quarantine. Its error surface MUST preserve the
authority needed to complete that cleanup.

## 01.9. Runtime routing and participation

The runtime set resolves logical nodes to admitted owner handles. It is a routing
and coordination view, not an independent duplicate state registry.

**[CN-NODE-40]** The runtime set MUST resolve every operation by semantic
node and current admitted binding. Unknown nodes, mismatched roles, stale
incarnations, and foreign operation tokens MUST refuse without dispatch effects.

**[CN-NODE-41]** Timing and execution-admission contracts MUST be retained per
owner or node binding. A heterogeneous runtime MUST NOT cache a single global
contract that erases stronger node guarantees or disguises weaker ones.

**[CN-NODE-42]** Event-driven nodes MUST participate through their input,
pending output, deadline, lookahead and state obligations. Their inactive local
cursor MUST NOT by itself prevent unrelated admitted progress or falsely prove
global quiescence.

**[CN-NODE-43]** Concurrent dispatch MUST retain exclusive owner custody and
commit results according to canonical event order. Host worker completion order
MUST NOT select scenario order in an exact deterministic profile.

**[CN-NODE-44]** Runtime routing MUST preserve incomplete publication and
boundary obligations across polling and retries. It MUST NOT expose a component
as independently reusable while its shared owner remains in an unresolved
operation.

## 01.10. Polling, thread affinity, and cancellation

Asynchronous polling separates host responsiveness from simulation semantics.
It allows an executor to supervise a slow simulator without advancing other
participants based on elapsed host time.

**[CN-NODE-45]** Host interfaces MUST support bounded progress polling or an
equivalent supervised asynchronous mechanism. A poll that returns pending MUST
retain its operation association and arrange a wake or documented repoll path.

**[CN-NODE-46]** Thread affinity MUST be declared by the provider's operational
contract. The common host interface MUST NOT require every owner to implement
`Send` or `Sync`; worker transfer MUST use an explicitly supported ownership
handoff or owning actor.

**[CN-NODE-47]** Cancellation MUST request termination of the original
operation without implying rollback, logical completion, or a stopped boundary.
The executor MUST obtain a final authenticated outcome or preserve containment.

**[CN-NODE-48]** Operational timeouts MUST remain separate from logical-time
permissions. A timeout MUST NOT authorize a guessed event timestamp, successful
advance, replay receipt, or resource release.

**[CN-NODE-49]** Exact execution owners MUST preserve the timing and stop
semantics of chapter 03 across different polling and host-worker schedules.
Quantized execution owners MUST preserve the declared windows, actual-progress
evidence, and nondeterminism provenance of chapter 04.

**[CN-NODE-50]** Optional observability and debugging MUST report their
nonperturbation or noncanonical status explicitly. Enabling a state-mutating
debug facet MUST require a separately admitted and recorded mode transition.

## 01.11. Conformance boundary

The contract establishes interoperable semantics, not a requirement to share
one implementation framework internally. A provider can use a discrete-event
engine, translation engine, cycle model, kernel interface or physical bus.
Its public effects remain subject to the selected contract.

Reference configurations appear in
[07-reference-profiles-and-examples.md](07-reference-profiles-and-examples.md).
Requirement-indexed qualification appears in [08-conformance.md](08-conformance.md).
Implementation choices and extensions appear in
[09-decisions-and-extensions.md](09-decisions-and-extensions.md).
