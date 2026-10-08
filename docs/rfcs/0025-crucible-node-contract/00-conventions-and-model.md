# RFC-0025 — 00. Conventions and simulation model

## 00.1. Scope and status

This chapter defines the conceptual model for the Crucible node contract.
The contract describes a target architecture, independent of a particular
simulator, programming language, transport, or migration sequence.
Compute, storage, filesystem, network, clock, and external-device participants
share scheduling, event, capability, and state-preservation rules.
Their role-specific behavior remains explicit.

QEMU, gem5, a hypervisor-assisted worker, and a physical-device adapter are
possible implementations of nodes. None defines the public meaning of a node.
A machine is a composition of compute and device nodes, possibly implemented
within one process. A scenario is a composition of machines and other nodes.

Implementation work and compatibility sequencing are recorded separately in
the [migration plan](../../plans/crucible-node-contract/README.md).
Examples and Rust fragments in this RFC are design fixtures; they do not assert
that a matching shipping interface or qualified provider exists.

## 00.2. Requirement language and traceability

Requirement keywords in capital letters use the interpretation of BCP 14,
[RFC 2119](https://www.rfc-editor.org/rfc/rfc2119.html) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174.html). Lowercase words carry
their ordinary prose meaning. This RFC places binding requirements in uniquely
identified paragraphs; surrounding explanations and sketches are informative.

**[CN-MODEL-1]** A conformance claim MUST identify the implemented requirement
set, node roles, operating modes, guarantee profiles, and protocol versions;
it MUST NOT claim compliance with unimplemented optional facets.

**[CN-MODEL-2]** Each normative requirement in this RFC MUST retain its unique
identifier across editorial revisions. A semantic replacement MUST identify
the superseded requirement and its compatibility consequences.

Requirement families are `CN-MODEL` for this chapter and `CN-NODE` for the
common runtime contract. Other chapters define their own requirement families.
Conformance evidence is indexed by these identifiers in
[08-conformance.md](08-conformance.md).

## 00.3. Vocabulary

| Term | Meaning |
| --- | --- |
| Node | A semantically named participant exposing role-specific behavior through the common contract. |
| Role | The semantic interface of a node, such as compute or clock. |
| Facet | An explicitly supported additional interface, such as debugging or fault injection. |
| Implementation | The code, models, configuration, and compatibility profile that realize a node. |
| Provider | A factory and supervisor that realizes one or more nodes and their owners. |
| Operating mode | The selected execution policy, such as exact simulated time or quantized execution. |
| Guarantee | An independently qualified property, such as exact preservation or repeatable execution. |
| Port | A named, typed event endpoint of a node. |
| Connection | An admitted relationship between compatible ports with explicit timing and ordering rules. |
| Coordinator | The authority that admits cross-owner events and commits scenario progress. |
| Executor | The operational driver that invokes admitted node operations under resource controls. |
| Execution owner | The exclusive runtime authority over an indivisible advancing state domain. |
| Capture owner | The exclusive authority that serializes or preserves an indivisible state domain. |
| Capture group | Owners whose state and connections form one atomic preservation transaction. |
| Realization | An instantiated implementation roster for an immutable scenario description. |
| Incarnation | One physical lifetime of an owner; restore or process replacement creates another. |
| Boundary | An authenticated stopped state together with event and progress observations. |
| Event-driven node | A node that progresses through admitted events rather than an independent instruction loop. |
| Logical tick | One picosecond on the canonical simulation coordinate. |
| Retirement count | A separately typed architectural instruction observation; it is not time. |
| Exact timing | Progress and event visibility satisfying the precise admission rules of chapter 03. |
| Quantized timing | Progress and event visibility satisfying a declared window/uncertainty policy of chapter 04. |
| Exact preservation | Retention of all state affecting the future promised behavior at the captured boundary. |
| Repeatability | Equal future observations under the same compatible state, implementation, inputs, and policy. |
| Replay | Re-execution governed by a recorded input/decision history and a stated equivalence contract. |

The coordinator and executor can reside in one host process. Their distinct
authorities remain relevant: a resource supervisor does not select semantic
event order, and a semantic scheduler does not manufacture native permission.

## 00.4. Roles, implementations, modes, and guarantees

A compute role describes architectural execution, not a particular CPU timing
algorithm. A clock role describes readings and programmed deadlines, not the
host wall clock. A network role describes admitted frames and delivery, not an
uncontrolled host socket. Detailed descriptions appear in
[01-node-contract.md](01-node-contract.md) and
[02-ports-capabilities-and-admission.md](02-ports-capabilities-and-admission.md).

**[CN-MODEL-3]** Node roles MUST be independent of implementation selection.
An implementation-specific restriction MUST be represented in the realized
capability/profile contract rather than hidden in the meaning of a role.

**[CN-MODEL-4]** Timing precision, run repeatability, exact preservation,
portable restoration, deterministic replay, and physical fork support MUST be
represented and admitted independently. Support for one MUST NOT imply any
other guarantee.

For example, a nondeterministic worker can preserve a complete stopped state
without promising identical futures after restoration. An exact-time model
can be repeatable while lacking complete checkpoint serialization. Neither
case qualifies for capabilities it has not demonstrated.

**[CN-MODEL-5]** An implementation or mode change MUST create a distinct
realization identity when it can affect promised semantics. A stateful artifact
MUST NOT be reinterpreted as belonging to the replacement realization.

**[CN-MODEL-6]** Admission MUST derive scenario-wide guarantees from all
participating owners and connections. It MUST NOT upgrade a quantized or
nondeterministic participant because another participant has stronger guarantees.

The policy may admit mixed exact and quantized owners. Such admission means the
complete mixed contract is accepted; it does not make the complete scenario
exact or deterministic. Policy and evidence appear in
[04-quantized-and-physical-nodes.md](04-quantized-and-physical-nodes.md).

## 00.5. Semantic identity and physical authority

`NodeId` identifies semantic membership within a scenario. Scheduling roles
describe how that member participates. Owner IDs identify instantiated authority
domains, not guest-visible names. An implementation identity binds the executable,
model parameters, state schema, and qualified compatibility profile.

**[CN-MODEL-7]** Every public node MUST have a unique canonical semantic
`NodeId` within its scenario. A scheduling role, port name, implementation name,
or process identifier MUST NOT substitute for that semantic identity.

**[CN-MODEL-8]** A node's semantic identity MUST remain distinct from its
realization identity, execution-owner identity, capture-owner identity, and
physical incarnation. Equality of semantic names MUST NOT authorize mutation,
capture, restoration, or continuation.

**[CN-MODEL-9]** A scheduling identity MUST resolve to one admitted node and
role in the immutable realization roster. An arbitrary caller-supplied role tag
MUST NOT create a second participant or bypass role validation.

**[CN-MODEL-10]** Any receipt authorizing an operation MUST be bound to its
actual owner, incarnation, admitted realization, operation, and boundary
generation. Copying descriptor fields MUST NOT create equivalent authority.

The distinction allows the same logical machine to receive a fresh process
after a valid restore without pretending the new process is the old owner.
It also permits a composite model to publish CPU and clock components without
granting independent access to one shared simulator state.

## 00.6. Composition and exclusive state ownership

Containment describes a model hierarchy: a machine can contain compute, memory,
clock, interrupt, and I/O components. Connections describe interactions.
Capture grouping describes preservation. These relationships are independent.

**[CN-MODEL-11]** Every mutable state item that can affect future promised
observations MUST have exactly one authoritative owner. Node descriptors,
coordinator indexes, and component views MUST NOT create duplicate authoritative
copies of that state.

**[CN-MODEL-12]** Nodes implemented within one indivisible advancing domain
MUST share an execution owner. Their public handles MUST NOT admit simultaneous
independent operations that mutate the shared domain incompatibly.

**[CN-MODEL-13]** State implemented within one indivisible capture domain MUST
share a capture owner. A capture manifest MUST enumerate each authoritative
payload once and refer to that payload from its public component views.

**[CN-MODEL-14]** Containment and consumer connections MUST NOT implicitly
transfer state ownership. A shared disk, link, clock, or external adapter MUST
retain its declared owner when connected to multiple consumers.

**[CN-MODEL-15]** A composition MUST identify its owner roster, dependency
relationships, and atomic capture groups before execution admission. A provider
MUST NOT conceal a stateful component whose omission changes promised future
behavior.

Native internal interactions can remain inside one simulator. Publishing an
internal component as a node does not require sending every internal cache or
pipeline event across the process boundary. Its state and scheduling obligations
remain included in the owning domain's contract.

## 00.7. Canonical time and observations

The canonical coordinate is an unsigned 64-bit picosecond value, with zero at
the admitted scenario epoch. Node-local clocks can use anchored mappings.
CPU cycles, instruction counts, timer frequencies, and physical timestamps have
their own units and conversion identities.

**[CN-MODEL-16]** Shared logical time MUST use checked `u64` picosecond
arithmetic. Overflow, an invalid mapping, or an unrepresentable required
coordinate MUST cause an explicit refusal rather than wrapping or saturation.

**[CN-MODEL-17]** Instruction retirement, cycles, host elapsed time, and
logical time MUST remain distinct observations. The common node contract MUST
NOT apply a universal fixed time-per-instruction conversion.

**[CN-MODEL-18]** Clock transformations and guest-visible clock faults MUST
NOT silently alter the coordinator's shared causal coordinate. Their effect on
readings and programmed deadlines MUST be explicit in the clock facet contract.

**[CN-MODEL-19]** An observation whose value or boundary is unavailable MUST
retain an explicit unknown state. Unavailable data MUST NOT be represented as
zero, no pending event, an empty complete inventory, or successful progress.

The timing model and boundary ordering are specified in
[03-time-and-scheduling.md](03-time-and-scheduling.md). Preservation of mappings,
clock state and uncertainty is specified in [05-state-and-replay.md](05-state-and-replay.md).

## 00.8. Authority and trust boundaries

The provider retains native state and operational authority. The coordinator
retains cross-owner event-order authority. The executor retains admitted
resource and lifecycle controls. Observational subscribers retain neither
execution permission nor state ownership.

**[CN-MODEL-20]** A provider MUST NOT independently choose cross-owner event
order, originate undeclared application traffic, or advance beyond admitted
permission. Internal scheduling within its declared owner domain MUST satisfy
the published external event and timing contract.

**[CN-MODEL-21]** The coordinator MUST authenticate actual owner observations
before committing progress or input delivery. Capability declarations and
well-formed messages MUST NOT be accepted as proof of physical completion.

**[CN-MODEL-22]** Observation, debugging, and diagnostics MUST preserve the
admitted canonical execution contract unless an explicit noncanonical mode is
selected and recorded. Host diagnostic timing MUST NOT become an implicit
semantic input to an exact deterministic mode.

Cross-process representation, protocol negotiation, containment, and security
are defined in [06-provider-protocol-and-security.md](06-provider-protocol-and-security.md).
Reference profiles are defined in [07-reference-profiles-and-examples.md](07-reference-profiles-and-examples.md).
Extensions and unresolved implementation choices are tracked in
[09-decisions-and-extensions.md](09-decisions-and-extensions.md).
