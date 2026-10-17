# Refactoring and compatibility plan

This nonnormative plan accompanies [RFC-0025](../../rfcs/0025-crucible-node-contract/README.md).
The [source audit](current-state.md) records the revision and source locations.
Task identifiers are defined in the [phased plan](phased-implementation.md).

## 1. Extract participation before adding implementations

Introduce a logical node descriptor, a runtime facade, and explicit owner
registration around the existing QEMU and deterministic host-device paths.
Provider discovery, graph admission, owner realization, and activation are
separate stages. The first facade delegates to the existing implementation;
it does not generate a second queue, execution counter, receipt, or state copy.

The common trait provides descriptor access, observation, and admitted input.
Compute, block, filesystem, clock, and link role facets provide specialized
metadata and operations that remain subject to scheduler admission. Exact and
quantized advancement are separate owner facets. Capture and branching attach
to state owners and describe their actual preservation scope. A collection
dispatcher addresses these interfaces without becoming the node itself.

The sketches in the RFC are architectural interfaces. Implementers should select
concrete Rust method names, lifetimes, error types, and polling representations
after auditing current actor ownership. Do not impose `Send`, a Tokio dependency,
or a trait-object downcast on every native handle. Host-level errors need a
structured failure classification and retained uncertainty evidence, rather
than a catch-all error string or automatic mode fallback.

Cache immutable realized capabilities at admission. Select typed facets once
when constructing dispatch routes. The node abstraction operates at control
and event boundaries, not on each translated guest instruction. Avoid new
per-instruction callbacks, heap allocation, dynamic lookup, or locks in native
execution hot paths.

## 2. Name changes by semantic scope

Names below are proposed source API directions, not new format tags. Audit each
use before changing it; a broad search-and-replace is insufficient.

| Existing symbol or module | Proposed extraction or name | Compatibility class | Task |
| --- | --- | --- | --- |
| `WorldNode` | `ComputeNodeDef` | Source rename first; its encoding stays unchanged | T-CN-02 |
| `NodeTemplate` | `ComputeNodeTemplate` | Source API rename with transition aliases if needed | T-CN-02 |
| `WorldNodeDef` | Keep heterogeneous name; extend declaration variants later | Versioned schema change for new variants | T-CN-08 |
| `NodeId` | Keep | No change; already universal | T-CN-01 |
| `SchedulerNodeId` | Keep initially; inspect whether kind remains needed in the new graph | Ordering and persisted identity if representation changes | T-CN-08 |
| `SimulationBackend` | Collection `NodeRuntimeSet` plus per-node `SimulationNode` and owner facets | Source extraction first; dispatch behavior preserved | T-CN-03 |
| `Backend` | Retained legacy compute adapter, then explicit compute/exact facets | Behavioral migration if mandatory capture methods disappear | T-CN-03 |
| `ConcurrentSimulationBackend` | Concurrent runtime dispatcher with exclusive owner leases | Source extraction; later owner-qualified semantics | T-CN-10 |
| `DeviceSchedulingSubNode` | `ScheduledIoNode` wrapper | Source rename; preserve ordering and checkpoints | T-CN-02 |
| `IoSubNode` / `IoCore` | Keep specialized deterministic I/O facet and lifecycle core | No need for universal rename | T-CN-11 |
| `WorldIoNode.owner` | Consumer/attachment relation; new state-owner relation | Field rename is a schema migration unless legacy encoding retained | T-CN-08 |
| `LinkDef` endpoints | Typed port references and directed causal edges | New schema, graph validation, and identity domain | T-CN-08 |
| `ExecutionHorizon.icount` | Logical horizon plus distinct retirement coordinates | Adapter cleanup first; explicit format/version migration later | T-CN-09 |
| `QemuModeledAttemptLifecycle` | `ModeledAttemptLifecycle` plus exact compute marker facet | Extract common semantics; keep QEMU evidence adapter | T-CN-04 |
| `qemu_campaign_driver` | Neutral modeled driver with QEMU launch/materialization adapters | Source-only extraction before new providers | T-CN-04 |
| `ProductionVmLifecycleLoop` | Common world lifecycle plus compute implementation adapters | Ownership extraction; do not conceal native QEMU resources | T-CN-05 |
| `GdbAttachInfo.qemu_endpoint` | Neutral debugger endpoint for the common surface | CLI/API field and protocol compatibility audit required | T-CN-05 |
| `current_qemu_gdbstub` | Current compute debugger endpoint in shared requests | Public request format migration, not cosmetic rename | T-CN-05 |
| `CampaignLineage.qemu_build` | Realization/owner implementation roster | Canonical identity and codec migration | T-CN-07 |
| `ExecutorCompatibilityProfile.qemu_build` | Versioned implementation compatibility set | Canonical identity and admission migration | T-CN-07 |
| `ExecutorCapabilitySet.qemu_profiles` | Realized provider/profile capabilities | Capability message version migration | T-CN-06 |
| `QemuNode`, `QemuNodeSet` | Keep implementation names | Native adapter names remain accurate | T-CN-03 |
| QMP, VMState, QEMU plugin, native fork receipt types | Keep implementation names | Preserve public/native protocol semantics | T-CN-05 |

Transition aliases are appropriate only for source callers. They must not create
two canonical serializations or two fault target identities for the same old
object. A renamed Rust type may continue to write the old canonical bytes until
the schema migration is admitted.

## 3. Three compatibility tracks

### 3.1 Source-only extraction

Keep scenario bytes, content addresses, hash domains, enum tags, field ordering,
fault names, scheduling tie-breaks, wire numbers, state schemas, and native
receipts unchanged. A source-only pull request includes golden byte and event
trace comparisons against its parent, in addition to behavior tests.

Shared campaign extraction must leave materialization ownership in its adapter.
Fresh execution, exact restore, and native fork retain their own permissions,
resource leases, and shutdown paths. A shared driver gets semantic operations;
it does not acquire authority to restore or terminate processes.

### 3.2 Versioned schema and identity migration

The new graph, capability messages, owner roster, nondeterministic attempt
identity, and state bindings need new versions. Define bounds and canonical
ordering, decode old formats explicitly, and reject unknown required features.
Keep old deterministic readers/writers available where promised. Do not append
fields to a strict canonical format without a version change.

Document the handling of old scenarios and saved states independently. A portable
old scenario may be interpreted as a default QEMU-SIM compute profile under an
explicit legacy policy. An old saved state can be restored only through an
authenticated legacy QEMU path with all existing bindings satisfied. It cannot
be promoted to gem5 or KVM state merely because a new manifest exists.

Changing a canonical fault name such as a `qemu.*` operation is not a formatting
task. Separate implementation lookup names from semantic fault schemas, retain
old registered identifiers, and version any new interpretation. Renaming a node
or its scheduling kind can also change content identities and deterministic
ordering; include such changes in the compatibility review.

The target `superdense-v1` event key orders
`(instant, microstep, phase, consumer, producer, sequence)`. Microsteps preserve
cause before effect through admitted zero-latency chains. This is a canonical ordering
and saved-state migration in T-CN-08/T-CN-09, not a P1 mechanical rename. Preserve
legacy keys byte-for-byte under the legacy compatibility profile. Bind the new
ordering profile and persist microsteps, phases, per-producer sequences, and
pending event keys in the new world and owner-connection closure. Qualify mixed-profile
refusal rather than comparing different key policies as equivalent traces.

### 3.3 New execution behavior

Node-qualified grants, passive event-driven roles, mixed-resolution lookahead,
and quantized acknowledgment require new runtime qualification. They are not
covered by passing source-level rename tests. Keep a strict existing QEMU
adapter available while each behavior is introduced behind explicit profile
selection.

Capture bindings include all state owners, not just compute nodes. Graph state,
pending inputs and outputs, clock origins, ordering sequences, transcript
positions, PRNG state, lifecycle state, and host-device state join the capture
closure. Only the coordinator activates a prepared restored world. A failed or
uncertain partial restore quarantines the whole candidate.

Initial activation uses the same all-owner readiness barrier: every owner and
connection must be prepared and admitted before any participant can produce
externally visible work. Commit the world activation record before ordinary
grants; bind those grants to its roster and owner-ready generation. This rule
applies even when no saved state is involved and makes no claim of simultaneous
physical startup.

## 4. Keep dependency directions explicit

Use the current `crucible` crate for the first host-level descriptors and
facades. Implement host-device wrappers there rather than adding a dependency
from `crucible-device` back to `crucible`. The QEMU crate can implement runtime
facets because it already depends on `crucible`.

Canonical identity values needed by campaign, executor, and storage formats
must sit below those consumers. T-CN-06 records a crate graph before choosing
placement. A new low-level contract crate is justified only if stable shared
types cannot fit an existing lower layer without mixed responsibilities. It
contains plain bounded values and codecs, not QEMU, gem5, OS process launch,
threads, evaluator logic, or dependency on the high-level runtime.

The protocol and shmem crates remain permissive process-boundary components.
Native implementation code remains in its applicable licensing scope. Rust
facets do not license linking simulator implementation into host-side crates.

## 5. Owner registries and composite implementations

Maintain separate registries for logical node routes, execution owners, state
owners, and admitted port connections. An owner may expose multiple logical
nodes; only one operation mutates a shared execution owner at a time. Composite
providers report which state covers each node and internal connection.

Do not create independent mutable clock, cache, or interrupt node replicas of
state already owned inside gem5 or QEMU. Such nodes can be addressable logical
components while their facets delegate into one native owner. Conversely, a
host disk model keeps authoritative overlay and queue state outside the compute
owner. The compute frontend owns its virtqueue, pending DMA, and interrupt state;
the capture closure includes both owners and their connection state.

For concurrency, preserve deterministic candidate preparation and canonical
commit order. Host completion order does not become simulation ordering. Owner
aliases remove conflicting RUNs from a concurrent dispatch set. Initially
qualify mixed implementations through serial dispatch; add parallel dispatch
only with adversarial completion-order tests and unchanged traces.

## 6. Admission policy is not feature detection after failure

Providers describe support; realized nodes retain the selected profile and
qualified facets. Admission checks the entire graph's timing, port, capture,
fault, and replay requirements before activation. Configuration determines
capabilities: architecture, CPU and memory model, device transport, queues,
clock sources, shared mappings, and external threads matter.

Keep nondeterminism, event resolution, physical pause, capture scope, branching,
and transcript replay as independent fields. Quantized timing does not imply
determinism; architectural capture does not imply exact continuation; exact
modeled capture does not imply preservation of real physical microstate.

An implementation declaring a facet without the required retained proof must
be rejected by qualification or admission. A later unsupported-operation error
must fail or quarantine according to contract, not silently change modes.

## 7. Review and change separation

Each extraction commit contains its intended source rename or moved semantic
core and necessary mechanical import updates. Keep unrelated formatting out.
Each functional commit describes the new admitted behavior, version change,
negative cases, tests, and performance impact.

Reviewers inspect both human legibility and ownership boundaries. Successful
formatting does not show that an extraction preserved native custody. Every
future Rust change also compiles application unit and integration targets using
the repository's `checks.rust.aos-test-targets` check. Boundary changes run ABI
and license gates; a documentation-only change does not need native builds to
pretend that future protocols already exist.
