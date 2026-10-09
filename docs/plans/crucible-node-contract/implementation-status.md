# RFC-0025 implementation status

The implementation scope is the complete [RFC-0025](../../rfcs/0025-crucible-node-contract/README.md),
including current QEMU integration, host-model nodes, exact gem5 preservation,
device parity, quantized KVM, external providers, and qualification. Shared
schemas and test adapters establish component behavior, not native support.

## Committed stages

| Commit | Change | Verification |
| --- | --- | --- |
| `0ab383efbdc72a8435ddd7342adec5cfc8a4132c` | Frozen reference after merging master | [Reference baseline](reference-baseline.md); the runnable reference needs the explicitly recorded vendor-hash correction |
| `6d91c87213` | Compute definitions, templates, scheduled I/O, and runtime collections receive accurate source names; compatibility aliases remain | Four compatibility tests use six vectors emitted by the archived parent; 39 compatibility, event graph, and content-address regressions pass |
| `39f4839292` | Modeled campaign semantics move into a backend-neutral driver | 82 existing campaign regressions and two digest golden tests pass; native materialization and marker evidence remain in the QEMU adapter |
| `d6697da092` | Portable contract, bounded transport, request journal and content custody | 21 contract and 25 provider tests, strict Clippy, and two package checks pass |
| `0c8ee840bd` | Separate observed execution provenance, original dispatch custody and authenticated CAS closure | 12 focused tests and all campaign integration targets compile; the preceding complete campaign suite passes 441 tests |
| `7a98fb0cde` | Equivalent integral JSON version and phase forms preserve canonical identities | 21 contract tests and three interoperability regressions pass |
| `ea179b4b00` | Authenticated connections, typed bodies, native custody, real checksum child, independent protocol probes and immutable installed profile | 86 provider unit tests and seven actual child-process tests pass; strict Clippy passes |
| `c98d5217e1` | Portable process-boundary license inventory and corresponding-source notices | License-boundary gate passes 18 cases; ABI and protocol golden checks pass 25 cases |
| `d37644f0e7` | Opt-in Linux x86 TSC projection and native run-owner clock control | Native kernel objects compile; 100,000 independent arithmetic cases pass; no live KVM execution |
| `15167101c9` | Source-built gem5 and DMTCP, nondraining event cuts and private-resource restoration | x86 and ARM O3/cache/DDR3 continuation fixtures survive source death and fresh restoration; complete state coverage remains unqualified |
| `d494cb3b67` | Runnable authenticated public checksum provider, native operation journal and independent conformance tool | 90 provider unit tests, four public-endpoint integrations and seven child-process tests pass; strict Clippy passes |
| `746d9f6407` | Capped KVM pvclock and software LAPIC timer source mediation | Common KVM, x86, VMX, SVM and LAPIC objects compile; 400,000 arithmetic cases and the native admission-policy truth table pass; no live KVM execution |
| `1b86797ab8` | Coherent workspace manifests, lock, shared source-vendor identity and crate-layer inventory | Locked metadata, actual source vendoring and crate-layer gate pass |
| `de7080cf59` | ARM architectural counter/timer source mediation and retained completion acknowledgment | Native x86 and ARM objects compile; 600,000 arithmetic cases pass; no live KVM execution |
| `e4e228d1a3` | Shared world trigger and debugger policy | 23 focused API regressions pass |
| `4088d46711` | Complete coupled-owner executor guarantees | Six executor capability regressions pass |
| `2ceb03754c` | Whole-graph admission, original causal scheduling, exclusive native runtime and authenticated host archives | Complete core library passes 690 tests with one pre-existing native fixture excluded; required application test-target compilation passes |
| `832a5c1a96` | Autonomous kernel run-ceiling gate and strict architecture admission | Native x86 and ARM objects compile; 700,000 arithmetic/admission cases pass; unsupported ARM event-stream mediation refuses strict admission |
| `b92a9da932` | Installed mixed-node daemon execution and private CLI control | 446 campaign, 344 CLI and 20 daemon tests pass; six actual connected-node witnesses and the CLI restart scenario pass |
| `c5dd8e0346` | Exact scripted request nodes and native pending-queue archive branching | 19 native adapter tests and three actual Block/9p/network archive branch regressions pass; expanded complete core suite passes 699 tests |
| `6f79344ee4` | Existing SHA256 dependency for process-image auditing | Locked metadata and actual source-vendor derivation pass; external package selection is unchanged |

Legacy codec bytes, hash domains, fault identifiers, and existing exact QEMU
restore semantics remain unchanged by these source extractions. New node
records use separate public schemas and cannot relabel legacy authority.

## Component verification in progress

| Component | Implemented behavior | Remaining integration or qualification |
| --- | --- | --- |
| Portable contract | Bounded scalar values, checked coordinates, closed CNP schemas, strict JSON, RFC 8785 canonical identity and normative vectors; 21 tests pass | Installed implementations and live native state require host authentication beyond these records |
| Provider transport and custody | Typed bounded framing, authenticated negotiation/reconnect, fatal fencing, original native journals, method correlation, bounded content custody and runnable public checksum endpoint | Additional native backend implementations and their complete lifecycle qualification |
| Whole-graph admission | Ownership, ports, immutable content, installed native evidence, qualifications, mode acceptance and zero-time-cycle checks; complete library and actual connected graphs pass | Complete QEMU/gem5/KVM installation qualification |
| Runtime | Exclusive owner custody, readiness/activation, retained operations, cancellation, publication and native quarantine; actual mixed daemon graphs and original nonce retries pass | Complete QEMU/gem5 implementations of those interfaces |
| Causal scheduling | Exact and quantized grants, conservative native bounds, original staged-input acknowledgment, superdense ordering and bounded paused snapshots; real connected-node byte/provenance checks pass | Full native CPU/device timing and broader backend concurrency qualification |
| Capture and restore | Backend-bound closure authentication, bounded signed archives and inactive all-owner staging; actual clock and pending Block/9p/network queues survive cold isolated branching without redispatch | Production archive commands, connected transfer-state closure and native backend complete-state qualification |
| Common lifecycle | Shared world trigger and debugger policy with API regression coverage; installed profiles use complete-owner activation | Complete native backend initial/restore activation |

These rows distinguish implemented shared behavior from production wiring. An
unsupported native operation must refuse admission or execution; passing a
model-only test cannot supply missing native stop or state evidence.

## Native workstreams

The [gem5 audit](gem5-feasibility.md) records the pinned source build and the
full-state gaps in stock checkpointing. Nondraining capture of an arbitrary
reached state, fresh-process durable restoration, resource-isolated branching,
guest device parity and architecture qualification remain required. A gem5
package that compiles is not an exact Crucible backend.

The native event-only process-image fixture preserves 15 queued equal-time
events across source-process death and two fresh restorations. A separate
open-file fixture reconstructs two divergent restorations without changing the
origin or sibling resource contents. These are component continuation tests;
detailed CPU, cache, memory-controller and complete external-resource coverage
remain separate requirements.

The x86 and ARM O3 fixtures additionally preserve guest execution, caches and
DDR3 memory across source-process death, removal of origin resources and two
concurrent restorations. Read-only native observers currently expose partial
event, RNG and object inventories. Typed CPU, cache, memory and device visitors
are being implemented; partial observers do not qualify exact admission.

The [KVM audit](kvm-feasibility.md) records the clock/timer/interrupt mediation
requirements. The current machine does not expose `/dev/kvm`, so native KVM
execution and qualification have not occurred. Quantized protocol and external
reference-device work can proceed independently; it cannot substitute for KVM
clock, device, architectural capture or multi-vCPU tests.

The Linux patches implement VM-wide capped/frozen x86 TSC read/write mediation,
run-owner accounting, pvclock, software LAPIC timers, ARM architectural
counters/timers and an autonomous run-ceiling admission gate. Native source
objects and integer/ABI checks pass locally. Strict ARM admission refuses an
unmediated architectural event stream. Complete device mediation and live
execution remain unqualified, so these components cannot qualify a runnable
KVM node by themselves.

The opt-in QEMU source mechanics build for x86_64 and aarch64. Actual x86 probes
cover exclusive retirement, equality ceilings, retained fractional instruction
credit and partition invariance; existing icount and vCPU-service unit tests
also pass. Nonzero phases, boundary settlement, halted idle, complete device and
input queues, fork and native journal preservation remain unsupported in this
partial path. Diagnostic binaries retain the previous source identity until the
new atomic source artifacts are reconstructed and checked.

## Performance evidence

The frozen parent, with its documented vendor-hash correction, passes the
production Linux boot witness twice and seven negative controls. Launch-to-ready
times are 48.58024 and 37.32346 seconds (mean 42.95185), with substantial host
variance. A distinct diagnostic guest averages 30.36386 seconds; these different
guest/placement results must not be compared as a speedup. The
[baseline record](reference-baseline.md) identifies executables, guest bytes,
clock policy, host placement and measurement limits.

There is no candidate speedup claim yet. Candidate comparisons must reuse the
same guest bytes and workload, record interventions and compare full witnesses.
Raw traces, build logs and state dumps remain local; only concise results and
artifact identities belong in the change description.

## Completion criteria

Task and requirement coverage remains governed by the
[phased implementation plan](phased-implementation.md) and
[qualification plan](qualification-plan.md). The existing requirement map is a
work allocation, not a conformance certificate. Completion requires the full
native and public-integration exit criteria, application test-target
compilation, relevant ABI/license checks, adversarial state/causality tests and
the final local performance comparison.
