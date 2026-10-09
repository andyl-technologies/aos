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
| `8130c7dfa9` | Signed atomic QEMU source for native CPU, PIT and KVM components | Atomic source/tree/signature regeneration and exact patch-license ledger pass |
| `52a34a1780` | Process-separated native QEMU command and observation plumbing | 17 portable, nine GPL-side and five host tests pass; three live CPU/PIT partition witnesses pass |
| `ccc87ca2ce` | Script continuation rejects invalid future evaluation and group cursors | Five focused source tests pass |
| `a109318848` | Original future-publication custody across phase cuts and mathematical-top closure | Five source, one coordinator future-birth and three closure/overflow regressions pass; original pending deliveries survive snapshot restoration |
| `1061007b83` | Independent complete native process-image custody authentication | Both guest ISAs pass authentic closure, source exit, original resource removal and two fresh restores; collector passes 23 adverse cases |
| `609e056961` | Bounded authenticated archive content reads | Actual clock archive read, exact limit, foreign metadata and absent reference checks pass |
| `8ee83d1181` | Streaming native image hashing through the existing BLAKE3 dependency | Actual source vendoring passes; external packages, checksums and dependency edges remain unchanged |
| `d556fa9318` | Complete original scheduler payload closure before capture authentication | Original-payload regression and actual source-gone Block/9p cold restores pass |
| `7c46d0bf3b` | Installed exact Source/Block/readonly-9p graph, explicit archive-only bindings and common exact execution planning | 13 ordinary and nine actual native observer regressions pass; two isolated cold continuations preserve original pending bytes, fids, dirty overlay and event history |
| `1b36fe6ffe` | Versioned native writer custody, retained hold diagnostics and matching signed atomic QEMU source | 144 portable protocol cases, 46 focused plumbing cases, four live native witnesses and strict checks pass; source/tree/signature regeneration passes |
| `fb87002297` | Independently authenticated public CNP client, byte-linked profiles and complete dynamic control-evidence transfers | 121 provider unit cases with one excluded native fixture, six actual public conformance scenarios, seven companion-process cases and an actual client launch/evidence/retry/reap witness pass; all-target provider strict Clippy passes |
| `070eeaeed7` | Backend-bound streamed native archives, complete-world capture credits and supervised inactive restore capsules | Three persistent storage and three pre-effect world-credit regressions pass; 725 core tests compile and core library strict Clippy passes; these shared checks do not qualify a backend |
| `c6a08382a7` | Process-separated gem5 controller, bounded journals, public service and backend-bound archives | Both guest ISAs pass native source-death and fresh-continuation fixtures; unsupported configurations refuse rather than inheriting qualification |
| `7c5274670b` | Common gem5 runtime adapter and retained observation/capture custody | Adapter regressions and current native profile checks pass; mixed-world native archive qualification remains in progress |
| `931ebbc90f` | Original native CPU/IRQ source diagnostics and production reader fencing | Configured two-ISA source builds, native units and actual source-fault refusal probes pass; signed atomic source reconstruction passes |
| `fe579e75ed` | Bounded KVM component controller with explicit unavailable and unqualified outcomes | Component policy and response regressions pass; no actual hardware execution is available on this machine |
| `56d415356c` | gem5 native journal and controller hardening | Scoped negative controls and native continuation regressions pass; full-system devices remain a separate qualification unit |
| `210b0dfdea` | Source-built AArch64 Linux, firmware and matching complete-source prerequisites | Kernel and guest fixture packages build locally; binary/source identity checks pass |
| `68cfc299e1` | Installed public launch edition three and typed reference-device controller | 123 provider unit tests, two actual client integrations, six public conformance cases and seven companion-process cases pass; one native fixture is excluded; strict all-target provider Clippy passes |
| `50a06eaa94` | Original native QEMU construction epochs, retained callback cuts, matching signed atomic source and independent KVM component edition | 168 protocol cases, GPL/host journal checks, two-ISA native builds and 46 native unit cases pass; actual initializer, four V4 controls and source-fault regressions pass; atomic reconstruction passes |
| `781b52d64f` | Locale-independent native auditor receipt channel | Actual AOS-built Bash test preserves original input and strict JSON under an inherited uninstalled locale |
| `0d062b6fff` | Source-built gem5 native CPU/cache/memory/event/device observers, bounded modern VirtIO mechanisms, ISA corrections and an optional absent-register platform | Two-ISA stopped O3 observations, 30 CPU and 17 memory diagnostic cases, CPUID handler/guest boundaries, 4,358 PMULL cases and ten native Packet controls pass; partial typed diagnostics remain explicitly incomplete |
| `d6389f1fa8` | Immutable fixed-workload gem5 profile and actual ARM Linux network/block/9p driver gates | Three real Linux driver packages pass; the refreshed profile passes sandbox witnesses and all 25 installed artifact identities independently remeasure; independent host fresh recapture exposed resource-root custody failure, so the successor profile remains unqualified until corrected host gates pass |
| `1ebca987b0` | Native restored gem5 resource-root rebinding with independent source-death and fresh-recapture qualification | Both ISAs pass forced-private-root builder witnesses and independent host source-death/two-fresh-restore witnesses, including supplementary branch files and fresh recapture; all 25 installed artifacts independently remeasure |
| `f735a42f96` | Signed atomic QEMU fixture alignment for native control and absolute instruction service | Nineteen extracted proofs, eleven compiled mutation controls, complete configured two-ISA builds and 46 native units pass; signed source/tree/signature reconstruction passes; production binary/source pair build remains in progress |

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
| Capture and restore | Backend-bound closure authentication, bounded signed archives and inactive all-owner staging; actual clock and pending Block/9p/network queues survive cold isolated branching without redispatch; installed Source/Block/readonly-9p graphs preserve original future publication and connected payload custody after source removal | Qualified host archive commands pass four actual CLI cold-restore tests and 30 daemon regressions; native backend complete-state qualification remains |
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

The independently audited process-image mechanism now establishes complete
opaque native closure for the fixed freestanding checksum workload on both
guest ISAs. It checks captured map, thread-context, descriptor and supplementary
file bytes, then survives source exit and two independent restorations. The
[process-image evidence](gem5-process-image-evidence.md) fixes the tested source,
artifacts, host ABI and limits. This result does not qualify arbitrary guest
programs, Linux devices or complete typed diagnostics. The common runtime,
installed qualification and mixed-world native archive bridge remain in progress.

Independent host reruns exposed a restored-resource custody defect in the
initial committed-source profile refresh: the capture plugin retained the
source resource-root environment while the restored controller used a fresh
private root. The corrected controller rebinds and reads back the native
resource root before callbacks resume. Its successor profile passes both
forced-private-root builder witnesses and independent host source-death,
two-fresh-restore and fresh-recapture witnesses on both ISAs. Those tests cover
actual supplementary branch files; all 25 installed artifacts independently
remeasure. This qualification remains limited to the fixed freestanding
workload and does not extend to full-system Linux or other devices.

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
partial path. CPU/PIT components and the versioned writer-cut diagnostics are
carried by the verified signed atomic artifact. The actual writer hold retains
three initial pending bottom-half callbacks without running or discarding them;
their unknown causal semantics correctly refuse native execution at that cut.
The GPL reader/worker gate, complete callback birth and payload ownership,
boundary settlement, device mediation and fresh native continuation remain
required before qualifying the common QEMU node.

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
