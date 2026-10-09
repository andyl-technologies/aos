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
| `8eb08881cd` | Exact guarded native headers and timer registration in mandatory QEMU source validation | All 269 static checks and three source mutation controls pass; production binary and matching complete source build, and both installed ISA refusal suites pass |
| `7e924dfeac` | Complete prepared-world authority, native input provenance, public reference runtime and conditional transcript boundaries | Strict production/all-target checks, 765 core regressions, actual public preparation and two-provider original-byte delivery/checksum/whole-custody reclamation pass; replay continuation and archive relocation remain separate work |
| `c0c94c9225` | Complete durable public-world activation with separately rooted coordinator bytes | Three actual filesystem-backed public-provider tests pass, including fresh reconciliation, corrupt/missing bytes, partial root writes and lost commit acknowledgment |
| `fd472ff836` | Authenticated native gem5 saved-copy relocation and co-retained patched DMTCP source | Both installed ISA witnesses remove the complete original image/resource/temporary namespace before two fresh continuations and recaptures; 25 native relocation controls and all 26 artifact identity checks pass |
| `3e245e6095` | Immutable negotiated provider features and bounded observation-only evidence | 151 provider unit cases, four actual client cases, six public conformance cases and seven companion cases pass; strict checks pass; observer handles cannot execute or acknowledge operations |
| `612f13bd63` | Original native phase/timer inventories and deterministic preparation barriers, with matching signed QEMU source | 190 protocol and 605 GPL-side cases, 13 host checks and strict checks pass; both installed ISA refusal suites, live PIT ordering and source-fault probes pass; production signed-source regeneration and matching corresponding source pass |
| `ac2b78c6d7` | Backend-neutral attempt evidence and bounded modeled event retention | 29 attempt, sealing and modeled-choice regressions pass with original bytes and compatibility aliases preserved |
| `3c769248d1` | Accepted-input bookkeeping failure retains original provider custody | Three actual two-provider/input-failure cases and production/all-target strict checks pass |
| `6b275160cc` | Native DMTCP restores captured file permissions | Original private files remain mode 0600 across two fresh restores and another source-gone continuation; both installed ISA namespace-deletion/private-mode witnesses pass and all 27 artifact bindings independently remeasure |
| `ba1f14accc` | Qualified logical property namespaces and read-only assertion deadline inspection | Four property admission/legacy identity regressions and strict production checks pass |
| `04892b92ae` | Signed continuation edition two, complete saved-copy manifests and original native process custody | 33 provider and 28 core gem5 checks pass; an actual umask-000 subprocess proves exclusive private file installation; the mixed x86 in-flight operation witness passes with two complete fresh worlds |
| `8e2c95a6fb` | Source-built independently measured public reference implementation | Package runs 152 provider unit cases, seven emitter cases, four actual client cases, six public conformance cases, seven companion cases and production Clippy; independent installed measurement verifies the complete runtime/build graphs and 290 regular ELF objects |
| `2b9492c247` | Installed bounded KVM candidate and separately versioned userspace-response caller | 34 controller/QMP checks and strict all-target checks pass; candidate preparation cannot qualify hardware execution |
| `7e31d0ab40` | Signed QEMU userspace-exit ledger and mandatory source validation | Production two-ISA build, 46 native units, 19 extracted proofs, 15 ledger controls, nine compiled mutation controls, signed-source regeneration and matching complete source pass; no live KVM qualification |
| `cd6c39b848` | Authenticated extension schemas, dependency admission and immutable selected closure | 25 admission, four contract and five native archive controls pass; unsupported archive extensions refuse before allocation; production strict checks pass |
| `9f8a6dae25` | Original gem5 Terminal birth, acknowledgment and bounded continuation mechanisms | Pure native Terminal and actual ARM PL011 continuations preserve held original bytes and acknowledgments through source deletion and two fresh branches; complete full-system closure and Linux boot qualification remain separate |
| `02832565cd` | Measured installed gem5 profile and supervised complete-world native cold continuations | Both architecture native witnesses pass; three installed policy checks, five backing checks, selected ISA/budget checks and actual actor-unwind reclamation pass; mixed native factory remains test-only |
| `5f958e0e52` | Exact original typed content roles for identical transcript bytes | All 17 registered transcript cases and production strict checks pass; altered bytes and unretained media roles refuse |
| `c01aa7496c` | Legacy host archive extension guards at capture, admission, construction and staging | All nine host archive cases and production strict checks pass; actual source bytes remain unchanged and bypass staging refuses before allocation |
| `2ae4d34e2a` | Local deliberate panic-test allowances for extension schema regressions | Allowances remain confined to test modules; production checks and admission behavior are unchanged |
| `13a48c240a` | Original native recording context, bounded typed fragments and complete refusal custody | Eight registered recording cases pass, including genuine direct-provider input recording and original whole-world reclamation after early/late preparation refusal; all-target strict Clippy passes without global exemptions |
| `64711d6bbf` | QEMU package metadata formatting | Source formatting preserves package behavior; changed raw-recipe identity requires rebuilding the production binary and corresponding source before final comparison |
| `6c22368da4` | Allocation-free borrowed gem5 address-range lookup predicates | More than 850,000 semantic comparisons and five matched lookup rounds pass; both installed fixed-workload ISA witnesses remove original resources and pass two fresh continuations/recaptures with all 27 bindings independently measured |
| `b6839fa7a1` | Bounded original KVM userspace-response completion and retry hooks | Public stage-five check builds actual x86/ARM objects, preserves earlier source/arithmetic checks and passes ABI/response/admission controls with six independently compiled rejected mutants; no live KVM execution or node qualification |

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

A subsequent signed mixed-world archive test removed the original checkpoint
image directory as well as the live resource directory. Its first fresh native
child failed before readiness: DMTCP still opened a saved supplementary file
through the deleted image-root spelling. The earlier fixed-workload witnesses
retained that historical image directory and therefore do not qualify archive
relocation. The successor native saved-copy hook now passes that stronger
namespace-deletion gate for both ISAs, with unchanged primary image bytes and
two independent imported saved-file roots. The required signed continuation
edition two and early-child kernel identity custody pass 61 focused core/provider
tests; the complete core suite passes 771 tests with three native fixtures
excluded, and production strict checks pass against the newly measured profile.
The subsequent managed-route discrepancy is corrected. Native reconstruction
also preserves the original private file permissions rather than DMTCP's
previous hard-coded mode 0640. Both installed ISA witnesses now require private
mode preservation and remove the entire original namespace; all 27 artifact
bindings independently remeasure.

The actual mixed x86 in-flight operation test passes after source destruction:
two independently restored complete worlds retain the same cut, original
operation ID and native prefix history, produce the same future checksum, and
complete the original commit, acknowledgment and native reclamation. Its
selected policy uses 65,536 callbacks per poll and retains every original raw
diagnostic body. The earlier ARM held-publication test failed before capture because ten
full native inventories consume 254,801,355 bytes of the unchanged 256-MiB
diagnostic allowance. That failed source and its original prefixes remain
recorded. A new, explicitly selected ARM policy uses 262,144 callbacks per poll
and passes the held-publication witness in 141.18 seconds: the complete original
namespace is absent, two fresh complete worlds preserve the same operation,
payload coordinates, original scheduling reservation and native acknowledgment,
and both produce the same future checksum. Every original poll budget is bound
into the signed configuration; cross-ISA or historical budget mismatches refuse
before materialization. The 256-MiB byte allowance is unchanged. Diagnostic-credit
preflight is a separate, unpromoted protocol successor. These mixed native tests currently use a private
test factory; production installed selection and CLI integration remain required.

The extension checkpoint passes the complete core library: 799 cases pass and
five actual-provider fixtures are explicitly excluded from that run. The public
ABI-conformance gate and required hermetic application test-target compilation
also pass at their recorded source checkpoints. Later registrations require
fresh checks; these results do not certify unregistered drafts or every backend.

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

The gem5 address-range predicate check removes one million temporary allocations
per one-million-query round. Five matched rounds preserve the identical 17-million
checksum; median lookup time drops from 17,114,414 to 3,254,498 ns (5.26x).
The source-built check is
`mjvd2kirzrqgqicl0x8yvvb0h8yg1iv0-gem5-addr-range-predicate-check-1`.
The successor fixed-workload profile has manifest SHA256
`9e2b4e66ef68d06e79526eaad33823bfca8071bdfe16e9d0bbd124c4fd939659`;
independent x86 and ARM witnesses preserve exact native birth/checksum context
through source removal, two fresh restores and complete fresh resource audits.
This isolated lookup result does not measure Linux boot, device parity, CPU
fidelity or complete typed diagnostics.

There is no overall Linux boot candidate speedup claim yet. Candidate comparisons
must reuse the same guest bytes and workload, record interventions and compare
full witnesses.
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
