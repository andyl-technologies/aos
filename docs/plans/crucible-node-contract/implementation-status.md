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
| `0380f47c6d` | Focused core lint cleanup | Production semantics and public formats are unchanged; subsequent central strict checks cover the registered source |
| `7fc5a56bbf` | Frozen extension semantics and complete selected dependency validation | Twenty-nine focused extension admission and semantics cases pass; broader native extension preservation remains profile-specific |
| `319ab8c710` | Protocol and GPL-side test lint cleanup | Test-only allowances remain scoped; subsequent complete registered protocol/GPL test groups pass |
| `bac1f09163` | Source formatting | No functional change; subsequent central checks cover the coherent formatted source |
| `ddc791bf66` | Production native actor, host-state/control/CLI integration, installed public qualification and matching package pins | Actual original Pending capture and two-fresh cold continuation pass in 159.79 seconds; actual actor-panic custody passes in 49.49 seconds; eight ledger and three control cases pass; ordinary daemon and CLI suites pass 882 and 360 cases respectively |
| `a530518937` | CLI native preservation through fresh daemon processes | Actual source daemon retirement, signed-state restart, exact original retry and two fresh completions pass in 158.93 seconds; help and strict target checks pass |
| `9dbb8a28de` | Campaign and daemon test-local lint cleanup | Scoped test allowances and equivalent reverse lookup pass strict checks; all 446 campaign library cases pass |

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
preflight is a separate, unpromoted protocol successor. The production native actor and control/CLI route now expose these explicit
original Pending and HeldPublication preservation points. The installed fixed
checksum plus HostClock scenario passes source retirement and two fresh worlds,
original completion/commit/acknowledgment, durable receipt retention and complete
custody reclamation. A separate actual panic proves that original native backing
remains owned through unwind. General fresh run-to-horizon, broader devices and
complete Linux/full-system qualification remain required; finite capture points
do not supply those claims.

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

## Latest registered checkpoint

The current central all-target strict and test-target compilation checks pass.
The core suite passes 809 cases with five actual-provider fixtures explicitly
excluded; the selected-extension subset passes all 29 cases.
The ordinary daemon suite passes 882 cases with 57 native fixtures explicitly
excluded, and the ordinary CLI suite passes 360 cases. Separate actual issuer
checks pass two cases in 49.31 seconds; eight review cases also pass. The public
native protocol/GPL/host trio passes all-target strict checks and its registered
protocol, GPL and host test groups: 208 protocol cases with one declared fixture
excluded, 628 GPL cases, 770 QEMU library cases with five declared fixtures
excluded, and the complete registered integration groups including 33 QMP cases.
These source checkpoints do not replace an ordinary production package build.

The signed `2e733` QEMU production regeneration now passes its mandatory fresh
original-status fixture, all new mandatory models, and the 13 plus 10 adversarial
mutants (`waqx` build). Matching production plugin generation, corresponding
source closure and final live pair probes pass. The registered `9fd9c5ee96`
checkpoint uses QEMU `2sp`, plugin `nqag`, and corresponding source `8ds`; the
packaged plugin passes all 632 cases. Eight current production native probes
pass in 0.26 seconds. All-target strict checks, ABI conformance (`p0y`) and
required hermetic application test-target compilation (`ixx`) also pass.

The original whole license attempt failed 15 engineering gates. After explicit
source inventory, typed-error, documentation and responsibility corrections,
all 6,305 controller tests pass, with 136 declared native fixtures excluded
(339.098 seconds). That attempt then failed an outdated packaging assertion
which omitted the already-packaged BSL-1.0 JCS formatter license. The correction
requires the exact expanded license list, formatter choice, nonempty license
file and byte equality with the canonical license. The complete frozen packaging
and source-reconstruction gate passes as `8fq`. Every one of the 85 staged
implementation files was independently compared byte for byte with that tested
source before commit; the additional file corrects the packaging assertion.
The original failures remain retained. This result covers the registered native
checkpoint, not later consolidated or private implementation stages.

The same checkpoint confines provider host deadlines to one private opaque
operational primitive. Raw clock coordinates have no accessor or codec; physical
elapsed reference-device evidence remains explicitly separate from modeled time.
Both SDK crates enter the dependency, artifact, unsafe-code and specification
inventories. Their four process tools are explicit Cargo targets. Opaque world
and operation comparisons retain actual local custody and complete immutable
scope; typed inventory and actor failures preserve original diagnostics.

The later source-probe checkpoint `d4d13e9edf` passes 12 source-probe guards and
the central controller all-target strict gate (83 seconds). The fresh core suite
passes 832 cases with five explicit native fixtures excluded (31.94 seconds),
and the ordinary daemon suite passes 882 cases with 58 excluded fixtures
(9.44 seconds). Four data probes, two actual issuer checks (34.59 seconds), and
six actual negative-provider cohort checks (13.62 seconds) also pass. The
registered V7 ABI-conformance gate (`lh6jr`) and required hermetic application
test-target compilation (`26w8`) pass. The local ARM mechanism checkpoint
`adf71aaae7` had a PID-reuse cleanup defect. The committed follow-up
`2283453725` supersedes that cleanup, after independently remeasuring the current
`cr9j`/`j0wr` artifacts, all 31 plus 13 checks, and an installed source-gone,
two-fresh reconstruction with three native groups reaped. These mechanism and
cleanup checks do not qualify full-system gem5 device parity or KVM. The 31-file replay slice
is committed as `7589ea2779` after 844 core cases (34.10 seconds), 882 daemon
cases (11.06 seconds), strict checks (57.32 seconds), and eight actual native
checks (13.44 seconds) pass. The first daemon run at 128/default test threads
passed 875 cases and failed seven at the 1,024-descriptor limit; its original log
is retained. A complete rerun at eight test threads passes all 882 cases. These
results qualify the recorded scope, not arbitrary counterfactual replay.

The consolidated checkpoint `ac5e3d2a32` registers terminal assertion and semantic
workflow continuation, Clock labels, production conditional recording/replay,
deterministic result reuse, public gem5 preparation and bounded source inspection.
Terminal state retains the original barrier, once-only report, acknowledgment
and complete owner/coordinator custody. The actual CLI deletes the source world
and restores two fresh continuations; Clock-label state requires its explicitly
selected typed archive policy. Result reuse authenticates the original result,
nonce, capability and input closure without allocating or executing a new world.
Coupled nondeterministic results refuse that reuse path. Source inspections remain
observations and cannot supply missing vendor behavioral qualification.

The checkpoint passes 2,586 focused library/CLI cases, all-target strict checks,
required hermetic application test-target compilation and all 33 QMP cases.
Actual CLI terminal/cache workflows, public gem5 preparation and ordinary
observed execution pass separately. Production native recording/replay passes
ten storage-failure controls while retaining the original source and raw evidence.
The complete registered license-boundary gate passes all 6,359 controller tests
with 153 explicitly excluded native fixtures, packaging and complete source
reconstruction. These results cover the captured checkpoint; later native,
capability, seeded-fault, scheduler and provider stages need their own checks.

The registered stage-six KVM package adds bounded original RUN-return custody
and exact native receipt Query/ACK. Both ISA object checks, the retained original
response oracles and seventeen compiled mutation controls pass. The
[native KVM implementation](kvm-native-implementation.md) documents its limits:
native return custody does not establish device closure, physical CPU stopping,
whole-node readiness or hardware execution qualification.

### Capability-selected preservation and durable preparation

The next controller stage resolves authored capability requirements against the
installed, independently regenerated catalog before allocating native peers. A
selected integer HostClock world supports exact preservation through a typed
archive: the original requirements, descriptor, compatibility, owner state,
coordinator ledger and artifact bodies remain authenticated together. Complete
portable and immutable storage credits are checked before native effects.
Reference, compute, EXT, fork and replay preservation require their own qualified
source policies and remain refused by this selected path.

Conditional replay preparation now records the exact request and an Awaiting
status durably before dispatch. Status inspection and exact retry preserve the
original operation; restarting the daemon does not redispatch uncertain work.
The actor fences callback panics during both normal operation and queued shutdown
while retaining the original native world for reclamation.

The integrated source passes all 51 admission cases, legacy native codecs,
conditional preparation and control codecs, strict checks across nine crates,
and the required hermetic application unit/integration test-target build.
Actual native Clock capture survives source removal and two fresh continuations.
The actual CLI recording/replay fixture passes ten storage-failure controls; two
real directory-completion panic branches pass the queued-shutdown reclamation
fixture. These results qualify the selected scopes, not general vendor readiness.

### Public gem5 continuation, seeded transport and capability control

The public fixed RF x86 profile preserves a complete preparation-bearing world
of the native CPU and integer Clock owners. Original Pending capture retains the
native seal through every capture failure. Source removal and two independently
qualified fresh restorations preserve original grants, native images and the
complete coordinator state; restored recapture remains source-qualified.
This scope requires the fixed no-ingress profile and does not qualify arbitrary
ARM, held-publication or full-system device state.

The installed static seeded link uses the existing integer jitter/reorder model
for original Source-to-Block request octets. Native state retains the exact
program, fault table, five-draw stream cursor and pending packets; restore does
not redraw captured frames. Actual worker execution and source-gone fresh worlds
match uninterrupted payloads, causal history, storage bytes and future RNG draws.
The [seeded transport workflow](seeded-transport-workflow.md) defines its bounded
selection and remaining device/fault scope.

Capability requests now have a daemon/CLI queue and durable status route. Exact
raw authored requirements remain bound to installed source regeneration and
selected compatibility. Clock continuation loads only the signed local archive;
its restored owner remains held through subsequent recapture. Existing control
routes, deadline and conditional-preparation unwind fences are preserved.

The merged stage passes the actual public gem5 continuation (193.12 seconds),
seeded native and ordinary worker tests, real capability CLI capture and two fresh
source-gone continuations, original queued-shutdown reclamation and all-target
strict checks across nine crates. Legacy control/native codecs and the required
hermetic application unit/integration test-target build pass. These tests qualify
the recorded selections; unsupported source policies remain refused.

### Typed original epochs and retained provider transmissions

The explicitly selected preservation profile retains original scheduler epochs
through fresh activation and later recapture. Version-two scheduler evidence
binds the original grant, input inventory, cursor and source generation while
the current activation has its own owner identities and boundary. Legacy
version-one encodings remain unchanged. The default native verifier refuses
the new scope before invoking native continuation; the installed fixed RF x86
profile independently verifies the complete typed records and finite credits.

The ordinary planner witness completes and acknowledges its original Clock
grant at 10 ps while the original CPU grant remains pending at 0 ps. After
deleting the source processes and namespace, two independently qualified fresh
worlds retain those exact requests and acknowledgements. A further source-gone
recapture preserves the original epoch through generation three, followed by
matching native suffixes, scheduler commits, acknowledgements and group
reclamation. The integrated witness passes in 231.57 seconds.

The provider SDK retains separate original requests and bounded transmission
journals. Explicit source-qualified repeats of Discover and original NotStarted
refusals send identical material under the original identity with fresh transport
sequences. Absent or exhausted reservations refuse before transmission; provider
loss retains attempted bytes and fences uncertain work. Completed Realize and
Admit repeats require a separate SDK qualifier; the actual fixture preserves
the same native child and original control bodies. The source caller currently
selects the safe pre-realization controls.
Its mandatory original peer census, world execution and retirement checks remain
part of the retained cohort.

Source metadata inspection runs once inside the owning actor. Inspection failure
or unwinding preserves prior objects and uncertainty; later report reads reuse
the original collection. The partial issuer retains four source-inspection
passes, 368 unexecuted requirements and ten inapplicable requirements. Ordinary
reference-provider admission still requires complete behavioral qualification.

The integrated source passes 325 targeted native, protocol, scheduler, state and
source-quality checks, together with all-target strict checks across nine crates.
The matching hermetic controller cohort passes all 6,399 tests, with 164
explicitly skipped fixtures. The required application unit and integration
test-target build also passes. The matching full license-boundary gate passes,
including the controller, plugin and corresponding-source dependencies;
its artifact is `iwfbh32dwrv1f3v2cnxiy8r903a1pg6y-crucible-phase1-license-boundary-0`.
This qualifies the original-epoch/provider and fixed-constructor checkpoint,
not subsequent implementation stages. Raw original cohorts and build logs
remain local.

## Fixed microvm constructor lifetimes

The signed QEMU integration `d30f55c938` retains the original native device,
bus, allocated-timer, BIOS and read-only FW_CFG lifetimes under the explicitly
selected fixed constructor profile. Its constructor record covers 17 devices,
10 buses, eight allocated timers and 13 FW_CFG buffers totaling 1,050,696 bytes.
These are observational roots; they do not authorize Ready, execution, a closed
input epoch, capture, restore or fork. The [constructor evidence scope](qemu-fixed-microvm-root-evidence.md)
describes the actual probes and remaining effect-closure requirements.

The registered atomic-patch regeneration check passes with both installed ISA
binaries, the mandatory constructor/firmware fixtures, compiled mutation
controls, preserved native cost baselines and default regressions. Matching ABI
conformance passes. The atomic patch is SHA256 `b6c8780ae6e541b2e8df840898fb0f51ec03d6a907ce7758b0688ab52bc7de08`;
its co-retained source bundle is SHA256 `e8641ee1b08a5dcc122ed6348ae33dadb64d9081a3f27a8ad93d6e3d423fdd20`.
The cost-baseline adapter strips only the precisely pinned constructor
prototype addition and reconstructs every original measured baseline byte.
Runtime `run-state` journals are excluded from both Cargo rebuild inputs and
corresponding-source exports, with mandatory export-absence checks. No raw
process evidence or runtime journal is committed.

## Original completed lifecycle repetitions

The CNP adapter retains optional, separately qualified repetition hooks for
completed Realize, Admit, WorldCommit, Ready, Input, Begin, Close and Consumed
requests. The default path retains its original no-repeat policy. A repetition
authenticates the actual original request, response, preparation, native owner
and closed-window custody; it cannot invent a replacement operation or reuse
another peer's authority. Ready is adopted before post-adoption qualification,
so a qualification error, unwind or provider death retains its actual custody.

The installed reference witness records thirteen real transmissions per archive
under the original two-provider world. It repeats two native Input/Begin/Close/
Consumed cycles, checks the independently computed nonempty input and checksum
oracle across three windows, and reclaims both original groups. Its recording
credit is reserved before child creation. Six separate adverse reader controls
are data-only checks, not substitute executions of a vendor criterion. The
source report remains four passes, 368 unexecuted requirements and ten
inapplicable requirements; these repetitions do not authorize ordinary vendor
admission.

Central verification passes 55 targeted tests: the actual source witness, actual
Ready/adoption failure-custody witness, eight legacy CNP cases, eight SDK cases
and 37 source-quality cases. All-target strict checks pass across nine crates.
The required current-master application test-target build passes for commit
`99fd6c6012`, with output `8y959xbrbrqz7z6sv8g8wmx2jicpznhd-aos-test-targets-0.1.0`.
This result covers the lifecycle integration before the subsequent ARM source
changes. Raw original evidence, including failed precursor
recordings, remains local and is never replaced by a successful later cohort.

## Fixed ARM original-state mechanism

The installed 33-role ARM root profile binds the actual Linux kernel, initramfs,
native controller and audit helpers separately from the earlier 31-role model
and the existing SE profile. Its manifest is SHA256
`497b3d4b6674846f40eeebab3bc73204ad265d9e7fa0d24430ece7dff6292af1`.
The production package carries the root profile as a runtime dependency; the
earlier model remains a separate fixture dependency. Execution admission still
refuses until a complete common-node profile is qualified.

The native mechanism retains original preparation, commands, completion or
refusal bytes, pending ACKs, process-group custody and opaque process images.
Historical archive records cannot mint live authority. Fresh reconstructions
require their own current process audit and exact authority, and distinguish
restored preparation from original preparation. The installed source verifier
remains mandatory for archive import; the native fixture authenticates its
actual original export rather than supplying an installed vendor verifier.

Central verification passes 23 installed/model cases and three separate actual
native witnesses. These cover preparation and failure custody, deletion of the
source followed by two coexisting fresh restores, and archive import after the
entire original source is removed. Each branch independently recertifies its
current owner, preserves the held original completion and ACK history, matches
the subsequent UART publication bytes, and reclaims its original native groups.
The provider library passes 192 cases with three explicit ignored cases: the
installed-locale witness, subprocess worker entrypoint and earlier SE native
capture witness. The three ARM witnesses above are separate integration targets.
One library case starts a nested child test, whose result is not counted again.
All 37 source-quality cases and all-target strict checks across nine crates pass.
The required application test-target build passes for the fixed ARM source
stage, with output `b7m5l1525q4hf54xk8q3sg7lb2g35m1g-aos-test-targets-0.1.0`.
This build predates the administrative metadata and subsequent reference changes.
Broader package qualification is recorded separately below.

The unchanged strict process-group census now retains its first bounded refusal
diagnostic. Successful rows keep the original parsing fast path. The earlier
malformed-row failure remains unexplained because its original row was not
retained; these changes do not claim to explain or fix it. This mechanism does
not establish application readiness, complete device parity, CPU timing-model
accuracy, ordinary common-node activation or vendor admission. Raw evidence,
images and runtime journals remain local.

The first broader package cohort fails in the lightweight reference-binaries
dependency: 191 library cases pass, one new case incorrectly requires a compiled
ARM profile, and three cases are ignored. That package deliberately carries no
ARM binding. A test-only successor leaves the production checker byte-identical,
runs the old-policy, forged-parent and promoted-flag schema negatives
unconditionally against inert scope data, and separately checks the actual
compile-time binding or its precise absent-binding refusal. Both binding
configurations pass their two cases; the genuine 33-role installed integration
also passes. All 37 source-quality cases and nine-crate all-target strict checks
pass for the successor. The failed cohort remains retained; broader package
qualification must rerun against the corrected source.

The second broader cohort passes the corrected library cases, then exposes the
same missing-binding assumption in the installed integration target. Its
original failed log remains retained. That target now has an explicit
compiled-profile requirement, and the native controller's build always executes
its exact installed test with `--ignored --exact` before the existing license
gate. Reference-only packages compile it without pretending an ARM profile is
installed; cross builds rely on the existing native-controller dependency.
The mandatory exact test passes centrally with the genuine source-bound profile.
Its assertions, profile bindings, native inputs and production code are
unchanged. Source-quality and nine-crate all-target strict checks pass for this
successor; broader package qualification remains pending.

The third broader cohort reaches the older `gem5_model` integration target and
fails its two unconditional installed-profile loads in the reference-only
package. Its 20 other cases pass and its original failed log remains retained.
A complete transitive audit of provider integration targets finds these two
remaining external-binding assumptions. The actual old-model measurement keeps
all its assertions, gains an explicit installed-profile requirement, and is now
mandatory beside the Root measurement in the native controller build. Metadata
negatives run unconditionally against seven inert fields copied from the actual
installed model, with a positive scope check first. A separate case checks the
precise missing-binding refusal or measures the genuine compiled binding.
Central verification passes all 22 ordinary old-model cases, the mandatory
actual installed measurement, 37 source-quality cases and provider all-target
strict checks. Independent standalone source checks also pass with the binding
absent. Production codecs, dependencies, manifests and admission flags are
unchanged. Broader qualification is running against this complete successor.

## Native administrative metadata during reply custody

The plugin retains immutable registration facts only after native validation
and actual reader PID/TID checks. It also retains the original owned inbox
descriptor independently of the mutable reply ledger. Startup can therefore
read its already validated manifest while the sole reader holds journal locks.
These historical facts do not prove current thread life, Ready or execution
authority. Native divergence and poisoned original custody withdraw them;
each registration retry still authenticates the source's actual reader.

Five new adverse cases cover held original locks, source divergence and poison.
Central verification passes all 633 plugin library cases, including six
registration and five inbox cases, plus all 37 source-quality cases and strict
all-target checks across nine crates. The first runner stopped after six passing
registration cases because its minimum-count assertion incorrectly expected
nine; its original log remains retained. The successor runs the remaining
targets with their actual inventories. Broader package qualification will be
recorded separately. No protocol schema, native callback or admission selector
changes in this stage.

## Original request conflicts and durable reply custody

Two actual source-owned providers now exercise changed material under the same
original request identity at preparation, second-window input and Begin. Each
of the six authentic conflicts refuses before effects, preserves the original
native journal and remains non-retryable. A third window independently checks
the unchanged ordered-input checksum. Both original groups are reclaimed and
their credit is released. Separate actual Ready tests cover adopted custody,
error and unwind paths, native death and preservation of the original authority.

Durable result publication encodes the original completion and retirement once
before placement. Placement retries reuse those exact buffers and object IDs.
An encoding failure or unwind parks the actor with its original context rather
than reevaluating an uncertain snapshot or producing a substitute completion.

Central verification passes 58 distinct selected cases: the actual two-provider
conflict witness, actual Ready custody witness, eight legacy CNP cases, eleven
SDK client cases and 37 source-quality cases. Strict all-target checks across
nine crates also pass. The mandatory installed ARM root test separately passes
against its genuine compiled profile. The original source witness completes in
50.02 seconds; the runner's first Ready invocation selected an ignored test
without enabling it, and its minimum-count check correctly stopped that cohort.
Its original log is retained. The corrected invocation runs the actual test
with the source-built provider and device paths. No failed semantic test is
replaced. This stage does not qualify reconnect, loss during uncertain native
execution, complete vendor conformance or ordinary provider Ready admission.
Broader hermetic package qualification remains pending.

## Native root construction and retained transport ownership

The fixed microvm construction protocol records source-authenticated board,
timer, CPU, IRQ and endpoint facts under explicit protocol editions. Native
registration retains the original initialization ACK, administrative FIFO, RUN
transport and teardown custody. Callback userdata remains pinned for the
registered process lifetime. Pending transport operations preserve their
original request and reply rather than block unrelated callbacks or substitute
a new operation.

The native epoch acquisition callback still clears its output and refuses with
`EAGAIN`. No execution epoch is issued. Root construction does not qualify
RootSeal, peer-input closure, effects, Ready, capture or fork. The recorded
instruction-then-timers mapping remains inert; a production finite dispatcher
and its distinct mapping edition are required before execution. The default
administrative edition and ordinary worker path remain unchanged.

The signed atomic native source is commit
`c1ca2f5d3f6593cc5620de25a0f39d3797229750`, with patch SHA256
`ec380a206d67caaca306d2e21f8472fdc64ad02e3f81d44f826102213cf85cb9`.
Its complete source bundle, licenses and mandatory source-derived fixtures are
co-retained. Regeneration passes for the complete default two-ISA build. The
new fixtures include 20 compiled causal mutants and 34 guard-before-effect
checks, alongside the unchanged existing proofs. Their modeled admission
conditions do not establish production execution authority.

Central checks pass all three affected native packages' test targets, 37
source-quality cases and strict all-target checks across nine crates. The test
output reports 1,828 passes including nested test runners; this is not a count
of distinct cases. ABI conformance and the hermetic application test-target
build also pass. The subsequent complete controller run reports 6,465 tests:
6,463 pass, two fail and 201 are explicitly skipped. The failures identify the
runtime module's source-size limit and missing safety sections in three FFI
files. They keep the broader license-boundary gate failing; their corrections
require a separate verified successor.

The installed matched QEMU/plugin pair passes the actual held-epoch refusal
and eight preserved ownership/transport selectors. A separate source diagnostic
pair passes 23 actual cumulative custody probes, including IRQ, reset, endpoint
and foreign-thread adversaries. That diagnostic binary has the exact enrolled
native source but its original diagnostic build identity; these 23 probes are
not attributed to the installed package. An initial mismatched plugin correctly
refuses identity authentication. A later installed endpoint fixture stops
because stripping removes its required private source symbol. Both original
failed cohorts remain retained locally, and neither is presented as a passing
native semantic test.

## Shared-owner dispatch and installed live host capabilities

A blocked public alias no longer reserves its execution owner before receiving
a grant. A runnable sibling can progress while the executor preserves one
original operation per owner and serializes overlapping ownership domains.
Four sealed-graph model cases verify alias progress, original FIFO staging,
one-operation ownership, shared-domain exclusion and disjoint-owner progress.
These fixtures do not qualify native multi-view host ownership.

Capability selection accepts `exact_run` and `boundary_settle` for existing
source-installed HostIo, HostScripted, HostNetLink and HostSemantics profiles
with the exact version-one `host/exact-v1` facet. Full candidate regeneration
and descriptor, configuration, schema and guarantee matching still precede
allocation. Unsupported controls, compute, extensions, richer operations and
archive policies retain their existing refusal.

Central verification passes four actual authored host scenarios: original
Script/Block results with a Clock, two native octet peers through a Link, the
installed no-ingress semantic evaluator and changed-contract/control/artifact
refusals. This semantic case qualifies version two without ingress; it does
not qualify version-one construction or the successor reaction convention for
semantic inputs. All 37 source-quality cases and nine-crate all-target strict
checks pass. The first central runner stops after selecting four ignored
fixtures without enabling them; its successor runs the actual fixtures. Later
quality failures identify one missing watchdog annotation and the second
substring inventory for the same single polling call. Their original cohorts
are retained; the final corrections change only that annotation and its
precise source-bound inventory. Production policy and native test behavior
remain unchanged by those corrections.

## Original provider loss and unread response custody

Two source-planned adverse workflows retain the original transmission and
process authority. After an actual nonempty native Close, provider-only loss
makes the duplicate transport incomplete while preserving the original receipt,
uncertain token and cached refusal. A separate SDK hook authenticates a
predeclared original Begin, records its first completed canonical write and
fences transport before any completion read. Physical execution in this second
case remains unknown; a completed write does not prove native progress.

The SDK hook is absent by default. Its observation handle exposes the retained
frame and explicit completion absence without handing out socket, controller
or signal authority. Both workflows preserve original cached archives and
reclaim the original provider/native groups without creating another wire row.
The unchanged same-ID conflict scenario independently preserves its third-window
native checksum oracle.

Central verification passes 51 distinct selected cases: both actual loss
workflows, the actual two-provider conflict regression, eleven SDK client cases
and all 37 source-quality cases. Nine-crate all-target strict checks pass.
Actual loss cases complete in 54.69 and 59.59 seconds; the unchanged conflict
case completes in 53.52 seconds on the same compiled test binary and installed
reference package. Raw original archives remain local. This stage does not
qualify loss during demonstrable native progress, reconnect, full vendor
conformance or ordinary Ready admission.

## Runtime safety and worker startup repair

The complete 6,465-test controller cohort reports 6,463 passes and two
source-hygiene failures, with 201 explicit skips. The repair documents the
native epoch ABI and callback pointer contracts, names unchanged callback
parameters, and extracts original RUN/teardown worker startup into a focused
module. Worker order, socket ownership, gates and fatal behavior are preserved.
`runtime.rs` shrinks from 3,042 to 2,977 lines, below the unchanged limit.
Only its existing source-review hash, count and cohesion explanation change;
detectors and ceilings remain unchanged.

Central verification passes all 674 plugin tests, five unsafe-boundary checks,
the source-size check, all 37 source-quality checks and nine-crate all-target
strict checks. A complete formatter check then identifies a module declaration
order mismatch. Its retained successor changes only that order and the exact
review hash; formatting across all five Rust inputs, the five unsafe checks,
size check, 37 quality checks and nine-crate strict checks pass again.
Independent review confirms those final bytes. Eight earlier native diagnostic
selectors exercise the extracted worker body; they are not installed-package
qualification of this final version.

The complete hermetic license-boundary gate now passes on the repaired stack
ending at `cbb361f8cb`, output
`3iykmi0gg3y8khn15zq2ywdbdizvb0l1-crucible-phase1-license-boundary-0`.
Its controller cohort passes all 6,469 tests across 292 binaries in 377.368
seconds, with 207 explicit skips. The final 18 license-boundary checks also
pass. Matching complete corresponding QEMU source is retained in
`db2x9iwp1mpxwz5v2grqgpk8kpscnwpf-qemu-crucible-source-11.1.1`.
This result does not qualify the subsequent semantic, phase or source-lineage
changes. Original failed cohorts remain local. This repair does not issue
native execution epochs, authorize effects or qualify capture.

## Canonical semantic profiles and exclusive reaction cuts

Generated semantic profiles sort the complete ownership and port rosters before
deriving identities. This makes version-one construction valid while retaining
the full original version-two no-ingress identity fixture byte for byte.
Imported compatibility tuples and native codecs are not retagged.

The selected semantic model retains its checked successor-microstep reaction.
Before executing a staged immutable batch, the adapter refuses an exclusive cut
that passes a delivery but excludes its reaction. No earlier batch input takes
effect on that refusal; a later valid grant consumes the same original staged
input once. Generic Block reactions retain their same-microstep convention.

Central verification passes 139 selected cases: the original golden fixture,
four actual installed semantic scenarios, 97 existing adapter cases and 37
source-quality cases. The actual cohort completes in 6.27 seconds; the existing
adapter cohort retains seven explicit ignored cases. Five-file formatting and
nine-crate all-target strict checks pass. Changed program/schema/compatibility
and unsupported controls refuse before allocation. Current source-review
metadata changes only two existing hashes and line counts, preserving the
runtime repair inventory. This stage does not qualify captured semantic input
state, imported compatibility migration or external-input profiles.

## Whole input-prefix phase protection

The pre-effect immutable-batch check now also covers generic same-microstep
Block and Link reactions. A phase-only grant can include Delivery while
excluding Reaction; claiming a closed prefix in that case would leave an
original input behind. The adapter refuses the entire remaining batch before
an earlier request can change native state. Later valid grants retain the same
batch and consume its original requests in order. Reaction mapping, native
codecs, receipt validation and scheduler closure rules remain unchanged.

Central verification passes 142 selected cases: the unchanged identity golden,
five actual installed scenarios, 99 existing/new adapter cases and 37
source-quality cases. The actual cohort completes in 7.69 seconds and includes
the genuine installed Script-to-Block pipeline; two direct Block/Link
state comparisons within the adapter cohort use explicitly synthetic admission.
Five-file formatting and nine-crate all-target strict checks pass. Original
failed capture attempts are retained: a staggered source/device cut cannot
serve as a common-cut archive oracle. Native state comparisons and the ordinary
installed pipeline are separate evidence; no capture guard is relaxed.

The hermetic application unit/integration target build passes for the preceding
runtime repair stack ending at `cbb361f8cb`, output
`54yppih35hb55m0l8g49mqza9ni0f6p7-aos-test-targets-0.1.0`. It does not extend
that compilation result to these later semantic and phase changes. Their
coherent application-target build remains required.

## Source-owned lineage and recorded Block ingress

The reference provider now exposes a distinct ordered-consumption source
mechanism with borrowed original native rows, two-group custody and an opaque
runtime association. Existing reference selection and exports remain available.
Transport fragments share the original operational deadline; an expired final
response is retained as unknown before quarantine, rather than accepting a
late close or acknowledgement. These operational deadlines do not advance
modeled time.

The suite retains a source-built lineage implementation together with its
source archive, contract, recipe, runtime closure and executable identities.
The installed guard measures the supplied current tuple before launching a
child and uses it for both original groups. The controller requires the exact
test selector to exist and then runs it explicitly after package construction.
An absent manifest binding refuses; historical scratch store paths are no
longer a fallback. This qualifies component custody, not a source class,
higher-hop causal lineage, native capture or admission readiness.

Recorded Block ingress preserves authored input bodies and FIFO order through
the owning executor. Whole-batch phase checks still precede native effects.
Actual CLI submission and completed-record restart tests preserve result status
and nonce after source removal; constructing another execution without its
source refuses. Completed-record continuity does not restore an original input
cursor or establish cold native continuation.

Central verification passes 341 selected cases across the provider, CNP,
recorded ingress, CLI, semantic timing, input-phase, QAPI and source-quality
cohorts. The final provider cohort passes 276 default cases and the explicitly
selected current installed guard passes separately. All 88 owned Rust files
pass formatting; nine affected crates pass all-target strict checks. Earlier
zero-selection command errors and failed historical package-binding attempts
remain local evidence and are excluded from successful counts.

The current hermetic lineage package passes at
`2v1m4yrrfz8100i4cgdfsxq9brwimxx9-crucible-reference-lineage-implementation-1`,
manifest SHA256
`2a9d9ff686361587bf6362ad3c00195915ca2572291f23a92ae9ed4d20e9f748`.
Independent streaming verifies all 305 declared content identities and extents
across 301 distinct paths, including the corrected transport and installed-guard
sources. Its explicitly selected actual guard passes separately in 0.42 seconds.
This is a new tuple; earlier installed artifacts remain separate evidence.

The fresh ABI qualification attempt stops while compiling its production-flight
dependency because its restricted source view omits twelve normative files
embedded by the qualification catalogue. The production-flight and Cargo-only
views now retain the RFC-0025 subtree and exclude runtime journals. Independent
Nix source materialization verifies all twelve embedded leaves byte-for-byte,
journal and adjacent-prefix exclusions, and two-file formatting. The failed
build remains retained; ABI and full boundary results remain pending. The
coherent hermetic application unit/integration target build passes for the
lineage, recorded-ingress, guard and KVM stack before the following ARM stage,
at `1lzi2560kfix1mqpiqrl3ydar7r09hfk-aos-test-targets-0.1.0`.

## Ordinary closed ARM Root and Clock preservation

The installed catalogue now selects the measured ARM Root and integer Clock
world through the ordinary public preparation path. Its original scheduler-one
permission remains distinct from generic epoch-two and conditional-replay
permissions. Preparation and restoration require actual owner custody and the
complete publication procedure; the existing reference, recorded-ingress,
Clock and conditional selectors remain available.

The frozen current-source native witness passes in 521.75 seconds: original
source removal, two fresh restored owners, recapture and third-generation
continuation preserve the original permission, native history and UART output.
This is the closed, no-input, no-edge installed model. Its committed Clock cut
is `(1000000000, 0, BoundaryControl)` while the original held Root output was
born at `(1166530000, 1)`; the archive retains that in-flight operation rather
than relabeling native time or claiming a quiescent common cut. General devices,
external ingress, CPU timing fidelity and universal peak descriptor reservation
remain separate qualification requirements.

Central current-union verification passes six encoding/ancestry cases, one
actual initial public preparation and reclamation case in 75.25 seconds, 37
source-quality cases and nine-crate all-target strict checks. The exact 43-path
integration preserves the independently enrolled current installed guard and
its testing inventory. Complete formatting exposed two mechanical changes in
widened helper signatures and module ordering; these are retained as a separate
formatting follow-up. The earlier hermetic target and boundary results do not
qualify this subsequent source stage.

## Original preparation exclusion, Root retirement and progress custody

All public preparation routes now share one durable compare-and-exchange before
native allocation. It binds the execution nonce, route and exact original
request bytes; retained custody does not authorize redispatch. The lifetime
quota includes losing contenders and refuses further publication after 4,096
reservations. Requests, claims, scanning and CAS retries have explicit finite
limits. Legacy foreign-route records continue to refuse competing preparation.

Initial and restored ARM Root worlds transfer their complete owner into an
explicit retirement handle. Namespace release requires both original runtime
and exact-target native reclamation, retaining the original directory pin on
failure. The actual current-source initial/restored retirement witness passes
in 247.46 seconds. This qualifies the closed installed Root/Clock model, not
arbitrary queued input or general devices.

The separately measured reference-progress implementation observes an actual
positive native response prefix before missing-response handling. The original
window remains unknown; received bytes, source custody and retirement obligations
are retained. Ordinary legacy and lineage defaults remain separate. Its
repository-relative package is integrated into the suite, while the component
witness uses the independently verified installed tuple
`lx4k2fd47pdfnrsv5s9p67yy0753n2dv-crucible-reference-progress-implementation-1`.
That component result does not qualify a later production-suite tuple or promote
a capability class.

Central verification of this 49-path source union passes 320 selected model,
provider, actual CLI and native cases, followed by all 37 current-source hygiene
checks and nine-crate all-target strict checks. All 45 owned Rust files pass
formatting. The artifact contract now
checks all ten explicit provider binaries and rejects missing, renamed,
rebound, duplicate or extra declarations. An earlier private hygiene run scanned
its compiled-in predecessor checkout; it supplies no retirement-stage quality
credit. The current review count is corrected against actual classified source,
and the central hygiene run scans this worktree.

The earlier complete boundary attempt runs 6,506 cases: 6,504 pass and two stale
artifact-inventory checks fail. The subsequent ABI build reaches 6,513 cases,
with the same two stale checks failing and 6,511 passing. A later boundary build
stops at a missing test-only unwrap annotation. These failures remain retained;
the corrected 49-path source checkpoint passes the hermetic application
test-target build (`5dgld99qrvibh0pff1srgv08kng3g3l3-aos-test-targets-0.1.0`).
Its complete ABI and license-boundary qualification remains in progress. No
successful complete gate is inferred from the earlier partial results.

## Controlled faults and live condition stops

The next source stage adds admitted deterministic packet/storage faults and live
condition observation to the installed host-model executor. Fault decisions
remain attached to the original operation and preparation. Genuine source-gone
fault continuations restore in two fresh owners, preserving future bytes and
once-only decisions. The live condition observer stops at the authentic first
hit, retains the original stopped operation, requires its durable report before
acknowledgment, then resumes the future operation once. A horizon alone does not
become an end-of-stream condition.

Condition snapshots use an explicit runtime edition. Current host archive
readers reject unsupported runtime edition 6 through a streaming version probe
before allocating its typed payload. Supported legacy editions 1 through 4
continue through their original decoder, including integral JSON version forms
and large numeric arrays. The condition DAG checks both unique and expanded
body/association credits before cloning: 64 MiB and 65,536 entries. These checks
cover repeated shared bodies, native history, provenance and stop records.

Central verification passes 19 condition model cases, five actual native
condition cases, 18 legacy host cases, six epoch regressions, two genuine
source-gone fault continuations and three early-version-probe cases. All 37
current-source hygiene checks and all 106 owned Rust formatting checks pass.
Four native adverse/controlled storage cases separately qualify the cooperative
polling successor, retaining each original dispatch, 20-second deadline and byte
oracle. All-target strict checks cover ten affected crates, including the device
crate. Independent review covers the source, expansion limits, unchanged legacy
serialization and streaming version refusal. Earlier source-hygiene failures
remain retained; allowances, thresholds and deadlines are unchanged.

This stage qualifies live condition stop/report/resume only. Cold restoration
of a condition-stopped world and the public debugger command workflow still
require their own native and operator evidence. The 108-path condition/fault checkpoint also passes hermetic application
test-target compilation (`ksx37flpzvj3rn1c9v5cdx933y8dw3xn-aos-test-targets-0.1.0`).
Complete ABI/license gates must qualify it separately from the preceding
49-path checkpoint.

## Recorded Block cold continuation

Selected recorded Block worlds now preserve their consumed FIFO cursor, original
input provenance, native Block/CoW state, pending or staged delivery, operation
journal and ACKs. The native envelope and portable coordinator use edition 5;
the runtime remains edition 2. Initial runtime 1 without provenance refuses
before immutable closure assembly or native capture. Legacy editions, controlled
faults and unsupported condition restoration keep their separate formats.

The matching native cohort passes two source-gone continuations in 88.55 seconds.
Each removes the original input and backing store, restores two independent
current owners, preserves the original acknowledged Write101 and exact delivery
history, then publishes Read102 bytes `[1, 2, 3]` once per branch. Subsequent empty
execution produces no duplicate publication, and all world reservations reclaim.
The production coordinator reader dispatches directly to its closed legacy or
portable decoder after the streaming runtime probe. Duplicate fields, trailing
input, unsupported scopes and wrong model/schema/configuration refuse.

Independent review verifies all 24 source pre/postimages, 8,410 tested
source/dependency leaves and retained executable identities. The matching private
cohort also passes 37 actual-source-root hygiene cases, four-consumer all-target
strict checks, 23 Rust formatting checks, five live recorded cases, five semantic
phase cases, the legacy no-ingress byte golden, six coordinator/header cases,
15 archive cases and 126 adapter cases with seven existing ignored fixtures.
Central verification passes 15 archive cases, five live recorded cases, both
genuine cold continuations (84.99 seconds), all 37 current-source hygiene cases
and ten-crate all-target strict checks. All 23 owned Rust files pass formatting.
This stage covers proof-bearing pending/staged recorded Block custody; it adds no initial-runtime,
9p, physical-ingress, replay/fork or cold-debug authority.

Temporary administrative mailbox contention now leaves the original construction
request pending before command, record or reply-credit admission. A real socket
regression holds the mailbox mutex, checks unchanged request bytes and cursor,
then admits that same request after release. The predecessor fails this case;
central verification passes all 671 plugin cases, 37 current-source hygiene
cases, plugin all-target strict checks and both owned-file formatting checks.
This transport correction establishes no additional native readiness authority.

The subsequent complete condition-stage run exposes four shared-owner fixture
failures because their scenario omitted the original authored input-context
bytes. Current-source reproduction fails all four before scheduling. A test-only
repair retains the exact scenario reference and bytes already verified by graph
admission; production authentication and scheduling assertions stay unchanged.
Independent source review approves this scope. All four original scheduling
cases, 37 current-source hygiene cases, daemon all-target strict checks and the
owned-file formatting check pass. The fresh corrected checkpoint's full
controller suite passes 6,578 cases with 242 skipped in 466.735 seconds.
The enclosing ABI/license gate also passes, yielding
`siyn3jizlvvnxa9pmy8q1j28v5sps4a9-crucible-phase2-abi-conformance-0`.
Its license component reconstructs the matching complete source and plugin.
This result qualifies that historical checkpoint; it supplies no subsequent
network, live-debug, KVM or native-effect credit.

The complete 49-path controller suite passes 6,536 cases with 230 skipped. Its
combined ABI/license gate subsequently fails because the packaging identity
probe omitted the required `patch` argument when importing the QEMU recipe.
The narrow probe repair reproduces that failure, then matches the exact shipped
QEMU build identity when supplying the AOS patch placeholder. Production QEMU
source, recipe and dependencies remain unchanged; complete gate success still
requires a new corrected run.

## Canonical gem5 closed Linux network continuation

The repository-relative closed-loopback source binds its own matching Linux
proof and installed profile, rather than inheriting the private predecessor's
qualification. The actual guest publishes its original 64-byte frame before
the sealed future receive reaction. After the entire original namespace is
removed, two concurrent fresh owners each pass a new image audit, original
retry/ACK and incoming guest readback; receipts, UART, disk, network, native
tick/ordinal and complete group reclamation agree.

The installed profile is `8nayi2xhjwdnd6991l20vbzy9cg0vbk9`, with manifest SHA256
`914e8d744f81446718500fef350bdb5a8c049e23c87a3ce03205bf983952b44e`.
Independent review remeasures all 42 artifact roles and 168 configuration files
(1,319,943 bytes). The 45-source enrollment includes seven required shared Block
leaves; four unrelated Block registrations remain excluded and their pending
qualification is not borrowed. Five native license rows are appended.

Candidate ACK ledgers are validated before native administration and installed
only after acceptance. Central checks pass 124 backend, wiring, profile,
archive-custody and diagnostic data cases, plus 37 current-source hygiene cases;
all owned Python sources parse and five Nix recipes pass formatting. These
results qualify the measured closed-loopback mechanism. Common Ready,
NativeArchive, external networking/serial, CPU timing and full device parity
remain unqualified. Combined callback publication bounds and post-effect
uncertainty custody remain required for broader execution admission.

## Installed live debug operations

The public node service and CLI preserve the original live stop, report, ACK
and resume transaction. A per-world worker retains the current native owner,
token and unpublished outcome across completion errors or unwinding. Original
debug claims and durable namespace credits precede dispatch; exact retries
recover the same immutable result. Resume requires reconciliation against the
current trusted report roots, and paused owners retain their aggregate capacity
until authenticated native reclamation.

Central verification passes eight actual native actor cases, the actual CLI
process case, one debug wire case, five existing control cases and 37
current-source hygiene cases. Daemon and CLI all-target strict checks pass.
The native continuation preserves stop position `(513010, 3, BoundaryControl)`
and the original future read exactly once, including its causal parent and
512-byte payload. Completion errors, panic recovery and historical report
reopening retain the original ownership and publication boundaries. A separate
format-only follow-up passes independent token-equivalence review, all 18 owned
Rust formatting checks and another 37 current-source hygiene checks.
The exact committed live-debug and formatting successor also passes hermetic
compilation of every application unit and integration target, yielding
`nzj8walq7j2rwqp0vc9y1mavh3s3x80q-aos-test-targets-0.1.0`.
This compilation result supplies no execution or later KVM/native-effect credit.
This stage supplies live Debug8 operations; cold debug preservation, Scheduler4,
scenario finalization and broader device support remain unqualified.

## Owned KVM component custody

Original Window and ACK requests retain finite, non-evicting journals before
dispatch. An ambiguous transport exchange fences its stream; recovery must
authenticate the same child generation, executable and Unix peer before
observing the original transaction. Child wait authority, installation files
and journals share a pre-reserved supervisory capsule. Dropping the owner
transfers that capsule to authenticated containment without replacing it.
Preparation requires the actual KVM device and exact native components before
child creation, with no accelerator fallback.

Central verification passes 66 component cases, 108 QMP cases and 37
current-source hygiene cases, plus all-target strict checks and formatting of
18 Rust files and one Nix recipe. The process cases include five actual stopped
TCG children and one pre-child supervisor refusal, using explicitly configured
signed native source `25df9f4e6896f40eb49958ca317be1429195808f`.
The fixture binding rejects absent or unusable executables; the packaging recipe
supplies it at test runtime through a build-only QEMU dependency. A source
confinement failure is repaired by delegating the unchanged five-second bound
to the existing private supervision API, without detector or allowlist changes.

This machine has no `/dev/kvm`; the hardware probe remains ignored. These
component results supply no whole-node readiness, common grants, device,
input/output or archive qualification. The new native-effect production tuple
and current hermetic controller/ABI/license builds require separate evidence.
The exact committed component checkpoint also passes hermetic compilation of
every application unit and integration target, yielding
`fwdl248b1n6ii5a9zyiq600i2286ry44-aos-test-targets-0.1.0`.
This result is compilation evidence, with no hardware execution credit.

## Native effect preparation and original CPU service

Native source `6016e9a056f07ef093dd38692e350ae413f9ed91` binds effect
preparation to the installed endpoint owner and original native execution
root. Pending and active epochs retain their original command, result and
acknowledgment identity. Observer callbacks cannot manufacture execution
authority. The plugin keeps semantic computation separate from publication,
retains immutable results for exact retries, and contains installed workers
and teardown under their original finite ownership.

The signed atomic patch and bundle reconstruct the exact native tree. The
configured production build passes both ISA targets, mandatory source and
mutation checks, and atomic patch regeneration. Four independently reviewed
fixture repairs preserve the native source and strengthen the sealed-owner
lifetime oracle. The first production attempt's extraction-anchor failure
remains recorded separately.

The matching production pair uses QEMU
`6n18q3i9xzzyarma6jbl8wzd4qr29ijg-qemu-crucible-11.1.1`, plugin
`rvp8rqair0z295rgx15n2wwf7dj2bqmy-crucible-qemu-plugin-0.1.0`, and complete
source `397lxbqjiaj4yqaaws0c1bszxrbmyhrp-qemu-crucible-source-11.1.1`.
Build identity is
`ab6c94899190535813e4b1e3b6922dab5d596dab6b94c9432f1e6dd292934f5a`.
Independent review matches all 42 host/plugin source postimages in the complete
source output and verifies the actual installed binaries and metadata.

The public service executes one instruction, retains its partial result, and
returns byte-identical history on the original command's resend. A genuine
observer probe verifies registration, acquired-root checks, pending-state
refusal and historical-result behavior. Both production cohorts pass once;
the release plugin passes 707 cases. The first instruction does not observe
an active callback, so these probes establish no active output authority.

Central verification passes 703 plugin cases, 227 protocol cases and 803 host
cases, plus one nested child case. It also passes 37 current-source hygiene
cases, five unsafe-boundary cases, the source-size check, host all-target
compilation and three-crate all-target strict checks. All 40 Rust files pass
formatting. Process-fixture cases in that central suite use the separately
identified earlier native build. A distinct current-build component cohort
passes 66 KVM custody cases and eight two-ISA native refusal groups; hardware
execution remains unavailable.

These results qualify preparation and one original CPU service. Complete
grants, continued execution, typed timers and IRQs, output publication and
prefix acknowledgment, common readiness, capture, fork and restore remain
unqualified. The exact committed checkpoint passes fresh hermetic compilation
of every application unit and integration target, yielding
`810500qqdd8naij3pmkyx0gg05ma4ibk-aos-test-targets-0.1.0`.
The complete combined controller/ABI/license gate also passes for this exact
`507a429f2c` source selection, yielding
`xfm482syk8qc2kx4ip7waha4lniyg3vw-crucible-phase2-abi-conformance-0`.
The controller passes 6,625 cases with 251 skipped in 361.813 seconds. The
license-boundary component passes all 18 cases in 2.16 seconds and verifies
matching complete corresponding source and the shipped native build identity.
The frozen input inventory contains 8,489 tracked source leaves. The realized
Nix source also includes two existing untracked engineering drafts; both are
retained and hashed separately, with no executable or schema-input references.
They remain outside the committed change. Later Root operators, KVM initial
journals, gem5 profile registrations, cold conditions and campaign extractions
receive no borrowed complete-gate credit.

## Installed Root operations and retained restoration custody

The node service and CLI expose original Root inspection, capture and
continuation transactions. A dedicated worker retains the native owner,
unpublished results and authenticated retirement work across errors and
unwinding. Original claims enforce exclusion against other node operations.
Initial preparation reserves one custody capsule; restoration reserves two
distinct staging and runtime capsules before effects. The per-world quota
and existing main catalog capacity remain unchanged.

The exact coordinator reader selects condition, recorded or closed Clock
state without discarding its original reference context. Fresh restoration
authenticates the current published target ownership while preserving the
original source outcome and signed archive. The native test independently
reads those two ownership records; it replaces only their declared vectors
and compares every remaining outcome field and all archive bytes.

Central verification passes 16 Root, 11 queue, 19 control and five CLI oracle
cases, 37 current-source hygiene cases, three-crate all-target strict checks
and 39 Rust formatting checks. The matching current-parent native CLI cohort
passes once in 400.14 seconds. It removes the entire original namespace,
restores two independently fresh owners, recovers the held original UART
transaction, commits and acknowledges it, verifies exact outcomes and
archives, then retires both owners and releases their namespaces. All 4,466
frozen source leaves and actual executable/profile identities match before
and after execution. The earlier private native cohorts remain separate.

These results qualify the installed fixed closed ARM Root and Clock queued recipe.
They supply no broader machine profile, Linux device parity, physical
lineage, conditional cold-state reader or performance credit.

## Canonical gem5 closed Linux disk and 9p mechanisms

The separately registered closed disk and 9p recipes bind actual Linux writes
to retained native requests and future device reactions. Each canonical
lifecycle removes the original namespace before two concurrent fresh owners
audit their bytes, recover the original request, acknowledge it and complete
readback and flush. Original payloads, receipts, UART history and native
tick/ordinal agree, and all three anchored groups reclaim.

Independent source review verifies 59 union leaves: 31 new sources and 28
unchanged reused dependencies. Existing network source and the shared native
foundations remain byte-identical. The added source-delta metadata also
materializes an existing network recipe dependency. The documentation
distinguishes historical private evidence from the separately qualified
canonical installed tuples.

The current source-owned profile recipes pass 14 disk and 20 9p checks,
yielding `xj1r38wdzsz59l6kmg84834sp2gkrb3a` and
`vjgz775w27g19lmzjzh2hkzd9l5ywxb4`. Central verification remeasures all
77 artifact roles and each complete 168-file configuration tree. Every
non-license artifact digest, lifecycle evidence object and semantic profile
field agrees with its original canonical profile. The new profiles bind the
current append-only license inventory; their unchanged native and lifecycle
derivations are reused. No duplicate native cohort is claimed.

All owned Python sources parse and six Nix recipes pass formatting. These
results qualify two distinct fixed Linux device mechanisms. Common readiness,
combined execution, CPU timing, external ingress, general device parity and
NativeArchive admission remain disabled and unqualified.

## Owned KVM initial response recovery

The installed owner retains the complete first pending response and its native
inventory before sending the original Submit. A finite journal reserves receipt
and observation capacity before dispatch, keeps conflicting callback facts
separate from accepted facts and preserves uncertainty through same-child
reconnection. Recovery polls the original transaction; it cannot submit a new
operation or turn request fields into callback authority. The complete original
result is retained before a later operation can replace the native source cache.

Independent review verifies the coherent 12-file implementation and its
comments-only format clarification. Current-source central checks pass 78 KVM
component cases, 117 QMP cases, 37 source-hygiene cases, all-target strict checks
and all 12 Rust formatting checks. The four source scanners bind the actual
current worktree. Earlier predecessor-bound scanner results remain withdrawn.

Positive callback and recovery cases use modeled QMP observations. A separate
actual stopped-TCG Initial refusal uses the matching native QEMU build. This
checkpoint supplies SDK and owning-journal credit only. Live KVM hardware,
ordinary execution grants, common clock windows, capture and readiness remain
unqualified.

## KVM original byte and completion custody

The prepared component SDK retains native response payloads, consecutive
completion identities and bounded complete reply histories across Initial,
More and Complete. Callback and completion requests remain distinct original
operations. Unknown replies and transport failures retain the same request;
reconciliation cannot replace its native ancestry or reexecute a later effect.
A pending or unfinished response chain refuses fresh Initial and Begin before
Query, I/O or a new credit reservation. Actual owner and channel authentication
remain separate from typed protocol facts.

The common prepared-node wrapper retains the original child, installed files,
peer, journals and supervisory reservation under one admitted owner. Preparation
refuses substituted installations, foreign owners and stronger guarantee claims.
Its execution gate stays closed: no executable facets, readiness, common grants,
physical capture, replay or branch authority are issued by component receipts.
Existing component launch arguments and general native profile gates are retained.

Current-source checks pass 111 KVM component cases, 145 QMP unit cases, 33 QMP
integration cases, 37 source-hygiene cases, all-target strict checks and formatting
of all 23 Rust paths. The KVM and QMP filters overlap; these counts do not claim
that every case is distinct. All 8,640 source leaves agree before and after the
checks. The two actual test executables and four source scanners are retained
outside Git, with every scanner binding the actual worktree. Callback positives
are modeled; matching stopped-TCG source refusals remain distinct. KVM hardware
execution is NotExecuted because this machine has no `/dev/kvm`.

## Cold preservation of original condition Stops

The selected installed Source/Block/condition world captures an acknowledged,
unresumed original Stop with its complete input, operation, publication and ACK
histories. Native/coordinator edition 6 retains Runtime 6 and Scheduler 4;
legacy codecs and ordinary defaults keep their previous bytes and refusals.
Restoration authenticates the complete signed source closure, prepares fresh
native owners and retains the stopped journal. Future work requires the original
Resume and current durable report reconciliation under the actual fresh owner.

The current-branch native cohort passes all three cases in 104.88 seconds.
Two positive cases compare the genuine original suffix with two simultaneous
fresh branches after source namespace deletion. They preserve a pending write's
payload, once-only completion, future read bytes and original FIFO/causal
identities. The larger case preserves the unchanged Stop through insufficient
runtime credit and the existing native capture ceiling, then reclaims its
resources. Declared per-scenario record credits are selected before preparation;
default 8 MiB, native 16 MiB and hard runtime 64 MiB limits remain unchanged.

Central checks pass 35 distinct archive/wire/model/geometry/domain cases,
37 current-source hygiene cases, all five consumer crates' all-target strict
checks and 39 Rust formatting checks. All 8,554 current source leaves agree
before and after execution. Complete local evidence and the actual test/scanner
executables are retained outside Git; independent review of the exact 40-file
source join preserves the current Root, Clock and initial-owner APIs.

These results qualify the closed Block condition preservation mechanism.
The public operator integration below supplies separate current-source credit.
Initial or already-resumed Stops, physical ingress, 9p, replay, fork, general
Compute and broader readiness remain separately unqualified.

## Public preservation of original condition Stops

Explicit control edition 10 exposes preserving prepare, status and once-only
Resume through the daemon and CLI. The closed Source/Block/condition route
claims the complete original request before allocating owners, captures its
acknowledged unresumed Stop, and restores a separately claimed fresh stopped
world. The fresh owner must reconcile the original durable report before Resume.
Source and target claims, signed capture links and complete output bodies remain
owned through publication, storage, shutdown and reclamation failures.

The current-source operator cohort exercises the freshly built CLI and daemon,
deletes the source program and condition, and restores two independent branches
at the same native cut. Both branches retain the complete 97-body content DAG,
original FIFO identities, payload bytes, positions, causal parents and native
Resume acknowledgements. Retried commands do not allocate another owner or
repeat suffix effects. Whole-record accounting applies the authored limit and
the unchanged 32 MiB hard ceiling before completed-ledger allocation; existing
parser and native capture limits are unchanged.

Current-source qualification passes the native operator case in 80.15 seconds,
six data cases, 37 source-hygiene cases, daemon and CLI all-target strict checks,
and formatting of all 21 functional Rust paths. All 8,627 source leaves agree
before and after execution. Complete original proof files, the actual daemon,
CLI and four source scanners remain outside Git; every scanner embeds the actual
worktree. A separate unchanged ContentRef checker verifies all 97 original body
references in each of the source and two branch outputs. The 22-path functional
join preserves unrelated factory, campaign, Clock, reader and cold-state review
rows. Independent current-source review precedes final evidence review.

The separate presentation commit formats one existing continuation call.
Qualification covers the explicit closed Block operator route. Initial or
already-resumed capture, physical ingress, 9p, replay, isolated fork, general
Compute and broader readiness retain their existing refusals.

## Backend-neutral choice closure and finding export

Shared attempt evidence, choice-closure encoding and final finding-export
transcripts now have backend-neutral module owners. Existing QEMU compatibility
paths, nominal errors, registered schema-owner paths, original request/Merkle
bytes, cancellation behavior, transfer credits and deadlines remain unchanged.
The extraction moves the same algorithms and retains the original public proof
types and forwarding entrypoints.

Current-source central checks pass eight export cases, 33 guarded campaign
cases, three choice-closure cases, the schema registry case, 37 source-hygiene
cases and daemon all-target strict checks. The fixed choice closure is nonempty;
the finding golden preserves an empty incorporated catalog with its complete
authenticated query transcript. It does not assert a nonempty finding catalog
or native object materialization. The initial formatter check identified two
files requiring declaration sorting and a wrapped test-helper reexport. A
separate formatting-only commit corrects those two files; all 11 selected Rust
files then pass the current-worktree formatter check. Module declarations,
attributes and import names retain their original meaning. The failed initial
formatter log remains part of the local evidence.

Independent reviews verify all 14 source images, the exact approved predecessor
algorithms and the two affected campaign responsibility rows. Current Root,
Clock and cold-condition rows remain unchanged. All 8,560 source leaves agree
before and after the central checks; actual daemon/schema/scanner executables
are retained locally with the scanners bound to this worktree. These results
supply extraction and compatibility credit only, without new native execution,
capability, schema, replay applicability or performance claims.

Fresh hermetic application unit/integration target compilation also passes the
committed `596e83bf03` Root/Initial checkpoint, yielding
`sxpz7dn0fmm1myljgd9j1vpvi9478xfz-aos-test-targets-0.1.0`. That source-specific
result supplies no subsequent cold-condition or extraction compilation credit.

## Original input lineage and installed reader

The common runtime retains complete original publication bodies, producer
permissions and consumer input acknowledgements. Source-local FIFO and duplicate
typed body roles remain distinct. Bounded closure validation checks the original
source before and after inspection; missing bodies, cycles, foreign scope,
changed owner epochs and exhausted credits refuse before consumer execution.
Legacy adapters retain their existing input route. Lineage-bearing capture
refuses until its complete preservation implementation is available.

A distinct installed candidate exercises three native rolling-checksum peers
through the common runtime: Source, Link and Disk. Nine actual windows and four
deliveries preserve original request/reply bytes, cumulative consumption
relations and cached native acknowledgements. Six complete initial/retired
journals remain local. Retirement persists every original journal, reclaims all
three capsules and releases the world reservation. Disk is a checksum peer;
this test does not exercise Block or 9p device I/O.

Current-source central checks pass 24 provider models, 15 core models, three
graph cases, the installed native case, the namespace refusal case and 37
source-hygiene cases. All three affected crates pass repository all-target
strict checks. The initial strict failure identified fixture panic annotations
missing from the source; a documented allowance now applies only to that
`cfg(test)` module and its children. The earlier private command's broader
allowances supply no equivalent strict credit. Original failures are retained.
All 8,608 source leaves are verified before and after the functional checks;
seven actual test/scanner executables and complete native evidence are retained
outside Git. A separate presentation commit adds 14 declaration-separating blank
lines, sorts the reader module declaration with its existing attribute and
refreshes only affected source-review digests. All 76 selected Rust files pass
formatting; current-source hygiene passes all 37 cases. Its initial hygiene
failure identified the factory digest changed by module sorting; the exact
owned digest is corrected without changing counts, rules or limits. This
presentation stage reruns no native/model tests and adds no functional credit.

These results supply the installed input-lineage mechanism evidence. They do
not qualify ordinary selection, accepted classes, Ready, source-gone restore,
physical ingress capture, CutoffFold bodies, Tape2 recording/replay or Linux
performance.

## Backend-neutral exploration ownership

Local exploration policies, branch construction and canonical planner fuel now
have backend-neutral module owners. Existing QEMU compatibility entrypoints and
nominal errors remain available. The algorithms, policy encoding, search order,
1,024-position scan limit and execution budgets retain their original behavior.
Two small checked-in golden fixtures preserve five complete original policy
bodies and the accepted branch identity/configuration-order projection. The
branch fixture does not represent a complete native branch execution.

Current-worktree verification passes all 36 campaign cases, the strategy mapping
case, 37 source-hygiene cases, daemon all-target strict checks and formatting of
all eight selected Rust files. All 8,613 source leaves agree before and after
these checks. The actual daemon executable and four worktree-bound source
scanners remain local. Independent review verifies the approved extraction and
the current-parent join, which updates only the two owned campaign source-review
rows and retains every other registration. These results qualify ownership and
compatibility, without native execution, device, replay or performance credit.

## Behavioral acceptance in installed admission

The qualification API retains complete original reports and accepted or refused
audit records against the full 382-requirement catalog. Independent host policy
binds the current measured unit, binding and required classes. Whole-record
credit is checked before authority callbacks, including worst-case diagnostic
encoding. Decoded accepted records cannot supply admission authority.

Installed catalogs can enforce this policy during ordinary preparation, before
native reservation, and repeat authentication at actual graph admission. The
required classes come from the regenerated guarantee and operating contract.
The exhaustive closed-selector table preserves existing limited source scopes;
unknown vendor selectors and substituted or widened profiles refuse. Specialized
and combined paths refuse the installed behavioral mode until separately
qualified. Existing native qualification remains mandatory.

Current-worktree checks pass 25 qualification cases, seven factory cases, 37
source-hygiene cases, daemon all-target strict checks and formatting of nine
owned Rust files. All 8,619 source leaves match before and after verification.
The current-parent join retains every registration except the owned factory
row; the actual daemon and four worktree-bound scanner executables remain local.
These checks qualify the audit and enforcement mechanisms. They do not provide
a complete native provider certificate, generic vendor constructor, Ready or
preservation capability. The owning CNP adapter's earlier wire admission needs
its separate mandatory-acceptance integration.

## Required acceptance before CNP admission

The public accepted-preparation capsule requires independent current behavioral
acceptance after original realization, native gate and companion authentication,
before sending Admit. The borrowed scope includes the complete actual profile,
realization, node/owner bindings, resource limits and native closed-gate record.
Consuming node construction repeats native and acceptance authentication; a
historical accepted record cannot authorize it. Refusal retains the original
process capsule under its reserved supervisor.

The daemon projects the complete realized unit into its installed report policy,
with finite pre-allocation bounds and one current installed scope. Current-source
checks pass 28 report/projection cases, the actual acceptance-ordering/refusal
test, unchanged legacy native preparation, 37 hygiene cases, core/daemon
all-target strict checks and formatting of ten Rust files. All 8,652 source
leaves match before and after verification. Actual test and scanner executables,
native companions and logs remain local. These tests establish enforcement for
the existing checksum peer and modeled report policy; the generic translator
and complete native vendor certificates require their separate qualification.

## Application test-target compilation

Fresh hermetic compilation passes for the application dependency closure at
exact committed checkpoint `3be5f583a3`. It includes the common Crucible and
node-provider crates; the daemon, CLI and QEMU adapter use their separate
current-source checks. The output is
`m4kx3rsnwq1p97jj8lgr00x8fgdcz8qp-aos-test-targets-0.1.0`; 167 test targets
compile, including 69 integration targets. This check compiles targets without
executing them and gives no compilation credit to later source changes.

The actual immutable application source contains 5,676 files: 5,657 matched
frozen inputs and 19 preexisting ignored Python bytecode files admitted by its
source filter. Their exact bytes and full source inventory are retained outside
Git and independently verified. This result does not claim execution of those
helpers. The separate source-filter correction excludes `__pycache__`, `.pyc`
and `.pyo` inputs. Comparing the actual selected sources removes exactly those
19 files and changes only the filter recipe among retained files; all other
bytes remain identical. The historical build inputs stay recorded as enrolled.

Fresh local release compilation with the corrected 5,657-file source passes,
yielding `scf2q1pwf01qa8x8xchfnvcqx5kv9fdc-aos-test-targets-0.1.0`. All 167
test targets, including 69 integration targets, compile. Its 943 compiler-artifact
records are byte-identical to the earlier check, with a successful build-finished
record. The immutable selected source matches before and after compilation;
the Nix source filter passes AOS formatting. This result supplies compilation
credit only for that selected application dependency image, without test
execution or later daemon, CLI, QEMU adapter or native qualification credit.

## Original-lineage transcript recording

The recording adapter retains original input and publication lineage beneath the
current replay cutoff. Schema 2 encodes explicit byte roles without changing the
inner control messages or legacy schema 1 encoding. Its signed captures require
complete original acknowledgements and one-shot export; legacy preservation
codecs refuse these new lineage bodies.

The current-worktree native recording test passes in 37.83 seconds. Three signed
tapes are persisted and independently reopened while the original peers remain
owned, before their actual retirement. Retained evidence preserves nine native
windows and four delivery joins. Complete content-reference checks pass for
1,289 tape bodies and 1,293 journal bodies; all nine journal archives preserve
the original request and object populations through shutdown.

Transcript models (37), context reconstruction (5), source hygiene (37),
core/provider/daemon all-target strict checks and formatting of 20 Rust files
pass. The 8,647 source leaves are checked before and after verification. The
first hygiene run found two stale responsibility hashes/counts; a metadata-only
successor corrects those cells and passes fresh hygiene checks. Executable
source and the original successful native cohort remain unchanged. Actual
executables, signed records, complete journals and the failed check stay local.
This recording mechanism supplies no conditional replay, physical capture,
ordinary Ready or complete provider qualification; those require their separate
native and installed-policy paths.

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

A provisional QEMU/plugin component comparison uses revision `2fc6fabd90` and
native source `0729c9712e`, with the identical frozen controller on both sides.
Six interleaved AB/BA/AB Linux boots preserve the complete RAM, register, serial,
grant, idle and timer witnesses, including original icount 8,481,484,328; seven
negative controls also pass. The same guest, 50 ps/instruction clock and CPU
placement are retained. Median launch-to-ready changes from 29.50669 to
29.54280 seconds (+0.12%). Mean times change from 31.50219 to 29.63408 seconds
(-5.93%), dominated by the first reference sample's 35.52384-second outlier.
All samples are retained without replacement or exclusion. These three pairs do
not support a reproducible material component gain or regression. This compares
components under the frozen controller, not the current controller, the complete
node executor or the final RFC implementation.

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
