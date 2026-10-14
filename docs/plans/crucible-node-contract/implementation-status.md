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
| `ac09b631d6` | Controller admission fixtures and complete installed provider tool roster | Seven admission and three artifact tests pass; repaired registered license gate passes |
| `799190ef5b` | Bounded semantic-prefix control, original native construction/callback custody and matching source | Plugin, host, protocol, archive and source-quality cases pass; registered four-vCPU ABI comparison fails at a timer deadline divergence, as recorded below |

Legacy codec bytes, hash domains, fault identifiers, and existing exact QEMU
restore semantics remain unchanged by these source extractions. New node
records use separate public schemas and cannot relabel legacy authority.

## Bounded QEMU control checkpoint and registered gate failure

Commit `799190ef5b` adds versioned semantic-prefix preparation, progress and
acknowledgment records, original native callback/construction custody, and
bounded host preparation, evidence and teardown. Unsupported native execution
and capture remain refused. Commit `ac09b631d6` fixes admission-test runtime
fixtures and checks the complete fourteen-tool provider roster.

The source checkpoint passes 736 plugin, 854 host, 248 protocol and 17 archive
cases, 37 source-quality checks, the unsafe-boundary and source-size checks,
strict compilation and formatting. Local hermetic application compilation
includes 167 test targets, including 69 integration targets. The repaired
registered license-boundary gate passes 6,963 cases across 309 binaries, with
274 registered skips.

The same checkpoint fails the registered four-vCPU ABI boot comparison. The
first retained timer-5 deadline differs by 200 ps, alongside four retired
instructions. Its primary host, QEMU, plugin and guest inputs match the preceding
tested inputs; the changed later host-parallel executable is not reached. These
comparisons narrow the investigation without establishing a causal origin. The original assertion, workload and deadline are unchanged. There is
no current overall ABI pass or native-readiness claim.

A separate source-built diagnostic tuple retains integer timer identities,
original APIC programming origins and CPU turn records in bounded rings. Its
composition preserves the original boot/cgroup/quota setup and assertions;
bounded rings are collected after the original execution and cleanup. The
original failed flight and all diagnostic source/build artifacts remain local.
The corrected reference diagnostic overflowed its 65,536-record ring before
the hostile lane ran. Its retained prefix identifies timer 5 as CPU 1's APIC
timer, but cannot supply a complete pair or explain the divergence. Diagnostic
observations do not supply a registered gate pass.

Local KVM is available inside the builder namespace. A patched nested guest
passes real API/capability discovery, empty-VM creation, and a pre-vCPU clock
configure/query probe including refusal and immutability checks. These probes
create no inner vCPU and run no guest instructions. A separate empty-VM
window probe also verifies arming, ceiling closure, frozen forward stepping,
and refusal through real controller ioctls. A separate one-vCPU probe passes
real RDTSC/RDTSCP guest execution, original private exit/clock acknowledgment
and child cleanup. These are scoped component probes; complete device
mediation, paced full-machine execution and native node qualification remain
required.

## Live four-owner execution and direct status

The installed live gem5 CPU, Clock, Script and Block group uses the original
prepared owner custody and complete-world activation. Requirements and source
bindings select the full group before construction. Its live profile advertises
no capture and refuses continuation; the preserving profile is a separate
implementation and cannot inherit readiness from this result.

Authenticated status requests read retained state directly, so a pending native
operation does not hold status requests behind the actor queue. Unknown
placements, nonce mismatches, and unsealed outcomes keep their existing refusal
or reconciliation behavior. The operation, pending input and retry retain the
same original custody.

Verification on the coherent source passes the actual four-owner workload, the
legacy Clock source-removal/two-fresh-restore scenario, five owned-preparation
cases, three native-selection cases, two direct-status cases, and the original
pending-operation/input/retry case. All three changed crates pass strict
all-target compilation, all 37 source-quality cases pass, and formatting passes.
Hermetic application compilation passes 167 test targets, including 69
integration targets. The preceding storage-exhaustion attempt remains a failed
build attempt; its unchanged-source retry supplies the completed gate result.

## Preserving four-owner transfer domain

The preserving gem5 CPU, Clock, Script and Block group retains the original
complete transfer domain, native process custody, outstanding input, and
acknowledgment associations. It uses a separate profile and preparation path
from the live group. Captured objects are joined by their original ownership
roles and exact content, including the dependency that connects the pending
Block input to its producer. Missing or changed transfer dependencies refuse
before native construction.

The actual x86 fixed-workload witness captures at the original pending input,
retires the source world, removes its source program, base resources and
namespace, and restores two independent complete worlds. Both preserve the
original CPU result, pending bytes, operation state and acknowledgment sequence,
then finish and reclaim their original custody. This qualifies that scoped
witness. It uses a separately frozen private source image; the current join
preserves its functional bodies and adds current-source model and quality
checks. Full-system Linux, ARM group preservation, device parity and ordinary
preserving execution remain separate work.

Verification on the coherent source passes twelve owned-preparation controls,
nine host-group controls and the explicit prebirth refusal. Three-consumer
all-target strict compilation, all 37 source-quality cases and formatting of
the 41 changed Rust sources pass. Hermetic application compilation passes 167
test targets, including 69 integration targets. Its selected source includes
the twelve core preservation paths; daemon preservation sources and their
metadata are outside that application gate. The original failed compilation,
zero-match test selection, missing-fixture invocation and temporary-storage
refusal remain separately retained; they supply no test or native qualification.

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

Fresh local release compilation also passes for the selected application
dependency image frozen at the authored-capabilities join, before its ledger edit
and the subsequent clock-list and roster changes. The immutable 5,676-file source
contains no Python bytecode caches. Output
`akjkbhjrl39qys0sqbq7ggr2fs7kad5n-aos-test-targets-0.1.0` records 943 compiler
artifacts, all 167 test targets, 69 integration targets and successful build
completion. The selected derivation, source inventory, command and output are
independently checked; all builds run locally with remote builders disabled.
This historical result supplies application compilation evidence only, without
test execution or later daemon, CLI, QEMU adapter or native qualification credit.

Fresh local release compilation passes for the selected application dependency
image frozen at the generic typed-peer consumer join, before its ledger edit.
All eleven consumer source paths are present in its immutable 5,679-file source,
which contains no Python bytecode caches. Output
`mk52jil5pcdaiyyizrxxs9xisydklczr-aos-test-targets-0.1.0` records 943 compiler
artifacts, all 167 test targets, 69 integration targets and successful build
completion. Independent review checks 11,366 source and artifact bindings with
no errors. The actual derivation, command and output are retained locally;
remote builders were disabled. This historical image supplies application
compilation evidence only, without test execution or later source, daemon, CLI,
QEMU adapter or native qualification credit.


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

## Rational host clock and original alarm preservation

The installed rational Clock and its Script request node use common admission,
activation, input delivery, execution, output acknowledgment and signed state
preservation. Read, arm and cancel requests retain their original identities,
full Positions and FIFO state. A fixed rational rate, epoch offset and drift
change the visible counter; coordinator time retains its original picoseconds.
Checked arithmetic refuses overflow and inverse alarm conversion rounds upward.
The old integer Clock and existing preservation bytes remain unchanged.

The selected Host8 producer codec retains complete stopped-root, native-state
and causal-child bodies, original inputs, pending alarms and issued responses.
Current activation custody is required even for empty evidence reads. Role and
expanded-byte credits precede retained observations and operation effects.
Missing, null, repeated, corrupt or foreign associations refuse. The receipt's
nullable input field must be present explicitly; omission refuses before typed
reconstruction.

The current-worktree native cohort passes both signed cold cases in 87.19
seconds, with drift zero and -500,000,000 ppb. Actual ordinary planner delivery
and acknowledgment reach cut11 after read, two arms and one cancellation. The
original runtime is reclaimed and its Script file deleted before two fresh
worlds restore. Each fresh world recaptures the unchanged Clock native state,
keeps the alarm absent before exclusive1000, fires it once before1001, keeps
the canceled alarm absent and produces the same later reading. Complete signed
archive bodies, original and fresh manifests, blobs, future events and genuine
reclamation markers remain private; authentication keys are never exported.

Five clock arithmetic/ordering controls, 21 Host regressions, nine archive
regressions and three required-input grammar controls pass. Current source
hygiene passes37, core/daemon all-target strict checks pass in80 seconds, and
all27 selected Rust files pass formatting. Two initial runner selectors matched
zero tests and supply no test credit; the corrected selectors execute the
actual retained tests. The first hygiene run refused a nonadjacent test
allowance comment. Moving that comment alone preserves all Rust statements and
attributes; its current checks are recorded separately from the original native
source image. Failed checks remain retained.

This selected state uses Runtime1, coordinator1 and Scheduling1. Combining it
with Tape2/Runtime7, conditional replay or selected extensions refuses before
owner reconstruction. It does not establish guest IRQs, dynamic rate changes,
wall-clock timing, mixed emulator execution, operator capture or a later-cut
recapture after suffix execution. Broader preservation remains separately
qualified.

## Exact typed peer extension negotiation

The opt-in `cnp.extension-negotiation/1` Hello extension selects format1 and
retains complete declaration ContentRefs, identifiers, exact SemVer and schema
identities. Source-installed definitions, handlers and all eight semantic axes
remain independently authenticated. Required tuples must match; optional
selection is deterministic and ambiguous versions refuse. Resume preserves the
original selected roster before registration, fencing or secret rotation.
Legacy Hello serialization and entrypoints retain their previous behavior.

A borrowed envelope preflight checks the one-mebibyte encoded ceiling and the
aggregate256-entry roster before serde retains tuple strings/references.
Required and optional arrays share one credit; selected responses have their
own bounded roster. Positional object substitutes refuse before decoding.
This corrects the separately retained predecessor's gap, where valid257-entry
JSON could allocate before its typed validation refused.

Current-worktree checks pass31 installed registry cases, ten pre-retention
and framed-peer controls, and all244 provider unit cases with13 existing ignored
cases. One deliberate nested subprocess independently passes; the initial
runner counted it as another primary unit and refused its own result guard.
The original successful program output is retained and correctly scoped without
rerunning those tests. Source hygiene passes37, core/provider all-target strict
checks pass in72 seconds and all12 selected Rust files pass formatting.
All8,666 source leaves are checked before and after verification. Actual
executables, scanners, exact commands, logs and two small legacy wire goldens
remain retained; raw evidence stays outside Git and release artifacts.

Generic negotiation supplies no installed provider class, native issuer,
readiness, execution, dynamic Input handler or preservation authority. Existing
measured providers continue to refuse the new opt-in. A separately measured
source/bootstrap/profile, ordinary graph consumer and source-owned semantic
policy are required before a native provider may use it.

## Authored capabilities in preserving and mixed native worlds

The installed preserving Source/Block/condition route now accepts complete
original capability requirements in request edition 2. It regenerates the same
whole-world demands, selected source policy and signed archive binding before
native reservation, and retains the exact wrapper through Stop capture and fresh
restoration. Legacy requests omit the field unchanged; explicit null and
inconsistent editions refuse. Independently installed policies still determine
which native operations may run.

The ordinary capability route also prepares the existing closed Clock/gem5
world using its genuine mixed owner, original graph admission and one complete
activation barrier. The authored requirements are authenticated beneath the
same native profile; they cannot install another CPU, widen its facets or grant
capture, fork or replay support.

The current-worktree join contains exactly 18 source paths above `6aac344340`.
Its only overlapping factory hunk retains the complete rational-clock support
and adds the condition wrapper without replacing the earlier implementation.
Both original private-stage prerequisites and the complete joined inventory
include the three new preserving-condition modules.

Current qualification passes five capability and seven preserving data cases,
two native cases, all 37 source-quality checks, daemon/CLI all-target strict
checks and formatting of all 18 files. The actual preserving CLI/daemon case
passes in 74.62 seconds: capture the original ACKed, unresumed Stop, remove all original
source files, restore two fresh worlds and compare unchanged suffixes and
once-only Resume. The actual mixed CLI case passes in 71.34 seconds with two
owners, original preparation/activation, independently computed guest checksum,
cached retries, six unsupported-demand refusals and graceful native retirement.
These durations are correctness-test results, not Linux performance evidence.

The final current receipt has SHA256
`2e995b316ef4656d1d7086a3a1821c87b76a30a603bbd7c4fdab411b0b2dc38c`;
its unchanged before/after source inventory contains 8,671 files. Local retention
preserves 1,181 public original-body/source/log/command files and seven actual
current executables. Private archive keys remain in their original namespaces
and are never read, hashed, copied or published by retention or review.

One runner failure is preserved: Cargo's integration-test feature unification
rebuilt the CLI after the standalone binary had been retained, so the hash guard
refused before any model or native assertion ran. The corrected runner reused
the completed unchanged-source builds, retained the actual integration-built
CLI and checked its original compile-time path before and after both native
cases. This supplies no extra native pass or source-change credit.

This checkpoint covers the selected preserving condition and fixed two-owner
mixed world. Additional node rosters, complete backend parity, Runtime7,
conditional replay, generic CNP semantics and physical/KVM execution remain
under their distinct implementation and qualification paths.

## Authored independent clocks in mixed gem5 worlds

The ordinary installed Clock/gem5 route accepts an ordered list of up to four
additional independent, portless HostClock selections. It validates the complete
authored roster and reserves model and node credits before the native child is
created. Every original owner participates in the same graph admission and
whole-world activation barrier. An empty list preserves the existing two-owner
request and world; the list grants no new CPU, timing, capture or replay facet.

Current qualification passes four clock-list and five capability data cases,
all 37 source-quality checks, daemon/CLI all-target strict checks and formatting
of the 11 functional source files. The same actual integration executable passes
the three-owner native CLI/daemon case in 73.02 seconds and the existing empty-list
two-owner case in 73.36 seconds. Both retain original ownership, admission and
activation records, independently checked guest output, cached retries,
unsupported-demand refusals and graceful native retirement. These are correctness
durations, not Linux performance measurements.

The unchanged before/after inventory contains 8,674 source files. The final
receipt has SHA256
`ae5c8f4679ec6233da75638f20aeef33d4a9491add9a864b41d08cbf7ba8bd46`.
Local retention preserves 447 public original-body/source/log/command files and
seven actual executables; raw evidence remains outside Git and release artifacts.
Two runner failures remain recorded: the initial catalog guard counted ignored
tests with ordinary tests, and the first reuse helper rejected an existing
retention directory. Both occurred before native execution. The corrected runner
reused completed builds without changing source or repeating either native case.

The separately reviewed presentation change is excluded from this functional
checkpoint. Arbitrary backend rosters, ARM execution, transformed clocks,
preservation, complete CPU/device closure and vendor classes require their own
implementation and qualification.

## Complete host-model preparation before child creation

The ordinary factory constructs its complete selected host-model roster before
launching any provider child. The reusable planner validates sorted independent
owners, authenticates initialization bodies and reserves finite node slots under
the existing 64-node and 4 MiB per-model limits. Each Block model receives its own
mutable overlay even when multiple models share immutable base bytes. Installed
source selection, whole-graph admission and the original all-owner activation
barrier remain mandatory.

The current five-path functional join passes an actual five-owner CLI/daemon
world in 3.64 seconds: one Clock and two independent Script/Block groups, distinct
write/read patterns, complete authored requirements, original FIFO ownership,
cached retries, unsupported demands and graceful native retirement. The same
integration executable passes the existing Clock source-deletion/two-restoration
case in 13.79 seconds. All three legacy process cases, four clock-list and five
capability data cases, all 37 source-quality checks, daemon/CLI all-target strict
checks and formatting of four Rust files also pass.

All 8,676 source files match before and after qualification. The final receipt
has SHA256
`4e42ab868d58d8565ded64dce99f3255e8fd24b6811ac7dadfc2fa8affee42d8`.
Local retention preserves 178 public original-body/source/log/command files and
eight actual executables. The five-owner original namespace remains available;
the legacy Clock temporary namespace was not retained, and its test result is
supported by the unchanged fixture, actual executable and original log. Raw
evidence stays outside Git and release artifacts.

The earlier private-stage failed unsupported-demand control and its original
output remain recorded separately; the corrected fixture distinguishes the
synchronous unsupported physical mode from queued unavailable demands. No
current native case was repeated. The separate import-layout change is excluded.
This planner adds no backend, profile, CPU, transformed-clock, preservation or
native qualification authority. These durations supply correctness evidence.

## Generic typed peer attachment with original process custody

The generic node-protocol consumer accepts negotiated extension attachments only
through the original private registrar for the current preparation and epoch.
Foreign, duplicate and revoked attachments return their complete offered
resources while retaining the same actual provider child and owning capsule.
Installed sources must explicitly provide the attachment hooks; the default
refuses before discovery. This mechanism grants no installed source, accepted
native class, common readiness or capture authority.

The current eleven-path functional join passes four focused controls (three
actual framed child-process cases and one inert helper), all 31 installed
registry cases and 247 primary provider cases plus one nested subprocess case.
Thirteen historical provider cases and seven historical native core cases remain
ignored. All 37 source-quality checks, core/provider all-target strict checks and
formatting of eleven Rust files pass. All 8,679 source files match before and
after qualification. The final receipt has SHA256
`d97fdc1abbc043434c733d719a2424f58ff57301d985fb88b9ac2c125fc19d8a`.

Local retention preserves 44 source, log and command files and six actual test
and source-quality executables. The transient peer namespaces were not retained;
their results are supported by the exact fixtures, executables and original
logs. Independent review checks 8,842 source and artifact bindings with no errors.
Earlier private compiler, strict-check and cached-scanner failures remain
recorded separately. Raw evidence stays outside Git and release artifacts.

## Common attempt routing with opaque source proofs

The backend-neutral attempt router owns fresh/resume dispatch and original
post-publication reconciliation. Adapters supply opaque selected-boundary,
selected-proof and inherited-prefix proof types. Construction requires equal
source-owned replay contracts; missing or mismatched contracts refuse while
retaining both complete original adapters. Later contract drift refuses before
execution. Routing metadata supplies no native or restoration authority.

The existing QEMU compatibility adapter delegates to the common router and
preserves its public constructor, accessors, trait contracts, nominal errors,
opaque QEMU proofs and original branch/reconciliation behavior. Wire formats,
snapshot formats and legacy serialized QEMU implementation identities remain
unchanged. Backend-specific native authentication stays with each adapter.

The current six-path functional join passes nine common data controls and both
unchanged legacy QEMU routing controls. All 37 source-quality checks, daemon
all-target strict checks and formatting of four Rust files also pass. All 8,681
source files match before and after qualification. The final receipt has SHA256
`9fa867dca515faf0518c577699c41162b8c8b7a01968eb4edaa06f14129f2497`.
Local retention preserves 33 source, log and command files and five actual test
and source-quality executables. These results qualify the source/API migration
and data routing controls; they supply no new backend, native class, readiness,
capture, mixed restoration or serialization authority. Earlier private tool and
source-quality refusals remain separately recorded. Raw evidence stays local.

## Original lineage preservation with bounded ownership

Runtime7 and Tape2 preserve the original input, evaluation, publication,
acknowledgment and continuation records. Native archive projection retains the
admitted dependency graph and authentic source identities. Restoration validates
the complete original role closure before installing ownership. Source pins share
verified immutable bodies across owners, and refused transfers return the
original content rather than discarding it. Metadata, code artifacts and recorded
payloads use explicit finite credits before copies or effects; the recorded-input
limit does not expand to accommodate executable artifacts.

The current 52-path prerequisite join passes all 1,019 core tests, 37 source-quality
checks, strict all-target checks for core, provider and daemon, and formatting of
51 Rust files. All 8,711 source files match before and after verification. Its
final receipt has SHA256
`7be355d069645156ca891d27b617db40f00dec1c66dc55b527f8a5eb4d137000`;
local retention preserves 91 source, log and command files and five actual
test/scanner executables.

The existing native Source-to-Block pending-transfer regression also passes
against the changed source in 25.96 seconds. It reclaims the original world,
deletes both source paths, and restores two independent owners that recover the
original reply and private disk state. Its separate receipt has SHA256
`a209ba24386084d9d53f8839de7305c1b4d94bedb0f70597157623a04d05b109`.
The test and companion executables, commands and logs remain local. The fixture
removed its transient archive namespace during cleanup; those archive bodies are
not retained for independent reinspection. This checks the existing
HostArchive/Scheduling1 path and supplies no Runtime7 conditional-capture,
installed typed-source, class or readiness qualification.

Fresh local hermetic application test-target compilation passes for the frozen
preservation image. Its immutable 5,709-file source contains all 51 changed core
Rust files and excludes only the engineering baseline from that join. Output
`13pp3wzwrzz957sgvnkn928wv73aak6s-aos-test-targets-0.1.0` records 943 compiler
artifacts, all 167 test targets, 69 integration targets and successful build
completion. Its receipt has SHA256
`394053438d4f01bd850dc615f4e7157bcc8404b8957bd7953e1f7eb43cd68392`.
This historical image predates the ledger, common-counter and typed-reader joins;
it supplies no later source, test execution, daemon, CLI, QEMU or native credit.
Earlier compilation receipts retain their original selected images. Raw evidence
stays local.

## Common execution-quantum accounting

Attempt execution budgets use a backend-neutral counter and exhaustion error.
Charging preserves the exact admitted unsigned ceiling, refuses without changing
the spent count, and cannot overflow at `u64::MAX`. The QEMU compatibility counter
delegates while retaining its nominal type, constant constructor/accessors,
copy/equality behavior, Debug fields and exact realization-error operation and
message. The original resource guard and its tests remain byte-identical;
cancellation and host-resource checks retain their original order before charging.

The current four-path migration passes four accounting controls and all 23
unchanged QEMU resource/workspace guard controls, 37 source-quality checks,
daemon all-target strict checks and formatting of four Rust files. All 8,713
source files match before and after qualification. The final receipt has SHA256
`b0174515938449af0f4ef866d4e08118ef9f8ec600b30d9449de658f009e215b`.
The initial harness selected only the 21 direct guard cases while expecting
the complete 23-case group; the corrected selector includes the two workspace
cases. The original four passing accounting controls were retained without
reexecution. Exact sources, commands, logs and five test/scanner executables stay
local. This changes API ownership and supplies no wire, native, capability,
readiness or capture qualification. Raw evidence is excluded from Git.

## Typed reader source and original negotiated construction

A distinct typed reader provider exports its complete source-owned extension
selection, profile, schemas and implementation manifest. Its startup requires the
original negotiated registrar and exact selected tuple. The semantic consumer
retains that same registrar through source preparation and revalidates it before
construction; the legacy constructor refuses typed mode. Package and suite wiring
retain this implementation separately from the historical reader installation.

The current 22-path source/API join passes all 1,020 core tests and 249 primary
provider tests, plus one subprocess test; 13 native provider tests remain
intentionally ignored. All 37 source-quality checks, core/provider/daemon
all-target strict checks, formatting of 18 Rust files and two Nix files pass.
All 8,720 source files match before and after verification. The final combined
receipt has SHA256
`2469b30767f6a7c9afed0affb25255e350a00872781fd9132d20429df3a2806e`.
Local retention preserves 64 source, log and command files and six actual
test/scanner executables. Release compilation passes against the immutable 5,716-file selected
application source image: 943 compiler artifacts and 167 test targets, including
69 integration targets. Every changed Rust/Cargo file and both package recipes
are included; the engineering baseline is excluded. Independent review checks
5,773 source, derivation, command and compiler-record bindings. This compile-only
image predates the typed-reader ledger and catalog join; it supplies no later
whole-image, daemon, CLI, QEMU, native execution or source-package qualification.

The separate privately frozen source22 image also passes source-built package
checks and produces the distinct `4ac8a9w60vm7w5lxsazp141znl44rkn2` implementation.
Independent review checks all 328 complete content-reference roles, 5,973 archived
workspace members and the generated platform role against that image, together
with its actual build and derivation. Its package review has SHA256
`f2775f54cb7827fe596338d72c6d8875b3b3c3d773af386bd7dc632bf430e2b4`.
This package is not the complete current worktree image and does not supersede
earlier package identities. Source exports and generic negotiated construction do
not supply installed behavioral acceptance, a native execution epoch, ordinary
selection, readiness, a class, or conditional capture. Those remain separate
owning-cohort requirements. Raw evidence stays local.

## Measured typed package catalog and owning policy boundary

The host catalog remeasures the exact installed typed package and regenerates its
source definition, profile, graph, handler and eight semantic axes. Independently
installed host policy is mandatory before package reads. Unsupported operation
credits refuse before reads or callbacks; an absent or incomplete installed peer
registry refuses before the owning callback. Successful preparation retains the
same measured package, profile, peer semantics and returned qualification.
Original installed package identities and complete pre-child model reservations
remain unchanged. This API does not create a provider child or activate a world.

The current twelve-path join passes nine focused tests and four separately run
measured-package data controls: two against the original `rxaw` package and two
against the distinct `4ac` package. Both data pairs preserve empty-registry
refusal without an owning-policy callback. All 37 source-quality checks,
daemon/CLI all-target strict checks and formatting of eleven Rust files pass.
Every one of 8,729 source files matches before and after verification. The final
receipt has SHA256
`af0e94bb39c844e7a10d308258ec9599b519f6de7ff89db8fada8e4533262ddc`.
Local retention preserves 36 source, log and command files and five actual test
and scanner executables. The independently reviewed private twelve-path image
has its own 8,727-file source inventory and evidence; current-root checks include
the two later common-counter files instead of borrowing that earlier image.

The installed owning behavioral policy, genuine typed source epoch, ordinary
selector, complete-world activation, native class, readiness and conditional
capture remain separate requirements. Package data and generic factory callbacks
do not supply that authority. Raw evidence remains local.

Committed checkpoint `03e54e906a`, formatted by `6a63581741`, adds separately
authorized finite conformance collection, original staged-input custody and
durable result publication. Its frozen 8,935-file image passes 195 selected
tests: 104 core, 86 daemon, four provider and one CLI. Declared all-target
strict checks pass; independent review verifies four rebuilt daemon/CLI groups
and their 24 retained artifacts. All 37 source-quality checks and formatting of
136 Rust files pass. Separate hermetic application compilation passes 167 test
targets, including 69 integration targets, for its selected 5,767-file image;
daemon and CLI sources are excluded and these targets are not executed. The
actual three-peer, nine-window fixture has not run, and the ordinary typed
profile remains unqualified against the full 382-requirement catalog. The
original registered QEMU ABI comparison remains failed; the historical
performance comparisons below supply no performance result for this checkpoint.
Raw evidence remains local.

Checkpoint `7f48787c88` retains original typed provider, reader and whole-world
custody across borrowed retirement and callback unwinds. Its frozen 8,939-file
image passes seven focused lifecycle controls, strict compilation, core library
and daemon lifecycle-target compilation, 37 source-quality checks and formatting
of 17 Rust files. The fresh hermetic `rust.aos-test-targets` gate also passes:
167 test targets, including 69 integration targets, across 48 test packages.
Its selected 5,769-file application image matches the frozen source; all 244
workspace compiler artifacts are freshly compiled, with no application test
execution. The output is
`85c2lkb8rb1wpvxvwvz730kkh2m03qsb-aos-test-targets-0.1.0`, and its retained
compiler messages have SHA256
`5692517fc0ebd870431f8fc634753119a9df8a9fcac69feb45c92be2ac29edc9`.
The focused controls use inert nodes and do not establish native shutdown,
reclamation, ordinary profile qualification or performance improvements.

Checkpoint `26ac82b440` adds mixed installed-provider preparation under one
original activation and custody slot. Complete source authentication precedes
contribution; selected descriptions and all retained authority revisions are
checked after graph admission. Ten mixed-provider controls and six existing
preparation custody regressions pass, alongside strict compilation and 37
source-quality checks. These controls use inert participants and do not qualify
native mixed-backend execution or full-system state preservation.

Checkpoint `62cbf4b7c2`, documented separately by `ac2dfbd8c2`, adds same-stream
gem5 shutdown reply continuation after eligible transient receive failure.
It retains the original deadline, partial reply and one-shot request. Nine
native-free controls pass against the exact functional source: five real Unix
stream cases and four durable-placement fault cases. The latter preserve the
original failed-retirement seal until same-byte storage reconciliation. These
results do not establish native shutdown acknowledgement, reclamation, release
or ordinary class acceptance. Current combined application-target compilation,
native qualification and boundary gates remain required; raw evidence stays
local.

## Common debugger names and replay imports

Shared debugger requests, reports and endpoint fields use backend names, and
common checkpoint consumers import replay-closure types from their neutral
defining module. QEMU launch channels and compatibility reexports keep their
implementation-specific names. Public Rust field and breakpoint-variant names
change, including their derived Debug labels; explicit diagnostic literals and
serialized formats keep their existing representation.

All targets compile across core, session, API and daemon consumers, and ten
existing debugger controls pass. These checks cover the rename and shared
imports; they do not add debugger capabilities to a native backend.

## Original behavioral collection and shutdown continuation

Behavioral collection borrows the original runtime through an evidence-only
interface. Reports retain the complete requirement population and every
unexecuted obligation; partial observations cannot produce accepted native
support. CPU and storage observations recheck the actual source, activation
and complete-world binding before collecting or publishing an outcome.

An incomplete graceful Shutdown reply can continue on its original stream and
first deadline. The request is never resent, and expired, foreign or permanently
failed replies retain the original exchange and containment state.

Verification includes 55 focused core/daemon cases on the unchanged production
bodies, a fresh provider test build and all five affected transport cases after
a test-only lint correction, strict all-target checks for core, daemon and
provider, and all 37 source-quality checks. These checks establish collection
and transport behavior. Complete native qualification and the registered
application-target, ABI and license gates remain separate requirements.

## APIC diagnostic resource admission

The first fresh four-vCPU diagnostic VM refused launch before its timer
comparison: configuration reserved one trace extent while the command builder
required both normalized and raw copies. Configuration now reserves both.
The real four-vCPU command/admission control passes and preserves refusal for
differently reserved commands; all `crucible-qemu` targets compile on that
frozen successor. The next fresh VM refused the aggregate disk ceiling before
guest execution: its two trace extents require 1,152 MiB, exceeding the admitted
1 GiB. Raw-copy diagnostics now receive an additional 256 MiB project quota and
file-size backstop; ordinary runs retain 1 GiB. The actual production host recipe
passes the new ordinary/diagnostic admission control, including refusal under
the old ceiling. CPU, memory, workload and clock settings remain unchanged.
New corresponding source, rootfs and the original VM comparison remain separate
validation. The earlier timer divergence is unresolved.

## Staged whole-operation control framing

The portable whole-operation protocol separates retained input stages from
compute operations, with independent finite capacities and complete original
bodies. Source receipts and consumed commit acknowledgments correlate the
original staged input. Queue plans validate ring geometry and logical names
using checked offsets; native pointers and callback objects remain private.
The explicit launch selection retains four-vCPU, 50 ps SIM provenance and
image commitments without granting native construction authority.

The staged constructor reserves the full 344-byte minimum result, including
its empty queue inventory, and rejects smaller capacities before construction.
All 199 protocol unit controls pass, with one preexisting ignored test. Strict
library/test compilation and Clippy pass. The ordinary composite setup encoding
remains edition two; the staged selection uses an explicit edition three.
Actual plugin producers, callback integration and complete native readiness
remain unqualified by these codec checks.

The Linux setup helpers retain the complete original 13-byte frame and three
descriptors across partial nonblocking transfers. One physical syscall runs per
step, with no hidden retry or descriptor duplication. A lifetime administrative
budget spans initial setup and staged control; failed attempts and offered write
bytes cannot be refunded. Malformed and foreign transfers retain their received
material. All 211 portable protocol controls pass, with one existing ignored
test; strict compilation and Clippy pass. These helpers still require integration
with the original host and plugin actors before native readiness is qualified.

Explicit Launch2 provenance adds a separate 256-byte prefix for the original
CPU arguments, SIM quantum, fixed RTC, run seed and four image/entropy resources.
The codec preserves Launch1 and reserves the future bounded readiness exchange
within the same lifetime administrative budget. It does not issue readiness.
All 213 portable controls pass with one existing ignored test, alongside strict
compilation and Clippy. Independently reviewed C/Rust vectors match at 625 bytes
for launch and 1,004 bytes for complete setup; the incomplete 876-byte setup
remains a negative fixture. Native component tests use modeled board peers and
do not qualify actual constructors, installed producers or Linux execution.

Complete setup sizing now uses checked nested lengths before allocating an
encoding buffer. Pending requests retain their entire original reply capacity
in that count. All 213 portable tests pass with one existing ignored test,
strict compilation and Clippy. Actual allocator controls report zero sizing
allocations for the complete 1,004-byte Launch2 setup and a 4,479-byte restored
setup containing a 4,096-byte reply reservation; both counts match the encoded
bytes. This helper supplies pre-effect resource admission and preserves the
wire format. It does not qualify an installed producer or readiness.

The runtime now requires an authenticated consumer commitment before releasing
input ownership or issuing execution grants. Both new adapter hooks refuse by
default. Host-owned adapters explicitly validate their retained original input;
socket adapters remain closed until their consumed-commit journal is integrated.
Pending retries preserve the original stage, commit and ownership reservation.
Snapshots distinguish pending from consumed commitment with an explicit custody
edition and refuse legacy staged records rather than upgrading an old ACK.

All core targets compile and strict Clippy passes on the frozen successor.
Focused input, scheduler, replay, host-model and reference-device controls pass
(10, 48, 29, 21 and one respectively), alongside 80 runtime regression controls.
The existing ignored reference control remains ignored. Independent review
verifies the 15 affected source bodies and emitted test executable. Test-support
fixtures, complete application gates and native continuation qualification
remain separate requirements.

The controlled reference wrapper now retains whether the original staging
transfer is host-owned or child-staged. An external staging acknowledgement
always selects the child path; the later original coordinator commit and its
validation must reach that actual child. Missing staging acknowledgement cannot
select host custody unless the implementation explicitly supports it. The
genuine reference device validates its parked owner, incarnation, generation
and exact original transfer before the host releases input ownership. Public
CNP and lineage readers refuse until their source-consumed commitment journal
is implemented.

All targets of the three affected crates compile on the final frozen source.
Three separately executed real-child controls verify refusal with a staging-only
ACK, refusal with an unsupported absent ACK, and successful execution of two
admitted reference-device quantums. The executed test source differs from the
final typechecked test only by five inserted blank lines; the production changes
are identical. These controls do not qualify public vendor acceptance or native
readiness.

## Process-private shared-memory ownership

Setup mappings retain their original ownership metadata across forks. A child
publishes a fresh process generation before entering ownership locks, so a
parent thread's inherited mutex cannot block child replacement. Whole-operation
selection fences ordinary aliases, while each original mapping retains its own
epoch, bounded operation account and paired ring scope. Ordinary teardown keeps
the original registration until the actual unmap completes.

Roster adoption restricts the original ring headers under the same ownership
guard; invalid or concurrently refused adoption cannot return usable custody.
Original ownership now reserves bounded retention before native observation
and can fence ordinary aliases before adopting an epoch. Failed observation
revokes the exact local permit while preserving the mapping and effect history.
The original retention ticket transfers its same mapping allocation once;
immutable process tags reject inherited tickets and unfinished initialization
before a child can wait on a vanished parent thread.

All 152 unit tests and 12 separately executed fork/socket fixtures pass,
including replacement while a parent holds an ownership lock or initializes
a retention ticket. Independent review verifies the exact source and executed
controls. These process-private changes preserve the shared-memory layout;
they grant no native readiness.
Actual plugin callback integration, complete ABI/license gates and application
target compilation remain separate requirements.

## Installed public vendor integration

The ordinary service installs the public vendor factory before binding its
control endpoint. Preparation retains the original pre-child custody slot,
rechecks authentic leases before native effects, and forwards durable
publication into that same journal. Uncertain publication remains retained;
a later outage cannot erase a positively committed original record. Duplicate
or foreign owner rosters refuse before storage callbacks.

Three affected crates compile their test targets, and all 16 scoped controls
pass. These checks establish preparation and publication behavior.

Ordinary cleanup now requires positive native semantic resolution and a durable
archive of the original peer, negotiation and complete control history. Reaping
alone cannot authorize release. Package source descriptors are retained before
child creation; their full bytes stream into the same private archive. Failed
writes retain the original file and capsule, and retries authenticate its exact
prefix, descriptor, directory, complete readback and synchronization before
clearing the active slot. Nine filesystem and source-retention controls pass;
three affected crates compile library and integration targets. Independent
review verifies all 22 changed source bodies and the emitted control executable.
The current ordinary package, complete singleton acceptance, end-to-end native
cleanup, readiness and capture/restore qualification remain incomplete.

The lifecycle successor retains complete controller and runtime histories through
semantic Shutdown, native reclamation, private archival and once-only resource
transfer. It counts the complete borrowed history before snapshots, base64
encoding or owning copies. A bounded streaming counter handles numeric tokens
across arbitrary writes and uses the authoritative canonical numeric encoder;
it replaces an insufficient multiplicative estimate for floating-point extension
values. The final canonical output uses the same encoder as existing identities.
Raw consumed input bytes remain immutable leaves even when they equal an existing
payload; their containing commitment retains the causal dependencies.

The final 50-file source passes strict all-target checks for the provider, core
and daemon. Two numeric-sizing controls cover split tokens, escaped strings,
exponents, integer rounding, final-token handling and exhausted credit. A fresh
actual-child retirement test passes with nonempty consumed input, original
journals, lost archive-sink retry, exact readback and duplicate transfer. These
executions retain their source cohort; the final lint-only test annotation is
separately verified to preserve production and assertions. Three preceding
actual preparation, lost-readiness and connected-world tests and 30 canonical
contract controls retain their earlier source scope. The ordinary singleton
collector and complete clause plan are implemented, but their current installed
package and full 382-obligation acceptance remain unqualified.

The singleton collector now seals its own pre-realization and prepared adverse
probe populations before constructing a child. It retains nonrenewing attempt
state and original observations rather than borrowing a two-owner fixture's
history. A complete-clause verifier checks exact compiled clauses, locations,
source references and dependency assignments. It still reports unresolved
behavioral reviews as NotExecuted; source equality cannot issue acceptance.

A separate owning terminal-history exporter preserves definitive original
refusals alongside completed replies. Refusals must have a known baseline error,
NotStarted effect and operation state, no retry and no response extensions.
Semantic release and actual native reclamation remain mandatory before archival;
the completed-only export API retains its existing contract.

The seven-file successor passes four focused controls and strict three-crate
all-target checks. Independent review binds every changed role to retained
test artifacts, including the actual core library consumed by the daemon and
its 569 source dependencies. The nine wired adverse probes have no installed
singleton execution witness yet. Six additional adverse branches, complete
independent clause reviews and factory acceptance remain unfinished. The
separate ordinary package build uses the preceding frozen source cohort.

The singleton's pre-realization plan additionally declares two valid requests
with insufficient process and descriptor budgets. It regenerates the exact
selected plan before execution while preserving the baseline probe population.
Strict all-target checks pass for all three affected crates, and retained
compiler metadata and dependency files bind the three changed source roles.
These are compiled probe definitions; their actual native collection and
memory or journal exhaustion remain unexecuted. They confer no full adverse
case or clause acceptance.

## Selected DMTCP writer package

The source-built `dmtcp-selected-writer-park` package passes its normal
application, checkpoint and two restore checks. Independent review verifies
the installed binary/source tuple, all 77 declared installed artifacts and
27 native source roles. The package retains the matching complete source and
original license notices. These checks establish ordinary package behavior;
the retained client receipts do not establish complete guest reclamation.

A fresh build of the complete current repository directory, including its
generic license inventory, passes the application, checkpoint and two fresh
restore checks. The matching source output independently preserves the upstream
archive, all ten patches, recipe, continuation fixture and current license
inventory. The earlier sparse-directory package result remains historical.

The subsequent exec-custody patch preserves the original selected writer's
complete log, control and account state across exec before assertion/runtime
initialization. A bounded descriptor census refuses inherited high descriptors
even when the process later lowers its descriptor limit. Its ordinary package
passes the original application, checkpoint and two fresh-restore comparisons;
a separate source-built check passes eight control groups. The matching source
retains all 542 prior files with exactly 12 modified and four added native files,
all 11 patches, the recipe, control source and additive license inventory.
Independent review reads back the installed binary and corresponding-source
artifacts. These results exclude the later source-custody patch and do not
establish semantic issuance, complete gem5 restoration or node readiness.

The source-custody successor retains the original coordinator's complete log,
control/account banks, restart script and final-request acknowledgement in a
versioned capsule before parking. Its ordinary package passes the unchanged
application, checkpoint and two fresh-restore comparisons; a separate check
passes five capsule/account control groups. The matching source preserves all
546 preceding files with exactly two modified and three added native files,
the complete patch sequence, control source and additive LGPL inventory.
Independent review verifies the installed binary/source tuple. This package
excludes the subsequent map-envelope work and does not authorize native
issuance or operational whole-node restore adoption.

The host archive importer verifies complete original writer histories, final
debits, control delivery and terminal-park framing against retained typed
dependencies before consulting the installed source verifier. The default
verifier refuses unsupported source qualification. Parsing historical data
creates no live native takeover permission. All 21 focused parser controls
passed; the five affected delivery controls passed again after integration
corrections. Core unit-target compilation and strict all-target core checks
also pass.

Selected native terminal parking, authenticated final-account issuance and
operational restore adoption remain unqualified. Configured native compilation
and eight inert descriptor controls have separate evidence; they do not execute
the real worker, kernel wait or source-issued takeover. The selected early
restore gate still refuses. This package result grants no common Ready,
full-system Linux, x86/AArch64 device parity or source-gone full-state
qualification. Those require the complete owning runtime, original transport,
conservation account and independently qualified fresh continuations.

## Native QEMU constructor preparation

The signed native source revision `23f599f17f57998b17f560eb4d8e9644acbead10`
retains 85 changed source roles and 12 new files with matching license inventory,
patch and source bundle. Original launch/control custody precedes effects;
constructor QOM, reset, firmware, IRQ, endpoint and runtime allocations retain
finite original histories. External nonzero-quantum SIM work publishes its
original wake before the host-selected CPU-exit store. Ordinary construction and
explicit RR work keep their existing branches.

Forty-eight complete translation units compile with the AOS production source
configuration and warnings treated as errors. Component controls retain their
explicitly modeled external authority scopes. The independent signed
reconstruction verifies the complete tree, source delta, sole upstream base,
DCO, license additions and matching artifact hashes. These are source preparation
checks; the selected guest and native readiness gates remain closed.

Complete RAMBlock and firmware aliases, lazy ACPI storage and callbacks, QOM
property retirement, remaining worker/traffic backing, device start/stop,
installed-provider execution and exact restoration remain required. ABI and
license boundary gates and the matching full package are not yet qualified.
The firmware audit also finds that the existing package installs 55 upstream
blobs without compiling them; complete source-built firmware providers and their
source/license closure remain part of package qualification.

The signed successor `4b403bd3bb67ea2471b8ca25990a34af05640496`
retains original RAM lifetimes, firmware metadata allocation credit, QOM property
retirement and authenticated callback entry. Its 19 changed source roles include
five new GPL-compatible files. Eleven complete configured translation units pass
strict compilation; component controls preserve their explicitly modeled peers.
Independent reconstruction checks the signed tree, DCO, license inventory and
matching patch/source bundle. Complete ROM reset copying, physical backing,
installed callback execution and readiness remain unqualified.

The coherent stopped-initialization successor retains 62 native source changes
and 32 newly licensed GPL files against that signed source. It combines complete
cold KVM construction dependencies, original argv selection, stopped RR callback
draining, module-bound after-return observation and mandatory fresh native
context recapture. ROM joins preserve original callback cuts, physical writes
and BIOS section correlation. Fixed caller-owned checksum state preserves exact
whole-codec digests without a temporary checksum allocation.

Fresh clean AOS configuration and complete x86_64/AArch64 compilation and linking
pass. Independent readback checks 2,133 compiled objects, both linked executables,
all 62 source preimages/postimages and the 32-file license inventory. Production
warning flags are retained; this result makes no new global strict-warning
claim. Full compilation exposed and corrected four dropped existing QAPI
definitions and an architecture-specific reader dependency. Historical failed
runs and component controls retain their original scopes. The matching signed
native revision is `87c118c8ed955952fab3e4283b29c4662899d7d4`, with a reconstructible
patch, source bundle and descriptor. Actual installed plugin participation,
complete physical state ownership, package and boundary gates, Linux/device
behavior and exact fresh restoration remain required. SourceReady and guest
entry remain closed.

The additive `qemu-firmware-x86` provider builds three BIOS images, nine VGA ROMs
and four option ROMs from the original QEMU source archive. Its actual package
and corresponding-source build passes in 32.47 seconds. Independent readback
checks all 16 installed products against retained compiler/linker products and
1,952 retained source members. The package retains the source archive, interpreter
edits, configurations, build products, recipe and licenses; its binary output
references the matching source output. It has not yet been integrated into
QEMU's firmware installation. The remaining 39 blob inputs and 12 EDK2 images,
guest boot and complete firmware/device qualification remain required.

The additive qboot provider uses raw AOS GCC and binutils with an explicit
freestanding static link. The source component compiles all 15 objects and
produces the original 65,536-byte i386 ROM. Product validation rejects dynamic or
interpreted ELF images and incomplete object/dependency inventories. An initial
component link exposed upstream linker-probe misclassification and produced an
oversized dynamic image; explicit supported linker flags correct it. The final
recipe passes Nix parsing and formatting, and its component products pass
readback. Independent review reconstructs every allocated ELF section at its
original load address and reproduces the complete raw image, including zero
gaps. The ordinary hermetic binary and corresponding-source build subsequently
passes in 9.03 seconds. Installed-byte and complete-output audits verify all
39 original sources, 19 compiler/link products, both full NARs and the retained
source reference. All 25 prerequisite NARs, references and actual derivers remain
unchanged. QEMU installation, guest behavior and the complete firmware roster
remain unqualified.

The additive iPXE provider retains the original eight PCI mappings and builds
both BIOS and combined BIOS/x86-64 EFI images. Its recipe uses raw AOS GCC for
freestanding firmware and the AOS compiler wrapper for hosted compression and
the bundled EDK2 EfiRom tool. The matching source output retains the complete
upstream archive, both source trees, configurations, compiler products,
interpreter edits and licenses. Product validation checks PCI identities,
image-chain extents, terminal indicators and legacy checksums. Source review,
Python parsing and Nix formatting pass; metadata evaluation, actual compilation,
installed-product auditing, QEMU integration and guest behavior remain required.
Sixteen proposed products cover the fourteen existing iPXE blobs and preserve
the complete original eight-target BIOS set.

The additive GLib variant supplies a native caller-owned GSource storage query
and constructor. It checks the exact extent, alignment, overflow and callback
table overlap before touching storage. Final unref runs the original finalizer
and retains caller backing; ordinary sources keep their original allocator path.
The variant preserves every existing GLib phase and feature and co-retains its
patch, recipe and actual-library control source. Source and formatting review
pass. Full library construction, guard-page and finalization controls, installed
source auditing and native Aio caller qualification remain unexecuted. The API
itself grants no process, credit or dispatch authority and does not establish
complete GLib context, poll, wakeup or thread backing ownership.

An actual iPXE metadata evaluation exposed a missing package argument: the
recipe requested `make`, while the AOS package catalog exposes `gnumake`.
The corrected recipe uses `gnumake` consistently in its formal dependency,
build dependency list and three command interpolations. Source syntax and
format checks pass. The earlier successful metadata evaluation explicitly
injected `make = gnumake` into the preceding recipe; its output identities
remain separate from this correction. Package compilation remains pending.

## Selected plugin preparation and process fencing

The selected plugin retains one original Unix socket, setup descriptor journal,
input and compute histories, finite readiness exchange storage and callback
userdata before native operations. Setup acknowledgement returns to machine
construction in Preparing; it does not wait for ordinary RUN or publish native
readiness. Native effect callbacks remain unavailable. A birth-PID fence exits
inherited children before TLS, userdata, logging or native access.

The final source cohort passes all 792 plugin unit controls in 15.62 seconds,
including real fork containment while the parent retains a TLS borrow and the
child receives invalid userdata. Ordinary installation controls pass. Strict
all-target Clippy passes on the recorded predecessor; the final four indentation
lines are separately proven to preserve source tokens. Native loader, claim,
authentication and registration peers remain explicitly modeled in these tests.

Actual native SDK execution, SourceHOLD/adoption, service and output collection,
consumed readiness acknowledgement, complete package and ABI/license boundary
qualification remain required. Literal native tracing also confirms that loader
and RR callbacks have different threads; constructor TLS cannot supply shared
callback participation. That ownership successor must preserve compiler-checked
thread safety and authentic native context before readiness is enabled.

The shared-custody successor retains the original socket, mapping setup and
journals in one compiler-checked `Arc`; constructor cursors remain on the loader
thread. A process-private native origin getter authenticates family-one callback
participation before guarded Rust access. Native pointer identities are compared
inside the GPL process and never enter a public protocol. Unauthenticated,
changed-registration and closed effect callbacks set only an atomic failure
flag. Constructor cleanup separately requires the original process and loader
thread.

All 794 plugin controls and strict all-target Clippy pass on the frozen successor.
A real Rust worker reaches the shared owner while loader TLS remains borrowed;
invalid-origin controls hold the actual mapping, compute and input-TLS guards and
preserve their state. Native dispatch and authentication peers remain modeled.
These checks do not execute the actual installed RR callback path or qualify
HOLD/adoption, native effects, readiness, package or boundary gates.

The original preallocated Ready cursor now belongs to that same shared owner
behind a mutex. A pointer-free, process-private 80-byte observation returns the
actual initialization mask, failure flag and setup digest after recapturing the
literal native origin. Invalid origin or userdata returns zero correlations
without entering mapping, journal, Ready or input guards. The affected installer
control and strict all-target Clippy pass on a fresh executable; 793 other unit
controls were filtered rather than rerun. Native peers remain modeled. Actual
paired stopped-RR participation and readiness require separate qualification.

## Original host scheduler and exact input collection

The common runtime retains one original scheduler allocation before Arm. Lazy
initialization and restoration install into that allocation; its host owner
observes the same queues, input commitments and credits. Private authority,
process, thread and world checks precede borrows. Containment and retirement
revoke external access while preserving the original retained state.

A separate exact-input collection route preserves time, phase and microstep.
Native staging, acknowledgement and commitment precede grants, including empty
input cuts. Legacy exact-input and quantized admission branches remain intact.
Daemon callers release scheduler borrows before subsequent runtime operations.
Snapshot preflight counts borrowed state against its byte limit before copying.

The final component source passes strict all-target, all-feature Clippy and 43
focused controls. A separate preceding executable passes 324 scheduler, runtime
and restoration controls; those executions retain their original source scope.
Thirty additional terminal and condition/debug controls pass on the retained
final scheduler executable. Positive runtime condition-stop/resume integration
has not been executed by that unit-test cohort.
The daemon caller cohort passes all-target, all-feature typing in its recorded
source composition. Its original compiler logs and source bodies are retained;
the historical daemon dependency files were overwritten by later checks and
provide no retained readback evidence. These checks do not qualify the complete
current source or actual connected native execution.

Host capture remains unsupported in this preparation profile. Full original
host continuation, fresh restoration, native peer capture and the connected
world's installed-provider execution remain required.

The exact-world provider now retains three native participants and the genuine
host scheduler in one original preparation capsule. The existing three-peer
provider implementation is byte-for-byte unchanged. Exact publication lineage
requires an additional native source validator; unsupported adapters refuse it.
Its provenance sidecar derives only from authenticated original terminal rows,
with complete aggregate byte credit checked before copying. Ordinary staging
still refuses lineage without provenance, and quantized lineage retains its
original window and empty-ancestry requirements.

Thirty-seven component controls pass: five exact-lineage controls with modeled
native peers, 29 legacy lineage controls, and three actual host-source factory
and retirement controls. Strict all-target, all-feature checks pass. The retained
executable and dependency files bind all 14 changed source paths. Production
Source2/4 codecs and complete connected native execution require separate
qualification; this stage confers no native readiness or capture guarantee.

Continuation edition two reads the actual attached host scheduler and complete
runtime ledger through an opaque observation. Its portable record retains
Runtime7 input associations, original bodies, scheduler queues and credits.
Restoration requires the same fresh runtime, attached host source and opaque
native restoration context. It prepares and installs into the original scheduler
slot without replaying Begin, Stage, Poll or ACK. A separate exact-ancestry route
requires every native participant's additional validator; the legacy route
continues to reject nonempty parent ancestry.

The 11-file component passes 21 distinct controls on its final executable:
17 restoration controls, including four new exact cases, and four portable
codec controls. Strict all-feature, all-target Clippy and formatting pass.
The tests use actual core runtime and restoration ledgers with modeled native
participants. A subsequent real four-owner run produces the genuine host
continuation from its attached runtime before the first grant. Independent
review verifies the complete runtime, scheduler, activation and source bindings
on that empty-ledger cut. The overall run still fails its first grant; this
producer witness does not establish nonempty capture or fresh native journal
installation. Source1 capture and unsupported native restoration callbacks
retain their existing refusals.

### Original host continuation ticket and scheduler installation seal

The distinct host continuation factory retains an opaque, nonserializable
ticket produced by the actual attached runtime. Fresh restoration consumes
that original ticket and checks its process/thread birth, complete compatible
selection, domains and Runtime7 record. A private installation seal binds the
same original scheduler allocation to its source record, scheduling identity
and target activation. An equally initialized scheduler cannot substitute for
that sealed allocation. Both scheduler and seal cells are reserved before
installation, so a busy cell cannot leave partially installed state.

Independent review verifies all 9,334 frozen source bodies, eight sparse current
preimages, the fresh test executable and its dependency file. Twenty-six
component controls pass: two factory guards, four original-slot guards, three
preserved source-one guards and 17 restoration regressions. Strict all-target,
all-feature checks pass. Native readiness and publication are modeled in the
slot controls; the new host validation/admission/installation callbacks are
compiled but have no operational whole-world restoration witness. The factory
still enforces CaptureNone and Unsupported. Native capture, archive edition
three, joint journal installation and genuine fresh restoration remain required.

## KVM constructor descriptor

The permissive protocol now decodes a distinct bounded KVM descriptor before
accelerator construction. Its version and domain separate it from SIM Launch2.
It validates complete asset and argument geometry, reserved fields, requested
clock policy, capability shapes, individual and aggregate output limits, and
checked retained-byte totals. Both native and provider history limits must
cover the complete selected output capacity, readiness traffic and descriptor.

All 225 protocol controls pass, with one existing ignored test, and strict
all-target Clippy passes. Five constructor controls include truncation,
changed backend/domain, aggregate zero and overflow, insufficient history
credit, malformed arguments and image extents. Source, executable, dependency
files and actual consumed module bodies were independently checked. The small
binary fixture tests framing; its assets and abbreviated arguments represent
no actual launch. Native constructor issuance, kernel and clock enforcement,
physical quantum stop, output closure and readiness remain required.

### Complete source-guarded Q35 kernel variant

The selected Q35 constructor kernel applies the complete fourteen-patch chain
to the pinned Linux archive. Its patch phase checks all 152 native roles before
and after each stage and refuses fuzz, offsets, changed patch bytes and changed
source bodies. A separate source-only check extracts the archive directly,
without requiring an ordinary kernel build. The ordinary kernel configuration,
features and output layout remain intact.

Independent review checks the complete inventory continuity, current preimages,
original source bodies and license notices, including 19 added GPL kernel roles.
The actual source-guard positive case and three corruption/refusal cases pass;
Nix source formatting passes. Prior configured translation units and modeled
controls retain their original component scopes. This stage has no complete
kernel build/link, active clock, physical stop/output or guest execution witness.
Capability 43 and selected RUN remain unavailable. The source-only check output
is a verification report; complete corresponding-source distribution remains
a separate requirement before publishing the patched kernel.

## Firmware, RAM and ACPI construction lineage

The canonical QEMU source revision `76a9f7c3d9` adds 24 reviewed source changes,
including three explicitly licensed GPL files. It retains original firmware
callback contexts and payloads in finite source-owned storage, binds five RAM
banks and their source-advertised maxima, and preserves the ordinary ACPI
builders while retaining their initial storage and ROM memory-region lineage.
The patch, signed source bundle, descriptor and license inventory agree on the
same complete source tree.

Independent review verifies the 24 source postimages and their original
preimages. Fresh compilation produced 2,133 object files and linked both x86_64
and AArch64 emulators. Review also found that the AOS-built Ninja dispatcher
invoked `/bin/sh` without retained AOS shell provenance. These outputs provide
compiler and linker feedback; they do not qualify hermetic command dispatch.
Direct replay through AOS Bash and ordinary package qualification remain open.
Runtime ACPI resize, complete source seals, guest execution and readiness remain
separate requirements. No ABI or license-boundary gate result is inferred from
this source stage.

## Mandatory gem5 diagnostic check packaging

The full ALL gem5 foundation retains its existing platform, terminal, causal
and closed-block checks. Five native ownership diagnostics now form a separate
mandatory check derivation, directly required by the Crucible suite. This keeps
the complete emulator build available for diagnosis if a diagnostic assertion
fails. The check binds actual process statuses and logs to the installed ELF,
complete matching source, patches, guest and build recipes.

Independent source review verifies all nine changed or added package inputs.
The original native ALL compilation and linking succeeded, but its combined
package check failed. The successor fixes the Python digest boundary by passing
integer sequences with the same bytes, as required by the native caster. The
split package has not yet passed ordinary evaluation or realization. Diagnostic
ownership checks confer no native issuance, restoration or readiness authority;
those remain production implementation and qualification requirements.

## Explicit source-built Ninja command shell

Ninja now executes commands through its compile-time AOS Bash dependency,
with `sh` argument semantics, instead of an ambient `/bin/sh`. The source change
verifies exact upstream and patched launcher bodies, preserves existing
qualification probes, and co-retains the complete patched source, original
archive, licenses, recipe, patch and compiler inputs. Actual source-built Ninja
pipe and console controls verify the executing shell through `/proc` despite a
bogus `SHELL`, and preserve command exit status 33. The component build and the
unchanged original probes pass; ordinary package realization remains separate.
The first ordinary build exposed invalid tar option syntax during unpack. The
corrected command extracts all 185 original files and verifies the original
launcher; the failed build remains recorded without package success credit.

A separate complete QEMU replay executes all 2,479 recorded build commands
through pinned AOS Bash. Independent review verifies the command records,
2,133 object bodies and both linked emulator targets. The original Ninja build
remains historically unqualified for shell dispatch. This replay qualifies
configured compilation and linking, while ordinary installed packages, runtime
behavior, readiness and ABI/license gates still require their own checks.

## Same-mapping stopped callback preparation

The shared mapping owner lends its unique ordinary mapping for callback
construction after pre-reserved retention, without holding a backing selection
lock across native setters or HOLD. Ordinary per-method gates remain active;
busy ownership, intent, failure and changed generation prevent publication.
A post-callback raw process check prevents a forked child from returning copied
results or invoking inherited result, guard or fence destructors.

Four original component controls and an isolated parent-lock-held fork fixture
pass on their recorded predecessor. The successor adds a passing real
in-callback fork control: the child leaves copied destructors untouched, while
the parent drops its result once and reacquires its original mapping. The
successor also passes strict all-target/all-feature shared-memory checks.
These helpers issue no native execution, capture, restoration or readiness
authority. Current complete application compilation and ABI/license gates
remain required with the final integrated source.

## Original stopped RR preparation source

Signed QEMU source `2d578074117056de32caecc9c72cf2fd21b1a955` joins
the original stopped-RR callback preparation, its literal initialization caller,
source-built builtin ROM identities and non-system tool stubs. Its patch, bundle,
descriptor and license inventory match all 21 changed source roles, including
the two new GPL files. A fresh configuration and 2,482 direct AOS Bash command
dispatches compile both CPU targets and qemu-img; nine changed complete source
units pass with warnings treated as errors, and three actual qcow2 tool checks
pass. Independent review verifies all source, command, object and linked-output
pins. These compiler records do not establish original process-group cleanup
custody. The installed plugin pair, native HOLD, complete source seals, guest
release, capture and restoration remain separate unfinished requirements.

The plugin caller retains a one-shot RR-local endpoint engine constructed from
the same original mapping, ending all Rust mapping borrows before native bind
and five pointer-exact setters. A fresh joined build consumes the committed
mutable-loan implementation; strict all-target checks and two affected controls
pass. Native getter, permit and registration peers are modeled in these Rust
controls. Endpoint callbacks refuse service until actual native dispatch and
staged membership are installed. This qualifies construction mechanics, not
the real installed QEMU/plugin pair or execution.

The corrected ordinary Ninja package and matching complete source build pass
in 24.40 seconds. Installed audits verify all 185 original and patched files,
the sole launcher content change, exact source-built Bash argument, normal
umask permission reduction, executable bits, NARs, references and actual
deriver. This resolves the command-shell package prerequisite.

A manual four-CPU diagnostic guest attempt fails before launching inner QEMU:
the production API rejects its staging paths outside the AOS store. The outer
guest was reaped with no remaining process group. The next attempt requires
genuine realized package paths and their runtime closures; this failure
supplies no evidence about the outstanding timer split or ABI conformance.

The patched Linux QEMU recipe now retains the source-built x86 firmware
provider and its corresponding source in a distinct selected-profile data
directory. Installation verifies all 16 products and the two native builtin
pins; the ordinary firmware directory and boot arguments are unchanged.
Actual installer/readback and changed-builtin refusal controls pass, with
independent source review. Its native resolver and ordinary package realization
remain pending; this does not complete the other firmware families.

## Mutable stopped-preparation loan across fork

The ordinary preparation helper now registers its mutable loan before invoking
construction callbacks. A forked child refuses mapping replacement while that
loan is live, before reading inherited mapping headers or changing the mapping.
The parent removes its marker and can borrow the original owner again. A real
in-callback fork control and its isolated wrapper pass; strict all-target and
all-feature checks pass for the shared-memory crate. This extends the earlier
preparation helper checks and grants no native execution or capture authority.

The construction callback now receives `OrdinaryPreparationView`, which
provides gated ring-pair construction and read-only identity instead of mutable
ownership of the entire mapped resource. Safe resource replacement and nested
loan swapping fail to compile. Six controls and three isolated fork fixtures
pass; the plugin caller is compiled and checked against this exact view. The
joined current-source strict checks, fresh ELF and two affected plugin controls
pass. No generic result-leak retention mechanism is needed.

## Complete workspace vendor staging hash

The workspace dependency hash now matches the exact current Cargo lockfile.
All 639 original source archives were checked against its checksums, and a
fresh complete NAR read reproduces the observed staging hash from the failed
collector build. The lockfile and staging helper are unchanged. This corrects
the stale fixed-output hash for ordinary Rust package and application checks;
it does not reclassify that failed build or establish package acceptance.
Future offline builds still require explicit local source admission, since
Nix's offline flag does not isolate fixed-output builders from networking.

## Singleton original conflict custody

The singleton collector reserves its conflict archive before native child
construction and transfers it only to the same authenticated live controller.
Each changed-body send checks the original journal and provider-only custody.
A completed refusal requires NotStarted, no retry and empty extension layers;
partial or ambiguous exchanges retain the original attempt. Private history
export borrows the complete contiguous archive without changing it. Seven
focused SDK controls, four actual source-built provider controls and strict
all-target checks pass. Independent review verifies all 18 changed source
roles and retained evidence. The installed singleton collector, remaining
adverse cases and complete 382-obligation acceptance are still unfinished.

## Original ACPI runtime update journal

The signed canonical QEMU source now retains each original ACPI producer offer
through a nonrenewing native RAM update journal. Resize, firmware directory
length changes, copying and dirty publication validate the original backing,
callback context and source generation before effects. Completed publication
is exposed through a read-only source phase. Selected builtin ROMs resolve
from the distinct source-built firmware directory; ordinary lookup remains
unchanged. No new QEMU files are introduced by this step.

A fresh ordinary-feature configuration regenerates Meson and QAPI, executes
2,482 recorded AOS Bash commands, and links both system emulators and
`qemu-img`. Four changed complete translation units pass with warnings treated
as errors. Three actual qcow2 controls and three coupled producer/update
controls pass; authority certificates in the latter controls are explicitly
modeled. Independent review verifies all ten changed source paths and retained
build dependencies. Installed plugin execution, complete physical/source
closure, HOLD, readiness, guest execution and boundary gates remain pending.

## Read-only RR preparation return observation

The GPL plugin now reads the native post-preparation tuple before accessing its
retained Rust owner or RR-local engine. It compares the original boxed engine,
constructor birth, callback identities and five completed setter families, then
returns an 88-byte pointer-free observation. Refusal fences callback admission
without taking mapping or journal guards. This process-private ABI does not
cross the Apache host protocol or authorize service, HOLD or readiness.

Strict all-target checks and a fresh unit build pass; three affected controls
cover the retained original SCM/mapping construction, refusal with ownership
guards held, and altered native context. Native getter peers in these controls
are modeled. Independent review verifies the three source paths and private
144/88-byte ABI. Selected installation now requires the native return getter
before claiming the setup descriptor; the preceding canonical native source
lacks it and correctly refuses. A matching native successor and genuine
installed pair qualification remain required.

## Original stopped-constructor diagnostic output

Selected guarded spawn can retain a preexisting nonblocking FIFO pair in the
same original launch capsule. Its capture buffer and pipe capacity are charged
before Child. Partial bytes, the original descriptors, initial socket journals
and setup custody remain retained through refusal. Successful natural child
reap and a final drain precede exact fixed-length output; this is diagnostic
correlation, not complete native retirement or execution authority.

Separate 128-byte INIT and 192-byte RR preparation profiles refuse truncation,
overflow and reinterpretation. Strict checks, fresh library/example test and
normal example builds, and eleven focused controls pass: nine actual FIFO or
capsule ownership controls and two portable parser controls. Independent review
verifies the ten source paths, compiler bindings and three executables. The
example's frozen source literals describe a precursor tuple; the RR hook is
absent and explicitly refuses. Current native/plugin realization, a distinct
source-bound RR operator, actual stopped-pair execution and readiness remain
unfinished.

## Same-build selected kernel corresponding source

The selected Q35 kernel recipe now guards nineteen patch stages across 154
native source roles and co-produces complete corresponding source in the same
build. It retains the original patched tree before generated signing inputs,
the complete AOS build/bootstrap recipes, actual configuration, generated
interfaces and Kbuild commands, then binds the installed image, modules and
ELF. Runtime, development and ELF outputs retain the source output. Ordinary
kernel configuration and features remain unchanged.

The optional source-output contract validates exactly four string phases before
derivation construction. Publication requires exactly one matching installed
configuration. Six representative collector controls pass, including changed
source/configuration, missing commands and missing or duplicate configurations;
the exact source guard and three corruption controls also pass. Independent
review verifies source continuity, per-file licenses and both functional and
formatting layers. Nix shape/equality controls, full Kbuild, installed output
and nested guest qualification remain pending. Active clock, RUN and readiness
remain unavailable.

## Canonical native preparation return getter

The signed QEMU source now supplies the five common native changes required by
the GPL return observer: a read-only 144-byte getter, same-loaded-module observer
binding and validation of the pointer-free 88-byte response after a fresh source
read. Setter, HOLD and guest permissions remain revoked during observation.
Both system targets and `qemu-img` link through 2,482 recorded AOS Bash commands;
four complete affected units, three helper controls and nine return-context
controls pass with modeled source authority peers. Independent review verifies
the ABI, exact five functional changes and consumed build dependencies.

The configured component tree includes inherited shebang rewrites, three mode
changes and nested export omissions; it is not a complete corresponding-source
inventory. Canonical reconstruction uses the complete signed Git tree and the
five exact posts, preserving the omitted files. The stale original build scope
label has a separate retained erratum. The 192-byte issuer/FIFO hook remains a
separate qualification change. Genuine normal/diagnostic packages and matching
plugins, full native seals, HOLD, readiness and guest/state qualification remain
unfinished.

## Connected packet execution and deferred publication

The connected packet source owns actual producer, relay and sink processes plus
an original host scheduler. Input Stage/ACK/Commit and separate Delivery,
Reaction and Publication positions retain their original native journals,
payloads and exact one-picosecond causal geometry. A deferred publication must
join the earlier acknowledged operation, retained pending event and completed
consumed retirement before the emitting grant. The scheduler keeps both exact
windows instead of moving the earlier evaluation into the later grant.

Review found that uncertain source validation could be skipped while searching
another prior operation. The correction immediately revokes the same original
scheduler on every non-None failure, retaining operations, queues and native
custody. Repeated receipt reads refuse before callbacks. Three adversarial
runtime controls and all 97 existing runtime controls pass on the corrected
ELF. Strict three-crate all-target/all-feature checks and 28 connected, source
and real Unix transport controls pass on their individually recorded revisions;
independent review verifies the 119-path composition and evidence scopes.

The frozen component workload completes 13 grants and 11 commits, including
two nonempty stages, in 53.75 seconds. A matched full-hash fallback completes
two grants before its unchanged 60-second deadline; finishing its in-flight
check and cleanup takes 122.38 seconds. This supports a completion advantage,
not a speedup ratio or Linux boot projection. Kernel read leases preserve the
complete initial executable hash, retained descriptor and process/namespace
checks; unavailable leases use full hashing and changed identities or broken
leases refuse permanently. Six original guard controls retain their separate
scope. Native5 capture, full vendor acceptance and final Linux performance
qualification remain unfinished.

## Precharged original protocol state

The provider SDK can reserve optional literal framing banks before Child,
retaining planned outgoing bytes and actual partial I/O progress without slot
refunds. The separate Hello journal can retain its actual framing as well.
Same-process/thread, original registration and issuer checks precede capture
and I/O. Borrowed protocol snapshots preserve correlations, complete literal
history and the exact pre-bound blob ledger, including chunks, pins, quarantine,
retirement and lifetime credits. Private owner results cannot be reconstructed
from decoded data and grant no native adoption or readiness.

Eleven focused controls pass, including real Unix partial writes, response and
Hello framing. Strict all-target/all-feature checks pass on the clean connected
packet composition; independent review verifies the original seventeen source
paths and actual compiled dependencies. Existing connected codec installation
and extension dispatch remain present in the reviewed joins. Full selected
codec/budget validation, unchanged model-generation proof, incoming native Hello,
complete native settlement and fresh adoption remain separate unfinished steps.

## Native-authenticated six-ring callback

The GPL callback authenticates the distinct 144-byte native mapping window and
original 88-byte status destination before borrowing the engine or mapping. Its
fixed journal retains the original tuple, six-ring snapshot and prepared status
before the effect. Every Rust guard ends before the second identical native
read and status publication. Failed source recapture retains the held mapping
and publishes no success. Mapping status edition 7 reserves worker and callback
fields as zero and supplies only the six-ring/exclusion observations.

Strict all-target checks and fresh unit compilation pass. Two actual C/Rust/Linux
controls exercise the frozen native request, dispatch, getter, status-pointer
check, read-slot consumption and revocation across the same Rust mapping helper.
Success observes six held headers; source loss after HOLD retains those headers
and emits no status. Broader constructor, QOM, BQL, clock and module certificates
are modeled. Seven prior Rust/Linux controls retain their separate revision.
Independent reviews verify the current seven source paths and actual compiled
inputs. The absent native capability remains closed and preparation with the
previous native source stays compatible. Installed-pair qualification, complete
worker/device HOLD, source readiness and current ABI/license gates remain pending.

## Native Hello and original Capture transport

The provider SDK retains literal incoming native Hello bytes and the same
outgoing response cursor, including failed partial writes. Selected nesting and
complete frame credit precede publication. A one-shot connected codec installer
checks negotiated binding and ownership before taking the original framing bank.
Administrative Capture uses the same controller with its capture owner and
without an execution owner; complete borrowed-frame credit precedes argument
decoding or journal effects.

Twenty-three focused controls pass, including actual Unix framing, partial
kernel prefixes, connected Stage/Commit, Capture blob/ACK history and oversized
precredit refusal. Strict all-target/all-feature checks and independent source,
ELF and dependency review pass on the recorded coherent SDK revision. Frozen
history copies and fresh registration mappings remain data and resources;
pending native Capture refuses adoption without private verified settlement.
The complete Native5 codec, native capture, fresh-world adoption, readiness and
current release gates remain unfinished.

## Selected checkpoint source owners

The selected DMTCP source retains original shared-area creation and thread
births in finite native banks. Its explicit exec-transfer edition 2 preserves
the complete shared-area journal; existing standalone codecs retain edition 1.
Seven native changes and their LGPL notices are co-retained with the component
controls and package recipe. The Crucible suite now explicitly requires the
separate source-owner check, including a real installed launcher/library exec
observation; retaining the check recipe alone would not run it.

Three source consumers compile and focused kernel, exec/remap, thread and
refusal controls pass on their recorded revisions. Independent review verifies
the native source, dependencies and corrected package-check extraction. Ordinary
toolkit application/checkpoint/two-restore checks remain mandatory. The selected
package and its complete production exec journal have not yet been realized or
executed. These changes supply no whole-process closure, native cut permit,
checkpoint issuer, restored-account adoption or readiness result.

## Bound stopped-RR diagnostic driver

The stopped-initialization example binds the signed native preparation-return
source and complete 192-byte diagnostic patch while preserving the separate
128-byte initialization profile. Its stdout marker now matches the selected
profile and JSON result. Current all-target strict checks and fresh normal
operator code generation pass. Historical FIFO/capsule/parser controls retain
their original source scope. Actual native diagnostic execution still requires
a genuinely realized matching native/plugin/source tuple; no installed pair,
HOLD, readiness, guest execution or capture result is claimed.

## Six prepared directed-ring mapping hold

The plugin constructor retains an opaque roster of its six original network,
block and 9P directed headers before constructing callback handles. The shared
mapping helper validates exact offsets, layout, backing identity and owner,
performs actual DONTFORK, and holds these six barriers once under the alias fence.
Failures keep the original mapping retained and prevent retries or release.
Foreign-process checks precede inherited locks; the full nine-family adoption
path retains its separate admission requirements.

Seven mmap, barrier and fork controls pass on the recorded helper revision.
The coherent plugin join passes strict all-target/all-feature checks and three
constructor controls exercising original SCM, setup mapping and DONTFORK.
Native getter/setter peers in those constructor controls are modeled. Independent
review verifies the helper evidence and the compiled production dependencies.
The native HOLD call, worker closure, source epoch, complete capture, readiness,
installed package pair and ABI/license gates remain unfinished.

## Canonical native directed-ring mapping call

Signed QEMU source `3157f824133986b86b4386f09856583929b4fbaf` binds the
mapping request to the original parked RR preparation invocation. Machine
completion calls it immediately after successful stopped endpoint preparation.
The native side authenticates the exact preowned status pointer before reading
it, requires fresh source reads on entry and after callback return, and revokes
callback permission before interpreting the result.

Four complete affected translation units compile with warnings treated as
errors. Two actual C/Rust/Linux coupled controls on the matching GPL callback
cover successful six-ring HOLD and source loss after the effect; the latter
retains the held mappings and publishes no success. Broader authority
certificates in the native component controls are modeled. Neither these
controls nor the canonical reconstruction establish full physical closure,
worker or in-flight callback sealing, an installed pair, Ready or guest release.

The canonical patch and bundle preserve the complete signed ancestor tree and
change exactly eight existing files. Independent cumulative reconstruction from
the sole upstream base produces tree `0001dd9eddbddcd7e836e53e3cf09e02b5f586df`.
The license inventory is unchanged. Earlier complete emulator-link and package
metadata results retain their original source identities; they are not new
results for this source revision. Current ABI and license gates remain required.

## Current compiler and native package prerequisites

The corrected ordinary LLVM17 build completes in 976.15 seconds. Full output
and runtime-closure audits and nine installed compiler controls pass, including
X86 and AArch64 object generation. The earlier interrupted supervisor attempt
remains a failure. The corrected supervisor preserves the original child's
wait status while independently retiring descendants. Its six race and wait
ownership controls pass. Nine inherited LLVM utility scripts still contain
host interpreter shebangs; the installed compiler audit does not establish
complete package interpreter-policy qualification.

The current signed native source and its separate stopped-diagnostic variant
have matching QEMU, plugin and complete-source derivations. Actual evaluation
completes in 6.85 seconds; the 767-derivation graph query takes 0.34 seconds.
Original clients are reaped and the serialized private-store writer lock is
released. The current vendor fixed-output hash agrees with the admitted local
source NAR. Neither tuple has been realized. The earlier
ordinary LLVM18 build runs for 1,073.12 seconds before its disk monitor encounters
a permission error and interrupts the build. No compiler failure is reported.
All 3,179 observed process generations retire and the original host confirms
writer-lock release. A corrected exact realization request subsequently
succeeds in 22.62 seconds using a registered LLVM18 output, with no new compiler
dispatch. Independent full-NAR, eight runtime-reference and nine installed
compiler controls pass on that registered output. Nine inherited utility
interpreter shebangs remain an open policy gap. The failed attempt stays
retained; neither result qualifies the backend package tuples.

The current native build prerequisites have complete NAR, reference and actual
producer readbacks. The first bounded package attempt stops after 22.41 seconds
when its disk monitor sees multiple declared outputs appear during scanning.
PAM and pixman complete; firmware begins. There is no compiler failure. The
original client and observed descendants retire, measured root leases close,
and the existing serialized writer lock is released. The failure remains
retained. A later complete stable-parent scan counts 110.73 GiB and 2,442,465
entries in 63.86 seconds. Compilation-operator scan work/time bounds are revised
separately; scenario/source capture limits and native authority do not change.
The complete current native package still requires a successful realization.

The direct selected DMTCP source diagnostic configures, builds and installs
successfully in 4.13, 27.26 and 0.70 seconds. Its first startup fails before port
publication. Correcting caller-owned console permissions progresses to later
coordinator and application exit86 failures. A bounded exit-stack diagnostic
identifies a selected thread-owner binding that receives a virtualized thread
ID while its verifier compares the raw kernel ID. The subsequent correction
uses the kernel TID only for selected owner binding and preserves virtualized
thread/PID behavior. Fresh complete-source build/install and noninstrumented
selected cancellation/EOF controls pass; the ordinary unselected application
and coordinator both exit zero. Earlier failures remain recorded separately.
These diagnostics do not qualify the ordinary package, full production exec
journal, native checkpoint issuer or two fresh whole-process restorations.

## Source-selected DMTCP helper commands

DMTCP helper commands use explicit AOS-built Bash and coreutils paths. A private
libc dispatcher preserves encoded exits, signals, concurrent signal-disposition
ownership and pthread cancellation. The launcher uses its initialized shared
tmpdir for copied executables; command storage includes the complete configured
copy-tool prefix. Explicit AOS C++ runtime search avoids the observed mixed
static/shared forced-unwind failure without disabling hardening or cancellation.
The package retains the dispatcher, generated paths, LGPL notices and required
source-built controls in its corresponding-source output.

Fresh complete-source configuration, build and installation pass in 4.04,
27.00 and 0.91 seconds. Selected startup preserves its intentional cancellation
and channel-EOF statuses; ordinary and copied-executable application/coordinator
controls exit zero. The prefix-inclusive storage successor separately compiles
the actual utility unit and passes normalized command/cancellation controls.
The final recipe handles absent incoming linker flags; it has formatting and
source review evidence, not an ordinary package realization. Earlier unwind,
copy and tracing failures remain retained at their original revisions.

Independent review verifies all source, recipe, dependency and execution pins.
Generic helper cancellation retains libc system semantics and uses a numeric
child PID; it is not an exclusive native identity or no-effect certificate.
These results grant no whole-node cut, checkpoint issuer, restored adoption or
readiness. Ordinary package qualification and genuine two-branch native state
restoration remain required.

## Sealed Native5 source codec and complete copy admission

The source-five service and controller retain an immutable typed codec policy
with the same original frame bank. Installation validates the original unused
endpoint, route and negotiated features before consuming the bank. Protocol
snapshots include the complete private Handshake policy and phase. Full literal
history-copy geometry is checked before issuer binding and encoding; a baseline
reservation cannot silently omit that history. An origin-guarded getter exposes
actual retained storage capacities as accounting data, without granting capture
or restoration permission.

Thirty focused component and actual Unix controls, all 355 enabled provider
unit tests, and all-target, all-feature strict checks pass on the recorded
source. Thirteen unit tests remain explicitly ignored. Legacy schema installers
refuse replacement of an installed Native5 codec. A readonly check verifies the
same installed verifier and current registration without repeating immutable
policy hashing or allocation. The client fixture authenticates its expected
executable before starting its unchanged two-second I/O deadline; independent
peer authentication remains required. Earlier long socket-path and fixture-order
failures stay recorded separately. Independent review verifies all 45 changed
preimages, the full owned source roster and consumed local dependencies. The retained evidence covers local emitted artifacts;
complete transitive binary-closure qualification is not claimed. The current
service still uses a baseline snapshot reservation, so full Capture safely
refuses until a genuine complete-capacity consumer is joined. Actual native
child Capture, blob settlement, fresh installation, two independent world
restorations and Ready remain unfinished.

## Fresh controller codec correspondence

An original protocol snapshot retains its actual immutable Native5 codec owner
alongside the literal captured bytes. A genuinely installed unused fresh
controller compares durable participant/host grammar, descriptor and ownership
selections, configuration, extensions and negotiated bounds. The prepared
association retains both complete policies and rechecks the same controller,
connection registration and codec owners immediately before its consumer runs.
A same-data replacement connection refuses without changing either journal.

This SDK association installs no archived counters, content, frames or native
state. Its original check identifies the retained issuer, cut and codec; it
does not bind a particular snapshot body or ticket. The signed Source5 target
context must independently authenticate the exact captured bytes and live
semantic/native association before installation. That production association
and native pending-state adoption remain unimplemented and refuse safely.

An independent materialization of the current committed source plus only the
seven SDK changes passes 36 focused controls, all 356 enabled provider unit
tests and strict all-target/all-feature checks; 13 unit cases remain explicitly
ignored. Unix transport is actual, while fixture supervisor/authority peers
remain modeled. Independent review verifies the complete 9,506-file source,
changed dependencies, emitted test binary and original process retirement.
Held Capture/storage/refusal changes are absent from this cohort. Full
transitive binary-closure qualification, native capture, two fresh world
restorations and readiness are not inferred.

## Exact current workspace vendor staging

The fixed-output staging helper copies the workspace lockfile verbatim, so
workspace-only dependency changes also change its NAR hash. The current lock
preserves all 639 external registry package tuples and archive checksums. A new
staging bundle copies the exact current lock and original checksum-matched local
archives. Independent canonical NAR streaming verifies 101,856,224 bytes and
SHA256 `bb071893b36afcd4e47ba13e1fd2720a1689e1eb222a7f03011babc70b6e2f45`.
The workspace staging hash now follows these exact bytes. This source correction
performs no fetching, store admission or package qualification and does not
relabel the earlier staging output.

## Coherent native device-state guards

Signed QEMU source `d9037e32ec3648d1fc24a35049248190f4b22792` joins original
firmware publication, ROM file-event correlation, held RAM lifetime checks,
endpoint membership and ACPI state/memory-region identity. Endpoint checks
validate original membership before dereferencing native owners or callback
structures. Foreign processes refuse before inherited journal or logging
access. The six-ring mapping path is preserved; its shared header receives
only additive firmware declarations.

Fresh configuration, 175 generator commands and 14 exact complete translation
units with warnings treated as errors pass on one materialization. All 64
existing component controls pass on that same source: 14 firmware, 10 ROM,
20 RAM, 13 endpoint and seven ACPI cases. Authority certificates in these
controls remain explicitly modeled. Earlier fixture failures and the mistaken
root-block suffix context selection retain their original scope. No complete
emulator link, installed pair or native guest result is inferred.

Independent review verifies the complete source and compiled dependencies.
Canonical reconstruction preserves all 78,082 signed parent entries, changes
exactly 16 existing files and reproduces final tree
`d690ff95f9ca59c14ae0f7f39d54ddc7ca0d36fe` from the sole upstream base.
The license inventory is unchanged. Genuine AddressSpace/FlatView ownership,
complete physical closure, full firmware/ROM sealing, readiness and current
package/ABI/license qualification remain required.

## Original constructor memory storage and cleanup

Signed QEMU source `c993991088114ff183aeb5aab6127d51d367f838` preserves the
complete 78,082-entry ancestor and adds exactly four existing-file changes and
one GPL memory-storage fragment. Its corresponding license row is retained.
The final tree is `a546ce30544d964543701bc04c1d6bb3528e2fc4`; independent
canonical patch/bundle, sole-base and explicit AOS signature checks pass.

Selected constructor MemoryRegion, AddressSpace and FlatView bodies, names,
ranges and index generations allocate from the same finite native history
arena. Membership and retained spans are checked before reference access;
retired generations retain their original storage. Cleanup checks the exact
selected callback, restored original root, published view and full retained
name before any native cleanup. Unknown event-fd storage or counts refuse.
Ordinary memory paths retain their existing allocation and cleanup behavior.

Four complete translation units are bound to the final source. The final
memory unit compiles with warnings treated as errors; the other three retain
byte-identical consumed source/header dependencies. Ten actual cleanup controls
and two causal check-removal controls pass on the final corrected path. Earlier
12 storage controls and four method controls keep their historical source scope;
they are not relabeled as final-source executions. Native pthread and literal
reference/cleanup functions execute, while constructor/QOM/BQL/RCU scheduling
peers remain modeled. Initial incomplete retirement-method and cleanup-tuple
findings are preserved alongside their corrections.

Dispatch/subpage, QOM/listener/CPUAddressSpace and temporary-name storage, actual
RCU dispatch, nonempty event-fd producers and complete held graph equality remain
open. This source component grants no graph seal, BIOS writer, installed pair,
package, native guest or Ready qualification. The separately evaluated d903
package tuple retains its original source identity.

## Complete endpoint refusal and original prepared banks

Complete Native5 endpoint construction now returns an indivisible recovery
owner containing the original native actor, connection, policy, supervisor,
literal Hello and both independently prepared protocol snapshot banks. It
compares the exact immutable native storage tuple, negotiated limits and actual
connection-bank capacities before reservations or control input. Retry uses
those same owners; compatible replacement tuples and changed bank geometry
refuse without replacement allocation.

All preparation callbacks run with borrowed originals inside an unwind boundary.
A panic permanently poisons retry and retains its actual payload, whose destructor
may itself have effects. The completed-Hello service retains the refusal capsule,
Handshake and original deadline until its original supervisor reclaims the
process. Earlier partial service-birth failures require a separate ownership
correction; this stage does not cover them.

The clean qualification source is the committed `fa2bbaa27d` tree plus exactly
these 21 paths, preserving the previously committed codec correspondence tests.
Its source index is `78466aa88dfd7770ac65e1015e4cd1698e06dac03b7dd31ec20126f8a442eb03`.
The same retained provider executable passes 52 focused controls and all 373
enabled unit tests; 13 existing tests remain ignored. All-target, all-feature
checks with denied warnings pass, and independent review confirms the exact
source, executable, dependency bodies and process/resource retirement. The
handoff is `4cbf50e01b663458535a139669a51865de3ca5f6d44ede7b458cf43b75b923f8`;
independent review is
`158f4e1c3a531a3ed20e01487a868fcea97685eefb027bc5334e30940489ad76`.

These component results grant no complete allocator qualification, native
Capture, prefix settlement, fresh-world adoption or Ready permission.

## Original dispatch storage and section membership

Selected native dispatch/map bodies, node and section growth banks, and subpage
bodies now use the same finite constructor history arena. Retired generations
remain retained. Section insertion authenticates the original destination map,
building view and local MemoryRegion membership before growth, copy or native
reference effects. Published subpages retain their exact class, operations,
opaque pointer, destructor, base and map/view association. Cleanup distinguishes
attempted retirement from completed retirement.

Four complete production-configured translation units compile with warnings as
errors. Twenty-two literal storage, lifetime and membership controls and two
causal erasures pass; protected owner-read and allocation/reference counters
check refusal before effects. The earlier seventeen-control cohort retains its
original scope. Constructor/source/QOM/ref-owner/BQL/RCU/page certificates in
these controls remain modeled.

The matching signed native commit is
`b41b01f985f51107ffafa60e670d10608cdd8f8e`, with complete tree
`80a67c3dc92d48380b495cf4e727792f70a7d3bb`. Reconstruction preserves all
78,084 entries, adds exactly one GPL source fragment, changes only the four
reviewed native roles, and replays the complete cumulative patch against the
sole signed base. Patch, bundle, descriptor and license inventory agree;
independent canonical review is
`72038e0211eca4b31371e7e0246eba63a7231c953bc15e15ca7b134b452f5eec`.

QOM, listener, CPUAddressSpace and name storage, complete original graph/RCU
closure, ROM sealing and BIOS writer permission remain pending. This stage
grants no native Capture, Ready, installed-pair or package qualification.

A subsequent actual build of the earlier `d9037e32ec` package source reaches
QEMU compilation but fails linking qemu-io, qemu-nbd and qemu-storage-daemon:
the ordinary utility route lacks `crucible_whole_setup_source_current`. Its
supervisor separately retains a process-binding failure whose historical
post-binding observation was not recorded. Neither failure is a successful
package result. The operator's failed record remains unchanged; all observed
build generations are now terminal. A strong refusing non-system stub and
terminal-only operator reclamation are separate follow-up work.

## Refusing non-system source provider and ordinary utility linkage

The existing non-system constructor stub now supplies a strong
`crucible_whole_setup_source_current()` implementation returning false. This
repairs the missing symbol observed in the actual qemu-io, qemu-nbd and
qemu-storage-daemon links. Ordinary utility targets have no selected system
constructor source owner. Their existing stub archive route and the real system
provider remain unchanged; the correction supplies no native permission.

The corrected stub and unchanged endpoint-utility translation units compile
with warnings as errors against the exact signed dispatch source. A focused
ordinary utility/QOM-support link and protected-owner refusal control pass.
Substituting the original stub reproduces the missing source-current symbol.
Historical archive support is explicitly fixture-only; the seven original
control/compiler processes are reaped. This is not a full current utility or
ordinary package build.

The final signed native commit is
`5158d178ac2f2b98a984cc0cd4b6f713535c86de`, with complete tree
`8dd8f156013c0d2bafb8aad587b0cb0270c48164`. Independent canonical review verifies
all 78,084 entries, the sole existing-file delta, unchanged license inventory,
sole signed base, patch and bundle, descriptor and explicit AOS signing client.
Its receipt is
`0d77bc824bff38b03a087384b7f8376ef345a3bf4a22f605f12305fb91b49e0f`.
The earlier failed package remains failed on its original source; current full
package/source qualification, system constructor closure and native Ready
remain pending.

## Owning protocol birth and read-only current custody facts

Additive complete-source constructors retain the original socket, authority,
callback owners and captured protocol actor lease through framing refusal and
retry. Literal Hello binding retains its same journal, bank and socket when
validation refuses. Constructor unwind retains the original payload and poisons
retry. These helpers perform no transport or supervisor callbacks during their
borrowed validation; legacy constructors remain unchanged.

Current Native5 lifetime-journal and physical-bank getters read the same sealed
controller and original registration. The three bank getter receivers now borrow
immutably without changing their validation bodies. The actual Unix control
reads original capacities twice, then checks refusal after revocation. Numeric
facts alone provide no native capture or geometry permission; the source must
borrow the same actual controller during whole-group admission.

The source qualification combines committed `82a538937e` with exactly 13 paths;
its source index is
`4e12ec046362b454a028b8829d8f751ecf7622d9835cf477f7421bc5430560ec`.
The same retained executable passes 60 focused controls and all 381 enabled
provider unit tests, with 13 existing tests ignored. Strict all-target,
all-feature checks pass. Independent review verifies the complete source,
current preimages, executable/dependency bodies and original resource release:
`6e379f73d8f18821c86fbcd4d2b95ba137fe441bab603fbeda69c4b56c6d2f34`.

The owning deadline helper itself performs no reset and returns the same handle
on refusal. That legacy handle remains externally resettable; this stage does
not seal an immutable birth cut. The separate immutable-cut successor, actual
phased service consumer, complete factory geometry, Capture and fresh adoption
remain required. No whole partial-birth closure or Ready permission is claimed.

## Immutable native birth cut and origin-guarded containment

Complete native birth now has a separate immutable cut captured before effects.
Its Unix stream wrapper checks the original process/thread and unchanged,
unexpired cut before read, write, flush, cloning or explicit control-stream
transition. Resetting an external clone of the legacy mutable deadline cannot
renew that birth. Refusal remains sticky and retains the same socket and cut;
legacy resettable control-stream behavior remains unchanged.

Containment authenticates the original owner before shutdown, independently of
cut expiration. An actual different-thread owner control leaves both Unix
socket directions usable; the legitimate original owner still fences an
expired or reset cut to kernel EOF. This successor corrects the earlier
unguarded fence path, whose failed review remains retained. The control is not
an actual fork qualification.

The qualification source is committed `70b54fe3f8` plus only three client paths,
with index
`94c5bb470ebd0c2369eea02e1bfc799fdcd0b5ce2f8c050497b4fbe68b133398`.
Sixty-five focused controls, all 386 enabled provider unit tests and strict
all-target/all-feature checks pass; 13 existing unit tests remain ignored.
Independent review verifies exact source/preimages, executable and dependency
bodies, raw results and original resource retirement:
`035f91182b2bc3f372592b56e1be92804cba4d64c6abaa76dcb28f45febb4a19`.

Actual phased service consumption and pre-effect admission of the new structures
and Rc allocations remain required. A transport transition grants no semantic
birth, Capture, fresh adoption or Ready permission.

## Original QOM instance body and retirement storage

Selected QOM instance bodies, complete alignment padding and allocation metadata
now spend the same finite constructor arena before native initialization. The
existing private allocator registration carries the original read-only span
provider, preserving ordinary allocation/free paths and avoiding system-only
link dependencies in generic QOM.

Literal finalization binds the source scope, incarnation, class, extent and
retained free method. Allocation, publication, attempted finalization, completed
finalization and retained retirement remain distinct. Class and free-method
checks run again after callbacks; retired bodies and journal generations stay
retained without refund or reuse.

Four complete object, VL, ordinary-stub and endpoint-utility translation units
compile with warnings as errors on the coherent signed `5158d178ac` source.
VL literally includes the changed early setter fragment and private QOM header;
there is no separate early-fragment translation unit. The exact earlier
seventeen body/lifetime controls and two class/free erasures retain their
original component scope. Type/class/init/property/finalizer-scope/history/BQL
and reference-owner certificates remain modeled in those controls.

The canonical native commit is
`5be074f96081040b197d5a7a30c3e2991dd9be80`, complete tree
`5113709f340de95f07e881a3c42b2774747e73c8`. Independent review verifies all
78,085 entries, exactly five reviewed native roles and one new GPL fragment,
sole signed base, regenerated cumulative patch, bundle, descriptor and additive
license inventory. Its receipt is
`758eeabed4a8650e3b7faf624919a4abff7ddc431384d8b723901eec79bb0e5f`.

Pre-main type/class bootstrap, property/registry/interface/name storage,
CPUAddressSpace/listener storage and complete original graph/RCU closure remain
pending. No type/class prototype is included here. Instance storage grants no
BIOS writer, full seal, Capture, Ready, installed-pair or package qualification.

## Bounded historical frame decoding and exact body association

The source-private historical frame decoder uses a fixed byte cursor. It admits
the complete byte and descriptor banks before either allocation, preserving raw
bytes, capacities, request IDs and unrecycled incoming/outgoing counts. Malformed
numbers, escaped strings, incomplete I/O, inconsistent extents and trailing
values refuse without parser scratch allocation or recursive parsing. Decoded
data cannot install state or authenticate a capture source.

Fresh protocol mappings bind the exact captured body digest, length and original
physical deadline alongside the original actor, codec and cut. Another body from
the same actor refuses before installation.

The three-role Source60 cohort passes 71 focused controls, all 392 enabled SDK
units and strict all-target/all-feature checks; 13 units remain ignored. Review
receipt `1a71171cf9b6397efc7cc15c377f5cbed69291daeb526aed9bdeebcd6b971958`
verifies the retained source, executable and exact current preimages. The earlier
serde decoder remains blocked: malformed escaped strings could allocate scratch
before admission despite passing its existing controls.

Whole factory allocation accounting, complete SDK installation, semantic source
and target context, native settlement and capture/adoption permission remain
pending. These data banks and mappings grant no Ready or conformance acceptance.

## Settled correlation data and one-shot reconstruction

The source-private correlation tuple now carries an explicit version-six tag
and a persistent installation flag. Its standalone data decoder preserves both
sequence counters and request credit, while requiring settled empty maps. A
fresh data guard retains its new session/incarnation and receives the original
counters once; even an empty source consumes that installation. Repeat,
same-scope, mismatched-credit and unsupported-extension attempts leave it intact.

A borrowed cursor validates the whole grammar and identifier roster before
owning copies. Named admission covers the decoded object, both identifier
strings, extension bytes and exact vector/string capacities. Parsing allocates
no serde scratch or tree nodes; applying data compares the existing extension
roster without allocation. The CNP wire grammar remains unchanged.

The coherent four-role Source63 cohort passes 76 focused controls, all 397
enabled SDK units and strict all-target/all-feature checks; 13 units remain
ignored. Independent receipt
`8431f1a13657f42b57a68a573621cd1cc0f505634071cd29cb766e45157a2e81`
verifies the current source join and retained executable. Prior failed and
fixed-allowance-only cohorts retain their original scope.

The public standalone guard provides no access to a connection's private guard.
Complete SDK installation, lifetime request-ID custody, pending native
settlement, signed source/target context and whole factory allocation closure
remain pending. These mechanics grant no native capture or Ready permission.

## Native capture antecedent correspondence

An original provider can now compare its opaque pending native snapshot with the
same channel after transport correlations settle. Authentication checks the
original actor, registration, native codec owner and physical cut, then compares
the exact complete literal prefix, including bytes, request IDs, slots and bank
capacities. It returns borrowed numeric facts without allocation or callbacks.

These facts cannot establish successful Capture. A real Unix-channel control
receives an explicit `not_started` refusal, obtains the physical correspondence
facts and still refuses adoption. The source must separately authenticate the
successful terminal result, complete three-object/ACK suffix and signed source
and fresh-target context before issuing settlement or installation permission.

The five-role Source65 cohort passes 77 focused controls, all 398 enabled SDK
units and strict all-target/all-feature checks; 13 units remain ignored.
Independent receipt
`569fe563944fcc5d6b4e35bbd4ef0128bdc89e7c4dbc063008079e93238b16f6`
verifies exact current preimages and retained source/executable evidence. Its
original tested cohort remains distinct from the later current-source join.
No native Capture, constructor, fresh installation or Ready permission is added.

## Original sent-frame read loans

A prepared native exchange retains its original actor and literal bank before
publication. Its sent-frame accessor checks that the supplied connection still
owns both, then matches the complete outgoing header, canonical body and physical
progress. The returned view holds an immutable bank loan, so callers can inspect
the original envelope and bytes without copying or serializing them. Foreign
connections, absent frames and incomplete sends refuse.

Source67 passes 77 focused controls, all 398 enabled SDK units and strict
all-target/all-feature checks; 13 units remain ignored. Independent receipt
`7db92260178a5cedc09b1b9419116bfa031f5e2e641ae63c55616b4baf87b092`
verifies the five exact current preimages and retained source/executable evidence.
Its original tested cohort excludes three disclosed current documentation,
spacing and ledger differences; this is not a full current-source compilation.

The retained actor pair and serialized alias metadata still require whole-factory
accounting. Transport correspondence grants no successful Capture, durable ACK,
source settlement or fresh installation permission.

## Three-object capture frame capacity

The selected native-five storage validator now includes the separately
transferred control-state object. Its complete capture suffix reserves chunks
for snapshot, control and anchor, their three Begin/Finish pairs and the terminal
response. The former two-object count could admit a bank that necessarily ran
out of descriptors during capture.

Two boundary controls pass: the formerly admitted 23 slots and insufficient 25
slots refuse while the complete 26-slot case passes; the hard 4096-slot boundary
passes exactly and refuses one additional control chunk. Strict all-target and
all-feature checks pass in the retained 9573-file cohort. Independent receipt
`c03546a11edbd56f6ee27a6522fe4b6903860b29e9879a34f0d81f926ca2068a`
verifies the two current-source preimages, executable and dependency evidence.
Legacy editions two and four are unchanged.

This descriptor minimum excludes prior lifetime history. Frame-byte capacity,
window credit and the complete four-owner allocation peak remain separate
checks before any full capture admission or Arm permission.

## Original KVM resource policy and matching kernel source

The integrated source chain retains original KVM file identities and CPU
readout metadata before effects. QEMU accepts a separate sealed resource-policy
FD through its original argv, preserving the existing launch descriptor. The
kernel pre-VM quote binds its system file, Task, mm and module; incomplete native
coverage refuses selected CREATE_VM before reserving an FD. Caller ceilings do
not authorize creation. The current quote covers one of eleven required domains.

The separate PS kernel variant and source check preserve the ordinary kernel
and constructor variant. The initial ordered 27-stage source chain reconstructed
the complete 162-role descendant; the allocator integration below extends that
same chain to 33 stages and 169 roles. Matching source collection includes the upstream
archive, patched tree, AOS/bootstrap inputs, configuration and actual generated
Kbuild records when a kernel is built. Component source replay already passes;
full kernel/package execution remains pending.

Fourteen configured QEMU, utility and kernel translation units compile across
their retained cohorts. Fresh option generation and a complete VL compile add
twelve literal option, FD-role and late-dispatch controls. Location, Task, mm,
allocator and usercopy peers remain modeled where used. Independent CLI receipt
`4957df74313563a4bea0339ee4961cc1a99443ae650f799751a3154c9f103bd8`
preserves the earlier thirteen-role evidence scope.

The signed native revision is `d8104fe3cc0a518bbb35b2d3f6c3dfa1bc819734`.
Independent reconstruction receipt
`360e4ecc996eb671a9ab9203a2259f0143fb13d0c3300955b7f3a771bb8ab4d5`
verifies its sole upstream parent, all 78,085 preceding entries outside the exact
fourteen-file delta, seven additive GPL source rows, patch and source bundle.
The failed automatic-thread packing attempt is retained; the same signed tree
packs successfully with one worker.

Complete allocation coverage, backend-two RAM, active timers, worker stop and
output closure remain pending. This source integration grants no selected RUN,
Ready, positive live ioctl, package or ABI/license-gate qualification.

## Dormant collection capture-profile admission

Collection graph admission now uses an explicit, default-refusing Capture-profile
callback. The installed authority must authenticate the original preassociated
factory, native source custody and host preparation before graph creation. This
preconstruction step is separate from the active Runtime7 capture memory check.
It cannot be satisfied by decoded bounds or a fabricated initialized graph.

Ordinary Capture qualification is unchanged. The collection route reauthenticates
its plan before the callback, refuses without falling back to ordinary evidence
and checks the original final scope before sealing. Six controls cover default
refusal, dispatch, foreign claims, no fallback and revocation. All 102 admission
tests and strict all-target/all-feature checks pass in the retained Core cohort;
1246 other unit tests are filtered. Independent receipt
`d269646949a2ece35051569e582c01f3c758e2ff771e03154351dd53f9be75c0`
verifies the four exact current preimages and executable/dependency evidence.

The test authorities model their own dormant profiles. The production complete
factory association remains pending, so this hook grants no native Arm, active
Capture, fresh restoration, accepted class or Ready permission.

## Actual protocol reservation allocation facts

Snapshot reservations now expose the actual encoded buffer separately from their
independent literal byte and descriptor banks. The getter reads lengths,
capacities, selected ceilings and allocation totals without allocating,
serializing, invoking callbacks or performing I/O. Bound reservations verify
the original process and thread; unbound numeric facts establish no association.

Source74 passes 80 focused controls, all 401 enabled SDK units and strict
all-target/all-feature checks; 13 units remain ignored. This complete SDK cohort
also executes the three-object geometry correction. Its earlier control fixture
selected an impossible eight-MiB snapshot plus eight-MiB control transfer within
4096 descriptors; the test now selects four MiB of control storage. Production
limits and old refusal evidence are unchanged. Independent receipt
`c3b4e7becce724e843de79e32811f873f73ebd69b1b248af107d859802dd816c`
verifies the exact three current preimages and retained source/executable cohort.

These component facts exclude whole-factory namespace and allocator closure.
Native registration, physical cut, source association, terminal Capture,
settlement and installation remain separate requirements.

## Immutable policy validation and per-frame live checks

Original policy construction and one-shot installation validate complete immutable
connected and coordinator content. Per-frame verification now checks the live
registration, session, incarnation, features, extensions and negotiated limits
without hashing that immutable content again. Both live fences and complete
Input4 predicates remain. The privately owned policy fields have no decoder or
mutable accessor that can change them after publication.

Source84 passes 82 focused controls, all 403 enabled SDK units and strict
all-target/all-feature compilation; 13 units remain ignored. New hostile cases
exercise the NativePacket policy with the same revoked registration, foreign
identity, missing features, over-limit chunks and unsupported extensions.
Existing positive ControllerPacket coverage exercises its changed branch; new
hostile ControllerPacket execution is not claimed. Independent receipt
`f4a49837baf0269fe9f259f710021dd3cb3f2a144b86b0db188aaa0b2509fd0e`
verifies the five exact current source changes and retained executable cohort.

In the distinct historical Source80 transfer cohort, profiling measured 30.751 ms
of frame planning against approximately five seconds of repeated immutable
validation. With the duplicate checks removed, both transfer controls pass in
0.99 seconds under their unchanged two-second limits. These controls use modeled
activation and registration; their success is not native Capture qualification
or an overall VM performance result. Source80 is not relabeled as Source84.

## Original snapshot ownership through fallible checks

Snapshot finalization validates the borrowed original reservation before moving
its encoded and literal banks. Failure keeps both allocations in the same slot;
the successful move invokes no callback, allocation or fallible revalidation.
Controller and endpoint APIs can fill the caller's completed result slot before
the source performs its later checks. An occupied result slot refuses without
moving either owner. Finished snapshots retain the original selected maximum
and expose their actual encoded and independent literal allocation facts.

Source85 passes 83 focused controls, all 404 enabled SDK units and strict
all-target/all-feature compilation; 13 units remain ignored. Its additional
control verifies pointer, byte, capacity and literal-allocation preservation
through refusal and successful transfer, followed by repeat refusal. Independent
receipt `7ff727c4478e5d688acf5ec7e733a9b34678527df9b00d86ac0b7eb783387cf9`
verifies the exact three current preimages and retained executable cohort. The
qualification source differs from its committed parent only in those three
roles and the disclosed implementation ledger, which compilation does not use.

These changes retain custody rather than grant Capture or restoration rights.
Compact encoding, archive payload transfer, source settlement, full peak memory
admission and the installed native factory remain separate requirements.

## Original kernel allocator scope and currentness

The selected kernel source chain now appends six explicit allocator stages to
the original CPU, clock and timer composition. Original Task control-delivery
scope retains its source references and allocation journal; selected large,
bulk, direct-page and nolock-page routes refuse uncovered allocation. A separate
final correction checks failed/current source state before reading a nodemask.
Ordinary null-scope and interrupt routes retain their existing behavior.

The unchanged production source guard replays all 33 stages across the complete
169-role roster without fuzz or offsets. Six complete configured translation
units pass with 1366 retained dependency bodies checked against that current
roster. The initial and final configuration bodies remain separately identified:
recursive configuration preparation changed the initial snapshot before actual
compilation. Protected-memory controls reproduce the prior currentness gap and
verify its correction. Independent receipt
`d1b515fa7be4cc4b6d7e5346a40d457e467aadbd5194ae4bab0c920fb18af81c`
verifies all ten source/package preimages, ordered composition and these scopes.
The earlier defective stage remains inspectable before its explicit correction.
Two new GPL source roles are recorded in the matching kernel license inventory.

Coverage remains one of eleven domains. These control-delivery and refusal paths
do not complete VM creation, aggregate backing, retry/reclaim, per-CPU/vmalloc,
asynchronous lifetimes or physical retirement. Selected CREATE, RUN and Ready
remain refused. Full Kbuild, generated Task offsets, objtool, linking, module
loading and patched nested-guest execution remain required; no host kernel or
module was changed, and no runtime qualification follows from these objects.

## Compact protocol representation and original payload transfer

The SDK adds a separate compact byte representation and deterministic ClientContent
alias edges. First occurrences retain complete payloads; subsequent edges retain
the same original Rc group, while equal bytes in different allocations remain
distinct. Every edge retains references, actual capacities and lifetime fields.
The borrowed decoder plan validates complete grammar before the caller reserves
its original capacity, then fills that same empty buffer without reallocation.
Empty buffers with spare capacity remain distinct from unallocated empty data.

The immutable installed codec binds the selected encoding and separate native
before, native after and settled-host protocol bounds. Captures compare the role,
cut and exact reservation before binding or writing. The default array profile
retains its existing serialization. The complete service refuses compact launch
before reservations or listener creation until its selected mechanism is wired;
a decoded profile alone cannot activate it.

Source-issued snapshots can move their encoded Vec once with an opaque owner
retaining original codec, actor, cut and literal history. Digest correspondence
does not establish allocation identity: archive copies and growth must charge
their actual current capacities independently from immutable issuance facts.

Source87 passes all 422 enabled SDK units and strict all-target/all-feature
compilation; 13 units remain ignored. Independent receipt
`0e6c63dce5f12b4a2c1c1cbcfff29d9534b87aac583a575dcf3aeb2767b39b1e`
verifies the eighteen exact SDK changes, complete source and tested executable.
The qualification uses the previous committed parent; the separately committed
kernel-source extension does not enter these Rust compilation inputs.

This component does not complete the owning-state decoder or native factory.
At this checkpoint the codec-owned coordinator Bytes serializer allocated a
temporary base64 String and omitted its independent Vec capacity; the next
metadata integration below fixes those two fields. Other remaining
metadata capacities, serializer/decoder scratch, full 512-MiB admission, local
settlement and native installation remain explicit requirements.

## Borrowed compact coordinator metadata

Compact codec views now serialize the coordinator's complete reference, actual
independent Vec capacity and borrowed compact bytes. The installed codec remains
the original owner; this separate Vec is not deduplicated as a ClientContent Rc
alias. Payload association uses that same selected codec view. The contract
Bytes capacity getter observes existing storage without copying or changing its
old base64 wire encoding. Original array snapshots remain unchanged.

Source88 passes all 422 enabled provider units, five contract units and strict
all-target/all-feature compilation for both crates; 13 provider units remain
ignored. The coordinator control restores its full body into the original spare
capacity without reallocating. Independent receipt
`03f8f518a63285905ada24983c80ebbe16da2db6f5a64a9423f721f8ac5c7236`
verifies the seven functional changes and separate comments-only correction.
The qualification retains its earlier source; current differences in kernel
patches and the implementation ledger do not enter these compilation inputs.

This removes the coordinator's allocating Bytes serializer from compact views,
without proving allocation-free whole snapshots. Other metadata capacities,
complete owning-state decoding, all serializer/decoder overlap, the source-local
journal and full native Capture and restoration remain required.

## Original identifier allocation capacity

The shared Id type reports its owned String allocation capacity, including spare
storage, without copying or changing wire bytes. Memory admission can therefore
charge an original short identifier with a large backing allocation rather than
substituting its serialized length. The existing Bytes capacity API is unchanged.

The standalone Source101 control passes against a freshly compiled contract
test executable. Its fourteen consumed contract source bodies match the current
contract except this additive getter and test. Qualified handoff
`5fcfa9bc07dedd2c74d0c5c6380c6fa989b6c2c53f26f2c696b72e864ef18cb4`
retains the exact source, executable and actual spare-capacity/wire round trip.
The larger private Core accounting changes and native memory admission remain
separate; this observation API does not grant allocation or capture authority.

## Original-bank after-capture encoding admission

The provider can check complete after-capture encoding capacity before publishing
its prepared suffix. It authenticates the original endpoint, codec, blob ledger,
reserved after buffer and exact pending requests. The bound includes the current
complete encoding, the entire selected raw frame bank, both directions of frame
descriptors and counter growth. Checking capacity does not send frames or issue
a completed snapshot. Insufficient or foreign reservations retain all originals.

Source89 passes all 423 enabled provider units and strict all-target/all-feature
compilation, with 13 units ignored. The new prepared-suffix control verifies zero
publication and unchanged originals on success and refusal. Independent receipt
`fa34cd0a636393beb3b6eeff80014e1d6dde1cc3b3ac7125d766ca7a422e861f` verifies the six production/test roles and actual results.
The current module-header wrapping is separately reconciled; tested declarations
remain byte-identical, without promoting unconsumed kernel or ledger differences.
The shared identifier-capacity addition uses its separate Source101 cohort.

Five separately compiled frame-bank controls pass with production serialization
unchanged. Actual streaming emission at the 512-MiB raw limit fits both bounds:
numeric output is exactly 2,147,483,649 bytes; compact output is 716,352,219 bytes
under its 716,352,237-byte bound. All 8,192 possible frame descriptors, maximum
accepted request IDs, chunk/padding boundaries, empty spare storage and partial
progress also pass. Independent test receipt
`784cb74ea0e0bdbb0d65ac7ff1917a0cb533bae2bdbeda3a0f2e4b832973af34`
verifies the two test-only roles and their actual executable. Counting streams
creates no giant output fixture. These controls prove serializer widths, not
envelope validity, acknowledgements, ownership or simultaneous native memory.

The capture source must still prove its prospective raw sends and replies fit
the same banks and retain the codec/blob geometry through the suffix. This
capacity check does not establish acknowledgement, semantic settlement, full
memory admission, native Capture or fresh restoration.

## Owning compact content reconstruction

The complete borrowed content cursor validates grammar, references, limits,
credit, capacities and first-group alias edges before owning allocation. The
data decoder then creates one original-capacity Vec per first group and shares
the same Rc on alias edges. Equal bytes in independent groups remain distinct;
empty spare buffers, partial transfers and reserved credit survive. Complete
transfers and objects verify their content hashes. The decoder uses no complete
JSON tree or intermediate decoded byte copy.

Source90 passes all 438 enabled provider units, five contract units and strict
checks, with 13 provider units ignored. Independent receipt
`27c2b47f56c464c4c41bd4efbcb4a81f892b8d1ccd2a862ffda870d5ca078ac8`
verifies the four exact current roles and actual cursor/owning controls. The
identifier-capacity addition and frame-bank supplement retain separate scopes;
this earlier full-suite receipt does not include their later test additions.

This returns independently owned data, without installing a controller or
issuing native authority. Content edition7 omits metadata String capacities;
those capacities require a distinct edition for exact allocation-state restore.
The caller must still charge fixed cursor scratch, temporary row indices, Rc,
metadata and tree storage alongside byte groups. Full protocol reconstruction,
source-local settlement, physical memory and native fresh adoption remain open.

## Original retained protocol metadata observations

Protocol snapshot owners report actual retained String, Id, Bytes and Vec
capacities from their original authority and codec. The observer exhaustively
visits typed policy fields and uses checked arithmetic, finite node counts and
JSON depth. It performs no serialization, copying, callbacks or I/O. Tree
container, entry and layout terms are separate observations; repeated shared
backing is conservatively counted per view, rather than declared unique storage.

The coherent Source91 cohort passes all 446 enabled provider units, six contract
units and strict checks, with 13 provider units ignored. It includes the owning
decoder, identifier-capacity control and complete frame-bank boundary tests.
Independent receipt
`a51326925ad48947d9e96cd2c678729e822c060a627251ad16f87dc86f816120`
verifies nine exact roles, current source, matching executables and release.
The actual metadata payload control covers ControllerPacket; NativePacket is
compiled, without a new native execution claim.

Hidden tree nodes, control blocks, allocator alignment, native and thread memory
remain separate peak terms. These observations cannot grant whole-budget or
capture permission, and content edition7 still cannot reconstruct omitted
metadata capacities. Source settlement and full native restoration remain open.

## Original VM-root allocation and retirement source

The selected kernel chain adds one corrected original VM-root stage, preserving
all 33 prior patches and 169 source roles. The quote uses the vendor's actual
allocation request instead of sizeof(kvm). Constructor custody binds the
original file, Task, mm and generation, retains the native return before later
checks, and records cleanup without refunding physical credit.

Review rejected the first private candidate because constructor/free helpers
trusted a substituted owner field. The integrated successor derives the owner
from the retained live-root record before following candidate data or changing
the journal. Closing precedes native free, so a new root at the same address
cannot retire the earlier journal. A NULL return retains the constructor error.

Independent receipt
`f6178d587f42fc4cf8e9723b02e1341b82255abef66439489d592d46b2636281`
verifies the corrected 34-stage, 169-role source replay, complete configured
common TU and unchanged x86 cohort, 19 positive controls and ten source erasures.
The controls include full protected-context access and real address reuse; their
native allocation and continuation peers remain modeled. Five exact package
roles include the patch, catalogs and existing license/scope notice.

Coverage remains one of eleven domains, with no source continuation issuer and
the before-FD CREATE fence unchanged. This source stage does not qualify full
Kbuild, generated offsets, linking, guest execution, physical peak/retirement,
RUN or Ready. Existing rejected candidates retain their separate evidence.

## Core complete-capture accounting and native restoration tickets

The Core closure binds capture geometry to the same original runtime, owner
roster and per-node preflight rows. A private budget moves from the writer into
geometry without allowing a copied row or changed maximum to issue authority.
Incoming identifier capacities are charged before snapshot or source callbacks;
native keys require the same preflight key and the selected closed schema.

The model names current, retained and future storage terms. Independent review
found three omitted failure/lifetime terms; the integrated correction narrows
complete-edition file reads to authenticated extents, includes the overlapping
index read, charges retained registry keys/nodes, and counts cloned restoration
reference storage. Duplicate shared snapshots and growing writer-map projections
remain conservative overlaps. Legacy index1/2 reader policy is unchanged.

A nonserializable, noncloneable native restoration ticket retains the verified
historical source and one owner. One-shot issuance and later same-source/target
context checks preserve original custody. Historical data alone cannot install
or activate a fresh native process. Original attempts retain capture results,
settlements and persisted records through failure.

Independent receipt
`7133f1be6e7454ad8eaf43d36091d5750e1b0100ba83815c7897df7b735a536c`
verifies 51 production and five necessary test/fixture roles, matching actual104b
strict checks, fresh executable and three focused controls. The current SDK91,
kernel and ledger reconciliation is explicit; this earlier SDK89 cohort is not
retagged as current combined compilation. No raw build evidence is added to Git.

Both factor42 safeguards and the deferred-Unknown fence remain. Selected-loader
preparse admission, source-local settlement, full physical memory and genuine
factory/adopter implementation still gate complete capture and fresh worlds.
This Core API closure does not qualify native Capture, Ready or the full budget.

## Compact content-eight metadata preservation

The explicit content-eight wrapper preserves the unchanged content-seven byte
groups and alias grammar and adds original key/reference String capacities.
Borrowed framing and both complete capacity rosters are validated before owner
allocation. Restoration creates each String at its original capacity, refuses
allocator capacity differences and retains shared byte owners, distinct equal
buffers, empty spare capacity and partial transfer credit.

Independent receipt
`dbc83d19229ae4d0e8f88bf56cdae9958034c0a1cefb2389aadb4bba6c74125d`
verifies the four exact current preimages and matching Source94 compiler/test
roles. Strict checks, all 449 enabled provider units and six contract units pass;
13 provider units remain ignored. The actual cohort uses kernel34/SDK91; the
57 current Core105/ledger differences are disclosed without retagging compilation.
Earlier compiler/lint failures remain separate evidence.

Compilation monitoring covers the complete private source and target trees,
charging the greater apparent/allocated extent: 28,107,710,464 bytes under the
34,359,738,368-byte compilation ceiling. Older 16 GiB receipts sampled target
storage only. These compilation limits do not change the scenario's 512 MiB
budget. Tree/control-block/allocator layout and native physical storage remain
separately admitted; this data codec does not install state, select a whole
profile or qualify native Capture, factory adoption or Ready.

## Original vmalloc metadata and deferred cleanup lifecycle

The additive kernel stage retains the original vm_struct allocation lease and
generation before native metadata allocation. Deferred cleanup records the
actual work item and method before list publication; enqueue, accepted schedule,
running callback, Closing and callback return remain distinct. Closing precedes
native free. A retained generation token prevents late publication from following
a reused or already-freed area address. Observers run outside native locks under
an allocation-refusal guard and retain original charges and references.

Independent source receipt
`02c6d70cb309950c582a3b420c9068d20e14da9c5618bf2683d271a255368876`
verifies three configured translation units, 18 modeled positive controls and six
source erasures. Independent package receipt
`5358b1ca861ec4984087724095e65afa139c82d74b07a21928e342e7edee5a43`
verifies the five exact package roles, unchanged prior 34 patch payloads and
zero-fuzz, zero-offset replay of all 35 stages and 170 terminal source roles.
The modified upstream vmalloc file retains its GPL-2.0-only notice.

Recorded alignment precedes IOREMAP transformation and is not complete effective
vmap geometry. Full backing, IRQ/perCPU cleanup, cancellation, flush, hotplug and
physical retirement remain open. Coverage stays one of eleven required coverage
bits, with no continuation
issuer and selected CREATE refused before descriptor allocation. These component
and source-replay checks do not qualify full Kbuild, linking, native workqueue
execution, physical peak, RUN or Ready.

## Original source preconstruction and protocol receiver association

The complete source retains its original native read, allocated source banks,
controller geometry and immutable capture profile through realization. A
separate original three-socket group is created before the Source Rc and child;
the sole consuming reader authenticates the same group before inspecting it.
Source, factory and oracle rechecks cannot replace the group with copied data or
derive active Capture authority from an empty socket observation.

Seven explicit provider prerequisites retain the original capture profile in
control records and continuation data. One-shot binding requires unused original
storage/coordinator state and precedes endpoint construction; captured profile
data without that original storage is refused. The existing compact prelistener
refusal remains. This closes the two missing fields found in the earlier
Source59 combined compilation without importing unrelated phased-service code.

Independent receipt
`d50b65f023f8ffd46b96f493677492bd839733b57ffca22361d01db14cd74c54`
verifies 50 production and twelve required test/fixture roles against current
preimages, all 9,617 actual compilation source bodies and matching artifacts.
Three-crate strict checks, twelve Source controls and three modeled provider
controls pass. Separate original three-child preparation, recorder, receiver
group and reap flights retain their own Source41/48 identities; they are not
retagged as Source60 native execution. Earlier failed cohorts remain evidence.

Capture preflight checks the original authority and demand, then refuses absent
local settlement and ancestry codecs. Both Core42 refusals remain. Source-local
journal issuance, the fourth native-after transfer/confirmation, complete
physical admission, genuine factory/adopter activation and fresh restoration
remain required; this association does not qualify Arm, Capture or Ready.

## Selected complete-archive preparse admission

The selected complete loader admits original file extents, exact read banks and
named parser/typed/canonical/validation storage before reads and decoding. A
direct edition-three envelope decoder avoids legacy variant retries. The
accounting includes authenticated index, manifest, administrator and coordinator
data; a private original loader receipt is required for later source issuance.
Parsed labels or a legacy load cannot recreate that receipt.

Independent review found that an ordinary readonly open could block on a FIFO
before checking its type. The corrected selected route opens nonblocking and
refuses nonregular entries before body reads. Regular files use the admitted
exact bank and a one-byte growth sentinel, preserving their existing bytes.
Legacy loading, formats, schema tags and MAC framing remain unchanged.

Independent receipt
`93f5298207d62449a18e12952b256cdbc324929197f25b1c47c6c4bcb31a060e`
verifies eight production roles and one necessary test role against current
Source60 preimages. Matching strict checks and a fresh executable pass the
no-writer FIFO control under its original ten-second guard and all four loader
controls. The earlier ten storage/four journal regressions, blocked FIFO review
and failed test-clock lint cohort retain their original identities.

This loader accounts selected host data and grants no native installation or
factory/adopter authority. Both Core42 and Packet148 safeguards remain; complete
physical capture, local source settlement and fresh worlds remain required.

## Original native-after confirmation SDK

The controller validates confirmation against the original Capture operation,
terminal envelope and three complete content references, then requires the
actual fourth content object before accepting its receipt. The provider checks
the same installed codec and incoming Poll, complete literal suffix credit,
sequence bounds and lifetime request identifiers before publication. Borrowed
closed projections avoid cloning the response DOM. Absent selection preserves
ordinary wire bytes; selected service activation remains refused until its
native source and journal mechanism is installed.

Independent production review
`f17da6321bf2fc8bcd439e1a62634fc2a22170acc223f774597646fee380de53`
verifies the eighteen SDK bodies and their original Source98 strict checks,
457 enabled provider tests and six contract tests; 13 provider tests remain
ignored. Successor review `f551e3c2f971d7733351b22e86254539fce5196e33afd90c9768f54d36df8dac` verifies the exact current
preimages and the daemon test's explicit None initializer. Distinct broader
Source116 all-target checks verify that initializer against the same public
launch layout; they do not represent a minimal nineteen-file execution.
Native source settlement, complete physical peak and fresh adoption remain open.

The separate Source60 repository-profile core suite records 1,405 passes and
five missing-provider failures in 45.329 seconds, with 24 ignored. A genuine
same-source provider build supplies only those five retries, all passing in
0.812 seconds under unchanged assertions and deadlines. Receipt
`d5f507b214f6bab30925832d8bc58598829185e286220a47e4cfab354c65d16c`
retains exact executable identities and original process retirement. All 1,410
enabled cases therefore pass across the explicit fixture conditions; the first
invocation stays failed. These results are not a current-HEAD full-suite claim.

## Original per-CPU vfree publication and immutable address lineage

The additive kernel stage records the original per-CPU list, work item and
method before atomic vfree publication, then records Closing before its worker
frees native storage. Late enqueue observations retain the original generation
without following a freed area. Cleanup observers cannot recursively allocate
through the constructor scope. The first canonical address is immutable:
matching observations preserve it, while substitutions, invalid phases and
counter exhaustion retain a sticky refusal before either constructor returns.

Independent receipt `6bd2d03da4ac920ee0a56aa414d23259ba1df5f2a49bfa7aac7ddff6bdb9c1ae` verifies three configured translation units,
880 source inputs, 33 modeled positive controls and five causal erasures. It
also verifies the five package roles and complete 36-stage, 170-role replay.
All prior 35 patch payloads remain unchanged; the new stage applies the corrected
Source43-to45 delta directly, excluding the rejected Source44 address rebinding.
Per-file licenses and corresponding-source catalogs match the new patch.

Coverage remains one of eleven required coverage bits. Shared backing, allocator
families, full Kbuild/linking,
native concurrency and physical retirement remain unqualified; selected CREATE,
RUN and Ready remain refused. These source and modeled controls do not grant
full native kernel execution or complete allocation accounting.

## One-shot original prebirth ticket roster

Original native and host tickets must all issue before the first target binding
attempt. That attempt permanently seals issuance, including missing-roster or
borrow refusals. Successful binding requires exactly the original three native
owners and host owner; neither late issuance nor another equal target can renew
the association. Creator process/thread checks precede state changes.

Independent review `9cb426dc1df58cb408a3ee229b4e28ed6d2ce2935b95ce82af9c09aadba10e65` verifies the one production and two
test-support changes. Matching strict checks and four controls pass, using real
signed archive files and verified byte closure with explicitly modeled native
verification and private target authority. Those controls cover missing tickets,
equal copies, reentrant binding and an injected foreign creator-thread marker.
The latter is not an actual cross-thread or forked native execution. Both Core42
and Packet148 safeguards remain intact. This sequencing correction does not
qualify a native Capture, source factory, restoration context or fresh adopter.

## Indexed signal-fault decision selection

Branch resolution now formats only its selected override instead of constructing
and discarding every override. Bulk and indexed selection share the original
canonical formatter. Public mutable or deserialized rosters still undergo full
validation before selection; candidate limits, parent authentication and error
behavior remain unchanged.

Independent review `69bfe00d418fb23cf51f1449bc87f85b9f02e6ae9f5d453a4a278fa8fd015ef1` verifies the two exact current
preimages, matching strict checks and twelve relevant test passes. The qualified
source is Source60 plus those two changes, without later loader/SDK/kernel work.
Its unchanged maximum-frontier test takes 33.095112 seconds in the baseline and
9.823934 seconds in the candidate (3.37x, 70.32% less wall time) in one matched
pair using the repository test profile and identical assertions. Wait-derived
child CPU falls from 32.889567 to 9.673638 seconds. Receipt
`3800fd5203cd1008043fc1c0b9e15c9d2c9afb6702bd48ead84d77704db49a1c`
retains both executables, source bodies, original waits and the earlier no-spawn
preflight refusal. No allocator event count was collected. This single workload
pair is not a repeated statistical benchmark, a Linux-boot improvement or a
current-HEAD full-suite result; native qualification and final boot comparisons
remain separate.

## Immutable signal-fault choice domains

Signal-fault opportunities now move one validated immutable domain into their
owned basis and retain its original domain and semantic identities. Branch and
replay helpers use that same read-only basis. Public mutable and deserialized
domains still undergo full validation. Canonical bytes, error order, Debug
output and raw-domain replay behavior remain covered by parity controls; these
cached data identities grant no source, capability or backend permission.

The preceding indexed implementation's maximum-frontier Callgrind run counts
141,913,276,238 instructions. Disjoint direct edges attribute 61.075% to domain
identity, 14.010% to semantic identity and 22.939% to roster validation (98.023%
combined). Independent review
`bce2d80759358eef42c1ea323a08b5313cd9aab0ee538db2fbfb8634f1b20394`
checks the original trace and avoids double-counting inclusive call paths. This
is instrumented instruction/call attribution, not CPU-time or allocation-count
measurement. It identifies repeated immutable-data work removed by this stage.

Independent actual review
`8d7f3024e5efe3137ecdc7b94f38ee3b43c728382bff5764e30f595328a9f675`
verifies strict all-target/all-feature checks, fresh Core and Campaign binaries,
fourteen focused Core passes, one ownership compile-fail doctest, and five new
Campaign passes. The qualification source is the committed 9,629-file parent
plus seven changes, including one new file. The original full Campaign run
remains failed at its 600-second limit: 314 passes and 141 unfinished cases,
without a reported assertion failure. A separately bounded continuation passes
exactly those 141 cases in 458.152480 seconds. Independent review
`f8a5979272ee1538a22cf3c6f4388b97c6261e09bd5e6c3a09f15b921e794ab2`
verifies their disjoint union with the original 314 passes: all 455 enabled
Campaign cases have passing results across two invocations, with no completed
case repeated. The first invocation remains failed. The completed geometry test's buffered
numeric output was not emitted, so no numeric geometry result is inferred.

One matched maximum-frontier pair preserves the original assertions and test
profile: wall time changes from 9.824600 to 0.205217 seconds (47.87x), and
wait-derived child CPU from 9.687800 to 0.173254 seconds (55.92x). The baseline
is the previously qualified indexed binary; 35 unrelated later source changes
are disclosed. Wall time includes 0.2-second polling granularity and uncontrolled
host load. Receipt
`e865ae828b8a2412e397854ea6935bba11b8fde2b4dbb9c0cf85efa4fa2ed71b`
retains source, original waits, both binaries and the incomplete Campaign run.
This pair does not establish a full-suite pass, overall complexity bound,
allocator peak, Linux-boot gain or native-backend qualification. Raw profiles
and qualification artifacts remain local and outside repository publication.

## Dedicated original per-CPU backing

The selected constructor family now uses a dedicated boot-born per-CPU arena
instead of borrowing the dynamic allocator's chunks and global balancing work.
The source records original boot geometry, admits whole arena/template/mapping
and keeper credit before clearing storage, and retains unreused logical slots
and generations through release. Its constrained SRCU constructor profile
accepts exact raw GFP_KERNEL flags; unsupported flags refuse before effects.
The permanent row retains raw output before observation. Pointer delivery then
rechecks the same task, scope, currentness, deadline and lease/delivery generation
after the sole final observer, so callback revocation cannot deliver a stale
pointer. Ordinary dynamic allocations retain their original path.

Independent source correction review
`cc6d4304b952b6a4d5aa13255dd740c332dd9b09b0bae70da2d2ef1737b146bb`
verifies two changed configured translation units and 879 inputs, sixteen
modeled positive controls and four causal erasures. Boot, task, CPU-map and
deadline peers remain modeled. Actual configured objects measure a 64 KiB
page-aligned per-CPU arena, 40 KiB keeper and 384-byte, 64-byte-aligned SRCU data.
The earlier correction candidate and failed erasure oracle remain retained.

Package review
`04087219047e03150745ac2c2fac1d61191f1c84a588effdbbfee5508c5ade84`
verifies the five source-package changes and exact 37-stage replay across 172
roles. All 36 earlier patch payloads remain unchanged. One corrected cumulative
Source45-to47 stage includes the exact flag fence and final observer guard;
the rejected intermediate Source46 is not a production stage. Source and
license catalogs distinguish newly catalogued upstream mm/percpu.c from the
sole new GPL-2.0-only pool fragment.

The backing bound covers selected possible-CPU slices, template, mapping bound
and keeper. Complete first-chunk allocation, slack, NUMA padding, boot peak,
actual mapping/PFNs and native CPU-map lifetime remain unqualified. Coverage
stays one of eleven required coverage bits; full Kbuild, boot, SRCU/concurrency,
CREATE, RUN and Ready remain
separate requirements. No full physical-budget or kernel execution claim follows
from configured translation units, model controls or patch replay.

## Measured installed Compute requirements

The installed catalog now supplies exact Compute demand data for its closed
gem5 x86_64 and AArch64 SE profiles. Resolution retains private source
qualifiers bound to the original complete world, owner, descriptor, machine,
devices and ISA. Preparation and admission reopen the measured source artifacts
and native operation witnesses. A borrowed proof authenticates the same demand
object; an equal copied demand cannot reuse it. Public demand data does not
grant live authority or implementation-class acceptance.

The supported model remains fixed O3, 1 GHz, 512 MiB, classic DDR3 and the
closed write_fd1/exit guest interface. Only exact_run and boundary_settle are
supported. Other backends, arbitrary guests, full-system devices, extensions,
fork and replay remain refused without their independent implementations.

Independent review
`b1b75e6e90b6975e0533aad538e430b186b9626fdfa426b779a0f04bbedefdcc`
checks the exact seven-role delta, current preimages and absences, 926 consumed
source bodies and the original executable. The tested source is Source112 on
the earlier indexed-decision parent, with source index
`bc76a06e7c6da106ed6d348b3199303eb8c42688356816c37954267dc2e8091e`.
Import does not relabel that cohort as a current whole-source build.

All-target/all-feature check, strict Clippy and library-test code generation
pass in 47.526, 124.557 and 479.256 seconds. That cohort uses its explicitly
inherited opt-level=0 profile override. Its 427,414,616-byte executable is
`3fed28d5efbf913e5e745e1d176c11764efdea5046420a67068cb6dc0be4c768`.
Nine individual controls pass: five source/demand controls and four existing
refusals. Four source-measurement controls are normally ignored and were
explicitly executed with include-ignored; they are not omitted passes.

The first typing failure, 180-second test deadline, separate optimized-profile
compiler deadline and interrupted measured test remain failures. A bounded
continuation runs only the four unfinished measured controls, which pass in
203.084, 213.095, 414.163 and 206.084 seconds. These controls remeasure installed
artifacts and launch no native gem5 child. Runtime HOME is absent in the
original minimal environment; it is not redirected to a task-specific home.

This establishes fixed-profile, no-effect demand interpretation and unchanged
live/class refusal. It does not qualify native preparation, execution, Ready,
capture, restoration, whole-factory allocation peak or device parity. Actual
Cargo target compilation does not substitute for the outstanding Nix
application unit/integration target gate.

## Fresh native64 compiler-runtime context

Genuine source configuration and header generation now complete after the
initial GCC stage is established serially before parallel prerequisites. The
previous parallel attempt failed when several recursive stage1-start calls
rotated the same directories. The correction retains the original compiler,
flags, dependencies, features and subsequent parallel targets. Earlier process
observation and configuration failures remain separate recorded outcomes.

The original configure35 work completes with status zero in 158.392440 seconds.
The same original Root issuing handle reaps its operator with status zero;
original work and group terminal receipts remain independent of incomplete
sampled ancestry observations. All eleven generated or linked headers exist.
The 1,616 sampled rows retain their actual retirement classifications, including
129 rejected birth observations and 28 descriptor-retired BirthUnknown rows.
Neither these rows nor unavailable topology observations establish complete
process ancestry or namespace authentication.

Independent full-context review
`cab1788d154b3d3af77dd47c2406ce79d60293b281c4c79056e9390c37f19ce3`
checks 148 direct selectors and 594 before/after source-body hashes. The complete
169,755-entry source roster has exactly 297 admitted fixups and no unexplained
extra paths. Generated-build and wrapper inventories, raw and resolved sysroot
inputs, all 121 original input provenance records, eleven headers, four raw
links and eight native ELF64 artifacts are retained and verified. This accepts
the newly configured native64 diagnostic context, with candidate identity
`ec033cbf700ac5359a746ed14b2afa21edfee7e31f0e1dc372e4a55420267301`.

The first read-only finishing audit failed at an incorrect gcc/dwarf2.h locator
after completing its inventories. Its failure remains recorded. A bounded
finishing audit reuses those exact inventories and verifies actual
include/dwarf2.h and resolved header links, then completes with status zero.
No GNU build is rerun or relabeled by that audit correction.

Optional /usr/bin/file invocations fail in the actual configure diagnostics.
The native x86_64 probe leaves the explicitly selected AOS linker at its native
64-bit default; pointer size and generator ELF class agree. No successful host
tool execution is inferred. Production hermeticity remains unqualified until
a declared predecessor-built file helper and audited source substitution avoid
the bootstrap dependency cycle. Private-unwind member compilation, scoped
linking, ordinary compiler/package qualification and complete QEMU binary/source
qualification remain separate unfinished requirements.

## Original embedded per-CPU group backing

Kernel source stage 38 records each original embedded first-chunk group before
its allocation and retains the raw result before publication or observation.
It preserves complete CPU-map padding, group requests and unit offsets, then
binds the pool's actual runtime arrays and aliases to that original geometry.
Selected backing accounting conservatively charges complete padded allocation
requests without subtracting later hole or tail frees. Virtual NUMA address
gaps are recorded separately and are not counted as physical backing.
Ordinary boot and failure cleanup retain their original behavior.

Independent Source48 review
`b7ef0ca8104f4622c585bfd1172536e26eab30c1c8cdb9041d8578402fa0eec4`
verifies four sparse roles, two complete configured translation units and
880 actual compiler/configuration inputs. Nineteen positive controls and three
causal erasures pass with their explicitly modeled peers. Native configured
objects measure a 36 KiB first-chunk keeper, 40 KiB pool keeper and 64 KiB
per-CPU arena. An unrelated mutable Rust metadata leaf in historical ancestry
is explicitly excluded; it is not a current C input or historical proof.

Independent five-role package review
`f67b5733ee1e853833f54862cbe573b13e23386e86ad82d67abe11bc7edd5255`
verifies all 37 previous patch payloads unchanged, the appended source patch,
strict 38-stage replay across 173 source roles, sparse package replay and Nix
formatting. The sole new first-chunk include is catalogued as GPL-2.0-only;
existing source notices remain unchanged. Raw compiler and control artifacts
remain local, outside Git and releases.

This closes the selected embedded group-backing and alias-origin gap. It does
not close first-chunk setup metadata, memblock internals, retries or resizing,
global boot peak, page-remapped/fallback paths, native PFNs/maps, concurrency or
whole physical-budget admission. Coverage remains one of eleven required coverage
bits, with CREATE before
FD allocation, RUN and Ready still fenced. Full Kbuild and nested/native
qualification plans remain prospective and unexecuted.

## Complete installed mixed-provider selection

The installed catalog now retains independently authored complete mixed-world
definitions and resolves their exact portable selections through ordinary
scenario and preparation routing. Each definition binds the complete disjoint
provider partition, node/owner/profile/configuration tuple, scenario, execution,
activation and runtime ceilings. Preparation delegates to the existing single
global mixed-world source, behavioral acceptance and all-owner barriers.
Singleton authorities are not combined to manufacture a mixed-world permit.
The table admits at most 64 definitions and 16 MiB of aggregate serialized data;
these are metadata limits, not physical retained-capacity or native budgets.

Independent actual review
`9a938f1b9cf1ba39798b1792957ae9d99a8f00209258fbb0b8f3ac9a58b383c6`
checks the exact f83 capability source plus four routing changes: 9,635 source
files, including two new modules. Strict all-target/all-feature checks pass in
256.280188 seconds. Fresh daemon test code generation passes in 1,948.502910
seconds using the unchanged repository opt-level=s profile, debug assertions
and overflow checks. The 155,674,664-byte executable is
`26382a48e6eb45ff49692afc086ba88844cb50795a4a3396142e5b0f60009a83`.
Its actual dependency information covers all four routing and seven Compute
roles. Later kernel and ledger changes are outside that qualification cohort.

Nine exact controls pass in 7.218169 seconds: six new definition/partition/
preparation/refusal controls and three existing wire/world-binding controls.
The executable lists 1,277 enabled and 147 ignored cases; that inventory is not
a whole daemon suite pass. Original waits, release and unchanged source checks
complete without cancellation or unresolved ownership. Earlier missing-Serialize
and incorrect hash-accessor compiler failures remain failed. Metadata credit
now uses the actual execution identifier's fixed 16-byte operational form.

The public export addition is committed separately from its token-equivalent
rustfmt reflow. Inert installed inspectors in these controls do not establish
mixed native execution, accepted backend classes, QEMU/gem5 device parity,
Arm, capture, Ready or ordinary package qualification. Those remain required
integration and runtime checks.

## Source-built private unwind members

Two actual GNU unwind source members compile against the independently qualified
native64 diagnostic context. Their complete symbol maps are renamed into the
private QOM namespace, preserving ordinary shared unwind linkage. The resulting
deterministic archive is 282,676 bytes; the coexistence executable is 219,576
bytes and runs successfully with both ordinary and private backtrace paths.
The original serial work completes in 26.773 seconds and is reaped successfully.

Independent actual review
`1d20ce798d7bdafae0664406311af4cb840f049be2f76c4554ba29e6315bfec1`
checks 466 retained selectors, 227 actual dependency bodies, both object symbol
maps, exact archive members, the coexistence ELF and 123 after-input producer
joins. The separate handoff is
`a6d73011b8c518614a6681fca116c8f1fec9757446dce8aea9fba00c11176503`.
All seven observed process records are retired; original terminal receipts
show no remaining group members, unknown retirements or dispatched signals.
These observations do not establish a complete process census or physical peak.

The comparator uses diagnostic heap and FDE forwarding shims. It tests coexistence,
not QOM arena ownership, exact stack equality, exception restoration or a complete
module graph. The earlier command-input failure before child birth and failed
optional FHS probes remain recorded as failures. Production context generation,
full emulator and utility links, corresponding-source release gates and native
Capture/Ready remain unqualified. Raw source/build evidence stays local.

## Original boot metadata and raw-result custody

Kernel source stage 39 accounts for per-CPU setup metadata and original memblock
allocation attempts before native calls. It preserves nested lower-limit retries,
allocation cardinalities, original chunk/map bindings and overlapping old/new
array backing during replacement. Accounting is monotonic; frees do not refund
credit. Ordinary allocation and cleanup behavior remains unchanged.

Finite token membership is checked before retaining the first raw result. Actor,
stack and failed-state reconciliation follows that retention. Allocated and final
resize pointers/results remain distinct, and duplicate or stale completions cannot
overwrite the original observation. The earlier prototype that reconciled actor
identity before retaining the raw result is rejected and is not a package stage.

Independent corrected component review
`ae78fff5d7bd5e72d55951fc510182c8910d33c8ec71849d29a1e5f9d0922148`
verifies the changed configured per-CPU translation unit, 775 consumed inputs,
16 positive controls and three causal erasures. The other two configured units
retain their earlier source scope. The permanent boot keeper measures 552,960
bytes; the existing 36/40/64 KiB first-chunk, pool and arena symbols are unchanged.

Independent package review
`24d9857795095c9cf70cb085e8f343acab3f0c630774cc38697aeb8fd060cfa4`
verifies five package roles, all 38 preceding patch payloads unchanged, strict
39-stage replay across 176 source roles, sparse AOS replay and formatting.
The sole appended patch contains the corrected cumulative change. Existing
memblock notices remain GPL-2.0-or-later; two new files are GPL-2.0-only.

This component does not qualify global boot peak, free-triggered metadata growth,
PFN/mapping acceptance, native concurrency or whole physical-budget admission.
Coverage remains one of eleven required coverage bits; selected CREATE before FD
allocation, RUN and Ready
remain fenced. Complete Kbuild and guest-only nested boot plans remain unexecuted.
Raw compiler and control evidence stays local, outside Git and releases.

## Original free-triggered boot metadata growth

Kernel source stage 40 retains the original per-CPU free operation before its
native effects. A nested memblock region-array resize reenters the same retained
operation and preserves its parent and depth. First native results are recorded
before reconciliation; overlapping, duplicate, stale and failed completions do
not restore consumed accounting credit.

Independent source review
`4c2664244690378d141cbb79f747586fede636787537af2e6265636a7a984675`
verifies two configured translation units, 778 consumed inputs, 12 positive
controls, three causal erasures and the 798,720-byte permanent boot keeper.
The removal/isolation peer in these controls models the resize path; it does
not establish actual native isolation, freeing or physical retirement.

Independent package review
`f5bfe9258e169ea20e3820fdfe3d1ab9aee98968985df47c381efba744c40011`
verifies the five package roles, 39 preceding payloads unchanged and the sole
appended three-file delta. Strict 40-stage replay covers the same 176 source
roles; sparse AOS replay and formatting pass. No new GPL files are introduced.

Coverage remains one of eleven required coverage bits. Complete Kbuild, nested
boot, native physical-budget
admission, CREATE continuation, RUN and Ready remain unqualified.

## Original post-init per-CPU physical backing

Kernel source stage 41 retains runtime per-CPU arena and permanent keeper page
references after page initialization. Its fixed bank reserves each row before
the native pin attempt and retains raw outcomes and partial prefixes on failure.
Currentness checks preserve the same direct-map address, page, PFN, reserved
status and non-CMA backing. The linker template remains historical because
its init-section lifetime ends at init-memory retirement.

Independent source review
`ae8e66c7ebe7b4e0b131bd0deed624bf198fec49b5178487bc2a37aa450c95ab`
verifies the configured per-CPU translation unit, 776 consumed inputs, 15 positive
controls and three causal erasures. The backing bank measures 675,840 bytes;
the existing permanent boot ledger remains 798,720 bytes. These are object
measurements and scoped controls, without native boot or hotplug qualification.

Independent package review
`5926b8c75c8902687bb13f504ca530edf86ceb0736c4ce246aae247ff167a955`
verifies the five package roles, all 40 preceding payloads unchanged, strict
41-stage replay across 177 roles, sparse AOS replay and formatting. The new
backing include is GPL-2.0-only and appears in the source/license inventories.

Coverage is a bitmask: 0x001 supplies one of eleven required bits; the complete
mask is 0x7ff. Earlier 1/2047 prose referred to numeric mask values and must not
be interpreted as 2,047 independent allocation domains. Global boot accounting,
native concurrency, complete Kbuild, nested execution, CREATE, RUN and Ready
remain unqualified. No native pin, kernel operation or host change was run.

## Original KVM constructor scope

Kernel source stage 42 scopes the actual CREATE caller before descriptor
allocation. It retains the original task, memory context, file table and
generation, records the raw native result before final reconciliation, and
releases the temporary file-table reference outside the registry and allocator
scope. Closed system-file origins cannot match a later file at a reused address;
completion authenticates the retained original generation independently.

Independent component review
`010fe67aac93c9c91f816782efb53e14263ccadd757a8c18cf70eab08d5b950b`
checks the complete configured kvm_main translation unit, 857 consumed inputs,
20 literal-source positive controls and six causal erasures. Kernel peers in
these user-process controls are modeled. The earlier stale-lookup source stage
53 remains rejected; the packaged delta goes directly from source 52 to 54.

Independent package review
`4d9f2330b0785aad2931706d6eeddd120351b4d625341811d9edfad37efd873b`
checks all 41 preceding payloads unchanged, 42-stage strict replay across 177
source roles, sparse AOS replay and formatting. Existing GPL notices remain
unchanged and no native source file is added.

Coverage remains one of eleven required bits (0x001 of 0x7ff). Selected CREATE
still refuses before descriptor allocation, including when supplied a fabricated
complete mask. FD/VFS/RCU ownership, physical retirement, complete Kbuild, nested
execution, CREATE/RUN and Ready remain unqualified. No host kernel change ran.

## Common preparation and authenticated packet integration

The integration adds original-controller assignment, authenticated canonical ACK
admission, retained packet transport and metadata banks, and one-shot complete
world admission. The same revocation guard spans final callback reauthentication
and native terminal validation. Failure or unwind retains original resources and
revokes the admission instead of renewing it.

QEMU preparation retains the actual node, process guard, full legacy scheduler,
fault state and optional VMState in one preallocated common participant. Its
checked clock mapping preserves the existing 50 ps lattice and reported idle
bias. This preparation profile still exposes no common execution or Ready facet.
The gem5 x86 model adds bounded physical-entry ELF and boot-geometry validation;
its component tests do not establish full-system execution or device parity.

These 122 sparse integration roles preserve the later campaign, mixed-provider
and kernel changes. Functional changes and formatting are separate commits.
Combined all-target/all-feature strict checks pass for Core, daemon, provider
and QEMU in 235.42 seconds. All-target compilation completes in 3,565.48 seconds;
four library test executables, the ordinary packet provider and its daemon
integration executable are fresh, with size optimization, debug assertions and
overflow checks. Dependency records cover all 113 changed Rust roles.

The compiler exits successfully, but its evidence collector then fails on an
incorrect assumed dependency-file location for the ordinary provider binary.
That failed outer result remains preserved. A separate retrospective check
authenticates Cargo's exact emitted executable, its same-inode hashed alias,
actual dependency file and retained bytes; compilation is not repeated or
relabeled. Eight inventories, 35 selected runtime controls and five further SDK
admission controls pass on these same executables.

The actual three-process admission fixture fails during the first child's
assigned Admit after 66.53 seconds. The native endpoint verifies its MAC and
installs the token, but the ordinary Control dispatcher rejects the retained
proof extension before replying. The original provider I/O times out; both
retained processes retire without supervisor signals or unknown cleanup.
The failed attempt remains preserved separately from the corrected
qualification below.

The next source correction hands the exact verified original to Control through
a private, consumed admission witness. It rechecks the installed token, boot,
policy, connection authority and original request; the unchanged signed proof
and request identity remain in the journal. Generic proof-bearing Admit refuses
before cached-response lookup or preparation callbacks. Four regression controls
cover the generic route, ordinary baseline, missing installed token and cached
proof replay. Independent source review and current all-target/all-feature
provider strict checks pass. Fresh provider tests, ordinary peer and host
integration binaries compile with size optimization, debug assertions and
overflow checks. All 29 selected provider controls pass, including the four new
regressions. The corrected three-child fixture passes: each actual child
completes source registration, typed Hello/Discover/Realize and once-keyed
protocol Admit, then reaps in its original private group. Its test reports
1.51 seconds; the complete supervised invocation takes 6.92 seconds without
signals or unknown cleanup. These results bind committed source
`0f664e33327cffb576314ba03163cad33e144678`. They establish genuine admission;
semantic Arm, complete-world execution, Capture and fresh restoration remain
separate requirements. The original failure is preserved.

## Production QOM observer inputs and stopped-current observation

The production recipes add a source-built private GNU unwind observer through
the selected QOM dependency. The existing global unwind dependency remains.
Its generator context runs on the build platform while its member compiler and
archive target the QEMU host platform. Package support declarations cover the
actual firmware, gem5 component and source-check producers.

The earlier source configuration passes both x86-builder routes and 25 shape
assertions per route. Two ordinary AArch64-builder baseline probes refuse at the
existing bootstrap restriction; they are not positive cross-build results.
These evaluations used the preceding QEMU source and do not qualify a newer
production realization.

The stopped-current source initially selects signed commit
`0351e3ad49c67c88cb1a14669a48e0d9d94a22be`, with its complete patch, bundle,
descriptor and updated per-file license inventory. Its additional stopped-current
getter observes the same parked original RR root, command, input epoch and
consumed preparation acknowledgement without dispatching modeled work.
Seventeen extracted C controls pass. Independent review verifies the complete
signed tree and patch replay; configured emulator/plugin execution, ordinary
production builds, complete preservation, readiness and release gates remain
pending for this source.

The ordinary production catalog passes for all 764 packages and the current
source tuple passes 14 checks. The first context build fails in its predecessor
`file` helper: its static compiler wrapper encounters shared libmagic during
the executable link. Selecting libtool's static executable link mode alone
still fails: the actual configure output reports that upstream disables static libraries by default.
The follow-up enables static libmagic alongside its shared library and retains
the executable link policy, all features and full upstream checks. Its actual
helper build passes the complete upstream check/install/fixup phases. The
registered output contains both libraries; ELF inspection confirms that the
executable has neither a dynamic interpreter nor a dynamic segment. The two
failed predecessor builds remain recorded.

The context then fails because Python receives a workspace source path that
is absent inside the Nix sandbox. The instantiated derivation confirms that
plain `toString` omitted source-path imports. A path-only interpolation helper
now retains those inputs and the recipe files in the store closure; derivation
contexts, numeric substitutions, flags and features keep their existing handling.
The corrected command imports all six source substitutions and retains its
recipe paths as store inputs. Actual GNU configuration and header generation
then complete, including all eleven selected headers. Installation fails while
copying a repeated read-only compiler source into an already copied directory.
The native build uses the same compiler for both roles: 28 source occurrences
resolve to 21 distinct paths. A reviewed deduplication copies each distinct
source once. The failed attempts and generated outputs remain retained;
the next build completes generation, installation, fixup, scrubbing and metadata.
Nix registration then rejects a mutual reference between the binary and source
outputs. The binary context names generated source paths, while the retained
source context and configure output name the binary output. This is a failed
realization, not an installed context. The reviewed correction generates directly
inside the source output and uses source-local GNU configure prefixes. The
recorder and provider consume those same source roots; metadata references source
in one direction. The corrected context and private observer now both realize
successfully. Independent inspection verifies their registered derivations,
complete source outputs, actual compiler dependency files and twelve archive
member commands. Streaming inspection finds no reverse output reference in the
context's 2.15 GB source archive. These results qualify these two build components.

The next complete QEMU build configures successfully and reaches compilation
step 3,641 of 3,788, then fails while linking the isolated ptimer test. Pulling
the endpoint owner utility through oslib also pulls the real main loop and timer
implementations, which conflict with the fixture's intentional replacements.
A reviewed one-file correction supplies the exact typed no-journal NULL backing
result in the existing test stub. Production code, clocks, test selection and
file licenses remain unchanged. The complete signed source successor is
`02bdf2de185682e4d211dff441527fcb4e7f7383`, tree
`1065454b7422d45f0baedd97ae979d20d03c7081`; independent review verifies its
single changed existing file, signature, complete patch/bundle and license
inventory. The next fresh full build reuses the successful context, observer
and toolchain but fails at the same unit link. The timer constructor inline
also imports the real timer backend; the first stub blocks only the separate
oslib dependency. Both failures remain recorded, without installed-QEMU or
complete-package credit. The second reviewed correction adds the exact typed
inactive-pool result to the same fixture, retaining every existing timer/clock
body and assertion. Signed native source
`f32fdf3fddad79ea95f84b77df68fa897f6c74d2`, tree
`74887a346dd284b0420c24fa9c7e54210d51af5c`, and its complete matching patch/bundle
pass independent signature, sole-file and source-tuple review. The production
recipe now runs all ptimer policy combinations, unfiltered, with a fixed GLib
seed and a 60-second timeout plus five-second grace. The next full build
successfully links ptimer, then fails at two isolated device fixture links:
their direct hwcore dependency now needs the inactive selected-node setup/reset
observer functions. No package runtime tests execute in this failed build.

The correction links a shared, explicitly licensed fixture helper into those
two executables and the two existing qdev fixtures with the same dependency.
Its typed false/no-op functions match production's inactive branches; production
observers and all test bodies remain unchanged. Native source
`103158b08fa6fd92cab2ae9911ef2b76f7599fdc`, tree
`f73ccacd9776301cef4b2e30f979802728434494`, carries the matching signed atomic
patch, complete source bundle and updated license inventory. The recipe runs
all four complete fixtures with the fixed seed and bounded timeout, in addition
to every ptimer policy combination. Ordinary builds use QEMU's supported
`make -k` forwarding so independent failures are collected without changing
failure status. The next build completes all 3,792 native build steps. Its four
unfiltered device fixtures pass eleven cases and the complete ptimer suite passes
578 cases. A later network-output source fixture fails because its extracted TX
signature and four direct calls still omit the actual sender argument. This is
a failed package check, not installed-emulator or corresponding-source success.

The reviewed correction preserves the actual original-endpoint admission body,
passes the real sender in the four fixture calls and keeps selected authority
unavailable in the isolated fixture. Every previous assertion and all nine
negative controls remain. Its locator checks reject missing, duplicate, prototype,
stale-type and truncated definitions; pure source extraction verifies all 48
selected production functions. Signed native source
`01b7a428d447a5ffa181c29729a2db45085b6183`, tree
`9cbc7d23f7cd9c3b35af89195badb52a3fff3544`, changes that existing Python fixture
only. The matching atomic patch, source bundle and unchanged license inventory
pass independent reconstruction review. C fixture execution, full package checks
and matching-source realization remain required. Earlier failures remain recorded.

The following build again completes all 3,792 native build steps and 589 unit
cases. The repaired network-output fixture and lifecycle projection now pass;
the deferred-control fixture then fails C compilation because its imported
shared prelude omits the genuine original-endpoint admission definition.
A reviewed correction moves that exact definition and its typed fixture
prerequisites into the common prelude and updates the independent stop-chain
fixture to the same sender signature. Existing behavioral assertions and
mutation branches remain intact. Pure extraction controls pass, and signed
native source `92e5b2b4d39ddf110188c3ea9829d2521fba5ee5`, tree
`e2463530f1f4c1e59acd871e4fc38acf1c8db2d5`, passes independent patch, bundle,
signature and unchanged-license reconstruction review. Full native execution
of this correction and package/source realization remain pending.

Corresponding-source assembly also unnecessarily pulls Cargo and Git into a
registry-only vendoring operation. A supplied lockfile now selects the required
tools, and both stages authenticate its exact raw bytes before vendoring effects.
Nine Python controls pass, including changed source and cached lockfiles, same
verified-byte parsing/copying, unchanged Git metadata routing, actual tiny
registry archive extraction and checksum rejection. Actual recursive derivation
inspection now finds zero Rust, LLVM or Git producers in this source-assembly
graph. All 639 registry archives match the current lockfile checksums; their
reconstructed source cache has a verified complete 101,856,240-byte NAR with
SHA256 `84df342660e9ec342c2aa74d2630a4f624802bb211cb3ae0aad8e44909fa6481`.
The corresponding provider dependency edge and workspace staging hash change
together. The real pure-vendor builder then passes and produces a registered
712,189,328-byte vendor NAR, with the exact current lockfile and 639 expanded
crate/checksum records. Full source and vendor NAR inspection pass. The temporary
reconstructed source tree is removed; original caches remain unchanged.
Network stage1 execution, complete matching QEMU source-bundle realization and
release qualification remain separate. This removes unnecessary build inputs;
it does not establish a guest-runtime speedup.

## Full gem5 production build and ownership check

The ordinary local ALL build links the native simulator and emits its matching
source output. Its base execution check reaches tick 10,944,163, and the inherited
platform, terminal, causal and closed-block checks pass. Build information retains
X86, ARM, MIPS, POWER, RISCV and SPARC, together with GPU, SystemC and multi-protocol
Ruby support. The native product is
`dmpzig3wdxrarca5kg51xcc21ny96y1i-gem5-native-original-scope-foundation-25.1.0.1`.

The mandatory separate native-original-scope check then fails its first owned
case: phase zero reports Refused rather than Walked, with unchanged before/after
queues. The complete invocation exits unsuccessfully. Its source, product and
failure remain retained for diagnosis; linking and the base checks do not qualify
the complete native backend, readiness, Linux boot or exact preservation.

Two bounded diagnostic flights reuse this exact simulator without recompiling
it. They preserve the original failing assertion, refusal tuple and unchanged
event queues. Permanent ownership records correlate the first visiting leaf
with the ARM instruction TLB. The second diagnostic also observes zero registered
table banks, placing the refusal before the first successful table-entry check.
Inspection of the actual executable and source identifies an always-false RTTI
comparison through the non-polymorphic replacement-data base. The correction
records constructor provenance in a finite preallocated bank and checks the
original policy, data pointer and shared ownership identity before the cast.
Nine fresh component controls pass, including foreign owners, pointer reuse,
retirement and exhausted capacity. They measure a 58,896-byte bank for 1,472
retained birth obligations. This is component evidence; the full native simulator
has not been rebuilt with the correction.

The selected configuration also contains a 1,280-entry L2 TLB, exceeding the
current 1,024-entry account. A separate correction preserves that default,
reserves sixteen 1,280-entry banks before object construction, and checks the
actual declared extent and complete owner/index correspondence. Nine fresh
component controls pass on eight exact production method bodies and current
headers. Independent review verifies all six selected compiler dependency
bodies, the emitted ELF and exact runtime control names. The component observes
452,520 bytes for the scope and 328,192 bytes for its table backing; scalar
bookkeeping and object identities remain test fixtures.

Native compilation and its complete corresponding source now have a separate
producer from host fixtures and source enrichment. Public packages retain both
native outputs and verify that their ELF is an exact copy. Earlier eight-variant
evaluation verifies that fixture-only edits preserve native derivation identity,
while a native command change alters it. The coherent current source passes the
ordinary package catalog and registered derivation checks. Its fresh native
compiler is `jrmwlbjxqllw5p1sg1pwvxdvjslvziby`, with a separate public wrapper and
mandatory native-scope check. The full local ALL build links and registers the
native/public products and their corresponding-source outputs. The two installed
ELFs are byte-identical. Base, platform, terminal, causal, closed-block and eleven
origin checks pass; the mandatory check also passes nine LRU and nine table cases.
Its first complete owned walk still refuses an unknown visitor with unchanged
queues, so the complete invocation fails. The later four modes never execute.

A bounded diagnostic using that same installed executable identifies the deepest
leaf as the ARM table walker, after closing all 64 ITB table entries. Source and
disassembly show uninitialized cached release and pending fields in its birth
state. The real MMU release exists before its sole initialization/binding path.
The reviewed correction initializes those fields and binds the cached pointer
to the actual MMU release, authenticating its owner before inspecting the getter.
All nine source-method component controls pass, including nonzero birth time,
rebinding, stale cache and foreign-owner refusal. The genuine configured ARM
translation unit compiles with the exact SCons producer flags; its relocatable
object has 573 verified dependencies, including the actual MMU and generated
parameters. Native source SHA256 is
`825aca2876a0ca8ef24c3f59227a230d69414d7f7122a61fabbcffe0e82c38d4`.
The first configured attempt timed out while generating cold prerequisites;
subsequent generated comment-path classification retains that and its own
validation failures. The six source, recipe, control and license changes are
ready for a fresh ordinary native/package/source build and mandatory owned walk.
Those complete checks remain pending, and the original failed walk remains failed.

## Complete SDK composition qualification

The first combined complete-protocol SDK candidate overlays 155 provider and
Cargo roles on `ca0dc85c22bad8bba9c63d231b00faae2fbb9879`. Its actual strict
all-target/all-feature provider compilation fails with 31 diagnostics in
16.05 seconds. These include missing exports and imports, duplicate metadata
implementations, incomplete typed collection decoders and endpoint construction
fields. The original compiler result, exact before/after source identity and
released process group are retained. The corrected candidate, including two
independent legacy and selected-field serialization controls, reduces the next
compilation to one borrow error in 15.56 seconds. Its process group also releases
without signals and its source remains exact. The remaining observer call uses
a mutable authority accessor through a shared connection reference. The fix uses
the existing authenticated immutable authority loan. The next strict invocation
closes those type errors but reports dead-code and Clippy issues, including
missing native Commit consumers; strict qualification remains incomplete.

With those diagnostics retained, a normal all-target/all-feature type check
passes on the subsequent exact 157-role composition. Its fresh provider libtest
build also passes. Forty-three distinct focused controls pass on that same
executable across invocations of 41 and two tests; the original 43-test selector
omitted a module in two names, so its exact-name collector failure is retained.
The second invocation runs only those two corrected selectors. The controls
include legacy policy wire-byte preservation and selected-field serialization.
They provide no whole-world Capture or native restoration claim. Actual Commit,
held-proof publication and complete suffix admission are still being integrated.

The later Source/Host/Core composition first fails three internal visibility
checks, then reports 103 diagnostics, largely cascading from incorrect module
paths and missing imports. Scoped corrections retain the selected reconstruction
limits and count the actual retained protocol supervisor. Integrating the actual
Commit/Held consumers exposes seven provider errors, including two callers
reverted to an older constructor form. Their correction restores the exact
selected arguments and retains the source-bound input-emitter chain. A new
private canonical encoder counts raw serialized extent before constructing its
DOM, counts bounded canonical output, then reserves and writes the exact bank.
These checks do not issue whole-memory or restoration authority.

The resulting provider passes normal all-target/all-feature typing in 35.20
seconds and emits a fresh libtest in 138.72 seconds. Its compiler dependency
file consumes all 174 selected provider Rust roles. One exact invocation runs
59 enabled controls: 58 pass and one fails. All 43 earlier controls and the three
new finite-encoding controls pass. The failed late-field test exposes a real
production defect: the borrowed scanner returns a quoted CNP U64, but sequence
and offset readers pass it to an unquoted integer parser. A reviewed correction
unwraps the string grammar before checked canonical-digit parsing; its new
runtime and compiler checks initially remain pending. The corrected provider
then emits another fresh libtest in 140.73 seconds and passes all 59 selected
controls in one invocation, including the strengthened quoted-number, actual-bank
and negative wire assertions. The earlier 58/1 invocation remains failed.

The shared four-crate compiler progresses through the provider and core
libraries after the corresponding corrections, then fails sixteen daemon
diagnostics involving eight attempts to format a structured OperationFailure
through a Display-only mapper. Those daemon corrections and the complete
unit/integration targets initially remain pending. The next shared run passes
those production branches and reaches the core unit tests, where five test-only
errors expose a fixture path, ambiguous enum and outdated demand initializer.
Their correction uses the existing fixture and actual public layout types;
current combined verification remains pending. No combined strict, complete
Capture or native restoration pass follows from these component results.

The required application-target invocation reaches its original 10,800-second
client timeout before application compilation, after building earlier LLVM
stages. Its original client is waited; external daemon builders are outside that
release observation. Read-only evaluation of a separately captured current target
finds 49 missing derivations, including LLVM 22 and 25 Rust stages. The selected
48 application bodies remain separately identified; their transitive Crucible
libraries still require current-source qualification. The next dependency build
will warm the exact required production compiler before reevaluating current
application targets. Neither the timeout nor the dry-run supplies a gate pass.

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

A separate source-built gem5 thread-list microbenchmark preserves the original
thread pointer across suspend/resume by splicing its persistent list node.
Five fresh matched 500,000-transition rounds reduce median time from 4,545,799
to 1,780,505 ns (2.55x) and remove all 500,000 temporary allocations per round.
The complete 100,000-transition pointer/refusal controls also pass. Independent
review verifies the retained source, executables, CSV and current compiler/run
commands; historical compiler arguments were not retained. The fresh run is
unpinned. This measures list mechanics only, without CPU/statistics/IRQ timing,
complete callback closure, common readiness or Linux boot performance credit.

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
