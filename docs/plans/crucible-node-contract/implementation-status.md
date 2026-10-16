# RFC-0025 implementation status

Implementation work tracks the full [RFC-0025](../../rfcs/0025-crucible-node-contract/README.md).
The PR remains draft. Component tests and separately qualified native profiles
do not establish completion of the full architecture.

This summary accompanies the [phased implementation plan](phased-implementation.md)
and [qualification plan](qualification-plan.md). Detailed test logs, images,
traces and experiment history remain local. Test counts below identify their
specific stage; they are not cumulative coverage of the latest source.

## Implemented areas

| Area | Implemented behavior | Remaining qualification |
| --- | --- | --- |
| Common node contract | Backend-neutral lifecycle, capabilities, graph admission, causal scheduling, owner exclusion and implementation-bound archives | Final-source checks and complete production routing |
| Existing execution | Shared campaign and attempt APIs with legacy compatibility aliases, canonical identities and separate observed provenance | Final legacy compatibility and performance comparison |
| Public providers | Authenticated CNP/1, extension negotiation, bounded control/evidence transfers, request journals and original pending-operation custody | Complete installed-source behavioral acceptance and vendor acceptance |
| Host models | Clock, source, Block, readonly 9p and network mechanisms; retained native state and original input lineage | Ordinary mixed-world service integration and complete conformance for each selected profile |
| QEMU | Process-separated native CPU/timer/control observations, original callback custody and matching corresponding source | Current ABI/license gates and full-scenario preservation |
| gem5 | Source-built x86/AArch64 models, process-separated controller, bounded journals and backend-bound continuation | Complete Linux device parity, common-node readiness and full-world preservation |
| Quantized execution | Nondeterminism propagation, explicit capabilities and KVM clock/timer mediation | Paced hardware execution and full KVM node qualification |

The Apache host and GPL-side QEMU/plugin remain separate processes, using
versioned socket/shared-memory protocols. QEMU publication retains the matching
complete corresponding source. Backend-neutral state cannot relabel a saved
backend implementation or upgrade observation data into execution authority.

## Verified checkpoints

### Shared runtime and public integration

Earlier committed stages exercise real public providers, connected-node routing,
original pending inputs, source retirement and fresh native continuations. The
CLI preservation stage also restarts through fresh daemon processes. Those
results apply to their recorded profiles and source revisions.

Original-owner capture budgets, bounded cleanup notification and collecting
restoration phases are committed in `dfd1c93c16`, with formatting separately in
`4feaa76dc2`. Normal four-crate/all-feature/all-target checking passes for that
stage. Fresh executables pass 83 selected controls: 62 Core, eighteen daemon and
three canonical-ACK integration cases, with no failures or ignored tests.
Earlier Waker-identity failures remain failures; the correction retains and
clones the same original Waker. These component controls do not qualify complete
native Capture or fresh restoration.

Provider storage projections and prepared Blob acknowledgement checks are
committed in `19b42f9d65`, with formatting separately in `15a7be2dec`. All 89
selected provider controls pass against the complete 435-file owned dependency
set. This checkpoint has no dependency on subsequent Core changes.

### Application compilation

The production compiler build and installed compiler verification pass. An
earlier mandatory application-target gate passes for the original-report,
deduplication and ARM-source checkpoint, compiling 167 test targets across all
48 selected application roots, including 69 integration targets. Independent
verification checks the actual compiler messages, captured source, artifact
roles and registered output. This gate compiles tests without executing them;
Crucible daemon runtime checks are separate.

The refreshed gate also passes for the original-owner preparation, Clock and
BLAKE3 checkpoint below. It compiles 167 fresh test targets across all 48
application roots, including 69 integration targets. Installed verification
checks the actual compiler messages, registered output, all selected source
pins and the complete production source filter over sixty local dependencies.
This gate compiles tests without executing them; daemon and native qualification
remain separate.

The gate also passes for the inactive-runtime checkpoint at `cda23fd9ec`.
It freshly compiles all 167 test targets across the 48 application roots,
including 69 integration targets, in 21 minutes 29 seconds. Independent
verification checks the installed Cargo messages, normal compiler profiles,
captured source, sixty-package local dependency closure and registered output.
The separate constructor failures below remain failures; this compilation gate
does not exercise inactive construction, activation or native preservation.

The gate also passes for the invocation and retained-storage checkpoint at
`c6de83ed87`. All 167 test targets freshly compile across the 48 application
roots, including 69 integration targets, in 21 minutes 50 seconds. Independent
review checks installed Cargo records, normal profiles, captured source and
registered output. The source filter contains the sixty-package local dependency
inventory; the installed messages contain artifacts for 59 of those packages,
with no standalone `crucible-harness` artifact. No test executable runs in this
gate, and the separate constructor failures remain unresolved.

### QEMU package

The ordinary QEMU package passes 589 upstream TAP checks, 44 project model/cost
fixtures and 274 static predicates. Installed verification checks its exact
binary/source pair, retained source, licenses and aggregate-only publication
policy. This does not establish success of the current ABI/license gates or
full-scenario preservation.

### gem5 packages and Linux boot

Commit `9decfccd3f` shares Linux fixtures, binds profiles to captured recipes and
filters Python bytecode from host source inputs. Independent installed
verification passes for the filtered package and corresponding source, including
ten registrations, thirty reports, 162 joins, 154 host entries and 47 recipes.
The native compiler is unchanged. Host capture is cache-free; unopened upstream
archives have not been independently scanned.

Commit `48eefd89ea` lets the Linux check package select a four-second simulated
horizon while preserving the checker's two-second default. Two fresh x86 Linux
boots reach PID1 and produce identical 20,717-byte consoles, 3,174,768,710,000
ticks and 317,480,064 callbacks. Independent installed verification checks both
raw consoles and receipts, source copies and registered outputs. The bounded
package and eleven modeled controls pass.

Both earlier two-second boot failures remain failures. The instrumented failure
reaches current tick 1,999,999,990,000 with the next event at the exclusive
2,000,000,000,000-tick horizon. The four-second result qualifies Linux/PID1 boot
only. It does not qualify common-node readiness, Capture, restoration, CPU timing
fidelity or device parity. The published birth digest agrees across runs; the
complete birth-event archive was not retained for independent recomputation.

Earlier separately qualified x86/AArch64 model profiles exercise source removal,
two fresh continuations, resource-root relocation and fresh recapture. Those
profile-specific results do not establish full Linux preservation.

The ARM Linux check also passes two fresh native boots. Both reach the two PID1
markers at tick 201,523,590,000 with 12,952,448 callbacks and identical
18,858-byte consoles. Installed verification checks both receipts and consoles,
the source copies and registered outputs. Loader geometry and console controls
pass. These results qualify the selected Linux/PID1 workload; common-node
readiness, capture, restoration and complete device parity remain outstanding.

### Original-owner preparation and Clock continuation

Commit `a836c25274` observes retained host and provider storage before
preparation, retains original query and Prepare owners, and connects Clock
continuation to the common node interfaces. Backend-neutral capability
accessors preserve the legacy positional encoding and compatibility diagnostics.
Normal five-crate, all-feature/all-target checking passes.

Fresh normal executables pass 312 selected controls: 104 Core, 154 provider and
54 daemon cases, with no failures or ignored tests. The Core and provider sets
retain all 71 and 120 earlier regression bodies respectively, alongside the new
storage, Prepare and Clock controls. Independent review verifies each crate's
source, executable, dependency and original wait records. These are
component checks; complete native Capture and restoration remain outstanding.

The full archive-admission case now passes in 87.83 seconds under its original
120-second limit. The earlier timeout remains a failed historical checkpoint.
A preceding executable also passed that archive case in 83.14 seconds, but
failed one positive fixture during setup: it selected the original 512 MiB
policy before reaching its intended missing-preparation refusal. The current
fixture explicitly selects the existing finite 768 MiB positive policy. Its
refusal assertions and the separate 512 MiB negative controls are unchanged.

### Native startup and retained protocol storage

Commit `fbad66af98` retains original executable, content, session and transport
owners through startup, and projects their serializer, frame and shared
allocation storage before allocation. Its shared-allocation quote uses the same
conservative header bound as the actual observer. The earlier exact-budget
custody test failed because the quote omitted that padding; its assertions and
resource ceiling remain unchanged and now pass.

Five-crate, all-feature/all-target checking passes for the startup changes.
After the quote correction, four fresh normal library-test executables pass
112 selected component checks and all 312 earlier regression checks: 424 test
instances covering 422 distinct tests, with no failures or ignored tests.
The archive group completes in 87.23 seconds under its original 120-second
limit. Independent review checks the complete 5,979-file source capture,
executables, dependency closures, original waits and exact earlier selectors.
The prior failed quote result remains recorded separately.

These checks cover startup and protocol components. Complete production
lifecycle routing, native Capture and restoration, the two deferred
installed-holder controls, and final-source application qualification remain
outstanding.

### Installed collecting scenes and lifecycle routing

The installed collecting-scene route reads a local manifest and its independent
ContentRef pin before endpoint admission. The `serve-complete-scene` command
retains the original Source, Host, content and coordinator owners in the installed
catalog. The version-twelve preparation request carries no manifest, resource
allowance or class grant. Preparation uses the existing owning actor and retains
original custody through refusal, failure and retirement; a collecting scene
does not become qualified by being installed or prepared.

The same stage connects original Host SDK startup, retained operation budgets,
complete Observe allocation records and the ordinary Clock qualification route.
Clock storage observation explicitly refuses catalogs containing an unsupported
complete-scene owner. The installed-scene holder accounts for its own retained
owners separately.

Normal all-feature/all-target checking passes for the contract, provider,
campaign, Core, daemon and CLI crates. Independent review verifies the complete
6,063-file source capture and actual compiler/dependency correspondence,
including reused unchanged metadata. This is compilation evidence; the 46 new
controls and one changed ignored native control remain unrun. The complete
application test-target gate and runtime qualification remain outstanding.

Two Host SDK constructor controls fail during fixture preparation, before their
constructor assertions. A separate diagnostic executable reproduces both
failures under the unchanged finite 768 MiB policy. Its first Source's native
quote refuses while adding the second coordinator-decode allowance:
742,759,697 + 268,290,528 exceeds 805,306,368 requested bytes. The coordinator's
encoded body is 113,202 bytes. That native quote reused the broader
restore-owner typed-layout bounds; the refinement below separates those paths.
These are quoted allowances, not measured physical allocations. The diagnostic
does not establish a successful constructor, native readiness or exact Capture.
Its instrumentation and raw evidence are excluded from the repository.

### Native quote precision and repeated preparation

Commit `b5e738f788` counts the native constructor's actual Value trees,
coordinator DTOs and separate validator allocations. Known Source and Admit
shapes retain every independent owner without expanding their encoded lengths
into arbitrary JSON bounds. Generic restoration accounting and the private
preauthentication parser remain unchanged. The whole-world calculation still
sums all three native participants under the existing policy.

Commit `f0185657d6` keeps a refused duplicate preparation from retiring an
already retained scene. Only a newly entered failed preparation initiates
retirement. Formatting is separate in `3d69f2f9b0`.

Normal six-crate, all-feature/all-target checking passes for these changes.
Independent review verifies the complete 6,065-file source, all sixteen changed
roles, compiler metadata and dependency coverage. Five fresh normal test
executables also compile for Core, provider, daemon, campaign and CLI. This is
compilation evidence, separate from runtime results.

Twelve new controls cover owned decode storage, exact and one-byte-short
budgets, unchanged contract bytes, duplicate custody, partial staging and
changed source files. A separate run passes eight provider controls and fails
one: the Value-only quote does not cover the conservative tree-root allowance
recorded by the owner observer for an empty object. A separate daemon run passes
the source-file drift control and fails both custody controls during scene
installation, before their custody assertions. The installer returns its
generic refusal; its cause remains under investigation. These failed phases
remain recorded. The missing object-root term needs a correction and fresh
qualification.

At that checkpoint, both constructor tests fail with `ResourceLimit` during
fixture preparation at this revision, before reaching their constructor
assertions. Both complete in a combined 6.14 seconds without exceeding their
execution limits. Their test phase stops at that failure before dispatching the
twelve new controls. The remaining constructor refusal is under investigation;
the earlier diagnostic does not identify its cause. Application compilation
remains held while this constructor failure is unresolved.

Commit `5a8c208928` corrects the missing object-root term for both Value-only
and native DTO decoding. It counts an independent tree root in each DOM phase,
including nested empty objects. Existing generic quote formulas, assertions
and resource limits remain unchanged; the counter's larger header is also
accounted. Formatting is separate in `9f2a3f84d8`.

Normal standalone Provider test compilation and sixteen focused controls pass:
the original nine controls, two nested-object controls and five related
metadata/layout/schema regressions. Independent review checks the actual
executable, dependency/source correspondence, original waits and unchanged
limits. These results cover that standalone dependency feature set; they do
not qualify the complete workspace or native startup.

A separately compiled diagnostic reproduces the two constructor and two
installer failures, with one source-drift control passing. The first Source's
SDK quote refuses at its final peak sum: 389,315,095 retained plus 646,573,512
transient requested bytes exceeds the unchanged 805,306,368-byte ceiling before
adding scratch. Hello handling contributes 418,418,084 transient requested
bytes. No full Source quote returns and the three-participant sum is not
reached. These are conservative requested-layout allowances, not measured
physical memory. The next refinement is reviewing their actual owner lifetimes.

Both installer diagnostics identify the private-parent-directory check.
The fixture uses default temporary-directory permissions rather than requesting
the required `0700` mode. Historical directory metadata was not captured, so
no actual mode is inferred from the diagnostic alone. Commit `29fd85764c` makes
the fixture request and assert the required private directory without changing
the production guard. Its paired public-parent
refusal and private-parent acceptance control now passes, together with the
installer controls below. Diagnostic instrumentation remains outside the
repository.

### Complete construction, capture archives and Fresh bindings

The next committed stage adds exact construction-storage helpers for Host nodes,
the common runtime, Oracle, scene and actor owners. The installed manifest
selects the explicit transfer, input-emitter and Fresh-allocation mechanisms.
Source bank reservation consumes its genuine original startup member before
allocation and retains partially created banks on failure.

Selected startup archives preserve the original allocation Report as a separate
content owner and evidence leaf. Their explicit outer version 13 and full native
version 14 readers authenticate both original cuts and the actual Report; legacy
archive framing remains available. Fresh-query binding follows the same completed
query and protocol frontier through assigned Prepare and receipt digests. These
helpers do not supply the missing installed restoration action or Source signer.
The ordinary Clock programme also retains real publication and damaged-archive
failure experiments without promoting an unexecuted conformance class.

Normal six-crate, all-feature/all-target checking passes for the combined stage.
Independent review verifies all 6,085 captured files, 841 selected roles and the
actual compiler dependency coverage of all eighty changed Rust files. Two prior
compilation failures remain recorded: a snapshot validator tuple mismatch, then
two stale storage getter calls and one test error conversion. Their narrow
corrections are included in the passing source. Formatting commits are separate.

The stage adds 38 test bodies and changes six existing bodies. Fresh normal test
executables compile for Core, provider, daemon, campaign and CLI. All 43 ordinary
new or changed controls pass, together with the two earlier object-root controls
on the same newly built provider executable: 45 passed, none failed or ignored.
The five ordered groups cover construction and archive storage, Fresh binding,
lineage compatibility, installer ownership and refusals, publication failures,
and retained Oracle/actor inputs. Source and executable checks remain exact
after each group.

The added native Clock case remains ignored pending genuine enrollment. At that
checkpoint, the two previously failing constructor controls still require the
lifetime-accounting work below. No current application test-target, native
Capture or complete restoration success is inferred from these component results.

Shared campaign APIs now use neutral replay-closure and fingerprint-bound names.
The lineage authoring key is `backend_build_identity`; legacy `qemu_build` remains
accepted, and conflicting dual values refuse before output creation. Persisted
lineage bytes and implementation-specific QEMU adapters are unchanged.

### Native startup allocation lifetimes

The lifetime-accounting stage through `43221c35a0` separates retained Value and
typed-object backing from temporary decoding, validation and canonicalization
work. Independent retained copies remain summed; only sequential temporary
phases share their maximum. The native Hello path reuses its already normalized
typed claims after checking correspondence and the existing authority guards.
Retained serialization backing is also checked before materializing output.

Normal six-crate, all-feature/all-target checking and three normal library-test
producers pass for the complete 6,087-file source. Nine selected storage and
handshake controls pass. Both unchanged Host SDK constructor controls still
fail with `ResourceLimit` during native-startup fixture finalization, before
their exact-budget and one-byte-short assertions. Their existing 768 MiB setup
policy, assertions and separate negative controls are unchanged. The precise
refusing row remains under investigation; these results do not qualify full
native construction or restoration. An earlier type-check failure remains
recorded separately from the corrected passing build.

The next runtime work must also resolve Fresh launch chronology. The current
Fresh-selected receive window requires Query before the ordinary Arm path can
proceed. Snapshot data helpers alone do not establish a reachable original
Capture or a settled restoration path.

### Inactive collecting runtime construction

Commit `d0552817e8` connects completed initial lifecycle custody to the actual inactive four-node runtime constructor. Three
separate Core-issued actions fund input owners, the collecting graph and nodes,
and runtime attachment. Each action binds the same installed holder, Source
roster and policy. The path shares the original reader and supervisor, converts
the same completed-Admit preparations, and transfers the original reserved
runtime slot through the provider into the retained actor.

Construction counts existing owners, new allocations, temporary work, observer
scratch and actual descriptor views before each phase. A whole-owner requery
checks growth afterward. Partial results and spent actions remain retained on
failure; unknown owner accounting refuses. The provider's borrowed activation
view is included in the static counter window before serialization. Supervisor
identity checks retain the actual original actor and operational handle without
extracting or cloning their payloads. Ordinary preparation behavior and finite
resource limits are unchanged.

Normal six-crate, all-feature/all-target checking passes for this source. All
twenty component controls pass: six Core, ten provider and four daemon controls,
with none ignored. They ran from three normal-profile library-test executables
built with a separate diagnostic overlay; the ordinary control bodies are exact.
Independent review verifies the source, executables and original test logs.
The overlay's five temporary probes are excluded from these commits.

Both separate constructor diagnostic cases failed during fixture startup
reservation, before their assertions. Adding the second Source's publication
allowance exceeds the installed memory limit; these values describe requested
layouts, not measured RSS. The SDK queries returned successfully, and the third
Source was not reached. Successful inactive construction and whole
fit remain unqualified, and earlier failed results remain recorded.

Arm, readiness, activation, Observe, Capture and restoration remain separate
qualification gates. The original-execution versus restoration-target launch
purpose also remains an outstanding prerequisite for the later native route.

### Native invocation ownership and retained backing

Commit `1cb7ed6616`, with formatting separately in `c6de83ed87`, retains native
invocation phase and storage through the original protocol owners. It adds
explicit original-versus-restoration invocation data, coordinator backing
accounting, publication lifetime accounting and full cold invocation readers.
Independent retained owners remain summed, and every later action still needs
its original admission and currentness checks.

Normal six-crate, all-feature/all-target checking passes over the complete
6,125-file source capture and 891 selected roles. Three fresh normal library-test
executables also compile. Independent review checks compiler profiles, complete
dependency/source correspondence and preservation of the original dependency
cache. The separate production binary still needs a fresh linked qualification.

The focused runtime sequence executes 46 component controls: 45 pass and one
publication control fails, with none ignored and no recorded resource-limit
violation. Its failed assertion expects actual Observe backing to exceed the
older conservative receive quote. A reviewed test-only correction instead
observes the empty-map root independently and checks its exact carry term while
preserving the actual-capacity upper bound. That correction remains outside this
checkpoint. The sequence stops at the failure; its remaining cold-data and daemon
groups are unrun.

A separately admitted run of the two unchanged constructor controls fails both
cases during fixture native-startup finalization, before their intended
exact-budget and one-byte-short assertions. The pair completes in 6.31 seconds
without a recorded cap violation. The current refusing numeric row remains under
investigation. These results establish neither successful construction nor
native Capture or restoration; earlier failed results remain recorded.

### Invocation Capture and restoration inputs

Commit `241370cb01`, with formatting separately in `2a9e92673d`, adds invocation
snapshot framing and declarations, archive/report correspondence, restoration
mapping and SDK upload construction. Existing legacy refusal guards remain in
place. These interfaces do not yet complete the installed restoration action.

Normal six-crate, all-feature/all-target checking passes over the exact
6,149-file source capture and 916 selected roles. Three fresh normal library-test
executables compile. Independent review checks their complete source/dependency
correspondence and preservation of the original dependency cache.

The selected runtime controls report 83 passed and two failed, with none
ignored. The passing controls include the corrected empty-map publication
assertion and the previously unrun cold-data and daemon groups. Both constructor
controls fail during fixture native-startup finalization with `ResourceLimit`,
before their intended budget assertions. No execution cap is exceeded. The
aggregate result remains a failure; these results establish neither native
Capture nor complete restoration.

A separate diagnostic on the preceding invocation checkpoint identifies a
requested aggregate of 892,017,380 bytes against its unchanged 805,306,368-byte
policy while adding the second Source publication allowance. The third Source
is not reached. These are requested storage allowances, not measured RSS, and
the numeric probe has not been rerun on the Capture checkpoint.

A prospective combination with the subsequent gem5 additions also passes normal
six-crate, all-feature/all-target checking over 6,238 files and 1,013 selected
roles. That check covers changed Rust and included JSON compiler inputs; its
Python and Nix additions have source review only. This combination is not yet
committed, linked-test qualified or native qualified. Its result does not resolve
the constructor failures or complete the production restoration path.

### Integrated Linux profiles and startup barriers

Commits `765dcd657a` and `45d75a9793` integrate the gem5 x86 root profile,
ARM continuation routing, original Host finalization barrier and separate native
launch-decoder accounting. Normal six-crate checks and three linked test
producers pass for that stage. Its focused checks pass 59 gem5 Rust cases, eight
Python cases, seven Host barrier cases, three launch-projection cases and eight
measurement cases. These are component results; neither installed model
binding is present in those test executables, and complete native readiness,
device parity and preservation remain outstanding.

Commits `2895360302` and `8ef77183ef` give generic executable measurement a
256 KiB streaming bank while retaining the selected Prepare path's 8 KiB bank.
Nine normal Provider controls pass, including the exact boundary, interrupted
read, growth, metadata and cross-bank content-reference cases. Independent
review qualifies the successful normal Provider Cargo artifact stages; their outer
postvalidator failures remain failures. The imported worktree matches all
6,241 captured source bodies and modes, including 1,017 selected roles.

A separate diagnostic still fails both constructor fixtures before their
intended assertions. At the second Source it requests 892,021,308 bytes against
the unchanged 805,306,368-byte policy. The third Source is not reached. Native
Hello and private initial parsing are the dominant quoted arms, at 163,084,470
and 181,652,752 bytes respectively. These requested allowances are distinct from
RSS. Parser admission and genuine multi-owner restoration remain in progress;
neither the hashing improvement nor a smaller component quote establishes fit.

## Work in progress

Packet startup/report, capture and restoration storage accounting is committed
in `196c68fd91`, with formatting separately in `5f2586267f`. Normal five-crate,
all-feature/all-target checking passes. A fresh daemon executable passes 34
selected controls, including all five corrected startup cases, two new
fixture/policy controls, original finite-bound negatives, and alias/drift checks.
At that checkpoint, the full archive-admission case exceeds its original
120-second budget in isolation. The later passing result is recorded above.

An earlier original-report/storage stage passes 196 selected controls: two
campaign, 120 provider, 71 Core and three integration cases. Its five startup
failures and archive timeouts remain recorded as failures at that stage.

The startup fixture originally selected a 512 MiB policy. A recorded census at
a 16 KiB negotiated message window projects 606.9 MiB for that checkpoint's
actual executable and retained reports. Its diagnostic confirms refusal after
restoring the original 512 MiB policy. The positive fixture now selects a finite
768 MiB policy; its runtime cases pass. The explicit 64 KiB-window/512 MiB
negative and production accounting remain intact.

A later archive run finishes with a missing immutable Host continuation definition.
The fixture now supplies the pinned definition, checks transitive content closure,
and explicitly accepts all four actual unqualified participants. New controls
reject missing or mismatched definition bytes, omitted participants, extras,
duplicates and noncanonical ordering. The later full admission test passes;
complete native Capture and restoration are separate outstanding gates.

Archive validation shares completed full hashes of exact aliases within one
pass while retaining every descriptor/path fence and sticky refusal. The next
pass hashes again. Ten aliases require one full measurement per pass, and all
four alias/inode/media/drift controls pass. Full-file streams now use 256 KiB
blocks, with the complete scratch allocation accounted at each owning boundary.
A matched mechanics experiment measures a 23.65% mean reduction against 64 KiB
blocks with identical framed hashes. This does not establish daemon or Linux
boot speedup. Commit `95297b8681` additionally selects the pinned BLAKE3
library's runtime-detected intrinsics while retaining framed hash bytes. Thirty
balanced three-way rounds over the same 160.8 MB file measure median hash times
of 77.11 ms for the original 64 KiB/pure configuration, 58.01 ms for 256 KiB/pure,
and 35.56 ms for 256 KiB/intrinsics. The combined reduction is 53.89%; all ninety
full hashes and 55 boundary vectors match. These cache-hot hashing measurements
do not establish an overall Linux-boot improvement or an ARM-host result.

The installed collecting-scene stage adds original allocation admission before
native startup, Prepare/report publication, same-owner query budgets, the
ordinary Clock qualification route and mixed-world service wiring. Compilation
and source review do not establish execution or native qualification. Missing
original owners, unknown storage and unavailable baseline/native prerequisites
continue to refuse.

## Known gaps and exit criteria

Completion requires the full [qualification plan](qualification-plan.md),
including:

- Complete native Capture, original source/resource removal and two independent
  fresh-world restorations with exact continuation.
- Production backend routing, mixed native execution, device parity and public
  vendor acceptance for every advertised operating mode.
- Final-source application test-target compilation, relevant ABI/license gates,
  and adverse state, timing, ownership and causality tests.
- Paced KVM qualification. Its selected CREATE still refuses before allocation,
  with only one of eleven required coverage bits implemented. Complete
  DMTCP/kernel qualification also remains outstanding.
- A clean final strict Clippy run. An earlier checkpoint stopped at 59 provider
  errors, mostly unused methods and fields awaiting their production callers;
  the current source still needs strict qualification. The four-vCPU ABI
  timer-deadline divergence also remains unresolved.
- Quiet final Linux comparisons against fresh origin/master, plus same-binary
  TCG+icount versus SIM with both set to 50 ps/instruction.

## Performance results

| Measurement | Result | Scope |
| --- | --- | --- |
| gem5 address-range predicate | 5.26x median improvement; one million allocations removed per round | Five matched lookup rounds with identical checksums |
| gem5 thread-list transitions | 2.55x median improvement; 500,000 allocations removed per round | Five matched list-mechanics rounds |
| QEMU/plugin Linux boot, six matched runs | Median 29.50669 to 29.54280 seconds (+0.12%) | Frozen controller, same guest and 50 ps/instruction; effectively flat |
| Full-file hash stream, 64 to 256 KiB blocks | 23.65% lower mean time | Thirty matched rounds over the same 160.8 MB file; identical framed hashes |
| Full-file hash stream and runtime-selected BLAKE3 intrinsics | Median 77.11 to 35.56 ms; 53.89% lower time | Thirty balanced three-way rounds; all ninety full hashes and 55 boundary vectors match |
| Generic executable measurement, whole-file buffer to 256 KiB stream | Mean 74.13 to 37.31 ms; 49.68% lower call time; mean process peak RSS 152 to 19.05 MiB | Thirty alternating pairs through the real public APIs; all sixty complete ContentRefs match |
| Maximum-frontier component pair | 3.37x improvement | One matched component pair |
| Immutable-domain component pair | 47.87x wall and 55.92x child CPU improvement | One matched component pair |

Component results do not add up to an overall Linux-boot speedup claim. The final
comparison must use the same guest bytes, clock policy and workload, preserve
complete deterministic witnesses, record interventions and retain all samples.

The generic measurement comparison uses the same cached 160,758,800-byte input,
compiler settings and reachable hash implementation. Whole dependency feature
graphs differ; independent review checks the reachable source, five BLAKE3
runtime dependencies and code/data/relocation correspondence. Separately waited
process CPU falls from 76.67 to 40.14 ms. The earlier 8 KiB streaming experiment
remains a negative result: mean call time rose from 71.72 to 193.96 ms despite
lower RSS. All raw samples, compiler evidence and binaries remain local.
