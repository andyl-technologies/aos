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

The gate also passes for the clock, observation-range and allocation-layout
checkpoint at `8309976a6e`: 167 test artifacts across 48 application packages,
including 69 integration targets. Independent review verifies the registered
output, actual compiler messages and all 4,126 included Rust/Cargo files against
that commit. This is compilation only and excludes the later selected-executable
buffer change and native runtime execution.

The refresh at `5285b8095f` also passes, including the selected-executable bank
change: all 167 test artifacts freshly compile across 48 application packages,
including 69 integration targets. Its captured Rust/Cargo payload matches all
4,126 included files at that commit. This remains compilation-only evidence and
excludes the subsequent ordinary packet and transport routing changes.

The refresh at `0e8630d1d1` passes for the journal-reservation checkpoint,
including the intervening routing, Hello and first-Observe changes: all 167 test
artifacts freshly compile across 48 application packages, including 69
integration targets. The captured source matches all 4,131 included Rust/Cargo
files at that commit. Independent read-only review verifies the registered derivation and NAR hash,
all 7,098 captured source files against the commit, and the installed compiler
messages reporting the ordinary test profile and successful completion. This
remains compilation-only evidence;
it excludes the later Input17 transport change and native execution.

The Input17 refresh at `e483be71b9` also passes: 167 newly compiled test
artifacts cover all 48 application packages and 69 integration targets.
Independent review verifies the registered derivation and output, recomputes
the actual NAR hash, and matches all 7,105 captured files (4,137 Rust/Cargo)
to the commit. This is compilation-only evidence and excludes the subsequent
startup-order changes and temporary diagnostic probes.

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

The current x86 Linux-root capture witness follows bounded progress grants until
its first UART publication. Commit `663c572a9b` permits at most ten million search
events across 39 grants, each limited to 262,144 events, while retaining the
100-millisecond simulated horizon and existing native wall limit. The earlier
single-grant failure remains preserved: it exhausted its event budget before any
UART output.

The installed profile check passes with the first UART byte (`[`) at
44,103,690,000 ps and event ordinal 4,410,378. Its source-bound assertions capture
the pending receipt, remove the original resources, restore into two distinct
fresh process groups, recapture both branches and compare eight future
publications. Independent review verifies the installed summary, both process
anchors, source and 27 artifact bindings. The installed summary does not retain
the raw images, individual grants or complete suffix arrays for a separate
post-build comparison.

This qualifies the selected opaque capture mechanism. Execution admission,
common-node readiness, complete Linux preservation, device parity and CPU timing
remain unqualified. The 139.34-second package check is validation time, not a
boot performance measurement.

Commit `e94a5faea0` strengthens the ARM Linux-root capture witness with an
explicit rendezvous. Both restored branches must finish recapture and remain
alive in distinct, authenticated process groups before either branch continues
its suffix or shuts down. Existing source-removal, pending-receipt, eight-future-
publication and reclamation assertions remain in place.

The new installed profile check passes, including 83 Python unit cases.
Independent review verifies both simultaneous process anchors, all 33 immutable
artifacts, 168 configuration files and the new source/foundation bindings. The
native compiler output is reused; the 74.06-second package check is validation
time. This qualifies the selected opaque restoration mechanism. Common-node
readiness, full-world preservation, device parity and CPU timing remain
unqualified.

A fresh x86-bound production fixture compiles but fails during initial native
preparation, before readiness, Arm or World publication: zero passes and one
failure. The retained error reports that the native owner exited; its exact
exit status is unavailable. Source tracing identifies an inherited descriptor
number ceiling of 256, imposed by the temporary test runner, that conflicts
with DMTCP's fixed descriptors above 820. That incompatibility is not a proven
cause of the observed exit. Source tracing also finds a missing temporary-directory
route. The failed run remains unqualified; the package witnesses do not establish
production-path success.

Gem5 launch, restart and retained-audit commands now share an independently
reserved construction budget. Each command is charged before owning its argument
and environment buffers; failure and completion do not renew the budget. Fresh
restoration requires a new caller-owned reservation. Both architectures pass
`TMPDIR`, `DMTCP_TMPDIR` and the working directory from the owned temporary root.
The restored Python controller also updates the native environment, clears the
cached Python temporary directory and changes its working directory before
rebinding the model.

The documented Cargo dev shell passes six-crate, all-feature/all-target checking
for this stage. On the worktree source, 115 gem5 Provider unit tests pass, including
all three new command-budget controls; three native controls remain ignored.
Both new Python temporary-root controls pass. The subsequent profile-v2 stage
below records the fresh package builds. These component results do not establish
native readiness, complete Capture, device parity or restored execution.

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

### Retained-owner restoration and selected startup

The checkpoint through `19d6d228d1` retains the original restoration owners,
rechecks the complete ownership set after transfers and keeps stage failures
terminal. Provider storage projections and selected native startup preparation
account for simultaneously retained frames, decoded values and launch banks.
The retained-owner fixture negotiates bounded evidence through the existing
codec and controller checks.

Normal six-crate, all-feature/all-target checking passes. Three fresh normal
library-test executables consume the captured source, including all 141 changed
roles. All 36 selected restoration controls pass, with no failures or ignored
tests, in 7.42 seconds. Independent review verifies source bodies and modes,
executable dependency closures, exact test selectors and all original process
waits and releases. Earlier fixture setup failures remain recorded separately.

The separate pair of unchanged Host SDK constructor tests still fails with
`ResourceLimit` during fixture finalization, before either constructor assertion.
Both failures reproduce on this checkpoint under the original 768 MiB policy;
the diagnostic run completes in 6.12 seconds. These fixtures launch no child
backend. The restoration controls do not establish constructor success, native
readiness, complete preservation or device parity. Connected native activation,
content upload and common restored-world installation remain in progress.

The follow-up through `06c951db24` counts three shared private-bootstrap/native
retained owners once in the combined startup sum. It authenticates the actual
inputs and complete rows, preserves the private launch buffer's spare capacity
and keeps independent native copies and Invocation additions fully charged.
Missing intersection metadata keeps the full sum; foreign metadata refuses.
Six-crate checking and three fresh library-test producers pass. All 39 selected
restoration controls pass, including the three new accounting controls, with no
failures or ignored tests in 7.70 seconds.

The unchanged constructor pair still reports two `ResourceLimit` failures at
fixture finalization under its original 768 MiB policy, before its boundary
assertions. This run also records a descriptor-census permission error and a
SIGTERM cancellation request in the test harness; signal delivery is not
established. Those observations remain separate from the literal assertion
failures and require investigation. The accounting change
does not establish constructor success or native readiness. Separately, the
connected activation/upload provider passes all-feature/all-target checking
after compiler corrections; the combined restored-world route remains under
integration and review.

A temporary probe of the unchanged fixture identifies an initial admission
failure while adding the third member: 803,938,934 plus 206,716,469 requested
bytes exceeds the unchanged 805,306,368-byte policy by 205,349,035 bytes, without
integer overflow. Its original failure remains a failure; the probe reaches no
SDK constructor assertions. These are requested-storage accounting values,
not physical RAM measurements. Phase lifetimes and projection bounds are under
investigation. Probe sources, binaries and raw evidence remain outside Git.

The restoration installation and activation checkpoint is committed in
`2c07b8f`, with formatter output separately in `938e5918ec`. It connects retained
runtime and scheduling custody, authenticated native activation and content
upload, and publication storage admission. Paused originals and partial failure
owners remain retained. The installed World dispatch and first Observe
continuation are separate work in progress.

Six-crate all-feature/all-target checking and four fresh normal library-test
executables pass. All 90 selected component controls pass with no failures or
ignored tests: 87 Core/provider/daemon controls in 11.66 seconds and three CAS
controls in 4.10 seconds. Independent audits verify complete source bodies and
modes, actual executable dependency closures, exact selectors and all 94 child
waits and releases. The CAS fault-instrumented build exercises an explicit
publication refusal; it does not qualify successful directory publication.

The storage-lifetime refinement is committed in `79f872e1a7`, with formatting
separately in `fac93465ae`. It preserves all retained owners and the whole-node
sum while separating acknowledgement, frame-preparation and launch-validation
workspaces whose lifetimes do not overlap. Six-crate checking and four fresh
normal test executables pass. All 98 selected component controls pass with no
failures or ignored tests: 95 controls in 11.86 seconds and three CAS controls
in 4.05 seconds.

Both unchanged SDK constructor controls still fail with `ResourceLimit` during
original startup finalization, before their constructor assertions. The 768 MiB
policy remains unchanged. A fresh independently audited temporary diagnostic
identifies the same initial third-member addition: 720,282,094 plus 188,954,635
requested bytes exceeds 805,306,368 by 103,930,361, without integer overflow.
The failing subtotal is 101,418,674 bytes (96.7 MiB) smaller than the earlier
probe, but later finalization and publication additions remain unreached.
The original diagnostic still fails; both child waits release cleanly. These
are requested-storage accounting values, not measured RAM. Neither the
component controls nor this reduction establishes constructor fit, native
restoration, device parity or runtime performance improvement.

### Restored World activation and first observation

Commit `00db7a389c` connects whole-roster World activation and the first restored
Observe continuation, with layout changes separately in `9264dca2c3`. The route
retains the actual World, original Source and controller owners, complete roster
and scheduling custody. Admission precedes preparation and publication; failed
attempts retain their partial owners and consume their original attempt rights.
Selected outcomes authenticate the current runtime and complete terminal and
scheduling evidence before acceptance.

Normal six-crate, all-feature/all-target checking and three fresh normal
library-test producers pass. All 131 selected Core, provider and daemon controls
pass with no failures or ignored tests in 15.16 seconds. Independent review
checks the captured source, executable dependency closures, exact selectors and
all 134 original child waits and releases. Three earlier CAS controls retain an
unchanged 48-file dependency closure; their execution remains a historical
result, not a fresh run on this checkpoint.

These are component results. The unchanged SDK constructor failures above
remain unresolved and were not rerun here. Complete native Capture, restored
execution with nonempty operations and inputs, fresh recapture, device parity
and final-source application qualification remain outstanding.

### Original canonical-output bounds

Commits `4ef69f432b` and `66e8fab2de` narrow only the canonical-output banks for
selected original Observe replies and their restricted first query. The pinned
formatter emits at most 25 bytes per number; its larger 132-byte scratch buffer
remains charged independently. The new conservative output bound is 32 times
the raw extent. Generic parsing, retained owners, correlation and full-cap
validation remain unchanged. At a 16 KiB extent this removes 13.4 MiB from each
affected returning-work term; other simultaneous phases can still determine the
whole peak. This is requested-storage accounting, not measured RAM or speed.

The same five Rust post bodies pass standalone six-crate all-feature/all-target
checking and three fresh normal library-test producers. A subsequent prospective
first-report/lifecycle combination passes 140 selected controls, including all
four new canonical-output controls, then fails its new three-Source fixture
with `ResourceLimit` during startup finalization. Two lifecycle controls are
unrun. Independent review verifies all 144 original waits and releases, source
and executable closures. The earlier standalone runtime stopped on descriptor
observation after 35 accepted passes; it remains a failed checkpoint.

At this checkpoint only the five canonical-output files were committed. The
first-report and lifecycle changes were subsequently integrated in the restored
suffix stage below. Neither earlier checkpoint establishes a full 135/143-control
pass, constructor fit or native restoration.

### Restored suffix bootstrap and current startup controls

Commits `88026454cd` and `11565e6dec` integrate the first-report/lifecycle changes,
restored-suffix bootstrap and retained Host custody. Ordinary six-crate,
all-feature/all-target checking passes in 2 minutes 19 seconds. The current Core
executable passes thirteen distinct suffix/continuation controls; the current
Provider executable passes seventeen. An initial Provider run failed three
fixtures because their binding purpose used the owner-binding domain instead
of the required node-binding domain. Correcting that test fixture preserves the
strict production validator; all seventeen controls then pass.

The 768 MiB positive startup setup was a test assumption, not an RFC or product
ceiling. A test-only named 2 GiB setup allowance lets controls reach their exact
and one-byte-short boundaries without changing the production resource policy.
The explicit 64 KiB-window/512 MiB refusal remains unchanged. With that fixture
change, the daemon startup selection passes 25 controls and fails three. The two
Host SDK controls still refuse with `ResourceLimit` while quoting their actual
constructor budget. The diagnostic's initial-report quote is 451,419,499 bytes,
which fits its restored 512 MiB policy; its old assertion that this quote must
exceed the policy is stale. This quote covers a different phase from the earlier
partial native-finalization probes and supplies no savings comparison. The
corrected diagnostic requires admission to match the actual observed quote and
retains birth, attempt and currentness checks.

A temporary ordinary Cargo diagnostic locates both SDK refusals at the third
member's aggregate ceiling: all individual Source quotes succeed, but the
2,359,983,863-byte aggregate exceeds 2 GiB. This conservatively reserves full
outstanding commitments and includes known overlaps; it is not unique live heap
usage. The two SDK boundary controls alone now use a finite 3 GiB setup allowance
before installing their actual derived exact or one-byte-short policy. Other
positive fixtures stay at 2 GiB. The temporary instrumentation is removed.
Commit `f896cea8c7` passes all 28 startup controls, with zero failures or ignored
cases, in 97.67 seconds. Production policy and all fixed negative assertions
remain unchanged.

These results do not qualify recurring native scheduling, complete Capture or
fresh-world recapture. The actual recurring Observe producer and host scheduling
caller remain under integration.

### Installed gem5 qualification-source separation

Commit `9545118` and formatting `fc7d89d669` introduce explicit installed profile
v2. Build-only qualification inputs bind the executed temporary-root test and
actual controller separately from the unchanged ARM33/x8627 runtime artifact
rosters. Legacy profile v1 remains explicit and rejects the v2 namespace. Native
witness, coexistence and capability guards remain unchanged. Independent source
review finds no blocking issue. All 119 gem5 Provider unit tests pass, with three
native tests ignored; all three new Python format/provenance tests pass.

The fresh ARM profile package passes its actual checks and emits profile v2.
The first fresh x86 profile installation fails its strict helper-binding check:
the witness includes the executed build-only check as a thirteenth runtime
helper. Commit `94a6ec77bd` moves that source out of the closed runtime directory
before the witness executes, retaining its separately verified qualification
receipt and installed source. The twelve runtime helper bindings and strict
reader guard remain unchanged. All five Python provenance controls pass, and
the fresh x86 profile rebuild passes.

A first compile-time-bound Rust rerun passes 118 cases and fails one because the
invocation supplies the wrong ARM manifest filename. The actual x86 installed
profile check passes. The corrected invocation uses the installed
`arm-model-profile.json`. The subsequent full Provider run passes both actual
compile-time-bound installed loaders and all 1,022 selected unit cases, with
thirteen native/installed controls ignored. An installed mechanism profile alone
is not a complete common-node or device-parity result.

The ordinary Cargo workflow also runs the previously failing, genuinely native
x86+Clock initial lifecycle fixture. It passes with one actual test, zero failures
and zero ignored cases in 47.85 seconds, after 4 minutes 13 seconds of codegen.
The assertions reach real native preparation, two-owner admission, Arm, prepared
coordinator construction, durable World activation and original process-group
reclamation. Both fresh v2 profile paths are compiled into the executable. This
qualifies that selected initial lifecycle, not Capture, restored continuation,
ARM native execution, device parity or a Linux boot benchmark.

### Cargo source packaging correction

The mandatory application test-target build fails on a real packaging error:
the source filter removes `src/.../target/phase.rs` because it treats every
directory named `target` as Cargo output. Commits `80640d187b` and `19e8c3e3b2`
share an ancestor-aware predicate across application, Crucible and dependency
artifact filters. Rust source modules named `target` survive; outer build output
and existing runtime-state exclusions remain pruned. The Cargo artifact
regression check passes, including dummy-source preservation and actual reuse of
the locked dependency. Its fixture hash changes only for the current Cargo
checksum-format comment; the locked archive and package bytes are unchanged.
The release-manifest fixture also models the current required paired QEMU outputs
without building or executing an emulator. Its ordinary build now reaches the
strict Provider Clippy dependency and fails on 129 diagnostics, including unused
integration APIs and mechanical lint issues. No lint guard is disabled. A narrow
cleanup addresses 27 reported sites while production integration continues; it
has not yet passed strict Clippy. The restarted full application test-target
build passes, compiling 167 test artifacts across 48 application roots, including
69 integration targets. This build uses the source-filter/profile-v2 checkpoint
before the subsequent recurring-Observe and final fixture changes. Final-source
application qualification remains outstanding.

### Recurring observation and historical alias validation

Commit `a037f51186` implements the native recurring-Observe receive, independent
admission/debit, current proof production and sent-prefix/ACK completion path.
Independent review catches a real inherited prerequisite bug: the actual prefix
builder puts its Response before the evidence-transfer requests, while completion
selects the last frame. Arm/World, first Observe and recurring Observe now select
the unique fully correlated Response at its actual retained index and validate
the complete sent/ACK prefix. The real prefix-builder regression also retains
refusal under insufficient negotiated correlation capacity.

Commit `d564eadef9` integrates the paired host/Runtime/Source/Node and concrete
daemon caller. They separate immutable admission/full census from mutable dispatch,
retain actual first evidence separately from fresh proof, and report unknown
effects after publication. Independent review finds no blocking issue. Ordinary
six-crate, all-feature/all-target checking passes after integration fixes.
The actual four-owner capture-to-restoration control remains unqualified.

A broader Provider run initially passes 1,012 cases and fails seven, with thirteen
ignored. It exposes an actual historical alias defect: a failed group can consume
its final row yet leave the completeness check accepting unfinished state.
Commit `28b89e7` rejects any in-progress summary while retaining the existing
unvisited/trailing-row guards and adds focused incomplete-group coverage.
Other corrections preserve typed-history declaration order, construct the real
Discover schema, fund the test's full lifecycle proof bank, and test both
preserved and tightened nonrenewed deadlines. Production capacity guards remain
unchanged. The corrected full Provider run passes 1,022 cases with zero failures
and thirteen ignored in 19.16 seconds, using both fresh installed profile bindings.

These component passes do not replace the real four-owner roundtrip. Integration
also identifies missing original actor lifecycle forwarding, durable Complete
result publication/enrollment and the operator's authenticated fresh-target
installation link. Those production paths and their native fixture are being
implemented; no synthetic Window or committed-result stub supplies qualification.

The current Core suite initially records 1,713 passes, eight failures and 32
ignored tests. Five failures require the installed reference-provider executable
at runtime; rerunning those five with its genuine source-built binary passes all
five. Three expose a real prelaunch descriptor-census dispatch error: the launch
reservation asks the launched guard for an executable that does not yet exist.
Commit `617ab7bd72` adds a reservation-specific borrowed census. The corrected
full Core suite passes 1,723 tests, with zero failures and 32 ignored, in 17.01
seconds using the real installed provider; the later complete-coordinator Source follow-up
rerun also passes all 1,723 in 18.03 seconds. The launched guard still refuses the
unlaunched shape; neither a fake process nor an executable is inserted. All six
new current-observation and retained-dispatch controls pass. The later
fresh-runtime, facet and recorded-repeatability checkpoint passes all 1,728 Core
tests, with zero failures and 32 ignored native controls, in 5.82 seconds using
eight test threads. This is correctness validation, not a performance comparison.

The ordinary native Complete four-owner initial-scene fixture compiles and runs,
but refuses before Child creation. Its complete immutable coordinator declaration
is 171,918 bytes, above the existing 131,072-byte installation limit; the template
and local declaration are individually within that limit. This is not a guest
execution or capture result, and a larger transport buffer alone cannot fix it.
Commit `db30acf3fa` derives a distinct 393,324-byte full-installation bound from
three separately bounded local selections, the Host selection, the unchanged
Control template limit and the exact wrapper. Each component is independently
checked; Connected4, Control and template bounds remain unchanged. The Provider
suite passes 1,024 tests, zero failures and thirteen ignored in 19.32 seconds
before the final two coordinator parser alignments; the current reference
provider rebuild passes. Follow-up `4e839e0e9d` corrects the same inherited
whole-installation mismatch in the Core constructors and measured daemon roster.
Actual installed runs expose those additional checks before Child creation.

Commits `4f5c5e3162` and `1ad448e99b` add retained original actor lifecycle,
concrete durable Complete publication and the explicit ticketed fresh-target
installer. Six actual lifecycle, content-bound and manifest controls pass in
11.42 seconds. Six-crate all-feature/all-target checking passes before the final
stored-publisher forward; the current daemon test target also compiles. The
current positive fixture includes a separately measured provider, three genuine
stored grants, Capture and selected reload, but has not yet passed its owning
native path. The initial two failures occur during installation before Child
creation. Commit `0fe7470ad1` validates the optional advertised restoration grammar
without selecting fresh startup from declarations; installation then succeeds.
Both selected native tests still fail during preparation, with zero passes and
two failures in 21.70 seconds. Temporary diagnostics locate the refusal in launch
resource admission, before baseline construction. Reclamation assertions pass.
Its finite content budget counts three actual peer artifact reads,
one Host artifact read and an explicit metadata allowance, preserving the older
fixtures and refusal limits. The publisher remains retained through reclamation.

A separate fresh-holder baseline driver retains the same cleanup supervisor.
Commit `a48cc8c721` corrects its native-slot reservation and descriptor census;
four focused schema and supervisor controls pass in 6.38 seconds. The broader
Complete daemon suite passes 109 tests with zero failures and two explicit native
tests ignored in 249.19 seconds after these corrections. No fresh native
qualification is claimed.

Commit `717e7a7093` adds construction projections for the same archived Host and
callback-free transfer of the actual three prepared peers, Host and cleanup slot
into a retained preparation. Six-crate all-feature/all-target checking and two
geometry/missing-owner controls pass. These helpers do not create graph admission
or restoration authority. Commit `fa60f20e67` supplies the genuine retained-owner
caller and early-failure cleanup, with formatting separately in `7517198ad1`.
Six-crate all-feature/all-target checking passes. Twelve selected controls pass;
the same run's real native startup case still fails while projecting the
FreshCompletedAdmit13 publication, before Child creation. Its original-observation
projection passes, and outer resource credit is not exhausted.

Commit `8471bf6d02` exposes the actual selected Complete CNP preservation
description while retaining generic Capture refusal and ticketed capture checks.
Its three pure controls pass in the full Core suite. Live admitted acquisition
remains part of the currently failing native fixture.

Commit `768237293a` shares the real effective-repeatability calculation between
admission and recorded-request recovery, including causal and shared-owner taint.
A genuine connected-world restart test passes: the same completed request returns
identical result bytes twice, preserves five durable namespaces and remains
ineligible for deterministic cache reuse. The paired fresh-owner declaration
control also passes; both finish in 5.31 seconds. These results do not qualify
complete native preservation. Restored nodes still need the ordinary operation
path beyond current-state Observe, including pre-effect admission, progressed
native evidence and durable outcome publication.

Commit `65edc1c024` adds the provider side of bounded recurring Producer work:
separate completed and post-retirement correspondence, independently spent native
and ingress scopes, retained SDK attempts and method-aware ACK completion. The
Provider suite passes 1,031 tests with zero failures and thirteen ignored in
10.06 seconds, including seven new controls. Its main action selector remains
closed until common-runtime admission and the actual durable publisher are
connected. Component recurrence does not qualify the full installed restoration.

Commit `c9ac1ea31e` separates FreshCompletedAdmit13 receive and publication
temporary peaks while retaining their simultaneous owned banks. The three
full-format launch projection controls pass without changing the existing
limits. Commit `db3592775b` prepares one immutable launch tuple for distinct
code-validation and fresh-target owners. Its real constructor control passes,
including changed-token, changed-schema, same-authority and occupied-output
refusals. The separate sibling-declaration control also passes. The combined
run has two passes and one native startup failure in 315.85 seconds.

Commit `7984660b5a` separates sequential native and report temporary peaks while
retaining simultaneous owned banks. The real full-roster, three-source no-Child
admission control passes against the unchanged 4 GiB limit. Native admission
then reaches a projected 3,342,478,453 bytes; report projection is 2,417,245,929
bytes. These are admission projections, not measured resident memory. The real
startup progresses to SDK admission, where it still refuses `ResourceLimit`.
Temporary diagnostics were removed after each run.

Commit `760970029d` records actual retained SDK request, raw response and typed
response history without granting restoration or Capture authority. The Provider
suite passes 1,039 tests, zero failures and thirteen ignored in 9.30 seconds.
Commit `9c9d5530bf` joins restored Producer admission, real C-input lineage,
durable publication, retirement and fresh observation. The two-world fixture now
requires a nonempty Producer result in each fresh world and removes the original
mutable scene/blob/reference stores before either load. Its exact selected
legacy Capture schema is authenticated against the complete actual binding;
the new settled-history family is not admitted by that compatibility path.

The joined tree passes 1,741 Core tests, zero failures and 32 ignored in 5.69
seconds. The preceding all-feature/all-target check passes across six crates.
The code-only schema-roster optimization retains full current-file checks before
and after the existing definition callbacks, including callback failure, with
an unchanged individual-schema fallback. Its Core equivalence, fallback and
revocation controls pass; native file-backed controls and performance measurement
are being qualified separately. No overall boot improvement is claimed.

A subsequent SDK phase-accounting change shares sequential native/report
transient space while retaining the previous complete native and report retained
commitments. It compiles and passes the full Core suite, but both the new
full-roster no-Child SDK control and the real initial startup still fail at SDK
admission: zero passes, two failures in 23.42 seconds after 3 minutes 46 seconds
of compilation. The remaining charge requires investigation; the phase change
is not a successful startup fix. The fixture has not reached native Capture,
source removal, either restored operation or recapture successfully.

### SDK startup commitments and exact retained history

Commits `593f52b6d0`, `0267b6ae70` and `ea85c352f2` add exact inert
history records and borrowed byte encoding. The full Provider suite passes
1,051 tests with zero failures and thirteen ignored; the corresponding Core
suite passes 1,745 tests and the contract suite passes seven. These serializers
do not admit a new Capture format or manufacture a restored execution owner.

Commit `1f847db9eb` derives future report commitments from the actual completed
native invocation's authenticated purpose. Original execution retains the full
OriginalObserve12 allowance; a fresh target retains the full
FreshCompletedAdmit13 allowance. Both allocation-row records and all existing
owners remain charged. Sequential native/report temporary phases share their
peak, while SDK construction, Hello, native retained commitments and all three
Source commitments remain independently additive. Neither the production
limits nor the fixture's existing 4 GiB limit changes.

The genuine full-roster SDK admission control now passes, including actual
three-member purpose checks and foreign-Source refusal. The real initial scene
still fails later. A temporary diagnostic observes a 3,628,311,225-byte SDK
admission projection and successful reservation checks for all three members;
this is requested storage, not RSS. A subsequent diagnostic reaches successful
launch/authentication of the first actual provider process, then fails while
writing its private bootstrap message. That run also fails the cleanup-completion
assertion, finishing with zero passes and one failure in 46.46 seconds. A later
process inspection finds no live reference-provider process; this does not make
the failed completion assertion pass. Temporary tracing is removed after each
run. The refreshed Core and contract suites pass 1,745 and seven tests
respectively, with 32 explicit native Core controls ignored.

An earlier proposed refinement of the initial14 report row was not the cause
of this improvement: these fixtures use invocation15 and retain its full broad
authorized report row. No successful native Capture, restored Producer operation
or recapture is claimed by the startup result.

Commit `efcb69dca1` fixes omitted allocated storage in saved operation close
submissions and dispatch effects. The bounded snapshot walk now counts refused
reason strings and both independently owned uncertain committed prefixes,
including spare identifier/vector capacity. Both exact/one-byte-short controls
pass. The full refreshed suites pass 1,747 Core, seven contract and 1,051 Provider
tests with zero failures; 32 Core and thirteen Provider native controls remain
explicitly ignored. The mandatory application-target gate passes for this
SDK/storage checkpoint, compiling 167 test artifacts across 48 application roots,
including 69 integration targets. This compiles the targets without executing
them; subsequent import-release changes require their own final-source gate.

Recursive serialization of additional decoded import ancestors is paused while
the smaller installed-import checkpoint design is reviewed. Its first stage
would replace repeated readers of immutable imported ancestry and release only
their duplicate decoded Core graphs. All current SDK/native/Source journals,
pending inputs, deferred evidence, current proofs and frontiers remain live.
Later consumed-journal retirement requires a separate durable post-Observe
checkpoint, acknowledgement, nonreuse state and reader migration. Capture must
not perform either transition implicitly. The separate
[installed-import plan](installed-import-checkpoint.md) gives ordering, reader
replacements and behavioral acceptance for both stages. The planned first
implementation retains the decoded Host needed by existing signing readers and
targets only the other three decoded import graphs.

### Guarded decoded-import release

The local release implementation keeps the original verified archive, decoded
Host and signing terminal, all current native/SDK/Source journals, pending and
deferred evidence, and actual Commit/Hold/currentness proofs. Its private
installed-boundary witness replaces only repeated immutable import validation.
All three decoded-owner write loans are acquired before removing any native-
before, native-after or registry graph. Failed admission or final checks retain
the old graphs; a completed release remains spent even if its later census fails.
Capture does not invoke this administration or serialize the local witness.

Normal six-crate, all-feature/all-target checking passes after correcting two
explicit Rust module paths. The full Core suite passes 1,748 tests with zero
failures and 32 ignored; all seven contract tests pass. The actual two-world
fixture selects release in only one world, requires a smaller same-owner backing
census and repeated-release refusal, and compares real Producer continuations.
It also adds a genuine empty second lifecycle under the existing two-slot
publisher allowance. These native assertions remain unrun: initial startup still
fails before either fresh world. No resident-memory or speed reduction is
claimed. The existing finite model cannot exercise an evaluation preceding the
next operation's start; genuine deferred-reaction coverage needs a distinct
model extension, not weakened old guards.

Commit `7b2a73d441` fixes retirement of prepared but unlaunched process
reservations. Their existing guard destructor releases the unused expected slots
or forwards an actual partial Child to its original supervisor. Commands, wire
banks and spent flags stay retained. The three-slot regression passes, and the
real failing startup now completes its reclamation assertions. A subsequent
trace reaches all three real process launches and bootstrap writes, then refuses
baseline admission. Its byte terms are 3,265,796,731 plus 3,947,862,714 against
4,294,967,296; descriptor usage stays within its separate limit. All temporary
tracing is removed. The selected lifecycle quote is under investigation.

### Preservation profiles and state-schema correspondence

Complete capture previously compared a preservation-facet version directly with
its native state-schema version. Genuine packet profile5 supports state codecs
11, 13 and 14; these numbers name different contracts. The correction recognizes
only those explicit packet families and Host profile2/state2, retains the existing
implementation/full-schema/facet checks, and leaves strict compiled-definition
validation in the defining decoder. Unknown and future settled17 formats remain
outside this legacy path. Facet-local configuration semantics are unchanged.

The full Core suite passes 1,752 tests with zero failures and 32 ignored; all
seven contract tests pass. Four new controls use actual compiled schema producers,
exercise substituted identities and prove that changing both the advertised and
claimed definition still fails the compiled-schema validator. Six-crate,
all-feature/all-target checking passes in 49.39 seconds. These component results
do not establish complete native Capture or restoration.

The same family predicate also corrects capture preflight, which separately
compared facet and state-schema versions. Preflight retains owning-producer,
owner/participant, implementation and full-schema checks. Its genuine schema14
constructor control accepts facet5 and rejects facet14; unknown families stay
outside this legacy route. The full Core suite passes 1,753 tests with zero
failures and 32 ignored, and all seven contract tests pass. Formatting passes
for both changed code files. Native Capture has not yet reached this preflight.
Six-crate, all-feature/all-target checking passes in 34.76 seconds.

### Constructor-specific startup projections

Raw Source JSON handling constructs Value trees, not Control snapshots. Its
occurrence projection now counts both actual Value owners, canonical work and
empty roots; independently typed Source decoders keep their own rows. The SDK's
retained coordinator projection now uses the defining complete DTO backing
counter. All three full coordinator decode/validation work terms remain charged
separately. Encoded bounds, checked sums and the 4 GiB policy are unchanged.

The normal suites pass 1,752 Core tests, seven contract tests and 1,053 provider
tests, with zero failures; 32 Core and thirteen provider tests remain ignored.
Controls compare the projections against actual parsed/cloned Value ownership
and a real decoded coordinator, retain foreign-grammar rejection, and test
independent one-short bounds. Formatting passes for all four changed code files.
The source-built provider rebuild passes in 18.87 seconds; six-crate,
all-feature/all-target checking passes in 45.05 seconds. The final-source
application-target gate remains outstanding for this stage.

With the same provider executable as the preceding failure, full-roster
admission passes and all three actual launches and bootstrap writes complete.
The selected lifecycle projection falls from 3,947,862,714 to 1,043,716,118 bytes.
The complete baseline sum is still 3,265,813,349 + 1,043,716,118 against
4,294,967,296: it refuses by 14,562,171 bytes. The combined run has one pass and
one failure in 34.67 seconds, and failing startup passes reclamation. These are
requested-storage projections, not RSS or execution speed. Temporary tracing is
removed. Native Capture and restoration remain unqualified.

### Source-owned assigned Admit projection

The initial Source now independently charges its normalized Admit from the
SDK's existing exact assigned-envelope shape, after authenticating the same
SDK, Source and complete launch. The opaque data includes the actual binding,
world and admission receipt, maximum request identifier and sequence, and a
conservative later MAC extension. All SDK ownership remains charged separately.
The general collecting caller has no such loan and keeps its previous arbitrary
frame bound. Actual message, body, route and extension checks are unchanged.

The normal suites pass 1,753 Core tests, seven contract tests and 1,054 provider
tests with zero failures; 32 Core and thirteen provider tests remain ignored.
New controls observe the real typed Envelope converted to Value, canonical
backing, independent one-short correspondence and foreign body/launch refusal;
the collecting fallback is unchanged. Formatting passes for the three code files.
Six-crate, all-feature/all-target checking passes in 43.95 seconds, and the
source-built provider rebuild passes in 19.99 seconds. The final-source
application-target gate remains outstanding for this stage.

Actual full-roster admission passes, all three launches and bootstrap writes
complete, and member zero baseline reservation now passes the unchanged 4 GiB
policy. Startup next refuses control-socket acquisition with OwnerUnavailable.
The combined run has one pass and one failure in 34.15 seconds; its reclamation
assertions pass. The provider executable in this run is built from the preceding
constructor correction. Temporary tracing is removed. Capture, fresh-world
restoration and continuation remain unqualified.

### Bounded initial socket readiness

A temporary probe establishes successful guard entry and SDK preconditions,
49.82 seconds remaining on the original host cut, and connect failing with
ENOENT while retaining its created descriptor. The SDK now waits for a same-user
socket before descriptor creation, using borrowed C-string stat calls with
NOFOLLOW and an empty-descriptor OS poll. The original deadline governs the
wait. A later connection still has one attempt and retains its descriptor on
failure. Symlinks, non-sockets, foreign ownership and other stat errors refuse.

All 1,753 Core, seven contract and 1,058 provider tests pass, with zero failures;
32 Core and thirteen provider tests remain ignored. Four new controls exercise
a delayed real listener, expiry without a descriptor, invalid paths, and retained
failed-connect/occupied-output custody. Formatting passes, and six-crate,
all-feature/all-target checking passes in 40.32 seconds. The source-built
provider rebuild passes in 25.65 seconds. The application-target gate passes
for committed preflight checkpoint `018661ff84`: 167 test artifacts across 48
application roots, including 69 integration targets, compiled without execution.
All 4,119 included Rust and Cargo source files match that checkpoint. This gate
does not qualify the later readiness change.

Actual startup first refuses during member zero socket acquisition after 71.25
seconds, with zero passes and one failure. Launches, bootstrap writes, baseline
reservation and reclamation pass. A subsequent failure-only probe on the
existing duplex bootstrap channel identifies the native refusal:
`ResourceExhausted("native baseline requested storage")`, during the original
private row claim, before launch validation, executable measurement or listener
binding. The failure arrives 1.776 seconds into bootstrap, with 128.85 ms in
that phase; this run does not expire the separate five-second native cut.
Its original startup test has zero passes and one failure in 71.15 seconds,
with reclamation passing. The temporary probe is removed in full. The defining
native projection is under investigation; no native Capture or fresh-world
continuation result is claimed. The production provider rebuild passes in 28.80
seconds and reproduces its pre-probe executable hash.

### Inert current model and displaced control readers

Strict readers now decode the actual current Producer and Reactive histories,
prepared/adoption/displaced model children, and raw ControlRecord editions five
and six. One capacity ledger spans their fields. Failed and incomplete state
remains retained data; settled-adoption eligibility is a separate check. The
readers construct no live Program, socket, Hold, registration or execution grant.
The existing old-edition readers and their alias vocabulary remain unchanged.

All 1,753 Core, seven contract and 1,069 provider tests pass with zero failures;
32 Core and thirteen provider tests remain ignored. Eleven new controls use
actual serializers, snapshots and model adopters, including completed Reactive
state, failed partials, nonempty payloads, spare capacities and insufficient or
malformed recorded fields. Transparent wrappers preserve the actual writer's
metadata traversal count as well as its full backing facts. All eleven changed
Rust files pass formatting. Six-crate, all-feature/all-target checking passes in
50.73 seconds. The full Prepared-root Hold alias roster, complete graph
correspondence and live Capture17/fresh-loader route remain unfinished.
The application-target result above covers its earlier committed checkpoint.

### Purpose-bound native restoration ingress

Core and the native invocation recount now use the same complete-target
projection for restoration ingress. Original execution has no reachable fresh
activation or first-Observe allocation. Fresh targets retain each independently
selected ingress row, with retained bytes summed and phase/counter maxima kept.
Core admits the fresh contribution before Source finalization or Child creation,
updates the full retained-row seal, and preserves the common-owner intersection.
All existing policy limits, baseline owners and native effect guards remain.

The normal suites pass 1,753 Core, seven contract and 1,072 provider tests with
zero failures; 32 Core and thirteen provider tests remain ignored. Three new
controls cover original host/native baseline parity, all fresh feature
combinations, exact and insufficient ceilings, and foreign targets. Formatting
passes for all six code files; the provider rebuild passes in 25.56 seconds.
Six-crate, all-feature/all-target checking passes in 35.80 seconds.

The clean production startup test still fails, with zero passes and one failure
in 71.24 seconds; reclamation passes. A subsequent temporary probe confirms
baseline authentication now passes and identifies the next refusal as
`Correlation("native report startup original allocation differs")`, 1.798
seconds into bootstrap. That run has zero passes and one failure in 71.52
seconds, with reclamation passing. The report validator's combined publisher
ceiling is under investigation. The complete probe is removed, and a 19.59-second
production rebuild reproduces its pre-probe executable hash. Native Capture,
restoration and continuation remain unqualified.

### Invocation-bound report declarations

The private invocation bootstrap checks each compiled report publisher against
its existing 512 MiB ceiling after authenticating the complete target and the
same Source purpose. Both declarations remain present and the returned peak
keeps their checked retained sum plus the largest complete transient/counter
phase. Core and SDK still admit all current owners under the existing global
policy. Legacy Source13/14 retains its combined-ceiling validator unchanged.

The normal suites pass 1,753 Core, seven contract and 1,074 provider tests, with
zero failures; 32 Core and thirteen provider tests remain ignored. The four
full-roster definition/admission controls pass in 25.11 seconds, including the
actual compiled report pair whose aggregate exceeds the individual publisher
ceiling. Boundary controls retain each row's independent ceiling and reject
missing, malformed, foreign and overflowing declarations. All six code files
pass formatting; the provider rebuild passes in 24.35 seconds. Six-crate,
all-feature/all-target checking passes in one minute six seconds.

The corresponding clean production startup test still fails, with zero passes
and one failure in 71.98 seconds. Its outer error is `installed complete
collecting scene unavailable`; the exact next bootstrap refusal is not yet
identified. No native Capture or fresh-world restoration is qualified by the
allocation controls.

The final campaign terminology cleanup preserves the documented compatibility
aliases and serialized identities. Four backend identity/profile controls and
the two directly affected lineage tests pass; this is not a full campaign-suite
result. The earlier broad campaign run has no final result after interruption.

### Complete Hello and launch layouts

Failure-only logging on the existing startup test confirms that the invocation
report check passes. Its next refusal is `ResourceExhausted("native5 actual Hello
allocation")`, 4.628 seconds into bootstrap and before the five-second cut. This
run has zero passes and one failure in 71.81 seconds. All six temporary logging
edits are removed; a 20.23-second rebuild reproduces the pre-probe executable.
These source-built provider checks use the normal unoptimized Cargo dev profile.

The selected test declaration included the raw Hello frame bytes but omitted
both retained frame descriptors. It now uses the defining allocation-free layout
getter, also consumed by baseline pricing. Actual construction, guards, limits
and deadlines remain unchanged. The shared launch counter also includes its
defining borrowed field views without duplicating its observer/facts headers.

All 1,753 Core, seven contract and 1,077 provider tests pass with zero failures;
32 Core and thirteen provider tests remain ignored. The actual Hello controls
compare requested and allocated layouts at minimum, ordinary and maximum frame
credits, retain exact/one-short guard behavior and reject invalid limits. The
clean provider rebuild passes in 20.59 seconds. Startup with the corrected
declaration still fails, with zero passes and one failure in 72.70 seconds. The
next precise refusal is unclassified; the final-source gates and native
preservation remain outstanding.

### Ordinary rational clocks and observation continuity

Authored capability selection now routes the existing rational-rate alarm clock
through ordinary exact execution and boundary settlement. Two real executor
controls pass in 3.85 seconds. They compare all six complete native publications
across two fresh catalogs and reject unsupported operations, Producer editions,
changed facets, configurations and enrolled script bytes. Preservation and richer
control capabilities retain their separate admission policies.

Nonempty observation batches now require their checked inclusive sequence range
to contain exactly their actual event count. The old validator could accept one
event claiming positions one through one hundred, allowing journal append to
advance past missing observations. All 25 public contract integration tests and
21 journal tests pass. New controls exercise actual decode/identity and append,
rejection without cursor or storage mutation, exact retries, whole-batch paging,
empty batches and valid ranges ending at the maximum sequence value.

### Ordinary opaque-packet capability routing

Authored capability selection now routes the existing opaque packet receiver
through the installed executor for `exact_run` and `boundary_settle`. Its
existing complete profile and installed admission policy remain authoritative.
Two executor controls pass in 3.99 seconds: nonempty binary packets retain exact
bytes, content identities, fixed response delay, causal Delivery parents and
FIFO order, with complete response publications equal across two fresh
catalogs. Changed script bytes, positive latency, facet configuration and
unsupported operations are refused. This does not qualify packet preservation
or transport fault controls. Formatting and six-crate all-feature/all-target
checking pass; the latter completes in 35.40 seconds.

The existing seeded and faulted links also route ordinary exact demands through
the same installed executor. Two controls pass in 13.26 seconds, exercising six
fresh catalogs with seeded Block timing, opaque-packet corruption and
duplication, and complete packet loss. Actual bytes, references, RNG-derived
timing and causal publications match their oracles and repeat exactly. A
separately consumed fault-decision journal supplies an output oracle; this does
not inspect or qualify the executor's private journal. Changed programs and
capabilities are refused. Independent source review, formatting and six-crate
all-feature/all-target checking pass; the latter completes in 53.28 seconds.
Preservation, runtime mutation and other control operations remain unenrolled.

### Selected executable measurement

The selected startup/Prepare path now reads through a 256 KiB bank. It retains
the same complete read/hash/metadata/reference implementation, immediate-growth
refusal and generic-path error precedence. Its shared scratch getter funds the
larger bank; private bootstrap also explicitly prices the complete measurement
phase and returned reference strings before authenticating its original row.
All retained owners, policy limits and original cuts remain unchanged.

Thirty alternating pairs use the same read-only 181,131,064-byte controller image
and ordinary Cargo dev profile, with matching provider features and BLAKE3
artifact records. Mean API time falls from 2,376.51 to 679.53 ms (71.41%); median
speedup is 3.49x. Separately waited whole-test-process CPU falls from 2,361.26 to
678.46 ms. All sixty complete ContentRefs match; the candidate wins every pair.
CPU includes the libtest harness and checks outside the timed API. The file is
warm in cache. Only the baseline has a separate untimed warm-up, a deviation
from the measurement plan; the first candidate sample is near its median and
all thirty pairs remain included. These are component results.

All 1,753 Core and 1,077 provider tests pass, with 32 and fifteen ignored tests
respectively. The two new ignored cases use the ordinary libtest harness for
reference initialization and measurement. All four full-roster controls pass
in 26.28 seconds; six-crate, all-feature/all-target checking passes in 41.15
seconds. The provider rebuild passes in 19.20 seconds. The actual startup test
still fails with zero passes and one failure in 74.83 seconds; its precise next
refusal remains under investigation. The application-target refresh also passes
for this measurement change at `5285b8095f`; native runtime qualification remains
separate.

### Invocation Hello selection

Failure-only diagnostics isolate the earlier Hello timeout to the child's old
fixed feature subset. The host requires the full immutable installed roster;
the child's handshake refuses that request before writing its reply.

Invocation births now select exactly the authenticated private registration and
installed provider declaration. Changed feature membership/order and undeclared
or duplicate envelope keys refuse. The private registration was independently
digest-checked at birth; its borrowed getter rechecks the original creator,
issued birth and retained Source/launch bodies. Other birth editions retain
their existing selection. The shared Hello quote prices the complete roster and
validation scratch under the same policy limits and original deadline.

Independent source review and formatting pass. All 1,079 provider tests pass,
with fifteen ignored; the two focused selection controls also pass on the final
source. Six-crate all-feature/all-target checking passes in 34.91 seconds.
All four full-roster definition/admission controls pass in 23.86 seconds.

The real optimized native startup still records zero passes and one failure.
The latest member-level probe takes 14.82 seconds and confirms that node zero
passes socket acquisition and Hello, then refuses in Prepare with
`OwnerUnavailable`. Original resources are reclaimed. This is diagnostic phase
progress, not a successful startup or a performance comparison. All temporary
logging is removed after the probes. Native preservation remains unqualified.

### First restored Observe evidence

The SDK now retains the actual raw and typed terminal, then receives the
promised singleton evidence root through its existing Session and original
absolute cut. It records the actual SDK completion frontier only after content
verification. A disconnect leaves the owner Publishing, with no completion
frontier, while retaining the terminal, incomplete bytes, original provider
requests and cached acknowledgements. The saved frontier remains correspondence
data; Source authentication and each subsequent action claim stay separate.

The actual public construction quote independently prices host receiver
retained, transient and counter storage before its Window claim. The row covers
all finite provider originals, acknowledgements, partial content, raw decoding
and failure owners. Prospective appended bytes follow immutable request/chunk
limits; numeric reserved lengths provide no allocation credit. Current owners
remain separately charged, and global policy ceilings are unchanged.

The component tests use the real Unix framed transport with a modeled installed
codec and inert proof content. They exercise dependency-first multi-chunk
receipt, every correlated acknowledgement, exact retained custody, failure
partials, unchanged cuts and exact byte-boundary refusal. They do not issue a
genuine Source/Window claim or qualify native restoration. A complete public
construction positive and fresh native continuations remain required.

All 1,753 Core, seven contract and 1,084 provider tests pass at this stage.
After independently reviewed receiver hashing headers are added, all 1,084
provider tests pass again in 11.84 seconds, with fifteen ignored. Formatting and
final six-crate all-feature/all-target checking pass; the latter completes in
34.47 seconds. All four full-roster definition/admission controls pass in 24.70
seconds. Native startup remains unqualified: a subsequent failure-only
probe records zero passes and one failure in 15.00 seconds and isolates Prepare
to the client's original-journal byte limit. Its declared growth and the Source
preflight requirement remain under investigation; no policy limit is raised.

### Initial journal reservation

The native failure exposes a mismatch between two existing accounting rules.
Source reserves full request and response frames before dispatch: its first
Prepare preflight requires 2,621,440 journal bytes. The SDK instead admits
549,165 bytes from expected literals and one spare frame. Both journals are
empty when this preflight refuses.

The initial lifecycle quote now covers the larger full-frame reservation across
its existing closed request and proof roster. The actual wire, proof, decoded
owner and failure allocations remain independently priced; the scalar journal
reservation allocates no backing. The existing 512 MiB absolute journal cap,
frame limits, request counts, content limits and original deadlines are unchanged.

Independent source review passes. All 1,085 provider tests pass in 12.15 seconds,
with fifteen ignored. The new control checks the actual custody setter against
the Source preflight, preserving installed content and retained backing without
dispatch or attachment. Its narrower-row assertion checks the independent
admission axis, rather than claiming that one fewer byte exhausts physical
journal storage. Six-crate all-feature/all-target checking passes in 36.06
seconds. All four full-roster definition/admission controls pass in 26.36
seconds.

The matching optimized provider and ordinary native fixture still record zero
passes and one failure, in 67.19 seconds. Node zero now completes Prepare; node
one refuses during Hello with `UnsupportedFacet`. All original children are
reclaimed. This is diagnostic phase progress, not successful startup, native
preservation or a performance comparison. Temporary probes are removed.

A subsequent child-side probe confirms an actual Hello timeout for node one,
with zero passes and one failure in 67.15 seconds. Greeting all three children
before Prepare is investigated under the same cuts: the clean experiment fails
in 14.72 seconds, and a member probe isolates node one's window reservation to
`ResourceLimit` in 14.58 seconds. Keeping the earlier Hello owners staged exceeds
the current resource bound. The experiment and all probes are removed. These
failures establish neither a startup success nor a performance improvement.

### Distinct Input17 transport

The new Input17 protocol family binds its complete schema across the provider
and every selected implementation binding. SDK assignment retains the actual
original and its cut before installing a Source artifact. A result extension
must match the actual retained Input17 request before result decoding; an old
Input4 or mixed original cannot select the new response grammar.

A private projection class pairs the five-object Input proof quote with its
actual original, full content references, bodies, literal cut and requote.
The existing three-object Observe path keeps its limit. Chunk acknowledgements
in the new class must name the exact next offset. The complete native owning
codec must preserve this discriminator before that class can be captured.

Wire validation grants no native action permission. The Endpoint explicitly
refuses every Input17 request before legacy restore, upload or control dispatch.
The genuine Source/Window claim, native MAC and funded action row, Stage/Commit
custody, signed recurring Observe and complete historical reader remain required.

Independent source review passes, including correction of a possible fallthrough
to legacy dispatch before the closed Endpoint guard is added. The first ordinary
compile exposes a module path and map-type mismatch; both are corrected. All
1,097 provider tests then pass in 11.40 seconds, with fifteen ignored. The twelve
new controls exercise schema and request-class isolation, exact proof-bank
correspondence, ACK offsets and refusal before legacy dispatch. They use inert
protocol fixtures and do not claim live Source/native authorization.

All 1,753 Core and seven contract tests also pass; 32 Core cases remain ignored.
The Core run completes in 6.10 seconds after compilation. Native startup and
complete preservation remain unqualified.
All four full-roster definition/admission controls pass in 24.82 seconds.
Final six-crate all-feature/all-target checking passes in 38.90 seconds.

Further review finds that the Input17 validation temporary was initially added
to the construction quote and then overwritten by the request serialization
quote. Checked addition preserves both independent terms. A regression exercises
the actual accounting tail after the unchanged live admission checks: the
exact Input17 temporary and scratch deltas remain, every retained component is
unchanged, the complete exact budget fits and one fewer byte is refused. All
1,098 provider tests pass in 10.85 seconds, with fifteen ignored. The earlier
1,097-test run excludes this regression and is not evidence for the correction.
Independent review confirms that the live class and owner checks remain before
the private accounting tail. Six-crate all-feature/all-target checking passes
for the correction in 33.96 seconds.
The corresponding optimized provider rebuild also passes.
All four full-roster definition/admission controls pass again after the quote
correction in 24.27 seconds.

### Per-member initial startup

Normal installed startup now prepares all original commands, cleanup slots and
private wires before the first Child, then completes each launched member's
initial lifecycle before launching the next. This preserves each original birth
cut while removing the wait behind an earlier member's host preparation. The
separate public launch and lifecycle methods retain their existing behavior.
Fresh-world startup uses the same per-member ordering and already includes the
shared fixed-layout quote; its later Query/restore phases keep their own paths.

The native launch-bank loan and selected Boot-material loan end before the
member callback. Only the actual written guard/socket can enter its window;
private member callbacks use their issued scope and sticky once/phase fields
without reborrowing a bank during guard transfer. The shared policy includes
the additional overlapping fixed launch views. No deadline or ceiling grows.

Independent source review passes for initial and fresh-world ordering.
Six-crate all-feature/all-target checking passes in 36.68 seconds before the
fresh-world caller update and in 10.62 seconds after it. All six scene controls
pass on the complete six-file source in 34.24 seconds, including refusal of
all unlaunched member indices before window/once/Child effects.
The fresh-world original-holder relabeling control also passes in 2.83 seconds.

The clean matching native run still fails: zero passes and one failure in 72.33
seconds. Temporary failure probes isolate member one beyond Hello and host
Prepare to the actual initial Admit exchange, which expires without a terminal
result. Further diagnostic runs fail in 74.67, 76.82, 77.42, 72.50 and 72.71
seconds. No child failure packet is observed at the host's timeout. These runs
show diagnostic progress only; startup, state preservation and performance
remain unqualified. All temporary source probes are removed.


### Complete host-image authentication bank

Wait-only tracing of the ordinary native startup fixture shows node one waiting
for its next request until cleanup; no Admit data arrives at its idle wait.
The SDK's original 60-second cut starts during prelaunch preparation and is only
tightened later. Source call-graph review finds four complete host-image checks
before assigned Admit publication, plus other birth and currentness checks.

The birth guard now streams the same complete executable through a 256-KiB
bank instead of 16 KiB. The same private constant supplies all three defining
scratch quotes. This adds 240 KiB to each synchronous check, preserves positional
reads and every before/after metadata, full ContentRef, origin and deadline
check, and retains the existing ceilings. The acquisition control still checks
size-independent quotes and refusal at one byte less; it now also requires the
actual birth scratch explicitly and bounds the remaining fixed work separately.
Independent source review passes.

All 1,753 Core and seven contract controls pass in 5.97 seconds. Six-crate
all-feature/all-target checking passes in 28.44 seconds. The matching
native fixture still fails (zero passes, one failure in 101.70 seconds); a
wait-traced repeat also fails in 66.70 seconds. These incomplete runs do not
establish an end-to-end speedup or startup success. Images, debugger output and wait traces
remain local. No temporary diagnostic source is part of this change.

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
| Selected startup/Prepare executable measurement, 8 to 256 KiB bank | Mean 2,376.51 to 679.53 ms; 71.41% lower call time; median 3.49x speedup | Thirty alternating pairs, ordinary dev profile and warm 181.1 MB input; all sixty complete ContentRefs match |
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


### Retained current17 provider reconstruction

The provider now has distinct typed current17 readers for retained Controller,
SDK, native Control/model, authority, lineage and mapping evidence. Their
outputs are historical DATA. The original source, administrative reservation,
fresh native adopter and whole-owner observation remain separate requirements;
this checkpoint does not enable the live signed17 effect or restore route.
Old mapping classes and the old11 admission vocabulary remain closed.

The reader constructors retain decoded children, completed siblings, spare
capacity and once state through refusal. Each lazy child bank requires an
independently admitted target ledger, is charged before reservation, and stays
in the actual census after failure or output transfer. This replaces recursively
inline attempt trees that overflowed the ordinary test-thread stack. No larger
stack, unsafe initialization or higher policy ceiling is used.

Shared-view row hashing now excludes the bank separator preceding a selected
span, while preserving all row contents and internal separators. Repeated equal
views therefore retain the same identity at the first or a later bank position.
Identifier validation also offers an owning refusal result so a decoder can keep
the invalid String and its exact spare allocation instead of dropping it.

Normal all-feature/all-target provider and contract checking passes. The full
unfiltered library run passes 1,268 provider tests and all eight contract tests;
fifteen existing provider tests remain ignored. This includes the two previously
aborting default-stack controls, exact preflight/build parity, one-byte-short
credit refusal, retained partials and selected response variants. The six-crate
all-feature/all-target workspace check also passes in 2 minutes 12 seconds.

At `eac4c1f76c`, the matching optimized provider rebuild passes in 1 minute
17 seconds. The full Core library suite passes 1,753 tests with 32 existing
ignored tests; all eight contract tests and all four installed-provider roster
controls pass. The mandatory production application-target gate also passes,
freshly compiling 167 test artifacts across 48 application packages, including
69 integration targets. Its test profile retains debug assertions and overflow
checks. Source verification compares all 7,426 captured files byte-for-byte
against this checkpoint and confirms that every committed crate role is present.
The final test-target build takes 10 minutes 43 seconds, after its prerequisite
production package builds. This gate compiles tests without executing them.

Native startup, complete Capture and fresh preservation remain separate runtime
qualifications. Uncommitted Capture/Window integration and fresh native-adopter
work are not covered by these results.


### Bounded child executable stream bank

The child executable currentness path now hashes through a separately allocated
256 KiB bank. Its defining scratch quote includes the full bank capacity and
its Vec header; both constructors enforce the original exact capacity bound.
The first inline-array candidate overflowed the native test's default stack and
was replaced with direct bounded heap reservation. No larger test stack,
additional hash omission, changed metadata fence or extended deadline is used.

The actual positional complete-file hash helper is compared in one ordinary
optimized test executable, using the same 13,418,304-byte provider image and
independent canonical digest. Thirty alternating pairs warm both paths equally
and keep all samples: mean time falls from 15.82 to 2.84 ms, an 82.03% reduction,
with a 5.62x median paired speedup and all thirty pairs improving. All sixty calls
verify the same complete digest. This component measurement reuses prefunded
banks and excludes bank construction, kernel/namespace checks and startup.
Deterministic controls also reject a changed final byte with either bank size.

The full Core and contract library runs pass 1,755 and eight tests, respectively;
32 existing Core tests and the new opt-in benchmark are ignored in the full run.
The benchmark passes separately. All-feature/all-target checks pass across all
six affected crates in 31.81 seconds. The production application-target gate
must be refreshed for this source alongside the next compiler checkpoint.

Native startup remains unqualified. The previous committed source refuses scene
creation after 66.94 seconds; the corrected heap-bank candidate refuses after
42.51 seconds without a stack overflow. Failure-path elapsed times establish
neither startup success nor an overall performance improvement.


### Unsigned decimal serialization without a formatter allocation

U64 keeps its canonical decimal JSON string while writing digits through a
fixed twenty-byte stack buffer. A static two-digit table avoids an owning
formatter String and shortens the wide-value loop. I64 and all wire grammars
retain their existing behavior. Independent controls compare the old formatter
bytes and round-trip every decimal and binary boundary, small values, zero and
the full-width maximum; a short output writer still refuses.

The ordinary optimized Contract test executable measures both implementations
with the same prefunded 22-byte output cursor. Every case uses thirty alternating
pairs of 200,000 calls, equal 4,096-call warmups and independent byte checks
before and after measurement. All 240 pairs improve; all samples are retained.

| Value | Previous ns/call | Current ns/call | Mean reduction |
| --- | ---: | ---: | ---: |
| 0 | 18.47 | 9.75 | 47.24% |
| 50 | 19.15 | 10.32 | 46.12% |
| 1,024 | 20.64 | 11.30 | 45.22% |
| 1,000,000,000 | 24.94 | 16.34 | 34.48% |
| 2^32 | 25.00 | 16.49 | 34.04% |
| 2^53 | 29.71 | 21.57 | 27.41% |
| 10^19 | 32.79 | 22.44 | 31.57% |
| u64::MAX | 32.59 | 22.65 | 30.49% |

The first single-digit-loop candidate improved small values but regressed wide
values by about 7-8%; the two-digit loop removes that regression. This is a
scalar serialization comparison, excluding output allocation and VM execution.
It cannot be added arithmetically to the separate executable-hash result. Raw
samples remain local.

The final ordinary Contract test executable passes all twelve library controls;
the benchmark remains opt-in and passes separately. The expanded compiler and
production application-target gates are reported with the Capture integration
checkpoint, which remains separate from this component measurement.
