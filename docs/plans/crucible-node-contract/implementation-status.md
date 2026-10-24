# RFC-0025 implementation status

Implementation work tracks the full [RFC-0025](../../rfcs/0025-crucible-node-contract/README.md).
The PR remains draft. Component tests and separately qualified native profiles
do not establish completion of the full architecture.

This summary accompanies the [phased implementation plan](phased-implementation.md),
[qualification plan](qualification-plan.md) and proposed
[SourceBirth worker design](source-birth-derivation-worker.md). Detailed test logs, images,
traces and experiment history remain local. Test counts below identify their
specific stage; they are not cumulative coverage of the latest source.

## Actual reply ownership in packet-prefix validation

Commit `3f44365e5e` lends the existing `PacketControlReply` to the prefix
validator. The validator still observes full evidence-vector and payload
capacities before planning; it retains every original correlation, authority,
class and owning-requote check. The defining counter adds the two actual reply
loans without discounting any prior term. Both saved counter controls retain
their independent original formulas and add the same new loan headers.

All 126 focused prefix-storage, endpoint and startup tests pass in each
standard and raw-JSON mode. All-feature/all-target Transport/Engine/Daemon
checking, scoped formatting and all six architecture gates pass. The required
application gate compiles 180 test executables across 58 packages, including
71 integration targets. All 468 frozen owned Rust/Cargo inputs match the
committed revision and captured application source. Production Transport
Clippy drops the `ptr_arg` error and remains at 46 errors and 1,733 warnings.
These checks do not qualify opaque Recipe/Initial production, full Native18
readiness or RFC-0025 completion.

## Original Bootstrap inputs and terminal claim custody

Commit `736b16256e` groups the actual borrowed Hello, opaque Recipe and Initial
inputs for the original Bootstrap row authenticator. Its defining counter pays
both aggregate loans; no wire announcement can construct those opaque values.
Commit `e7708c9f50` checks the original process, thread and nonrenewing deadline
immediately before clearing the sticky failure flag on both original14 and
Invocation15 claims. Expired or foreign custody keeps the claim failed.

The first complete raw-JSON run passed 2,084 tests and exposed one stale saved
counter expectation. Commit `64758d006f` adds the same 156 bytes of terminal
views to that independent composition control, preserving the old counter.
The fresh complete raw-JSON and standard suites each pass 2,085 tests with
zero failures, 16 existing ignored tests and no filtering.
All-feature/all-target Transport/Engine/Daemon checking, scoped formatting and
all six architecture gates pass. The required application gate compiles 180
test executables across 58 packages, including 71 integration targets; all 462
frozen owned Rust/Cargo inputs match its captured source and committed revision.
Production Transport Clippy remains at 47 errors and 1,733 warnings.

These results qualify the borrowed input contract and terminal claim checks.
They do not construct genuine five-phase Recipe/Initial outputs, qualify full
post-Hello native custody, or complete Native18 readiness or RFC-0025.

## Shared parent and native initial-construction arithmetic

Commit `7b28a81a48` routes the native initial-construction projection through
its existing parent producer after checking the actual private-key and birth-ID
widths. Both original entry paths now use one complete formula. The fixed
counter includes the additional borrowed projection and result headers; each
original row remains independently authenticated without moving grant between axes.

All eight focused initial-construction/reconstruction tests pass in each
standard and raw-JSON mode, including 30 actual inherited-socket flights per
mode. All-feature/all-target Transport/Engine/Daemon checking, formatting and
all six architecture gates pass. The required application gate compiles 180
test executables across 58 packages, including 71 integration targets.

The registered funded Source/Birth VM also passes both fresh positive consumers,
small-policy spent-retry controls, the foreign-pin refusal, terminal cleanup and
the default-feature CLI refusal controls. All 456 frozen Rust/Cargo inputs match
the committed revision and the application, VM support, default CLI and ordinary
peer component captures. This qualifies the shared arithmetic and preboot Source
census. It excludes subsequent Bootstrap input and deadline changes and does not
produce opaque Recipe/Initial values or qualify Native18 readiness or full RFC-0025.

## Isolated parent private Birth construction

Commit `07aad75c6f` connects the accepted original worker result and
bank-free seed to genuine private Birth construction. The Source separately
quotes both startup-bank copies, authenticates the unchanged original launch
and completion, and transfers the original executable File, private identity
and signing key once. The completed job retains its original response bytes;
partial copies and failed Births stay in their actual owners and storage census.
Cancellation revokes the private Birth before releasing deployment custody.

The actor advances all three members on its existing poll, outside Source
loans. Its test-support observer distinguishes authenticated templates, three
retained private Births and a subsequent derivation failure. The public command
continues to refuse preparation success. No startup finalizer, Initial, Recipe,
native readiness, Capture or preservation authority follows from this transition.

The registered funded-template VM check adds two independent actual consumers
that must finish all three confined jobs and private Births, retain spent retry
credit, and reclaim their namespaces before publishing success. Separate finite
worker policies fund this positive flight; the earlier small-policy foundation,
foreign pin and default-feature CLI refusal controls remain. The component
derivation now depends on the source-built Rust compiler/Cargo output rather
than its developer-tools-only output; the measured adapter path also follows
its existing `semantic/` module location.

All-feature/all-target Engine and Daemon checking, the six registered
architecture gates and changed-file Rust/Nix formatting pass. Full configured
library runs pass 2,034 Engine and 1,823 Daemon tests with zero failures and no
filtering; existing ignored populations remain 33 and 164. The Engine run uses
the actual built packet executable. Daemon uses the measured device and the
source-built gem5 closed-profile manifest, including its two fresh restorations
on each of x86_64 and AArch64. This fixed profile does not establish device parity.

The required application test-target gate passes for the construction, transport
lint repairs and actor failure observer in `e50b1042c1`: 180 test executables
across 58 package IDs, including 71 integration targets. All 25 owned changed
Rust paths match the captured source. This gate compiles without running tests
and emits no Crucible runtime unit-test ELF. Native funded-worker/Birth VM
execution remains unqualified: the initial process-reservation refusal and the
subsequent installed-mechanism refusal are recorded below. These component
results do not qualify common Ready or full RFC-0025 completion.

## Initial Source census under original deployment custody

Commit `c1a7de3131` adds a typed initial-lifecycle Source read joined to the
same original deployment reservation. It reuses the complete component visitor,
including mandatory Capture banks and both unresolved native-read refusals.
Deployment and Source terminal checks run after either component outcome;
the first component error retains priority. Numeric storage DATA grants no
funding, Bootstrap completion, Initial, Recipe or native permission.

The test-support private-birth observer independently funds that visitor, reads
all three actual Sources and requires exact-bound success after a refused
one-byte-short walk. The VM requires its census marker in both fresh positive
consumers, alongside the existing spent-retry and terminal cleanup controls.

All-feature/all-target Engine/Daemon checking, changed-file formatting and all
six architecture gates pass. The two initial Source tests and three existing
prebirth controls pass. The required application gate compiles 180 test
executables across 58 packages, including 71 integration targets. All 443 frozen
Rust/Cargo inputs match the committed revision and the captured application,
VM support, default-feature CLI and ordinary-peer component sources. The
generated guest init contains the new assertion for both birth consumers.

The registered VM fails qualification. Both small-policy consumers pass; the
positive consumer reaches all three private Births and original launch
commitments, then reports retained derivation failure without the new census
marker. Code review finds that the isolated route never installs the Capture
banks required by the initial-lifecycle visitor. Those checks remain mandatory.
Separately admitted bank reservation and production-holder integration are the
next implementation step. No positive initial-Source VM or full RFC result is
claimed for this revision.

## Funded initial Source banks and complete deployment census

Commit `da6c5b3689` separately admits and reserves the defining Source Capture
banks after accepting each original isolated worker result and before private
Birth construction. It binds the actual installed coordinator policy, retains
the Source-bound construction row before reservation, and observes every failed
constructor prefix after releasing the mutable Source loan. Accepted worker
banks remain in their original completion; this step runs no legacy BirthWorker.

The production whole-Prepared observer uses the complete initial-lifecycle
component visitor for retained private Births under the same original deployment.
Earlier stages keep their strict prebirth visitor. Mandatory Capture banks,
complete native-read checks and terminal custody checks remain enforced. The
stage chooses a DATA visitor and supplies no native permission.

All-feature/all-target Engine/Daemon checking, changed-file formatting and all
six architecture gates pass. The required application gate compiles 180
test executables across 58 packages, including 71 integration targets. All 443
frozen Rust/Cargo inputs match this commit and the captured application, VM
support, default-feature CLI and ordinary-peer component sources.

The registered funded-template VM passes. Two fresh positive consumers retain
all three actual worker results and private Births; each requires exact-bound
Source deployment reads after one-byte-short refusal. Both small-policy
failure/spent-retry controls, foreign-pin refusal, namespace/world-credit cleanup
and the separate default-feature CLI's two public refusals and normal shutdown
also pass. This qualifies the preboot initial Source census, not post-Hello
Source/Controller funding, opaque five-phase Recipe/Initial production, native
Ready, Capture, performance or full RFC-0025 completion.

## Capture encoding quote headers before live inspection

Commit `f7e7c6a38b` places the actual before-cut bounds in the borrowed encoding
plan and shares its defining fixed-header counter with startup admission.
The completed quote preserves the separately counted candidate and actual
serialization windows. Both real call sites retain the same SDK, metadata,
bank and terminal authentication; no provisional after bound funds the before cut.

All 79 focused report, Capture, continuation, endpoint and encoding test
executions pass in each standard and raw-JSON mode. Changed-file formatting,
all-feature/all-target Transport/Engine/Daemon checking and all six architecture
gates pass. The required application gate compiles 180 test executables across
58 packages, including 71 integration targets. All 456 frozen Rust/Cargo inputs
match the pushed revision and captured source. Production Transport Clippy still
fails with 49 errors and 1,733 warnings under the unchanged workspace policy.
These results exclude subsequent initial-projection changes and establish no
new VM, complete native preservation or full RFC qualification.

## Capture candidate inputs and defining scratch admission

Commit `dc1c4e379b` groups the seven actual borrowed Capture owners into a
named input view. Its defining candidate counter now includes those views,
checked-result and fixed iteration storage. The outer report quote pays that
same complete counter before borrowing live roots; the candidate reports it
again for its own walk. Original SDK and control authentication still surround
the callback, and compact chunk arithmetic retains its existing refusal order.

All 75 focused report-startup, native Capture, observation-lifetime, continuation
storage and endpoint test executions pass in each standard and raw-JSON mode.
Formatting, all-feature/all-target Transport/Engine/Daemon checking and all six
architecture gates pass. The required application gate compiles 180 test
executables across 58 packages, including 71 integration targets. All 455 frozen
Rust/Cargo inputs match this pushed revision and the captured source. Production
Transport Clippy still fails with 51 errors and 1,733 warnings under the unchanged
workspace policy. No new complete-library run, VM, full native Capture or full
RFC qualification is claimed.

## Fallible borrowed JSON cursor qualification

Commit `4114a7ae88` names the borrowed cursor operation `next_value` in the
Transport facade and all four Engine readers. The defining scanner, borrowed
spans, errors, storage counters and wire formats are unchanged. Ordinary Rust
iterators retain `next`; this fallible cursor does not implement Iterator.

All three cursor controls pass in each standard and raw-JSON Transport mode.
All 18 focused Engine controls for parent framing, historical scope proofs,
initial declarations and Source reader construction also pass. Formatting,
all-feature/all-target Transport/Engine/Daemon checking and all six architecture
gates pass. The application gate compiles 180 test executables across 58
packages, including 71 integration targets; all 453 frozen Rust/Cargo inputs
match the pushed revision and captured source. Production-library Clippy still
fails with 53 errors and 1,733 warnings under the unchanged workspace policy.
No new VM or full RFC qualification is claimed.

## Historical Control model and Controller layout qualification

Commits `e7bf876227` and `5af66c7f3b` separate the closed Controller17 layout
catalogue and retain the current Control model inline as an optional value.
Only the exact unfinished-restoration tag has no model. Actual model, writer,
retained-builder and census views keep their existing wire grammar and failed
prefixes; the defining counter additionally prices the borrowed optional views.
The catalogue retains every typed child and all three decoder Result layouts.
The retained endpoint and suffix guard simplifications preserve their real
RefMut lifetimes, interruption flags and terminal checks.

Both standard and raw-JSON modes pass the historical snapshot (322 tests),
current Control reader (11), restored suffix (38) and endpoint (27) groups,
with zero failures or ignores in each group. These groups can overlap and are
not a new full-library run. Formatting, all-feature/all-target
Transport/Engine/Daemon checking and all six architecture gates pass.
The required application gate compiles 180 test executables across 58 packages,
including 71 integration targets. All 448 frozen Rust/Cargo inputs match the
committed revision and captured application source, including the new module.

Production-library Clippy falls from 61 to 54 errors with 1,733 warnings under
the unchanged workspace policy. This qualification adds no VM result, native
phase admission, opaque Recipe/Initial production or full RFC acceptance.

## Original Bootstrap predecessor and admission grouping

Commit `b13804f4f6` groups the four actual borrowed Bootstrap predecessors and
the three distinct proof, preparation and publication callbacks. Each operation
keeps its original spent flags, received SDK loan, validation order and terminal
guards. The defining counters separately price the new borrowed view headers;
existing conservative terms remain charged. These views provide no funding,
currentness, opaque Recipe, Initial result or native phase permission.

Complete standard and raw-JSON Transport runs each pass 2,083 tests, with zero
failures, no filtering and 16 existing ignores. Changed-file formatting,
all-feature/all-target Transport/Engine/Daemon checking and all six architecture
gates pass. The required application gate compiles 180 test executables across
58 packages, including 71 integration targets. All 445 frozen Rust/Cargo inputs
match the committed revision and its captured application source.

Production-library Clippy falls from 66 to 61 errors under the unchanged
workspace deny policy, with 1,733 warnings. Strict acceptance, complete
Source/Controller funding, opaque five-phase Recipe/Initial production and full
RFC-0025 implementation remain unfinished.

## Effective JSON key-visitor qualification

Commit `c1c7dd3ae0` visits actual BTreeMap keys directly in the effective text
census and materialization quote. Both defining counters add the actual Keys
iterator controls; the materialization quote also names its borrowed key and
optional iterator result. Existing conservative iterator terms remain charged.
No input population, retained backing, constructor work or refusal is omitted.

All 125 raw-value reparse tests pass in each standard and raw-JSON feature mode,
with zero failures or ignores. Changed-file formatting, all-feature/all-target
Transport/Engine/Daemon checking and all six architecture gates pass. The
required application gate compiles 180 test executables across 58 packages,
including 71 integration targets; all 445 frozen Rust/Cargo inputs match this
commit and its captured source. Production-library Clippy falls from 68 to 66
errors with 1,731 warnings under the unchanged workspace deny policy. Strict
acceptance and full RFC implementation remain unfinished.

## Process-child census and transport lint repairs

The actual VM refusal exposed an absent runtime prerequisite. The pinned Linux
source guards `/proc/<pid>/task/<tid>/children` with `CONFIG_PROC_CHILDREN`, which
was disabled in the system kernel. The deployment supervisor requires this
original census before actors or children exist; it correctly refuses an
unavailable file rather than assuming an empty process tree. The required kernel
fragment now enables it. The resolved kernel configuration gate passes, and the
funded-Source VM also checks the configuration and actual readable interface
before attempting its consumers. The corrected VM passes those preflights and
process reservation, then refuses installed worker-mechanism verification before
Source preparation. No worker or private-Birth execution success follows.

Commit `450087ad6c` removes four redundant field initializers and expresses nine
eight-word counter terms using equivalent fixed array layouts. All 1,746
Transport library tests pass, with zero failures, no filtering and 15 existing
ignores; formatting passes. Library Clippy errors fall from 176 to 163 without
new allowances or accounting changes. All-target checking also finds test-only
diagnostics; neither Clippy scope is qualified by this repair. The refreshed
application compilation gate above includes all thirteen lint-repaired paths.
The six registered architecture gates also pass for those inputs.

A further transport cleanup derives eleven equivalent empty/default states in
six existing read-attempt and lineage modules. All 1,746 Transport library tests
pass with zero failures, no filtering and 15 existing ignores, and scoped
formatting passes. The production-library Clippy diagnostic count falls from
163 to 152 errors; it still emits 1,426 warnings. No lint setting, constructor,
field layout or accounting term changes. Strict Clippy remains unqualified.

A separate cleanup removes terminal returns and automatic dereferences, elides
two equivalent reference lifetimes and uses a Copy fieldless controller grammar
selector. Wire encodings, object fields, check order and accounting rows remain
unchanged. Complete standard and raw-JSON Transport library runs each pass all
1,747 tests with zero failures, no filtering and 15 ignores. Production-library
Clippy reports 131 errors and 1,426 warnings; its earlier 152-error checkpoint
remains a failure. No lint allowance or strict acceptance criterion changes.
The edited restored-suffix module's existing content-bound source review is
refreshed after a full source read; the six architecture gates pass.

The actual ResponseShape child tag depths now combine through a private const
maximum helper, preserving every child-type dependency and the resulting depth.
Complete standard and raw-JSON Transport library runs each pass 1,747 tests with
zero failures, no filtering and 15 ignores. Formatting and all six architecture
gates pass. The content-bound decoder review is refreshed after a complete
source read. Production-library Clippy reports 128 errors and 1,426 warnings;
strict Clippy remains unqualified. The required application-target compilation
gate passes for `142f67c950`: all 67 owned changed Rust files match its registered
source, and it compiles 180 test executables across 58 package IDs, including
71 integration targets. This compilation-only gate excludes later changes.

Two further expression repairs use an eager static error and an explicit empty
array check. Complete standard and raw-JSON Transport library runs each pass
1,747 tests with zero failures, no filtering and 15 ignores. Production-library
Clippy reports 126 errors and 1,426 warnings; strict acceptance still fails.
No wire, check-order, accounting or lint-policy change follows.

A subsequent twelve guard simplifications flatten nested conditions across nine
small modules while retaining the same short-circuit order, borrow lifetimes,
refusal points and accounting terms. Complete standard and raw-JSON Transport
runs each pass 1,747 tests with zero failures, no filtering and 15 ignores.
Formatting and all six architecture gates pass. Production-library Clippy falls
to 114 errors with 1,426 warnings; strict acceptance remains failed. The earlier
application compilation snapshot excludes this later cleanup.

Commit `e50b1042c1` adds a fixed test-observer diagnostic from the actor's retained
first failure. Its actual VM run identifies the installed-mechanism refusal;
the public command continues to return its existing refusal. Subsequent verifier
stage diagnostics return the runtime cause beside a fixed stage label; only the
label reaches that observer. Their all-feature/all-target Engine/Daemon check,
formatting and all six architecture gates pass. The required application gate
again compiles 180 test executables across 58 package IDs, including 71 integration
targets, and all 27 owned changed Rust paths match its captured source. Its
compilation-only scope is unchanged. The fresh VM reaches the runtime-inventory
and loader-edge check, then refuses before Source preparation. Nine focused
installation/loader controls pass. The separate pure-worker owner VM also passes
actual resource-limit refusals, sticky cancellation and waited cleanup; it does
not perform the installed artifact/loader verification.

The actual AOS libc contains PT_INTERP for direct execution. The loader verifier
incorrectly rejected that unused header when libc was mapped as a DT_NEEDED
library. Its correction preserves authentication of the exec image's real
interpreter and every selected dependency. A regression uses actual encoded ELF
files and confirms that a library's unused interpreter is never opened, while an
unresolved exec interpreter still refuses. All eleven focused installation
controls pass, including an explicitly run readonly installed launcher/worker ELF
graph check as DATA. The full configured Engine library passes 2,035 tests with
zero failures, no filtering and 34 ignores; the additional ignored control needs
that explicit installed artifact. Engine/Daemon all-feature/all-target checking,
formatting and all six architecture gates pass. The required application gate
compiles the same 180 test executables across 58 package IDs and 71 integration
targets; all 29 owned changed Rust paths match its capture. The confined installed
VM flight now passes installed worker verification and refuses during Source
preparation, before any worker or private Birth success. Test-only fixed
operation labels identify the actual preparation operation entered while
preserving the original typed failure and custody. Their all-feature/all-target
Daemon check, formatting and six architecture gates pass. The required
application compile gate again emits 180 test executables across 58 package IDs,
including 71 integration targets; all 31 owned changed Rust paths match its
captured source. The operation-stage VM localizes the next refusal to neverborn
code Source construction, before namespace or child creation. The full configured
Daemon library run passes 1,823 tests with zero failures, no filtering and 164
existing ignores.

The graph validator's expected native roster omitted the eight declared settled17
definitions. It now authenticates both full immutable rosters and all six features
before adding those exact compiled bodies; unknown extras still fail the final
exact comparison. The actual packaged configuration constructs all three
neverborn code Sources in an explicitly run artifact control. Missing, duplicate
and changed declarations refuse in a separate control. These constructors confer
no deployment, native startup or readiness. Formatting and the six architecture
gates pass. The required application gate compiles 180 test executables across
58 package IDs, including 71 integration targets; all 34 changed Rust paths at
that checkpoint match its source capture. The full configured Daemon suite passes
1,824 tests with zero failures, no filtering and 165 ignores. The confined VM
passes Source construction and next refuses the collecting fixture serialization
ceiling before any worker or private Birth success.

The complete settled17 fixture tuple exceeded its independent one-MiB object
bound because each full launch embeds its original coordinator. A versioned
qualification metadata document now references separately retained complete
canonical coordinator and launch records. Older declarations keep their original
inline tuple and identity. The one-MiB object and two-MiB aggregate limits remain
unchanged; no native schema, query allowance or admission permission changes.
An explicitly run packaged regression creates a fresh configuration with the
actual test ELF, installs the genuine code authority, plan and graph, then reads
and verifies every reference against the original full bytes. Its explicit code
fetch limits cover that large test ELF and the fixture's declared content budget;
this does not qualify the production capsule's default cold-archive limits.
The focused regression passes. The complete configured Daemon suite again passes
1,824 tests with zero failures and 165 ignores, and all six architecture gates
pass. The application gate compiles the same 180/58/71 targets and captures all
37 changed Rust paths, before the final test-only explicit-budget adjustment.
Its compilation-only scope is unchanged. The fresh confined VM gets beyond the
previous serialization failure but its public control exchange times out before
the actor publishes a terminal result. No worker or private-Birth success is
claimed; synchronous preparation responsiveness and production code fetch limits
remain unqualified.

## Funded setup dispatch and code fetch budget

The funded command now spends its original entry and returns its existing Refused
result before setup. The same actor performs that setup on its subsequent poll;
duplicate requests cannot create another attempt. A preparation refusal stays in
the retained capsule. Setup itself is still synchronous within one actor poll,
so this change does not qualify bounded polling or ordinary Ready.

Funded code-graph fetches use the independently pinned scene's content budget,
intersected with its memory limit and original reserved parent address space.
Both per-object and cumulative fetches are bounded, and repeated reads remain
charged. This supports the actual whole host ELF, which exceeds the cold decoder's
64-MiB object default. Cold archive limits and the unfunded preparation route
retain their existing caller-selected limits. The test observer distinguishes a
spent entry awaiting its original poll without certifying completed preparation.

Formatting and the final Daemon all-feature/all-target check pass. The complete
configured Daemon library passes 1,824 tests with zero failures, no filtering and
165 ignores, and all six architecture gates pass. The required application gate
compiles 180 test executables across 58 package IDs and 71 integration targets.
Its source snapshot predates the final test-only requested-state observer and
rustdoc additions, which the final all-feature check includes. The fresh confined
VM terminated its first consumer at about 65 seconds of guest uptime under the
60-second parent CPU policy, before a terminal preparation observation. This is
consistent with exhaustion of the parent's hard CPU ceiling; the last operation
was not available after that process kill. No runtime worker, private Birth,
native or Ready success follows from these component checks.

A contained derivation failure now retains the spent capsule and world credit
while its same supervisor continues cancellation and original child waits. It
no longer requests daemon shutdown merely because the logical derivation failed.
The completed template authenticator is retained in every build; a partial setup
cannot select that polling path. The tiny-policy VM control waits for the actual
DerivationFailed observation before retrying and checking its retained credit.
Fixed test-support stage transitions are also written once when they change, so
a subsequent process kill cannot erase the last entered operation.

The full configured Daemon library again passes 1,824 tests with zero failures,
no filtering and 165 ignores. Daemon all-feature/all-target checking and scoped
Rust/Nix formatting pass. The six architecture gates pass for the final trace
addition. The required application gate compiles 180 test executables across
58 package IDs, including 71 integration targets; all 38 owned changed Rust paths
match its captured source, including the final trace and deadline changes. This
compilation-only gate does not run the native consumers. A second VM run with the
earlier 60-second parent policy again kills its first consumer before any terminal
preparation observation. A repository-wide formatting check additionally encounters
unrelated existing formatting and scratch diff parse errors; scoped formatting
passes without editing those files.
The qualification fixture now selects a finite 180-second parent CPU policy and
240-second consumer wall limit, leaving worker limits and source checks intact.
The fresh VM must still establish actual fit, retained failure/retry, worker
results and private Births. No native qualification or full RFC completion is
claimed.

## Complete Import18 declaration before identity construction

The traced 180-second-parent VM reaches isolated Source declaration binding,
then reports a typed preparation refusal before starting a worker. Its fixture
requests Import18 while its immutable provider and binding rosters contain only
the forty older definitions. An independent actual-artifact selection check
refuses that same incomplete launch.

The fixture producer now includes both full Import18 schemas, their canonical
bodies and all three required features before constructing provider, binding,
World or coordinator identities. The ordinary graph validator authenticates
both exact immutable rosters and every required feature before adding those
two compiled definitions to its expected roster. Missing, duplicate, changed
and unknown definitions still refuse; older declarations remain unchanged.
This declaration supplies no native mechanism or startup permission.

All 1,747 Transport library tests pass with zero failures, no filtering and
15 existing ignores, including the new incomplete-roster controls. Changed-file
Rust formatting and all six architecture gates pass. The explicitly run fresh
packaged configuration regression passes: its actual measured test ELF is bound
before fresh World construction, its original code authority and graph install,
and all three unchanged launches bind distinct fresh Import18 Source templates.
Daemon all-feature/all-target checking also passes. The required application
compilation gate passes with 180 test executables across 58 package IDs,
including 71 integration targets; all 55 owned changed Rust paths exactly match
its registered source capture. This gate does not run tests or emit Crucible
runtime unit-test executables. The rebuilt funded VM must still establish the
subsequent actual worker/private Birth path. Native startup,
Initial/Recipe production, common Ready and full preservation remain unqualified.

The rebuilt VM passes both independent small-policy consumers: all three actual
launches bind, the derivation attempt fails under that policy, duplicate credit
remains spent, and terminal retirement reclaims its namespace. Its first positive
consumer starts the original isolated derivation but refuses during polling.
The VM therefore fails before any accepted worker result or private Birth. A
separate test-only observer now lends the original failed outcome after actual
waited cleanup and reports its failure class, exit status, OOM delta and bounded
stderr once. Candidate-bank stdout is never rendered. It issues no completion
or acceptance permission. The new diagnostic flight is pending; Engine/Daemon
all-feature/all-target checking and all six architecture gates pass.
The required application test-target gate passes for the observer and expression
cleanup, compiling 180 test executables across 58 package IDs with 71 integration
targets. All 66 owned changed Rust paths match its registered source capture.
Its compilation-only scope does not qualify the pending native diagnostic flight.

The ordinary Authority currentness check now measures all original files at
entry and exit around its closed retained-data body. It preserves all four
original Source/Host guards and both scope comparisons, performs no SDK,
transport, vendor or evidence callbacks inside the interval, and always checks
the terminal measurement even when the retained-data check refuses. No earlier
read is cached as later native permission. This reduces full file passes from
four to two for this interval only. The complete configured Daemon library run
with `test-support` passes 1,835 tests with zero failures, no filtering and
166 ignores. An earlier default-feature run had one QEMU child-lease
descriptor-count failure that passes on a focused recheck; that earlier full
run is not recorded as passing. The current run changes no test or assertion
in that QEMU control.

## Confined worker standard-descriptor startup

The diagnostic VM reaches the first positive original worker, which exits on
SIGSEGV with zero cgroup OOM kills and no stdout or stderr. No result or private
Birth is accepted. A trace of the same measured ELF shows Rust's pre-main
three-descriptor, zero-timeout `poll`. Denying that syscall triggers abort;
denying its subsequent signal delivery reproduces the same silent SIGSEGV.
The pure-worker profile previously denied both calls.

The profile now admits only `poll` with at most three descriptors and zero
timeout. Existing network, process, filesystem and signal restrictions remain.
Every actual kernel probe checks that this census succeeds while a fourth
descriptor or nonzero timeout refuses. The separate pure-worker owner VM passes
all existing resource, cancellation, completion-custody and waited-cleanup
controls with these added checks. This x86_64 startup correction does not qualify
another architecture's libc syscall mapping.

The rebuilt funded-Source VM passes both positive consumers. Each accepts all
three actual confined-worker results, constructs the three genuine private
Births, retains retry credit and reclaims its terminal namespace. The two
small-policy consumers and foreign-pin control also pass. The enclosing VM then
fails during its separate default-feature CLI control, so the full check remains
failed. Added stage-specific failure diagnostics retain that control's assertions
and deadlines. Native startup, common Ready and full preservation remain
unqualified.

## Borrowed original Source declaration

The isolated Source lends the unchanged pre-report bank directly from its
accepted worker completion. The opaque serializer retains a shared loan of the
actual private Birth. It authenticates the original Source, selected launch,
completion, both Birth banks and complete executable before and after each
serialization, including failed writes. The parent creates no response DOM or
additional bank copy. The transport bank view is explicitly serialization-only
DATA; native full roster and semantic validation remain unchanged.

The funded actor admits this loan's concrete construction and guard workspace
before obtaining and dropping it from each genuine private Birth. It releases
the loan before whole-Prepared observation. Actual formatter, serializer, error
and output owners still require separate admission. This transition creates no
Initial, Recipe, startup finalizer, native member or Ready grant.

All-feature/all-target Engine, Daemon and Transport checking and all six
architecture checks pass. The complete configured Engine library run passes
2,035 tests with zero failures, no filtering and 34 ignores. Its first run
omitted the required installed packet-provider input and failed five fixture
setups; the complete configured rerun uses the same actual test executable.
All 1,747 standard Transport library tests pass, with zero failures, no filtering
and 15 ignores, including direct equality with the original owned Bytes codec.
Changed-file formatting passes. The rebuilt VM reaches all three genuine
Source declaration loans in both positive consumers, retains their retry credit
and completes namespace cleanup. The small-policy and foreign-pin controls also
pass. The enclosing check then fails in the spent default-feature CLI retry:
the original prepare returns Refused, but the retry's actor exchange expires
with EAGAIN. No deadline or assertion is relaxed. This remains a failed full VM
check and does not qualify an actual declaration serialization callback.

The required application-target gate passes for `b714e6711f`: all 74 owned
changed Rust files match its registered source capture. It compiles 180 test
executables across 58 package IDs, including 71 integration targets, without
running them. The gate excludes the later retained-custody lint cleanup,
submission guard and raw-bootstrap receiver.

## Retained original Source declaration encoding

The funded private-Birth path now encodes each genuine borrowed Source
declaration into a bank retained by its original Member. The quote derives the
actual declaration's canonical bank, temporary Value/JCS work, Bytes formatter,
original loan guards and error controls. It admits the full row before output
allocation. The bounded writer cannot grow the retained bank, occupied outputs
refuse unchanged, and failed allocations or partial output remain counted by
both the direct and projected storage censuses. All Source/Birth loans end
before the complete Prepared census.

The original worker response and SourceBirth6..12 bank remain opaque and
unchanged. The new declaration's Value executes the genuine serializer's
before/after original-custody checks. The ordinary producer/reactive negative
controls refuse both quoting and encoding without output or Birth effects.
The funded VM observer now requires three nonempty encoded declaration banks
beside three genuine private Births.

The complete configured Engine library passes 2,036 tests, with zero failures,
no filtering and 34 ignores. Standard and raw-JSON Transport libraries each pass
1,755 tests, with zero failures, no filtering and 16 ignores. All-feature and
all-target checking for Engine, Daemon and Transport, formatting and the six
architecture gates pass. The funded Source VM passes both actual consumers,
all three encoded declarations/private Births, spent credit, retry and cleanup
controls. That VM and the complete library snapshot precede the final explicit
Vec/Option constructor-header additions to the encoding row; final-source
qualification remains pending. The complete configured Daemon library passes
1,837 tests, with zero failures, no filtering and 166 ignores. The required
application compilation gate passes for the earlier encoder snapshot: 180 test
executables across 58 package IDs, including 71 integration targets. Ninety-two
of 93 owned Rust paths at `27c9fdd9b2` match that capture; the final explicit
Vec/Option constructor-header additions are the one excluded path. This gate
does not run the tests or compile a Crucible runtime unit-test executable.
No Initial, complete Recipe, native startup, Ready or preservation is claimed.

## Immediate spent preparation submission refusal

The service reserves complete-scene submission before queue admission. Once its
original command enters the actor queue, duplicate submissions return Refused
without waiting behind the actor's foundation or template work. A full or
unavailable queue resets this submission reservation because no command entered;
a lost reply after admission never resets it. Shutdown still returns Unavailable.
This is an operational submission guard, not Source once authority, a native
completion cache or permission to construct any model.

All four durable-status model tests pass, including the withheld-original-reply,
full-queue and lost-reply controls. The six registered architecture checks pass
with the content-bound actor source review refreshed. The complete configured
Daemon suite passes 1,837 tests with zero failures, no filtering and 166 ignores
in 239.74 seconds, using four test threads and the source-built gem5 manifest
compiled into the executable. The preceding direct-executable run failed 38
tests: its build omitted that manifest and its default concurrency exhausted the
existing 1,024-descriptor process limit during fixture setup. Assertions and
production bounds remain unchanged.

The required application-target gate passes for `a821942d3e`: all 89 owned
changed Rust files match its registered source capture, with 180 test executables
across 58 package IDs and 71 integration targets. Compilation runs no tests and
excludes the later raw EOF refinement and actual declaration encoding.

The complete funded-Source VM now passes both genuine private-Birth/declaration
loan consumers, the small-policy and foreign-pin controls, default-feature CLI
original and spent refusals, retained world credit and terminal namespace cleanup.
Its snapshot predates the receiver-only EOF refinement and actual declaration
encoding. General bounded actor polling, native readiness and preservation remain
unqualified; neither the submission guard nor this VM establishes those claims.

## Physical import18 raw bootstrap receipt

The new private receiver owns the inherited Unix socket, original five-second
cut, fixed prefix and every partial raw body before fallible reads. It checks
actual parent PID/UID, prefix MAC, independent body restrictions and its own
raw-storage floor before reserving the three banks. Actual capacities and read
cursors remain retained after refusal. All three completed raw hashes and exact
private-channel EOF precede a completed raw loan; an unexpected suffix byte is
retained, and an open writer expires the same original cut. Re-entry cannot
renew successful or failed receipt.

The complete standard and RawValue Transport library configurations each pass
1,755 tests with zero failures, no filtering and 16 ignores. Eight new controls
exercise actual parent-child descriptor inheritance, exact raw bodies, each
one-byte-short raw axis, independent policy refusal, partial prefix/body custody,
changed hashes, wrong origin/thread, overflow, spent receipt, unexpected suffix
and the real five-second open-writer timeout. The private child helper is ignored
in ordinary discovery and invoked explicitly by its parent tests. These fixtures
contain inert raw bodies and construct no opaque Initial or Recipe.

The same raw owner also constructs seven distinct empty receiving-bank headers
before any read. Their exact role order, transfer state and zero capacities
survive successful and refused receipt. The raw floor includes their actual
inline headers and constructor/counter states; the census counts any backing
separately. All eight physical inherited-channel controls pass with these
headers. No backing allocation, Prepare token, reference binding or completed
seven-bank custody is implied by their empty construction.

This physical precursor remains unselected from native startup. Its raw floor
omits dynamic typed backing; the later decode transition below derives that
additional demand independently. Complete seven-bank custody and the independent
Initial producer remain unfinished. No model, native Boot,
startup finalizer, common Ready or full-RFC qualification follows. All six
architecture checks pass for the final EOF source. Application compilation still
needs that refinement; the passing funded VM snapshot predates it.

## Original bootstrap typed decoder accounting

The three new inert body DTOs now have exhaustive decoder field rosters. Their
counter DAG follows the pinned serde visitors, fixed arrays, tagged program
buffers, Bytes/base64 codec and error formatting. Heap geometry distinguishes
inline root headers from actual allocating Vec elements and map entries. No
Wire DTO is converted into an opaque Initial or Recipe by these declarations.

An allocation-free quote examines the original raw banks before strict Value
parsing and the actual owned DTO decoders. Separate terms cover lexical Value
backing, canonical work, typed backing, nested tagged buffers, RawValue resets,
failed diagnostics and concrete parser controls. The quote excludes the physical
receiver, raw banks, inline output slots and later semantic/native constructors;
the independent complete Initial producer must combine their simultaneous
ownership before granting any parser admission.

Four decoder controls exercise actual producer/reactive Launch5 fields, opaque
Source bytes, Bytes growth boundaries, malformed codec/schema prefixes, exact
and one-byte-short complete work, and RawValue behavior. A fifth control checks
inline versus actual allocating container geometry. The complete standard and RawValue
Transport libraries each pass 1,760 tests with no failures, no filtering and
sixteen existing ignores. All-feature/all-target checking and all six
architecture checks pass for this accounting checkpoint. These are inert parser/accounting controls; physical
typed receipt and complete Initial/Recipe production remain unfinished.

The funded Source VM also passes on the later source containing the final
Vec/Option declaration-encoder headers and seven empty physical receiving-bank
headers. Both actual consumers, spent credit and namespace cleanup pass. The
production application-target gate emits
`zsj7xsyixc3nhhirm5zvwmdax440smrr-aos-test-targets-0.1.0`; its capture predates
the later base64-counter, heap-geometry and complete parser-quote additions.
Neither result qualifies those later additions or full native startup.

## Physical import18 typed DATA receipt

The original inherited-socket owner now retains empty actual recipe, selected9
and boot18 output slots before receipt. After complete raw hashes and EOF, its
separate once transition derives parser demand from those unchanged owned banks.
It combines all simultaneous retained owners with sequential maximum work,
checks each announced axis and the independent complete restriction, and spends
the occurrence before parsing. Actual strict Value parsing and the real owned
DTO decoders install each successful prefix before the next fallible body.
Every parse outcome receives terminal original-channel/hash/cut authentication.
No operational deadline or failed occurrence is renewed.

The retained census walks actual selected-launch fields, private key/birth banks,
opaque Source bytes, Host registration, private ID and executable reference.
Constructor-specific lexical/reset populations fund the walk, including expanded
RawValue depth and work. Ordinary depth/work limits and SDK response-forest
allowances remain separate. A later decoder refusal preserves the original raw
banks, successfully installed typed prefixes, actual capacities and spent state.

Both complete Transport library configurations pass 1,766 tests with zero
failures, no filtering and sixteen existing ignores. Six new parent/child
controls exercise actual producer/reactive decoding, every underfunded parser
axis, independent complete restriction, malformed recipe/launch/boot prefixes,
RawValue expansion, changed raw bytes, foreign thread, expiry, retry and checked
ownership overflow. All-feature/all-target checking and the six architecture
gates pass. The required application-target gate passes for `d9ec1e7028`:
all 112 owned changed Rust files match the captured source byte-for-byte. It
compiles 180 test executables across 58 package IDs, including 71 integration
targets, without running them. Its output is
`0gyl9pvxk3fhmj26wk5xcyrb1za1zlfb-aos-test-targets-0.1.0`. The funded Source
VM also passes for this receiver checkpoint, including both actual consumers,
three worker results/private Births/declaration banks, the original small-policy
and foreign-pin refusals, retained spent retry credit and terminal namespace
cleanup. Neither capture includes the later prospective body projection.

The fixtures and returned loans contain inert DATA. No parsed announcement is
converted into an opaque Recipe/Initial. Seven empty headers still contain no
input backing, Prepare token or completed native custody. Genuine Initial/full
Recipe production, semantic joins, startup selection, native effects and common
Ready remain unfinished; this receipt does not qualify full RFC-0025 completion.

## Prospective private-body construction

The Source-side precursor now projects actual recipe, Launch5, declaration and
private operands before an Initial row exists. Only the three future U64 decimal
string widths are projected; no placeholder Initial numbers, recipe, hash or
permission are constructed. The three parser rows share the actual receiver's
population/layout calculation and additionally price its real typed census.
Physical Bootstrap18/header ownership, Source semantic validation and the complete
Initial producer remain separate unfinished terms.

The actual borrowed serializer walk observes RawValue marker strings without a
Value or encoded bank. A separate raw-token bound covers the native scanner's
quoted/escaped literal extent, and actual outer wrappers consume the same finite
canonical nesting profile. Custom serializer formatters and original Source
custody guards still require their independent admission and lenders.

The first prospective comparison failed on boot parser S: decoded marker length
did not cover the raw scanner's complete encoded token. The corrected quote uses
the canonical literal bound. Eight controls now compare prospective populations
with independent actual Value/raw walks, streamed Display keys, character
strings, forest addition, exact/one-byte-short reset work, wrapper depth, and
actual closed body encodings at both program families, Bytes boundaries and
full-width U64 decimals. The complete standard and RawValue Transport suites
each pass 1,774 tests, zero failures, no filtering and sixteen existing ignores;
all-feature/all-target checking and the six architecture checks pass. No opaque
Initial/Recipe or native startup is produced by these tests.

## Original Source correspondence under the physical bootstrap cut

The raw owner now retains a separate Source-comparison spent bit and result row
before receipt. After typed decoding, it independently admits the actual launch
formatter before serialization, then the complete original Source parser,
canonical equality, typed-field comparison and diagnostic windows before the
first Source parser. Parent and native quotes share actual bank length and real
Value/container/JCS layouts; the parent leaves its worker bank opaque. Each
announced axis restricts independently derived demand, and the independent total
restriction remains mandatory. Matching DATA creates no Source purpose, genuine
Birth, opaque Initial/Recipe or native admission.

The actual parser and every terminal outcome remain under the original socket,
process/thread, raw hashes and nonrenewing five-second cut. Failed and successful
attempts stay spent, with unchanged raw banks and installed typed outputs. Five
new inherited-socket controls cover both program families, every underfunded
axis, independent total demand, malformed/changed/noncanonical Source bytes,
forbidden startup report fields, foreign thread, changed raw bytes, expired cut,
retry and checked population overflow. Three separate accounting controls check
parent/native row equality, exact and one-byte-short complete demand, opaque
malformed/RawValue-looking banks and the existing full Source field checker.

Both full Transport library configurations pass 1,782 tests, zero failures, no
filtering and sixteen existing ignores. All-feature/all-target checking passes.
The six architecture checks and required application-target compilation gate
pass for `97de81af79`. All 121 owned changed Rust files match its captured
source; it compiles 180 test executables across 58 package IDs, including 71
integration targets. The output is
`7xh4nrvnp7hjxr7xi2j0v0n51366hkii-aos-test-targets-0.1.0`. This capture excludes
the later capacity correction and initial reconstruction. Full Initial/Recipe production and native
startup selection remain unfinished; these DATA controls do not establish full
RFC-0025 completion.

## Independent initial DATA reconstruction

The physical owner now retains an additional once-only reconstruction slot
before reading. After complete original Source correspondence, it admits the
actual formatter window and independently repeats the prospective body/parser
formula from the received immutable recipe and actual launch/private operands.
The combined row includes the real receiver, seven empty bank headers, all raw
and typed outputs, parser/census windows, Source checks and reconstruction
controls. Announced Initial numbers never enter that calculation. Unknown
Initial decimal widths retain their defining U64 maximum independently of the
eventual values.

All three announced Initial rows, the prefix/selected/Source recipe commitments,
the complete repeated recipe and the actual private key must join that derived
DATA. Each independently derived initial axis must also fit the same announced
whole escrow. Original raw/hash/channel/cut guards run before and after the
transition; successful and failed attempts remain spent. Derived DATA stays
retained even when a later join refuses. This selects no native model, full
recipe producer, phase issuer, input backing, Hold or common Ready.

The shared Source comparison formatter now follows the existing typed Bytes
observer's actual initialized-length maximum. Parent spare capacity remains in
its separate retained census and cannot change independently reconstructed
constructor demand. A regression keeps Source fields unchanged while adding
spare token/program-vector capacity and verifies identical constructor rows.

The initial positive socket fixture first refused because its 64 MiB transient
escrow was smaller than the independently derived 140,713,496-byte window. Its
corrected inert phase partition remains inside the same original 256 MiB
independent total restriction; no production ceiling changes. Three real-socket
controls now pass both program families, changed body/prefix rows and recipe
identities/copies, changed private key, insufficient escrow, unchecked Source,
foreign thread, changed raw bytes, expired cut, independent total demand and
retry. Two separate formula controls cover simultaneous actual raw/typed owners,
unknown decimal widths, exact/one-byte-short demand and checked overflow.

Both full Transport configurations pass 1,788 tests, zero failures, no
filtering and sixteen existing ignores. All-feature/all-target checking and
the six architecture checks pass. Required application compilation passes for
`530d5845bc`: all 126 owned changed Rust files match the captured source. The
output is `39qdrm75zxpk20lgvqsr0vbh37w3v0kc-aos-test-targets-0.1.0`, with 180
test executables across 58 package IDs and 71 integration targets. This capture
precedes the subsequent recipe-independent projection.
Genuine full five-phase Recipe/Initial production and native startup remain
unfinished. These fixtures contain inert Wire DATA throughout.

## Initial projection before recipe construction

The shared Initial DATA formula now projects the entire fixed Recipe grammar,
recipe commitments and Initial decimals at their defining maximum widths. It
borrows actual launch/private operands without requiring a recipe, recipe hash
or provisional row. The native path repeats this same recipe-independent
calculation before joining the actual received recipe and announcements. The
existing exhaustive recipe and allocation-row field witnesses remain in force;
closed enum witnesses also require new variants to revisit maximum spellings.

Both program families cover short and maximum-width recipe numbers/commitments,
multiple Bytes lengths and actual decoded ownership. Parent/native derived rows
and body maxima agree without passing a recipe to either calculation. These
are inert parser DATA controls, with no opaque Recipe/Initial construction or
native startup selection. Both full Transport configurations pass 1,788 tests,
zero failures, no filtering and sixteen existing ignores. All-feature/all-target
checking and the six architecture checks pass. Required application compilation
passes for `5a9b81dfe2`: all 127 owned changed Rust files match its captured source.
The output is `1jk8f48jzx0q6wfrihczlq948zcxxan7-aos-test-targets-0.1.0`, with
180 test executables across 58 package IDs and 71 integration targets. These
compilation captures do not execute the native restore or select import18.

## Original parent initial projection

The genuine accepted worker/Source/private-Birth loan now lends its actual
original launch, private-launch ID and shared typed registration plan to the
recipe-independent initial projection. It does not parse either worker bank,
copy a secret, construct a registration DOM or manufacture recipe values. The
private key and Birth ID use their genuine constructor's defining `[u8; 32]`
Bytes extents; native separately refuses received widths that differ. Actual
launch formatter work and fixed original-loan/projection controls are admitted
before serialization, with original guards on successful and refused outcomes.

The real Prepared member retains the resulting numeric observation in an
explicit inline slot. Every Source/Birth loan ends before whole-Prepared census;
partial/failure custody remains intact. Its future-native axes are not charged
as new parent backing and issue no opaque Initial, Recipe, phase permission or
native readiness. The funded private-Birth completion probe now also requires
this real retained projection in each of the three members.

A new equivalence control uses the actual shared nine-field registration view
and verifies identical parent/native rows and body maxima without secret
operands. It also refuses short received key/Birth fields; real inherited-socket
controls exercise both short fields under original custody. The first synthetic
Host fixture used a RawValue-looking object, whose native reparse changes that
object under raw JSON; its equality assertion failed. Replacing it with the
actual closed registration type fixes the control's premise. Existing hostile
RawValue population controls remain in place.

Both full Transport configurations pass 1,789 tests, zero failures, no filtering
and sixteen existing ignores. All-feature/all-target checking for affected
crates and the six architecture checks pass. The full Engine suite passes
2,036 tests with zero failures, no filtering and 34 existing ignores. The full
default-feature Daemon suite passes 1,826 tests with zero failures, no filtering
and 165 existing ignores; this does not include its optional test-support tests. Required application compilation passes for `2e04d39385`: all
128 owned changed Rust files match its captured source. It compiles 180 test
executables across 58 package IDs, including 71 integration targets, at
`la1x4s7amrz7aq1vv76bsq5v74qnvh2g-aos-test-targets-0.1.0`.

The funded Source VM passes at
`ams009ilkffkj0190nz30ywfmiga8cps-aos-vm-test-crucible-funded-source-templates-0`.
Its support, ordinary-peer and default-CLI components all capture the same
production Rust implementation as `2e04d39385`; the only owned Rust difference
is the earlier synthetic Host unit control, corrected before that commit. Both
independent private-Birth consumers retain three genuine worker results,
private Births, encoded declarations and the new initial projections. Small
policy, foreign pin, spent retry, default-feature CLI refusals and terminal
namespace/credit release controls also pass. This VM selects no Native18 route.
Genuine full five-phase Recipe/Initial production and native startup remain
unfinished; these captures precede subsequent private-identity joins.

## Private bootstrap identity joins

Initial reconstruction now joins the actual received private key to the
unchanged genuine Birth derivation domain, and the full Boot Host executable
reference to the selected launch reference. Its real Hasher/Hash and borrowed
comparison controls enter the shared independent initial formula. The physical
owner also compares the launch's controller PID/UID to the actual credentials
of its same original inherited socket. This happens under the original once
bit and nonrenewing cut, with terminal custody checks on every outcome.

The real-socket controls now cover 21 flights across the existing three tests.
Four additional cases preserve raw hashes and consistent funding announcements
while changing the full-width Birth ID, Host digest, controller PID or UID.
They require their specific private-identity/kernel refusal, with unchanged
retained owners and seven still-empty input headers. Both program families
pass the valid joins. No input backing, native model, full Recipe/Initial,
executable measurement or Ready is issued by these DATA comparisons.

Both full Transport configurations pass 1,789 tests, zero failures, no filtering
and sixteen existing ignores. All-feature/all-target checking for affected
crates and the six architecture checks pass. Required application compilation
passes at `icrmn7gfpqfmd9aj3zz8qwqv27ng77ry-aos-test-targets-0.1.0`, compiling
180 test executables across 58 package IDs and 71 integration targets. Of the
129 owned Rust paths at `46dfe817ba`, 128 match the registered source exactly;
the sole difference is seven subsequently added rustdoc lines in the private
identity helper. All production behavior matches. The next checkpoint adds
actual executable measurement; full native/bootstrap/phase constructors remain
unfinished.

## Running controller executable correspondence

After authenticating the original inherited socket's PID/UID and the private
Birth/header joins, the native initial reconstruction now measures that same
controller's running image through `/proc/<pid>/exe`. It compares the complete
normative ContentRef to the retained selected-launch reference. The existing
stream reader checks the opened descriptor's length and metadata before and
after hashing. Its 256 KiB read bank, 256 MiB image restriction, CNP hash framing
and existing growth refusal behavior remain unchanged.

The shared initial formula now prices that actual sequential measurement,
metadata/hash controls, hexadecimal output layout, partial String construction
and temporary full-reference comparison. The caller admits this independent
row before the read, retaining all original raw/typed owners throughout. No
measurement sample, prospective digest, executable-sized buffer or renewed cut
is created to derive its numeric demand. Failed measurements leave the original
initial reconstruction spent and still run the terminal custody checks.

The real inherited-socket matrix adds a case in which both announced full
executable references agree but differ from the running controller image. It
requires the specific executable-correlation refusal. Both valid program
families pass using the actual test parent's image, and the seven input headers
remain empty. The three focused tests cover 22 flights in each JSON
configuration. Both full Transport configurations pass 1,789 tests, zero
failures, no filtering and sixteen existing ignores. All-feature/all-target
checking for Transport, Engine and Daemon and all six architecture gates pass.
Required application-target compilation passes for `9bb90d2f8a`, with all 133
owned changed Rust paths matching the registered source exactly. Its output is
`cw47xygaqh73wzml5mfjc5mxk70sw117-aos-test-targets-0.1.0`, with 180 test
executables across 58 package IDs and 71 integration targets. These compilation
checks do not execute native restoration or construct full Recipe/Initial,
native model or common Ready;
seven-bank Prepare/upload custody and the complete phase constructors remain
unfinished.

## Seven-bank reservation and transfer primitives

The seven physical bank headers now retain distinct optional full references,
a reservation/receive cursor and partial allocations. The separate backing
formula counts exact byte requests, all four String leaves in each full
reference, partial reference construction and the actual reservation/upload
controls. The initial formula continues to count its real empty headers and
retained-census controls; later transfer work has its own row. No future phase's
counter workspace substitutes for initial demand.

Reservation spends the occurrence before validation, validates every role
extent/reference before allocating, and installs each empty full reference
before its first fallible String reserve. Exact String and byte reserves are
checked against requested capacities. Every partial reference and earlier bank
remains in the same physical owner after refusal, and its census includes all
actual spare capacity. The full-reference and bank-field census rosters are
exhaustive.

Private Blob primitives enforce ordered full-reference Begin, unique transfer
IDs, contiguous nonempty chunks of at most 4 KiB, and full normative CNP content
hash/length agreement at Finish. Copying never grows reserved backing. A failed
new mutation poisons the occurrence while retaining all received bytes; only
seven completed banks can be borrowed together as DATA. The original dispatcher
must separately authenticate the genuine Prepare token/current connection and
retain literal retries and cached replies before selecting these primitives.
No public native dispatcher or token constructor is enabled by this component.

Five new primitive controls cover all seven distinct bodies, a multi-chunk
seventh body, unchanged backing throughout upload, one-byte-short construction,
invalid full references, wrong offsets/transfer/order/extensions/content and a
reused role transfer. A deterministic `Vec` capacity-overflow control fails
before asking the allocator for a huge layout and verifies that all six earlier
banks and the seventh full reference stay retained. The inherited-socket controls
continue to verify that all seven headers remain empty throughout bootstrap.
Both full Transport configurations pass 1,794 tests, zero failures, no filtering
and sixteen existing ignores. All-feature/all-target checking for Transport,
Engine and Daemon and all six architecture checks pass for the final exhaustive
counter roster. Required application compilation also passes at
`/nix/store/kk9s1mjip0v7hsnmz5y238ghxjrin4ll-aos-test-targets-0.1.0`.
Its registered source matches all 136 Rust paths changed through `d6304b309b`
byte for byte; the artifact inventory contains 180 test executables across 58
package identities, including 71 integration targets. This is component DATA
validation; genuine native Prepare custody, completed full Recipe/Initial,
model adoption and the full RFC remain unfinished.

## Original launch commitments in parent and bootstrap

The actual original Source/Birth loan now derives the selected-launch commitment
from its complete typed launch's canonical encoding and the private-launch
commitment from its actual private-launch ID. The lender authenticates original
Source, accepted completion, immutable launch and private Birth before and after
every outcome. The original worker response and SourceBirth bank remain opaque.
Formatter prewalk, complete canonical construction and terminal whole-Prepared
census are admitted separately; Prepared retains the resulting fixed DATA inline.
The funded-Source probe requires this actual result for all three members.

The independent initial formula includes the sequential launch canonicalization
and fixed commitment controls. Formatter demand uses initialized Bytes lengths;
spare capacity stays in the parent's retained census. A regression grows both
private-token and program-event capacity, verifies unchanged canonical bytes and
construction rows, and verifies increased retained backing independently.

Native initial header checks derive both commitments from actual decoded launch
and private-launch operands before comparing the announced recipe fields. Three
additional inherited-socket controls change the selected commitment, private
commitment and actual private-launch ID while preserving the other body/prefix
joins. These controls remain DATA-only; no parsed wire announcement becomes an
opaque Recipe/Initial, native Prepare token or model. Complete five-phase recipe
production, native dispatch and the full RFC remain unfinished.

Both full Transport configurations pass 1,797 tests, zero failures, no filtering
and sixteen existing ignores. All six architecture checks pass. The first
standard run had one existing gem5 secondary-process containment refusal
(`ESRCH` while polling the original group); its isolated rerun and the subsequent
complete standard and raw-value suites pass without source changes. Affected
all-feature/all-target checking passes. The Engine suite passes 2,036 tests,
zero failures and thirty-four existing ignores. The Daemon suite passes 1,826
tests, zero failures and 165 existing ignores in 240.64 seconds. Required
application compilation and the funded-Source VM pass. The application output is
`/nix/store/9z9q647gi6f0jircz704c32r8lpjsgvb-aos-test-targets-0.1.0`; its
registered source at
`/nix/store/kijm5h7hkmbakz1sbb6q6zdbp1hj0bm4-aos-workspace-src` matches all
139 Rust paths changed through `92632f3f01` byte for byte. Its artifact inventory
contains 180 test executables across 58 package identities, including 71
integration targets.

The funded-Source VM output is
`/nix/store/a3p4gjnxdz4rsafmrs1728lnd3pcq8ci-aos-vm-test-crucible-funded-source-templates-0`.
All three component derivations use
`/nix/store/jcb1qjwi37axc8328ddwainlmd2w8c5r-crucible-workspace-src`, with all
139 Rust paths byte-exact to `92632f3f01`. Two independent consumers retain three
actual worker results, private Births, declaration banks, initial projections and
new launch commitments. Spent retries, policy failures and terminal namespace
and credit release pass. This remains the genuine Source precursor; no native18
model, Bootstrap ACK, Prepare/upload or common Ready path is selected.

## Complete recipe commitment self-consistency

The new recipe commitment definition hashes canonical JSON of all twenty-three
actual fields other than `identity`, under the separate BLAKE3 derive-key domain
`source-owned.packet-native-import-prebirth-recipe-identity/18`. Its borrowed
serializer has an exhaustive field roster. The complete Import18 SchemaRef binds
this definition explicitly. No old transfer12/import17 definition changes.

The initial construction formula adds this sequential canonicalization window
using the existing fixed-width twenty-four-field declaration as a conservative
bound before recipe values exist. Its actual transient owners, fixed counter
and result controls remain separate from retained raw/typed bodies. Native
header checking recomputes the commitment after the exact body/copy/launch joins;
matching stale digests in all announcements no longer satisfy that check.

New component controls compare the actual borrowed roster with independent
removal of the digest from the full wire object, perturb every variable operand,
verify that only the digest itself is excluded, and refuse one-byte-short encoded
and complete-construction bounds. Two inherited-socket controls retain matching
prefix/selected/Boot recipe announcements while changing the digest or an actual
committed geometry operand. All three commitment controls and all three
inherited-socket reconstruction tests pass; the latter cover twenty-seven
separate flights in both standard and raw-value configurations. The initial
one-byte-short control exposed an irrelevant parser restriction in the shared
serialization report. The fixed finite declaration is now calculated before
applying the independent restriction to actual canonicalization owners; no
parser bank is executed or priced as this constructor's demand. Both full
Transport configurations pass 1,800 tests, zero failures, no filtering and
sixteen existing ignores. The affected all-feature/all-target check and all six
architecture gates pass. The required application output is
`/nix/store/07zwh9pywyz12hd7g541494sg7ca1i4z-aos-test-targets-0.1.0`, with
180 test executables across 58 package identities and 71 integration targets.
Its registered source at
`/nix/store/y10197yw7x7fbgisdkqy52zw0vgf2shj-aos-workspace-src` matches all
141 Rust paths changed through `10790624da` byte for byte.

The funded-Source VM output is
`/nix/store/8n3d37nmdkyhz105pfpzgaz5655zmdsf-aos-vm-test-crucible-funded-source-templates-0`.
All three components use
`/nix/store/3cl9sdf6asfn23kzcmqjy9f9rmpj6hvc-crucible-workspace-src`, with
all 141 Rust paths byte-exact to `10790624da`. Its genuine Source precursor,
independent consumers and terminal failure/release controls pass. Self-consistency
supplies no opaque Recipe/Initial or phase grant; independent full recipe
reconstruction from completed seven-bank inputs remains required before model
adoption.

## Completed input reference correspondence

The recipe full-reference commitment now has an explicit Import18 definition:
length-prefixed algorithm, domain, digest and media strings, followed by the
u64 body length, under the existing separate full-reference derive-key domain.
The public projection borrows every actual field without a canonical bank or
copied HashRef. Exhaustive ContentRef/HashRef and closed schema matches expose
future field or grammar additions for review.

An allocation-free DATA check binds the five archived roles in Snapshot, after,
Control, anchor and Journal order and the independent seventh semantic-spend
reference to the recipe. It checks exact lengths and selected semantic media.
Normalization stays separately bound by signed Prepare and fresh-target grammar;
it is not substituted into an archived commitment. Completed receiver reference
loans point directly into all seven retained original banks and refuse before
all transfers finish. Their future transfer and comparison counters remain
separate from initial bootstrap work.

Independent framing controls cover every full-reference operand, thirty field
mutations and ten equal-length archive-role swaps. The physical receiver control
uses all seven actual hashed bodies, checks pointer identity and unchanged
backing census, and rejects swapping equal-length after/Control references.
The focused standard/raw-value controls and both full Transport configurations
pass: 1,802 tests each, zero failures, no filtering and sixteen existing ignores.
The affected all-feature/all-target check and all six architecture gates pass.
The required application output is
`/nix/store/vr371g2rplx0xl4gz0f0i64m15vm4gbh-aos-test-targets-0.1.0`, with
180 test executables, 58 package identities and 71 integration targets. Its
registered source at
`/nix/store/z126c4ikb57xc9ssyl76nh6lsr49g6wx-aos-workspace-src` matches all
143 Rust paths changed through `f6b003f84d` byte for byte.
These checks do not issue native Prepare custody, an opaque Recipe/Initial,
model installation or readiness; actual semantic body validation and independent
complete recipe reconstruction remain required.

## Original completed-input loans

The physical bootstrap now lends its same parsed recipe and seven completed
reference/body pairs only after independent initial DATA reconstruction. It
checks full recipe reference correspondence under the original parent, channel,
raw-body and nonrenewing-cut guards, then repeats those checks after inspection,
including callback refusal. References and bytes point into the retained banks;
no replacement recipe or caller-selected reference enters this loan.

The callback returns Copy DATA only. Constructed outputs must stay in the
caller's retained attempt so that terminal refusal cannot drop an otherwise
returned owning object. Its separate fixed counter names the actual raw guard,
reference-join and loan work; initial-only construction and layouts are unchanged.

Four focused inherited-socket tests pass in both standard and raw-value builds,
covering thirty-five flights including eight new completed-input cases. They
exercise unchanged bank pointers/census, equal-length role substitution,
incomplete transfer, absent initial completion, foreign thread, expired cut,
expiry during a real callback and callback refusal. Both full Transport suites
pass 1,803 tests, zero failures, no filtering and sixteen existing ignores.
The affected all-feature/all-target check and all six architecture gates pass.
Required application compilation passes at
`/nix/store/qg46v68riqzgqa885rc96wfji6qw5n6z-aos-test-targets-0.1.0`.
Its immutable source at
`/nix/store/vlvwkxnx6pj2nywxncvnz5k9jn42zyns-aos-workspace-src` matches all
145 Rust paths changed through `7d46895ce4` byte for byte. Its inventory contains
180 test executables across 58 package identities, including 71 integration
targets.
This is a guarded DATA inspection boundary; native signed Prepare custody,
semantic decoding, complete recipe reconstruction and model adoption remain
separate required transitions.

## Native input framing under the original loan

The original bootstrap can now run the existing bounded nonowning Snapshot17
framing reader over its actual completed input banks. The same guarded loan
selects Snapshot17 explicitly and reconstructs announced reader limits as DATA;
Snapshot18 cannot enter this older reader. Five native roles are projected from
the exact seven-bank upload order without copying references or bodies.

The reader checks full body hashes, Snapshot framing, embedded Control/before
correspondence and the final Journal role roster. Its existing cold admission
receives the actual begin, construct and finish boundaries. The independent
whole-owner caller must admit both the separate wrapper controls and concrete
reader work before entering. Initial-only construction and layouts are unchanged.

All five focused inherited-socket tests pass in standard and raw-value builds,
covering forty-five flights. Ten new framing cases include actual structured
roles, rehashed changed Control/before dependencies, incomplete Journal roles,
a different Snapshot edition, an unsupported selected native family, refusal
at each of the three admission boundaries and one-byte-short counter funding.
Refusal retains the original completed banks and unchanged backing census.
These fixtures establish framing only: their inert model/lineage objects cannot
produce a sealed native graph or installation.

Both full Transport configurations pass 1,804 tests, zero failures, no filtering
and sixteen existing ignores. The affected all-feature/all-target check and
all six architecture gates pass. Required application compilation passes at
`/nix/store/cqw73y7rk8p961xpa2scqb6yyzlvri8p-aos-test-targets-0.1.0`, with
180 test executables across 58 package identities and 71 integration targets.
Its source at
`/nix/store/il5xn75s7xyw180ryl4p9fd48bgj24qr-aos-workspace-src` matches all
147 Rust paths changed through `dd7892c5d6` byte for byte.
Full graph/Controller/Source proof conjunction, semantic-spend and normalization
validation, independent complete recipe reconstruction and native model adoption
remain required before readiness.

## Initial demand stays in the original Prepare partition

Native initial header authentication now compares every independently derived
retained, transient and counter axis with its own original Prepare partition,
then with the whole escrow. A later phase's larger maximum or redistributed
retained row cannot fund this already-spent initial work. The Import18 definition
binds this rule explicitly; older contract editions remain unchanged.

Three additional inherited-socket flights preserve the original whole escrow,
valid recipe commitment and matching copied headers while independently reducing
one Prepare axis. Each refuses at the actual partition check. The positive inert
fixture previously assigned only ten MiB to Prepare despite roughly thirty-nine
MiB of independently derived initial retained demand. It now assigns forty-two
MiB to Prepare and two MiB to each later inert phase, preserving the same fifty-MiB
retained sum and all original transient/counter maxima. This does not constitute
a complete producer recipe or raise a native resource ceiling.

All five focused tests pass in standard and raw-value builds, covering
forty-eight inherited-socket flights. Both full Transport suites pass 1,804 tests,
zero failures, no filtering and sixteen existing ignores. The added fixed
comparison controls also enter the shared initial counter calculation. Affected
all-feature/all-target checking and all six architecture gates pass. Required
application compilation passes at
`/nix/store/s0iq62b766n4j89mm2pqsywcmn6n6pbq-aos-test-targets-0.1.0`, with
180 test executables across 58 package identities, including 71 integration
targets. Its capture at
`/nix/store/d5m7plgzv9dfpx928pgklwygf0ywzdn1-aos-workspace-src` matches all
147 Rust paths changed through `935a278725` byte for byte.

The funded-Source VM passes at
`/nix/store/kknsipcsdns57a31mq7nsppn1i2mq4yb-aos-vm-test-crucible-funded-source-templates-0`.
All three components use
`/nix/store/im1hi2pd34vx0k592zmp9sx39vcni87w-crucible-workspace-src`, with
all 147 changed Rust paths byte-exact to `935a278725`. The two independent
consumers, three actual Birth/declaration/projection/launch results, failure
controls and terminal namespace/credit release pass. Full native phase custody,
complete recipe production/reconstruction, model installation and RFC
qualification remain unfinished.

## Normalization decoding under original completed-input custody

The actual sixth input bank now has a separately retained, one-shot strict
normalization decoder. Its quote uses the shared concrete serde partial DAG,
raw JSON extent and RawValue reset accounting. Independent whole-owner admission
precedes parsing and observes actual typed backing after success or refusal.
Decoded DATA and formatted failure diagnostics survive later correspondence,
admission or original-cut failures. The attempt binds its quote to the exact raw
bytes and cannot retry after a refused quote, substituted input or terminal guard.

The decoder runs inside the original seven-bank loan. It checks all selected
families, nonce/generation, twelve native reader/constructor limits, five archived
full references, the seventh semantic reference and maximum, the normalization
projection and sixty-four-KiB ceiling, and the original complete Host registration.
The Import18 contract explicitly lists the actual thirty-five normalization
fields. Actual signed Prepare authentication remains a separate required join
for the complete archive and fresh target bindings.

Seven focused tests pass in standard and raw-value builds, covering eighty
inherited-socket flights and exact/one-byte-short quote controls. Both unfiltered
Transport suites pass 1,806 tests with zero failures and sixteen existing ignores.
Affected all-feature/all-target checking, scoped formatting and all six
architecture gates pass. Required application compilation passes at
`/nix/store/iv08x1n4k2mn77fxahfi58kz66vficjd-aos-test-targets-0.1.0`, with
180 test executables across 58 package identities, including 71 integration
targets. Its source at
`/nix/store/33wsbwgiga6sf66qqcqn1llfpv7gz04x-aos-workspace-src` matches all
152 owned changed Rust paths through `54ef51558a` byte for byte. The funded-Source
VM passes at
`/nix/store/2k49rzc91yxf6xvcfs35v9chy91qq624-aos-vm-test-crucible-funded-source-templates-0`.
All three component captures use
`/nix/store/3k0kq6hmlpv4yhb3mbd0ad9995dakapj-crucible-workspace-src`, with
all 152 owned changed Rust paths byte-exact to `54ef51558a`. Both independent
consumers, three actual Birth/declaration/projection/launch results, refusal
controls and terminal namespace/credit release pass. Full signed Prepare custody,
complete native proof/semantic-spend validation, recipe production/reconstruction and model
installation remain unfinished.

## Normalization and native framing share the original input loan

Completed normalization DATA now reborrows only with its exact original raw
bank. A combined framing pass repeats its recipe and Host correspondence under
the same original completed-input guards, then joins the embedded before full
reference and Journal's semantic and Runtime references. It independently checks
the before bank's whole original capacity, including spare bytes, against the
normalization's own before limit. These comparisons allocate no replacement
body and establish historical DATA correspondence only.

Twenty new inherited-socket flights cover all three changed context references,
full-reference media changes, absent/refused/foreign normalization, changed typed
recipe/Host operands, exact and one-byte-short used/spare capacity, every cold
framing admission boundary, callback refusal and expiry during the callback.
They verify that the actual decoded owner is lent and all original input pointers
and backing survive refusal. All eight focused reconstruction tests pass in both
builds, covering one hundred inherited-socket flights and the separate quote
control. Both complete Transport suites pass 1,807 tests, zero failures, no
filtering and sixteen existing ignores. Affected all-feature/all-target checking,
scoped formatting and all six architecture gates pass.

Required application compilation passes at
`/nix/store/51n008mx7zjxxlj9xzan8mzd9s428s83-aos-test-targets-0.1.0`, with
180 test executables across 58 package identities, including 71 integration
targets. Its capture at
`/nix/store/z1ll67jfr386mifp4qhlclhbsh8p8xp6-aos-workspace-src` matches all
154 owned changed Rust paths through `8a06469476` byte for byte. The original
initial row, physical bootstrap fields and contract bytes are unchanged by this
later input-validation pass. Genuine signed Controller/SDK/Source proof conjunction, complete native model/semantic-spend
validation and independent recipe reconstruction remain mandatory before fresh
native installation or Hold effects.

## Native Hello roster retained by the original bootstrap

The original physical bootstrap now retains the actual native Hello declaration,
feature vector and envelope-key map. Its one-shot constructor installs every
partial selection in that same owner before fallible work. Independent admission
precedes allocation and observes the whole surviving owner after either result.
Original raw/typed correspondence and the nonrenewing inherited-channel cut
surround construction and every completed roster loan. Callback refusal or expiry
preserves the actual roster and all original input pointers.

Both parent and native initial calculations price the same defining roster
constructor before receipt of the private bodies. The original physical floor
includes its inline partial fields; its terminal census includes the actual
selection backing. Initial projection refuses missing required selectors or a
changed sole binding. Inert test launches now carry the genuine required selector
tuple and matching Source8 fields; their programs remain unvalidated DATA.

All nine focused reconstruction tests pass, covering 114 inherited-socket flights
and the separate quote control. The fourteen new Hello flights include both
program families, occupied partial output, each one-byte-short constructor axis,
admission refusal, incomplete initial custody and expiry before, during and after
construction/loan. Both complete Transport suites pass 1,809 tests with zero
failures and sixteen existing ignores. Affected all-feature/all-target checking,
scoped formatting and all six architecture gates pass. Required application compilation passes at
`/nix/store/11bjzh0g66231zrckgl4w83cw4xfv330-aos-test-targets-0.1.0`, with
180 test executables across 58 package identities and 71 integration targets.
Its source at `/nix/store/3yj766sh7rf3wmjl757cid64gvjh65f8-aos-workspace-src`
matches all 156 owned changed Rust paths through `4cf6428d9b` byte for byte.
The funded-Source VM passes at
`/nix/store/rfdkk98ch4kq32sycql5mr7chfnrp9i9-aos-vm-test-crucible-funded-source-templates-0`.
All three component captures use
`/nix/store/xdz7fy57a8g7yjk5j5xfnx9pgnp2a66w-crucible-workspace-src`, with
all 156 owned changed Rust paths byte-exact to `4cf6428d9b`. Both independent
consumers, the three private Birth/declaration/projection/launch results, refusal
controls and terminal namespace/credit release pass.

A retained roster is not a completed native Hello, model-absent policy,
bootstrap ACK, opaque Initial/Recipe or restoration permission. Those actual
constructors and the complete native/Source proof conjunction remain required.

## Native full-definition checks precede Hello roster construction

The same original bootstrap now checks the compiled Import18 and Stage18
SchemaRefs against the complete provider and target-binding rosters. Exact
feature membership is mandatory. The attempt checks original initial custody,
admits the defining sequential factory quote before allocation and observes
terminal custody after success or refusal. Failed checks remain spent and retain
all original raw/typed bodies. The Hello roster constructor now requires this
completed correspondence check; skipping it refuses before roster allocation.

The shared initial calculation independently includes these same compiled
factory windows and their fixed controls before any private receipt. No old
native policy constructor, coordinator/model installation or Ready conversion
is used. The result is definition correspondence, not a native policy issuer.

Twenty-three new inherited-socket flights exercise complete provider and binding
references, missing/duplicated formats, changed schema IDs, versions, media,
digests, lengths, hash domains and extensions, missing/duplicated features,
incomplete initial custody, both admission boundaries and real cut expiration.
Both inert program families pass. A separate Hello flight refuses an unchecked
selection. All ten focused tests pass, covering 138 inherited-socket flights and
the separate quote control. Both complete Transport builds pass 1,810 tests,
zero failures and sixteen existing ignores. All six architecture gates pass.
Affected all-feature/all-target checking and scoped formatting pass. Required
application compilation passes at
`/nix/store/cxhwd99bid293lg6aav0hzvh7alj50qj-aos-test-targets-0.1.0`, with
180 test executables across 58 package identities and 71 integration targets.
Its source at `/nix/store/14x0i5sqdal7sm13wl38rcn684ba6rin-aos-workspace-src`
matches all 158 owned changed Rust paths through `8697d521e9` byte for byte.
The funded-Source VM passes at
`/nix/store/4pq9xvshnyk8swpnq98wsv80mvmqlwgj-aos-vm-test-crucible-funded-source-templates-0`.
All three component captures use
`/nix/store/z6v351sfmy64kmdbyhr119sbnfvsbl0d-crucible-workspace-src`, with
all 158 owned changed Rust paths byte-exact to `8697d521e9`. Both independent
consumers, three private Birth/declaration/projection/launch results, refusal
controls and terminal namespace/credit release pass. The broader Engine/Daemon
run was interrupted as the next physical-owner source changed; it is not
qualification evidence and will run on that final source.

The complete native model-absent policy, physical Hello/ACK custody, opaque
Initial/full Recipe producers and actual signed native/Source restoration
conjunction remain unfinished.

## Native Hello journal and literal storage retained before allocation

The original bootstrap now retains the actual Hello reservation capsule, literal
byte/descriptor bank and journal. The capsule is installed before fallible
reservation. The same bank moves into one shared allocation and the journal
retains that exact bank. The backing census checks actual shared-pointer identity
before deduplication, counts distinct journal banks separately and refuses an
outstanding mutable borrow. Failed reservations, occupied destinations and later
admission/cut failures leave their actual constructor and allocations retained.

Both initial calculations price the literal directions, two descriptors, shared
header and bank payload beside the raw/typed owners and Hello roster. Inline
constructor fields belong to the physical raw floor. Only completed full
selection and roster checks permit journal construction. Each journal loan
rechecks original custody after the callback, including callback refusal.

The actual journal's Rc ownership makes the entire bootstrap neither Send nor
Sync. A compilation control enforces both properties. Runtime origin controls
additionally challenge the recorded creator with a real foreign thread identity;
they no longer transfer an owner whose real journal forbids that transfer.

All eleven focused reconstruction tests pass, covering 149 inherited-socket
flights and the separate quote control. Eleven new literal-storage flights cover
both program families, unchecked roster, occupied constructor, both admission
boundaries, callback refusal and real expiration before/during/after work.
All eight retained-reservation tests pass, including three new actual Hello
constructor/census controls. Both complete Transport builds pass 1,815 tests,
zero failures, no filtering and sixteen existing ignores. Affected
all-feature/all-target checking, scoped formatting and all six architecture
gates pass. Commit `99dc0fdb5e` also passes the required application compilation
and funded-Source VM gates. The application gate emits 180 test executables
across 58 package identities, including 71 integration targets, at
`/nix/store/24niahf6mszds4jj4rv7kk6sxlbbaqjx-aos-test-targets-0.1.0`.
Its source capture and all three VM component source captures match the
checkpoint's 162 owned changed Rust paths byte for byte. The VM at
`/nix/store/6wv60ywi6464h3ymg99m4krs33058c7l-aos-vm-test-crucible-funded-source-templates-0`
passes both independent consumer flights, three real retained private
Birth/declaration/projection/launch results, refusal controls and terminal
namespace/credit release. The configured full Engine library passes 2,036 tests
with zero failures, no filtering and 34 existing ignores; the configured full
Daemon library passes 1,826 tests with zero failures, no filtering and 165
existing ignores. These results qualify this immutable checkpoint, including
the retained Hello storage, without selecting the NativeImport18 startup route.

This constructs physical journal storage, not an authenticated Hello exchange,
model-absent native policy, bootstrap ACK or opaque Initial/Recipe. Those actual
constructors and complete native/Source restoration remain required.

## Original public descriptor and unchanged private startup cut

The physical bootstrap can now retain its actual public descriptor before the
first private read. Retention performs no allocation, credential query or I/O.
An occupied or late destination preserves the caller's incoming descriptor.
The socket stays in the original root after every later refusal.

After completed initial correspondence, immutable definitions, Hello roster and
literal storage, a separately admitted constructor checks the public socket's
actual parent PID/UID and binds it to the unchanged opaque pre-parser deadline.
It retains both real shared allocations and moves the same descriptor into its
bounded stream. No new duration renews the cut. The backing census discounts
only actual cut/deadline pointer equality, counts distinct allocations and keeps
surviving backing visible after expiration. Deadline reset remains sticky even
if its previous value is restored. Outer typed guards and whole-owner terminal
admission run after either constructor outcome.

The physical raw floor includes the inline capsule and its allocation-free
retention moves/controls. Both independent initial calculations include the
actual two shared deadline allocations and binding work beside every retained
raw/typed/Hello owner. No announced row supplies these terms.

Three physical channel controls and all twelve initial-reconstruction tests
pass. The latter cover 162 inherited parent/child flights and the separate quote
control, including thirteen new public-channel flights for both program
families, occupied/missing/late descriptors, wrong peer, unchecked prior work,
constructor/terminal refusals and actual expiration. Queued public bytes remain
unread, no public bytes are emitted and the same descriptor/raw bank pointers
survive every outcome. A reused schema-fixture helper now limits requested
schema mutations to its own cases instead of treating a missing socket as a
missing schema.

Both complete Transport configurations pass 1,819 tests with zero failures,
no filtering and sixteen existing ignores. Affected all-feature/all-target
checking, scoped formatting and all six architecture gates pass. Commit
`2e89a44c92` passes the required application compilation at
`/nix/store/ikazis4v9sf2xhcb873rzwb4jvjxnvjc-aos-test-targets-0.1.0`:
180 test executables across 58 package identities, including 71 integration
targets. It also passes the funded-Source VM at
`/nix/store/8cpl6qdjsiiqnpnb6lgj36111v8gsbqv-aos-vm-test-crucible-funded-source-templates-0`,
with both independent consumers, three actual retained private
Birth/declaration/projection/launch results, refusal controls and terminal
namespace/credit release. Its immutable application and three VM component
captures match all 168 owned changed Rust paths byte for byte. The full
Engine/Daemon results above remain tied to `99dc0fdb5e`.

This transition binds physical custody only. The native Hello exchange,
model-absent immutable policy, bootstrap ACK, full five-phase Recipe/Initial
producers and complete Native/Source restoration remain required.

## Retained original public Hello framing exchange

The original bootstrap now transfers its actual public channel and journal into
one retained framing constructor. An empty destination precedes either move.
The reservation keeps its original shared bank. Successful framing allocates
nothing; an owning bind refusal retains the actual Box, journal and same stream.
Missing streams and failed transfers preserve initialized partials and spent
state. Immutable loans recheck the physical cut and typed original guards after
the callback, including callback refusal.

The census walks the actual remaining stream, exchange and refusal owners. It
counts the Box payload, actual moved stream/cut backing and any distinct literal
bank. Only checked Rc equality with the original reservation or an earlier real
edge permits a bank discount. Outstanding original bank borrows refuse the
whole census. Exhaustive reader, journal and refusal field walks keep future
heap-bearing fields visible to this boundary. Binding errors are restricted to
the actual no-I/O constructor's static variants; an allocating successor error
requires its own retained layout.

Both initial calculations retain the same original channel/bank charges and add
only the new refusal Box bound, actual constructor moves and fixed controls.
Inline partials belong to the physical raw root. No duplicated reservation,
socket, renewed cut or old eager native policy is constructed. The public
channel's Read/Write implementation additionally checks its own completed,
unchanged original binding before the same bounded stream can perform I/O.

Four focused retained-exchange controls and all thirteen initial-reconstruction
tests pass. The latter cover 172 inherited-socket flights and a separate quote
control. Ten new flights check both program families, unchecked/expired prior
work, construct/terminal refusal, callback refusal and real expiration. The same
actual descriptor, journal bank and private raw pointers survive each outcome;
queued public bytes remain unread and no public bytes are emitted. A separate
physical I/O control checks actual read/write/flush, incomplete binding and
changed-cut refusal without consuming queued bytes or emitting a reply.

Both complete standard and raw-value Transport libraries pass 1,825 tests,
zero failures, no filtering and sixteen existing ignores. Affected
all-feature/all-target checking, scoped formatting and all six architecture
gates pass. The required application gate and funded-Source VM also pass for
`515e271742`. The application gate compiles 180 test executables across 58
package IDs, including 71 integration targets; all 172 owned changed Rust paths
match its immutable capture byte for byte. All three VM component captures
likewise match those 172 paths. Both independent consumers retain three actual
private Birth/declaration/projection/launch results, exercise refusal controls
and release their terminal namespaces and credit. The VM result is
`/nix/store/zm2lf3a24hyhjn1yrv6k88sflhpgrk28-aos-vm-test-crucible-funded-source-templates-0`.
The full Engine/Daemon runs remain qualified at `99dc0fdb5e`.

This creates a physical framing exchange only. Receiving/authenticating Hello,
the complete model-absent policy, bootstrap ACK, genuine five-phase Recipe and
Initial producers, native adoption and complete restoration remain required.

## Retained original public Hello literal

The original bootstrap now admits a bounded body allocation before its first
public read, then retains the actual header, body allocation and read cursors.
The incoming literal slot belongs to the same original journal and records each
observed prefix. Partial headers, partial bodies, expired reads, invalid lengths
and terminal refusals preserve initialized owners and a spent attempt. The
seven input banks and original private raw bodies remain unchanged.

The body retains an actual shared edge to its original journal allocation.
Complete-DATA loans require checked pointer equality with the same exchange,
its same reader bank and actual slot/header/body/progress correspondence.
Identical bytes on a different actual bank cannot substitute custody. The
whole census includes this fifth actual bank edge, discounts checked aliases
and separately charges distinct backing. No body hash or numeric identifier
substitutes for this actual ownership check.

Both initial calculations independently include the maximum separate body bank,
constructor moves and actual read/guard controls. The grouped Hello populations
keep roster, journal and body terms explicit. The public channel sets each
native socket timeout from the original opaque cut; deadline and changed-cut
refusals use allocation-free error kinds, including expiration between the
physical check and remaining-time calculation. The existing legacy stream path
keeps its original behavior.

Five lower-level controls cover unchanged literal bytes, partial allocations,
invalid lengths, occupied outputs and different-bank substitution. The original
exchange census control additionally checks fifth-edge alias/unique-bank charges
and borrowed-bank refusal. Fifteen new actual inherited-socket flights cover
both program families, missing prior framing, pre-read/construct/terminal
refusal and expiration, malformed lengths, partial headers and bodies, timeout,
callback refusal and an expired loan. Refused pre-read admission leaves the
public header queued; successful reads leave the following suffix queued. No
public reply is emitted, no retry is accepted and actual allocations survive.

Both complete standard and raw-value Transport libraries pass 1,831 tests,
zero failures, no filtering and sixteen existing ignores. Affected
all-feature/all-target checks, scoped formatting and all six architecture gates
pass for `eed8d27107`. The required application gate also passes, compiling
180 test executables across 58 package IDs, including 71 integration targets.
All 175 owned changed Rust paths match its immutable source capture byte for
byte. The funded-Source VM passes with three independently checked component
captures matching the same 175 paths. Both consumers complete all three private
Births, declaration and launch projections, refusal controls and cleanup. The
default-feature CLI refusal also passes. Engine/Daemon full library execution
remains qualified at `99dc0fdb5e`.

A complete literal deliberately leaves response publication disabled. Strict
Hello parsing and authentication, complete model-absent policy, bootstrap ACK,
genuine Recipe/Initial producers, native adoption and restoration remain open.

## Strict original public Hello Value

The same original literal now has a separately admitted strict JSON parser
occurrence. Its empty owner exists before the first private read. A fixed quote
admission precedes the lexical census, and a separate constructor admission
precedes Value allocation. The actual Value or owned grammar diagnostic is
installed before terminal follow-up. Quoted-string errors retain fixed
category/line/column DATA while their unchanged raw token remains in the body
and journal. Failed admission, parsing, terminal correspondence and expiration
leave the occurrence spent and every surviving owner in the whole census.

Both prospective initial calculations price this same parser from the bounded
future literal population. The actual quote uses its immutable lexical counts
and the same population-to-layout function. The diagnostic text bound comes
from one closed roster used by the actual strict parser; accepted grammar and
error text remain unchanged. The strict tree census admits its own lexical
work and 64-container/terminal-scalar depth, without DTO or RawValue expansion
or an SDK response-forest allowance. Parser outputs, diagnostic growth,
temporary serde error layout, lookup and actual guard controls remain separate
terms under the unchanged independent peak restriction.

Three lower controls cover retained success and failure, a real depth-64 leaf,
and actual/future row correspondence. Nineteen new inherited-socket flights
cover both families, malformed grammar, duplicate keys, nonfinite numbers,
Unicode errors, depth limits, ordinary RawValue-named keys, each admission,
expiration, callbacks and retries. Existing original-body pointers, seven empty
input banks, the same queued suffix and absence of public replies are checked.
The finite inert Prepare fixture is enlarged to fund its actual new tree;
production ceilings and the independent 256 MiB restriction are unchanged.

Both unfiltered standard and raw-value Transport libraries pass 1,836 tests
with zero failures and sixteen existing ignores. The Format library passes
33 tests with one existing ignore. Scoped formatting and all six architecture
gates and affected all-feature/all-target checking pass for `f2150ce5c7`. The
required application gate passes with 180 test executables across 58 package
IDs, including 71 integration targets. The funded-Source VM passes both
independent consumers, each retaining three actual private Births and passing
refusal/cleanup checks, plus the default-feature CLI refusal. All 183 owned
changed Rust paths match the application capture and each of the three VM
component captures byte for byte against that commit. The full configured Engine
library passes 2,036 tests in 8.67 seconds, with zero failures, no filtering and
34 existing ignores. The full configured Daemon library passes 1,826 tests in
244.36 seconds, with zero failures, no filtering and 165 existing ignores.
Parsing supplies DATA only.
Complete Hello authentication, the model-absent native policy, bootstrap ACK,
genuine Recipe/Initial producers and native adoption/restoration remain required.

## Original initial Hello request and typed offer

The retained bootstrap now owns a separate request attempt before its first
private read. Fixed quote admission precedes inspection, and a stored concrete
row precedes the actual borrowed-Value offer decoder. Initial-only envelope and
body fields, sequence, identifiers, session, canonical token/nonce, feature
rosters and receiving limits are checked against the same original launch,
retained native roster and nonrenewing cut. Limits use the defining validation
predicate without allocating a diagnostic; token decoding writes into a fixed
caller-owned slice. Neither operation copies the original envelope or body.

The actual closed Offer1 decoder is priced through its concrete field partials,
root vectors, String leaves, pinned serde error layout and actual validation
reasons. Aggregate cardinality is checked before typed allocation. Both initial
calculations independently include this output alongside the original strict
tree. The declared typed registry is empty: valid optional definitions remain
unselected, and required definitions refuse. This does not install a live
registry, issue a connection, publish Hello or admit native execution.

Actual typed outputs and validation reasons survive refusal; syntax failures
retain scalar coordinates beside the unchanged original tree. Original input
and terminal guards surround inspection and Copy-only loans, including callback
failure and expiration. Retry remains spent. Eight lower controls cover both
families, every closed request field, canonical base64, actual validator reasons,
required/optional definitions, failed partials and the real 256-definition bound.
Nineteen inherited-socket flights additionally cover all admission boundaries,
expiration, foreign claims and original allocation/pointer custody without replies.

Both final unfiltered standard and raw-value Transport libraries pass 1,845
tests with zero failures and sixteen existing ignores. Format passes 33 tests
with one existing ignore; Source-birth passes all 62 tests. All six architecture
checks pass. The first raw-value run passed 1,844 tests and failed the prior
initial peak fixture; its isolated rerun passed. That fixture regenerated a
child-local launch/PID and commitments instead of pricing the parent's received
operands. The corrected control prices those actual inputs and sets its ceiling
one byte below their independent row; both final full libraries include it.
Production checks and ceilings are unchanged.

Affected all-feature/all-target checking and scoped formatting also pass for
`42f8197dd0`. The required application gate passes with 180 test executables
across 58 package identities, including 71 integration targets. The funded-Source
VM passes both independent consumers, each retaining three original private
Births and passing refusal and cleanup controls, plus the default-feature CLI
refusal. All 190 owned changed Rust paths match the committed checkpoint in the
application capture and each of the three VM component captures. Full Engine
and Daemon libraries remain qualified at `f2150ce5c7`. Full live Hello
authentication, model-absent policy, bootstrap ACK and the remaining RFC
acceptance exits are still required.

## Fresh Hello configuration and exact empty-registry census

An allocation-free clone-backing supplier walks the original installation
fields and defining native feature/key declaration. Fresh String and Vec lengths
replace original spare capacities; concrete field witnesses cover the complete
installation and negotiation policy. Tree populations share the same maximum
entry layout as the retained owner's metadata census. JSON is ordinary Value
data, including RawValue-named keys, with the existing 64-container depth bound.
An unavailable pinned map layout or owning Number representation refuses.

A retained Handshake constructor validates the actual installation and policy
before moving either owner. Validation errors preserve both original slots;
success moves their allocations once into a fresh unadmitted issuer. The normal
constructor uses the same validation and fresh initialization. Its validation
order, epoch/gate allocations and admission behavior are unchanged.

The boot extension wrapper now has a census requiring its exact concrete
registry Rc, the internal zero-field marker and an unselected wrapper. Equal
empty advertisements from another allocation cannot substitute for this owner.
The corresponding wrapper constructor refuses an owning marker before consuming
the plain handshake. Historical known-registry owners keep their separate census.

Ten new controls pass for `66e859f087`. Both complete standard and raw-value Transport libraries
pass 1,855 tests, with zero failures, no filtering and sixteen existing ignores.
Scoped formatting, affected all-feature/all-target checking and all six
architecture checks pass. Required application compilation passes with 180 test
executables across 58 package identities, including 71 integration targets. The
funded-Source VM passes both independent three-Birth consumer flights, refusal
controls, cleanup and the default-feature CLI refusal. All 199 owned changed Rust
paths match this committed checkpoint in the application and three VM component
source captures. Subsequent clone-control work is excluded from these results.

The clone supplier prices backing only. Complete constructor validation and
control rows, original initial funding, bootstrap-retained registrar slots and
guarded invocation remain required before native use. These helpers supply no
opaque Initial/Recipe, connection lease, Hello reply, ACK, model or Ready result.

## Retained fresh registrar under original bootstrap custody

The complete registrar component now prices the pinned Rust String, Vec and
BTreeMap clone controls, the actual closed installation/policy validation,
partial owners and fresh shared epoch/gate/registry allocations. Concrete field
rosters bind the typed compositions; quote-control arrays share their actual
compiler-checked roster types. The original empty request-ID tree contributes
its real combined-census delta without being represented as a cloned map.

Source and native initial calculations independently include this retained
population beside every earlier raw, typed, literal and request owner. The
physical registrar attempt exists before the first private read. Separate
admissions cover quote work and the stored constructor row before allocation.
Actual configuration, validation errors, plain issuer, concrete empty registry
and unselected extension wrapper remain in their initialized slots on failure.
The same original request, launch, roster and cut guard every callback and
constructor outcome; retries refuse without releasing surviving allocations.
An immutable completed-wrapper loan checks the same guards after both successful
and error callbacks. This component creates no connection, reply, ACK or model.

Nine lower registrar controls, all four independent initial-construction controls
and fifteen inherited-socket flights pass. The inherited positive launch fixtures
now sort the complete schema roster by its actual (ID, edition) contract; the
older malformed order remains a refusal control and retains its real SDK
validation error. Both program families, quote/constructor/terminal admission
refusals, expiry, substituted cuts, unchanged original allocations and spent
retries are covered. Production ceilings and validation remain unchanged.
For `d96da4c4b9`, both complete standard and raw-value Transport libraries pass
1,861 tests, with zero failures, no filtering and sixteen existing ignores.
Affected Transport/Engine/Daemon all-feature/all-target checking, scoped
formatting and all six architecture gates pass. The required application gate
passes with 180 test executables across 58 package identities, including 71
integration targets. The funded-Source VM passes both independent three-Birth
consumer flights, refusal controls, cleanup and the default-feature CLI refusal.
All 207 owned changed Rust paths match this committed checkpoint in the
application capture and each of the three actual VM component captures. The
exact running VM derivation supplies those captures; later reevaluation after
repository metadata changes is not substituted for its recorded inputs.

Later SDK request construction is excluded from these results. Full Engine and
Daemon libraries remain qualified at `f2150ce5c7`. Full Native18 policy, live
Hello authentication, reply/ACK and the remaining RFC acceptance exits remain
unfinished.

## Actual SDK request under original Hello custody

The original bootstrap now decodes the real SDK `HelloRequest` directly from
its checked strict body after the original claims and fresh registrar checks.
The physical attempt exists before the first private read. Quote, constructor
and terminal census require separate admissions; the original cut and complete
input correspondence guard every outcome. A completed typed request remains in
its actual slot when correspondence or terminal admission refuses. Decode
failures retain their actual scalar serde coordinates, and retries stay spent.

Every typed body field is checked against the original tree. Fixed-array
base64 decoding compares the original nonce and token without re-encoding
secrets. Unsorted unique offered versions, unknown optional features and larger
advertised receiving limits remain intact; selected limits stay unchanged.
Initial resume fields and body extensions remain unavailable. A Copy-only
immutable loan checks original correspondence after error callbacks as well.

Both independent initial projections include the actual SDK request row.
Bounds cover the real derive partials, cautious Vec growth, decoded text,
two Bytes decoders, diagnostics and complete comparison controls. Subsequent
construction prices a completed registrar loan separately from the earlier
configuration constructor. The enclosing calculation uses the maximum controls
of the sequential registrar and request quotes while retaining their independent
fixed rows. Earlier runs exposed that summed controls exceeded the unchanged
1 MiB raw-only test policy; no policy or production ceiling is raised.

All seventy bootstrap controls pass with zero failures and one existing ignored
private child. Seven new controls include seventeen inherited-socket flights across
both program families, admission refusals, expiry, substituted cuts, surviving
allocation identity and spent retries.

For `5c3ed76904`, both complete standard and raw-value Transport libraries pass
1,868 tests each, with zero failures, no filtering and sixteen existing ignores.
Affected Transport/Engine/Daemon all-feature/all-target checking, scoped
formatting and all six architecture gates pass. The required application gate
passes with 180 test executables across 58 package identities, including 71
integration targets. The funded-Source VM passes both independent three-Birth
consumer flights, refusal controls, cleanup and default-feature CLI refusal
with normal shutdown. All 211 owned changed Rust paths match this committed
checkpoint in the application capture and all three actual VM component source
captures. These captures come from the exact running build derivations.

Subsequent HelloResult and provider-challenge work is excluded from this
qualification. Full Engine and Daemon library runtime qualification remains at
`f2150ce5c7`. This transition issues no connection, reply, bootstrap ACK, native
policy, model or opaque Initial/Recipe; remaining RFC exits stay unfinished.

## Retained actual SDK Hello result and provider challenge

The original bootstrap now constructs the real initial SDK `HelloResult` after
the typed request and fresh registrar. Its physical attempt, fixed challenge
array and scalar entropy-error slot exist before the first private read.
Separately admitted construction obtains actual Linux kernel entropy with
nonblocking `getrandom`, checking the original cut before and after reads.
Partial progress remains in the same array, EINTR retries only its unwritten
suffix, and unavailable entropy refuses without substituting bytes or renewing
credit. Completed result ownership precedes terminal admission and guards.

The result owns fresh copies of both challenges, original session/incarnation,
selected features and the complete provider manifest, including all supported
profiles, facets, schema references, qualification references and extensions.
The selected receiving limits remain unchanged; initial resumption stays empty.
Compiler-bound concrete field rosters price the actual pinned clone DAGs.
Both independent initial projections include the new retained population, its
constructor/clone overlap and exact quote controls. A first broad bootstrap run
exposed summed sequential manifest-walk controls exceeding the raw-only policy;
the complete field walks now reuse their maximum recursive control window while
retaining actual quote arrays and result headers. No resource ceiling changes.

Five lower controls and seventeen inherited-socket flights pass, including
actual kernel result construction, complete profile/facet/extension cloning,
spare-capacity independence, partial reads, interruption, unavailable entropy,
both program families, all admissions, expiry and retained error-callback
custody. All 76 bootstrap controls pass with zero failures and one existing
ignored private child.

For `094ae8e7b9`, both complete standard and raw-value Transport libraries pass
1,874 tests each, with zero failures, no filtering and sixteen existing ignores.
Affected Transport/Engine/Daemon all-feature/all-target checking, scoped
formatting and all six architecture gates pass. Required application compilation
passes with 180 test executables across 58 package identities, including 71
integration targets. The funded-Source VM passes both independent three-Birth
consumer flights, refusal controls, cleanup and default-feature CLI refusal.
All 217 owned changed Rust paths and the Transport manifest match that committed
checkpoint in the application and all three actual VM component captures.
These captures come from the exact build derivations.

Full Engine and Daemon library runtime qualification remains at `f2150ce5c7`.
Subsequent envelope construction is excluded from this qualification. This
component does not perform live SDK authentication, publish Hello/ACK, construct
Native18 policy, adopt a model or supply opaque Initial/Recipe authority.

## Original SDK request envelope construction

The original bootstrap now decodes the actual SDK request Envelope directly
from the same checked strict Value, after the typed request, fresh registrar and
real HelloResult. Physical attempt/output/error slots precede private receipt.
Separate original admissions surround quote, decoder and terminal census. The
complete actual output is retained before correspondence and validation; every
header, body member and extension value must match the unchanged original tree.
Immutable Copy-result loans repeat all original guards on either callback
outcome. Refusal preserves output ownership and spends the occurrence.

Both independent Initial projections include the new retained body and extension
population. Compiler-bound field witnesses cover the entire closed initial
selection grammar, including each semantic-version object. The pinned JSON Value
visitor ignores sequence size hints; all five array populations include their
actual minimum four-slot allocation and geometric growth. Full initial limits
remain unchanged. Six lower controls and seventeen inherited-socket flights
exercise the actual decoder, original-field correspondence, fresh backing,
full 256-selection geometry, stale/substituted cuts, admissions, expiry and
retained callback failures. A first broad run exposed six Prepare refusals: the
new retained projection priced 256 selections even when their required literal
fields could not fit the frame. The corrected future population uses a
compiler-bound minimum encoded extent for all five objects, every field name,
validated scalar leaves and both 64-character digests. Body array counts also
include their required comma separators. All original program families now have
an explicit regression checking each unchanged Prepare axis. All 83 bootstrap
controls pass with zero failures and one existing ignored private child.

For `ffbe2ee404`, both complete standard and raw-value Transport libraries pass
1,881 tests each, with zero failures, no filtering and sixteen existing ignores.
Affected Transport/Engine/Daemon all-feature/all-target checking, scoped
formatting and all six architecture gates pass. Required application compilation
passes with 180 test executables across 58 package identities, including 71
integration targets. The funded-Source VM passes both independent three-Birth
consumer flights, refusal controls, cleanup and default-feature CLI refusal.
All 222 owned changed Rust paths and the Transport manifest match that committed
checkpoint in the application and all three actual VM component captures.
These captures come from the exact build derivations. Subsequent response
construction is excluded. Full Engine and Daemon library runtime qualification
remains at `f2150ce5c7`.

This transition grants no live SDK connection, response publication, bootstrap
ACK, Native18 policy, model or opaque Initial/Recipe authority.

## Actual Completed Hello response and response Envelope

The original bootstrap now serializes the real SDK HelloResult into an actual
Value, moves its object into the real Completed response, and serializes that
response into a second independently owned body. The real response Envelope
retains its own original request identity, actual selected incarnation and
explicit empty installed-selection extension. Each serializer output enters a
physical slot before the next fallible step. Header ownership precedes fallible
body moves; a nonobject move restores its exact original Value. Refusal retains
all initialized output and scalar serializer coordinates, and retries stay spent.

Separate original quote, constructor and terminal admissions remain under the
same cut and complete immutable request/result guards. Both independent Initial
projections price the two simultaneous DOM populations, real header clones,
selection map, typed empty roots and intermediate empty envelope root. Actual
serde JSON associated compound types and exhaustive manifest field rosters
bound the serializer controls. Sibling field paths reuse their maximum window;
JSON retains the checked 64-container plus terminal-scalar population. Future
32-byte challenges contribute their defining 43-byte unpadded representation
without constructing fake result/challenge DTOs in Source quoting. Actual
formatting occurs only in the admitted native serializer. Census never formats
secrets. No resource ceilings change.

Six lower controls and seventeen inherited-socket flights cover both program
families, independent body backing, complete profile/facet/extension content,
literal RawValue marker keys, original spare capacities, serializer refusal,
partial moves, original admissions, expiry and spent retries. All 90 bootstrap
controls pass with zero failures and one existing ignored private child.

For `ea264ebca3`, both complete standard and raw-value Transport libraries pass
1,888 tests each, with zero failures, no filtering and sixteen existing ignores.
Affected Transport/Engine/Daemon all-feature/all-target checking, scoped
formatting and all six architecture gates pass. Required application compilation
passes with 180 test executables across 58 package identities, including 71
integration targets. The funded-Source VM passes both independent three-Birth
consumer flights, refusal controls, cleanup and default-feature CLI refusal.
All 229 owned changed Rust paths and the Transport manifest match that committed
checkpoint in the application and all three actual VM component captures.
These captures come from the exact build derivations. Subsequent selected and
retired SDK census work is excluded. Full Engine and Daemon library runtime
qualification remains at `f2150ce5c7`.

Live SDK admission, response publication, bootstrap ACK, Native18 policy, model
adoption and opaque Initial/Recipe construction remain separate unfinished
transitions.

## Selected and retired original SDK census

A separate empty-registry state census now covers the actual SDK wrapper and
its supplied retained lease through selection, failed authentication, containment
and supersession. The original unselected-only census keeps its phase contract.
Both registrar allocations must match before their shared backing is discounted;
equal epochs, connection claims or selected contents cannot establish aliases.
Actual lease-owned capacities are counted under an exhaustive field roster.
The selected slice is counted once only when its Arc matches. Resumption leaves
an older lease's distinct empty allocation charged after revocation.

Eight new controls cover genuine admissions, retained spare capacity, rejected
authentication and contract checks, containment, supersession, equal-looking
foreign owners, missing/nonempty selections and each independently substituted
registrar allocation. For `83aad1de3f`, both complete standard and raw-value
Transport libraries pass 1,896 tests each, with zero failures, no filtering and
sixteen existing ignores. Affected Transport/Engine/Daemon all-feature/all-target
checking, scoped formatting and all six architecture gates pass. Required
application compilation passes with 180 test executables across 58 package
identities, including 71 integration targets. All 232 owned changed Rust paths
and the Transport manifest match that committed checkpoint in the exact
application derivation's captured source. No funded-Source VM is rerun for this
standalone census checkpoint. Subsequent borrowed-custody changes are excluded.
This census grants no currentness or native authority and does not yet perform
original Native18 SDK admission.

## Borrowed original physical custody

The raw receiver and initial kernel/launch join now use a shared borrow of the
original process, thread, immutable deadline and inherited socket fields. The
view allocates nothing and duplicates no descriptor. Its separate field borrows
allow later SDK verifier callbacks to check physical custody while the original
registrar is mutably borrowed. Constructing the view authenticates nothing;
each channel use checks origin, expiry and actual parent/UID credentials.
The controller join uses the same kernel snapshot for its launch PID/UID check.

Actual borrow and guard controls are included in raw and initial construction
scratch. Both independent Initial calculations remain under the unchanged
limits. Cross-thread and same-process socket substitution controls pass, as do
all 92 original bootstrap controls, with zero failures and the existing private
child ignored.

For `976b2c992d`, both complete standard and raw-value Transport libraries pass
1,898 tests each, with zero failures, no filtering and sixteen existing ignores.
Affected Transport/Engine/Daemon all-feature/all-target checking, scoped
formatting and all six architecture gates pass. Required application compilation
passes with 180 test executables across 58 package identities, including 71
integration targets. The funded-Source VM passes both independent three-Birth
consumer flights, refusal controls, cleanup and default-feature CLI refusal.
All 233 owned changed Rust paths and the Transport manifest match that committed
checkpoint in the application and all three exact VM component source captures.
Subsequent SDK authority/failure slots are excluded. Full Engine and Daemon
library runtime qualification remains at `f2150ce5c7`. Live Native18 SDK admission
and its model-absent policy/ACK route remain unfinished.

## Retained initial SDK admission primitive

The pre-read registrar attempt now includes physical slots for actual SDK
connection authority and admission failure, plus a separately spent occurrence.
Its initial-only primitive calls the real SDK against borrowed original request,
response and typed Hello operands. A returned lease enters its slot before
fallible terminal cut/registration checks. SDK or terminal refusal retains the
actual diagnostic and contains the issuer. Later enclosing refusal can revoke
registration without reclaiming the lease or its backing.

The selected/retired census includes these real owners. A distinct state loan
checks the retained selected lease while preserving the original unselected-only
loan's phase contract. Subsequent immutable Hello guards use that state loan;
failed or revoked admission cannot reopen those loans. Complete diagnostics
remain retained when an unknown error representation makes census refuse.

Six new model-callback controls exercise genuine SDK issuance for both program
families, actual diagnostic capacity, post-SDK expiry, later containment,
request/response correspondence refusal, incomplete/resumed operands and spent
retries. All 98 bootstrap controls pass, with zero failures and the existing
private child ignored. These SDK unit controls establish no native process
qualification. The original bootstrap still needs the complete separately
admitted SDK constructor row and genuine Native18 verifier before invoking this
primitive; response publication, ACK, model-absent policy and opaque
Initial/Recipe production remain unfinished.

For `7f03e6b84c`, both complete standard and raw-value Transport libraries pass
1,904 tests each, with zero failures, no filtering and 16 existing ignores.
Affected Transport/Engine/Daemon all-feature/all-target checking, scoped
formatting and all six architecture gates pass. Required application compilation
passes with 180 test executables across 58 package identities, including 71
integration targets. The funded-Source VM passes both independent three-Birth
consumer flights, refusal controls, cleanup and default-feature CLI refusal.
All 235 owned changed Rust paths and the Transport manifest match that committed
checkpoint in the application and all three exact VM component source captures.
Subsequent selection lookup and SDK backing projection changes are excluded.
Full Engine and Daemon library runtime qualification remains at `f2150ce5c7`.

## Direct SDK selection lookup

Initial Hello admission now queries the validated, strictly ordered required and
optional feature arrays directly. It preserves their union membership semantics
without collecting an intermediate tree. Selected envelope-extension names enter
the final retained set by insertion, avoiding the temporary vector and stable
sort used by the pinned standard library's `BTreeSet::from_iter` implementation.
The complete installed policy still determines every retained selected name.

Three focused controls pass: all 32 small advertised/selected feature
combinations against an independent union oracle, invalid order/duplicate
refusal before callbacks, and all four feature combinations against the complete
installed envelope-name projection. This change grants no native authority and
does not supply the remaining SDK constructor funding row or Native18 verifier.

For `741fc2442b`, both complete standard and raw-value Transport libraries pass
1,907 tests each, with zero failures, no filtering and 16 existing ignores.
Affected Transport/Engine/Daemon all-feature/all-target checking, scoped
formatting and all six architecture gates pass. Required application compilation
passes with 180 test executables across 58 package identities, including 71
integration targets. All 236 owned changed Rust paths and the Transport manifest
match the committed checkpoint in that exact application source capture. This
standalone lookup checkpoint has no separate VM rerun; its preceding SDK
ownership checkpoint retains the VM qualification above. Subsequent initial SDK
backing projection work is excluded. Full Engine and Daemon library runtime
qualification remains at `f2150ce5c7`.

## Prospective initial SDK retained backing

Both independent Initial calculations now reserve the additional retained owners
of successful initial empty-registry SDK admission: two connection strings, lease
session/incarnation strings, two selected-feature vectors, complete selected
envelope names, the request-ID journal and the new shared empty selection.
The existing concrete configuration seeds the combined tree geometry; smaller
standalone set layouts cannot discount the existing census's larger JSON entry
layout. Shared-header arithmetic also retains the existing registrar/registry
population when the new selection changes maximum alignment. No lease is
constructed or cloned by this calculation.

The new census control passes for both program families, maximum-length request
IDs and spare request/feature capacities. It compares independently projected
backing with real SDK admission's before/after census and verifies containment
retains that same ownership. Four independent Initial controls pass.

The first complete bootstrap run passed 97 controls and failed two: the reactive
Initial retained projection exceeded the unchanged 80-MiB Prepare partition by
9,654 bytes. The Offer decoder's former eight-times-per-root vector allowance
was tightened to the pinned serde cautious-size-hint and Rust Vec growth bound,
four times each bounded length plus four slots. Its actual 256-definition
control remains passing. The corrected run passes all 99 bootstrap controls,
with zero failures and the existing private child ignored. No resource ceiling
was raised.

For `1093ea1f08`, both complete standard and raw-value Transport libraries pass
1,908 tests each, with zero failures, no filtering and 16 existing ignores.
Affected Transport/Engine/Daemon all-feature/all-target checking, scoped
formatting and all six architecture gates pass. Required application compilation
passes with 180 test executables across 58 package identities, including 71
integration targets. The funded-Source VM passes both independent three-Birth
consumer flights, refusal controls, cleanup and default-feature CLI refusal.
All 237 owned changed Rust paths and the Transport manifest match that committed
checkpoint in the application and all three exact VM component source captures.
The later SDK I/O census change is excluded. Full Engine and Daemon library
runtime qualification remains at `f2150ce5c7`.

Only retained successful ownership is reserved by this addition. Complete SDK
constructor transient/validation/callback funding, the genuine Native18 verifier
and original-root invocation remain unfinished. No response publication, ACK,
Native18 policy, model adoption, opaque Initial or Recipe is granted.

## SDK I/O failure custody

The registrar census now recognizes the pinned Rust I/O error representations
that contain no custom owner. Its public `get_ref()` query returns `None` for
OS codes, simple kinds and static messages; their complete storage stays inside
the already retained error header. A custom error still returns `Some` and makes
census refuse while its actual diagnostic remains owned. The query formats
nothing and invokes no erased diagnostic callback. Its additional borrowed
query controls are included in the same Source/native calculations.

A model-callback control passes raw OS, simple-kind and owning custom refusals
through the actual SDK. It checks the original wrapper, contained/nonloanable
state, actual retained error, unchanged census for nonowning cases, preserved
custom diagnostic pointer/capacity on census refusal, and spent retries.
The existing exact encoded-credit control also passes after replacing discarded
preflight error text with a nonowning simple kind; its public resource refusal
is unchanged.

For `3e19413bc5`, both complete standard and raw-value Transport libraries pass
1,909 tests each, with zero failures, no filtering and 16 existing ignores.
Affected Transport/Engine/Daemon all-feature/all-target checking, scoped
formatting and all six architecture gates pass. Required application compilation
passes with 180 test executables across 58 package identities, including 71
integration targets. All 238 owned changed Rust paths and the Transport manifest
match that committed checkpoint in its exact application source capture. This
standalone I/O census checkpoint has no separate VM rerun; the preceding initial
SDK backing checkpoint retains the VM qualification above. Later borrowed
manifest ordering work is excluded. Full Engine and Daemon library runtime
qualification remains at `f2150ce5c7`. This establishes no Native18 process,
SDK constructor funding, verifier, policy, ACK or model grant.

## Borrowed Hello manifest ordering

The portable ordering helper now permits keys borrowed from the original roster.
Hello's full Provider/Node/Implementation manifest validators compare those
original identifier, edition and domain/digest keys directly. All IdSet ordering
checks likewise borrow identifier text. Their array ceilings, strict order,
duplicate rejection, field diagnostics and child-validation order are unchanged.
No validator sorts or modifies the original roster. Historical constructor
key-clone allowances remain conservative; no existing resource credit is reduced.

Three new contract controls cover duplicate and reversed order in all ten actual
Hello manifest rosters, identifier/edition and domain/digest tie breakers, and
oversized-roster refusal before duplicate or child errors. All 64 active format
crate tests pass, with zero failures and the existing private child ignored.
For `966aba7b3a`, both complete standard and raw-value Transport libraries pass
1,909 tests each, with zero failures, no filtering and 16 existing ignores.
Affected Transport/Engine/Daemon all-feature/all-target checking, scoped
formatting and all six architecture gates pass. Required application compilation
passes with 180 test executables across 58 package identities, including 71
integration targets. The funded-Source VM passes both independent three-Birth
consumer flights, refusal controls, cleanup and default-feature CLI refusal.
All 242 owned changed Rust paths and the Transport manifest match that committed
checkpoint in the application and all three exact VM component captures. Later
verifier callbacks are excluded.

An attempted runtime refresh passed 1,828 Daemon tests and failed nine, with
166 existing working-tree ignores. Eight require the missing reference-device
setting; one requires the source-built gem5 profile compiled into the binary.
That invocation stopped before Engine runtime tests. It included preserved
external arm-root working-tree edits. A separately configured rerun is pending;
this failed invocation does not refresh the `f2150ce5c7` runtime qualification.

This reduces transient copies on the SDK path. Its complete constructor row and
original-root invocation remain unfinished, along with policy/ACK/model authority.

## Original Native18 Hello verifier callbacks

A private initial-only verifier now borrows the actual original process/thread,
private socket, unchanged cut, completed public exchange, immutable launch,
selected native roster and original SDK request/result objects. Each callback
checks the real kernel parent/UID and completed stream before and after its work.
It remeasures the controller image and compares its full ContentRef. Installation
identities, private token, complete implementation and launch receipt must match
the same launch. Contract selection requires the original result/feature objects,
exact native roster, empty initial schema policy and complete binding guarantees.
The enclosing root still owes its complete original input guards and funding.
These field loans do not establish enclosing Source/Birth provenance; the
genuine native producer must supply that grant independently of launch claims.

Callback state is spent before fallible work. Authentication precedes contract
selection; failures, repeats, resumption and replacement fencing refuse. The
verifier creates no descriptor, deadline, configuration clone or SDK lease.

The actual inherited-process control passes for both program families. It checks
identity/token/implementation/receipt substitution, copied request/result and
manifest/feature operands, nonempty schemas, changed guarantees, callback order,
spent retries, foreign process/thread, a substituted socket, changed/expired cuts
and a different full controller image reference. Original census is unchanged,
all banks and response remain retained, and SDK authority stays absent. All 101
bootstrap controls pass, with zero failures and the existing private child ignored.

The committed callback component (`bc505d677a`) passes all 1,910 Transport
library tests in both ordinary and RawValue configurations, with zero failures,
no filtering and sixteen existing ignores. All-feature/all-target checking,
changed-file formatting and all six architecture checks pass. The production
application-target gate compiles 180 test executables across 58 package IDs,
including 71 integration targets. All 245 owned Rust/Cargo inputs match that
commit and the registered application source capture; this gate runs no tests.

The complete configured runtime refresh passes 1,837 Daemon tests (248.34
seconds) and 2,055 Engine tests (7.99 seconds), with 166 and 34 existing ignores.
Daemon compilation uses the installed AOS gem5 closed-profile manifest; both
libraries use the source-built reference-device fixture. The first Engine run
has five fixture setup failures because its installed packet-provider variable
is absent. The unfiltered retry passes using the same compiled Engine executable
and the matching source-built packet provider. The runtime build also includes
the separately preserved arm-root working-tree changes; it is not an exact
committed-source qualification of those unrelated edits. The earlier complete
borrowed-ordering VM remains scoped to `966aba7b3a`; no callback VM is claimed.

This is a callback component. The original root has not invoked SDK admission
with it: the complete separately admitted SDK constructor and callback rows are
still required. Publication, ACK, Native18 policy, model adoption and opaque
Initial/Recipe production remain unfinished.

## Initial SDK tree and comparison control windows

The next constructor component follows the pinned Rust 1.98.1 incremental set
path through entry/search, leaf and internal splits, root growth and separator
propagation. Its private-record bounds follow complete field rosters rather than
constructing library-private values. The three actual key types are borrowed
version Strings, owned envelope names and original request IDs. Normal destruction
of the temporary borrowed-version set has a distinct loop/navigation row; no
arbitrary key destructor or comparator is included in that closed bound.

The SDK supplies initialized original-entry and verifier-bridge header controls
from their defining modules. The complete Provider/Node/Implementation field DAG
now also supplies initial request/result comparison depth, using exhaustive
field destructuring and actual child types. The comparison visitor names its own
concrete layer states, results and borrowed adapters. JSON children retain the
existing 64-container plus scalar profile. No serializer or comparison executes
during this calculation.

A real SDK model-callback control accepts 1,025 descending, unique protocol
versions for both program families, exercises internal tree splits, and preserves
the original wire order. Adding a duplicate preserves the original typed reason,
refuses before either trusted callback and spends admission. These controls do
not use the native verifier or grant native Source/Birth provenance. Both
complete Transport configurations pass 1,911 tests with zero failures, no
filtering and sixteen existing ignores; affected all-feature/all-target checking
and scoped formatting pass. The architecture gate initially rejected the enlarged
SDK negotiation module above its responsibility-review threshold. Its new pure
counter now lives in a focused child module. Commit `ef44e27984` passes all six
architecture checks and the required application test-target build: 180 test
executables across 58 packages, including 71 integration targets. All 250 owned
Rust/manifest inputs match that committed tree and the actual captured application
source. Both complete Transport configurations pass again after the extraction.
No threshold, review exception, limit or assertion is changed. No new VM run is
claimed; the complete borrowed-ordering VM remains scoped to `966aba7b3a`.

These are partial construction terms. Complete decoder/writer and validator
work, owning leaf clones and backing, native callback measurement/equality,
terminal census and genuine native producer admission remain required before
connecting the SDK call to the original root. Initial/Recipe, policy, ACK and
full RFC implementation remain unfinished.

## Initial SDK constructor funding

The closed original initial SDK path now has one composed retained/transient/
scratch row. It includes its repeated borrowed-Value offer decode, actual empty
selection decoder, nonnumeric bounded JSON writer and quoted U64 leaf, borrowed
version-set validation, complete typed comparison paths, original-body serializer
comparison, owning String/Id/feature clones, tree insertion and concrete native
verifier measurement/custody windows. The second typed offer remains local across
later phases and its complete retained demand joins transient demand. The actual
SDK's successful outputs and bounded closed validation failures join retained
demand. Arbitrary callbacks, changed input trees, nonempty installed registries
and resumption are outside this row.

Both independent initial formulas now compose all three axes instead of reserving
only success backing. The original Prepare and escrow limits are unchanged. The
102 focused bootstrap controls pass before the final quote-specific test addition;
the new short-credit, zero and overflowing-frame controls then pass separately.
The real SDK census-growth control now also checks the complete row for both
program families and spare-capacity variants. Commit `0740d92532` passes both
complete Transport configurations: 1,912 tests each, zero failures, no filtering
and sixteen existing ignores. Affected all-feature/all-target checking, scoped
formatting and all six architecture checks pass. The required application gate
compiles 180 test executables across 58 packages, including 71 integration targets;
it executes no tests. All 254 owned Rust/Cargo inputs match that committed tree
and the exact captured application source. No new VM or configured Engine/Daemon
runtime run is claimed for this constructor component.

At this checkpoint the original root does not invoke SDK admission. A pre-read
physical phase, separately admitted complete original guards/census and its genuine
enclosing Source/Birth producer must join this constructor before invocation. This change
produces no opaque Initial/Recipe, native policy, publication, ACK or model.

## Original root SDK admission transition

The original raw bootstrap now retains a fixed SDK admission occurrence before
its first private read. It spends before quote/guards, stores the independent
complete constructor row before allocation, and borrows the same original
request/result, request/response envelopes, inherited stream, immutable launch,
selection and nonrenewing cut for the concrete native verifier. Actual SDK lease
or failure custody stays in the registrar before any terminal guard or census.
A later refusal contains a successful lease while retaining its actual fields.
Only Copy DATA inspection of that same completed lease can leave the guarded
loan; this transition publishes no response, ACK, policy, model or opaque grant.

The complete native constructor row includes sequential original guard/census
windows and joins both independent initial formulas. Prepare/escrow limits remain
unchanged. One inherited-socket control passes all seventeen cases in 30.52s:
both program families, valid unsorted version advertisement, optional feature and
larger receiving limits, absent response, refusal/expiry at each admission
boundary, lease inspection refusal/expiry and cut substitution. It checks physical
input identity, actual census growth, once behavior and retained contained leases.
The inherited inert manifest's unsorted extension advertisement exposed a real
SDK validation refusal. Successful controls now supply a valid ordered fixture;
a separate negative control keeps the malformed input and its original typed
reason. Production validators and accepted grammar are unchanged.

Commit `29010f7389` passes both complete Transport configurations: 1,913 tests
each, zero failures, no filtering and sixteen existing ignores. Affected
all-feature/all-target checking, scoped formatting and all six architecture
checks pass. The required application gate compiles 180 test executables across
58 packages, including 71 integration targets; it executes no tests. All 257 owned
Rust/Cargo inputs match the committed tree and exact captured application source.
No new VM or configured Engine/Daemon runtime run is claimed for this transition.

The admissions in these controls are model funding callbacks; they do not grant
genuine Source/Birth credit. The
genuine enclosing producer, opaque Initial/Recipe, Native18 policy, publication,
ACK, model adoption and full RFC acceptance remain unfinished.

## Original literal response publication custody

A new byte-only publication primitive retains its original cut, actual shared
journal edge, outgoing lifetime slot and first failure. It spends before original
checks, copies the complete independently prepared response into the existing
reserved journal before any write, and advances only successful write counts.
Interrupted writes retry under the same cut; partial, zero or failed writes stay
spent. Expiry after the last write preserves complete physical progress while
refusing successful completion. Replacing the publication capsule cannot reopen
the journal. Neither this transition nor its raw frame digests marks an incoming
literal as parsed or grants SDK, Source, policy, ACK or native readiness.

Seven focused controls pass, including a real Unix socket and actual kernel
broken pipe, every partial prefix, zero writes, unknown custom I/O ownership,
expired/substituted cuts, foreign literal/bank custody and final-write expiry.
The bank keeps the complete original proposal beside actual progress. Non-owning
kernel/simple I/O failures have no additional retained heap; unknown custom
errors stay owned and their census refuses without a source layout declaration.
The byte transition's row excludes independently admitted response preparation,
stream implementation work/backing and containing-root guards/census. These
controls do not qualify a whole Native18 publication route or genuine credit.

Commit `66847e70c4` passes both complete Transport configurations: 1,920 tests
each, zero failures, no filtering and sixteen existing ignores. Affected
all-feature/all-target checking, scoped formatting, all six architecture checks
and the required application test-target build pass. The application gate
compiles 180 test executables across 58 packages, including 71 integration targets;
it executes no tests. All 259 owned Rust/Cargo inputs match the committed tree and
exact captured application source. No new VM or configured Engine/Daemon runtime
run is claimed for this byte component.

Original-root response encoding, pre-read physical publication custody, complete
funding, lease containment on terminal refusal and
the genuine enclosing producer still need to join this primitive before the
Native18 route can publish. All full RFC acceptance exits remain open.

## Borrowed canonical Hello response writing

The authoritative JCS object implementation now accepts both original JSON map
and extension BTreeMap borrows at their actual enclosing container depth. The
existing Value writer uses that same object implementation. UTF-16 key ordering,
number formatting, escaping and the 64-container limit remain unchanged. New
collection-adapter controls join the original counter; no Source limits change.

A closed borrowed Envelope writer emits its exhaustive thirteen-field roster in
canonical order and lends its body/extension maps directly. Header serializers
handle only the original typed strings, nullable IDs, unit variants and U64;
numeric JSON leaves stay in the authoritative JCS writer. No second whole Value
or request reconstruction supplies the response. Two focused Transport byte
comparisons pass, and the complete Format suite passes 67 tests with one existing
ignore, including three new integration controls for both collection types,
Unicode ordering, depth/array limits and every refused output prefix.

Commit `9255eee791` passes both complete Transport configurations: 1,922 tests
each, zero failures, no filtering and sixteen existing ignores. Affected
all-feature/all-target checking, scoped formatting, all six architecture checks
and the required application test-target build pass. The gate compiles 180 test
executables across 58 packages, including 71 integration targets; it executes no
tests. All 263 owned Rust/Cargo inputs match the committed tree and exact captured
application source. No new VM or configured Engine/Daemon runtime run is claimed.

The bounded retained output owner, prospective complete construction row,
original-root publication/containment transition and
genuine enclosing Source/Birth funding remain to be connected. This codec grants
no SDK, Source, policy, Initial/Recipe, ACK or native readiness.

## Original-root admitted Hello publication

The original bootstrap now installs its concrete encoding/publication attempt
before private receipt. Separate admissions cover the complete pure quote,
construction/publication and surviving census. Encoding borrows the original
thirteen-field response into one bounded retained byte bank. The existing SDK
lease and all original input/response/socket owners stay in place. An actual
frame overflow refuses before the journal or public socket is written.

The same retained exchange publishes the complete proposal through the original
literal and journal. Full original SDK/input guards precede the first byte and
follow publication and the terminal census callback. Terminal refusal contains
the actual lease while preserving partial bytes, diagnostics, the journal edge
and physical write progress. Guarded Copy-only inspection lends the completed
body without moving any owner. Retry cannot re-enter admission or publish again.

Both independent Source Initial formulas include the complete publication row.
It covers future complete Envelope shape, bounded output, canonical ordering,
serializer/error work, retained diagnostics and concrete Unix write controls.
The timeout/send operands use the defining libc ABI types; no extra descriptor
or deadline owner is constructed. Whole-bootstrap census includes initialized
publication backing even before binding or after failure. Existing Source caps
remain unchanged.

All seventeen inherited-socket publication controls pass, including both
program families, pre-effect admission refusal/expiry, terminal refusal/expiry,
actual broken pipe, response frame overflow and guarded body loans. The complete
Format suite passes 67 tests with one existing ignore.

Commit `4563cc63ee` passes both complete Transport configurations: 1,923 tests
each, no failures/filtering and sixteen existing ignores. Affected all-feature/
all-target checking, scoped formatting and all six architecture gates pass. The
required application gate compiles 180 test executables across 58 packages,
including 71 integration targets; it executes no tests. All 267 owned Rust/Cargo
inputs match the committed tree and exact captured application source. Adding
the already locked libc dependency required refreshing the exact vendor staging
hash; the initial stale-hash refusal is retained as evidence. No new VM or
configured Engine/Daemon runtime qualification is claimed.

Its test admissions remain model controls: they do not create genuine Source/Birth credit or publication
permission. The genuine enclosing producer, model-absent Native18 policy,
bootstrap ACK, opaque Initial/Recipe, restoration and full RFC acceptance remain
unfinished.

## Shared original decoded launch custody

The native decoder now moves the actual successful selected9 DTO into one
immutable Rc before any later boot decoder. Original typed-body borrows still
refer to that same object. A future model-absent policy can retain its graph
without cloning the launch, configuration or children. Equal separately decoded
launches remain distinct owners; future alias discounts must prove pointer
identity with this original shared edge.

Both independent parser calculations include the defining shared allocation,
move headers and fixed controls. Whole decoded-body census counts its actual
out-of-line payload and header beside the existing child allocations. A failed
later boot decoder preserves the original graph and refuses replacement.
Existing Source caps remain unchanged. This ownership transition constructs no
policy, native model, bootstrap ACK, opaque Initial/Recipe or genuine funding.

All 22 focused startup parser/ownership controls pass, including three new
ownership cases for both program families. The seventeen-case inherited-socket
publication control also passes with the same shared launch owner. The first
complete standard run passes 1,922 tests and fails four raw-receipt controls:
their fixed 1 MiB independent fixture policy refuses the enlarged complete
counter row before the expected reads. The raw-JSON and affected target runs
have not run for this checkpoint. Full transition qualification remains open;
these failures are retained while its positive funding fixture is corrected.

## Completed original Hello evidence and corrected launch qualification

The raw-receipt fixture correction (`ed68d10fba`) derives its positive independent
budget from the complete current raw row. Its peak negative is exactly one byte
short. All 45 focused bootstrap controls pass, with one existing ignore. No
production allowance, read bound or refusal changes.

Commit `435ddbcf98` lends role-normalized hashes from the actual complete literal
Hello frames. It joins the original publication stage, journal/write progress,
live SDK lease, input custody and pre-read cut around inspection. Callback
refusal still runs terminal checks; substituted or expired cuts and every
terminal publication refusal fail closed. Existing raw-journal parsed flags
remain unchanged. Returned Copy digests prove correspondence only.

The defining modules name actual borrowed iterator, framing, hash-state and
loan controls. The complete initial formula includes the fixed inspection
window; generic callers separately fund their Copy result and inspection work.
No owner, socket, lease, native policy or ACK moves through this loan.

The expanded inherited-socket control passes all eighteen cases. Both complete
Transport configurations pass 1,926 tests each, with no failures, no filtering
and sixteen existing ignores. This includes the corrected raw controls and all
three shared-launch ownership tests, closing their earlier four-test failure.
Format passes 67 tests with one existing ignore. Affected all-feature/all-target
checking, scoped formatting and all six architecture gates pass.

The required application gate passes: 180 test executables across 58 package
identities, including 71 integration targets. All 269 owned Rust/Cargo inputs
match the committed tree and exact application source capture. This gate
compiles tests without running them. No new VM or configured Engine/Daemon
runtime qualification is claimed; genuine enclosing Source/Birth funding,
Native18 policy/ACK, opaque Initial/Recipe and full RFC acceptance remain open.

## Complete original launch validation before native policy adoption

Commit `3e48176797` runs the unchanged full launch validator on the original
shared decoded launch. Its temporary coordinator and policy DATA are dropped
before terminal observation; it installs no runtime model, Control, socket,
native policy or ACK. The spent attempt retains its row and original pre-read
cut, and refuses retry or substituted custody. Both validator outcomes run the
surviving-owner observer and terminal original guards. A Copy-only loan keeps
inspection tied to that same validated launch and cut.

The complete initial calculation now includes this validator's actual factory,
formatter and fixed controls in both Source and native projections. The valid
producer fixture exceeds the old fixed retained partition by 7,332 bytes; its
independent positive budget is derived from the complete row under the same
256 MiB ceiling. Production limits and existing negative controls are unchanged.

All thirteen inherited-socket validation cases pass, covering valid producer and
reactive launches, invalid model/selection DATA, every admission boundary,
terminal callback refusal, expiry, substituted cut and spent retry. Both complete
Transport configurations pass 1,927 tests each with no failures, no filtering and
sixteen existing ignores. Affected all-feature/all-target checking, formatting
and all six architecture gates pass.

The required application gate passes and compiles 180 test executables across
58 package identities, including 71 integration targets. All 271 owned Rust/Cargo
inputs match this committed tree and its exact captured application source.
Compilation does not execute these targets. No new VM or configured Engine/Daemon
runtime result is claimed. Genuine Source/Birth funding, model-absent Native18
policy/ACK, opaque Initial/Recipe and full RFC acceptance remain unfinished.

## Complete Record18 definitions and closed restoration DATA

Commit `315bbf0846` supplies the full canonical Record18 definition and distinct
closed CommitHeld and FirstObserved DATA shapes. Their scope carries the exact
fourteen-coordinate target, SourceBirth reference, original Hello pair, recipe,
import binding, all seven input references and Prepare pair. Held DATA names the
current Commit request and physical Hold; observed DATA names completed
Commit/Arm/World pairs, the current first Observe request and native proof.
The carrying response is excluded to avoid recursive content addressing.
Old editions, unknown fields and mismatched phase shapes are refused.

Full-definition selection now requires exactly one Import18, Stage18 and
Record18 reference plus all four features in both provider and selected binding.
The Daemon validates all three actual compiled bodies and refuses partial
announcements. Checked construction quotes and exhaustive retained metadata
cover these definitions and DATA; neither parsing nor equality creates live
native permission, a phase issuer or a physical witness.

Focused definition, typed-record and inherited-socket suites pass, including
full-reference substitution, all seven actual Prepare input roles, malformed
phase shapes and missing/duplicate Record18 declarations. Both complete
Transport configurations pass 1,938 tests each, with zero failures, no filtering
and sixteen existing ignores. Configured Daemon and Engine library runs pass
1,839 and 2,055 tests respectively, with existing ignored populations of 166
and 34. They use the installed packet/device executables and closed gem5
profile. Their binaries finished compiling before the subsequent policy edits;
these runtime results qualify this component only. Preserved unrelated ARM
Root changes were present during compilation and are not qualified as committed
by this record.

Affected all-feature/all-target checking, changed-file formatting and all six
architecture gates pass. The required application gate compiles 180 test
executables across 58 package identities, including 71 integration targets.
All 280 owned Rust/Cargo inputs match the commit and its exact captured source.
This compilation gate does not execute tests. No new funded-Source VM result is
claimed. Live Native18 policy/ACK and all five native phase consumers, genuine
Source/Birth funding, opaque Initial/Recipe and full RFC acceptance remain open.

## Model-absent policy DATA under original bootstrap custody

Commit `8d0df4c5ee` retains a new immutable policy DATA owner after complete
original launch validation, full three-definition selection, actual SDK admission
and completed literal Hello publication. It shares the exact original decoded
launch allocation and borrows its definitions, without copying the configuration
or constructing a runtime model, Control, effect socket, physical Hold or old
Native5Policy. The native identity geometry now names this new owner; it still
has no issuer or dispatcher constructor.

Its fixed attempt captures the pre-read cut and spends construction once.
Failed terminal guards contain the actual SDK lease while retaining the policy
and every original population. Completed Copy-only loans check original custody,
current SDK/publication, exact recipe identity and cut before and after either
callback outcome. Equal DTOs in a foreign allocation receive no shared-backing
discount. Both independent initial formulas include the real additional shared
owner and complete guard/constructor controls within unchanged production caps.

The valid combined fixture preserves required baseline schemas and rebuilds its
provider/binding/World identities before receipt. All fourteen inherited-socket
policy cases pass, including both program families, missing prerequisites,
refused construction/census, expiry, changed cut, contained lease and spent retry.
Both complete Transport configurations pass 1,940 tests each with zero failures,
no filtering and sixteen existing ignores. Affected all-feature/all-target
checking, formatting and all six architecture gates pass.

The required application gate compiles 180 test executables across 58 package
identities, including 71 integration targets. All 285 owned Rust/Cargo inputs
match the commit and exact captured application source. This gate executes no
tests. No new funded-Source VM or configured Engine/Daemon runtime result is
claimed. This DATA transition does not supply genuine Source/Birth funding,
a live Native18 policy/ACK, opaque Initial/Recipe, native phase authority or full
RFC acceptance; those obligations remain open.

## Closed Stage17 DATA under explicit Stage18 selection

Commit `e7b2ccdbfa` implements the declared closed Stage17 binding, context,
proof and receipt grammars for Arm, World and first Observe. Bindings carry
actual typed Prepare/Commit17 receipts, the full target, physical Hold reference
and phase-specific completed pairs. Nullable history fields remain mandatory.
The Stage18 definition and unchanged inner17 cryptographic domains select this
DATA explicitly; old activation/observation proofs and transfer12 receipts do
not substitute for it.

Assignment checks bind the complete original Envelope and baseline target body,
omitting only the carrying proof or receipt from its respective digest. First
Observe requires exactly one item after sequence zero. Exhaustive retained
metadata counts malformed owners as well as valid DATA. These codecs create no
Source grant, SDK history, native phase, World publication or released witness.

All nine focused controls pass, including complete compiled field-list agreement,
mandatory histories, full target and receipt joins, assignment mutation, phase/key
substitution and recomputed-digest attacks. Both complete Transport configurations
pass 1,949 tests each with no failures, no filtering and sixteen existing ignores.
Affected all-feature/all-target checking, changed-file formatting and all six
architecture gates pass.

The required application gate compiles 180 test executables across 58 package
identities, including 71 integration targets. All 291 owned Rust/Cargo inputs
match the commit and its exact captured application source. This gate executes
no tests. No new VM or configured Engine/Daemon runtime result is claimed.
Actual paired Source issuers/native consumers, full phase construction rows,
genuine Birth funding and full RFC acceptance remain unfinished.

## Defining Stage17 crypto construction geometry

Commit `6a833fd86e` projects the actual Context, proof, receipt and unsigned
receipt-input grammars without allocating a positive DTO. Each phase uses its
own exact schema, label, physical report and fixed digest encoding. The receipt
MAC borrows its actual exhaustive unsigned field structure; wire encoding and
cryptographic domains remain unchanged.

The component quote counts actual retained crypto outputs, typed constructor
controls and simultaneous canonical work, including the context output still
live during receipt-input construction. Formatter and fixed projection/MAC
controls are explicit. A larger independent restriction supplies no extra credit.
This quote excludes binding/Envelope work, typed parsing, diagnostics, caller and
async frames, live custody, publication and effects; it is not a full phase row.

All eleven focused stage controls pass. Independent serializer/metadata oracles
match all four projected shapes and actual retained outputs for all three phases.
Exact-peak funding passes, one byte less refuses, and extra restriction leaves
the row unchanged. Both complete Transport configurations pass 1,951 tests each
with no failures, no filtering and sixteen existing ignores. Affected all-target
checking, changed-file formatting and all six architecture gates pass.

The required application gate compiles 180 test executables across 58 package
identities, including 71 integration targets. All 293 owned Rust/Cargo inputs
match the commit and its exact captured source. This compilation executes no
tests. No new VM or configured Engine/Daemon runtime result is claimed. Full
phase funding, actual paired issuers/adopters, opaque Initial/Recipe production
and full RFC acceptance remain unfinished.

## Complete authenticated Stage17 exchanges and predecessor joins

Commit `145c3874c7` checks complete borrowed Arm, World and first-Observe
exchanges. Authentication binds the original assigned request, full target,
carried proof, terminal body, carried receipt and both complete Envelope
references. A valid MAC does not replace baseline semantics: Arm requires its
staged gate and owner, World requires its gate and owner, and first Observe
requires exactly the initial empty staged batch with the assigned identities.

World authenticates its actual Arm predecessor. Observe authenticates both
predecessors and checks that World's own Arm pair is the same pair. Complete
import, Source/Birth, Runtime, Scope, transaction, Prepare/Commit receipts and
physical Hold joins must agree. This DATA verifier allocates no native phase,
issues no Source permission and publishes no World or observation.

All sixteen focused stage controls pass, including re-signed baseline and
common-join mutations, replacement carried authenticators and predecessor
substitution. Both complete Transport configurations pass 1,956 tests each,
with no failures, no filtering and sixteen existing ignores. Affected
all-feature/all-target checking, changed-file formatting and all six
architecture gates pass.

The required application gate compiles 180 test executables across 58 package
identities, including 71 integration targets. All 295 owned Rust/Cargo inputs
match the commit and its exact captured application source. This gate executes
no tests. No new VM or configured Engine/Daemon runtime result is claimed.
Actual paired issuers and native adopters, full phase funding, genuine opaque
Initial/Recipe production and full RFC acceptance remain unfinished.

## Original typed bootstrap policy normalization

Commit `ba36cff750` lends the actual decoded Source binding, same fixed recipe
identity, three full selected definitions and current SDK negotiation under the
original immutable-policy guards. It preserves the existing five-field policy
wire grammar while avoiding an intermediate Source DOM and copied recipe bank.
Original input, cut, launch, literal Hello and SDK guards run around either
callback outcome; only Copy DATA can leave the loan.

The allocation-free projection walks every typed Source field and the full
announced Recipe24. It prices the original Source-bank and fixed recipe base64
formatters separately from DOM/JCS, parser and output banks. Fixed loan controls
have a separate checked quote. No initial row, retained owner or public API
changes, and no ACK or native phase permission follows from normalization.

The existing fourteen physical-channel cases pass for producer and reactive
launches, absent policy, changed cut, callback refusal/expiry and SDK containment.
The projected populations and storage match an independent serializer oracle;
exact-peak and larger restrictions pass, and one byte less refuses. Both complete
Transport configurations pass 1,956 tests each with no failures, no filtering
and sixteen existing ignores. Affected all-feature/all-target checking,
changed-file formatting and all six architecture gates pass.

The required application gate compiles 180 test executables across 58 package
identities, including 71 integration targets. All 300 owned Rust/Cargo inputs
match the commit and its exact captured source. This gate executes no tests.
No new VM or configured Engine/Daemon runtime result is claimed. Genuine
Source/Birth funding, live ACK publication, full phase construction and full
RFC acceptance remain unfinished.

## Original typed bootstrap birth association

Commit `1edce95c74` borrows the actual birth identifier, private launch, Host
executable, complete typed Source binding and original Host registration from
the decoded private body. Its six-field serialization matches the existing
birth-association grammar and excludes the private key. The enclosing composite
loan keeps the actual immutable policy, Source/launch, cut, literal Hello and
live SDK guards around either callback outcome.

The complete projection prices both original Bytes formatters separately from
DOM/JCS, parser and output banks. It creates no intermediate Source DOM, copied
birth bank or retained owner. Its fixed controls have a checked independent
quote; the initial row and existing public wire API remain unchanged.

All fourteen physical-channel cases pass. An independent raw-body/wire oracle
matches the normalized view, and the actual serializer matches projected storage
and populations. Exact-peak and larger restrictions pass; one byte less and a
malformed birth identifier refuse. Callback refusal, expiry, changed cut and
SDK containment retain original ownership. Both complete Transport configurations
pass 1,956 tests each with no failures, no filtering and sixteen existing ignores.
Affected all-feature/all-target checking, formatting and all six architecture
gates pass.

The required application gate compiles 180 test executables across 58 package
identities, including 71 integration targets. All 302 owned Rust/Cargo inputs
match the commit and its exact captured source. This gate executes no tests.
No new VM or configured Engine/Daemon runtime result is claimed. Live ACK
publication, genuine Source/Birth funding, complete phase construction and
full RFC acceptance remain unfinished.

## Original native bootstrap kernel measurement

Commit `8817e06077` measures the actual running native image once under the
original model-absent policy, cut and live SDK guards. The pre-read attempt
retains the resulting full executable reference before terminal guards and
whole-owner observation. Refusal spends the occurrence, contains the actual SDK
lease and preserves surviving outputs. The kernel loan borrows the original
controller coordinates and full executable reference together with the actual
native PID, UID and retained image measurement.

The defining initial construction formula includes the actual measurement
factory's retained strings and separate transient/counter controls. The original
256 MiB ceiling and later four partitions remain unchanged. Admission callbacks
in the physical controls remain models; neither the measurement nor its Copy
loan supplies genuine Source/Birth credit, a native ACK or a phase grant.

All twenty-five physical policy/kernel cases pass, including missing policy,
short admission, terminal census refusal, callback refusal, expiry, substituted
cut and SDK containment. The measurement matches an independent current-image
read. Both complete Transport configurations pass 1,957 tests each with no
failures, no filtering and sixteen existing ignores. Affected all-feature and
all-target checking, changed-file formatting and all six architecture gates pass.

The required application gate compiles 180 test executables across 58 package
identities, including 71 integration targets. All 304 owned Rust/Cargo inputs
match the commit and its exact captured source. This gate executes no tests.
No new VM or configured Engine/Daemon runtime result is claimed. Genuine
Source/Birth funding, live ACK publication, complete phase construction and
full RFC acceptance remain unfinished.

## Original native bootstrap registration

Commit `9d400659e4` borrows all nine native registration fields from the
original live SDK authority under the existing immutable policy and original
input/Hello guards. The caller cannot supply a controller connection ID through
this loan. The public registration serializer retains its existing wire grammar.
The native projection requires the original native connection and empty typed
extension roster, and exhaustively names every registration and limit field.

Projection runs without allocating a normalization DOM or a Bytes formatter.
The existing twenty-byte scalar reserve remains present. Checked loan controls
include the concrete Copy result; callback construction is independently funded.
The loan creates no connection, Source/Birth funding, native ACK or phase grant.

All twenty-seven physical cases pass. An independent nine-field SDK oracle and
actual serializer agree with the normalized view and projected storage. Exact
and larger restrictions pass; one byte less refuses. Changed cut, SDK containment,
callback refusal and both callback outcomes during expiry remain closed. Both
complete Transport configurations pass 1,957 tests each with no failures, no
filtering and sixteen existing ignores. Affected all-feature/all-target checking,
changed-file formatting and all six architecture gates pass.

The required application gate compiles 180 test executables across 58 package
identities, including 71 integration targets. All 308 owned Rust/Cargo inputs
match the commit and its exact captured source. This gate executes no tests.
No new VM or configured Engine/Daemon runtime result is claimed. Genuine
Source/Birth funding, live ACK publication, complete phase construction and
full RFC acceptance remain unfinished.

## Combined original bootstrap ACK operands

Commits `ead22bb4de` and `aae8f9089b` lend the actual birth, measured kernel,
immutable policy and native registration views through one original guard chain.
The policy and registration borrow the same actual SDK authority. Each shape is
projected before a normalization serializer runs; the caller still owes the
combined construction schedule. Copy results include their actual control sizes.
No original owner moves and no resource ceiling or operational deadline changes.

All thirty-three physical policy/kernel/operand cases pass. Controls cover exact,
short and larger restrictions, complete field rosters and cross-view joins,
callback refusal, substituted cuts and expiry after either callback outcome.
The independent executable oracle is prepared before creating the timed receiver;
production measurement remains under the unchanged five-second original cut.
This avoids test expectation work consuming the production operation's deadline.
The earlier combined-operand checkpoint failed one full raw-value oracle case;
the corrected checkpoint below supersedes that qualification attempt.

For `aae8f9089b`, both complete Transport configurations pass 1,957 tests each,
with no failures, no filtering and sixteen existing ignores. Affected
all-feature/all-target checking, changed-file formatting and all six architecture
gates pass. The required application gate compiles 180 test executables across
58 package identities, including 71 integration targets. All 310 owned Rust/Cargo
inputs match the commit and its exact captured application source. This gate
executes no tests. No new VM or configured Engine/Daemon runtime is claimed.

The admissions in these controls remain models. Combined views and their DATA
shapes supply no genuine Source/Birth funding, opaque Initial/Recipe, live ACK,
model or phase authority. Their normalization constructor, genuine enclosing
owners and full RFC acceptance remain unfinished.

## Original five-role bootstrap normalization hashes

Commits `5fe3686908` and `a8c2e06cea` compute the original birth, measured
kernel, immutable policy, native registration and retained Host hashes under
one original raw/typed/policy/SDK guard chain. An external attempt retains its
current Value, inline BLAKE3 writer and computed digest prefix. Each role is
admitted before allocation and observed after either constructor outcome;
failed output remains owned and both original occurrences stay spent.

Canonical bytes stream directly into the bounded hash writer. The Host Value
is borrowed from the original decoder. The other four serde Value constructors
have a separate backing bound covering copied strings, actual sequence growth
and the pinned tree census, including possible empty roots. Existing DOM/JCS
scratch remains intact. No canonical output bank or JSON parser is constructed.
The initial Source and native calculations use the same complete five-role
schedule, actual compiled schema factories and sequential counter maxima.
The independent 256 MiB ceiling, later four inert partitions and original
five-second operational cut remain unchanged.

Thirteen new physical flights cover both program families, incomplete kernel,
changed cut, construction/role refusal, every retained output prefix, expiry
and actual SDK revocation. Independent canonical hashes agree with the
accepted streamed bytes. Separate controls check sticky short writes, exact
and short complete restrictions, checked overflow, and actual Value census
through sequence growth and nested/empty objects. The older thirty-three
policy/kernel/operand flights retain their independent field oracles. Their
oracle work now stays in its own timed flights; the first full standard run
before this harness correction failed an older kernel callback control.

For `a8c2e06cea`, both complete Transport configurations pass 1,961 tests each,
with zero failures, no filtering and sixteen existing ignores. Affected
all-feature/all-target checking, changed-file formatting and all six architecture
gates pass. The application compilation gate emits 180 test executables across
58 package identities, including 71 integration targets. All 316 owned
Rust/Cargo inputs match the commit and its exact captured application source.
The gate executes no tests. No new VM or configured Engine/Daemon runtime
result is claimed.

These admissions remain models and the retained Host fixture is still inert
DATA. Complete Host-plan authentication, genuine enclosing Source/Birth funding,
opaque Initial/Recipe production, live ACK publication and full RFC acceptance
remain unfinished.

## Original Host-plan checks around completed hash loans

Commit `03328ea912` checks the original complete controller registration plan
before lending completed normalization hashes. The same immutable original
launch, Hello declaration and actual native SDK authority remain borrowed.
Every plan field is checked, including connection-ID grammar, actual session
and incarnation, all five canonical limits, exact feature/key rosters and
empty typed extensions. This comparison creates no controller connection.

Original plan, input, channel, cut and SDK guards surround either callback
outcome. No Value, registration graph or hash bank is copied. The concrete
Copy result, nested decoded-body loans and comparison controls have checked
counter quotes; the complete initial schedule includes their sequential maximum.
Neither resource policy nor the original operational deadline changes.

Twenty physical flights cover both program families, each changed plan field,
missing/extra fields, incomplete hashes, callback refusal, substituted cut,
containment, actual SDK revocation and expiry after either callback outcome.
The original raw/typed owners, launch pointer and computed hashes remain intact.
Both complete Transport configurations pass 1,962 tests each, with zero failures,
no filtering and sixteen existing ignores. Affected all-feature/all-target
checking, formatting and all six architecture gates pass.

The application gate compiles 180 test executables across 58 package identities,
including 71 integration targets. All 317 owned Rust/Cargo inputs match the
commit and its exact captured source. The gate runs no tests. No new VM or
configured Engine/Daemon runtime result is claimed. These callback admissions
remain models. Genuine enclosing Source/Birth funding, opaque Initial/Recipe,
actual bootstrap dispatch/publication and full RFC acceptance remain unfinished.

## Original post-Hello literal custody

Commit `7407b938af` receives the next complete frame through the original
Hello capsule and socket, under the original nonrenewing cut and actual live
native SDK. Completed original normalization hashes and full Host-plan
correspondence precede admission and every public read. No replacement socket,
reader, journal, registration or deadline is introduced.

The external attempt reserves the negotiated complete header/body bank before
I/O. It retains every accepted prefix, cursor, length header and complete literal
hash on either outcome. Both original and external occurrences are spent before
the first guard. Empty, oversized, partial, timed-out, admission-refused and
terminally refused input stays observable; retry cannot replace those owners.
Raw receipt remains unparsed DATA, including arbitrary non-UTF-8 bytes. A later
loan checks the literal hash and original launch association, Host plan, SDK,
channel and cut around either callback outcome.

The independently calculated Source/native initial row includes the new full
bank, external owner and actual read/loan controls. This introduces no larger
resource policy, operational deadline or numeric-to-allowance conversion.
Fifteen physical flights cover both program families, malformed/partial framing,
missing normalizations, admission/census refusal, changed cut, actual SDK
revocation, callback refusal and expiry. Earlier physical controls remain.

Both complete Transport configurations pass 1,965 tests each, with zero failures,
no filtering and sixteen existing ignores. Affected all-feature/all-target
checking, formatting and all six architecture gates pass. The application gate
compiles 180 test executables across 58 package identities, including 71
integration targets. Its 319 owned Rust/Cargo inputs match the commit and exact
captured source. The application gate runs no tests; no new VM or configured
Engine/Daemon runtime result is claimed.

These admissions remain models. Strict bootstrap decoding, actual assigned
request/proof handling, genuine enclosing Source/Birth funding, opaque
Initial/Recipe, bootstrap dispatch/publication and full RFC acceptance remain
unfinished.

## Original post-Hello strict JSON custody

Commit `44ab824c31` retains the strict parser's actual Value or fixed failure
coordinates under the same original Hello capsule, Host plan, native SDK and
nonrenewing cut. Admission precedes parsing. Both occurrences are spent before
guards; every surviving output is counted and observed on success and refusal.
Later Value loans recheck the literal hash, original launch association, full
Host plan and actual SDK around either callback outcome.

A closed prospective bootstrap field population bounds the parser row, including
all keys, seven maximum-width IDs, four quoted unsigned integers, three encoded
digests and sixfold escaped spelling. Allocation-free lexical census checks the
actual parser storage against each admitted component. These bounds do not
validate the typed bootstrap request or authenticate its proof.

The Source/native calculation includes the new owner and parser controls. Its
retained maximum follows actual lifetimes: failed normalization retains its
Value while later attempts remain empty; completed normalization clears that
Value before literal receipt and parsing. The completed-hash loan enforces this
ordering. Sequential scratch remains a maximum. Neither the 256 MiB policy nor
the operational deadline or later phase partitions increases.

Twenty-one physical flights cover both program families, escaped and padded
input, duplicate fields, invalid UTF-8, malformed and excessive graphs,
admission/census refusal, changed cut, missing originals, actual SDK revocation,
callback refusal and expiry. Earlier physical controls remain. Both complete
Transport configurations pass 1,968 tests each, with zero failures, no filtering
and sixteen existing ignores. Affected all-feature/all-target checking,
formatting and all six architecture gates pass. The application gate compiles
180 test executables across 58 package identities, including 71 integration
targets. Its 322 owned Rust/Cargo inputs match the commit and exact captured
source. That gate runs no tests; no new VM or configured Engine/Daemon runtime
result is claimed.

These admissions remain models. Typed request decoding, actual assigned request
and proof handling, genuine enclosing Source/Birth funding, opaque Initial/Recipe,
bootstrap dispatch/publication and full RFC acceptance remain unfinished.

## Original typed bootstrap DTO custody

Commit `b16b150902` retains the actual first post-Hello Envelope, bootstrap
request and proof as separate unassigned DATA outputs. A complete allocation-free
field/leaf preflight precedes typed allocation. Each completed output is stored
before validation; fixed serde failure coordinates and every earlier output
remain observable after refusal. Both original and external occurrences are
spent before guards, preventing replacement by a fresh attempt.

One full original literal/strict-Value/Host/native-SDK loan surrounds decoding
and observation on either outcome. Intermediate checks use the same borrowed
live SDK. The envelope targets the actual session/incarnation, follows the
original Hello sequence and uses a distinct request ID. Its full body/extensions
match the original strict tree. The decoded request joins the actual private
Recipe identity and independently reconstructed initial row. Proof checks here
validate structure only; a correctly shaped all-zero MAC remains unauthenticated
DATA. These checks create no SDK request assignment or native permission.

The independent Source/native initial formula includes all typed string, tree
and byte backing, actual decoder partials, expanded diagnostics, constructor
windows, census, callbacks and concrete loan results. The pinned base64 decoder
retains capacity 33 for each decoded 32-byte digest; all three banks are priced.
A maximum-width census covers seven 128-byte IDs, four quoted unsigned integers,
all closed maps and each actual decoded capacity. Retained lifetimes extend the
existing normalization/literal/parser schedule without increasing the policy,
original deadline or later phase partitions.

Thirty-one physical flights cover both program families, closed-field refusal,
typed numeric/ID/base64 errors, wrong current target/sequence/Recipe/funding,
admission and census refusal after each output, changed cut, actual SDK
revocation, expiry and callback refusal. Both complete Transport configurations
pass 1,972 tests each with zero failures, no filtering and sixteen existing
ignores. Affected all-feature/all-target checking, formatting and all six
architecture gates pass. The application gate compiles 180 test executables
across 58 package identities, including 71 integration targets. Its 327 owned
Rust/Cargo inputs match the commit and exact captured source. That gate runs no
tests; no new VM or configured Engine/Daemon runtime result is claimed.

Actual request correlation/assignment, complete proof verification, genuine
enclosing Source/Birth funding, opaque Initial/Recipe, bootstrap dispatch and
publication, all later native phases and full RFC acceptance remain unfinished.

## Original bootstrap SDK correlation qualification

Commit `192ad35873` retains the first actual typed bootstrap request in an SDK
`CorrelationGuard` constructed from the same admitted original connection.
Negotiated IDs and declared extension keys are borrowed from that SDK before
cloning. The guard reserves the actual Envelope once under the original
normalization, Host-plan, literal, strict-Value and typed-decoder guards.

Both attempt occurrences are spent before guards. Construction and receive
outcomes receive actual retained-state observation and terminal authority checks.
Refusal fences the guard while preserving every accepted request record; a fresh
external attempt cannot retry the spent original occurrence. This is transport
correlation DATA: proof MAC acceptance, opaque Source funding, native phase
permission and bootstrap ACK publication remain separate implementation work.

The independent Source/native initial formulas include the complete correlation
row. Its tree quote uses the ordinary census's largest `(Id, Envelope)` layout
for all eight trees, including nested body/proof maps and the actual declared
extension-key set. No policy cap, original deadline or later phase partition was
increased.

Qualification of that exact commit completed with:

- 1,975 transport unit tests passed in each of the standard and `raw_value`
  configurations; 16 intentional ignores in each configuration.
- The correlation control covers 18 independent inherited-channel flights,
  including admission refusal, expiry and revocation at construction and receive
  boundaries, missing typed input, changed cut and guarded-loan refusal.
- Independent initial construction, retained-lifetime arithmetic, exact-peak,
  short-credit, actual tree-census and concrete Copy-result checks passed.
- Transport, engine and daemon all-feature/all-target compilation passed.
- All six phase-1 architecture checks and owned-source formatting passed.
- The required application-target gate compiled 180 test executables from 58
  packages, including 71 integration targets.
- All 330 tracked Rust/Cargo inputs matched both the committed bytes and the
  application gate's captured Nix source.

No new VM or configured engine/daemon runtime qualification is claimed here.

## Original bootstrap proof verification qualification

Commit `245daaf89e` verifies the original correlated bootstrap proof inside the
same current SDK, Host-plan, literal, strict-Value and typed-input loan. The
context binds all five normalization hashes, both actual published Hello frame
digests, the SDK's retained assigned request, Recipe identity and initial row.
The actual private key remains borrowed inside its owner.

Construction, assignment, context, context digest and verification have separate
admissions and surviving-state observations. Both attempt occurrences are spent
before guards. Refusal fences the actual SDK correlation while preserving its
accepted request and every constructed output; neither a fresh external attempt
nor a matching MAC supplies opaque Source funding, native permission or an ACK.

The independent Source/native initial formulas include the complete proof row
and its actual context backing. Assignment quotes include the typed body clone,
both canonicalization DOMs, canonical output and concrete loan controls. Failed
normalization and completed decoding retain their separately calculated lifetime
maxima. The policy cap, original cut and later partitions remain unchanged.

Qualification of that exact commit completed with:

- 1,978 transport unit tests passed in each of the standard and `raw_value`
  configurations; 16 intentional ignores in each configuration.
- The proof control covers 46 independent inherited-channel flights: complete
  and reactive peers; altered context operands, funding, key, MAC and digest;
  missing correlation, changed cut and loan failures; and admission refusal,
  expiry and revocation at nine construction/verification boundaries.
- Independent initial construction, retained-lifetime arithmetic, exact-peak,
  short-credit and concrete Copy-result checks passed.
- Transport, engine and daemon all-feature/all-target compilation passed.
- All six phase-1 architecture checks and owned-source formatting passed.
- The required application-target gate compiled 180 test executables from 58
  packages, including 71 integration targets.
- All 334 tracked Rust/Cargo inputs matched both the committed bytes and the
  application gate's captured Nix source.

No new VM or configured engine/daemon runtime qualification is claimed here.
Genuine Source/Birth funding, opaque Initial/Recipe production, actual bootstrap
reply publication and the remaining full RFC acceptance criteria remain open.

## Original bootstrap reply and retained response frame

Commit `863b5161e4` extends `aef72d0ccc` with the original bootstrap reply's
retained frame preparation. The verified first request produces BootstrapResult18
and a complete four-field common response body. The response echoes its actual
correlation fields, uses sequence 2 from the actual SDK, and carries the distinct
receipt18 extension bound to the original verified context and assigned response.
Every output is stored before validation and remains in its original attempt on
refusal. Proof verification and preparation complete only after the enclosing
original Source, Host, SDK and channel terminal guards.

A separate journal reserves the closed response shape's canonical byte bound
and actual frame descriptors before encoding. It retains the sealed serializer
tree, measured canonical length, four-byte prefix, original request ID and encoded
body. The writer never grows a new output bank. Actual live SDK byte/nesting
ceilings restrict measurement, with the original launch limits checked separately.
A failed measurement or encoding retains its count or byte prefix and spends its
attempt. The prepared slot records zero transferred bytes and incomplete I/O;
the original Hello journal keeps its own pair.

The independent Source/native initial calculations include actual typed outputs,
serializer trees, retained frame backing, constructor partials, canonical work
and concrete borrowed controls. Failed normalization and completed decoding keep
their independent lifetime maxima. Proof construction borrows immutable decoded
bodies once inside the full correlation loan; duplicate pre-step test censuses
are removed while every output and terminal census remain. The original cut,
policy cap and four later partitions remain unchanged.

Qualification of the exact committed inputs completed with:

- Standard and `serde_json/raw_value` transport suites each pass 1,985 tests
  with 16 intentional ignores (584.08 s and 580.01 s).
- The reply control covers 61 independent inherited-channel flights: complete
  and reactive peers, changed cut, missing proof, and admission refusal, expiry
  and revocation at 19 construction/preparation boundaries.
- The separate proof control covers 46 inherited-channel flights. Maximal reply
  population, independent lifetime/initial formulas, exact/short credit,
  retained failure prefixes and parser-equivalent nesting controls pass.
- Transport, engine and daemon all-feature/all-target compilation passes (2m13s).
- All six phase-1 architecture checks and eight owned-file formatting checks pass.
- The required `rust.aos-test-targets` gate passes: 180 executable test artifacts
  across 58 application crates, including 71 integration targets.
- All 340 tracked Rust/Cargo inputs match the committed bytes and the application
  gate's captured Nix source.

The earlier `aef72d0ccc` raw-value run failed a completed proof context inspection;
the corrected committed inputs above pass both complete suites. No new VM or
configured engine/daemon runtime qualification is claimed. Actual bootstrap reply
reservation/publication, current Native18 ownership, genuine Source/Birth funding,
opaque Initial/Recipe production and the remaining full RFC criteria remain open.

## Original bootstrap reply publication and SDK custody

Commit `14b0a830c5` publishes the prepared Bootstrap18 response on the same
original public stream. The full proof, preparation and publication path shares
one original Codec/Source/Host/SDK custody scope. The existing nonrenewing cut
is preserved. Completion stays private until all enclosing terminal guards pass.

Reservation records the exact response in the actual SDK. The unbuffered writer
uses the previously prepared frame and advances its journal immediately after
each successful write. A partial write retains its byte prefix and first error;
a terminal refusal after a full transfer retains the physical completion fact.
Only a complete physical write permits confirmation, which moves both actual
SDK request and response records into the retained publication owner. No request
is reconstructed during confirmation. Failed or completed attempts cannot retry.

The original Hello exchange remains in the same allocation behind a checked
borrow holder. Busy loans refuse full inspection rather than reporting absent
custody. Publication releases its mutable stream loan before each complete
original/SDK/output census. The independent initial formula includes additional
SDK reservation and confirmed-record backing, clone/decoder partials and concrete
borrow, dispatcher and I/O controls inside the existing Reply component.

The fixtures announce their independently calculated initial Prepare row before
semantic fault injection. Deliberately short retained/transient/scratch and
whole-escrow controls remain short. Four unused later fixture transient allowances
change from 160 MiB to 156 MiB; each later retained allowance remains 2 MiB and
scratch remains 4 MiB. The initial row remains independently derived rather than adjusted to fit the
announcements. The fixed 256 MiB policy cap and original five-second cut are
unchanged. The reactive publication fixture selects
its actual reactive participant before complete launch identities are rebuilt.

Commit `18bd949f08` keeps completed-context proof inspection ahead of duplicate
fixture censuses. It preserves every construction/effect census and the final
complete predecessor census; the original five-second cut is unchanged. This
supersedes the earlier full-run inspection expiry on `14b0a830c5`.

The complete standard Transport library passes 1,989 tests, with zero failures,
no filtering and 16 existing ignores (592.58 seconds). The complete raw-JSON Transport library also passes all 1,989 tests, with
zero failures, no filtering and 16 existing ignores (590.04 seconds). The
Transport/Engine/Daemon all-feature/all-target check passes (2 minutes 12 seconds).
All six registered architecture checks pass. The required application-target
compilation gate emits 180 test executables across 58 package IDs, including
71 integration targets. All 349 owned Rust/Cargo inputs match both committed
`18bd949f08` and its actual captured Nix source. This compilation gate does not
execute runtime tests.

The physical publication control covers 26 inherited-channel flights: producer
and actual reactive completion, changed cut, missing preparation, broken pipe,
and refusal, expiry and revocation at seven construction/effect boundaries. Its
independent parent verifies the actual second frame's canonical body, correlation,
assigned-response digest, distinct receipt MAC and BootstrapOnly state. Lower
controls cover partial/Interrupted I/O, zero writes, full transfer followed by
terminal refusal, unchanged backing, and the actual SDK request allocation moved
into confirmed custody.

This checkpoint grants no native phase or common Ready. The Source-side
Bootstrap18 SDK transaction and genuine Source/Birth funding remain incomplete;
so do opaque Initial/Recipe production, the actual five-phase native adopter,
complete Source/runtime preservation and remaining full RFC qualification. No
new VM or configured engine/daemon runtime result is claimed.

## Source bootstrap original custody and initial Hello cut

Commit `73573ba403` adds dedicated SDK correlation DATA transitions for the sole
sequence-two Bootstrap18 request and response. Settlement moves the actual
pending request into the caller's retained slot before later fallible checks.
It advances incoming sequence once; duplicate settlement refuses. An occupied
destination preserves both owners before effects. Other receive refusals fence
the guard and preserve the actual original wherever it remains owned.

The checks require the distinct negotiated proof/receipt positions, null native
routes and no other SDK traffic or imported continuation. They authenticate
transport correspondence only. Bodies, proof/receipt MACs, genuine Source
ownership and the complete admitted Source holder remain separate requirements.
The received DATA predicate cannot prove that supplied historical records are
genuine owners.

Both real Session construction paths capture the initial opaque Hello deadline.
The dedicated typed Bootstrap constructor checks that unchanged, still-live cut
beside the actual unused Controller SDK, recorded Hello and current registration.
It refuses a renewed timer even when all protocol scalars remain unchanged.
The cut has no portable clock-coordinate codec. Existing generic exchange
behavior and serialized Session17 grammars remain unchanged. Defining constructor
quotes include the additional cut-capture and frontier controls.

All ten new custody/cut/frontier tests pass. The affected client, connection and
existing session namespaces pass 186, 196 and six tests respectively, with zero
failures or ignores. Transport/Engine/Daemon all-feature/all-target checking and
all six architecture checks pass. After full-file review, the two changed large
source files have refreshed digest-bound engineering review records.

The required application compilation gate emits 180 test executables across
58 package IDs, including 71 integration targets. All 362 owned Rust/Cargo inputs
match committed `73573ba403` and its actual captured Nix source. This gate executes
no tests. The preceding complete Transport library qualification remains bound
to `18bd949f08`; no new full-library, VM or configured runtime result is claimed.

The actual Source Bootstrap assignment/seal/publication/receive transaction,
independent whole funding, opaque Initial/Recipe producers, five native phase
consumers and remaining full RFC work are still incomplete. These SDK DATA
transitions grant no native phase, model installation or common Ready.

## Retained closed Source bootstrap response decoding

Commit `ce44658aaa` adds a dedicated closed Bootstrap18 response decoder and an
independent component R/T/S quote. Allocation-free preflight checks the complete
response header, body, funding strings and sole receipt position before DTO
construction. Each initialized Envelope, typed original request, completed body,
result and receipt stays in its retained owner before later fallible checks.
Failures retain their last construction step and fixed serde coordinates;
occupied output refuses reuse without replacing the original owner.

The decoder borrows the caller's strict raw tree. Its completed-body constructor
avoids the generic internally tagged response buffer, and its quote includes the
actual partial DTO, base64 and diagnostic construction windows. It excludes the
separately retained raw parser, literal bank, live SDK, Source holder and MAC work.
Decoded receipt fields remain DATA: they authenticate no Source, settle no SDK
original and issue no bootstrap completion or native readiness.

All fifteen Bootstrap ACK namespace tests pass in both standard and raw-JSON
modes, including ten new closed-decoder controls. Transport/Engine/Daemon
all-feature/all-target checking and all six architecture gates pass. The required
application compilation gate emits 180 test executables across 58 package IDs,
including 71 integration targets. All 366 owned Rust/Cargo inputs match committed
`ce44658aaa` and its actual captured Nix source. That gate runs no tests.

The actual Source Bootstrap transport transaction, independently admitted whole
funding, genuine opaque Initial/Recipe production and remaining full RFC work
remain incomplete. No new full Transport library, configured runtime or VM
qualification is claimed by this component checkpoint.

## Dedicated Source bootstrap Connection transport

Commit `a67e995b43` adds a separate Bootstrap18 transport path beneath the actual
immutable Controller policy. It reserves the original literal slot before
signing, checks the closed request and proof against the exact proposed bytes,
retains the actual SDK request before publication, and preserves write progress
in the original frame bank. The receiver saves the bounded strict raw frame
before closed DTO decoding and moves the actual pending SDK request only after
the decoded owner has retained every successful construction prefix.

The path requires the complete baseline policy, all three exact Native18 schema
definitions and the negotiated Bootstrap proof/receipt positions. It rejects
native routing and intervening SDK traffic. Generic send and receive continue
to refuse Bootstrap. Failed writes, partial reads and failed result correspondence
fence the same connection and retain actual original custody; no fallback or
retransmission is introduced. Occupied outputs refuse before effects.

All eleven new Unix transport controls pass beside the prior frontier test.
The complete affected connection namespace passes 207 tests in standard mode;
all twelve frontier tests pass in raw-JSON mode. Transport/Engine/Daemon
all-feature/all-target checking and all six architecture gates pass. The required
application compilation gate emits 180 test executables across 58 package IDs,
including 71 integration targets. All 369 owned Rust/Cargo inputs match committed
`a67e995b43` and its actual captured Nix source. That gate executes no tests.

These private transport primitives verify no Source MAC and issue no Source
completion, model, native phase or common Ready. The defining caller must retain
and independently admit the whole Source/SDK holder, raw parser and every
constructor and containment window. Controller transaction ownership, genuine
Initial/Recipe production and the remaining full RFC work are still incomplete.
No new full-library, configured runtime or VM qualification is claimed here.

## Unrenewed Source Bootstrap Session cut

Commit `4be2a5590b` brackets the dedicated Bootstrap transport operations with
the deadline captured before the original Hello. Reservation and sealing keep
sequence two; publication spends sequence three before attempting the write.
Receive and decode require that spent sequence and the same original cut. Every
terminal guard runs after either operation outcome, including an already fenced
endpoint, while constructed outputs and actual SDK custody remain retained.
Occupied output destinations refuse before further guards or transport effects.

All eleven cut controls pass in both standard and raw-JSON modes. The broader
affected client namespace passes 194 tests, and all twelve connection frontier
controls pass after the shared model-fixture extraction. Transport/Engine/Daemon
all-feature/all-target checking and all six architecture gates pass. The required
application compilation gate emits 180 test executables across 58 package IDs,
including 71 integration targets. All 371 owned Rust/Cargo inputs match committed
`4be2a5590b` and its actual captured Nix source. That gate executes no tests.

These primitives verify no Source MAC and complete no Source transaction. Whole
Source funding, genuine Initial/Recipe production, Controller transaction work
and the remaining full RFC obligations remain incomplete. This checkpoint adds
no full-library, configured runtime or VM qualification.

## Closed Source Bootstrap envelope projection

Commit `27badd5b33` derives independent serialization and backing demand for the
sealed Bootstrap request and completed bootstrap-only response. It counts the
three bounded ASCII IDs, four explicit null native routes, sequence two, full
body/funding maps and exact proof/receipt positions. The empty completed-body
extension map remains an independently owned root. Caller restrictions constrain
the derived demand without becoming storage demand or protocol authority.

Actual serialized DATA controls cover short and maximum-width IDs, a checked
maximum-width funding axis, exact field/value populations, separately retained
backing and actual canonical output. All seventeen Bootstrap ACK namespace tests
pass in standard and raw-JSON modes; Transport/Engine/Daemon all-feature/all-target
checking and all six architecture gates pass. The required application compilation
gate emits 180 test executables across 58 package IDs, including 71 integration
targets. All 373 owned Rust/Cargo inputs match committed `27badd5b33` and its
actual captured Nix source. That gate executes no tests.

This projection does not fund the raw parser, typed decoder, SDK custody, private
Source guards or complete Source holder. Genuine Initial/Recipe production and
the complete Bootstrap transaction remain unfinished, together with the remaining
full RFC obligations. No new full-library, configured runtime or VM qualification
is claimed by this checkpoint.

## Retained Source Bootstrap assignment and literal reservation

Commit `84114ffd2f` connects the genuine typed Controller owner to a retained
unsigned request and the actual original literal slot. The closed DATA builder
derives its component demand independently, retains failed prefixes and counts
actual backing capacities. The Controller saves the original cut and validates
its creator, Hello and typed inputs before construction. Reservation saves its
attempt and actual slot before later guards, uses the derived sealed-request
bound and preserves sequence two without writing or renewing the deadline.

All 194 affected client, 209 connection and 21 Bootstrap ACK controls pass in
standard mode. Raw-JSON runs pass 21 ACK, fourteen frontier and eleven cut
controls. Transport/Engine/Daemon all-feature/all-target checking and all six
architecture gates pass. The required application gate compiles 180 test
executables across 58 package IDs, including 71 integration targets. All 381
owned Rust/Cargo inputs match committed `84114ffd2f` and its captured source.
That gate runs no tests.

Component rows do not fund the complete Source holder or supervisor callback.
No proof is issued, no Source receipt is authenticated and no Bootstrap
transaction completes here. Genuine Initial/Recipe production and the remaining
full RFC obligations remain unfinished. This checkpoint adds no full-library,
configured runtime or VM qualification.

## Guarded original Source Bootstrap signing loan

Commit `c85e0596e8` lends the actual reserved unsigned request through the
Controller under its original creator, Hello, typed-input, SDK-slot and deadline
guards. The same guards run after either callback outcome. The immutable loan
accepts only a Copy result; the defining Source independently funds its callback
and retains signing outputs before returning. Changed request data, renewed time
and revoked leases refuse without replacing the request or original literal bank.

All 198 affected client and 209 connection controls pass. All fifteen Bootstrap
cut controls also pass in raw-JSON mode. Transport/Engine/Daemon all-feature/
all-target checking and all six architecture gates pass. The required application
gate compiles 180 test executables across 58 package IDs, including 71 integration
targets. All 382 owned Rust/Cargo inputs match committed `c85e0596e8` and its
captured source. That gate runs no tests.

The loan issues no Source proof and authenticates no receipt MAC. Complete
Source funding, genuine Initial/Recipe production, the complete Bootstrap
transaction and remaining full RFC obligations remain unfinished. No new
full-library, configured runtime or VM qualification is claimed here.

## Retained Source Bootstrap proof and canonical request construction

Commit `3c4cfce86d` moves the actual unsigned assignment and typed proof into a
retained DATA materializer before fallible validation. The same original gains
its sole proof extension, while its full DOM and canonical literal occupy
independent banks. Failed construction keeps all initialized outputs and writer
prefixes. The quote counts moved typed capacities separately from serialized
copies; no SDK, Source signing permission or MAC verification follows.

All 26 Bootstrap ACK and sixteen original-cut controls pass in both standard
and raw-JSON modes. The socket control takes the retained assignment through
actual reservation, materialization, sealing and publication, then compares the
peer's bytes with the same canonical bank and checks the unchanged original cut.
Transport/Engine/Daemon all-feature/all-target checking and all six architecture
gates pass. The required application gate compiles 180 test executables across
58 package IDs, including 71 integration targets. All 384 owned Rust/Cargo
inputs match committed `3c4cfce86d` and its captured source. That gate runs no tests.

This DATA materializer does not complete the Controller/Source transaction.
Independent whole-holder funding, genuine Initial/Recipe production, private
receipt verification and the remaining full RFC obligations remain unfinished.
No new full-library, configured runtime or VM qualification is claimed here.

## Guarded Controller Bootstrap materialization

Commit `467b346280` retains the materialization attempt and exact row in the
original Controller owner before fallible checks. Construction moves the same
assignment and proof into retained DOM and literal banks. Identity, typed inputs,
original Hello cut and the still-unregistered physical slot are checked after
either outcome; failed construction preserves initialized outputs.

All 202 affected client, 209 connection and 26 Bootstrap ACK controls pass in
standard mode. Raw-JSON runs pass seventeen original-cut and two materialization
row controls. Transport/Engine/Daemon all-feature/all-target checking and all six
architecture gates pass. The required application gate compiles 180 test
executables across 58 packages, including 71 integration targets. All 387 owned
Rust/Cargo inputs match committed `467b346280` and its captured source. That gate
runs no tests.

Whole Source funding, SDK registration/publication ownership, genuine
Initial/Recipe production, private receipt verification and the remaining full
RFC obligations remain unfinished. This checkpoint adds no full-library,
configured runtime or VM qualification.

## Retained Controller Bootstrap SDK registration and publication

Commit `db9d75c9e3` retains separate registration and publication attempts and
exact component rows in the same Controller owner. The SDK registers an
independent clone of the unchanged materialized request; publication spends the
Session sequence before writing the same literal. Terminal guards compare actual
SDK custody, the exact journal slot, bytes and transferred/completed progress
under the original Hello cut. Refused attempts keep their saved rows and banks.

The component quote derives nested tree populations from the defining Envelope
projection and prices the combined SDK/incident census at its actual largest
entry layout. Actual socket failure retains the SDK original and a separate
incident clone; the combined census fits the independently derived row. Exact
and one-byte-short restrictions remain separate from negotiated frame limits.

All 204 affected client, 211 connection and 26 Bootstrap ACK controls pass in
standard mode. Raw-JSON runs pass eighteen original-cut, two SDK-storage, one
publication-row and two Envelope-projection controls. Transport/Engine/Daemon
all-feature/all-target checking and all six architecture gates pass. The required
application gate compiles 180 test executables across 58 packages, including 71
integration targets. All 392 owned Rust/Cargo inputs match committed `db9d75c9e3`
and its actual captured source. That gate runs no tests.

These operations do not receive or authenticate a Source receipt or complete the
Bootstrap transaction. Whole Source funding, genuine Initial/Recipe production,
private receipt verification and the remaining full RFC obligations remain
unfinished. No new full-library, configured runtime or VM qualification is claimed.

## Retained Controller Bootstrap raw response

Commit `6d0d035992` retains the concrete incoming body bank, framing cursors,
closed-preflight progress and strict parsed tree in the same Controller owner.
Every refusal keeps initialized read prefixes. An allocation-free scanner checks
the exact Bootstrap grammar before generic JSON parsing; valid whitespace and
ASCII escapes do not expand the closed tree population. The original SDK request
stays pending for a separately admitted typed settlement.

The row separately prices actual body capacity, the closed parsed tree under the
SDK's largest entry layout, parser intermediates, real containment clones and
fixed controls. Actual socket receipt and combined raw/SDK/incident census tests
pass without turning a frame limit into a JSON population allowance.

All 207 affected client, 217 connection and 30 Bootstrap ACK controls pass in
standard mode. Raw-JSON runs pass four scanner, eight raw-response, one receive-row
and two Envelope-projection controls. Transport/Engine/Daemon all-feature/all-target
checking, owned-file formatting and all six architecture gates pass. The required
application gate compiles 180 test executables across 58 packages, including 71
integration targets. All 399 owned Rust/Cargo inputs match committed `6d0d035992`
and its actual captured source. That gate runs no tests.

Typed SDK settlement, private Source receipt verification, independently admitted
whole Source funding, genuine Initial/Recipe production and the remaining full
RFC obligations remain unfinished at this checkpoint. No new full-library,
configured runtime or VM qualification is claimed.

## Retained Controller Bootstrap typed response and SDK settlement

Commit `cdd23d7980` saves the typed settlement attempt and exact row before
fallible guards. It decodes the same retained raw tree and moves the actual SDK
pending request into the Controller owner. Terminal checks authenticate the
unchanged literal, raw/typed correspondence, moved request and actual post-move
SDK state under the original cut. Failed attempts retain every initialized
output and cannot restart settlement.

The defining decoder census now joins an enclosing observer directly. Its nine
trees and twenty-five entries are priced at the actual SDK entry layout; moved
request backing, possible containment clones and guard construction remain
independent terms. Real-socket controls cover altered receipt data, raw framing,
foreign moved requests, actual fencing and deadline replacement without losing
retained outputs. Response tests moved into a focused Session module.

All 209 affected client, 218 connection and 31 Bootstrap ACK controls pass in
standard mode. Raw-JSON runs pass 21 original-cut, 31 Bootstrap ACK, seven
raw-response module and one settlement-row controls. Transport/Engine/Daemon
all-feature/all-target checking and all six architecture gates pass. The required
application gate compiles 180 test executables across 58 packages, including 71
integration targets. All 403 owned Rust/Cargo inputs match committed `cdd23d7980`
and its actual captured source. That gate runs no tests.

Private Source receipt verification, whole Source funding, genuine Initial/Recipe
production and the remaining full RFC obligations remain unfinished. No new
full-library, configured runtime or VM qualification is claimed.

## Guarded original Bootstrap receipt loans

Commit `263c6e6095` lends the actual moved SDK request, typed response and
decoded Bootstrap request/result/receipt without another read, decode or SDK
move. The Controller and Session authenticate their original owners, raw/typed
correspondence, actual settled SDK state and unchanged operational cut before
and after the callback, including callback failure. Expiry or revocation keeps
the original failure and every initialized output; a later loan refuses before
its callback.

The defining callback controls are separately declared. This loan supplies no
private Source MAC, whole Source funding or native completion. The genuine
Source handler must admit its own complete holder and callback work, retain
outputs before returning, and authenticate its private Birth independently.

All 212 affected client controls pass in standard mode; all 24 original-cut
controls pass with raw JSON. Real-socket tests cover pointer identity, callback
failure, deadline replacement and actual SDK revocation without additional
transport effects. Transport/Engine/Daemon all-feature/all-target checking,
owned-file formatting and all six architecture gates pass. The required
application gate compiles 180 test executables across 58 packages, including 71
integration targets. All 404 owned Rust/Cargo inputs match committed
`263c6e6095` and its actual captured source. That gate runs no tests.

The remaining Source, genuine Initial/Recipe and full RFC obligations remain
unfinished. No new full-library, configured runtime or VM qualification follows.

## Fixed Bootstrap context encoding

Commit `9e515d6e6a` encodes the complete validated Bootstrap ACK context in a
fixed 873-byte buffer before hashing it. Digest fields use the defining URL-safe
unpadded `Bytes` spelling; funding fields retain their exact decimal strings and
all fields retain canonical order. Context encoding constructs no temporary JSON
tree or heap buffer. The defining counter includes the real fixed buffer and
formatter controls; existing conservative dynamic-work terms remain charged.

Independent canonical-JSON controls cover 256 digest patterns, every individual
binding, decimal width boundaries and invalid contexts. Complete standard and
raw-JSON Transport library runs each pass 2,077 tests with zero failures, no
filtering and 16 existing ignores. Transport/Engine/Daemon all-feature/all-target
checking, changed-file formatting and all six architecture gates pass. The
required application gate compiles 180 test executables across 58 packages,
including 71 integration targets. All 408 owned Rust/Cargo inputs match the
committed revision and its actual captured source. That gate runs no tests.

The requirement-index gate added by `aee9f43da2` and strengthened by
`9d78e3ad81` also passes its eleven controls and all 382 defining RFC anchors.
It enforces exact locations, declared tasks and suites, and each family's RFC
primary suites. Twenty-six capability rows now include protocol suite P in their
planned coverage. All 382 statuses remain planning annotations; this consistency
check supplies no backend acceptance or implementation completion evidence.

Private Source verification, genuine Initial/Recipe production and the remaining
full RFC obligations remain unfinished. No new configured runtime or VM
qualification follows from these results.

## Canonical Bootstrap digest spelling

Commit `e802d89c5c` corrects three Bootstrap paths that used the standard Base64
alphabet: unsigned recipe construction, SDK wire correspondence and raw response
preflight. Each now uses the defining `Bytes` type's unpadded URL-safe alphabet.
The change preserves fixed buffers, decoder layouts and accounting terms. Valid
digests containing `-` or `_` now survive construction and receipt scanning;
standard-alphabet spellings refuse before generic response parsing.

The regressions cover all 256 recipe byte values, all 256 values in each of four
response digest fields, standard alphabets, padding and noncanonical trailing
bits. Six actual Unix-socket flights complete assignment, reservation, sealing,
publication, raw receipt, typed decoding and the actual SDK request move. Their
negotiation and MAC fixtures remain inert and issue no Source or native grant.

All 212 client, 220 connection and 38 Bootstrap ACK controls pass separately in
standard and raw-JSON modes. Transport/Engine/Daemon all-feature/all-target
checking, owned-file formatting and all six architecture gates pass. The required
application gate compiles 180 test executables across 58 packages, including 71
integration targets. All 409 owned Rust/Cargo inputs match the committed revision
and its actual captured source. That gate runs no tests. No new full-library,
configured runtime or VM qualification follows from this checkpoint.

## Named decoder fields and fixed counter layouts

Commit `a28bf4c043` names existing retained decoder result shapes, including
validation-only versus built output, independent role-group ordinals and borrowed
input spans. The aliases preserve the exact tuple types, field order, lifetimes
and storage layouts. Ten counter terms now name arrays of eight native words
instead of multiplying a word's size by eight; their byte totals are identical.

All fifteen type-complexity and ten manual-bits errors disappear. Production
Transport library Clippy errors fall from 149 to 124, with 1,727 warnings; strict
qualification remains failed and no allowance changes. Existing regression runs
pass 220 connection, 322 snapshot, 27 endpoint, one fresh-query, 53 Hello
construction and two Bootstrap codec tests. Transport/Engine/Daemon
all-feature/all-target checking, owned-file formatting and all six architecture
gates pass.

The required application gate compiles 180 test executables across 58 packages,
including 71 integration targets. All 419 owned Rust/Cargo inputs match the
committed revision and its actual captured source. This gate runs no tests.
No new full-library, configured runtime, VM or full RFC qualification follows
from the declaration and layout-expression cleanup.

## Original-owner and retained-state guard simplification

Commit `40fcee8a72` flattens 39 nested conditions across 27 Transport files.
The checks retain their original short-circuit order, actual owner comparisons,
refusal points and accounting terms. No lint allowance or protocol changes.
Production-library Clippy falls from 124 to 85 errors, with 1,727 warnings;
strict qualification remains failed.

The complete standard Transport library run passes 2,082 tests with zero
failures, no filtering and 16 existing ignores. The complete raw-JSON run
passes 2,078 tests and fails four native Bootstrap subprocess tests, with the
same 16 ignores. Correlation, proof, reply and publication encounter an expired
original operational deadline; one expected callback is never entered. This
failed concurrent run does not qualify raw-JSON operation. A separate serial
rerun of the unchanged compiled binary passes correlation, proof and publication,
but reply still refuses during shared correlation setup. The failure remains
unresolved; production deadlines remain unchanged.

Owned-file formatting and all six architecture gates pass. The required
application gate compiles 180 test executables across 58 packages, including
71 integration targets. All 435 owned Rust/Cargo inputs match committed
`40fcee8a72` and its actual captured source. That gate runs no tests. The
library script stops at the failed raw-JSON run before its all-target check.
No new configured runtime, VM or full RFC qualification follows.

## Grouped Initial construction accounting

Commit `abf3e09ad9` groups the existing launch and Bootstrap constructor rows
before combining their independent retained, transient and counter axes. Parent
projection and native reconstruction retain the same evaluation order and field
associations. The fixed counter additionally names both new group headers; the
change creates no opaque Initial, Recipe, phase grant or new wire format.

The borrowed Initial15 validator now ends in an explicit lexical scope before
the origin and retained-storage census. A primitive empty-input check uses
array membership, and the Launch decoder keeps both child-type depth
dependencies through a private constant maximum helper. Existing checks,
refusal behavior and decoder layouts remain intact.

All 22 startup-wire, 322 snapshot and 220 connection tests pass separately in
standard and raw-JSON modes. Transport/Engine/Daemon all-feature/all-target
checking, owned-file formatting and all six architecture gates pass. Strict
Transport library Clippy still fails, with 81 errors and 1,727 warnings; no
allowance changes. These focused results do not resolve the complete raw-JSON
run's native Bootstrap failures recorded above.

The required application gate compiles 180 test executables across 58 packages,
including 71 integration targets. All 437 owned Rust/Cargo inputs match
committed `abf3e09ad9` and its actual captured source. This gate runs no tests.
No new complete-library, configured runtime, VM or full RFC qualification
follows from this construction cleanup.

## Bootstrap fixture failure diagnostics

Commit `b8c8f03abb` includes the exact private fixture case in child-failure
reports and reports original-cut expiry when shared correlation preparation
refuses. The diagnostics preserve all assertions, production checks and
deadlines; they supply no new completion or native authority.

The raw-JSON Transport unit-test executable compiles, formatting and all six
architecture gates pass, and the required application gate compiles 180 test
executables across 58 packages, including 71 integration targets. All 437 owned
Rust/Cargo inputs match the committed revision and its actual captured source.
These compilation results execute no new runtime test and do not resolve the
earlier raw-JSON failures.

## Immutable Bootstrap proof fixture preparation

Commit `8bb1db4375` prepares immutable private-wire fixture bodies and the
independent Birth/Host digests before starting a deadline-bound child. Actual
child identity, Hello frames, negotiation, assigned request and proof still
come from the live exchange. The original production cut remains unchanged.

The complete raw-JSON Transport run passes 2,081 tests and fails one reply
subprocess test, with 16 ignores and no filtering. Correlation, proof and
publication pass. The remaining flight is
`initial_policy_kernel_normalizations_host_reply_reject_literal_measurement`;
it refuses in shared codec preparation before its intended reply rejection.
The failure remains unresolved at this checkpoint. The script stops before
the standard run and all-target check.

The raw-JSON unit-test executable compiles, formatting and all six architecture
gates pass, and the required application gate compiles 180 test executables
across 58 packages, including 71 integration targets. All 437 owned Rust/Cargo
inputs match the committed revision and its actual captured source. The
application gate executes no tests. These results supply no configured runtime,
VM, Source/native restoration or full RFC qualification.

## Downstream Bootstrap normalization setup

Commit `b766ca7222` separates downstream fixture preparation from the dedicated
normalization tests' independent wire and canonical-hash oracles. Preparation
still executes the complete production normalization under the original cut,
checks every phase and actual retained output, and requires all five completed
digests. Dedicated normalization flights retain every independent comparison
and refusal control. Codec setup failures now identify the last retained step
and original-cut expiry. Production checks and deadlines remain unchanged.

Transport/Engine/Daemon all-feature/all-target checking, owned-file formatting
and all six architecture gates pass. The required application gate compiles
180 test executables across 58 packages, including 71 integration targets.
All 437 owned Rust/Cargo inputs match the committed revision and its actual
captured source. That gate executes no tests. The complete raw-JSON run passes
2,081 tests and fails the same reply flight, with 16 ignores and no filtering.
It now expires in shared correlation preparation before reaching the intended
reply rejection. The standard run does not start because the script stops at
that failure. The fixture change does not resolve the raw reply failure.

## Parent Hello fixture preparation

Commit `94c6667d9c` constructs the parent's immutable Hello fixture before
spawning the deadline-bound child. That fixture reconstructs the selected launch
and independently measures the parent executable. Sending Hello, validating it,
publishing its actual response and binding the bootstrap proof still happen on
the original live channels. The child's original five-second cut is unchanged.

Both standard and raw-JSON Transport test executables compile, and
Transport/Engine/Daemon all-feature/all-target checking, owned-file formatting
and all six architecture gates pass. The required application gate compiles
180 test executables across 58 packages, including 71 integration targets.
All 437 owned Rust/Cargo inputs match the committed revision and its actual
captured source. The complete raw-JSON run passes 2,081 tests and fails one,
with 16 ignores and no filtering, in 452.58 seconds. The reply control fails
at `initial_policy_kernel_normalizations_host_reply_expire_literal_reservation`:
shared codec preparation expires at its Proof step before the intended reply
expiry injection. Correlation, proof and publication pass. Moving parent Hello
preparation does not resolve the failure. The complete standard run passes all
2,082 tests, with 16 ignores and no filtering, in 598.05 seconds. Its reply
control passes. Both suites run against unchanged committed source and stable
test executables after all compilation jobs finish.
These results establish no configured runtime, VM or full RFC qualification.

## Borrow endings and Bootstrap phase timing

Commit `ebc9a8dfb7` removes explicit drops of six borrowed views/closures and
returns the Bootstrap preflight result directly. Nonlexical lifetimes end those
borrows. Actual RefCell guards and the observation producer that owns an Rc
retain their explicit release points. No allocation, row or authority changes.
The endpoint responsibility review is refreshed in `ffd8ecb284` after reading
the complete module; its existing scope rationale and thresholds are unchanged.

Commit `1ba5a34df1` adds test-only remaining-time reports around normalization,
codec input preparation and codec census callbacks. Reports use the original
cut. Child output travels through stdout because stderr is the public protocol
socket. Parent diagnostics retain each actual case name. There are no retries,
new deadlines, filters or completion grants in the fixture.

All 96 focused endpoint and observation17 tests pass across standard and raw
JSON. Raw-JSON test compilation, Transport/Engine/Daemon all-feature/all-target
checking, owned-file formatting and the six architecture gates pass. Strict
Transport library Clippy decreases from 81 to 74 errors, with 1,727 warnings;
no allowance changes. The required application gate compiles 180 test executables
across 58 packages, including 71 integration targets. All 442 owned Rust/Cargo
inputs match committed `1ba5a34df1` and its actual captured source. The subsequent
responsibility-ledger update changes no compiled Rust input.

The focused raw-JSON reply test passes its inherited subprocess cases in 385.06
seconds, with 2,097 other tests filtered. Timing shows roughly 0.23 seconds in
normalization and tens of microseconds in each codec census, while literal and
Value preparation together take about 1.14 seconds. Shared codec preparation
leaves approximately 0.85 to 0.92 seconds on the original five-second cut.
This focused pass does not resolve the previous unfiltered raw-JSON failure.
No new full-library, configured runtime, VM or full RFC qualification follows.

## Nested original Hello response custody

Commit `9d02d82c2e` keeps one complete original request-envelope loan around
response inspection. Previously the response loan opened and completed that
whole predecessor loan separately before and after inspection, recursively
repeating its earlier custody walks. The same predecessor now checks both
sides of the actual callback within one loan. Response completion/cut checks
remain on both sides, and terminal checks still execute when inspection fails.
No deadline, retained owner, allocation, transport action or permission changes.

The counter now prices the actual Copy result through the predecessor's result
frames and the extra borrowed closure reference. Existing inherited response
controls return a 4 KiB Copy value and retain their callback-refusal, expiry,
substituted-cut, retry and ownership assertions. A separate counter control
requires funding for the large result in both retained loan frames.

Standard and raw-JSON Transport test executables compile. Transport/Engine/Daemon
all-feature/all-target checking, owned-file formatting and all six architecture
gates pass. The required application gate compiles 180 test executables across
58 packages, including 71 integration targets. All 442 owned Rust/Cargo inputs
match the committed revision and its actual captured source.

The complete raw-JSON Transport run passes all 2,083 tests, with zero failures,
16 existing ignores and no filtering, in 428.03 seconds. The previously failing
reply control passes. The complete standard run also passes all 2,083 tests,
with zero failures, the same 16 ignores and no filtering, in 427.55 seconds.
Both suites use unchanged committed Rust inputs and stable test executables
after this change's compilation jobs finish.
These results establish no refreshed configured runtime, VM, full signed
Source/native restoration or complete RFC qualification. Strict Clippy remains
unqualified; its last measured library checkpoint has 74 errors.

## Borrowed Bootstrap codec predecessors

Commit `be4a28cb84` groups the four actual predecessor references into one
borrowed codec view. Admission and observation retain their original validation,
census and error order. The quote adds the local view, its overlapping closure,
observer and admission borrows, and the expanded counter-array controls. It
creates no ownership, allocation, renewed cut or production dispatcher.

Standard and raw-JSON test executables compile. Transport/Engine/Daemon
all-feature/all-target checking, owned formatting and all six architecture
gates pass. Strict library Clippy reports 72 errors and 1,729 warnings, down
from 74 errors; it remains failed. The added dead-code warnings expose the
unconsumed view and observation helper in the unwired production path.

Each JSON mode passes all three focused codec tests, with zero failures,
zero ignores and 2,096 other tests filtered. The inherited-channel test exercises
31 flights covering retained typed prefixes, malformed and substituted inputs,
callback refusal, expiry, revocation and once-only retry refusal. Raw JSON takes
96.94 seconds; standard JSON takes 96.80 seconds. Sources and test executables
remain stable after compilation completes. These focused results do not replace
the preceding revision's separately recorded complete-library passes.

The required application gate compiles 180 test executables across 58 packages,
including 71 integration targets. All 442 frozen Rust/Cargo inputs match both
this committed revision and the registered captured source. No configured
runtime, VM, complete Source/native restoration or full RFC qualification follows.

## Scoped Bootstrap proof and reply operands

Commit `84e2837e32` groups each received-request and constructed-verification
scope into a borrowed DATA view. The verifier and reply step helpers use the
same actual SDK, envelopes, DTOs, digests and custody operands. Creating a view
completes no pending verification, publication, Source credit or native phase.
MAC checks, separate admissions, surviving-output censuses, SDK sequencing and
terminal-guard/error order remain unchanged.

The independent scratch quotes add each local view and its overlapping helper
borrows. Counter-array and iterator headers grow with the extra terms. Existing
individual argument and digest terms remain conservative. The complete initial
construction schedule consumes these updated defining quotes.

Standard and raw-JSON Transport executables compile. Transport/Engine/Daemon
all-feature/all-target checking, owned formatting and all six architecture
gates pass. Strict library Clippy reports 68 errors and 1,731 warnings, down
from 72 errors; it remains failed. No lint allowance changes.

The required application gate compiles 180 test executables across 58 packages,
including 71 integration targets. All 442 frozen Rust/Cargo inputs match both
the committed revision and its registered captured source.

The complete raw-JSON Transport suite passes all 2,083 tests, with zero failures,
16 existing ignores and no filtering, in 426.09 seconds. The complete standard
suite also passes all 2,083 tests, with zero failures, the same 16 existing
ignores and no filtering, in 427.77 seconds. Sources and executables remained
stable throughout both runs after compilation finished. These component results
establish no refreshed configured runtime,
VM, complete Source/native restoration or full RFC qualification.

## Original launch custody and shared startup geometry

Commit `47b53d8b09` extends the portable startup calculations in `d96b7ff900`.
Preparation moves the three original launch records into an immutable owner;
jobs retain a lease to their selected original member. Metadata collection reads
that member's actual capacities and checks its owner association. Cancellation
fences further collection and acceptance before releasing the lease. The separate
Linux attempt owner retains responsibility for process drainage and cleanup.

Frame charges, Hello, launch decoding, packet-prefix startup and observation
lifetimes, report aggregation and private bootstrap calculations now share their
defining portable bodies. Native owners, currentness and admission remain upper.
Saved complete old bodies remain independent test oracles; the shared calculations
preserve their query positions, checked arithmetic and refusal order. New headers
are explicitly priced. Composite tests include the genuine adapter families while
retaining their independent original counters and adapter-only assertions.

The final thirteen-crate all-feature/all-target check, all six registered
architecture gates and formatting for the 77 changed Rust files pass. The
content-bound Connection responsibility review is refreshed after reading the
complete module; the continuation review is removed because its implementation
is now below the existing review threshold. Thresholds and exceptions are unchanged.

Full default libraries pass 2,031 Engine, 1,823 Daemon, 1,746 Transport and 61 DATA
tests, with zero failures and no filtering. Ignored populations are 33 Engine,
164 Daemon and 15 Transport; Daemon includes the new asset-dependent native test.
Full raw-JSON Engine, Transport and DATA runs separately pass 2,031, 1,746 and 61
tests with zero failures, no filtering and the same ignored populations. Default
and raw-JSON worker runs each pass 61 DATA, one unit and three stdio controls.
Both unchanged pre-extraction stdio executables pass all three controls against
each new worker variant.

Daemon's default dependency graph enables raw JSON; default Engine and Transport
use default/std JSON.

The new fixed ARM Root/Clock control is also explicitly executed: one native test
passes in 232.98 seconds. After the original process owners and namespace are
removed, two independent fresh restorations reject foreign receipt/ACK custody,
acknowledge their own captured output and produce matching new native output.
The final marker follows child reclamation and namespace cleanup. This is a
direct test-ELF result; the new Nix recipe remains unregistered and unrun. It does
not qualify userspace boot, general Source2, device parity or common Ready.

The ordinary worker package passes strict all-target Clippy, nine emitter tests,
one unit test and three stdio controls. Independent inspection verifies the
2,053,008-byte installed worker, captured source/vendor joins and its four-path
launcher/worker runtime graph with 477 entries and 290 ELF records. The worker's
own compiler graph remains Worker, DATA and Node Format. These artifact checks
do not establish installed Source admission.

The mandatory application gate passes compilation only: 180 freshly compiled
test executables across 58 full package IDs, including 71 integration targets.
Final compilation takes 9 minutes 35 seconds after separate prerequisites.
Worker and application captures precede two later Transport test-expectation
corrections and a test-comment reorder; production inputs match this checkpoint.
The application gate executes no targets and emits no Crucible unit-test ELF;
Crucible CLI, Daemon, worker and QEMU host/plugin remain compiler-excluded.

Request2, selected Fresh15 Source construction, installed common Ready, full
RFC-0025 qualification, backend/device parity and matched Linux VM performance
remain outstanding. Later producer proposals are separate from this checkpoint.

## Portable DATA and contained-worker checkpoint

The extraction in `130525c154` introduces the Apache-licensed L1
`crucible-source-birth-data` crate. It owns the shared records, schema factories,
serializers and bounded SourceBirth algorithm. Engine and Transport retain
native ownership, currentness and admission. The worker's complete Cargo graph,
including development, build and target dependencies, reaches only three local
packages: Worker, DATA and Node Format. Its 48 registry dependencies are distinct
from the workspace's unchanged 639 registry records.

Original public record paths remain reexports. Upper-specific accounting methods
now require named extension traits, and the constant counter entry point is a
free function. These are source API changes. Failed literal reads transfer their
owners into the existing reserved retirement bank without allocating another
bank; executable controls verify the returned error types stay below 128 bytes.
Sharing the original metadata facts record removes adapter storage that caused
twelve real Transport regressions. The original assertions and limits remain.

Thirteen selected crates pass all-feature/all-target checking. All six registered
architecture gates pass. The unfiltered default library suites pass **2,025
Engine, 1,823 Daemon, 1,693 Transport and 34 DATA tests**, with zero failures.
Existing ignored populations are 33, 163, 15 and zero, respectively. Default and
raw-JSON worker runs each pass 34 DATA, one worker unit and three stdio controls.
Both unchanged pre-extraction stdio executables also pass their three controls
against each new worker variant. Current raw-JSON parent oracles separately pass
eight Engine and seven Transport controls.

The ordinary worker package passes its strict all-target Clippy step, one unit
test and three stdio controls; its build-only manifest emitter passes nine tests.
The installed worker is 2,048,912 bytes and needs only glibc and its loader. Its
combined launcher/worker runtime graph contains four store paths: worker,
launcher, glibc and libseccomp. Independent inspection matches its 477 tree
entries, 290 ELF records and actual store-reference edges. The source and vendor
archives match their real derivation inputs. OpenSSL and SQLite declarations
remain unchanged and are absent from this measured runtime graph.

The shared vendor hash is refreshed from the actual new staging output. Exact
lockfile guards remain enabled; canonical, captured, staging and realized vendor
locks agree on 82 local and 639 registry packages. All registry checksum joins
verify. Source identity is established independently of normalized output hashes.

The fresh application gate passes compilation only: **180 freshly compiled test
executables across 58 full Cargo package IDs**, including 71 integration targets.
Final target compilation takes 9 minutes 6 seconds after prerequisites. Its
audited capture has 10,757 files, 1,975 directories and 82 manifests. All 250
owned changed paths are accounted for: 243 captured paths and seven excluded
documentation/architecture roles. Two preserved unrelated ARM source files are
also captured. The gate executes no tests and emits no Crucible unit-test ELF;
Crucible's CLI, Daemon and worker remain compiler-excluded.

The strict reference package still has substantial unused private implementation
diagnostics. Installed Source/native readiness, backend parity, full RFC-0025
qualification and new VM performance measurements remain outstanding. Subsequent
Fresh15 proposals are separate from this tested checkpoint.

## Private seed and import-cleanup checkpoint

Twenty Transport roles remove only verified unused private imports/reexports;
sixty facade groups remain. This cleanup changes no public API/runtime route,
lint allowance or visibility. The separate private seed retains the original
Job/Completion and bank ranges. It authenticates the original Host operand and
retains host/launch clones, executable File, revision and key, including failed
prefixes. No bank is copied into a Birth or adopted from a public DATA summary.

The actor quotes and admits the seed row before its synchronous construction,
then rechecks the original Source/Job/mechanism after every return. A started
failure stays spent and revokes further bank acceptance. These known-byte rows
do not bound opaque runtime, descriptor, kernel or child-resource use; those
remain separate original-deployment obligations. This seed constructs no Initial,
Recipe, native member or Ready state; genuine selected-route producers remain
missing and the selected funded path still refuses readiness.

Twelve selected crates pass all-feature/all-target checking, and all six
registered architecture checks pass. The full Engine suite passes **2,052 tests,
zero failures and 33 existing ignores**; Daemon at eight threads passes **1,823
with zero failures and 163 existing ignores**. Both are unfiltered. The prior full
Transport result of **1,696 passes, zero failures and 15 existing ignores** is
unchanged by the seed.

The mandatory application gate passes compilation only for its audited capture:
**180 freshly compiled test executables across 58 full Cargo package IDs and
manifests**, including 71 integration targets across 15 packages. It runs no tests
and emits no Crucible unit-test executable. CLI, Daemon and worker are excluded
from compilation. The 10,687-file, 1,946-directory capture has 81 manifests and 30
changed paths: 20 Transport, eight Engine and two Daemon, including five new
Engine files. The test-only File correction is within those paths; manifests,
lock and vendor remain unchanged. No whole-HEAD or runtime qualification follows.

The local strict-Clippy comparison fails before and after cleanup: visible
primary diagnostics fall from 1,596 to 1,573, with 23 removed and none added;
Transport falls from 1,595 to 1,572 while Store remains at one. In both runs,
the Transport footer exceeds its visible count by one; the cause is unexplained.
This scoped diagnostic reduction neither clears package Clippy nor supplies a
registered VM, installed-job or end-to-end Source/native/Ready result. All earlier
qualification limits remain.

## Configuration and supervised-job checkpoint

The portable logical configuration is committed in `36d4a75506`, and genuine
service-startup extraction in `afcd81a1fa` preserves the original startup
schedule. The producer, actor observer and registered VM wiring are committed
in `6dc61277ad`. The original supervised-job join is separately committed in
`6643f5a607`; its distinct application gate also passes within the scope below.

The new configuration recipe omits PID-derived Host tokens and derived
coordinator/initial/launch references. The actual consuming actor constructs and
retains its genuine Host before deriving those local records. The same pinned
logical input can produce different operational references, receipts and saved
state across processes. This fixed four-node recipe retains Unqualified native
nodes, Nondeterministic native/world rows and the genuine Host's unchanged
guarantees. It refuses deterministic scenario requirements and does not repair
or reinterpret installation snapshots.

The producer writes configuration separately from measuring the finished file.
The VM recipe builds test-support producer/consumer separately from the
default-feature CLI and independently measures the actual consumer and CLI ELFs.
It does not substitute fixture features or the current executable for that CLI. The
actor observer records first authenticated template outcome and retained world
credit; its phase is neither authority nor continuous Source-custody proof.
Normal commands still return `Refused`. The registered failure below supplies no
execution result for these planned flights.

All nine focused configuration controls pass. The complete default-feature
Daemon run with **eight test threads passes 1,823 tests, zero failures and 163
existing ignores**, with zero filtering. An earlier automatic-thread run had
1,822 passes and one failure in the unchanged 10ms Vec fixture; the same exact
binary passed that control alone. That fixture's assertion, deadline and ignore
status were unchanged.
Twelve selected crates pass all-feature/all-target checking, and all six
registered architecture checks pass after startup extraction, without a policy
exception. These runs supply neither a full-graph nor a two-PID template result.

The registered funded-Source-template VM attempt fails **before boot** while
building its canonical worker dependency: Store reports one Clippy error and
Transport 1,595 errors at that captured input. The failure audit locates these
1,596 primary diagnostics in 406 defining files, without overlap with this
batch's named source owners; neither master nor the full branch is thereby
proved clean. No template, full-graph, two-PID
positive, installed CLI deployment or Ready execution follows. This result does
not qualify the intended observer/credit/cleanup flight.

The mandatory application gate passes for its independently audited immutable
capture: **180 newly compiled test executables across 58 full Cargo package IDs
and manifests**, including 71 integration targets across 15 of those packages.
Final target compilation takes 9 minutes 29 seconds after separate prerequisites;
this is not performance evidence. The capture contains 10,676 files, 1,942
directories and 81 manifests. Its 34 changed paths comprise 33 Daemon paths
outside compiler selection and one captured Engine cfg(test) fixture, which is
not compiled as a Crucible unit-test target.
The gate executes no tests and emits no Crucible unit-test executable. CLI,
Daemon and worker packages are compiler-excluded, and the VM recipes are outside
its source filter.
All later worker-job posts are excluded. This result grants no current whole-tree,
VM, template, worker-job or Ready qualification.

The committed original-job join retains the real Linux attempt, its strong
attempt/program identities, immutable input receipt, sealed completion and first
typed failure independently of Source loans. The actor exports once through the
concrete quota-owned input, then ends Source loans before starting or polling.
Same-Source/program verification checks that completion's captured output;
successful banks remain ranges in that original allocation, with currentness
reauthenticated on access. Cancellation revokes acceptance, including after
completion. Retirement keeps all jobs, failed prefixes and world credit until
actual drainage, receiver closure and namespace cleanup permit release.

For this distinct job checkpoint, twelve-crate all-feature/all-target checking
and six architecture checks pass. The full default Engine suite passes
**2,047 tests, zero failures and 33 existing ignores**, zero filtered, including
all seven new job controls. The complete default-feature Daemon suite passes
**1,823 tests, zero failures and 163 existing ignores**, zero filtered, at eight
threads in 298.06 seconds. These are component/unit results, not an installed
successful job or bank-acceptance witness. The registered VM's preboot failure
remains unresolved. Genuine selected-route Initial/Recipe constructors are
absent; their next step is design-only. Normal commands still refuse readiness.

The distinct job application gate also passes for its independently audited
immutable capture: **180 newly compiled test executables across 58 full Cargo
package IDs and manifests**, comprising 56 library, 53 binary and 71 integration
targets. The integration subset spans 15 of those packages. Final target
compilation takes 10 minutes 3 seconds after separate prerequisites; the two
application captures are not performance comparisons. This capture contains
10,682 files, 1,944 directories and 81 manifests. Its 21 changed paths comprise
five Daemon and sixteen Engine paths, including six new files, over the prior
capture; the restricted reexport correction is within those 21 roles. All member
manifests, the workspace manifest and lock are unchanged. It executes no tests
and emits no Crucible unit-test executable; Daemon, CLI and worker packages remain
compiler-excluded. Owner-baseline metadata is outside this application filter.
Neither application result qualifies the whole current HEAD, an installed job,
VM execution, accepted Source/Ready, preservation or strict lint.

The separately committed testing-standards baseline migration changes only 82
owner keys: 59 Provider, 12 QEMU and 11 Engine. All 318 existing debt entries
retain their counts, patterns and targets; no allowance is added. The actual
rerun still fails with four passes and one failure. Findings fall from 220
(138 unbaselined plus 82 stale) to 56 unbaselined and zero stale, independently
reconciled against the exact residual set. These 56 remain unresolved. The
historical strict harness result of 26 passes and five known failures is
separate and has not been rerun.

The earlier checkpoints below retain their own captured input, feature and
execution scopes.

The branch includes the master merge and schema/owner corrections through
`f7b0d801af`. The target-discovery correction in `e8df62e9ef` classifies library
targets from Cargo manifests and source presence. Its strict harness run passes
26 tests and retains five known failures. Its independently audited application
target capture compiles 180 test executables across 58 packages and executes no
tests; that capture predates the deployment foundation.

The deployment foundation in `752c428f54` adds an explicit before-actors
operational deployment: one nonrenewable whole-parent CPU/address-space/descriptor
envelope,
same-original process-scoped leases, and an actor-owned installed mechanism and
namespace. Selected template preparation checks actual known component demand
against that installed envelope and retains failed output. This does not turn
partial known-byte observation into complete allocator accounting. Even after
successful template preparation, the actor command returns `Refused`; this
foundation starts no worker job and issues no accepted Source result, Initial,
Recipe or Ready state. Later configuration changes are outside this checkpoint.

For the foundation's captured inputs, the complete default Daemon suite passes
**1,814 tests, zero failures and 163 existing ignores**, with zero filtered, in
278.85 seconds. All six registered architecture checks pass, as do 35
HostResources tests. The registered L2 control executes all four dedicated-process
modes: same-original thread handoff/drop, retained birth refusal, stricter inherited
ceilings across exec, and sticky revocation after soft-limit restoration. Its
launcher limits remain unchanged. These controls do not prove forked-owner
transfer, forced partial kernel-update failure, resource exhaustion or Source
acceptance. Twelve selected crates, including the CLI, pass all-feature/all-target
checking in 2 minutes 21 seconds; this is compilation, not test execution. The
focused CLI parser control passes with 363 tests filtered: it accepts the
operational-policy flag and refuses authority/bank-stage flags. That tests
argument parsing, not installed CLI execution.

The initial full default Engine run reports **2,039 passed, one failed and 33
existing ignores**, with zero filtering. Its peer-close failure-retention control
passes alone using the same binary. After a separate test-only explicit-shutdown
and retained-alias correction, the full default rerun passes **2,040 tests, zero
failures and 33 existing ignores**, with zero filtering, in 4.72 seconds. Both
full runs use automatic default thread selection. This establishes the corrected
fixture result without proving the failed run's precise descriptor-inheritance
cause. That separate fixture correction is committed in `065f8815d1`.

The mandatory application-target gate passes for its immutable foundation capture:
**180 newly compiled test executables across 58 full Cargo package IDs**,
including 71 integration targets across 15 of those packages. Final target
compilation takes 10 minutes 8 seconds after separate prerequisites. Independent
audit verifies all 10,666 captured files and 81 manifests. This gate executes no
tests and emits no Crucible unit-test executable; CLI and Daemon sources are
captured but their packages are outside its compiler selection. The capture
excludes the later fixture correction, configuration, producer and observer
changes; no runtime or latest whole-tree qualification follows.

The earlier worker and mechanism checkpoints below retain their own captured
source and configuration scopes.

The private derivation-worker foundation is committed in `3aca144b23`, with
separate presentation changes in `628a575a8a`. It adds closed request/result
streams, the Engine-only worker process, its measured source-built package recipe,
retained Linux process supervision and child containment. The worker is the
81st workspace member. Parent Source activation and accepted-result bank joins
remain unfinished.

The installation verifier in `c3aafd62b0` retains the original opened program
while checking the measured source-built installation, complete read-only
runtime inventory and supported ELF dependency resolution. All nine focused
controls pass. Its complete default Engine suite passes **2,038 tests, zero
failures and 33 existing ignores** out of 2,071 declared tests. These results
do not qualify an installed worker or parent Source acceptance.

A separate `serde_json/raw_value` run passes Engine 2,038 and Transport 1,696:
**3,734 passed, zero failures and 48 existing ignores**. The nested child control
is part of the Transport count, not an extra test. The raw-value worker CLI/stdio
run passes all four tests. These inputs predate the later mechanism-template
bridge. Earlier foundation runs retain their own scope: HostResources 30,
two Daemon deadline controls and its supervisor error-mapping control, and
Protocol 234 library passes with one existing ignore plus 18 ABI integration
passes. No counts are cumulative across source states or feature selections.

The Source mechanism bridge is committed in `5fd925f1d2`, following separate
constructor presentation in `024efdf782`. Both new default-feature controls
pass, and the final composite default Engine run after extraction passes
**2,040 tests, zero failures and 33 existing ignores**, with zero filtering out
of 2,073 declared tests. Both intended compile-fail documentation controls
remain valid: the quote cannot be cloned and bindings DATA cannot replace the
verified mechanism owner. The earlier doctest loader failure was resolved by
forwarding the existing Cargo-shell link flags to rustdoc.

The earlier engineering-hygiene refusal is resolved through a meaningful
123-line constructor child and a human-reviewed parent with 1,396 implementation
lines. All six registered architecture checks now pass for that Source
checkpoint, without an exception or policy relaxation. The cleanup of six
private Transport imports in `fbe620c2ee` preserves runtime bodies; its complete
default suite passes 1,696 tests with zero failures and 15 existing ignores.
Eleven-crate all-feature/all-target checking including the final Source and
Transport imports passes in 49.26 seconds. The Engine and Transport runs have
separate captured states and are not combined into a new latest-suite total.

The bridge retains the mechanism through original template/Source handles;
selected complete census, worker-job execution and accepted-result joins remain
unprovided. Module comments in `00d4929c4b` and the private-function cleanup in
`f4921f9a25` have source-only body-preservation evidence, not separate runtime
qualification.

The earlier application-target gate passes for its captured composite:
180 compiler-reported test executables across 58 Rust packages and 58 application
roots, including 71 integration targets. Final target compilation takes
10 minutes 15 seconds after separate prerequisites. Independent audit binds
10,656 captured files, all 81 workspace manifests and the matching vendor/lock
inputs. The reduced compiler workspace has 70 members. It emits no Crucible
unit-test executable or worker binary, and executes no tests.

This working-tree capture includes the final Source binding and six Transport
imports at their selected postimages, plus the Native11 source inputs. It is
not a clean committed-tree identity, and source presence alone does not execute
the native component. The earlier 11-minute-29-second capture predates the
verifier, bridge and later Spawn changes and retains only its historical scope.

The disposable Linux containment VM passes its actual cgroup, Landlock,
seccomp, descriptor, filesystem, output, cancellation and waited-cleanup
controls. Independent review binds the compiled sources, binaries and VM
results. Its memory control requires a mapped allocation followed by SIGKILL
and an increase in the original cgroup's OOM counter; the kernel log also
records that OOM kill. Address-space refusal is tested separately. Quota
installation and release are exercised; quota exhaustion and quarantine-error
injection are not. This qualifies the selected child containment boundary,
without qualifying Source acceptance or total parent/constructor memory
admission.

The post-merge owner corrections in `f7b0d801af` retain schema and wire versions,
discover nested workspace owners from manifests and check the active ABI30
field at byte 39. Registered shared-memory layout and QEMU launch checks pass;
the Store source check also passes. The Spawn fixture correction in
`b27d6712f1` passes 70 default-feature spawn controls with one existing ignore.
The registered spawn check separately passes 55 parent controls; its nested
child is not counted again. These task-level results do not establish guest
execution or complete lifecycle preservation. Earlier worker installation and
gem5 SE/ARM gate attempts failed on the same 1,602 Transport lint sites at their
captured inputs, before the later Transport import cleanup. That historical
count is not a current total. None of those attempts qualifies an installed
worker, SE preservation,
ARM boot or aggregate ABI/license compliance. No lint allowance or gate-policy
change is used to bypass these failures.

The separate gem5 thirteen-mode native callable check passes with independently
verified source, compiler and output bindings, including all five new adverse
controls. These results are distinct from the modeled cache/table/walker
controls and do not qualify SE preservation, ARM boot, common Ready or capture.

For the frozen native10 inputs, whose native changes are committed in
`9b572d78e4`, the registered packaged QEMU native-prefix check passes
all three selected cases with zero failures or ignores: budget exhaustion at
350 ps returns PartialPrefix; the exclusive 151 ps interval completes; and a
query of the genuine initial stopped source reports raw count zero and the
next CPU frontier at 50 ps before that same session completes its interval.
Each case checks its original command/ACK association and reaps its child.
The source observation runs on the native RR thread and crosses the process
boundary as a versioned scalar record. These results do not qualify common
Ready, operation turnover or capture.

The matching QEMU package completes all 3,794 build steps and selected package
checks; its plugin passes all 803 tests with no skips. Registered atomic patch
regeneration verifies exact patch equality, the signed bundled commit and the
installed package identity. Independent review verifies the captured source and
runtime identities. Ten-crate all-feature/all-target checking also passes for
these captured inputs. The included Source/ArmRoot changes and later result-wire
codec, process worker and containment changes receive no runtime qualification
from these runs; aggregate
architecture, ABI/license and release qualification remain pending.

The native11 changes are committed in `ba0fc1dfb6`. Their fresh registered
installed-session gate passes all four selected ordinary cases, each with zero
failures or ignores. The matching signed atomic
successor `d4506b2d27` includes the reviewed cached-query rollover correction.
Its QEMU package completes all 3,796 build steps and selected package checks,
including six pure arithmetic controls; the matching plugin passes all 808
ordinary tests with zero skips.

The new installed case observes completed-prefix retirement, quiet 151→175 ps
at raw3, same-tick Boundary→Reaction Settle, quiet advance to 199 ps and refusal
at the due CPU frontier of 200 ps. All five original command/ACK associations
reach durable retirement and the original child is reaped. The registered host
binary is freshly built from its captured source; that capture precedes the six
Transport import changes. This is bounded completion/partial, initial-source
observation and completed-prefix quiet-turnover evidence. General evaluating
turnover, common Ready, capture and full backend/device parity remain unqualified.

The refactor at `b86bcd18eb` shares secret-free launch, Hello and registration
operands with their original consumers, and adds bounded literal-Value streams
with iterative success/failure ownership and closed diagnostics. Engine and
Transport pass all-feature/all-target checking. Their complete default and
separate raw-value library runs each pass **3,706 tests with zero failures and
48 existing ignores**. All 28 new controls execute in both configurations: seven
launch-validation comparisons, five Hello/registration comparisons, four shared
serializer comparisons and twelve literal-stream controls. The current
application-target capture includes these operands and literal streams; the
verifier, bridge and Spawn components retain their separate evidence above.
The parent job join and native activation remain unqualified; the child
containment result has only its separately recorded boundary scope.

The earlier workspace at `cb1f6ae448` includes the merge of `origin/master`
(`68851a3bf1`, merge `f83ea82651`), the reference-provider vendor and source-filter
refresh, safe callback-layout measurements, strict-parser cursor extraction,
owned identifier refusals and the ordinary Prepared observer projection. The
split node-format, transport, host-resource and control API owners preserve
executable names and wire identities.

An independent audit of the complete five-library run records **5,562 passed,
zero failed, 211 existing ignores and zero filtered tests**, including all nine
new controls. The existing Daemon preparation fixture also executes the new
projected-versus-original census and retained registration assertions. Separate
node-format default and raw-value configurations each pass 60 tests; eight
focused transport controls pass. Eleven-crate all-feature/all-target checking
and the refreshed unsafe-fence and engineering-hygiene checks pass. These
results cover their recorded source and configurations; earlier feature,
artifact, layer and specification checks remain historical evidence.

The cursor writes its numeric state directly through short input/state loans;
the identifier refusal retains the original owned string and typed cause; the
observer follows exhaustive actual fields through one shared Counter. These
changes preserve ordinary parser/error order and actual failed-owner custody.
They do not supply the retained strict attempt, dynamic constructors,
authentication join, partial census or iterative retirement needed for the
later Source18 path. They grant no Initial, Recipe or native permission.

The mandatory production application-target gate passes for `cb1f6ae448`: 180
test executables across 58 application roots, including 71 integration targets.
Final compilation takes 10 minutes 14 seconds after prerequisites. Its 10,575
captured files and all 80 workspace manifests match that commit; shared vendor
and lockfile checks agree. This gate compiles tests without executing them.

An earlier post-native11 strict harness refresh remains failing: 21 tests pass
and five fail, with zero ignored or filtered tests out of 26, in 16.47 seconds.
No new diagnostic-emission total is claimed. An earlier checkpoint recorded
599 diagnostic emissions after ten stringly-error and six bare-unsafe findings
disappeared. Its private compile-time standard-IO layout alias carried a reviewed
explanation under the existing line-local policy. Scanner, rules, source
selection, ignored-test population and limits remain unchanged in this refresh.

The sixth registered kernel source check passes 21 source-consuming FD cases
with modeled kernel peers, four ordinary build-host FD groups and compilation
of four configured kernel translation units. Its mandatory legacy dependency
retains the successful 39 PIC/EOI/queue controls and eight configured objects.
These are distinct modeled, host-FD and Kbuild results; full kernel/module
linking, source-companion builds, boot and patched-kernel runtime remain
unqualified. Constructor coverage stays `0x001` of required `0x7ff`, with no
FD-table, CREATE, KVM_RUN or readiness capability issued.

For the QEMU source checkpoint `d5e5a60107`, registered patch regeneration,
ordinary native compilation and the selected package checks pass. All 3,794
build steps complete, and all four native FW_CFG directory-validator cases
pass. Atomic patch/bundle identities, ABI30 header and license ledger match the
selected source. Full upstream testing, aggregate ABI/license and release gates,
matching source-package realization, complete q35 readiness and capture/fresh
restore remain pending. Full-system gem5 execution, matched performance and full
preservation remain unqualified.

A separately reviewed gem5 change inspects the actual callback target and
original SystemCounter owner without copying or invoking the callable. Five
new adverse controls join the eight existing modes. The thirteen-mode native
check now passes within the limited callable-identity scope described above;
no additional native capability is issued.

The cleanup extraction at `9559fe3526` moves bounded, descriptor-relative
private-directory removal into HostResources; QEMU keeps its existing storage
error mapping. Traversal is iterative, authenticates directory identity and
unlinks symlinks without following them. The caller still excludes writers and
retains the original root and quota through partial failure; this helper proves
neither process reap nor permission to release those resources. All 20
HostResources unit tests and eleven selected QEMU storage tests pass with zero
failures or ignores. Six registered layer, specification, artifact, feature,
unsafe-fence and engineering-hygiene checks also pass for this checkpoint.

The registered native-prefix check at the `0e9d17fd99` checkpoint passes both
selected cases, with zero failures or ignores. The original 350ps control
returns PartialPrefix after exhausting its allowance; the exclusive 151ps case
returns Completed. Both assert their original command/ACK association, and
each reaps its original owned child before reporting success. These are two packaged native
prefix results, not common Ready, operation-turnover, complete retirement,
capture, full-profile or performance qualification. Their captured source
predates the eighteen later worker projection and codec successor changes;
those changes receive no execution result from this run.

## Earlier construction and qualification checkpoints

The Source18 construction path now retains an explicit installation selection
through separate code and fresh Sources, prospective admission, capture-bank
reservation and private Birth-worker initialization. Original inputs, failed
prefixes and spent attempts remain owned. Owning response-shape checks preserve
the existing schema order; the guarded flat-value materializer constructs and
retires deep values iteratively. First Coordinator decoding, later validation,
encoding, private File creation and native startup remain disconnected. This
checkpoint grants no Initial, Recipe, readiness or restoration permission.

The Source18 functional checkpoint passes 5,212 tests with zero failures and
211 existing ignores. It includes all 159 controls added since `a488bf1a4b`;
no existing control was removed or newly ignored. The complete Provider suite
also passes separately with ordinary Serde JSON and with raw values enabled.
The formatted checkpoint also passes six-crate all-feature/all-target checking
in 1 minute 57 seconds. The mandatory application-target build compiles 167 fresh
test targets across 48 packages, including 69 integration targets, in 11 minutes
41 seconds after its prerequisites. Its captured source matches `33303283c4`.
Full preservation and strict gates remain outstanding.

Daemon preparation now allocates its large restored-load destination only when
the actual restoration path enters. Its original owner retains the allocation,
once-only row and partial attempt through refusal. This fixes the default-stack
overflow without increasing stack, timeout or resource limits. The previously
aborting fixture passes in 261.38 seconds. The four selected compiler frames
total 1,685,488 bytes versus 2,245,712 before the change, a reduction of 560,224
bytes. These selected frame extents do not establish maximum stack use or an
overall performance improvement.

Native79 passes the existing complete startup/reclamation control in 655.45
seconds at the formatted checkpoint. The current-source Device, optimized
Provider and daemon test executable are frozen with their actual compiler
records. All three runtime rechecks, attached actor, maximum/exact/one-byte-short
whole-holder census, destination assertions, final census, retirement and child
reclamation complete. The default stack, single test thread and fifteen-minute
limit remain in effect. The refreshed helpers match the historical effective
profile fields; their bytes and source have changed. This single successful
control supplies no matched performance comparison or full state-preservation
qualification.

The SDK receive components now retain immutable input custody through quotation,
normalization and failed-prefix observation. The twenty-five-file change adds
flat first/second-pass projections, structural Envelope/ResponseShape cuts and
private owning raw-frame selections. The subsequent thirteen-file change moves
the same first-pass engine behind borrowed and by-value owning adapters. The
fourteen-file successor adds an independently funded immutable first bank and
movable second-pass state around the existing second-pass engine. A subsequent
ten-file change adds owning structural Envelope fields and a separately admitted
canonical-body check. The following thirteen-file change adds the movable
response cursor around the same schema schedule. These components remain disconnected from
the live Source18 route; they grant no Initial, Recipe or native permission.
The earlier production application-target build passes for `33303283c4`,
including these receive components. It compiles tests without executing them.

`23f0513b98` adds the guarded flat literal-state codec. It preserves literal
keys, full integers and floating-point representations, retains failed prefixes,
and retires deep constructed trees iteratively. It enables no Source18 or native
import path. `930ff6028b` selects the initial census from actual actor custody,
preserves its first error, and uses the existing initial graph precredit walk.
`b11ba2f059` separately formats the census call.

| Check | Latest recorded scope and result |
| --- | --- |
| Source18 functional libraries (`060f025eef`) | Core 2,013/33 ignored, Daemon 1,511/162, Provider 1,676/15 and Contract twelve/one: 5,212 passed, zero failures, 211 existing ignores, no filtering. Core takes 8.68 seconds, Daemon 364.06 seconds and Provider 11.91 seconds. |
| Earlier Provider configurations | Each separate complete suite passes 1,676 tests with zero failures and fifteen existing ignores: ordinary Serde JSON in 12.05 seconds and raw values in 11.60 seconds. All twenty new materializer controls pass in both. |
| Earlier stack regression | The exact previous-overflow fixture passes on the default stack in 261.38 seconds. All five new allocation/custody controls also pass in the complete Daemon suite. |
| SDK receive formatting | The raw custody, owning-first, owning-next, ten-file owning-Envelope and thirteen-file response-cursor cohorts pass. The two Envelope test-assertion corrections also pass. |
| Prior SDK integration checking | Six-crate all-feature/all-target checking passes in 1 minute 41 seconds after owning-Envelope, and in 1 minute 47 seconds after owning-next. The earlier owning-first/debug-label checkpoint passes in 1 minute 51 seconds. |
| Neutral debug diagnostics | Four files pass formatting. The existing Core invalid-endpoint/unknown-node control and three Session debug-runtime transaction controls pass. Only backend-neutral diagnostic labels and the matching existing expectation change. |
| SDK receive controls | All 74 targeted controls pass with ordinary Serde JSON in 0.02 seconds, including ten new owning-response controls. Both complete suites also execute all 74 controls. |
| Prior SDK Provider regression | Each complete suite passes 1,570 tests with zero failures and fifteen existing ignores: 11.91 seconds for ordinary Serde JSON and 11.69 seconds with raw values enabled. |
| Prior runtime checking | The thirteen-file runtime accounting correction passes six-crate all-feature/all-target checking in 1 minute 28 seconds and targeted formatting. |
| Earlier application-target compilation | Passes for `33303283c4`: 167 fresh test artifacts across 48 application packages, including 69 integration targets, in 11 minutes 41 seconds after prerequisites. All 7,990 captured source files and modes match that commit. This gate executes no tests. |
| Runtime correction library checkpoint | All four unfiltered libraries pass: Core 1,967, Daemon 1,504, Provider 1,496 and Contract twelve, totaling 4,979 with zero failures. Existing ignores remain 33/162/15/1. Ten focused Host attachment controls also pass, including both new accounting controls. |
| Prior runtime test compilation | Standard four-library compilation passes in 4 minutes 2 seconds. Assertions, overflow checks and default stack remain enabled. |
| Earlier startup/reclamation pair | Baseline reaches the fifteen-minute limit during inactive-runtime construction; optimized construction finishes, then its recheck refuses after 641.39 seconds. Normal retirement and child reclamation pass. |
| Earlier startup/reclamation control | Native79 passes in 655.45 seconds with its recorded source helpers and the standard default-stack, fifteen-minute control. All three runtime rechecks, attached actor, exact/one-byte-short whole-holder census, destination assertions, retirement and child reclamation complete. Full native preservation remains unqualified. |
| Kernel FD source and object checks | The selected 43-stage source catalog contains 182 roles totaling 5,151,081 bytes. The sixth registered check passes 21 source-consuming FD cases with modeled kernel peers, four ordinary build-host FD groups and exact-source/dependency Kbuild checks for fs/file.o, mm/crucible_allocator.o, mm/slub.o and virt/kvm/kvm_main.o. Its required legacy dependency retains 39 passed controls and eight configured objects. Full kernel/module linking, source-companion builds, boot, patched-kernel runtime and complete FD coverage remain unqualified. |
| QEMU FW_CFG insertion lineage | Registered regeneration, the ordinary 3,794-step native build and selected package checks pass at the recorded source checkpoint. All four native directory-validator cases pass; exact atomic patch/bundle, ABI30 header and license-ledger bindings agree. The earlier 296-entry license ledger and configured 1,576-test inventory keep their separate scope. Full upstream testing, aggregate ABI/license/release gates, matching corresponding-source realization, host/plugin-pair checks and complete q35 readiness/capture/fresh restore remain pending. |
| gem5 SystemCounter observation | Source review and package evaluation pass for the bounded cached-state producer and registered counter controls. Compilation and native execution remain pending. Listener, callback backing, full-system timer ownership, capture and fresh restore remain unqualified. |
| Real-host KVM preparation | The existing exact stopped-VM test passes: one passed, zero failed, 884 filtered, in 0.04 seconds. Standard test compilation passes in 4 minutes 52 seconds. It creates no vCPU or guest execution and does not qualify the controller profile. |
| Outstanding qualification | Full preservation, strict lint, ABI and license gates remain pending. |

The kernel FD checkpoint retains original publication and retirement identity
across growth, slot clearing, replacement, final files-table release and queued
RCU callbacks. A publication token now survives a peer clearing the visible slot
before the installer returns. Source review checks this race and the original
identity, generation and once-only checks. Twenty-one source cases and four
ordinary FD groups extend the existing registered PIC source-check facility;
the existing controls and resource limits remain intact.

The earlier complete source-application derivation remains a separate
source-only result. The sixth registered check uses the updated 43-stage,
182-role catalog totaling 5,151,081 bytes. It passes all 21 source-consuming
FD cases with modeled kernel peers and four ordinary build-host groups for
growth, exhaustion, concurrency and exec. Kbuild compiles fs/file.o,
mm/crucible_allocator.o, mm/slub.o and virt/kvm/kvm_main.o; installed dependency
records bind each object to its actual selected source. The required independent
legacy check retains its successful 39 controls and eight configured objects.

These results establish neither patched-kernel execution nor full kernel/module
linking, boot, matching source-companion release or physical accounting.
Constructor coverage remains `0x001` of required `0x7ff`; this checkpoint grants
no FD-table, CREATE, KVM_RUN or readiness capability.

The QEMU FW_CFG directory mechanism observes original entries, payload and
callback identities, selectors, both tables and the live directory backing
before insertion is published. The existing native insertion body remains in
place. Four ordinary QEMU unit cases cover valid sorted moves and adversarial
lineage changes, including an identical directory copy with foreign backing.
The complete atomic patch, signed branch bundle, descriptor and license ledger
are updated together. The source-package probe now checks its shipped atomic
descriptor and manifest-named patch and bundle, including their hashes.

The registered native QEMU build completes all 3,794 steps for the selected
x86_64 and aarch64 softmmu targets, followed by its selected package checks.
The four native FW_CFG cases pass: all insertion positions, original-owner
controls, pre-effect refusal and directory alias. They execute the production
inline directory validator against fixture views; they do not exercise complete
q35 initialization or the full payload/callback lifecycle.

The registered atomic-patch regeneration gate also passes. Its regenerated
patch, branch bundle, installed ABI30 header and license ledger match the
selected identities. The repository check verifies pinned embedded signature
bytes and presence, not independent trusted-signer cryptography. The earlier
296-entry patch-license ledger and configured 1,576-test inventory remain
separate scoped results, rather than aggregate process-boundary acceptance.

The full/thorough upstream suite was not selected. Matching complete
corresponding-source package realization, aggregate ABI/license/release gates
and installed host/plugin-pair checks remain pending. Full FW_CFG payload/callback
ownership, ROM closure, Ready admission, Linux guest continuation and exact
capture/fresh restore remain unqualified.

The gem5 SystemCounter producer reads cached values, frequency-table storage and
the original frequency-event identity without updating the counter or servicing
its queue. The concrete ownership visitor admits only an exact counter with no
listeners. Three additional stopped-counter modes extend the five existing
registered diagnostic modes. A separate ordinary gem5 control observes a stale
cache at a nonzero tick and checks the real frequency callback. These controls
are authored and source-reviewed but have not run. Package evaluation passes;
compilation, full-system timer/listener ownership, native backing resources,
source issuance and fresh adoption remain pending.

One matched pair reaches the same inactive-runtime construction milestone in
approximately 624 versus 364 seconds (41.6% less time). Only the three currentness
files differ; all 7,046 source inputs, actual compiler profiles and common
Provider/Device inputs were independently checked. Both use the existing test,
default stack and unchanged limit, without a debugger or concurrent builds from this work.
This is a partial startup-test measurement, not a completed preservation control
or Linux-boot result. The optimized recheck reports `UnsupportedFacet`; source
review finds that an inapplicable dormant fallback masks its first census error.
Two reviewed repairs select the census from actual actor custody and use the initial
graph precredit walk. They pass checking and the unfiltered library suites. The ordinary Native75
control then exposes the original `ResourceLimit` at inactive-runtime recheck
after 667.18 seconds. Retirement and child reclamation complete. The diagnostic-only
Native76 follow-up passes standard four-library test compilation and reaches the
same refusal after 684.65 seconds. Actual requested storage is 3,499,478,788 bytes
against the original 3,480,992,798-byte peak, a gap of 18,485,990 bytes (17.63 MiB).
The unchanged 4 GiB byte policy and 128-descriptor policy are satisfied; actual
descriptors total 67. Retirement and child reclamation complete. This identifies
an incomplete prospective quote rather than a need to increase resource ceilings
or the timeout.


A subsequent four-file plan-view optimization keeps both fixed currentness bodies,
all eight Source/Host parent checks, both selectors and the full entry/terminal
file reads, while removing the two interior full-file read series. Its separately
quoted controls add 1,138 bytes to callback transient demand. The ordinary path
stays unchanged. Source review records one concurrency limit: file drift at a
removed interior read is detected at the terminal read; an intervening plan
mismatch remains the primary error. Terminal drift still revokes the same owner.

Six new real-fixture controls pass in 6.51 seconds, and six-crate all-feature,
all-target checking passes in 1 minute 18 seconds. All five changed Rust files,
including the diagnostic file, pass formatting. Native77 runs the same existing
startup/reclamation test in 571.27 seconds versus Native76's 684.65 seconds:
16.56% less time (1.20x). Both reach the same inactive-runtime recheck refusal,
with the identical 18,485,990-byte gap and 67 descriptors, and complete normal
retirement and child reclamation. The added 1,138-byte control row appears on
both sides of the peak comparison. Frozen Provider/Device inputs and actual
compiler profiles/features match; only the four plan-view Rust files differ.
The test ELF grows by 24,680 bytes, including the six unselected helper tests.
Command evidence includes Root's actual execution record; the independent
provenance review does not establish a historical prelaunch environment snapshot.
This is one failed-startup control pair, not full preservation, a Linux-boot
result or an additive overall speedup. Final ABI/license qualification remains
outstanding for this stage.

The subsequent runtime accounting correction separates real new allocations
from additional conservative ownership reports. The same graph and attached
Host source appear through several independently authenticated observers after
transfer into the runtime. The prospective quote now derives those report paths
from the genuine original graph, Source, registry and node owners; it separately
prices the one new world-hash clone and the added quote controls. Other purposes
retain their existing path, and post-construction observations cannot request
new construction credit. The original policy ceilings, once-only members,
partial-failure custody and final actual-versus-admitted comparison remain in
force.

Native78 passes the existing complete startup/reclamation control in 678.05
seconds with the same frozen Provider/Device, standard fifteen-minute limit,
default stack and no concurrent builds. All three runtime construction phases
complete their rechecks. The test then authenticates the real attached actor,
checks maximum/exact/one-byte-short whole-holder storage, verifies missing,
correct and wrong destinations for all three members, repeats the exact census,
and completes normal retirement and child reclamation. Its zero-budget actor
`ResourceLimit` diagnostic is an expected negative assertion. Independent review
checks the completed log, all 11,427 tracked files and modes, the thirteen
selected source roles and unchanged protected files. This qualifies startup and
reclamation, not full state preservation or Linux performance; its extra
assertions preclude treating elapsed time as a matched comparison with failed
Native77. The current-source unfiltered libraries subsequently pass 4,979 tests
with zero failures: Core 1,967 in 8.39 seconds, Daemon 1,504 in 354.13 seconds,
Provider 1,496 in 11.50 seconds and Contract twelve. All 211 existing ignores
remain unchanged. The mandatory application-target refresh subsequently passes
for `751d8331cf`, as detailed below.

The earlier diagnostic run timed out after fifteen minutes. Its nine read/hash stack observations
and 2.957 TB of read accounting are diagnostic evidence, not statistical CPU
sampling or a VM performance measurement. SourceDeclaration18 remains unissued:
the genuine ACK, SDK preflight, complete initial funding/recipe, SourceRoot and
held-Commit conjunction are still being implemented.

### SDK receive custody

The first-pass rows retain real immutable raw/subtree loans rather than treating
an address as content identity. The next-pass rows retain those same completed
owners and selected nodes. A private immutable raw-frame bank takes the actual
received frame before fallible checks and lends checked root-relative selections;
it exposes no mutable recovery or shared-pointer escape. Failure preserves the
original frame, initialized flat children and their current census.

The initial 36 component controls cover the locked Serde adapter behavior, duplicate
keys, numeric representations, structural map and sequence cuts, late errors,
deep intermediate children, foreign owners, slot replacement and exact versus
one-byte-short resource demand. All pass in both actual feature configurations:
Serde JSON 1.0.150 with default/std and default/raw_value/std. Dependency manifests
and the lockfile remain unchanged; arbitrary-precision numbers and alternate map
representations are not enabled. Both complete Provider suites also pass. Tests
use the ordinary Cargo shell, default stack, assertions, overflow checks and
four test threads. All fifteen existing ignored tests remain ignored.

The subsequent owning-first component retains a checked immutable selection
beside source-free state. Both the existing borrowed adapter and new movable
owner call the same normalization loop; source review verifies its token-preserving
relocation. Failed states need no success-only allocation. Seven additional
controls cover borrowed/owning parity, by-value moves, late deep-child failure,
reuse, exactly one normalization pass and exact/short demand before effects.
All 43 targeted controls pass with ordinary Serde JSON. Each complete Provider
suite then passes 1,539 tests with zero failures and fifteen existing ignores:
11.14 seconds for ordinary Serde JSON and 11.56 seconds with raw values enabled.
All thirteen selected files pass formatting. The component quotes actual demand;
it does not execute or replace the parent scheduler's separate admission.

The owning-next successor moves the actual completed first owner into a private
immutable bank after a separately quoted allocation. Checked root-relative
selections retain that bank beside source-free second-pass state. Both borrowed
and owning adapters call the same second-pass engine; completed text is not fed
back through an extra pass. Failures retain the original input and partial flat
children. The actual prewalk precedes logical-spine allocation, and the complete
row precedes execution. Twelve additional controls exercise real framed input,
transfer/freeze, child selections after parent drop, foreign owners, reuse,
exact/short rows and deep late failures. All 55 targeted controls pass with
ordinary Serde JSON, and both full suites pass 1,551 tests with fifteen existing
ignores. All fourteen selected files pass formatting. Requested storage remains
a source-level accounting claim rather than measured physical stack usage.

The owning-Envelope successor shares the existing field visitor with the
borrowed adapter. It owns typed header partials, member keys and each actual
flat first-pass result beside the original immutable frame. Body and Extensions
remain structural maps, without an extra root normalization. Canonical body
checking has a separate quote and admission stage; failure retains all completed
fields and the original input. A deep Extensions value does not acquire an
unrelated whole-Envelope canonical restriction.

Nine new controls compare actual framed map/sequence input with the locked
Serde decoder and cover field order, nullable IDs, structural Raw keys, deep
body/Extensions behavior, exact/one-short demand, foreign selections and reused
outputs. All 64 targeted receive controls pass. Both unfiltered Provider suites
pass 1,560 tests with zero failures and fifteen existing ignores, in 11.34 seconds
for ordinary Serde JSON and 11.45 seconds with raw values enabled. The first
compile found two test assertions requiring an unavailable enum Debug trait;
equivalent variant assertions fix only those tests. The corrected targeted build
passes in 1 minute 14 seconds; raw-value test compilation passes in 1 minute
12 seconds. All ten selected files pass formatting, and six-crate
all-feature/all-target checking passes in 1 minute 41 seconds. Live header/correlation,
response-cursor integration, typed materialization and Source permissions remain
separate work.

The response-cursor successor shares one source-free schema schedule between
borrowed and owning adapters. It consumes the actual canonical-completed
Envelope, retains pending first-pass transfers, and separately quotes the
immutable first bank, checked selection and second-pass work. Completed and
failed prefixes stay under the same owner; every changed return observes the
current parent and actual error. The existing normalization engines remain
unchanged. It adds no whole-result normalization or live correlation authority.

Ten additional real-frame controls cover schema/key/output parity, late error
prefixes, canonical ordering, deep second-pass failure, all eleven exact/short
action rows, foreign banks, reused outputs and structural Raw/Extensions rules.
All 74 targeted controls pass after a 1 minute 15 second compile. Both complete
Provider suites pass 1,570 tests with zero failures and fifteen existing ignores:
11.91 seconds for ordinary Serde JSON and 11.69 seconds with raw values enabled.
The raw-value compile takes 1 minute 12 seconds. All thirteen files pass
formatting. The real live parent still requires header/session/original-request
matching before canonical work. Shape validation, typed result/receipt
construction and live history integration remain separate prerequisites.

These results qualify the selected components, not a live receive transition.
AssignedPhase/history integration, full structural
Envelope/ResponseShape validation and actual Initial/Recipe producers remain
separate prerequisites. No Source18, native import, Capture or preservation
route is opened by this change. The prior native startup and application-target
results above predate these SDK source changes.

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

The latest recorded refresh passes for `4fbaa7eb15`, including all 37 SDK receive
files selected then. It predates the owning-Envelope successor. All 167 test
artifacts freshly compile across the 48 selected application
packages, including 69 integration targets, in 14 minutes 1 second after
prerequisite builds. Independent review matches all 7,840 captured source files
and file modes to the commit, checks the normalized modes of 1,323 directories,
and verifies the registered output, successful compiler completion and installed
compiler records. The artifacts
comprise 45 library targets, 53 binary targets and 69 integration targets. Each
uses opt-level s, no debug information, and enabled assertions and overflow
checks. Provider is a non-test dependency with no features selected;
Serde JSON 1.0.150 has alloc/default/raw_value/std through dependency unification.
This differs from the separate ordinary-Serde component control run.

All three Core debug paths are captured, including the integration-test source;
the gate compiles no Core or Provider test target. Core is a non-test dependency
with default and test-support features, without test-double. Session and Daemon
are excluded from this source and compiler slice. The installed output retains
compiler metadata rather than test executables. This gate executes no tests and
gives no native runtime, preservation or Linux-performance verdict.

The earlier refresh passes for `751d8331cf`. All 167 test artifacts freshly
compile across the 48 selected application packages, including 69 integration
targets, in 10 minutes 3 seconds after prerequisite builds. Independent review
matches all 7,805 captured source files and modes to the commit and verifies
the installed compiler records and registered output. The artifacts comprise
45 library targets, 53 binary targets and 69 integration targets. Each uses
opt-level s, no debug information, and enabled assertions and overflow checks.
The installed output retains compiler metadata rather than the test executables.

All nine Core paths from the runtime correction are included through the
non-test Core dependency, compiled with default and test-support features; its
test-double feature is absent. The four Daemon paths are excluded. This gate
compiles no Core library test target and executes no tests. It gives no codec,
Daemon census, native runtime, preservation or Linux-performance verdict.

The prior codec/census refresh for `b11ba2f059` independently passes with 167
rebuilt test artifacts and 7,804 matching captured files. Its source scope
predates the subsequent runtime accounting correction.

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

At `eac4c1f76c`, the matching provider rebuild passes in 1 minute
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


### Settled Capture construction and retained owner census

The restored Capture preparation now retains its real pending identity, current
coordinator boundary, independent Source construction rows and counting banks
before allocation. Its census includes failed partials, spare capacity and
future commitments. The once phases remain spent on refusal or unwind; successful
encoding does not renew credit. Actual Runtime and scheduler snapshots, their
DOMs and canonical objects have independent constructor funding, separate from
the six later ticket-validation windows. The archive join compares complete
references and bytes before any owner submits.

Current17 history observation now follows the actual native, SDK, startup,
lifecycle, alias and committed-prefix owners. Pointer tokens compare ownership
only and never enter serialized state. Historical native authentication and
normalization have separate constructor and overlap terms. Recursively inline
optional graph caches are replaced by independently admitted lazy zero-or-one
slots; initialized children and failed reservations remain counted. The
previously overflowing sealed-history control passes on the default test stack.

The normal unfiltered library run passes 1,868 Core tests, 1,310 Provider tests
and all twelve Contract tests. Existing and opt-in ignored populations are
33, fifteen and one respectively; no control is newly skipped to pass this
checkpoint. The expanded Daemon run passes 1,464 tests and fails ten, with 162
existing ignored tests: nine failures identify missing packaged reference-device
or gem5-profile test inputs, and one identifies the shared-owner fixture's absent
source-consumed input commitment implementation. Their corrected qualification
is pending; the failures are retained as evidence.

These constructors and DATA loans do not enable a live Capture effect, establish
a native successful boot or qualify fresh continuation. The complete native
prospective request/failure budget, genuine Node and Host dispatch, per-owner
full reobservation and signed archive publication remain required. Full compiler
and production application-target qualification are tracked independently.

The final all-feature/all-target check passes across Core, Daemon, Provider, API,
Session and QEMU in 2 minutes 16 seconds. This is compiler qualification; the
production application-target gate must be refreshed for this checkpoint.

A following test-only shared-owner fixture repair implements the missing actual
source-consumed commitment callbacks. It retains the same armed activation,
staged bytes, commitment tuple and opaque World authority. All four shared-owner
controls pass; the original starvation control also verifies that administrative
commitment does not deliver semantic input before causal polling. Production
refusal defaults are unchanged. The nine packaged-input failures still require
a correctly configured full Daemon rerun.


### Production application compilation for the construction checkpoint

At `f89845137e`, the refreshed production application-target gate passes. It
freshly compiles 167 test artifacts across 48 application packages, including
69 integration targets. Debug assertions and overflow checks remain enabled.
The final test-target derivation takes 12 minutes 29 seconds after its production
prerequisites. This gate compiles tests without executing them.

All 7,612 captured source files match this checkpoint byte-for-byte. Its selected
application dependency source contains 330 changed crate roles since `9a96e120d6`.
The fifteen changed Daemon roles are outside this application gate; the separate
six-crate all-target check and four shared-owner controls cover them. Neither
this source snapshot nor these results cover later native Capture/observer
integration changes, which require separate qualification.

Provider build statements refer to the ordinary development profile unless an
optimized measurement explicitly identifies a different executable and profile.
Component timings retain their original pinned inputs; a later provider rebuild
is not a new performance measurement.


### Scoped Capture dispatcher and current owner construction

The current17 construction path now lends the actual Window scope through its
separate owner-ticket family. It retains the genuine prepared Host producer and
current Runtime, scheduler and coordinator objects. Native and Source loans join
the same Boot, original launch, raw first envelope and Source owner. After each
owner callback returns, private claims and result-slot loans are released before
full observation admits the next owner; refusal retains partial outputs and
spent occurrences.

Controller and SDK growth quotes follow actual retained records and serialized
fields. Native Capture request hashing uses the complete original identity;
prospective geometry does not substitute for a future result hash. Strict
Snapshot17 output follows the exact nested reference field order required by its
reader. The new observer view borrows the real split Runtime owners instead of
constructing a stand-in whole Runtime.

The ordinary unfiltered library run passes 1,895 Core tests, 1,367 Provider tests
and twelve Contract tests, with existing ignored populations of 33, fifteen and
one. With the source-built gem5 profile and matching reference-device/provider
inputs, the full Daemon rerun passes 1,479 tests, with 162 existing ignored
tests, in 332.03 seconds. No tests are filtered or newly ignored.

These are constructor, custody, dispatch and DATA-reader controls. The complete
native Capture issuer, signed publication and fresh continuation remain closed
until their actual owner and historical-reader conjunction is implemented and
qualified. The production application-target result at `f89845137e` applies to
its earlier immutable source snapshot and must be refreshed for this source.

The configured rerun exposed a source-manifest reader that predated the current
gem5 producer. Its strict typed extension reader now validates and measures the
retained platform, terminal and native-origin source bindings. Genuine older v1
producers remain supported; explicit nulls, unknown nested fields, incomplete
pairs and qualification promotions are refused. All five new metadata controls
and the actual installed-profile epoch control pass. These source bindings do
not widen the fixed profile’s execution or device qualification.


### Retained dependencies and terminal verifier admission

Current17 Source materialization retains its actual signed parent Index3 body
and exact dependency rows, including a separate twelfth Core output copy.
Imported closure geometry comes from the genuine retained original ticket and
completed Source copies. The Window checks Source/request provenance before
using the stored eight-field geometry loan; a refused row remains retained.

Host format selection now precedes World construction and requires the actual
three Sources' immutable declarations. The separate terminal verifier ledger
retains independently admitted prewalk, bank and constructor commitments in
actual dependency order. Prior live pure-parser caches are fully funded as
transient overlap; failure preserves numeric debits, capacities, genuine owner
outputs and once state. Numeric phase completion cannot replace signed-reader
validation or authorize publication.

The ordinary unfiltered library runs pass 1,908 Core, 1,482 Daemon, 1,367 Provider
and twelve Contract tests. Existing ignored populations remain 33, 162, fifteen
and one. The full Daemon run takes 342.68 seconds. All-feature/all-target checking
passes across the six integration crates in 1 minute 33 seconds. Matching
reference-provider and reference-device development binaries rebuild in
17.15 seconds. The full-original identity control checks all thirteen Envelope
fields and changes that preserve the normative request hash while changing raw
original Values.

The actual staged terminal reader, native Capture issuer, final historical
conjunction and fresh adopter remain required. This ledger does not enable
them. The production application-target build currently running is pinned to
the earlier `268284137c` source; it does not cover this subsequent batch.


### Production compilation for scoped Capture construction

The production application-target gate passes for `268284137c`. All 7,664
captured source files matched that commit before subsequent archive work began.
The selected source includes 152 of the construction checkpoint's 159 changed
crate roles; its seven Daemon roles are outside this application dependency
closure and receive separate all-target/library qualification.

The final derivation freshly compiles 167 test artifacts across 48 packages:
69 integration targets, 53 binaries, 42 libraries and three combined cdylib/rlib
targets. Debug assertions and overflow checks remain enabled. Final compilation
takes 12 minutes 10 seconds after the production prerequisites. This gate
compiles tests without executing them and excludes the subsequent archive
checkpoint at `019e07ac58`.


### Per-operation closure and Native construction phases

Each quantized operation retains its own deadline from one shared monotonic
anchor before native submission. Close requests preserve accepted, refused,
uncertain and failed state; an unwind cannot retry the original request.
Partial starts retain accepted tokens and unused grants. A close acceptance
does not settle the round, publish outputs or advance simulated time.

The cold Native reader exposes ten defining construction steps, with separate
prewalk and constructor admission and complete prior-cache overlap. Terminal
sequencing refuses missing, repeated or unkeyed Native work. Launch validation
and Hold serialization have independent geometry helpers. Capture argument
observation exhaustively covers every field and actual spare container capacity.

The separate upload graph retains the original request, actual Blob receiver and
transaction, native ancestry, response and terminal before publication. Its full
phase demand precedes the one-use debit and effect. The current internal issuer
admits Begin only. Chunk/Finish, the Source full-phase signer, final Capture
registration and fresh adoption remain closed pending their actual integration.
These DATA and custody changes do not establish successful native Capture.

The normal unfiltered four-library run passes 1,910 Core, 1,488 Daemon, 1,410
Provider and twelve Contract tests. Existing ignored populations remain 33,
162, fifteen and one. Daemon completes in 333.98 seconds; all ten shared-owner
and deadline controls pass. Debug assertions and overflow checks remain enabled,
with the default test stack. Six-crate all-feature/all-target checking passes in
1 minute 54 seconds, and matching reference binaries rebuild in 1 minute
2 seconds. Production application-target qualification must be refreshed for
this source.

Earlier failed runs exposed two model errors: the parked quantum cursor used
Publication instead of BoundaryControl, and a synthetic early completion
bypassed Runtime's mandatory original close. Corrected controls use the genuine
close, poll and cached-completion path; production validation remains intact.
Failed logs remain local. Temporary startup probes are removed and excluded
from this qualification; startup and native preservation remain unqualified.


### Production compilation for Native construction and closure

The production application-target gate passes for `511bffa914`. Independent
installed-artifact verification matches all 7,689 captured source files to that
commit. Its dependency source includes 63 of the checkpoint's 69 changed crate
roles; the six Daemon roles remain outside this application's dependency closure
and receive separate all-target and library checks.

All 167 test targets freshly compile across 48 application packages, including
69 integration targets, with optimized test compilation, debug assertions and
overflow checks. The final test-target compilation takes 10 minutes 39 seconds
after its production prerequisites. This is compilation-only evidence for that
commit; it excludes subsequent cold restoration, upload continuation and startup
census changes and does not establish native preservation.

The separately registered ABI dependency gate fails during the Provider's strict
Clippy package check, after ordinary release compilation succeeds. The retained
diagnostics include unconsumed selected17 paths, unused imports, visibility
mismatches and structural lints. No ABI or production-flight success follows from
that run. The normal gate and its source coverage remain unchanged while actual
consumers and source defects are addressed; complete native qualification remains
required.


### Cold restoration, upload continuation and initial Source observation

The initial preparation census now uses each member's exact original Source
through the closed initial owner walk. It includes both Reactive peers when the
third member starts, while ordinary Input/Capture observers retain their strict
static-graph requirements. Exact/one-byte-short and foreign-allocation controls
pass. The correction is committed in `acae9a0382`.

The cold reader completes three actual Native construction sequences, signed
parent occurrences, the original Initial15 group and each retained Source
decoder before the terminal conjunction. The enclosing current17 writer retains
actual outputs and failure custody through Index construction and persistence.
This implements the Initial15 predecessor path; recursive current17 ancestry and
genuine fresh adoption remain required.

Upload continuation joins the actual published Begin, contiguous Chunk history,
immediate predecessor, Source proof and current Blob receiver before its own
quote, debit and effect. A defining future producer now prices the complete
primitive/reply/terminal/transport/record phase, and the genuine Source signer
uses that distinct row instead of ingress credit. The generic receiver's 64 KiB
object limit remains unchanged. Final Capture, registration/confirmation and the
public current17 route remain closed pending their complete producers and owners.
This checkpoint is committed in `1cb233a8aa`; `6b477d60ad` contains separately
reviewed import, visibility and layout-expression lint repairs.

The unfiltered four-library run passes 1,928 Core, 1,488 Daemon, 1,428 Provider
and twelve Contract tests. Existing ignored populations remain 33, 162, fifteen
and one. Compilation takes 5 minutes 11 seconds; Core completes in 7.85 seconds,
Daemon in 332.07 seconds and Provider in 11.45 seconds. Six-crate all-feature and
all-target checking passes in 1 minute 13 seconds. Matching development reference
binaries rebuild in 1 minute 2 seconds, with debug assertions and overflow checks
enabled. No deadline, stack or production limit is increased.

The subsequent native control completes the three initial preparations and
enters inactive-runtime graph construction, then still refuses before returning
an inactive runtime. Its normal failure path reclaims the original children.
An attached host stack sample observes full-file hashing through graph-admission
currentness checks while the Providers wait. This is diagnostic evidence, not a
successful startup, preservation result or performance comparison. Temporary
phase diagnostics are excluded from commits and qualification.

The refreshed production application-target gate passes for `6b477d60ad`, with
remote builders disabled. All 7,730 captured files match that commit. Its source
includes 126 of this checkpoint's 129 changed crate roles; three Daemon roles
are outside that application dependency closure. The installed compiler record
contains 167 newly compiled optimized test artifacts across 48 application
packages, including 69 integration targets. Debug assertions and overflow
checks remain enabled. Final test-target compilation takes 10 minutes
29 seconds after prerequisites. This gate compiles tests without running them
and does not qualify subsequent changes or native preservation.

### Retained restoration construction and initial supervisor handoff

The next restoration checkpoint retains the actual current17 Source, Host,
manifest and prepared-scene owners before construction and before issuing each
native ticket. Cold member slots now use independently funded, initially empty
single-member banks. Failed reservations and partially decoded members remain
owned and counted. Parent archive headers remain DATA checks; recursive native,
Source and coordinator provenance are separate unfinished obligations. The
functional checkpoint is `8cd5d22107`.

Initial SDK attachment now retains its actual protocol supervisor in native
custody before later Source callbacks. Node handoff authenticates that same
witness, registry and operational handle. This correction is `284c005`; the
existing native control gains test-only retained-failure reporting in
`f0f5304c7b`. Formatting is separate in `d115fc9e5f`.

The combined functional source passes six-crate all-feature/all-target checking
in 44.84 seconds. The unfiltered ordinary library run passes 1,938 Core, 1,492
Daemon, 1,431 Provider and twelve Contract tests, with the existing ignored
populations unchanged. Core takes 7.68 seconds, Daemon 342.88 seconds and Provider
11.71 seconds. Debug assertions, overflow checks and the default test stack remain
enabled. The extended prepared-scene regression separately passes in 258.66
seconds. Its machine-code entry frame decreases from approximately 2.27 MiB to
625 KiB after the member-bank correction; this measures the test fixture's stack
frame, not VM performance.

The existing source-built native control still fails after 696.98 seconds. It
now retains a constructed graph, all three actual nodes and the Host, without
node, provider, preparation or attachment failure. It refuses before the inactive
runtime phase begins, and its normal retirement path reclaims the children.
Source review locates a stale initial-lifecycle census after preparation owners
have moved into those nodes. A correction must authenticate and count the actual
destination owners before this control can pass. No native preservation result
or overall performance improvement follows from these library results.

The refreshed production application-target gate passes for the committed,
formatted `2788ced205` checkpoint. Independent registered-artifact verification
matches all 7,744 captured files to that commit. The source includes 48 of the
69 changed crate roles; all 21 excluded roles belong to the Daemon, which has
separate all-target and library coverage. The installed compiler record contains
167 freshly compiled optimized test artifacts across 48 application packages,
including 69 integration targets, with assertions and overflow checks enabled.
Final test-target compilation takes 11 minutes 34 seconds after prerequisites.
The gate compiles tests without running them. The installed output contains
compiler metadata, and its identical normalized hash across checkpoints does
not establish source identity. The registered derivation and full captured-source
comparison establish which committed input was compiled. This gate excludes
subsequent changes.

The subsequent Control projection component (`7ff72b5e15`) retains both actual
decoded DOM owners and a separate provenance wrapper for the exact body and full
content reference. A spent ColdGroup attempt retains its raw bytes, reference,
decoded owner and failures. This later Window cut cannot fund earlier native
birth or modify a sealed startup carrier. Early Source/ticket construction is
a separate remaining implementation.

This component passes six-crate all-feature/all-target checking in 1 minute
28 seconds, plus 1,940 Core and 1,433 Provider library tests in 8.04 and 11.49
seconds after 4 minutes 24 seconds of ordinary optimized test compilation.
Existing ignored tests remain unchanged. New controls exercise actual fullref
and body provenance, complete retained backing, exact/one-byte-short ceilings,
foreign creators and failed partial ownership. These results establish neither
successful native restoration nor a refreshed production application gate.

The moved-preparation correction (`971a054f24`) authenticates actual destination
owners against the original ticket, Source and plan. Six-crate checking and all
four unfiltered libraries pass: 1,940 Core, 1,492 Daemon, 1,433 Provider and twelve
Contract tests, with existing ignored populations unchanged. The native startup
control still refuses after graph/node construction; retirement and reclamation
pass. Source review identifies a separate Oracle observer that requires an empty
journal after mandatory validation has populated it. Its repair must fund the
prospective copies and count their actual retained backing. Test diagnostics in
`b339f8c333` now run before automatic retirement revokes witnesses; six-crate
checking and ordinary test compilation pass. These results do not qualify native
startup or full preservation.

The production application-target gate passes for `b339f8c333`: 167 newly
compiled test artifacts across 48 application packages, including 69 integration
targets, with assertions and overflow checks enabled. Final compilation takes
12 minutes 23 seconds after prerequisites. Independent registered-artifact
verification compares all 7,753 captured files directly with the committed
source. This compiles tests without running them and excludes later changes.

The subsequent prebirth collection and borrowed serializer helpers
(`f085042b94`) pass six-crate all-feature/all-target checking and all four
unfiltered libraries: 1,941 Core, 1,492 Daemon, 1,433 Provider and twelve Contract
tests (4,878 total). Existing ignored populations remain unchanged. Initial15
native geometry (`7832632fac`) separately passes six-crate checking and 1,437
Provider library tests; its real borrowed validator prices retained alias-bank
construction before allocation. These components do not establish successful
early adoption or native startup.

Embedded JSON RawValue reparsing has an independent quote for the enabled
parser, source copies, expanded DOM and error owners (`6ee0c61c2b`). Six-crate
all-feature/all-target checking and all 1,450 Provider library tests pass,
including thirteen new controls. Callers still owe their actual expanded typed
and canonical construction rows. The helper supplies no permission or new
decoder limit. These later components await a refreshed production gate.
