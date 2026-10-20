# Profile qualification and evidence allocation

This is an informative allocation of the normative requirements in chapters
10, 11, and [14](../../rfcs/0021-crucible-paged-ram/14-implementation-profiles.md).
The [requirement inventory](requirement-map.tsv) enumerates every normative ID.
Its case references allocate design obligations; concrete source, executable,
positive/negative outcomes, and capability certification must be bound at release.
Cases are required evidence designs, not existing passing tests. Owners name
responsibilities, not a claim that proposed provider APIs already exist.

## Shared and implementation-specific evidence

Every profile runs the independent full-backing oracle, canonical format and
topology negatives, integrity failures, stale completion rejection, lease
retention, bounded resource refusal, and private mutation isolation. Execute
these through the actual admitted writer/pager/storage path. Shared helper
tests alone cannot qualify that deployment. An oracle must not reuse dirty
bits, cached roots, changed-page lists, or the production tree builder.

| Requirement | Owner | Positive evidence | Causal negative evidence | Capability blocked without evidence |
| --- | --- | --- | --- | --- |
| PROFILE-1 | Admission and actual execution/capture provider | Bind exact implementation/build, semantic configuration, owner graph, mode, mappings, fault origins, capture fidelity, and requested capability set before launch | Select an unknown build/mode or unsupported mapping, clock, capture, branch, or removal combination; verify refusal before execution and no fallback | Each requested profile/capability combination |
| PROFILE-2 | Complete-state inventory and capture owners | Inventory all future-affecting gem5 domains; capture dirty cache data/permissions, coherence transients, pending transactions, controllers, pipelines, predictors, translations, devices, PRNG and event state when realized | Remove a realized domain or double-own it; independently detect stale architectural observation or divergent complete continuation despite equal backing root | Complete gem5 capture and deterministic continuation |
| PROFILE-3 | Boundary and serialization owners | Preserve a reached gem5 continuation with outstanding transactions and dirty caches; reproduce identical complete state and future trace without modeled work during capture | Introduce a drain, flush, event step, instruction retirement, or warm-up; witness the prohibited modeled effect or reject the capture | Exact detailed capture/restore |
| PROFILE-4 | Coherent inspection and fault/assertion owners | Compare backing versus cache-owned values under the declared projection; inspect without changing caches, queues, ordering, or service counters | Use stale backing for an architectural predicate or make inspection alter replacement/coherence state; verify detection/refusal | Fault preconditions and assertions using that projection |
| PROFILE-5 | KVM clocks, devices, and window coordinator | Delay a real kernel-originated page fault; attest held affected owners/clocks/timer injection, preserved due timers/input batch, acknowledged stopping, and closed-window output custody | Enable an unholdable clock/device or publish before acknowledged closure; verify preflight refusal or retained containment | Paged KVM quantized execution |
| PROFILE-6 | KVM execution budget and host supervision | Preserve the original budget basis; exclude only attested held intervals for active budgets while elapsed-wall/operational deadlines expire; record actual work separately | Renew a grant/budget on population, lose service, corrupt backing, or fail stopping; verify no guest finding/window receipt and retained cleanup ownership | KVM paging under the selected budget contract |
| PROFILE-7 | Checkpoint compatibility and branch reconstruction | Same-profile/build-compatible exposed-state and coordinator window/grant/timer/input-output/budget/closure-prefix reconstruction into fresh execution objects with independent mutable RAM and leases | Equal RAM roots but incompatible implementation/configuration/schema/mode; inherit KVM descriptors without reconstruction or retain source mutable references; verify refusal/isolation failure | Each claimed restore/branch combination |
| PROFILE-8 | Scenario provenance and replay admission | Record nondeterministic node provenance through capture/restore and the coupled scenario; stronger guarantees require separately qualified replay | Remove provenance or claim deterministic replay from equal RAM roots/clock freezing; verify rejection | Stateful scenario fidelity and any stronger replay claim |

PROFILE-2 through PROFILE-4 are exercised against each actual detailed gem5
model, not merely the provider family. PROFILE-5 and PROFILE-6 require actual
kernel fault/clock/window evidence; mock doorbells or sysctl selection alone do
not qualify them. All eight rows also inherit common ownership, integrity,
supervision, containment, and bounded-resource requirements.

## Additional per-profile matrices

| Profile | Writer and epoch matrix | Removal/fault matrix | Capture/branch matrix | Timing and correctness criterion |
| --- | --- | --- | --- | --- |
| QEMU-SIM initial target | TCG fast/slow/atomic stores; DMA/direct/native/debug/fault/reset/restore/discard/reporting; independent dirty consumers | Actual RAMBlock aliases, BQL/RCU/AIO/raw borrowers, kernel faults, mapping modes and deployed userfaultfd features | Existing full CPU/device/RR continuation; native workers, descriptors, registrations, source/child leases and cold reconstruction | Identical complete fingerprints/event traces and exactly-once original modeled access across policies |
| Proposed deterministic gem5 | Cache/coherence and backing writes separately; DMA/devices; functional/debug/loader/reset/restore/fault; pending request identity | Retained packets/pointers/events, actual threads/queues, aliases/kernel accesses, granularity/permissions and independent progress | Every realized future-affecting modeled domain; no drain/flush/warm-up; event/thread reconstruction; cold capture/restore accesses | Identical complete state and event trace under the actual admitted deterministic model |
| Proposed nondeterministic KVM | Hardware dirty logging plus devices/DMA/host; epoch rotation and held-boundary reconciliation | Kernel-originated accesses, secondary translations, retained mappings/pins, stop/hold receipts, real feature/ioctl set; unsupported passthrough refusal | Exposed VM/vCPU/device state into fresh kernel objects; independent mutation and full schema/mode compatibility | Coherent state/integrity, kernel progress, clocks/timers, original budgets/input batch, qualified stop overrun, captured window/grant/custody/closure prefix, quantum containment; no repeated-run equality claim |

## Scope changes and unchanged format

INV-2 and PAGER-1 retain their original strong guarantee within deterministic
QEMU-SIM and qualified deterministic gem5. KVM receives the explicit quantized
contract rather than a silent exception. POLICY-1 excludes operational policy
from semantic identity and authored modeled events; only deterministic profiles
claim trajectory independence. LIFE-15, CHECK continuation, TEST-11, and TEST-12
use the declared capture fidelity and operating-mode relation. TEST-1 and TEST-2
allocate correctness arguments and live tests to the actual profile. TRANSFER-2
retains destination timing under the same declared mode; it does not authorize
cross-profile continuation. CONF-1,
FP-1/FP-11, and PAGER-2/PAGER-4 explicitly name profile coordinates/evidence/owners.
Chapters 14 and 10 record the allocation without renumbering existing IDs.

No page preimage, digest domain, logical edition, topology/alias rule, bounded
resource cap, original deadline, or QEMU performance baseline changes. Equal
declared backing/topology retains equal RAM roots. Complete checkpoint identity
and restore authority still include the enclosing execution/capture contract.

## Execution, release, and reporting

Keep the initial paused-only full-peak reservation plus independent progress
resources. A profile cannot use an advisory resident target as proof of a
lower guaranteed peak. Concurrent removal and new fault-safe suspension
boundaries have independent lifetime, wait-for, and performance gates.

Run all qualification locally with remote builders disabled. Freeze exact
source/build/configuration and retained executable evidence before execution;
record fixture conditions, actual adversary activation, original resource
limits/deadlines, every attempt, outcome, and cleanup. Missing/failed cases
remain explicit blocked capability cells. Historical checks do not qualify a
later source revision or another profile.

CPU and elapsed-time comparisons retain separate zero-regression gates and
fixed, declared sample plans for each workload family. Do not pool profiles,
trade a faster family for a slower one, raise caps, or disguise failed attempts
as completed throughput. gem5/KVM profiles require their own comparable
operating-mode baseline; they cannot replace the current QEMU regression gate.

Native integration `7754cef75d9333b943b731c4634226d025e1cce6`
passes signed source reconstruction and all 3,863 C compile/link actions. All six
selected native unit binaries pass, including seven bounded-thread and two
CPU-instance subtests. The standalone fixture run remains failing: 18 of 26
fixtures pass, seven have incomplete emitted callback dependency closure, and
the mandatory launched capture lifecycle still fails. These results do not
qualify prepared Source providers, actual CPU pin return, RAM rearm or VM activation.
Callback dependency repairs must use actual production functions and genuine
providers; an ordinary monitor reference-count model cannot stand in for CPU
custody. Preserve the lifecycle failure until the launched path is implemented
and tested.

The cleanup successor `64e15551afefa730e3919aa4c63dd3d1139637e4` passes syntax
checks for all four changed production C units and compiles and links its actual
generated fixture. Ten new cleanup controls and the replacement capacity control
pass. Four independently rebuilt mutations each fail at their exact intended
semantic assertion while their named baselines pass. Across all 182 Source
scenarios, 166 pass and 16 fail; each failure reproduces the identical assertion
and signal in the predecessor binary. The complete native build result above
covers the same production cleanup source; the successor changes one test file.

The existing required-role fixture still refuses.
That fixture lacks real RUN/teardown rows and a matched worker module; its
remaining budget cannot fund the required workers. Appending role labels or
raising fixture limits would not qualify the production constructor. All four
native metadata retirement paths now use canonical ownership and checked
continuations, preserving consumed projections, physical return and settlement
debt independently. The new controls use disclosed modeled retained inputs;
genuine Source activation, positive RCU grace and launched cleanup remain required.

Normal Cargo compiles all 520 current workspace test targets. All workspace
doctests complete: 41 pass and 26 existing cases are ignored. The 510 non-daemon targets
complete with 12,085 passes, 88 failures and 75 ignored tests. Twenty-six
tool/configuration failures and ten watcher failures pass targeted reruns with
the actual native tools, isolated Git fixtures and controlled test concurrency;
no assertion or deadline changes are needed. Remaining fixture, integration,
source-policy and behavioral failures are unresolved.

The separate normal Cargo daemon run covers all targets/features: 1,890 tests
pass with 47 existing ignored tests, and six doctests pass. Engineering hygiene
and all 27 boundary checks pass. Source-policy controls have 64 passes and one
failing broad integration gate for the same 15 unclassified paths. These local
results cover the metadata-admission and resume-error retention changes; they
do not establish native activation, reduced residency or performance parity.

The worker cutover passes all 43 host-resource, QEMU-host and plugin test targets:
2,716 passes with five existing ignored tests. The three new native-join controls
include a real held TLS destructor. Campaign tests have 448 passes after stale
schema-owner assertions are corrected to the existing registry. All twelve
owned-process diagnostic controls pass in the standalone and composed CLI targets.
The new source controls require exact bounded waits and reject substituted workers,
missing physical receipts, changed deadlines, fabricated wait status and unrelated
retries; they preserve the same fifteen unresolved daemon findings.

Native source `7754cef75d9333b943b731c4634226d025e1cce6` changes only the settlement
fixture. Its configured runner passes all 112 publication cases, sixteen intentional
waits and the control boundary. All fifty component externals are `main` or private
component symbols; real QOM/event/thread/lock/notifier providers remain separate.
The exact guard-deletion binary aborts at `publication_matrix`, observing one blocked
park against the required zero. Optimized unselected Source code removes the CPU
unref edge; a separate unoptimized object audit retains the genuine `object_unref`
relocation. Neither result qualifies selected CPU-pin return. The complete native
build and owning runner produce the eighteen passing fixtures recorded above.

The whole-node RAM cutover compiles all 520 workspace targets and passes all
workspace doctests (41 passes, 26 ignored cases). Its latest complete affected
host/daemon/test-support run has 3,611 passes, eleven failures and 51 ignored tests
across 68 targets. The daemon library passes all 1,881 active tests, including
physical quota collection; the host library has 1,210 passes and eight helper
failures. All 22 new cleanup controls, both registry controls and all eight
whole-set teardown controls pass in that run. Earlier totals above are historical.

Three source-policy failures in that run include two stale whole-set shutdown
companions. Their subsequent repair passes all 66 specific controls, including
23 additional causal mutations, while the broad gate still reports fourteen
daemon and seven host paths. The prior fifteen-path count described the daemon
subset. The obsolete baseline for the relocated RAM wait was removed without a
replacement waiver; the actual wait still needs its owning contract. All 65
ABI/license/unsafe controls, five hygiene controls, 36 harness controls and both
Rust documentation controls pass against the current cleanup implementation.
Source review records retain their original shape limits. The actual node-field
destructor-panic control proves an empty reentry cannot manufacture physical
return or release generation leases after uncertain destruction.

Native source `8024030523d0e7ee6512e8fecbbcd342c779e26a` again completes signed
reconstruction, 3,863 compile/link actions and six selected suites. Standalone
fixtures remain 18 passing and eight failing. Deferred-control extraction now
compiles but has unresolved genuine `object_unref` linkage; six other callback
closures and launched capture lifecycle remain failing. The next signed source,
`bc75333383c5d64014b2d91044e370b45aaf2d95`, only retains the actual component
object before its existing final link. Its complete normal native check repeats
the same build, selected-suite and 18/8 fixture results. The actual object has
125 defined global symbols and 28 provider references. Its genuine QOM closure
required component symbol isolation. Signed source
`a6bd0cc8571ad77bc4a08a7d684b84536a879878` applies that isolation and completes the
normal 3,863-action build with six passing suites and 19 passing fixtures; seven
fixtures remain failing. The owning runner uses actual configured QOM objects and
link dependencies, verifies all 125 component definitions and 28 provider references,
and passes both deferred-control mutations at their exact native assertions. All
60 ABI/license controls also pass against that integration. No generated support
body was inspected to infer provider semantics or activation. These component
results do not qualify Source activation, physical CPU-pin return or performance.

Signed source `c1c525a232b485acf878439c1d3049d6224086b3` passes the same complete
build and six selected suites. Its two shared-body callers now forward the actual
validated source mapping. Template control drain passes, giving twenty passing
fixtures and six failing fixtures. Stopped control rearm reaches a real QOM
`object_unref` declaration dependency instead of the former Python argument error.
The remaining RAM-worker helper closure still requires genuine bounded-thread
storage, incoming source-pin closure and provider/runtime qualification.

Current status: QEMU-SIM implementation qualification and final performance
parity are in progress. All gem5/KVM live evidence above is unavailable; these
are specified future profiles and remain disabled.

The configured Main/Source and native Root producer bodies are present in source,
but the plugin installer still refuses callback activation. Group registration
leaves members inactive, native registry binding returns unavailable, and current
command-receive custody proves neither a publisher/action parent nor peer return.
Activation/ingress support editions must remain zero until real issuance and
teardown are implemented. The existing normal-service native-flight adapter is
the appropriate later positive consumer; its current presence does not bypass
this production refusal. Source-unit runtime geometry must also match the genuine
plugin module, allocator, stack and task claims. Supplying two missing rows or
changing a roster-only expected total cannot establish that qualification.
