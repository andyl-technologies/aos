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

Current status: QEMU-SIM implementation qualification and final performance
parity are in progress. All gem5/KVM live evidence above is unavailable; these
are specified future profiles and remain disabled.
