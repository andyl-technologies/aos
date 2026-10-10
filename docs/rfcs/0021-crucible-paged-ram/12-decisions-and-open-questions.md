# 12 - Decisions, alternatives, and open questions

## 12.1 Decisions made by this RFC

| Decision | Reason and consequence |
| --- | --- |
| Keep guest machines unmodified | RAM placement remains a host implementation detail; no ballooning, guest swap interface, or guest agent dependency |
| Preserve timing under the declared operating mode | Deterministic QEMU-SIM and qualified gem5 retain modeled access latency and event order; nondeterministic KVM follows the explicit clock, budget, and quantum contract in chapter 14.5 |
| Fix logical pages at 4 KiB | Digests and checkpoint coordinates stay portable across host/target page geometry |
| Use unkeyed BLAKE3 with 32-byte output for logical pages and Merkle digests | Reuses the existing CAS hash primitive and its C/Rust ecosystem; preserves explicit logical domains and representation-independent identities |
| Keep storage identities distinct | Existing CAS representation authentication, packing, and future encodings are not conflated with decoded RAM identity |
| Use ordered binary trees with defined padding | Position is committed while equal-content pages/subtrees can share across positions |
| Use named scopes and complete topology inventory | Removes current inconsistent implicit coverage while avoiding an accidental omission of mutable device RAM |
| Use complete write tracking with independent epochs | Shared discovery supports multiple consumers without one clearing another's observation |
| Start removal at coherent paused boundaries | Requires physical-borrow safety and sound inter-boundary peak admission; unsupported smaller peaks are refused |
| Gate fault-safe reclamation separately | A blocked fault must be able to reach a safe reclamation mechanism or fail, rather than wait for an unreachable boundary |
| Prefer a precise custom backend after a kernel-swap baseline | Kernel swap remains measurement-only unless independent preserved-byte integrity qualification satisfies the unchanged threat model |
| Keep implementation-private mapping work with its execution owner | QEMU mapping/fault work remains GPL-side across the public process boundary; gem5/KVM mechanisms require their own admitted profile and boundary review |
| Make runtime policy operational and revisioned | Tuning does not change guest identity; reservation and convergence remain auditable |
| Amend outer caps through separate operational transactions | Expiry precedence, original elapsed time, shared supervision, and restart recovery stay explicit |
| Store direct root-based RAM checkpoints | Persistent trees encode shared unchanged state without an eight-layer replay chain |
| Require complete local closure before lazy restore | Fault latency does not silently become a remote availability dependency |
| Transfer missing authenticated state | Tree differences reduce work while ownership, possession, and publication remain independently checked |
| Separate stored closure from restore readiness | Storage-only archive publication needs no execution admission; maintenance ownership handoff does |
| Make the experimental cutover immediate | Avoids legacy readers, digest conversion, dual algorithms, and mixed-peer execution |

These are normative choices through the requirements in their owning chapters.
Open implementation details below must be resolved before their capability is
enabled. They do not authorize substituting a weaker invariant.

## 12.2 `mmap` versus custom file management

This is not an exclusive choice. `mmap` supplies the stable virtual-address
space expected by QEMU's direct RAM accesses. Explicit backing management
supplies policy, preservation, page authentication, versions, and lifetime.
The recommended precise design uses both, with a fault-driven population path.

Ordinary private anonymous mappings with kernel swap are the least invasive
baseline. Kernel policies own reclamation and shared-page accounting; cgroup
limits supply aggregate containment. The host cannot infer precise guest
residency from `memory.max` or direct individual-VM eviction from a global
swappiness value.

File-backed `MAP_PRIVATE` mappings permit reload of clean file contents, but
writes become anonymous COW pages that still need preservation. They do not
automatically make all dirty RAM disk-backed. Writable `MAP_SHARED` would
share child writes and mutate a source unless additional ownership mechanisms
are supplied; that violates the hot-fork model. One mapping per logical page
would multiply VMAs and destabilize mapping/descriptor budgets.

Reflink-backed private files can be useful physical storage, but require
filesystem capabilities, clone/rebinding transactions, and cache accounting.
They do not establish QEMU dirty tracking, source immutability, page-level
authenticity, or complete fork barriers. Explicit buffered I/O without stable
mapped RAM would require changing every CPU/device access to use an accessor,
with substantial TCG and device audit cost. It is not the proposed fast path.

Kernel-managed swap remains a labeled measurement baseline unless independently
qualified under PAGER-22. Accurate approximate-residency reporting alone does
not satisfy authenticated preserved-byte integrity. It is not a silent fallback
for a requested precise budget or strict residency mode, and this edition does
not add an ordinary-swap deployment profile with a weaker storage threat model.

## 12.3 Why Merkle state is foundational rather than incidental

The hash primitive is fixed to unkeyed BLAKE3 with a 32-byte output. Existing
QEMU observers use SHA-256, making SHA-256 a conservative integration option,
but guest determinism and Merkle geometry require no particular SHA family.
The immediate cutover removes a compatibility reason to retain that primitive.
Crucible's CAS already uses BLAKE3, and the official C and Rust implementations
provide a common source and validation foundation for the new logical format.

Performance is a qualification question rather than an assumed speedup.
Measurements must cover 4 KiB page preimages, small branch-node preimages,
partial pages, and batches of dirty pages against a declared accelerated
SHA-256 benchmark. The latter is an offline comparison, not a second production
RAM algorithm. BLAKE3's internal hashing tree does not supply the persistent,
address-positioned RAM tree defined in chapter 02. Logical and storage identities
remain distinct even though their primitives now agree.

The [offline host measurements](measurements/host-hashing/README.md) record the
selected implementations and canonical workloads. SHA-256 was faster on that
measured host; those results do not establish a general ranking or measure the
native C implementation, persistent allocation, or physical residency costs.

Incremental digests avoid paging unchanged RAM in merely to observe it.
They also supply immutable fork baselines, checkpoint roots, and transfer
differences. The benefit depends on complete write discovery and coherent
capture. A hash tree over a stream generated by rereading every page would
not solve the original density problem.

Write tracking is therefore directly relevant to hot forks and state streaming.
Forks already share physical memory by COW, but an immutable logical root
describes what they share across backing tiers and hosts. Dirty epochs identify
the candidate differences; content digests identify actual differences. A
write followed by a revert can reuse old content, while a never-written page
can still be physically nonresident. Neither mechanism alone establishes live
migration consistency, source authority handoff, or pending-I/O ownership.

A digest per store is rejected. The required unit of publication is a coherent
boundary or preserved immutable version. Binary versus wider-fanout trees is
settled in favor of binary logical geometry for edition 1. Physical storage
may group nodes or encode repeated subtrees without changing logical identity.
Changing the logical construction later requires another coordinated edition.

## 12.4 Required unresolved engineering choices

| Question | Constraint | Evidence required before enablement |
| --- | --- | --- |
| Fault-safe suspension or concurrent removal? | Must identify an independently runnable discard primitive, preserve interrupt/RR/timer order, and cover physical borrowers while an access is blocked | Complete wait-for/lifetime proof and real-QEMU adversarial tests; general low-peak paging remains blocked until then |
| Exact GPL companion topology and startup? | Must preserve the public license/process boundary and fault authority across fork/death | ABI/license review, process lifecycle specification, and retained-barrier dependency tests |
| Supported userfaultfd mapping modes and host kernels? | Cannot assume fork/WP/kernel-fault behavior from generic availability | Deployed feature probes, permission checks, and positive/negative tests for every advertised mode |
| Host page sizes larger than 4 KiB? | Logical pages stay fixed; population/removal may need grouped host pages | Complete group versioning, preservation, bounds, and portability evidence |
| Access sampling and replacement policy? | Dirty pages are not necessarily hot; missing faults do not observe resident accesses | Bounded overhead and thrash/working-set measurements, avoiding guest-semantic effects |
| Temporary spill format and filesystem? | Latest versions remain readable, authenticated, and owned; no unjustified durability claim | Crash/failure semantics, stale-slot tests, capacity and file-cache measurements |
| Store packing and indices? | Dense distinct pages exceed current flat limits | Bounded paged traversal, authenticated random retrieval, realistic scale benchmarks |
| Minimum RAM and I/O reserves? | Pager must not compete away its own progress resources | Dense metadata calculation, host-page accounting, fork peaks, emergency fault/cancel tests |
| Policy default values and rates? | No workload-independent residency or latency promise | Representative baseline measurements with observable actual paging and explicit refusal rates |
| Runtime operational journal durability? | Restart cannot double-reserve or forget accepted updates | Defined commit points, reconciliation states, idempotency quota tests |
| Exact numeric protocol registrations? | Cutover must reject incompatible definitions even for same-width fields | Complete current-head registry review and C/Rust codec vectors before publication |

These questions are implementation gates with owners in
[the delivery plan](11-implementation-plan.md). Default values are intentionally
not presented as proven operating recommendations. Numeric ABI versions must
be allocated against the actual implementation revision; blindly reserving
“current plus one” in a design written earlier can collide with intervening
work. Logical RAM edition 1 and its tags are fully specified here.

## 12.5 Deferred capabilities

Remote demand paging requires additional authenticated fetch authorization,
network availability and latency supervision, remote retention, security,
and loss-of-service behavior. Local lazy restore is not remote postcopy.
Live migration additionally needs an exact final coherent boundary, source
freeze/fencing, pending-I/O disposition, and one authoritative execution owner
after handoff. A receiver having all RAM pages is not proof it can resume.

Compression and encryption affect representation, not logical identity. Their
working memory, CPU, authentication, key ownership, and random-access behavior
must be admitted. Cross-tenant deduplication has confidentiality and retention
consequences and is not enabled merely because two pages have equal hashes.
Huge pages can improve resident performance but complicate fine reclamation;
their use is backend capability, not a change to logical geometry.

gem5 and KVM implementation remains future work. [Chapter 14](14-implementation-profiles.md)
specifies separate proposed profiles and their admission gates, without declaring
support. Paging does not establish exact capture, deterministic execution,
branch reconstruction, or cross-implementation continuation. Common guest images
can be tested in fresh KVM, QEMU-SIM, and gem5 runs; moving a reached continuation
requires a separately specified conversion with explicit lost guarantees.

Continuous reference/fault-modified RAM layers are deferred. This RFC does not
maintain a parallel hypothetical fault-free image or require fault-overlay
provenance retention. Existing admitted read transformations and physical fault
mutations remain supported under chapter 03's integration requirements.
Optional historical before/after versions can use explicitly retained immutable
pages, but are not dependencies of paging, Merkle identity, fork, or transfer.
The full-recompute qualification oracle checks the actual logical image; it is
not a second runtime image or a counterfactual execution model.

## 12.6 Acceptance of the design versus acceptance of performance

The design can be accepted before every deployment value is known. A release
cannot claim the full capability until its blocking engineering questions and
conformance evidence are resolved. Performance evidence must report campaign
throughput, guest-progress latency, backing bandwidth, fault rates, dirty/writeback
pressure, metadata, source sharing, and operational failure rate together.

The desired endpoints are an explicitly guaranteed resident mode and a
disk-oriented mode with an admitted minimum operational working set. They are
not proof that every workload benefits from maximum eviction. Aggressive
reclamation may increase useful parallelism for sparse or paused guests and
reduce throughput for active random access. Runtime tuning lets the operator
respond while preserving the declared operating-mode contract and complete ownership.
