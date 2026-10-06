# 10 - Validation, adversarial acceptance, and performance

This chapter defines evidence required before implementing, admitting, and
enabling the paged RAM design. All `gate:ram-*` names below are proposed gates,
not existing passing checks. Existing checks are useful integration points but
do not establish paging correctness. Implementation sequencing is specified in
[11-implementation-plan.md](11-implementation-plan.md).

## 10.1 Proof obligations and evidence classes

Paging is admissible as host work outside the guest-observable boundary. The
argument is that it changes placement and completion time of host work while
preserving the logical bytes, virtual event coordinates, and modeled state
transition sequence. Merkle hashing is similarly observation-only when it
consumes a coherent immutable view. The existing Class A/Class B distinction in
[RFC-0010 performance admission](../0010-crucible/25-performance-targets.md)
remains applicable. Successful run-twice comparison supports that mechanism
argument; it does not replace it.

- **[TEST-1]** Admission MUST include a written correctness argument identifying
  every RAM reader and writer, every publication barrier, ownership generation,
  and every path by which a host operation could affect modeled state. It MUST
  explain why policy updates, reclaim, reads, writeback, prefetch and background
  hashing cannot change guest-visible timing or canonical event ordering.
- **[TEST-2]** Tests MUST distinguish pure format tests, controlled model tests,
  live patched-QEMU tests, and packaged multi-host acceptance. Reports MUST
  identify which class supplies each claim. Static source-pattern checks MUST
  NOT stand in for live eviction, fault handling, fork isolation, or restart
  evidence. Every adversarial test MUST record whether the intended condition
  occurred; merely requesting reclaim does not prove paging occurred.

Test artifacts must identify the source/build, schema versions, fixtures,
kernel/filesystem capabilities, runtime policy, storage adversary, requested
logical coordinates, and observed outcome. Reproduction should preserve bounded
diagnostics and the first divergent coordinate without including raw guest
secrets. Tests of infrastructure failure compare its classification and
cleanup behavior; they do not require a failed host run to produce a completed
guest trace identical to a successful run.

## 10.2 Canonical vectors and independent Merkle oracle

Chapter [02](02-logical-ram-and-merkle-format.md) is the sole authority for byte
encoding, unkeyed BLAKE3-256 domain separation, fixed 4,096-byte logical pages,
ordered binary region trees, padding and scoped RAM inventory. `PageDigest` authenticates
content length and bytes. Logical position is committed by the ordered tree and
region inventory, not included in the content leaf; identical real zero pages
therefore remain shareable. `ContentId` authenticates canonical serialized object
bytes independently. The two identities must not be conflated in vectors or tests.

- **[TEST-3]** `gate:ram-format` MUST verify independently implemented canonical
  vectors across the host and GPL-side implementations. Vectors MUST cover
  empty inventories when a scope permits them, one page, multiple pages,
  non-power-of-two trees, final partial pages, multiple regions, real zero pages,
  padding leaves, aliases and excluded regions. They MUST demonstrate rejection
  of wrong ordering, wrong length, wrong scope, ambiguous topology and malformed
  bounds. Chapter 02's reference-vector procedure MUST agree with both compiled
  peers.

The format gate MUST also cover the official BLAKE3 primitive vectors and the
default unkeyed 32-byte mode, incremental input splitting, and every enabled
portable/SIMD implementation path. Negative controls MUST demonstrate that
keyed/derive-key mode, altered output length, and internal BLAKE3 chaining
values cannot substitute for canonical logical digests. A SIMD choice or
worker count MUST NOT change identity. Primitive tests do not replace the
logical topology, position, scope, and padding tests above.

- **[TEST-4]** `gate:ram-merkle-oracle` MUST compare cached roots against a
  complete independent recomputation from all logical bytes at coherent
  boundaries. The reference MUST NOT consume the cached leaves, incremental
  tree, dirty bitmap, or changed-page list used by the implementation under test.
  It MAY stream full logical contents through bounded buffers. It MUST rebuild
  the declared scope and tree from the canonical format.

The independent oracle is the protection against mutually consistent bugs in
capture and restore. A cached tree copied into a checkpoint and then restored
unchanged can agree with itself while describing stale contents. A reference
that visits only pages marked dirty cannot detect a missing dirty notification.
Whole-execution fingerprint comparisons alone may likewise share the same
faulty RAM component implementation.

- **[TEST-5]** A causal negative test MUST deliberately suppress a valid dirty
  notification while changing a page's bytes, leaving the cached root stale.
  `gate:ram-merkle-oracle` MUST fail at the next comparison. Additional negatives
  MUST corrupt a cached leaf, swap two page positions, reuse an older page
  generation, and substitute a valid page from another root. The gate MUST
  demonstrate each injected defect was reached and detected.

Full recomputation is expensive by design and belongs to validation. It is not
a requirement to retain the old flat digest or two production RAM algorithms.
The coordinated cutover in
[09-security-and-cutover.md](09-security-and-cutover.md) remains immediate.

## 10.3 Write tracking, scopes, and publication barriers

The writer inventory must connect the guest access to the actual dirty
instrumentation, including translated CPU stores, slow paths, device/DMA
helpers, direct device writes, debugger operations, fault mutations, reset,
restore and discard. Tests cannot assume that tracking stores emitted by TCG
captures host writes through every QEMU helper. Current checkpoint tracking is
useful groundwork, but its commit clear operation is not a fingerprint or
writeback acknowledgement.

- **[TEST-6]** `gate:ram-dirty-epochs` MUST exercise every supported RAM write
  origin with independent fingerprint, checkpoint/transfer and writeback
  consumers. Every acknowledgement, abort, rollover and clear MUST preserve
  changes still required by another consumer. Tests MUST cover one-byte writes,
  cross-page writes, unchanged-byte writes, change-and-revert, dirty cold pages,
  repeated writes during I/O, and topology changes.

The following matrix is required live coverage, supplemented by unit tests for
precise races. Unsupported guest/device profiles remain explicit admission
restrictions; they MUST NOT be hidden by silently omitting a writer or region.

| Dimension | Required cases | Observable assertion |
|---|---|---|
| Region scope | Ordinary writable RAM, ROM, RAM-device, migratable device RAM, aliases and multiple blocks | Each scoped root includes exactly its specified logical inventory. |
| CPU writes | Fast/slow stores, page crossings, relevant supported architectures and multi-vCPU RR boundaries | Incremental and independent roots agree at requested coordinates. |
| Host/device writes | DMA, debug, fault injection, reset, restore, discard and initialization | Correct pages and consumers observe changes, including direct host paths. |
| Existing fault continuations | Retention/rowhammer victims, staged physical mutations, read-only transforms, and deferred `MemoryService` loads/stores | Cold pages preserve fault opportunity counts, grant/ready coordinates, replay state, and every committed write. |
| Hardware reporting | Guest-RAM error records and realized supported delivery paths | Reporting writes are tracked; guest-visible delivery is established independently of command acceptance. |
| Epoch order | Fingerprint before/after checkpoint commit, abort during writeback, restore followed by capture | No consumer can erase another consumer's pending changes. |
| Snapshot coherence | Writer admitted just before freeze; background operations paused or draining | Published root describes one exact boundary, never mixed generations. |
| Root acknowledgement | Queued hash work, cancelled request, stale generation and worker failure | Publication and matching acknowledgement retain their specified order. |
| Fork ownership | Shared immutable tree, private updates, simultaneous sibling writes | Parent and siblings retain their own logical contents and roots. |

The current fingerprint callback captures immutable full material and a worker
publishes it before acknowledging the request. New tests must preserve that
ordering while replacing its memory cost. Every pager/hash worker introduced
into hot-fork needs barrier coverage; declaring the VM paused is insufficient
if a worker can still install bytes, publish metadata, or own mutable locks.

## 10.4 Paging, runtime policy, and operational failures

- **[TEST-7]** `gate:ram-paging` MUST prove actual cold-page reads and dirty-page
  eviction under each admitted backend. It MUST exercise storage latency,
  partial I/O, transient interruption, corruption, unavailable storage, disk
  exhaustion and memory pressure. The gate MUST verify bytes before use and
  preserve the final authoritative copy until backing ownership is established.
- **[TEST-8]** `gate:ram-runtime-policy` MUST change residency and aggressiveness
  while execution, capture, hashing, writeback and prefetch are active. It MUST
  distinguish accepted policy revision, effective revision, current residency
  and convergence. Stale revisions, lost responses, repeated requests, rejected
  admission and cancellation MUST preserve valid ownership and logical state.
- **[TEST-9]** `gate:ram-supervision` MUST show that configured high storage
  latency succeeds within the correct operation budgets. No-progress, total
  duration, storage-operation, setup and cleanup expiries MUST remain separately
  attributable host failures. A polling slice expiry MUST NOT become a terminal
  guest outcome. Cancellation MUST remain responsive within the declared
  control budget while guest execution is blocked on paging.

The concurrency adversary must provide causal controls: hold a read completion,
write the page again, then release the old completion; pause after writeback
submission, change the policy, then finish writeback; retire a VM, reuse a logical
identifier with a new generation, then deliver the old response. Assertions must
demonstrate stale work cannot mark new bytes clean, install old bytes, or release
the new owner's lease. Pager failure while QEMU holds BQL or a device lock needs
an explicit recovery/termination experiment so the host control plane is not
blocked indefinitely by a guest access.

Memory-pressure tests must include the pager's reserve, shared template pages,
page-cache pressure, dirty backlog, swap exhaustion, failed cgroup delegation,
denied fault permissions and missing kernel capabilities. Proactive reclaim
tests MUST inspect achieved residency and fault counters. Kernel advice is
best-effort; a test requiring an exact byte target must belong to a backend that
actually promises that target.

## 10.5 Guest transparency and exact continuation

- **[TEST-10]** `gate:ram-guest-transparency` MUST run the same unmodified image
  with fully resident policy, the labeled kernel-swap measurement baseline,
  and admitted custom-pager policies. A baseline run MUST NOT be presented as
  authenticated-backend qualification without PAGER-22's independent proof.
  It MUST require no guest kernel changes, agents, balloon driver, guest swap,
  changed disk image, special allocator or workload cooperation. Input bytes,
  guest RAM capacity, launch entropy and modeled device configuration MUST be
  identical. Immutable disk backing MUST remain unchanged.
- **[TEST-11]** `gate:ram-determinism` MUST compare completed runs at identical
  logical coordinates across residency budgets, eviction order, runtime update
  timing and artificial storage delays. The compared evidence MUST include all
  scoped RAM roots, architectural/device fingerprints, modeled clocks, I/O
  delivery coordinates, canonical logs and outcome signatures. Every mismatch
  MUST fail and localize to the first differing boundary.
- **[TEST-12]** `gate:ram-continuation` MUST compare local hot forks, cold exact
  restore and thin replay at the same authenticated boundary and subsequent
  trajectory. It MUST repeat the comparison after changing host residency and
  moving the portable checkpoint to another admitted instance. Every restored
  RAM scope MUST also pass the independent full-Merkle oracle.

Guest transparency has a wider corpus obligation than a diskless synthetic
fixture. The initial matrix must include booting an unmodified general-purpose
guest, multiple RAM sizes, supported device profiles, SMP, memory-intensive and
device-write workloads. Results must name the tested coverage honestly. The
existing any-guest gate explicitly limits its initial fixture claims; this RFC
does not turn that limited evidence into proof of every possible guest.

Portable acceptance must also cover failed-node state, pending modeled I/O,
scheduler continuation, timers, fault state, dirty epochs and disk overlays.
The RAM root is one part of the full execution relation. Tests should compare
the complete continuation after restore rather than only observing equal roots
immediately before the first resumed instruction.

## 10.6 Storage, transfer, and cutover negatives

- **[TEST-13]** `gate:ram-store-transfer` MUST exercise bounded streaming through
  each admitted placement, representation and durability mode. The matrix MUST
  include missing, corrupt, truncated, excessive, duplicated, reordered and
  wrong-root objects; packing, caching and deduplication; source/destination
  cancellation; lease loss; interrupted publication; and garbage collection
  during an active reader. A failed operation MUST leave no published partial
  root or executable partial destination.
- **[TEST-14]** `gate:ram-cutover` MUST reject each unsupported predecessor in the
  chapter 09 inventory before execution. Tests MUST cover mixed host/plugin/QEMU
  peers, stale worker capabilities, old retained templates, old fault evidence,
  and old exact roots. Rejection MUST NOT delete archived data or start a legacy
  reader, converter, or alternate production digest path.

The current exact-closure streaming acceptance already covers fragmented reads,
delayed archive access, failed publication, durable placement and identical root
identity. Its fixture and native codec need extension to the new RAM objects.
Its successful result does not establish fault-time page authentication or
eviction safety. Likewise, checkpoint restore authentication must not be
weakened to trust a stored Merkle root without checking the actual page bytes.

Distributed acceptance must show that the destination can reconstruct and resume
from the new representation with fewer transferred bytes when it already owns
the unchanged content. It must also show correct full transfer with no reusable
objects. Live pre-copy migration and post-copy execution across a running source
are deferred; no gate in this RFC may claim those capabilities from offline
checkpoint transfer evidence.

### 10.6.1 Mandatory progress, history, and child-lock negatives

The following gates explicitly qualify the resource and lifecycle requirements
added in chapters 04 through 06. They are proposed gates, with the same evidence
obligations as the other `gate:ram-*` names above.

- **[TEST-15]** `gate:ram-fault-progress` MUST run an unmodified guest that touches
  more distinct pages within one execution quantum than the requested resident
  peak can hold. The test MUST include device activity and a runtime target
  reduction, and MUST establish that it exercised a blocked capacity fault
  without relying on unreserved resident capacity. A general low-peak backend
  MUST make bounded progress with correct bytes and unchanged modeled timing.
  The initial paused-only backend MUST refuse the unsupported peak at launch
  and on a live reduction; its valid-admission case MUST retain the sound
  interval reservation. A separate adversary MUST remove resources after valid
  admission and require typed host failure before the independent progress
  reserve is exhausted. Deliberately undersized admission MUST NOT pass by
  terminating later. Neither result may deadlock waiting for the unreachable
  quantum boundary, install zeroes, or quietly obtain extra host memory. The
  gate MUST include a causal negative that withholds the only qualified reclaim
  path and detects lack of progress or the specified safe operational failure.
- **[TEST-16]** `gate:ram-policy-history` MUST exhaust accepted-update count,
  per-target and aggregate history disk quotas, and request-rate/burst limits.
  A refused unique update MUST NOT allocate unadmitted history, mutate policy,
  advance revision, consume a unique-update slot, or forget a previous key.
  After unique-update capacity is exhausted, an authenticated known-key retry
  MUST recover its original acceptance without new history or revision, subject
  to the declared request-rate admission. Rate limiting MAY temporarily refuse
  that retry; the existing acceptance MUST remain recoverable when the retry is
  admitted. The test MUST evict its memory-cache entry and recover it through
  the bounded authoritative index, then repeat after journal reconciliation.
  History exhaustion MUST NOT consume fault-service emergency memory or block
  cancellation/status operations.
- **[TEST-17]** `gate:ram-fork-residency` MUST fork from a successfully locked
  `resident-required` parent and separately deny or fail the child's
  reservation, prefault, locking and verification operations. Parent lock
  success MUST NOT satisfy child readiness. Each failure MUST reject readiness
  before guest execution and retain ownership through rollback or quarantine,
  without a silent weaker policy. A successful case MUST verify the child's own
  locks and residency, and a descendant MUST repeat the same establishment.
  The gate MUST show that the denied child operation was actually attempted;
  observing inherited resident pages alone is insufficient evidence.

### 10.6.2 Fault, physical-access, checkpoint, and deadline qualification

- **[TEST-18]** Fault integration qualification MUST repeat resident and cold
  runs with persistent mutations, retention/rowhammer victims, suppressed and
  torn writes, read corruption, poison, and the admitted memory-service model.
  Paging, observation, COW, and host paging retries MUST leave modeled access
  opportunities, random/occurrence state, cell refresh, row counters, and
  controller service unchanged. Deferred loads/stores MUST retain grant/ready
  coordinates, access
  order, store count, and replay state through live policy updates, fork,
  checkpoint, and transfer. Read-only transforms MUST include equal-RAM-root
  cases whose complete continuation differs as expected. Cold multi-fragment
  mutations MUST inject page-in/COW/resource failures before preparation and
  after preparation but before commit, proving unchanged-state refusal or
  contained uncertain failure without accepted partial mutation. Scope
  expansion MUST NOT authorize unsupported fault targets. Hardware-error tests
  MUST use the actual admitted CPU/machine/firmware profile and independently
  assert the supported guest-visible delivery/handling contract; an applied
  command or evidence-envelope marker alone MUST NOT qualify it.
- **[TEST-19]** Initial removal MUST exercise retained direct DMA mappings,
  cached pointers, aliases, kernel pins, observation readers, and pre-save
  activity, with fault injection both disabled and enabled. The test MUST prove
  the intended physical borrower was reached and cannot retain stale contents
  or bypass the qualified fault path. General low-peak qualification MUST
  demonstrate the actual discard executor making bounded progress while a CPU
  or device thread is fault-blocked, including fork-COW pages and retained
  barriers. Pressure arriving at different TB positions with pending interrupts,
  timers, and queued device work MUST preserve uninterrupted execution's polling,
  RR choices, event order, and partial-turn state. Companion-death negatives
  MUST include nonzero cold pages and blocked CPU/device/child-initialization
  access, and attempt final fault-reference release during cancellation and
  fork handoff. Registration MUST remain retained until verified repopulation
  or completed containment; a sent stop/kill request MUST NOT count as completion.
- **[TEST-20]** Checkpoint qualification MUST hold page fetch/install,
  replacement/removal, writeback, and accepted policy changes across capture,
  cancellation, and restore. It MUST verify the disposition barrier, independent
  baselines, retained source authority, fresh controller namespaces, and refusal
  of late source completions. Transfer qualification MUST publish an archive on
  a storage-only destination without QEMU execution admission, then independently
  refuse an incompatible or under-resourced restore. Maintenance MUST retain
  source recovery authority when `RestoreReady` becomes stale before ownership
  commit. `ClosureStored` MUST NOT be accepted as execution readiness. Tests
  MUST also show that packing, compression, encryption, and placement of the
  same canonical CAS object preserve its `ContentId`, while distinct canonical
  objects may share a decoded RAM digest.
- **[TEST-21]** Supervision qualification MUST refuse infrastructure phases
  with absent class budgets and no finite applicable outer cap, including live
  updates and amendments that remove the last bound. Outer-cap tests MUST race
  amendment against expiry, cancellation, and completion; expire a cap before
  its watcher runs; lose the accepted response; exhaust bounded history; shorten
  below elapsed time; and restart before and after journal commit. All affected
  watchers MUST observe the same revision, original start, terminal decision,
  and limiting-cap status. Lost clock-incarnation or elapsed-time evidence MUST
  fail closed without restarting the allowance. Independently bounded cleanup
  MUST remain possible after execution expiry, and unlimited guest execution
  MUST NOT imply unlimited infrastructure waits.

## 10.7 Tree arithmetic and resource costs

For a single region of logical length `L > 0`, let `N = ceil(L / 4096)` and let `P`
be the least power of two covering the region's real leaves. Chapter 02 forbids
zero-length regions; empty inventories are separate format-vector cases.
A fully materialized binary tree has `P` leaf positions and `P - 1` internal
nodes. Real-page content, padding and logical
length semantics remain distinct. The following values count only 32-byte
digests for a power-of-two region; they exclude node objects, allocator overhead,
generation metadata, indexes, dirty state and resident bytes.

| Guest RAM | Real 4 KiB pages | Real leaf digests | All leaf/internal digests |
|---|---:|---:|---:|
| 512 MiB | 131,072 | 4 MiB | 8 MiB minus 32 bytes |
| 1 GiB | 262,144 | 8 MiB | 16 MiB minus 32 bytes |
| 64 GiB | 16,777,216 | 512 MiB | 1 GiB minus 32 bytes |

This is arithmetic, not a benchmark or the expected implementation footprint.
Padding can approach a doubling of leaf positions, and multiple small regions
have independent tree overhead. A dense digest array alone can consume more
than a deliberately small residency target. Sparse zero subtrees, shared
immutable nodes and storage placement of metadata therefore require explicit
accounting; they cannot be advertised as free because guest bytes are cold.

- **[PERF-1]** Admission and measurements MUST include guest resident pages,
  shared/COW pages, tree metadata, dirty tracking, pager buffers/reserves,
  checkpoint/transfer buffers, page cache, storage indexes and backing capacity.
  Reports MUST distinguish logical bytes, private bytes, shared resident bytes,
  physical storage bytes and deduplicated content. RSS summation alone MUST NOT
  serve as accounting for shared templates.
- **[PERF-2]** Incremental cost MUST be measured against both dirty-page count
  and total logical size. Sparse changes should rehash changed pages and the
  union of ancestor paths; dense changes may approach a complete recomputation.
  The implementation MUST bound queues and batching in both cases. Change-and-
  revert can reuse immutable content but still incurs tracking and hashing work.

Hash measurements MUST include 4 KiB page preimages, final partial pages,
small leaf/branch/root preimages, and sparse/dense batches of changed pages.
Reports MUST compare the selected BLAKE3 implementation with a declared
SHA-256 benchmark, enabling hardware acceleration where available and recording
the actual paths used. This is offline performance evidence, not a retained
production SHA-256 RAM path. Large-buffer hash throughput alone MUST NOT justify
claims about page or small-node performance.

For `D` changed pages the obvious path-update upper bound is proportional to
`D * (1 + log2(P))`, capped by the whole tree's nodes, with byte hashing
proportional to changed page contents. Shared ancestors reduce that count.
Physical copy-on-write granularity can copy an entire metadata allocation or
host page for one logical-node change. Thus a claim of fork cost proportional
to guest data delta must include metadata COW, persistent-node allocation and
page-table work, not only newly private guest pages.

- **[PERF-3]** Storage design MUST pass a scale test before choosing one physical
  CAS object per logical page or tree node. The current packed backend caps
  logical objects at 65,536; a 512 MiB non-deduplicating RAM image alone exceeds
  that at 4 KiB pages. The solution MUST specify bounded indexing, packing,
  object inventory, publication, reads and collection. It MUST preserve logical
  page identity while allowing independent physical grouping.

Worst-case tests require incompressible and entirely changed pages, no reusable
objects, many small RAM regions, repeated sibling divergence and a full dirty
backlog. Best-case tests include sparse dirtiness, repeated contents, canonical
zeroes and shared templates. Neither case can stand in for the other.

## 10.8 Performance evidence and qualification order

- **[PERF-4]** `gate:ram-performance` MUST measure completed campaign
  attempts per host-hour against residency budget and parallel guest count.
  Supporting metrics MUST include page-in/writeback bytes and latency, physical
  I/O, faults, storage saturation, logical progress, fingerprint cost, fork cost,
  capture/restore latency, transfer bytes, metadata footprint and resource
  failures. Increasing admitted VM count alone MUST NOT count as improvement.
- **[PERF-5]** Benchmarks MUST use a declared reproducible host/storage profile,
  pinned source/build and content-addressed corpus. They MUST report cold and
  warm storage separately, comparable fully resident execution, sparse/dense
  workloads, repeated samples and uncertainty. Regression thresholds MUST be
  based on measured reviewed baselines, never invented values or a result
  copied from a different host/storage configuration.

The existing campaign performance gate has no reviewed measured baseline pinned
in source and explicitly reports `BLOCKED` in that case. This is a known evidence
gap, not evidence that the paging design meets its throughput goals. Existing
performance language calls guest RAM footprint unavoidable; it must be updated
to distinguish logical capacity from residency without disguising storage and
metadata cost. Slow storage may reduce completed campaign throughput even when
many more VMs fit in memory.

- **[PERF-6]** Qualification MUST proceed through separately reviewable stages:
  contract/schema/oracle work; kernel-swap measurement and Merkle tracking in
  parallel where their dependencies permit; scalable storage representation;
  custom pager and boundary/eviction safety; independently qualified fault-safe
  low-residency progress; fork and lazy restore; then portable transfer. General
  strict low-peak capability MUST remain disabled until `gate:ram-fault-progress`
  and its lifetime/wait-for proof pass. Each stage MUST pass its correctness
  gates before its performance claims enable broader admission. Live migration
  remains deferred.

The first prototype should establish dirty-writer coverage and suppressed-
notification detection. In parallel, measure the kernel-swap path with current
full-material fingerprint capture to expose its temporary-memory and I/O costs.
After the Merkle path exists, measure the same corpus without full-preimage
capture. Next, validate storage scale before custom paging relies on that store.
These experiments determine implementation choices without prematurely claiming
that a particular kernel mechanism or object granularity is adequate.

Existing required integration gates remain `gate:abi-conformance`,
`gate:license-boundary`, `gate:any-guest`, `gate:single-vm-fingerprint`,
`gate:replay-oracle`, `gate:layer1-injection`, `gate:control-responsive`,
`gate:qemu-inert`, relevant hot-fork isolation/scaling checks, exact-closure
streaming, fleet equivalence and performance qualification. The new gates must
be wired into the same packaged execution families rather than recorded as
unattached local successes. No performance waiver may turn a RAM integrity or
determinism mismatch into an accepted tolerance.

## 10.9 Informative design-completion validation record

The design audit and format validation on 2026-10-05 used RFC revision
`991bf1e3549d4d6838711afb0bf6e62b736f3468`. Repository checks ran against the
same runtime, package, and test sources, unchanged from the source baseline
in the overview. Subsequent documentation edits add this record and clarify
qualification wording; they change no normative requirements or format
fixtures. This record supplies evidence about the document, its fixtures,
and the executed repository checks; it does not qualify an implementation
of this proposal. The `gate:ram-*` gates remain future work.

Every Nix invocation disabled remote builders with `--option builders ''`.
Checks were invoked through the AOS development shell and repository CLI;
production check derivations used `aos-dev --no-cache`. Local builds may reuse
existing store outputs, but no test execution was offloaded to another host.

| Validation | Outcome | Evidence and limit |
|---|---|---|
| Document integrity | PASS | All 234 requirement definitions are unique and contiguous within their families; local requirement references, document links, tagged fences, and JSON syntax are valid. |
| RAM format fixtures | PASS | A freshly compiled official BLAKE3 1.8.5 portable C implementation agreed with independent reconstruction of 15 named digests, every tree level and supplied preimage, and all three scoped roots. Domain, endianness, length, padding, and scope controls were also checked. |
| Nix formatting | PASS | All 2,046 Nix files passed Alejandra. |
| Rust formatting | FAIL | `aos-dev fmt all --check` reported differences in unchanged baseline Rust files. The check did not modify them. |
| System evaluation and structure | PASS | The `eval` check completed locally, including its Linux 7.2.3 and ZFS dependencies. |
| Packaged Rust test targets | PASS | `rust.aos-test-targets` compiled all application unit and integration test targets. This compilation check does not execute their tests. |
| Packaged license boundary | PASS | All 18 boundary tests passed. Its controller prerequisite also passed Clippy, doctests, and 5,560 executed tests across 266 binaries, with 75 explicitly skipped tests. |
| All-features Rust workspace | FAIL | Compilation completed and the `--no-fail-fast` run finished with seven failed test targets, listed below. This run does not establish an all-green workspace. |
| Full repository aggregate | BLOCKED | `all checks` failed during evaluation on missing Samba resource classifications, before it could schedule the full check inventory. |
| Crucible phase 1 aggregate | BLOCKED | Evaluation rejected the baseline `packaged-midpoint-flight` feature declaration without a consuming `cfg`. |
| Shared-memory ABI check | FAIL | Eight Rust cases passed; the unchanged generated C fixture then failed to compile against renamed or removed instruction-count fields. This is not a passing ABI gate. |
| VM boot basics | FAIL | The guest booted and passed OS-release, hostname, and running-system checks, then failed an unchanged assertion requiring `6.18` in `uname -r`; the repository builds Linux 7.2.3. Later assertions did not execute. |
| Packaged live SQL dialects | FAIL | Local VM fixtures started PostgreSQL 18.6 and MariaDB 12.3.3. PostgreSQL and SQLite contracts passed; the MariaDB contract failed on an unchanged GC query with unknown column `cache_gc_generations.cutoff_at`. |

The aggregate failures are explicit missing coverage, not waivers. The package
platform-support check requires classifications for
`networking/_samba-cross/aarch64-linux.answers` and
`networking/_samba-cross/heimdal-build-tools.nix`. The ABI fixture still names
`icount_shift` and `preemption_*_icount` fields that its current public headers
do not expose. These sources, the feature declaration, and the VM assertion
were not changed to obtain a passing result for this documentation change.

The workspace command used a separate worktree-owned Cargo target directory,
denoted by `RFC_CARGO_TARGET_DIR` below:

```bash
nix develop --accept-flake-config --option builders '' -c \
  env CARGO_TARGET_DIR="$RFC_CARGO_TARGET_DIR" \
  cargo test --manifest-path crates/Cargo.toml --workspace --all-targets \
  --all-features --no-fail-fast -j 16
```

Its failed targets were:

- `-p aos --test apr_cache_cli`
- `-p aos-hub --test dialect`
- `-p aos-hub-core --lib`
- `-p aos-package --lib`
- `-p crucible-api --lib`
- `-p crucible-cli --test campaign_store_process`
- `-p crucible-cli --test gate_campaign_store_composition`

The workspace dialect failures reported missing live database URLs. The separate
packaged live-SQL result above uses actual fixtures and therefore supplies
different evidence. Three failures from the parallel workspace run passed when
rerun individually using the same compiled executables with `--test-threads=1`:
the Hub concurrent baseline installation test, its expired inventory range-owner
test, and Crucible's host-continuation clone-cost test. The latter originally
reported 88,352 KiB private memory for 64 clones. Isolated reruns do not erase
the original failures or establish the other failed targets passed. No runtime
or test sources were edited to address these failures in this RFC change.

The packaged check commands were:

```bash
nix develop --accept-flake-config --option builders '' -c \
  aos-dev fmt all --check

nix develop --accept-flake-config --option builders '' -c \
  aos-dev --no-cache all checks \
  --no-out-link --keep-going --option builders '' --show-trace

nix develop --accept-flake-config --option builders '' -c \
  aos-dev --no-cache build check eval \
  --no-out-link --keep-going --option builders ''

nix develop --accept-flake-config --option builders '' -c \
  aos-dev --no-cache build check rust.aos-test-targets \
  --no-out-link --keep-going --option builders ''

nix develop --accept-flake-config --option builders '' -c \
  aos-dev --no-cache build check crucible.phase1 \
  --no-out-link --keep-going --option builders ''

nix develop --accept-flake-config --option builders '' -c \
  aos-dev --no-cache build check crucible.phase2.shmemAbiConformance \
  --no-out-link --keep-going --option builders ''

nix develop --accept-flake-config --option builders '' -c \
  aos-dev --no-cache build check crucible.phase1.gates.licenseBoundary \
  --no-out-link --keep-going --option builders ''

nix develop --accept-flake-config --option builders '' -c \
  aos-dev --no-cache build check vm.boot-basics \
  --no-out-link --keep-going --option builders ''

nix develop --accept-flake-config --option builders '' -c \
  aos-dev --no-cache build check integration.aos-hub-dialect-tests-live-dialects \
  --no-out-link --keep-going --option builders ''
```

The earlier format review additionally established agreement with the official
Rust reference, 210 primitive checks, agreement across 35 selected-mode input
lengths, and nine RAM mutation controls. The completion run above freshly
recompiled the C implementation and reconstructed the RAM fixtures; it did not
repeat every earlier primitive/reference experiment. Neither set of format
results supplies live page-fault, eviction, fork, or transfer evidence.
