# Live eviction investigation

This is an implementation candidate, not a capability qualification. The
current full-RAM admission and paused-boundary eviction remain required until
both initial population and steady-state progress have smaller proved bounds.
The investigation covers private anonymous mappings in QEMU software execution;
it grants no capability to another execution profile or mapping type.

## Virtual addresses and physical pins

A retained userspace pointer names a virtual address. Replacing physical backing
behind that stable address does not by itself require a lease on every TCG
load/store or software DMA copy. The candidate uses synchronous userfaultfd
write protection, durable preservation, discard, and authenticated refill.
This is an inference from ordinary Linux translation and fault semantics,
conditional on controlling every writable alias and excluding physical pins.
In the inspected [Linux 7.2.3 implementation](https://github.com/gregkh/linux/blob/v7.2.3/mm/userfaultfd.c),
the write-protection path completes its protection update and TLB operation
before returning. Successful completion supplies the cut before copying frozen
bytes; it does not prove application progress or snapshot coherence.

Actual kernel/device pins are different. Direct I/O and RDMA pins do not have
ordinary unmap/clean synchronization. A writer can retain the old physical page,
write after preservation, and leave the refilled virtual address with stale
bytes. Read-only pins also retain physical backing. The
[kernel pinning documentation](https://docs.kernel.org/core-api/pin_user_pages.html)
therefore requires classifying the actual buffer lifetime, rather than treating
a protected PTE or an I/O completion counter as sufficient authority.

The current native paging path already forces `address_space_map` through
bounce buffers and disables direct `MemoryRegionCache` pointers. Virtqueue and
block I/O using those mappings can retain bounce allocations until actual I/O
completion; inbound unmap copies through `address_space_write`. Preserve these
rules. Audit independent direct-iovec paths separately, retain bounce resource
ownership, and keep current vhost, VFIO and unclassified-listener refusals.
An outstanding bounce map does not inherently pin a guest page, although it
can still matter to a coherent device snapshot.

## Candidate transaction

Use the existing single fault actor and retained `FaultWorkOwner`, with an
explicit eviction journal. The actor serializes victim preservation with
write-fault handling and refill. Do not call the existing paused Native
transaction from a faulting thread that may already hold BQL.

1. Select a genuinely admitted resident victim and retain its version, original
   preservation and residency debit. Exclude snapshot/fork and active progress
   ownership before beginning effects.
2. Complete synchronous write protection. Copy the still-present page into
   separately paid fixed scratch. Retain partial effects if protection fails.
3. Preserve and verify the exact bytes with the existing durable `PageRecord`
   path, including `sync_data`. Publish the immutable preservation while
   excluding any write-protection clear.
4. Issue a single-page `MADV_DONTNEED`. Publish absence and return the residency
   slot only after successful discard; failure or uncertainty retains custody.
5. Reserve fill/progress capacity, authenticate backing, and populate using
   `UFFDIO_COPY_MODE_WP | UFFDIO_COPY_MODE_DONTWAKE`. Publish the actual resident
   state before wake. A newly arriving reader may access an installed PTE even
   when existing fault waiters have not been woken.
6. For a write request, publish the logical dirty/version transition before
   clearing write protection. Physical eviction/refill itself changes neither
   logical content nor its version, dirty epoch, Root frontier or capture ACK.

The [anonymous discard path](https://github.com/gregkh/linux/blob/v7.2.3/mm/memory.c)
drops write-protection markers; do not depend on protection
surviving absence. Keep missing and WP registration and reinstall protection
with the populated page. The [kernel userfaultfd contract](https://github.com/gregkh/linux/blob/v7.2.3/Documentation/admin-guide/mm/userfaultfd.rst)
describes combined missing/WP handling and protected copy. Full-kernel fault
support remains required; `UFFD_USER_MODE_ONLY` cannot transparently handle
kernel-originated guest-buffer accesses.

A queued WP event describes an access request, not permanent page residency.
Reconcile it with the current journal after discard or refill. The current
`WP && !resident` refusal needs this explicit replacement before live eviction;
an old event must never clear protection during a later preservation cut.
Retain the consumed PageIn Original through victim work, fill and wake. Any
separate Writeback Original must come from the genuine existing factory.

## Progress floor remains open

Correct fault handling alone does not prove instruction retirement. A host
instruction crossing two pages can repeatedly fault if one residency slot
alternates between them. Multiple runnable actors can similarly evict one
another's working pages. No universal two-page constant has been established.

Reserve a bounded working set for actual admitted access domains and retain
its pages through real native completion or safe-point receipts, or establish
another measured progress mechanism. A whole guest quantum may touch many
pages and cannot be assigned an invented small bound. Selecting a preferred
fault TID does not stop other runnable actors. Keep fault-service progress
distinct from guest instruction progress in supervision and measurements.

The local `checks.crucible.ram.kernelProgress` experiment passed using the real
Linux 7.2.3 fault path in a disposable VM. One x86-64 `MOVDQU` load spanning two
registered pages remained incomplete through eight alternating missing faults
with one populated page. Retaining both pages allowed the exact 16-byte result
and physical thread join. Two real threads accessing disjoint page pairs each
remained incomplete through eight alternations; retaining both pairs allowed
both exact results and joins. The probe checks residency, actual fault TIDs,
post-instruction notifications and the existing full-kernel missing/WP cases.
This is host-instruction component evidence, not a universal guest progress
bound or qualification of a general live-eviction implementation.

Before reducing admission, add concurrent load/store/atomic stress, stale WP
events, actual pin refusal or bounce-path evidence, and failures at
preservation/discard/fill/wake. Establish the real access-domain completion
mechanism and measure physical high-water use, including pins, COW, backing
I/O, page tables and reclaim lag.

## Access units and completion

The next candidate is to reserve residency for complete, bounded memory
operations, including their already resident operands. Protecting only the page
that most recently faulted is insufficient: another actor can evict an earlier
operand before the blocked operation retries. Page delivery and waiter wakeup
are not operation completion receipts. The
[Linux userfaultfd contract](https://raw.githubusercontent.com/torvalds/linux/v6.17/Documentation/admin-guide/mm/userfaultfd.rst)
describes atomic page population and waking fault waiters; it does not report
that the resumed instruction or syscall has returned. This interface observation
does not qualify the running kernel or supply a progress bound.

The patched QEMU source exposes several different access lifetimes:

| Access path | Existing structure | Required residency lifetime |
| --- | --- | --- |
| Scalar TCG helper | `MMULookupLocals.page[2]` handles the helper's split access through 16 bytes. | All actual host pages through the helper's memory and dirty-publication work. The two-entry lookup is a local bound, not a universal instruction bound. |
| Atomic helper | Alignment checks and the existing serialized fallback preserve the guest operation. | The complete atomic unit, including widened host accesses and exceptional cleanup; independent page loans cannot split guest atomicity. |
| String, vector and probing helpers | REP repeats individual accesses; `probe_access*` can return raw host pointers retained by other helpers. | A proved bounded iteration, element or helper unit, covering every retained pointer. Returning from a probe alone is insufficient. |
| Physical RAM copy | `flatview_*_continue_step` can copy a caller-sized contiguous span. | Bound each managed-RAM copy by actual host-page spans and retain all operands until that copy returns. |
| Device mapping | Managed RAM already uses bounce mappings and disables direct memory-region caches. | Complete the RAM-to-bounce or bounce-to-RAM copy before returning guest residency. Retain and pay the bounce independently through asynchronous completion. |
| Kernel access and service actors | A syscall, capture or pager operation may borrow RAM while another actor waits. | Actual completion of the borrowed access, with independently resident service storage and no recursive dependency on the fault being resolved. |

An operation loan would enumerate its complete footprint, reserve all needed
credits before acquiring any page, exclude those pages from eviction, supply
missing contents and handle write protection, then execute the existing memory
operation. Its real return or explicit exceptional cleanup would release the
loan. Reserving only part of an operation's footprint can deadlock two actors
that each retain credits needed by the other. Eviction must not protect or
reclaim a loaned page and wait for that same blocked operation to finish.

Exception handling needs an explicit join. TCG exits use `siglongjmp` through
`cpu_loop_exit` and `cpu_exec_longjmp_cleanup`; lexical C cleanup alone does not
establish that a borrowed access cannot resume. Ordinary plugin callbacks also
do not cover this lifetime: instruction callbacks precede execution, and memory
callbacks describe successful accesses. Their documented timing does not prove
completion of exceptional or partially completed operations. See the
[QEMU plugin callback contract](https://www.qemu.org/docs/master/devel/tcg-plugins.html).

A proposed reservation has the form:

```text
progress_bytes = host_page_bytes * sum(concurrent_units[class] * pages_per_unit[class])
               + service_bytes + bounce_bytes + transition_bytes
```

Each term must come from actual admitted actors, access paths and retained
lifetimes. Include page walks, nested helpers, device/Aio work and asynchronous
borrowers; a vCPU count alone is insufficient. A lower concurrency limit needs
its own dependency and fairness argument. A resident target of zero can coexist
with explicitly reserved transient progress capacity, but cannot eliminate it.
The formula is a design obligation, not a measured physical high-water result.

Forcing managed accesses through slow TCG helpers could provide the first
bounded experiment. It has no performance qualification. Longer leases tied to
software-TLB validity could preserve inline resident hits, but require actual
invalidation and quiescence before release. Their full TLB coverage must be
bounded and paid, and they do not cover escaped helper or device pointers.
Keep the existing resident baseline while evaluating both approaches.

The next experiment should join one real scalar access family and one
page-bounded physical-copy path to actual residency loans. Exercise cross-page
operands, REP source/destination traffic and concurrent actors, including
operands that were resident before pressure began. Record actual helper returns,
guest architectural progress and exact resulting bytes independently of fault
and wake counts. Then cover atomic fallback, exceptional exits and raw-pointer
helpers before generalizing the envelope. Until this closure and authenticated
streaming initialization are implemented, retain full-RAM admission.

## Integration order

First implement and test the transaction under the existing full entitlement.
Reuse `engine/service.rs`, `service/capture_work.rs`, `engine/placement.rs`,
`storage.rs` and `kernel.rs`; avoid a parallel pager implementation.
`engine/checkpoint_owner.rs` and the actor pause protocol must retain or settle
an in-progress eviction before acknowledging a snapshot. Resident raw readers
still need their coherent fence: stable virtual addresses do not make a
concurrent multibyte snapshot coherent, and a paused sole fault actor cannot
service a reader fault caused by an unfenced discard.

Preserve current page-version, authored-write and ordinary-capture exclusions.
Fork must settle or retain the journal before joining the parent actor, then
create fresh child registration and backing custody. Do not inherit operational
authority or infer that a shared COW folio has been freed from a vanished PTE.

After the steady-state transaction and real progress floor are qualified,
remove the separate all-page-prefault startup peak through authenticated
streaming initialization. Only then change admission formulas to the proved
combined envelope. Keep resident-mode behavior and the fixed performance
baseline throughout; structural feasibility supplies no performance result.
