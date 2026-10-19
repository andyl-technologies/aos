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

Before reducing admission, run actual cross-page host instructions with one
slot, verify bounded refusal despite serviced faults, and repeat with a paid
progress set that permits retirement. Repeat with competing real threads and
require acknowledgements issued after the instructions execute. Add concurrent
load/store/atomic stress, stale WP events, actual pin refusal or bounce-path
evidence, and failures at preservation/discard/fill/wake. Measure physical
high-water use, including pins, COW, backing I/O, page tables and reclaim lag.

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
