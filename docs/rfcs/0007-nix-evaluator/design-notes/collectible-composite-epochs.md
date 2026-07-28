# Collectible composite epochs

## Evidence and target arithmetic

The exact terminal retention census found that 3,438,570 of 4,335,701
suspended thunks (79.3%) are reachable only through permanent lists and
attrsets that are themselves unreachable from the complete evaluator root
set. Those composites carry 12,084,245 direct suspended-thunk edges. The
164,611,056 bytes of dead-composite-only inline thunk storage exclude captured
frames, typed work, and external list/attrset payloads.

The same run projected 1,673,793,536 bytes in zero-live reservation pages.
That is a factor-level reclamation opportunity, but it is not sufficient for
the final memory target. Current measurements also attribute approximately:

```text
module IR                    326,130,731 bytes
retained source text          46,594,467 bytes
terminal live reservation     31,797,248 bytes
                              -----------
subtotal                     404,522,446 bytes
```

The required ceiling is 414,326 KiB. This subtotal leaves only about 19 MiB
for the executable, stacks, hash indexes, live external payloads, allocator
metadata, and every other resident category. Passing therefore requires both
heap reclamation and module/source lifetime or representation work.

## Why the existing non-moving sweep is not enough

The current worker sweep treats every permanent list and attrset as a root and
therefore retains precisely the graph identified by the census. Extending that
sweep to retire unreachable composites is a useful semantic proof, and the
flat stores already provide validate-then-retire selection tokens. It is not a
complete physical-memory design:

- the shared reservation interleaves strings, paths, lists, attrsets, closure
  records, typed-head blocks, and boxed scalars;
- retiring individual objects leaves tombstones and cannot reuse their direct
  Candidate-C addresses without an ABA hazard;
- live objects interspersed on a page prevent page advice; and
- terminal reclamation cannot lower the chronological peak.

Earlier projections illustrate the fragmentation problem: one ordinal exposed
62.7 MiB of logical death but only 31.16 MiB of whole pages, while an earlier
worker retirement exposed only about 1.09 MiB. The terminal graph becomes
mostly dead, but too late.

## Proposed architecture

Candidate-C serial evaluation should allocate lists and attrsets into
segregated chronological epochs. Each epoch owns a distinct arena domain,
flat-list store, flat-attrs store, allocation-byte counter, and sealed state.
The active epoch rotates at proven evaluator statepoints and eventually on a
32-64 MiB composite-allocation budget.

Each epoch should reserve only its 32-64 MiB page-aligned budget, not the full
four-gigabyte Candidate-C domain maximum. `ReservedArena::with_capacity`
already supports bounded reservations; `SharedFlatStoreArena` needs a matching
constructor. Domain IDs remain ample and the existing process-wide
domain-to-base registry can resolve each bounded epoch.

At a collection statepoint:

1. Build the complete mutable root set, including the caller result, and
   require zero active force, typed-work, native-continuation, call-plan,
   composite-accumulator, and import/module blockers.
2. Trace from true roots across every heap kind. Hash-cons tables remain weak
   and do not seed marking.
3. Select unreachable list and attrset coordinates in sealed epochs. Validate
   every coordinate and all required staging storage before mutation.
4. Purge the selected identities from list/attrset hash-cons tables and clear
   their cold/stale side hashes.
5. Commit the prepared flat-store retirement tokens without allocation.
   Dropping the payloads breaks their worker edges immediately.
6. Run the worker closure sweep again from the same roots, now that dead
   composites no longer retain the suspended graph.
7. Advise only whole pages whose allocation ledger reaches zero.

Live objects do not move in this first stage. Their direct words, addresses,
and pointer-identity shortcuts remain unchanged. An epoch arena is not dropped
while any live object remains.

Candidate-C words already encode an arena domain. Hot list/attrset resolution
can dispatch through a small domain-to-epoch table without introducing a
global stable-handle indirection. Empty old epochs can later be dropped as a
unit; partially live epochs retain their address space until a rarer
whole-domain rotation.

## Typed heads, work, and caches

Composite retirement exposes large worker graphs, but stable typed heads and
their generated work pools require separate treatment.

The first executable proof should keep live stable heads fixed and rebuild
only live suspended work into fresh pools. Preparation stages
`(head, old_handle, new_handle)` tuples, validates that there are no blackholes
or active leases and that every old handle is unchanged, then retargets heads
and swaps pools atomically. Segmented work pools are the longer-term form.

Typed-head blocks need block-aware retirement. Their fixed lane records one
allocation per block, so retiring an eight-byte head must not decrement the
page ledger as though each slot were an independent allocation. A block may be
retired and advised only when all of its initialized slots are dead.

Local Ready caches must not become accidental owners:

- `ReadyCellDirectory` source thunks are weak identities and should be cleared
  or filtered at collection;
- direct values in `ReadyCellPlanCache` must be enumerated as writable roots or
  invalidated when their referent dies;
- import Ready values already participate in the mutator root set;
- L0/L1 content payloads are self-contained and remain enabled; and
- identity-keyed advisory sets and force-payload memo state must be cleared or
  rewritten at any moving rotation.

This preserves same-run caching between collections without using caches as
hidden strong roots.

## Whole-domain rotation

Epoch retirement is the common-case mechanism. It cannot recover pages that
contain a small number of long-lived objects, cannot reuse direct addresses,
and does not compact typed-head or module storage. The tracing backstop is an
occasional whole-domain Candidate-C rotation at a complete writable
statepoint:

1. prepare a fresh arena domain;
2. copy each reachable object once and record forwarding;
3. rewrite every mutable root, heap edge, typed-work handle, and live weak-cache
   entry;
4. rebuild weak hash-cons indexes only from forwarded live candidates;
5. rescan roots, heap fields, caches, side maps, and tail handles for residual
   old-domain aliases; and
6. retire the old domain only after the audit is empty.

Blackholed or leased typed heads fail closed. A new domain avoids ABA without
adding a read barrier to every `Value`.

## Milestones and gates

1. **Terminal all-kind retirement proof.** Retire unreachable composites and
   worker closures at terminal quiescence. Require exact output, weak-index
   cleanup, loud stale-handle failure, and measured payload destruction. This
   proves semantics but receives no peak-memory credit.
2. **Single pre-peak epoch.** Rotate a list/attrset epoch at a known
   final-configuration completion point with a complete-root proof. Require
   exact Nix 2.24 and 2.34 output, at least 90% of selected dead composites
   retired, at least 32 MiB current-RSS reduction, and lower later peak.
3. **Repeated budgeted epochs.** Collect on composite allocation bytes and
   measure amortized collector instructions. The initial overhead ceiling is
   2-3%; the final benchmark must still beat stock C++ Nix by more than 2x.
4. **Typed-work/head retirement.** Rotate live work pools and retire empty
   typed-head blocks with generation/lease stress coverage.
5. **Whole-domain rotation.** Add complete writable-root/cache healing and
   residual-alias auditing before dropping old Candidate-C domains.
6. **Module/source lifecycle.** Compact cold IR and release or compress source
   text after lowering while preserving error/span behavior and compatibility.

The first milestone now has a default-off terminal implementation behind
`AOS_NIX_TERMINAL_COMPOSITE_RETIREMENT=1`. It traces from the complete terminal
root set, validates and retires unreachable flat lists and attrsets, purges
their weak hash-cons and side-hash identities, then runs the existing worker
closure sweep after the composite payloads have dropped their edges. Its
strict-JSON report explicitly records `"terminal_only":true` and
`"peak_credit":false`; Candidate-C exact-system parity and full payload/page
measurements remain required before promoting the experiment to milestone 2.

The exact typed-head system-toplevel proof remained byte-identical and retired
555,027 flat lists plus 1,566,298 flat attrsets. It dropped 539,269,456 inline
bytes, 10,944,848 bytes of list-spine capacity, and an estimated 674,517,560
bytes of attr-array storage. The shared reservation exposed and advised 116,063
zero-live pages (475,394,048 bytes).

The legacy post-retirement worker sweep failed closed and retired no worker
closures because its marker assumes worker records/flat closures and cannot
traverse stable typed heads. This result receives composite payload/page credit
only, never worker or peak credit. The next semantic slice must rotate or
retire unreachable typed heads and their generated work pools from the already
computed true-root reachability set; rerunning the old permanent-seeded worker
sweep is not a typed-compatible solution.

The final acceptance test remains the pinned nixpkgs system toplevel under
strict-cold external state with every intra-run cache enabled. Intermediate
retirement and parity gates are evidence, not completion.

## Related collector designs

Chronological composite epochs correspond most closely to Beltway's
independent FIFO increments. Immix explains why segregated blocks and lines
recover space that object retirement in an interleaved arena strands. LXR is a
useful model for combining prompt common-case reclamation with infrequent
tracing:

- Stephen M. Blackburn et al., *Beltway: Getting Around Garbage Collection
  Gridlock* (PLDI 2002).
- Stephen M. Blackburn and Kathryn S. McKinley, *Immix: A Mark-Region Garbage
  Collector with Space Efficiency, Fast Collection, and Mutator Performance*
  (PLDI 2008).
- Steve Blackburn et al., *LXR: Defragmenting the Heap by Bridging the Gap
  between Tracing and Reference Counting* (PLDI 2022).
