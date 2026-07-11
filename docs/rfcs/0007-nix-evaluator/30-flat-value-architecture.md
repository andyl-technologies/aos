# RFC-0007 - The flat-value architecture campaign

> A `Value` should be a pointer to its bytes. Today it is a ticket into
> a lookup service.

This document records the **flat-value architecture campaign** (approved
2026-07-09), a later addition to the RFC-0007 set in the same manner as
[25](25-intermediate-representation.md)–[29](29-tiered-content-keyed-memoization.md).
It is the plan for removing the evaluator's largest remaining
*architectural* slowdowns — the ones that no pass, cache, or JIT tier can
compensate for because they are paid on every heap-value dereference and
every closure capture. Like [29](29-tiered-content-keyed-memoization.md),
it is written against the shipped vocabulary (`Value`, `HeapObject`,
`HeapRecord`, `EvalEnv`, `AtomicValueCell`, `AOS_NIX_GC=sweep`) and cites
the landed commits that produced its evidence. Divergences between this
plan and the code as it stands are flagged, not resolved (§11).

Nothing here weakens the byte-parity contract of
[02](02-compatibility-constraints.md): every stage of the campaign is an
internal representation change gated on byte-identical `.drv` output, and
the stage order is chosen so that at most one representation variable
changes per landing.

---

## 1. The problem: every dereference is a probe, a record, and a chase

### 1.1 Anatomy of a native value dereference

C++ Nix's `Value` carries a direct pointer: dereferencing a string, list,
or attrset is one load from the pointed-to bytes. At the campaign opening,
the native evaluator's
`Value` (`crates/ratchet-value/src/value.rs`) is a 16-byte tag+payload
pair whose heap payload is a `NonNull<HeapObject>` — and `HeapObject` is
deliberately opaque (`_private: [u8; 0]`): **nothing lives at the pointed-to
address**. The Tier-A bump arena (`crates/ratchet-value/src/heap/arena.rs`)
reserves aligned slots in `mmap` chunks and returns stable addresses, but
its own module header says it "deliberately avoids raw memory writes until
concrete heap object layouts exist." The address is an identity, not a
location.

The typed payload lived elsewhere. Resolution funneled through the record
side table (`crates/ratchet-oracle/src/eval/heap/record_table.rs`):

```text
Value { tag, payload: NonNull<HeapObject> }
  └─> AddressHasher probe                    HashMap<usize, u32> (12.3 MiB at wide-eval peak)
        └─> records[position]                Vec<HeapRecord>    (38.7 MiB; 160-byte records)
              └─> HeapRecord.object          HeapObjectValue
                    └─> Arc<EvalThunk> / Arc<EvalLambda> / Arc<EvalPrimOp>
                        NixString / NixList / FlatAttrs        (separate malloc allocations)
```

Every `get_string`/`get_list`/`get_attrs`/`get_thunk`, every hash-cons
collision confirmation, and every GC address lookup pays: **one hash, two
dependent loads (map bucket, record), and then an `Arc`/owned-buffer chase
to a third, unrelated allocation.** A single logical value cost three
allocations in three allocators — an arena address whose bytes are never
written, a `HeapRecord` slot in the table `Vec`, and a malloc'd payload —
with no locality between them. The spine work of package evaluation
(lambda application, attrset construction, string coercion into
derivation attributes) performs this millions of times per eval: the
whole-set `bench.wide` root pins 273 packages under one eval, and B1's
sweep telemetry alone observed ~254k forced thunks on that workload
(214k shed + retirement counts, commit `9422a34c8`), each of which was
allocated, probed, resolved, and chased at least once — with strings,
lists, and attrsets a large multiple of that (`EvalHeapAllocationCounters`
tracks the `nrValues`/`nrAttrsets` analogs; `eval/heap/alloc_counters.rs`).

### 1.2 What the landed evidence says

The record-table architecture was the right Phase-1 choice — it made the
oracle a fail-loud, `unsafe`-free interpreter, and the address-index fix
already took resolution from `O(n)` scans to `O(1)` probes (see the
`record_table.rs` module header). But four independent landings have now
measured its ceiling:

1. **The memory decomposition** (`eeb940630`, nix-bench memory columns):
   a single cold wide-eval peaks at **238 MiB vs C++ Nix's 77 MiB
   (3.1x)**. Of ~160 MiB live malloc at mid-eval: a **38.7 MiB record
   `Vec`**, a **12.3 MiB address map**, **179k × 160-byte records**, and
   the balance in `Arc`'d payload graphs. The record table and its index
   are pure representation overhead — bytes that exist only because
   payloads do not live at their addresses.
2. **The flat profile** (the profiling round behind `38da57c37`):
   allocator traffic was ~15% of on-CPU time, and the dereference path —
   address-hash probe + record load + `Arc` chase — was the recurring
   motif under every spine operation. (The ~15% figure is from the
   session profile that drove that commit, not from an in-tree artifact;
   see §11.)
3. **The B1 sweep decision** (`9422a34c8`, [06](06-memory-management-and-gc.md)
   §4 implementation note): the copying-vs-nonmoving fork was decided
   *by this representation*. Copying compacts almost nothing "because a
   `Value` is an opaque address key into the record side-table and object
   bytes live in refcounted payloads" — while carrying corruption risk
   through ~30 `payload_bits` address-identity sites. Tier-B's stage B2
   (the copying nursery) is explicitly gated on "value-rep flattening":
   this document is that gate's design.
4. **The tier-2 JIT landings** (`8c0680193`..`b307bbb53`): compiled Nix
   beats C++ Nix by 20–25x exactly where the grammar escapes the value
   plumbing — self-recursive arithmetic with zero helper calls, fused
   fold/genList loops, filter and `all`/`any` seams. `bench.compute.fib`
   collapsing from 650 MB to 30 MB RSS under JIT is the same fact from the
   other side: the cost was never the arithmetic, it was the per-value machinery.
   Extending the compiled grammar to allocating bodies (the alloc-family
   FFI the tier-2 handoffs name as the next unlock) requires objects
   with *fixed field offsets native code can write* — which the record
   table structurally cannot provide.

### 1.3 Why this is the campaign, not a pass

Each prior optimization round attacked work *volume*: fewer evals (root
cutoff, memo tiers, [29](29-tiered-content-keyed-memoization.md)), fewer
thunks (strictness, `6ab65fbf8`/`00c8ef665`), fewer interpreter steps
(tier-2). This campaign attacks work *unit cost* — the constant factor
under everything that remains. It decomposes into six coordinated
changes: the flat object layout (§2), value-word compression (§3), the
closure/environment architecture (§4), arena-owned payloads (§5),
dispatch follow-ups (§6), and a set of memory-management extensions
(§7). §2 is the keystone: §3, §5, §7, and Tier-B B2 are all gated on it.

---

## 2. The flat value representation (the keystone)

### 2.1 Target layout: header + payload at the pointed-to address

The design: a `HeapObject` becomes real. The bump arena's stable address
points at an **object header followed by the payload inline**:

```text
flat heap object (Tier-A arena, 8-byte aligned):

  ┌──────────────────────────────────────────────────────────────┐
  │ header word 0:  kind | size class | GC bits (mark, gen) | flags │
  │ header word 1:  structural hash / hash-cons key | shape id     │
  ├──────────────────────────────────────────────────────────────┤
  │ payload, inline:                                              │
  │   String  -> len + bytes (+ context ref)                      │
  │   List    -> len + [Value; len]                               │
  │   Attrs   -> shape id + [Value; slots]                        │
  │   Thunk   -> state word (claim protocol) + captured refs      │
  │   Lambda  -> pattern/body ids + captured env ref/values       │
  └──────────────────────────────────────────────────────────────┘
```

Dereference becomes **one load** from the address the `Value` already
carries. The address-hash probe, the record `Vec`, and the payload `Arc`
all disappear from the hot path. And because the arena is a bump
allocator, **allocation order is traversal order**: the attrset built
while walking a package body is contiguous with its strings and lists —
sequential spine locality that the three-allocator layout can never have.

The arena anticipated this. `heap/arena.rs` already defines
`OBJECT_HEADER_BYTES` (16), `THUNK_BYTES`, `LAMBDA_BYTES`,
`LIST_ELEMENTS_OFFSET_BYTES`, and `CONS_BYTES`, and its `HeapObjectKind`
enum sizes allocations per kind — the layout constants have been reserved
since the arena landed; this campaign finally writes bytes behind them.

### 2.2 Where every record-table field goes

`HeapRecord` (`eval/heap/mod.rs`) is the migration's checklist; each
field must land somewhere or be shown dead:

| `HeapRecord` field | Destination in the flat object |
| --- | --- |
| `ptr` | Becomes the object itself — the identity *is* the address; no index entry needed. |
| `layout` (size, align) | Header size-class bits (needed by the sweep's free-list and §7.4 slabs). |
| `structural_hash: Option<HotXxh3Hash>` | Header word 1. Hash-cons tables (`ratchet-value/src/hashcons.rs`) keep their bucket structure but collision confirmation compares flat payload bytes instead of chasing a record. |
| `allocation_domain` (Worker / PermanentShared) | Header flag bit (or, better, per-domain arenas — §7.4 — making it positional). |
| `generation: HeapGeneration` | Header GC bits. |
| `minor_gc_forwarding: Cell<Option<..>>` | A forwarding word, present only under Tier-B B2 (copying); absent in Tier-A layouts. |
| `last_touch_epoch: Cell<u64>` | The cold-value advice machinery's input; moves to a sparse side map with the cold hashes (below) — it must *not* stay inline, or every read re-dirties the object's cache line. |
| `object: HeapObjectValue` | The inline payload (§2.1). |
| cold hashes side map (`ColdHashMap`) | Unchanged — already sparse and off the hot path by design. |

The record table itself survives only as GC bookkeeping if at all: B1's
free-slot recycling becomes a per-size-class free list threaded through
retired objects' headers, and "retired" becomes a header state instead of
a `HeapObjectValue::Retired` payload swap.

### 2.3 Staged migration by value kind

The whole point of the staging is that byte parity is re-proven with one
representation variable moved at a time:

1. **Strings and paths, then lists** (first): self-contained payloads —
   bytes and `Value` cells — with no captured environments and no state
   machine. They are also the hash-consed immortal kinds
   (`string_cons`/`path_cons`/`list_cons` tables in `EvalHeap`), so the
   hash-cons key migration (§2.2) is proven here at the lowest risk.
2. **Attrsets** (second): `FlatAttrs` slots move inline; the header's
   shape-id word aligns with [09](09-attribute-sets-hidden-classes-and-inline-caches.md)
   — a PIC hit finally lands its guard + constant-offset load on real
   object memory, which is the layout Phase 5 assumes.
3. **Thunks, lambdas, primops** (last): thunks carry the claim protocol
   — the serial `ThunkCell` state machine, the optional boxed
   `TreeWalkParallelThunkCell` (~648 bytes, deliberately out-of-line
   today), the B1 capture-shedding transition
   (`EvalThunkKind::Released`), and the parallel claim/park discipline.
   The flat thunk's state word must reproduce all of it in place:
   suspend → claim → publish → shed as header/state transitions on one
   object, with the same release/acquire publication edges the
   `AtomicValueCell` documentation pins. This stage is last because it
   is the one that can create *torn-state* bugs rather than mere
   wrong-bytes bugs.

Each stage ships behind the full gate battery (§9.2) before the next
begins.

### 2.4 The parity-critical identity audit (`payload_bits`)

The record side table is not only overhead — it is where **address
identity** is currently anchored. The executable audit now classifies 65
accessor sites across 22 source files: 40 raw scalar/diagnostic reads,
five address-only reads confined to collector-free recursive walks, and 20
relocation-sensitive identities. The production subset is 63 sites across 21
files (40/5/18); the two additional relocation-sensitive sites are the
`cfg(test)` capture-plan validator, retained in the B2 worklist so moving-GC
tests cannot silently use stale identities. The families (the B2 repair
worklist, enumerated):

- **Force-cache and memo identity:**
  `eval/tree_walk/eval_core/force_identity.rs`, `eval_core/memo.rs`,
  `eval_core/force_payload.rs`, `eval_core.rs` — cache keys and
  force-capture identities derived from payload addresses.
- **Tier-1/tier-2 slot publication:** `eval/tree_walk/tier1_publish.rs`
  — compiled-entry slots keyed and validated by representation identity
  (the tier-2 landings re-check the self-callee upvalue "by
  representation identity at every boundary", `8c0680193`).
- **Pointer-equality fast paths:** `eval_compare.rs` (O(1) equality for
  identical heap values — sound *because* addresses are stable and
  hash-consing canonicalizes).
- **Environment cells:** `eval/env.rs` — `AtomicValueCell` stores raw
  tag/payload word pairs; `decode_value` reconstructs pointers from
  payload bits.
- **Serializers and codecs:** `eval_codec.rs`, `serialize_xml.rs`,
  `outcome.rs`, `eval_source.rs`, `eval_raw.rs`, `eval_trace.rs` —
  visited-set cycle detection and result encoding keyed by address.
- **Hash-cons interning:** `alloc_intern.rs` plus the heap's cons
  tables — bucket candidates compared and reused by address.
- **Heap/GC internals:** `eval/heap/{roots,gc,arena,shared_arena,shared_backend}.rs`
  — root sets, scan plans, shard resolution.
- **JIT lowering:** `ratchet-jit/src/lower.rs` and `lower/alloc_cons.rs` —
  payload words embedded as constants in compiled code; heap constants are
  rejected before either scalar or singleton-list emission site.
- **Shape instances:** `ratchet-value/src/attrs/shape/instance.rs`.

The campaign's §2 stages **preserve** this invariant: flat objects keep
the arena's stable, never-reissued addresses through the whole Tier-A
campaign. `Value` now names the distinction directly:
`payload_bits` is reserved for scalar decoding and diagnostics,
`address_identity_bits` marks a heap identity whose whole use lies in a
no-relocation interval, and `relocation_sensitive_identity_bits` marks a
key/reference that B2 must repair. The checked-in table at
`eval/heap/tests/payload_identity.rs` discovers Rust sources in
`ratchet-value`, `ratchet-oracle`, and `ratchet-jit`, pins per-file counts,
and gives every relocation-sensitive family a concrete B2 disposition.
Any new or reclassified production caller fails the audit until reviewed.
The five B2 repair slices now disposition all 22 callers in the original
production-sensitive worklist. `relocation_identity.rs` stages the live
survivor mapping before any
root or heap mutation, rekeys the lazy-identity/fold and tier-1 publish tables
after a successful live writeback commit, prunes dead young keys before nursery
address reuse, and clears the advisory unhashable-value memo. The JIT lowerer
rejects heap-backed constants before either embedding site emits constant CLIF
words, leaving no compiled address word to patch. Active, suspended, and
heap-captured lexical frames enumerate their `AtomicValueCell` payloads as
writable roots; the heap-field stage validates shared lambda/thunk capture
targets and defers their stores until the allocation-free live commit. Active
forces derive their side-table removal key from the relocated force root, and
raw/trace traversal state retains full `Value`s in writable transient roots
rather than copying address words across recursive evaluation. The
16-leg package matrix, compute x8, `bench.wide`, and all 646 current canonical
strict-JSON seeds in four execution modes stayed byte-green. Five interleaved
release A/B rounds against pristine `e613b5b19` measured zlib cold/warm at
-1.4%/-5.6%, wide at -0.6%/-2.3%, and JIT fib at +0.3%/+0.3%, with exact
7.5/67.5/160 MiB arena peaks; five-sample wide retained-RSS medians were 6.0%
lower cold and 3.9% lower warm. The final structural slice transactionally
stages rebuilt list/attr hashes and replacement hash-cons tables before any
collector field mutation, then publishes payloads, flat header hashes, stale
markers, and buckets in an allocation-free commit. Shaped-attr fingerprints
are transient collector-free walks: a dedicated no-safepoint accessor supplies
scalar payload or heap-address representation identity, so no persistent
fingerprint requires relocation repair. The force/render landing's full battery
remained byte-green, including all 645 generated strict-JSON seed expressions
in four modes. Five interleaved release
A/B rounds against pristine `a91f2ae31` measured zlib cold/warm at
-1.4%/-3.4%, wide at +4.0%/+3.4%, and JIT fib at +0.4%/-3.0%; retained-RSS
medians were lower in every comparison and the 7.5/67.5/160 MiB arena peaks
were unchanged. The structural landing's final suites passed 351
`ratchet-value`, 354 `ratchet-core`, and 3,030 `ratchet-oracle` tests (34
ignored), 322 `aos-nix` tests, 38 pinned language tests, and 32 Miri flat-heap
tests. Its differential battery was byte-green across the 16 package legs,
wide serial/K4/JIT/sweep-zero plus all three shape modes, compute x8, cache
validation, and all 648 generated strict-JSON seeds in four modes; the frozen
source-size offender set did not grow. Five alternating release A/B rounds
against pristine `51dddcb18` measured zlib cold/warm at -5.2%/-5.7%, wide at
+0.8%/+9.5%, and JIT fib at -0.05%/+0.74%. Median retained RSS moved about
+1.3% for zlib and +2.5%/+3.9% for wide cold/warm, while JIT fib was flat;
arena peaks matched exactly at 7.5/71.5/160 MiB.

The post-campaign live-JIT audit found one FV-5 integration regression hidden
by the tier-2 unit fixtures: those fixtures had not run capture-plan annotation,
while production did, and the promotion/dispatch guards still indexed only the
linked-frame suffix of `EvalEnv`. Production `fib` therefore reset promotion
every eight calls and interpreted about 1.03 million thunks. The repaired seam
resolves all tier-2 coordinates through the hybrid environment, guards the
curried-chain root def-site and reads the currently dispatched captures after
flat copying removes the old frame-prefix relation, and carries `EvalEnv` in
the pinned runtime context so native upvalue helpers can ask the tree walk to
validate flat-tail reads. The tier-2 fixture
families now annotate capture plans. Five-sample byte-parity medians against
C++ Nix 2.24.12 are 24.8x/29.2x faster for fib, 20.3x/20.1x for tak, and
28.0x/25.4x for sum-fold cold/warm; fib telemetry is one promotion, nine
dispatches, zero deopts, and 17 thunks. The opaque ABI signature is unchanged,
and the expanded runtime-context pointer decodes are count-pinned by the unsafe
audit. The landing remained byte-green across the 16 package legs, seven
wide/shape modes, compute x8, cache validation, and all 648 strict-JSON seeds in
serial/K=4/JIT/sweep-zero.

The follow-up strict-collection landing (`cffda6a76`) reuses the filter
predicate compiler for `builtins.all` and `builtins.any`, but gives them a
dedicated runtime loop so native execution stops at the exact short-circuit
element. A new `bench.compute.all-any` fixture makes the standing compute suite
x9. Five-sample medians against pristine `5179fb1c2` moved from 582.1 to
266.7 ms cold and 810.1 to 261.5 ms warm-mode; stock C++ Nix in the candidate
run measured 234.1/220.9 ms. Thus this seam closes the cold gap from roughly
2.5x to 1.14x while preserving byte identity and lazy error behavior.

### 2.5 GC integration: header-resident marks

The B1 sweep (`9422a34c8`) is record-table machinery today: mark states
live beside records, retirement swaps the payload enum, and the free
list is a `Vec<u32>` of slot positions (`record_table.rs`). Under flat
objects the sweep must learn **header-resident marks**: mark bits in
header word 0, retirement as a header state + size-class free-list link
written into the dead object's payload area, and the address-index
removal step deleted (there is no index). The fail-loud property changes
form but survives: Tier-A never reuses *addresses across region pops*
today; under flat objects with free-list reuse, the loud-failure
guarantee is carried by a header kind/epoch check instead of an
`UnknownPointer` map miss — an object resurrected at a reused address is
detectable by generation/epoch mismatch. This is a real weakening of
B1's "never reissue" simplicity and is called out as a risk (§9.4).

This section **is** the "value-representation flattening" that
[06](06-memory-management-and-gc.md) §4 names as Tier-B stage B2's third
gate. After §2 completes, copying's `O(survivors)` reset finally has
bytes to copy, and B2 becomes reachable.

---

## 3. Value-word compression: pointer tagging and 8-byte values

### 3.1 What is already reserved

The 16-byte `Value` is the Phase-1 baseline
([05](05-value-representation.md) §2), and the bit-layout contracts for
its successors are already pinned in safe code:
`ratchet-value/src/value/tag.rs` reserves the low three bits of every
8-byte-aligned heap pointer (`POINTER_TAG_BITS = 3`), names bit 0 as the
thunk `FORCED` shortcut, and provides checked encode/decode helpers that
deliberately do not dereference; `value/nanbox.rs` pins the NaN-box
layout contract; `value/small.rs` pins the 0/1/2-element inline
constructor contract. Doc [22](22-implementation-checklist-all-phases.md)
tracks these as P8 precursors. Platform assumptions are settled by C-24
(64-bit, 8-byte-aligned, canonical pointers; x86-64/aarch64 only).

Halving the value word matters because values are what containers hold:
**every attrset entry, list element, environment slot, and interpreter
stack cell is a `Value`**. An 8-byte value halves the payload mass of
exactly the objects §2 just made contiguous, and doubles the number of
values per cache line on the spine. §2 and §3 rewrite the same seams
(every allocation and access site), which is why they are one campaign:
the seams are opened once.

### 3.2 The i64 wall, restated

[05](05-value-representation.md) §2.1/§4.1 already worked this problem:
Nix's `int` is a first-class `i64` with the full range observable, and a
NaN-box payload (~48 usable bits) cannot hold it. Any 8-byte value
representation must choose where big integers go. Three candidates:

### 3.3 Candidate A: NaN-boxing — not the primary

NaN-boxing optimizes for a language whose native number is the double.
Nix is the opposite: `float` is the rare type. Taking on NaN
normalization, canonical-pointer masking, and the boxed-i64 fallback
*simultaneously* buys nothing over Candidate B (which gets the same
8 bytes with plain bit tests) except verbatim float storage — and floats
are cold in package eval. Candidate A remains a built-and-measured P8
variant per the budget mandate (`M-4`/`Q-E`), but it is not the
recommended primary. The `nanbox.rs` contract stays as its layout spec.

### 3.4 Candidate B: tagged word with immediate small ints

One 64-bit word; low-3-bit tag (the `tag.rs` reservation), with one tag
pattern meaning "immediate int, value in the upper 61 bits". Integers in
`[-2^60, 2^60)` — which is every length, index, timestamp, size, and
all but adversarial constants — stay inline; the rare out-of-range `i64`
boxes into an 8-byte arena cell (hash-consed, so each big constant
allocates once per eval). Bools/null are immediate tag patterns. Heap
values are the tagged address itself, with bit 0 doubling as the thunk
`FORCED` shortcut exactly as `tag.rs` reserves.

Cost: a shift on int construction/extraction, a magnitude branch on
construction, and a boxed fallback on the hottest *compute* type. Doc
[05](05-value-representation.md) §2.1 called boxing large ints
"unacceptable for the baseline"; the campaign does not contradict that —
the 16-byte baseline stays the oracle's representation until §2 is
byte-green — but the JIT profit census (`4515a9972`) materially weakens
the objection for the *variant*: package-eval bodies contain essentially
no native arithmetic (gated mass peaks at 2–5 native instructions), and
the workloads where integers are hot are exactly the tier-2 compute
benchmarks, which run unboxed in native registers past a one-time tag
guard (`8c0680193`).

### 3.5 Candidate C: compressed 32-bit arena indices

The JVM's compressed-oops move, enabled *by* §2: once every payload is
flat in one arena, a heap reference need not be a 64-bit pointer at all —
it can be a **32-bit byte offset from a single reserved arena base**,
addressing 4 GiB of heap (the current measured wide-eval arena peak is
83,361,792 bytes, leaving about 50x headroom). A `Value` becomes
`(tag: u32, offset: u32)` or a packed single word; container slots that
hold only heap references (list spines, attr slots after shape
classification) can shrink to 4 bytes.

Candidate C's distinctive advantages:

- **It sidesteps the NaN-box-vs-i64 problem entirely** at the 8-byte
  value size: the value word has a full 32-bit half free for tag bits
  and small immediates, and `i64` takes the boxed fallback exactly as in
  Candidate B (with a smaller inline-int range: 32-bit immediates
  instead of 61-bit).
- **Indices are not pointers.** Encode/decode is safe integer
  arithmetic; Rust pointer-provenance rules (which `tag.rs` documents
  itself dodging today by storing address bits without provenance) stop
  applying to the value representation. The unsafe surface concentrates
  into one place: the arena-base-plus-offset dereference. This is a
  material shrink of §8's audited zone relative to Candidate B.
- **GC- and parallel-friendly.** Offsets are position-independent:
  cross-worker handles in the shared arena (§9.4) and any future
  arena-remap/out-of-core spill ([06](06-memory-management-and-gc.md)
  §3.4) survive without pointer fixup; a B2 copying collector forwards
  by offset rewrite with no provenance laundering.

Candidate C's cost: it **requires a reservation-based arena** — one
contiguous virtual reservation committed on demand — where Tier-A today
allocates independent 2 MiB+ `mmap` chunks (`c11acc759`,
`heap/arena.rs`). That is a real prerequisite no earlier doc commits to,
flagged in §11. It also taxes every dereference with one add (base +
offset), which on modern cores is free in the addressing mode.

### 3.6 Recommendation

Staged, per the P8 build-the-variants-and-keep-the-winner mandate:

1. **The 16-byte `Value` is retained through every §2 stage.** Layout
   flattening and word compression must not land in the same stage;
   byte-parity bisection depends on one variable at a time.
2. **Candidate C (compressed indices) is the recommended primary** for
   the 8-byte value, *conditional on* the single-reservation arena
   landing cleanly. Rationale: package-eval spine mass is
   references-and-strings, not integers — C halves the same slots B
   does, while shrinking the audited unsafe zone and buying the
   parallel/GC properties for free. The 32-bit immediate-int range is
   the honest weakness; the compute benchmarks are the workload where it
   bites, and they are JIT-dominated.
3. **Candidate B is the fallback**, built to the same seams (the
   `tag.rs` contract) and selected if the reservation arena stalls or if
   compute-suite A/B shows the 32-bit immediate range regressing real
   workloads.
4. NaN-boxing (A) is built as the P8 measured variant it already is; it
   ships only if it beats the winner of B/C on the full benchmark
   matrix, per `M-4`/`Q-E`.

---

## 4. Environment architecture: hybrid closures

### 4.1 The measured invariant

`EvalEnv` (`crates/ratchet-oracle/src/eval/env.rs`) is
`Arc<[Arc<EvalFrame>]>`; a frame is a boxed slice of `AtomicValueCell`
slots. The module's own protocol documentation establishes the fact this
section builds on: **slots are written by the constructing thread while
the binding form is assembled, and are immutable after publication** —
every cross-thread hand-off passes a release/acquire edge, and readers
then see fixed tag/payload pairs. Frames are, today, *already
persistent-capable data structures with zero copy-on-write machinery
needed*: nothing mutates a published frame.

One honest caveat, from the same docs: slots are not literally
write-once. `let`/`rec` assembly writes slots incrementally, reads
interleave on the constructing thread, and **`__overrides` rewrites
already-written slots**. The invariant is *immutable after publication*,
not *write-once* — so the design below must pin the publication boundary
(the first capture that escapes the constructing form) as the point
after which a frame is frozen, and the `__overrides` rewrite must be
proven to happen before it. This is flagged in §11.

### 4.2 Today's cost

Capturing an environment — which happens at **every** thunk, lambda, and
primop-arg allocation — copies the entire frame *array*:
`EvalEnv::capture` allocates a fresh `Arc<[Arc<EvalFrame>]>` and clones
every frame `Arc` into it. The generation-keyed capture cache
(`38da57c37`: `env_capture_cache` keyed by `env_generation`, all
mutation sites routed through counter-bumping helpers in
`eval_core/module_env.rs`) amortizes consecutive captures of an
unchanged environment, but every env mutation invalidates it and the
copy is re-paid. The session profile behind that commit measured the
capture-array copy at roughly 251k per wide eval and total small
environment allocations near 599k (session-profiled figures — see §11),
and identified allocation traffic overall at ~45% of on-CPU time before
the cache landed. The capture copy is also a *retention* problem: a
thunk capturing a 12-frame stack retains all twelve frames until shed,
which is part of why B1 found 54% of the worker heap dead-at-end
(`9422a34c8`).

### 4.3 The hybrid design

One closure representation is wrong at both ends: flat capture of large
free sets copies too much; linked chains for two-variable lambdas pay a
pointer walk for nothing. The design — the GHC/OCaml/V8 convergence
point — is a **static, per-allocation-site choice** between two forms,
made by the front-end from free-variable facts:

- **Flat closure** (`|free set| <= K`, with the shipped `K = 2` selected by
  measurement):
  the closure/thunk object (flat, per §2) inlines the captured `Value`s
  directly after its header. Capture cost: `|free set|` value copies into the
  object being allocated anyway. Access cost: **one load at a constant
  offset** — no frame chain, no slot indirection. The lexical
  coordinates in the lowered IR ([25](25-intermediate-representation.md)
  §3) are rewritten by closure conversion into capture indices.
- **Linked persistent frame chain** (`|free set| > K`, or sites the
  analysis cannot prove): frames gain a parent pointer and environments
  become a chain instead of an array. Capture cost: **one pointer** (the
  innermost frame). Access cost: a depth walk bounded by the lexical
  coordinate's frame index — already static in the resolver's de Bruijn
  form. Structural tail sharing replaces array cloning: two thunks
  capturing sibling scopes share every common ancestor frame.

`with`-scope stacks (`EvalWithEnv`, today a `Box<[EvalWithScope]>` copy
per capture) and scoped-import globals (`EvalScopedGlobalEnv`) become
persistent cons lists under the same rule — capture is one pointer,
which matters because they are captured alongside *every* `Node` thunk
(`EvalThunkKind::Node` carries all three environments).

### 4.4 The analysis dependency

The site classification runs on Phase-4 facts. Chunk A landed the real
demand lattice and the intra-module fixpoint (`6ab65fbf8`); Chunk B
landed totality-licensed eager derivation-attr assembly (`00c8ef665`).
Chunk D then landed per-site free-variable sets, capture-mutability and
publication-boundary proofs, and single-use/escape refinement; FV-5 consumes
those facts for inline captures and persistent frame chains. Chunk E now adds
the next cross-module layer: analysis-version-7 lambda demand/escape summaries,
structural totality, static exact/all-except attribute provenance through
right-biased `//` and `removeAttrs`, persisted/remapped fact sidecars, and a
tree-walk call-site consumer that can elide binding thunks during safe formal-set
assembly. The same provenance seeds only surviving derivation-boundary values.
Fresh imports compute only these contracts plus capture plans; complete
intramodule strictness/cardinality/escape refresh remains on the durable-cache
path, avoiding a full demand walk for each of 496 cold imports. The final wide
work counters record 325 thunk elisions (215 during binding assembly) with the
arena peak memory-neutral at 67.5 MiB. An immediate five-sample A/B on the noisy
host measured mean wall -3.6% cold/-2.7% warm, recorded as a non-regression
rather than a broad speed claim. The remaining Phase-4 gap is the global
memoized closed-world fixpoint and worker/wrapper rewrite, not fact transport or
the current tree-walk consumer.

### 4.5 What dies

The capture-array copy dies at flat sites and shrinks to a pointer at
linked sites. The generation-keyed capture cache — machinery whose only
purpose is amortizing the array copy — **becomes obsolete at flat sites
and vestigial elsewhere**, and is expected to be deleted at the end of
the stage (`38da57c37`'s four counter-bumping helper seams are exactly
the mutation sites the persistent-chain design must instrument instead).
Transitive retention drops from "all frames in scope" to "the free set",
which directly feeds the B1 sweep's mid-eval effectiveness and the
238 MiB → ≤2x-of-C++ memory target (`eeb940630`).

---

## 5. Arena-owned payloads

Before FV-6 every thunk, lambda, and primop payload was an `Arc` in
`HeapObjectValue` (`eval/heap/mod.rs`), and strings/lists own separate
heap buffers. Reference counting is pure overhead in this heap: the
object graph is owned by the arena+record table, lifetimes are decided
by the B1 sweep or the end-of-eval drop, and the `Arc` counts decide
nothing — but they are bumped on every payload clone, resolution that
hands out an owned handle, and capture.

Under §2 the payloads *are* the arena objects, so this section is mostly
a consequence rather than a work item; it is stated separately because
it has its own gate: **reclamation moves from `drop`-the-`Arc` to the
sweep**. Before FV-6 B1 reclaimed by swapping the payload enum
(`HeapObjectValue::Retired`), letting Rust drop the `Arc` graph. Flat
payload bytes have no drop glue; anything a payload *references outside
the arena* (interned symbols, string-context elements — kept `Arc`-backed
by `38da57c37` deliberately, boxed parallel thunk cells) must either
move into the arena too, or be owned by a side structure the sweep
notifies. The header space §2 reserves for mark bits is what makes the
sweep able to reclaim payload bytes at all. Refcount traffic on the
clone-heavy paths (hash-cons confirmation, coercion fan-out from
`33ce21f9e`) disappears with the `Arc`s.

---

## 6. Interpreter dispatch (secondary, evidence-gated)

Two dispatch-level items ride behind the campaign, deliberately
separated by their evidence quality:

**Superinstructions — build against measured shapes now.** The JIT
profit census (`4515a9972`) is dispositive about *where* interpreted
time goes: package-eval bodies are attrset/string/list/apply plumbing
whose native-instruction mass peaks at 2–5, i.e. dispatch and operand
shuffling, not compute. The same census names the fusable families —
**string-interpolation (`Interp`), `List`, and `AttrSet` constructor
bodies, and nested `Select`/`Update` chains** — and the tree already
carries the precedent that fusing a measured shape pays
(`068f40598`'s one-pass `//` merge; `636b9c3ef`'s fold/genList fusion;
`b307bbb53`'s filter seam). Tree-walk superinstructions are the same
move inside `eval_core`: one handler for a fused node pair, added
shape-by-shape with a wall-time A/B per shape, never grammar-wide.

**Flat bytecode + explicit operand stack — only if the residual says
so.** Replacing the recursive tree walk with a flat bytecode loop over
an explicit operand stack would (a) remove segmented-stack transitions
from deeply recursive evaluation (goal-tracker item #49 is already closed
correctly by 256 KiB-red-zone/2 MiB-segment stack growth, with the semantic
default max-call-depth reached on a 512 KiB thread; tier-2's separate
1024-frame interpreter-headroom check remains in `8c0680193`), and (b) create
the stable interior execution states that OSR needs
([08](08-execution-tiers-and-cranelift.md)). But it is a
whole-interpreter rewrite with byte-parity risk everywhere, and the
census does *not* yet show dispatch as the top cost — the deref path
(§1) is. **Decision: measure-gated, not committed.** It is re-evaluated
only from post-§2–§4 profiles, if interpreter dispatch is then the top
residual. Until then segmented stacks plus the existing semantic depth
check reproduce C++ Nix's max-call-depth error without a native-stack
abort.

---

## 7. Memory-management extensions

Companion levers approved with the campaign (2026-07-09), each gated on
or unlocked by §2–§5. The first extension of the approved set —
compressed 32-bit indices — is treated as a first-class §3 candidate
(§3.5) rather than repeated here.

### 7.1 Closure/environment hash-consing (campaign follow-on)

The wide eval allocates on the order of 599k small environment objects
(session-profiled; §11), and the tier-up economics measurements say they
are heavily duplicated: the same `lib` scaffolding lambdas are
bit-identical across packages (the top hot bodies are shared-library
scaffolding — `lib/strings.nix`, `pkgs/default.nix` call sites — and the
source-keyed def-site census found 296 of 375 spine def-sites shared
across all five probe packages), applied to the same canonical values
across 273 package instantiations. Structurally identical environments
are allocated fresh every time.

Hash-consing them is blocked *today* by a settled decision: unforced
thunks are unhashable (C-15/S-15 — forcing-to-hash destroys laziness),
and today's captures are frame graphs full of thunks. §4 changes the
economics: a **flat closure's identity is `(def-site, captured value
words)`** — and when every captured word is an immediate or a
hash-consed canonical address (the common case for the lib-scaffolding
duplicates, whose captures are the same canonical `lib` attrsets), the
closure is hash-consable *without hashing any thunk*: address identity
of canonical captures substitutes for structural hashing, exactly as the
existing cons tables use address-equality confirmation. Closures with
non-canonical (thunk) captures simply decline interning — same
declined-admission pattern as MEMO-1
([29](29-tiered-content-keyed-memoization.md) §5.7).

Recorded as a **follow-on after the §4 stage**, not part of it: it needs
flat closures to exist, and its win must be sized against the §4 win
already banked (much of the 599k mass dies at capture time under §4
before interning could see it).

### 7.2 The semantic-swap eviction ladder (drop-and-recompute)

Nix evaluation has a property ordinary language runtimes lack: **almost
every heap object is a memoized result of a pure computation the
evaluator can redo.** Memory pressure therefore has a semantic response
ladder — trade recompute time for residency — rather than only a paging
response:

1. **B1 sweep** — reclaim the provably unreachable (`9422a34c8`).
2. **Capture shedding** — drop forced thunks' closure graphs (B1's
   other half; extended by §7.4's last-use shedding).
3. **Memo-tier eviction** — demote/evict L0/L1 records under the
   size-pressure policy already specified in
   [29](29-tiered-content-keyed-memoization.md) §5; a re-demand is an L2
   hit or a recompute, never an error.
4. **Cold module IR eviction** — drop lowered IR for modules with no
   live frames; the parse cache re-materializes a module in
   milliseconds (per-file artifacts, `nodes/parse-artifacts.index`), so
   module IR is a cache, not state.
5. **Thunk drop-and-recompute** (the deep rung) — drop a *suspended*
   thunk's work and re-create it on demand from `(module, node,
   captured identity)`, Adapton-style, using the same recursive
   content-keyed record identity MEMO-1 builds
   ([29](29-tiered-content-keyed-memoization.md) §3). This rung is
   research-grade until the §4 closure identity work lands (a
   recomputable thunk needs a durable identity for its captures).

Two explicit rejections, recorded with reasons:

- **Literal thunk serialization-to-disk is rejected.** A suspended
  thunk's captures reference the live heap graph (frames, `with`
  scopes, receiver values); serializing one means serializing its
  reachable closure — and thunk value-hashing is unsupported by design
  (S-15). Swap-by-recompute (rung 5) is the sound form of the same idea.
- **In-memory compression of evaluator data is rejected.** The OS
  already runs page-granularity compression under pressure (macOS
  compressed memory; zram on Linux hosts that enable it); adding zstd
  inside the process pays CPU to compress bytes the OS would compress
  anyway, against access patterns we would then have to decompress
  synchronously on the force path. **zstd is appropriate exactly where
  doc 29 puts it: the L2 disk sidecar packs**
  ([29](29-tiered-content-keyed-memoization.md) §5.4), where
  decompression amortizes against I/O.

### 7.3 Store-path segment interning

Derivation-heavy evaluation is textually dominated by store paths:
`/nix/store/<32-char-nix32-hash>-<name>` — a 44-byte prefix
(`/nix/store/` + hash + `-`) that repeats across `inputDrvs`, `env`
attribute strings, string-context elements, and every coerced dependency
reference, with whole paths repeated many times each. Byte compression
is the wrong tool (it taxes every access); **structural sharing is
free at access time**: intern path *segments* (store-dir, hash-name
stem, output suffix) in a permanent-domain segment table and represent
store-path-bearing strings as segment references — the same move symbol
interning makes for attribute names
([09](09-attribute-sets-hidden-classes-and-inline-caches.md) §3), and an
extension of what `38da57c37` already did for context elements
(`Arc`-backed, clones no longer deep-copy path bytes).

Sizing, honestly: the `eeb940630` decomposition did not split payload
mass by value kind, so the win is not sizable from existing artifacts.
The structural argument — string payloads are a large share of the
~90 MiB live working data and permanent hash-cons domain, and store
paths dominate derivation strings — justifies a **one-off counting
probe** (bytes in string payloads matching the store-path shape, unique
vs. total) as the stage's first deliverable; the interning implementation
is gated on that probe showing a multi-MiB dedup ratio.

The probe is now closed as a measured rejection. On the current
`bench.wide-eval` profile, all eligible store-path-shaped string payloads
together account for 1,250,076 bytes. Even an impossible 100% elimination
is below the required multi-MiB gate, so segment interning is not built;
the residual memory campaign stays focused on value-bearing storage.

### 7.4 Smaller committed items

- **Per-kind arenas.** Segregate allocation by object kind (at minimum:
  hash-consed immortal strings/paths/lists vs. sweepable worker
  thunks/attrs). The B1 sweep then scans only sweepable pages —
  today it iterates the whole record table and skips
  (`gc.rs`/`record_table.rs` retire-in-place) — and immortal pages need
  no mark bits at all. Also the natural place to make
  `allocation_domain` positional (§2.2).
- **Size-class slabs** for the measured populations (16-byte
  cons/value-pair cells and the thunk-sized class that replaces today's
  160-byte records, `eeb940630`), so the free-list reuse §2.5 introduces
  is exact-fit and fragmentation-free.
- **Last-use capture shedding.** B1 sheds at force-publish; cardinality
  facts ([07](07-laziness-and-whole-program-analyses.md)) prove many
  values are consumed exactly once, licensing shedding at the *last
  use* — before the force even completes, and for values that are never
  forced at all. The `SingleEntry` force-storage mode
  (`EvalThunkForceStorageMode`, `eval/heap/mod.rs`) is the existing
  proof that per-site analysis can select thunk storage regimes; this
  extends it from "skip publishing" to "release captures eagerly."
  Depends on Chunk-D facts (§4.4).
- **Weak hash-cons tables for daemon residency.** The permanent shared
  domain is immortal by design in one-shot mode; in a long-lived daemon
  ([14](14-integration-with-aos.md)) it is a slow leak. Weak-reference
  buckets (entries cleared when the sweep proves the canonical value
  unreachable from any root) bound daemon residency; one-shot mode keeps
  the immortal fast path. Gated on §2 (the sweep must be able to see
  hash-cons keys in headers to clear them).

---

## 8. Unsafe placement (decision, recorded)

**Decision (user directive, 2026-07-09; recorded here as the campaign's
placement rule, extending S-21's crate fence):**

> The tagged-pointer/compressed-index encode–decode and the
> inline-payload access `unsafe` introduced by §2–§3 lives in
> **`ratchet-value`**, as a new sealed, audited module family under the
> existing `heap/safety.rs` token-count discipline — **not in a new
> crate.** Complementarily, `#[forbid(unsafe_code)]` (or
> `deny(unsafe_code)` plus a CI lint where a scoped exception exists) is
> rolled out to every workspace crate except `ratchet-value`,
> `ratchet-runtime-ffi`, and `ratchet-jit`, making the sanctioned zones
> compiler-checked rather than convention-checked.

Why not a crate boundary: the value representation is inseparable from
the hash-cons, attrs, and list internals that already live in
`ratchet-value` (`hashcons.rs`, `attrs/`, `list.rs` all manipulate the
same words the flat layout redefines). A `ratchet-flat` crate would have
to export `pub unsafe fn` seams for exactly the operations that must
stay sealed — turning module-private invariants into cross-crate API
contracts, the opposite of containment. The precedent is
`ratchet-runtime-ffi`'s wrappers: the unsafe stays where the invariants
are provable, with the audit machinery co-located.

The discipline being extended is concrete and already enforced by test:
`ratchet-value/src/heap/safety.rs` pins the crate lint
(`#![deny(unsafe_op_in_unsafe_fn)]`), the `// SAFETY:` requirement,
second-reviewer sign-off, the sanitizer/miri/loom tool matrix, and — via
`reviewed_heap_unsafe_lines_keep_safety_comments_and_counts` — a
**per-file expected unsafe-token count** that fails the build when a new
unsafe operation appears without a review-table update (the file's own
history shows the process: "resident.rs count 4 -> 6", "advice.rs count
12 -> 13"). `ratchet-runtime-ffi/src/safety.rs` does the same with a
per-wrapper-family token allowlist. The campaign's new modules
(flat-object layout, tagged-word/index codec) get new entries in these
tables — new `HeapInnateUnsafeOperation` variants (inline-payload
access; tagged-word encode/decode or compressed-index dereference) and
new expected counts — per the documented update process, before any
unsafe lands.

**Implementation resolution (2026-07-09):** `ratchet-cache` is the
sanctioned fourth hand-written zone. Its new `src/safety.rs` manifest
pins all 20 mmap/lock/lease operations by file and requires the local
`# Safety`/`// SAFETY:` contracts. The oracle's region rewind moved
behind `Arena::pop_caller_validated_region_to_mark`; the raw rewind is
now value-crate-private and `ratchet-oracle` is `forbid(unsafe_code)`.
`ratchet-core`'s workspace-policy test discovers every crate root and
pins the four-zone set.

One generator-owned scoped exception remains, using the directive's
explicit `deny(unsafe_code)` + CI-lint branch: Buffa 0.3 generates 60
unsafe default-instance witness implementations in `aos-proto` (and
no unsafe blocks). They are confined to one private `generated` module;
`aos-proto/src/safety.rs` pins the four generated files, counts, and
three accepted trait families. This is not a sanctioned hand-written
zone. All hand-written protocol code stays under `deny`, and every
other non-sanctioned crate root uses `forbid`. The prior `aos` signal
reset also left Rust entirely: the hermetic fleet launcher now builds a
tiny C signal-reset trampoline before entering the AOS-built Bash
payload, preserving background-job Ctrl-C cleanup while allowing the
Rust binary to use `forbid`.

Implemented inventory (reviewed source operations, not comment/string
mentions; 2026-07-09):

| Crate | Unsafe ops | Lint today | Under the decision |
| --- | --- | --- | --- |
| `ratchet-value` | 55 heap operations | `deny(unsafe_op_in_unsafe_fn)` + per-file count manifest | Sanctioned zone; flat object/tail operations and the private arena rewind are pinned. |
| `ratchet-runtime-ffi` | wrapper-family allowlist | `deny(unsafe_op_in_unsafe_fn)` + token allowlist | Sanctioned zone (native ABI decoding/calls). |
| `ratchet-jit` | native-entry allowlist | `deny(unsafe_op_in_unsafe_fn)` + token allowlist | Sanctioned zone (code-pointer/native-entry calls). |
| `ratchet-cache` | 20 | `deny(unsafe_op_in_unsafe_fn)` + per-file count manifest | Sanctioned fourth zone (read-only mmap, advisory locks, immutable pack leases). |
| `aos-proto` generated module | 60 generated unsafe trait impls, 0 unsafe blocks | crate `deny(unsafe_code)` + one private scoped allow + generated count manifest | Generator-owned exception, not a hand-written sanctioned zone. |
| Every other workspace crate | 0 | `forbid(unsafe_code)` | Enforced by compilation and the workspace sanctioned-set test. |

`forbid` is preferred over `deny` wherever no exception exists, because
`forbid` cannot be `#[allow]`-overridden downstream. The only scoped
`deny` exception is the count-pinned Buffa output described above.

---

## 9. Sequencing and acceptance

### 9.1 When

The campaign starts **after Phase 5 (hidden classes + PICs; goal-tracker
item #41) lands.** The dependency is real, not calendrical: stage FV-2
(flat attrs) bakes a shape-id word into the attrs header (§2.2), so the
shape/PIC layout must be settled first or the header gets designed
twice. Phase-5 PICs also *amplify* the campaign — a PIC hit today still
terminates in a record probe; after FV-2 it terminates in a constant-
offset load, which is the whole point of the PIC design
([09](09-attribute-sets-hidden-classes-and-inline-caches.md) §5).

### 9.2 Stage order and the per-stage gate

```text
FV-1  strings/paths, then lists  ->  flat payloads, hashcons key migration proven
FV-2  attrsets                   ->  shape id in header, PIC lands on object memory
FV-3  thunks/lambdas/primops     ->  claim protocol + shedding as header states
FV-4  value-word compression     ->  Candidate C (fallback B), per §3.6
FV-5  hybrid closures            ->  after P4 Chunk D; flat FV + linked chains
FV-6  arena-owned payloads       ->  Arc removal; sweep owns reclamation
        (then: §7 extensions, each individually gated; B2 unblocked)
```

**Every stage** ships only through the full battery, which is the
week's proven landing pattern (B1, tier-2 landings 1–4, MEMO-1/2 all
shipped this way):

- **Byte-parity x4** (zlib/openssl/bash/coreutils): serial, `K=4`
  parallel, and `AOS_NIX_JIT=1`; plus `AOS_NIX_GC=sweep` and
  stress-threshold configurations for stages touching reclamation.
- **Compute suite x9** (`bench.compute.*`, including `all-any`) under default
  and force-promote JIT configs.
- **`bench.wide` / `bench.wide-eval`** (the 273-package root) in-bench
  parity.
- **The budgeted eval-json corpus** (`8f91742fd`) and its adversarial
  differential arms.
- **Perf A/B via nix-bench including the memory columns**
  (`eeb940630`): candidate <= baseline on time, and the
  `--memory-regression-threshold` gate on peak-RSS/arena gauges.
- **No size-gate offender growth** (`crates/aos-nix/tests/source_file_size.rs`).
- For FV-3 and any stage touching the parallel substrate: the loom/miri
  discipline of C-12/R-4 on the changed protocols.

### 9.3 Expected wins (honest ranges, tied to evidence)

- **Dereference-path shortening.** The probe+record+chase sequence
  (§1.1) is replaced by one load on every heap-value access. The
  bounded evidence: allocator traffic ~15% of on-CPU (session profile,
  §11) plus the address-map/record loads under every spine op. Honest
  range: this is a *mass removal* whose wall-clock yield depends on how
  memory-bound the spine really is; the campaign claims the mass, not a
  specific multiple. It is the same category of win as the
  symbol-table and store-validity removals that produced the existing
  cold-eval parity — architectural cost that vanishes rather than
  shrinks.
- **Memory.** The 38.7 MiB record `Vec` and 12.3 MiB address map fold
  into the objects; three allocations per value become one; §4 cuts
  capture retention; §7 items stack on top. Against the 238 MiB peak
  and the standing ≤2x-of-C++ (~154 MiB) target (`eeb940630`), the
  table/index/record consolidation alone is plausibly the largest
  single contributor, but ~90 MiB of live working data remains the hard
  core the extensions must attack.
- **Spine locality.** Allocation order = traversal order is claimed
  directionally (it cannot be measured ex ante); the mechanism is real
  and is the property copying GC would otherwise have to buy back.
- **JIT alloc-family unlock.** Flat objects with fixed field offsets
  are the precondition for compiled allocation (the alloc-family FFI
  named by the tier-2 handoffs — goal-tracker items #41/#43's
  consumers): tier-2 bodies that today blacklist at any allocating
  shape can construct strings/lists/attrs natively.
- **Tier-B B2 (copying) unblocked.** §2 closes the third B2 gate of
  [06](06-memory-management-and-gc.md) §4; the audit of §2.4 closes the
  second; B1 stress-proving continues to close the first.

### 9.4 Risks

- **The payload-identity audit** (§2.4): 65 audited sites across 22 files,
  mechanically split 40 raw / 5 address-only / 20 relocation-sensitive
  (63 production sites; two `cfg(test)` validator sites). Stable Tier-A
  addresses keep them sound through the campaign, but every stage must
  re-verify no site depended on *record
  table* semantics (e.g. `UnknownPointer` fail-loud shape changes under
  header-based retirement, §2.5). Mitigation: source discovery and exact
  per-file counts make drift fail the unit suite, and B1's stress-mode
  loud-failure discipline remains the proving tool.
- **Parallel shared-arena interplay.** The L2-P3a design
  (`eval/heap/shared_arena.rs`) exists precisely because payloads are
  *not* at their addresses: per-worker shards with stable record
  addresses are the cross-worker handles, and the module's header
  documents the side-table blocker verbatim. Flat objects make
  cross-worker reads a plain load — a simplification — but the
  **publication protocol must be preserved exactly**: single-writer
  shards, release/acquire hand-off, and the claim/park thunk discipline
  (`8770cf9d0`) now expressed on flat state words instead of
  `ThunkCell`s. FV-3 is where this bites; K=4 parity and the loom audit
  are the gate.
- **Hash-cons key migration.** Collision confirmation changes from
  record-payload comparison to flat-byte comparison; the
  `structural_hash` relocation (§2.2) must not change which values
  intern (interning changes are invisible to parity only if equality is
  unchanged — a subtle class of bug the FV-1 stage exists to flush at
  minimum blast radius).
- **Sheer surface area.** Every allocation site, every accessor, the
  sweep, the shared arena, the FFI wrappers, and the JIT lowering all
  touch these seams. Mitigation is the campaign's whole structure:
  six stages, one representation variable each, full battery per stage,
  and the token-count unsafe gates (§8) forcing every new raw operation
  through review.

---

## 10. Non-goals, and relation to the existing docs

### 10.1 Non-goals

- **No semantic or parity change.** No stage may alter `.drv` bytes,
  error classes, force order, or trace output; the campaign is
  representation-only.
- **Not the parallel-eval L2 completion.** The campaign simplifies the
  shared-graph story but does not deliver work-stealing whole-graph
  forcing; P3.5's remaining hard part stays its own line of work.
- **Not the JIT profit-promotion heuristic or the persistent
  compiled-body cache** — approved separately; the campaign only feeds
  them (alloc-family FFI, §9.3).
- **Not shipping NaN-boxing by default** — it remains a P8
  build-and-measure variant (§3.3).
- **No change to the memoization/persistence layer** — doc 29's record
  store is a consumer of value identity, not a party to this redesign
  (except §7.2's eviction rungs, which use its existing policies).

### 10.2 Relation to the doc set

- **[05](05-value-representation.md)** specified this trajectory —
  16-byte baseline (§2), pointer tagging (§3), measured 8-byte variants
  (§4), hash-consing (§5) — before the record side table existed as an
  implementation convenience. This document is doc 05's §§2–4 *executed
  against the code as built*, plus the compressed-index candidate doc
  05 did not consider. Where doc 05's checklist says "pointer tagging /
  NaN-box variant," the concrete plan now lives here.
- **[06](06-memory-management-and-gc.md)** §4's implementation note
  names value-rep flattening as B2's gate; §2 is that flattening, and
  §2.5/§7.4 restructure the B1 sweep it describes. The out-of-core and
  `madvise` machinery (§3.4–§3.6 there) composes unchanged.
- **[09](09-attribute-sets-hidden-classes-and-inline-caches.md)**: FV-2
  gives shapes and PICs the object memory their design assumes; the
  campaign's Phase-5 sequencing dependency (§9.1) runs through it.
- **[25](25-intermediate-representation.md)**: closure conversion (§4)
  consumes the scope-resolved lexical coordinates and adds a per-site
  capture plan to the facts the IR already persists (`facts.bin`
  versioning per `6ab65fbf8`).
- **[22](22-implementation-checklist-all-phases.md)**: the campaign
  annotates existing rows rather than replacing them — the P8
  pointer-tagging/NaN-box deliverables (now §3's B/C decision), the
  Tier-B B2 row (gate closed by §2), and the P3 arena rows (reservation
  arena, §3.5). Doc 22 carries the cross-phase summary rows for this
  campaign; the fine-grained tracker is §12 below.
- **[27](27-engineering-standards.md)** / **[28](28-generalization-and-language-dialects.md)**:
  §8 tightens S-21's crate fence to compiler-checked `forbid` and keeps
  the engine/dialect split untouched (everything here is `ratchet-*`
  substrate; no dialect surface changes).

---

## 11. Divergences, tensions, and unverifiable figures (flag, don't resolve)

Recorded per the doc-29 §13 convention; the code is ground truth where
they conflict.

1. **Session-profiled figures.** The ~15% allocator share (§1.2), the
   ~251k capture-array copies and ~599k small environment allocations
   per wide eval (§4.2, §7.1), and the ~45% pre-cache allocation share
   come from the profiling sessions that drove `38da57c37` and
   `eeb940630`, not from in-tree artifacts. The commits corroborate the
   *shape* (the capture cache exists because the copies were hot; the
   decomposition names the table/index/record masses precisely) but not
   these exact counts. The campaign's first checklist item adds the
   missing counters so its own A/B does not rest on unreproducible
   numbers.
2. **"Write-once slots" vs. `env.rs` as documented.** §4's premise is
   often stated as construction-only writes; the module docs explicitly
   describe incremental `let`/`rec` writes, interleaved reads, and
   `__overrides` rewriting already-written slots. The load-bearing
   invariant is *immutable after publication*, and the publication
   boundary is currently implicit (any escaping capture). §4 must make
   it explicit and prove `__overrides` precedes it; if a counterexample
   exists (an `__overrides` rewrite after a capture escapes), the flat
   plan for that site falls back to the linked chain.
3. **Doc 05 §2.1 vs. §3's boxed-i64 fallback.** Doc 05 calls boxing
   large integers "unacceptable for the baseline." §3 does not overturn
   that for the baseline — the 16-byte value survives the whole §2
   campaign — but both 8-byte candidates accept an i64 box in the
   variant, on the strength of the profit census's finding that
   package-eval arithmetic is cold. If the compute-suite A/B falsifies
   that, the 16-byte value is retained (doc 05's option 3) and §3 ships
   only the FORCED-bit tagging.
4. **The §8 crate list vs. the workspace as it stands.** The directive
   named three sanctioned crates while C-13 already required
   `ratchet-cache`. *Resolved 2026-07-09:* cache is the audited fourth
   hand-written zone with its own per-file manifest; the oracle rewind
   moved behind a safe value-layer handoff and the oracle now forbids
   unsafe. Buffa-generated protocol witness impls use the directive's
   separately count-pinned scoped-exception path and do not expand the
   hand-written zone set. Doc 27's planned `ratchet-gc` and
   `ratchet-parallel` crates remain unnecessary: GC lives in
   `ratchet-value`/safe oracle code and parallelism in the safe oracle.
5. **Candidate C's arena prerequisite.** Compressed indices require a
   single contiguous reservation; the Tier-A arena is chunked mmap
   (`c11acc759`). *FV-4 resolution:* the real 4 GiB reservation,
   byte-offset index space, codec, and shared-mode flat-store migration
   are now landed (§12 FV-4). Every production shared flat store publishes
   geometric object runs into one common reservation, so those addresses
   now have checked `u32` offsets. Active adoption still requires migrating
   the serial flat arena and changing the evaluator/FFI/JIT value ABI.
6. **B1's fail-loud shape changes under flat objects.** Today a stale
   handle to a retired record fails as an `UnknownPointer` map miss;
   with the index gone, §2.5 substitutes header epoch/kind checks. This
   is a *different* (and slightly weaker) loud-failure mechanism than
   the one B1's soundness argument cites; the stress-mode suite must be
   re-derived for it.
7. **`value/small.rs` overlap.** The 0/1/2-element inline-constructor
   contract predates the flat layout and overlaps FV-1/FV-2's inline
   payloads (a flat list *is* inline). The small-constructor pointer
   tags (b1..b0 per doc 05 §3) must be reconciled with the header
   size-class bits so the same information is not encoded twice.
8. **Doc 29 §5's residency tiers and §7.2's ladder** describe eviction
   from two vantage points (record store vs. heap). They compose, but
   the trigger machinery (the memory-budget escalation of
   [06](06-memory-management-and-gc.md) §3.6, `EvalHeapMemoryBudget*`)
   must drive both from one policy or the ladder's rungs will fire in
   the wrong order.

---

## 12. Implementation checklist

Per the [22](22-implementation-checklist-all-phases.md) conventions:
deliverables with module paths, per-stage gates, and falsifiable exit
criteria. The **standing gate battery** for every `[ ]` below is §9.2
(byte-parity x4 serial/K=4/JIT, compute x9, `bench.wide`, eval-json
corpus, nix-bench perf+memory A/B, no size-gate offender growth); items
list only their *additional* gates.

### Stage FV-0 — instrumentation and prerequisites

- [x] Campaign counters: capture-array copies, environment allocations,
      per-kind payload byte mass (strings split by
      store-path shape for §7.3), deref-resolution counts — in
      `EvalStats` + the `AOS_NIX_EVAL_STATS` JSON dump
      (`eval/tree_walk/eval_stats.rs`, `eval/heap/alloc_counters.rs`).
      Exit: the §11-flagged session figures are reproducible from a
      stock build.
      *Landed (FV-0): the nested `campaign` block
      (`eval/tree_walk/campaign_counters.rs`) carries record-table probes
      by kind, flat resolutions, payload `Arc` clones, capture-copy
      count+bytes, frame-allocation count+bytes, and per-kind payload
      byte mass with the store-path split. Environment-allocation
      *size-class histograms* remain open.*
- [x] The `payload_bits` identity classification table: every §2.4 site
      tagged {address-identity-only | relocation-sensitive}, checked in
      as a reviewed table (extends the B1 audit). Exit: table complete;
      B2's rehash-hook worklist derivable from it.
      *Landed: the sealed `Value` API distinguishes raw scalar/diagnostic
      bits, address-only identities, and relocation-sensitive identities.
      The executable audit pins 40/5/20 sites respectively across 22 source
      files and records the required root writeback, side-table rekey,
      structural-hash rebuild, compiled-constant patch/reject, or no-repair
      disposition for every family. The production subset is 40/5/18 across
      21 files; two `cfg(test)` capture-validator sites remain deliberately in
      the worklist. Test directories and `tests.rs` modules are excluded;
      UFCS and method-call spellings are both counted.*
- [x] Compiled-root prerequisite for B2 relocation and Tier-B reclamation:
      finalized Cranelift SP offsets are joined to live intrusive frame
      bindings, moving-GC root plans have a transactional two-word slot
      writeback path, and mapped force safepoints automatically run the
      non-moving sweep with nested compiled roots registered. Every currently
      emitted tier-1/tier-2 force call is mapped, including live operands across
      arithmetic-tree calls and module-local tier-2 inner bodies. Physical
      stack-address anchors select finalized maps without depending on backend
      block order. Future
      unmapped sites fail closed by skipping collector dispatch. Allocation-site
      maps and automatic moving-minor-GC plan application remain outside this
      slice.
- [x] P4 **Chunk D** — per-def-site free-variable sets, capture
      publication-boundary proof, single-use/escape refinement
      (`ratchet-core/src/analysis/` beside `strictness/` and
      `escape.rs`); facts persisted behind an `IR_ANALYSIS_VERSION`
      bump. Gate: adversarial differential arms for `__overrides` and
      rec-forward-reference capture shapes. Exit: every lambda/thunk
      def-site carries `|FV|` + a capture plan or an explicit decline.
      *Landed in the P4 Chunk-D landing and extended for FV-5:
      analysis version 5 introduced both the per-site `CapturePlan` and
      constant-index `FlatCaptureAccess` facts; the current
      `IR_ANALYSIS_VERSION = 7` additionally persists structural totality and
      cross-module lambda demand/escape summaries. Dynamic
      scope, over-width, and conservative publication sites retain an
      explicit `SharedChainReason`; the recursive-assembly validation arms
      cover deferred publication after `__overrides` and forward-slot
      writes.*

### Stage FV-1 — flat strings, paths, lists

- [x] Flat object header (kind, size class, GC bits, hash word) +
      inline string/path byte payloads and list `Value` spines, in a new
      sealed `ratchet-value` module family (e.g.
      `ratchet-value/src/heap/flat/` or `value/flat/`); arena writes
      real bytes behind the reserved `heap/arena.rs` layout constants.
      *Landed (FV-1a/FV-1b/FV-1 lists): `ratchet-value/src/heap/flat.rs`
      writes header (kind word, hash word, atomic epoch word) + payload
      in place for strings, paths, and lists (serial mode). String and
      path *bytes* are inlined after the payload struct
      (`alloc_with_trailing_bytes` + the sealed `FlatBytes` witness in
      `heap/flat/bytes.rs`) up to a 4 KiB inline cap — the measured
      `string-builder` worst case shows inlining oversized quadratic
      accumulator products pays an O(bytes) copy and bloats the arena
      peak, so large payloads keep their moved owned buffer as FV-1a
      stored them. The accessor stays `&NixString` via an internal
      owned-vs-flat byte-storage representation whose
      equality/hash/clone semantics are slice-defined and
      representation-independent; the flat stores also cap their
      arenas' chunk doubling (32 MiB) so the mapped peak tracks the
      payload mass. Shared mode publishes flat objects
      per shard through `heap/flat/shared.rs`
      (`SharedFlatObjectStore`): safe chunked `OnceLock` slots whose
      stable address is the handle, resolved by membership arithmetic
      with no address index, preserving the P3a release/acquire
      publication protocol exactly (shared bytes stay `Vec`-owned).
      List spines remain `Vec<Value>` behind the flat object — the
      inline `Value`-spine layout rides with FV-2's inline attrs slots.
      The four list GC couplings are wired: the B1 sweep's
      permanent-edge seeding (`eval/heap/gc.rs`), worker-region-pop
      retained-edge validation over the flat registry
      (`eval/heap/arena.rs`), collector-poll edge snapshots plus
      staged direct heap-field writebacks committed through the flat
      store's exclusive `resolve_mut` door (`eval/heap/roots.rs`,
      `HeapFieldWriteTarget`), and `scan_flat_list_edges` beside
      `scan_record_edges`.*
- [x] Hash-cons migration: `hashcons.rs` collision confirmation over
      flat payload bytes; `structural_hash` resident in the header.
      Gate: interning-rate counters unchanged vs. baseline (same values
      intern), plus the standing battery.
      *Landed for strings/paths/lists: confirmation compares the header
      hash word + flat payload; dedup semantics unchanged (interning
      counters byte-identical on the probe workloads). A collector-poll
      writeback that rewrites a flat list element marks the address's
      header hash stale in a sparse side set (the flat analog of a
      record commit's `structural_hash = None`), so admission never
      dedups against a rewritten spine.*
- [x] `heap/safety.rs` audit-table extension: new
      `HeapInnateUnsafeOperation` variants (inline payload access) +
      per-file token counts, second-reviewer sign-off, miri/ASan on the
      new modules (§8). Exit: safety tests green with the new counts.
      *Landed: `FlatObjectPayloadAccess` variant; `flat.rs` allowlisted
      at 5 audited unsafe operations. Extended for FV-1b/lists: `flat.rs`
      now 8 (trailing-bytes copy + placement write, `resolve_mut`) and
      `flat/bytes.rs` 3 (the `FlatBytes` witness read + `Send`/`Sync`
      impls); `heap/flat/shared.rs` is deliberately safe code only.*
- [x] Record-table bypass for migrated kinds in
      `eval/heap/{mod,record_table}.rs` and the shared arena
      (`shared_arena.rs`, `shared_backend.rs`): resolution for
      string/path/list is one load; records no longer allocated for
      them. Exit: wide-eval record count and record-`Vec`/addr-map
      bytes drop by the string+list share (memory columns).
      *Landed for strings/paths/lists in both modes: serial resolution
      is membership-check + header load (`eval/heap/flat_values.rs` +
      `flat_values/lists.rs`); shared-mode resolution is per-shard flat
      slot membership with no private-index or cross-shard `RwLock`
      probe (`shared_backend.rs` over `heap/flat/shared.rs`). No
      records or record slots are allocated for the three kinds in
      either mode.*

### Stage FV-2 — flat attrsets

- [x] `FlatAttrs` slots inline; shape id in header word 1; PIC/select
      caches read the header (`ratchet-value/src/attrs/`,
      `eval/tree_walk` select paths). **Sequenced after Phase 5** so
      the shape layout is final (§9.1). Gate: iteration-order
      conformance ([09](09-attribute-sets-hidden-classes-and-inline-caches.md)
      §7) re-pinned; `068f40598` merge telemetry unregressed.
      *Landed (FV-2) with one documented divergence from the sketch:
      the shape metadata rides at the **front of the payload**
      (`FlatAttrsPayload` in `eval/heap/flat_values/attrs.rs`), not in
      header word 1 — the header keeps the full 64-bit hash-cons key
      for every kind (splitting it would weaken collision confirmation
      crate-wide, and the three-field `EvalHeapAttrsMetadata` does not
      fit a half-word anyway), while the leading payload position keeps
      the select-cache guard load header-adjacent with no record probe.
      A header-resident shape id remains an FV-4 candidate alongside
      size-class bits. Serial and shared modes both flatten attrsets
      (`FlatObjectKind::Attrs`; shared slots publish the same payload
      struct through `heap/flat/shared.rs` unchanged); no records or
      record slots are allocated for attrsets in either mode, and the
      `//` merge/update paths allocate their results flat with no
      record+index insert per merge product. All four list GC couplings
      are extended to attrs (`AttrBinding`-labelled edges): sweep
      seeding, region-pop retained sources, collector-poll
      snapshot/staleness/writebacks through `resolve_mut` with the
      shared stale-hash side set (`flat_stale_hashes`), and
      `scan_flat_attrs_edges` beside the list scan. The §11.7
      `value/small.rs` boundary is resolved by retirement: the
      0/1/2-element inline-constructor contract had no consumers and no
      assigned tag bits, so the module is deleted and the boundary note
      lives in `heap/flat.rs`. Zero new unsafe operations (the sealed
      generic store hosts the new payload type as-is). After FV-2 the
      record table's population is worker-domain thunks/lambdas/primops
      only; the permanent-shared typed-allocation vtable
      (`runtime/alloc.rs`) is now dead in lib builds and is FV-3 /
      retirement fodder.*

### Stage FV-3 — flat thunks, lambdas, primops

- [x] Thunk claim protocol as flat header/state words: suspend → claim
      → publish → shed transitions with the existing release/acquire
      contract; serial `ThunkCell`, `SingleEntry` mode, and the boxed
      parallel payload cell re-expressed (`eval/heap/thunk.rs`,
      `eval/thunk*.rs`, `eval/parallel_force*`). Gate: standing battery
      **plus** `AOS_NIX_GC=sweep` + stress-threshold-0 + K=4 claim/park
      parity, and loom/miri on the changed protocol (C-12/R-4
      discipline).
      *Landed (FV-3) with two documented divergences from the sketch,
      both decided by code reality (`eval/heap/flat_values/closures.rs`
      records the rationale):*
      1. *Interior-`Arc` payload, not in-place state words.* The flat
         closure object is header + `FlatClosurePayload` (an `Arc`
         handle per kind). `get_thunk` (229 call sites) hands out
         `&EvalThunk` and `clone_thunk` hands out `Arc` clones the
         force paths hold across `eval_thunk_body` re-entry and across
         the shed swap; making the flat object the shared mutable site
         would have been a viral borrow rewrite of the whole tree walk.
         The claim protocol therefore stays in the payload's interior
         `ThunkCell`/parallel-cell atomics exactly as it was, and the
         shed/retire transitions are whole-payload swaps through the
         store's exclusive `resolve_mut` door — the same swap the
         record slot hosted. The record *probe* dies now (the FV-3
         target); the payload `Arc` dies in FV-6 (arena-owned
         payloads), keeping one representation variable per landing.
      2. *Placement is mode-selected, not total.* The collector-poll /
         minor-GC machinery (destination reservation, byte copies,
         forwarding headers, generation writes — the Tier-B B2
         relocation proving ground) and the Tier-B transition-admission
         generation rewrites operate on record-table worker objects,
         and after FV-2 the young population is exactly these kinds.
         Porting relocation to flat objects *is* B2, which this campaign
         gates rather than delivers. Worker-closure placement is
         therefore `WorkerClosurePlacement::{Flat, Record}`: every
         production heap allocates flat (serial and shared), and heaps
         under an installed `GcStressPolicy`, a generational
         write-barrier tier, or the explicit
         `TreeWalkOptions::set_record_worker_closures_for_gc_scaffolding`
         option keep the record layout so the B2 scaffolding and its
         proving-ground tests stay green. Resolution, region pops, and
         the sweep handle both populations (each empty in the other
         mode).
      *Serial mode: one `FlatObjectStore<FlatClosurePayload>` hosts all
      three kinds (`FlatObjectKind::{Thunk,Lambda,Primop}`), so one
      registry mark covers a worker lexical region across kinds; worker
      arena stats/advice fold the store's arena. Shared mode publishes
      closures per shard through `SharedFlatObjectStore` (the FV-2
      protocol, `OnceLock` release/acquire): sound because the payload
      handle is never swapped after publication — shedding and the
      sweep are serial-only by the existing quiescence pins — while
      thunk force state keeps mutating through the payload's interior
      atomics. This retires the shard record slots' worker population
      and the worker-private address mirror; cross-worker closure
      resolution is membership arithmetic with no `RwLock` index
      probe.*
- [x] B1 sweep over flat objects: header marks, per-size-class free
      lists, epoch/kind fail-loud checks replacing `UnknownPointer`
      map-miss semantics (`eval/heap/gc.rs`, `eval/gc_*`). Gate: the
      re-derived stress suite (§11 item 6); shed/retire counts match
      baseline behavior on zlib and `bench.wide`.
      *Landed with a simpler reclamation shape than the sketch: no
      free lists and no header state bits. Sweep retirement swaps the
      payload for a `FlatClosurePayload::Retired` tombstone in place —
      the entry, header, and address remain, addresses are **never
      reissued** (stronger than §2.5's epoch-guard alternative; §11
      item 6's re-derivation is unnecessary because the loud-failure
      shape did not weaken: a retired address fails as
      `UnknownPointer` from the payload check, and any resolution of a
      wiped/popped address fails the header magic check). Slot
      recycling is deliberately dropped: the tombstone is
      header+handle-sized (~40 B) versus the recycled 160 B record, so
      retire-in-place costs less than the machinery it replaces; exact
      per-size-class free lists remain FV-6/§7.4 material if daemon
      workloads ever need them. Region pops reclaim for real:
      `FlatObjectStore::pop_region` drops payloads, wipes header kind
      words, and rewinds the store's arena (LIFO address reuse, the
      record-table pop contract), fenced against retirement by the
      same `RegionPopAfterSweep` interlock extended with the flat
      retired count. Pop validation checks retained edges in both
      directions across both populations (records, flat lists/attrs,
      and flat closures as sources; record suffix plus flat-closure
      suffix as targets).*
- [x] Retirement (the FV-2 handoff's enumerated fodder): the dead
      permanent-shared typed-allocation vtable family
      (`runtime/alloc.rs`: `PermanentSharedAllocationVTable`, its
      entrypoint/ABI tables, routing fns, and vtable tests — a
      test-only `test_alloc_string` keeps the permanent domain's
      accounting/advice/poll machinery covered) and the
      never-constructed `HeapObjectValue::{Path, Attrs}` variants with
      every match arm. **`HeapRecordTable` and its address map are
      retained, unpopulated in production**: their only remaining
      population is the B2 proving ground's record-placed closures, so
      `record_table_records` reads 0 on every production workload
      (including `bench.compute.lambda-interp`'s former 11M-record
      peak) while the relocation scaffolding keeps its subjects. The
      table retires outright when B2 lands on flat objects (or is
      abandoned). The `record_or_unknown` per-kind fallback survives
      only on the flat-miss path, which production never takes.

### Stage FV-4 — value-word compression

**Landed (FV-4) as the compatible-layout subset and now re-entered with a
real Candidate-C reservation/index/codec substrate; the active 8-byte
value word (Candidates B and C) remains open and separately gated:**

1. *The §11.5 reservation prerequisite is no longer hypothetical.* In
   addition to the original feasibility probe, `heap/reservation.rs` now
   maps the actual demand-paged 4 GiB Candidate-C address space, bumps
   aligned objects within it, checks both pointer/index directions
   against the used prefix, supports caller-validated rewind, and releases
   the exact mapping. `value/compressed.rs` seals the corresponding
   high-32-bit kind/metadata + low-32-bit payload word, including inline
   `i32`, typed boxed-scalar/heap indices, and the thunk `FORCED` bit.
2. *The shared-mode structural blocker is closed.* One
   `SharedHeapArena` now owns one demand-paged 4 GiB reservation shared by
   every worker shard and typed flat store. Each store allocates geometric
   object runs from that address space and keeps compact `AtomicU8`
   publication sidecars; exact range/stride membership plus Release/Acquire
   publication replaces the boxed `OnceLock<SharedFlatObject<T>>` slot.
   Stores still return the active native-pointer handle, but every such handle
   also round-trips through the common checked `u32` index space. Unsupported
   platforms retain the boxed compatibility backend. Serial flat objects
   remain outside this reservation and are now Candidate C's store blocker.
3. *The current memory profile reopens the measured case.* On pristine
   `951159cc9`, `bench.wide-eval` maps 83,361,792 arena bytes and retains
   181,747,712 bytes cold / 190,382,080 bytes warm, while the sampled
   stock child peak is 91,684,864 bytes. Value-bearing mass includes
   145,557 list slots (~2.33 MB at 16 bytes), 295,810 flat-capture slots
   (~4.73 MB), and 4,148,192 environment-slot bytes before attr slots and
   other value storage. This does not predict the final delta, but it
   satisfies the reason to build and measure the compressed variant.
4. *Sequencing.* §3.6 rule 1 forbids landing layout flattening and
   word compression as one variable; the subset below rewrites the
   payload layouts and is itself §3.5's "container slots narrowed"
   prerequisite. FV-5/FV-6 have landed and the current inactive
   Candidate-C substrate passes independently. Shared publication is now
   reservation-backed; serial-store migration and evaluator/FFI/JIT ABI
   conversion remain their own gates.

- [x] **Single shared permanent-domain flat arena** (the FV-2/FV-3
      handoff's per-type chunk-slack kill): `SharedFlatStoreArena`
      (`heap/flat/backing.rs`), one bump arena hosting the
      string/path, list, and attrset stores through a single-threaded
      handle; each store keeps its registry plus an allowed-kind set
      (`FlatKindSet`) so the header kind word stays a sound payload
      type witness over interleaved chunks; typed resolution rejects
      foreign kinds before any cast, region marks/pops are rejected on
      shared backings (the popping worker-closure store keeps its
      owned arena), and arena stats/advice are read once through the
      handle (`EvalHeap::flat_arena`). Gate met: arena gauges + budget
      machinery read true (permanent columns fold the shared arena
      once); memory columns moved down, not up.
- [x] **Inline attrset arrays — and a measured NO on inline list
      spines** (doc 30 §2.3's inline payloads, generalized from FV-1b
      bytes): `FlatSlice<T>` typed inline-run witness +
      `FlatTailLayout`/`FlatTailWriter` (`heap/flat/slice.rs`) and
      `FlatObjectStore::alloc_with_trailing`; `FlatAttrs` gained
      two-variant storage (owned `Vec`s for temporaries/shared-mode/
      cache payloads; flat witnesses for serial heap-resident values,
      capped at 4 KiB of tail per object — the FV-1b oversized-payload
      cutoff, which an uncapped build violated at 15-20% wall on
      `bench.compute.attr-fixpoint`'s large-unique-attrset churn) with
      clone-deep-copies-to-owned escape semantics (the `NixString`
      FV-1b pattern). An interned small attrset carries none of its
      three arrays (entries, source order, iteration order)
      out-of-line. **List spines stay a moved owned `Vec`**: a fresh
      interned list pays copy-plus-`Vec`-teardown where the move is
      free, churn workloads are ~all hash-cons misses
      (`bench.compute.qsort` held ~+1.5% wall under 4096- and 512-byte
      caps, and ~+1% from the two-variant spine enum's access-path tag
      alone), and no package/wide workload showed a spine win — so
      `NixList` keeps its plain contiguous-`Vec` representation and
      the checklist's list half closes as
      rejected-by-measurement. Collector writebacks replace payloads
      with owned storage (stress modes only; the abandoned inline run
      is dead arena padding).
- [x] **Header size-class bits** (the FV-2 handoff's deferral): the
      kind word is now `magic:32 | aux:24 | kind:8`; `aux` carries the
      saturating payload cardinality (byte length for strings/paths,
      element count for lists, entry count for attrsets;
      `FLAT_AUX_SATURATED` = consult the payload). No hot path
      consumes it yet — it pins the header classification field the
      compressed layout plans against, and resolution validity still
      checks only magic + kind.
- [x] **Candidate-C reservation/index/codec substrate:** one contiguous
      demand-paged 4 GiB reservation with `u32` byte offsets, absolute
      alignment, checked used-prefix pointer/index conversion, LIFO rewind,
      cross-worker ownership, and exact unmap; plus a sealed 64-bit word
      codec for inline `i32`, booleans/null, boxed `i64`/`f64`, typed heap
      indices, and the thunk `FORCED` bit. The unsafe manifest pins seven
      reviewed operations. The active evaluator still uses the 16-byte
      `Value`, so this row proves the prerequisite without claiming the
      Candidate-C or FFI/JIT ABI rows below. The landing gate passed 360
      `ratchet-value` tests, the core/JIT/oracle/aos-nix/runtime-FFI/cache
      suites, all 16 package byte legs, compute x9, wide-eval in four modes,
      zlib/wide cache validation, and all 645 strict-JSON seeds in those four
      modes. A baseline-first three-sample release A/B was regression-free:
      zlib candidate/baseline medians were ~1.020 cold and ~1.015 warm;
      wide medians were ~1.047 cold and ~0.854 warm. Wide arena peak was
      exactly 83,361,792 bytes in every baseline and candidate sample; noisy
      retained-RSS maxima stayed within the 10% gate. This is intentionally a
      no-regression substrate result, not a compression speed or memory claim.
- [x] **Candidate-C shared flat-store adoption:** the reservation bump cursor
      is atomic and eight-writer tests prove disjoint aligned ranges; one
      production `SharedHeapArena` supplies the same reservation to every
      shard's string/path, list, attrset, and thunk/lambda/primop store.
      Geometric reserved object runs preserve stable addresses, compact
      `AtomicU8` sidecars publish each slot with Release/Acquire ordering, and
      exact range/stride checks reject foreign and interior pointers before the
      typed cast. The compatibility constructor retains boxed `OnceLock`
      levels for unsupported mappings and isolated tests. Store drop destroys
      every published payload before the last reservation owner unmaps it;
      `heap/safety.rs` pins the three reviewed placement/resolution/drop unsafe
      operations. Production K=4 tests prove cross-shard resolution and one
      common offset space. This row does not change the active 16-byte `Value`.
      The full landing gate passed 364 value tests; 3,037 active oracle tests
      after an isolated rerun of the known parallel environment-counter flake;
      the core/JIT/runtime-FFI/cache/aos-nix and 38-test language suites; all 16
      package byte legs; compute x9 under JIT; wide-eval in
      serial/K=4/JIT/sweep-zero; zlib/wide cache validation; and all 648
      selected strict-JSON expressions in those four modes. The frozen global
      source-size gate remains pre-existing red; the touched production files
      are 573 and 937 lines. A baseline-first three-sample K=4 wide release A/B
      against pristine `adbd59d22` moved native means from 3.515 to 3.415 s
      cold and 3.247 to 2.903 s warm (-2.8%/-10.6%); retained-RSS maxima moved
      from 629.1 to 562.8 MiB cold and 642.1 to 527.7 MiB warm
      (-10.5%/-17.8%). Legacy shared record storage still dominates total RSS,
      so this is a non-regressing shared-flat migration, not the final
      beat-stock-Nix memory claim.
- [ ] Candidate C: compressed 32-bit index `Value` behind the sealed
      codec module; container slots narrowed where profitable. Boxed
      hash-consed `i64` cell for out-of-range ints. **The reservation, codec,
      and shared-mode flat-store adoption are landed; serial-store migration
      and the active ABI conversion remain.**
- [ ] Candidate B: tagged 61-bit-immediate word to the `value/tag.rs`
      contract, same seams, built for the head-to-head. **Deferred
      with C (same re-entry conditions).**
- [ ] The B-vs-C selection: full benchmark matrix (packages + compute +
      wide + memory columns) per the P8 build-and-select mandate;
      closes doc 22's P8 pointer-tagging row and feeds `M-4`/`Q-E`.
      Exit: one variant default, delta recorded, no regression shipped;
      FORCED-bit fast path live in the winner. **Deferred with B/C.**
- [ ] FFI/JIT ABI rev: `ratchet-runtime-ffi` wrappers and
      `ratchet-jit/src/lower.rs` value-word constants updated in
      lock-step; token-count tables extended (§8). Gate: tier-2
      landings' pinned differentials (wrap-boundary, deopt paths) all
      green under the new word. **Deferred with B/C — the shipped
      subset preserves the 16-byte value word exactly, so no ABI rev
      was needed (tier-1/tier-2 dispatch and sweep-stress counters
      byte-identical A/B).**

### Stage FV-5 — hybrid closures (needs FV-3 + Chunk D)

- [x] Flat free-var capture for `|FV| <= K` sites: closure conversion
      pass in `ratchet-core` (capture plans in facts), inline `Value`
      capture in flat lambda/thunk objects, access rewritten to capture
      indices. K tuned by A/B.
- [x] Linked persistent frame chains + persistent `with`/scoped-global
      lists for the remainder (`eval/env.rs`): capture = one pointer;
      depth-walk access by lexical coordinates. Gate: `__overrides` and
      rec-assembly adversarial corpus from FV-0's Chunk-D arms.
- [x] Delete the generation-keyed capture cache and its four
      mutation-site helpers (`eval_core/module_env.rs`) once both forms
      land; capture counters (FV-0) show the copy mass gone. Exit:
      capture-array copies ~0 at flat sites; wide-eval env allocation
      mass reduced with the delta recorded.
      *Landed (FV-5). Serial production flat closures reserve a typed
      trailing `Value` run in the closure object; reads use the persisted
      constant capture index and a prevalidated registry handle. Recursive
      binding assembly initially retains the linked frame graph, then writes
      the tail and publishes the flat environment only at the outermost
      immutable boundary. The shared-parallel `OnceLock` slot layout and the
      record-placed B2 stress proving ground deliberately use the linked form:
      both still capture one persistent-chain head and perform no frame-array
      copy, while avoiding a second shared object layout or an unsound
      collector writeback seam.*

      *`K = 2` was selected from the repository census and an isolated A/B:
      it covers 87.9% of statically eligible sites and reduced
      `bench.wide-eval` arena peak from 39.5 MiB at `K = 8` to 35.5 MiB.
      The ceiling is a memory-policy threshold, not a correctness boundary:
      the sound site-qualified owner check passes the source-path parity canary
      at both `K = 2` and `K = 8`. The observed `K = 8` failure was traced to
      and fixed by removing an experimental read shortcut that omitted
      allocation-site identity; wider captures take the linked fallback solely
      to avoid trailing-storage cost. Capture reads retain the complete
      module/allocation-site identity check. A trial direct-base shortcut that
      skipped it also failed the fresh cache/full-analysis `bench.wide-eval`
      gate (`expected attrs, got Lambda`) and was rejected before landing.
      Valid alternating compact-handle pairs split within noise (`K = 2`
      ~2.2% slower cold and ~1.9% faster warm by paired median), so no
      throughput win is claimed for the ceiling choice. Five valid interleaved
      exact-final/baseline pairs likewise put the paired-median ratio at
      ~0.987 cold and ~1.035 warm; the arena peak fell from 47.5 MiB to
      35.5 MiB, while median post-run RSS moved from 177.2 MiB to 172.4 MiB
      cold and from 191.2 MiB to 186.7 MiB warm. Earlier load-contaminated
      probes were excluded before this five-pair run. On the final wide
      workload, the FV-0 counters move lexical array capture from
      156,584 captures / 620,980 copied frame handles to zero; 205,084 flat
      captures copy 256,555 `Value`s, while linked captures clone one head.
      Persistent `with` and scoped-global captures each retain their 240,223
      capture events but copy zero scope entries. The generation-keyed cache
      and its invalidation helpers are gone.*

### Stage FV-6 — arena-owned payloads

- [x] Remove the payload `Arc`s (`HeapObjectValue`) for migrated kinds;
      out-of-arena references (symbols, context elements, parallel
      cells) either migrated or side-owned with sweep notification
      (§5). Gate: standing battery + sweep-mode stress; refcount-traffic
      profile delta recorded. Exit: **Tier-B B2's flattening gate
      closed** — doc 06 §4's B2 row unblocks on B1-stress + the FV-0
      identity table.
      *Landed with `EvalThunk`, `EvalLambda`, and `EvalPrimOp` stored by
      value in both the production `FlatClosurePayload` and the B2/shared
      `HeapObjectValue` fallback. Thunk force state is the only independently
      live portion: `Arc<ThunkCell>` plus the optional parallel-cell `Arc`
      survive evaluator re-entry, and replacing the direct payload at shed or
      sweep drops the payload's sidecar owners and captured graph. Lambda and
      primop snapshots carry no payload `Arc`. The flat capture handle is one
      word after moving owner identity back to the existing `Value` field; the
      store still validates the exact owner pointer and registry entry before
      any tail access.*

      *On the exact final wide workload, outer payload-handle clones move from
      845,467 to zero; 691,617 thunk-state sidecar clones remain (one per
      ordinary owned thunk snapshot). Threshold-zero sweep is byte-green with
      one sweep retiring 135,872 closures and 203,794 forced-thunk payloads
      shed. Six balanced fixed-executable-path pairs are byte-green with
      paired-median candidate/baseline ratios of ~0.941 cold and ~0.962 warm;
      separate medians are 0.392 versus 0.408 seconds cold and 0.378 versus
      0.385 seconds warm. Median post-run RSS falls from 172.7 to 140.6 MiB
      cold and from 189.2 to 156.9 MiB warm. Direct process peak is effectively
      flat (199.1 versus 201.1 MiB): arena mapping rises from 35.5 to 67.5 MiB
      because those payload bytes moved from separate malloc allocations into
      the measured arena. A package-sized `pkgs.zlib` probe is flat on time
      (~87.1 vs ~87.3 ms cold, ~79.7 vs ~80.5 ms warm) and RSS. Invalid probes
      from a non-native baseline executable were discarded before the six-pair
      run. The standing Rust/Miri gates cover direct
      payload relocation, shared publication, region pop, and sweep-sidecar
      release; the full parity battery is recorded at the campaign exit.*

### Extensions (each independently gated; order by measured yield)

- [x] Registered-root strict raw-traversal sweep checkpoints (first #52
      slice): post-root list/attr rendering registers every pending child and
      nested ancestor in the transient root stack, then applies B1's configured
      allocation cadence between children. Threshold-zero stress proves four
      mid-render collections are byte-invisible and reclaim dead captures. This
      deliberately does not claim a general evaluator safepoint: JSON used by
      structured derivations can run with unregistered Rust evaluator locals,
      and the wide fail-loud gate rejected that broader placement. Record-table
      segmentation is also not a production lever after FV-3: production keeps
      the table at zero records, while only the B2 relocation proving ground
      opts into it. Reconsider segmentation with B2 measurements rather than
      adding an idle production structure.
- [x] First JIT alloc-family unlock: scalar singleton-list tier-1 bodies lower
      to a stack-mapped `aos_alloc_cons` call. The semantic runtime wrapper
      initializes and hash-conses the current flat list representation, rather
      than exposing the obsolete storage-only cons reservation. GC-stress,
      direct-tail chaining, finalized symbol relocation, and native execution
      are covered. Broader list constructors and attrs/string/closure allocation
      remain gated on complete semantic ABIs. The full serial/K=4/JIT/sweep-zero
      parity battery, cache validation, and 645-seed strict-JSON corpus are green;
      seven baseline-first release A/B pairs are regression-free with identical
      83,361,792-byte arena peaks.
- [ ] Closure/env hash-consing (§7.1): intern flat closures whose
      captured words are all canonical; declined-admission otherwise.
      Gated on FV-5; sized by FV-0 counters *after* FV-5 banks its win.
- [ ] Semantic-swap eviction ladder (§7.2): wire rungs 3–4 (memo-tier
      eviction per doc 29 §5; cold module-IR eviction with parse-cache
      re-materialization) into the `EvalHeapMemoryBudget` escalation;
      rung 5 (thunk drop-and-recompute) research-grade, gated on FV-5
      closure identity. Rejections recorded: no thunk serialization; no
      in-process compression (zstd only in L2 packs).
- [ ] Store-path segment interning (§7.3): first the counting probe
      (FV-0 counters), then the segment table + segmented string
      representation, gated on a multi-MiB measured dedup ratio.
- [ ] Per-kind arenas + size-class slabs (§7.4): sweepable vs. immortal
      page segregation; sweep scans sweepable pages only. Gate: sweep
      cycle-time and memory columns.
- [ ] Last-use capture shedding (§7.4): cardinality-fact-driven eager
      release, extending the `SingleEntry` seam; gated on Chunk D.
      Gate: shed counters + the mid-eval peak (the B1 "after the RSS
      peak" gap this closes).
- [ ] Weak hash-cons tables (§7.4): daemon-mode residency bound;
      one-shot immortal fast path preserved. Gate: daemon soak
      (long-lived process, repeated evals) memory profile.
- [x] Unsafe-placement enforcement (§8): `#[forbid(unsafe_code)]`
      rollout (oracle's region-pop op relocated behind a safe
      `ratchet-value` API first; `ratchet-cache` reconciliation decided
      and recorded); CI lint asserting the sanctioned-zone set; safety
      manifests extended per audit process. Exit: every workspace crate
      outside the sanctioned zones compiles under `forbid`, except the
      directive-authorized `deny` + scoped-CI path for Buffa-generated
      `aos-proto` witnesses. Landed resolution: four hand-written zones
      (`ratchet-value`, `ratchet-runtime-ffi`, `ratchet-jit`,
      `ratchet-cache`); cache's 20 operations and proto's 60 generated
      impls are count-pinned; oracle is `forbid`; workspace discovery
      fails on any zone/lint drift. The `aos` interactive fleet signal
      reset moved into its hermetically compiled launcher trampoline, so
      the Rust binary also reaches `forbid` without losing Ctrl-C cleanup.

### Measure-gated dispatch items (not committed)

- [ ] Superinstructions for census-named shapes (`Interp`/`List`/
      `AttrSet` constructor bodies; nested `Select`/`Update` chains) —
      one shape at a time, wall-time A/B per shape, `4515a9972`
      methodology.
- [ ] Flat bytecode + explicit operand stack: **only if** post-FV-5
      profiles show dispatch as the top residual; carries the
      goal-tracker #49 recursion fix and OSR boundaries as side
      benefits. Re-evaluate, do not build, until then.

**Campaign exit criteria (falsifiable).** All six FV stages landed with
the standing battery green at every stage; the record `Vec` and address
map no longer exist on the deref path; wide-eval peak memory at or below
the ≤2x-of-C++ target *or* the residual decomposed and attributed to
named extensions; the B2 gate formally closed; unsafe confined to the
sanctioned zones under compiler-checked lints with all token tables
current; and the selected value-word variant's benchmark delta recorded
with no shipped regression.
