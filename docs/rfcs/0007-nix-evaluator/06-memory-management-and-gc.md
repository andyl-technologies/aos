# RFC-0007 - Memory Management and Garbage Collection

This document specifies the heap and garbage-collection design for `aos-nix`.
It covers the dual-tier allocator (a bump-pointer one-shot arena for CLI
evaluation, a precise generational copying collector for the daemon), the
*alloc-via-symbols* indirection that lets the JIT stay oblivious to GC strategy,
region inference as a finer-grained refinement, and the path to concurrent
low-pause collection. It also explains *why* a Nix evaluator is an unusually
favorable target for the most aggressive of these techniques — and why the
single biggest GC win is simply deleting C++ Nix's Boehm conservative collector.

Memory management is the second-ranked item in the RFC roadmap (after the
incremental early-cutoff cache), and for a reason this document makes precise:
the Nix evaluator is allocation-bound. It manufactures, touches once, and
discards an enormous population of short-lived thunks and attribute sets. The
allocator *is* the inner loop. The value representation those allocations carry
is specified separately — see [value representation](05-value-representation.md);
the analyses that *avoid* allocation (strictness, escape analysis, scalar
replacement) are specified in
[laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md).
This document owns the heap underneath all of that.

---

## 1. Why memory management dominates Nix evaluation

### 1.1 The allocation profile of an evaluator

A Nix evaluation is not a long-running mutator with a stable working set; it is
a *fan-out batch transformation*. Evaluating `nixpkgs`-scale expression trees
allocates millions of heap objects, the overwhelming majority of which are:

- **Thunks** — `(code_ptr, captured_env, state)` triples created to defer a
  subexpression, forced exactly once (or never), then never touched again.
- **Attribute sets** — the result of every `{ ... }`, every `//`, every
  `derivation` call, every recursive `rec { ... }` environment.
- **Cons cells / list backbones** — `map`, `genList`, `++`, `filter`.
- **Strings** — store-path fragments, interpolation results, `toString` output.

The defining statistic, confirmable with `NIX_SHOW_STATS=1` on any real C++ Nix
evaluation, is the ratio of *allocated* objects to *live-at-any-instant*
objects. It is enormous. Intermediate thunks are born, forced, and die within
the dynamic extent of a single `force` call. This is the **generational
hypothesis** — "most objects die young" — not as a statistical tendency but as a
near-law. In a Java heap the hypothesis holds for perhaps 90–98% of objects; in
a Nix evaluation it holds for *almost all* intermediate allocation, because the
language has no mutation, no long-lived mutable caches in user code, and a value
graph that is a pure function of its inputs.

This single fact drives the entire design:

1. The allocator's *fast path* (allocate) must be as close to free as a pointer
   bump and a compare.
2. The reclaimer must exploit the fact that almost everything it scans is
   already dead — i.e. a **copying** collector that touches only survivors, not
   a mark-sweep collector that touches corpses.
3. In the common CLI case we should not reclaim *at all* — we should allocate
   until the process exits and let the OS reclaim the address space in one
   `munmap`.

### 1.2 The baseline we are beating: Boehm conservative GC

C++ Nix uses the **Boehm–Demers–Weiser** conservative garbage collector
(`libgc`). BDW-GC is a remarkable piece of engineering — a drop-in
`malloc`/`free` replacement that works "in an uncooperative environment" where
the compiler provides no type information, by scanning the stack and heap and
conservatively treating any word-aligned bit pattern that *could* be a pointer
into the heap as if it *were* one ([Boehm, *Garbage Collection in an
Uncooperative Environment*][bdwgc-paper]). That conservatism is exactly its
weakness for our workload:

- **False retention.** Any integer, packed bitfield, or stale stack slot whose
  bits happen to look like a heap address pins the pointed-to object and its
  entire transitive closure. In a Nix evaluation that manipulates 64-bit
  integers, hashes, and string-context bitsets, the probability that *some* live
  word aliases *some* dead object is non-trivial, and the retained object can be
  arbitrarily large (an attrset closure, a parsed file). Managing this
  unnecessary retention "continues to be an important problem" for conservative
  collectors ([BDW-GC project][bdwgc-repo]).
- **No compaction / no copying.** Because BDW-GC cannot move objects (it does
  not know which words are pointers that would need updating), it cannot
  compact. It is fundamentally mark-sweep, which means its work is proportional
  to the *dead* set it must sweep and the fragmentation it must tolerate — the
  opposite of what a high-mortality nursery wants.
- **Cache-hostile layout.** Mark-sweep leaves survivors wherever they were
  allocated; a copying collector compacts survivors into a dense region,
  restoring locality. For an evaluator that walks large attrset closures, layout
  *is* throughput.

The Nix community has repeatedly measured GC as a dominant cost of evaluation,
and BDW-GC tuning (heap-size hints, `GC_INITIAL_HEAP_SIZE`) is folklore for
making `nix` eval-heavy commands fast. **Replacing the conservative collector is
therefore not a micro-optimization; it is removing the single largest structural
inefficiency in the reference implementation's eval path.** Because `aos-nix`
controls its own value representation (see
[value representation](05-value-representation.md)) it can be *precise*: it knows
exactly which fields of which objects are pointers, so it can move objects,
compact, and never falsely retain.

This is the rare situation where a clean-room reimplementation has a structural
advantage the incumbent cannot retrofit: C++ Nix cannot become precise without
rewriting its value representation, because BDW-GC's whole premise is *not*
knowing the layout.

### 1.3 The hash-consing advantage: a strictly smaller live set

There is a second, independent reason `aos-nix` uses less memory than C++ Nix,
and it is *not* about the collector at all — it is about how much gets allocated
in the first place. **C++ Nix is a memory hog partly because it does not
maximally share: structurally-equal values are duplicated.** Every time an
expression produces an attrset, a list, or a string that is value-equal to one
already on the heap, C++ Nix allocates it again. In a `nixpkgs`-scale evaluation
the duplication is enormous: the same store-path strings, the same `meta`
attrsets, the same `stdenv`/`lib` fragments recur across tens of thousands of
derivations, each materialized fresh.

`aos-nix` **hash-conses** its value graph (see
[value representation](05-value-representation.md)): structurally-equal attrsets,
lists, and — critically — the constantly-recurring store-path and option strings
collapse to a *single* allocation, looked up through a dedup table and returned
by pointer. The store path `"/nix/store/…-stdenv-linux"` that appears in a
million places is one heap object referenced a million times, not a million
copies. Maximal sharing turns structural equality into pointer equality and, as
a side effect, makes the *live set itself smaller* — there is simply less
distinct data alive at peak.

The consequence is a memory **advantage**, not mere parity. For the same
evaluation, before any reclamation or spill happens at all:

```text
   live_set(aos-nix)  =  distinct values  (hash-consed, one copy each)
   live_set(C++ Nix)  =  distinct values  +  all the duplicates
   ⇒  live_set(aos-nix)  <  live_set(C++ Nix)        (strictly, on shared-heavy input)
```

This frames everything that follows. The spill-to-disk story (§3.4), the OS
paging cooperation (§3.5), and the budget-driven escalation (§3.6) all operate on
a working set that is *already* smaller than the incumbent's. Hash-consing
shrinks the live set; spill + `madvise` then bound the *peak*. The two are
complementary: sharing reduces what must be alive, and out-of-core spill bounds
what must be resident.

---

## 2. The `alloc-via-symbols` contract

Before describing any GC strategy, we fix the interface, because the interface
is what makes the strategies swappable. **Every heap allocation in compiled
code, in interpreted code, and in primops goes through a small, stable set of
runtime symbols.** The JIT never emits an inline bump sequence; it emits a call
(direct, and in the hot path inlined by the optimizing tier — see §6.3) to a
runtime entry point.

```rust
/// The allocation ABI. Every tier (tree-walk, baseline JIT, optimized JIT)
/// and every primop allocates exclusively through these symbols. The concrete
/// `Heap` behind them is chosen at startup; compiled code is identical
/// regardless of which collector is installed.
///
/// # Safety
///
/// All of these return raw, uninitialized (header-initialized only) memory.
/// The caller MUST fully initialize the object's pointer fields before the
/// next safepoint, or a moving collector may scan garbage. See §6.4.
unsafe extern "C" fn aos_alloc_thunk(rt: *mut Runtime, code: CodePtr, env: *const Env) -> *mut Thunk;
unsafe extern "C" fn aos_alloc_attrs(rt: *mut Runtime, shape: ShapeId, n: u32) -> *mut Attrs;
unsafe extern "C" fn aos_alloc_cons(rt: *mut Runtime, head: Value, tail: *const List) -> *mut List;
unsafe extern "C" fn aos_alloc_string(rt: *mut Runtime, len: usize) -> *mut StrHeader;
unsafe extern "C" fn aos_alloc_raw(rt: *mut Runtime, size: usize, align: usize, tag: TypeTag) -> *mut u8;
```

These symbols are registered into the Cranelift JIT module exactly like primops
are (`JITBuilder::symbol`, see
[primops and runtime ABI](10-primops-and-runtime-abi.md)); the Cranelift JIT
crate "takes care of managing a symbol table, allocating memory, and performing
relocations" ([wasmtime cranelift-jit][cranelift-jit]), so a `call` to
`aos_alloc_attrs` is resolved at finalize time to the installed implementation.

Why this indirection is non-negotiable:

| Property | Consequence |
|---|---|
| **GC strategy is a startup choice** | `aos-nix eval` (one shot) installs the bump arena; `aos-nix daemon` installs the generational collector. No recompilation of JIT code. |
| **The collector can evolve independently** | We can ship the bump arena first, add generational collection later, add concurrency later still, *without touching the compiler or the 120 primops*. This is what de-risks the roadmap. |
| **Safepoints are centralized** | The allocators are the natural place to poll for a GC request (the "allocation safepoint" model used by HotSpot and most managed runtimes). Compiled code does not need explicit poll instructions on every back-edge in the first cut. |
| **Write barriers live behind one wall** | When the generational/concurrent collectors need card-marking or load/store barriers, they are emitted by the runtime around these symbols and a small set of mutator helpers, not scattered through every codegen site. |

The cost is one (often inlinable) call per allocation. The benefit is that the
hardest, most experimental component of the system — the moving, concurrent
collector — is hidden behind a frozen ABI that the rest of the evaluator was
written against on day one. This mirrors how managed runtimes separate the
*allocation sequence* the JIT emits from the *collector* that services it: in
HotSpot the JIT emits a TLAB bump-and-check and calls into the runtime on slow
path; here we start with the call always going to the runtime and inline it only
where measurement justifies it.

---

## 3. Tier A — the bump-pointer one-shot arena (CLI)

### 3.1 Rationale: a batch job should never collect

`aos-nix eval file.nix -A pkg` is a *batch process with a bounded lifetime*. It
reads inputs, computes a `.drv` graph, writes the `.drv` files, and exits. For
such a process the theoretically optimal memory strategy is well known and
brutally simple: **allocate forever, never free, and let `exit()` reclaim
everything at once.** Any cycle spent reclaiming memory mid-run is wasted,
because the OS will reclaim the entire address space in a single `munmap` when
the process dies — work that is `O(1)` in the number of objects.

This is the *arena* / *region* / *bump allocator* pattern, and it is the fastest
allocator that exists: allocation is

```text
ptr  = arena.cursor
next = ptr + round_up(size, align)
if next > arena.limit { slow_path_new_chunk() }   // rare
arena.cursor = next
return ptr
```

— an add, a compare, and a predicted-not-taken branch. No free lists, no size
classes, no GC headers needed for reclamation (objects still carry a *type* tag
for the evaluator's own use, but no *mark* bits), no synchronization in the
single-threaded case. It is the same discipline `bumpalo` provides in Rust and
that arena allocators provide in compilers (LLVM's `BumpPtrAllocator`, the rustc
arenas) precisely because a compiler pass, like an evaluator run, is a
bounded-lifetime batch.

### 3.2 Structure

```text
                 arena (one per worker thread)
   ┌───────────────────────────────────────────────────────────┐
   │ chunk 0 (2 MiB, mmap'd)                                     │
   │ ┌───────┬───────┬───────┬───────┬─────────── free ───────┐ │
   │ │ thunk │ attrs │ cons  │ str   │^cursor                 │ │
   │ └───────┴───────┴───────┴───────┴────────────────────────┘ │
   │ chunk 1 (2 MiB) ...                                         │
   │ chunk 2 (grows geometrically) ...                          │
   └───────────────────────────────────────────────────────────┘
   drop = for each chunk: munmap(chunk)   // O(#chunks), not O(#objects)
```

- Chunks are `mmap`'d in geometric steps (e.g. 2 MiB → 4 MiB → …) to amortize
  the syscall and keep the chunk list short.
- The arena is **thread-local** for the coarse parallel model (see
  [parallel evaluation](13-parallel-evaluation.md)): each top-level derivation
  is evaluated on a worker with its own arena, and the only cross-thread sharing
  is *immutable, never-collected* tables (interned symbols, hash-consed values,
  parsed IR). No locks on the allocation fast path.
- Hash-consed / maximally-shared values (see
  [value representation](05-value-representation.md)) live in a **distinct,
  permanent arena** keyed by the dedup table, so a worker arena drop never frees
  a shared value another worker might still reference.

### 3.3 Bounded memory and the spill safety valve

The honest objection to "never free" is *peak memory*. A pathological
expression could allocate without bound and OOM. Three mitigations, in order of
preference:

1. **Most allocation is dead and most peaks are modest.** Real `nixpkgs`
   evaluation has a large *cumulative* allocation but a far smaller *live* set;
   the arena's high-water mark is driven by live data plus the dead data we
   chose not to collect *within the current evaluation*. In practice this fits
   comfortably in memory for whole-package-set instantiation, which C++ Nix also
   does in a single process.
2. **Region inference (§5) reclaims the obvious wins even in arena mode.**
   Inferred regions give us *intra-run* reclamation of provably-dead sub-arenas
   without a full collector — a stack of regions, popped at region exit, exactly
   in the Tofte–Talpin discipline.
3. **A configurable high-water threshold flips Tier A into Tier B.** If the
   arena crosses a memory ceiling, the runtime can install the generational
   collector *for the remainder of the run* (the `alloc-via-symbols` contract
   makes this a pointer swap on the allocator vtable, not a recompile). This is
   a safety valve, not the common path.

These three are not the whole story, though. "Flip to a collector" still assumes
the live set must fit in RAM. The next three subsections add the part vanilla Nix
structurally lacks: an **out-of-core** path (§3.4) that lets cold values live on
disk, **OS page-level cooperation** (§3.5) that lets the kernel manage the
resident working set, and a **single configurable budget** (§3.6) that drives all
of these — eviction, paging hints, and the collector flip — as escalating
responses to one knob.

### 3.4 Out-of-core spill: the mmap'd CA store as a swap-to-disk mechanism

The mitigations above keep everything in RAM. But `aos-nix` has a resource
vanilla Nix does not: the **content-addressed value store** (the **CA store**)
of the incremental evaluation cache (see
[incremental evaluation cache](12-incremental-evaluation-cache.md)). That store
is an `mmap`'d, content-addressed, on-disk arena of hash-consed values — and it
**doubles as a swap-to-disk mechanism for the evaluator's own heap.** This
converts the peak-memory objection from "the live set must fit in RAM" to "the
live set must fit in RAM + disk, with the OS managing which part is resident."

The mechanism has three properties that make it unusually clean, each a direct
consequence of the value representation:

- **Cold values are evicted to the CA store and rematerialized on demand.** A
  hash-consed value that has not been touched recently can be dropped from the
  in-RAM arena, leaving behind only its content hash (a small, fixed-size
  handle). When some later access dereferences that handle, the value is
  rematerialized by reading it back from the on-disk store. The in-memory
  footprint of a cold value collapses to one hash.
- **Because the store is `mmap`'d, the OS pages it in and out.** We do not write
  our own pager. The CA store is a memory-mapped file; the kernel's virtual-memory
  system brings pages of cold values into physical RAM on fault and evicts them
  under pressure via the standard page-cache machinery. The evaluator addresses
  the whole content-addressed store as if it were memory, and the working-set
  management is the OS's job — exactly the leverage `madvise` (§3.5) lets us
  steer.
- **Eviction is write-back-free, because the hash *is* the address.** This is
  the crucial difference from a conventional swap file. In a content-addressed,
  immutable store, a value's on-disk location is determined by its content hash;
  the value is never mutated after creation. So evicting a cold value requires
  **no write-back**: either the value is already present in the CA store (it was
  hash-consed there on creation) and eviction is a pure drop of the RAM copy, or
  it is written once and is thereafter immutable. There is no dirty-page
  write-out on the eviction path, no coherence problem between the RAM copy and
  the disk copy — immutability plus content-addressing guarantee they are the
  same bytes. Rematerialization is a pure read keyed by hash.

The net effect is that the "allocate forever, never free" discipline of Tier A no
longer implies "everything stays resident." Cumulative allocation can exceed
physical RAM as long as the *resident working set* fits, with the cold tail
spilled to the CA store and faulted back only when touched. This is precisely the
out-of-core capability C++ Nix's BDW-GC heap cannot offer: a conservative,
in-RAM, non-content-addressed heap has no notion of "the disk copy is
authoritative, drop the RAM copy for free."

### 3.5 OS page-level cooperation (`madvise`)

Vanilla Nix does not collaborate with the operating system's pager: its heap is
opaque RAM, and the kernel must guess the working set from raw access patterns.
`aos-nix` instead tells the kernel what it knows, using `madvise(2)` to steer
which pages stay resident. Because the evaluator understands its own liveness and
temperature (which arena chunks are dead, which cached values are cold), it can
hand the kernel advice no access-pattern heuristic could infer. The semantics
below are verified against the Linux man page ([madvise(2)][madvise]); all of
them are **advisory hints**, **Linux-specific**, and therefore gated behind a
portability shim that compiles to a no-op on non-Linux hosts.

| Advice | What we use it for | Verified semantics |
|---|---|---|
| `MADV_DONTNEED` | Return *dead* arena pages to the OS after a region pop (§5) or a worker-arena drop, when we want the RSS reclaimed immediately and the contents are genuinely garbage. | Destructive: subsequent access re-faults to zero-fill (anon) or re-reads the file. Immediate RSS reduction. Original Linux; Huge-TLB support added 5.18. |
| `MADV_FREE` | Return *probably-dead* arena pages cheaply, letting the kernel keep them if there is no memory pressure (lazy reclaim) and reuse them on a write. | Lazy: the kernel may free under pressure or on next write; non-destructive until then. Private anonymous pages only. Linux 4.5+. |
| `MADV_COLD` | Demote *cold* cache/value pages — hash-consed values not recently touched — to make them preferred reclaim targets *without* forcing them out. | Non-destructive deactivation: marks pages as reclaim candidates; a hint only, does not force reclaim. Linux 5.4+. |
| `MADV_PAGEOUT` | Actively evict cold CA-store/value pages to swap (or write back, for file-backed) when we want to *force* the demotion, e.g. when approaching the budget (§3.6). | Forced reclaim: anonymous pages are swapped out, dirty file-backed pages written; data preserved, pages removed from RAM now. Linux 5.4+. |
| `MADV_HUGEPAGE` | Back the **cache-resident nursery** (and the hot CA-store region) with transparent huge pages to cut TLB miss pressure on the allocation hot path. | Enables Transparent Huge Pages for the range; the kernel collapses/scans to huge pages. Optimization hint, non-destructive. Linux 2.6.38+ (needs `CONFIG_TRANSPARENT_HUGEPAGE`). |

The distinction between the pairs is deliberate and load-bearing:

- **`MADV_DONTNEED` vs. `MADV_FREE`.** We use `MADV_DONTNEED` only where the
  contents are *known dead* and we want the RSS back now (popped region, dropped
  arena); `MADV_FREE` where pages are *probably* dead but cheap to keep — we let
  the kernel decide based on pressure, and a subsequent write silently reclaims
  the page for reuse. `MADV_DONTNEED` is destructive on next read; `MADV_FREE` is
  not, until the kernel actually reclaims.
- **`MADV_COLD` vs. `MADV_PAGEOUT`.** `MADV_COLD` is the gentle hint — "these
  cold value pages are good reclaim candidates, take them if you need them";
  `MADV_PAGEOUT` is the forceful version — "evict these now." Under the budget
  (§3.6) we escalate from the former to the latter as pressure rises.

The portability shim matters: `MADV_PAGEOUT`/`MADV_COLD` need Linux 5.4,
`MADV_FREE` needs 4.5, and none of these flags exist on macOS or the BSDs with
the same semantics. The shim presents one internal API
(`advise_dead`, `advise_cold`, `advise_evict`, `advise_huge`) and lowers each to
the best available primitive per platform, falling back to no-ops where the
kernel is too old or the OS differs. Correctness never depends on the advice
being honored — these only affect *when* the OS reclaims, never *what* the
evaluator observes (cf. §8: GC and paging are observationally invisible).

### 3.6 The configurable memory budget: one knob, three escalating responses

The user- and CI-settable piece tying §3.3, §3.4, and §3.5 together is a single
**high-water memory budget** (e.g. `--max-rss`, or an environment variable, or a
daemon config field). It is not three separate thresholds; it is one budget that
drives three *escalating* responses as the resident set climbs toward it:

```text
   resident set vs. budget          response
   ────────────────────────         ─────────────────────────────────────────
   well under budget          (1)   never-free, fully in-RAM Tier A bump arena
                                     (the common, fastest path — §3.1)

   approaching budget         (2)   spill cold hash-consed values to the mmap'd
                                     CA store (§3.4); MADV_COLD / MADV_PAGEOUT the
                                     cold value pages and MADV_FREE dead arena
                                     pages (§3.5) — keep the resident set under
                                     the budget without ever tracing the heap

   still over after spilling  (3)   install the generational collector for the
                                     remainder of the run (the §3.3.3 flip) — a
                                     true tracing reclaim, the last resort
```

The ordering is deliberate: each response is cheaper and less disruptive than the
next. Step (1) costs nothing. Step (2) is out-of-core paging with no tracing —
the OS moves bytes between RAM and disk, and we only pay for values we actually
touch again. Step (3), installing a tracing collector mid-run, is the genuinely
expensive escalation (it must root-scan and may relocate; see §3.7 and open
question §10.5), so it fires only when out-of-core spill *plus* page eviction
still cannot hold the line — which, given the strictly-smaller hash-consed live
set (§1.3), is rare for real `nixpkgs`-shaped input. One knob; three responses,
escalating only as far as the workload forces.

### 3.7 When Tier A is correct

Tier A is correct **whenever the process is single-shot and the peak live +
retained set fits the memory budget.** That is the default for `aos-nix eval`
and for the differential harness (which runs one instantiation per invocation).
It is *incorrect* for a long-lived daemon that evaluates many independent
requests over hours, because retained-but-dead memory would grow without bound
across requests. That case is Tier B.

---

## 4. Tier B — precise generational copying GC (daemon)

### 4.1 When and why

A long-lived `aos-nix` daemon (serving editor integrations, a registry hub, or
repeated CI evaluations in one process — see
[integration with AOS](14-integration-with-aos.md)) must reclaim memory *within*
its lifetime. Here we install a **precise, generational, copying** collector.
Each adjective is load-bearing:

- **Precise** (not conservative): the collector knows the exact pointer layout
  of every heap object from its type tag and shape, so it can (a) never falsely
  retain and (b) *move* objects, updating every reference. This is the
  capability BDW-GC structurally lacks and the primary reason we win.
- **Generational**: collect the young generation (nursery) frequently and
  cheaply; promote survivors to an old generation collected rarely. Justified by
  the extreme generational hypothesis of §1.1.
- **Copying** (for the nursery): a copying collector's work is proportional to
  *live* data, not *allocated* data. When 99% of the nursery is dead at
  collection time, a copying collector copies the surviving 1% and resets the
  nursery to empty in `O(survivors)`. A mark-sweep collector would instead do
  work proportional to the dead 99%. **This is the single most important
  algorithmic choice in the collector**, and it is the same choice GHC makes for
  the same reason ([Marlow et al., *Parallel Generational-Copying GC with a
  Block-Structured Heap*][ghc-gc]).

### 4.2 The GHC lineage and why Nix fits it even better

GHC's runtime is the closest prior art, because Haskell, like Nix, is a lazy,
immutable, garbage-collected functional language. GHC allocates *everything*
(including every thunk) in a nursery, runs a generational copying collector, and
"exploits the immutability of data … immutable data can be copied in parallel"
([GHC GC paper][ghc-gc]). The design lessons transfer directly:

| GHC property | Nix analogue | Why it's *stronger* in Nix |
|---|---|---|
| Bump-allocate thunks in nursery | Same | Nix has no `IORef`/mutable arrays in the language; the heap is *more* immutable than Haskell's. |
| Two generations, copying young gen | Same | Nix's young-death rate is at least as extreme. |
| Immutability ⇒ parallel/concurrent copying is sound | Same | A pure value graph has *no* mutator-visible mutation except thunk update (§6.4), so the barrier surface is tiny. |
| Block-structured heap, per-block bump | Same | Lets workers allocate lock-free from private blocks. |

The one place Nix is *harder* than idealized immutable data is **thunk update**:
forcing a thunk overwrites its `state` along the serial `Suspended → Blackhole →
Forced` machine (the serial subset of the parallel superset in
[value representation](05-value-representation.md) §6 / [parallel evaluation](13-parallel-evaluation.md)).
That is the *only* mutation in the value graph, and it is the
source of the single write barrier the generational and concurrent collectors
need (§4.5, §6.4). Compared to Java — where every field of every object can be
mutated at any time and the GC must assume so — Nix's mutation surface is a
single, well-typed transition on one object kind. This is precisely why
techniques that are *partial* on the JVM become *total* here.

### 4.3 Heap layout

```text
 nursery (young gen)                old generation
 ┌──────────────────────┐          ┌───────────────────────────────┐
 │ from-space  to-space │  promote │ blocks (mark-compact or        │
 │ ┌────────┐ ┌───────┐ │ ───────▶ │  generational copy on major GC)│
 │ │ bump → │ │       │ │          │ remembered set ◀── card table  │
 │ └────────┘ └───────┘ │          └───────────────────────────────┘
 └──────────────────────┘
   minor GC: copy live from-space → to-space (+ promote aged) ; swap
   major GC: collect old gen (rare)
```

- **Nursery**: sized to comfortably fit in L2/L3 so that the entire
  allocate-then-collect cycle is cache-resident — the *cache-resident nursery*
  technique that makes minor GC nearly free because both the bump allocation and
  the survivor copy stay in fast cache. A minor collection is triggered when the
  nursery fills; it copies survivors to to-space (or promotes them), then the
  nursery is reset to empty.
- **Old generation**: holds promoted survivors. Collected by a major GC, which
  is rare. Initially a stop-the-world mark-compact (or full copy); upgraded to
  concurrent in §6.
- **Promotion policy**: copy-count or age-based. Objects surviving *N* minor GCs
  are promoted. Because hash-consed values are effectively immortal, they are
  allocated directly in a non-collected permanent space (or the oldest
  generation with a never-collect flag), bypassing promotion churn entirely.

### 4.4 Precise root and field scanning

Precision requires the collector to enumerate, for any object, exactly which
words are heap pointers. We get this from the value representation:

- **Type tag → layout.** Each heap object's header (or its NaN-box/pointer tag —
  see [value representation](05-value-representation.md)) identifies its kind:
  `Thunk`, `Attrs`, `Cons`, `String`, `Lambda`. Thunks have `(code, env)`
  pointers; attrsets have a `shape` pointer plus `n` value words; cons cells
  have head/tail; strings and integers have no outgoing pointers.
- **Shape → attrset field map.** An attrset's `ShapeId` (see
  [attribute sets, hidden classes, and inline caches](09-attribute-sets-hidden-classes-and-inline-caches.md))
  names a hidden class whose descriptor records which slots are values to scan.
  The collector consults the shape, not a per-object map — one descriptor shared
  across all attrsets of that shape, which is both compact and cache-friendly.
- **Roots.** Unlike BDW-GC, we do **not** conservatively scan the C stack.
  Roots are explicit: the current evaluation's value stack, the in-flight
  `force` continuation chain, primop argument registers spilled at safepoints,
  and the interned/hash-consed tables (treated as permanent roots). At JIT tiers
  this requires **stack maps** describing which registers/stack slots hold live
  `Value`s at each safepoint; Cranelift emits stack maps for exactly this purpose
  and they are consumed by the collector to find roots precisely.

Because scanning is driven by tags and shapes rather than guesswork, there is
**zero false retention** and objects are **movable**.

### 4.5 The generational write barrier (one, and only one)

Generational collection requires the collector to find old→young pointers
without scanning the whole old generation, or it would lose the entire benefit
of "collect young cheaply". The standard solution is a **write barrier** that
records when a mutator writes a young pointer into an old object, maintaining a
**remembered set** (commonly via a **card table**). In Java this barrier fires
on *every* reference-field store, a pervasive tax.

In Nix the barrier surface collapses to essentially one site: **thunk update.**
The value graph is built bottom-up and immutable; the only way an *already
allocated* (possibly already promoted/old) object acquires a *new* pointer to a
*younger* object is when an old, blackholed thunk is resolved to a value that was
allocated after the thunk — i.e. `Thunk::state` transitions `Blackhole →
Forced(young_value)`. We therefore emit the card-marking write barrier *only*
around the thunk-update helper, not around general field stores (there are no
general field stores — attrsets, cons cells, and strings are initialized once
and never mutated). This is a direct dividend of immutability: the generational
collector's most invasive instrumentation shrinks to a single, centralized,
rarely-hot code path behind the `alloc-via-symbols` wall.

```rust
/// Resolves a forced thunk to its value. This is the ONLY mutating write into
/// an already-allocated heap object, and therefore the only site that needs a
/// generational write barrier.
///
/// # Safety
///
/// Caller holds the forcing right to `thunk` (it is blackholed by this thread).
/// The barrier records `thunk -> value` in the remembered set if `thunk` is old
/// and `value` is young.
unsafe fn thunk_resolve(rt: *mut Runtime, thunk: *mut Thunk, value: Value) {
    // SAFETY: thunk is blackholed and owned by the current forcing context.
    aos_gc_write_barrier(rt, thunk as *mut Obj, value); // card-mark if old<-young
    // `state` is the AtomicU64 from doc 05 §6; publish the Forced(value)
    // encoding with a release store so other threads see a fully-initialized
    // result (see parallel evaluation, doc 13).
    (*thunk).state.store(encode_forced(value), Ordering::Release);
}
```

---

## 5. Region inference (Tofte–Talpin) as the finer-grained generalization

### 5.1 The idea

**Region-based memory management** (Tofte and Talpin) infers, by a type-and-
effect analysis, the *lifetime* of every allocated value and assigns it to a
**region**; the store becomes a *stack of regions*, and memory management
"predominantly consists of pushing and popping regions"
([Tofte & Talpin, *Region-Based Memory Management*][tofte-talpin];
[*A Retrospective*][region-retro]). The headline guarantee — proven for the full
language including higher-order functions and recursive datatypes — is that
"all well-typed programs will be free of dangling pointers at runtime" *without*
a garbage collector. The ML Kit with Regions demonstrated a real,
GC-free Standard ML implementation on this basis.

For `aos-nix`, region inference is the principled generalization that connects
the two tiers:

- The **one-shot arena** of Tier A is the degenerate case: *one* region for the
  whole program, popped at `exit`.
- **Inferred sub-regions** let us pop provably-dead allocations *during* a run
  without a tracing collector — recovering memory in CLI mode (addressing the
  §3.3 peak-memory objection) and reducing nursery pressure in daemon mode.
- Where region inference is *imprecise* (a value's lifetime is data-dependent
  and not statically bounded), allocation falls back to the GC'd heap. **Regions
  and tracing GC compose**: regions handle the statically-obvious lifetimes
  (the common case in a batch evaluator with lots of locally-scoped `let` and
  `with`), the collector handles the residue.

### 5.2 Why Nix is a good fit, and the open questions

Nix's purity and absence of mutable references remove the hardest cases the ML
Kit had to handle (regions interacting with `ref` cells). Many Nix allocation
sites are obviously region-scoped: the attrset built inside a `let` body that
does not escape, the cons cells of an intermediate list consumed by a `foldl'`,
the temporary environment of a non-escaping lambda application. These overlap
heavily with the **escape analysis** of
[laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md);
indeed escape analysis is the dual — "does not escape" ⇒ "stack/region
allocatable" ⇒ "scalar-replaceable".

**This is the most research-grade part of the GC design, and we mark it
explicitly as such.** Open questions:

- **Laziness vs. region lifetimes.** A thunk allocated in region *r* may be
  forced after *r* would naively be popped (the value escapes via a captured
  closure). The type-and-effect system must account for the latent effect of
  forcing. The interaction of *full region inference* with *non-strict
  evaluation* is precisely where the classical algorithm is most delicate, and
  we do not assume the textbook algorithm transfers unchanged.
- **Cost/benefit vs. just running the generational collector.** A
  cache-resident copying nursery is *already* nearly free for short-lived data.
  Region inference must earn its complexity by reclaiming things the nursery
  cannot cheaply reach (large, medium-lived intermediate structures), or by
  enabling GC-free CLI runs with bounded peak. This is a **measure-first**
  decision (RFC §Roadmap): ship the arena + generational GC first, add region
  inference only where profiles show medium-lived allocation that neither tier
  handles well.

We therefore scope region inference as: (1) a *conceptual unification* of arena
and nursery, realized concretely as (2) a **lexical/escape-driven region pass**
that pops obvious non-escaping sub-arenas, with (3) *full* effect-based region
inference built as the advanced P8 variant and kept only where profiles show it
beats the simpler lexical/escape policy.

---

## 6. Concurrent, low-pause collection (daemon, follow-up)

### 6.1 When it matters

Stop-the-world pauses are irrelevant to a CLI batch job (Tier A never collects)
and tolerable for a daemon doing bulk CI evaluation. They become a problem only
for *interactive* daemon use (editor integration, a responsive registry hub)
where a multi-hundred-millisecond major-GC pause is user-visible. Concurrent
collection is therefore explicitly a P8 **advanced measured variant**, last in
the RFC's ranked build sequence, not part of the first cut.

### 6.2 The ZGC / Shenandoah model and how it maps

When we do build it, the model is **colored pointers + load barriers**, as in
**ZGC** and **Shenandoah**. ZGC stores GC metadata *in spare high bits of the
pointer* (the "color"), encoding whether the referent is known-live, whether the
address is current, etc., and uses a **load barrier**: when the mutator loads a
reference, a small injected code sequence checks the color and, if the pointer
is stale (the object was concurrently relocated), repairs it to the new location
before the mutator ever sees a bad address ([JEP 333][jep-333];
[*Deep Dive into ZGC*, TOPLAS][zgc-toplas]; [JEP 439, Generational
ZGC][jep-439]). This lets the collector relocate objects *concurrently with a
running mutator* with sub-millisecond pauses, agreeing on pointer *color* rather
than synchronizing on every object's authoritative address.

This dovetails with our design in two convenient ways:

1. **We already tag pointers.** The WHNF/constructor pointer tagging from
   [value representation](05-value-representation.md) means the mutator already
   masks pointer bits before dereferencing. A GC color is *more* tag bits in the
   same spare-bits budget, and the unmask already on the hot path can fold in the
   load-barrier check. The marginal cost of the barrier is lower than in a
   runtime that wasn't already tagging.
2. **The barrier surface is tiny.** A ZGC load barrier fires on reference loads;
   our reference loads are concentrated in `force`, `select` (attrset access),
   and list traversal — the same handful of runtime symbols we already route
   through. Emitting load barriers becomes "augment `force`/`select_ic` and the
   GC read path", not "instrument every memory access".

### 6.3 Inlining the barriers without breaking `alloc-via-symbols`

The `alloc-via-symbols` contract says compiled code calls runtime symbols. For
the *cold* tree-walk and baseline tiers, a `call` to `aos_gc_read_barrier` is
fine. For the *optimized* tier, an out-of-line call on every reference load
would dominate; there the optimizing JIT **inlines the barrier fast path**
(color-check, predicted not-taken) and calls out only on the slow path
(relocation/repair) — exactly HotSpot's strategy of inlining the TLAB/barrier
fast path and calling the runtime on the slow path. Crucially, *which* barrier is
inlined is a property of the installed collector, decided when the optimized
tier compiles; the *interpreted* and *baseline* tiers continue to go through the
symbol. The ABI stays frozen; only the optimizer specializes.

### 6.4 The hard part: concurrent GC × thunk mutation

The genuinely difficult interaction — flagged here as the central risk of
concurrent collection — is **thunk update racing with relocation**. Forcing
mutates a thunk (§4.5); a concurrent collector may be relocating that same
thunk. The mutation surface being a *single* well-typed transition
(`Suspended → Blackhole → Forced`) is what makes this tractable: the CAS that
claims a thunk for forcing (see
[parallel evaluation](13-parallel-evaluation.md)) and the load barrier that
repairs a relocated reference must be made jointly atomic with respect to the
`state` word. This is one focused concurrency problem on one object kind, versus
the JVM's "any field of any object, any time". We still treat it as research-
grade and gate it behind the differential harness and stress testing.

---

## 7. The dual-tier decision and its rationale

```text
                aos-nix invocation
                       │
          ┌────────────┴─────────────┐
          │                          │
   single-shot CLI / harness    long-lived daemon
          │                          │
   install BUMP ARENA          install GENERATIONAL GC
   (Tier A)                     (Tier B)
   - alloc = ptr bump           - cache-resident copying nursery
   - never collect              - precise (tag+shape scanning)
   - drop arena at exit         - one write barrier (thunk update)
   - region pops for peak       - major GC rare
          │                          │
          │                    interactive daemon?
          │                          │ yes
          │                    upgrade to CONCURRENT
          │                    (colored ptrs + load barriers)
          └──────────── same compiled code, same primops ───────────┘
                        (alloc-via-symbols makes both identical)
```

The two tiers are not a hedge; they are the *correct* answer to two genuinely
different workloads. A batch job's optimal allocator (never free) and a daemon's
optimal allocator (collect young cheaply, relocate concurrently) are different
points in design space, and the only reason we can serve both from one codebase
is the `alloc-via-symbols` indirection. The default and overwhelmingly common
case for AOS's build-time bottleneck — `aos-nix eval` shelling out a `.drv` —
is **Tier A**, whose allocation fast path (a pointer bump) is about as cheap as
allocation gets, and which is also the simplest and lowest-risk to ship first.

---

## 8. Correctness, determinism, and the compatibility constraint

GC must be **observationally invisible**. The acceptance gate (see
[differential testing and benchmarking](15-differential-testing-and-benchmarking.md))
diffs `.drv` bytes against `nix-instantiate`; memory management may not perturb a
single byte. Two specific hazards:

1. **GC must not change value identity in observable ways.** Nix exposes no
   `eq`-by-address operation to user code, and `==` on attrsets/lists is
   structural, so a *moving* collector is observationally invisible *provided*
   it updates every reference precisely. Hash-consing (which gives O(1) pointer
   equality used *internally* for the incremental cache) must be consistent
   across collection — hash-consed permanent values are not relocated by the
   nursery collector, preserving their identity for the cache keys in
   [incremental evaluation cache](12-incremental-evaluation-cache.md).
2. **Allocation order / addresses must not leak into output.** No `.drv` content
   may depend on a heap address (it must not in C++ Nix either, since BDW-GC
   addresses are nondeterministic). Deterministic attribute iteration order
   comes from the shape/sorted-key representation, *not* from allocation order
   (see
   [attribute sets, hidden classes, and inline caches](09-attribute-sets-hidden-classes-and-inline-caches.md)),
   so a collector that compacts and reorders the physical heap cannot change
   observed order.

The collector is therefore validated on two fronts: the **differential `.drv`
harness** (end-to-end observational equivalence) and **miri / sanitizers run
against the safe tree-walk oracle** (memory-safety of the GC-free path), with the
moving collector additionally stress-tested under forced-frequent-GC modes (a
"GC stress" flag that collects at every safepoint to flush out missing roots and
barrier bugs — the standard technique GHC and the JVM both use to validate
collectors).

---

## 9. Implementation phasing

Aligned with the RFC roadmap (memory management is item 2, after the incremental
cache):

| Phase | Deliverable | Risk | Depends on |
|---|---|---|---|
| **M0** | `alloc-via-symbols` ABI; allocator vtable; tree-walk oracle allocates through it | Low | value rep (05) |
| **M1** | **Bump arena (Tier A)**; drop-at-exit; this alone services all CLI eval | Low | M0 |
| **M2** | Precise root/field scanning via tags + shapes; stack maps from Cranelift | Med | M0, shapes (09), Cranelift tiering (08) |
| **M3** | **Generational copying GC (Tier B)**; cache-resident nursery; single thunk-update write barrier | Med | M2 |
| **M4** | Escape-driven region pops (lexical region inference); bounded-peak CLI | Med | escape analysis (07) |
| **M5** | Full effect-based region inference | **Research** | M4 |
| **M6** | Concurrent colored-pointer + load-barrier collector; barrier inlining in optimized tier | **Research** | M3, pointer tagging (05), parallel (13) |

M1 is the high-value, low-risk first cut: it makes CLI evaluation use the
fastest possible allocator and is sufficient to ship the differential harness
and the eval-time baseline. Everything past M3 is gated on measurement.

---

## 10. Open questions

1. **Nursery sizing policy.** Fixed (cache-resident) vs. adaptive? GHC uses a
   tunable nursery; the optimum for `nixpkgs`-shaped fan-out is unmeasured.
2. **Region inference under laziness.** Does the type-and-effect system remain
   sound and *useful* when latent forcing effects extend region lifetimes, or
   does it degrade to "almost everything is the global region"? (§5.2)
3. **Hash-cons table lifetime in the daemon.** Permanent hash-consed values are
   immortal by construction, but a long-lived daemon may want to *evict* cold
   interned values. Eviction interacts with the incremental cache's pointer-
   equality keys (12). Likely answer: never evict within a run; clear between
   epochs.
4. **Concurrent-GC × CAS-thunk atomicity.** The precise memory ordering that
   makes thunk-claim CAS and load-barrier repair jointly correct (§6.4) needs a
   formal argument and TSAN/loom validation before M6 ships. (13)
5. **Cross-tier flip cost.** When Tier A's safety valve installs Tier B
   mid-run, the already-allocated arena must become a GC root region. Cost and
   correctness of that transition are unverified; the safe fallback is to treat
   the pre-flip arena as one immortal old-generation region.

---

## Implementation checklist

Per-feature tracker for memory management and garbage collection (the alloc-via-symbols ABI, the bump arena, out-of-core spill, precise generational GC, region inference, and concurrent low-pause collection); master roll-up: [implementation checklist (all phases)](22-implementation-checklist-all-phases.md). Per the unlimited-budget mandate, every item here is in scope — including research-grade ones — built in dependency order and gated by the differential harness, never cut for scope.

GC must be observationally invisible (§8): every item is gated by the differential `.drv` harness (no perturbed byte), by miri/ASan on the safe tree-walk oracle, and — for the moving and concurrent collectors — by a GC-stress mode that collects at every safepoint, plus `loom`/Miri for the concurrent interactions.

### The `alloc-via-symbols` ABI (§2)

- [x] Current P1 safe allocation substrate: the tree-walk `EvalHeap` routes heap
      object creation through `BumpArena` `aos_alloc_*` entry-point-shaped Rust
      helpers (`thunk`, `attrs`, `cons`/`list`, `string`, `raw`, plus lambda),
      reserves opaque aligned `HeapObject` handles in never-free owned chunks,
      registers typed side-table records, and exposes arena accounting for tests.
- [x] Current P3 allocation-dispatch precursor: `ratchet-oracle::runtime::alloc`
      installs a `RuntimeAllocator` strategy object for the tree-walk oracle;
      `EvalHeap` no longer owns `BumpArena` directly and routes every typed heap
      allocation through the centralized `aos_alloc_*`-shaped methods. The only
      current backend is Tier-A `BumpArena`, so the frozen exported runtime/JIT
      ABI row below remains open.
- [ ] Frozen runtime allocation ABI still open: actual exported
      `unsafe extern "C"` `aos_alloc_thunk` / `aos_alloc_attrs` /
      `aos_alloc_cons` / `aos_alloc_string` / `aos_alloc_raw` symbols, startup
      allocator vtable selection, every-tier/every-primop routing through those
      symbols, and collector/JIT swapping without caller recompilation (§2) —
      **M0** (within **P3**), `S-8`.
- [ ] Centralized allocation safepoints and the single write-barrier wall behind these symbols (§2) — **P3**, `S-8`.
- [x] Current allocation-safepoint metadata precursor:
      `ratchet-oracle::runtime::alloc` records an `AllocationSafepoint` event
      at every centralized `RuntimeAllocator` `aos_alloc_*` entry point and at
      every permanent-shared allocation entry point, capturing the allocator
      tier, entry-point name, object kind, allocation sizes, and post-allocation
      arena accounting. Tests prove every worker route (`thunk`, `lambda`,
      `attrs`, `cons`, `list`, `string`, `raw`) and every permanent route
      (`attrs`, `list`, `string`) records exactly one safepoint. This is
      metadata only: it does not yet invoke a collector, build a live root set,
      run GC-stress collection, export C ABI symbols, or integrate the
      thunk-resolve write barrier with allocation dispatch.
- [x] Current GC-stress safepoint-poll precursor:
      `ratchet-oracle::runtime::alloc::GcStressPolicy` lets worker and
      permanent-shared allocators mark allocation safepoints as collector-poll
      candidates under disabled, every-safepoint, or every-N-safepoints stress
      policies; `AllocationSafepoint::gc_poll_reason` records why the poll was
      requested, and `EvalHeap::set_gc_stress_policy` installs one policy across
      both allocation domains. Periodic policies use the allocator lifetime
      safepoint sequence, and enabled stress policies poll once the sequence
      saturates. Tests cover zero-period rejection, default-disabled behavior,
      every-safepoint polling, lifetime-sequence periodic polling, saturation
      polling, permanent-shared allocation polling, and heap-level installation
      across both domains. This is poll intent only: no live root set is built
      and no collector or GC-stress collection is invoked yet.

### Tier A — bump-pointer one-shot arena (§3)

- [x] P1 safe owned-chunk arena prerequisite: `BumpArena` established aligned
      monotonic allocation by cursor/limit checks, geometric or dedicated
      oversized chunks, never-free object handles, and allocation stats/layout
      tests before the P3 mmap backend replaced the concrete chunk storage.
- [x] Current P3 mmap-backed chunk precursor: `BumpArena` now reserves chunks
      with anonymous `mmap`, releases them with `munmap` on arena drop, reports
      logical reserved bytes plus page-rounded mapped bytes, and exposes
      `ThreadLocalBumpArena` for per-worker Tier-A arenas. The full Tier-A row
      below remains open until CLI-wide/full-closure byte-green proof and
      benchmark evidence are recorded under the runtime default.
- [ ] Final Tier-A runtime arena still open: geometric `mmap` chunk growth,
      thread-local per-worker arenas, per-chunk `munmap` drop (O(#chunks)),
      CLI-wide Tier-A default, and byte-green differential proof under Tier A
      (§3.1–§3.2) — **P3**, `S-8`/`C-10` (per-invocation first).
- [ ] Distinct permanent arena for hash-consed/shared values, never freed by a worker-arena drop (§3.2) — **P3**, ties to hash-consing ([05](05-value-representation.md) §5.5).
- [x] Current permanent-shared arena precursor:
      `ratchet-oracle::runtime::alloc::PermanentSharedAllocator` provides a
      separate permanent domain with accounting independent from the Tier-A
      worker allocator, and `EvalHeap` owns both domains. Canonical hash-consed
      strings, paths, list spines, and flat attrsets allocate through the
      permanent domain and keep side-table records marked `PermanentShared`;
      thunks, lambdas, and primop wrappers stay in the worker domain. Tests pin
      split accounting, worker/permanent placement, and the current caveat that
      permanent list/attr containers may still reference worker-domain child
      handles that precise root scanning must see. The exported allocator ABI,
      process-wide daemon lifetime, worker-arena reset/drop admission policy,
      and Tier-B collector integration remain open in the rows above and below.
- [ ] Configurable high-water memory budget (one knob) driving the three escalating responses (§3.6) — **P3**, `C-17`.
- [x] Current high-water budget policy precursor:
      `ratchet-value::heap::budget` defines the single-knob decision table for
      resident memory pressure: remain in Tier A below the derived soft limit,
      request cold/dead-page spill or advice near/above the budget when cheap
      reclaim can restore residency, and request Tier B only when projected
      residency stays above the hard budget after known cheap reclaim. Tests pin
      zero-budget rejection, derived headroom, cheap-reclaim saturation, and the
      Tier-A-vs-Tier-B boundary. No CLI/env/daemon configuration, actual CA-store
      spill, `madvise` call, live RSS sampler, or collector installation is wired
      yet, so the full row above remains open.

### Out-of-core spill and OS cooperation (§3.4–§3.5)

- [ ] CA-store-backed spill: evict cold hash-consed values to the `mmap`'d CA store leaving a content-hash handle, rematerialize on demand, write-back-free because the hash is the address (§3.4) — **P3/P8**, `C-17`; depends on the incremental cache's CA store ([12](12-incremental-evaluation-cache.md)).
- [ ] `madvise` portability shim (`advise_dead`/`advise_cold`/`advise_evict`/`advise_huge` → `DONTNEED`/`FREE`/`COLD`/`PAGEOUT`/`HUGEPAGE`), no-op fallback off-Linux; correctness never depends on advice being honored (§3.5) — **P3/P8**, `C-17`; benchmark-gated.
- [ ] Region-pop reclamation within arena mode (intra-run dead sub-arena pop) (§3.3 item 2, §5) — see region inference below.

### Tier B — precise generational copying GC (§4)

- [ ] Precise, generational, copying collector for the daemon: cache-resident copying nursery (work ∝ survivors), promotion policy, rarely-collected old generation (§4.1–§4.3) — **P3**, `S-8`; harness byte-green under Tier B, miri/ASan-clean.
- [x] Current minor-GC frontier precursor:
      `ratchet-value::heap::gc::MinorGcPlan` builds the future minor
      collection's initial young-object survivor frontier from precise roots
      plus a caller-supplied remembered set that must be complete for the same
      collection epoch and target current nursery objects. It filters non-young
      roots, deduplicates young roots plus remembered targets, validates unique
      nursery age metadata, and classifies each survivor as copy-to-next-nursery
      or promote-to-old with an age-threshold policy. This is not yet a copying
      collector: remembered-set epoch validation, field expansion,
      relocation/writeback, nursery semispace storage, old-generation
      collection, GC-stress mode, and byte-green Tier-B harness execution remain
      open in the full collector row above.
- [ ] Precise root + field scanning: type-tag → layout, `ShapeId` → attrset field map, explicit roots (value stack, force continuation, spilled primop args, interned tables) — no conservative C-stack scan; Cranelift stack maps at JIT tiers (§4.4) — **P3** for tree-walk roots; JIT stack maps **P6** ([08](08-execution-tiers-and-cranelift.md)).
- [x] Current tree-walk precise root/field-scan graph precursor:
      `ratchet-oracle::eval::heap::roots` provides explicit
      `EvalRootSet` descriptors for value-stack slots, force continuations,
      primop arguments, permanent interned/hash-cons roots, and future
      stack-map slots supplied by tests or future safepoint builders;
      `EvalHeap::scan_precise_roots` validates evaluator-owned heap tags
      against the typed side table before deduplication, filters inline and
      external-runtime values out of roots/edges, uses stable sorted labels for
      interned roots, and scans lists, shape-qualified attr bindings,
      lambda/thunk captured environments, primop arguments, suspended thunk
      captures, blackholed thunk captures, and forced-thunk cached results. This
      is a copied-value graph report, not relocation-writeback slots, and the
      production tree-walk safepoint root builder, real Tier-B collector, and
      Cranelift stack-map emission/consumption remain open in the row above and
      in [08](08-execution-tiers-and-cranelift.md).
- [ ] The single generational write barrier at `thunk_resolve` (`Blackhole → Forced(young)`), card-marking only there — no general field-store barrier (§4.5) — **P3**, `S-8`.
- [x] Current thunk-resolve write-barrier precursor:
      `ratchet-value::heap::gc` defines the generational decision table for the
      only mutating heap transition, records old/permanent-to-young thunk
      resolution edges in a deduplicating `RememberedSet`, and disables the
      barrier in one-shot arena mode. `ratchet-oracle::eval::thunk` routes
      `ForceGuard` publication through `finish_with_barrier`, with the default
      tree-walk `finish` using a disabled barrier and tests proving barrier
      execution happens while the thunk is still blackholed and before the
      forced result is published. The real daemon card table, object-generation
      metadata, and Tier-B collector integration remain open in the row above.
- [ ] Hash-consed values allocated in non-collected permanent space, bypassing promotion churn (§4.3) — **P3**, `M-12` sizing measure-gated.
- [ ] Cross-tier flip: Tier A safety valve installs Tier B mid-run, treating the pre-flip arena as one immortal old-generation region (§3.3 item 3, §10.5) — **P3**, research-grade transition cost (IN SCOPE), gated by harness + GC stress.

### Region inference (§5)

- [ ] Lexical/escape-driven region pass: pop obvious non-escaping sub-arenas (the committed subset, dual of escape analysis) (§5.1–§5.2) — **P8** (`M4`-style escape-region pops), `M-14`; depends on escape analysis ([07](07-laziness-and-whole-program-analyses.md) **P4**); benchmark-gated.
- [x] Current region precursor: `ratchet-value::heap::region` defines the
      conservative region-placement decision table used by future IR/effect
      analysis. Only private allocations with positive no-escape,
      no-latent-force, speculable-effect, bounded-lexical-lifetime proofs select
      `LexicalSubregion`; permanent shared values bypass region pop, and every
      missing proof falls back to the active root arena or daemon GC heap.
- [ ] Full effect-based region inference (Tofte–Talpin) accounting for latent forcing effects under laziness — the research-grade tail, now IN SCOPE (§5.2) — **P8**, `R-5`; built in dependency order after the lexical pass, gated by the differential harness; not cut for scope.

### Concurrent, low-pause collection (§6)

- [ ] Concurrent moving collector for interactive daemon use: colored pointers + load barriers (ZGC/Shenandoah model), co-designed with the existing WHNF/constructor pointer tag bits (§6.1–§6.2) — **P8**, `R-1`/`R-3` (research-grade, IN SCOPE), daemon-only; sidestepped by the bump arena in CLI mode.
- [x] Current concurrent-GC precursor: `ratchet-value::heap::concurrent_gc`
      defines the safe daemon-only barrier-address/load-barrier decision
      contract. Already-uncolored aligned address bits with collector-supplied
      `Current` color take the fast path in daemon mode, stale colors route to
      relocation/marking repair, and one-shot arena mode disables concurrent
      barriers. It does not decode high-bit-colored pointer words, move objects,
      dereference addresses, allocate memory, or alter the bump arena.
- [ ] Load-barrier fast-path inlining in the optimized tier without breaking `alloc-via-symbols` (cold tiers keep the symbol call) (§6.3) — **P8**, `R-2`; depends on tier-2 ([08](08-execution-tiers-and-cranelift.md) **P7**).
- [ ] The hard interaction: thunk-update CAS made jointly atomic with load-barrier relocation repair on the `state` word (§6.4) — **P8**, `R-4` (the load-barrier proof remains research-grade with R-1/R-2); gated by `loom`/Miri + GC stress before shipping.
- [x] Current thunk-mutation barrier precursor: `ratchet-value::heap::concurrent_gc`
      classifies the required ordering before a thunk-state mutation. In daemon
      mode, a `Current` thunk address permits the mutation only after the
      load-barrier fast path; stale colors require relocation/marking repair
      before claim/publish; one-shot arena mode disables the barrier. The real
      CAS integration and `loom`/Miri proof remain open.

### Correctness gates (§8)

- [ ] Moving collector preserves value identity (precise reference update) and never leaks allocation order/addresses into `.drv`; deterministic iteration comes from shape/sorted-key order, not allocation order (§8) — every GC phase, harness byte-green.
- [ ] GC-stress mode (collect at every safepoint) to flush missing roots / barrier bugs (§8) — **P3** onward.

## References

Memory-management and collector prior art verified for this document:

- Hans-J. Boehm, *Garbage Collection in an Uncooperative Environment* — the
  conservative collector C++ Nix relies on; its false-retention and
  non-moving limitations are the baseline we beat.
  <http://shiftleft.com/mirrors/www.hpl.hp.com/personal/Hans_Boehm/spe_gc_paper/preprint.pdf>
- BDW-GC project (bdwgc) — confirms conservative scanning and unnecessary-
  retention as an open problem.
  <https://github.com/bdwgc/bdwgc>
- Marlow, Harris, James, Peyton Jones, *Parallel Generational-Copying Garbage
  Collection with a Block-Structured Heap* (ISMM 2008) — GHC's nursery +
  copying + immutability-enables-parallel-copy design, the closest lineage.
  <https://www.microsoft.com/en-us/research/wp-content/uploads/2008/06/par-gc-ismm08.pdf>
- Tofte & Talpin, *Region-Based Memory Management* (Information and Computation,
  1997) — region inference, stack-of-regions, dangling-pointer-freedom proof.
  <http://ropas.snu.ac.kr/lib/dock/ToTa1997.pdf>
- Tofte et al., *A Retrospective on Region-Based Memory Management* (HOSC 2004)
  — ML Kit with Regions, GC-free SML, practical lessons.
  <https://link.springer.com/article/10.1023/B:LISP.0000029446.78563.a4>
- A. Shipilev, *JVM Anatomy Quark #18: Scalar Replacement* — clarifies that
  HotSpot does scalar replacement, not literal stack allocation; the precise
  semantics our escape-analysis tie-in relies on.
  <https://shipilev.net/jvm/anatomy-quarks/18-scalar-replacement/>
- JEP 333, *ZGC: A Scalable Low-Latency Garbage Collector* — colored pointers +
  load barriers, the concurrent-collection model for the daemon tier.
  <https://openjdk.org/jeps/333>
- JEP 439, *Generational ZGC* — generational extension of ZGC.
  <https://openjdk.org/jeps/439>
- *Deep Dive into ZGC: A Modern Garbage Collector in OpenJDK* (ACM TOPLAS) —
  authoritative architecture reference for colored pointers and load barriers.
  <https://dl.acm.org/doi/full/10.1145/3538532>
- Cranelift JIT (`cranelift-jit`) — symbol table, memory allocation, and
  relocation management used to register `aos_alloc_*` and primops.
  <https://github.com/bytecodealliance/wasmtime/tree/HEAD/cranelift/jit>
- `madvise(2)` — Linux manual page; verified semantics of `MADV_DONTNEED`,
  `MADV_FREE`, `MADV_COLD`, `MADV_PAGEOUT`, and `MADV_HUGEPAGE` used for the
  OS page-level cooperation in §3.5 (advisory hints, Linux-specific, kernel
  version gates).
  <https://man7.org/linux/man-pages/man2/madvise.2.html>

[bdwgc-paper]: http://shiftleft.com/mirrors/www.hpl.hp.com/personal/Hans_Boehm/spe_gc_paper/preprint.pdf
[bdwgc-repo]: https://github.com/bdwgc/bdwgc
[ghc-gc]: https://www.microsoft.com/en-us/research/wp-content/uploads/2008/06/par-gc-ismm08.pdf
[tofte-talpin]: http://ropas.snu.ac.kr/lib/dock/ToTa1997.pdf
[region-retro]: https://link.springer.com/article/10.1023/B:LISP.0000029446.78563.a4
[jep-333]: https://openjdk.org/jeps/333
[jep-439]: https://openjdk.org/jeps/439
[zgc-toplas]: https://dl.acm.org/doi/full/10.1145/3538532
[cranelift-jit]: https://github.com/bytecodealliance/wasmtime/tree/HEAD/cranelift/jit
[madvise]: https://man7.org/linux/man-pages/man2/madvise.2.html
