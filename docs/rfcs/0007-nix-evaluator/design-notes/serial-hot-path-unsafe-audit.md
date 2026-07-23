# Serial evaluator hot-path and `unsafe` audit

**Status:** measured exploration plus first implementation, 2026-07-23. This
note compares the Candidate-C tree walker with the pinned C++ Nix 2.24.12 tree
walker. It does not propose bytecode.

## Conclusion

The evaluator is not slow because Rust needs indiscriminate `unsafe`, and a
different one-word tag encoding is not a plausible 2-5x fix. It is slow because
the serial hot path repeatedly crosses abstractions built for context-free
values, checked heap diagnostics, snapshots/GC, and parallel publication while
C++ Nix operates on stable `Value *` and `Env *` directly.

Selective `unsafe` is justified if it creates a **trusted serial arena path**:

1. resolve a Candidate-C `(domain, index)` through a heap-owned cached base;
2. validate the value tag/domain once at an evaluator boundary;
3. dereference the non-moving flat object directly for the duration of the
   serial evaluation; and
4. borrow thunk/lambda payloads in place rather than clone or mint shared
   handles merely to release an `EvalHeap` borrow.

The checked/context-free paths must remain for FFI, snapshots, shared heaps,
GC-stress, parallel workers, and diagnostics. The optimization is a split
between trusted serial and general paths, not a global weakening of checks.

## What the C++ reference actually does

The pinned C++ evaluator is a tree walker too, but its inner representation is
substantially less mediated:

- `Env` is a raw parent pointer followed by inline `Value *` slots
  (`eval.hh:135-139`). A lexical lookup follows `env->up` and indexes
  `env->values[var.displ]` (`eval.cc:873-876`).
- A thunk stores direct `Env *` and expression pointers in the `Value` payload.
  `forceValue` saves those pointers, overwrites the same `Value` with a
  blackhole, evaluates into that same cell, and restores the thunk on an
  exception (`eval-inline.hh:85-108`).
- `ExprVar::eval` gets the slot's `Value *`, forces the shared cell in place,
  then copies the result (`eval.cc:1347-1352`).
- Lambda application allocates one `Env`, assigns its raw parent and argument
  pointers, and evaluates the body (`eval.cc:1499-1584`).

This is not a bytecode advantage. It is a direct-object, mutable-cell advantage
inside another tree-walking interpreter.

## What the shipped Rust path pays

Candidate C already gives the evaluator an 8-byte value. The high word carries
kind/domain/forced metadata and the low word carries an inline `i32` or arena
index. Historical carrier A/B data show Candidate C is neutral on
`lambda-interp` (0.983x versus the old direct-pointer baseline) and roughly
within 1-2% on the package and wide-eval legs. Therefore carrier compression
itself cannot explain a 4.6x instruction gap.

The remaining hot-path layers are:

- `Value::as_heap_ptr` scans the process-global atomic reservation registry to
  turn `(domain, index)` into a pointer. The registry's own documentation says
  arena-internal hot paths should bypass it, but `force_value` and the typed
  getters still enter through context-free value accessors.
- `get_thunk_ptr`/`clone_lambda` then resolve the pointer through the flat
  object store, check membership and kind, handle retired/record fallbacks, and
  optionally touch epoch/counter state.
- Force uses an atomic state machine and `AtomicValueCell`. Candidate C reduces
  a cell read to one `AtomicU64`, but it remains an acquire load plus checked
  word decode even in a single-thread evaluator.
- Lambda application clones lambda metadata to end the heap borrow, constructs
  an `Arc<EvalFrame>`, installs an active `Vec<Arc<EvalFrame>>`, and enters the
  general root/call-scope protocol.
- Captured lexical values are commonly flat and efficient, but reading them
  still resolves the owning closure and validates its tail handle.

## Current `lambda-interp` evidence

Linux builder, release Candidate-C binary, cache-off/cold-only:

```text
baseline retired instructions (three runs):
  71,692,560,337
  71,692,468,873
  71,692,741,962

baseline wall (five quiet samples):
  median 5.851 s
```

The stock evaluator counters for the same deterministic evaluation report:

```text
function_calls              6,833,414
thunks_forced               7,083,450
flat_thunk_resolutions     22,333,542
flat_lambda_resolutions     6,833,414
env_frame_allocs            7,250,083
captured env installs      13,916,861
empty captured installs    12,833,477
```

Only 1,083,384 installs are non-empty. Of 83,368 distinct non-empty captured
environments, 83,367 are installed exactly once. Install depth mass is
2,083,482 across 13,916,861 installs (average 0.150). This rules out memoized
environment flattening and deep-chain copying as the primary fix for this
benchmark. An O(1) environment head is still the right representation, but the
bigger opportunity is removing the general call/force scaffolding around that
head.

### Stacker ceiling experiment

Temporarily replacing the `stacker::maybe_grow` wrapper around every
`eval_node` with a direct call produced:

```text
retired instructions (three runs):
  70,496,067,227
  70,496,442,912
  70,496,070,874
```

That is a repeatable 1.67% instruction reduction. The experiment was reverted.
Stack-growth checking should eventually be hoisted or made less frequent, but
it cannot close the gap.

## Ranked experiments

### 1. Heap-owned pointer resolution and trusted typed dereference

Add a serial-only resolver that checks the Candidate-C domain against the
`EvalHeap`, adds the index to a cached reservation base, and returns a typed
flat payload through one direct dereference. Keep the current getter as the
checked fallback.

Required invariants for the `unsafe` block:

- the reservation mapping outlives every returned borrow;
- serial production placement is flat and non-moving during the borrow;
- domain and index were produced by this heap and remain in bounds;
- the value word's semantic tag agrees with the allocation header at the
  validation boundary;
- no sweep, restore/rebase, region pop, or parallel mutation can run while the
  borrow is live.

Measure it first on thunk re-force and lambda apply, which account for about
29.2M flat closure resolutions in this benchmark. Do not rewrite every getter
until those two choke points demonstrate a material win.

### 2. Borrow closure payloads through a scoped evaluator API

`clone_lambda` exists so application can mutate the evaluator after obtaining
lambda metadata. A scoped API (or carefully documented stable pointer) can
borrow the arena payload while evaluating the body, avoiding metadata clones
and refcount traffic. Apply the same pattern to the force path so a serial flat
thunk does not need an `Arc` merely to escape the heap borrow.

This is more consequential than pointer tagging: it changes the ownership work
performed per call/force, not just the address decode.

### 3. Split serial cells from parallel cells

The serial evaluator should not pay CAS/acquire/release and `Sync`-compatible
frame storage merely because parallel forcing exists. A serial `Cell<Value>` /
plain thunk-state backend can be selected with the serial heap, while shared
heaps retain `AtomicValueCell` and the parallel thunk protocol. Much of this can
remain safe Rust; `unsafe` is needed only if a stable arena borrow crosses
re-entrant evaluation.

This needs a representation boundary rather than weaker atomic orderings: on
x86, relaxed versus acquire/release often emits the same load/store, so merely
changing orderings is unlikely to recover much.

### 4. Make the active environment a persistent head

Captured environments already have a linked `Arc<EvalFrame>` head, but
application expands the head back into a `Vec` and installs it. Carrying the
head directly makes installs O(1) and aligns lookup with C++'s parent walk.
This can be implemented safely first; raw non-null frame pointers are a later
optimization only if `Arc` traffic remains measured.

The current benchmark says this is not a depth fix: it is a way to simplify the
per-call scope protocol and remove vector allocation/swap work.

### 5. Hoist stack and immutable-IR checks

The stacker experiment establishes a 1.67% upper bound for one wrapper.
Immutable lowered IR also permits unchecked indexing after a module-level
verification pass, but those checks should be grouped as a final 1-3% diet,
not treated as the main architecture.

## Tagged pointers specifically

Candidate B's low-bit tagged pointer prototype is useful, but not the leading
experiment:

- Candidate C is already one word and was measured roughly neutral against the
  prior direct-pointer carrier.
- A direct pointer removes the reservation-base lookup, but semantic kinds
  still need an object header or another tag scheme.
- A forced bit in a copied value word cannot update every alias. C++ gets the
  stronger shortcut by making environments and lists point to one shared,
  mutable `Value` cell and overwriting that cell when forced.
- Keeping memory at 8 bytes per value is compatible with a direct tagged
  pointer, but wide integers/floats, snapshots/rebase, GC movement, and shared
  arenas still need a side representation or a checked general path.

So the useful lesson from C++ is not merely “tag pointers.” It is “make the
serial evaluator's shared identity be a stable mutable cell, then touch that
cell directly.”

## Decision

Prototype experiments 1 and 2 together at the thunk/lambda choke points. They
have the clearest causal connection to the measured 29.2M resolutions and to
the structural difference from C++ Nix. Preserve Candidate C's 8-byte carrier,
the existing memory gates, and the checked general paths. Pursue serial-cell
splitting next if the direct arena path confirms that general-mode machinery is
a material part of the remaining instruction budget.

## First implementation result

The serial heap now caches its Candidate-C reservation identity and resolves
owned thunk/lambda handles with a checked `base + index` operation. More
importantly, the default serial, GC-disabled, non-tiered force path borrows an
inline flat thunk directly across evaluator re-entry. Shared heaps, parallel
payloads, GC modes, tiered execution, and compatibility records retain the
owned/shared checked path.

The one `unsafe` dereference is local to `force_value`, allowed explicitly
under a crate-wide `deny(unsafe_code)`, and documents these invariants:

- the pointer was resolved as a live flat thunk owned by this serial heap;
- the production flat arena is stable and non-moving;
- GC, payload shedding, replacement, and tier-engine mutation are disabled;
- the active force root prevents lexical reclamation during re-entry; and
- nested allocation uses disjoint stable arena addresses.

An equivalent direct-borrow experiment for lambda application passed the full
test suite but did not measurably reduce retired instructions, so it was
reverted rather than expanding the unsafe surface without evidence.

### `lambda-interp` measurements

Linux builder, release Candidate C, three alternating fresh-process samples:

```text
                         baseline                 direct serial thunk
retired instructions     71.693B                  69.873B   (-2.54%)
peak RSS                 3,876MiB                 2,766MiB  (-28.6%)
cold-only wall           15.385s                  9.960s    (-35.3%)
```

The wall samples were taken on a shared builder and are secondary to the
deterministic instruction count. The disproportionate wall and RSS reductions
are consistent with eliminating millions of transient `Arc<EvalThunk>`
allocations and their allocator-retained pages.

The standard three-sample parity harness remained byte-identical to the pinned
oracle:

```text
cold native mean         5.819s
C++ Nix mean             0.627s
native / C++             9.286x
warm native mean         5.267s
warm native / C++        8.406x
```

A fresh-process wrapper also measured about 431MiB peak RSS for C++ Nix. That
is materially stricter than the benchmark harness's post-evaluation RSS and
process-watermark delta, and shows that the native evaluator is not yet below
the requested memory ratio on this leg. Future performance gates should use
fresh child processes for both implementations so prior process watermarks
cannot hide the true peak.

## Second implementation result

Candidate-C `AtomicValueCell` now validates its private storage invariant at
the write boundary and reconstructs a value directly after the acquire load.
The cell can contain only the empty sentinel or an intact word copied from a
constructed `Value`; `AtomicU64` prevents tearing. The unchecked constructor is
documented at both carrier layers and confined to this cell load. Candidate-C
cell traffic is covered by the serial and K=4 parity batteries.

Fresh-process retired-instruction comparisons against the preceding
inline-frame-stack build were:

```text
lambda-interp   68.739B -> 67.820B  (-1.34%)
fib              8.160B ->  7.988B  (-2.10%)
attr-fixpoint    9.320B ->  9.316B  (-0.05%)
hash-loop       21.486B -> 21.378B  (-0.50%)
all-any         10.215B ->  9.975B  (-2.35%)
```

Together, the inline-frame-stack and trusted-cell changes reduce
`lambda-interp` from 69.525B to 67.820B instructions (-2.45%). Peak RSS is
unchanged at approximately 2,765MiB. The five-workload byte-parity run remained
green. This is a justified local `unsafe` optimization, but its size confirms
that checked word reconstruction is only one layer of the end-to-end gap.

The product acceptance axis remains the live AOS system evaluation, not this
stress case. On the same current release build, three byte-identical samples of
`systems.server.build.toplevel` measured 1.980s native versus 0.554s in pinned
C++ Nix 2.24.12: native is 3.58x slower cold (3.62x warm). Future microbench
work must explain and predict movement on that toplevel result.

## Third implementation result

The default one-shot serial force path now resolves a flat thunk once and uses
the same stable payload pointer for both the already-forced probe and suspended
body evaluation. Previously every first force performed one checked flat-store
resolution to inspect the force cell and a second resolution to recover the
payload for evaluation. Shared heaps, parallel payloads, GC, and tiered
execution retain the general checked path.

On `systems.server.build.toplevel`, the successful fresh-process retired
instruction count fell from 24.757B to 24.379B (**-1.53%**) at unchanged IPC.
The three-sample benchmark remained byte-identical to pinned C++ Nix, the
isolated telemetry test passed, and the Candidate-C oracle suite passed
serially (2,670 passed, 37 ignored). The parallel suite also passed 2,669 tests
before hitting its separately tracked process-global memory-telemetry isolation
flake.

## Fourth implementation result

A direct-resolver experiment tested whether the remaining flat-thunk cost was
primarily defensive pointer validation. The prototype used a local `unsafe`
mapped-reservation resolver that skipped the flat store's region-partition
search while retaining reservation bounds, alignment, object-header, and kind
validation. On a successful byte-identical
`systems.server.build.toplevel` run it retired 24.437B instructions versus the
24.379B baseline (**0.24% worse**). It was reverted: a broader unsafe surface
is not justified when the product workload regresses.

The same audit found a separate instrumentation bug: the normal production
path updated FV campaign `Cell<u64>` counters on every heap resolution even
though those detailed counters are emitted only for
`AOS_NIX_EVAL_STATS=1`. The full toplevel performs 18,750,711 such resolutions
(2,980,929 strings, 850 paths, 2,141,946 lists, 1,737,487 attrsets, 8,705,350
thunks, 3,169,141 lambdas, and 15,008 primops). Counter updates are now opt-in
with the stats-dump option; direct heap users retain counters by default, and
focused tests prove both disabled and enabled behavior.

Three fresh-process product runs retired 24.247-24.249B instructions, down from
24.379B by approximately **0.53%**, at unchanged 2.78-2.80 IPC. A separate
stats-enabled run retained all nonzero campaign counts, and full toplevel
`.drv` closure parity remained byte-green. This is a small uniform
instrumentation-tax removal, not a resolution of the remaining approximately
3.88x instruction ratio to pinned C++ Nix.

Gating the broader production telemetry set (allocation, function-call,
thunk-allocation, and inline-cache counters) provided only another approximately
0.15% reduction. That prototype was reverted: those counters support public
statistics and GC policy, and their measured ceiling did not justify splitting
their semantics.

## Fifth implementation result

The Candidate-C serial heap was still entering the process-global reservation
registry in two places where it already owned the required address context:

- every flat string, path, list, attrset, thunk, lambda, and primop allocation
  reverse-scanned the registry to encode a just-allocated pointer; and
- lambda and primop getters scanned the domain registry even though
  `EvalHeap` caches its own reservation base and domain.

Flat allocation now performs a checked `pointer - cached_base` conversion and
constructs the known `(domain, index)` handle directly. Lambda and primop
resolution use the same heap-owned cached resolver already used by thunks.
Compatibility carriers and context-free accessors retain the registry path.
The change adds no `unsafe`: subtraction, reservation capacity, and `u32`
conversion are checked before handle construction, while typed getters retain
their flat-store membership/header validation.

Three isolated cache-off `systems.server.build.toplevel` runs retired
24.2099-24.2102B instructions, approximately **0.16%** below the 24.247-24.249B
baseline. Peak RSS was 854,288-854,708KiB and IPC 2.52-2.58 on the shared
builder. Full toplevel `.drv` closure parity remained byte-green. This closes a
real direct-addressing mismatch with C++ Nix, but its small measured bound shows
that process-global reservation lookup is not a primary cause of the remaining
approximately 3.88x instruction gap.

## Sixth exploration result

Full-toplevel environment telemetry reports 4,861,457 captured-environment
installs: 4,337,801 empty and 523,656 non-empty. The non-empty path currently
clones frames into a temporary `Vec` and then converts it into the inline
`SmallVec` active suffix, so shallow installs still perform a transient heap
allocation despite the inline-stack design.

A prototype cloned directly into the inline `SmallVec` while preserving the
single-pass chain walk and fallible reservation. Focused capture-chain tests
passed, but three successful isolated full-toplevel runs retired
24.2354B instructions versus the 24.210B baseline (**0.10% worse**). The
prototype was reverted. Removing the allocation through a more generic buffer
made code generation worse than the allocator saving; the redundant staging
should be removed only as part of a direct persistent-head active environment,
where it also eliminates frame cloning and stack conversion rather than merely
changing the destination container.

## Seventh implementation result

The serial tree walker now carries the active shared-frame suffix as its
existing persistent innermost `Arc<EvalFrame>` head plus a frame count.
Production push/pop follows immutable parent links, captured-environment
installation clones one head, and suspension swaps that compact head instead of
materializing an outermost-first `SmallVec`. Depth-relative lexical lookup now
walks the same parent chain as C++ Nix's `Env *`. Independently constructed
unlinked test/restore frames retain the old inline-array compatibility path,
and safepoint root enumeration preserves outermost-first frame indices.

This removes the clone/conversion work from the 4,861,457 full-toplevel
environment installs rather than merely changing its destination buffer.
Dedicated tests pin linked depth lookup, push/pop restoration, and unlinked
compatibility order. The serial Candidate-C suite passed 2,674 tests (37
ignored) plus doctests.

Three isolated cache-off `systems.server.build.toplevel` runs of the final
source retired 23.8293-23.8296B instructions, down from 24.2099-24.2102B by
approximately **1.57%**, at IPC 2.77-2.78. Full `.drv` closure parity remained
byte-green.

The pinned C++ Nix process currently retires 6.2181B instructions at IPC
2.81-2.89, leaving a **3.83x** instruction ratio.

Fresh-process peak RSS was 855,940-858,492KiB native versus
344,140-345,528KiB C++ (approximately 2.49x), essentially flat versus the
preceding native build but still far outside the requested `<0.5x` fresh-peak
memory gate. The change is a measured CPU win, not a memory-gate claim.

## Eighth exploration result

The full toplevel forces approximately 2.94 million previously suspended
thunks, and each serial claim currently uses the future-parallel
`compare_exchange(Suspended, Blackhole)`. Because an uncontended x86
read-modify-write can look disproportionately expensive, a scoped prototype
used a relaxed load plus relaxed store only for the already-established direct
flat-arena path: one-shot arena, GC disabled, no tier-1 engine, and no parallel
payload cell. Shared, parallel, GC, and tiered paths retained the CAS.

Two isolated cache-off `systems.server.build.toplevel` runs retired
23.8914B and 23.8930B instructions versus the 23.8293-23.8296B baseline,
approximately **0.26% worse**, with peak RSS unchanged at 858,096-859,576KiB.
The prototype was reverted. The serial CAS is therefore not a profitable
selective-`unsafe` lever on this build: removing the locked operation does not
reduce retired instructions, and the extra claim-path split/code layout costs
more than it saves. Keep the atomic protocol shared with parallel forcing
unless a future profile identifies a different architecture or contention
regime; pursue the remaining uniform interpreter dispatch/representation tax
instead.

## Ninth provisional exploration result

Candidate-C getters reconstruct a pointer from the heap-owned reservation and
then every flat store performs a sorted live-region membership search before
loading the object header. To bound the maximum benefit of direct
dereferencing, an explicitly non-shippable prototype removed the membership
search globally while retaining alignment and header-kind checks.

After refreshing the C++ oracle derivations, two successful isolated cache-off
`systems.server.build.toplevel` runs retired 23.1754B and 23.1756B
instructions, approximately **2.74%** below the 23.8293-23.8296B baseline.
IPC remained 2.73-2.76 and peak RSS 852,752-858,648KiB. The prototype was
reverted because the public resolver can receive arbitrary Candidate-C
in-reservation offsets and therefore cannot safely dereference before proving
an exact allocation start. A subsequent restore exposed stale incremental
cross-crate codegen and required cleaning package artifacts to recover the
baseline, so treat this number as a **provisional upper bound**, not an
acceptance-quality A/B, until both legs are repeated in isolated target
directories.

This indicates a bounded direct-addressing opportunity: an O(1)-class exact
allocation-start/provenance proof may recover up to the provisional 2.74%, but
unchecked header dereferences do not satisfy Rust's safety contract. The
discovered soundness TODO in the master checklist must be resolved as part of
any shipped version.

## Tenth implementation result

`force_node_result` used to call `is_suspended_lazy_identity_thunk` before its
ordinary WHNF test. For almost every node result, that out-of-line helper
tested `value.is_thunk()`, returned false, and the caller immediately tested
`value.is_thunk()` again. The common scalar, string, path, list, attrset,
lambda, and primop result now returns on the first carrier-tag test; only an
actual thunk consults the lazy-identity set.

Against a cleanly rebuilt 23.8292-23.8315B baseline, three isolated cache-off
`systems.server.build.toplevel` runs retired 23.1874-23.1880B instructions,
approximately **2.70%** fewer, at IPC 2.70-2.75. Peak RSS remained
857,520-858,744KiB. Full toplevel `.drv` closure parity remained byte-green,
and the complete serial Candidate-C suite passed 2,674 tests (37 ignored) plus
doctests.

Pinned C++ Nix retired 6.2186B instructions at IPC 2.84, leaving a **3.73x**
instruction ratio. This is a larger win than its one-branch source diff
suggests because the avoided helper call sits on nearly every already-WHNF
node-result boundary.

## Eleventh implementation result

Every recursive node entry used `stacker::maybe_grow`, whose inlined wrapper
still called the out-of-line `remaining_stack` helper and read its private
thread-local stack limit. Removing stack protection entirely bounded this
full-toplevel tax at approximately 2.03%, but is not shippable: deeply
recursive Nix must grow a temporary native stack and reach the configured
`max-call-depth` error rather than aborting the process.

On x86-64 and AArch64, the evaluator now reads the native stack pointer with
one local, documented inline-assembly block and compares it with a one-word
thread-local cached stack floor. It asks `stacker::remaining_stack` only when
initializing that floor, clears the cache while `stacker::grow` runs on a
temporary segment, and restores it through an unwind-safe guard. Other
architectures retain the original safe `stacker::maybe_grow` path. The zero
sentinel is valid because a process stack cannot begin at address zero; using
it also avoids the two-word representation and discriminant load of
`Option<usize>`.

Three cache-off `systems.server.build.toplevel` runs retired
23.0727-23.0728B instructions versus the 23.1874-23.1880B baseline,
approximately **0.49%** fewer, at IPC 2.77. Peak RSS remained
855,616-858,620KiB. Full `.drv` closure parity was byte-green, and dedicated
tests crossed the native-stack boundary both successfully and through the
configured Nix depth error. The complete Candidate-C suite passed 2,674 tests
(37 ignored) plus doctests. Pinned C++ Nix remains at 6.2186B instructions,
leaving a **3.71x** instruction ratio. The result recovers only part of the
no-check ceiling because a sound per-entry stack-pointer comparison remains;
further removal requires a proven amortized or recursive-edge-only check, not
an unprotected tree walk.
