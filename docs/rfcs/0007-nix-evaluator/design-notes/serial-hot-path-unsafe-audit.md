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

## Twelfth exploration result

The last instruction profile attributed visible mass to the environment
save/restore closure around thunk and lambda bodies. Because the default
full-toplevel run has collection disabled, a prototype kept each displaced
environment in the caller's Rust frame instead of reserving and pushing it
onto the explicit suspended-GC-root vector. The production rooted path remained
unchanged whenever GC was enabled.

Three cache-off `systems.server.build.toplevel` runs retired
23.0892-23.0915B instructions versus the 23.0727-23.0728B baseline,
approximately **0.07% more**, with peak RSS unchanged at
855,268-858,004KiB. The prototype was reverted. The reusable root vector is
already cheaper than the extra mode split and larger scoped helper after
optimization; do not special-case no-GC environment suspension again without
new profile evidence. The result also reinforces that the current gap is a
flat per-operation instruction tail rather than hidden wait time.

## Thirteenth exploration result

A refreshed CPU-time sample of the cache-off
`systems.server.build.toplevel` benchmark found that the earlier `memmove`
hotspot disappeared after the persistent-environment-head change. The two
hottest named functions were instead
`FlatObjectStore::alloc_with_aux` and
`FlatObjectStore::alloc_with_value_tail`. Their generated code copies the
roughly 144-byte closure payload through stack temporaries while crossing the
generic crate boundary.

A clean isolated-target build forced `#[inline]` on those entry points and
their shared trailing-allocation helper. Three full-toplevel runs retired
23.0732-23.0773B instructions, versus the pushed 23.0727-23.0728B baseline,
with no peak-RSS improvement. The annotations were reverted. Compiler-hint
tuning alone does not remove the allocation-door cost; any follow-up should
specialize the closure path structurally and prove that it avoids payload
copies and generic registry work.

## Fourteenth exploration result

The dedicated inline-`Value`-tail door now performs its concrete operation
directly: checked object-plus-tail sizing, one arena reservation, one tail
copy, one payload write, and one already-flagged registry insertion. The old
path built a generic tail plan, entered a callback writer, then looked up and
mutated the registry entry it had just appended. This specialization adds no
new unsafe premise; its single write block is the same fresh-reservation,
alignment, and immutable-tail argument already used by the generic door.

Three isolated-target, cache-off `systems.server.build.toplevel` runs retired
22.9732-22.9770B instructions at IPC 2.76-2.77, approximately **0.43% fewer**
than the 23.0727-23.0728B baseline. Peak RSS remained
857,588-858,096KiB. Byte-level `.drv` closure parity passed, followed by all
2,674 active Candidate-C tests (37 ignored) and doctests. The pinned C++ count
remains 6.2186B, leaving a **3.69x** instruction ratio.

The paired stats run also quantified the next structural problem. The
toplevel allocates 3,218,224 thunks; `EvalThunk` and `FlatClosurePayload` are
both 120 bytes, so the flat object is 144 bytes after its three-word generic
header. The worker lane reaches 566,881,608 used bytes. A single largest enum
variant and a generic hash/epoch-bearing header therefore tax every common
node/apply thunk. Closing the memory and instruction targets requires a compact
thunk-specific layout, not more annotations on the uniform payload.

## Fifteenth exploration result

The common closure representation is now compact without changing the value
carrier or adding an unchecked dereference. `EvalEnv` uses one variant enum so
the majority chain-plus-flat shape is inline instead of splitting its parts
across a uniform outer layout. Its flat-tail registry coordinate is a checked
28-bit index plus four-bit length, and its flat-prefix and linked-suffix depths
are checked 16-bit counts. Evaluations configured above that depth disable the
flat-capture optimization, and an unexpectedly deeper lexical environment
falls back to the conservative chain rather than truncating. Non-default
single-entry/parallel force storage is out of line,
the 597 observed two-argument application forces use a boxed rare payload, and
builtin-attribute thunks retain the stable `BuiltinKind` handle from which the
exact declaration is reconstructed.

These changes reduce `EvalEnv` from 64 to 48 bytes, `EvalThunk` and
`FlatClosurePayload` from 120 to 96 bytes, and the complete flat closure from
144 to 120 bytes. On the stats-enabled full toplevel, the worker heap's used
bytes fell from 566,881,608 to 475,818,840 while the allocation count remained
3,218,224 thunks / 4,313,668 total flat objects.

Three fresh isolated-target, cache-off `systems.server.build.toplevel` runs
retired 22.8920-22.8943B instructions at IPC 2.78-2.79, approximately **0.35%
fewer** than the 22.9732-22.9770B baseline. Peak RSS improved
from 857,588-858,096KiB to 763,468-769,716KiB (about 86-92MiB, 10.2-11.0%).
Byte-level `.drv` closure parity
passed. Against the pinned C++ count of 6.2186B, the remaining instruction
ratio is **3.68x**.

The result validates payload compaction as a substantial memory lever, but it
does not close the memory target.
Every closure still pays the generic three-word header and every thunk still
carries a 24-byte `ThunkCellSlot`; those are the next representation targets.

## Sixteenth implementation result

Candidate C now uses its invalid-word space to collapse serial thunk state and
the cached result into one atomic word. `u64::MAX` represents `Suspended`,
`u64::MAX - 1` represents `Blackhole`, and every other private word is a
validated Candidate-C `Value` representing the terminal forced state. The
claim path therefore reads one atomic instead of a state word followed by a
result cell. Reconstructing a forced `Value` uses one local unsafe operation;
its invariant is closed because the private atomic is initialized only with
the two sentinels and every non-sentinel write copies an already-validated
`Value` word intact.

The previous `ThunkCellSlot` enum was 24 bytes because it held either a
16-byte cell or an `Arc` plus a discriminant. `EvalThunk` now keeps the compact
cell inline and promotes the rare shared identity into the existing boxed
force-storage extension. Record-table placement, relocation, and parallel
storage preserve shared force identity; the common flat serial record neither
allocates nor carries the enum discriminant. `EvalThunk` fell from 96 to 80
bytes. `FlatClosurePayload` fell from 96 to 88 bytes rather than 80 because
`EvalLambda` is now its largest variant, reducing a complete generic-header
flat closure from 120 to 112 bytes.

Two exact cache-off `systems.server.build.toplevel` runs retired 22.8943B and
22.9036B instructions. This is effectively flat against the pushed
22.8920-22.8943B range; the lower first-run IPC was host contention, not extra
retired work. Peak RSS fell from 763,468-769,716KiB to
732,156-732,468KiB, another 31-37MiB reduction, while stats-enabled worker
used bytes fell from 475,818,840 to 445,464,584. Byte-level `.drv` closure
parity passed. The serialized Candidate-C suite passed 2,677 active tests (37
ignored), and the baseline suite passed 3,154 active tests (34 ignored), plus
seven doctests in each configuration.

The parallel Candidate-C suite also exposed an independent instrumentation
race: flat-capture campaign counters are process-global atomics whose
baseline/delta snapshots can include other evaluators' work. The affected
conservative-capture test passes alone and with `--test-threads=1`; the RFC
checklist now tracks making those counters evaluator-local or otherwise
ownership-safe.

The compact cell materially improves memory but not retired instructions. The
next representation targets are therefore the 88-byte lambda that pins the
closure union and the generic 24-byte hash/epoch header, rather than more
force-cell unsafe code.

## Seventeenth implementation result

Rare dynamic-scope state now uses one shared `EvalClosureDynamicEnv` payload.
Lambdas box it directly; node thunks place it in the existing out-of-line
force-storage extension. Empty dynamic captures therefore add no word or
allocation to either common closure. `EvalThunk` and `EvalLambda` are both 72
bytes. `EvalPrimOp` now stores the stable `BuiltinKind` instead of copying the
full static `Builtin` declaration, so no primop variant pins the union above
those common records. `FlatClosurePayload` fell from 88 to 80 bytes and the
complete generic-header flat closure from 112 to 104 bytes.

Two exact cache-off `systems.server.build.toplevel` runs of the retained
`BuiltinKind` form retired 22.936815651B and 22.936846621B instructions. That
is a stable approximately 0.19% regression from the preceding
22.8943B-class build, so this is a memory win rather than a CPU win. Peak RSS
fell again to 710,244-712,668KiB, approximately 19-22MiB below the compact-cell
build. A static builtin-declaration pointer alternative retained the layout
but did not recover the instruction cost (22.943081284B) and was rejected.
Shared-builder contention depressed IPC during these samples; retired
instructions, not wall time or IPC, are the acceptance signal.

The serialized Candidate-C suite passed 2,677 active tests (37 ignored), and
the baseline suite passed 3,154 active tests (34 ignored), plus the doctest
sets. The full daemon-primed native toplevel produced the same derivation path
as pinned C++ Nix. Against the pinned 6.2186B C++ count, the remaining native
instruction ratio is approximately 3.69x. The generic three-word flat-object
header remains the next pure representation target; the measured 42.5M
instruction increase from the dynamic-sidecar/builtin-handle change is also a
small explicit recovery target.

## Eighteenth direct-resolution audit result

The refreshed instruction profile attributed 3.28% self time to
`flat_closure_probe` and 2.12% to `serial_heap_ptr`, so a sealed reservation
capability was prototyped to replace the flat store's sorted-region membership
search. The capability validated the Candidate-C domain, reservation bounds,
word alignment, and backing identity before loading the magic/kind header.
Targeted tests passed for malformed aligned offsets, foreign reservations,
kind mismatches, popped headers, retired payloads, and the chunked
compatibility backend.

The prototype was reverted before a performance acceptance run because those
checks still do not prove that the address is an exact allocation start. Safe
Candidate-C word constructors can name any aligned in-reservation offset, and
an interior word that happens to contain the permitted magic/kind value cannot
soundly witness `FlatObject<T>` provenance. This is the same open
allocation-start issue recorded in the master checklist; an opaque
reservation-bounds token does not close it. The earlier 2.74% unchecked
experiment remains the performance upper bound. Revisit direct resolution only
with an O(1)-class exact-start proof whose resident-memory cost is measured
against the `<0.5x` target.

The audit also found that Candidate-C cannot currently exercise the intended
record-table fallback: after selecting record worker closures, `alloc_thunk`
fails in `Value::thunk` with `UnregisteredReservation` because the record
allocator's address has no Candidate-C reservation domain. The master
checklist now tracks either supplying a registered encoding for that placement
or making the incompatibility explicit and tested.

## Nineteenth lambda-clone representation result

The refreshed profile attributed 2.75% self time to `EvalLambda::clone`, so two
shared representations were prototyped. The first placed the entire 72-byte
lambda behind `Arc`; the second retained the 16-byte module, pattern, body, and
frame metadata inline while placing only the lexical and rare dynamic captures
behind `Arc`. The second form made `EvalLambda` 24 bytes and preserved a
72-byte `FlatClosurePayload`.

Both forms reduced retired instructions by approximately 0.47%, but both
increased peak memory. In alternating exact
`systems.server.build.toplevel` runs, the whole-record form retired
22.829146011B and 22.829363479B instructions versus baseline
22.940839314B and 22.938390499B, while peak RSS rose from
723,804-729,040KiB to 748,836-754,604KiB. The capture-only form retired
22.832696262B and 22.830219825B instructions versus baseline
22.939581135B and 22.937269072B, while peak RSS rose by 7,888-16,132KiB
in paired runs. Every native run produced the same derivation path as pinned
C++ Nix.

Both representations were rejected. Sharing does remove the hot full-record
clone, but it replaces inline closure storage with one separately allocated
reference-counted payload per lambda. With 2.44M captures in the primary
workload, allocator and reference-counting overhead overwhelms the union-size
saving and moves directly away from the `<0.5x` C++ peak-memory target.
Future lambda work should remove cloning without adding one allocation per
closure, for example by shortening the heap borrow or copying only the call
metadata needed after the borrow is released.

A guarded empty-dynamic-scope call path also tested that latter direction. It
borrowed the heap lambda, copied only its four lowering identifiers, and built
the active environment directly, eliminating the intermediate `EvalLambda`
clone and one transient frame-head `Arc` increment/decrement without adding
resident allocations. A focused lexical-capture/lazy-argument test passed and
the primary evaluation was byte-correct, but the inlined form retired
23.051171376B instructions versus 22.937385346B for the adjacent baseline
(+0.50%). Keeping its preparation and application helpers out of line worsened
the result to 23.111332311B (+0.75%). The guarded second lookup and separate
call machinery cost more than the saved shared-handle operation, so this
prototype was also reverted.

## Twentieth header and architectural-gap result

The generic serial flat header's epoch word was moved to optional side
storage, reducing each object head from 24 to 16 bytes. After removing all
sidecar checks from the default flat-store allocation and resolution paths, two
exact byte-correct `systems.server.build.toplevel` runs retired
23.081109959B and 23.081060212B instructions. Adjacent preserved baselines
retired 22.938147240B and 22.939322173B: a stable 0.62% regression. Paired
peak RSS fell by 34,724KiB and 40,368KiB. The isolated header shrink was
therefore reverted; its memory benefit must be recovered as part of a larger
representation change that also improves resolution and registry costs.

A deeper cross-evaluator audit found nearly matched semantic work where it
matters most: AOS performed 3,176,715 function calls and allocated 3,452,016
environment frames, versus 3,163,155 calls and 3,454,439 environments in
pinned C++ Nix. The remaining 3.69x instruction ratio is therefore primarily a
constant-factor representation/execution problem, not duplicated whole-module
evaluation. One material discrepancy remains: AOS allocated 3,218,252 thunks
versus C++ Nix's 2,795,794, an excess of 422,458 (15.1%).

The resident populations identify the next factor-level design. AOS retains
415,116,488 worker-arena bytes across 4,313,738 flat objects, plus approximately
65.8MiB of 16-byte `FlatStoreEntry` registry records and millions of separately
reference-counted frames. Of the 3,218,252 thunks, 2,942,515 are forced. A
reservation allocation-start bitmap can simultaneously close the direct
resolver's exact-start proof, replace much of the registry, and serve
production marking. A stable compact force/result cell with per-kind
variable-size suspended metadata can then reclaim most forced-thunk metadata
without changing thunk identity. Those combined designs have plausible
double-digit leverage on both instructions and memory; isolated pointer,
lambda-clone, and header changes do not.

Two GC-derived shortcuts were also measured and rejected. The existing full
sweep retired 1,502,923 closures but raised instructions from approximately
22.94B to 27.83B and peak RSS to approximately 853MiB because its million-entry
hash sets/vectors peak before non-returning arena storage can be reclaimed.
Force-time capture shedding without the terminal sweep cost 7.44% more
instructions for only about 5-9MiB lower peak RSS. Future reclamation must use
compact bitmap work state and actually reuse or return storage; blanket capture
shedding is not sufficient.

Finally, an explicit `lazy_identity_thunks.is_empty()` return was added ahead
of the helper's existing set membership test because the helper held 1.68%
self time in the sampled profile. Two exact runs retired 23.005337858B and
23.007704557B instructions versus adjacent baselines 22.938006244B and
22.938635880B, a stable 0.30% regression. The empty `HashSet::contains` path is
already cheap; the additional branch/code layout lost more than it saved, so
the guard was reverted.

## Twenty-first lexical-alias elimination result

The force-shape census was extended with allocation counts and an
order-sensitive-assembly subset. On the primary toplevel it classified
3,218,268 thunk allocations and 2,942,531 forces. The 275,737 never-forced
records were led by `Select` (77,939), `PrimOp` (56,297), `LocalVar` (47,520),
and `UpvalVar` (36,335). More importantly, `LocalVar` and `UpvalVar` bodies
accounted for 698,638 allocations, of which 524,896 occurred outside
order-sensitive binding assembly.

A demand-position lexical alias has no deferred work or dynamic scope of its
own. Once frame population has finished, reading its referenced slot returns
the exact value its body would later return, including an existing thunk's
identity and laziness. The evaluator now performs that read directly rather
than allocating a second thunk. Recursive and source-ordered assembly retains
storage because the referenced slot may not yet be populated. Active
force-cache observation also retains storage because initial broad testing
showed that collapsing aliases there erases child force-observation nodes even
though output bytes remain unchanged. An ancestor frame is not sufficient
proof during nested assembly because recursive `__overrides` may still rewrite
it, so all assembly aliases remain conservative pending a published-and-sealed
frame proof. Oversized call-depth configurations that disable compact flat
capture retain the conservative path as well, and the ordinary allocation
planner still runs first so malformed IR preserves its established error.

The full `ratchet-oracle` library suite passed 3,155 active tests with 34
ignored. The daemon-primed native and preserved baseline evaluators produced
the same `/nix/store/iil3b0igdqis3n786y550a197dl54shp-aos-system-toplevel.drv`.
Two exact cache-off candidate runs retired 21.901551745B and 21.899740922B
instructions versus adjacent preserved baselines of 22.938427469B and
22.938568384B, a repeatable 4.52% reduction. Candidate peak RSS was
646,684-648,968KiB versus 712,168-714,208KiB, saving 63-67MiB. Wall time was
load-sensitive and did not improve in these samples, so the acceptance rests
on byte parity, deterministic retired work, and peak memory.

The stats leg confirms the mechanism: thunk allocations fell by exactly
524,896 to 2,693,372; forces fell by 476,066 to 2,466,465; flat captures fell
by 524,896; flat objects fell by 534,653; and worker-arena used bytes fell from
415,120,008 to 356,331,656. Function calls remained exactly 3,176,739. The
remaining forced-thunk population is still large enough that splitting stable
force/result identity from reclaimable suspended metadata remains the next
high-leverage thunk-representation target.

The follow-up suspended-work census records allocation as hypothetical work
acquisition and successful forced-result publication as work release. On the
same primary workload it observed 2,466,465 releases, a final conservative
upper bound of 226,907 unpublished records, and a peak upper bound of 230,470.
The bound intentionally does not decrement thunks destroyed without forcing or
retired with a region, so it can overstate rather than understate the pool a
real design would require. Even at a deliberately large 64-byte work record,
the measured peak is only about 14.1MiB. Reclaiming suspended work is therefore
useful but cannot by itself close the roughly 477MiB gap to the `<0.5x` C++ RSS
gate. The larger architectural leverage is shrinking the stable closure
identity, the 16-byte-per-object flat registry, and separately reference-counted
frame storage; a work pool should be designed as part of that combined
representation rather than treated as the primary memory fix.

A follow-up source audit also rules out interpreting the largest census
buckets as duplicated evaluator work. Lowercase `apply` is the synthetic lazy
result thunk created principally by `map`, `genList`, and their specialized
relatives; its 1,344,477 allocations are not source `Apply` nodes. `PrimOp`
means a normal node thunk whose body is a direct builtin call, not a
partial-application closure. Native function calls remain within about 0.4% of
the C++ counter, but the retained evaluator spends roughly 6,894 instructions
per call versus about 1,966 in C++. The remaining instruction gap is therefore
the cost of representing and interpreting nearly matched semantic operations.

At the current 24-byte header plus 80-byte uniform closure payload, the
2,693,372 remaining thunk objects alone have an approximately 267MiB fixed-body
ceiling before capture tails and roughly 41MiB of registry records. A dedicated
synthetic-apply representation could save only about 41-62MiB even if it
removed 32-48 bytes from every such object. It is a bounded memory experiment,
not an instruction-factor solution. The factor-level instruction avenue is a
fused internal execution spine for the modal force-variable-apply-simple-lambda
sequence, measured with an eligibility census and required to deopt before any
observable work on cold/error paths.

## Twenty-second exact-start witness result

A sparse reservation-sidecar prototype recorded one allocation-start bit per
eight-byte granule. Fresh serial flat objects publish their bit only after
placement and registry insertion; resolution checks the bit before reading the
header; and lexical-region pop clears it before destruction and address reuse.
The production four-GiB reservation therefore reserved 64MiB of virtual bitmap
space while demand paging commits only pages covering actual starts. A forged
aligned interior word carrying valid flat magic was rejected, and snapshot
restore globally preflighted and published its object manifests before the
first typed access. Retired tombstones remained unpublished.

The snapshot publication door is explicitly a trusted same-build capture
contract, not a validator for attacker-authored raw Rust object bytes. The
existing image copies placement-written payload representations and protects
them with an xxh3 corruption digest, not authentication. Fully untrusted image
loading would require validated object reconstruction (or an authenticated
producer contract); a serialized index cannot manufacture Rust layout
provenance by itself.

All 53 automated snapshot tests passed with two manual probes ignored, and the
complete Candidate-C oracle suite passed 2,678 active tests with 37 ignored.
Two exact byte-correct primary runs retired 22.143938849B and 22.141869138B
instructions. The retained lexical-alias candidate retired approximately
21.900B, so the isolated exact-start load costs about 1.11%. Peak RSS remained
approximately flat at 649,196-650,224KiB. The safety stage therefore cannot
land as a standalone performance change; it proceeds only as part of the
planned compact-registry design, whose measured population gives it a
substantially larger memory ceiling.

The combined stage then halved reservation-backed `FlatStoreEntry` records from
16 to 8 bytes by storing a 32-bit reservation offset plus word-sized extent and
tail flag; chunked compatibility stores retained native pointer/size records.
All flat, snapshot, unsafe-inventory, and full Candidate-C gates remained
green. Two exact primary runs retired 22.394868690B and 22.394553208B
instructions, however: another 1.14% above bitmap-only and about 2.26% above
the retained lexical-alias candidate. Peak RSS was 636,592-638,212KiB versus
729,896-730,476KiB for adjacent preserved baselines. Comparing the paired
saving with the alias-only result attributes roughly 26-29MiB of additional
memory improvement to the compact registry plus sidecar, consistent with the
metadata-population estimate.

That memory win does not waive the no-regression rule. Compact entry decoding
and exact-start publication/checking add deterministic work to millions of
allocations, tail-handle resolutions, iteration, and drops. Both code stages
were therefore rejected together; the adversarial proof, snapshot trust
boundary, representation design, and measured economics remain recorded for a
future closure-specific layout that can remove enough object/header work to
pay for the witness.

## Twenty-third producer census and compatibility-layout result

The stats-only force-shape census now attributes batched synthetic lazy
applications to their builtin producer. The primary workload accounts for
every allocation exactly: `genList` creates 1,133,765 of the 1,344,477
one-argument apply thunks (84.3%), `map` creates the remaining 210,712
(15.7%), and `mapAttrs` creates all 793 two-argument apply thunks. The
instrumented run still allocated 2,693,372 thunks, forced 2,466,465, and
produced the same derivation. No unexplained synthetic producer remains.

That concentration makes `genList` a useful bounded experiment, but not the
factor-level source. Each current element repeats the generator value,
function and argument node references, function span, and force cell inside a
104-byte flat closure plus a 16-byte registry entry. A dedicated store with a
shared per-list call site and a 24-byte per-element payload would make a
48-byte flat object and save about 60.6MiB across the measured population.
It would retain all 1.13 million allocations and semantic calls, add shared
site ownership, and require new force, root-scan, GC, retirement, and snapshot
paths. The more ambitious slab form can approach the full roughly 121MiB
`genList` object-and-registry mass, but needs its own exact-start and
cell-to-slab proof. Neither closes the 15.68B-instruction gap.

A separate source audit found a safer general representation win first.
`EvalEnvStorage`'s compatibility fallback stored independently constructed
frames as an unsized `Arc<[Arc<EvalFrame>]>`. Its two-word fat pointer widened
the entire enum even though the production linked-frame path does not construct
that variant; the primary stats counter confirms zero compatibility captures.
Changing only that fallback to a thin `Arc<Vec<Arc<EvalFrame>>>` preserves its
shared immutable slice behavior while removing one word from every production
closure. Candidate C `EvalEnv` fell from 48 to 40 bytes, `EvalThunk` and
`EvalLambda` from 72 to 64, `FlatClosurePayload` from 80 to 72, and the complete
flat closure from 104 to 96 bytes.

Two exact cache-off candidate runs retired 21.878115971B and 21.875908947B
instructions with peaks of 610,524KiB and 608,676KiB. Adjacent preserved
baseline runs retired 22.941202722B and 22.939091745B with peaks of 708,688KiB
and 706,140KiB, and every leg produced
`/nix/store/83zva9q4hf8sqqi4f3883q3xzwxm8i1y-aos-system-toplevel.drv`.
The immediately preceding retained alias-only candidate was approximately
21.9068B instructions and 638,964KiB, so the layout correction recovered about
28-30MiB while slightly reducing retired work. Unlike the rejected header and
registry prototypes, it adds no production branch, side lookup, or allocation.
The serialized Candidate-C suite passed 2,678 active tests (37 ignored), the
default suite passed 3,155 active tests (34 ignored), and both doctest sets
passed.

The suspended-work census also admits a stronger interpretation than work-pool
size alone. Its 230,470-record upper bound says a reusable work store can stay
near 14.1MiB at 64 bytes per live record while 2.69 million stable identities
remain. A fixed-stride 16-24-byte stable thunk head, that bounded work pool, and
no 16-byte per-head registry record has an estimated 232-253MiB saving ceiling
against the current thunk object/registry mass. This combined typed-head lane
is the only measured next representation experiment with hundred-MiB leverage.
It still projects well above the `<0.5x` C++ RSS gate by itself, and instruction
parity additionally requires a broader stackless or superinstruction execution
path covering the modal force/environment/lambda-call transitions. The next
measurement should therefore census that modal spine and direct strict
consumers such as `map(genList)` before committing to either fusion or the
larger typed-head arena.

## Twenty-fourth ownerless-capture result and ABA correction

The flat-tail registry coordinate already names the closure object that owns a
capture, so storing the same owner again as a heap `Value` widened
`EvalFlatCapture` and therefore every environment. Removing that duplicate
word reduced `EvalEnv` from 40 to 32 bytes, `EvalLambda` from 64 to 56,
`FlatClosurePayload` from 72 to 64, and the complete flat closure from 96 to 88
bytes. `EvalThunk` remains 64 bytes because its one-argument `Apply` variant
still pins the internal union.

The first ownerless prototype was not safe to retain. Its handle encoded only
registry index and tail length; a lexical-region pop can truncate the registry
and rewind the closure arena, so a later same-length object can reuse both
coordinates. The old handle would then have resolved the replacement object.
The retained encoding adds a monotonically issued 32-bit generation that is
never rewound by region pop. Tail entries pack that generation into the high
half of their existing size word, so the 16-byte registry entry does not grow.
Every owner, immutable-tail, and mutable-tail resolution compares the signed
generation before exposing bytes. A deterministic test pops a tail allocation,
reuses its exact registry index and arena address, rejects the stale handle,
and resolves the freshly signed handle. Retirement also invalidates an
out-of-range read before it can return `None`.

Widening the handle from four to eight bytes would otherwise have erased the
environment-layout saving. The allocation site is therefore a checked 32-bit
coordinate: 12 module bits and 20 node bits. Capture planning declines the flat
optimization and retains the exact linked environment when either field
exceeds that envelope; snapshot restore rejects an impossible compact site
rather than truncating it. The primary stats run retained the exact previous
environment population (`Chain=526,028`, `ChainFlat=644,436`, `Empty=705,559`,
`Flat=39,974`), proving that this fail-closed fallback did not fire on the
measured workload.

The complete producer/work census remained unchanged at 2,693,372 allocations,
2,466,465 forces, and a 230,470-record peak unpublished-work upper bound. The
first reported performance pair for this state (21.714890416B and
21.715136408B instructions) was later found to be invalid: the remote builder
checkout still contained the previously rejected 128-line
`PlainLambdaCall`/`prepare_plain_lambda_call` experiment even though that code
was absent from the authoritative worktree. The symbol occupied 2.52% of the
resulting profile. After synchronizing every tracked source file and rebuilding
with the exact Candidate-C feature and rpath recipe, two clean runs retired
21.602356694B and 21.602228603B instructions with 602,456KiB and 597,796KiB
peaks. Candidate and pinned C++ produced
`/nix/store/hwvzgyhp8a944ggz40mi5ym8pw3jhryd-aos-system-toplevel.drv`; C++
retired 6.220031315B instructions and peaked at 342,548KiB. The source
representation and safety result remains retained, but only this corrected
pair is authoritative.

Candidate C passed 2,679 active oracle tests with 37 ignored; the default
carrier passed 3,156 with 34 ignored; both seven-test doctest sets passed; and
`ratchet-value` passed 380 Candidate-C plus 391 default tests. The RFC factor
targets remain unmet.

## Twenty-fifth builder provenance correction and active-env follow-up

The stale `prepare_plain_lambda_call` symbol was not an unexpected compiler
artifact: SHA-256 comparison showed that the remote
`eval_primop_apply.rs` differed from the worktree, and the remote diff was
exactly the rejected plain-call prototype already measured as a 0.50-0.75%
regression. Synchronizing the complete tracked-file manifest removed the
symbol and recovered approximately 112.7M instructions. Future acceptance
runs must checksum or `rsync --checksum --dry-run` the tracked manifest before
building; the remote Git index is intentionally old and is not a provenance
oracle. The exact build must also include `--features candidate_c_value` and
the pinned OpenSSL rpath. An intermediate rebuild without those flags was
discarded before measurement.

The clean profile still grouped the environment boundary at the top:
`pop_env_scope` 3.69%, `push_env_scope` 3.46%, `EvalLambda::clone` 3.02%,
the lambda-call closure 2.60%, `EvalFrame::new_linked` 1.83%, and
`clone_env_frames` 1.52%. Two bounded representation fixes were retained:

- `ActiveEvalFrames` now boxes its unlinked compatibility vector instead of
  embedding a two-handle `SmallVec` header in every production active handle.
  The active-frame handle fell to 24 bytes, the complete active environment to
  48 bytes, and a suspended environment to 64 bytes. Two primary runs retired
  21.573091706B and 21.571127334B instructions.
- `EvalWithEnv` and `EvalScopedGlobalEnv` now answer `len`/`is_empty` from the
  persistent head directly. Previously method resolution fell through
  `Deref<[T]>` and consulted or materialized the `OnceLock` slice merely to
  test the stack head. With both changes present, two runs retired
  21.542081762B and 21.541739151B instructions, about 60.4M (0.28%) below the
  clean source-identical baseline. The final tracked-manifest acceptance build
  reproduced that result at 21.542206060B and 21.542101519B instructions with
  584,388-585,756KiB peaks. Pinned C++ produced the identical
  `/nix/store/1q5pmgxm4saj0vvdq8f2rlyj5hpqxyzf-aos-system-toplevel.drv` at
  6.219938415B instructions and 343,572KiB, leaving 3.46x instructions and
  1.70-1.71x peak RSS. The active/suspended layouts are deterministically
  smaller even though isolated RSS samples remain noisy.

Focused tests pin the 24/48/64-byte layouts, linked and unlinked frame behavior,
and prove that direct dynamic-stack length/emptiness queries do not initialize
the cached slice. Two tempting extrapolations were rejected. A lexical-only
restore marker grew suspended records to 72 bytes and produced overlapping
21.539726618B/21.541935285B counts. Consuming the already-cloned lambda
environment to avoid one additional `Arc` increment produced
21.532954130B/21.535115917B, only about 0.04% better, below the complexity
bar. The profile percentages therefore identify a representation boundary,
not a sum of independently removable helper costs. Factor-level progress still
requires the combined environment arena/compact handle and parameterized
evaluation design rather than more ownership micro-splits.

The final serialized oracle matrix passed 2,680 Candidate-C tests with 37
ignored and 3,157 default-carrier tests with 34 ignored. Both configurations
also passed the runnable doctest and all seven compile-fail doctests.

## Twenty-sixth unified-environment and same-install rejection

The environment profile suggested eliminating the active/captured
representation boundary. A complete safe-Rust prototype therefore used
`EvalEnv` as both the closure capture and `TreeWalk`'s active environment,
deleted `ActiveEvalFrames`/`ActiveEvalEnv`, collapsed the borrowed-view
dispatch, and made suspension a direct 32-byte environment clone. Suspended
records fell deterministically from 64 to 48 bytes. Compatibility arrays used
fallible copy-on-write, while production linked and flat-linked variants
supported direct push/pop with bounded-window tests. Candidate C passed all
2,680 active tests and both doctest groups.

The full-toplevel gate rejected the design decisively. Two runs retired
21.731783837B and 21.734091973B instructions with 583,784-587,496KiB peaks,
approximately 0.89% more instructions than the retained
21.542206060B/21.542101519B pair and no RSS improvement. Although capture and
install became simpler, the six-way captured-storage enum moved onto every
lexical read. That monomorphism loss outweighed the boundary savings. The
prototype was fully reverted. A future arena design must keep active reads on
a compact, monomorphic handle; reusing the polymorphic closure-capture enum as
the active representation is not an acceptable intermediate state.

A second, default-off census tested a narrower no-swap fast path before
committing another mode split. Of 4,285,421 captured-environment installs,
only 65,063 (1.52%) already matched the complete active lexical environment.
The other 98.48% would pay a new branch without benefiting, and even free
elision of every match has only a 1.52% install-count ceiling. The one-off
instrumentation was removed. Coincidence-based install bypass is therefore
also rejected; the next representation work must reduce the cost of all
installs and reads rather than specialize this small subset.

## Twenty-seventh modal apply-spine census and exact `genList` fusion

The retained stats-only modal census classified the synthetic apply population
before selecting another representation project. Across 2,693,363 allocations
and 2,466,456 forces, `genList` produced 1,133,765 synthetic apply thunks. The
dominant complete force signature was:

```text
genList|lambda|simple-formal|elemAt:upvalue-add:argument-int-one|whnf|one-apply|whnf
```

It occurred 1,050,218 times; the same body with no nested apply occurred 78,620
times. The apparently more general direct-upvalue/argument shape occurred only
502 times and was rejected as too small. This concentration changed the next
step from a speculative typed arena into a bounded execution experiment.

The retained implementation adds `EvalThunkKind::GenListElemAtAddOne`, a
runtime-only marker with exactly the same five fields and field types as the
ordinary one-argument `Apply` variant. It therefore leaves the 64-byte
Candidate-C `EvalThunk` and `FlatClosurePayload` layouts unchanged. Admission
requires the exact lowered body: a simple one-argument lambda whose result is
`builtins.elemAt` of a captured upvalue at `local_argument + 1`. Reversed
addition, other constants, and the direct index remain ordinary applies.
Force-time validation repeats the shape check and resolves the receiver only
when the generated element is demanded, preserving the zero-length and
unselected-receiver laziness contracts.

The fast path reuses the evaluator's existing integer-add, `elemAt`, force,
module-switch, native-stack-headroom, and call-depth machinery. It declines
before observable work whenever GC, tier-1 dispatch, force caching,
shared/parallel forcing, or stats collection is active. Root scanning,
writeback, collapse, and GC classify the marker with `Apply`. Snapshot encoding
intentionally writes the ordinary apply wire kind, and restore constructs an
ordinary `Apply`; a focused round-trip test proves the downgraded thunk remains
forceable. This compatibility boundary avoids making heap images depend on the
admission rules of the producing binary.

Three isolated-target, cache-off full-toplevel runs before the retained
per-kind work-census follow-up retired
19.770597084B, 19.770389232B, and 19.770454506B instructions at IPC
2.53-2.63. That is approximately 8.23% below the restored
21.542206060B/21.542101519B pre-census baseline. All three produced
`/nix/store/z89iw2mi2i2xklmjhmfx813zh5gpvnfv-aos-system-toplevel.drv`;
pinned C++ Nix produced the identical path at 6.218661661B instructions and
343,628KiB, reducing the instruction factor from 3.46x to 3.18x without
closing it.

Peak RSS in the final enabled runs was 616,488KiB, 615,704KiB, and
626,192KiB. A controlled build of the same implementation with only marker
admission disabled retired 21.5815-21.5820B instructions and peaked at
616,016-634,164KiB. The enabled and disabled distributions overlap, so the
fusion itself has no demonstrated RSS regression; the source-layout/census
state remains materially above the older 584-598MiB samples and the RFC memory
target is still open.

Candidate C passed 2,687 active oracle tests (37 ignored), including the final
snapshot compatibility test; the default carrier passed 3,163 active tests
(34 ignored). Candidate and default doctests each passed the runnable doctest
and all seven compile-fail doctests. The result rejects two broader avenues:
eagerly rewriting the lambda body would violate receiver laziness, while a
compact pre-resolved execution-plan payload is unnecessary until a later
census proves the repeated validation itself is a material residual. The next
work should profile the post-fusion binary and re-evaluate the fixed-stride
typed thunk-head/work-pool design against that new residual rather than
extrapolating from the pre-fusion profile.

## Twenty-eighth per-kind suspended-work bound

The aggregate 230,470-record unpublished-work peak proved that suspended
metadata is reusable, but its earlier 64-byte-per-record estimate could not
choose arena size classes or distinguish a broadly live node population from a
single dominant apply kind. The retained stats-only census now records, per
force-shape class, allocations, successful-publication releases, final live
work, per-class peak live work, and the class composition at the exact global
peak. Successful publication is the release boundary; errors and unforced
identities conservatively retain work.

The full toplevel allocates 2,693,355 thunks, releases 2,466,448 work records,
ends with a conservative 226,907 records, and peaks at the same 230,470 total
as the earlier aggregate census. At that global peak the material classes are:

| Work representation | Peak records |
|---|---:|
| 40-byte `Node` payload (all IR body classes combined) | 221,654 |
| 40-byte one-argument `Apply` payload | 7,371 |
| `Apply2` payload | 196 |
| 24-byte dedicated select payload | 1,240 |
| builtin-attribute payload | 9 |

Using 72 bytes conservatively for the rare `Apply2` work, the complete
shape-sized peak pool is 9,204,944 bytes (8.78MiB). This is substantially below
the earlier 14.1MiB uniform-record bound. The current typed closure occupies 88
bytes and retains a 16-byte `FlatStoreEntry`, or 280,108,920 bytes across the
2,693,355 stable identities before out-of-line dynamic-environment side
storage. A 24-byte stable head plus the measured work pool projects 73,845,464
bytes, saving 206,263,456 bytes (196.7MiB). A 16-byte head plus the pool projects
52,298,624 bytes, saving 217.3MiB. Both comfortably pass the independent
150MiB prototype threshold; typed stable heads plus a reclaimable size-classed
work arena are now the selected next memory experiment.

The additional census code is default-inert and split below the source-size
gate. Six focused shape/work-accounting tests pass. Because even inert code can
move optimized functions, the exact release binary was rebuilt and remeasured:
three clean runs retired 19.784756662B, 19.786885205B, and 19.786795082B
instructions with 612,328-613,700KiB peaks. Pinned C++ Nix produced the
byte-identical
`/nix/store/7l09b5q9ighircgzwhcjd4hmd2na271w-aos-system-toplevel.drv` at
6.219205899B instructions and 343,780KiB. The retained result is approximately
8.15% below the restored pre-fusion baseline and remains 3.18x C++ in retired
instructions.

The first implementation stage is narrower than the final byte projection so
it can fail safely. It admits only serial one-argument Apply-shaped thunks with
no capture tail or storage extension, behind a default-off option, into
permanent 16-byte heads backed by a generational reusable work handle. That
set includes ordinary `Apply` and the layout-identical
`GenListElemAtAddOne` marker. The existing arena has only one rewindable high
lane and `flat_closures` owns it, so the prototype uses a disjoint permanent
low-lane typed store; exposed head addresses are never reused. Keeping the
existing 24-byte header and 16-byte registry entry makes the stage-1 head cost
56 bytes rather than the final 16-24-byte target.

The work coordinate is a 64-bit `(generation, slot-plus-one)` identity.
Generation increments on every free-to-reserved transition, zero is invalid,
and an exhausted slot is poisoned rather than wrapped. Force publication
linearizes through the stable head; the winning force retains the work until
terminal-result publication and only then recycles the slot. Errors retain the
identical work handle for retry. Stage 1 explicitly refuses worker regions,
GC/stress, shared/parallel forcing, tiering, force caching, stats, memory
governance, and heap snapshots when typed heads exist. Focused coverage proves
stale-handle ABA rejection, owned work surviving vector growth, exact
generation release, abort retention, successful publication/reforce,
incompatible-option fallback, and explicit region/snapshot refusal. There is
one work class in this stage, so cross-class forgery and parallel publication
belong to later all-kind/shared generalization rather than this serial gate.

## Twenty-ninth typed Apply-head prototype result

The first measurement admitted only ordinary `Apply` and exposed an apparent
census discrepancy: 212,109 heads, a peak of 637 live work slots, and only
about 9MiB lower peak RSS. The implementation was internally consistent.
Replacing one 104-byte closure-plus-registry identity with a 56-byte typed
identity saves 48 bytes, so `212,109 * 48 = 10,181,232` bytes (9.71MiB)
before the small work pool. The stale assumption was the admission population:
the retained exact `genList` fusion had changed 1,133,765 formerly ordinary
applications into `GenListElemAtAddOne`. The force-shape census deliberately
still reports that layout-identical marker as lowercase `apply`, but the first
predicate did not admit it.

Admitting both exact one-argument layouts restores the intended bounded
experiment without broadening to `Node`, `Select`, captures, extensions, or a
second size class. The final full-toplevel diagnostic reported:

```text
heads=1,344,477 live_work=3,707 peak_live_work=7,374
slots=7,374 slot_capacity=8,192
```

The enabled and disabled runs of the same optimized binary produced the
byte-identical
`/nix/store/gbrgrqr2nxs93xk5wmf3s3fx6msgwvg2-aos-system-toplevel.drv`.
Enabled retired 20.242476948B instructions and peaked at 566,616KiB; disabled
retired 20.099327610B instructions and peaked at 615,872KiB. The prototype
therefore saved 49,256KiB (48.1MiB) at a 0.71% instruction cost. Its 8,192-slot
capacity is less than 1MiB even with the current approximately 80-byte
full-`EvalThunk` slot, confirming that reusable suspended work is not the
memory bottleneck.

The complete Candidate-C oracle suite passed 2,697 active tests with 37
ignored, and the default carrier passed 3,172 active tests with 34 ignored.
Both configurations passed the runnable doctest and all seven compile-fail
doctests. Focused typed-head coverage adds five pool/layout tests and five
force/admission/boundary tests.

This passes the stage-1 approximately 47MiB signal but not the independent
150MiB all-kind prototype threshold. The experiment remains default-off under
`AOS_NIX_TYPED_THUNK_HEADS=apply`; it is evidence for the representation, not
a production default. The next memory stage should add the dominant
shape-sized `Node` work class and reduce or eliminate the generic header and
registry cost. Before shared/default-on use it must also replace metadata-only
compatibility readers with explicit head/work APIs and implement the deferred
GC, region, snapshot, cache, and parallel publication contracts.

## Thirtieth retained-frame and allocator-owner correction

The 3,451,992 frame-allocation count does not describe simultaneous frame
residence. An opt-in allocation-minus-drop gauge on the exact primary workload
measured only 338,804 frames at peak and 338,557 at the post-evaluation
boundary. The existing heap census independently found 338,536 distinct
captured frames, 473,887 slots, and a 6,499,384-byte packed serialization
estimate. Ordinary small `Arc<EvalFrame>` boxes therefore hold roughly
15.5-20.7MiB at peak, not the approximately 158MiB obtained by multiplying
every allocation by its box size.

Widening `FLAT_CAPTURE_MAX_SLOTS` from two to eight was tested as a deliberately
large sever-the-chain experiment. It reduced the frame peak from 338,804 to
3,573, but copied 3,450,282 capture values instead of 2,038,263 and increased
the worker arena from 304,015,592 to 315,311,744 bytes. The same-source result
peaked at 603,660KiB rather than the retained 615,872KiB control, but retired
20.559234960B instructions rather than 20.099327610B. A 12.2MiB memory saving
at approximately 2.3% more instructions is far below the required factor-level
gate, so the width change was reverted.

Mimalloc's process-exit accounting reported 294MiB committed and 312.6MiB
cumulatively purged at a 601MiB process peak. Forcing
`MIMALLOC_PURGE_DELAY=0` changed the exact K=2 run from 615,028KiB to
610,676KiB while leaving retired instructions effectively unchanged
(20.132410807B versus 20.130324442B). Eager purge therefore recovers only about
4.3MiB and falsifies allocator retention as the missing factor.

The corrected non-arena owner model is live structure: approximately 76.5MiB
of flat-store registry capacity, roughly 36MiB of hash-cons buckets and their
candidate vectors, 20-32MiB of list-spine capacity, 15.5-20.7MiB of live
frames, 2.54MiB of symbols, and an unmeasured 80-95MiB dominated by retained
module IR, analysis facts, source, and dense per-node caches. The custom
worker/permanent arenas alone consume 356.8MiB, already more than twice the
whole target. The selected next representation remains headerless,
registry-free stable thunk lanes with reclaimable shape-sized work; IR/facts
and hash-cons compaction become explicit later owners rather than being
misclassified as frame or allocator residue.

## Thirty-first headerless typed heads and direct-island coverage

The typed Apply experiment was moved from the generic flat-store
header/registry into a permanent `HeaderlessFlatLane`. On the primary workload,
1,344,477 typed identities then replaced the corresponding entries in the
generic closure lane. The first exact measurement reduced peak RSS from
615,196KiB to 498,708KiB, but increased retired instructions from
20.144321859B to 21.183132165B. Moving suspended work out of its reusable slot
instead of cloning it reduced only about 82M instructions. A constant-time
first/last-address rejection before the lane's block search recovered about
623M instructions; a sparse page classifier was approximately 200M
instructions worse and was reverted. The retained address-envelope result
demonstrates that representation metadata must remain off unrelated value
lookups.

The stable Candidate-C head was then compressed from 16 bytes to one
`AtomicU64`: suspended state contains a generated work coordinate, blackhole
is a distinct invalid word, and successful publication overwrites the same
word with the forced Candidate-C value. An independent adversarial audit found
that the first high-16-bit marker collided with a reachable forced-thunk value,
and that `Option<EvalThunk>` alone conflated taken and free work slots. The
retained encoding fixes an invalid Candidate-C kind byte plus a secondary
payload marker, so every handle and blackhole fails checked value decoding.
The pool now records free membership, rejects double release, and permanently
poisons the maximum 24-bit generation rather than wrapping. Detached head
dereference is explicitly unsafe with a live-originating-heap obligation
instead of being exposed through a safe lifetime-free method. Seven focused
state/pool tests and five evaluator force/admission/error tests pass.

Against the closest preceding typed run, the one-word head reduced peak RSS
from 498,932KiB to 486,528KiB and retired 20.379375741B instructions rather
than 20.396358717B. The same-source C++ and candidate evaluations both produced
`/nix/store/rzqv3lqx4lp0vj2g2v9kx3bjanp936sz-aos-system-toplevel.drv`.
The 12,404KiB saving with a slight instruction improvement passes the local
8MiB/0.5% gate, so the compact head remains in the default-off experiment.
It does not approach the terminal 171,858KiB target by itself. Before
production use, the force owner, exact head/work capability, and moved-out work
must become one rollback-safe lease so panic unwind cannot restore a suspended
head after losing its work; post-publication pool reclamation must also become
infallible from the semantic caller's perspective.

For speed, an inclusive probe around the demanded `configWithFreeform`
`evalModules` node measured 1,199,048,610ns of 1,614,198,718ns (74.28%) and
1,995,245 of 2,466,451 forces (80.89%). Reaching the approximately 3.1B
instruction terminal bound from roughly 21.18B requires eliminating at least
85.37% even if the selected region executes for free; realistic local speedups
require at least 95% coverage. The narrow module island is therefore
quantitatively rejected. The next speed experiment must measure and encompass
the whole demand graph rooted at the requested attribute path, rather than
special-casing one lazy module combinator.

Two immediate breadth experiments were also rejected. Enabling the existing
per-def-site JIT produced the same derivation but retired 23.509247565B
instructions and peaked at 827,912KiB, confirming that its tiny-body
compile/helper-crossing model is not the required whole-demand executor.
Broadening the typed-head predicate from Apply shapes to every serial thunk
without a storage extension admitted only 185,905 additional heads. After
adding the necessary forced-head compatibility read, the run remained
byte-identical and retired 20.359529009B instructions, but peak RSS fell only
from 486,528KiB to 478,020KiB. Admitting all plain serial work, including
dynamic scopes, reached 1,530,695 heads and 461,364KiB at 20.361246259B
instructions. The dominant remaining allocation door was instead ready flat
lexical capture. A sound shared-owned capture prototype allowed escaped child
closures to retain those values after parent publication and increased the
head population to 1,832,271, but the same-source run peaked at 456,916KiB
and retired 20.549252406B instructions. The roughly 4.3MiB incremental saving
is far below the 100MiB all-serial gate, so the globally wider capture-backing
representation was reverted while retaining the layout-neutral broad serial
admission for further measurement. Any follow-up should preserve the one-word
capture descriptor and use a compact stable side-pool handle instead of
widening every environment.

## Thirty-second weak-root liveness and the reclamation window

A default-off census now marks from the evaluator's explicit root set without
treating the hash-cons indexes as roots. It traverses every flat and
record-backed value kind, including synthesized edges for headerless typed
thunk heads, and compares reachable counts and reserved inline bytes with the
monotonic heap totals. The completed primary instantiation retained only 933
objects. Almost all of the final heap image is therefore historical allocation,
not semantically live state.

Import-watermark samples locate the economically useful collection window.
Typed heads were disabled for this diagnostic so a blackholed typed head could
not hide moved-out work from the marker. Summing the reported inline bytes and
list-spine bytes gives:

| Loaded modules | Reachable | Total | Collectible | Dead share |
| ---: | ---: | ---: | ---: | ---: |
| 1,024 | 56.41MiB | 121.86MiB | 65.45MiB | 53.7% |
| 1,152 | 112.85MiB | 275.79MiB | 162.94MiB | 59.1% |
| 1,200 | 158.26MiB | 365.42MiB | 207.16MiB | 56.7% |
| 1,216 | 158.27MiB | 372.16MiB | 213.89MiB | 57.5% |
| 1,220 | 158.25MiB | 373.30MiB | 215.05MiB | 57.6% |

The candidate and the primed stock evaluator produced the same
`/nix/store/xr8y1mf0a0qjy6v5vvfxf2901df7hl9s-aos-system-toplevel.drv`.
The 215.05MiB late-window ceiling clears the 80MiB architecture gate for weak
hash-consing plus segmented reclamation. It does not itself prove an RSS
saving: the census excludes index and allocator overhead, marking tables
perturb diagnostic RSS, and a monotonic backing cannot release dead objects.
The next prototype must weaken the indexes, reclaim or reuse whole storage
segments before the primary peak, preserve stable identities for live values,
and show at least an 80MiB same-source peak-RSS reduction.

An allocation-extent follow-up tested whether reachable and dead objects are
too interleaved for page advice to realize that logical opportunity. It marks
every 4KiB page overlapped by a live flat object, counts only allocated pages
with no live overlap as reclaimable, and conservatively pins every boxed scalar
cell because scalars are not yet part of the object marker. Reclaimable pages
were 70.92MiB at 1,152 modules, 88.19MiB at 1,200, 92.08MiB at 1,216, and
92.82MiB at 1,220. Candidate and primed C++ Nix produced the same
`/nix/store/mk32p8dmgqcfh3im9s0mpxj1549jmxg0-aos-system-toplevel.drv`.
Page-level reclamation therefore clears the 80MiB falsification gate, but only
late and without enough margin to stand alone. The mutation prototype must
also drop external payloads, weaken and shrink intern indexes, and consider
segregated allocation epochs if its observed peak saving falls below the
projection.

The first mutation substrate is retained but not yet activated:
`HashConsTable::retain_committed` removes caller-rejected committed handles,
removes empty unreserved buckets, and shrinks the candidate vectors and outer
table. Its focused tests cover collision-bucket filtering and, critically,
preserving the capacity promised by an outstanding reservation. A collector
must run this pass before invalidating dead flat objects. It remains unwired
until the import watermark is either proven to be a complete-root safepoint or
moved behind one; the read-only census alone does not authorize destructive
collection.

The root audit subsequently proved that the watermark is not a destructive-GC
safepoint. `eval_intersect_attrs_primop` retains its left operand in an ordinary
Rust local while recursively evaluating the right operand; that recursion can
import a module and hit the watermark, but `mutator_root_set` explicitly does
not enumerate arbitrary Rust locals. `all`/`any` retain their predicate across
list evaluation, and direct builtin dispatch likewise does not register every
argument the way first-class primop application does. Moving the hook around
`push_module` or import-cache insertion cannot repair values held by callers
higher in the recursive stack. The existing GC-stress and quiescent-sweep
predicates already encode this limitation by declining unless transient
control state is empty.

The smallest sound repair for the recursive evaluator is an RAII shadow-root
lease for every value and value buffer live across reentrant evaluation,
forcing, import, or allocation, followed by a collector entry that accepts only
that registered safepoint. That is a broad and error-prone retrofit. The
preferred architecture now converges with the speed result: a trampoline,
bytecode, or direct-linked whole-demand executor keeps intermediates in an
explicit value stack and supplies stack maps at allocating helpers. The same
representation removes recursive dispatch/helper crossings and exposes
complete nonmoving roots for pre-peak reclamation.

The failed typed-head milestone scan is a useful safety result. While a typed
head is blackholed, its work has been moved out of the heap slot and may be held
only by evaluator control state. Marking that head as edge-free would silently
under-mark arbitrary Apply work. Production collection therefore depends on
the same rollback-safe owner/work lease already required by the typed-head
audit: the active lease must expose its work edges as roots until publication
or rollback completes.

## Thirty-third exact whole-demand instruction coverage

The whole-demand coverage probe uses no performance-counter unsafe code in the
evaluator. A temporary parent wrapper owns the Linux perf events and passes
command and acknowledgement pipes through inherited descriptors. The
instantiation API sends the begin command before demand-pool creation and waits
until the counters are enabled; after successful derivation snapshot it sends
the end command and waits until they are disabled. An owned guard sends the end
command on error or unwind. This excludes process startup and outcome
diagnostics without racing either boundary.

Three paired measurements on the broad serial typed-head candidate produced:

| Sample | Complete process | Demand epoch | Coverage | Outside | Projected at 10x |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 20.544938969B | 20.284239657B | 98.7311% | 260.699M | 2.289B |
| 2 | 20.549922031B | 20.284529543B | 98.7085% | 265.392M | 2.294B |
| 3 | 20.544785419B | 20.284844824B | 98.7348% | 259.941M | 2.288B |

The mean is 98.7248% coverage with 262.011M instructions outside the epoch.
Candidate and primed C++ Nix produced the same
`/nix/store/imrljqchv841m26jga3bjhj02aj45i0v-aos-system-toplevel.drv`.
A genuine 10x regional executor projects to 2.290B complete-process
instructions, below the approximately 3.110B terminal ceiling. The
whole-demand architecture therefore passes its instruction-coverage gate.
An independent stats-enabled structural run started the epoch at zero forced
thunks and zero function calls, ended at 2,466,452 and 3,176,700 respectively,
and the final evaluator stats reported exactly those same totals. Candidate
and primed C++ Nix produced the same
`/nix/store/3j082wi157ac8q7r4wlh3sdl3vfyljiz-aos-system-toplevel.drv`.
The stats run's hardware count is not a performance sample because the
force-shape timers deliberately add substantial in-epoch work.

This is a ceiling result, not an executor result. Per-definition JIT remains
rejected. A viable implementation must direct-link large demanded regions,
inline common force/environment/select/apply/builtin paths, and deforest the
synthetic `genList`/`map` apply spines. It must preserve lazy attr-path demand,
thunk identity and blackholes, force and error order, diagnostic module/span
state, string contexts, and effect ordering. Unsupported regions must decline
before observable work or deopt through an exact resumable continuation.
Compiled values live across allocating helpers must use the existing stack-map
root and compiled-safepoint machinery.

## Thirty-fourth explicit-stack foundation and alternative-source falsification

The first executable whole-root foundation is default-off behind
`AOS_NIX_DEMAND_MACHINE=1`. It deliberately admits only closed speculable
scalar IR composed of `Int`, `Bool`, `Null`, `If`, and integer `+`, `-`, `*`,
and `/`. Its complete preflight marks nodes when enqueued, so shared IR DAGs
are visited once and every unsupported or effectful node, including one in an
untaken conditional branch, declines before semantic work. Once admitted it
uses an explicit control stack and the evaluator-owned transient value-root
stack. There is no recursive fallback after admission; structural mismatch is
an error. The scoped root prefix is pre-reserved and restored on ordinary
return, error, or panic, and machine errors receive the same current-module
source context as the tree walker.

Reachable nodes are now predecoded into a compact boxed op tape. Runtime
control records carry tape PCs, so an admitted execution performs no
`self.node` lookup and does not repeatedly decode `IrNode`. Ten focused
Candidate-C tests originally passed. The attempt now lives at the complete
instantiation/attribute-path boundary instead of inside `eval_root`: the
initial grammar admits only an empty path, while a nonempty path declines
before root preflight or execution and leaves the unchanged oracle
root-plus-path session to run once. Twelve focused Candidate-C tests now pass.
They cover that ownership seam, differential lazy-branch and arithmetic
results, Add's special left-type-error-before-right-evaluation order, effectful
untaken-branch refusal, a shared DAG, a 20,000-node conditional chain without
native recursion, default-off flag parsing, transient-root cleanup after an
error, malformed reachable nodes, out-of-bounds children, and exclusion of
malformed unreachable arena slots. The broader Candidate-C library run
now reports 2,713 passed and 37 ignored with no failures.
The preceding release binary, with the demand machine both absent and explicitly
enabled, produced the same current source-pinned result as C++ Nix:

```text
/nix/store/xbw6lhmr5vkf9sp8b0qxr47ryqrjlkgg-aos-system-toplevel.drv
```

The primary root currently declines this tiny grammar, so this establishes an
executable control/rooting substrate rather than a performance improvement.
The default-off control retired 20.428294752B instructions and peaked at
472,776KiB RSS; explicitly enabling the declined path retired 20.429084033B
and peaked at 475,120KiB. This is not a primary-workload speed result.
The next admission expansion must remain whole-region and preserve the rule
that no unsupported operation is discovered after observable work.

An independent audit explored whether the large discrepancy instead lives
outside evaluator execution. Its retained frontend census was only:

| Owner | Bytes |
| --- | ---: |
| IR plus all dense facts | 14,147,432 |
| Module table | 1,343,488 |
| Source copies | 3,645,472 |
| Path bases | 20,819 |
| Symbols | 2,660,914 |

The total is about 20.8MiB. Frontend timers were 26.91ms parse, 3.83ms
resolve, 8.71ms lower, 15.72ms annotate, and 1.05ms module setup: 56.21ms
total, or 61.35ms including import fingerprint I/O. Against 2.365s of summed
non-overlapping force self-time this is at most 2.38%. The instruction profile
also assigns only 0.55% to direct hash-cons reserve/publish, 1.92% to
`node_in_module`, about 1.30% to symbol intern/rank work, and about 0.85% to
direct derivation ATerm build/write work. All work outside the exact demand
epoch is only 262.0M instructions.

These alternatives do not add up to the roughly 85% instruction reduction
required. A compact runtime op tape may still improve the executor, but IR
layout is not a standalone factor-level hypothesis. The factor-level
alternative findings are memory owners: 215.05MiB logically collectible at
the late census, approximately 76.5MiB of generic flat-store registry
capacity, and a projected 32-36MiB hash-cons structure. Frontend retention and
derivation payloads are at most secondary targets. The speed program therefore
continues through whole-demand execution, while the memory program combines
that executor's complete roots with typed representation, weak indexes, and
pre-peak segment/page reclamation.

The new default-off `AOS_NIX_RSS_PHASES=1` trace locates the memory growth:

| Phase | Current RSS | Worker mapped/used | Permanent mapped/used |
| --- | ---: | ---: | ---: |
| 1,024 modules | 226.1MiB | 51.1MiB | 29.8MiB |
| 1,152 modules | 351.8MiB | 121.1MiB | 60.2MiB |
| 1,200 modules | 440.2MiB | 155.1MiB | 77.2MiB |
| 1,220 modules | 451.2MiB | 160.3MiB | 78.6MiB |
| demand complete | 454.9MiB | 161.5MiB | 78.8MiB |
| post derivation snapshot | 463.0MiB | 161.5MiB | 78.8MiB |

Quiescent sweep is disabled in this configuration and changes neither RSS nor
arena accounting. Derivation snapshot adds only about 8.0MiB; the measured
peak is overwhelmingly accumulated evaluation state rather than external
materialization.

## Thirty-fifth primary grammar and resumable import boundary

A fresh primary force census shows why expanding the scalar `eval_root`
grammar is not the next meaningful stage. The machine currently returns before
attribute-path selection and final forcing. It must instead own the complete
`eval_root -> attr path -> final force` session with module-qualified op
coordinates.

The current workload forces 2,466,453 thunks. Its principal dynamic shapes are:

| Shape | Forces | Share |
| --- | ---: | ---: |
| Synthetic apply | 1,340,770 | 54.36% |
| Exact `genList`/`elemAt(index+1)` subset | 1,130,104 | 45.82% |
| Static select | 193,177 | 7.83% |
| Local plus upvalue | 138,717 | 5.62% |
| Let | 73,630 | 2.99% |
| Source Apply | 56,985 | 2.31% |
| PrimOp | 430,154 | 17.44% |

The lexical/thunk/simple-apply/static-attrs/list/if/update kernel projects to
23.15% force coverage. Adding the recognized `genList` spine projects to about
69% cumulative coverage; the remaining map synthetic spine raises the
synthetic-plus-kernel proxy to 77.51%, and concat/interpolation to 81.98%.
These are prioritization proxies, not substitutes for exact demand-epoch
instruction coverage.

Imports cannot be modeled as full oracle leaves: 2,442,897 of 2,466,453 forces,
or 99.04%, are classified as prelude/import work. The required boundary is
begin/resume/finish. Begin performs path coercion, cache recursion checks,
`Evaluating` publication, I/O, parse/lower/annotation, and module publication,
then returns either a cached `Value` or a new module root plus an owned import
lease. The machine pushes restoration/finish controls and evaluates that root
itself. Finish records observations, publishes `Ready`, and restores module,
lexical, `with`, and scoped-global state; error or unwind removes `Evaluating`
and restores the same state. An unsupported newly loaded module is a
predeclared one-shot oracle-module operation, never replay after partial work.

The next counters are machine-executed forces, oracle boundary calls, nested
oracle forces, and module declines. `oracle_nested_forces` must eventually be
below 0.5% of total forces, or apparently atomic boundaries are hiding the
demand graph. The next implementation stage is session ownership and import
lease mechanics, not additional scalar literals.

## Thirty-sixth pre-peak reclamation alternatives

The module-count watermark is not a sound collection boundary. The current
mutator root set omits ordinary Rust locals held across recursive evaluation;
examples include the retained left operand of attribute intersection, the
predicate and copied elements in `all`/`any`, and zip/group assembly values.
Typed blackholes can also detach work from the heap. A milestone immediately
after `push_module` therefore cannot prove that either ancestor locals or
detached typed work are dead.

A substantially different, conservative causal experiment is an import
allocation-fence nursery. On an ordinary import-cache miss, capture allocation
positions immediately after publishing `Evaluating` and before loading,
parsing, lowering, or evaluating the module. After the import body has returned
and restored module/env/dynamic-scope state, explicitly root its result,
conservatively retain every pre-fence allocation, scan all pre-fence outgoing
edges into the suffix, and collect only unreachable post-fence allocations.
In serial evaluation, an arbitrary value retained by a suspended ancestor must
predate its immediate descendant's fence. A pre-fence thunk or cache entry
mutated to reference a suffix value is protected by the prefix edge scan.
Nested fences are LIFO. The initial experiment must be success-only,
default-off, avoid address reuse, and report projection before mutation.

Three architectures were compared:

1. A fence nursery plus weak-index pruning and dead-page advice is the smallest
   experiment. Flat registry entries and side maps must be retired before
   advising their inline-header pages, and all hash-cons tables must be
   weak-pruned before object invalidation.
2. Whole-demand machine roots plus generalized collection removes the
   conservative prefix once oracle boundaries have returned. Boundary
   arguments/results live in transient machine slots, and an evaluator-owned
   typed-work lease roots any detached blackhole work until publish or rollback.
3. Stable identity heads with movable per-import payload segments can promote
   live payloads and release whole regions. It is the largest change, but it
   converts fragmented logical garbage into reclaimable storage without
   changing user-visible identity.

Page advice alone is limited by the measured 88.19MiB whole-page opportunity
at 1,200 modules and 92.82MiB at 1,220 modules, so it is a causality gate rather
than the terminal design. The memory arithmetic does identify a viable
factor-level program: from the current roughly 461.7MiB peak to the roughly
167.8MiB target requires about 293.9MiB. The independently owned ideal
opportunities are about 215.05MiB logically dead heap storage, 76.5MiB of
registry/hash-cons capacity, and 20.8MiB of retained frontend artifacts, or
about 312.4MiB total. Crossing the target therefore requires realizing most of
the logical-dead opportunity through compaction or segmentation, shrinking
weak indexes, and releasing frontend artifacts; isolated page advice cannot do
it.

## Thirty-seventh lazy-machine and reclamation prior art

The next architecture is grounded in lazy-runtime and collector literature
rather than a benchmark-specific shortcut:

- Marlow and Peyton Jones, [*Making a Fast Curry: Push/Enter vs.
  Eval/Apply*](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/07/eval-apply-icfp.pdf),
  supplies the closest calling convention for the compact machine: explicit
  `Apply` and `Update` continuations, one arity-dispatch boundary, and distinct
  exact-, under-, and over-application paths. This maps directly to the
  apply-dominated primary force mix.
- Peyton Jones, [*The Spineless Tagless
  G-machine*](https://doi.org/10.1017/S0956796800000319), is the baseline for
  closure entry, explicit stacks, blackholes, update frames, and graph update
  on stock hardware. The DemandMachine should be reviewed as a specialized
  STG-like machine rather than an accumulation of recursive helper calls.
- Jones, [*Tail Recursion Without Space
  Leaks*](https://www.cambridge.org/core/services/aop-cambridge-core/content/view/3F1FE7625B1633B8D8BEC0955F0F4906/S0956796800000277a.pdf/tail_recursion_without_space_leaks.pdf),
  shows why entering/blackholing a shared closure should sever obsolete payload
  reachability while an update frame preserves identity. This supports stable
  thunk heads with detachable or movable payloads.
- Blackburn and McKinley's
  [*Immix*](https://openresearch-repository.anu.edu.au/items/32c6080b-51ee-433e-981d-e5960787a3fb)
  and Shahriyar, Blackburn, and McKinley's [*Fast Conservative Garbage
  Collection*](https://www.steveblackburn.org/pubs/papers/consrc-oopsla-2014.pdf)
  support block/line reclamation with opportunistic evacuation and show that
  ambiguous roots can pin only fine-grained lines while exact objects remain
  movable. This is the concrete model for combining temporary conservative
  Rust-local roots with exact machine roots.
- Tofte and Talpin's [*Region-Based Memory
  Management*](https://ropas.snu.ac.kr/lib/dock/ToTa1997.pdf) and Terauchi and
  Aiken's [*Memory Management with Use-Counted
  Regions*](https://www2.eecs.berkeley.edu/Pubs/TechRpts/2004/5216.html)
  motivate import/demand epochs whose storage is bulk-releasable but whose
  escaping values keep a region live or are promoted.

The synthesis is a whole-session eval/apply machine, stable blackholed identity
heads with detachable payloads, exact machine roots plus validated
fine-grained conservative pinning at oracle boundaries, and dynamically owned
import regions. No collector paper removes the approximately 10x execution
reduction required inside the demand epoch; the speed and memory programs
remain coupled but distinct.

## Thirty-eighth owned import continuation leases

The first two begin/resume/finish layers are implemented without yet widening
the machine grammar.

An ordinary import-cache miss now owns an evaluator-resident
depth-plus-generation token. Lease-vector reservation and generation
exhaustion checks precede `Evaluating` publication. Success preserves
shared-`Ready` publication before local cache replacement; error and panic
remove the marker. A stale token that reuses the same stack depth cannot pop a
later lease.

Imported module evaluation has a separate evaluator-owned token. Begin
reserves both suspended-root and lease capacity before module publication,
then preserves the established module publication, milestone, scoped-global,
env/`with`/scoped swap, and suspended-root order. Finish attaches imported
source context while the imported module remains current, restores the caller
module, and then restores the displaced lexical and dynamic scopes. Panic uses
the same restoration before the outer cache lease removes its marker.
Registered modules and symbol-table growth remain published on evaluation
error, matching the previous behavior.

Six focused cache-lease and six focused module-lease tests pass, including
success, error, recursive import, nested contexts, stale tokens, generation
exhaustion before mutation, source-correct diagnostics, and panic cleanup
through both lease layers. The combined Candidate-C library run passes 2,725
tests with 37 ignored. The preceding cache-only toplevel matched pinned C++ Nix
at:

```text
/nix/store/f3rmflqsirl18gkzvl2iwynrqbn953dn-aos-system-toplevel.drv
```

It retired 20.425546259B instructions and peaked at 472,844KiB RSS, within the
existing class. These leases remove stack-local continuation ownership and
make module bodies resumable; they do not by themselves execute primary work
in the compact machine.

The bounded third layer now installs the default-off demand-machine decision
inside that owned module interval. An admitted imported scalar root executes
one machine body; an unsupported root or a non-text-store force-cache root
records one decline and enters exactly one established root-cache oracle
continuation. The existing text-store force-cache bypass remains admissible.
Evaluator-owned counters distinguish machine bodies, module declines, and
oracle module calls. The active allocation-root marker is displaced and
restored through a panic-safe wrapper, including when a caller already owns a
different root marker.

Ten focused imported-module tests and thirteen focused demand-machine tests
pass on the Linux builder. The full Candidate-C library run passes 2,730 tests
with 37 ignored, plus all doctests. After daemon priming, pinned C++ Nix and
both candidate modes produced:

```text
/nix/store/fgy6434wsw869hj3ssmqjcaj34iq8cph-aos-system-toplevel.drv
```

The disabled run retired 20.430051996B instructions at 473,664KiB peak RSS.
The enabled run retired 20.425230101B at 472,964KiB. The approximately 0.024%
instruction difference is noise-class and confirms that the current scalar
import grammar owns essentially none of the primary workload. This validates
the continuation boundary but is not a speed or memory result. The next
executor increment must admit the measured lexical/select/lazy kernel across
module bodies, rather than adding more closed scalar syntax.

Evaluator-returned statistics now expose the three ownership counters without
requiring process-global instrumentation. A stats-enabled primary run measured
zero machine bodies, 1,220 module declines, and exactly 1,220 oracle module
calls. Thus the noise-class A/B is not hiding a small scalar win: every
installed imported root declined. The broad Candidate-C run remains green at
2,730 passed and 37 ignored after adding the stats fields.

## Thirty-ninth compact-machine alternatives and the synthetic-work gap

Two independent architecture audits sharpened the terminal arithmetic. With
about 262M instructions outside the measured demand epoch, the approximately
20.284B-instruction epoch must fall below about 2.848B to hold the process below
3.110B. This requires at least a 7.12x epoch reduction. A conventional
whole-module bytecode interpreter expected to improve dispatch by roughly
2-4x is useful substrate, but is not a terminal design by itself.

The deeper discrepancy is that source syntax coverage is not execution
coverage. Runtime-generated synthetic Apply thunks account for 54.36% of
forces; the exact `genList`/simple-lambda/`elemAt` spine accounts for 45.82%.
Source `Apply` nodes account for only 2.31%. A machine that admits additional
`IrKind` variants but still calls the existing force/apply/builtin/update
protocol can therefore report broad source coverage while retaining most of
the instruction cost.

The current DemandMachine is intentionally a correctness seam, not yet the
compact VM assumed by the 10x projection. Its operations retain IR IDs, spans,
and operands; it builds multiple vectors for each admitted body; and its
runtime loop still enters general `Result`-returning numeric helpers. Expanding
that representation literally risks recreating the recursive tree walk on an
explicit stack.

The ranked terminal direction is a whole-session STG-like eval/apply reducer:
packed persistent module code, explicit value/argument/update stacks, stable
small thunk heads with detachable payloads, and fused builtin
producer-consumer loops. The smallest causal speed experiment should own the
complete dominant synthetic thunk-entry/update sequence for
`genList -> simple lambda -> elemAt(upvalue,index+1)`, with no call back through
the general force/apply helpers and no per-element synthetic payload. Require
at least 7x local instruction reduction before widening it.

Before even the lexical kernel can suspend safely, forcing and lambda
application need evaluator-owned depth-plus-generation leases. The existing
`ForceGuard<'_>` borrows a thunk cell across recursive body evaluation, and the
lambda path owns module/environment restoration on the Rust call stack.
Begin/finish/abort force and call leases must preserve blackhole, cache,
impure-trace, module, environment, call-depth, error, and panic ordering while
keeping all live Values in scanned evaluator storage. Only then can a mixed
module program use predeclared one-shot oracle leaves without replaying work.

The lexical/select/lazy kernel is a meaningful semantic gate but represents
only about 23.15% of the force proxy. It must be followed immediately by
synthetic Apply plus the exact `genList` spine (about 69% cumulative), then the
remaining synthetic map, primop, and concatenation work. Persistent regional
native compilation remains an alternative only if a source-keyed trace census
first proves that a small set of long regions covers at least 90-95% of the
epoch; the rejected tiny-body JIT already rules out per-thunk compilation.

A code-level audit of the exact `genList` shape further constrains that first
superblock. The existing lowered-IR marker is already source-independent and
previously saved about 8.23% whole-process instructions, but it still allocates
one full synthetic thunk payload per generated element and enters general
force/apply helpers. Of 1,128,838 exact outer cases, 1,050,218 have one direct
child Apply and only 78,620 have no child. An outer-only superblock can be a
sound representation gate, but cannot claim a 7x inclusive reduction while
the selected child remains an oracle Apply.

The smallest sound representation experiment keeps one stable memoizing head
per element but moves repeated work into a shared block descriptor containing
the program, lazy captured receiver, and length. A compact suspended head
encodes block plus index; blackhole and forced words remain per element.
Admission must refuse GC/shared/tier/cache/stats/snapshot modes initially and
preserve zero-length and unused-element laziness. The force loop owns claim,
rooting, call/module state, index addition, receiver force/type check, bounds,
selection, selected-value force, restoration, and outer update. Error or panic
restores the exact coordinate.

Gate the experiment with old and new paths in one release binary over at least
one million cold heads, subtracting an identical zero-force setup and requiring
the pessimistic local instruction ratio to exceed 7x. Separately require the
primary to report about 1.13M block forces, byte parity, and an inclusive
outer-plus-child reduction of at least 7x. An exclusive outer win with roughly
one million nested oracle Apply calls is not terminal evidence. A selected-child
shape census should precede absorption of that Apply protocol.

The first prerequisite force lease is now implemented but deliberately unused
by production forcing. A crate-private detached cell claim transitions an
ordinary reusable Node thunk without retaining a borrowing `ForceGuard`.
Before that claim, the evaluator reserves a depth-plus-generation lease and
two slots in the existing scanned active-force-root stack: the possibly
relocated source head and the eventual result. Finish re-resolves the cell from
the rooted head, preserves resolution-barrier, publication, work-release, and
capture-shedding order, then removes the roots. Error and injected body panic
abort the blackhole before restoring the previous root prefix.

Single-entry, parallel-payload, non-Node, and Candidate-C typed heads decline
before mutation. The typed-head test verifies both state and detached-work
counts are unchanged, so this narrow lease cannot orphan typed suspended work.
Nine focused tests cover publish/replay, error retry, stale same-depth tokens,
generation exhaustion before blackholing, strict nesting, panic cleanup,
displaced older roots, non-Node decline, and typed-head decline. The Linux
Candidate-C suite passes 2,739 tests with 37 ignored plus all doctests.
The release default-off control remains byte-identical to pinned C++ Nix at:

```text
/nix/store/ykmkbnxa58m0x8w2x337qpj1lb035cdg-aos-system-toplevel.drv
```

It retired 20.433786707B instructions and peaked at 478,060KiB RSS, within the
established noise class. Because no production force path calls the lease yet,
there is no enabled performance claim.

## Fortieth fresh profile, repeated-call reuse, and reclamation research gate

A fresh instruction callgraph on the marker-session build invalidates another
narrow representation hypothesis. `eval_node_on_current_stack` remains 72.11%
inclusive, lambda application 40.81%, thunk-body evaluation 36.82%, primop
dispatch 28.73%, and `eval_all_any_elements` alone 15.08%. The exact session
step is only about 0.34% self time. The session removes part of recursive force
traffic but retains node dispatch, thunk allocation, environment capture and
push/pop, lambda cloning, and hashing. A compact session work pool cannot be a
large memory lever either: Candidate-C heads are already one eight-byte word,
and the measured reusable work pool peaks at 7,374 live entries with 8,192
slots, below one MiB.

A proposed one-entry `genList` recipe lookup cache was therefore tested rather
than assumed. It preserved bytes but retired 19.506382877B and 19.508606331B
instructions against the preceding 19.491862639B session control, a stable
14-17M regression, and was reverted.

Immutable lambda metadata reuse across repeated `all`/`any` calls was retained.
The helper preserves per-call counter, frame, environment, binding, module,
memo, and error behavior, while cloning the immutable lambda and resolving the
synthetic argument span once. The first retained release measured:

```text
session: 19.274192423B, 19.276329242B instructions
default: 19.598127872B instructions
```

Extending the same path to `filter`, `concatMap`, and `groupBy` passed all 73
Candidate-C list-builtin tests, including empty-list laziness, error order,
short-circuiting, and comparator-order fixtures. On the exact same-source
derivation it measured:

```text
/nix/store/n6badpp6znmybn6l6sahq2k7dwbrscsl-aos-system-toplevel.drv

session: 19.269143484B, 19.268848650B instructions
default: 19.593185330B instructions
typed heads: 19.815991542B instructions, 487,892KiB RSS
C++: 6.220177428B instructions, 343,316KiB RSS
```

The generalization is a reproducible roughly 5M-instruction improvement over
the `all`/`any`-only release, but is strategically tiny. `sort` and `partition`
are not attractive next targets: their exact force/comparator ordering makes
safe hoisting more invasive, and the primary source has four `sort` sites and
no material `partition` use. `foldl'` has 39 source sites and is the next
bounded candidate only if a runtime census proves it material. Repeated-call
reuse is not a substitute for the whole-session reducer.

The memory literature and current census now select a concrete falsification
experiment. Tofte-Talpin regions, the MLKit region-plus-generational collector,
Appel's survivor hash-consing, Haskell weak pointers/stable names, ephemerons,
and Immix all support the same combined direction: nested evaluation epochs,
survivor promotion, collector-integrated weak indexes, and block/line physical
reclamation. No isolated collector result covers the terminal arithmetic.
Dropping the typed peak from 487,892KiB below the current half-C++ ceiling of
171,658KiB requires recovering about 316MiB before the high-water point.

The first experiment is therefore diagnostic, not a collector. On every
serial cached-import miss it records a heap allocation watermark immediately
after `Evaluating`, then, after the imported module restores its caller and
before publishing `Ready`, measures the cohort allocated since that watermark.
The returned value, all evaluator-owned roots, and all prefix-to-cohort edges
seed survivor traversal; hash-cons indexes deliberately do not. It must report
cohort bytes, survivor/dead bytes, cross-epoch edges, list-spine bytes, index
retention, and wholly dead 4KiB/64KiB/1MiB units without mutating the heap.
This answers the missing causal question: the late census proves roughly
215MiB is dead eventually, but not that enough of it is dead at nested import
returns to reduce peak RSS.

The default-feature test configuration currently cannot compile several
Candidate-C-aware tests because `Value::word`, refusal-census, weak-liveness,
and storage-census methods are feature-gated inconsistently. Candidate-C
focused tests compile and pass. This is a pre-existing test-configuration
defect, not evidence for or against the retained optimization, and must be
repaired before a default-carrier full-suite claim.

## Forty-first import-lifetime falsification and terminal architecture split

The read-only import-epoch census is now implemented behind
`AOS_NIX_IMPORT_EPOCH_CENSUS=<stride>`. A serial cache miss records flat-store
watermarks immediately after installing `Evaluating`. On successful return,
after module/environment restoration and before `Ready` publication, it scans
the complete mutator root set, prior ready-import values, and the returned
value. Hash-cons indexes are intentionally weak rather than roots. The report
separates cohort/reachable/dead object counts and inline bytes for records,
strings/paths, lists, attrs, closures, typed heads, and malloc-backed list
spines. Boxed scalars are pinned and captured environments, typed work slots,
hash indexes, and blackhole external state are explicitly excluded rather than
misreported as reclaimable. Focused Candidate-C suffix and nested-fence tests
pass, and the diagnostic does not mutate the heap.

The exact primary workload falsifies cached-import return as a material
reclamation boundary. An all-import run produced 1,377 reports across three
identical native executions, or 459 cache misses per execution. Every report
had import depth one. Of those 459 misses, 448 allocated only one reachable
88-byte closure. Only one miss per execution had any measured dead cohort:
168 objects, 17,040 inline bytes, and 1,208 list-spine bytes. Across all misses
in one execution, measured cohort mass was only 94,048 inline bytes plus 1,584
spine bytes, and total dead mass was 18,248 bytes. The new same-source primary
remained byte-identical to C++ at:

```text
/nix/store/62gn77k92xqxw846v9xvisghj24cxadm-aos-system-toplevel.drv
```

The causal explanation is laziness: import loading publishes a small root
closure, while the large graph is allocated later when that closure is forced.
Therefore the previously measured approximately 215MiB of eventual garbage
cannot be recovered at cached-import returns. This rejects cache-miss-to-WHNF
return as a terminal region boundary, not module provenance as a lifetime
signal. Lazy descendant forces occur after the lease is popped; scoped imports,
pre-fence path work, frontend storage, captured environments, registries, and
allocator pages are also outside this census. A provenance-tagged descendant
epoch remains unmeasured and plausible.

The exact disabled diagnostic build also established the current same-source
control:

```text
C++:         6.220427333B instructions, 342,864KiB RSS
default:    19.593054908B instructions, 629,188KiB RSS
session:    19.270948769B instructions, 628,536KiB RSS
typed heads:19.818322184B instructions, 499,796KiB RSS
```

The current exact half-C++ ceiling is 171,432KiB and the greater-than-2x
instruction ceiling is approximately 3.110B. Typed heads still need about
328,364KiB of peak reduction, while the fastest session control needs about a
6.20x whole-process instruction reduction.

Two independent adversarial architecture audits now define the next split.
For speed, the current session machine cannot meet the gate even if made free:
it owns only about 6.36% inclusive and calls the general evaluator from its
marker step. The scalar DemandMachine admitted none of 1,220 primary imported
roots, and per-force JIT boundaries are too expensive for the sub-microsecond
call tail. The credible terminal direction is a persistent whole-session
STG/GRIN-style reducer: packed immutable module blocks with cold source maps,
one eval/apply loop, explicit value/argument/update stacks and stack maps,
direct saturated calls, detachable thunk work, and predeclared cold oracle
leaves.

The smallest causal execution island should own one complete primary
`all`/`any` demand run, including element thunk claim/update, predicate frame
and body, Boolean force, and short-circuit, with no TreeWalk callback or
per-element hash lookup. `eval_all_any_elements` is 15.08% inclusive, large
enough to make the whole-process effect unmistakable. Require at least 10x
local inclusive instruction reduction; at 10x reducer speed the eventual
oracle share must fall below about 4.5% to satisfy the 7.12x epoch gate.
Failure to remove every per-element force/eval/apply callback, or failure to
produce the predicted whole-primary movement, kills that island shape.

For memory, the strongest non-import architecture is a small copying nursery
feeding an Immix-style old generation, combined with weak/ephemeron registries,
inline exact-length spines, packed GC-owned frames, and permanent one-word
thunk identities whose suspended work is movable and detachable. This cannot
be bolted safely onto the current recursive tree walker: arbitrary Rust locals
are not roots, production flat objects contain interior pointers and Rust
owners that are not byte-relocatable, and returned heap borrows can cross
allocation. The whole-session reducer's explicit stacks are therefore also the
root-completeness prerequisite for moving collection.

Before implementing movement, broaden the nonmoving compact-head substrate to
essentially every serial thunk shape. Require at least 150MiB same-source peak
RSS reduction, byte parity, and no more than 0.5% instruction regression.
Then prototype an 8-16MiB copying nursery only for self-relative strings,
inline lists, and attrs on a machine-owned slice. Require less than 25%
survival, collector work below 10% of retired instructions, at least 80MiB
actual or causally projected primary peak reduction, and exact
collect-at-every-allocation stress parity. These are falsification gates, not
permission to infer the terminal result from representation size alone.

## Forty-second captured-thunk and equality-island censuses

Two additional default-off allocation/execution censuses resolve the next
prototype choice. The typed-head admission report counts exactly one terminal
outcome per thunk allocation and separates work kind, capture readiness, and
runtime refusal reason. On the typed primary it measured:

```text
total identities:       2,693,368
typed heads:            1,530,695
generic fallbacks:      1,162,673
ready-capture fallback:   301,576 (428,734 captured Values)
pending-capture fallback: 861,097 (1,110,675 captured Values)
all other refusal doors:        0
```

The remaining generic identities project to 120,917,992 bytes at the current
88-byte inline object plus labelled 16-byte registry entry. The captured words
themselves project to 12,315,272 bytes. Current typed heads occupy 12,245,560
bytes and their 65,536-slot work-pool capacity projects to 5,242,880 bytes.
Thus even an impossible zero-cost conversion of every fallback cannot save the
150MiB required by the compact-head standalone gate. Captured-head broadening
is still useful identity/collector substrate, but it is arithmetically
falsified as the terminal memory solution.

The complete all/any census measured 90,608 calls, 1,013,176 examined elements,
1,309,912 nested force events, and 2,225,417 nested function calls. One source
shape dominates:

```text
lib/lists.nix:
  elem = x: list: builtins.any (e: e == x) list;

dynamic population:
  calls:          81,243
  elements:      984,576
  nested forces: 1,188,890
  function calls:2,093,079
  element state: 977,824 already-forced thunks, 6,752 Node thunks
```

Across all call sites, equality predicates own 83,172 calls and 992,453
elements. This overturns the proposed genList-element island: the dominant
all/any opportunity is repeated equality predicate eval/apply after elements
are already forced. The next bounded execution experiment should recognize
only the exact `any (e: e == captured)` closure/capture shape before mutation
and fuse it to the existing Nix equality/elem loop. It must preserve list,
predicate, captured candidate, element, error, cycle, and short-circuit order;
unsupported equality shapes decline before work.

The instrumentation itself exposed a hot-path discipline failure. With both
censuses disabled, two same-binary samples retired 19.641700536B and
19.641969349B instructions versus the preceding 19.593054908B control, about a
48.6M or 0.248% regression. Avoiding classification and recorder calls behind
one predictable allocation gate did not recover the code-layout/branch cost.
These one-shot census hooks must be removed after their captured reports are
consumed; default-off is not synonymous with free.

The nonmoving memory alternative also gains a concrete research gate from
Mesh (Powers et al., PLDI 2019): compatible sparse same-size pages can share
physical backing without changing object virtual addresses. This could bridge
the present pointer-stability constraint, but only after dead objects are
identified and freed. A future provenance cohort census should therefore
report per-size-class 4KiB occupancy masks and compatible non-overlap page
pairs alongside 64KiB/1MiB whole-cohort packing. It is a projection gate, not
a reason to mesh the current append-only arena blindly.

## Forty-third exact equality island result and specialization ceiling

The exact `builtins.any (element: element == captured)` island is implemented
behind `AOS_NIX_ALL_ANY_EQ_ISLAND=1`. Admission requires the exact lowered
lambda, formal, local-element, captured-upvalue, and equality shapes. It
declines tiered execution, all memo/force caches, GC and GC stress, parallel
payloads/workers, and shared evaluation before changing state. The loop
preserves element-before-candidate forcing, direct equality, function-call
counts, call depth, module switching, panic cleanup, short circuiting, and
empty-list capture laziness.

The primary same-source result is byte-identical to C++ Nix at:

```text
/nix/store/hkqw6az72kcs812jjhgrr1a7l88lzpjz-aos-system-toplevel.drv

C++:      6.220472430B, 6.220478837B instructions; 343,056-344,348KiB RSS
disabled:19.593769306B,19.593152534B instructions; 639,548-641,136KiB RSS
enabled: 18.074480595B,18.074253433B instructions; 640,768-640,984KiB RSS
```

Removing both one-shot censuses recovered the exact 19.593B disabled control.
After both adversarial semantic fixes described below, the retained island
saves about 1.519B instructions, or 7.75% of the whole process,
with no material RSS change. This is substantial enough to retain as an
experimental executable proof, but it fails the predeclared complete-island
gate: the 15.08% inclusive all/any profile implied about 2.66B savings for a
10x local reducer, while this callback-bearing loop continues to call general
forcing and equality for every element.

The global bound is decisive. Even making all all/any execution free saves at
most about 2.955B instructions and leaves 16.638B. Weighting that bound by the
exact equality shape's 97.18% element share leaves about 16.722B. Families of
similar builtin islands therefore cannot close the approximately 14.8B
remaining gap to the 3.110B terminal ceiling. Further shape islands are
rejected as the main architecture; their role is limited to semantics canaries
and eventual direct entries in a persistent reducer.

An adversarial diagnostic review found one imported-module edge in the first
implementation: source-less force/equality errors were propagated after
restoring the caller module, unlike generic `eval_node(lambda.body())`.
The island now attaches a source-less body error while the lambda module is
current, before call/module cleanup. It deliberately leaves `enter_call`
errors unmapped because the generic path also attaches those only in the
caller. A differential test constructs the predicate in an imported module,
triggers unsupported external equality, and proves generic/fused error kind,
span, imported source name, and imported source bytes match.

The same review found that directly forcing raw Local/Upval values skipped
generic node entry's ordinary cached-thunk forwarding loop. A forced thunk may
legally cache another unmarked thunk, so one demanded-force call is not
equivalent to evaluating the operand node. Both island operands now run
`force_node_result` followed by `force_demanded_value`, in the original
left-to-right order. A focused canary manually publishes a two-level forwarding
chain and proves generic and fused equality both reach the terminal integer.

## Forty-fourth cached-WHNF reducer and provenance-projection falsification

The first persistent-block experiment deliberately removed recursive evaluator
callbacks from the exact equality payload. It cached a decoded reducer block,
stored live values only as transient-root indices, ran an explicit
`NextElement`/`FinishComparison` control stack, replayed bounded cached-thunk
chains directly, and compared scalar terminals without `eval_node`,
`force_value`, `apply_lambda_value`, or recursive equality callbacks. Twenty-four
focused list tests passed, including forced-thunk replay, code reuse, structural
fallback, and invalid argument-node ordering.

The primary benchmark nevertheless admitted exactly zero calls and zero
elements:

```text
disabled: 19.682871534B, 19.682584719B instructions
enabled:  19.748794476B instructions
coverage: 0 admissions, 0 elements
```

The whole-list preflight required every element and the captured candidate to
already terminate in scalar WHNF before the reducer changed state. The primary
list is lazy at admission even though most elements become cached by the time
the equality body demands them. The experiment therefore proves that a
cached-WHNF replay block is not the required reducer boundary. It was removed,
including its disabled entry branch and tests. The next reducer slice must own
the complete `Force -> Update -> Apply/Compare -> Branch` transition for one
element, suspend on a Node thunk without returning to TreeWalk, and resume from
an explicit update frame. Cached scalar replay can be an opcode inside that
machine, but cannot be its admission predicate.

An independently audited source-module cohort diagnostic was also rejected as
an acceptance instrument. Its first version attributed flat allocations to
modules and projected 4KiB/64KiB/1MiB packing plus 64-byte-line Mesh
compatibility. The audit found that:

- final-return liveness is not peak liveness;
- per-cohort rounded capacity can count segregation padding as reclaimed
  physical memory;
- missed allocation hooks can assign an earlier gap to the next module;
- non-identical overlapping external extents can be counted twice;
- string/list/attrs capacities, captured frames, indexes, and allocator
  padding make the tracked survivor ratio incomplete; and
- virtual reservation occupancy is not resident-page evidence.

The diagnostic was repaired to mark unknown ownership gaps, separate external
payload lower bounds from reservation packing, reject overlapping extents,
report dead payload and padding separately, and hard-code acceptance invalid
until peak-aligned physical accounting exists. That repaired scaffold still
inserted a fence and branch after the central allocation wrappers. Same-source
controls rose from about 19.593B to 19.683B instructions, approximately 90M or
0.46%, versus the 0.05% retention ceiling. The hooks and scaffold were
therefore removed after recording the design constraints.

A future memory experiment must sample or reproduce the actual high-water
ordinal with a complete root set, distinguish resident 4KiB pages from
reserved address space, and calculate net reduction from current committed
footprint after copying/segregation fragmentation. Ideal packing and Mesh
compatibility remain useful lower-bound projections, never substitutes for the
less-than-half peak-RSS gate.

## Forty-fifth architecture pivot and peak-memory orientation

The bounded genList producer-consumer superblock was stopped before
integration. Existing evidence proves that 1,050,218 exact outer markers
select one nested Apply that returns WHNF, but it does not prove a closed
selected-child code grammar. The current marker session can tail-enter another
marker; every ordinary selected Apply necessarily returns to generic force,
lambda application, and recursive node evaluation. A shape-restricted child
prototype would therefore have unknown primary coverage and could not support
the predicted at-least-500M instruction effect.

This changes the implementation order. The next executable unit is not a
genList-specific file layered over TreeWalk. It is the reusable persistent
reducer substrate: module-qualified packed code blocks, Node entry, detached
Force/Update, exact-arity lambda Apply, explicit environment/call restoration,
and predeclared resumable oracle leaves. Once that substrate can preflight an
Apply body before mutation, the existing genList marker becomes its first
producer entry and the measured selected-child population becomes its first
coverage gate.

This is also a reversal of RFC 0007's original executor choice. TreeWalk plus
per-thunk JIT was preferred over a Snix-style bytecode machine. The current
primary invalidates that premise: demand execution is 98.7% of process
instructions, per-thunk JIT boundaries are closed by measured dispatch cost,
and a conventional 2-4x bytecode speedup would still miss the required 7.12x
demand-epoch reduction. TreeWalk remains the semantic oracle. Production
execution must use STG eval/apply conventions, direct saturated calls,
producer-consumer superinstructions, and explicit value/argument/update
stacks. A reducer increment is retained only when it owns the complete admitted
transition and reports nested oracle force/apply work below 0.5%.

Default phase telemetry gives the first physical memory shape:

```text
default demand complete:
  RSS:                625,913,856 bytes
  worker arena used:  304,018,952 bytes
  permanent used:      70,087,560 bytes

typed-head demand complete:
  RSS:                505,270,272 bytes
  worker arena used:  169,317,792 bytes
  permanent used:      82,670,472 bytes
```

At final return the default weak census sees 90,813 dead reservation pages
(371,970,048 bytes); typed heads see 60,964 dead pages (249,708,544 bytes).
This does not prove a peak reduction because most become dead only after the
high-water work. At the default 1,152-module milestone RSS is 505,356,288
bytes while reservation pages include about 201MiB live and 74MiB dead. Typed
heads reduce the same milestone RSS to 370,520,064 bytes, but milestone weak
scans correctly refuse blackholed typed work whose detached edges are not in
the reported root set.

Decommitting final dead pages alone would leave roughly 255MiB in either
representation, still above the approximately 172MiB terminal ceiling. The
memory architecture therefore needs both timely reclamation and at least
another roughly 83MiB of live/permanent/runtime compaction. A valid experiment
must reproduce an actual high-water ordinal, include active typed work and
every explicit reducer stack in its roots, and compare resident 4KiB pages
before and after reclamation. Final weak liveness remains orientation only.

## Forty-sixth peak-ordinal and belt-collector experiment contract

Peak-location instrumentation must be compile-time-only. A
`peak_ordinal_probe` feature will add a monotonically increasing ordinal after
each successful fresh serial allocation and sample RSS every 4,096 objects,
then every 256 objects around the winning interval. The ordinary candidate
build must contain no counter, branch, environment lookup, or changed heap
layout. Feature-on totals must reconcile exactly with authoritative heap
allocation counters; hash-cons hits, failed reservations, and replayed values
must not advance the ordinal. Three locating runs must agree within 0.1%, and
the sampled maximum must be within 8MiB or 2% of external maximum RSS.

The second pass targets that ordinal but may snapshot only at a complete-root
reducer safepoint. Value, argument, update, control, pending accumulator,
module/import lease, callback argument/result, and typed detached-work roots
must all be explicit. If the target lands inside a TreeWalk oracle callback,
the diagnostic defers until reducer re-entry after the callback result is in a
machine slot; more than 8MiB or 2% RSS drift invalidates the snapshot. Native
stack scanning cannot repair this because Rust locals may own heap `Vec`
storage containing Values.

At the target, `mincore` or the platform equivalent must classify resident
4KiB pages before allocating census buffers. The report separates current
resident reservation pages, live-overlapped resident pages, wholly dead
resident pages, external allocation lower bounds, registry/hash capacity, and
the simulated destination footprint including metadata and fragmentation.
Overlapping extents, unknown allocation coverage, a blackholed typed head
without an owned work lease, or more than 32MiB failure to reconcile accounted
physical memory with RSS invalidates the result. A mutation is attempted only
after the simulation predicts at least 180MiB net physical reduction.

The smallest causal mutation is nonmoving Beltway-style allocation belts:
1MiB page-aligned belts with 64KiB sub-block accounting, per-belt registry
slabs/exact-start maps, no address reuse, weak pruning of all cons tables, Rust
payload destruction, and `madvise(DONTNEED)` only after a belt is empty.
Current reservation pop merely rewinds cursors and cannot reduce RSS. The
experiment triggers at the earliest complete-root pre-peak ordinal with the
180MiB opportunity, then continues evaluation. Retention requires byte/error
parity, at least 150MiB external peak reduction, immediate RSS loss within
20MiB of prediction, less than 10% collector instructions, and no stale
resolution under collect-at-every-eligible-belt stress. Below 120MiB actual, or
below 150MiB in two of three runs, rejects belts as the next collector.

Even a successful belt result is non-terminal. Perfect final decommit leaves
about 255-261MiB in both default and typed-head layouts. At least another
84-89MiB must come from registry/hash/frame/external-spine compaction or
survivor evacuation. The planned terminal collector remains a reducer-rooted
8-16MiB copying nursery feeding an Immix-style old generation; Mesh remains
only a compatibility projection until page contents are safe to remap.

## Forty-seventh per-element force/update replay result

The corrected per-element experiment moved admission inside the exact equality
island rather than preflighting the whole list. For each demanded element it
planned cached forwarding and a bounded reusable Node subset before mutation,
held terminals in transient roots, claimed suspended work with evaluator force
leases, published updates inner-to-outer, and compared scalar payloads without
recursive evaluator, apply, demand, or structural-equality callbacks.

Adversarial review found and fixed typed-head admission, marked lazy-identity
stop/consume semantics, cross-module Node source timing, stats-mode decline,
and abort-stack invariants before measurement. Twenty-nine focused list tests
passed. The primary coverage run then reported:

```text
cached replay elements: 914,738
owned Node updates:            0
immediate elements:            0
fallback elements:        76,522
```

Despite broad cached coverage, the causal result is negative:

```text
corrected island, machine disabled:
  18.144154309B, 18.146438432B instructions

corrected island, machine enabled:
  18.518390726B, 18.519534577B instructions
```

The machine adds approximately 373.7M instructions. Its duplicate cell
inspection, chain planning, alias/identity/module safety checks, inline control
construction, and replay cost more than the established optimized force
helpers. It owns no primary suspended Node updates. The source addition also
moved the island-disabled control from about 19.593B to 19.633B instructions
and the corrected island from about 18.075B to 18.145B through disabled
branch/code-layout effects, failing the 0.05% retention ceiling.

The machine and entry/report hooks were removed. This falsifies a second
important middle layer: an explicit control stack is not automatically faster
when it re-decodes the same high-level heap representation and reproduces
TreeWalk's safety checks one operand at a time. The persistent reducer must
amortize preflight in cached immutable code blocks and change the calling/value
representation enough to remove work, not merely restate generic forcing as a
local state machine.

## Forty-eighth terminal peak bands and selected-child grammar

The compile-time-only peak probe now retains its sampled records and reports
the earliest sample within 16MiB, 32MiB, and 64MiB of the sampled maximum.
With a 4,096-allocation stride, the exact primary run reconciled every fresh
publication:

```text
serial publications: 3,779,140
values allocated:    3,779,140
samples:                    922

sampled maximum:
  ordinal:             3,776,512
  RSS:               615,108,608 bytes
  worker used:       303,797,480 bytes
  permanent used:     70,072,128 bytes
  modules loaded:          1,221

earliest within 16MiB:
  ordinal:             3,661,824
  RSS:               598,622,208 bytes
  modules loaded:          1,196

earliest within 32MiB:
  ordinal:             3,526,656
  RSS:               581,951,488 bytes
  modules loaded:          1,196

earliest within 64MiB:
  ordinal:             3,039,232
  RSS:               548,134,912 bytes
  modules loaded:          1,188
```

The peak is therefore not a narrow import or temporary terminal burst. RSS
grows through roughly the final 740,000 fresh publications and remains within
64MiB of the maximum for about 20% of the allocation stream. Pass B must trace
lifetimes across this interval and model repeated minor collections; a
single-point decommit at the maximum cannot establish the required causal
collector.

The enabled-only selected-child census also closed the grammar uncertainty
that stopped the earlier genList superblock. It observed 1,128,838 exact
children. Of those, 1,049,970 are marker thunks whose imported unary lambda has
the same supported five-node, depth-two `PrimOp` body, using only a literal,
lexical access, strict primop, and integer addition. The dominant capture
depth is nine lexical frames:

```text
five-node PrimOp body, 9 lexical frames: 1,034,868
five-node PrimOp body, 3 lexical frames:    11,536
five-node PrimOp body, 6 lexical frames:       594
five-node PrimOp body, 11 lexical frames:    2,972
already-WHNF strings:                       74,201
forced LocalVar node thunks:                 4,419
other supported Apply bodies:                  248
```

This is sufficient coverage for the first executable STG entry, but not for a
new shape-specialized helper. The retained unit must be a cached,
module-qualified code block executed by a persistent PC/value/argument/update
machine. The five-node body is its first profile-proven block; lexical access,
strict primop application, error coordinates, module restoration, detached
thunk ownership, and return/update are reusable instructions. Admission must
preflight the whole block before claiming a thunk, and unsupported work must
cross one explicit oracle continuation rather than recursively mixing the two
evaluators.

The existing marker-only session provides a control measurement. It tail-enters
marker chains and owns detached update publication, but still delegates the
selected body to generic forcing:

```text
default:
  instructions: 19,593,282,232
  max RSS:          615,056 KiB

marker session:
  instructions: 19,273,498,706
  max RSS:          603,920 KiB
```

The roughly 320M-instruction, 1.63% reduction proves that persistent update
ownership is useful but far from the speed gate. The next implementation must
execute the selected lambda body in the same session and then broaden to the
dominant ordinary `Apply`, `PrimOp`, `Select`, `LocalVar`, and `Let` grammar.
Retaining only the marker optimization would leave more than six times the
allowed instruction budget.

## Forty-ninth independent architecture fork and physical-residency seam

An independent design pass ranked alternatives that do not assume a persistent
STG interpreter is the terminal execution architecture. For the strict cold
acceptance run, the strongest alternative is whole-module promise SSA/PIR with
native AOT code. Promises, environments, force/update state, blackholes,
effects, and oracle/deoptimization continuations become explicit compiler IR.
Partial escape analysis can then scalar-replace nonescaping thunks and frames,
fuse force/apply/select sequences, and emit exact stack maps. This differs from
the earlier per-definition JIT: it removes the evaluator object protocol across
module and demand boundaries instead of compiling operations that still pay
that protocol.

The first falsification gate is deliberately short. A nonexecuting demand trace
must classify promise and environment escape, represent at least 90-95% of
dynamic demand operations, project at least 70% scalar replacement, and keep
semantic side exits below 5%. The dominant force/apply block must then show a
5-7x local native speedup. Failure rejects promise SSA as the immediate route;
success promotes it ahead of extending an interpreter through low-coverage
grammar. The relevant precedents are PIR's explicit lazy arguments and
environments ("R Melts Brains", Flückiger et al.) and partial escape analysis
(Stadler et al., CGO 2014).

The strongest conditional alternative is a root-pruned frozen evaluator image:
packed module IR, symbols, ready imports, and live heap pages mapped directly
`MAP_PRIVATE`, with a mutable overlay for newly forced thunks. It could avoid
snapshot reparsing, whole-image read/copy, historical garbage, and registry
reconstruction. A full result-keyed image is not credited to the cold
empty-cache gate because it is a precomputed answer. A prelude-only image
remains eligible only if its resumed execution independently falls below the
instruction ceiling. The one-day lower-bound probe is existing snapshot
adoption plus an offline root-pruned image size and resident working-set
projection.

Perceus-style ownership/RC, meta-tracing with partial escape analysis, and
import regions were ranked below those paths. `Value: Copy` prevents sound
incremental RC without a compiled ownership IR, recursive attrsets require
cycle handling, recursive TreeWalk traces fragment, and perfect region
decommit still leaves the measured 255-261MiB terminal floor. They remain
representation components, not complete current answers.

The physical-memory diagnostic now has the missing first primitive.
`ReservedArena::residency` queries only pages intersecting the used low and
high lanes, accounts for a shared boundary page exactly, and reports resident
page counts without touching the unused 4GiB gap. Both owned evaluator entry
paths sample process RSS first and emit this reservation sample after the root
and parallel pool return but before the optional quiescent sweep. The weak-root
liveness census was moved to that same root-complete terminal point. This
terminal sample is approximately 2,628 publications (0.07%) after the measured
peak ordinal; it validates residency/inventory accounting but does not replace
the four clean-run lifetime snapshots required for nursery/Beltway/Immix
simulation.

## Fiftieth physical residency, tombstone sweep, and bounded STG result

The root-complete terminal probe closed the virtual-versus-physical ambiguity.
Before allocating the weak-census work set it measured 616,775,680 bytes of
process RSS. Every page intersecting either used arena lane was resident:

```text
used/resident pages: 91,336 / 91,336
resident arena bytes:      374,112,256
permanent low lane:         70,088,624 used bytes
worker high lane:          304,020,352 used bytes
```

At the same terminal point the precise weak-root traversal reported 524 live
pages and 90,812 dead pages, or 371,965,952 dead resident bytes. The root
completeness predicate was true and includes detached force, typed-thunk,
lambda-call, import, and packed-machine ownership. Historical arena garbage is
therefore a real RSS owner rather than reserved-address accounting.

This result does not promote the existing nonmoving sweep. With
`AOS_NIX_GC=sweep` and a zero threshold, the exact primary derivation remained
unchanged, but the terminal sweep increased current RSS from 625,786,880 to
738,480,128 bytes. The complete run retired 26.428B instructions and peaked at
726,788KiB, compared with the approximately 19.59B/607MiB default class. The
sweep installs in-place tombstones and retains arena pages and registries; its
large mark set raises the high-water mark. It is a root-sound validation
collector, not the memory architecture for the acceptance target.

The terminal storage census explains the external component:

```text
flat closure objects/capacity: 3,269,477 / 4,194,304
lists/capacity:                  306,036 /   524,288
attrs/capacity:                  186,289 /   262,144
list elements/capacity:        2,550,674 / 2,553,097
module IR:                    14,147,432 bytes
module source/path state:      3,666,291 bytes
```

Even perfect page discard without rebuilding closure registries, hash-cons
indexes, list spines, and module-side state leaves more than the approximately
172MiB target. A viable collector must evacuate the rooted graph, rebuild weak
indexes and address registries from survivors, and drop the old cage. It also
needs explicit reducer/compiled roots before the peak; a terminal-only
compaction cannot lower `ru_maxrss`.

The bounded packed-STG ordinary-Apply executor is correct but fails its breadth
gate. It caches module-qualified blocks, owns value/argument/update/call/control
stacks, scans and writes those roots back, restores force/lambda/module state
on error and panic, and implements literals, lexical reads, numeric
arithmetic, exact `elemAt`, and staged overloaded Add. Imported builtin symbols
must resolve through the evaluator-global table after module symbol remapping.
Seven focused Candidate-C tests cover success, dominant captured
`elemAt xs (i + 1)`, exact Add oracle exit, error, and panic.

On the daemon-primed exact primary source, however, it reported:

```text
ordinary Apply attempts: 205,002
declines:                205,001
blocks lowered:                13
claims/completions:           1 / 1
force continuations:              2
oracle leaves:                    0
```

The STG-session run produced the exact
`/nix/store/qs2q775b7czyp98r1yjixq0kqi8drz40-aos-system-toplevel.drv` and
retired 19.535B instructions at 621,292KiB. Its same-source default produced
the same derivation at 19.707B and 610,092KiB. The instruction difference is
attributable to the pre-existing marker session and run/layout variance: one
new generic claim cannot account for it. The new executor is retained
default-off as a semantics/rooting substrate, but is rejected as a performance
branch. Extending a recursive per-body lowerer through hundreds of cold
declines is not the factor-level route.

Pinned C++ Nix on that exact source and already-primed store produced the same
derivation at 6,221,006,209 instructions and 342,844KiB peak RSS. The strict
same-source ceilings are therefore fewer than 3,110,503,105 instructions and
fewer than 171,422KiB. The default native evaluator is currently about 3.17x
the C++ instruction count and 1.78x its peak RSS; reaching the requested target
requires approximately a 6.34x native instruction reduction and a 3.56x native
RSS reduction, not a marginal dispatch improvement.

The approximately 262M-instruction outside-demand floor makes the execution
coverage constraint more severe. The native demand epoch is approximately
19.445B instructions and may spend at most 2.8485B. It therefore needs about a
6.83x epoch reduction. For a covered fraction `f` with local speedup `s`,
acceptance requires:

```text
0.262B + 19.445B * ((1 - f) + f / s) < 3.1105B
```

Infinite local speed still requires more than 85.35% coverage. A 7x executor
requires more than 99.6%, 10x requires more than 94.83%, and 20x requires more
than 89.84%. A conventional 2-4x bytecode interpreter cannot pass at any
coverage. The target is about 979 instructions per native function call,
roughly half C++ Nix's 1,967; reaching C++ parity is itself insufficient.

The residual gap is uniform evaluator protocol. Parsing, resolve, lower,
annotation, and module setup account for at most 2.38%; direct hash-cons work
is 0.55%, symbols about 1.30%, IR lookup 1.92%, and derivation ATerm work about
0.85%. Granting zero cost to all of them saves only about 7%. Removing 524,896
lexical alias thunks plus 476,066 associated forces saved about 1.039B
instructions; extrapolating that deliberately generous rate across every
remaining thunk would still leave about 14.38B. The exact genList fusion saved
about 1.756B and the all/any island about 1.519B, but independent islands still
leave more than five times the target. Whole-demand native regions must remove
the force/apply/frame/allocation protocol together and specialize higher-order
builtin loops without per-element oracle callbacks.

Compaction alone is also falsified for the current representation. The
1,220-module weak census retains 158.250MiB of inline heap plus list spines.
The independently measured retained frontend is 20.807MiB and packed captured
environments add 6.198MiB:

```text
reachable heap and spines: 158.250 MiB
frontend/module state:      20.807 MiB
packed captured frames:      6.198 MiB
                            -----------
packed-live lower bound:    185.256 MiB
target:                     167.404 MiB
```

This assigns zero bytes to indexes, registries, allocator metadata, evaluator
stacks/caches, code/libraries, typed work, and result state, yet exceeds the
target by 17.85MiB. The operational cross-check is larger:
451.2MiB milestone RSS minus 215.05MiB logically dead leaves 236.15MiB.
List capacity trimming is irrelevant: only 2,423 excess slots, about 19KiB,
exist at the terminal census. Collection must be coupled to promise/frame
scalar replacement, packed/releasable module code, smaller stable
thunk/work representations, synthetic-list fusion, and rebuilt weak indexes.

A representation/root-policy audit makes the stricter budget explicit. The
1,220-module 451.2MiB sample contains approximately 238.9MiB of used worker
and permanent arenas, 76.5MiB of flat registries, 34MiB of hash-cons
structures, 20.807MiB of frontend state, and 6.198MiB of frames. The residual
process floor is therefore approximately 74.795MiB. After reserving that floor,
the 167.404MiB strict target leaves only 92.609MiB for the complete compact
heap, frames, frontend, and indexes. A credible 4MiB frontend, 3MiB frames,
and 8MiB indexes leave about 77.6MiB for resident heap, so the current
158.250MiB reachable heap must shrink or become nonresident by at least
80.6MiB (50.9%). Eliminating 80% of allocation *events* is not a memory proof;
the PIR gate must be retained-byte weighted.

This also defines a materially different memory avenue if virtual-object
elimination cannot remove half the rooted heap: freeze quiescent immutable
Ready-import subgraphs directly into position-independent, headerless,
file-backed segments with 32-bit segment-local values, while keeping mutable
promise heads/work in a small typed overlay. Ready roots retain stable
`(segment, slot)` identities, but cold segment pages may be unmapped or advised
away without semantic eviction or re-evaluation. Construction must evacuate
directly into the packed segment and release the old cohort; holding old and
packed copies together cannot reduce peak RSS. The read-only projection gate is
at most 85MiB of projected named state, or at least 64MiB of Ready-root-exclusive
cold mass with no more than a 48MiB next-window working set. Headerless/compact
edges alone are killed above the absolute 92.609MiB named-state ceiling.

These two results converge on one architecture requirement. The execution
layer must represent the whole demand epoch with explicit promises,
environments, force/update effects, and oracle statepoints, so it can both
scalar-replace synthetic heap objects and publish complete roots at repeated
peak-band collections. Promise SSA/PIR plus native AOT is now the primary
strict-cold hypothesis. A root-pruned mapped image remains conditional on an
admissible non-precomputed benchmark contract.

## Fifty-first promise-SSA coverage and imported-fact discrepancy

A default-off full-primary census measured the two prerequisites that the
bounded STG experiment could not establish: dynamic operation coverage and
physical lexical-frame handle lifetime. The diagnostic classified resolved
direct builtin calls by their declaration's effect metadata rather than
treating every statically known pure helper as an oracle exit. On the exact
daemon-primed source it produced:

```text
dynamic IR entries:             17,634,894
native control + pure helpers:  17,632,317  (99.9854%)
effectful oracle statepoints:         1,595  ( 0.0090%)
unclassified primop entries:            982
unsupported entries:                       0

thunk allocations:               2,693,375
synthetic Apply allocations:     1,344,477  (49.9179%)
linked frame handles:            3,452,049
handles dead at lexical pop:     3,113,478  (90.1922%)
handles retained after pop:        338,571
```

The frame split was 2,866,270/295,439 nonescaping/escaped lambda
frames, 247,203/42,795 `let` frames, and 5/337 recursive-attrset
frames. The exact derivation was
`/nix/store/zdi1q1vrijnjnp1z7a66wc6b85xb2m23-aos-system-toplevel.drv`.
The timer/atomic-heavy census retired 33.029B instructions at 624,988KiB;
those figures are diagnostic overhead, not a candidate performance result.

Pure builtin helpers are sufficiently concentrated for whole-demand codegen:
`elemAt` alone accounts for 1,223,076 entries, followed by `isAttrs`
(237,032), `hasAttr` (180,223), `length` (148,722), `genList` (89,667),
`any` (83,434), `map` (56,036), `head` (52,028), and `toString`
(38,226). A PIR/native runtime can keep these as direct helper or loop nodes
without crossing back into recursive TreeWalk. Operation coverage therefore
passes the 95%/5% gate decisively.

Allocation elimination is the tighter gate. Even granting scalar replacement
to every synthetic Apply promise and every frame handle dead at lexical pop
eliminates only:

```text
(1,344,477 + 3,113,478) / (2,693,375 + 3,452,049)
  = 4,457,955 / 6,145,424
  = 72.5410%
```

That misses the deliberately optimistic 75% pilot gate, and frame-handle death
is itself only a physical prerequisite, not a semantic scalar-replacement
proof. Promise SSA must additionally virtualize ordinary node promises or
eliminate their producer/consumer regions. The existing force census shows
2,466,468 of 2,693,375 thunk work items release, but release alone does not
prove that lazy identity, update, blackhole, or repeated-force behavior may be
removed.

The census exposed a more immediate analysis discrepancy.
`annotate_import_ir` supplied fresh imported modules with import strictness,
lambda-summary escape, and capture plans, but deliberately left every per-node
cardinality and escape fact conservative. Imported/prelude work accounts for
approximately 99% of forces, while `tree_walk_thunk_allocation_plan` consumes
those facts on the module's first evaluation. The durable-cache rationale is
therefore insufficient: a fresh import cannot use single-entry storage or
per-node no-escape facts before a later cache refresh. The A/B experiment ran
the sound cardinality and escape passes for fresh imports. It preserved the
exact pinned-C++ derivation and exposed 76,449 single-entry thunks, of which
76,432 were forced, but the default run regressed from the preceding
19.707B/610,092KiB class to 19.816B instructions/622,456KiB. The fact passes
therefore are useful input to a virtual-object compiler but are not
independently a runtime optimization. Fresh-import defaults returned to the
narrower contract; a future whole-demand PIR entry must request the complete
facts as part of its own admission path.

The Candidate-C single-entry representation still removed one avoidable
allocation from that future path: the common environment-free record now uses
a third invalid compact-value word as its stable non-publishing marker instead
of allocating a boxed mode-only sidecar. Focused repeated-force, parallel
admission, and shared-cell tests pass. This changes no primary allocation while
fresh imports retain conservative per-node facts.

A separate packed-STG breadth probe reinforced the complete-region rule.
Enabling the existing session executor produced 205,002 ordinary-Apply
attempts, but its original executable subset completed only one. Adding exact
selection semantics raised that to 416 completions with exact derivation
parity, yet three runs averaged 19.6718B instructions versus the original
session executor's 19.6704B sample. The isolated opcode did not help and was
removed. The approximately 0.93% session-vs-default instruction reduction
comes from the pre-existing fused `genList` session, not generic packed-STG
coverage. `Thunk`, `Apply1`, and nested lambda support must be designed as a
single allocation-virtualizing region rather than accumulated as isolated
interpreter opcodes.

The follow-up unique-block decline census removed the cache-hit distortion from
those 205,002 attempts. There were 203,902 cache hits, leaving 1,100 dynamic
cache misses. The lowerer admitted 13 complete blocks and rejected 840 unique
blocks after preflight; the remaining 247 attempts declined before lowering.
Of the 840 lowerer rejections, 835 were unsupported IR kinds, three were
non-numeric binary operators, one was a selection default, and one was a
dynamic selection path. There were no missing, invalid, or ambiguous frame
facts. The first unsupported-node distribution was:

```text
AttrSet 770   Interp 42   If 11   Let 6   Str 5
BinOp     3   Select  2   List 1
```

Thus `AttrSet` alone accounts for 92.2% of unsupported-kind block rejection.
This falsifies lexical-frame repair and another isolated control opcode as the
next breadth step. The first coherent promise-SSA/PIR slice must own static
attribute construction, its lazy binding promises and shape, plus the
`Interp`/`If`/`Let` control that encloses it. Dynamic keys, recursive
`__overrides`, effects, and imports remain explicit materialization/statepoint
boundaries. The current packed lowerer's explicit `OracleLeaf` facility is
useful for shadow validation of those boundaries, but executing attrset bodies
through oracle leaves cannot itself remove allocation or recursive evaluator
traffic and is not a performance candidate.

Two default-off controls with the census hooks still compiled in retired
19.9426B and 19.9440B instructions. That is approximately 236M above the
preceding 19.707B clean class. Because source/layout changed, it is not a
strict isolated attribution, but a cached `OnceLock` predicate on every
dynamic node is an unjustified production risk. The census hooks and module
were removed after recording these results.

The researched terminal architecture remains a typed promise/environment CFG,
whole-module heap/call-target analysis, partial escape analysis with transitive
materialization, and native AOT. A generic `LazyApplyVector` must preserve
per-index memoization while eliminating the 1,133,765 `genList`, 210,712
`map`, and 793 `mapAttrs` Apply cells. A substantially different fallback
hypothesis is effect-delimited copy-and-patch specialization of TreeWalk
transitions; its promote gate is the same: no recursive evaluator callbacks
inside a region, at least 95% instruction-weighted coverage, and at least 11x
inclusive local speed.

The first shadow planner is consequently allocation-weighted rather than
opcode-weighted. Its nontrivial control grammar is `ThunkAlloc`, `Let`,
single-formal `Lambda`, `Apply`, and pure `PrimOp`; literals, lexical reads,
static nonrecursive `AttrSet`, `List`, and static `Select` are mandatory value
forms in the same region. It must represent promises, frames, closures, lists,
and attrsets as virtual identities and materialize their transitive reachable
graph only at publication/statepoint boundaries. Effectful operations,
`tryEval`, dynamic scope/global lookup, unknown first-class calls, dynamic
attribute keys, recursive attrsets/`__overrides`, and the first unsupported
formal-set surface are conservative statepoints. Complete per-node facts are
admission input, but the region planner must re-prove transitive escape and
frame context rather than trusting a local `NoEscape` bit.

The avenue has explicit early falsifiers. Offline and then dynamic shadow
measurement must project at least 80% elimination of allocation bytes/events,
keep instruction-weighted oracle exits below 5%, and avoid unbounded cloning by
frame signature. This is stricter than the failed 72.541% optimistic
synthetic-Apply-plus-dead-frame bound. Shadow interpretation must then match the
oracle's force/update events, statepoint order, diagnostics, and materialized
graph fingerprints before any result is consumed. A compiled pilot must cover a
whole known-call region with no recursive TreeWalk callback and reach at least
11x inclusive local speed; otherwise the strict global instruction inequality
still cannot pass.

## Fifty-second runtime-weighted promise-region entry census

The first terminal planner run validated all 1,221 imported modules after
honoring the evaluator-global symbol remap, but proved that module roots are
the wrong admission population. Of 1,221 root plans, 1,213 were entry-only
statepoints and 1,211 stopped on a formal-set lambda. The root report exposed
the symbol-ownership contract but measured package wrapper allocation rather
than executed demand.

The replacement default-off census records bodies only after a lambda has
successfully bound its argument or a claimed node thunk has installed its
captured environment. Lambda keys are the exact
`(module, body, Some(resolver frame))`; existing thunk records do not retain a
resolver `FrameId`, so their `(module, body, None)` population is diagnostic
and remains ineligible for compiled admission until a fail-closed static
ambient-frame map is available. On the exact daemon-primed primary evaluation:

```text
distinct runtime entries:       17,748
dynamic entry events:        3,156,622
  lambda:                    2,032,873
  claimed node thunk:        1,123,749
planner failures:                    0
entry-only events:             190,619  (6.04%)
statepoint-free events:       2,619,713 (83.00%)
events exposing virtual sites:1,094,878 (34.69%)
```

The exact derivation matched pinned C++ Nix at
`/nix/store/mab8r0c0q4arjbxg1npz0pmilvc0ggsy-aos-system-toplevel.drv`.
The hash-map and terminal-planning diagnostic retired 21.514B instructions at
622,540KiB; those figures are probe overhead, not a candidate result.

Static sites multiplied by entry frequency project 3,021,484 virtual
allocations: 1,281,137 promises, 328,345 frames, 742,020 closures, 476,230
lists, and 193,752 attrsets. This is an optimistic structural projection, not
the 80% allocation or retained-byte proof: branches, lazy bindings, nested
entries, and statepoints are path-dependent. The corresponding projected
statepoint sites are dominated by 780,250 unknown-call and 184,266
dynamic-select sites. Dynamic allocation/materialization counters inside
exclusive active regions remain required.

The follow-up dynamic target census makes the unknown-call population much
less ambiguous. Across 759,497 executions at 2,192 syntactically unknown
application sites, 2,151 sites / 712,732 events were monomorphic, 17 sites /
32,325 events had two through four targets, and only 24 sites / 14,440 events
were megamorphic. Thus 93.84% of unknown-call executions were monomorphic and
98.10% had no more than four targets. Profile-only direct linking remains
inadmissible, but the distribution strongly promotes proof-producing closure
flow inference and bounded target cloning.

A sparse, symbol-agnostic lexical frame chase then tested how much of that
population ordinary alias resolution can prove. It resolved 154 sites /
21,571 events (2.84%) and every prediction matched the actual forced closure;
there were zero mismatches and zero analysis errors. This validates the chase
as a sound seed but kills it as the primary dispatch lever. The unresolved
events are overwhelmingly function-valued upvalues (427,023 events, only
21,122 resolved) and nested applications returning functions (306,623 events,
none resolved); local variables, selects, and primops contribute only 25,851
events. The next analysis must therefore propagate finite closure target sets
through lambda arguments and application results rather than extending the
alias chase ad hoc.

That larger module-local 0CFA was implemented with dense expression/static
frame-slot variables, bounded eight-target lambda sets, a monotone worklist,
simple-formal argument edges, and lambda-body-to-application-result edges.
Focused tests cover higher-order arguments, function-returning applications,
and finite conditional target sets. Across the primary call population it
created only 18,615 inclusion edges, activated 648 call edges, and required
2,090 worklist pops, so solver size was not the problem. Precision was: it
produced candidates for 226 sites / 38,380 events, with actual guard hits on
36,315 events (4.78%); singleton candidates covered 36,065 events. The 0CFA is
retained as a bounded guarded-candidate primitive but killed as the principal
unknown-call lever.

The promoted alternative is guarded runtime-environment specialization.
Existing tier-2 curried-chain promotion already resolves upvalue callees from
the concrete closure environment, pins their definition-site identity, and
revalidates those guards at dispatch. General Promise/PIR regions should reuse
that contract: evaluate and force the function in original order, guard the
actual closure definition site, pass its real captured environment and lazy
argument into direct code, and fall back generically on a miss. Only a later
context-bearing virtual-heap proof may remove closure/frame allocation.

A caller-entry call graph confirms that boundary amortization is available.
All 759,497 unknown-call events form only 2,623 dynamic edges from 1,556
executing lambda/thunk entries. The hottest 20 caller entries account for
661,239 events (87.06%), and the hottest four account for 512,906 (67.53%).
Those four are all in `lib/modules.nix` and have only two through five concrete
targets. The next executable pilot should therefore compile guarded multi-body
regions rooted at those entries, not install one native trampoline per lambda.

These last two reports came from a diagnostic evaluation that reached the
terminal census but then computed a native `format-ignition` derivation hash
different from the freshly primed C++ graph and could not materialize the
missing `.drv` into the read-only store. Its 22.026B instruction and 622,776KiB
figures are invalid for parity or candidate scoring. The call population is
retained only as architecture evidence; the derivation discrepancy must be
reconciled before the next strict benchmark result is accepted.

One exact-frame lambda entry alone accounts for 984,576 events (31.19% of all
runtime entries) and has a three-node, statepoint-free, allocation-free plan.
It is the first transition-cloned speed candidate once its source grammar is
identified. It cannot move RSS by itself. The next highest entries include
regions with virtual promise/frame/closure sites, so the executable pilot must
join the hot direct CFG to partial escape analysis rather than treating the
single hot body as completion.

The census also corrected two planner overclaims. Evaluating `Lambda` and
`ThunkAlloc` allocates deferred work but does not execute the body; structural
planning now stops there. A statically known simple application reconnects
the lambda body explicitly and counts its call frame at the application,
where the frame is actually created. Formal-set binding remains a statepoint
and cannot be bypassed by syntactic descent. Nine focused tests cover these
contracts.

This matches the GRIN/flow-inference, partial-escape, and weval literature:
make promise storage/fetch/update and calls explicit; retain objects in a
virtual SSA heap; materialize only on escaping edges; then specialize
TreeWalk's transitions into direct control flow. The alternative
transition-cloned-region pilot is not another opcode interpreter: admitted
code contains no generic `eval_node`, force, apply, or primop dispatch. It
shares the same virtual-object and statepoint contract, because transition
specialization without allocation removal cannot meet the memory target.

The separate frozen-Ready hypothesis now has a one-run falsifier. At the
1,188-module start of the final peak band, partition the precise roots into
`ImportCache` and all other sources, retain the Ready-exclusive difference,
and use existing non-scanning last-touch epochs through demand completion.
Project current, headerless-64, compact-32, touched packed pages, and the
mandatory mutable promise overlay. In-memory headerless/compact-only work is
killed above the absolute 92.609MiB named-state ceiling and promoted only at
or below 85MiB with credible frontend/frame/index budgets. File-backed frozen
segments remain necessary only if at least 64MiB is Ready-exclusive and
untouched while packed touched pages plus overlay are no more than 48MiB.
Root-union mismatch, unrooted blackholed work, unstamped access paths, or more
than 8MiB unattributed candidate mass invalidates the run.

## Fifty-third Ready-exclusive window and exact hot call edges

The Ready-exclusive falsifier is now feature-gated through the complete
evaluator. At exactly 1,188 loaded modules it builds one precise root set,
partitions `ImportCache` roots from every other mutator root, reconciles their
union with an unfiltered traversal, and retains only stable addresses plus
their current touch epochs. At demand completion it reads those epochs without
stamping them. Three focused heap tests prove exclusive/shared partitioning,
exact union reconciliation and byte attribution, and that capture itself does
not refresh an object's epoch.

The primary diagnostic measured:

```text
Ready roots:                    458
other roots:                  1,884
all reachable objects:   1,226,800
Ready-reachable objects:       928
shared Ready/other objects:    474
Ready-exclusive candidates:    454
Ready-exclusive bytes:      40,296
final-window touched bytes:       0
final-window cold bytes:      40,296
unattributed bytes:                0
root union reconciled:          true
```

The frozen-Ready alternative therefore fails by roughly three orders of
magnitude before any representation projection: it requires at least 64MiB of
exclusive cold mass, while the exact candidate population is about 39.4KiB.
Almost every object behind a Ready import root is also reachable from active
non-import roots. Independently freezing, dropping, or remapping the import
cache cannot materially lower peak RSS on this benchmark.

The same run later failed while trying to create a newly hashed derivation in
the read-only store, so its 25.587B instructions and 665,104KiB RSS are probe
overhead and not candidate measurements. The ownership result is captured
before that store operation and remains valid; the terminal access window ends
at demand completion.

After rebuilding the ordinary Candidate-C binary and freshly priming C++ Nix,
the strict same-source control again produced identical top-level derivations:

```text
C++:    6,221,603,802 instructions   343,220KiB RSS
native:19,844,167,546 instructions   615,220KiB RSS
path: /nix/store/xrdplsp65z5ryc80w091m08vrfsyqajj-aos-system-toplevel.drv
```

These figures confirm current primary-path parity but miss the strict
3,110,503,105-instruction and 171,422KiB ceilings by wide margins.

The runtime call graph now reports exact edges and caller source spans. The
second-hottest caller is the `dedup` lambda in `lib/modules.nix`, spanning
bytes 11,585 through 11,915. Its 162,486 unknown calls split evenly:

```text
dedup -> equality predicate body 685: 81,243
dedup -> recursive dedup body 684:     81,243
```

This is a clean two-target guarded-region pilot, but the equality half already
has an exact fused-island experiment that saved 1.519B instructions without
moving RSS. A new pilot is useful only if it treats the complete recursive
region as a virtual promise/environment graph, removes its list/thunk/frame
protocol, and side-exits generically on a failed closure-definition guard.
Another callback-bearing equality or `genList` island is already globally
falsified.

The Nix-specific maximal-laziness literature also motivated a duplicate-work
audit. The existing MEMO-1 economics census already keys safe node forces by
expression identity and captured value hashes; prior floor-one measurements
found repeats but made execution 25-31% slower and saved no arena storage. It
does not answer the stronger lower bound because it omits single-entry thunks,
open/cyclic identities, and many closures. A distinct future census must use
the exact module/node plus raw identities of only statically referenced
captured slots at the central node-body seam. It is promoted only if repeated
successful body work is at least 25% or conservatively avoidable records reach
64MiB; otherwise maximal sharing is rejected as a principal architecture.

## Fifty-fourth projected maximal-laziness census and super-region bound

The projected duplicate-work census is now implemented behind the
`maximal_laziness_probe` feature. It admits only serial, nonmoving Tier-A
evaluation with memoization, the force cache, parallel evaluation, and the JIT
disabled. Its key is the exact module-qualified node body plus the raw
representation identities of only the lexical slots that the body reads.
Dynamic environments, scoped globals, effects, unknown applications, nested
lazy work, and unsupported shapes fail closed. The retained raw words do not
root heap values and are sound only because the admitted heap never moves or
reuses addresses.

Allocation is observed after the captured environment exists, and every Node
body execution is timed at the central `eval_thunk_body` seam. Errors never
seed a reusable successful result. The report distinguishes admitted time from
all successful Node-body time, so a high repeat rate in a tiny admitted subset
cannot overstate global leverage. Three focused tests cover error exclusion,
duplicate-record accounting, and bounded-map behavior. The dormant
full-laziness precursor was also corrected to reject `GlobalVar` and `Apply`;
all 15 focused full-laziness tests pass.

The initial 65,536-key run overflowed and was retained only as a warning. A
second run used the capped diagnostic override at 524,288 keys and reached a
complete 212,174-key population with zero overflow:

```text
all Node allocations:                    1,345,508
all Node record bytes:                  86,112,512
all successful Node bodies:              1,123,753
all successful Node-body nanoseconds:  224,514,178,898

admitted allocations:                      245,387
admitted successful forces:                300,311
repeated successful forces:                118,464
repeated successful nanoseconds:        17,317,725
repeat share of all Node-body time:             77 ppm
avoidable Node-record lower bound:         4,744,128 bytes
```

Thus the newly covered open-environment identity population contains many
numerically repeated cheap bodies but only 0.0077% of inclusive Node-body
work. Duplicate generic records contribute a 4.52MiB lower bound, versus the
64MiB promotion gate; even every generic Node record in the evaluator totals
only 82.1MiB before captures. This exact population is not an execution lever.
Combined with MEMO-1's broader content-key result (no arena savings and a
25-31% instruction regression at floor one), maximal sharing is rejected as
the principal architecture. It may remain a local simplification inside a
larger virtual-heap region, but it cannot replace that region.

The diagnostic reached demand completion and emitted its report before the
new source hash required writing a derivation into the read-only store. It
then failed at that store operation. Its 22.394B instructions and 638,548KiB
RSS are probe overhead, not candidate measurements, and do not alter the last
strict same-source control.

Independent GRIN and demand/cardinality audits converge on a stronger bound.
With the measured 0.262B outside-demand floor, a region running 10x faster
must own more than 94.8% of current demand instructions to pass the
3,110,503,105-instruction ceiling; even a 20x region needs about 89.8%.
Therefore the hottest 20 callers' 87.06% share of unknown calls is not enough.
The next architecture must enter once around the requested-attribute demand
epoch and preserve virtual promises, closures, frames, lists, attrsets,
blackholes, and updates across module and call boundaries. Bounded concrete
closure-definition guards may clone the observed one-to-four-target calls;
misses materialize transitive virtual state and resume the ordinary evaluator
without repeating effects.

Before implementing a production executor, an allocation- and
instruction-weighted shadow linker must prove at least 95% demand-instruction
coverage, at least 98% guarded-call hits, less than 5% oracle/statepoint work,
at least 80% virtualized allocation bytes, and at least 80.6MiB of eliminated
or nonresident live heap. The complete `body684`/`body685` recursive `dedup`
region remains a semantic canary, but it is promoted only if its common path
has no TreeWalk callbacks, exceeds 11x inclusive local speed, and eliminates
more than 80% of its allocation bytes.

## Fifty-fifth source-attributed demand-region shadow census

The cross-module shadow artifact is now concrete in `ratchet-core`. Each
fragment retains a 32-byte module-content identity, source IR ids and spans,
lexical-frame specializations, an exact versioned capture layout, and a
whole-demand epoch. Its declarative operations explicitly distinguish
Promise, Closure, Frame, List, Attrs, Force, Update, GuardCall, Materialize,
and Statepoint. Guarded code references include the module digest, definition
and body ids, resolver frame, and ordered capture coordinates. Four focused
tests cover stable source identity, canonical bounded targets, invalid target
metadata, and fail-closed dynamic/effect boundaries.

The runtime shadow census separately records actual allocation wrappers keyed
by exact `(module, IR node, allocation kind)` and joins only those keys to
planner virtual sites. It does not infer site ownership from a whole
allocation class. Exact arena deltas, exact list-spine capacity, and
conservative external frame/capture lower bounds are kept distinct. The old
class-wide projection remains in the report only as an explicitly loose
ceiling. Three focused source-join/guard/bounded-map tests and the remote
feature build pass.

One complete primary diagnostic reported the same population on all three
cold/warm harness evaluations:

```text
all known allocation lower bound:         485,188,888 bytes
source-attributed arena bytes:             356,225,424 bytes
source-attributed external lower bound:     97,646,152 bytes

planned-site matched events:                 2,293,355
planned-site matched arena bytes:          185,980,528 bytes
planned-site matched total lower bound:    196,846,040 bytes

planned runtime entry events:                3,156,643
statepoint-event upper bound:                1,022,709
unknown-call statepoint upper bound:           780,257

guard sites:                                     2,192
monomorphic guard sites:                         2,151
guard events:                                  758,672
dropped guard-target events:                       825
allocation/entry map drops:                          0
```

The exact site join is a substantial positive result: current static plans
name about 196.85MB of cumulative allocation traffic, so the planner is not
confined to another single-digit-megabyte island. It is not retained-live-byte
evidence, however, and cannot by itself prove the required 80.6MiB peak-heap
reduction. Conversely, the current static region is not yet execution-ready:
its statepoint-event upper bound is 32.4% of runtime entry events, dominated
by unknown calls, far above the less-than-5% gate. Statepoints can overlap and
events are not instruction weights, so this does not reject the architecture;
it rejects treating the present per-entry static plans as sufficient. The
linker must consume observed closure-definition populations, form
cross-caller traces, and measure instruction-weighted side exits.

The diagnostic binary ran the harness's repeated cold/warm evaluations, so
its aggregate 93.901B instructions and 637,832KiB RSS are instrumentation and
harness overhead, not candidate measurements. The source-attributed report is
emitted at demand completion before derivation/store materialization and is
the result retained from the run.

An independent architecture audit also rules out allocator-only and
bytecode-only fixes. The measured packed-live floor is about 185.26MiB before
indexes and runtime state, while the credible heap budget is about 77.6MiB;
more than 80.6MiB of reachable representation must disappear. Candidate C
already makes a `Value` one 8-byte word with a 32-bit arena offset. The two
useful independent falsifiers are therefore:

1. transition-specialized native traces that cross force, apply, and return
   boundaries, first tested by the callback-free `body684`/`body685` canary;
2. an exact peak-safepoint compact-destination simulation with stable 8-byte
   thunk heads, typed work pools, packed frames/collections, and rebuilt weak
   indexes, promoted only below the 77.6MiB heap and 92.609MiB total named-state
   ceilings.

Whole-graph list/attribute deforestation remains complementary. Prior
`genList` and all/any islands saved about 3.275B instructions together but did
not approach the coupled gates because they retained evaluator callbacks and
generic object protocol.

## Fifty-sixth compact-destination projection and callback-free dedup canary

Two independent falsifiers now give the first mutually consistent
speed-and-memory evidence.

The read-only compact-destination probe traverses the precise mutator-root
graph at the 1,188-module peak-band boundary. It retains no `Value`s and
mutates nothing. Exact reachable counts and observed current bytes are
reported separately from assumed compact lower and upper layouts. The upper
model uses stable 8-byte thunk heads, typed suspended-work pools, exact-length
list spines, packed attrsets and frames, and rebuilt weak indexes. Unknown
records remain charged at current size.

The complete projection was identical across the harness evaluations:

```text
roots:                              2,342
reachable objects:             1,226,800

string/path compact upper:      4,302,352 bytes
list compact upper:             7,184,088 bytes
attrs compact upper:            7,777,152 bytes
thunk-head compact upper:       8,930,288 bytes
typed-work compact upper:       1,550,008 bytes
lambda compact upper:             492,960 bytes
primop compact upper:                 616 bytes

distinct captured frames:          87,358
captured frame slots:             173,659
packed frame bytes:             2,088,136
rebuilt weak-index bytes:        2,094,128
unattributed objects/bytes:              0 / 0

compact heap upper:            30,237,464 bytes
reported named-state upper:    44,912,048 bytes
heap gate:                     81,369,497 bytes
named-state gate:              97,107,574 bytes
```

This decisively promotes the stable-head/typed-work/packed-frame architecture:
its modeled heap has more than 48MiB of headroom beneath the strict heap
budget. The reported named-state total still uses only a 4MiB frontend
allowance and excludes source code, so it is not yet a complete RSS proof.
Charging the previously measured 20.807MiB frontend instead would add about
16.8MiB and still leave the projection below the named-state gate. A second
projection at the actual later maximum-resident safepoint is required before
mutating the heap.

The executable `dedup_string_list_canary` targets exact body 684 in
`lib/modules.nix`. Production admission is pinned to the source path, body id,
and byte span, followed by a full structural match. The matcher uses the live
evaluator symbol table because imported modules remap primop symbols and leave
their per-module table as an emptied husk. It locates `h` and `t` by value
shape rather than binding order and validates recursive branch targets
relationally, because the real recursive let has `combined` in slot zero and
`dedup` in slot one. A permanent full-`modules.nix` lowering test covers this
imported-source shape.

Runtime admission requires serial nonmoving cache/JIT/memo-off evaluation and
already-WHNF string list elements. The empty case returns the original
accumulator without forcing it. The nonempty loop compares string bytes
directly, allocates at most one final list, and has no TreeWalk callbacks.
Unsupported values and insufficient conservative call-depth headroom fall
back before output mutation. Five focused tests cover the complete primary
source, renumbered execution and order, empty-case laziness, non-string
fallback, and nearby structural rejection.

The diagnostic population per native evaluation is:

```text
body-684 applications before fusion:       89,157
structurally admitted fused entries:         7,914
callback-free executions:                    7,914
runtime value declines:                          0
```

Each fused entry consumes the complete remaining list, explaining why 7,914
entries replace 89,157 recursive body applications. Byte parity remained
true. On the same repeated cold/warm harness, enabling the canary changed:

```text
aggregate retired instructions:
  feature binary, canary off:       76,960,920,900
  feature binary, canary on:        53,626,891,689
  reduction:                        23,334,029,211 (30.32%)

native wall time:
  off cold/warm:                    1.892s / 1.640s
  on cold/warm:                     1.122s / 1.016s

native RSS after evaluation:
  off cold/warm:                    252.8 / 250.3MiB
  on cold/warm:                     162.4 / 174.1MiB
```

The wrapper includes three native evaluations plus oracle/harness work.
Dividing the aggregate instruction delta by the three identical native
evaluations gives an approximate 7.778B instruction saving per native
evaluation. Applied to the last 19.844B strict control, the remaining native
work is still roughly 12.07B, so this canary alone cannot meet the 3.110B
gate. Its maximum-process RSS figure also includes the oracle and harness and
is not a strict native-only peak. Nevertheless, the result is qualitatively
different from every callback-bearing island: deleting one recursive
evaluator protocol reaches the target RSS neighborhood and removes about 39%
of native instructions.

This promotes both major architectural branches. Transition-specialized
traces must link across force/apply/return boundaries and virtualize object
protocol; a faster bytecode interpreter is insufficient. Independently, the
compact moving heap should retain stable promise identity in one-word heads
while relocating only live typed work and packed environments. The exact
instruction-coverage proof must use a frozen discovery/validation linker
profile and externally segmented retired-instruction counting; event counts
and `Instant` timings cannot prove the 95%/5% gates. All synthetic thunk kinds,
not only Node work, must participate because synthetic Apply work was already
measured as more than half of thunk allocation traffic.

## Fifty-seventh master merge and whole-demand specialization direction

`origin/master` was merged as commit `970e7ee08`. The pre-merge branch is
preserved as `codex/pr-104-pre-master-merge-20260725`, and the pre-merge dirty
state remains recoverable from `stash@{0}` because restoring it produced the
expected `Cargo.lock` conflict. The working tree contains the restored
evaluator work plus master's package, profile, hub, and store changes.

The combined workspace initially caused Cargo to opportunistically select AWS
crate releases requiring Rust 1.94.1. Regenerating the lockfile was therefore
incorrect. Restoring master's lock as the base and allowing Cargo to add only
the evaluator packages retained `aws-config` 1.8.17 and `aws-sdk-s3` 1.134.0.
A hermetic Rust-1.93 workspace check then exposed one actual merge defect:
`aos-core` used `aos_nix_env` after its import had been lost. Restoring that
import made the full `aos` check pass with both callback-free canary features.

The most plausible route to the remaining instruction gate is now a guarded
whole-demand trace supercompiler, not a larger collection of isolated
handwritten callbacks. Its trace key may contain exact source, module,
closure-code, resolver-frame, and capture-layout identity, but never runtime
values, addresses, string bytes, list lengths, or observed branch outcomes.
A trace must carry force/apply/return control explicitly and virtualize
promises, closures, frames, lists, and attrsets until escape. Before resumable
side exits exist, all guards must be checked before mutation and any decline
must occur before publication.

This direction follows several directly relevant results:

- Boquist's GRIN work uses whole-program heap points-to information to remove
  unknown calls and repeatedly transform a lazy functional program.
- `weval` demonstrates whole-program compilation by partial evaluation of an
  interpreter, including control-flow reconstruction from an interpreter loop.
- Bolz et al. show allocation removal through tracing partial evaluation by
  virtualizing objects and materializing only on escape.
- Supercompilation by evaluation provides the binding-time and residualization
  model needed to keep specialization independent of dynamic values.

Primary references:

- <https://research.chalmers.se/en/publication/890>
- <https://arxiv.org/abs/2411.10559>
- <https://stups.hhu-hosting.de/downloads/pdf/BoCuFiLePeRi2011.pdf>
- <https://simon.peytonjones.org/supercompilation-evaluation/>
- <https://doi.org/10.1145/158511.158618>
- <https://www.cambridge.org/core/services/aop-cambridge-core/content/view/A1CF974BD4A92A2A9B47287F55B68DB6/S0956796897002712a.pdf/deriving_a_lazy_abstract_machine.pdf>
- <https://simon.peytonjones.org/assets/pdfs/modular-higher-order-cardinality-2016.pdf>
- <https://arxiv.org/abs/1612.06668>
- <https://arxiv.org/abs/1012.1802>

The first standalone falsifier is `region_machine.rs`. It defines a
runtime-value-independent `TraceKey` and a nine-operation explicit tape for
body 684, with branches and a backedge but no TreeWalk callback. Six tests
cover reuse across different runtime values, order and deduplication,
empty-accumulator laziness, unchanged-result reuse, fail-closed unsupported
values, and static-only trace identity. It remains a prototype: generic tape
dispatch may be slower than the direct callback-free Rust loop, so only an
external instruction A/B can promote it.

The next candidate region is the `finalConfig` fold:

```nix
foldl'
  (acc: key: deepMerge acc (setPath entry.path entry.finalValue))
  {}
  (attrNames mergedOptions)
```

The default-off `final_config_trie_canary` now pins the complete source and
matches this pipeline structurally instead of relying on arena ordering or
source spans. It derives the unique four-field
`{ path, finalValue, option, definitions }` entry-record code reference and
counts only runtime Node thunks with that exact module/body identity as
projectable. Two focused source tests pass.

An independent lowering inspection and a second exact matcher then established
the capture route that avoids forcing this wrapper. The matcher derives all
code references structurally rather than treating arena numbering as stable.
The entry thunk's shared environment exposes the `decl`/path owner at
`(depth 0, slot 0)` and the already-lazy `finalValue` at `(0, 10)`. The exact
suspended `decl` thunk is a dynamic `optionMap.${key}` select whose two-slot
flat capture is `(1, 0)` for `key` and `(2, 5)` for `optionMap`. The runtime
census validates the derived code and allocation-site identities, requires a
context-free key whose bytes equal the current merged-options symbol, performs
raw attr lookups only on already-ready attrsets, and classifies the resulting
`decl.path` and `finalValue` values.

The census intentionally performs no force, apply, evaluator dispatch,
select-cache operation, evaluator allocation, or publication and records zero
callback-free executions. The first production census exposed one additional
lazy layer: every `optionMap[key]` value was a suspended
`ThunkAlloc(UpvalVar decl)` alias. The dynamic key
`concatStringsSep "." decl.path` is evaluated before that RHS alias is
allocated, so a surviving entry proves that the captured original declaration,
its path list, and every path string have already been forced. A fail-closed
alias projector now requires a suspended Node thunk, an exact
`ThunkAlloc(UpvalVar)` body/site pair, and a one-slot flat capture plan before
reading that capture. It never reconstructs the path by splitting the dotted
key, which would be unsound for path segments containing dots.

The resulting per-evaluation census is complete:

```text
exact entry thunks:                 4,825
option-map lookups:                 4,825
uniform alias Node thunks:          4,825
captured declarations ready:        4,825
projected path lists:               4,825
path elements:                      6,193
ready context-free path strings:    6,193
path element declines/context:          0
empty paths:                            0
duplicate path pairs:                   0
proper-prefix path pairs:               0
suspended finalValue values:        4,825
```

This passes the read-only and prefix-free prerequisites for a trie builder
that removes the entry-record force plus the complete
`foldl'`/`setPath`/`deepMerge` protocol without changing final-value laziness.
Empty, duplicate, or proper-prefix paths would require `deepMerge` to force and
inspect a conflicting `finalValue`; the executable path must preflight and
decline those shapes before its first allocation. Publication remains disabled
until direct attrset construction proves source order, source positions, and
allocation metadata.

Fresh same-source post-master strict controls now produce
`/nix/store/jy9s3v5f48bwvklrmbhhbsckqgkqdl7l-aos-system-toplevel.drv`:

```text
C++ Nix:  6,242,245,155 instructions, 341,096 KiB peak RSS
AOS:     12,094,356,826 instructions, 373,608 KiB peak RSS
```

The exact gates on this graph are therefore fewer than 3,121,122,578
instructions and fewer than 170,548 KiB. The current candidate still needs a
74.2% instruction reduction and a 54.3% RSS reduction. The final-config region
is a useful mechanism and coverage test, not a plausible endpoint by itself.

An independent alternatives audit rejects equality saturation, richer demand
facts, and generic deforestation as standalone gate-closing architectures.
They do not model promise identity, blackholes, force/update, dynamic calls,
effect order, or virtual-heap materialization. The only avenue whose coverage
arithmetic can plausibly close the remaining gap is guarded whole-demand
partial evaluation of a deliberately small explicit lazy promise machine,
lowered as one native CFG. Demand/cardinality and deforestation remain analyses
inside that compiler; a bounded e-graph may later choose pure region-local
forms, but raw Nix IR should not enter a global equality-saturation pass.

## Executable final-config trie result

The final-config trie is now executable rather than census-only. Admission has
two phases. The first projects every entry and builds an unpublished trie
without evaluator allocation, force, apply, select, or thunk publication. It
declines empty paths, duplicates, proper prefixes, excessive depth, non-ready
path elements, and any code/capture/storage mismatch. Only after all decline
doors are closed does the second phase allocate attrsets bottom-up. It
reproduces `deepMerge` versus `setPath` allocation metadata, binding positions,
lexicographic lookup order, and the source-visible insertion order of each
node. Six focused tests pass.

The first production attempt exposed a useful capture-ABI guard defect. The
entry-record structural matcher correctly admitted both a three-slot flat plan
and `SharedChain(TooManyFreeVars)`, but the runtime projector unconditionally
required a flat allocation site. Production used the proved shared-chain
case, so all 357 folds declined. The runtime guard now records the capture
storage class in the plan: flat plans require the exact flat allocation site,
while the exact shared-chain plan requires the absence of a flat base. Body,
module, lexical-coordinate, and source identity checks remain mandatory.

On the exact synchronized post-merge graph the complete executable census is:

```text
structurally admitted folds:          357
merged-options entries:             8,883
projected entries:                  8,883
projection declines:                    0
projected path elements:           11,124
callback-free executions:             357
```

Canary-off and canary-on runs from the same release binary both produce:

```text
/nix/store/q0z36bnbl7k9a9kg07x7vjz2vi2blsp2-aos-system-toplevel.drv
```

Fresh same-source measurements are:

```text
C++ Nix:
  wall time:                         13.25s
  retired instructions:     21,263,549,573
  peak RSS:                     467,944 KiB

AOS, trie disabled:
  wall time:                          4.92s
  retired instructions:     33,481,850,291
  peak RSS:                   1,035,356 KiB

AOS, trie enabled:
  wall time:                          2.54s
  retired instructions:     13,651,367,833
  peak RSS:                     437,268 KiB
```

The executable region removes 19.83B instructions (59.2%) and 598,088 KiB of
peak RSS (57.8%) from the native evaluator, with exact derivation-path parity.
It also subsumes the earlier body-684 dedup opportunity: with the trie enabled,
the dedup canary reports zero body attempts because the eliminated fold was
its caller.

The requested speed target is met on this graph: 13.25s / 2.54s is about
5.2x. The memory target remains decisively open. Half of C++ is 233,972 KiB;
the candidate is 437,268 KiB and must remove another 203,296 KiB (46.5% of its
current peak). Therefore further local fold islands are not a sufficient
endpoint. The next experiment must identify which live object classes account
for the post-trie peak and test region reclamation or compact destination
construction against that measured population.

Post-trie weak-liveness and reservation telemetry makes the next direction
quantitative. At demand completion the process holds 436,785,152 resident
bytes and the flat reservation holds 235,835,392 resident bytes. Only 603 of
57,577 reservation pages are reachable from the complete terminal root set;
56,974 wholly dead pages account for 233,365,504 bytes (222.55MiB). The live
terminal graph has only 991 objects. A terminal sweep cannot change
`ru_maxrss`, but this proves that retained garbage alone is larger than the
entire remaining target gap.

The growth is already visible during imports:

```text
modules    total pages    live pages    wholly dead pages
  1,152         32,561        22,142              10,419
  1,200         36,663        25,369              11,294
  1,220         36,901        25,539              11,362
terminal         57,577           603              56,974
```

At module 1,188, the compact-destination projection traces 386,586 reachable
objects and computes a 21,933,816-byte compact-heap upper bound and a
36,221,952-byte named-state upper bound. The largest contributors are 8,137
strings/paths, 16,096 lists, 34,500 attrs, 323,850 stable eight-byte thunk
heads, 147,192 pooled typed-work records, and 38,127 packed frames. There are
no unattributed reachable objects. This rules out allocator tuning and further
pointer compression as primary answers: the compact reachable graph is already
small, while dead pages and current payloads dominate.

The process RSS milestones are 244,043,776 bytes at 1,024 modules,
272,371,712 at 1,152, and 302,845,952 at 1,220. Half-C++ is crossed before the
existing 1,188-module projection boundary. Consequently the falsifiable next
step is a sequence of earlier read-only compact projections, followed by
repeated evacuation/decommit at explicit complete-root statepoints. A one-shot
terminal collector and a single late import collector are both ruled out by
peak timing.

The multi-milestone projection now supplies that schedule:

```text
modules   reachable objects   heap upper   named-state upper
    512             116,002     8.19MiB              20.28MiB
    768             190,305    12.20MiB              24.39MiB
    896             219,356    14.65MiB              26.85MiB
  1,024             281,118    17.40MiB              29.75MiB
  1,088             326,330    19.26MiB              31.73MiB
  1,152             331,802    19.81MiB              32.27MiB
  1,188             386,586    21.93MiB              36.22MiB
  1,220             389,556    22.22MiB              36.52MiB
```

No milestone has unattributed reachable objects. A first evacuation around
768-896 modules therefore needs only a 12-15MiB compact heap (24-27MiB named
state), well before ordinary RSS crosses the target. A second collection around
1,088-1,152 modules leaves similar headroom for the final demand window. The
collector implementation must make these boundaries real writable-root
statepoints; the current `EvalRootSet` records copied words for tracing but
does not by itself provide writeback addresses for arbitrary recursive Rust
locals.

The first implementation stage is now executable and read-only. The
default-off `evacuation_plan_probe` traces the storage-aware weak graph,
classifies every reachable object into permanent-flat, typed-head,
worker-flat, or compatibility-record lanes, assigns deterministic
address-ordered dense offsets, and rescans every edge through the exact storage
resolver. It allocates no destination and mutates no heap field. Four focused
tests prove unique non-overlapping destinations, edge closure, deterministic
layout, and source-heap immutability.

Production planning initially exposed that the generic precise-root scanner
resolved a headerless typed thunk through the legacy record path. Both runtime
tags were `Thunk`, but the storage classes disagreed. The planner now uses the
same storage-aware typed-head/list/attrs/flat-closure/record dispatch as weak
reachability and keeps the mismatch fail-closed.

The same-layout destination sizes are:

```text
modules   objects      edges   inline destination   known list storage
    512   116,002    691,715             15.47MiB              0.13MiB
    768   190,305  1,042,844             25.39MiB              0.24MiB
    896   219,356  1,082,011             29.81MiB              0.28MiB
  1,024   281,118  1,630,827             37.46MiB              0.34MiB
  1,188   386,586  2,538,820             50.28MiB              0.43MiB
  1,220   389,556  2,563,172             50.81MiB              0.44MiB
```

Thus dropping unreachable objects with current layouts is already plausible;
packed destinations buy additional overlap headroom rather than making
collection possible in the first place. The first production planner used an
all-allocated-object classification map and inflated diagnostic RSS to
590MiB. That is unacceptable collector behavior. It has been replaced by a
reachable-sized vector populated while streaming the existing stores, so plan
memory now scales with the live graph rather than 1.8 million historical
allocations.

The next staged mutation is also complete but remains isolated from TreeWalk.
For a plan containing only edge-free strings and paths, the writer preflights
every source address, tag, extent, lane, and supported kind before constructing
a fresh serial `EvalHeap`. Existing allocation doors place the copied payloads
at exactly the planned dense offsets in a distinct Candidate-C arena domain.
Six focused tests now include source/destination coexistence, cross-domain
resolution rejection, exact offset reproduction, and destination survival
after the source heap is dropped. Graph-bearing kinds still decline before the
destination exists; no evaluator root or source field is rewritten.

Permanent compound objects now use an unpublished builder rather than
temporary hash-cons identities. Feature-gated raw list/attrs allocators always
create one exact-layout destination object at the planned offset and register
it only with the private flat store. Once complete forwarding exists, the
builder rewrites list elements and attr entry values, recomputes every
structural hash, builds complete replacement list/attrs hash-cons tables,
updates headers, and clears stale markers. Only this fallible finalizer can
return the destination wrapper; any failure drops the unobservable heap. The
seven-test suite covers attr-to-list-to-string nesting, duplicate child alias
preservation, metadata/order preservation, source-drop survival, and
post-finalization list/attrs interning parity. At this boundary, every worker
object, typed object, boxed-scalar edge, and TreeWalk root publication still
declines.

The first worker-flat slice is now executable as well. Flat primops allocate
in reverse plan order because the worker lane grows downward; after allocation,
the writer verifies every lane-relative address and exact object extent against
the Stage-A plan. Once complete forwarding exists, it reconstructs each primop
with the same symbol and registered builtin identity and rewrites every partial
application argument while preserving its module, IR id, and source span. The
eight-test focused suite includes two mutually referring destination classes,
source-heap drop, a callable registered builtin, and a partial application
whose argument points at a relocated string. Lambdas, thunks, captured frames,
typed thunk heads/work, record-layout worker objects, boxed-scalar edges, and
TreeWalk root publication still decline before any destination is exposed.

The lambda slice now follows the primop slice without widening the heap-lane
plan. Exact source tail length reproduces each downward-growing flat object,
and the existing snapshot frame codec captures and rebuilds the out-of-object
frame DAG. Complete forwarding then rewrites lexical frame slots, with-scope
values, scoped globals, and inline flat-tail values before the private lambda
payload is installed and its flat-base handle is re-signed. A ninth focused
test drops the source heap after evacuating two lambdas that share one frame;
the destination retains that shared `Arc<EvalFrame>` identity and resolves
relocated strings through every capture surface. Thunks and shared thunks,
typed thunk heads/work, record-layout worker objects, boxed-scalar edges, and
TreeWalk root publication remain fail-closed.

Headerless typed heads now cover both stable production states in the private
destination. Suspended synthetic work (`Apply`, `GenListElemAtAddOne`,
`Apply2`, `Select`, and `BuiltinAttr`) receives a fresh generational work
coordinate; forced heads receive their forwarded cached result. In both cases
the exact Stage-A typed-lane offset is checked before complete forwarding
rewrites work or result edges. The ten-test focused suite includes source-drop,
replayed suspended application, forced-result resolution, and exact typed-lane
offsets. Blackholed heads still decline because an active force guard points
directly at the source head and may have moved work into a TreeWalk lease.
Capture-bearing node work, ordinary flat thunks/shared thunks, and record
workers likewise remain outside this bounded slice.

The first publication audit also rules out treating the existing heap-image
adoption seam as a mid-evaluation swap. Candidate-C identity includes the arena
domain as well as the offset, and flat capture handles are heap-relative. A
moving commit therefore needs a staged replacement for every TreeWalk root
container and every flat-owner handle, plus a destination-domain audit, before
an infallible critical section replaces the heap and drops the old heap last.
Import milestones are not intrinsically quiescent: active environments and
capture owners may still exist there.

An adversarial memory-path audit therefore promotes a second collector
hypothesis rather than assuming moving publication is inevitable:
storage-aware nonmoving retirement, destruction of dead Rust-owned payloads,
weak registry/hash rebuilding, and `MADV_DONTNEED` over coalesced wholly-dead
reservation pages. This is not the existing tombstone sweep, which leaves
pages and registries resident and paid a large hash-set peak. At 1,152 imports,
259.754MiB RSS includes 40.699MiB of wholly-dead pages, giving a 219.055MiB
in-place floor before dead external payloads or metadata shrink. At 1,220,
those pages alone leave 244.434MiB, so exact external/index destruction must
supply at least another 15.946MiB. The terminal opportunity is larger, but
cannot undo an earlier `ru_maxrss`.

This alternative still requires an early first collection around 768-896
imports and later collections before adjusted RSS reaches the ceiling. Its
read-only falsifier must carry advised-page nonresidency forward and account
for exact dead-owned external bytes, rebuilt live registry/hash capacity, mark
scratch, and page re-touch. It advances to mutation only if every simulated
checkpoint stays below 216MiB, preserving about 12MiB of safety beneath the
228.488MiB acceptance ceiling. Otherwise the staged moving collector remains
necessary. Fork/restart, the current whole-reservation snapshot, and page-table
remapping do not avoid source/destination overlap or the need to serialize the
active lazy continuation; they are not equivalent low-risk substitutes.

An audit invalidated the first import table: it had credited compaction of the
flat-closure registry even though `FlatValueTailHandle` embeds that registry's
slot index. Shrinking it without re-signing every live handle is unsound. The
corrected fresh-process 1,220-module projection is:

```text
raw RSS                                               315,486,208
resident wholly-dead pages (11,365 * 4,096)           46,551,040
dead list-spine capacity                                1,640,688
sound string/list/attrs registry shrink                 3,771,280
projected mark scratch added back                       6,997,294
strict adjusted RSS                                   270,520,494
acceptance ceiling                                    239,587,328
```

Closure-registry savings of 28,268,848 bytes and hash-index structural savings
of 9,020,328 bytes are both reported but excluded. Thus simple root-free
retirement misses the ceiling by 30,933,166 bytes at imports alone.

Fresh independent samples inside the 357 callback-free final-config executions
reject repeated nonmoving collection more strongly:

```text
execution   modules   reachable   raw RSS       strict adjusted RSS
        1        63      11,632    24,563,712            24,515,000
       64       296     103,891    77,123,584            70,071,136
      128       628     161,688   148,344,832           133,194,596
      192       881     207,099   203,677,696           173,451,646
      256     1,046     304,493   257,839,104           219,217,397
      320     1,299     417,755   316,186,624           269,487,172
      357     1,556     525,710   436,224,000           354,549,610
```

At execution 357, 20,560 pages are wholly dead but 36,936 pages still contain
at least one live object. Metadata-only variants remain far above the target;
the dominant cost is sparse survivors pinning mixed append-only pages.

The same-layout moving plan confirms that live volume is not the obstacle:

```text
execution   reachable   destination inline   permanent lane   worker lane
      256     304,493            40,198,160       15,534,104    24,664,056
      320     417,755            54,409,592       20,230,504    34,179,088
      357     525,710            70,664,008       28,156,848    42,507,160
```

All three final-config samples contain only permanent-flat and worker-flat
objects: no record-lane object and no headerless typed head is live. A compact
destination therefore has comfortable steady-state size, but publishing it
still requires rewriting every root-bearing TreeWalk container and every
heap-relative capture handle.

The reclamation probe's retired-instruction delta is diagnostic work, not an
evaluator regression. An execution-1 sample retires 13.68B instructions,
matching the 13.65B accepted path; moving the graph traversal to execution 357
raises it to 17.02B. The probe performs precise root construction, a complete
weak traversal, and full store scans with `HashSet`/`Vec` scratch. Acceptance
counters must therefore remain probe-free.

Before widening moving publication, a root-stable address-preserving
alternative is now under an exact read-only falsifier. The Mesh-style probe
marks one occupancy bit per 64-byte line of each live 4KiB page and constructs
only disjoint page pairs. At execution 357 it must demonstrate at least 15,254
saved page equivalents; otherwise even the independently projected
closure-handle and mark-scratch improvements cannot close the 59.6MiB
remaining gap. The mutation, if admitted, must use shared backing pages at both
original virtual addresses and permanently prohibit reuse of retired holes.

The first execution-357 projection found 36,906 live pages and 1,230,299
occupied lines. Pair-only greedy matching saved 12,086 page equivalents; four
deterministic multi-page packing orders improved that to 14,047, still short
of 15,254. The average-occupancy upper bound was 17,682, so packing alone did
not certify rejection.

Linux RSS accounting does. The acceptance harness samples `ru_maxrss`, which
counts resident mappings rather than unique physical pages. On the benchmark
builder, a one-page memfd was mapped and touched through 16,384 aliases:

```text
page=4096 aliases=16384
rss_pages_before=280 rss_pages_after=16672
rss_delta_bytes=67141632 ru_maxrss_kib=66076
```

The RSS delta is essentially one page per alias even though every PTE names the
same physical page. Mesh can reduce physical footprint and proportional set
size, but not this strict per-process RSS metric. The page-remapping avenue is
therefore rejected before mutation, independently of whether a stronger
hypergraph coloring could close the remaining pairing gap.

A third alternative avoids both root writeback and permanent handle
indirection: pin only the objects named directly by the complete
`EvalRootSet`, evacuate every other reachable object into fresh space in the
same Candidate-C reservation/domain, and rewrite exact heap edges. Root words
remain byte-identical because their immediate targets do not move. Read-only
planning shows that direct roots pin very little of the fragmented arena:

```text
execution   roots   distinct pinned objects   pinned pages   movable inline
      256   4,283                     1,426            453       40,052,768
      320   4,385                     1,527            559       54,255,256
      357   1,248                       920            508       70,570,864
```

At the final sample, directly rooted objects pin only 1.98MiB of source pages.
This is the measured Bartlett/Immix-style seam: ambiguous or copied roots pin
their immediate object, while exact heap fields can still point to evacuated
children. It is preferable to a universal ObjectId lookup if the worker lane
can be copied at quiescent no-blackhole/no-region-mark points. The next
falsifier classifies ordinary flat thunks by force state, source/synthetic
shape, and inline captures before widening the destination writer.

The promoted collector design is consistent with several useful primary
references:

- Immix supplies the mark-region and opportunistic evacuation model for
  reclaiming fragmented blocks without requiring a permanent full semispace:
  <https://doi.org/10.1145/1379022.1375586>.
- Beltway separates collection increments from object age, a useful model for
  repeated explicit import-boundary collections:
  <https://sites.cs.ucsb.edu/~ckrintz/racelab/gc/papers/beltway-pldi-2002.pdf>.
- `Using Destination-Passing Style to Compile a Functional Language into
  Efficient Low-Level Code` motivates constructing materialized results
  directly in their destination rather than retaining source and compact copies:
  <https://www.microsoft.com/en-us/research/wp-content/uploads/2016/11/destination-passing-style-1.pdf>.
- Allocation removal by partial evaluation supplies the virtual-object and
  materialize-on-escape model needed to prevent the whole-demand compiler from
  recreating collector pressure:
  <https://doi.org/10.1145/1929501.1929508>.
- Mesh is the direct precedent for address-preserving compaction through
  virtual-memory page aliasing:
  <https://doi.org/10.1145/3314221.3314582>.
- Bartlett's ambiguous-root collector and the Immix-derived conservative
  collector show how exact heap edges can coexist with pinned ambiguous roots:
  <https://www.hpl.hp.com/techreports/Compaq-DEC/WRL-88-2.pdf> and
  <https://doi.org/10.1145/2660193.2660198>.

The first compact-footprint calculation is not yet a peak-RSS proof.
`ru_maxrss` is a monotonic watermark: a collector invoked after the process
crosses 239,587,328 bytes cannot repair the result, and an evacuation must
include the maximum transient coexistence of source pages, destination pages,
scratch, and old/new metadata. At execution 357, retaining current weak hash
tables and applying only the independently measured registry shrink gives:

```text
probe-free RSS                                    436,224,000
- source reservation resident                     235,507,712
+ compact destination and pinned pages             72,654,848
- registry structural shrink                       31,958,816
+ compact scratch                                   6,374,298
= conservative post-commit                        247,786,618
target                                             239,587,328
shortfall                                            8,199,290
```

Crediting the probe's lower-bound hash shrink would produce 234,640,186 bytes,
but that number excludes SwissTable control bytes, allocator rounding, and
old/new rebuild overlap. It is therefore not an acceptance claim.

The exact early-trigger probe rejects a complete-source-overlap copy at
execution 192 in the current merged source. Before planner allocation it
sampled 232,394,752 bytes current RSS and a 231,297,024-byte kernel watermark.
Appending the compact low/high destinations touches 28,065,792 new reservation
bytes; page-rounded compact scratch raises the conservative upper bound to
262,975,488 bytes, 23,388,160 bytes above the target.

The exact page schedule admits a first dead-first collection at execution 192.
All 21,893 source pages containing registered allocations were resident.
Destroying unreachable allocations first made 21,560 pages releasable, leaving
exactly the 333 pages intersected by direct-root-pinned objects. The 6,852
destination pages therefore never raised the reservation above its starting
resident footprint. Charging page-rounded compact scratch produced a
234,909,696-byte upper bound, 4,677,632 bytes below the target.

This is an admission to implement the first collection, not a terminal memory
claim. Uncollected execution-256/320/357 snapshots already exceed the target,
and their object addresses, root pins, cursor positions, and releasable pages
do not describe the heap after a real execution-192 move. Repeated collection
must be measured on the mutated post-collection heap; subtracting the first
projected saving from later uncollected snapshots is only a rough trigger
estimate.

Persistent select and call-site caches are not the missing non-reservation
mass. An exact checkpoint census measured:

```text
execution   flat PIC map   primop dense table   formal layouts   other PIC maps
      192         408,576             1,179,760          200,088                0
      357         408,576             1,867,488          346,580                0
```

At execution 357 only 4,286 of 103,922 primop slots are populated, so a sparse
representation could recover roughly 1-2MiB, but it would put hashing back on a
hot path and cannot materially close the memory target. Shaped, record, HAMT,
and static-literal shape maps are empty in the accepted flat-representation
configuration. A broad cache-layout rewrite is rejected as the primary memory
avenue; captured frames, module ownership, and allocator mappings remain the
next non-reservation attribution targets.

Every active flat-thunk blackhole was directly pinned at the measured
checkpoints (36 of 36 at execution 192 and 30 of 30 at execution 357), removing
blackhole movement from the first collector. Registry-index tail handles remain
the bounded prerequisite for compacting or sparsifying closure registries.

Additional primary references sharpen the implementation direction:

- The Compressor computes relocation with compact side metadata and returns
  processed source pages while bounding mapped coexistence:
  <https://doi.org/10.1145/1133255.1134023>.
- The 2024 One-Pass Compactor is the follow-up to consult when reducing
  compaction passes and scratch after a correctness-first writer exists:
  <https://doi.org/10.1145/3652024.3665513>.
- The 2026 offset-vector compactor study implements and compares Compressor
  variants and the One-Pass algorithm on modern OpenJDK workloads, and adds a
  branch-free forwarding computation. Its result that One-Pass does not beat
  Compressor argues for measuring the compact forwarding table before adding
  pass-fusion complexity:
  <https://doi.org/10.1145/3814942.3816135>.
- ALASKA demonstrates optimized logical handles and explicit pin intervals in
  unmanaged code, but its permanent handle table argues for narrow direct
  arena-coordinate handles here rather than universal indirection:
  <https://arxiv.org/abs/2405.00038>.
- Transparent Pointer Compression reports both heap-size and cache/runtime
  improvements for pointer-intensive structures. Candidate C already reserves
  one 4GiB domain, making 32-bit arena-relative fields a natural
  allocation-time complement to evacuation:
  <https://llvm.org/pubs/2005-06-12-MSP-PointerComp.html>.
- Liveness-based collection for lazy languages motivates clearing provably dead
  environment/capture slots, though higher-order dynamic Nix limits direct
  adoption of its whole-program analysis:
  <https://arxiv.org/abs/1604.05841>.

An exact captured-frame census rejects frames as the primary memory avenue but
requires charging them to the first collection's transient. With C++ priming,
both implementations produced
`/nix/store/nsl5bsfqb872h50z6r94przza2f5f5hk-aos-system-toplevel.drv`.
The probe measured:

```text
execution   reachable frames   reachable modeled   total frames   total modeled
      192             18,455           1,492,432        113,544       6,129,088
      357             58,612           4,397,064        371,376      19,540,216
```

The model includes each distinct `Arc<EvalFrame>` allocation and heap-backed
slot storage. The current destination writer also transiently owns serialized
frame payloads, capture identity maps and retained `Arc` vectors,
per-environment frame-id vectors, and a newly rebuilt frame graph before the
old graph can disappear. The admission model now charges a conservative
writer-specific upper bound for those allocations in addition to compact
mark/forwarding scratch. An in-place frame-slot rewrite or a packed
Candidate-domain frame lane can later remove that charge.

The same execution-192 run sampled 216,231,936 bytes before planner allocation.
Without the newly added frame-staging charge, exact source-page streaming gave
a 218,746,880-byte upper bound and 20,840,448 bytes of headroom. This differs
from the earlier 4.68MiB margin because process RSS varies across optimized
probe builds; neither result is acceptance evidence. The charged projection
must pass repeatedly, and only a real collection followed by continued
evaluation can establish the post-collection watermark.

The frame alternatives rank as follows:

1. A packed Candidate-domain frame lane with direct arena coordinates,
   segregated reusable pages, and prompt page release best complements the
   collector. The historical full graph's packed wire-format lower bound was
   6.50MiB versus roughly 15.5-20.7MiB of `Arc` storage.
2. Reusable transient stack frames plus one shared captured-slot projection per
   lexical scope could recover approximately the prior 12MiB capture-expansion
   ceiling without per-closure copying, but it is not a factor-level result.
3. Frame virtualization belongs inside whole-demand Promise/PIR/SSA regions:
   keep slots in SSA/value-stack positions and materialize compact captures
   only at escape/statepoints. This is the only frame avenue coupled to the
   required factor-level execution architecture.

Direct frame work is otherwise bounded to roughly 2.8-3.4% of execution time,
so a standalone frame rewrite is rejected. Correctness requires preserving
recursive self-visibility, `__overrides`, lazy update identity and error order,
active and suspended environment roots, parent-window semantics, shared slot
mutation, snapshot identity, and panic rollback.

The first optimized run with the conservative frame charge rejected the
snapshot-style writer at execution 192:

```text
pre-plan current RSS                              234,586,112
compact mark/forwarding scratch                     2,511,118
frame staging upper bound                           9,162,200
page-stream peak upper                            246,259,712
target                                             239,587,328
excess                                               6,672,384
```

The exact page schedule still has zero net reservation-page growth, so the
failure is external staging rather than the move schedule. Removing only the
frame staging would leave approximately 2.49MiB of margin in this run. The
generic serialize/rebuild writer is therefore rejected for the first
collection; the mutating collector must preserve frame identity and rewrite
reachable frame slots in place, or allocate frames in a compact same-domain
lane whose old pages can be returned during the same stream.

A mutation-order audit found two correctness omissions in the initial page
projection. Candidate-C boxed integer and float cells share the reservation but
were not enumerated, so a page could appear releasable while still containing a
live scalar. `FlatValueTailHandle` also embeds a registry index, length, and
generation, so moving a reachable tail owner without preserving that exact
entry invalidates published handles. The V1 projection now conservatively pins
all scalar pages, initialized typed heads, blackholes, and reachable tail
owners. This is intentionally pessimistic until registry tombstones and
per-slot typed-head liveness exist.

The smallest safe mutating sequence is:

1. Perform a fully fallible preflight before touching the heap: prove the exact
   safepoint, reject shared or unsupported state, close the pin set, compute
   complete forwarding, reserve metadata, and prebuild weak indexes.
2. Destroy unreachable objects first and return only pages whose every
   registered extent has been processed. Every registry entry needs an
   exactly-once-drop tombstone; decommitting bytes while normal `Drop` still
   visits them would be undefined behavior.
3. Stream movable objects in source-address order with no fallible operation
   after the first mutation. Clone or move at most one external payload at a
   time, rewrite its edges through complete forwarding, tombstone the source,
   and release newly empty pages immediately.
4. Rewrite outgoing edges in pinned objects and each shared `EvalFrame` once,
   publish rebuilt string/path/list/attrs weak indexes, repair or clear
   address-keyed evaluator caches, reset remembered/card state, and advance
   allocation epochs.

Ordinary flat thunks dominate this workload, while the existing fresh-heap
writer is only a payload-semantics oracle: it does not yet supply the
tombstones, allocation-free commit, root/cached-identity repair, or
one-object-at-a-time staging required by this protocol.

Three further primary references refine the selective-evacuation design:

- Mark-Scavenge combines scavenging and mark-evacuate, uses prior liveness to
  avoid moving likely-dead objects, detects completely evacuated regions, and
  performs address-order evacuation under memory pressure:
  <https://doi.org/10.1145/3689791>.
- Nofl reclaims holes down to allocator alignment while retaining bump
  allocation and single-pass tracing. It is the alternative if pinned objects
  make page or line granularity too coarse, though its current evidence is a
  limited microbenchmark evaluation:
  <https://arxiv.org/abs/2503.16971>.
- LXR reclaims most memory without copying on an Immix heap and uses limited
  stop-the-world mature copying plus remembered sets. It supports the proposed
  post-first-collection shape: compact survivors as old, new allocations in a
  nursery, and existing card-table machinery for minor collections:
  <https://arxiv.org/abs/2210.17175>.

Earlier triggering materially widens the first-collection envelope. With the
conservative V1 pin policy already active, exact-source runs measured:

```text
execution   current RSS   pinned objects   movable bytes   full-copy upper   headroom
      160   191,307,776          110,326      11,941,152       213,123,072   26,464,256
      176   198,406,144          114,338      12,248,920       220,872,704   18,714,624
      192   233,205,760          129,391      15,388,128       260,276,224            0
```

The execution-160/176 full-copy bounds include the conservative 7.76/8.04MiB
frame-staging charge. Execution 160 is therefore the preferred first mutation
checkpoint while the writer remains allocation-heavy. Its dead-object prepass
also makes 4,409 pages immediately releasable. This is still only an admission
bound: the present writer rejects ordinary flat thunks and the model must add
all payload-vector, forwarding-map, registry-growth, and weak-index staging
before a fresh-heap swap can be trusted.

After adding those missing clone-all structures, the writer is decisively
rejected even at execution 160. Its conservative staging is 47,265,992 bytes
and the full-copy upper bound is 251,957,248 bytes, 12,369,920 above target.
The streaming bound at the same checkpoint is 192,745,472 bytes, leaving
46,841,856 bytes of headroom, because it retains only the 2,104,118-byte
compact mark/forwarding state and moves at most one payload at a time. This
supersedes the provisional early-trigger full-copy admission above: triggering
early is still correct, but only the streaming/in-place architecture has an
admitted peak.

There is one materially different post-tombstone alternative worth keeping
alive: replace the two-ended append-only arena with a precise reusable-hole
arena, rather than evacuating survivors. This is the Nofl direction, not the
earlier nonmoving projection. That projection credited only wholly-dead page
advice and structural shrink; it did not credit allocating later objects into
dead mixed-page holes. Nofl preserves bump-style allocation while making every
alignment-sized gap reusable, so direct root words, frame slots, tail-owner
addresses, and blackholes never need publication-time rewriting.

The measured requirement is demanding but not absurd. The execution-160
dead-object prepass exposes 4,409 pages (18,059,264 bytes), reducing its
191,307,776-byte sample to a 173,248,512-byte reservation-adjusted starting
point and leaving 66,338,816 bytes below the acceptance ceiling. In the
unmutated snapshots, strict nonmoving reclamation is still only 219,217,397
bytes at execution 256. It first fails at execution 320 by 29,899,844 bytes.
Across that interval raw RSS grows by 58,347,520 bytes while dense reachable
inline storage grows by only 14,211,432 bytes. A reusable-hole allocator must
therefore absorb or release at least 29,899,844 / 58,347,520 = 51.2% of that
raw growth. Across execution 160 to 357 it must avoid 178,577,408 of
244,916,224 bytes of raw growth after crediting the first page release, or
72.9%. The dense live inline heap at execution 357 is only 70,664,008 bytes,
so capacity exists; size-class fit, external payloads, registries, and frame
growth decide whether it is realizable.

This avenue can be falsified before changing allocation. Record the exact
ordered allocation/retirement stream after the execution-160 trace, including
aligned extent, lane, external capacity, registry slot, and page residency,
then replay it through Nofl-style hole metadata. Require a modeled watermark at
or below 226,492,416 bytes (216MiB, retaining about 12.5MiB of RSS margin), no
unreclaimed external payload, and fewer than 1.2 candidate-hole probes per
allocation. The successful tombstoning sweep and controlled dead-page advice
are shared prerequisites. Reusing an address must allocate a fresh
generation-bearing registry slot; the retired slot remains a tombstone so a
stale `FlatValueTailHandle` cannot acquire the replacement object.

The performance envelope also admits this experiment. One diagnostic
execution-160 trace-and-sweep added about 0.61 billion instructions, 3.7% over
the 16.30-billion-instruction control, while the accepted native path was about
5.2x faster in wall time than C++ Nix. Repeated full traces and an unbounded
free-list search could consume that margin, but constant-time size-class
selection and trigger spacing plausibly retain the required greater-than-2x
wall-time result. If the replay misses either the memory or probe-count gate,
selective streaming evacuation remains the implementation path; if it passes,
precise hole reuse removes the riskiest part of that path, namely root and
heap-edge publication after movement.

Reference-counting research supplies useful mechanisms but not a direct
replacement for this trace/reuse experiment. Perceus derives precise drops and
in-place reuse from an explicit-control-flow, cycle-free functional core, and
drop-guided frame-limited reuse prevents an optimizer from increasing peak
space without bound:

- <https://www.microsoft.com/en-us/research/publication/perceus-garbage-free-reference-counting-with-reuse/>
- <https://www.microsoft.com/en-us/research/publication/reference-counting-with-frame-limited-reuse/>

Those results strengthen the case for inserting exact retire points inside
future whole-demand compiled regions. They do not justify global reference
counting for the current evaluator: Nix is dynamically typed and lazy, recursive
bindings deliberately form cycles, promise update mutates identity-bearing
nodes, and most execution still lacks the explicit residual CFG needed to
prove last use. Lazy constant-time reference counting is another relevant
bounded-cost result, but its uniform-allocation premise conflicts with the
measured variable-size flat strings, lists, attrsets, and captures:
<https://cse.hkust.edu.hk/~parreaux/publication/flops24/>.
The actionable hybrid is therefore precise compile-time drops where the
whole-demand compiler proves them, feeding the same generation-safe hole
allocator used by tracing sweeps elsewhere.

The first destructive page-advice run establishes the safe lower-level
primitive but rejects page granularity as the main collector. The shared
reservation now owns a lazy dense `u16` live-allocation count per operating
system page. Every ordinary flat allocation, boxed scalar, rewindable
allocation, and complete headerless fixed block increments each intersected
page before returning typed storage. Exact flat-store retirement decrements
only after payload destruction completes. High-lane rewind clears only full
pages outside the new lane, while restored heaps, count overflow, and any
accounting inconsistency disable advice. This puts the only `unsafe` operation
inside the reservation owner; `ratchet-oracle` retains `#![deny(unsafe_code)]`.
Thirty-three flat-store tests and the high-rewind/reuse boundary test pass.

At final-config execution 160, the existing precise sweep retired 221,924
closures while retaining 250,848. Arena-owned zero-liveness accounting found
only 267 complete pages in 224 runs, all accepted by the kernel. Continued
evaluation remained byte-identical to freshly primed C++ Nix:

```text
/nix/store/nrz4v9ah4j0vyy51yqq0zclf19js2dkn-aos-system-toplevel.drv
```

Paired exact-counter samples from the same probe build were:

```text
                         instructions       wall       peak RSS
native control          13,889,961,734      1.730s     444,196 KiB
sweep + page advice     17,151,563,095      1.734s     439,720 KiB
C++ Nix                 21,269,261,111        --       468,548 KiB
```

The diagnostic planner and full trace dominate the instruction delta; the
mutation itself is not an acceptance build. More importantly, safe whole-page
release lowers the observed peak by only 4,476KiB and leaves it 205,446KiB
above the exact half-C++ ceiling of 234,274KiB. The earlier planner's
4,409-page `dead_phase_released_pages` described pages made releasable while
streaming both dead and moved objects; it was never a promise that tombstoning
dead objects alone would empty those pages. Mixed-page reuse or survivor
movement remains necessary.

The first exact hole-reuse shadow corrects another optimistic model. With only
the execution-160 sweep feeding holes, the terminal replay reported:

```text
allocations                                      2,099,899
retirements                                        221,924
actual ordered reservation extents             235,841,800 bytes
modeled high water                              215,729,520 bytes
reused extents                                   20,112,280 bytes
reuse allocations                                  221,933
candidate probes                                 2,252,296
maximum probes per allocation                            8
remaining reusable holes                            855,008 bytes
```

Alignment-bounded mixed-page reuse consumed almost every hole the first sweep
exposed, but it could save only 20.11MiB because that sweep retired only
20.97MiB of inline extents. The apparent `<=216MiB` replay admission was a unit
error in the alternative's original gate: this high water covers the
Candidate-C reservation, not whole-process RSS. Subtracting 20.11MiB from the
444,196KiB process control still leaves roughly 414.6MiB, about 186MiB above
the half-C++ target. The shadow's 72.14s wall time is diagnostic
instrumentation overhead from recording approximately 2.1 million events, not
a projected allocator cost.

One early sweep is rejected. A final stable-address falsifier must feed the
model repeated exact sweeps at later quiescent final-config boundaries; only
that can determine whether later garbage is created soon enough to recycle
before the process watermark. If repeated retirement still cannot avoid about
190MiB, Nofl-style reuse is rejected and survivor movement is mandatory.

The strong repeated falsifier swept at executions
`160,192,224,256,288,320,352`. It preserved exact parity after a stable C++
prime:

```text
/nix/store/cjpgc893p82biv54cagr0phhk08v55n9-aos-system-toplevel.drv
```

Across seven exact traces it retired 859,540 closures. The terminal shadow
reported:

```text
actual ordered reservation extents             235,841,800 bytes
terminal live inline extents                    155,033,872 bytes
peak live inline extents                        157,817,480 bytes
modeled high water                              171,185,712 bytes
reused extents                                   64,656,088 bytes
reuse allocations                                  713,896
remaining reusable holes                         16,151,840 bytes
```

This is the best realistic stable-address result under the tested cadence, and
it is still insufficient. Crediting its complete 64.66MiB reservation saving
against the 454,856,704-byte process control yields about 390.2MiB, more than
150MiB above the 239,587,328-byte target. Even perfect reuse of every remaining
reported hole cannot close that gap. A real run with the same seven sweeps
remained byte-identical but retired 53.54B diagnostic instructions and peaked
at 495,476KiB because seven full `HashSet` plans/traces and their allocator
retention are deliberately unoptimized; this is stress evidence, not an
allocator performance projection.

Stable-address Nofl-style hole reuse is therefore rejected as the primary
memory architecture. It remains useful after the first compaction, especially
inside a nursery or pinned-object line, but it cannot replace moving survivors
and compacting the registries/non-reservation owners. The implementation path
returns to the execution-160 dead-first source-address streaming collector.

The first physical survivor-movement primitive now exists below the safe
evaluator. `FlatObjectStore::relocate_plain_with` performs every fallible step
before mutation: it validates an exact live kind, rejects inline/self-relative
and `Value` tails, reserves the destination registry slot, allocates fresh
backing storage, and refreshes membership metadata. Its commit callback is
type-level infallible so kind-specific edges can be rewritten without opening
a rollback path; it then moves header/payload ownership, wipes and tombstones
the source, appends the destination entry, and retires the source from arena
page-liveness accounting. `relocate_plain` is the no-rewrite form. The
destination remains unpublished until the evaluator completes root/edge
publication.

Thirty-seven flat-store tests pass. They cover edge rewriting, structural hash
and epoch preservation, exactly-once drop, stable source tombstones, rejection
without mutation for tail owners, and safe source-only page advice while the
destination remains readable. This is a real mutation seam, not another
projection, but it is not yet invoked by the execution-160 collector.

The compact old generation should use a second Candidate-C reservation/domain,
not a third lane in the source reservation. Candidate-C words already encode a
23-bit domain plus 32-bit index, and the process reservation registry supports
multiple live domains. A second demand-paged 4GiB mapping costs no resident
semispace by itself and allows an unpinned source domain to disappear; a middle
lane would invade every low/high cursor, residency, page-advice, snapshot, and
region-pop invariant while still requiring split closure registries.

The staged V1 may retain the destination as `Option<Box<EvalHeap>>` to prove
two-domain routing before extracting a lean store-only
`EvacuatedGeneration`. It must:

1. route the two hot domains directly in `serial_heap_ptr` and every typed
   getter/mutator, while enumerating both for trace/sweep;
2. keep boxed scalars, typed heads, tail owners, blackholes, and unsupported
   ordinary thunks pinned initially;
3. stream supported permanent objects and plain lambdas/primops through compact
   forwarding records, without the clone-all payload/`HashMap`/frame staging;
4. share existing `Arc<EvalFrame>` identities and rewrite each distinct frame,
   pinned object field, and exact root slot in place;
5. rebuild combined weak indexes from moved plus pinned survivors, clear or
   repair address-keyed caches, reset card/remembered state, then publish the
   new generation.

Cross-domain placement is now implemented as `relocate_plain_to` and
`relocate_plain_to_with`. They validate both allowed-kind sets, require
distinct physical backing, preallocate and register destination capacity, then
rewrite/move/tombstone with the same allocation-free commit. Tests prove
distinct nonzero Candidate-C domains, destination resolution, edge/hash/epoch
preservation, exactly-once drop, rejection before mutation for same backing or
wrong destination kind, and source-domain zero-liveness page advice while the
destination remains intact. The full Candidate-C flat suite passes 40 tests,
including the hole-shadow feature combination.

The next evaluator slice is therefore no longer an allocator primitive. It is
the compact forwarding lookup plus a store-specific plain closure transaction
and two-domain resolver routing.

The first allocation-free two-hot-domain router is now present. The serial
resolver performs two direct domain comparisons, then the existing capacity,
checked-add, and alignment validation; it returns both the pointer and whether
the nursery or evacuated generation owns it. The ordinary one-domain
`serial_heap_ptr` API wraps that result, and both constructors leave the
secondary resolver absent. Production must not install the second resolver
until the destination owner and typed-store routing are installed in the same
transaction: valid address reconstruction followed by a nursery-store lookup
would otherwise reject a moved object. Focused tests cover both domains,
foreign and wrong-tag values, unaligned indices, and truncated end-of-range
words.

The first destination owner is now coupled to that router. An
`EvacuatedClosureGeneration` owns an independent Candidate-C arena and a
non-rewindable closure store. A plain primop transaction rewrites captured
argument edges inside the allocation-free relocation commit, retires the old
slot, and returns the destination-domain value. Construction and movement do
not change heap routing. A separate exclusive install boundary validates the
registered domain/base/capacity and publishes the owner and cached resolver
together; new allocations still target the nursery. Once installed,
`get_primop`, raw-pointer `get_primop_ptr`, and `clone_primop` keep the nursery
probe first and route destination addresses through the evacuated store before
the record fallback. Tests prove rewritten payload preservation, old-source
failure, pre-install isolation, and post-install value/raw/clone resolution.
This is still a one-object transaction, not execution-160 root/edge
publication.

A research-to-accounting audit also rules out treating the remaining gap as one
large forgotten side owner. After repeated stable reuse, the gap is
150,613,288 bytes:

```text
process control                                  454,856,704
- modeled stable-address reuse                    64,656,088
- acceptance target                              239,587,328
= remaining gap                                  150,613,288
```

Plausible non-reservation savings total only about 74.6MB: approximately
32.0MiB of registry capacity, 9.02MiB of weak indexes, 15.1MiB of unreachable
frame storage, 16.8MiB of frontend packing, and 1.64MiB of dead list spines.
Survivor representation remains mandatory.

The substantial alternative to exact reachability evacuation is therefore
**demand-liveness-guided packed immutable generations**. Future-demand and
capture masks would scavenge provably unused frame slots and collection edges,
then write immutable ready subgraphs into headerless 32-bit segment-local
storage. The terminal compact projection is 30.24MiB versus 155.03MiB of live
inline extents, a 124.80MiB representation saving; combined with registry and
weak-index removal it can close the full stable-reuse gap mathematically.
File-backed cold compact pages could additionally leave RSS without semantic
eviction.

This alternative advances only through a no-mutation falsifier at execution
160, 192, and terminal: liveness-filter the exact graph using continuation and
capture plans while failing closed for dynamic/higher-order cases, assign
compact segment offsets, and replay later object/page touches. Its gates are a
whole-process modeled watermark no greater than 226,492,416 bytes, zero
unclassified edges, no old/new packed-copy overlap, and no more than 5% dynamic
demand fallback. Relevant primary work includes:

- liveness collection for lazy languages, including closure-carried demand and
  its first-order limitation: <https://arxiv.org/abs/1604.05841>;
- selective reclamation of shared closure environments:
  <https://kar.kent.ac.uk/21162/>;
- space-efficient closure representation:
  <https://doi.org/10.1145/182590.156783>;
- precise reference counting and reuse in Perceus:
  <https://doi.org/10.1145/3453483.3454032>;
- drop-guided, frame-limited reuse:
  <https://doi.org/10.1145/3547634>;
- transparent 32-bit pointer compression:
  <https://llvm.org/pubs/2005-06-12-MSP-PointerComp.html>;
- optimized handles and pin intervals in ALASKA:
  <https://arxiv.org/abs/2405.00038>.

Two complementary but non-terminal experiments remain. A per-page
allocation-start bitmap plus a generation-bearing tail-owner directory projects
to about 5.45MiB instead of roughly 32MiB of tombstone-heavy registries.
Perceus-style last-use/reuse analysis is credible only inside explicit
whole-demand CFG regions; global reference counting is rejected because Nix
thunks and recursive attribute sets form cycles and the measured force-time
capture-shedding trade already lost speed for only single-digit MiB.

The first soundness audit rejects implementing the global demand-liveness
falsifier from today's metadata. Existing strictness facts are relative to an
execution unit's normal completion, not residual last use at a continuation
PC. Flat capture plans already omit their proven complement at construction,
while shared-chain/dynamic/overflow captures must remain all-live. The GRIN
artifact has no successor graph, kill sets, continuation PCs, or statepoint
live masks, and the recursive tree walker records roots but not the active
program point needed to join them to residual liveness. A probe now would
therefore either report zero new eligible bytes or double-count existing
capture omission/shedding while failing the zero-unclassified-edge gate.

The smallest honest experiment first adds a `ResidualLivenessPlan` keyed by
execution unit and continuation point, then an active runtime continuation
descriptor with frame/transient masks. A default-off probe can classify every
root and edge as proven live, proven terminal, or unclassified and reject any
later touch of a terminal edge. Until that explicit control model exists, the
experiment should be restricted to a closed GRIN/demand-machine region where
all successors and call targets are known; it cannot license global packing.

The two-domain closure owner now also supports the precisely bounded lambda
case. A lambda can move only when it has no inline value tail, dynamic `with`
scope, scoped-global capture, or flat capture base. Those decline doors are
checked before source mutation. The destination retains the existing shared
`Arc<EvalFrame>` identities rather than cloning or rewriting frames per lambda;
eventual publication must repair each distinct frame once. Focused tests prove
destination-domain value and raw-pointer reads, nursery-first later allocation,
and rejection without mutation for unsupported captures.

Selective movement also has a failure-safe temporary publication artifact.
`EvacuationForwardingDirectory` stores one sorted `(source_offset,
destination_offset)` pair per moved object, with shared source/destination
domains, for eight bytes per entry. Its builder reserves the exact capacity
before movement. A sealed append token validates capacity and strictly
increasing source order before the source retires; committing the destination
offset afterward is allocation-free and infallible. If a later move fails, the
completed nonempty prefix can be finalized and published, so no already-retired
source is stranded.

`EvalHeap` can install the destination owner, direct two-domain resolver, and
immutable directory together after validating all domain geometry. Old source
lambda/primop values and raw pointers then route through the destination, while
direct destination words take one range check and ordinary live nursery
closures probe the nursery first. Thus the directory is not searched on the
normal unmoved-closure path. Five closure-generation and seven directory tests
pass.

This is not a production collection door. Precise root scanning, GC and census
walks, snapshots, direct post-assembly mutation, JIT recursion guards, FFI
stack-map bindings, and context-free `Value` decoding can still observe source
coordinates. Raw old/new closure words can also defeat identity fast paths.
The sound short-lived use of the directory is therefore a closed-set healing
transaction:

1. stop at a serial TreeWalk safepoint and prevalidate every root and heap-edge
   writer;
2. compute a complete reverse-edge inventory and remove any candidate with an
   unwritable incoming edge;
3. reserve all destinations and the complete forwarding relation before
   copying payloads, so forward references can be rewritten;
4. stage and commit root, record, permanent-flat, nursery-closure, shared-frame,
   and active stack-map replacements without later allocation;
5. rescan every root, edge, side table, and raw-identity seam and require zero
   old moved coordinates before dropping the directory or advising source
   pages.

At execution 160, the complete closure upper bound is 140,522 objects after
the existing pin rules. Even that deliberately broad bound needs only
1,124,176 bytes of forwarding entries, within the 2,104,118-byte compact
scratch budget and the streaming model's 46,841,856-byte headroom. Permanent
handles are therefore unnecessary as the first design. A stable handle or
offset-vector table avoids the one-time healing scan but permanently taxes
millions of closure resolutions and crosses the Candidate-C carrier, JIT, ABI,
snapshot, and FFI surfaces. Brooks-style source words are worse for RSS because
scattered source pages remain resident.

The exact first-slice census then falsified **closure-first** ordering. On the
execution-160 diagnostic checkpoint it reported:

```text
plain primops                         11 objects       968 bytes
plain lambdas                       966 objects    85,008 bytes
direct-root plain lambdas           220 objects
eager movable closure slice         757 objects    66,616 bytes
alias-forwarded closure slice       977 objects    85,976 bytes
eager net page reduction           -233 pages    -954,368 bytes
alias-forwarded net reduction      -234 pages    -958,464 bytes
```

Allowing the 220 direct-root lambdas to move therefore gains only one
additional 4KiB page. The routing and healing work remains reusable
infrastructure, but this slice cannot materially affect the approximately
205MiB process-RSS gap.

The same census identifies permanent flat data as the next executable class:

```text
movable permanent-flat objects       28,046
movable inline bytes              8,852,528
movable outgoing edges              152,282
additional source pages released      4,453
destination pages                     2,162
net page reduction                   -2,291  (-9,383,936 bytes)
```

Moving forced tail-free flat thunks alone is rejected as an ordering: 23,451
movable thunks release only 74 additional source pages while touching 504
destination pages, a 430-page (1,761,280-byte) increase. Worker objects must
move only as part of page-completing groups after the permanent class or a
full streaming compaction.

These figures came from a diagnostic run that deliberately skipped final
parity because the current dirty source evaluates a different derivation graph
from the freshly primed C++ evaluator and cannot materialize its missing
`.drv` in the read-only store. They classify movement order only; they are not
acceptance memory, speed, or parity evidence. The probe feature also exposed a
silent configuration dependency: its execution-count checkpoint is inside the
otherwise default-off final-config canary. `evacuation_plan_probe` now enables
that detection seam explicitly so a nominal probe build cannot omit the hook.

The next implementation order is consequently:

1. split permanent-flat accounting by strings, paths, lists, and attrsets and
   measure individual and cumulative page completion;
2. build a store-only second-domain permanent generation and physical
   cross-domain movement, beginning with the no-edge string/path subset;
3. add the missing nursery-flat-closure staged write target and run the
   zero-residual-alias healing audit;
4. move permanent objects in the measured page-effective order, then admit
   worker objects only when they complete source pages;
5. reconcile the current C++/native derivation discrepancy before treating any
   mutated run as parity or acceptance evidence.

The subtype census invalidates the apparent no-tail-first implementation order.
The exact execution-160 populations are:

```text
current mover (owned strings/paths/attrs plus lists)
  movable objects                         7,275
  movable inline bytes                  352,896
  outgoing edges                         28,742
  source pages released                      18
  destination pages                          87
  net page increase                          69  (+282,624 bytes)

excluded inline-tail strings/paths/attrs
  movable objects                        20,771
  movable inline bytes                8,499,632
  outgoing edges                        123,540
  source pages released                   1,980
  destination pages                       2,076
  net page increase                          96  (+393,216 bytes)

whole permanent-flat population
  movable objects                        28,046
  movable inline bytes                8,852,528
  outgoing edges                        152,282
  source pages released                   4,453
  destination pages                       2,162
  net page reduction                      2,291  (-9,383,936 bytes)
```

The apparent contradiction is page co-location. Another 2,455 source pages
(10,055,680 bytes) contain both a currently supported object and an inline-tail
object, so neither partial mover can release them. Combining both populations
also saves one destination packing page. Thus strings, paths, lists, and
attrsets must enter the same page-completing collection pass. Implementing and
measuring the no-tail classes as an independent optimization would make RSS
worse and cannot be retained merely as an incremental milestone.

The inline-tail soundness audit also removes the need for a new generic unsafe
rebasing primitive. A fresh, unpublished aggregate generation can copy these
objects through the existing sealed semantic allocation doors:

- inline strings and paths use their byte view, source context, structural
  hash, and last-touch epoch to allocate a new flat-byte witness;
- inline attrsets copy the entry, source-order, and iteration-order arrays
  through a new flat-tail allocation;
- attr value edges are rewritten in place only after the complete forwarding
  directory exists, because forward references may target later objects;
- attr structural hashes are recomputed after edge rewriting because they
  include relocation-sensitive identity bits; string and path hashes remain
  semantically unchanged.

All destination allocation, forwarding capacity, and external-write staging
remain fallible only while the source is untouched and the destination is
unpublished. Publication then installs the aggregate owner, direct two-domain
resolver, and complete forwarding directory atomically before any destination
word becomes externally visible. Root and heap-edge healing is allocation-free.
Source retirement is permitted only after a full residual-alias audit reports
zero old moved coordinates. A post-publication failure is roll-forward: retain
the owner, forwarding directory, and unretired sources and retry healing rather
than attempting rollback.

At execution 160 the complete permanent destination occupies 2,162 pages
(8,855,552 bytes) and its 28,046-entry forwarding directory occupies 224,368
bytes. Even conservatively staging every outgoing edge in a 16-byte record
raises the specific transaction bound only to about 11.52MB, below the prior
46.84MB streaming headroom. This is not yet an acceptance watermark: the
whole-process gate still requires a same-source parity run, and page release
cannot be credited until the zero-alias transaction is implemented.

The derivation discrepancy attached to the diagnostic runs was source drift,
not evidence of evaluator divergence. The pinned C++ prime completed at
04:13:21. Both forwarding Cargo manifests changed at 04:16:26 before the first
native result at 04:25; further source writes at 04:30-04:41 preceded the
04:43 native result; and `evacuation_plan.rs` changed at 04:46:55 before the
04:51 native result. `pkgs.aos.src` is a `builtins.path` over `crates`, so each
change necessarily produces a different source store path and propagates into
the system derivation. The four distinct roots belonged to four distinct input
trees and must not be compared.

Future parity gates freeze one immutable input before invoking either
evaluator. A filtered staging tree excludes `.git` and target directories and
is materialized through the daemon with `nix store add-path`. Comparing a live
tree root with the frozen root is invalid: derivations embed the different
source store path, so the roots differ even when the bytes staged from the
working tree are identical. `aos nix-diff SNAPSHOT/default.nix -A
systems.server.build.toplevel --mode byte` instead compares the pinned C++,
file-backed closure with the native in-memory closure recursively at ATerm-byte
granularity over the same immutable input. Recreating and adding an independent
filtered staging tree afterward must return the same source store path, which
detects edits during the run. This avoids both read-only-store materialization
failures and the weaker retry-based drift mitigation in the live-tree
benchmark. Speed and RSS remain separate acceptance runs over that same frozen
source.

The first corrected frozen gate passed on 2026-07-25. Two independent staging
trees both materialized as
`/nix/store/j7m02a30037ghi5fc8sndlg5sybjbgyn-aos-parity-snapshot`.
With the pinned Nix 2.24.12 oracle, impure evaluation, and an explicit
`x86_64-linux` current system, both evaluators produced
`/nix/store/75ahva6ffllxs86w1jg83fzcr0mlv095-aos-system-toplevel.drv`.
Byte mode reported `matched: true`, no root divergences, and no contaminated
or evaluator divergences. The explicit system is semantically required:
without it, the native evaluator deliberately rejects the unconfigured
CLI-sensitive `builtins.currentSystem` constant rather than guessing ambient
CLI state.

The parity audit found but then measure-falsified another apparent speed
avenue. `source_store_string_cache` is initialized and queried as the intended
C++ `srcToStore` equivalent, but no path inserts a completed result. Its current
key also omits the requested store name, so simply adding an insertion would
incorrectly conflate custom-name `builtins.path` calls. However, the profile
that originally attributed 53% of cycles to this area preceded the fix that
excluded `target-*` build directories from source hashing. In the post-fix
primary toplevel flamegraph, all branches of
`source_path_store_string_from_bytes` total 131.629M of 40.736B instruction
samples (0.32%), and all ring SHA totals 0.83%. The hot `pkgs.aos` path is
filtered and deliberately cache-ineligible. Even impossible elimination of
the whole coercion path would remove only about 44M of the current 13.89B
instructions, roughly a 1.003x improvement. A future correctness cleanup may
key plain coercions by `(path bytes, requested name, recursive)` and insert
only after successful computation, but it is rejected as a current
performance lever.

A longitudinal lower-bound audit also rejects **permanent-only evacuation** as
the terminal memory architecture. In the current post-trie measurements,
execution-160 RSS is 191,307,776 bytes and execution-357 RSS is 436,224,000
bytes, a sustained 244,916,224-byte increase. The accepted peak is 447,762,432
bytes and the terminal sample is only 10,977,280 bytes lower, so this is not a
narrow terminal burst. The exact half-C++ ceiling is 239,896,576 bytes, leaving
a 207,865,856-byte peak gap.

The directly evidenced whole-permanent collection releases 9,383,936 net
bytes. Crediting that entire result still leaves 438,378,496 bytes, or
198,481,920 bytes above the goal. From execution 160 to 357, dense permanent
storage grows by only 19,304,320 bytes. Avoiding every byte of that later
growth in addition to the measured collection win is therefore still two
orders of magnitude short of the remaining gap. Under the comparable
first-slice inference, worker dense storage grows by another 39,418,536 bytes;
permanent plus worker live-inline growth explains only 58,722,856 bytes
(24.0%) of the 244,916,224-byte RSS increase. The other approximately
186,193,368 bytes is fragmentation/dead residency and side ownership.

The existing side-owner upper bounds reinforce the conclusion: about 32.0MiB
of registry capacity, 9.02MiB of weak indexes, 15.1MiB of unreachable frames,
16.8MiB of frontend packing, and 1.64MiB of dead list spines total only about
74.6MiB. These measurements come from related diagnostic revisions rather
than one exact longitudinal run, so they determine collection order rather
than acceptance credit. A time-series probe at final-config executions
160, 192, 224, 256, 288, 320, 352, 357, and terminal must split resident
permanent/worker pages, external capacities by kind, registry/hash capacity,
reachable/total frames, module/frontend bytes, and the compact-overlap
counterfactual. Permanent-only is hard-rejected if even its optimistic
counterfactual exceeds 239,896,576 bytes at any checkpoint; engineering
admission retains the stricter 226,492,416-byte watermark.

The resulting order is:

1. move all reachable permanent kinds together at execution 160 and switch
   later permanent allocation to the aggregate generation;
2. use the exact time series to select whole source-page-completing worker
   groups, never closure-only or forced-thunk-only slices;
3. stream worker movement while rebuilding registries/weak indexes and
   releasing external payloads;
4. validate the actual whole-process watermark against a frozen-source byte
   parity run.

Whole-permanent evacuation is therefore a necessary first page-effective
transaction and a proving ground for healing, but it is not itself a credible
route to the final RSS threshold.

### Worker-memory alternatives after the longitudinal rejection

A separate architecture audit challenged broad worker streaming before it
becomes the default next step. Streaming remains the only currently
peak-admitted movement primitive: the execution-160 overlap model is
192,745,472 bytes, leaving 46,841,856 bytes below the half-C++ ceiling.
However, its conservative execution-357 post-commit is 247,786,618 bytes,
still 8,199,290 bytes above that ceiling. Only an incompletely costed hash and
registry shrink reaches 234,640,186 bytes. The current heap also owns only one
optional compact generation, so repeated collection cannot yet maintain a
compact old generation plus nursery without another generation-management
design.

The ranked challengers and their falsifiers are:

1. **Lifetime-segregated import/demand regions.** Keep stable thunk heads
   outside nested regions, place closure work, frames, and collection payloads
   in region segments, promote only the escaping transitive result, and
   decommit the rest as a unit. This directly targets the approximately
   186,193,368 bytes of execution-160-to-357 growth not explained by dense
   worker plus permanent bytes. The cohort replay must classify every
   allocation and cross-region edge, project a whole-process watermark no
   greater than 226,492,416 bytes, re-promote no more than 5% of bytes, and
   admit no unclassified pre-fence-to-suffix edge.
2. **Residual-demand liveness plus packed immutable Ready generations.** A
   prior projection compresses 155.03MiB of live inline state to 30.24MiB;
   eliminating registry and weak-index identity adds roughly 41MiB. Combined
   with measured stable-address reuse, the modeled process range is about
   218-225MiB. Admission is limited to closed demand-machine/STG regions and
   requires zero later touches of eliminated edges, zero unclassified admitted
   edges, and no more than 5% dynamic fallback.
3. **Selective mark-scavenge/Immix-style block planning.** Segregate objects
   into lines or belts, pin the small direct-root set, and evacuate only sparse
   blocks whose reclaim/copy ratio clears the overlap budget. The exact
   execution-357 census has only 920 direct-root objects pinning 508 pages,
   while all reachable inline data packs into 70,664,008 bytes. This can reduce
   healing scope but still needs structural registry/hash shrink; its planner
   must project at most 226,492,416 bytes with at most 80MB copied, about 6.4MB
   scratch, and collector instructions below 10%.
4. **Effect-proven recomputation and cache eviction.** This remains an adjunct,
   not a primary route. The safely attributable frontend side is only about
   16.8MiB, and forced-tail-free thunk movement alone costs pages. It is
   rejected unless a trace proves more than 100MB peak saving with fewer than
   5% re-forces while preserving the greater-than-2x instruction gate.

Allocator purge or generic stable-address hole reuse remain rejected as
terminal strategies: eager purge saved only about 4.3MiB, the corrected
nonmoving projection remains 30,933,166 bytes above the ceiling, and the
stable-address replay recovered 64,656,088 bytes but left process RSS near
390.2MB. The next time-series run therefore feeds both a lifetime-cohort replay
and a selective-block planner before broad worker movement is admitted.

Mesh-style virtual-page aliasing is also rejected for the current acceptance
metric. It can preserve every virtual `Value` address by copying disjoint line
contents and remapping multiple virtual pages to one physical frame, so it
avoids pointer writeback but still performs physical relocation below the
address abstraction. The execution-357 constructive projection saves only
14,047 pages, or 57,536,512 bytes, below its 15,254-page requirement.
More decisively, the 16,384-alias memfd experiment charged approximately one
page of process RSS per alias even when aliases shared one physical page.
Mesh can reduce cgroup- or PSS-accounted unique physical memory, as measured
in the [Mesh paper](https://people.cs.umass.edu/~mcgregor/papers/19-pldi.pdf),
but it cannot reduce the `ru_maxrss` acceptance measure. Meshed holes also
cannot be reused under the current tombstone/no-address-reuse contract because
an offset dead in one alias may be live in another. No executable Mesh
experiment is admitted unless the goal metric changes.

Pure lifetime regions are also arithmetically insufficient. Even impossible
100% reclamation of the 186,193,368 unexplained bytes gives

```text
191,307,776 - 9,383,936 + 58,722,856 = 240,646,696 bytes
```

at execution 357: 750,120 bytes above exact half-C++ and 14,154,280 bytes
above the 226,492,416-byte engineering gate. Allowing the region experiment's
5% escape/fallback budget yields 249,956,364 bytes and requires at least
23,463,948 bytes of additional structural compression. The credible challenger
is consequently a hybrid: chronological demand/import segments, stable
eight-byte thunk heads, copying escapees into packed Ready generations, and
rebuilding compact registries and weak indexes. Recovering a conservative
25-32MB from the measured approximately 40.98MB registry/index capacity models
224,956,364-217,956,364 bytes; regions alone are hard-rejected.

The first falsifier is a streaming `lifetime_cohort_probe`, not a collector.
It records allocation ordinal/extent/site/region, external capacity, registry
slot, every frame/thunk/capture cross-region write, import boundaries, and
final-config completions. Offline replay checkpoints at executions 160, 176,
192, 224, 256, 288, 320, 352, 357, and terminal must reconcile within 8MiB,
classify every incoming edge, keep promotion at or below 5%, project no more
than 226,492,416 bytes, retain at least 80% packed-Ready occupancy, and charge
less than 10% collector plus 2% barrier instructions. Any later read through
an edge classified residual-dead rejects residual-liveness pruning.

The research base supports this hybrid rather than lexical regions alone:

- Hallenberg, Elsman, and Tofte,
  [Combining Region Inference and Garbage Collection](https://doi.org/10.1145/512529.512547);
- Hallenberg et al.,
  [Combining Region Inference and Generational Garbage Collection](https://elsman.com/pdf/gengc-techreport.pdf);
- Blackburn et al.,
  [The Beltway Framework for Garbage Collection](https://doi.org/10.1145/512529.512548);
- Blackburn and McKinley,
  [Immix](https://doi.org/10.1145/1375581.1375586);
- Zhao et al.,
  [Mark-Scavenge](https://doi.org/10.1145/3689791);
- Kumar, Sanyal, and Karkare,
  [Liveness-Based Garbage Collection for Lazy Languages](https://arxiv.org/abs/1604.05841);
- Sansom and Peyton Jones,
  [Generational Garbage Collection for Haskell](https://doi.org/10.1145/165180.165195).

The publication alias audit also tightens the permanent proving-ground
protocol. Hash-cons tables are weak indexes and must not seed discovery; all
four are rebuilt from translated live entries. Every live worker owner must
heal permanent children, including shared lexical frames, flat thunk fields,
and inline capture tails. Address-keyed cold/stale caches, force-payload memo
entries, remembered edges, and dirty-card sources must be rebuilt or cleared.
Every source flat allocation, including dead weak-only objects, must pass
through `FlatObjectStore::retire` before its registry is replaced and
zero-liveness pages are advised. Merely dropping a store does not decrement the
shared page-liveness ledger. Since ordinary permanent accessors do not follow
the temporary forwarding directory, source retirement requires a zero-old-word
audit rather than relying on lazy forwarding.

The default-off terminal proving ground now implements that transaction behind
`AOS_NIX_PERMANENT_EVACUATE_TERMINAL=1`. It first performs an unconditional
worker sweep, scans only mutator roots plus the result, copies the exact
reachable permanent batch, prevalidates typed root writebacks, installs the
aggregate owner/resolver/forwarding directory, commits staged heap and root
healing, clears address-keyed memo state, re-scans, and retires every source
allocation only after the residual-source audit reaches zero. Its strict gate
requires all evaluator stacks, leases, dynamic scopes, remembered edges, dirty
cards, and native sessions to be empty. Focused Candidate-C tests cover
reachable-versus-weak discovery, worker-to-permanent edge healing, post-publish
precise scanning, zero-alias retirement, continued nursery allocation, and
TreeWalk result-word replacement. This establishes the correctness protocol;
because it runs after the observed peak, it does not receive acceptance memory
credit.

The first full-workload publication exposed and fixed a pre-existing typed
writeback resolution bug. `FlatObjectStore::kind_of` intentionally reports the
header kind of any object in the shared reservation, including objects owned by
another typed store. `heap_field_write_target_for_reference_slot_object`
treated any successful list/attrset-store probe as ownership, so a worker
closure could be misclassified as a list merely because the list store's
shared-region snapshot covered its address. Resolution now requires the exact
`List` or `Attrs` kind, and the focused worker-healing test refreshes the
foreign list-store region index to preserve this regression shape.

After daemon-priming the read-only store, the corpus-scale transaction
completed and produced the exact pinned-C++ root:

```text
/nix/store/1qvq13ghk35bzk2b31plxxc0r28ki2xg-aos-system-toplevel.drv

retired source objects                         279,004
copied reachable permanent objects                 175
healed worker fields                                87
zero-liveness pages advised                     19,739
instructions                            16,379,544,379
peak RSS                                   492,516 KiB
```

Every page-advice request succeeded and the fresh residual-alias audit reached
zero before retirement. The run is nevertheless a decisive performance
rejection for terminal placement: the scan/copy overlap itself created a new
492,516KiB watermark, 51,836KiB above the same-source 440,680KiB native
control. The transaction added 2,385,734,312 instructions to that control's
13,993,810,067 while retirement occurs too late to lower the earlier
evaluation peak. The
transaction remains the correctness substrate for an earlier root-complete
boundary; it is not an independently shippable memory optimization.

The stronger immutable-input closure gate is green with the terminal feature
enabled. Byte mode over
`/nix/store/j7m02a30037ghi5fc8sndlg5sybjbgyn-aos-parity-snapshot/default.nix`
reported `drv diff matched: nix-cli vs aos-nix (Byte)` after the transaction
retired 278,997 source objects, copied 175, healed 87 fields, and successfully
advised 19,776 pages. Thus publication, healing, the zero-alias audit, and
retirement preserve recursive ATerm bytes rather than merely reproducing a
top-level derivation path.

The paired same-source pinned-C++ sample retired 21,044,146,093 instructions
at 467,360KiB RSS and took 10.878s wall, producing the same root. The native
default-off control retired 13,993,810,067 instructions at 440,680KiB with
2.080s evaluator wall time. Native is therefore 5.23x faster by wall, but its
instruction count is only 1.50x lower; the performance claim remains explicitly
wall execution, not a claim of more than 2x fewer retired instructions. The
strict paired half-C++ memory ceiling is 233,680KiB (239,288,320 bytes),
leaving the control 207,000KiB above target.

### Aggregate lifetime-cohort falsifier

The first lifetime experiment is deliberately a census rather than a
collector. The compile-time `lifetime_cohort_probe` feature and strict
default-off `AOS_NIX_LIFETIME_COHORT_PROBE=1` gate admit only the serial,
nonmoving, cache/JIT/memo-off configuration. Selected successful final-config
executions and terminal demand quiescence scan the complete mutator roots,
partition Ready-import and other reachability, reconcile their union, and
attribute inline and known external bytes across every iterable heap store.
The probe records no per-allocation hot-path log. Its interval survival figures
are consequently conservative bounds, and later reads through currently
unreachable residual edges remain explicitly `unknown`.

The focused Linux tests for checkpoint parsing and survivor bounds pass, as do
the four permanent-publication regression tests in the same source state. A
single-checkpoint release run produced the same freshly primed pinned-C++ root,
`/nix/store/k3v5xc9zz9g0raan9wz9n2yi9rrbyyfw-aos-system-toplevel.drv`.
The full checkpoint trajectory was:

```text
execution  total bytes  reachable bytes  unreachable bytes
      160   65,138,360       23,039,048         42,099,312
      176   70,222,368       23,743,080         46,479,288
      192   91,118,720       28,427,912         62,690,808
      224  107,412,600       33,834,440         73,578,160
      256  124,788,432       40,570,680         84,217,752
      288  143,918,352       47,681,656         96,236,696
      320  162,791,520       54,899,424        107,892,096
      352  216,926,784       67,133,368        149,793,416
      357  238,886,264       71,284,688        167,601,576
 terminal  239,226,952          107,096        239,119,856
```

The pre-terminal reachable maximum is only 71,284,688 bytes while unreachable
mass grows monotonically from 42,099,312 to 167,601,576 bytes. At terminal only
107,096 bytes remain reachable. This strongly supports chronological
reclamation and rejects terminal-only cleanup, but it does not authorize
retirement at an intermediate sample: a presently unreachable object may
still be reached through a residual edge before the next sample.

The diagnostic cost is also separated from acceptance evidence. One checkpoint
plus terminal took 16,455,460,517 instructions, 2.058 seconds internal wall,
and 446,084KiB peak RSS. The nine-checkpoint run took 43,671,872,745
instructions, 3.662 seconds, and 468,100KiB. The repeated scans therefore
perturb both instructions and RSS; neither figure replaces the default-off
paired baseline.

Perfectly reclaiming the execution-357 unreachable flat mass from the
440,680KiB control still models 283,654,744 bytes (270.5MiB) before directory,
index, frame, frontend, and allocator effects. The independent layout audit
found a measured
25-32MB realizable registry/weak-index opportunity, enough to supply the
hybrid's required structural adjunct but not enough by itself to close the
211,968,000-byte process gap. Headerless 32-bit Ready segments remain the
factor-level representation candidate. A Nofl-style reusable-hole allocator is
the independent nonmoving challenger; its trace replay must avoid at least
72.9% of post-execution-160 raw growth while keeping average hole probes below
1.2 per allocation and the modeled watermark at or below 226,492,416 bytes.

Phase B must now classify later use without making instantaneous reachability a
death proof. The smallest admissible diagnostic retains cohort identities at a
checkpoint and uses precise later root membership plus non-stamping
last-touch-epoch reads to report resurrection, transient reuse, cold mass, and
unattributed storage at the next boundary. Any touched or resurrected byte is
an escape, not reclaimable mass. Only after all incoming edges and
generation-bearing tail handles reconcile may the existing publication and
retirement transaction move from terminal to an earlier boundary.

The Phase-B residual-retirement shadow window is now implemented under the same
strict probe. An admitted evaluator enables existing per-resolve touch epochs
from construction; default and refused modes retain the ordinary no-stamping
path. Each selected checkpoint inventories exact unreachable stable addresses
and bytes. A new candidate is `Pending`, not cold. At every later checkpoint it
becomes `Cold`, `Touched`, `Resurrected`, `VanishedOrReused`, or `NoEpoch`;
typed heads without generic epochs remain pinned. Hash indexes stay weak, no
reclamation occurs, and the report reconciles both the current unreachable
inventory and the cumulative tracked classification bytes. Ten focused tests
cover pending-to-cold transition, touch without later rooting, resurrection,
changed storage identity, typed-head pinning, byte reconciliation, schedule
parsing, and conservative interval bounds.

The same-source full trajectory produced the freshly primed pinned-C++ root,
`/nix/store/qllqg0wa853p97x5fnla7pac8hg73dcd-aos-system-toplevel.drv`.
The cumulative classification at the important boundaries was:

```text
execution   pending bytes   cold bytes   touched bytes   resurrected bytes
      176       4,381,880   42,073,360          24,048               1,904
      192      16,220,160   46,413,560          57,016              10,616
      224      10,901,696   62,225,816         450,576              24,960
      256      10,642,352   73,112,384         462,792              27,872
      288      12,021,680   83,734,072         480,632              30,696
      320      11,656,392   95,732,848         502,456              31,776
      352      41,905,672  107,161,064         725,352              37,056
      357      17,814,112  149,051,176         735,032              42,936
 terminal      71,476,672  166,859,112         741,208              42,936
```

At terminal, the 167,643,256 bytes tracked before the terminal snapshot split
into 166,859,112 cold bytes and only 784,144 disqualified bytes. Thus 99.53%
remained cold and 0.47% was touched or resurrected, decisively passing the 5%
escape-budget economic gate. Already at execution 176, 42,073,360 bytes from
the execution-160 cohort had survived a later complete-root and touch check.
No captured address vanished or changed identity in this nonmoving run.

The shadow run retired 51,444,164,616 instructions, took 7.369 seconds internal
wall, and peaked at 888,796KiB because it deliberately retains up to millions
of candidate records while performing repeated complete scans. These are probe
costs, not acceptance measurements. The result promotes early chronological
reclamation on economics, but not yet on safety: touch epochs cover ordinary
resolvers, while raw value-word observation between selected final-config
boundaries remains explicitly unknown. The next gate is a complete read-path
audit or instrumentation proving that every semantic object observation in the
admitted serial mode either stamps the epoch or appears in the complete roots.

That read-path audit found ordinary payload accessors well covered but rejected
the selected callback as a collection boundary. The callback runs inside
nested recursive Rust evaluation. `mutator_root_set()` deliberately does not
infer arbitrary Rust locals and, at the time of the audit, omitted even the
evaluator's registered `transient_value_stack_roots`. Those registered shadow
slots are now included and have focused root-source coverage, closing that
specific omission. The final-config fast path itself is still GC-off-only and
recursively allocates the trie result without first suspending all callers into
evaluator-owned continuation state. An intermediate collector there could
therefore invalidate unregistered live Rust values, borrows, raw handles, or
heap-backed local buffers regardless of the retrospective touch result.

One concrete admitted side reference is also missing from the root set:
`genlist_elem_at_add_one_plans` retains
`GenListElemAtAddOneRecipe.receiver: Value` and later dereferences it. This
advisory identity cache should be cleared at a collection boundary rather than
made an immortal root. Weak hash-cons candidates are another expected source:
an exact weak-table hit calls `touch_reusable_value` and may return a formerly
weak-only object into a later root. A real collection must purge dead weak
entries before retiring their objects, causing a later equal value to receive a
fresh identity. The observed 741,208 touched bytes and 42,936 resurrected bytes
are therefore safety failures to attribute and eliminate, not an acceptable
0.47% loss rate. After explicitly handled weak and pinned cases, unexplained
touches and resurrection must both be zero.

The audit also found and closed a diagnostic admission hole: the probe is
constructed before a tier-1 engine can be installed. `set_tier1_engine` now
drops an admitted lifetime probe, emits a refusal reason, and restores the
ordinary cheap-advice-only epoch policy before installing the engine. Useful
intermediate canary execution still has no JIT, and late installation can no
longer leave a nominally admitted probe alive.

The smallest useful next instrumentation records the origin of a watched
candidate touch, distinguishes weak-intern reuse from ordinary semantic reads,
reports the first resurrection root source and predecessor edge, and emits
checkpoint completeness (call depth, transient roots, suspended continuations,
and side-table counts). The architectural fix is a root-complete
evaluator-owned continuation boundary around the hot final-config/demand
sequence. This is now coupled to the earlier performance direction: a guarded
lazy abstract machine or transition-cloned region can remove generic
force/apply/return overhead while making live values explicit enough for early
reclamation. Merely adding the two known missing containers to the current
sample is insufficient because arbitrary recursive Rust locals remain.

The independent root-boundary audit therefore selects a whole-demand-entered
eval/apply/update trampoline as the smallest sound substantial restructuring.
The current path reaches the final-config canary through `eval_root`, recursive
`eval_node` force/apply helpers, and `eval_foldl_strict_primop`. Moving the
sample within that call chain cannot discover caller locals. The replacement
must be entered around the complete instantiation attribute demand, above
`TreeWalk::eval_root`, and retain every heap value in indexed evaluator-owned
slots. Its minimal control vocabulary is `EvalNode`, `Force`,
`EnterThunk`, `UpdateThunk`, `Apply`, `EnterLambda`, `ReturnLambda`,
`FoldlStrict`, `Return`, `FinalConfigCompleted`, and an `OracleCall` leaf.

Existing force and lambda leases plus `StgApplyRuntime`'s value, argument,
update, call, and control stacks supply most of the ownership substrate.
Unsupported work may run through the old evaluator only as one synchronous
oracle leaf; collection remains deferred until that callback fully returns.
The canary records a pending `FinalConfigCompleted` rather than collecting.
Publication may run only when the root loop observes oracle depth zero, no
locally assembled composite operation, and every continuation/value in machine
or evaluator storage. The completed result remains in a machine slot while
advisory identity caches are cleared and dead weak indexes are purged.

The first increment is coverage-only. It must prove that all 357 final-config
completions return to root-complete machine polls. A completion hidden inside a
long oracle callback is not a safepoint; the next implementation step must add
the highest enclosing missing transition. The initial executable set is
ordinary Node/Apply force, simple lambda entry/return, lexical reads, strict
`foldl'`, and update/return. Before any collection it must preserve byte parity,
claims, publications, errors, call depth, module restoration, blackholes, and
panic rollback while materially reducing local generic transition cost. The
machine is rejected if it merely recreates the tree walker as an opcode
dispatcher or leaves the 357 folds inside oracle leaves.

The first default-off root-continuation coverage shadow is now implemented
under the `root_continuation_probe` feature and
`AOS_NIX_ROOT_CONTINUATION_PROBE=1`. It performs no collection or relocation.
Each exact final-config completion snapshots the explicitly registered
continuation counts, while a nested-session counter reconciles pending
completions only when the outer demand returns successfully. Three focused
tests cover successful reconciliation, failed-root abandonment, and nested
`eval_root` returning without prematurely polling.

The initial full run exposed an important boundary error in the design rather
than merely confirming it. A session entered only by `eval_root` reported all
357 completions outside the session: instantiation first evaluates the root
attrset and then forces `systems.server.build.toplevel` through
`eval_instantiation_attr_path`. The root-complete machine must therefore own
the entire attribute demand in `api.rs`; `eval_root` is a nested operation, not
the outer control boundary.

After moving the outer session to that API boundary, a freshly primed paired
run produced the identical C++ and native result
`/nix/store/a67kldq3qp587lzvdxhcx4jbhxr9khf4-aos-system-toplevel.drv`.
All 357 completions occurred inside the one whole-demand session and all 357
reconciled at its successful terminal poll, with zero outside, pending, or
abandoned completions. At completion sites the observed ranges included Nix
call depth 1--102, up to 109 active force roots, five primop frames, and 151
suspended environments. Registered transient roots, composite-accumulator
depth, and order-sensitive-binding depth happened to be zero at those exact
sites.

The coverage run retired 13,994,655,096 instructions, took 2.014 seconds
internally, and peaked at 437,344KiB. This is close to the accepted default-off
control and shows that the counter shadow itself is cheap, but it is not a new
acceptance result. The report deliberately states
`native_rust_continuations=unscanned` and
`mid_evaluation_collection_safe=false`: returning 357 events to one terminal
poll proves outer-boundary coverage, while providing no intermediate
safepoint. The next slice must lift the highest enclosing force/apply/fold
transition out of the recursive oracle callback; only completions reached with
oracle depth zero and all live values in evaluator-owned slots can authorize
chronological reclamation.

An independent alternatives audit keeps the whole-demand machine as the
soundest combined speed/rooting architecture but selects a smaller falsifier
before broad CPS conversion: explicit evaluator-owned shadow frames plus a
nonmoving quarantine. At execution 176, the shadow first builds roots from the
ordinary mutator set and fixed slots for the complete instantiation,
strict-fold, force, lambda-call, import-resume, and primop chain. Candidate-dead
objects remain allocated but every later dereference reports quarantine use.
The prototype is rejected on any unexplained later access or resurrection,
unbalanced error/panic unwind, or more than 10% instruction overhead. Only a
zero-use shadow may advance to nonmoving sweep/reuse, where the first gate is
at least 40MiB of actual RSS reduction and a cadence projection sufficient to
remove roughly 170MiB before peak.

Conservative native-stack discovery is retained only as a possible retention
census, not a collector proof. Safe Rust cannot enumerate register roots;
`stacker::grow` suspends parent segments that its public API does not expose;
and native stack words contain only pointers to local `Vec<Value>` buffers,
not their elements. Scanning all writable allocator mappings would also root
weak caches and advisory indexes and likely preserve most garbage. Ambiguous
roots cannot support moving writeback. The relevant distinction is between
Boehm-Weiser conservative discovery
(<https://doi.org/10.1002/spe.4380180902>) and Henderson's accurate shadow-stack
technique (<https://doi.org/10.1145/773039.512449>). The latter is the closer
model for the nonmoving falsifier; Sestoft and the call-by-need functional
correspondence remain the basis for eventual CPS/defunctionalized update
markers (<https://doi.org/10.1017/S0956796897002712>,
<https://www.brics.dk/RS/04/3/>).

The first execution-176 nonmoving quarantine shadow is now implemented behind
`lifetime_cohort_probe`. It installs only the current unreachable inventory
from the exact execution-176 census, not the probe's cumulative candidate
history, and leaves every candidate allocated. Generic flat objects use an
exact reservation-relative sparse bitmap: a direct 4KiB-page directory and
one 64-byte bitmap for each occupied page. Record-table candidates outside
the Candidate-C reservation use a separately sorted exact address set that is
consulted only by the record semantic door, so record compatibility does not
add binary-search cost to flat hot accesses. Typed heads remain explicitly
excluded until their semantic state probes are separated from scan-only head
classification.

The observer is attached to semantic record touches, flat string/path/list and
attrset reads, attrset metadata reads, closure payload reads, inline closure
capture-tail reads, closure mutation/sharing, allocation-domain/generation
closure inspection, and exact hash-cons identity reuse. It is deliberately
absent from `serial_heap_ptr` (which only decodes a handle), root/census
verification, `flat_verify`, scan-only closure payload access, and
capture-owner reconstruction used by scanners. This prevents the terminal
census from manufacturing quarantine hits against its own candidate set.
Hits are aggregated by origin with 32 bounded first-hit samples and emitted
once at terminal quiescence; there is no per-access output. A late tier-1
installation clears the shadow when it revokes lifetime-probe admission.

Four focused tests cover exact candidate/noncandidate membership, the
out-of-reservation record fallback and typed-head exclusion, scan/self-check
silence, and refusal clearing prior state. The Linux Candidate-C feature check
and focused tests pass. This remains a falsifier, not reclamation: the next
primary run must establish byte parity, zero unexplained generic hits and
resurrections, and less than 10% instruction overhead before any sweep/reuse
mutation is permitted.

The 2026-07-26 full run on `builder-hil1-87eb5b00` rejects that first shadow.
For `/nix/store/d2ymls1pk5da3vklrxw1zgs71gx8qghh-aos-system-toplevel.drv`,
C++ used 21,268,859,432 instructions, 7,902,427,137 cycles, and 467,340KiB
peak RSS. Native used 18,927,893,346 instructions, 7,776,079,339 cycles,
734,884KiB peak RSS, and 3.430562604 seconds internally. Against the accepted
native control (13,994,655,096 instructions, 5,740,888,192 cycles, 437,344KiB,
and 2.013909003 seconds), the shadow regressed instructions by 35.25%, cycles
by 35.45%, RSS by 68.03%, and wall time by 70.34%, far beyond the 10% gate.

The checkpoint installed 425,208 objects and 46,477,936 attributable bytes.
The terminal report recorded 337,735 semantic accesses: 164,734 hash-cons
reuse, 155,877 string/path, 9,889 list, 7,234 attrset, and one closure access.
The lifetime classification found 1,068 touched objects/133,416 bytes, one
resurrected object/72 bytes, and 424,139 cold objects/46,344,448 bytes.
This is a rejection, not reclamation authority. The report also conflated
repeated calls with candidate mass and omitted raw identity comparisons and
identity-bit control decisions. The follow-up adds one centralized checked
identity observer and reports calls, unique objects, and unique bytes per
origin before another full experiment.

The identity-complete, live-graph-only rerun on 2026-07-26 preserves exact
parity at
`/nix/store/wwaxcfgqmg7ym2a0v6v577dcla730s5p-aos-system-toplevel.drv`.
C++ used 21,269,113,990 instructions, 7,925,389,801 cycles, and 466,236KiB
peak RSS. Native used 18,454,301,040 instructions, 7,079,212,428 cycles,
501,648KiB peak RSS, and 1.907794365 seconds internally. The terminal check
now traverses only 991 live objects instead of inventorying the full heap;
one quarantined string/72 bytes is live through `ImportCache { index: 423 }`.
The access report records 381,817 calls but only 1,068 unique hash-cons
candidates/133,400 bytes and 470 unique identity candidates/48,408 bytes.
Payload origins remain comparably small: 794 string/path objects/97,648
bytes, 148 lists/13,872 bytes, 111 attrsets/20,800 bytes, and one
closure/88 bytes. These sets may overlap.

This substantially reduces the diagnostic's memory cost but still rejects
the under-10% instruction gate against the 13,994,655,096-instruction native
control. The next mutation is therefore purge-only: remove checkpoint
candidates from the four weak hash-cons tables and clear the genList recipe
cache while leaving all heap objects allocated. Exact parity plus collapsed
later accesses would attribute the apparent liveness to disposable weak
indexes, but cannot authorize retirement because the one terminal
resurrection and native Rust continuations remain. The production direction
is a hybrid defunctionalized demand machine: final-config completion sets a
pending collection request, and collection occurs only at a dispatcher with
no active native-oracle call. This follows the explicit-control evaluator
construction described by Sestoft and by the functional-correspondence
literature cited above without requiring conservative Rust-stack scanning or
compiler-specific statepoints.

The purge-only rerun on 2026-07-26 validates that attribution. It preserves
exact parity at
`/nix/store/wzrw8zgm2kgwaxj5db4aj71iv16nfc3a-aos-system-toplevel.drv`.
Before installing the quarantine, it removes 4,979 string, 214 path, 24,344
list, and 29,730 attrset candidates from the four weak hash-cons tables and
clears 4,284 genList recipes. It does not retire or reclaim any object.
All later hash-cons, string/path, list, attrset, and raw-identity quarantine
hits fall to zero, as does terminal resurrection. One direct closure payload
access remains: one object/88 bytes.

The paired C++ run uses 21,045,218,259 instructions, 7,815,393,837 cycles,
and 468,232KiB peak RSS. Native uses 18,348,403,751 instructions,
7,027,166,365 cycles, 489,676KiB peak RSS, and 2.087198545 seconds
internally. This is still diagnostic-only: it fails the instruction-overhead
gate and remains above C++ RSS, while the acceptance ceiling for this pair is
234,116KiB. The result authorizes weak-index purging as part of a future
collection transaction, not collection at execution 176. The remaining
closure access and unscanned native continuation still require either
promotion/root ownership or deferral to an evaluator-owned quiescent
dispatcher.

The coarse import-region alternative is also measured before implementation.
With `AOS_NIX_IMPORT_EPOCH_CENSUS=50`, ten sampled depth-one import misses
(ordinals 1 through 451) each allocate only one reachable flat closure/88
bytes inside the fenced dynamic extent and no reclaimable covered object.
Evaluation still preserves the paired `wzrw...drv` root, but the repeated
live-graph diagnostic itself costs 58,804,610,277 instructions and
1,050,628KiB peak RSS. This rejects depth-one import completion as the
profitable region boundary for this workload. A region collector remains
plausible only around selected large force/lambda dynamic extents with a
complete old-to-young publication barrier; it does not replace explicit
continuations at nested final-config completions.

The whole-demand allocation shadow further quantifies the opportunity without
claiming reclamation. Its fence is valid and records 641,222,664 exact arena
bytes plus 194,755,096 known external bytes during root-plus-requested-attr
demand. The largest traffic classes are promises (419,092,408 bytes), frames
(at least 129,796,256), closures (94,723,560), attrsets (90,449,824), and
lists (26,769,984 inline plus 38,456,600 spine capacity). Runtime weighting
sees 5,326,366 force/lambda entries and 1,169,910 unknown-call events.
Planner-site joining covers 3,797,828 allocation events and at least
332,623,016 requested bytes, but these are cumulative traffic/opportunity,
not live, retained, or reclaimable bytes. The class-existence
`virtualizable_requested_bytes_ceiling` and derived
`mandatory_oracle_requested_bytes_lower_bound` are intentionally optimistic
taxonomy bounds and are not memory-savings or fundamental-floor claims.

This diagnostic emitted deterministically twice but the benchmark then failed
while materializing a temporary native derivation in a read-only Nix store, so
it supplies no new byte-parity acceptance result. The output is still enough
to rank engineering attention: Promise/PIR and explicit control target the
dominant allocation traffic, whereas import regions do not.

An exact-door purge rerun identifies the remaining 88-byte access as one
`flat_thunk` resolved through `serial_flat_thunk_payload_ptr`; allocation
domain, generation, lambda, primop, generic thunk, clone, capture, mutation,
weak-reuse, and identity doors all remain zero. Terminal reachability also
remains zero. The paired derivation is exactly
`/nix/store/fy7idj3aymhyy44sfl8f11wrgsybxiid-aos-system-toplevel.drv`;
native uses 18,329,979,019 instructions and 489,468KiB RSS versus C++ at
21,045,763,187 instructions and 466,160KiB. This is direct evidence that a
thunk handle survives in an unscanned continuation after execution 176, not a
weak-index artifact. Collection at that nested callback remains fail-closed.

The existing packed-STG apply executor is not yet the continuation solution.
An initial `AOS_NIX_STG_SESSION=1` run appeared to regress to 39.75 billion
instructions and 1.04GiB RSS, but an exact control showed that this was the
ordinary evaluator without the final-config trie fast path; STG was not the
source of that large discrepancy. With `AOS_NIX_FINAL_CONFIG_TRIE_CANARY=1`
held constant, the no-STG control uses 15,254,554,961 instructions,
6,087,659,880 cycles, 436,600KiB RSS, and 1.637456736 seconds internally.
STG uses 15,420,742,600 instructions, 6,176,401,110 cycles, 436,568KiB, and
1.753071629 seconds, preserving the exact `fy7...drv` root.

All 191,233 STG attempts still decline: 15 blocks lower, 189,770 attempts hit
cached results, and zero thunk claims or machine completions occur. The
controlled overhead is therefore about 1.09% instructions and 1.46% cycles
with no execution benefit. Lowering declines are dominated by unsupported
attrsets and interpolation, while every lowered block contains a currently
non-executable thunk, apply, select, or non-`elemAt` primop opcode. This
rejects enabling the current session machine, but not the architecture. The
next explicit-control slice must preflight cheaply and target measured hot
Promise/PIR entries rather than attempting every Apply thunk.

The relevant implementation literature supports that split. Peyton Jones's
STG machine gives the explicit update/value/control-stack model
(<https://doi.org/10.1017/S0956796800000319>), while Marlow and Peyton Jones
show why known saturated calls and unknown higher-order applications deserve
different apply paths
(<https://www.microsoft.com/en-us/research/publication/make-fast-curry-pushenter-vs-evalapply/>).
The rejected import-region experiment is also consistent with Tofte and
Talpin's requirement that region lifetimes be justified by a type/effect
discipline rather than guessed from a convenient callback
(<https://ropas.snu.ac.kr/lib/dock/ToTa1997.pdf>).

The first executable static-`Select` continuation preserves exact parity at
`/nix/store/8bwjqpldil00rqvs676nsya0mrq80dh2-aos-system-toplevel.drv`.
The paired C++ run uses 21,045,257,740 instructions, 7,692,537,196 cycles,
and 468,780KiB peak RSS. With the final-config trie canary held constant, the
same native binary without STG uses 15,255,617,499 instructions,
6,083,824,737 cycles, 437,108KiB peak RSS, and 1.773430985 seconds
internally. Enabling STG uses 15,415,695,169 instructions, 6,171,712,772
cycles, 436,864KiB, and 1.527066635 seconds. It completes 425 claimed
applications with zero errors or panics, but still adds 1.05% instructions
and 1.44% cycles. The internal wall improvement is not accepted against the
stable hardware counters.

Capability preflight now makes the remaining breadth exact. Seven of the 15
lowered blocks have no disqualifier, five require `Thunk` and `Apply1`
together (bitmap 6), and three require another primop (bitmap 8). There are
186,385 negative-cache hits rather than repeated retained-block scans. This
accepts the `Select` continuation's semantics and falsifies isolated
`Select` as a performance optimization. A combined `Thunk`/`Apply1` slice is
only a bounded breadth falsifier for those five blocks; it is not evidence
that source-opcode expansion can cover the dominant runtime-synthetic
Promise traffic.

The combined `Thunk`/`Apply1` result closes that falsifier. It preserves exact
parity at
`/nix/store/cixjja6pj2p2885ac3cbwgvscpzkkfcs-aos-system-toplevel.drv`.
Pinned C++ Nix uses 21,044,685,164 instructions, 7,737,680,807 cycles, and
468,028KiB peak RSS. The same native binary with the final-config canary but
without STG uses 15,274,125,475 instructions, 6,079,144,966 cycles,
436,048KiB, and 1.681072026 seconds internally. STG uses
15,416,414,418 instructions, 6,177,327,327 cycles, 437,520KiB, and
1.645106483 seconds. It completes 18,376 claims with zero errors or panics,
but adds 0.93% instructions, 1.62% cycles, and approximately 1.4MiB RSS.
Eleven of twelve lowered blocks are now executable; the remaining block is
an unsupported primop. There are 69,780 thunk and 71,320 apply continuations,
but they still delegate lazy argument construction, call protocol, and forcing
to generic evaluator helpers. This rejects further isolated packed source
opcode expansion as the factor-level speed path. Retain the explicit
update/value/control-stack work only as substrate for a callback-free
whole-demand region that virtualizes Promise, frame, and closure allocations.

The feature-matrix control also confirms that compiled diagnostic hooks are a
material secondary cost. After rebuilding both sides against the exact source
and daemon-priming the store, pinned C++, lean native, and instrumented native
all preserve
`/nix/store/am0rgvxmp85c5ypjhlrn6h02qci10fpn-aos-system-toplevel.drv`.
The lean build has exactly `candidate_c_value` plus
`final_config_trie_canary` and uses 14,026,535,915 instructions,
5,747,476,710 cycles, 437,156KiB peak RSS, and 1.780151660 seconds
internally. The same-source build that additionally compiles lifetime-cohort
and root-continuation probes uses 15,275,200,737 instructions,
6,074,144,720 cycles, 437,528KiB, and 1.746288987 seconds. Compiled
diagnostics therefore add 1,248,664,822 instructions, or 8.17%, despite their
runtime probes being unset, and must be absent from the production acceptance
binary.

Pinned C++ for this source uses 21,045,392,473 instructions,
7,711,489,867 cycles, and 466,864KiB peak RSS. Lean native retires 33.35%
fewer instructions and is substantially faster in wall time, but its
437,156KiB RSS remains 203,724KiB above the strict half-C++ ceiling of
233,432KiB. The canary qualification below still applies: this is exact
performance evidence for the structurally specialized fold, not yet a general
evaluator speed claim.

The final-config trie result also needs a stronger qualification. It replaces
the complete `mergedOptions -> finalConfig` fold behind a default-off
compile/runtime canary. The corresponding generic path in the same
instrumented build uses about 39.68 billion instructions and 1.059GiB RSS.
Therefore the 15.26-billion-instruction result cannot establish a general
native-evaluator speedup. Instead, the roughly 24.4-billion-instruction and
622MiB delta identifies the generic order-sensitive attr-fold construction as
the largest current source of avoidable work. The production experiment must
derive an order-preserving attr-fold transducer from structural and effect
facts, with no final-config module/path/name identity guard, and prove lazy
leaf, duplicate-precedence, error-order, dynamic-attribute, and identity
semantics on adversarial non-final-config folds.

The current helper checks are not sufficient to remove the source pin:
`exact_deep_merge_attr_construction` and
`exact_set_path_attr_construction` identify construction sites but do not
prove the complete recursive merge equations. The smallest safe
generalization is a `ratchet-core` certificate over the complete reachable
transducer slice. Canonicalize lexical references to frame coordinates and
SCC-local node numbers, then prove
`foldl' (acc, key -> merge acc (singletonPath(path(source[key]),
leaf(source[key])))) {} (attrNames source)`. The certificate must validate
the full recursive set-path and right-biased deep-merge graphs, not merely
remove helper names from the existing shallow matcher.

Stage this as analysis-only matching, then dual agreement with the current
source-pinned plan, then alpha-renamed/relocated and independently authored
equivalent folds. Runtime preflight must still require the same source for
`attrNames` and entry lookup, exact ready context-free path strings, exact
suspended leaf handles, source-order reconstruction, and no empty, duplicate,
or proper-prefix paths. Colliding paths decline because ordinary deep merge
can force leaves to decide attrset versus non-attrset, making simple
right-precedence substitution observably wrong. Allocation begins only after
all decline doors close.

The attempted bounded Stage-A matcher stops at a real prerequisite rather than
weakening that proof. Lowered lexical reads carry only `(depth, slot)` and the
core currently has no binder-aware def-use slice. A naive DFS fingerprint can
equate different shadowing/capture graphs, while hashing whole enclosing lets
makes unrelated bindings observable. Recursive `deepMerge` and its local
`dedup` also require SCC-aware alpha equivalence. The prerequisite
scope-aware semantic-slice analysis is now implemented in `ratchet-core`. It
resolves lexical reads to binder identities, retains only transitive selected
definitions, exposes recursive binder SCCs, canonicalizes alpha names/slots
and unused binding frames, and preserves semantic lambda depth, attr keys,
shadowing, and recursion targets. Ten focused tests cover those invariants,
malformed lexical coordinates, and retained definitions evaluated in their
owning lexical frame, and the core check passes.

The report-only Stage-A comparison is now implemented too. It builds a checked
reference certificate only after the unchanged exact source-pinned matcher has
accepted, then compares the complete fold plus captured `deepMerge`, recursive
`dedup`, and `setPath` semantic slices. The current primary full graph agrees
with the exact plan, including a recursive SCC in `dedup`. Synthetic
alpha-renaming, slot relocation, and unrelated-helper changes agree, while
reversed merge bias and a changed recursion target decline. The primary
full-certificate test, two mutation tests, twelve core semantic-slice tests, and
the oracle feature check pass. This remains analysis-only: neither execution
admission nor the exact matcher's source pin has changed.

An adversarial audit found and closed one certificate collision before that
admission: formal-set names were serialized separately from first-use binder
IDs, so `{ a, b }: a` and `{ a, b }: b` could canonicalize identically.
Formal names are now explicitly associated with preallocated canonical binder
roles in semantic-name order, while the whole-set alias receives a distinct
role. Tests distinguish element/element and element/alias swaps while
preserving alias alpha-renaming and formal source-order/slot invariance.
The fix leaves exact executable admission unchanged.

Stage B now implements the first distinct source-unpinned dual-admission step
behind strict default-off
`AOS_NIX_FINAL_CONFIG_TRIE_STAGE_B=1`. It initializes its trusted reference by
independently parsing, resolving, lowering, and annotating the bundled primary
source rather than depending on encounter order. On exact-matcher decline, a
candidate must equal all four fold/`deepMerge`/`dedup`/`setPath` role slices,
retain the recursive dedup SCC, and prove that every named helper definition is
transitively selected by the fold binder graph. Only then does it use a
source-guard-free copy of the structural extractor, initially retaining helper
name uniqueness and merged-options slot 7. The exact matcher and its
name/source-byte guards remain unchanged.

Runtime admission additionally validates the operator's module, pattern, body,
frame, and empty dynamic environments before using the existing unpublished
trie construction and preflight. Candidate-only reference boot, relocated and
commented full-source admission, helper semantic mutation rejection, and
operator-body mismatch tests pass; the complete canary module and feature
checks pass too. This proves one algorithmic idiom beyond a path/byte identity,
not general Nix evaluation. The next generalization must derive helper roles
and coordinates entirely from the certified reachable graph, then demonstrate
coverage and declines over an independent corpus.

The broader research map supports the already-measured compact-destination
result rather than collector choice in isolation. Reclaiming dead pages while
retaining the present pointer-rich live layout is not the same as constructing
the measured 22.22MiB compact reachable heap at module 1,220. The
highest-value paired implementation mechanisms are:

- segregated per-kind pools, hot/cold structure splitting, and 32-bit
  arena-relative handles, following
  [Automatic Pool Allocation](https://llvm.org/pubs/2005-05-21-PLDI-PoolAlloc.html)
  and the whole-program heap representation in
  [GRIN](https://research.chalmers.se/en/publication/890);
- young allocation without eager interning, hash-consing only survivors or
  promoted objects as in
  [Hash-consing Garbage Collection](https://www.cs.princeton.edu/research/techreps/115);
- shape/PIC-guarded selection and quickened force/select/apply
  superinstructions, informed by
  [polymorphic inline caches](https://research.google/pubs/optimizing-dynamically-typed-object-oriented-languages-with-polymorphic-inline-caches/),
  [quickening](https://ucsrl.de/publications/ecoop10.pdf), and
  [interpreter superinstructions](https://jilp.org/vol5/v5paper12.pdf);
- whole-demand call-pattern specialization and scalar replacement, following
  [SpecConstr](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/07/spec-constr.pdf)
  and
  [partial escape analysis](https://cgo.org/cgo2014/wp-content/uploads/2013/05/Partial_Escape_Analysis.pdf).

The compact-live layout census has already passed its model gate with
substantial headroom; the remaining proof is executable repeated
evacuation/decommit before RSS crosses half-C++, with destination-first
publication and exact root writeback. A top-demand-site escape/promotion
census still gates demand nurseries: reject them if promotion traffic
approaches reclaimed traffic. In parallel, a survivor-only hash-consing canary
must preserve all measured identity doors while reporting duplicate bytes,
actual reuse, instructions, and RSS. Native trace or copy-and-patch compilation
is deliberately later: it is supported by the
[copy-and-patch](https://sillycross.github.io/assets/copy-and-patch.pdf)
results, but code/cache growth works against the primary RSS constraint until
the representation model closes.

The repeated-compaction audit also closes an unsafe shortcut. Import
milestones and final-config completions can publish a shadow root set, but
they still run inside recursive Rust continuations; measured final-config
depth reaches 102 and native continuation locals are neither completely
enumerated nor writable. Only the post-root terminal boundary currently
satisfies the full quiescence/writeback contract, which is too late to change
`ru_maxrss`. The existing evacuation writer constructs a real private
destination for permanent values, lambdas/primops, and limited serial
synthetic typed thunks, and terminal publication can heal roots/heap/env
edges, rebuild weak indexes, audit aliases, retire sources, and advise pages.
It is nevertheless one-shot: the heap owns one compact generation and
forwarding directory, a second batch is rejected, and ordinary flat thunks,
record workers, boxed-scalar edges, node-shaped typed work, and blackholes are
not relocatable.

The no-collection `CollectionPollGuard` preflight is now implemented behind a
compile-time probe with no production call site. It checks 29 structured unsafe
state classes, then proves unique root sources, raw snapshot/readback equality,
and one mutable writeback target per root. Eight focused tests pass, including
recursive continuation, active STG, transient caller root, duplicate source,
unsupported flat-capture copy, and Ready-import roots; lean Candidate-C
compiles without the probe helpers. This currently proves only idle/Ready-root
states because there is not yet an explicit suspended STG poll. The next slice
must add that dispatcher state after all native locals are spilled, permit its
writable STG value/argument stacks, and invoke the guard there.

Only after the real dispatcher proof should the existing whole-permanent
transaction run at a first pre-peak poll as a protocol test. Actual repeated
reclamation additionally requires generation rotation or whole-heap swapping,
ordinary flat-thunk relocation with handle re-signing, complete address-keyed
cache invalidation, survivor-only rebuilding of all four weak indexes, and
zero residual aliases before source-page advice.

## Post-master exact dedup repair and lean acceptance rerun

Merging current master renumbered `lib/modules.nix` and made the earlier
body-684 dedup pin stale: body 684 is now `builtins.any`. The repaired
default-off canary pins pattern 656, body 705, frame 55, and the body `If` span
`13592..13922` (the enclosing remaining-argument lambda is node 706 with span
`13571..13922`). The cached structural plan additionally requires exact
current `lib/modules.nix` bytes. Five focused tests cover order, empty-list
laziness, non-string fallback, nearby structural rejection, and the complete
current module source.

The exact-source production run takes 10,391 of 10,391 attempts through the
callback-free implementation with no value declines. Against the same lean
binary's generic control, both legs preserve
`/nix/store/7l5kzxqdjrqzz7sv4rf2nd4xrflpx404-aos-system-toplevel.drv`:

| leg | instructions | cycles | peak RSS | internal wall |
|-----|-------------:|-------:|---------:|--------------:|
| generic native control | 34,612,129,451 | 13,159,736,972 | 1,037,036KiB | 4.801853270s |
| dedup canary | 19,183,652,747 | 7,730,817,495 | 634,584KiB | 3.072381629s |

The repaired island removes 44.58% of generic instructions, 41.25% of cycles,
38.81% of peak RSS, and 36.02% of internal wall time. It is therefore a real
whole-demand optimization, not the previously observed stale-pin no-op.
Nevertheless it does not meet either absolute target: versus pinned C++ it
uses 8.86% fewer instructions but essentially equal cycles and 35.71% more
RSS.

The final-config transducer and dedup island are alternatives on this
workload, not additive optimizations. With the final-config canary enabled,
dedup reports zero attempts because the transducer bypasses the generic helper
graph containing dedup. The exact lean rerun is:

| leg | instructions | cycles | peak RSS | internal wall |
|-----|-------------:|-------:|---------:|--------------:|
| pinned C++ Nix 2.24.12 | 21,047,904,475 | 7,716,330,254 | 467,608KiB | n/a |
| final-config lean native | 14,030,054,434 | 5,826,183,736 | 441,080KiB | 1.911070544s |
| final-config plus dedup reporting | 14,059,261,379 | 5,827,028,868 | 442,468KiB | 2.027412770s |

All three legs produce the same derivation path. Lean native retires 33.34%
fewer instructions and 24.49% fewer cycles than C++, but that is only 1.50x
and 1.32x respectively, not greater than 2x. Its 441,080KiB peak is only 5.67%
below C++ and remains 207,276KiB above the strict half-C++ ceiling of
233,804KiB. Reporting the unused dedup canary adds overhead and must stay out
of acceptance runs. More importantly, the source-pinned final-config
transducer still cannot establish a general evaluator speed claim until the
binder-aware certificate safely controls execution beyond this one source.

The fresh post-master whole-demand profile also invalidates the old
984,576-entry body-660 target: body 660 is now only `acc`. The hottest
allocation-bearing entry is `collectDefsAtPath` in module 6, body 632, frame
45, span `12213..13087`, with 84,947 entries, 283,882 guarded calls to six
targets, nine virtual allocation sites, and four monomorphic unknown-call
statepoints. A callback-free implementation requires pre-binding dispatch,
virtual Promise/blackhole/update state, virtual frames and captures, static
select/list/attrs operations, direct primops, and materialize-on-exit support.
The present GRIN shadow planner proves none of those execution contracts, so
no speculative executor was retained.

## Remaining-cost attribution and stable-handle alternative

Sampling the exact lean final-config binary confirms that the remaining
14.03-billion-instruction cost is distributed across the generic lazy runtime,
not one dispatch opcode. Mutually exclusive symbol-family attribution assigns
16.70% of instructions and 14.24% of cycles to environment/frame/capture
protocol, 17.05%/15.19% to eval/force/apply/dispatch, and 12.22%/10.75% to
Promise/closure allocation. Those families total 45.97% of instructions and
40.18% of cycles. Adding attrs/select/string-context work and allocator/data
movement expands the virtualizable surface to 59.65% of instructions and
55.40% of cycles. Hashing consumes another 9.05%/12.34%, with SHA-256 alone at
4.07%/7.30%; ATerm/derivation serialization is 3.05%/1.80%.

The greater-than-2x ceilings are 10.524 billion instructions and 3.858 billion
cycles. A guarded whole-demand transition-cloning compiler that partially
evaluates complete force/apply/return transitions and removes 70% of the
measured virtualizable surface projects 8.17 billion instructions and 3.57
billion cycles. This is qualitatively different from the rejected isolated
STG opcode expansion: it links guarded multi-body regions, virtualizes
Promise/frame/closure/list/attrs state, and materializes only at effect or
escape exits. Existing coverage evidence makes the hypothesis falsifiable:
99.985% of dynamic IR is native or pure-helper work, 93.84% of unknown calls
are monomorphic, 98.10% have at most four targets, and the hottest four caller
entries cover 67.53% of unknown calls.

Before executable transition cloning, a report-only trace-plan shadow must
cover the hottest four callers plus transitive at-most-four-target guards.
Retain the avenue only if it covers at least 60% of instruction-weighted
baseline work, hits at least 98% of guards, exits to effects/oracles for under
5%, and virtualizes at least 70% of allocation bytes. The first
`collectDefsAtPath` caller-SCC executor must then remove at least 70% of
inclusive instructions, 65% of inclusive cycles, and 70% of allocation bytes,
with at least a 4x inclusive cycle improvement. Otherwise the global
projection cannot honestly cross both ceilings.

The frozen hottest-four report rejects that first frontier. Fresh pinned C++
and instrumented native preserve
`/nix/store/i0rk5byd7b3sggnh6ryzpb95jdfb8d32-aos-system-toplevel.drv`.
The shadow selects four roots and twelve linked entries, with zero selected or
global plan failures, twelve valid GRIN fragments, 127 operations, and zero
GRIN failures. Its bounded guards hit 535,207/535,207 observations; after
3,165 conservatively dropped target events the ratio is still 99.4121%.
Effect exits are zero and the effect-or-oracle upper bound is 9,651 events, or
0.1987% of selected operation weight.

The decisive misses are breadth and allocation virtualization. Operation-
weighted coverage is 50.2581%, below the 60% gate, and only 41,410,304 of
250,071,480 attributed allocation bytes, or 16.5593%, match virtual sites,
far below 70%. External-profile attribution covers 4,206,063,936 instructions
(29.9789% of baseline) and 1,622,183,603 cycles (27.8429%). Even perfect
elimination has an instruction floor of 9,823,990,498 but a failing cycle
floor of 4,204,000,133; the realistic 70%-elimination projection is
11,085,809,679 instructions and 4,690,655,214 cycles. Only one of the four
floor/projection gates passes.

The instrumented binary uses 19,449,480,187 instructions, 7,533,916,094
cycles, and 443,204KiB RSS versus fresh C++ at 21,237,243,419 instructions,
7,803,904,272 cycles, and 467,232KiB. Its 2.031-second internal wall is
contended and probe-instrumented. Do not build an executor for the hottest-four
frontier. A report-only frontier sweep may next test whether the hottest
8/12/20 roots actually increase operation and allocation-byte coverage enough
to cross both ideal floors; if the optimistic twenty-root bound still fails,
reject guarded transition cloning as the factor-level route on this workload.

The authoritative frozen frontier sweep now closes that question. Fresh C++
and native preserve
`/nix/store/cmg2hihjiam93gbmi6ybs86i8d50098f-aos-system-toplevel.drv`.
Every frontier has zero selected/global plan failures and zero GRIN failures:

| roots | linked | operation coverage | guard ratio | exit ratio | byte coverage | ideal instructions / cycles | 70% instructions / cycles |
|------:|-------:|-------------------:|------------:|-----------:|--------------:|-----------------------------:|---------------------------:|
| 4 | 12 | 50.2581% | 99.4121% | 0.1987% | 16.5593% | 9.824B / 4.204B | 11.086B / 4.691B |
| 8 | 23 | 56.0612% | 99.4890% | 0.3589% | 22.3382% | 9.338B / 4.017B | 10.746B / 4.560B |
| 12 | 28 | 59.4241% | 99.5147% | 0.3385% | 23.0946% | 9.057B / 3.908B | 10.549B / 4.484B |
| 20 | 53 | 62.4834% | 98.7010% | 0.5964% | 25.2002% | 8.801B / 3.809B | 10.370B / 4.414B |

Top twenty finally crosses both optimistic ideal floors and the 70%-
elimination instruction floor, but its 70%-elimination cycle projection still
misses 3.858B. More decisively, only 25.20% of attributed allocation bytes
match virtual sites, versus the required 70%. The widened trace therefore
fails the combined speed/memory architecture gate. Do not build this guarded
transition-cloning executor from the current Promise/GRIN plan. The probe-
instrumented native run uses 21,009,359,637 instructions, 8,341,090,803 cycles,
and 443,656KiB RSS versus fresh C++ at 21,236,882,792 instructions,
8,152,147,248 cycles, and 466,472KiB; its contended 2.284-second wall is not
acceptance evidence.

For memory, the strict current-source reduction is 212,250,624 bytes:
441,080KiB native minus the 233,804KiB half-C++ ceiling. The accumulated
falsifiers reject reaching that with the current address-bearing layout:
terminal compaction cannot change `ru_maxrss`; sparse survivors pin too many
nonmoving pages; hole reuse saves only about 64.66MiB; weak-index purge about
4.3MiB; permanent evacuation about 9.38MiB; and the combined
registry/index/frame/frontend/list-spine opportunities total only about
74.6MiB. Pointer compression is already present in the eight-byte
Candidate-C value and its 32-bit cage offset.

The stronger alternative is chronological packed generations behind stable
32-bit object handles. Reinterpret the Candidate-C payload as a `HandleId`
resolved through per-kind segmented tables. Keep mutable thunk heads and
suspended work in stable nursery cells, but freeze every immutable object in a
closed allocation cohort into headerless packed generations and atomically
retarget the handles. Suspended native locals remain sound without discovery
or writeback because their handle IDs do not change; packing the complete
immutable cohort also avoids requiring a liveness proof. Existing projections
show enough representational leverage: execution 357 has 525,710 reachable
objects but a dense same-layout destination of 70,664,008 bytes, while the
stronger headerless projection accounts for all named state in 36,221,952
bytes.

The next report-only falsifier projects every allocation suffix at
final-config executions 160, 192, 224, 256, 288, 320, 352, and 357. It must
classify every object as Ready-freezable or mutable/pinned, charge the handle
table, exact compact layouts, source/destination overlap, and page release,
then replay later transitions and report any mutation of projected Ready
objects. Retain stable handles only with zero unclassified objects or illegal
mutations, a modeled process watermark at or below 226,492,416 bytes, at least
212,250,624 bytes peak saving, named state at or below 92.609MiB, no
source/destination overlap breach, and at most 5% handle-resolution overhead.

The first frozen exact-source projection appears to reject this conservative
all-object design, but its absolute watermark is provisional pending the
probe-pollution correction below.
Fresh pinned C++ and native both produce
`/nix/store/i0rk5byd7b3sggnh6ryzpb95jdfb8d32-aos-system-toplevel.drv`; the
earlier `7l5k...` path necessarily changed because the new evaluator sources
are themselves part of `pkgs.aos`. All eight epochs classify every object and
report zero later mutations and zero vanished objects, so semantic
immutability is not the failure.

The byte model passes only the first epoch. Modeled watermark / named state /
projected saving progress as follows:

| execution | watermark | named state | saving | watermark / named / saving gates |
|----------:|----------:|------------:|-------:|:---------------------------------:|
| 160 | 166,047,268 | 47,295,040 | 285,618,652 | pass / pass / pass |
| 192 | 233,118,320 | 65,157,256 | 218,547,600 | fail / pass / pass |
| 224 | 258,020,628 | 76,926,376 | 193,645,292 | fail / pass / fail |
| 256 | 327,723,076 | 89,562,272 | 123,942,844 | fail / pass / fail |
| 288 | 380,390,928 | 103,267,200 | 71,274,992 | fail / fail / fail |
| 320 | 406,976,416 | 117,054,008 | 44,689,504 | fail / fail / fail |
| 352 | 463,393,924 | 155,253,512 | 0 | fail / fail / fail |
| 357 | 568,839,624 | 170,613,056 | 0 | fail / fail / fail |

The gates are 226,492,416 bytes watermark, 97,107,574 bytes named state, and
212,250,624 bytes required saving. Terminal state contains 1,213,908
freezable and 882,852 pinned objects; raw RSS is 552,509,440 bytes and
projected post-publication RSS is 563,008,576 bytes. The diagnostic run itself
uses 25,428,886,738 instructions, 10,771,276,438 cycles, and 574,160KiB peak
RSS; its 3.219-second wall time is contended and not an acceptance signal.
On the initial accounting, stable handles plus packing every immutable object
in the current mixed layout add more persistent/overlap state than they can
release by the peak. Do not implement publication from this model.

The initial postmortem estimates the segregation lower bound as follows. At
the first failure, execution
192, stable handles cost only 6,289,368 bytes. Freezable inline storage is
61,307,752 bytes but only 27,607,040 bytes of source pages can release, so
mixed pages strand about 33.70MiB. Ideal segregation would reduce the modeled
watermark from 233,118,320 to 209,638,640 bytes and pass that epoch.

Terminal handles are still only 16,774,080 bytes. Ideal segregation could
release all 153,110,440 freezable inline bytes instead of 66,686,976 page
bytes, but the optimistic terminal watermark remains 490,898,792 bytes.
Across executions 160 through 357 the ideal-segregation watermark is
166,047,268; 209,638,640; 224,319,916; 288,576,916; 335,860,576;
356,240,192; 406,824,508; and 490,898,792 bytes. It only postpones the first
failure to execution 256. The terminal gap is therefore historical
live/pinned cohort and nonheap growth, not handle-table size or mixed-page
placement alone.

The only remaining packing falsifier is liveness-filtered chronological
generations: charge compact bytes, handles, live weak indexes, and scratch only
for objects reachable from a complete durable root set, and credit extents
owned solely by unreachable old generations. It must report zero missing
roots/edges and remain at or below 226,492,416 bytes at every epoch. The
current recursive Rust continuation prevents that root proof; stable handles
make movement safe but do not make deletion of an unenumerated local safe.
Consequently a liveness-filtered experiment must follow, not precede, a suspended
evaluator-owned whole-demand dispatcher. If even an optimistic liveness oracle
misses any epoch, neither compaction nor file backing can rescue the current
live representation.

However, the raw-RSS cadence used by that model is itself polluted by the
diagnostic. Raw RSS jumps from 435,732,000 bytes at execution 352 to
552,509,440 at 357, while the ordinary lean evaluator peaks near 441MiB. The
execution-352 scan retains a 1.1-million-entry fingerprint vector, constructs a
new large map while the previous roughly 809,000-entry map remains live, and
allocates page/projection tables whose freed pages remain resident in mimalloc.
Because the probe samples raw RSS before the next scan, it mistakes its own
retained diagnostic state for evaluator growth. The 568,839,624-byte terminal
watermark and the derived 490,898,792-byte ideal-segregation watermark are
therefore not final architectural bounds.

The correction is a two-pass protocol: first record the same eight epoch RSS
samples with an allocation-free cadence probe; then run the full projection
using that strict eight-value external baseline for watermark deltas while
reporting, but not modeling, its polluted observed RSS. Only the corrected
watermark may accept or reject stable-handle packing. The semantic result
(zero unclassified objects, mutations, and vanishings) and exact parity remain
valid.

A separate ownership audit finds no hidden production-side nonheap pool large
enough to close the goal. The complete measured frontend is 21,818,125 bytes:
14,147,432 IR/facts, 1,343,488 module-table, 3,645,472 source, 20,819 path-base,
and 2,660,914 symbol bytes. Persistent structural caches are only about
1.44MiB at execution 160. The plausible registry/hash/frame/frontend/list-
spine savings total roughly 74.6MiB, and several components are semantic
identities rather than independently droppable storage: global symbols,
module/IR identities, captured `Arc` frames, Ready import-cache values, and
the 28.269MiB closure registry without value re-signing. There is no sound
non-GC source/module/cache streaming package worth 100MiB.

The diagnostic itself can eliminate over 100MiB of pollution by streaming
sorted fingerprint runs to a temporary file, merging old/current runs
sequentially, reusing page/frame scratch, and purging scratch after each
report. That is useful only to validate the projection. Require the corrected
execution-357 pre-scan RSS to stay within 16MiB of execution 352 while
preserving identical counts and zero mutation/vanish; it does not count as a
production memory improvement.

The two-pass correction is now complete and confirms the architectural
rejection with clean inputs. The allocation-free RSS schedule for executions
160, 192, 224, 256, 288, 320, 352, and 357 is respectively 154,898,432;
207,794,176; 231,075,840; 250,155,008; 297,824,256; 324,829,184;
417,435,648; and 448,720,896 bytes. That lightweight leg uses
14,027,385,308 instructions, 5,889,545,707 cycles, and 442,060KiB peak RSS,
and preserves the fresh `cmg2hi...` C++ derivation.

Feeding that exact schedule into the full projection yields:

| execution | epoch/cumulative watermark | post-publication | projected saving | named state | gates |
|----------:|---------------------------:|-----------------:|-----------------:|------------:|:------|
| 160 | 165,404,196 | 158,735,288 | 286,261,724 | 47,295,040 | all pass |
| 192 | 222,657,136 | 213,017,496 | 229,008,784 | 65,157,256 | all pass |
| 224 | 241,968,404 | 236,663,544 | 209,697,516 | 76,926,376 | watermark/saving fail |
| 256 | 262,182,980 | 255,825,176 | 189,482,940 | 89,562,272 | watermark/saving fail |
| 288 | 310,840,848 | 303,693,520 | 140,825,072 | 103,267,200 | all size gates fail |
| 320 | 337,979,296 | 330,876,464 | 113,686,624 | 117,054,008 | all size gates fail |
| 352 | 445,097,092 | 427,071,016 | 6,568,828 | 155,253,512 | all size gates fail |
| 357 | 465,051,080 | 459,220,032 | 0 | 170,613,056 | all size gates fail |

Classification still passes with zero mutations and vanishings at every epoch.
The first clean failure is execution 224, 15,475,988 bytes over the watermark
gate. The revised perfect-segregation cumulative watermark is 165,404,196;
199,177,456; 208,267,692; 223,036,820; 266,310,496; 287,243,072;
388,527,676; and 388,527,676 bytes. It passes through execution 256 but first
fails at 288 and remains 162,035,260 bytes above the terminal gate. The
corrected conclusion is therefore unchanged but now authoritative: mixed-page
release matters, while only liveness-filtered old-generation retirement can
close the remaining gap, and that requires evaluator-owned root suspension.
The full projection's 25.43-billion instructions and 568,828KiB RSS are
diagnostic pollution and must not be compared with lean execution.

For the final frozen source, fresh C++ uses 21,236,882,792 instructions,
8,152,147,248 cycles, and 466,472KiB RSS. The lightweight RSS-only native leg
uses 14,027,385,308 instructions, 5,889,545,707 cycles, and 442,060KiB. Thus
the current-source lean-class signal is about 1.51x by instructions and 1.38x
by cycles, with RSS still 208,824KiB above the strict current half-C++ ceiling
of 233,236KiB. The stronger 226,492,416-byte projection engineering gate keeps
additional headroom; neither speed nor memory acceptance is met.

File-backing the immutable generations is also rejected without an
implementation. Grant perfect segregation, zero refault cost, and complete
eviction of every prior packed generation before constructing the next. The
modeled watermarks become 165,404,196; 180,402,312; 182,763,180; 194,294,388;
233,662,808; 250,102,328; 346,856,940; and 334,013,084 bytes. Execution 320
still exceeds the 233,236KiB acceptance ceiling by 11,268,664 bytes, and
execution 352 misses by 108,023,276. Even impossibly evicting the generation
being written before its own peak remains 6,738,672 and 95,179,420 bytes over
at those epochs. File backing can remove at most about 54.5MiB of packed
residency; late mutable/pinned and nonheap growth dominates.

Later-use evidence is favorable but immaterial: 166,859,112 bytes appear cold,
with only 741,208 touched and 42,936 resurrected bytes. Since the zero-refault
upper bound already fails, do not add disk-backed mmap, `madvise`, `mincore`,
or refault machinery. It cannot close the peak and would add write/fault cost
against the speed target.

## Whole-demand ownership seam and option-map portfolio

The first target-directed dispatcher slice is implemented behind the existing
default-off collection-poll feature and
`AOS_NIX_WHOLE_DEMAND_DISPATCHER_PROBE=1`. It enters at the complete
instantiation-plus-requested-attr-path boundary, owns value-free control
coordinates, writable value-slot indices, and force/lambda/import lease-token
stacks, and adds a dispatcher-specific token/root/writeback preflight. It
performs no execution substitution, collection, or relocation. Thirteen
focused dispatcher/poll tests and propagated feature checks pass; modeled
storage for the measured maximum stacks is capped below 64KiB.

The exact primary run preserves
`/nix/store/dyv4qhgw9xnlvwp8sr6cbxpwkg1m3p0r-aos-system-toplevel.drv`.
All 357 final-config completions occur inside the one synchronous generic
oracle callback: hidden 357, safe loop-head zero, returned-loop-head 357,
pending/abandoned zero. One loop-head proof accepts and one declines; maximum
control/value depths are one/one and actual modeled storage is 96 bytes. This
is the expected coverage baseline and proves that merely wrapping the API
cannot create a pre-peak collection point. Native uses 13,978,667,218
instructions, 5,803,927,121 cycles, and 435,904KiB RSS versus C++ at
21,010,987,701 instructions, 7,676,994,820 cycles, and 468,336KiB.

The repaired target-directed attr-path slice now substitutes only the outer
`eval_instantiation_attr_path` loop. Root evaluation, formal-set auto-call,
receiver force, list-or-attrs selection, and terminal force remain synchronous
oracle leaves. Current values live only in one relocation-aware transient root
slot; controls contain only kind and segment coordinates. A correctness repair
avoids materializing a root set when no completion is pending and validates
dispatcher `ValueStack` roots against the transient root storage rather than an
empty ordinary stack. Fourteen focused dispatcher tests and eight
collection-poll tests pass, including relocated-root bijection.

The exact repaired run preserves
`/nix/store/dphfrvs78lx22p0csf63znc7p4ghjqxq-aos-system-toplevel.drv`.
Five alternating runs of the same release binary give these medians and
ranges:

| mode | instructions, median (range) | cycles, median (range) | peak RSS KiB, median (range) |
| --- | ---: | ---: | ---: |
| generic control | 13,979,018,382 (13,978,983,408--13,979,277,747) | 5,662,026,896 (5,640,066,372--5,673,680,043) | 438,044 (437,500--438,572) |
| attr-path dispatcher | 13,988,070,561 (13,987,880,898--13,988,144,688) | 5,669,117,064 (5,657,304,785--5,703,720,541) | 438,084 (437,452--440,512) |

The slice therefore adds 9,052,179 instructions (0.0648%), 7,090,168 cycles
(0.125%), and 40KiB median peak RSS. It passes the under-2% instruction and
under-1MiB RSS overhead gates despite noisy individual RSS high-water samples.
All 357 completions are hidden, returned, and exactly attributed: 77 to
`AutoCall` segment 4 and 280 to `FinalForce` segment 5. Conservation is exact;
the safe-loop-head count remains zero, and pending and abandoned counts are
zero. All 18 loop-head proofs accept with zero declines: 16 structural
no-pending proofs and two rooted pending proofs. Maximum control/value-slot
depth is one/one and modeled storage is 504 bytes. Collection remains disabled.

The slice gates pass, but the global goal does not. Fresh C++ on this root uses
21,012,154,512 instructions, 7,799,560,375 cycles, and 466,904KiB RSS. The
dispatcher median is only 1.50x better by instructions and retains 93.8% of
C++ RSS, 204,592KiB above the strict 233,452KiB half-C++ ceiling. The next
expansion must split only the backward continuation path from the two
attributed leaves and monotonically move completions to safe pre-peak loop
heads. Generic leaves that cannot reach the target remain synchronous. Require
zero hidden/outside/pending completions, exact token/root bijection, under 2%
instruction overhead, and under 1MiB RSS before attempting one
liveness-filtered retirement.

A smaller alternative is a private pure-eval `YieldForPoll` propagated to the
API, transactionally aborting active claims, polling after native unwind, and
restarting the requested attr demand through already-Ready thunks. It is not a
general architecture: trace/warn/IFD/time/environment/store/process effects,
parallelism, and observable memo/cache writes must all be absent, and aborted
ancestor work repeats. Only a one-shot epoch-160/192 falsifier is defensible:
effect cursor zero, every lease/blackhole stack empty, exact parity, under 10%
instructions, and at least 40MiB peak reduction. Reject immediately on an
effect-certification decline or replay overhead breach.

The eligibility probe rejects both candidate epochs on the exact primary.
At execution 160, pure mode is false, IFD is active, and the effect cursor is
483: 452 impure inputs plus 31 text-store realizations. There are 51 force
roots but zero owning force leases, five environment frames, 67 suspended
environments, call depth 43, a non-root module, six pending native states, and
no terminal root. Execution 192 is likewise ineligible: effect cursor 581
(550 impure inputs plus the same 31 text-store realizations), 36 unowned force
roots, five environments, 48 suspended environments, call depth 32, a
non-root module, and five pending native states. Neither checkpoint has
transactionally owned rollback state.

All four fresh legs preserve
`/nix/store/l9si086hcad85bzbzmbaa3zmcmf9vqqn-aos-system-toplevel.drv`.
Same-binary control uses 13,978,273,510 instructions and 435,444KiB RSS; the
two-snapshot probe uses 13,982,062,012 instructions and 436,920KiB, only
0.0271% instruction overhead. This is a semantic rejection, not an
instrumentation-cost failure. Do not implement `YieldForPoll` on the primary
workload.

The strongest independent semantic-transducer candidate is the `optionMap`
fold:

```nix
builtins.foldl'
  (acc: decl:
    let key = builtins.concatStringsSep "." decl.path;
    in acc // { ${key} = decl; })
  {}
  allOptionDecls
```

For 4,825 distinct keys, the triangular lower bound is 11,637,900 copied
entries. At the measured 40-byte conservative attr-entry lower bound, that is
465,516,000 bytes of repeated metadata traffic. A report-only, source-
independent binder certificate and post-generic readiness census now exist.
Before any one-pass right-biased builder is implemented, require one admitted
fold with at least 4,000 keys, eight million cumulative copied entries,
256MiB conservative traffic, and completely Ready context-free path strings.
The first run found exactly one structural candidate but exposed an uncounted
semantic-subslice error; that zero-traffic result is a probe defect, not a
hypothesis rejection. The corrected certificate covers the complete outer
operator lambda and adds a full-current-source admission regression.

The defect was the evaluator's symbol-table adoption protocol: live imports
move `ir.symbols` into the evaluator-global table, leaving the module IR's
table empty. Runtime semantic slicing therefore returned `InvalidSymbol`,
while unit-test IRs retained their symbols. `ratchet-core` now exposes explicit-
symbol semantic-subslice and retained-definition APIs; the ordinary APIs still
delegate to `ir.symbols`. Adoption tests require the old path to fail and the
live-table path to produce byte-identical certificates. The option probe and
runtime Stage A/B checks now pass the evaluator's live symbols.

The corrected exact primary census genuinely rejects `optionMap` as a
target-closing executor. It finds one structural and one semantic plan with
zero analysis/reference/certificate/operator declines, and all 357/357 runtime
calls project successfully. Across those folds there are 8,883 elements,
8,883 distinct keys, zero duplicates, and 11,124 path elements; every
readiness/type/context/allocation decline is zero. But the largest fold has
only 219 elements. Cumulative copied entries are 208,711 and conservative
traffic only 8,348,440 bytes (7.96MiB), because the workload performs many
small folds rather than one 4,825-key fold. That is 2.61% of the copied-entry
gate and 3.11% of the traffic gate. Do not build the one-pass optionMap
executor.

The same run confirms the repaired production Stage-A path: fourteen attempts,
one admission, and one exact agreement with zero context errors or certificate
mismatches on the exact candidate. The final-config canary completes 357 folds
and projects all 8,883 entries with zero declines. Native uses 14,067,822,629
instructions, 5,806,983,654 cycles, and 438,352KiB RSS versus C++ at
21,049,030,469 instructions, 7,825,778,387 cycles, and 468,276KiB, preserving
`/nix/store/z2vqjrw09a6djc3xl3aq5qfvzq0c883p-aos-system-toplevel.drv`.

The proposed batched `collectDefsAtPath` inversion is classified
secondary-only before instrumentation. Its complete enclosing hottest-four
frontier accounts for 4,206,063,936 instructions but only 1,622,183,603
cycles. `collectDefsAtPath` is a strict subset, so even perfect removal cannot
reach the required 2.0-billion-cycle opportunity. The only proven virtual-site
allocation is 41,410,304 bytes, 30.85% of the 128MiB gate; exact source-level
batching bytes are unknown, but there is no measured non-overlapping caller or
downstream cycle cost to credit without double-counting. Do not add a low-value
probe or executor unless broader attribution changes that upper bound.

## Full mixed-shape force-corridor census

The Node-only corridor hypothesis is now replaced by a bounded, default-off
full-shape census rooted at the exact dispatcher coordinates `AutoCall`
segment 4 and `FinalForce` segment 5. Fixed-width, value-free coordinates cover
Node, Apply, the `genList` marker, Apply2, Select, and BuiltinAttr suspended
work. Root reconciliation uses each owner's real multiplicity rather than
frame count; typed work is independently bijected. Released or otherwise
unstable positions remain explicitly incomplete. The census stores no
`Value`, raw pointer, span, or string and performs no execution substitution or
collection.

The frozen exact-source diagnostic, default-off carrier, and pinned C++ Nix
all produce
`/nix/store/5fr3s10vh0w5w6a72y4cr5mzlkylq2mi-aos-system-toplevel.drv`.
All 357 target completions conserve: 77 at `AutoCall` segment 4 and 280 at
`FinalForce` segment 5. The bounded result is 208 exact, zero incomplete, 149
overflow, and zero untargeted. Root mismatches, unstable completions, LIFO
failures, and counter failures are all zero. Maximum active depth is 338 of
512. Census backing is exactly 60,928 bytes and combined dispatcher/census
backing is 61,432 bytes, below the shared 65,536-byte cap. The representative
arena fills at 699 of 704 frames and fails closed; capacity must not be raised.

The complete-session shape observations are 307,733 Node, 87,762 Apply, 8,954
`genList` marker, 285 Apply2, and 1,128 Select forces. BuiltinAttr, Released,
unsupported, detached-lease, and typed observations are zero on this workload.
There are 405,862 balanced generic claims and 764,510 already-forced replays.

Fifteen distinct exact chains are already present before bounded overflow, so
the at-most-four modal-recipe gate fails decisively. The eight `AutoCall`
chains have completion/depth pairs `1/5`, `1/31`, `35/18`, `26/29`, `3/29`,
`3/67`, `2/72`, and `6/68`, accounting for all 77 completions. The seven
stored `FinalForce` chains have pairs `51/27`, `29/51`, `11/56`, `1/55`,
`9/50`, `29/36`, and `1/105`, accounting for 131 completions before the
remaining 149 fail closed as overflow. This is too much coordinate entropy for
a generated partial-evaluator recipe selected from four modal corridors.

The diagnostic run records 14,201,554,235 instructions, 5,828,084,477 cycles,
1.424654495 seconds, and 438,088KiB peak RSS. These are single diagnostic
figures, not an alternating overhead result or an acceptance claim. Because
overflow is nonzero, the instrumentation-overhead experiment was intentionally
not run.

The supported next architecture is a hand-defunctionalized mixed-force grammar
that represents the recurring control vocabulary without enumerating complete
dynamic chains. This is a recommendation only; no grammar executor or
transition clone has been implemented. Its eventual acceptance still requires
zero incomplete/overflow completions, exact root/token ownership, exact
default-off and C++ parity, and the existing overhead gates before collection
or liveness-filtered retirement is enabled.

## Ordinal-192 nested nonmoving proof-only inventory

The frozen release probe was run with both ownership doors and the final-config
canary explicit:

```text
cd /home/dylan/codex-rfc0007
nix develop /nix/store/qfjmacfd4np2awbf8s7iyirfqbf21xkb-aos-dev-env.drv -c \
  env CARGO_TARGET_DIR=/home/dylan/target-restart-to-root \
  AOS_NIX_STORE_DIR=/nix/store AOS_NIX_STATE_DIR=/nix/var/nix \
  NIX_REMOTE=daemon AOS_NIX_FINAL_CONFIG_TRIE_CANARY=1 \
  AOS_NIX_WHOLE_DEMAND_DISPATCHER_PROBE=1 \
  AOS_NIX_NESTED_NONMOVING_PROOF_ORDINAL=192 \
  /home/dylan/target-restart-to-root/release/aos \
  --eval-system x86_64-linux --impure-eval nix-bench \
  -A systems.server.build.toplevel
```

The daemon-prime reference and native byte comparator agree on
`/nix/store/nphdfbpq3kqiqpjx29q8qpdkklwpgbl9-aos-system-toplevel.drv`;
both cold and warm legs report `parity=byte:aos-nix`, and the final parity
summary is true. Each of the seven evaluator instances observes 357
final-config completions and makes exactly one conserved attempt at ordinal
192. The non-writeback inventory contains 1,143 roots: one result root and one
transient root, with zero pending flat captures, pending values, pending
environment values, or pending flat owners. Five active environment frames,
48 suspended environments, call depth 32, one IFD state, 550 impure inputs,
and 31 text-store realizations are observed but are not collection
authorizations.

The mixed-force proof is exact at the checkpoint: the session and outer
coordinate are active; all 36 stable generic coordinates have 36 owners and
reconcile 36 expected roots with 36 actual roots. Expected and actual force
leases and typed work are all zero, with no failed-closed, unstable,
nonordinary, or LIFO state. Every other enumerated blocker class is zero.
Nevertheless, the proof refuses with exactly one blocker:
`unshadowed_native_continuation=1`. The probe performs no collection,
relocation, sweep, writeback, replay, or mutation.

This isolates the next safety step. The generic force roots are already
bijective, but the synchronous oracle callback still owns a live native
continuation and its Rust locals. Those values must be moved into explicit,
evaluator-owned native shadow-root slots, with balanced installation and
removal across success, error, and panic, before a nested nonmoving collection
can be considered. Native-stack scanning or treating the reconciled force
roots as the whole root set would not discharge this blocker.

For orientation only, this `nix-bench` invocation reports native/oracle means
of 1.457095/12.154122 seconds cold and 1.275520/12.154122 seconds warm. Its
relative RSS diagnostics are 218.6/436.1MiB cold and 225.1/436.1MiB warm.
These are `nix-bench` relative outputs from this diagnostic run, not a pinned
C++ counter comparison, a global performance proof, or satisfaction of the
RFC speed and half-memory acceptance gates.

## Native-continuation shadow narrowing through batch 3b

A separate, bounded native-continuation shadow now records selected
`eval_node`, `force_value`, and `apply_lambda_value` callers without scanning
the native stack. The first corrected ordinal-192 census found 148 selected
frames: 146 uncovered frames and two already-covered semantic canaries. Exact
IR-site classification had no unknowns. Generic semantic wrappers were then
added only where their post-child live values and cleanup obligations were
audited: Node thunk body, force-node result, apply-lambda portal, lambda body,
let body, interpolation child, interpolation hook force, interpolation
`outPath` force, selected if condition and branch, binary left operand, and
select receiver. Feature-off paths call the original operation directly.

The batches deliberately stopped whenever their predicted gate was missed and
used diagnostic-only call-site markers before converting a site to semantic
coverage. Batch 1 reduced uncovered frames from 146 to 76; batch 2 reduced
them to 29. Batch 3a exposed six exact zero-root call sites rather than
guessing from parent classes. Batch 3b converted only the proven if,
binary-left, and select-receiver sites.

The authoritative batch-3b release was built solely through the pinned AOS
development derivation
`/nix/store/qfjmacfd4np2awbf8s7iyirfqbf21xkb-aos-dev-env.drv`.
The production release check passed; continuation-shadow tests passed 15/15;
the nested-safepoint, root-continuation, corridor-census, and lifetime-shadow
filters passed 6/6, 4/4, 15/15, and 6/6. The exact dual-door ordinal-192 run
returned byte parity with pinned C++ Nix and the same
`/nix/store/2igl8a61abwpbg01g2k86g9zfkqgbqvm-aos-system-toplevel.drv`.

At the final checkpoint, 275 selected frames contain 69 explicit roots and 256
covered semantic frames. Exactly 19 recursive child edges remain uncovered;
there are no uncovered diagnostic or semantic frames, active overflows,
imbalances, unknown classes, root mismatches, unstable coordinates, counter
overflows, or LIFO failures. Shadow storage is 28,136/65,536 bytes and combined
diagnostic storage is 89,568/131,072 bytes. The proof remains fail-closed with
one blocker and performs no collection or mutation.

All 19 residual edges are below direct PrimOp work:

| Parent | Edge | Child | Frames |
|---|---|---|---:|
| PrimOp | `eval_node` | apply | 1 |
| PrimOp | `eval_node` | local variable | 1 |
| PrimOp | `eval_node` | PrimOp | 2 |
| PrimOp | `eval_node` | upvalue variable | 5 |
| PrimOp | `force_value` | local variable | 4 |
| PrimOp | `force_value` | upvalue variable | 6 |

The next step is diagnostic-only attribution at the exact PrimOp child leaves.
It must preserve all 19 uncovered edges and may not confer root coverage until
each leaf's values live across success, error, and panic have been audited.

Batch 4a adds diagnostic-only portals to 29 direct PrimOp `eval_node` leaves,
51 direct PrimOp `force_value` leaves, and four separately named lazy-demand
force leaves. The portals carry no semantic roots and do not authorize their
children. A feature-off facade inlines directly to the original operation;
the 88-byte shadow payload, vectors, counters, panic machinery, field, and
reports remain absent unless `collection_poll_probe` is enabled. The ordinary
Candidate-C-only Linux release check and the feature-off direct-path test pass.
The probe suites pass 17/17 native-shadow, 6/6 nested, 4/4 root, 15/15
corridor, and 6/6 lifetime tests. Exact C++ and native output remains
byte-identical.

The static leaf hypothesis itself failed honestly: only five of the 19
original edges were inside those diagnostic portals at ordinal 192. All five
were `PrimOpEvalChild`; four eval edges and all ten force edges remained bare.
This falsifies static helper enumeration as a complete model of PrimOp
continuations. `Builtin::apply_direct` fans into shared evaluator, coercion,
callable, equality, and lazy helpers, while the shadow's permit model sees only
the immediate active parent.

Batch 4a2 therefore adds a separate bounded direct-PrimOp control stack at the
three central `apply_direct` exits. Central eval and force entry consults this
diagnostic context only after ordinary proof permits and explicit diagnostic
portals decline. One exact structural fallback handles a force that occurs
after the special `with`-variable dialect evaluator returns: it requires no
active context and an immediate uncovered `EvalNode(PrimOp)` parent. Neither
path grants roots or coverage.

The final two-feature release and dual-door run is byte-identical to pinned C++
at
`/nix/store/i5fgiash1nq2rrbwf4g3d1ycf0wzk4db-aos-system-toplevel.drv`.
The original 19 uncovered edges are conserved and have exactly 19 unique
diagnostic markers: nine eval and ten force. The snapshot has 294 active
frames, 256 covered frames, 38 uncovered frames, and 69 roots. Unknown class,
active frame overflow, imbalance/LIFO failure, PrimOp-context allocation
overflow, and context exit-module mismatch are all zero. Sixteen contexts are
active; bounded metadata coalesces 14,239 deeper entries without losing the
outer context or attribution. Modeled shadow storage is 29,416/65,536 bytes
and combined diagnostics are 90,848/131,072 bytes. Collection and mutation
remain false and the proof correctly retains its one native-continuation
blocker.

Batch 4a3 uses probe-only `#[track_caller]` entry points to attach the exact
Rust caller location to each active eval/force edge. The feature-off attribute,
location state, and helpers disappear completely. The exact run preserves all
batch-4a2 counts and gives nonzero source coordinates for all 19 original
edges, with no diagnostic-helper location collapse. Only seven Rust lines own
the residual work:

| Edge | Selected sites | Rust caller |
|---|---|---|
| eval | modules 622/626/627/880, site 33 | `eval_list_map.rs:436` |
| eval | module 4, site 66 | `eval_list_filter.rs:806` |
| eval | modules 295/4, sites 1641/65/211/898 | `builtins.rs:247` |
| force | modules 621/622/626/880, site 5 | `eval_derivation.rs:864` |
| force | module 627, site 5 | `eval_derivation.rs:391` |
| force | module 73, site 326, four frames | `eval_hash.rs:147` |
| force | module 12, site 467 | `eval_source.rs:872` |

The nine eval callers have no pre-child heap `Value` local and therefore admit
a zero-root semantic permit. The force callers do not share one root contract.
The derivation callers retain the current value and all values in the remaining
`IntoIter`; the hash caller retains the current element and the live element
slice; the source caller requires its scalar `out_path`. Batch 4b must publish
those complete bounded composites at the caller lines. Rooting only the force
input, the original list owner, or saturated PrimOp arguments would omit
derived iterator/container locals. Caller-location diagnostics add no coverage
and perform no collection or mutation.

Batch 4b converts exactly those seven audited caller lines to semantic
continuations. The nine eval edges use zero-root permits. The force edges use
bounded manifests for the current derivation entry and remaining entry values,
the current derivation argument and remaining argument values, the current
concatenation element plus its live element slice, and the JSON `outPath`.
Manifest construction exists only with the collection probe. A count above the
4,096-root cap, reserve failure, incomplete builder, or aggregate shadow-cap
failure executes the original child without a semantic parent, preserving Nix
behavior while leaving the proof uncovered.

The authoritative Candidate-C-only release check, feature-off direct test,
23/23 native-shadow tests, 6/6 nested tests, 4/4 root tests, 15/15 corridor
tests, 4/4 lifetime tests, and exact two-feature release all pass. The
dual-door result is byte-identical to pinned C++ at
`/nix/store/wq1izc6d353asl03m05qh9fxrrzz2nw9-aos-system-toplevel.drv`.
All 294 active native frames are covered, uncovered active frames and
diagnostic markers are zero, and 91 native roots reconcile. The seven new
semantic kinds contribute 19 frames and 22 roots: four zero-root `getAttr`
evals, one zero-root map-list eval, four zero-root strict-unary evals, one
derivation-attribute root, four derivation-argument roots, 16 roots across four
concatenation frames, and one JSON `outPath` root. Unknown class, active
overflow, imbalance, PrimOp-context overflow, and module mismatch remain zero.
The nested proof reports zero blockers and `reconciled=true`; collection and
mutation remain false.

A single probe-only runtime rose from 2.0997 to 2.3411 seconds, approximately
11.5%, across changed diagnostic revisions. This is not an acceptance
benchmark, but it prohibits shipping the shadow or manifest path as ordinary
evaluator control. The feature-off facade remains the production path. The
first collector experiment must keep all instrumentation behind its explicit
door and separately measure collector instructions and RSS.

The completed root proof does not authorize the existing worker-only sweep.
That sweep treats permanent flat objects as immortal seeds and retires only
worker records and closures, whereas the historical ordinal-192 census
classified 62,690,808 bytes as logically unreachable across the storage-aware
weak graph. The same-source Batch 4b run did not enable the reclamation census,
so that historical value is an opportunity estimate rather than a current
retirement plan.

The first collector follow-up is therefore a separate report-only retirement
door at ordinal 192. It must retain the actual 1,234-entry non-writeback root
set through tracing rather than discard it after inventory, and report dead
inline and owned-external bytes by store and kind, weak/advisory alias hits,
blackholes, unsupported typed heads and boxed scalars, page-ledger validity,
and simulated wholly-dead resident page runs. The logical admission gate is
at least 48MiB of storage that the exact transaction can successfully destroy;
the physical gate is at least 40MiB of currently resident whole pages that
become advice-eligible. Registry capacity, record slots, typed-head work
storage, and allocator-dependent external-payload release receive no credit
unless the proposed transaction actually and safely releases them.

Ordinal 192 is preferred to 224 even though the later historical census
contains more garbage. The allocation-free RSS trajectory was approximately
154,898,432 bytes at 160, 207,794,176 at 192, and 231,075,840 at 224; ordinal
192 retains about 31.8MiB of headroom beneath the engineering watermark while
224 retains only about 8.5MiB before mark scratch. Earlier executions 160 and
176 classified 42,099,312 and 46,479,288 unreachable bytes and fail the 48MiB
logical gate. The monotonic `ru_maxrss` counter cannot measure an immediate
drop; the report must use current RSS and per-page residency, while a later
fresh-process continued-evaluation run alone decides peak RSS.

The nonmoving avenue is expected to fail the physical gate because mixed live
objects strand dead inline storage. An earlier destructive execution-160
worker sweep retired approximately 20.97MiB of inline extents but exposed only
267 complete pages, about 1.09MiB. A broader immutable packing audit projected
only 27,607,040 source-page bytes at execution 192, still below 40MiB and
already requiring survivor movement. If the exact nonmoving report misses
40MiB, the result rejects page-decommit-only tombstoning for the peak-memory
goal; it does not reject stable-hole reuse or an Immix/Beltway-style selective
evacuation that completes partially live pages.

The corrected same-source report confirms that rejection. Candidate-only and
feature-enabled release checks pass; the focused retirement, nested-safepoint,
and native-continuation suites pass 9/9, 6/6, and 23/23. At ordinal 192 the
planner retains the exact 1,234 explicit roots, augments them with every
excluded retained record and typed-head seed, and weak-traces 207,105 reachable
objects out of 786,211. The supported dead cohort contains 579,106 flat
objects and 62,700,384 logical bytes: 2,719,040 bytes of strings/paths,
2,750,080 bytes of lists and owned spines, 10,593,680 bytes of attrs, and
46,637,584 bytes of closures. The logical 48MiB gate passes.

Only 7,608 of 21,897 resident reservation pages contain no live object. Those
pages form 1,532 runs, the largest 144 pages, and total 31,162,368 bytes. The
40MiB physical gate therefore fails by 10,780,672 bytes. The planner also
reports 81,156 dead weak hash candidates and deliberately keeps
`admitted=false` because the semantic identity/memo side-table audit remains a
separate blocker. That pending audit cannot repair the physical shortfall.
The run performs no purge, retirement, advice, or other mutation and returns
the same `/nix/store/c2fm5wb3xgbvpm6b2gw6xbis2yl2yxhq-aos-system-toplevel.drv`
as the pinned C++ daemon prime. Pure nonmoving page decommit is now rejected;
the next physical-memory experiment must combine stable-hole reuse with
selective survivor evacuation or introduce Immix/Beltway-style segregated
allocation.

The exact permanent-flat page-completion follow-up rejects the bounded
selective route as a primary architecture. With the same ordinal-192 roots and
inventory, the conservative selector moves zero objects and recovers zero
additional bytes. It reports 32,475 hash-reinstall blockers, 122,430
writeback-validation blockers, and 134,382 unstageable incoming edges; direct
roots, unsupported owners and their targets, hash-indexed survivors, closure
tails, thunks, and mixed pinned pages therefore consume the entire otherwise
eligible set. The model also charges a 2MiB destination liveness table,
page-rounded 16-byte destination registry entries, persistent forwarding, and
committed scratch, and it remains explicitly one-shot because the heap owns
only one optional evacuated generation. Its hypothetical target is only the
10,780,672-byte first-slice shortfall, not the roughly 205MiB global deficit.
The report remains fail-closed with semantic purge, destination metadata,
hash reinstall, exact writeback, and repeated-cadence gates false, and performs
no mutation.

Selective page completion may still validate relocation primitives, but the
factor-level memory route is now a rotating whole-domain rollover at an
evaluator-owned root-complete dispatcher. Mutable stable thunk heads and other
pinned identities must live outside the chronological source domain; immutable
survivors and typed work move directly into the compact representation; live
registries and weak indexes are rebuilt densely; and a zero-old-domain-alias
audit precedes unregistering and unmapping the entire source reservation.
Historical execution-357 evidence attributes 167,601,576 of 238,886,264 bytes
as unreachable and projects the 71,284,688-byte live same-layout state to
about 30.24MiB compact. Combining rollover, representation compaction, and the
lower bound of the measured dense-registry opportunity projects approximately
217.6MiB from the paired 451,256,320-byte control. These components came from
related rather than one replayed run, so they justify the next report-only
projection but do not satisfy the memory gate. The projection must replay
checkpoints 160, 176, 192, 224, 256, 288, 320, 352, and 357 from each previous
post-rollover state, charge source/destination overlap and every persistent
metadata class, and keep admission false until writable-root, complete-edge,
hash/tail identity, zero-alias, and fresh-process peak gates all pass.

The closest collector precedent is
[Beltway](https://www.steveblackburn.org/pubs/papers/beltway-pldi-2002.pdf):
FIFO independently collectible increments and survivor promotion match
chronological rollover, but its remembered-edge completeness requirement
means the current 134,382 unstageable incoming edges are a hard blocker rather
than a tolerated residual. [Older-First](https://people.cs.umass.edu/~moss/papers/oopsla-1999-age-based.pdf)
supports delaying collection long enough for very young objects to die, while
[Generational Garbage Collection for Haskell](https://www.microsoft.com/en-us/research/publication/generational-garbage-collection-for-haskell/)
shows that age partitioning remains useful in a lazy updating graph. The
stable-island alternative is
[ALASKA](https://users.cs.northwestern.edu/~pdinda/Papers/asplos24-alaska.pdf)
combined with [Immix](https://www.steveblackburn.org/pubs/papers/immix-pldi-2008.pdf):
stable handles can isolate identity while payloads move into compact blocks,
but ALASKA's reported approximately 8-10% geomean overhead and eight-byte
entry per handled object reject universal hot-`Value` indirection. Handles are
therefore limited to cold payload or unavoidable identity seams unless direct
measurement proves that translation is hoisted out of the fused runner.

The benchmark schema now distinguishes an exact per-child oracle peak from the
legacy `RUSAGE_CHILDREN` watermark. Rust's `Child::wait` reaps with `waitpid`
and exposes no `rusage`; the already-vendored safe `rustix` and `nix` APIs also
provide no `wait4` result. Adding local unsafe FFI solely for measurement would
violate the evaluator's safety bar. Schema v5 therefore records
`unavailable_safe_per_child_wait_api` and never promotes a maximum from a
partially measured sample set; human output labels the old value
`oracle_child_peak_rss_watermark`. The rollover gate must remain false until a
hermetic safe wait4 wrapper, an isolated child self-report, or equivalent exact
per-child mechanism supplies the paired C++ peak.

The static liveness audit rejects blanket conversion of those portals. Of the
29 eval leaves, 20 have no pre-child heap `Value`, six retain exactly one
callable or attrset, and three retain cloned container elements that require
caller-local root manifests and may approach the root cap. The 51 force leaves
span immediate argument forces, sequential strict operands, list/output loops,
and folds; their live state ranges from the current input to callables,
accumulators, remaining iterator elements, output collections, and group
values. `active_primop_arg_roots` is writable for original saturated builtin
arguments, but it does not alias derived locals or cloned containers.

The four lazy-demand diagnostic markers surround an already-covered
`LazyDemandForce` semantic frame. They cannot authorize a `ForceValue` child
because their immediate child is the semantic frame rather than the force
edge. At most they can become explicit root holders with the then-current
value and no expected child; they do not discharge the original 19 PrimOp
edges. Several generic helper paths also need module-aware wrappers:
`force_primop_arg` switches to the argument module before marking, while other
`EvalPrimOpArg` helpers do not. Batch 4b may therefore convert only
runtime-attributed source groups, using caller-local live-root manifests and
leaving every unobserved site diagnostic. This remains a nonmoving proof;
anonymous copied shadow values are not relocation writeback slots.

## Residual factor-speed partition and surviving architecture families

The lean exact run above measures 14,027,385,308 instructions and
5,889,545,707 cycles. Mutually exclusive sampled symbol families attribute
16.70%/14.24% to environment, frame, and capture protocol;
17.05%/15.19% to evaluation, force, apply, and dispatch; and 12.22%/10.75%
to Promise and closure allocation. In absolute terms these measured sampled
partitions are approximately 2.343B/0.839B, 2.392B/0.895B, and
1.714B/0.633B instructions/cycles. Adding the separately attributed attrs,
select, string-context, allocator, and data-movement families brings the
measured virtualizable surface to 59.65%/55.40%, approximately
8.37B instructions and 3.26B cycles. Hashing is separate at
1.27B/0.727B, ATerm and derivation serialization at 0.428B/0.106B, and the
remaining unclassified or nonvirtualized floor at approximately
3.96B/1.79B.

Those are profile measurements, not savings. The following arithmetic is a
projection: removing 70% of the measured virtualizable surface would save
approximately 5.86B instructions and 2.28B cycles, leaving approximately
8.17B/3.61B. That projection crosses the factor-speed ceilings, but no
implementation has achieved it. Conversely, hashing plus serialization has
an optimistic combined ceiling of only about 1.70B/0.83B before charging any
replacement work. The requested factor-speed avenue must therefore remove at
least 57.3% of the combined environment, evaluator, Promise, attrs, and
allocator cycle surface; another local diet cannot close the gap.

Exactly two execution architecture families remain independently plausible:

1. A hand-defunctionalized mixed-force eval/apply machine owns all current
   values, update markers, and roots, then links static multi-entry
   superinstructions over the recurring Node, Apply, `genList`, Apply2, Select,
   and BuiltinAttr grammar. This differs from the rejected isolated STG
   expansion: complete force/apply/return transitions keep environment,
   frame, Promise, attrs, and list intermediates virtual and materialize only
   at effect or escape exits. The outer ownership seam is
   `tree_walk/whole_demand_dispatcher.rs`; force/update ownership begins in
   `tree_walk/alloc_intern/force_thunk.rs`; node entry is in
   `tree_walk/eval_core/stack.rs`; and eval/apply plus frame installation is
   in `tree_walk/eval_primop_apply.rs`. The explicit-machine and calling-
   convention basis is Sestoft's call-by-need machine and
   [From Push/Enter to Eval/Apply by Program Transformation](https://arxiv.org/abs/1606.06380);
   call-pattern specialization follows
   [SpecConstr](https://www.microsoft.com/en-us/research/wp-content/uploads/2016/07/spec-constr.pdf).
2. Interpreter partial evaluation specializes a small safe explicit machine
   with module IR and a binder-aware semantic certificate. It must specialize
   complete force/apply/update basic blocks, promote bounded call targets,
   scalar-replace virtual heap state, and side-exit at effects, rather than
   specialize source bytes or complete observed traces. The analysis anchors
   are `ratchet-core/src/analysis/semantic_slice.rs`,
   `analysis/promise_region.rs`, `grin_region.rs`, and `stg.rs`; the semantic
   source of truth remains the same force, node, and apply seams as the
   handwritten family. This direction follows
   [Partial Evaluation, Whole-Program Compilation](https://arxiv.org/abs/2411.10559),
   whose reported interpreter-specialization result motivates the avenue but
   does not predict this evaluator's result, and uses bounded unfold/fold
   discipline from
   [A Positive Supercompiler](https://www.cambridge.org/core/services/aop-cambridge-core/content/view/4EEE2EBC972AA2FDC861EF7A713EE898/S0956796800002008a.pdf/positive_supercompiler.pdf).

Both families must pass the same report-only weighted gate before an executor
is built: cover all 357 completions with zero incomplete, overflow, unstable,
root/token, or LIFO failures; use no more than 64KiB session metadata; cover at
least 60% of baseline instructions and 55% of baseline cycles; keep weighted
effect-or-oracle exits below 2%; and classify at least 70% of attributed
allocation bytes as virtualizable. The first executable slice must preserve
exact default-off and C++ parity, add at most 2% whole-process instructions
and 1MiB RSS when it declines, remove at least 70% of its inclusive
instructions, 65% of its inclusive cycles, and 70% of its allocation bytes,
and improve its inclusive cycles by at least 4x. Collection remains forbidden
until hidden, outside, and pending completions are zero and all 357
completions occur at an owned safe loop head.

The old top-20 trace cannot seed either family: its 25.20% allocation-byte
coverage and 4.414B-cycle 70%-removal projection fail those gates. Static IR
blocks and explicit grammar states must replace exact dynamic-chain recipes.
A complete semantic producer-to-consumer fusion spanning `deepMerge`, dedup,
`collectDefsAtPath`, `setPath`, and final-trie publication remains a
report-only contingency, not a third surviving architecture family. It may be
promoted only if exclusive allocation provenance directly attributes at least
3.7B instructions, 1.9B cycles, and 200MiB traffic to the complete pipeline,
with at least 95% producer-consumer coverage and zero effect, context,
duplicate, prefix, or order declines. The standalone `collectDefsAtPath` and
`optionMap` bounds already fail, so their costs must not be added twice.

Hash-consing and maximal sharing are rejected as a factor-speed route.
The maximal-laziness census found repeated successful bodies at only 77 ppm
of Node-body time and a 4.52MiB avoidable-record lower bound. Existing weak
indexes are purgeable collection metadata, not an independent speed
opportunity. Appel and Goncalves likewise identify the per-allocation lookup
cost and motivate survivor-only rather than eager hash-consing in
[Hash-Consing Garbage Collection](https://www.cs.princeton.edu/~appel/papers/hashgc.pdf).
Survivor hash-consing may compose inside a future owned collector, but receives
no factor-speed credit without a new nonoverlapping census that alone reaches
3.7B instructions and 1.9B cycles. The exact dedup canary is also real but
nonadditive: the final-config transducer bypasses its helper graph, so its
generic-control saving cannot be subtracted from the current 14.03B run.

## Staged mixed-machine specialization decision

The two surviving speed families are sequential rather than competing
implementations. The first stage is a small, exact mixed-force abstract machine
that is the sole owner of value, argument, update, call, and control stacks.
Only after that machine owns force/apply/update continuations and their roots
may a partial evaluator specialize it into program-point superinstructions.
Specializing `TreeWalk` directly is rejected: its callback, borrow, error,
panic-cleanup, and effect boundaries would duplicate semantics and multiply
specialization contexts before native-continuation ownership is explicit.

The machine uses an immutable packed module tape with fixed-width hot PCs and
opcodes, cold span/capture metadata, and virtual Promise, Closure, Frame, List,
and Attrs objects. Its finite transition vocabulary includes enter, force
claim/blackhole/WHNF, eval, exact/under/over apply, update, return, guard call,
select, virtual allocation, and materialize/side-exit. This is a recursive
grammar, not a table of the 15 observed chains: the mixed census has a maximum
depth of 338 and 149 bounded-representative overflows, so chain enumeration
would be neither complete nor bounded.

The specialization clone key is the machine-format and semantic-certificate
versions, module content digest, entry/body IR identity, lexical frame,
versioned capture layout, machine PC/control kind, an at-most-four target
callee set, and effect/dynamic-scope mode. It excludes runtime addresses,
string values, dynamic list lengths, observed branch outcomes, and force-chain
history. State is virtualized as SSA values or block parameters, with
generalization at force, update, and call loop headers to prevent the
block-parameter and clone explosion reported by
[weval](https://arxiv.org/abs/2411.10559). Effects, unsupported dynamic scope,
errors, and unbounded calls materialize and side-exit to the one interpreter
implementation.

This ordering is evidence-driven. Ertl and Gregg report a 1.74x elapsed-time
result for real Gforth superinstructions and up to 3.17x only when combined
with replication in
[The Structure and Performance of Efficient Interpreters](https://jilp.org/vol5/v5paper12.pdf).
Weval reports 2.17x for SpiderMonkey and 1.84x for Lua, with state
virtualization supplying a material part of the SpiderMonkey result. Those
results do not predict Ratchet's speedup, but they reject dispatch removal as
the sole hypothesis. The Ratchet target requires removing at least 57.3% of
the measured virtualizable cycle surface, so complete state ownership and
scalar replacement are required parts of the experiment.

Before any executor is built, a report-only weighted grammar census over both
`AutoCall(segment=4)` and `FinalForce(segment=5)` must attribute mutually
exclusive Force/Eval/Apply/Update/Return intervals and allocation provenance
for all 357 completions. In addition to the existing root, token, LIFO,
metadata, exit, and parity gates, it must prove at least 5.286B inclusive
instructions, 2,923,076,924 inclusive cycles, and 200MiB of traffic without overlap
with final-trie or dedup savings, and classify at least 70% of attributed
allocation bytes as virtualizable. The inclusive floors are the opportunity
required to deliver 3.7B instructions at 70% elimination and 1.9B cycles at
65% elimination. The cycle floor is approximately 89.7% of the measured
3.26B-cycle virtualizable surface, so a genList-only, PrimOp-only, or handful-
of-corridors executor cannot pass. The census must use bounded streaming
interval counters rather than store traces and remain within the 64KiB
diagnostic budget.

The first executable must not be a generic-dispatch performance milestone.
The corrected explicit local machine added approximately 373.7M instructions,
the packed STG breadth experiment with 18,376 completions still added 0.93%
instructions and 1.62% cycles, and the best callback-heavy marker session
saved only approximately 320M instructions. Generic machine semantics remain
the reference and root-ownership model, but the first executable slice must
pair that model with a static generated runner and one broad
force-enter-apply-update-return fusion over the complete admitted grammar.
It must preserve exact C++ parity, hit its guard at least 98%, keep weighted
exits below 2%, and improve inclusive region cycles by at least 4x while
removing at least 70% of inclusive instructions, 65% of inclusive cycles, and
70% of allocated bytes. A declining path is capped at 2% whole-process
instructions and 1MiB RSS. Prototype hot code is capped at 256KiB,
specialization scratch at 8MiB, and specialization CPU at 2% of benchmark
evaluation unless served from the content-addressed cache. Only after this
fused runner passes should weval-style partial evaluation generalize its
specializations. These are experimental rejection budgets, not evidence that
the global greater-than-2x and half-C++-memory goals have been reached.

### Report-only mixed-machine opportunity census

The first bounded implementation now streams mutually exclusive
Force/Eval/Apply/Update/Return phases beneath the exact
`AutoCall(segment=4)` and `FinalForce(segment=5)` leaves. Phase tokens live in
the caller's native stack frame and restore the previous phase by generation
and depth; the census stores no event trace. Exact worker- and permanent-arena
cursors are flushed at every phase transition, so allocation traffic is
attributed to one phase only. Materializing exits are not inferred from a
heap-valued result tag: that would confuse an existing heap value with a new
virtual-object escape and miss effects returning scalars. The classifier
therefore remains explicitly unavailable until transition sites carry exact
materialization/effect provenance. The existing full-corridor coordinates
supply the at-most-four-targets/site calculation without another target table;
the identity includes outer mode, shape and execution flags as well as the
payload. Fixed counters are charged to the existing 64KiB dispatcher budget.

The inherited hardware-counter protocol is factored into a process-local
exclusive window controller. It opens the existing control and acknowledgement
descriptors once, then sends acknowledged `B`/`E` toggles around the two target
leaves. Its state distinguishes closed, open, and indeterminate-after-write:
a failed acknowledgement never causes `Drop` to replay a possibly delivered
non-idempotent command. This prevents competing acknowledgement readers but
does not create evaluator/session/window provenance for the one-byte wire
format, so exact PMU attribution remains unavailable.

This is still fail-closed evidence, not an accepted speed opportunity. The
evaluator reports window balance, all 357 completion and structural gates,
exclusive arena traffic, the mixed-phase virtualizable-byte candidate ceiling,
materializing exits, and target fanout. Allocation-kind provenance is not yet
joined, so the 70% virtualizable-byte gate also remains false rather than
treating every byte allocated during an evaluative phase as removable. The
inherited pipe currently returns only an acknowledgement, not the accumulated
instruction and cycle values. Until the external wrapper joins those exact
values and allocation-kind evidence to the report, inclusive
instructions/cycles and the 70%/65% absolute savings gates remain zero and
false with the explicit
`exact_external_pmu_counts_and_allocation_kind_provenance_not_joined` blocker.
The PMU interval is also explicitly instrumentation-inclusive and lacks a null
overhead control; feature-off code-generation neutrality is unmeasured. Return
entries and exits now conserve on success and error, cursor regressions and
aggregate overflow fail closed, and the corrected cycle floor no longer falls
50,000 projected saved cycles short. No estimate is substituted, no generic
executor exists, and no `TreeWalk` specialization is enabled.

## Rotating-rollover runtime checkpoints and stable-head ruling

The merged-revision runtime producer samples the fixed successful-final-config
schedule `160,176,192,224,256,288,320,352,357`. Process RSS and reservation
residency are sampled before roots or traversal scratch. A weak traversal is
selected for exactly one ordinal per process with
`AOS_NIX_ROTATING_ROLLOVER_TRAVERSAL_ORDINAL`; this prevents an earlier
`HashSet` traversal from leaving allocator-resident scratch in a later RSS
checkpoint. Every run retains nine bounded scalar snapshots, while only the
selected checkpoint records the named-root liveness lower bound. The producer
constructs no replay input and cannot call admission, collection, mutation, or
memory advice.

The isolated selected-ordinal runs produced:

| Ordinal | RSS bytes | Reservation bytes | High lane bytes | Reachable | Allocated | Unreachable |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 160 | 186,916,864 | 64,166,264 | 44,620,584 | 173,529 | 555,842 | 382,313 |
| 176 | 194,035,712 | 69,183,552 | 48,670,056 | 179,265 | 604,474 | 425,209 |
| 192 | 239,325,184 | 89,688,264 | 63,135,840 | 207,105 | 786,221 | 579,116 |
| 224 | 262,377,472 | 105,828,376 | 75,059,704 | 249,476 | 930,264 | 680,788 |
| 256 | 300,552,192 | 123,032,512 | 87,046,424 | 304,498 | 1,077,029 | 772,531 |
| 288 | 332,034,048 | 141,930,232 | 100,195,720 | 360,395 | 1,238,741 | 878,346 |
| 320 | 359,100,416 | 160,609,496 | 113,039,048 | 417,760 | 1,396,324 | 978,564 |
| 352 | 448,000,000 | 213,838,776 | 153,507,328 | 500,821 | 1,889,905 | 1,389,084 |
| 357 | 472,936,448 | 235,556,496 | 171,019,136 | 525,718 | 2,096,930 | 1,571,212 |

The ordinal-192 liveness result exactly repeats the independent retirement
census: 207,105 reachable objects out of 786,221. This validates the lean
traversal, but not moving-root completeness. Each checkpoint still has between
one and fourteen safepoint blockers. At ordinal 192 the native-continuation
shadow reconciles, but the force proof finds 36 active force roots outside its
owned session. Those values are present in the non-writeback root set, so the
reported reachability remains a useful lower bound; their writable provenance
is not proved, so rollover admission remains false.

These measurements reject direct age-arena movement as the first executable
memory slice. Several anonymous or unsupported root kinds still lack writers,
the page-completion census found 134,382 unstageable incoming edges, and
old-domain alias absence and unmap remain unproved. The largest sound first
lever is instead stable serial thunk identity with movable or reclaimable work
payloads:

1. Broaden the existing headerless stable thunk heads and ABA work handles
   from Apply/genList to the dominant ordinary Node, Apply2, Select, and
   builtin-attribute shapes.
2. Allocate shape-sized work in chronological segmented pools. Successful
   update preserves the one-word head identity while releasing its suspended
   work; empty work segments can then be decommitted without rewriting a
   `Value`.
3. At a zero-blackhole and zero-typed-work-lease dispatcher boundary, rotate
   surviving work into a new payload generation, atomically retarget heads,
   audit old handles, and unmap the old work segments.
4. Eliminate the parallel 16-byte-per-entry flat closure registry as heads
   become the authoritative identity table, and rebuild survivor-only weak
   indexes during later whole-source publication.

This ordering follows the measured economics. The high/closure lane grows from
44,620,584 to 171,019,136 bytes while flat closure identities grow from
472,772 to 1,818,236. Eight-byte heads for the final identities occupy about
14.55MB before live work, and eliminating their flat registry attacks roughly
another 27.7MB. By contrast, weak purge alone previously saved about 4.3MiB,
and the combined registry/index opportunity is only around 41MiB. Dense
registries and survivor weak indexes are required adjuncts, but cannot replace
stable-head payload reclamation as the primary architecture.

The final selected run also has approximately 226MiB of RSS outside the
Candidate-C reservation. That is already near the entire strict half-C++
budget before charging any rollover destination. Therefore stable payload
reclamation alone is necessary but not sufficient: late rotations must also
remove the flat identity registry, shrink weak indexes, and reduce other
process-owned caches. No component projection is promoted to the global memory
gate until a current exact paired C++ peak and whole-process measured RSS prove
the strict inequality.

### Broad stable-head implementation and overlap rejection

The source already admitted every plain serial thunk shape behind the
historical `AOS_NIX_TYPED_THUNK_HEADS=apply` spelling, but it was incompatible
with the retained final-config transducer. The transducer's forced-chain peek
read the compatibility `EvalThunk` cell, which is deliberately
non-authoritative for a stable head. Consequently all 357 structurally
admitted folds declined and the evaluator returned to the generic path. That
explains an initially attractive but nonadditive generic-path result: broad
heads saved roughly 229-237MiB there, while the process executed about 34B
instructions. It did not describe the 14B optimized evaluator.

The implementation now reads authoritative typed-head publication state
before falling back to an ordinary thunk cell. A focused chain test proves
that a forced typed outer head followed by a suspended typed inner head
declines, then returns the terminal value after the inner publication. The
dominant ordinary Node suspended work also uses its own generated-handle domain
and a smaller shape-specific slot; dynamic-scope and extended Nodes safely
remain in the general pool. Existing stable identity, ABA rejection,
take/restore on error and panic, edge scanning, update publication, and
post-success work release remain intact.

The clean exact-source optimized comparison is:

| Mode | Instructions | Cycles | Peak RSS KiB | Result |
| --- | ---: | ---: | ---: | --- |
| final-config control | 13,923,540,932 | 5,486,448,061 | 464,660 | `d0j2pv...` |
| final-config + broad shaped heads | 13,984,011,424 | 5,572,274,112 | 439,804 | `d0j2pv...` |
| current C++ Nix | 21,015,134,294 | 7,702,849,500 | 467,012 | `d0j2pv...` |

The typed run preserves all 357 callback-free executions and the byte-identical
derivation. It saves 24,856KiB (24.27MiB), but adds 60,470,492 instructions
(0.43%) and 85,826,051 cycles (1.56%). The strict memory ceiling is below
233,506KiB, leaving the typed run 206,298KiB above it. Therefore broad shaped
stable heads are a useful retained component, but the generic-path
approximately 236MiB result mostly overlaps the final-config transducer and
must not be added to its saving. Stable heads are rejected as the primary
factor-memory architecture on the optimized workload.

The evidence restores rotating liveness-filtered retirement as the primary
memory task. Stable heads remain useful for work payloads whose identity makes
direct movement expensive, while direct immutable values, registries, weak
indexes, and nonheap owners require whole-source rotation or independent
compaction. The next rollover slice must close writable-root provenance rather
than project the already-rejected stable-head saving a second time.

### First writable native portal and stable-handle alternative

The first real writable native-continuation portal now covers
`ForceNodeResult -> ForceValue`. Its caller-live thunk is copied into the
indexed transient root stack, the recursive force reads that slot, and the
outer loop reloads the copied-back value before identity observation or the
raw-equality decision. The semantic continuation shadow carries no duplicate
`Value` for this portal. Transient-root writeback now also copies back before
resuming a panic, because a same-frame catch would otherwise make a relocated
caller array stale. Success, error, and panic tests prove writeback and balanced
transient/native stacks; all 24 focused native-continuation tests pass.

The current release's separate ordinal-192 nested-nonmoving run conserves all
357 completions in each of seven evaluator instances and reports zero runtime
blockers, no root error, 1,234 named roots, 24 transient roots, 68 diagnostic
native-shadow values, and the exact 36/36 generic-force root reconciliation.
Cold and warm comparisons retain `parity=byte:aos-nix`. This is intentionally
only a nonmoving proof. Other native continuations still retain read-only
diagnostic copies, and the force implementation can retain decoded pointers,
borrowed thunk payloads, guards, and cloned payload state across recursive
evaluation. The green proof does not authorize moving those heads or retiring
their domain.

The refreshed ordinal-357 rotating lower bound contains 2,096,963 objects:
25,590 string/path, 105,978 list, 147,129 attrs, and 1,818,266 flat-closure
objects. It finds 525,718 reachable and 1,571,245 unreachable objects in
235,559,656 resident reservation bytes. The closure dominance confirms that
successful compaction must address closure identity rather than optimize a
minor object family. That rotating checkpoint still has eight runtime blockers
and the seven explicit rollover evidence domains remain missing, so it performs
no collection or mutation.

A table-free region-relative handle cannot compact holes inside a logical
region: preserving the handle also preserves the object's within-region
offset. It is therefore bounded by the already-insufficient page-completion,
hole-reuse, and virtual-remap results. A two-level stable handle using the
existing Candidate-C word could encode `{u16 segment, u16 slot}` and store a
`u16` eight-byte-scaled offset per object. At 2,096,963 objects that costs about
4MiB, but resolution requires two serial metadata loads. Candidate C already
has a 23-bit domain epoch and a 32-bit payload, so a flat monotone
`u32 object-id -> u32 byte-offset` table is strictly simpler: approximately
8MiB of raw entries and one dependent load. A full pointer table would cost
approximately 16MiB.

The resulting order is:

1. Continue direct offsets plus writable-root and raw-alias closure; this has
   no permanent table and no extra dereference load.
2. If provenance cannot be closed, measure a default-off flat `u32` stable-ID
   resolver before changing the heap ABI broadly.
3. Reject the segmented two-load directory unless the flat table fails for a
   reason segmentation actually fixes.

Stable IDs would remove reference writeback but not root discovery or the rule
that decoded pointers and borrows must end at a safepoint. In particular,
typed thunk heads remain pinned while an atomic force guard borrows the head
across recursive evaluation. This prevents a handle prototype from being
misreported as whole-domain movement.

### Writable apply portal and combined terminal architecture

The next real portal now covers `ApplyLambda -> LambdaBody`. The outer apply
publishes its function and argument only through indexed transient roots, and
the reused-lambda path reloads the argument after the recursive body before the
package-boundary probe can observe it. The cloned lambda environment is copied
into the explicit call environment and published through evaluator
environment roots before body entry. The Candidate-C formal-set semantic test
passes. The older moving-GC lambda-default test is intentionally compiled out
under Candidate C and therefore supplies no evidence for this path.

The rebuilt ordinal-192 run remains byte-green and reconciles all 357
completions in each evaluator with zero proof blockers or root error. Compared
with the first writable-force run, diagnostic native-shadow values fall from
68 to 38 while transient writable roots rise from 24 to 70; total named roots
rise from 1,234 to 1,250. All 294 active continuation frames remain covered,
the 36 force coordinates still reconcile exactly, and cold and warm results
retain `parity=byte:aos-nix`. This is useful provenance progress, not moving
authorization: the central force path can still retain decoded pointers,
guards, and payload borrows across recursive work.

The completion census also puts a hard ceiling on collection alone. A
proportional ideal reclamation of the 1,571,245 currently unreachable objects
would leave whole-process RSS around 267MiB, approximately 34MiB above the
strict half-C++ gate. Same-layout evacuation is consequently only an enabler.
The terminal design must combine:

1. early, repeated liveness-filtered domain rollover at the writable
   whole-demand loop head;
2. packed per-kind survivor destinations and compact direct 32-bit relative
   references;
3. elimination or scalar replacement of Promise, closure-environment, and
   frame allocations inside admitted demand regions; and
4. a fused force-enter-apply-update-return runner with generic materializing
   exits.

This combination is supported by complementary primary results rather than by
one directly comparable Nix benchmark:

- [Liveness-Based GC for Lazy Languages](https://doi.org/10.1145/2926697.2926698)
  supplies continuation-specific future-use analysis; it reports
  factor-level minimum-memory reductions on suitable lazy programs.
- [R Melts Brains](https://doi.org/10.1145/3359619.3359744) makes promises,
  environments, force, and apply explicit, then removes or lazily materializes
  environments through scope and data-flow analysis. Its runtime resembles
  Nix more closely than a purely functional core because promises and
  first-class environments remain explicit.
- [Compiling Tree Transforms to Operate on Packed Representations](https://doi.org/10.4230/LIPIcs.ECOOP.2017.26)
  demonstrates cursor-based execution over pointer-free packed data, while
  [Garbage Collection for Mostly Serialized Heaps](https://doi.org/10.1145/3652024.3665512)
  supplies a region lifecycle for mostly packed heaps.
- [Optimizing R VM: Allocation Removal and Path Length Reduction via
  Interpreter-Level Specialization](https://doi.org/10.1145/2544137.2544153)
  and [Optimizing Indirect Branch Prediction Accuracy in VM
  Interpreters](https://doi.org/10.1145/1286821.1286828) motivate
  allocation-removing specialization and replicated superinstructions for the
  fused runner.

The first decisive memory implementation slice is ordinary-thunk evacuation,
not another lambda-only mover: the previous eager movable closure slice was
only tens of kilobytes. It must run early enough to avoid the `ru_maxrss`
high-water mark, rebuild survivor-only registries and weak indexes, prove zero
old-domain aliases, and decommit the source before later demand rebuilds the
peak.

The ordinary serial `Node` destination now supplies the required semantic
reconstruction oracle. It preserves suspended or forced state, module and
body, shared lexical frames, owner-relative inline capture tails, dynamic
`with` scopes, scoped globals, and rewritten cached results after the source
heap is dropped. It rejects blackholes, shared payloads, synthetic work, and
non-serial force storage. The two focused destination tests and the exact
mover-admission census pass on the Linux builder. Fourteen of the fifteen
evacuation-plan tests pass; the remaining deterministic-layout test compares
two live RSS samples and observes different process RSS values rather than a
different graph or destination layout.

The rebuilt exact ordinal-160 census rules out the conservative mover as a
material memory mechanism. Of 143,544 reachable inline flat thunks, 132,333
are ordinary `Node` thunks, but only 9,143 are suspended, serial-only,
tail-free, capture-free, dynamic-scope-free, exact-extent relocation sources.
They total only 804,584 inline bytes. The whole reachable graph contains
173,470 objects and 22,817,416 inline bytes, while the source reservation has
64,167,936 resident bytes. The dead-first page-stream projection remains below
the acceptance watermark, but the clone-all correctness writer now has a
52,817,032-byte staging bound and cannot be the production collector.

The production form is therefore a repeated packed-generation rotation:

1. allocate normally into the full-layout nursery;
2. at the writable whole-demand loop head near the demonstrated 195--200MiB
   watermark, stream live objects into header-minimal per-kind lanes;
3. heal every root and edge to direct Candidate-C domain/`u32` offsets;
4. rebuild weak indexes, prove zero old-domain aliases, and discard the
   temporary forwarding directory; and
5. decommit both the old nursery and prior survivor generation before
   resuming.

The ordinal-160 boundary is not completely movable: it retains 51 blackholed
flat thunks whose force guards make their source identity non-relocatable.
Exact fixed-point traversal disproves the initially plausible small-island
fallback. Those 51 seeds retain 173,216 of 173,470 reachable objects,
22,793,928 inline bytes, and 11,248 resident source pages. Their captured
environments therefore keep effectively the entire live graph in the old
domain. Direct roots and 109,916 capture-tail-owner pins are healable, but
that distinction does not help while the blackhole closure remains
transitively dominant.

Early rotation must instead detach rollback-critical body/environment work
from an active blackhole into an explicit rooted force lease or stable-head
work slot. The pinned publication cell can then have no outgoing heap edge;
success publishes the rewritten result, while error or panic restores the
exact suspended work before rollback. Merely retaining old pages or copying
all descendants cannot meet the memory gate.

Keeping an 8-byte source/destination directory would cost about 16MiB at the
2,096,963-object final population, while a persistent stable-ID table would
cost about 8MiB and add a dependent load to every resolution. Both consume too
much of the approximately 10MiB margin in the current 217.6MiB packed
whole-process projection. Same-layout semispace rotation remains above the
memory gate. Direct healed offsets plus a transient streaming directory are
the selected design.

The speed audit likewise rejects a dispatcher-only fused runner. Against the
latest alternating same-binary medians, the optimized evaluator must remove
another 1,762,246,709 cycles to beat twice the C++ reference. The measured
environment/frame, force/eval/apply, and
Promise/allocation families total about 2.367 billion cycles; even a fourfold
local improvement across all three saves only about 1.775 billion cycles,
leaving very little acceptance margin.
Consequently the runner must jointly eliminate frame installation, generic
force/apply dispatch, and promise allocation/claim/update, with allocator and
attribute work providing safety margin. A typed opcode loop is not sufficient:
the first executable slice must be a directly generated
`Node force -> guarded lambda apply -> update -> return` superblock, then grow
to the observed recursive `Node`, `Apply`, `GenListElemAtAddOne`, `Apply2`, and
`Select` grammar. Authoritative per-window PMU accounting is required before
coverage counts are credited as cycle savings.

The evaluator and Linux wrapper now implement an identified version-2 PMU
protocol with exact session, window, and outer-leaf kind, grouped instruction
and cycle replies, and null-window calibration. The wrapper uses monotone
counter deltas because inherited task aggregation made group reset samples
nonlocal; seven census-disabled sessions have zero null-window deltas,
balanced requests, exact provenance, and no controller failure. Their binary
still constructed otherwise-unused force coordinates because the nested
source-file sync missed that final no-op guard, so the following measurements
are an upper bound on the minimal probe overhead:

| Window | Instructions | Cycles |
| --- | ---: | ---: |
| `AutoCall4` | 3,337,071,757 | 1,306,989,769 |
| `FinalForce5` | 11,416,829,383 | 4,658,120,481 |
| Paired total | 14,754,471,950 | 5,965,110,250 |

The paired cycle range is 5,958,836,284--5,997,509,111. Compared with the
same dispatcher binary's earlier whole-process median, this upper-bound probe
adds about 5.2% cycles and 5.5% instructions. Despite that overhead, the result
establishes that these two leaves encompass essentially the entire remaining
execution, rather than merely a high event count. A reconciled build with
coordinate construction disabled still needs a repeat measurement. The
current result does not establish a speedup: the fused implementation must
still remove about 31% of the uninstrumented native cycles, and
allocation/materialization exit provenance remains a promotion gate.

## Reconciled PMU and active-blackhole cut

The reconciled census-disabled PMU build removes coordinate construction as
well as counter storage and emission. Seven identified sessions are
authoritative: every null window reports exactly zero instructions and zero
cycles, requests are balanced, and the controller reports no failure. Median
windows are:

| Window | Instructions | Cycles |
| --- | ---: | ---: |
| `AutoCall4` | 3,377,895,027 | 1,324,744,725 |
| `FinalForce5` | 11,591,145,793 | 4,763,876,424 |
| Paired total | 14,969,399,412 | 6,088,621,149 |

`FinalForce5` owns 78.24% of the paired cycles. Matched whole-process controls
bound the identified PMU handshake at 0.073% cycles and the
dispatcher-plus-disabled-census path at 0.188% cycles. The approximately 7%
movement from the historical dispatcher run is therefore a source/workload
shift, not instrumentation overhead. These results support a whole-demand
force/update/apply runner; they do not by themselves demonstrate a speedup.

The first active-work detachment transaction is correct but insufficient. It
moves tail-free ordinary Node work into evaluator-owned writable leases while
preserving the original force cell, rollback order, recursion detection, and
root writeback. Focused lifecycle and force-lease tests pass. In the real
ordinal-160 run it releases 12,999 completed Node payloads, but the 51 active
blackholes still retain 172,974 of 173,479 reachable objects and 22,766,696
inline bytes.

An exact per-seed reachability census explains the failure. Ten seeds are
already edge-free Released shells. Of the remaining seeds, 39 contribute to
the retained island: 31 value-tail Nodes, two physically tail-free Nodes with
inherited flat capture bases, and six synthetic Apply thunks. Every one of
those 39 reaches the same 172,905-object core. The exact minimum full-collapse
cut is therefore all 39 contributing seeds; leaving any one unchanged retains
essentially the whole island. Tail-only detachment is disproven. The next
transaction must detach all serial active work shapes and materialize both
physical-tail and inherited capture ownership into the evaluator-owned lease.

The registry-free packed destination now has exact semantic lanes for thunk
heads/work, frames, lists, and attrsets. Attrsets retain shape metadata,
projected shape, representation kind, source positions, direct symbol lookup,
and both observable orders without a finalized hash table. Packed projection
accounting must use vector capacity rather than initialized length: the thunk
and frame lanes now expose both quantities. In particular,
`Vec<Option<T>>` work slots occupy their actual safe Rust layout (16-byte
Node, 48-byte Apply, 80-byte Apply2, 32-byte Select, and 12-byte BuiltinAttr
slots). A production rotation must either charge this capacity or freeze lanes
to exact immutable storage before claiming the roughly 10MiB projected
acceptance margin.

## Generalized detachment and direct packed cutover

Generalized active-work detachment closes the hard-island blocker. The lease
now takes logical ownership of every serial active work shape, including
physical and inherited flat captures, while the source retains its exact force
cell and an edge-free `Released` shell. The pinned Linux force-lease suite is
19/19 green. At the exact ordinal-160 boundary the 51 hard seeds now retain
zero transitive objects: the complete hard island is 51 shells, 4,888 inline
bytes, and 24 resident source pages. Native output remains byte-identical to
the C++ oracle.

Nonmoving reclamation is not a substitute for rotation. A real ordinal-160
run retired 221,940 worker objects but found only 267 advice-eligible pages.
Against a matched control it reduced peak RSS by 3,196 KiB while increasing
instructions by 3.0% and cycles by 4.2%. This falsifies a sweep-first terminal
design and strengthens the requirement for packed coalescing.

The clone-all writer now preserves forced `Released` thunks, including their
old nonsemantic physical extent, and its planner/writer suite is 20/20 green.
The determinism test compares forwarding records and lane extents rather than
volatile process RSS telemetry. The real writer then reaches the 51 active
`Released + Blackhole` shells. A throwaway diagnostic copy of those shells
exposed the next inherited-lambda-tail case, but review proved that such a copy
must not become production behavior: the active lease still owns the source
cell pointer and may retain its source `FlatValueTailHandle`. A copied
blackhole without transactional lease retargeting is an orphan. The diagnostic
admission was therefore removed.

The selected first cutover keeps those 51 source cells and their 24 pages
identity-pinned. The active-work lease remains authoritative; all of its
detached edges participate in root writeback. Every other reachable object is
assigned a direct packed coordinate, roots are healed, the destination is
installed, and the old reservation is retired except for the exact shell
allowlist. Successful publication makes a shell eligible for a later rotation;
abort still restores work through its unchanged source coordinate and tail.

Exact-capacity, source-map-free builders now exist for thunk, frame, and
collection lanes. They reserve all storage before construction, reject
over-capacity appends before mutation, expose initialized and allocator-granted
capacity bytes, and verify no capacity growth. Six focused Linux tests cover
exact fill, underfill, overfill, and no-growth behavior.

The strict admission limit is half of the authoritative 466,904 KiB C++ peak:
239,054,848 bytes. The older 239,587,328-byte constant in the evacuation
projection is too loose and must not govern production admission. At ordinal
160 the direct packed cutover projects a conservative 211--216 MB overlap peak,
leaving about 23--28 MB. The existing same-layout writer's 49,186,480-byte
staging is inadmissible and does not solve the final representation.

Alternative architecture review leaves one contingency, not a preferred
route. A segmented stable-handle generation projects about 232.9 MB and could
avoid later incoming-edge rewrites, but leaves only about 5.9 MiB, requires a
broad resolver/ABI cutover, and adds dependent loads to hot resolution. It
advances only if direct alias/writeback closure stalls and only after a
production-shaped resolver demonstrates at most 1% whole-process cycle
overhead. Pure regions, nonmoving/Immix, stable-ID directories, and
same-layout semispace remain quantitatively rejected as terminal designs.

## Packed-at-birth and terminal-increment experiments

The stable reserved typed lane supplies the direct-indexing primitive needed
by both packed-at-birth allocation and exact-capacity rotation. On the focused
read microbenchmark it takes 14.391 ms versus 13.919 ms for direct storage, a
1.034x ratio below the 1.05x admission gate. Focused allocation takes
1.762 ms versus 6.406 ms for the headerless flat lane. The six focused tests
and the complete single-threaded `ratchet-value` suite are green (432 passed,
3 ignored). The alternative segmented lane takes 2.547x direct-read time and
is rejected for the hot resolver.

An active packed thunk lane now provides fixed-capacity, direct-`u32`
references and transactional claim, abort, publish, and stale-reference
semantics. Its work pools use the real Rust layouts: 16-byte Node, 48-byte
Apply, 80-byte Apply2, 32-byte Select, and 12-byte builtin slots. Capacity and
resident accounting distinguish initialized bytes, allocator-granted
capacity, and virtual reservation. The standalone lane's three focused Linux
tests pass. This is a substrate result, not an RSS result: the first evaluator
integration admits only serial Apply and `GenList` work, must intercept the
logical domain before `thunk_ptr`, and fails loudly rather than falling back
after an eligible allocation.

The first real ordinal-357 young-increment projection correctly refused to
produce a memory claim. It observed all 358 completion fences but found eight
runtime blockers: four uncovered active native frames, two active primitive
frames with four primitive roots, an unreconciled force proof, and one
unshadowed continuation among 1,351 roots. No projected RSS from that run is
admissible evidence. Earlier milestones also cannot collect while recursive
state remains active. The revised experiment records milestones 160--352 but
keeps them explicitly fail-closed; only ordinal 357, after return to the
rooted outer dispatcher loop head with zero recursive/native/force state, may
trace and project.

Death alone cannot meet the late memory gate. At ordinal 352 the same-layout
increment would need to reclaim 178.38 MB but has only 149.79 MB dead; at
ordinal 357 it needs 209.67 MB with only 167.60 MB dead. The remaining
requirements are at least 28.59 MB and 42.06 MB respectively. Compacting the
71.28 MB live same-layout population to its approximately 30.24 MiB packed
layout supplies roughly 41 MiB, nearly the entire ordinal-357 gap. Therefore
young reclamation is useful only when paired with dense registries and packed
typed streams; it cannot replace them.

The exact outer `FinalForce5` partition counts 206,729 claims: 158,510 Node
(76.67%), 41,266 Apply (19.96%), 6,567 `GenList` (3.18%), 200 Apply2, and
186 Select. An Apply-only superblock cannot close the speed gate even under an
optimistic fourfold local improvement. Since `FinalForce5` owns
4,763,876,424 paired cycles, the evaluator must remove at least 37.0% of that
region to supply the remaining 1,762,246,709-cycle whole-process reduction.
The smallest target-capable grammar is consequently
`Force(Node) -> Claim -> EvalStaticNode -> ApplyGuarded -> BindVirtualFormal1
-> ExecuteCalleeBlocks -> nested Force -> UpdateLifo -> Return`, with Node and
Apply measured by disjoint inherited-PMU leaves before implementation credit
is granted.

The corrected returned-loop ordinal-357 run closes every read-only projection
gate. It preserves the exact derivation, observes 491 roots and 991 reachable
objects among 2,100,912 classified objects, has zero unclassified objects and
zero runtime blockers, and reconciles all 359 initial/completion/tail fences.
The exact same-layout projections are:

| Segment | Retained bytes | Projected steady RSS | Margin below 239,054,848 |
| ---: | ---: | ---: | ---: |
| 4 KiB | 1,695,744 | 210,464,768 | 28,590,080 |
| 16 KiB | 4,947,968 | 213,716,992 | 25,337,856 |
| 64 KiB | 10,223,616 | 218,992,640 | 20,062,208 |
| 256 KiB | 25,427,968 | 234,196,992 | 4,857,856 |

This is still not peak-RSS evidence. The pre-scan process is already at
444,710,912 bytes, so a terminal decommit cannot erase the historical peak.
The same returned-loop proof must succeed at a pre-peak milestone, starting at
ordinal 160, and a fresh process with real mutation must remain below the
ceiling for the entire evaluation.

The complete returned-loop schedule falsifies that last assumption. Internal
completions 160, 192, 224, 256, 288, 320, and 352 are all observed, but the
outer dispatcher jumps directly from cumulative completion 77 to 357. None of
the seven pre-peak milestones has an exact returned outer boundary, so every
one refuses without tracing or projecting. The latest matched run remains
byte-identical to C++ but actually peaks at 437,688 KiB versus C++ at
467,544 KiB. Terminal projection does not change that result.

Among the terminal geometries, 16 KiB is the selected production candidate:
its latest projected steady RSS is 213,299,200 bytes, leaving 25,755,648 bytes
below the stricter established ceiling. Its 15,508 segments require about
496,256 bytes at 32 bytes per descriptor, versus 1,945,824 bytes for 60,807
4-KiB segments. Moving to 64 KiB saves only about 347 KiB more descriptor
metadata while consuming about 5.28 MB of RSS margin. A real pre-peak cutover
therefore requires a resumable, root-bijective portal inside `FinalForce5`;
outer-loop reclamation is structurally unavailable.

The first active packed Apply/GenList run also rejects append-only work as the
terminal design. It allocates 355,726 Apply and 1,987,767 GenList heads with
zero fallback, retaining 131,235,608 initialized bytes in its head/work lanes.
Against the runtime-off leg of the same feature binary it reduces instructions
from 40.817 to 39.613 billion, cycles from 16.042 to 15.080 billion, and the
one-shot harness high-water from 1,034,816 to 927,276 KiB while preserving the
exact derivation. The established one-word typed head with a reusable work pool
instead reaches 789,152 KiB in that binary. Absolute totals from this feature
build are approximately 2.9x the accepted 13.979-billion-instruction baseline,
even when runtime-off, so they are not an accepted new baseline. The selected
follow-up isolates the logical-domain force branch from the generic hot
function until the feature-off binary is within 2%, then combines direct
`u32` stable heads with generational reusable shape-sized work slots. The
append-only tombstone lane is rejected for production.

That isolation pass found a feature-topology defect before any hybrid result
could be credited. `active_packed_thunk_probe` had temporarily inherited the
broad compact-destination and collection-poll probes merely to compile, while
`candidate_c_value` alone failed with 152 errors because ordinary flat
`EvalListView`/`EvalAttrsView` APIs were incorrectly hidden behind those
moving-collection probes. The flat view surface is now available throughout
the candidate-value domain, with packed variants and collection writeback
remaining probe-gated. A pinned Linux `candidate_c_value`-only release build
therefore compiles and completes the exact cold-only derivation at
35,183,768,949 instructions, 20,431,988,968 cycles, 1,039,564 KiB peak RSS,
and 7.066059753 seconds, producing
`/nix/store/k5fgx08pvw7sil4wgy0hj0r3pswg3pzm-aos-system-toplevel.drv`.
This is a feature-topology and generic-path control only, not an accepted
performance baseline: it deliberately omits the final-config trie canary whose
runtime specialization reduces the ordinary evaluator's previously recorded
roughly 39.75-billion-instruction path to the 13.979-billion-instruction
control. Active-probe overhead must instead be measured in a same-source,
same-feature binary with the final-config canary compiled and enabled, changing
only the active packed-thunk runtime door. Hybrid reusable-slot work remains
paused until that matched comparison is complete.

A deeper three-way representation check selects the already implemented
one-word typed head plus generational reusable work pool, rather than a second
pool design. For the active run's 2,343,493 Apply-shaped allocations, an
eight-byte stable head lane costs 18,747,944 bytes. The previously measured
reusable pool peaks at 7,374 live entries and 8,192 slots; even the existing
approximately 80-byte full-`EvalThunk` slot is only 655,360 bytes at capacity.
The combined upper estimate is therefore about 19.4 MB, roughly 111.8 MB below
the active append-only lane's exact 131,235,608 initialized bytes. Shape-sized
work would reduce the sub-megabyte term further but cannot materially improve
the dominant permanent-head term.

Packing each head and its 48-byte optional Apply work into one hole-reused
object does not establish a smaller safe bound. Without precise reachability it
is exactly the rejected 56-byte append-only geometry
(`2,343,493 * 56 = 131,235,608` bytes). The 7,374 work-live peak is not a
head-liveness proof: a forced thunk's stable identity and published result can
remain reachable after its suspended work is released. Reusing such a head
would require a complete root/edge trace plus either forwarding or a
generation-bearing value coordinate; a side generation table would also
restore metadata and another hot resolution dependency. The current
`StableThunkHead`/`TypedThunkWorkPool` design already supplies claim
linearization, rollback to the same reserved slot, release only after result
publication, generation-checked stale-handle rejection, generation-exhaustion
poisoning, and focused claim/abort/publish/ABA tests behind
`AOS_NIX_TYPED_THUNK_HEADS=apply`. The active experiment should reuse that
substrate and specialize work shapes only if a matched full-workload
measurement justifies it.

The first exact leaf-PMU attempt produced no class totals because its
descriptor transfer was unusable and therefore failed closed. Even disabled,
its transition hooks raised the seven-run `FinalForce5` median from the prior
4.764-billion-cycle result to roughly 5.9 billion cycles, about 23% region
perturbation. No attribution is credited from that run. A replacement reader
must use an inline disabled guard and a low-overhead inherited counter mapping;
the complete enabled diagnostic must demonstrate at most 2% matched
whole-process perturbation before its exclusive Node/Apply partition is
authoritative.

The inherited metadata-page failure was subsequently isolated to the Linux
perf ABI rather than descriptor transfer: `mmap(MAP_SHARED)` returned `EINVAL`
for the inherited event group, while an otherwise identical non-inherited
group exposed capabilities `0x1e`, including userspace RDPMC. A second
simultaneous pair was not viable because it competed with the authoritative
pair, and a launcher-thread process-local pair recorded zero because the
native evaluator runs on a Tokio worker TID. The final full-density experiment
therefore opened, mapped, reset, and enabled the group on the exact evaluator
worker. That experiment did not complete even its first native sample in more
than six minutes and was terminated. The executed version had a `gettid`
syscall in every snapshot; moving that ownership check to outer boundaries
removes the identified syscall error, but the full-density path remains
rejected from acceptance consideration. It has no class, conservation, or
overhead result and must not be used to justify the Node fusion.

The bounded fallback is statistical hardware sampling on the existing
native-only cold path. `AOS_NIX_BENCH_COLD_ONLY=1` executes one cold native
evaluation with no C++ oracle, warm replay, history, or parity subprocess. The
release profile retains ELF symbols despite ThinLTO, so the first attempt uses
one userspace cycle sample per one million cycles and LBR call graphs:

```text
cd /home/dylan/codex-rfc0007
AOS_NIX_BENCH_COLD_ONLY=1 \
AOS_NIX_FINAL_CONFIG_TRIE_CANARY=1 \
AOS_NIX_WHOLE_DEMAND_DISPATCHER_PROBE=1 \
AOS_NIX_WHOLE_DEMAND_CORRIDOR_CENSUS=1 \
perf record -o /home/dylan/final-force-cycles.data \
  -e cycles:u -c 1000000 --call-graph lbr -- \
  /home/dylan/target-leaf-pmu/release/aos \
  --eval-system x86_64-linux --impure-eval \
  nix-bench -A systems.server.build.toplevel
```

The expected roughly five-billion-cycle cold evaluation yields approximately
five thousand samples. `perf report --stdio --comms aos --sort symbol,dso` and
`perf script` provide the symbol and stack rankings. If AMD LBR is unavailable,
`--call-graph dwarf,4096` is the fallback, but it is admissible only if matched
cold-only `wall_ns` controls show at most 2% perturbation. Sampling establishes
a ranking, not savings: any selected fusion still requires byte parity plus
matched whole-process instruction, cycle, wall-time, and RSS validation.

### Result-unwind portal inside `FinalForce5`

A default-off falsifier now tests the smallest resumable seam inside the
pre-peak `FinalForce5` interval. `AOS_NIX_FINAL_FORCE_RESUME_ORDINAL=160`
arms only at successful final-config completion 160 in segment 5. It does not
unwind at the completion callback. Instead, the next owning thunk update first
publishes its result as `Ready`, sheds captures when enabled, and only then
raises a private typed `Result` error. Normal error propagation performs every
environment, force-lease, blackhole, and native-shadow cleanup; the outer
dispatcher alone recognizes the typed category, reconstructs its value from
the relocation-aware root slot, and requires the ordinary collection-poll
preflight to prove root/writeback bijection before replay.

The private channel is deliberately not a panic payload. A panic would skip
manual cleanup that is sequenced after nested evaluator calls. Nor is it a Nix
evaluation error: error-context decoration declines it without evaluating the
context expression, and `tryEval` catches only throw, assertion, and missing
search-path categories. Three focused tests cover exact ordinal/segment
selection, rooted loop-head reconstruction, and the combined
`addErrorContext`/`tryEval` bypass.

The first immediate-unwind prototype established the cleanup and root proof,
but replaying the entire subject from completion 160 was not a valid semantic
transaction. The independent eligibility audit already records `pure=false`,
active IFD, and effect cursor 483 at that point. The implementation also
initially compared the inner completion node with the outer dispatcher node,
which made the private error escape; removing that invalid identity check fixes
the catcher but does not authorize rollback across those effects.

The deferred post-publication form succeeds on the exact primary. It suspends
once and resumes once with zero declines, at zero-completion lag, immediately
after a committed `PrimOp` thunk at `IrId(1523)`. The preflight sees a
bijective rooted loop head, and structural differential evaluation preserves
the byte-identical result
`/nix/store/cyn24s3mrxiknf8a0abf3c201ycvjdir-aos-system-toplevel.drv`.
This proves a one-commit incremental portal, not yet reclamation: the current
hook only exposes the safe seam. A collector still needs to run at that seam
and demonstrate a fresh-process peak below the half-C++ ceiling, while a
matched benchmark must keep the replay and probe overhead within the existing
instruction gate.

### First real portal publication transaction

The existing packed publication stack was narrower than the terminal
young-increment projection. Its moved inventory is exactly every reachable
`String`, `Path`, `List`, `Attrs`, boxed `Int`, and boxed `Float`. String
contexts and bytes, collection edges and attr metadata/orders/positions, and
scalar payloads are copied into direct-coordinate lanes. Roots and fields in
retained flat owners are translated, and the four weak hash-cons indexes are
rebuilt against the new logical domain.

Every reachable `Lambda`, `Primop`, `Thunk`, and `External` remains flat.
More importantly, the finalized packed thunk and frame lanes are constructed
with zero capacity: no stable thunk head, suspended work, captured frame, flat
closure, record-table entry, or typed-work pool is moved. Successful source
retirement removes all flat string/path/list/attr allocations and all boxed
scalar cells, but leaves the closure stores, typed heads/work, frames, record
tables, and their source reservation live. The owner also currently rejects a
second packed generation, so this is a single cutover rather than repeated
rotation. The young-increment projection's simulated packed-at-birth segment
streams must not be confused with this physical inventory.

A separate `packed_portal_cutover` feature now connects that real transaction
to the deferred ordinal-160 portal without changing the read-only
`young_increment_projection_probe` contract. The runtime door is
`AOS_NIX_PACKED_PORTAL_CUTOVER=1`, with an exact ordinal selected by
`AOS_NIX_PACKED_PORTAL_CUTOVER_ORDINAL` (default 160) and an explicit safety
charge in `AOS_NIX_PACKED_PORTAL_SAFETY_BYTES` (default 8 MiB).

The driver consumes the portal's root-bijection guard, samples RSS after the
precise scan, charges the exact root-stage allocation, prepares the packed
owner, retained-edge healing, weak indexes, and complete source-retirement
inventory, and validates every supported root coordinate before installation.
It also checks current and process-peak RSS after all preparation allocations.
After installation it is roll-forward only: roots are committed
allocation-free, the identity-keyed force-payload memo is cleared, and a fresh
root scan must report zero selected-source aliases before retirement. A
post-install scan or audit failure keeps the old sources and continues
evaluation with the semantically valid packed generation; it never becomes a
user-visible Nix error.

Telemetry distinguishes moved and retained objects, healed fields, initialized
and capacity destination bytes, modeled overlap and headroom, physically
retired immutable/integer/float populations, and RSS before and after.
Focused tests cover successful direct-root publication plus physical source
retirement and an unsupported-root decline before owner installation. This
bridge receives no half-memory credit until a fresh Linux run passes parity and
peak RSS, and its empty thunk/frame lanes make it unlikely to be sufficient on
its own.

### Mixed Node/Apply runner contract repair

The first attempt to connect the validated `MixedExecutionRunner` to real
oracle work found two semantic gaps in the substrate rather than an adapter
mechanics problem. A `Force` terminator selected static successors from only
the coarse `Node`, `Apply`, or `GenListElemAtAddOne` family. Two Node thunks can
name unrelated bodies, so that contract could execute the wrong static body.
Plan format version 3 carries an exact module/definition/body/frame/capture
identity for each force family. The runtime receives those guards before the
claim, must decline a mismatch without mutation, and returns the observed
identity with every successful claim. The runner independently compares it
and aborts a mismatched token before entering a static successor.

The requested `Force(Node) -> ApplyGuarded` grammar also places a speculative
call guard beneath an owned outer update. The previous format correctly
rejected its resumable statepoint because it had no exception recipe. Version
3 adds a fail-closed `RestartEntry` statepoint: a nested guard or fixed-call
capacity miss aborts every update in LIFO order, makes the activation terminal,
and asks the adapter to evaluate the named outer entry through the semantic
oracle. It never resumes partially executed state. Focused contract tests cover
both a claimed-work identity mismatch and a second guarded call that rolls
back an already claimed Node.

Node records retain runtime frames but not resolver `FrameId`, which initially
appeared to require widening every work record. The chosen alternative is an
on-demand immutable-IR analysis keyed by module/body. It propagates binder
frames through Lambda, Let, recursive attrset, and deferred thunk bodies,
returns only a unique frame identity, and declines shared ambiguous bodies.
The result is cached with the lowered body, adding zero bytes per runtime
thunk. A real-IR front end now combines that recovery with complete packed-STG
lowering and emits an exact guarded Node work identity only when the body
contains unary Apply work.

This route has enough population reach but not yet measured cycle credit.
Node plus Apply comprise 199,780 of 206,733 observed FinalForce claims
(96.63%). Removing the required 37% of FinalForce cycles therefore requires at
least 38.29% average savings across the admitted Node/Apply corridor; Node
alone would require 48.26%. The existing recursive packed-STG Apply
specialization starts from only 41,266 Apply claims (19.96%) and still calls
generic `apply_lambda_value`, `force_node_result`, and oracle leaves. Even a
perfect claim-count-proportional Apply path cannot close the required gate.
The mixed route is preferred because it can retain Node ownership, guarded
calls, nested force, LIFO update, and return in one fixed-slab activation.
Actual credit still requires translating the real packed body into the mixed
CFG, wiring the default-off oracle adapter, and measuring a matched Linux run;
an interpreted operation loop may still need direct-threaded or generated
superblocks to deliver the required 38.29%.

### Portal adversarial audit and replay-free pre-FinalForce cutover

An independent adversarial pass found three portal control-path failures. A
collection-preflight decline could escape as a user-visible portal invariant
error, an armed publication request could disappear without suspension credit
when the next publication used an unhooked path, and several node/slot errors
could bypass dispatcher cleanup. The probe now resumes normal evaluation on a
preflight decline, counts an unconsumed terminal request as declined, and
closes dispatcher/root/census state on those invariant errors. Focused tests
cover all three paths.

The review also confirmed that post-publication replay is not yet a promotable
semantic boundary. Publishing the selected child prevents that child body from
running twice, but replay still re-enters the surrounding FinalForce traversal.
The selected primary run is impure, has an IFD realizer, and has already
observed 483 effects. There is no per-attempt effect journal proving that the
prefix between FinalForce entry and suspension is idempotent. Byte-identical
derivation output alone does not prove trace, warning, IFD-callback, filesystem,
or store-effect parity, so the ordinal replay portal remains experimental and
receives no semantic or performance credit. Its publication hook now fails
closed before requesting an unwind unless the whole evaluator session is pure,
has no IFD, parallel, memo, or persistence capability, and has accumulated no
trace, warning, impure-input, text-store, or source-store effects. The primary
benchmark therefore declines replay rather than relying on derivation-byte
parity as an effect proof.

The dispatcher already exposes a stronger seam immediately after the final
attribute selection and before entering FinalForce. At this point it is at its
ordinary rooted loop head: the selected subject lives in the relocation-aware
transient slot, no FinalForce Rust continuation exists, and evaluation can
continue forward after root rewriting. The packed feature therefore has a
second default-off door, `AOS_NIX_PACKED_PREFINAL_CUTOVER=1`, which runs the
same precise packed transaction at this seam without any private unwind or
replay. A failed proof or preparation simply leaves the original heap live.

The pre-install live gate now runs after the root stage, retained-owner healing,
replacement weak indexes, and source-retirement inventory have all been
allocated. It compares the larger of current and process-peak RSS plus the
configured safety allowance against the strict half-stock ceiling, with checked
arithmetic, and folds that observation into reported projected peak/headroom.
This repairs the earlier projection hole: the initial generation estimate did
not include allocations made later by the complete publication transaction.
The replay-free seam and corrected admission still receive zero target credit
until compiled and measured on the pinned Linux host.

The replay-free seam now performs one additional validate-then-commit worker
sweep after immutable/scalar source retirement. This ordering is load-bearing:
before packed weak-index replacement and removal of old immutable stores, a
currently unrooted hash-cons candidate can be resurrected and its worker edges
must remain seeds. Afterwards, the healed precise scan is the complete durable
graph. A new scan-driven sweep extracts its exact worker-address set, validates
all absent record and flat-closure candidates, rejects an absent blackhole
before mutation, retires the validated candidates, and advises zero-liveness
reservation pages. The replaying ordinal portal does not use this sweep.
The reachable set is a sorted, deduplicated address vector rather than a hash
table, bounding its primary mark scratch at one word per scanned worker plus
allocator capacity.

The selective flat-store retirement token validates exact registry coordinates,
headers, kinds, and duplicate freedom while holding an exclusive store borrow;
commit performs no allocation or fallible lookup. Focused tests cover retaining
scanned workers, retiring absent workers, all-or-nothing blackhole rejection,
selective flat retirement, and the combined pre-FinalForce publication path.
This can release dead closure pages and payload-owned environment graphs before
FinalForce grows the peak, but it does not compact tombstoned registry capacity,
typed thunk heads/work pools, or live frames. It receives no overlap or RSS
credit until the Linux run reports actual retired populations, advised pages,
and a lower fresh-process peak.

The source-retirement commit is now failure-atomic across all five source
stores. Candidate-C scalar stores expose an exclusive prepared token, and the
three immutable stores use the same complete-store token. Hash-cons contents,
exact registry coordinates, headers, kinds, and source inventories all validate
before any cell is changed. Commit then retires boxed integers, boxed floats,
strings/paths, lists, and attrsets without allocation or fallible lookup.
Complete-store commits also release empty registry/region vectors while
preserving the shared arena, allowed-kind contract, and monotonic tail
generation. Thus an immutable validation failure can no longer follow an
already-committed scalar retirement or be reported as “all sources retained.”

The zero-alias result is now represented as a linear proof token rather than a
caller-side convention. Publication yields a source-live token; rebuilding and
auditing the precise graph consumes it and returns either a zero-alias token or
an audit failure that still owns the source-live state. Physical retirement
accepts only the zero-alias token, so another evaluator caller cannot bypass the
audit accidentally. Cutover telemetry also reports immutable and boxed-scalar
candidate/advised pages and advice failures separately from the post-worker-
sweep re-enumeration. This makes failure to return source pages observable
instead of silently reporting only the later sweep result.

### Alternative speed architecture and control-provenance gate

An independent read-only pass re-audited the remaining cycle surface rather
than assuming that packed reclamation is also the speed architecture. The
worktree's last preserved accepted lean control is 13,979,018,000 instructions,
5,662,027,000 cycles, and 438,044KiB peak RSS. The later handoff reports
14,511,000,000 instructions, 6,428,000,000 cycles, and 436,396KiB, but its raw
`perf stat` output is not preserved in this tree. That later result has only
3.8% more instructions but 13.5% more cycles than the accepted control. No
architectural conclusion may treat the difference as evaluator work until a
same-source, same-binary alternating runtime-off/on series reproduces it.
The next Linux battery therefore records instructions, cycles, task clock,
minor/page faults, context switches, branches/misses, L1/LLC load misses, and
dTLB misses, and retains the raw output as an artifact.

The evidence-ranked alternative is a generated whole-demand graph-reduction
engine, not the current callback-bearing mixed-plan interpreter and not a
per-thunk JIT. The measured virtualizable evaluator/allocation families account
for 55.40% of lean cycles. `FinalForce5` alone owns 4.764 billion paired cycles,
and Node plus Apply comprise 96.63% of its claims. Hashing/serialization and
collector-only changes are too small to close the remaining cycle gate.
The proposed unit is consequently a direct native superblock spanning
`Force(Node) -> Claim -> Eval -> ApplyGuarded -> Bind -> nested Force ->
UpdateLifo -> Return`, with virtual promises/frames and packed-at-birth
per-kind epoch storage only for escaping values. Complete oracle statepoints
remain on guard, effect, or unsupported-shape exits.

This route receives no projected credit. From the preserved 5.662-billion-cycle
control, greater-than-2x versus the 7.800-billion-cycle C++ reference requires
removing about 1.762 billion cycles. Even at a fourfold local improvement, the
admitted generated regions must cover at least 2.350 billion cycles. If the
6.428-billion handoff result is reproduced, the required coverage rises to
about 3.371 billion cycles. Before backend implementation, paired PMU windows
must show that admitted regions cover the applicable floor, at least 70% of
their allocation bytes are virtual or epoch-resettable, and effect/guard exits
remain below 2%. A synthetic repeated Node/Apply/Update comparison must also
show that direct generated control can improve inclusive local cycles by at
least fourfold over the reusable mixed runner without exceeding the hot-code
cap. Failure of any floor falsifies this route rather than weakening the final
target.

The first denominator is now executable as three ignored `ratchet-core` tests:
`mixed_runner_transition_cost_probe` repeatedly restarts the exact fixed-slab
runner, while `direct_transition_cost_probe` executes the same successful
guarded Apply, Node claim, frame load, update publication, and return as one
monolithic test-only function. `empty_transition_cost_probe` measures their
common counted loop and test-process control. The semantic probes reuse runtime
storage, clear the single publication entry between iterations, and emit a
checksum. Run each test in a separate `perf stat` process with the same
`AOS_MIXED_TRANSITION_PROBE_ITERATIONS`; subtract the empty control before
comparing cycles per iteration. This probe can reject
plan-dispatch as a route, but cannot promote a backend: real oracle
integration still must meet region coverage, exit, parity, code-size, RSS, and
whole-process gates.

A CPU-pinned Linux run against the already-built release test binary removes
Cargo and Nix startup from the PMU interval. Two alternating 100-million
iteration samples retired 127,003,019,478 and 127,003,019,644 instructions for
the reusable runner, 28,502,301,750 and 28,502,301,624 for the monolithic
direct path, and 802,298,767 and 802,298,465 for the empty loop. The
corresponding cycle counts were 29,972,421,060 and 30,139,714,054;
11,804,903,549 and 11,804,701,726; and 201,913,186 and 201,651,107.
Subtracting the median empty control gives 1,262.01 versus 277.00
instructions per iteration, a 4.56-fold reduction, but 298.54 versus 116.03
cycles per iteration, only a 2.57-fold reduction. Checksums were identical and
all six legs had zero context switches.

The reusable mixed runner is therefore rejected, and the Rust monolithic
surrogate fails the predeclared fourfold local-cycle gate even though it passes
the instruction gate. It supplies no performance credit to the native
architecture. The callback-free Cranelift artifact must be measured directly
with its activation slab reused outside the interval; if that generated code
also remains below fourfold net cycle improvement, reject this lowering shape
rather than weakening the gate.

The direct generated-artifact measurement passes that gate. Two alternating
CPU-pinned 100-million-iteration legs of the finalized callback-free Cranelift
artifact retired 14,906,082,396 and 14,906,082,608 instructions and
2,403,783,857 and 2,406,850,748 cycles. Its matched activation-reset/checksum
baseline retired 2,102,821,021 and 2,102,820,652 instructions and 452,003,189
and 451,958,110 cycles. After subtracting median baseline, the generated
corridor costs 128.03 instructions and 19.53 cycles per iteration. Relative to
the reusable runner's empty-subtracted 1,262.01 instructions and 298.54 cycles,
that is a 9.86-fold instruction reduction and a 15.28-fold cycle reduction.
All four generated/baseline legs emitted the same checksum and had zero
context switches.

This promotes the callback-free lowering shape through the synthetic local
gate, not through the global gate. It still receives no whole-primary credit
until real lowered regions demonstrate the required cycle coverage,
virtual/resettable allocation fraction, effect and guard exit rate, exact
parity, bounded code size, and complete statepoint/root cleanup.

The shortest native integration point is the rooted dispatcher immediately
before `run_rooted_final_force_attempt`, not the existing per-thunk tier-1
entry. One activation must own the complete admitted FinalForce corridor.
There are two explicit prerequisites before this can be called a real
backend. First, `mixed_machine/oracle_lower.rs` currently stops at packed STG;
it does not translate multiple real bodies into the validated mixed CFG.
Second, plan v3 rejects virtual objects and generic materialization because it
has no exact recipe or oracle action. The native slice may compile the existing
no-virtual fixture for the local-cycle falsifier, but real integration requires
a versioned recipe/action contract rather than silently routing those forms
through generic callbacks.

The eventual call boundary is one status-returning, non-unwinding Candidate-C
entry over a pinned, caller-owned activation slab. Complete, oracle,
restart-entry, runtime-error, panic, and capacity exits preserve the exact
statepoint/action, resume coordinate, activation/call/update/frame depths,
result destination, and live-set identity. Every allocating helper must use
the existing one-word spill/bind/reload stack-map protocol. Suspended live
values leave native code through relocation-aware transient roots, not an
unregistered boxed slab. A Rust guard snapshots force and lambda ownership
depths and aborts back to those baselines in strict LIFO order on every
non-complete exit. Inability to make helper failure/panic cleanup
non-panicking, or any collecting call without a complete stack map, falsifies
the native route before performance is considered.

The strict pre-FinalForce cutover gate also exposes a decisive timing failure.
It requires `max(current RSS, process peak RSS) + safety` to remain below
239,054,848 bytes. The accepted native peak is already 436,396KiB before this
seam, so the primary transaction is mathematically guaranteed to decline even
with a zero-byte destination. This portal is a correctness and post-cutover
reclamation laboratory only; monotone `ru_maxrss` gives it no acceptance
credit. The memory route must change construction-time allocation or rotate
earlier while the process is still below the ceiling.

The codebase already contains a useful full-graph falsifier:
`write_supported_evacuation_destination` rebuilds closure-owned frame graphs,
rewrites frame slots through complete forwarding, reconstructs ordinary Node
thunks and other supported workers, and returns a fresh heap. A replay-free
full-heap swap can test exact parity and steady-state compaction after adding
boxed-scalar handling, configuration transfer, complete root staging, strict
absence of active leases/blackholes, and a zero-old-alias audit. Dropping the
old rewindable worker store can decommit the whole high lane rather than only
tombstoning absent workers. Its historical peak remains explicitly non-credit.

The unused packed thunk/frame lanes are not a shorter immediate mover. The
installed packed generation cannot be extended or replaced, finalized packed
collections may already contain worker coordinates, and there are no packed
lambda/primop lanes or representation-neutral production force/read/scan
paths. Moving Node alone cannot rewind the shared closure lane. A real packed
rotation must build immutable values, Node work, frames, lambdas, and primops
in one transaction, install once, heal all roots/edges/indexes, rebuild the
precise graph, obtain the zero-source-alias proof, then rewind the complete
source worker store.

This makes the speed and memory architectures converge. The only useful
collection points below the peak occur inside the recursive FinalForce
corridor, where the current Rust call stack lacks a replay-free resumable
boundary. Generated whole-demand statepoints can provide those ownership-clean
loop heads while simultaneously scalar-replacing promises/frames. Earlier
packed rotation and native superblocks are therefore coupled requirements, not
independent optimizations that can be accepted separately.
