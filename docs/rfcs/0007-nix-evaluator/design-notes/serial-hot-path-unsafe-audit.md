# Serial evaluator hot-path and `unsafe` audit

**Status:** measured exploration, 2026-07-22. This note compares the shipped
Candidate-C tree walker at `db666f2c` with the pinned C++ Nix 2.24.12 tree
walker. It does not propose bytecode and makes no runtime change.

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
