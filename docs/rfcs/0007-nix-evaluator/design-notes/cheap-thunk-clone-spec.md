# Cheap thunk clone on the force path — spec (fv5)

Primary cold-axis increment for the real-workload finding (doc 15 §5.5: native
~4.8x slower cold on the system toplevel). Profile-picked lever, not a guess.

## 0. Why does `clone_thunk` clone at all? (answer first — it sets the design)

**Borrow-detach artifact, not semantic isolation.** `force_value`
(`eval/tree_walk/alloc_intern.rs:1632`) calls `self.heap.clone_thunk(value)` to
get an *owned* `EvalThunk`, then passes `&thunk` into `force_serial_thunk_value`,
which re-enters the evaluator (`&mut self`, allocating on the heap) to evaluate
the body. Holding a `&EvalThunk` borrowed *out of* `self.heap` across that
re-entry is a borrow-check conflict, so the thunk is cloned to release the heap
borrow. `clone_thunk`'s own doc says exactly this: "so forcing can release the
heap borrow before re-entering evaluation." The thunk's `kind`/env is immutable
during force and the result is published through the `Arc<ThunkCell>`, so nothing
here needs an *isolated* copy — the clone exists purely to satisfy the borrow.

## 1. What is actually expensive (refines the plan)

The captured env is **already cheap to clone** — this is the key finding that
changes the design:

- `EvalEnv.storage` = `EvalEnvStorage::Chain { head: Option<Arc<EvalFrame>>,
  frames: usize }` — clone is **one Arc bump** (the frame chain is shared via
  `EvalFrame.parent: Arc`). (`Array(Arc<[..]>)` compat variant: also one bump.)
- `EvalEnv.flat_base` = `Option<EvalFlatCapture>`, and `EvalFlatCapture` is an
  all-`Copy` handle `{ allocation_site, frame_count, owner: Value, tail }` — the
  captured values stay **inline in the owner's flat object** (FV-5 intact). Copy.
- `with_env` / `scoped_globals` = `PersistentEnvStack` (`Arc`-linked). Cheap.

So `EvalThunk::clone` (9.5% self-time) is **not** a deep env copy. It is:
1. a `memcpy` of the whole ~128-byte `EvalThunk` (kind enum + env + with_env +
   scoped_globals + `Arc<ThunkCell>` + `force_storage_mode` + `parallel_cell`),
2. ~4-5 `Arc` refcount **increments** (storage head, with_env, scoped_globals,
   cell, maybe parallel_cell),

done **2.9M times** (once per force). The matching ~4% drop cluster
(`Arc::drop_slow` ×2, `drop_in_place<EvalThunk>`, `mi_free`) is those Arc
**decrements** when the per-force clone is dropped moments later — pure churn.
(The separate 15% `memmove` under `apply_lambda`/`eval_binary` is Value/list/attr
copying in the eval path, a distinct second lever, not this clone.)

**Consequence:** the lever is NOT "Arc-share the env" (already shared). It is to
stop cloning the whole `EvalThunk` per force — either detach a minimal handle or
share the record by one Arc.

## 2. Candidate representations

- **(A) Arc the thunk record.** Store thunks as `Arc<EvalThunk>` (or force reads
  through the flat-store slot by a cloned `Arc`), so `clone_thunk` = one
  `Arc::clone` (1 bump, no struct memcpy). Kills most of 9.5% + 4%. Cost: +16 B
  refcount + an allocation per thunk (memory — but toplevel RSS is 0.03x, ample
  headroom), and it must reconcile with the flat-thunk store (FV-3) which owns
  thunks inline today.
- **(B) Minimal owned `ForcePlan`.** `clone_thunk` returns a small
  `{ body: EvalNodeRef, env: EvalEnv, with_env, scoped_globals, cell: Arc<ThunkCell> }`
  instead of the full `EvalThunk` — drops `force_storage_mode`/`parallel_cell`
  from the copy and lets the compiler pack it tighter. Smaller memcpy, same Arc
  bumps. Lower ceiling than (A) but zero memory cost and zero representation
  change.
- **(C) Borrow restructure.** Split the heap borrow so force reads the thunk
  fields by reference and re-enters `&mut` on a disjoint sub-borrow (e.g. take
  the body+env by value up front, then borrow only the allocator). Highest
  ceiling (no clone at all) but the deepest change to the force loop.

**Recommendation:** prototype **(B)** first (cheapest, no representation/memory
change, measurable) to bank the memcpy-shrink and confirm the split of clone
cost between memcpy and Arc-churn; if the residual is Arc-churn-bound, escalate
to **(A)**. Hold **(C)** unless (A)+(B) miss the double-digit target.

## 3. Hazard rows (must each stay green)

| Interaction | Concern | Requirement |
|---|---|---|
| FV-5 inline flat captures | must not un-inline (29.2M `payload_arc_clones` kill measured) | `EvalFlatCapture` stays a Copy handle into the owner; (A)/(B) copy the handle, never materialize values |
| Parallel eval (K=4) | sharing primitive must be worker-safe | `Arc` is Send+Sync; (A) is worker-safe. `parallel_cell` path unchanged; parity gate at K=4 |
| `shed_forced_thunk_captures` (env-release) | (A) changes "sole owner" reasoning (an Arc'd record has >1 ref during force) | shed already swaps the flat/record payload; verify the swap-door still has exclusive access, or gate shed to refcount==1 |
| JIT `dispatch_env` clone (`engine.rs`, "owned clone so native never sees the live env stack") | native dispatch relies on an owned env snapshot | keep dispatch's owned-snapshot semantics; (A)/(B) must still hand JIT an owned env, not a shared live handle |
| GC sweep | released/forced records must remain sweepable | sweep reads record kind; (A)'s Arc wrapper must not hide the record from the sweep walk |

## 4. Gates per landing

Byte parity ×4 (serial + JIT + K=4 + sweep) + a before/after of the exact
profile lines (`EvalThunk::clone`, `memmove`, drop cluster) and the toplevel
cold `native_mean`. **Target: double-digit-% cold win** on the toplevel, else
re-examine. Land as: (1) this clone lever, (2) frame-alloc fast path, (3)
env-release-on-force behind a flag (daemon reclaim).
