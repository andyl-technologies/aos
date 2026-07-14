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

## 2. The cost is Arc-refcount churn, not memcpy (so the fix is (A))

The memcpy-vs-churn split is resolvable by arithmetic, which rules out the two
cheaper candidates before any build:

- **memcpy is ~1%.** `EvalThunk` is ~128 B; 128 B x 2.9M forces = ~371 MB copied;
  at ~15 GB/s that is ~25 ms = ~1% of the 2.6s cold wall. Negligible.
- **the clone+drop clusters are Arc atomics.** `EvalThunk::clone` (9.5%) is ~5
  `Arc::clone` **increments** (`EvalEnvStorage::Chain` head, `with_env`,
  `scoped_globals`, `cell`, parallel-cell slot) x 2.9M forces ~= 14.5M atomic
  ops; the ~4% drop cluster (`Arc::drop_slow` x2, `drop_in_place<EvalThunk>`,
  `mi_free`) is the matching ~14.5M decrements when the per-force clone is
  dropped moments later. ~13.5% combined is refcount churn.

**Chosen representation — (A) single-Arc thunk record.** Put the record behind
one `Arc` so `clone_thunk` on the force path is a single `Arc::clone`
(1 increment) and its drop is a single decrement, and force reads all the
handles *through* the `Arc` — no struct memcpy, no dangle across the serial
record-`Vec` realloc (the `Arc` keeps the record alive + at a stable address).
Collapsing ~5+5 atomics to ~1+1 takes the ~13.5% to ~1.5% = **~12% cold win,
clearing the double-digit target on its own.** The before/after profile of the
`clone`/`drop` clusters is the measurement; there is no cheaper probe (a copy
shrink can't move a churn-bound cost).

Rejected alternatives, recorded so the escalation question never reopens:
- **(B) minimal `ForcePlan`** — the two fields it would drop
  (`force_storage_mode`, `parallel_cell`) are read on the hot path
  (`is_single_entry_force_storage`; serial-vs-parallel routing), so dropping
  them is a behavior change, not a shrink; and even if reordered (route first,
  clone `kind`+`cell`), it removes ~8 B from an already-~1% memcpy and **zero**
  Arc bumps on the serial path (`parallel_cell` is `None` there). Answers
  nothing.
- **(C) borrow restructure** — the serial record table is a `Vec` that
  reallocates when body-eval allocates, so a `&EvalThunk` held across the force
  re-entry dangles. That realloc hazard is *why* `clone_thunk` detaches; a pure
  borrow can't replace it on the serial path. (Rider-1 answer: the Arc bumps
  that would have to become borrows under (C) are exactly the ones (A) removes,
  so (A) captures (C)'s ceiling without the unsafe borrow.)

**FV-3 reconciliation (the real design fork).** The flat-thunk store owns thunks
inline today; (A) needs the force path to obtain a stable ref-counted handle to
a thunk regardless of whether it lives in the record `Vec` or the flat store.
Options to resolve in the impl increment: (i) store `Arc<EvalThunk>` in the
record slot / flat slot uniformly; (ii) keep inline storage but hand force an
`Arc` minted lazily and cached in the slot on first force (amortizes the alloc
to first-force, not per-force). Prototype (ii) first — it preserves FV-3's
inline placement and only pays the +16 B on thunks that are actually forced.

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

## 5. Implementation increments (grounded in the storage)

Thunks live in three stores, each read by `clone_thunk`
(`eval/heap/arena.rs:2567`): the **serial flat store** (FV-3, default via
`WorkerClosurePlacement::Flat` -> `flat_alloc_thunk`; `FlatClosurePayload::Thunk`
holds the `EvalThunk` inline), the **record table** fallback
(`reserve_record_slot`; `HeapObjectValue::Thunk`), and the **shared arena**
(parallel; `shared_alloc_thunk` / `clone_thunk_ptr`).

- **I1 — serial flat store (the hot path; ~all toplevel forces).** Lazily mint
  `Arc<EvalThunk>` on first `clone_thunk`: move the inline `EvalThunk` into an
  `Arc` through the existing `flat_swap_thunk_payload` door (add a
  `FlatClosurePayload::SharedThunk(Arc<EvalThunk>)` variant, or a slot-side
  `OnceLock<Arc<EvalThunk>>`), cache it in the slot, return `Arc::clone`.
  `force_value`/`force_serial_thunk_value` take `&EvalThunk` via `Arc` deref —
  read through the Arc, no per-force struct copy. Keep a `get_thunk` borrow for
  the routing reads (`parallel_payload_cell`, `is_single_entry_force_storage`)
  before the detach. Gate: parity ×4 serial + JIT, before/after profile, cold.
  This alone should show the ~12%.
- **I2 — record-table + shared/parallel paths.** Extend the same Arc handle to
  the record-table fallback and the shared `clone_thunk_ptr` (worker-safe: `Arc`
  is Send+Sync; the parallel_cell path is unchanged). Gate: K=4 parity + sweep.
- **I3 — frame-alloc fast path** (`EvalFrame::new_linked` + alloc cluster).
- **I4 — env-release-on-force behind a flag** (promote `shed_forced_thunk_captures`
  to Tier-A at publication; per hazard row 3, gate its swap on `Arc` sole
  ownership — `strong_count == 1` / `Arc::get_mut` — else defer, since an
  in-flight force holds a second ref).

**I3/I4 SHELVED (2026-07-14, measured).** I1+I2 landed and eliminated the
Arc-churn counters (serial −93 %, K=4 −61 %) with byte-identical behavior —
but an interleaved pre/post toplevel A/B measures the cold wall **neutral**
(doc 15 §5.5 addendum, 0c602a208): the churn was counters-large, wall-small.
Applying the same test to I3 before building: a 5 s top-of-stack sample of
`bench.compute.lambda-interp` (the module-fixpoint shape-class proxy) shows
**no `EvalFrame` allocation in the hot leaves at all** — the wall is
interpreter dispatch (`eval_node_on_current_stack`), attrs allocation
(`alloc_attrs_with_projected_shape_metadata`), `memmove`, and compressed-word
decode (`kind`/`semantic_tag`). I3 targets a non-hotspot; projected neutral.
I4 is a memory lever and the memory target is already exceeded (wide-eval
0.19x of C++). Both shelved with this evidence; re-open only if a profile of
a real workload shows frame alloc/retention in the leaves. The load-bearing
wall levers for this shape class are JIT coverage of the module-fixpoint
shape and the heap-image prelude snapshot (doc 31 §1) — and the sample
points at attrs-alloc + word-decode as the next attribution targets after
those.

Hazard resolutions to encode in I1: JIT `dispatch_env` keeps cloning an **owned**
env snapshot out of the Arc'd thunk (never the shared handle); GC sweep reads the
record kind through the Arc deref; FV-5 `EvalFlatCapture` stays a Copy handle
(the Arc wraps the thunk, not the capture values, which remain inline in the
owner).
