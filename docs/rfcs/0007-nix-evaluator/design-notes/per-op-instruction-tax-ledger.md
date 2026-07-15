# Per-op instruction-tax ledger — the modal force+apply+var op

**Status:** analysis / design-note. No code changes proposed here; this ledger
ranks removable always-on work for the instruction-bloat campaign (task #22).

## Why this exists

The census finding that motivates the campaign: the ~5x cold-toplevel gap to
C++ Nix is **instruction count at equal IPC** — roughly 2000-2500 retired
instructions per evaluator op versus C++'s ~500, with op counts already
matched. The cost is *uniformly smeared* (every prior profile was flat, no
dominator), which is exactly the signature of a fixed per-op overhead stack
rather than one hot function. This note walks one representative op end-to-end
through the source and itemizes every piece of **always-on side work** (present
in the default config: cache-off, stats-off, gc-off, serial), with a rough
instruction estimate, a fires-per-op multiplier, and a removability class.

**Method and caveat.** Estimates are *static* — read from the source and sized
by hand (x86-64, release inlining assumed where annotated). They are
order-of-magnitude, meant to **rank** layers, not to be trusted to ±20%. Any
lever selected from this ledger must be confirmed with `perf stat` /
`size_of` before and after. Two structural facts (below) dominate the ranking
and are robust to the estimate error.

## The modal op and its call tree

Modal op (per the census): **one thunk force whose body performs one lambda
application, whose function position is one variable read.** Concretely the
force of a `Node` thunk whose body is `f x` where `f` is a `LocalVar`. That
single op expands into this Rust call tree (fires-per-op in brackets):

```text
force_value                                            [1]  force entry
 ├─ classify_whnf_tag_fast_path                        [1]
 ├─ reforce_already_forced_thunk → heap.get_thunk      [1]  full carrier resolve #1
 ├─ heap.share_thunk                                   [1]  full carrier resolve #2 (same Value)
 ├─ begin_force (cell CAS) / push+pop active_force_root [1]
 ├─ tier1 hook skip-check / force_cache_active check   [1]
 ├─ eval_thunk_body → eval_thunk_body_inner (Node arm) [1]
 │   ├─ ENV SWAP BLOCK (clone_env/with/scoped, reserve,
 │   │   swap, 2×mem::replace, push/pop suspended roots) [1 here … see ×2]
 │   └─ with_current_module → eval_node(body = `f x`)
 │        └─ eval_node  (stacker::maybe_grow + dispatch + force_node_result)
 │             └─ eval_apply → eval_apply_expression
 │                  ├─ node(f).span                    [1]  fetch for span
 │                  ├─ eval_node(f) → eval_local_var   [1]  the var read (+ force_node_result)
 │                  ├─ tag check / ensure_applicable    [1]
 │                  ├─ eval_call_argument → ALLOC arg thunk  [1]  alloc-plan + capture
 │                  └─ apply_lambda_value
 │                       ├─ ENV SWAP BLOCK (again)      [1]  ← the same block, 2nd time
 │                       ├─ EvalFrame::new_linked (Arc alloc) + try_reserve_exact(1)
 │                       └─ eval_node(lambda body)      [1]
 └─ finish_forced_value (publish barrier, gc shed check) [1]
```

`eval_node` fires **~3-4 times** in this op (thunk body, function subexpr,
lambda body, plus any nested thunk force), and the **ENV SWAP BLOCK fires
twice** — once installing the thunk body's captured env, once inside
`apply_lambda_value` installing the call frame. Both multipliers are structural,
not workload-dependent.

Evidence for the spine: `force_value`
`crates/ratchet-oracle/src/eval/tree_walk/alloc_intern/force_thunk.rs:27`;
`eval_thunk_body_inner` Node arm `force_thunk.rs:442-468`; `eval_node`
`crates/ratchet-oracle/src/eval/tree_walk/eval_core/stack.rs:39`;
`eval_node_on_current_stack` `eval_core.rs:474-537`; `eval_apply_expression`
`eval_apply.rs:206-232`; `apply_lambda_value` env re-swap
`eval_primop_apply.rs:348-424`.

## The two structural themes (robust to estimate error)

**Theme A — the `Result<Value, TreeWalkError>` return ABI is a ~144-byte
memory round-trip on every call boundary.** `TreeWalkError`
(`crates/ratchet-oracle/src/eval/tree_walk/errors.rs:26-32`) is an *unboxed*
struct: `kind: TreeWalkErrorKind` (a **160-variant** enum,
`error_kind.rs:8`) + `span` (8B) + `contexts: Vec` (24B) + `labels: Vec` (24B)
+ `source: Option<EvalErrorSource>` (two more `Vec`s, ~48B). Hand-sized to
**~130-150 bytes**. Because `Value` is only 8 bytes, every
`Result<Value, TreeWalkError>` is sized to the error (~144B) and, being far
larger than two registers, is returned via a hidden pointer (sret): each of the
~15-25 call boundaries in the op **stores the discriminant + 8-byte Ok payload
into a ~144-byte caller stack slot and reads it back**, on the success path,
for an error that is almost never constructed. The crate already **knows** this
— `crates/ratchet-oracle/src/lib.rs:20` carries
`#![allow(clippy::result_large_err, …)]`, suppressing the exact lint that flags
it. This is the single fattest *uniformly-smeared* layer and the cleanest
design-change: box the cold payload (`Result<Value, Box<TreeWalkError>>`, or box
the `Vec`s/`source` inside `TreeWalkError`) to shrink the `E` to a pointer,
making `Result<Value, _>` ~16 bytes and register-returnable. `map_err`
closures that build `TreeWalkError::new(...)` do **not** run on the Ok path
(confirmed — they are closures passed to `map_err`), so the cost is purely the
oversized *slot*, not eager error construction.

**Theme B — the value carrier is resolved to a heap record twice per force, and
each resolve is not O(1).** `force_value` calls `reforce_already_forced_thunk`
→ `heap.get_thunk(value)` (a full carrier decode + reservation-base lookup +
bounds check) purely to test for a cached result; on a cold miss it falls
through to `heap.share_thunk(value)` — a **second, independent full resolve of
the identical `Value` word** (`force_thunk.rs:40-48, 82`). And each resolve's
`as_heap_ptr` walks a **linear scan** of the reservation registry
(`crates/ratchet-value/src/heap/reservation_registry.rs:156-166`,
`high_water`-bounded, monotonic) rather than reading a cached base, then a
**binary-search** bounds check against live chunk regions
(`crates/ratchet-value/src/heap/flat.rs:752-762`), then re-reads the tag a
second time from the on-heap kind word (distinct from the Value word's tag
bits). The carrier tag itself decodes cheaply (~4-6 instr) but is re-derived
~2× per accessor because the accessors are not `#[inline]` across the
`ratchet-value`→`ratchet-oracle` crate boundary
(`crates/ratchet-value/src/value/candidate_c_carrier.rs:222-249, 398-410`).

## The ledger (grouped by the campaign's six categories)

Removability key: **free** (mechanical, no behavior change) · **flag-gate**
(compile/runtime gate an opt-in feature's scaffolding out of the default path) ·
**design-change** (structural, needs a plan + parity battery) · **load-bearing**
(correctness/GC-required, leave it).

### (1) Stat / counter increments

| Item | est. insn | fires/op | class | evidence |
|---|---|---|---|---|
| `note_with_env_capture` + `note_scoped_global_env_capture` — **4 unconditional global `AtomicU64::fetch_add(Relaxed)`**, NOT stats-gated, on every thunk/lambda alloc | ~40 (atomics ~10 ea) | ~2× (per alloc) | **flag-gate** (highest-confidence cheap win; also removes cross-thread contention under parallel) | `crates/ratchet-oracle/src/eval/env.rs:175-184, 311, 385` |
| `increment_thunks_forced` / `_thunk_cache_hits` / `_reforce_fast_path_hits` — plain non-atomic `self.stats.FIELD.saturating_add(1)` | ~3 ea | 1-2× | free-ish (cheap, evaluator-local; low priority) | `eval_stats.rs:463-467`, `attr_repr_stats.rs:431` |
| `begin/end_force_accounting` — `Instant::now()` **correctly gated** on `eval_stats_dump()`, returns `None` first | ~2 (branch only) | 1× | load-bearing (already gated) | `eval_stats.rs:596-627` |
| `capture_probe::note_capture`, prelude accounting — gated on `eval_stats_dump()` | ~2 (branch) | per alloc | load-bearing (already gated) | `eval_apply.rs:171`, `alloc_intern.rs:441` |

Verdict: stats are *mostly* compiled/gated out — **except** the two
`capture_persistent` atomic counters, which are always-on globals and should sit
behind the same stats gate as everything else.

### (2) `Result` + span construction / threading

| Item | est. insn | fires/op | class | evidence |
|---|---|---|---|---|
| `Result<Value, TreeWalkError>` sret round-trip (Theme A) — ~144B slot store+load on the Ok path | ~8-10 per boundary × ~20 boundaries ≈ **150-200** | ~20× | **design-change** (box the error; flagship lever) | `errors.rs:26-32`, `lib.rs:20` |
| `?` discriminant branch per boundary | ~2 ea | ~20× | load-bearing (control flow) | throughout |
| `Span` threading — 8B `Copy`, passed in registers | ~1 ea | ~20× | free (already cheap) | `aos-nix-syntax/src/lexer/mod.rs:18-23` |
| `error_with_current_source` / `map_err` closures on Ok path | 0 (don't run on Ok) | — | load-bearing | `eval_core.rs:534-547` |

### (3) Validation / branch layers

| Item | est. insn | fires/op | class | evidence |
|---|---|---|---|---|
| `stacker::maybe_grow` red-zone check wrapping **every** `eval_node` | ~15 (SP read + cmp + closure indirection) | ~3-4× | design-change (hoist to coarser granularity; or skip for leaf kinds) | `eval_core/stack.rs:39-43` |
| `force_node_result` wrapper after **every** `eval_node` — `is_suspended_lazy_identity_thunk` + `is_thunk` re-check | ~14 | ~3-4× | flag-gate/design-change (fold into the dispatch tag test) | `eval_core.rs:568-587` |
| `with_current_module` — runs `module_ir(module)?` validity re-fetch **before** the same-module equality fast-path | ~12 | ~2× | free (reorder: test equality first) | `eval_core/module_env.rs:159-176` |
| `eval_local_var` — decode + `active_env_frame_count()==0` guard + slot read | ~24 | 1× (per var) | load-bearing (lean already) | `alloc_intern.rs:188-202`, `module_env.rs:359-378` |
| `eval_apply_expression` applicability layer — `node(f).span` fetch + `tag()` match + `ensure_applicable_value` | ~30 | 1× | design-change (cacheable per-site, like the primop cache) | `eval_apply.rs:206-232` |
| `eval_lambda` — two discarded `self.node(pattern/body)?` existence fetches | ~20 | per lambda | free (drop the validation fetches; ids are immutable post-lowering) | `eval_apply.rs:164-165` |
| `*self.node(id)` copies whole `IrNode` (~32-40B) by value at several sites | ~5 ea | ~3× | free (borrow instead of copy where the node outlives no mutation) | `eval_core.rs:475`, `alloc_intern.rs:227,237` |

### (4) Value-carrier decode → heap-resolve per touch (Theme B)

| Item | est. insn | fires/op | class | evidence |
|---|---|---|---|---|
| Double full resolve of the same `Value` per force (`get_thunk` then `share_thunk`) | ~40 ea, one redundant ≈ **40 wasted** | 1× | **design-change** (thread the decoded record through) | `force_thunk.rs:40-48, 82` |
| `reservation_base` **linear scan** on every resolve (not a cached base) | ~10-25 | every resolve (~5×/op) | **design-change** (cache per-heap base → O(1) arithmetic) | `reservation_registry.rs:156-166` |
| `contains_address` **binary search** bounds check per resolve | ~10-15 | ~5× | design-change (single `[base,base+len)` range compare) | `flat.rs:752-762` |
| Tag decoded ~2× per accessor (non-inlined cross-crate) + on-heap kind-word re-read | ~8-12 | ~5× | flag-gate (`#[inline]` the carrier accessors) | `candidate_c_carrier.rs:222-249, 398-410, 485-497` |
| `classify_whnf_tag_fast_path` | ~4 | 1× | free (already minimal) | `whnf_tag.rs:73-79` |
| `note_flat_resolution` (Cell add) + `object.touch(epoch)` (Relaxed atomic) per resolve | ~6 | ~5× | flag-gate (gate the epoch touch to gc-on) | `flat.rs` resolve path, `deref_counters.rs` |

### (5) Allocation-plan machinery per thunk / lambda alloc

| Item | est. insn | fires/op | class | evidence |
|---|---|---|---|---|
| Alloc-plan classification + gc-stress dispatch checks + `defer_flat_capture` bookkeeping (all short-circuit when opt-ins off) | ~60-90 | ~2× | **flag-gate** (collapse behind one "any-lever-active" check) | `alloc_intern.rs:256-260, 293-299`, `alloc_intern/gc_stress.rs:20-27,331-345`, `flat_capture.rs:37-71` |
| `capture_env` — flat-plan flag read + `facts.capture_plan(id)` lookup + `capture_linked_with_flat_base` | ~20-30 | ~2× | design-change | `eval_core/module_env.rs:270-330`, `env/capture.rs:309-317` |
| `capture_dynamic_envs` → 2× `capture_persistent` (the atomics of row (1)) | see (1) | ~2× | flag-gate | `capture_on_demand.rs:83-101` |
| `EvalFrame::new_linked` **`Arc::new` alloc** + `try_reserve_exact(1)` **2nd Vec malloc** per apply | malloc-class (~50-100) | 1× | design-change (frame arena — note: FV-6 found residual ~2.8-3.4%, see closed-lever memo) | `eval_primop_apply.rs:351-358` |
| `increment_thunks_allocated` (non-atomic) | ~3 | ~2× | free-ish | `attr_repr_stats.rs:416` |

### (6) Surprises

| Item | est. insn | fires/op | class | evidence |
|---|---|---|---|---|
| **ENV SWAP BLOCK fires twice** per op (thunk-body install + apply-frame install), each ~90-120 insn of clone/reserve/swap/push/pop | ~100 × **2** ≈ **200** | 2× | **design-change** (the structural one — fuse apply into the body force, or share chain-head; note env *payload* is 89% empty per the closed env-flatten lever, so the target is the **swap count**, not flattening) | `force_thunk.rs:449-467`, `eval_primop_apply.rs:348-424` |
| `stacker::maybe_grow` on every node (row 3) is a per-node function-call + SP probe most ops never need | ~15 | ~3-4× | design-change | `eval_core/stack.rs:39` |
| `clone_with_scopes`/`clone_scoped_globals` are genuinely O(1) `Option<Arc>` clones even when non-empty (persistent tail) — **not** a target | ~8 | ~2× | free (already optimal) | `module_env.rs:586-602`, `env.rs:208-211` |

## Budget reconciliation

Summing the always-on layers across the modal op (force entry ~300, ~3 `eval_node`
dispatch wrappers ~150, apply layer ~285, var read ~24, ~2 allocs ~270,
cross-cutting `Result` sret + `?` ~240, ~5 heap resolves ~200, plus ~3 real
mallocs amortized ~225) lands in the **~1500-1900 instruction** range before
counting the actual arithmetic of the op — consistent with the census's
2000-2500. Crucially, it **decomposes into ~15-20 identifiable 15-200-instruction
layers**, which is the campaign's thesis: there is no single 1500-instruction
function to delete, but there *is* a stack of dietable layers.

## Ranked levers (fattest removable first)

1. **Box `TreeWalkError`** (Theme A, category 2). ~150-200 insn/op, uniformly
   smeared, whole-crate but mechanical; the lint is already suppressed so the
   size is known-bad. Confirm with `size_of::<Result<Value,TreeWalkError>>()`
   before/after and the 546 battery. **Highest expected wall impact.**
2. **Collapse the double heap-resolve + O(1)-ify the reservation base** (Theme B,
   category 4). ~50-80 insn/force; design-change with a clear shape (thread the
   record; cache the base the registry doc already claims exists but isn't
   wired).
3. **Halve the ENV SWAP BLOCK** (category 6). ~200 insn/op if the apply-site
   re-install can be fused with the body force. Biggest structural item; needs
   its own design note (the env *payload* work is already closed as
   empty-dominated — this is specifically the swap-count/rooting scaffolding).
4. **Gate the two `capture_persistent` atomics** (category 1). ~40 insn/op +
   removes parallel contention; cheapest, highest-confidence, near-free to do.
5. **`#[inline]` the carrier accessors + gate the epoch touch** (category 4).
   Removes redundant tag re-decodes; small but free.
6. **Reorder `with_current_module`, drop `eval_lambda`'s validation fetches,
   borrow `IrNode` instead of copying** (category 3). A cluster of small free
   wins, each ~5-20 insn but on every-node multipliers.

Items 4-6 are the "diet one by one, ships on non-negative A/B" class (mirroring
the wave-1 discipline); items 1-3 are design-changes each warranting a plan +
byte-parity battery. Item 1 is the recommended first strike: largest smeared
share, mechanical, and independently measurable.

## Related closed levers (do not relitigate)

Env-payload flattening (89% installs empty), L2-parallel-toplevel (Amdahl
~1.04x), and FV-6 frame-arena (residual ~2.8-3.4%, MEMORY-coupling kill) are
closed — see the campaign memory. This ledger's env item (6) targets the swap
**count/scaffolding**, which those did not; the frame-alloc row (5) overlaps
FV-6 and inherits its caution.
