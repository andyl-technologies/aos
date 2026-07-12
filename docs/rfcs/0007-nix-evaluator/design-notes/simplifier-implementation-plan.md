# RFC-0007 — Simplifier implementation plan (design note)

> Design-only prep for the doc-26 simplifier (task #7 / doc 22 "Tier 4a"). This
> note maps [26 — optimization pass catalog](../26-optimization-pass-catalog.md)'s
> §1 fixpoint driver and first four passes onto the **actual** ratchet IR,
> lowering pipeline, and parse/compile cache as they exist today, cites the code
> seams by `file:line`, and proposes a staged, parity-gated landing order. It is
> a plan, not an implementation; no code was changed and no build was run to
> produce it. Where doc 26/25/07 claim something the code does not yet support,
> it is called out in §7 (doc-vs-code divergences).
>
> Companion specs: [26](../26-optimization-pass-catalog.md) (per-pass contracts),
> [25](../25-intermediate-representation.md) (IR taxonomy + content-addressed
> cache), [07](../07-laziness-and-whole-program-analyses.md) (the licensing
> analyses), [28](../28-generalization-and-language-dialects.md) (Core/dialect
> factoring, the open effect lattice `S-23`).

## 0. Executive summary

- **There is no IR-to-IR rewrite infrastructure today.** Every existing
  "optimization" is either a *fact annotator* that writes only the side
  `IrFacts` table (`ratchet-core/src/ir/annotate.rs:223-236`) or a *planning
  pass* that returns a read-only plan and explicitly "does not rewrite IR"
  (e.g. `ratchet-core/src/analysis/dead_binding.rs:6`,
  `ratchet-core/src/analysis/scalar_replacement.rs:8-9`). The simplifier will be
  the **first structural rewriter** in the codebase.
- **The IR arena is append-only and externally immutable.** `IrArena` exposes
  read accessors and `from_raw_parts`, but `push_node`/`push_child_slice` are
  `pub(super)` and there is no `node_mut` / `set_node` / `remove`
  (`ratchet-core/src/ir/arena.rs:15,41,55`). A rewriter must either widen that
  visibility (build the pass inside the `ir` module) or **rebuild a fresh `Ir`
  via `from_raw_parts`**, remapping `IrId`s across all six side tables.
- **The single safe choke point is the lowering→persist seam.** Run the
  simplifier immediately after `nix_lower` and before the IR is encoded to
  `ir.bin` / fingerprinted / handed to eval and the JIT, inside
  `ratchet-oracle/src/cache/parse/entry.rs:write_resolved` (between `:103` and
  `:116`) and the cold-parse path in `.../parse/mod.rs:409-413`. Because warm
  loads reload `ir.bin` **verbatim** without re-lowering
  (`.../parse/entry.rs:read_ir`, `:378-417`), simplifying before persistence
  keeps every downstream fingerprint coherent (§2).
- **The first increment must be a no-op.** Land the phased fixpoint *driver
  skeleton with all passes off*, so `simplify(ir) == ir` byte-for-byte and no
  cache key moves. Then enable one pass at a time behind a flag, each gated by
  the byte-identical `.drv` diff.
- **Recommended first four passes, in code-effort order:** (1) constant folding
  (§2 doc 26 §2.2 — smallest, most local), (2) case-of-known (§2 doc 26 §2.3),
  (3) inlining/beta (§2 doc 26 §2.1 — the keystone, but the hardest because of
  frame/slot rewriting), (4) dead-binding elimination (§2 doc 26 §2.4 — needs
  the demand fixpoint and arena compaction). This deliberately reorders doc 26's
  numbering to front-load the low-risk, arena-stable rewrites.

## 1. Where the pass pipeline slots in

### 1.1 The IR that passes operate over

The lowered artifact is `Ir` (`ratchet-core/src/ir/mod.rs:266-294`):
`root: IrId`, `arena: IrArena`, `facts: IrFacts`, `symbols: SymbolTable`,
`frames`, `with_chains`, `attr_paths`, `bindings`, `shapes`. Nodes are fixed
-stride `Copy` `IrNode { kind: IrKind, span: Span, effect: EffectClass, data:
IrData }` (`.../ir/mod.rs:453-475`); variable-arity payloads (children,
bindings, attr-paths, shapes, with-chains) live in the flat side tables, **not
inline**. A rewrite that changes a node's arity must keep those side tables
consistent — this is the main structural-integrity burden of a rewriter.

`IrKind` is a closed 29-variant taxonomy (`.../ir/mod.rs:478-539`); `IrData` is
the kind-specific payload union (`.../ir/mod.rs:542-710`). The exact
`IrKind → IrData` pairings the first four passes match on (verified at the
lowering push sites):

| Node | `IrKind` | `IrData` (fields) | Push site |
|------|----------|-------------------|-----------|
| Application | `Apply` | `Pair { first = fn, second = arg }`, **arg lowered lazily** (`LazySecond::Yes`) | `.../ir/lowering.rs:498` |
| Field read | `Select` | `Select { site: IrInlineCacheSiteId, receiver, path: IrAttrPathId, default: Option<IrId> }` | `.../ir/lowering.rs:519-528` |
| Has-attr | `HasAttr` | `HasAttr { site, receiver, path }` | `.../ir/lowering.rs:571-579` |
| Conditional | `If` | `Triple { first = cond, second = then, third = els }` | `.../ir/lowering.rs:613-620` |
| Binary op | `BinOp` | `Binary { op: BinOpKind, lhs, rhs }` | `.../ir/lowering.rs:633` |
| Unary op | `UnaryOp` | `Unary { op: UnaryOpKind, operand }` | `.../ir/mod.rs:600-605` |
| Let | `Let` | `Let { bindings: IrBindingSlice, body, frame: Option<FrameId> }` | `.../ir/lowering.rs:590-598` |
| Attr set | `AttrSet` | `AttrSet { shape: IrShapeId, bindings, recursive, has_dynamic, frame }` | `.../ir/lowering.rs:272` |
| Direct builtin | `PrimOp` | `PrimOp { symbol, args: IrChildSlice }` | `.../ir/primops.rs` via `lower_apply` |
| `.drv` boundary | `PrimOp` | `DialectNode { op: NIX_OP_DERIVATION_STRICT, argument }` | doc 25 §4.7; effect `NIX_EFFECT_DERIVATION_STRICT` |
| Lazy cell | `ThunkAlloc` | `Node(inner)` | `.../ir/lowering.rs:851` |
| Local / upvalue ref | `LocalVar` / `UpvalVar` | `Local { slot }` / `Upval { depth, slot }` | `.../ir/lowering.rs:62-73` |

Two structural facts that shape every pass:

1. **Variables are born resolved.** Scope resolution, de-Bruijn slot/upvalue
   assignment, and `with`-chain resolution happen in `ratchet-core/src/scope/`
   *before* lowering; lowering copies the coordinates straight through
   (`.../ir/lowering.rs:62-73`). Free-variable checks a pass needs (for
   inlining, float-out, CSE identity) are therefore exact `(depth, slot)`
   comparisons over `IrData::Local`/`Upval`, not name lookups — doc 25 §3's
   "born resolved" promise holds in code. **But** substituting a term across a
   binder (beta-reduction, inlining) changes de-Bruijn depths and frame slot
   layouts; the rewriter must renumber `Local`/`Upval` slots and rewrite
   `frame: Option<FrameId>` payloads, or it will silently mis-resolve variables.
   This is the single largest correctness hazard in the inlining pass.
2. **`Select`/`HasAttr` carry an inline-cache `site: IrInlineCacheSiteId`**
   (`.../ir/lowering.rs:518-528, 570-579`), allocated by `next_inline_cache_site`
   from a per-module counter. Folding a `Select` away (case-of-known) drops a
   site; duplicating one (CSE, inlining) reuses a site id. The plan must confirm
   whether the runtime indexes a per-module IC table by dense `site` ids (if so,
   a rewrite that changes the live site set must renumber them) — flagged as an
   open question (§5, Q3).

### 1.2 The effect model the soundness floor consults

Doc 26's soundness floor ("fold only `Pure`/total, never make a lazy binding
strict unless proven") maps onto `EffectClass { speculable: bool, key: u8 }`
(`.../ir/mod.rs:717-760`) via `is_speculable()` (`:752`) — this is decision
`S-23`'s open lattice (doc 28 §5, §8 checklist line 398). The Nix dialect
supplies the members in `aos-nix-dialect/src/lib.rs`: `NIX_EFFECT_PURE` plus the
non-speculable members `DERIVATION_STRICT`, `IMPORT`, `IFD`, `READ_FILE`,
`FILE_IO`, `ENV`, `FETCH`, `TRACE`, `GENERIC` (lib.rs:30-57), classified per
builtin by `nix_builtin_effect_of` (lib.rs:116-137). **Every "is this node
speculable / foldable / movable" test in the simplifier reads
`node.effect.is_speculable()`** and must never hard-code `Pure`/`Effectful` —
exactly the `S-23` contract.

Divergence to design around (§7, D3): the dialect has **no** effect member for
`builtins.currentSystem` or other CLI-sensitive builtins. Such a builtin
currently classifies as `NIX_EFFECT_PURE` (speculable) if flagged pure metadata,
or falls to `NIX_EFFECT_GENERIC` if effectful. A constant-folding or
specialization pass that trusts `is_speculable()` could fold a
`currentSystem`-dependent expression to the builder's system string and bake it
into the `.drv` — a parity break on any cross-system eval (`--eval-system`).

### 1.3 The fixpoint driver, mapped

Doc 26 §1 (lines 40-72) specifies `simplify(ir)`: run analyses, then for each
phase `[Gentle, Main, Final]` repeat `apply_passes` to a local fixpoint capped
at `MAX_ITERS`, refreshing facts on the smaller IR. Mapped onto today's code:

- **`run_analyses` already exists** as the fact producer: `annotate_ir`
  (`.../ir/annotate.rs:185-195`) → `run_analyses` (`:223-236`) runs
  strictness → cardinality → escape → capture and stamps
  `IR_ANALYSIS_VERSION = 7` (`:56`, doc 26 checklist line 630 calls this the
  "current precursor"). The driver's `facts = run_analyses(ir)` and
  `refresh_facts(ir)` steps are `annotate_ir(&mut ir)` calls — it already resets
  to a conservative baseline and re-runs, so re-running on the smaller IR after a
  rewrite is directly supported. **After any structural rewrite, facts are
  invalid and `annotate_ir` must be re-run** (it reallocates the fact table to
  the new `node_count`, `:186-187`).
- **The fixpoint termination test `ir' == ir`** needs a cheap structural
  equality. `IrData` derives `PartialEq` but not `Eq`/`Hash` (it carries `f64`,
  `.../ir/mod.rs:542`), so the driver should compare the encoded artifact
  (`encode_lowered_ir`, see §3) or a `LoweredIrFingerprint` (§1.4) rather than a
  deep `==` walk. Comparing fingerprints per iteration is O(size) and reuses
  existing code.
- **`MAX_ITERS`** is decision `M-24` (doc 26 §1 line 66). The skeleton should
  take it as a const with a conservative default and a stats counter for
  iterations-to-fixpoint.
- **Phase enum + per-pass phase membership** come straight from doc 26 §3's
  table (lines 580-596). The skeleton encodes `Phase { Gentle, Main, Final }` and
  a static pass registry mapping each pass to the phases it runs in.

### 1.4 Cache-key coherence (the load-bearing analysis)

Changing the IR changes fingerprints that are used as memo and JIT cache keys.
The relevant keys and how they move:

- **`LoweredIrFingerprint`** = blake3 over `encode_lowered_ir(ir)` +
  `encode_symbols(ir.symbols)`, salted with `PARSE_CACHE_SCHEMA_VERSION`
  (`.../cache/parse/mod.rs:137-150`, verified). It hashes the **full lowered-IR
  structure including node ordering / `IrId`s** plus the symbol table — no source
  bytes. Any structural rewrite moves it.
- **`facts.bin`** embeds the fingerprint of the IR it was computed against
  (`.../cache/parse/format.rs:255`, checked on decode at `:477`). A rewrite
  invalidates persisted facts unless they are recomputed against the new IR.
  Note `write_resolved` deliberately persists facts at **analysis version 0**
  (conservative, "the analysis pipeline has not run", `.../cache/parse/entry.rs:119-121`);
  `annotate_ir` runs later on warm refresh (`.../cache/parse/mod.rs:486`) and
  imports use `annotate_import_ir` (`.../eval/tree_walk/eval_load.rs:181,256`).
- **JIT tier-2 compiled-body key** `CompiledBodyRecordHash::for_unary_tier2`
  folds in the `LoweredIrFingerprint` **and** the def-site `pattern`/`body`
  `IrId`s (`crates/aos-nix/src/jit/engine/tier2/compiled_body_cache.rs:413-429`,
  `.../cache/hashing.rs:442-491`). Both the fingerprint and the raw `IrId`s move
  under a rewrite; they move together, so within one schema version the key stays
  self-consistent, but there is no cross-version reuse.
- **Eval demand memo key** `DemandCacheKey`/`CacheExprIdentity`
  (`.../cache/key.rs:33-71,110-167`) = `(module identity, node span, IrId,
  free-var value hashes)`. Module identity uses **source bytes when present**
  (`.../eval/tree_walk/eval_core/module_env.rs:48-53`, verified) and falls back
  to `lowered_ir_fingerprint(module.ir)` only for source-less modules (`:54-58`).
  So for a normal user file the memo key is stable across a rewrite **iff the
  pass preserves each surviving node's `span` and `IrId`** — which a compacting
  rewrite (DCE, inlining) will not.
- **`ParseCacheKey`** (on-disk entry dir) is source-bytes only
  (`.../cache/parse/mod.rs:96-105`, verified) — it does **not** move; the same
  directory is reused, but its `ir.bin` content changes.

**Conclusion — the seam.** Every consumer recomputes the fingerprint from
whatever IR it holds. Coherence therefore requires that all holders observe the
same post-pass IR. The one seam that guarantees this is **immediately after
`nix_lower`, before the IR is encoded / fingerprinted / persisted / evaluated**:

- `.../cache/parse/entry.rs:write_resolved` between `:103` (`nix_lower`) and
  `:116` (`encode_lowered_ir`) / `:118` (fingerprint), and
- the cold-parse path `.../cache/parse/mod.rs:409-413` (`nix_lower` →
  `write_resolved`), plus the metadata path `.../cache/parse/meta.rs:45-47`.

Because `read_ir` reloads `ir.bin` verbatim (`.../cache/parse/entry.rs:378-417`),
running the pass before `write_resolved` makes the persisted and in-memory IR
byte-identical, so the fingerprint every reader derives equals the one eval and
the JIT compute — all keys stay coherent, and warm loads pay zero simplifier
cost (the doc's "memoized compile-node" property, doc 26 §1 line 69, achieved
here by piggy-backing on the parse-cache artifact rather than a separate node).

**Two ways to realize the doc's "compile-node keyed by input-IR hash":**

- **(A) Seam / persist-simplified (recommended first).** Simplify inside the
  lowering→persist seam; `ir.bin` stores the *simplified* IR; its fingerprint is
  the simplified fingerprint. Simplest, fully coherent, no new cache format. The
  downside is the input IR is not separately addressable, so the simplifier is
  not *independently* memoized — it is memoized transitively with the parse
  artifact (which is keyed on source bytes). Adequate for cold-eval wins.
- **(B) Separate compile-node (doc-faithful end state).** Persist input IR and
  cache simplified IR against the input `LoweredIrFingerprint` in a new
  content-addressed store (mirrors doc 25 §7 / doc 26 §1). Needed only if we want
  cross-source IR-sharing or to memoize the simplifier independently of parsing.
  Defer until (A) is proven; it is a cache-format change (schema bump).

Either way, a compacting pass that renumbers `IrId`s/spans invalidates the eval
memo key and the JIT def-site key even for semantically-equal IR. If cross-run
JIT-cache reuse matters, treat a change to the pass set as a
`PARSE_CACHE_SCHEMA_VERSION` bump (`.../cache/parse/mod.rs`) and a tier-2
`SCHEMA_VERSION` bump (`.../jit/engine/tier2/compiled_body_cache.rs`) so stale
records are cleanly superseded, not silently mismatched.

## 2. The first four passes: match sets, hazards, preconditions

For each pass: the match predicate in **our** `IrKind`/`IrData` taxonomy, the
Nix-specific parity hazards, and the preconditions that make the rewrite
observation-preserving. The soundness floor (doc 26 §1 lines 86-98) binds all
four: fire only when `node.effect.is_speculable()` holds and totality/proof
conditions are met; a fold that would raise **declines** (the error is
quarantined at runtime, not surfaced at compile time).

### 2.1 Constant folding (doc 26 §2.2) — recommended first

- **Matches.** `BinOp` (`IrData::Binary`), `UnaryOp` (`IrData::Unary`), and
  `PrimOp` (`IrData::PrimOp`) all of whose operand `IrId`s resolve to literal
  nodes — `IrKind::{Int, Float, Bool, Str, Path, Null}` — or already-folded
  constants. Rewrite to a single literal node.
- **Preconditions.** (a) `node.effect.is_speculable()`; (b) the operator/primop
  is **total** for these literals, from a fixed per-operator table (doc 26 §2.2
  lines 163-169) — *not* an analysis. Partial ops decline: `BinOp(Div, _, 0)`,
  `PrimOp(head, [])`, `elemAt` OOB, integer overflow.
- **Parity hazards.**
  - **String contexts (doc 25 §4.6, lines 424-443).** Folding `Str ++ Str` must
    concatenate and **union the string contexts**, not just the bytes. A
    context-dropping fold changes `derivationStrict`'s environment serialization
    and thus the `.drv` (doc 25 line 361). The folder must carry context through,
    or decline on any operand that carries a non-empty context until context
    merging is implemented.
  - **`currentSystem`/CLI-sensitive builtins (§1.2, D3).** Do not fold any
    `PrimOp` whose value depends on eval-time CLI/system state, even though it may
    report `is_speculable()`. Until an effect member exists, maintain a static
    deny-list in the dialect fold table.
  - **Float/int distinction and Nix numeric coercion.** `1 + 1.0` is a float in
    Nix; the fold table must reproduce Nix's numeric tower exactly (compare
    against the tree-walk's own arithmetic, not Rust defaults).
- **Why safe.** Totality guarantees a folded value can never *be* an error;
  laziness is preserved because the folded literal is trivial and needs no thunk
  (`is_trivial_value`, `.../ir/mod.rs:957-962`).
- **Precedent already in code.** Lowering already performs a fold-adjacent
  shortcut: `builtins.<name>` selects collapse to `IrKind::BuiltinAttr` at lower
  time (`.../ir/lowering.rs:510-511`). Good model for a total, context-free fold.

### 2.2 Case-of-known (doc 26 §2.3)

- **Matches.** `Select { receiver, path, default }` and `HasAttr { receiver,
  path }` where `receiver` resolves to a statically-known `AttrSet` literal; and
  `If (Triple { cond, then, els })` where `cond` resolves to a known
  `IrKind::Bool`. Rewrite to the selected field / `Bool(has)` / the taken branch.
- **Preconditions.** (a) the `AttrSet` has `has_dynamic == false`
  (`IrData::AttrSet`, doc 25 §4.3 line 357) and the key is statically present or
  statically absent (with `default` for absent); (b) `is_speculable()` throughout.
- **Parity hazards.**
  - **`rec { }` / `__overrides` assembly order.** A recursive attrset's fields
    may reference each other and be assembled through `__overrides`; folding a
    `Select` on a `rec` set must respect the resolved binding semantics, not just
    the syntactic field. Restrict the first cut to **non-recursive**
    (`recursive == false`) attrsets with static keys.
  - **Missing-attribute errors are observable.** A `Select` with no `default`
    whose key is statically absent must **not** be folded to an error — leave it
    intact so the runtime raises the same error C++ Nix does (doc 26 §2.3 line
    207-209).
  - **Inline-cache site accounting (§1.1.2, Q3).** Folding a `Select`/`HasAttr`
    removes its `site` id; confirm site ids need not stay dense.
  - **Discarded-branch effects.** The unselected `If` branch / unselected field
    must be droppable — true only when it is `is_speculable()` (an effectful
    discarded branch that the runtime would never have forced is still safe to
    drop, but a *floated* effect would not be; here we only drop, never move).
- **Why safe.** The discarded subterm was never going to be demanded on the taken
  path; dropping an undemanded speculable subterm cannot change termination.

### 2.3 Inlining / beta-reduction (doc 26 §2.1) — the keystone, hardest

- **Matches.** `Apply (Pair { first = fn, second = arg })` where `fn` resolves
  (possibly after inlining a `LocalVar`/`UpvalVar` bound to a `Lambda`) to a
  `Lambda` node; and `Let`/`AttrSet` bindings whose RHS is small or used-once.
- **Rewrite.** Beta: `Apply(Lambda(param, body), arg) → Let(frame={param =
  ThunkAlloc(arg)}, body)`; drop the `ThunkAlloc` only when strictness proves the
  arg forced (doc 26 §2.1 lines 118-123). Note the arg is **already** a
  `ThunkAlloc` because `Apply` lowers its second operand lazily
  (`LazySecond::Yes`, `.../ir/lowering.rs:498`), so beta is largely a re-binding,
  not a re-thunking, in the common case. Used-once let: inline the RHS at the use
  site and drop the binding.
- **Preconditions.** `is_speculable()` on `fn` and any inlined binding (never
  duplicate/move an effectful node); the size/used-once decision from
  **cardinality analysis** (`analysis::cardinality`, doc 07 §5) — `Once` licenses
  unconditional inline, else a size threshold (`M-24`).
- **Parity hazards — the big one: de-Bruijn / frame rewriting.** Substituting the
  arg into the body, or inlining a binding, moves terms across binders. Every
  `IrData::Local { slot }` / `Upval { depth, slot }` in the moved term must be
  renumbered for its new binding depth, and the `frame: Option<FrameId>` on the
  new/residual `Let`/`Lambda` (`.../ir/lowering.rs:589-598, 652-659`) must be
  rebuilt (`FrameInfo`, doc 25 §3). Getting this wrong silently mis-resolves
  variables with no parse error — the highest-risk rewrite in the catalog and the
  reason to land it *third*, after the arena-stable folders prove the harness.
- **Other hazards.** Re-thunking preserves call-by-need (never evaluate an
  inlined-but-undemanded arg); `with`-scoped variables (`DialectScopeVar`,
  `.../ir/mod.rs:641-650`) resolve dynamically and must not be treated as
  statically inlinable.
- **Why safe.** Re-thunking + `is_speculable()` gating make beta observationally
  transparent; the thunk is dropped only under a positive strictness proof.

### 2.4 Dead-binding elimination (doc 26 §2.4)

- **Matches.** `Let`/`AttrSet` bindings (and `Lambda` formal slots) whose
  **cardinality is `Absent`** — never demanded on any path.
- **Preconditions.** `Cardinality::Absent` from `analysis::cardinality`
  (`ratchet-core/src/ir/facts.rs:65-74`, doc 07 §5.2) and `is_speculable()` (an
  effectful unused binding is **never** deleted — its effect may be observable).
- **What already exists (do not duplicate).** `dead_binding_elimination_plan`
  (`.../analysis/dead_binding.rs:27`) already computes the eliminable set and the
  tree-walk evaluator **already elides** those bindings at eval time by skipping
  the thunk alloc while keeping a `DummyFrameSlot`
  (`.../eval/tree_walk.rs:804` → `.../eval_core/module_env.rs:217` →
  `.../eval_apply.rs:49-54`, `thunks_elided`). So a *runtime elision* already
  ships; what doc 26 §2.4 adds is the **IR-level rewrite + frame compaction** the
  plan explicitly says it does not do ("does not rewrite IR or compact frame
  layouts", `dead_binding.rs:6`).
- **Parity hazards.**
  - **Frame-slot compaction renumbers `Local`/`Upval` slots** — same hazard class
    as inlining. The existing plan deliberately keeps a **dummy slot** to avoid
    renumbering; the rewrite pass must either preserve slot indices (delete the
    binding's *value code* but keep a dummy slot, exactly mirroring the runtime
    elision — the low-risk first cut) or do a full compaction with slot
    renumbering across the frame and all references (the doc's end state).
  - **`rec`/`__overrides`.** A dead binding in a `rec` set can still be referenced
    through `__overrides` assembly; restrict the first cut to non-recursive lets.
- **Recommendation.** First cut = *value elision only* (drop the binding's RHS
  code, keep a dummy slot), which is arena-stable (no slot renumbering, spans of
  survivors unchanged, eval memo key stable per §1.4) and makes the IR-level
  rewrite match the already-shipping runtime behavior. Frame compaction is a
  later, separately-gated step.

## 3. The golden-IR test harness

There is **no snapshot framework** (`insta` absent from all `Cargo.toml`) and
**no IR text-dumper** today; existing analysis tests assert structurally on
plans/facts (`crates/ratchet-core/src/analysis/tests/dead_binding.rs`, etc.).
The harness therefore needs three pieces:

1. **A deterministic IR dump.** Add a stable textual renderer
   `fn render_ir(&Ir) -> String` in `ratchet-core` (walk from `root`, print each
   reachable node as `kind`, key `data` fields, resolved `(depth, slot)`, effect
   key, and *canonicalized* span — see below). Prefer a text dump over the binary
   `encode_lowered_ir` for reviewable diffs; the binary encoder
   (`.../cache/parse/format.rs:198-244`) remains the fixpoint-equality oracle
   (§1.3). Golden files live beside the pass tests under
   `ratchet-core/src/ir/tests/` (mirroring the existing `lowering_tests.rs`
   layout) or a new `simplify/` tests dir; one golden `.txt` per
   `(input-snippet, pass, phase)` capturing before → after.
2. **Per-pass before/after assertions.** Each pass test lowers a Nix snippet
   (`nix_lower`), snapshots `render_ir` (before), runs the single pass, snapshots
   again (after), and asserts against the committed golden. A `--bless`-style
   env-gated regen keeps goldens maintainable. Span canonicalization: because a
   rewrite that synthesizes nodes must choose spans (there is no span-provenance
   system; precedent is to inherit the replaced node's span, `wrap_lazy`
   `.../ir/lowering.rs:844-852`), the dumper should render spans as
   *source-relative* or *elided* so a span choice does not churn every golden.
3. **Byte-parity composition — the real gate.** Golden-IR tests prove the *shape*
   of a rewrite; the byte-identical `.drv` diff proves *semantics*. The pass set
   is behind a flag (§4), so the harness runs the full parity battery **twice** —
   passes-off and passes-on — and both must print "drv diff matched". Commands
   (verified working this session): `aos --eval-system x86_64-linux nix-diff
   --attr=<attr> --mode byte` over `pkgs.zlib`, `pkgs.openssl`, `stdenv.bash`,
   `stdenv.coreutils`, with `AOS_NIX_NATIVE=1` and an `AOS_NIX_ORACLE` pointing at
   `nix-instantiate`; the gate implementation is `crates/aos-nix-harness/src/diff.rs`
   + `crates/aos/src/commands/nix_diff.rs`. Passes-on must match passes-off
   byte-for-byte on the whole AOS closure before any pass is enabled by default.
   Add a differential fuzz corpus run (`crates/aos/src/commands/nix_fuzz_corpus.rs`)
   as a broader net.

## 4. Staged landing order

Each stage is a small, parity-gated commit in the repo's house style. Every
stage keeps the passes-off battery byte-green; a stage that *enables* a pass adds
its passes-on golden + parity evidence.

1. **Driver skeleton, all passes off (identity).** Add the `Phase { Gentle, Main,
   Final }` enum, the `MAX_ITERS` const (`M-24` default), a pass-registry trait
   (`trait SimplifyPass { fn phase_mask(); fn run(&mut Ir) -> Changed; }`), and
   the fixpoint loop using fingerprint equality (§1.3) for termination. Wire it
   into the lowering→persist seam (`.../cache/parse/entry.rs:103-116`,
   `.../cache/parse/mod.rs:409-413`) behind an off-by-default flag
   (`AOS_NIX_SIMPLIFY` env + a config field). With no passes registered,
   `simplify(ir) == ir` and **no fingerprint moves** — prove it with a test that
   the pre/post `LoweredIrFingerprint` is identical across the AOS closure. This
   is the "skeleton first with all passes off" the task requires.
2. **Golden-IR harness (§3).** Land `render_ir` + the before/after test rig + the
   twice-run parity wiring, still with zero passes. Establishes the review
   surface every later stage plugs into.
3. **Constant folding (§2.1), flag-gated.** Total ops only; string-context union
   or decline-on-context; `currentSystem` deny-list. Golden per op class + parity
   on-vs-off. Arena-stable (folds `n → 1` node; keep the folded node's span).
4. **Case-of-known (§2.2), flag-gated.** Non-recursive static attrsets +
   known-`Bool` `If`. Decline on absent-without-default. Resolve the IC-site
   question (Q3) before enabling `Select`/`HasAttr` folding; `If` folding is
   safe first because it touches no IC site.
5. **Dead-binding elimination, value-elision cut (§2.4).** Drop RHS code, keep
   dummy slot (arena-stable, matches shipping runtime elision). Consumes
   `analysis::cardinality` `Absent`. No frame compaction yet.
6. **Inlining / beta (§2.3), flag-gated, Gentle sub-cut first.** Only
   tiny/used-once, `Once`-cardinality bindings; implement and test the de-Bruijn /
   frame renumbering in isolation with dedicated slot-renumbering unit tests
   before enabling on the closure. This is the first arena-*rebuilding* pass
   (`from_raw_parts`, `.../ir/arena.rs:15`).
7. **Fact-refresh integration.** After each stabilized rewrite, call
   `annotate_ir` on the smaller IR (`.../ir/annotate.rs:185`) so later passes see
   sharper facts; add the iterations-to-fixpoint stats counter.
8. **Flip default-on per pass, one at a time,** each behind its own parity-green
   gate across the full closure + fuzz corpus; frame compaction and the remaining
   doc-26 passes (CSE, float, strictness-eager, worker/wrapper, escape/SRA,
   specialization, fusion, unboxing) follow as their own staged notes.

Sizing note: stages 1-2 are pure scaffolding (no semantic change, trivially
parity-green); stages 3-5 are arena-stable and low-risk; stage 6 is the one that
warrants the most test investment and possibly its own multi-commit sub-plan.

## 5. Open design questions (need a human/lead decision)

- **Q1 — Seam (A) vs separate compile-node (B) (§1.4).** Recommend (A) first
  (persist simplified IR in `ir.bin`, no new cache format). Confirm we are not
  required to keep the *un-simplified* IR independently addressable for some
  downstream consumer (e.g. a debugger/`repl` that wants source-faithful IR). If
  we are, (B) is forced earlier.
- **Q2 — Schema-version policy.** Should enabling/altering the pass set bump
  `PARSE_CACHE_SCHEMA_VERSION` (and tier-2 `SCHEMA_VERSION`) to hard-invalidate
  stale artifacts, or do we rely on the fingerprint moving? Bumping is safer
  (clean supersede); fingerprint-only reuse risks a mixed cache after a pass
  logic change that keeps the same IR shape on some inputs. Recommend: bump on
  every pass-set change during development.
- **Q3 — Inline-cache site identity (§1.1.2).** Does the runtime index a dense
  per-module IC table by `IrInlineCacheSiteId`, such that folding/duplicating
  `Select`/`HasAttr` requires renumbering sites? If sites are sparse/opaque keys,
  case-of-known and CSE are simpler. Needs a read of the tree-walk / JIT IC
  dispatch before enabling `Select` folding.
- **Q4 — Where does the driver live (Core vs oracle)?** Doc 26 §1 (lines 74-84)
  says the framework is Core (`ratchet-core`) and only the dialect *rules* (list
  fusion) are `aos-nix-dialect`. But the seam is in `ratchet-oracle`'s parse
  cache. Recommend: the pass framework + generic passes in `ratchet-core`
  (alongside `analysis/`), invoked from the oracle seam; dialect fold tables
  (totality, `currentSystem` deny-list, list-fusion rules) registered from
  `aos-nix-dialect`, matching how effect members are already supplied.
- **Q5 — `currentSystem`/CLI-sensitivity effect member (§1.2, D3).** Do we add a
  non-speculable dialect effect member for CLI/system-sensitive builtins (clean,
  reuses `is_speculable()`), or maintain an ad-hoc fold deny-list? The effect
  member is the principled fix and unblocks specialization later. Recommend
  adding it (`aos-nix-dialect/src/lib.rs:30-57` member set + classification at
  `:116-137`).
- **Q6 — P2 vs P4 phasing (§7, D1).** Doc 25 places the simplifier compile-node
  at **P2**; doc 26 and task #7 place it at **P4**. Confirm the intended tier so
  the checklist rows and task board agree.
- **Q7 — `MAX_ITERS` value + measurement (`M-24`).** Needs a measured default
  once ≥2 passes interleave; the skeleton should expose it and a stats counter
  from day one.

## 6. Summary of verified code seams

| Concern | Location (verified) |
|---------|--------------------|
| IR arena (append-only; `from_raw_parts` is the rebuild hook) | `ratchet-core/src/ir/arena.rs:15,41,55` |
| `Ir` artifact + side tables | `ratchet-core/src/ir/mod.rs:266-294` |
| `IrKind` / `IrData` taxonomy | `ratchet-core/src/ir/mod.rs:478-539, 542-710` |
| Node `IrData` pairings (Apply/Select/If/Let/BinOp) | `ratchet-core/src/ir/lowering.rs:498,519-528,613-620,590-598,633` |
| `EffectClass` + `is_speculable` (`S-23`) | `ratchet-core/src/ir/mod.rs:717-760` |
| Nix effect members / classifier | `aos-nix-dialect/src/lib.rs:30-57,116-137` |
| Fact orchestrator `annotate_ir` / `run_analyses` | `ratchet-core/src/ir/annotate.rs:185-236` (version `:56`) |
| `LoweredIrFingerprint` computation | `ratchet-oracle/src/cache/parse/mod.rs:137-150` |
| **The seam: `write_resolved`** | `ratchet-oracle/src/cache/parse/entry.rs:95-151` (nix_lower `:103`, encode `:116`, fingerprint `:118`) |
| Cold-parse seam | `ratchet-oracle/src/cache/parse/mod.rs:409-413` |
| Verbatim reload (why the seam works) | `ratchet-oracle/src/cache/parse/entry.rs:378-417` |
| Eval memo identity (source vs IR fallback) | `ratchet-oracle/src/eval/tree_walk/eval_core/module_env.rs:48-58` |
| JIT tier-2 compiled-body key | `aos-nix/src/jit/engine/tier2/compiled_body_cache.rs:413-429`, `ratchet-oracle/src/cache/hashing.rs:442-491` |
| Existing dead-binding plan + runtime elision | `ratchet-core/src/analysis/dead_binding.rs:27`, `ratchet-oracle/src/eval/.../eval_apply.rs:49-54` |
| `.drv` parity gate | `aos-nix-harness/src/diff.rs`, `aos/src/commands/nix_diff.rs` |

## 7. Doc-vs-code divergences

- **D1 — "Committed (C-21)" ≠ implemented.** Doc 26 §2's per-pass **Status**
  lines say passes 2.1-2.5 are "Committed (C-21)" (e.g. lines 145, 179, 210, 237,
  264), which reads as *done*. In code **none of the 14 passes is implemented as
  a rewrite** — only analyses/plans exist (§0, §2.4). Doc 26's own implementation
  checklist (lines 630-648) is accurate: every pass is `[ ]` unchecked with a
  "Current precursor" note. "Committed" refers to the *decision* being settled,
  not shipped code. Recommend a one-line clarification in doc 26 §2 that "Status:
  Committed" means the decision, and the checklist is authoritative for
  implementation state. (Not changing doc 26 in this note per the task's
  edit-only-the-new-file constraint.)
- **D2 — Simplifier tier: P2 (doc 25) vs P4 (doc 26 / task board).** Doc 25 §7
  checklist (line 735) says "add the simplifier compile-node keyed by input-IR
  hash … simplify-node **P2** (C-21)"; doc 26 checklist (lines 626, 630) and task
  #7 say **P4**. These must be reconciled (Q6).
- **D3 — No `currentSystem`/CLI-sensitive effect member.** Doc 07/26 lean on the
  effect lattice to gate speculation, but the Nix dialect has no member for
  CLI/system-sensitive builtins (`aos-nix-dialect/src/lib.rs:30-57`); such
  builtins classify as `PURE` or fall to `GENERIC`. A fold/specialize pass
  trusting `is_speculable()` alone could bake `--eval-system`-dependent values
  into the `.drv`. Needs the member added or a fold deny-list (§1.2, Q5).
- **D4 — `NodeKind` (docs) vs `IrKind` (code).** Docs 25/26 name the taxonomy
  `NodeKind`; the code type is `IrKind` (`ratchet-core/src/ir/mod.rs:478`).
  Cosmetic, but worth a doc note so implementors grep the right symbol.
- **D5 — Three doc-26 "precursor" analyses are dormant.** `full_laziness`,
  `scalar_replacement`, and `worker_wrapper` are only re-exported
  (`ratchet-core/src/lib.rs:45,49,50`), never called outside tests, and
  `scalar_replacement` has no consumer at all. Doc 26 §2.7/§2.11 cite them as
  live precursors; they are present but inert. Not blocking (these back later
  passes), but the plan should not assume they are wired.
- **D6 — Lowering already does a fold-adjacent transform.** Doc 26 frames all
  rewriting as post-lowering, but lowering already collapses `builtins.<name>`
  selects to `IrKind::BuiltinAttr` (`ratchet-core/src/ir/lowering.rs:510-511`).
  Benign (it is a resolution shortcut, not a value fold), but it means "the IR is
  never simplified today" is not strictly true — a precedent to cite, and a case
  the constant folder must not double-handle.
