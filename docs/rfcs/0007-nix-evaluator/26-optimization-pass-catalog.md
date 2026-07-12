# RFC-0007 - The optimization pass catalog

> Part of the RFC-0007 aos-nix documentation set. This document is the
> *operational* specification of the simplifier: a per-pass catalog of every
> IR-to-IR rewrite, written concretely against the formalized IR. Where
> [laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md)
> gives the *narrative* (why each analysis exists, what prior-art system it comes
> from, why Nix lets us go further) and
> [the intermediate representation](25-intermediate-representation.md) gives the
> *data structure* (the `NodeKind` taxonomy, the `EffectClass` annotation, the
> one-IR-for-all-tiers contract), this document is the *spec the implementor
> builds the simplifier from*: it names each pass, says which IR `NodeKind`s it
> matches, shows a before/after rewrite, states the preconditions and which
> analysis supplies them, places the pass in the fixpoint ordering, and records
> the soundness and status note for each.
>
> Read it alongside [laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md)
> (the analyses that license these passes), [the intermediate representation](25-intermediate-representation.md)
> (the node taxonomy the passes operate over), [execution tiers and Cranelift](08-execution-tiers-and-cranelift.md)
> (the consumers of the simplified IR), [incremental evaluation cache](12-incremental-evaluation-cache.md)
> (the demand graph that memoizes the simplifier as a compile-node), and
> [differential testing and benchmarking](15-differential-testing-and-benchmarking.md)
> (the `.drv`-parity gate that validates every rewrite).

## 1. The driver: a memoized fixpoint of pure IR-to-IR passes

The simplifier is **one optimizer that runs a set of passes iteratively to a
fixpoint**, exactly as GHC's Core-to-Core pipeline runs its simplifier
interleaved with the demand, float, specialization, and CSE passes
([laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md)
§7.5). It is *pre-JIT IR simplification* — it improves the IR the tier-0 oracle
walks **and** the IR the tier-1/tier-2 Cranelift JITs later compile, before any
JIT exists. In the demand-graph framing
([architecture overview](03-architecture-overview.md) §3.4) the whole optimizer
is one pure (effect-class) **compile-node**, memoized by input-IR hash: optimized
IR is a pure function of input IR, so the result caches across runs exactly like
the parse artifact ([the intermediate representation](25-intermediate-representation.md)
§6).

Each pass is, formally, a **pure `IR -> IR` transform**. The driver structure:

```text
simplify(ir):
    facts = run_analyses(ir)            # strictness, cardinality, escape (§§4-7 of doc 07)
    for phase in [Gentle, Main, Final]:
        repeat up to MAX_ITERS:
            ir' = apply_passes(ir, phase, facts)
            if ir' == ir: break          # local fixpoint for this phase
            ir = ir'
            facts = refresh_facts(ir)     # analyses re-run on the smaller IR
    return ir
```

- **Phased, gentle -> final.** Early *Gentle* passes do conservative, cheap
  reductions (inline only tiny/used-once nodes, fold obvious literals) so later
  analyses see a cleaner graph; the *Main* phase runs the full interleave of
  reductions and analyses; the *Final* phase runs the heuristic-heavy and
  layout-shaping passes (specialization, fusion, join-point formation) once the
  graph has stabilized. This mirrors GHC's `-O2` phase ordering.
- **Interleaved with analyses.** Reductions and analyses are not separate stages.
  Inlining (§2.1) exposes strictness (§2.8); strictness exposes worker/wrapper
  (§2.9) and unboxing (§2.14); float-out (§2.7) exposes constant folding (§2.2);
  specialization (§2.12) exposes more inlining. Each pass therefore *exposes* work
  for later passes, recorded per-pass under **Phase**.
- **Iteration cap.** The repeat loop runs to a local fixpoint or a capped
  `MAX_ITERS` (a measure-gated constant; see [decision register](19-decision-register.md)
  M-24), never unbounded — a pass that keeps finding work past the cap yields to
  the next phase rather than spinning.
- **Memoized as a compile-node.** Because the whole pipeline is a pure function of
  the input-IR hash, it is one memoized graph node; a file whose IR is unchanged
  reuses its simplified IR with no work
  ([incremental evaluation cache](12-incremental-evaluation-cache.md)).

Under the Core + dialect factoring ([generalization and language dialects](28-generalization-and-language-dialects.md)
§4–§5), this catalog splits along the band boundary. The simplifier itself is a
**framework in `ratchet-core`**: the generic IR-to-IR machinery — inlining/beta
(§2.1), constant folding (§2.2), case-of-known (§2.3), DCE (§2.4), CSE (§2.5),
let-floating (§2.7), and the rest of the language-agnostic reductions — operates
over Core nodes and carries no Nix knowledge. The **dialect-specific rewrite
RULES** — chiefly Nix list fusion (§2.13) and any rule keyed on Nix builtin
identities — are supplied by the Nix dialect (`aos-nix-dialect`) and registered
into the framework, exactly as the dialect supplies its primop table and effect
members. The driver, phase ordering, and soundness floor are Core; the Nix-specific
algebraic identities are the dialect's contribution.

Every pass below shares one **soundness floor**, restated once and binding on the
whole catalog: a rewrite fires only if it is *observably transparent* with respect
to Nix semantics. Never fold a *failing* or *effectful* node eagerly (folding is
restricted to total, `Pure` operations; a folded error is *quarantined* — stashed
against the node and re-raised only on genuine demand); never make a lazy binding
strict unless strictness is *proven*. The "is this node speculable / movable /
foldable" test consults the **open, dialect-supplied effect lattice**
(`is_speculable` + `effect_key`, decision `S-23`,
[generalization and language dialects](28-generalization-and-language-dialects.md)
§5) rather than a closed `enum { Pure, Effectful }`: the framework asks the lattice
whether a node is speculable, and the Nix dialect supplies the members (`import`,
IFD, `readFile`, `derivationStrict`). Where this catalog writes `Pure` /
`Effectful` below, read it as "`is_speculable` holds" / "does not." The `.drv`-parity gate of
[differential testing and benchmarking](15-differential-testing-and-benchmarking.md)
diffs every rewrite against `nix-instantiate` across the AOS closure, anchored at
the `DerivationStrict` nodes ([the intermediate representation](25-intermediate-representation.md)
§4.7).

The remainder of this document is one subsection per pass, each with the same
template: **Matches** / **Rewrite** / **Preconditions** / **Phase** /
**Soundness** / **Status**.

A **Status** of "Committed (`C-21`)" records the *decision* status — the pass is
committed to the design under `C-21` — **not** shipped code. As of this writing
**none of the 14 passes is implemented as an IR-to-IR rewrite**; only the
licensing analyses (the "current precursor" notes) exist. The
[implementation checklist](#implementation-checklist) below is the authoritative
record of what is actually built, and every pass there is unchecked.

## 2. The pass catalog

### 2.1 Inlining / beta-reduction (GHC simplifier)

- **Matches.** `Apply(fn, arg)` where `fn` resolves (possibly after this pass
  inlines a `LocalVar`/`UpvalVar` bound to a `Lambda`) to a `Lambda` node; and
  `Let` / `AttrSet` bindings whose right-hand side is a small expression or is
  used at most once.
- **Rewrite.**

```text
  Apply(Lambda(param y, body), arg)
    -- beta-reduce: substitute arg for the param slot in body
    -->  Let(frame={ y = ThunkAlloc(arg) }, body)      -- lazy arg: re-thunk
    -->  Let(frame={ y = arg }, body)                  -- if arg is strict/WHNF: no thunk
```

  Inlining a used-once `let` binding then collapses the residual `Let`:

```text
  Let(frame={ x = e }, BinOp(Add, LocalVar x, LocalVar x))   -- x used twice: keep
  Let(frame={ x = e }, Select(LocalVar x, "a"))              -- x used once: inline
    -->  Select(e, "a")
```

- **Preconditions.** `Pure` effect class on `fn` and on any inlined binding (an
  `Effectful` node is never duplicated or moved). The size/used-once decision
  comes from **cardinality analysis** ([07](07-laziness-and-whole-program-analyses.md)
  §5): cardinality `Once` licenses unconditional inline regardless of size;
  otherwise a GHC-style size threshold gates it.
- **Phase.** Gentle (tiny/used-once only) and Main (size-thresholded). Inlining is
  the keystone pass: it *exposes* constant folding (§2.2), case-of-known (§2.3),
  and strictness at the call site (§2.8), which is why it must iterate.
- **Soundness.** Re-thunking the substituted argument (`ThunkAlloc(arg)`) preserves
  Nix's call-by-need: an inlined-but-undemanded argument must not be evaluated. The
  thunk is dropped only when strictness (§2.8) proves the argument forced. Never
  inline an `Effectful` binding (would duplicate or reorder an effect).
- **Status.** Committed (C-21). Size threshold and used-once policy measure-gated
  (M-24).

### 2.2 Constant folding (GHC simplifier)

- **Matches.** `BinOp(op, lhs, rhs)`, `UnaryOp(op, operand)`, and `PrimOp(prim,
  args)` whose operand `NodeId`s are all literal nodes (`Int`, `Float`, `Bool`,
  `Str`, `Path`, `Null`) or already-folded constants.
- **Rewrite.**

```text
  BinOp(Add, Int(1), Int(2))            -->  Int(3)
  BinOp(Add, Str("a"), Str("b"))        -->  Str("ab")
  UnaryOp(Not, Bool(true))              -->  Bool(false)
  PrimOp(length, [List elems])          -->  Int(len(elems))
  PrimOp(stringLength, Str("abc"))      -->  Int(3)
```

- **Preconditions.** The operation must be **total** for the given literals and
  the node must be `Pure`. Totality is decided per-operator/per-primop from a fixed
  table (it is the *operator*, not an analysis, that is total): arithmetic on
  in-range integers, string concat, boolean ops, and the pure total primops
  (`length`, `stringLength`, `typeOf` on a known value) fold; *partial* operations
  do **not** (`BinOp(Div, _, Int(0))`, `PrimOp(head, [])`, `PrimOp(elemAt, xs,
  oob)` are left intact).
- **Phase.** Gentle and Main; fires continuously as inlining (§2.1) and
  float-out (§2.7) bring literals together.
- **Soundness.** The first sharp edge of the soundness floor: *never fold a failing
  subexpression eagerly*. `BinOp(Div, Int(1), Int(0))`, `PrimOp(throw, ...)`,
  `Assert(Bool(false), _)` are not folded to an eager error — if the surrounding
  context is lazy and the node is never demanded, the error must not surface at
  compile time. Folding is gated on totality precisely so a folded value can never
  *be* an error; where a fold would raise, the pass declines (the runtime stashes
  it under error quarantine instead).
- **Status.** Committed (C-21).

### 2.3 Case-of-known: select / if / has-attr on a known value (GHC simplifier)

- **Matches.** `Select(recv, path, default?)` and `HasAttr(recv, path)` where
  `recv` is a statically-known `AttrSet` literal; `If(cond, then, els)` where
  `cond` is a known `Bool`.
- **Rewrite.**

```text
  Select(AttrSet{ a = #5; b = #6 }, "a")     -->  #5            -- field read folds
  Select(AttrSet{ a = #5 }, "z", default #9) -->  #9            -- missing -> default
  HasAttr(AttrSet{ a = #5 }, "a")            -->  Bool(true)
  If(Bool(true),  then=#t, els=#e)           -->  #t
  If(Bool(false), then=#t, els=#e)           -->  #e
```

- **Preconditions.** `recv` / `cond` resolves to a known constructor *literal*
  with no dynamic keys (`has_dynamic = false` on the `AttrSet`, see
  [the intermediate representation](25-intermediate-representation.md) §4.3) and
  with the selected key statically present or statically absent. `Pure` effect
  class throughout. This is GHC's case-of-known-constructor, specialized to Nix
  attrsets and `if`.
- **Phase.** Main, immediately after inlining (§2.1) makes the constructor visible
  at the use site. Folding the dead `If` branch *exposes* DCE (§2.4) of the
  un-taken branch's bindings and float-in (§2.7) opportunities.
- **Soundness.** The discarded branch / unselected field must be *droppable* — it
  is, because it was never going to be demanded on the taken path, and dropping an
  undemanded `Pure` subexpression cannot change termination. A `Select` on an
  attrset with a *dynamic* key, or whose key may be absent and has no `default`, is
  left intact (the missing-attribute error is observable and must match C++ Nix).
- **Status.** Committed (C-21).

### 2.4 Dead-binding elimination (GHC simplifier / absence analysis)

- **Matches.** `Let` and `AttrSet` / `rec { }` bindings, and `Lambda` formal
  slots, whose **cardinality is 0 (absent)** — never demanded on any path through
  the body.
- **Rewrite.**

```text
  Let(frame={ x = e_used; dead = expensive() }, use(x))
    -->  Let(frame={ x = e_used }, use(x))        -- `dead` binding and its code dropped

  -- in a worker (§2.9), an absent formal becomes a dummy:
  $w(used: Value, _dead: Dummy) -> ...            -- caller passes no value for _dead
```

- **Preconditions.** **Cardinality `Absent`** from the usage component of the
  demand analyser ([07](07-laziness-and-whole-program-analyses.md) §5.2), computed
  as the dual of the demand fixpoint. Effect class `Pure` — an `Effectful` binding
  is never deleted even if its value is unused (its effect may be observable).
- **Phase.** Main and Final, after the demand fixpoint and after case-of-known
  (§2.3) has pruned dead branches (which often makes more bindings absent).
- **Soundness.** Absence is a "never demanded on *any* path" property, so deleting
  the binding cannot change which expressions are forced — even a binding whose
  only effect is to diverge is safely dropped *iff* no path forces it. A binding
  that *might* be forced on some path stays.
- **Status.** Committed (C-21).

### 2.5 Common-subexpression elimination (GHC simplifier)

- **Matches.** Two or more structurally-identical `Pure` subtrees (same
  `NodeKind`, same resolved `(depth, slot)` references, same children) within a
  scope.
- **Rewrite.**

```text
  BinOp(Add, expensive(x), expensive(x))
    -->  Let(frame={ t = expensive(x) }, BinOp(Add, LocalVar t, LocalVar t))
```

- **Preconditions.** Both occurrences `Pure`. Crucially, CSE is *safe and
  desirable here* in a way it is not in GHC: Nix values are immutable and the
  [value representation](05-value-representation.md) already maximally shares via
  **hash-consing** (interning to maximal sharing), so eliminating a duplicate
  subexpression can only *help* sharing, never silently change laziness or
  observable identity. GHC must be cautious about CSE altering sharing/space
  behavior; we are not.
- **Phase.** Main. Cheap to run repeatedly because the IR is a flat, hash-consable
  arena — structural equality is a `u32`-keyed table lookup, not a deep walk.
- **Soundness.** Immutability is the license: an immutable value has no identity
  beyond structural equality, so collapsing two equal computations into one
  shared binding is observationally invisible. Effectful subtrees are never CSE'd
  (sharing an effect would change how many times it runs).
- **Status.** Committed (C-21).

### 2.6 Eta-reduction / eta-expansion (GHC simplifier)

- **Matches.** *Reduction:* `Lambda(param x, Apply(f, LocalVar x))` where `x` does
  not appear free in `f`. *Expansion:* a partially-applied function used in a
  context that wants a known arity.
- **Rewrite.**

```text
  -- eta-reduce:
  Lambda(x, Apply(f, LocalVar x))   -->  f         -- when x not free in f

  -- eta-expand (to expose the worker calling convention, §2.9):
  f                                  -->  Lambda(x, Apply(f, LocalVar x))
```

- **Preconditions.** `Pure` `f`; and — the Nix-specific care — eta-reduction must
  not change *arity observability*. Nix's `builtins.functionArgs` and the
  pattern/arity errors are observable, so eta-reduction fires only where the
  reduced form has identical observable arity and argument-pattern behavior.
  Expansion is licensed by the arity demanded at the call site (often from
  worker/wrapper, §2.9).
- **Phase.** Main (reduction, to simplify) and Final (expansion, to shape the
  worker calling convention before lowering).
- **Soundness.** Eta in a lazy language can change strictness (an eta-expanded
  function is more defined); we only expand where the function is applied (so the
  extra `Lambda` is immediately consumed) and only reduce where arity is provably
  unchanged. Never across an `Effectful` `f`.
- **Status.** Committed core; aggressive eta-expansion to drive unboxing is
  measure-gated (M-24).

### 2.7 let-floating: float-out and float-in (GHC, ICFP '96)

- **Matches.** `Let` (and `AttrSet` / `ThunkAlloc`) bindings positioned *inside* a
  `Lambda` body (candidate for float-out) or in a scope broader than their uses
  (candidate for float-in).
- **Rewrite.**

```text
  -- float-OUT (full laziness): a binding not depending on the lambda param
  Lambda(x, Let(frame={ prefix = "${pkgs.hello}/bin/" }, Interp[prefix, x]))
    -->  Let(frame={ prefix = "${pkgs.hello}/bin/" },     -- hoisted: computed once
             Lambda(x, Interp[prefix, x]))

  -- float-IN: sink a binding to the branch that uses it
  Let(frame={ t = e }, If(c, then=use(t), els=other))
    -->  If(c, then=Let(frame={ t = e }, use(t)), els=other)  -- not built on else path
```

- **Preconditions.** `Pure` binding; float-out requires the binding *not* reference
  the lambda's parameter slot (a free-variable check over the resolved `(depth,
  slot)` coordinates — exact, because the IR is born resolved,
  [the intermediate representation](25-intermediate-representation.md) §3). The
  residency caveat ([07](07-laziness-and-whole-program-analyses.md) §6.3) is the
  only brake on float-out, and it is *absent in the one-shot arena tier* (the heap
  is dropped at process exit), so we float aggressively there; daemon mode bounds
  the size/cost of what we hoist (M-24-adjacent tuning).
- **Phase.** Float-in runs **before** the strictness fixpoint (to tighten demand
  scopes so absence/cardinality are sharper); float-out runs **after** (to hoist
  proven loop-invariants). Both are part of the same fixpoint loop, not separate
  phases — a hoist *exposes* an inline and a fold, and vice versa.
- **Soundness.** Floating never changes results in a pure language (it only trades
  time for space), so the correctness floor is purity; the only risk is residency,
  a *performance* property the differential gate is indifferent to. An `Effectful`
  binding is *pinned* — never floated across a `Lambda` boundary or into a branch,
  because that would change how often or whether the effect runs.
- **Status.** Committed (C-21). Float-outward residency policy in daemon mode is an
  open tuning question ([07](07-laziness-and-whole-program-analyses.md) §10.2).

### 2.8 Strictness-driven eager lowering (GHC demand analysis)

- **Matches.** `ThunkAlloc(inner)` nodes (and binding positions that would
  otherwise be thunked) whose binding is **proven strict** — always demanded
  whenever the surrounding expression is evaluated.
- **Rewrite.**

```text
  Let(frame={ name = ThunkAlloc(Interp["${pname}", "-", "${version}"]) },
      DerivationStrict( ... name ... ))
    -- derivationStrict forces every attr => name is strict => drop the thunk
    -->  Let(frame={ name = Interp["${pname}", "-", "${version}"] },   -- EAGER, no thunk
             DerivationStrict( ... name ... ))
```

  At lowering this means the THUNK strategy becomes the EAGER strategy
  ([07](07-laziness-and-whole-program-analyses.md) §2): no `aos_alloc_thunk`, no
  `aos_force` round-trip — straight-line evaluation inline.
- **Preconditions.** A **positive proof of strictness** from the backward demand
  fixpoint ([07](07-laziness-and-whole-program-analyses.md) §4), seeded by the
  strict contexts (`BinOp` operands, `If` condition, string interpolation
  fragments, and above all `DerivationStrict`, which forces every attribute). The
  binding must also be `Pure` *or* its strictness must be unconditional — an
  `Effectful` node is lowered eagerly only at the exact demand point, never
  speculatively hoisted earlier.
- **Phase.** Main, as the §4 strictness fixpoint reaches a fixed point. Removing
  the `ThunkAlloc` *exposes* worker/wrapper (§2.9), unboxing (§2.14), and scalar
  replacement (§2.11) on the now-eager value.
- **Soundness.** The second sharp edge of the soundness floor: *strictness must be
  proven, never speculative*. Forcing a should-be-lazy `throw`/`abort`/`assert
  false`/infinite-recursion thunk would turn a never-demanded divergence into an
  actual error and change the `.drv` (or fail eval where C++ Nix produced a
  derivation). Eager lowering is licensed *only* by the positive proof; an unproven
  binding stays a `ThunkAlloc`. This is observationally invisible by construction.
- **Status.** Committed (the analysis is roadmap item 3, lands before any Cranelift
  work); aggressiveness measure-gated (M-24).

### 2.9 Worker/wrapper split (GHC worker-wrapper)

- **Matches.** `Lambda` nodes with one or more strict and/or absent parameters
  (from §2.8 strictness and §2.4 absence).
- **Rewrite.**

```text
  mkDerivation = { pname, version, ... }@args:
    DerivationStrict(args // { name = "${pname}-${version}"; ... });

  -- split into worker (unboxed strict args) + always-inline wrapper:
  $w_mkDerivation(pname_val /*WHNF*/, version_val /*WHNF*/, ...):
      let name_val = string_concat(pname_val, "-", version_val)   -- eager
      ... build derivation attrset in registers ...
  mkDerivation(args):                       -- wrapper, marked always-inline
      let pname_val   = force(select(args, pname))
      let version_val = force(select(args, version))
      $w_mkDerivation(pname_val, version_val, ...)
```

- **Preconditions.** Strictness (§2.8) for which parameters arrive already-forced;
  absence (§2.4) for which are dropped to a dummy; `Pure` body for the parameters
  being unboxed. The wrapper's always-inline marking is what makes the split pay
  off — at the call site the wrapper disappears and the caller calls `$w` directly
  with WHNF values it frequently already holds.
- **Phase.** Final, after strictness/absence/eta have stabilized, so the worker's
  calling convention is decided once. The wrapper is then inlined (§2.1) at every
  call site, collapsing its `force` calls against callers that pass WHNF values.
- **Soundness.** Inherits §2.8's discipline exactly: a parameter is moved into the
  worker's strict (pre-forced) convention only where strictness is *proven*. The
  wrapper preserves the original lazy calling convention for callers that cannot be
  inlined, so observable arity and laziness are unchanged.
- **Status.** Committed core ([07](07-laziness-and-whole-program-analyses.md) §4.2);
  boxity decisions measure-gated.

### 2.10 Cardinality-driven single-entry thunks (GHC usage analysis)

- **Matches.** `ThunkAlloc(inner)` nodes whose **cardinality is `Once`** —
  demanded at most once per evaluation — that were *not* eliminated by strictness
  (§2.8) because they may not be demanded at all.
- **Rewrite.**

```text
  ThunkAlloc(inner)            -- update-thunk: Suspended -> Blackhole -> Forced
    -->  ThunkAlloc.single(inner)   -- single-entry: no Blackhole write, no Forced update
    -->  CallByName(inner)          -- frame-local + pure: no heap cell, re-eval freely
```

  The single-entry form drops the `Blackhole`/`Forced` update machinery; the
  call-by-name downgrade drops the heap cell entirely (re-evaluation is free in a
  pure language).
- **Preconditions.** **Cardinality `Once`** from the usage component of the demand
  analyser ([07](07-laziness-and-whole-program-analyses.md) §5.1). The
  call-by-name downgrade additionally requires the thunk be proven **frame-local**
  by escape analysis (§2.11) — never published to a shared slot — so that under
  parallel forcing ([parallel evaluation](13-parallel-evaluation.md)) no second
  thread can reach it and race on the missing `Blackhole`
  ([07](07-laziness-and-whole-program-analyses.md) §10.4, decision closed).
- **Phase.** Main, after the demand fixpoint. The update machinery exists only for
  sharing and cycle detection; cardinality `Once` removes the sharing need.
- **Soundness.** *Purity converts an imprecise analysis into a correct one*: even a
  *wrong* "used-once" classification cannot change the result value (recomputation
  is observationally identical to reuse in a pure, deterministic language —
  `throw`/`abort` throw the same thing every time). Precision is chased only to
  avoid the *performance* pathology of recomputing an expensive shared thunk. The
  frame-local restriction keeps the blackhole-skip sound under work-stealing.
- **Status.** Committed; cardinality precision under higher-order Nix is an open
  research edge ([07](07-laziness-and-whole-program-analyses.md) §10.1).

### 2.11 Escape analysis -> scalar replacement (HotSpot C2 SRA)

- **Matches.** `AttrSet` / `List` construction and `ThunkAlloc` nodes whose result
  **does not escape** the frame that builds it — no reference survives the
  allocating activation, reaches another thread, or flows into the heap-resident
  WHNF result.
- **Rewrite.**

```text
  Let(frame={ pair = AttrSet{ a = Apply(f, x); b = Apply(g, x) } },
      BinOp(Add, Select(pair, "a"), Select(pair, "b")))
    -- pair never escapes => decompose it into scalars (SRA), allocate nothing:
    -->  v_a = call f(x)            ; was pair.a, now an SSA value (EAGER -> SCALAR)
         v_b = call g(x)            ; was pair.b
         v_r = iadd v_a, v_b        ; no attrset, no hidden class, no select IC
```

  The attrset, its hidden-class pointer, its key array, and its value array are
  never built; `.a`/`.b` become reads of `v_a`/`v_b` resolved at compile time.
- **Preconditions.** **`NoEscape`** from escape analysis
  ([07](07-laziness-and-whole-program-analyses.md) §7), which — because Nix values
  are immutable, have no identity beyond structural equality, no virtual dispatch,
  no reflection, and the whole program is visible — is closer to a *syntactic
  reachability* check than HotSpot's points-to analysis. Escape is decided against
  the per-primop **escape-signature table** for the ~120 builtins
  ([primops and runtime ABI](10-primops-and-runtime-abi.md)): `length`, `+`,
  comparison, transient `attrNames` do **not** escape; `DerivationStrict` and any
  construction flowing to the WHNF result **do**.
- **Phase.** Final, on values already made eager by §2.8 (the EAGER -> SCALAR step).
  A value about to be **interned** (hash-consed) has by definition escaped into the
  global intern table and the incremental cache, so SRA applies only to *transient*
  aggregates *between* interned values.
- **Soundness.** Immutability is the decisive license: with no aliasing-through-
  mutation and no hidden channels, "no syntactic reference survives the frame" *is*
  "cannot be observed outside the frame." A mis-signed escape-transparent primop
  could scalar-replace an aggregate that actually escapes — caught as a `.drv` byte
  diff by the differential gate ([07](07-laziness-and-whole-program-analyses.md)
  §10.3); default-off until green.
- **Status.** Committed analysis ([07](07-laziness-and-whole-program-analyses.md)
  §7); the builtin escape-signature table wants property-test fuzzing and is
  measure-gated default-off (M-24-adjacent, [14](14-integration-with-aos.md)).

### 2.12 Specialization (GHC SpecConstr / specialization)

- **Matches.** A higher-order `Apply` such as a `map`/`foldl'`/`filter` call (or a
  user combinator) whose *function argument is statically known* — a `Lambda`
  literal or a `GlobalVar`/`PrimOp` bound to a known builtin.
- **Rewrite.**

```text
  Apply(Apply(GlobalVar map, f_known), xs)
    -- specialize a copy of `map` with f_known inlined into the per-element body:
    -->  PrimOp(map_specialized_to_f_known, [xs])
         -- the call through the generic apply path becomes a direct, inlinable loop
```

- **Preconditions.** The function argument resolves statically (`Pure`, known
  `Lambda` or known builtin identity — exactly the `PrimOp`-vs-`GlobalVar`/`Apply`
  distinction the IR draws, [the intermediate representation](25-intermediate-representation.md)
  §4.5). Whole-program closure makes the callee body visible, so the specialization
  is *exact*, not a separate-compilation approximation.
- **Phase.** Final, before fusion (§2.13) and after inlining has propagated known
  functions to their call sites. Specialization *exposes* inlining of the now-known
  per-element function and further constant folding.
- **Soundness.** Specialization duplicates a `Pure` body with a fixed argument; it
  changes no value and no effect ordering. The generic apply path remains for the
  indirect case (a builtin passed as a value stays `GlobalVar`/`Apply`).
- **Status.** Measure-gated (M-24): over-specialization bloats IR; enabled and tuned
  against `NIX_SHOW_STATS` counters and the harness.

### 2.13 Rewrite RULES / list fusion (GHC RULES + foldr/build fusion)

- **Matches.** Nested `PrimOp` list pipelines — `map`/`filter`/`concatMap`/`length`
  chains — that allocate intermediate lists.
- **Rewrite.**

```text
  map f (map g xs)        -->  map (x: f (g x)) xs       -- one traversal, no temp list
  length (map f xs)       -->  length xs                 -- f never runs
  concatMap f [ x ]       -->  f x
  filter p (filter q xs)  -->  filter (x: q x && p x) xs
```

- **Preconditions.** Both stages `Pure`, both builtins reached *directly* (so they
  appear as `PrimOp` nodes the rule can match, not as indirect `GlobalVar`/`Apply`).
  The `length (map f xs) -> length xs` rule additionally requires that dropping `f`
  is observationally safe — `f` must be `Pure` and total over `xs`'s elements (if
  `f` could `throw`, the original `length` still never forces the elements, so `f`
  never runs in C++ Nix either — the rule is correct precisely *because* `length`
  is non-strict in elements).
- **Phase.** Final, after specialization (§2.12) has turned higher-order maps into
  matchable `PrimOp` shapes. Fusion *exposes* DCE of the eliminated intermediate
  bindings.
- **Soundness.** Each RULE is a semantics-preserving algebraic identity over pure,
  immutable lists; the standout `.drv`-relevant risk is *changing sharing* — a fused
  pipeline that forces elements in a different multiplicity could change which
  thunks get blackholed. The gate is the differential `.drv` diff; over-eager fusion
  that changes observable sharing is reverted by measurement.
- **Status.** Measure-gated (M-24): which RULES (especially fusion) to enable is
  tuned against the harness, never assumed; this is the highest-value Nix-specific
  rewrite ([07](07-laziness-and-whole-program-analyses.md) §7.5.2).

### 2.14 Unboxing / unboxed returns / join points (GHC + Cranelift SSA)

- **Matches.** Worker functions (§2.9) returning several scalar values; merge
  points after `If`/`Let` where a scalar-replaced (§2.11) value must cross a
  control-flow join.
- **Rewrite.**

```text
  -- unboxed multi-return: a worker returns decomposed scalar fields in registers
  $w(...) -> (v_a, v_b)          ; multiple return values, not a boxed tuple attrset

  -- join point: the continuation after an If is a labelled block, not a closure
  If(c, then=block_t(v), els=block_e(v))
    -->  brif c, block_t(v_then), block_e(v_else)
         merge(v):  ...           ; CLIF block parameter == GHC join point
```

- **Preconditions.** The consumer immediately uses the decomposed fields (so they
  need not be reboxed); the values are `Pure` scalars from §2.11 scalar replacement.
  Cranelift's multiple-return-value calling convention and SSA block parameters are
  the mechanisms ([execution tiers and Cranelift](08-execution-tiers-and-cranelift.md)).
- **Phase.** Final, downstream of worker/wrapper (§2.9) and scalar replacement
  (§2.11) — it is the lowering-shaping pass that lets their scalars survive across
  `if`/`else` and `let` without being boxed to cross the merge.
- **Soundness.** Unboxing and join-point formation are representation choices, not
  value changes: the same scalars are computed, merely passed in registers / via
  block params instead of a heap aggregate. No effect is moved; immutability
  guarantees the unboxed scalars equal the fields they replace.
- **Status.** Committed as the supporting transform for §§2.9/2.11
  ([07](07-laziness-and-whole-program-analyses.md) §7.4); register-allocation
  specifics belong to the Cranelift tiers, not the IR simplifier.

## 3. Phase ordering

The passes run in three phases, repeated to a per-phase fixpoint (§1). The table
records *which phase* each pass runs in and *why that ordering* — what it consumes
and what it exposes.

| Pass | Gentle | Main | Final | Why this slot |
|------|:------:|:----:|:-----:|---------------|
| 2.1 Inlining / beta | tiny/used-once | thresholded | — | Keystone; exposes 2.2/2.3/2.8. Gentle first so analyses see a clean graph. |
| 2.2 Constant folding | • | • | — | Fires whenever inlining/floating bring literals together; total-only. |
| 2.3 Case-of-known | — | • | — | Needs the constructor inlined to the use site first (2.1); exposes 2.4/2.7. |
| 2.7 Float-IN | — | • (early) | — | Runs *before* the strictness fixpoint to tighten demand scopes (sharper 2.4/2.10). |
| 2.8 Strictness eager-lowering | — | • | — | Runs as the §4 demand fixpoint settles; exposes 2.9/2.11/2.14. |
| 2.4 Dead-binding elimination | — | • | • | Needs the demand fixpoint (2.8) and pruned branches (2.3). |
| 2.10 Single-entry thunks | — | • | — | Needs cardinality (demand fixpoint) and 2.11 frame-local proof for call-by-name. |
| 2.5 CSE | — | • | — | Cheap on the hash-consed arena; safe under immutability, run repeatedly. |
| 2.6 Eta reduce / expand | — | reduce | expand | Reduce to simplify (Main); expand to shape the worker convention (Final). |
| 2.7 Float-OUT | — | — | • | Runs *after* strictness to hoist proven loop-invariants; aggressive in arena tier. |
| 2.9 Worker/wrapper | — | — | • | After strictness/absence/eta stabilize, so the convention is decided once. |
| 2.11 Escape -> scalar replacement | — | — | • | On already-eager values (2.8); transient aggregates only, interning is the escape boundary. |
| 2.12 Specialization | — | — | • | After inlining propagates known functions; exposes 2.13. |
| 2.13 RULES / fusion | — | — | • | After specialization makes maps matchable `PrimOp`s; exposes 2.4. |
| 2.14 Unboxing / join points | — | — | • | Lowering-shaping; downstream of 2.9/2.11 so their scalars cross merges. |

The ordering principle, stated once: **expose before exploit.** Cheap reductions
that *reveal* structure (inline, fold, case-of-known, float-in) run first; the
analyses (strictness, cardinality, escape) run interleaved and settle in Main; the
heuristic, layout-shaping, IR-growing passes (worker/wrapper, scalar replacement,
specialization, fusion, unboxing) run last, once the graph is stable — exactly
GHC's gentle-to-final strategy. Every loop is capped at `MAX_ITERS` and every phase
returns to the driver (§1) at its local fixpoint.

## 4. This catalog is the spec

This document is the specification the implementor builds the simplifier from.
Each subsection of §2 is a self-contained pass contract: its match set is a
predicate over the `NodeKind` taxonomy of
[the intermediate representation](25-intermediate-representation.md) §2; its
rewrite is a concrete IR-to-IR transform; its preconditions name the
**analysis** ([laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md))
that must have proven the licensing fact and the **effect class** that must hold;
its phase fixes where it sits in the driver of §1 and §3; its soundness note ties
it back to the one error/effect-quarantine discipline; and its status records
whether it is committed (C-21) or measure-gated (M-24) per the
[decision register](19-decision-register.md). The whole pipeline is one pure,
content-addressed compile-node, validated end-to-end by the byte-identical `.drv`
gate of [differential testing and benchmarking](15-differential-testing-and-benchmarking.md).

## Implementation checklist

Per-feature tracker for the optimization pass catalog (the simplifier driver and its 14 IR-to-IR passes); master roll-up: [implementation checklist (all phases)](22-implementation-checklist-all-phases.md). Per the unlimited-budget mandate, every item here is in scope — including research-grade ones — built in dependency order and gated by the differential harness, never cut for scope. This is the compact roll-up; each per-pass §2.N subsection above is the spec the implementor builds from (its own **Status** line is authoritative), and this list does **not** duplicate those Matches/Rewrite/Precondition contracts.

The simplifier is the GHC-style Core-to-Core optimizer (decision `C-21`), a memoized pure compile-node landing in **P4** (it consumes the strictness/cardinality/escape analyses of [07](07-laziness-and-whole-program-analyses.md) and annotates the IR the tier-0 oracle walks, before any JIT exists). Every rewrite is validated end-to-end by the byte-identical `.drv` gate ([15](15-differential-testing-and-benchmarking.md)), anchored at the `DerivationStrict` nodes.

### The driver (§1, §3)

- [ ] Memoized fixpoint driver: phased `Gentle → Main → Final`, repeat-to-local-fixpoint per phase, analyses interleaved (`refresh_facts` on the smaller IR), capped at `MAX_ITERS`, the whole pipeline one compile-node keyed by input-IR hash (§1) — **P4**, `C-21`; iteration count / aggressiveness `M-24`. Current precursor: `ir::annotate_ir` refreshes facts from a conservative baseline and runs the current strictness/cardinality/escape producers once; memoization, phased rewrites, and fixpoint iteration remain open.
- [ ] The "expose before exploit" phase ordering and the binding soundness floor — only observably-transparent rewrites, never fold a failing/effectful node eagerly (error quarantine), never make a binding strict unless *proven* (§1, §3) — **P4**, `C-21`.

### The 14 passes (§2.1–§2.14)

- [ ] 2.1 Inlining / beta-reduction — the keystone, re-thunking substituted args to preserve call-by-need (§2.1) — **P4**, committed `C-21`; size threshold / used-once policy `M-24`.
- [ ] 2.2 Constant folding — total, `Pure` operations only; a fold that would raise declines (§2.2) — **P4**, `C-21`.
- [ ] 2.3 Case-of-known — `select`/`if`/has-attr on a statically-known value, no dynamic keys (§2.3) — **P4**, `C-21`.
- [ ] 2.4 Dead-binding elimination — cardinality `Absent`, `Pure` bindings only (§2.4) — **P4**, `C-21`.
- [ ] 2.5 Common-subexpression elimination — licensed by immutability/hash-consing, cheap on the arena (§2.5) — **P4**, `C-21`.
- [ ] 2.6 Eta-reduction / eta-expansion — arity-observability-preserving; expansion shapes the worker convention (§2.6) — **P4**, committed core; aggressive expansion `M-24`.
- [ ] 2.7 let-floating (float-out / float-in) — purity floor; effectful bindings pinned; aggressive in the arena tier (§2.7) — **P4**, `C-21`; daemon residency policy `R-6`. Current precursor: `analysis::full_laziness` reports only closed, pure static-key `let` binding values under simple lambdas as future float-out candidates; dynamic keys, nested thunk/frame producers, and dynamic-scope probes stay conservative; no rewrite or residency policy is implemented.
- [ ] 2.8 Strictness-driven eager lowering — positive proof from the backward demand fixpoint drops the `ThunkAlloc` (§2.8) — **P4**, committed (analysis lands before any Cranelift work); aggressiveness `M-24`. Current precursor: `analysis::strictness` now produces conservative strictness facts for guaranteed demanded positions and the tree-walk oracle can consume those facts to elide a direct-lambda argument thunk; the full fixpoint/simplifier integration remains open.
- [ ] 2.9 Worker/wrapper split — unboxed strict args + always-inline wrapper (§2.9) — **P4**, committed core; boxity decisions measure-gated.
- [ ] 2.10 Cardinality-driven single-entry thunks — `Once` drops the blackhole/update machinery; call-by-name downgrade only for escape-proven *frame-local* thunks so it stays sound under parallel forcing (§2.10) — **P4**, committed; `C-8`; cardinality precision an open research edge. Current precursor: `analysis::cardinality` produces local `Absent`/`Once` facts for simple same-frame `let` bindings, `analysis::escape` supplies a narrow static-key, unique-reference direct-body `let x = ...; in x` lazy-thunk `NoEscape` proof, `analysis::thunk_sharing` exposes the `Once`+`NoEscape` preflight, and tree-walk frame assembly consumes that lazy proof as single-entry storage while still blocking eager/omitted frame rewrites; thunk-sharing rewrites and broad escape/demand precision remain open.
- [ ] 2.11 Escape analysis → scalar replacement — `NoEscape` decided against the per-primop escape-signature table; transient aggregates only, interning is the escape boundary (§2.11) — **P4** analysis; escape-signature table property-fuzzed, default-off until green `R-9`. Current precursor: `analysis::escape` marks allocation-free immediate scalar literals, scalar-result primops, narrow strict thunk wrappers, aggregate scalar-primop arguments, and direct-body static `let` thunks `NoEscape`; aggregate SRA and the full primop escape surface remain open.
- [ ] 2.12 Specialization — statically-known function argument, exact under whole-program closure (§2.12) — **P4**, measure-gated `M-24` (over-specialization bloats IR).
- [ ] 2.13 Rewrite RULES / list fusion — semantics-preserving algebraic identities on pure immutable lists; the highest-value Nix-specific rewrite (§2.13) — **P4**, measure-gated `M-24` (over-eager fusion can change observable sharing; reverted by the harness).
- [ ] 2.14 Unboxing / unboxed returns / join points — Cranelift multi-return + SSA block params let §2.9/§2.11 scalars cross control-flow merges (§2.14) — **P4** IR shape; register-allocation specifics belong to the Cranelift tiers (**P6**/**P7**, [08](08-execution-tiers-and-cranelift.md)).

## References

- GHC Core-to-Core simplifier (the iterated IR-to-IR pipeline, gentle-to-final
  phasing, RULES) — Peyton Jones & Santos, *A transformation-based optimiser for
  Haskell*:
  <https://www.microsoft.com/en-us/research/wp-content/uploads/2016/07/comp-by-trans-scp.pdf>
- GHC User's Guide, *Optimisation (code improvement)* — worker/wrapper, full
  laziness / let-floating, CSE, specialization, SpecConstr:
  <https://downloads.haskell.org/ghc/9.12.1/docs/users_guide/using-optimisation.html>
- Sergey, Vytiniotis, Peyton Jones et al., *Theory and Practice of Demand Analysis
  in Haskell* — combined strictness + cardinality demand analysis (the §2.4/2.8/2.10
  licensing facts):
  <https://www.microsoft.com/en-us/research/wp-content/uploads/2017/03/demand-jfp-draft.pdf>
- Peyton Jones, Partain & Santos, *Let-floating: moving bindings to give faster
  programs*, ICFP 1996 — float-out / float-in (§2.7).
- Aleksey Shipilëv, *JVM Anatomy Quark #18: Scalar Replacement* — HotSpot SRA, the
  model for §2.11:
  <https://shipilev.net/jvm/anatomy-quarks/18-scalar-replacement/>
- Companion documents: [laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md)
  (the narrative and the analyses), [the intermediate representation](25-intermediate-representation.md)
  (the node taxonomy and effect classes), [decision register](19-decision-register.md)
  (C-21 committed, M-24 measure-gated).
