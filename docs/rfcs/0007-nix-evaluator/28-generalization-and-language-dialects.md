# RFC-0007 - Generalization and language dialects (the `ratchet` engine)

> Part of the RFC-0007 aos-nix documentation set. This document records a
> *structural* decision that does not change what aos-nix delivers — a
> byte-identical Nix evaluator — but changes how its crates are *named and
> layered* so the language-agnostic machinery is reusable. The substrate (the
> demand graph, the Core IR, the execution tiers, the GC, the value
> representation) is factored out as a standalone engine, **`ratchet`**, and Nix
> becomes the first *dialect* that plugs into it. No second language is in scope
> for RFC-0007; this document only ensures a second one would be *additive*
> rather than a rewrite.
>
> Read this alongside [architecture overview](03-architecture-overview.md) §3.4
> (the unified demand graph, which already frames the engine as general), the
> [intermediate representation](25-intermediate-representation.md) (the IR that
> becomes the generic *Core*), [engineering standards](27-engineering-standards.md)
> §1.1 (the crate split this document renames and extends), the
> [incremental evaluation cache](12-incremental-evaluation-cache.md) §1.1 (the
> soundness argument this document bounds), and the
> [decision register](19-decision-register.md) (which gains `S-22` and `S-23`).

## 1. What this document is, and what it is not

The architecture overview already states the strongest version of the thesis
([03](03-architecture-overview.md) §3.4): *aos-nix is first a general incremental
computation engine, and Nix evaluation — including its own front-end — is the top
layer.* Lexing, parsing, scope resolution, optimization, compilation, and thunk
forcing are all one kind of thing: a memoized, content-addressed, suspendable
unit of deferred work. That generality lives in the engine *already*; nothing
about it is Nix-specific.

This document takes that observation one step further — up into the IR — and pins
down the consequence for the crate topology:

> **The engine and the Core IR carry no Nix knowledge. The Nix-specific concepts
> — `derivationStrict`, `with`, string contexts, the builtin set, the concrete
> effects — are a *dialect* layered on top.** The engine is named `ratchet`; Nix
> is the `ratchet` dialect that AOS ships.

What this document is **not**: a commitment to build a second frontend. RFC-0007
delivers Nix and only Nix, gated by the byte-identical `.drv` harness
([15](15-differential-testing-and-benchmarking.md)). Generality is adopted only
where it is free or nearly free — clean layering and naming we would want anyway —
and never where it would tax the byte-identity gate. That scoping is decision
`S-22` (§8).

## 2. The reframe: LLVM is the wrong analogy, and CLIF is already the right one

The intuitive pitch — "make the IR generic like LLVM IR so other languages can
share the optimizer" — misnames the layer. LLVM IR is a *universal low-level* IR:
it unifies C, Rust, Swift, and Zig because they all compile to roughly the same
von Neumann machine (SSA over basic blocks, load/store to mutable memory, machine
ints/floats/pointers, eager evaluation). LLVM is language-agnostic only across
languages that *share that abstract machine*.

The aos-nix IR is the opposite kind of artifact: a **high-level, lazy, GC'd,
demand-driven functional IR**. Its peers are not LLVM IR — they are **GHC Core,
STG, and System F<sub>C</sub>**: core calculi that unify *pure lazy functional*
languages. Two facts follow:

1. **The low-level universal IR already exists in the stack: it is Cranelift
   CLIF.** The Core IR lowers *to* CLIF ([08](08-execution-tiers-and-cranelift.md));
   CLIF is the von-Neumann target that plays LLVM's role. There is nothing to
   build here and nothing to generalize — CLIF is already language-neutral.
2. **The "generic IR" worth factoring is one layer up: a lazy-functional Core.**
   It unifies the *pure lazy functional* language family (Nix, Haskell, the
   expression fragment of TLA+, PureScript, …), not the imperative family. This
   is the layer this document names *Core* and houses in `ratchet-core`.

The right architectural template is therefore **MLIR, not LLVM**. MLIR is "one IR
infrastructure, many dialects, progressive lowering between them, shared passes
over a common structure." `ratchet` adopts that shape — a common Core substrate
plus per-language dialects plus lowering — and adds the property MLIR does not
have: every node is a citizen of the demand-driven memoization graph
([12](12-incremental-evaluation-cache.md)).

```text
   surface syntax (per language)          aos-nix-syntax,  aos-hs-syntax, ...
        |  lower (per dialect)
   Core IR  (lazy functional)             ratchet-core      <- the "generic IR"
        |  lower (ratchet-jit)
   CLIF     (Cranelift)                   ratchet-jit       <- the real "LLVM"
        |
   machine code
```

## 3. The three bands of the topology

The crate set splits into three bands. The happy fact that makes this cheap: the
band boundary *coincides with the safe/unsafe fence already drawn in*
[27](27-engineering-standards.md) §1.1 — the UNSAFE engine crates are exactly the
ones that carry no Nix knowledge, and the SAFE per-language crates are exactly
where Nix lives. Generalizing does not fight the fence; it rides it.

```text
ENGINE  (language-agnostic; was the aos-nix-* UNSAFE band — rename only)
   ratchet-value      UNSAFE   tagged/NaN-boxed value, hash-consing
   ratchet-gc         UNSAFE   bump arena + precise copying collector
   ratchet-jit        UNSAFE   Cranelift tier-1/tier-2 codegen, runtime ABI, deopt
   ratchet-cache      UNSAFE   demand-graph cache + content-addressed value store
   ratchet-parallel   UNSAFE   fibers, work-stealing deques, the CAS thunk protocol

CORE IR + DIALECT INFRASTRUCTURE  (language-agnostic)
   ratchet-core       SAFE     the Core IR: NodeKind taxonomy, de-Bruijn resolve,
                               the simplifier *framework*, serialization
   ratchet-dialect    SAFE     the trait a language plugs into (§5)
   ratchet-oracle     SAFE     the generic Core tree-walk interpreter

NIX = the first dialect  (a per-language band; repeats per future language)
   aos-nix-syntax     SAFE     Nix lexer, parser, arena AST, spans
   aos-nix-dialect    SAFE     derivationStrict, `with` lowering, the builtin
                               table, string-context semantics, Nix effects,
                               Nix-specific rewrite rules (list fusion)
   aos-nix-compat     SAFE     ATerm / .drv / store-path hashing (nix-compat glue)
   aos-nix-harness    SAFE     the differential .drv-diff harness vs C++ Nix
   aos-nix            UMBRELLA  the AOS-facing Evaluator: wires the Nix dialect
                               onto ratchet; NixNative shims over this
```

The dependency direction is unchanged from [27](27-engineering-standards.md)
§1.1: SAFE frontend/core crates sit below the UNSAFE engine crates, the umbrella
sits on top, and `aos-nix-compat` / `aos-nix-harness` are leaves. The dialect
crates are SAFE leaves that *parameterize* the engine — never a build-time
dependency of it.

The naming rule, stated once and binding on every other doc:

> **`ratchet-*` = language-agnostic and potentially extractable as a standalone
> crate. `aos-nix-*` = the Nix dialect plus AOS integration.** The `.drv`/ATerm
> leaf stays `aos-`prefixed because it is irreducibly Nix.

## 4. What is generic and what is a dialect

Walking the IR taxonomy ([25](25-intermediate-representation.md) §2), the
Nix-specific surface is small — which is why this is a factoring, not a redesign:

| IR concept | Band | Note |
| --- | --- | --- |
| Int/Float/Bool/Null/Str, de-Bruijn vars, Lambda/Apply, Let, If, BinOp/UnaryOp, List, ThunkAlloc | **Core** | A lazy lambda calculus. Haskell Core has all of it. |
| AttrSet + hidden class, Select/HasAttr | **Core (generalized)** | "record/object with hidden classes" is exactly V8 objects — generalize to data-constructor + projection. |
| PrimOp + per-primop strictness | **Core mechanism, dialect contents** | The node kind is generic; the *builtin set* is the dialect's. The escape hatch (§5). |
| `DerivationStrict` | **Nix dialect** | A distinguished effectful primop; the `.drv` boundary. |
| `WithVar` / dynamic `with` scope | **Nix dialect** | The resolver's "unresolved name" path becomes a dialect hook: Nix emits `WithVar`; a dialect without dynamic scope errors. |
| String context (union-on-concat, `.drv`-observable) | **Nix dialect** | Already a *runtime value property*, not an IR node ([25](25-intermediate-representation.md) §4.6) — barely pollutes the IR. The bitset repr moves out of `ratchet-value` into the dialect as a cons-key discriminator. |
| `EffectClass { Pure, Effectful }` | **Core split, dialect members** | The Pure/Effectful *lattice* is generic; the concrete effects (`import`, IFD, `readFile`, `derivationStrict`) are the dialect's. Today a closed enum — the one place Nix leaks into the engine (§5, `S-23`). |

So the entire Nix-specific surface is: `DerivationStrict`, `with`, string-context
value semantics, the builtin identities, and the concrete effect members.
Everything else is already generic.

## 5. The dialect interface (`ratchet-dialect`)

A dialect supplies, at **IR-construction time**:

- its **extra ops** — node kinds beyond Core, reached through the existing
  indexed escape hatch rather than new core variants (below);
- its **effect-lattice members** — what is speculable, and the opaque effect key
  the cache uses for re-execution boundaries (`S-23`);
- its **primop table** — the builtin identities and their per-argument
  strictness;
- its **rewrite rules** — dialect-specific simplifier RULES (Nix list fusion);
- its **lowering hooks** — how an extra op lowers in the oracle and in
  `ratchet-jit`.

The one hard constraint, inherited from [27](27-engineering-standards.md) (no
`Box<dyn>` on the force hot path):

> **The dialect is a registration-time seam, never a per-force `dyn` dispatch.**

This is already how the IR works. `PrimOp(symbol, args)` is a *direct,
statically-known* call whose `symbol` is an index baked into the IR at lowering
([25](25-intermediate-representation.md) §4.5). A dialect op is the same shape: an
indexed escape hatch resolved *once*, at lowering, into a concrete runtime symbol
the oracle and JIT see directly. The engine is monomorphized over the dialect (a
generic parameter), not dynamically dispatched. `DerivationStrict` is "just" a
distinguished effectful primop under this lens; the escape hatch you need is the
one you already built.

The single change that crosses into an UNSAFE engine crate is the effect lattice:
`ratchet-cache` gates speculation and re-execution on the per-node effect tag but
must not *interpret* it. So the engine API moves from a closed
`enum EffectClass { Pure, Effectful }` to a trait — `is_speculable() -> bool` plus
`effect_key() -> EffectKey` — and the dialect supplies the members. This is
decision `S-23`.

## 6. The cache-soundness boundary (the sharp caveat)

The cache's soundness argument ([12](12-incremental-evaluation-cache.md) §1.1)
rests on **three** Nix properties — purity, immutability, and *whole-program
closed-world batch nature* — and they do not all transfer to every language. The
machinery must be split accordingly:

- **The demand-graph engine itself** (memoization, suspend/resume, parallelism,
  the node model) is **fully generic** — a Salsa/Adapton-style incremental
  computation library that reuses for anything. This transfers unconditionally.
- **The persistent content-addressed cache and early cutoff** transfer **only to
  pure, closed-world-batch frontends**:
  - **Nix** ✓ — has all three properties.
  - **TLA+ / TLC model-checking** ✓ — a fixed spec plus fixed constants is a
    closed world; memoizing pure operator evaluations is sound, and incremental
    re-checking after a spec edit (early cutoff) is a capability TLC lacks today.
  - **A running general-purpose program (e.g. compiled Haskell)** ✗ — its runtime
    is *open-world* (stdin, sockets, the clock), so the cross-run persistent cache
    does **not** apply to its execution. It *does* apply to compile-time
    evaluation (CAFs, Template Haskell), a much narrower win.

The rule to carry: **the memoization engine is generic; the cross-run persistent
soundness requires pure *and* closed-world-batch.** Nix and TLC have it; a running
program does not.

## 7. How three candidate languages fit

Recorded for completeness, to validate that the Core boundary is drawn in the
right place. None of these is in scope (`S-22`).

- **Haskell — fits very well, with one fork.** Laziness, purity, immutability,
  closures, and ADTs map directly; the strictness/worker-wrapper and escape
  analyses ([07](07-laziness-and-whole-program-analyses.md)) are lifted from GHC
  and would feel *more* at home here than on Nix. Two differences: (1) **types** —
  Core is untyped (Nix is dynamic), GHC Core is typed; the clean resolution is to
  target the **STG level** (essentially untyped) for the shared Core and let typed
  frontends keep a typed IR above the seam; (2) **effects are values** — Haskell
  has no `derivationStrict`; `IO` is a pure value and effects happen in the RTS,
  so its effect lattice is nearly empty at Core level (which the §5 machinery
  handles — it just populates differently).
- **TLA+ — fits *partially*, and the split is instructive.** TLA+ is a
  specification language, not an executable one. Its **constant/data fragment**
  (sets, functions, records, tuples, integers, `CHOOSE`, comprehensions) is
  evaluable and looks strikingly like Nix — it maps onto Core directly, and a
  TLC-style checker needs exactly this to evaluate guards and next-state
  assignments. Its **temporal/action layer** (primed variables, `[]`/`<>`,
  `ENABLED`, `WF`/`SF`, the next-state relation) is *not* a value evaluator at
  all — it needs a **state-space exploration engine** that sits *on top of*
  `ratchet-oracle`/`ratchet-cache` and calls into them. So TLA+ would reuse the
  evaluator as a *library*, plus a separate model-checking driver crate
  (`aos-tla-mc`), not "another frontend that produces values."
- **Nix — the reference fit.** Full delivery, the byte-identical `.drv` gate, the
  one dialect RFC-0007 ships.

The recurring cost per *additional* language lives entirely in its band: a syntax
crate, a dialect crate, and — the real expense — **its own differential oracle**
(Nix diffs C++ Nix; Haskell would diff GHC; TLA+ would diff TLC). The engine and
Core are paid for once.

## 8. Scope decisions

Two decisions enter the [register](19-decision-register.md):

- **`S-22` — Core + dialect architecture (`ratchet`), Nix-only delivery.** Adopt
  the MLIR-style Core/dialect factoring and the `ratchet-*` topology. Deliver Nix
  and only Nix in RFC-0007. Generality is adopted only where free or nearly free
  (naming, crate boundaries); no second frontend, no abstraction that taxes the
  byte-identity gate.
- **`S-23` — open, dialect-supplied effect lattice.** The effect class is an
  engine trait (`is_speculable` + `effect_key`), not a closed `{ Pure, Effectful }`
  enum; the dialect supplies the members. This is the one generalization that
  touches an UNSAFE engine crate (`ratchet-cache`).

Both are recorded as *settled* (they constrain shape, not behavior; the harness is
the backstop either way).

## 9. The crate topology change, before and after

| Before ([27](27-engineering-standards.md) §1.1) | After | Change |
| --- | --- | --- |
| `aos-nix-value` | `ratchet-value` | rename; string-context moves out to `aos-nix-dialect` |
| `aos-nix-gc` | `ratchet-gc` | rename only |
| `aos-nix-jit` | `ratchet-jit` | rename only |
| `aos-nix-cache` | `ratchet-cache` | rename; gates on the open effect lattice (`S-23`), opaquely |
| `aos-nix-parallel` | `ratchet-parallel` | rename only |
| `aos-nix-ir` | `ratchet-core` **+** `aos-nix-dialect` | split: generic Core vs Nix nodes |
| `aos-nix-oracle` | `ratchet-oracle` | rename; dialect-provided op semantics |
| — | `ratchet-dialect` | new: the dialect trait |
| `aos-nix-syntax` | `aos-nix-syntax` | unchanged |
| `aos-nix-compat` | `aos-nix-compat` | unchanged |
| `aos-nix-harness` | `aos-nix-harness` | unchanged |
| `aos-nix` (umbrella) | `aos-nix` (umbrella) | unchanged role; now wires a dialect |

Net: a Nix-only delivery is still ~12 crates, but 8 of them (`ratchet-*`) are
named and scoped as a reusable engine + generic Core, and a second language is
"add a 4-crate band," not "fork the IR." The safe/unsafe fence, the one-way
dependency direction, and the one-Core-IR invariant all survive unchanged — the
dialect axis is orthogonal to all three.

## 10. Phase 1b — the migration plan

The implementation today is a **single monolithic `aos-nix` crate**, early in
Phase 1 ([17](17-roadmap-and-risks.md) §6), with a tree-walk oracle and no engine
crates yet (`ratchet-cache`/`-gc`/`-jit`/`-parallel` do not exist). The
re-layering is therefore captured as **Phase 1b**: a structural pass that is
**behaviorally inert** (it changes no `.drv` output; the harness stays byte-green)
and runs alongside the tail of Phase 1.

**Ordering.** Phase 1b *enters* once the parser → Core IR → oracle skeleton
compiles and the first fixtures are byte-green; it overlaps the remainder of
Phase 1 feature work and the P1.5 measure-first gate; it **must complete before
Phase 2**, because Phase 2 builds `ratchet-cache` and the open effect lattice and
those should be *born* in the new model, not retrofitted.

**Constraint (the reason this is a separate phase, not an in-place rewrite).**
Existing P1 items are not rewritten where they stand. They gain a one-line "→
re-layered in Phase 1b" pointer; the migration work lives here. Agents continuing
P1 fold these in as they go, rewriting already-done modules to fit.

### Phase 1b checklist

- [ ] **Crate split with `ratchet` naming.** Break the `aos-nix` monolith into
  `ratchet-core` (from `compile/ir.rs` + `compile/scope.rs`), `ratchet-oracle`
  (from `eval/`), `ratchet-value` (from `value.rs`/`list.rs`/`attrs.rs`/`heap/`),
  `ratchet-dialect` (new), and the Nix band (`aos-nix` umbrella, `aos-nix-syntax`
  from `syntax/`, `aos-nix-dialect` new, `aos-nix-compat` from the store glue,
  `aos-nix-harness`). Reserve but do not create `ratchet-gc` (P3),
  `ratchet-cache` (P2), `ratchet-jit` (P6), `ratchet-parallel` (P3.5).
- [x] **Core/dialect IR split.** Generic `IrKind` stays in `ratchet-core`;
  `DerivationStrict` and `WithVar` are dialect-owned ops registered through the
  same indexed escape-hatch *mechanism* as `PrimOp(symbol, args)` — not collapsed
  into an ordinary builtin `PrimOp` symbol. `DerivationStrict` keeps its own
  distinct, statically locatable dialect-op key/payload (the `.drv` boundary the
  harness anchors on, per [25](25-intermediate-representation.md) §4.7), owned by
  the Nix dialect rather than Core. The resolver's "unresolved name" path becomes
  a dialect hook (Nix emits `WithVar`; other dialects error).
- [x] **`EffectClass` → open trait (`S-23`).** Replace the closed
  `enum EffectClass { Pure, Effectful }` with a `ratchet-core` trait
  (`is_speculable` + `effect_key`); the Nix dialect supplies the members
  (`import`/IFD/`readFile`/`derivationStrict`). Delete the hardcoded
  `effect_for(DerivationStrict) => Effectful`.
- [ ] **String-context extraction.** `ratchet-value` keeps the generic tagged
  value + hash-consing; the context bitset + union-on-concat semantics move to
  `aos-nix-dialect`, with the engine's cons-key hashing taking a dialect-supplied
  discriminator so identical-bytes / different-context strings still do not
  collapse.
- [ ] **`ratchet-dialect` trait definition.** The registration-time interface of
  §5 (extra ops, effect members, primop table, rewrite rules, lowering hooks);
  monomorphized, never `dyn` on the force path.
- [ ] **Habit guard (carries through the rest of P1).** No new Nix-specific
  `IrKind` variants — every new builtin routes through `PrimOp`; keep
  string-context confined to the dialect.

**Exit criterion.** The `.drv`-diff harness is byte-green on the same fixtures as
before the split (the refactor is behaviorally inert), and the crate boundaries
match §3 / [27](27-engineering-standards.md) §1.1.

## 11. Summary

- **The engine is already general; this document names it.** `ratchet` is the
  language-agnostic substrate ([03](03-architecture-overview.md) §3.4 made
  concrete); Nix is the first dialect.
- **CLIF is the LLVM-analog; Core is the GHC-Core-analog.** The "generic IR" worth
  factoring is a lazy-functional Core (`ratchet-core`), not a low-level SSA — that
  already exists as CLIF.
- **MLIR is the template.** One Core substrate, per-language dialects, lowering,
  shared passes — plus demand-graph memoization MLIR lacks.
- **The Nix-specific surface is small.** `DerivationStrict`, `with`,
  string-context, the builtins, the effect members — everything else is generic.
- **The dialect is a registration-time seam.** Reuse the indexed-primop escape
  hatch; monomorphize, never `dyn` on the force path.
- **Cache soundness is bounded.** The engine is generic; cross-run persistence
  needs pure + closed-world-batch (Nix ✓, TLC ✓, a running program ✗).
- **Nix-only delivery (`S-22`); open effect lattice (`S-23`).**
- **Phase 1b** re-layers the monolith into `ratchet` + the Nix dialect, behaviorally
  inert, byte-green at exit, before Phase 2.

## References

- MLIR (one IR infrastructure, many dialects, progressive lowering) —
  <https://mlir.llvm.org/docs/LangRef/>
- GHC Core and STG (the typed and untyped lazy-functional cores) —
  <https://gitlab.haskell.org/ghc/ghc/-/wikis/commentary/compiler/core-syn-type>
- The Spineless Tagless G-machine (STG) —
  <https://www.microsoft.com/en-us/research/wp-content/uploads/1992/04/spineless-tagless-gmachine.pdf>
- Cranelift IR (CLIF) — the low-level universal target —
  <https://github.com/bytecodealliance/wasmtime/blob/main/cranelift/docs/ir.md>
- TLA+ and TLC (the constant fragment vs the temporal/model-checking layer) —
  <https://lamport.azurewebsites.net/tla/tla.html>
- Salsa (query-based incremental computation, the generic engine shape) —
  <https://github.com/salsa-rs/salsa>

## Implementation checklist

Per-feature tracker for the generalization and the Phase 1b re-layering; master
roll-up: [implementation checklist (all phases)](22-implementation-checklist-all-phases.md).
The architecture decisions are `S-22`/`S-23` ([19](19-decision-register.md)); the
migration is Phase 1b ([17](17-roadmap-and-risks.md) §6, [22](22-implementation-checklist-all-phases.md)).

### Architecture (this doc)

- [ ] `ratchet-*` naming and the three-band topology adopted (§3) — `S-22`.
- [x] Core/dialect boundary drawn at the IR (§4): `DerivationStrict`, `with`,
  string-context, builtins, effect members are the Nix dialect; everything else is
  Core — `S-22`.
- [x] `ratchet-dialect` registration-time trait, monomorphized, no force-path
  `dyn` (§5) — `S-22`.
- [x] Open effect lattice (`is_speculable` + `effect_key`) replacing the closed
  enum (§5, §8) — `S-23`.

### Phase 1b migration (§10)

- [ ] Crate split with `ratchet` naming; engine crates reserved per phase.
- [x] Core/dialect IR split via the `PrimOp` escape hatch; resolver unresolved-name
  dialect hook.
- [x] `EffectClass` → open trait; remove the hardcoded `DerivationStrict` effect.
- [ ] String-context extracted from `ratchet-value` into `aos-nix-dialect`.
- [ ] Behaviorally inert: `.drv` harness byte-green at exit, on the pre-split
  fixtures.
