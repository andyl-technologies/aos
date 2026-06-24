# RFC-0007 - Architecture Overview

This document is the architectural spine of RFC-0007. It states the *shape* of
aos-nix — the layered stack, the four hard problems the design must solve, the
synthesis thesis that lets us solve them by harvesting one proven technique per
problem, and the tier model that organizes execution from a correctness oracle
up to an optimizing JIT. The sibling documents drill into each layer; this one
explains why the layers exist and how they compose.

Read this after [motivation and goals](01-motivation-and-goals.md) and
[compatibility constraints](02-compatibility-constraints.md), which establish
*why* we are building an evaluator at all and the *non-negotiable* output
contract it must honor. Everything below is downstream of two facts established
there:

1. **Eval, not build, is the bottleneck we attack.** aos-nix replaces only the
   path from `.nix` source to a `.drv` derivation graph. Real Nix still *builds*
   the resulting `.drv`. A faster evaluator attacks eval-time exclusively.
2. **The output is a bug-for-bug contract.** aos-nix must emit byte-identical
   `.drv` files and store paths to C++ Nix, using SHA-256 derivation hashing and
   exactly-matching string contexts. Any divergence yields a different store
   path, a total cache miss, and a catastrophic from-source toolchain rebuild.
   This constraint shapes the architecture as much as performance does.

---

## 1. The synthesis thesis

The central claim of RFC-0007, restated here because the whole architecture is
its corollary:

> A fast Nix evaluator is a fast implementation of a language that is
> simultaneously **(1) lazy**, **(2) dynamically typed**, **(3) garbage
> collected**, and **(4) purely functional and immutable** — wrapped in **(5) a
> recomputation/caching layer**. Each of those five properties has a mature,
> battle-tested implementation tradition in some *other* language runtime. We do
> not need to invent technique; we need to *port the right technique per problem*
> and exploit the fact that Nix's purity makes several of those techniques —
> partial or unsound elsewhere — **total and sound here**.

This is the load-bearing insight. Most discussion of "fast Nix" frames it as a
parsing or interpreter-dispatch problem. It is not primarily either. It is a
*lazy functional language runtime* problem plus an *incremental computation*
problem, and both of those fields are decades deep. The contribution of aos-nix
is not a novel algorithm; it is the disciplined assembly of known-good
algorithms against a workload whose semantic constraints happen to be unusually
friendly to them.

Because that assembly is language-agnostic — none of its five techniques is
Nix-specific — the substrate is factored as a standalone engine, **`ratchet`**,
with Nix as the first *dialect* plugged into it. This is a naming-and-layering
decision (`S-22`), not a second-frontend commitment: RFC-0007 delivers Nix and
only Nix, gated by the byte-identical `.drv` harness. See [generalization and
language dialects](28-generalization-and-language-dialects.md).

### 1.1 Why purity changes the economics

Consider the optimizations that are *risky, partial, or speculative* in
mainstream runtimes and what they cost there:

| Technique | Origin | Why it is partial/unsound *elsewhere* | Why it is total/sound *in Nix* |
|-----------|--------|----------------------------------------|--------------------------------|
| **Strictness / demand analysis** | GHC | Bounded by separate compilation; cross-module demand is conservative | Whole-program batch eval: the entire expression closure is visible at once |
| **Escape analysis + scalar replacement** | HotSpot | Mutable aliasing and reflection defeat it; Java objects escape through fields | Values are immutable; an attrset that does not flow to an output truly cannot be observed elsewhere |
| **Hash-consing / maximal sharing** | LISP, term rewriting | Mutation invalidates interned identity | Values never mutate after construction; interning is permanently valid |
| **Memoize + early cutoff** | Salsa, Adapton, build systems | Hidden state and I/O make "same inputs -> same output" false | Eval is a pure function of source + captured environment; memoization is *referentially transparent* |
| **Parallel forcing** | GHC sparks | Shared mutable state requires locks everywhere | The only mutable state is the thunk-update protocol, which is monotonic (Suspended -> Forced) and idempotent |

Each row is a place where the *generic* version of a technique pays a soundness
tax, and where Nix's semantics waive that tax. That waiver is the entire reason
this project is tractable as an *assembly* job rather than a research program.

### 1.2 What we are *not* claiming

We are explicitly **not** claiming "rewrite it in Rust and it gets fast." The
cautionary data point is hnix (the Haskell Nix evaluator), which is notably
*slow* despite Haskell's reputation — language choice is not the lever. The
lever is the *technique stack*. Equally, we treat C++ Nix as the reference
baseline **to beat**, not Haskell or any toy. C++ Nix is genuinely fast; its
dominant cost is the Boehm conservative GC and the per-thunk allocation churn,
both of which we attack head-on rather than assuming we win by default. See
[motivation and goals](01-motivation-and-goals.md) for the measure-first discipline
that holds us to this.

---

## 2. The four hard problems

The synthesis thesis decomposes into four engineering problems plus the caching
layer. Naming them precisely matters because the rest of the RFC is organized
around them, and because each maps to a *specific* prior-art runtime we mine.

```text
                         aos-nix: four hard problems
  ┌──────────────────────────────────────────────────────────────────────┐
  │                                                                        │
  │   P1  LAZINESS          make thunks nearly free        <- GHC          │
  │       "evaluate as little as possible, as cheaply as possible"         │
  │                                                                        │
  │   P2  DISPATCH/SHAPES   make attrset access O(1)       <- V8 / LuaJIT  │
  │       "the hottest data structure is the attribute set"                │
  │                                                                        │
  │   P3  MEMORY/GC         stop paying Boehm's tax         <- HotSpot/GHC │
  │       "intermediate thunks die instantly; collect precisely or never"  │
  │                                                                        │
  │   P4  CODEGEN/TIERS     don't re-interpret hot code     <- HotSpot     │
  │       "compile per-expression once, not per thunk-activation"          │
  │                                                                        │
  ├──────────────────────────────────────────────────────────────────────┤
  │                                                                        │
  │   P0  RECOMPUTATION     don't evaluate at all           <- Salsa/      │
  │       "the fastest evaluator is the one that does not evaluate"           Adapton │
  │                                                                        │
  └──────────────────────────────────────────────────────────────────────┘
```

We number the caching layer **P0** deliberately. It sits *above* the other four
and is the single biggest expected real-world win, because it can short-circuit
the other four entirely. The remaining problems P1–P4 govern the cost of the
work that the cache *cannot* avoid.

### P0 — Recomputation / incremental caching (Salsa, Adapton, Skip)

The systemic, order-of-magnitude lever — bigger than any constant factor
available from P1–P4. We model evaluation as a **demand-driven incremental
computation graph**: each thunk/derivation result is memoized keyed on a hash of
its expression plus captured environment. The decisive feature is **early
cutoff**: when a recomputed node produces a value-hash equal to its previous
value-hash, change propagation *stops* — editing a comment in a widely-imported
file recomputes almost nothing. This is the Salsa/Adapton model, the same one
that lets rust-analyzer recompile incrementally as you type: backward change
flooding halts at the first query whose result is unchanged despite a changed
input.

This is sound *only* because Nix is pure (P0 inherits the purity waiver from
§1.1). The cache is persisted content-addressed and shared across CI machines —
extending AOS's existing Attic cache from build *outputs* to eval *outputs*. The
mantra: **aos-nix is first an incremental computation engine that happens to
evaluate Nix.** Full treatment in [incremental evaluation
cache](12-incremental-evaluation-cache.md).

### P1 — Laziness (GHC)

Nix is lazy. A naive evaluator allocates a heap thunk for every unforced
subexpression, forces them through indirect calls, and pays update/blackhole
machinery on each. GHC spent thirty years making laziness nearly free, and
neither C++ Nix nor Snix applies those techniques. We port:

- **Strictness / demand analysis + worker-wrapper**: bindings provably always
  forced compile *eagerly*, with zero thunk allocation. GHC's demand analyser
  gathers exactly this strictness information for its simplifier, then the
  worker/wrapper transform exposes an unboxed calling convention.
- **Cardinality / usage analysis (0/1/many)**: a binding used at most once needs
  no blackhole/update machinery (single-entry thunk); a binding used zero times
  is dead-code-eliminated. GHC's usage analysis answers exactly "evaluated at
  most once vs. not at all."
- **Full-laziness / let-floating**: hoist constant subexpressions out of
  lambdas, so a thunk built inside a `map`/`genList` loop is computed once
  rather than per iteration.

Detailed in [laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md).

### P2 — Dispatch & shapes (V8, LuaJIT)

The attribute set is the single hottest data structure in any nixpkgs-scale
evaluation. Naive attrset access is a hash-map lookup per `.field`. V8 solved
the structurally-identical JavaScript-object problem with **hidden classes
(shapes)** and **inline caches**: objects reaching a program point share a
hidden class (same keys, same insertion order), so `obj.field` becomes a
shape-check plus a constant-offset load. The inline cache at each access site
walks the states `uninitialized -> monomorphic -> polymorphic -> megamorphic` as
it observes shapes, caching `shape -> offset`. Nix attrsets map onto this almost
exactly, with one twist: **iteration order is observable and must match C++ Nix
byte-for-byte** (it feeds `derivationStrict`), so our shape model carries a
deterministic ordering invariant that V8 does not need. Full treatment in
[attribute sets, hidden classes and inline caches](09-attribute-sets-hidden-classes-and-inline-caches.md).

### P3 — Memory & GC (HotSpot, GHC)

C++ Nix's dominant cost is its Boehm conservative GC. We replace it. The
**generational hypothesis** — most objects die young — holds in an *extreme*
form here: intermediate thunks built during forcing are dead almost immediately.
We therefore want a **precise generational copying collector** (cache-resident
nursery) for long-lived daemon mode, and a **bump-pointer never-free arena** for
one-shot CLI eval (the fastest possible allocator; correct for a batch job that
drops its whole heap at process exit). Precise (not conservative) GC eliminates
Boehm-style false retention. **All allocation routes through runtime symbols
(`aos_alloc_*`)** so the JIT-emitted code is independent of which GC strategy is
live. Full treatment in [memory management and GC](06-memory-management-and-gc.md).

### P4 — Codegen & tiers (HotSpot)

The key execution-model decision: **compile per-expression once (bounded: tens
of thousands of expressions), not per thunk-activation (billions).** A thunk is
`(code_ptr, captured_env, state)`; forcing checks state and, if `Suspended`,
calls the *already-compiled* code for that expression. We borrow HotSpot's
**tiered compilation**: a tree-walking interpreter as oracle and cold-code
executor, a Cranelift baseline JIT for warm code, and a Cranelift optimizing
tier with speculation, **deoptimization** (uncommon traps), and **on-stack
replacement**. Full treatment in [execution tiers and Cranelift](08-execution-tiers-and-cranelift.md);
the tier model is summarized in §4 below.

### The mapping is the architecture

```text
   PROBLEM                 PRIOR-ART SOURCE        aos-nix DOC
   ─────────────────────   ─────────────────────   ─────────────────────────
   P0 recomputation        Salsa / Adapton / Skip   12-incremental-...
   P1 laziness             GHC (STG, demand)        07-laziness-...
   P2 shapes/dispatch      V8 hidden classes        09-attribute-sets-...
   P3 memory/GC            HotSpot G1/Z, GHC gen    06-memory-management-...
   P4 codegen/tiers        HotSpot tiered + deopt   08-execution-tiers-...
   ─────────────────────   ─────────────────────   ─────────────────────────
   cross-cutting: value representation              05-value-representation
   cross-cutting: parallel forcing (GHC sparks)     13-parallel-evaluation
   cross-cutting: drv/store ATerm parity (nix-compat) 11-derivation-...
```

---

## 3. The layered stack

aos-nix is a pipeline from `.nix` source bytes to a `.drv` on disk. The layers
are designed so that (a) each has a single responsibility, (b) the boundaries
are stable contracts that let lower tiers swap implementations without
disturbing upper ones, and (c) the *correctness oracle* (tree-walk tier) and the
*fast path* (JIT tiers) share the value representation, primops, and store
backend, so they are differentially testable against each other and against C++
Nix.

The stack below is also the *band* boundary of the `ratchet`/dialect split
([28](28-generalization-and-language-dialects.md)): the lower, language-agnostic
machinery (value representation, GC heap, execution tiers, the incremental cache,
the Core IR) is the `ratchet-*` engine, and L1–L2 plus the Nix-specific runtime
(`derivationStrict`, `with`, string contexts, the builtin set) are the Nix
dialect that sits on top. The layer numbering and the band naming are orthogonal:
a layer names a stage in the pipeline; a band names whether the code is
engine (`ratchet-*`) or dialect (`aos-nix-*`).

```text
  ┌───────────────────────────────────────────────────────────────────────┐
  │                          aos CLI / aos-core                             │
  │   trait NixEval { instantiate(file, attr) -> DrvPath; eval_expr -> .. } │
  │   NixCli (subprocess, PERMANENT fallback)  |  NixNative (aos-nix)       │
  └───────────────────────────────┬───────────────────────────────────────┘
                                  │  AOS_NIX_NATIVE=1 gates NixNative
  ┌───────────────────────────────▼───────────────────────────────────────┐
  │  L7  INCREMENTAL CACHE (P0)                                             │
  │      demand-driven graph · early cutoff · content-addressed persist    │
  │      keys: blake3(expr-hash ⊕ env-hash);  Attic-backed cross-machine   │
  └───────────────────────────────┬───────────────────────────────────────┘
                                  │  cache miss -> evaluate
  ┌───────────────────────────────▼───────────────────────────────────────┐
  │  L6  EXECUTION TIERS (P4)                                               │
  │      tier0 tree-walk ORACLE  ->  tier1 Cranelift baseline  ->           │
  │      tier2 Cranelift optimized (speculate / deopt / OSR)               │
  │      uniform runtime ABI:  extern "C" fn(*Runtime,*Env[,arg])->Value   │
  └──────────┬───────────────────────────────────────┬────────────────────┘
            │                                       │
  ┌──────────▼─────────────────┐   ┌─────────────────▼────────────────────┐
  │  L5  ANALYSES (P1)          │   │  L4  RUNTIME / PRIMOPS                │
  │  strictness · cardinality   │   │  ~120 builtins as Rust fns           │
  │  full-laziness · escape     │   │  registered as Cranelift symbols     │
  │  -> annotates IR for L6     │   │  force/select_ic/alloc/derivStrict   │
  └──────────┬─────────────────┘   └─────────────────┬────────────────────┘
            │                                       │
  ┌──────────▼───────────────────────────────────────▼────────────────────┐
  │  L3  VALUE REP (cross-cut)  + ATTRSET SHAPES (P2)  + GC HEAP (P3)       │
  │      16-byte tagged value (NaN-box later) · pointer tagging (WHNF)     │
  │      hash-consing/maximal sharing · hidden classes + inline caches     │
  │      bump-arena (CLI)  /  precise generational copying GC (daemon)     │
  └───────────────────────────────┬───────────────────────────────────────┘
                                  │
  ┌───────────────────────────────▼───────────────────────────────────────┐
  │  L2  FRONTEND                                                          │
  │      hand-written recursive-descent parser -> compact arena AST        │
  │      scope resolution -> static env slot indices (de Bruijn-style)     │
  │      lowered to IR; parse artifacts cached content-addressed by hash   │
  └───────────────────────────────┬───────────────────────────────────────┘
                                  │  forcing reaches a derivation node
  ┌───────────────────────────────▼───────────────────────────────────────┐
  │  L1  DERIVATION / STORE BACKEND (HARD COMPAT)                          │
  │      derivationStrict -> nix-compat Derivation -> ATerm .drv           │
  │      input-/content-addressed output hashing (SHA-256) · string ctx    │
  │      byte-identical .drv + store paths to C++ Nix  (acceptance gate)   │
  └───────────────────────────────────────────────────────────────────────┘
```

### 3.1 Reading the stack top-down

- **L7 short-circuits everything below it.** A cache hit means L1–L6 never run
  for that node. This is why P0 is the biggest lever: the cheapest evaluation is
  the one elided entirely. See [incremental evaluation cache](12-incremental-evaluation-cache.md).
- **L6 is where the tier model lives.** tier0 is always present as the oracle;
  L1–L5 are shared by all tiers, which is what makes differential testing
  between tiers (and against C++ Nix) coherent. See [execution tiers and Cranelift](08-execution-tiers-and-cranelift.md).
- **L5 is pure compile-time analysis.** It does not execute; it *annotates* the
  IR with strictness, cardinality, full-laziness, and escape information that L6
  consumes to emit eager code, drop blackhole machinery, hoist loop-invariant
  thunks, and scalar-replace non-escaping allocations. See [laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md).
- **L4 is the runtime ABI surface.** Every builtin and every runtime service
  (`force`, `select_ic`, `alloc`, `import`, `derivationStrict`) is a Rust
  function exposed to JIT code through `JITBuilder::symbol`, the documented
  Cranelift mechanism for resolving names declared-but-not-defined in a compiled
  module. See [primops and runtime ABI](10-primops-and-runtime-abi.md).
- **L3 is shared mutable-free state.** Value representation, attrset shapes, and
  the heap are the substrate every tier reads and writes. Hash-consing and the
  shape table are immutable interning structures safe to share across threads —
  the foundation that makes P0's value-hashing and P2's shape-checks cheap. See
  [value representation](05-value-representation.md), [attribute sets, hidden classes and inline caches](09-attribute-sets-hidden-classes-and-inline-caches.md), and [memory management and GC](06-memory-management-and-gc.md).
- **L2 parses once per file.** A compact arena AST (not a rowan lossless CST on
  the hot path) with scope pre-resolved to static slot indices, cached
  content-addressed so the AOS package set is parsed exactly once. See [frontend, parser and IR](04-frontend-parser-and-ir.md).
- **L1 is the compatibility firewall.** This is where the hard constraint is
  enforced: `derivationStrict` collects the string environment in deterministic
  attr order, builds a `nix-compat` `Derivation`, serializes ATerm, and hashes
  output paths with SHA-256 — byte-identically to C++ Nix. See [derivation and store compatibility](11-derivation-and-store-compatibility.md) and [compatibility constraints](02-compatibility-constraints.md).

### 3.2 The execution-model contract (L6 ⇄ L3)

The contract between the codegen layer and the value/heap layer is small,
explicit, and the reason tiers are interchangeable. A *thunk* and a *lambda*
have fixed shapes; *forcing* is a fixed state machine.

```rust
/// A suspended computation: closure code plus its captured environment,
/// guarded by an evaluation state. `state` is the only mutable field, and it
/// only ever advances Suspended -> Blackhole -> Forced (monotonic).
struct Thunk {
    code: CodePtr,      // compiled expression OR tree-walk node id
    env:  EnvPtr,       // captured static-slot environment
    state: ThunkState,  // see below
    slot:  Value,       // result, valid once state == Forced
}

// The serial thunk-state machine (the serial subset of the parallel superset
// `Suspended -> Pending -> Awaited -> Forced/Failed` in doc 13). Single-threaded
// forcing only ever visits these three states.
enum ThunkState {
    Suspended,   // not yet forced
    Blackhole,   // forcing in progress -> infinite-recursion detection
    Forced,      // `slot` holds the WHNF result, cached forever
}

/// A function value: compiled body plus captured environment.
struct Lambda { code: CodePtr, env: EnvPtr }
```

The `force` operation is the heartbeat of the runtime:

```text
  force(thunk):
    match thunk.state:
      Forced     -> return thunk.slot                  # tag test, no call
      Blackhole  -> error "infinite recursion"         # cycle detected
      Suspended  -> thunk.state = Blackhole
                    v = call thunk.code(runtime, thunk.env)   # the only real work
                    thunk.slot  = v
                    thunk.state = Forced
                    return v
```

Two architectural consequences fall out of this contract:

1. **Pointer tagging makes the common case a tag test.** GHC's spineless-tagless
   insight: encode WHNF-evaluatedness (and small-constructor info) in spare
   pointer bits, so forcing an *already-evaluated* value is a bit test on the
   pointer, not a memory load plus an indirect call. The `Forced` arm above
   degenerates to a tag check. See [value representation](05-value-representation.md).
2. **The `state` transition is monotonic and idempotent**, which is precisely
   what makes parallel forcing sound: a thread can `CAS` `Suspended -> Blackhole`
   to claim a thunk, and a thread that loses the race (or hits a foreign
   blackhole) can work-steal elsewhere. This is the GHC spark model and the
   approach Determinate Systems took for parallel Nix eval. See [parallel evaluation](13-parallel-evaluation.md).

### 3.3 Why value representation, GC, and parallelism are *cross-cutting*

Notice that three concerns appear in the diagram at L3 rather than as their own
horizontal tier: value representation, the GC heap, and (implicitly)
parallelism. They are *substrate*, not *stage*. Every layer above them depends
on them, and they depend on nothing above. This is deliberate: by pinning the
value ABI and the allocation ABI at the bottom and routing every allocation
through runtime symbols, we keep the *fast-moving* layers (L5 analyses, L6
codegen) free to change without recompiling or re-reasoning about the substrate.
It is the same discipline HotSpot uses to let C1, C2, and the interpreter share
one object model and one GC.

### 3.4 The unified demand graph: parser, compiler, and forcer are one model

The deepest statement of this architecture is that **lexing, parsing, scope
resolution, optimization passes, compilation, and thunk forcing are all the same
kind of thing**: a memoized, content-addressed, suspendable unit of deferred work
whose output is a pure function of its inputs' identities. We do not build a
serial front-end that feeds a separate evaluator; we build **one demand-driven
incremental dataflow graph** in which each stage is a *node kind*. This is the
model Salsa (rust-analyzer) uses — lex/parse/name-resolution/type-inference are
all queries in one incremental graph — and it is the full conclusion of the
synthesis thesis (§1): *aos-nix is first a general incremental computation engine,
and Nix evaluation — including its own front-end — is the top layer.*

That general engine is named **`ratchet`**, and the split it implies is an
explicit architectural layer, not just a framing
([28](28-generalization-and-language-dialects.md)). The demand graph, the
execution tiers, the GC, the value representation, and the *generic* lazy-functional
IR — **Core** (`ratchet-core`), the GHC-Core-analog — carry no Nix knowledge. The
low-level universal target one layer below Core is **CLIF** (Cranelift), which
plays LLVM's role (the real LLVM-analog in this stack); Core lowers to CLIF
([08](08-execution-tiers-and-cranelift.md)). The Nix-specific concepts —
`derivationStrict`, `with`, string contexts, the builtin set, the concrete effects
— are a **dialect** layered on top: Nix is the first `ratchet` dialect, and the
recurring cost of a *second* language would live entirely in its own band, not in
a rewrite of the engine ([28](28-generalization-and-language-dialects.md) §3).

The payoff is that every cross-cutting concern is a property of **the graph
engine**, implemented once, and every node kind inherits it:

| Concern | How it is uniform across node kinds |
|---|---|
| Memoization / early cutoff | every node keyed by content hash; an unchanged output halts propagation ([12](12-incremental-evaluation-cache.md)) |
| Parallelism | every node is a work item on the rayon work-stealing pool ([13](13-parallel-evaluation.md)) |
| Suspend / resume | a node parks on I/O *or* on a dependency another worker is computing — one fiber scheduler ([13](13-parallel-evaluation.md) §5.5) |
| Speculation | any *pure* node may be computed ahead of demand ([04](04-frontend-parser-and-ir.md) §9.6) |
| Diagnostics | every node carries spans; errors render through one path ([24](24-observability-and-diagnostics.md)) |
| Persistence | every cacheable node lands in the same content-addressed store ([12](12-incremental-evaluation-cache.md) §6.5) |

So `import ./foo.nix` is not "call the parser then call the evaluator"; it is
*demand a parse node, which a worker may already have computed speculatively,
whose IR feeds a compile node, whose code feeds the thunk that produced the
demand* — all in one graph, scheduled by one pool, cached in one store.

**Two seams keep this honest** — the model is uniform in *shape*, but two
per-node properties differ by kind:

1. **Effect class.** Pure nodes (lex, parse, resolve, analyze, compile, and
   *most* thunks) get the full treatment — freely memoized, speculated, re-run,
   parallelized. **Effectful** nodes — `derivationStrict` (writes a `.drv`),
   `import`/`readFile` (reads the filesystem), IFD (triggers a build) — are a
   constrained subclass: at-most-once execution, **no speculation**, effects
   keyed into the cache as explicit inputs. The scheduler reads a per-node effect
   tag. This is the general form of the speculative-parse-error-quarantine rule
   ([04](04-frontend-parser-and-ir.md) §9.6): *speculation and re-execution are
   sound only for pure nodes.* The effect class is no longer a closed
   `{ Pure, Effectful }` enum: it is now an **open, dialect-supplied effect
   lattice** (the engine reads `is_speculable` plus an opaque `effect_key`; the
   dialect populates the members), so the engine carries no Nix effect names.
   This is decision `S-23` ([28](28-generalization-and-language-dialects.md) §5).

2. **Two-tier granularity.** The *coarse* nodes — files (parse/compile),
   whole-program analyses, derivations, heavy library bindings — live in the
   durable, dependency-tracked query graph. The *fine* thunk forcing *within* a
   node is plain in-memory laziness, **not** a tracked query, because a billion
   micro-thunks each carrying a memo-probe and a dependency edge would cost more
   than they save (the granularity policy, [12](12-incremental-evaluation-cache.md)
   §3.3–§3.4). One node *model*, two instantiation tiers selected by a cost rule.

With those two qualifiers — effect class (gates speculation/re-execution) and
two-tier granularity (gates tracking overhead) — the front-end stops being a
serial prelude and becomes a first-class citizen of the deferred-execution graph,
and the whole evaluator is one incremental dataflow engine. See the
[decision register](19-decision-register.md) (C-20) and
[frontend](04-frontend-parser-and-ir.md) §9.6.

---

## 4. The tier model

The tier model is HotSpot's, adapted to a lazy functional workload. The premise
HotSpot established and we inherit: **most execution time concentrates in a small
fraction of the code, and the cost to compile an expression is the same whether
it runs once or a million times.** So we run cold code in a cheap interpreter
and progressively compile hot code with more optimization, promoting on profile
evidence.

```text
              PROFILE-GUIDED PROMOTION  ───────────────────────►

   ┌──────────────┐      ┌──────────────────┐      ┌──────────────────────┐
   │ tier0        │ hot  │ tier1            │ hot  │ tier2                │
   │ TREE-WALK    ├─────►│ Cranelift        ├─────►│ Cranelift OPTIMIZED  │
   │ interpreter  │      │ BASELINE JIT     │      │ + speculation        │
   │              │      │                  │      │ + deopt (uncommon    │
   │ • ORACLE     │      │ • fast warmup    │      │   traps)             │
   │ • cold code  │      │ • per-expr once  │      │ + on-stack replace   │
   │ • run-once   │      │ • no speculation │      │ • inline-cache PIC   │
   │ • debuggable │      │                  │      │ • escape/scalar-repl │
   └──────▲───────┘      └──────────────────┘      └──────────┬───────────┘
          │                                                    │
          └──────────────── DEOPTIMIZE (assumption failed) ◄───┘
            execution resumes in tier0 with correct semantics
```

### 4.1 tier0 — tree-walking interpreter (the oracle)

tier0 is not just the slow path; it is the **correctness oracle**. It is the
simplest possible faithful implementation of Nix semantics, walking the arena
AST directly. Its roles:

- **Run-once and cold thunks.** Compiling an expression that forces once is pure
  overhead; tier0 just interprets it. This mirrors HotSpot Tier 0.
- **The differential reference.** When the JIT tiers and C++ Nix disagree on a
  `.drv`, tier0 is the tie-breaker we trust by construction — it has no
  speculation, no codegen, nothing to get subtly wrong. The acceptance gate
  (§5) runs against tier0 first to localize whether a divergence is a *semantics*
  bug or a *codegen* bug.
- **Debuggability.** JIT-compiled code is hard to step through; the oracle is
  trivially traceable, which matters for diagnosing the long tail of `.drv`
  divergence (the top risk in [roadmap and risks](17-roadmap-and-risks.md)).
- **The `miri`/sanitizer host.** AOS's "avoid unsafe at all costs" rule is
  necessarily violated by NaN-boxing, JIT fn-ptr calls, and raw-heap code. We
  keep the *safe* tree-walk oracle under `miri` and sanitizer CI precisely
  because it is the unsafe-free tree we can validate exhaustively. See
  [integration with AOS](14-integration-with-aos.md).

### 4.2 tier1 — Cranelift baseline JIT

When a thunk's expression crosses a force-count threshold, we compile it once
with Cranelift's baseline configuration: fast codegen, no speculation, no
deopt. This is the "simple compiler" of HotSpot's two-compiler design. Cranelift
is documented to perform code generation roughly an order of magnitude faster
than an equivalent LLVM-based system, which is exactly the property that makes a
*JIT* tier viable — warmup cost must be small relative to the work saved. We
compile **per expression**, not per activation, so the tens-of-thousands-of-
expressions budget bounds total compile time regardless of the billions of
activations.

### 4.3 tier2 — Cranelift optimized, with deopt and OSR

The top tier adds speculation guarded by **deoptimization**. The canonical
example: a `select` site whose inline cache has been monomorphic on one shape
gets compiled assuming that shape, with a guard that, on failure, fires an
**uncommon trap** — HotSpot's term — discarding the speculated code and resuming
in tier0 with correct (unspeculated) semantics. This is what lets us be
aggressive without being unsound: the speculation is always backed by a safe
fallback. Deoptimization in HotSpot suspends execution, scans frames, and
patches them back to interpreter format; our analogue rebuilds the tier0
interpreter state for the affected thunk.

**On-stack replacement (OSR)** handles the long-running-loop case: if a thunk is
already executing a hot loop (think a large `foldl'` or `genList`) when it
crosses the threshold, OSR lets us compile and *enter the compiled code mid-loop*
at a backedge rather than waiting for the next fresh call. HotSpot does exactly
this for hot loops.

### 4.4 Why Cranelift, and why not LLVM or WASM

The backend choice is a first-class architectural commitment, justified here and
expanded in [execution tiers and Cranelift](08-execution-tiers-and-cranelift.md):

| Option | Verdict | Reasoning |
|--------|---------|-----------|
| **Cranelift** | **Chosen** | Pure-Rust JIT backend, born in Wasmtime; compiles roughly an order of magnitude faster than the WAVM/LLVM Wasm pipeline (the figure varies by workload — ~40% on rustc, 20–35% on query compilation); designed for JIT/warmup; `JITBuilder::symbol` gives us the exact runtime-symbol mechanism our ABI needs; fits AOS's hermetic-from-source ethos (no C++ LLVM toolchain dependency). Already proven by `rustc_codegen_cranelift`. |
| **LLVM** | Rejected for the JIT path | Superior peak codegen (~14% faster than Cranelift in steady state) but far slower compilation — fatal for a warmup-sensitive JIT. Reserved at most as an *optional AOT cache tier* that precompiles a stable hot core offline, where compile time is amortized. |
| **WASM** | Rejected | Buys sandboxing/portability we do not need (we run our own trusted code), fights the custom precise GC (P3), and adds a host-boundary cost on every runtime-symbol call. The wrong abstraction for an in-process evaluator. |
| **Copy-and-patch** | Noted alternative | An ultra-low-warmup compilation technique (stencils patched at runtime) worth measuring if even Cranelift's baseline warmup proves too high for the one-shot CLI workload. Flagged as research-grade, not committed. |

### 4.5 Tier interaction with the heap (P3 ⇄ P4)

The tier model and the GC model are not independent. In **Tier A** (one-shot CLI
eval) the bump-arena never frees, so tier0/tier1/tier2 can hold raw interior
pointers freely — there is no collector to invalidate them. In **Tier B**
(daemon) a precise generational copying collector *moves* objects, so JIT code
must cooperate with read/write barriers and precise stack maps, which the
optimizing tier must emit. This coupling — concurrent/moving GC interacting with
JIT-emitted barriers and with the thunk-mutation protocol of §3.2 — is the
hardest cross-cutting interaction in the whole design and is called out as such
in [parallel evaluation](13-parallel-evaluation.md) and [memory management and GC](06-memory-management-and-gc.md). The mitigation that keeps the two tiers coherent is, again, the
**alloc-via-runtime-symbol discipline**: JIT code calls `aos_alloc_*` and never
inlines allocation, so swapping the arena for the collector changes the symbol
implementation, not the emitted code.

---

## 5. The acceptance gate as an architectural force

The architecture above is not free to optimize however it likes. It is clamped
by a single gate, restated from [compatibility constraints](02-compatibility-constraints.md) because it constrains *every* layer:

> The **differential `.drv`-diff harness** — running aos-nix against
> `nix-instantiate` across the entire AOS package set and diffing the resulting
> `.drv` files and store paths — is the acceptance gate. aos-nix is
> **default-OFF** (`AOS_NIX_NATIVE` unset) until that harness is byte-green on
> the full closure, and `NixCli` remains a *permanent* subprocess fallback.

This gate shapes the architecture in three concrete ways:

1. **It forces the tier0 oracle to exist before any JIT work.** The build order
   (see [roadmap and risks](17-roadmap-and-risks.md)) mandates parser + scope +
   tree-walk oracle + harness *first*, because only the oracle proves parity is
   achievable on AOS constructs and yields the baseline eval-time number that
   the measure-first characterization demands. JIT speed is meaningless if parity is not
   first demonstrated.
2. **It makes L1 (the store backend) a firewall, not an optimization target.**
   We do *not* get to be clever about ATerm serialization, attr ordering, string
   contexts, or output-path hashing. We use the `nix-compat` crate (from the
   Snix project, pinned to a git rev) precisely so we inherit a faithful,
   already-tested implementation of these formats rather than re-deriving them.
3. **It bounds speculation in L6.** Every deopt path must land in semantics
   identical to the oracle's, because a speculation that subtly changes
   evaluation order or string-context propagation could change a `.drv` and blow
   the gate. The uncommon-trap fallback is therefore not merely a performance
   feature; it is a *correctness* guarantee that the fast path can never observe
   a different result than the oracle.

The conformance suite (reusing the C++ Nix language test suite, as Snix does)
and `NIX_SHOW_STATS`-driven, Windtunnel-style per-commit benchmarking sit
alongside the `.drv`-diff harness. See [differential testing and benchmarking](15-differential-testing-and-benchmarking.md).

---

## 6. Tier model of *adoption*: the ranked build sequence

Distinct from the *execution* tiers, the architecture is delivered in a ranked
order chosen so that the biggest real-world wins land first and each phase is
independently valuable even if later phases slip. This previews [roadmap and risks](17-roadmap-and-risks.md); it is included here because the *ordering* is itself an
architectural decision (it determines which layers must be solid before others
are even attempted).

```text
  RANK  DELIVERABLE                                  PRIMARY PROBLEM   INDEP. VALUE
  ────  ─────────────────────────────────────────   ───────────────   ───────────
   0    parser + scope + tree-walk oracle + harness  (foundation)      baseline #, parity proof
   1    incremental early-cutoff cache + hash-cons   P0                may solve build-time alone
   2    bump-arena heap + precise generational GC    P3                kills Boehm tax
   3    strictness + escape analysis                 P1                deletes allocations; helps tier0 too
   4    hidden classes + PIC, then Cranelift tiering P2, P4            constant-factor on the residue
   5    pointer tagging, full-laziness, region inf., P1/P3/P4 +       advanced stack;
        concurrent moving GC                         profiles          build variants
```

The ordering encodes a thesis: **rank 1 (the P0 cache) is expected to be the
single largest real-world win and is largely independent of interpreter speed —
it may solve the build-time bottleneck on its own.** Ranks 2–3 attack the cost
of the work the cache cannot avoid and *also help the tree-walk oracle*, so they
pay off before any JIT exists. Only at rank 4 do we build the Cranelift tiers,
because by then the foundation, the cache, the heap, and the analyses are proven
and we are optimizing a well-understood residue rather than a moving target.

This is the practical face of the synthesis thesis: we are building the full
technique stack through a ranked sequence where each step is measurable,
individually shippable behind the `AOS_NIX_NATIVE` gate, and backed at all times
by the tier0 oracle and the permanent `NixCli` fallback.

---

## 7. Open questions and uncertainties

Per RFC discipline, the following are explicitly *not settled* and are flagged as
research-grade or measurement-dependent:

- **Q1 (warmup vs. one-shot).** The dominant AOS workload is one-shot CLI eval,
  which is the *worst* case for any JIT (no time to amortize warmup). It is an
  open question whether tier1/tier2 ever pay for themselves in CLI mode, or
  whether the win there comes entirely from P0 (cache) + P3 (arena) + tier0
  improvements, with the JIT reserved for daemon mode. **Copy-and-patch**
  (§4.4) is the hedge. Resolution is *measurement-gated*, not assumable.
- **Q2 (NaN-boxing payback).** Nix ints are `i64` and do not fit a NaN-box
  payload, forcing a boxed-int fallback. The first cut is a 16-byte tagged
  value; whether NaN-boxing's register-passing win survives the boxed-int tax is
  an open measured optimization, not a foregone conclusion. See [value representation](05-value-representation.md).
- **Q3 (concurrent moving GC × thunk mutation).** The interaction of a
  concurrent/moving collector (ZGC/Shenandoah-style colored pointers + load
  barriers) with the monotonic thunk-update protocol and JIT-emitted barriers is
  the deepest unsolved coupling. Daemon-mode only; CLI mode sidesteps it via the
  never-free arena. See [parallel evaluation](13-parallel-evaluation.md).
- **Q4 (nix-compat API stability).** We depend on `nix-compat` from the actively
  evolving Snix project, pinned to a git rev. Its CLI and crate APIs are
  explicitly unstable; we expect to contribute fixes upstream and to carry local
  patches. See [derivation and store compatibility](11-derivation-and-store-compatibility.md).
- **Q5 (long tail of `.drv` divergence).** Bug-for-bug parity has a long tail
  (obscure string-context propagation, floating-point formatting, attr-ordering
  edge cases). The architecture mitigates with the oracle + harness + permanent
  fallback, but the *size* of that tail is unknown until the harness runs the
  full closure. This is the top entry in the risk register.

---

## References

External claims in this document were verified against the following sources.

- Cranelift JIT and `JITBuilder::symbol` (runtime-symbol resolution; ~10x faster
  compilation than LLVM; born in Wasmtime):
  - <https://docs.rs/cranelift-jit/latest/cranelift_jit/struct.JITBuilder.html>
  - <https://github.com/bytecodealliance/wasmtime/blob/main/cranelift/README.md>
  - <https://cranelift.dev/>
  - <https://github.com/bytecodealliance/cranelift-jit-demo>
- GHC demand/strictness analysis, usage/cardinality analysis, worker-wrapper
  transform:
  - <https://downloads.haskell.org/ghc/9.12.1/docs/users_guide/using-optimisation.html>
  - <https://www.microsoft.com/en-us/research/wp-content/uploads/2017/03/demand-jfp-draft.pdf>
  - <https://fixpt.de/blog/2018-12-30-strictness-analysis-part-2.html>
- HotSpot tiered compilation, deoptimization (uncommon traps), on-stack
  replacement:
  - <https://devblogs.microsoft.com/java/how-tiered-compilation-works-in-openjdk/>
  - <https://eme64.github.io/blog/2024/12/24/Intro-to-C2-Part01.html>
- V8 hidden classes / shapes and inline-cache states
  (uninitialized/monomorphic/polymorphic/megamorphic), transition trees:
  - <https://medium.com/faster-javascript/hidden-classes-in-javascript-and-inline-caching-6bc2a318c4b4>
  - <https://braineanear.medium.com/the-v8-engine-series-iii-inline-caching-unlocking-javascript-performance-51cf09a64cc3>
- Salsa / Adapton incremental computation, demand-driven evaluation, early
  cutoff (and its use in rust-analyzer):
  - <https://github.com/salsa-rs/salsa>
  - <https://salsa-rs.github.io/salsa/overview.html>
  - <https://rust-analyzer.github.io/blog/2023/07/24/durable-incrementality.html>
  - <https://docs.rs/adapton>
- Snix (Tvix fork/rename, 2025), `snix-eval` bytecode VM, `nix-compat`:
  - <https://snix.dev/docs/components/overview/>
  - <https://oceansprint.org/reports/2025/>
  - <https://devenv.sh/blog/2024/10/22/devenv-is-switching-its-nix-implementation-to-tvix/>
