# RFC-0007 - Laziness and Whole-Program Analyses

> This is one topic document in the RFC-0007 set on `aos-nix`, the Rust Nix
> evaluator for ANDYL OS. It assumes the layered stack from
> [architecture overview](03-architecture-overview.md), the value model from
> [value representation](05-value-representation.md), and the heap model from
> [memory management and GC](06-memory-management-and-gc.md). It feeds the
> execution machinery in [execution tiers and Cranelift](08-execution-tiers-and-cranelift.md)
> and the attrset machinery in
> [attribute sets, hidden classes, and inline caches](09-attribute-sets-hidden-classes-and-inline-caches.md).

## 1. Why this document exists

Nix is a *lazy* language. Every binding, every list element, every attribute
value is, semantically, a suspended computation that is evaluated at most once
and only when demanded. C++ Nix implements this the textbook way: a `Value` is a
tagged union that may hold a `tThunk` (an expression pointer plus an environment
pointer), and forcing it walks the expression tree in a tree-walking
interpreter, mutating the thunk in place to its result. This is correct, simple,
and — for the AOS package set — *expensive*. The profile of a cold
`nix-instantiate` of the AOS closure is dominated by three costs that all trace
back to laziness implemented naively:

1. **Thunk allocation.** A thunk is a heap object. The vast majority of thunks
   in a real evaluation are forced exactly once, immediately, and never shared —
   the allocation, the GC tracing of it, and the in-place update are pure
   overhead. C++ Nix allocates these through the Boehm conservative collector,
   which [memory management and GC](06-memory-management-and-gc.md) identifies as
   the dominant single cost in C++ Nix evaluation.

2. **Forcing dispatch.** Each force is a state check followed, in the
   `Suspended` case, by an interpreter re-entry. In a tree-walker this is an
   indirect dispatch per AST node, repeated for every activation.

3. **Re-forcing the obviously-strict.** A binding like
   `name = "${pname}-${version}"` inside a `stdenv.mkDerivation` call is *always*
   demanded, immediately, by `derivationStrict`. Building a thunk for it, then
   forcing that thunk one nanosecond later, is wasted work that a smarter
   compiler would never have emitted.

This document specifies the analyses `aos-nix` uses to make laziness *nearly
free*: to emit eager, allocation-free, register-resident code wherever the
program's own structure proves it is safe to do so, while preserving exact Nix
semantics (and therefore byte-identical `.drv` output) everywhere it is not.

The thesis of the wider RFC ([architecture overview](03-architecture-overview.md))
is that a fast Nix evaluator is a fast implementation of a *lazy,
dynamically-typed, garbage-collected functional language* plus a
recomputation/caching layer. The single richest body of prior art for the
"lazy functional language" half is **GHC** — the Glasgow Haskell Compiler has
spent three decades making laziness cheap through *static analysis*. The central
argument of this document is that **the analyses GHC must approximate, `aos-nix`
can often compute exactly**, because Nix is purer, smaller, and evaluated as a
closed whole-program batch rather than as separately-compiled modules. Neither
C++ Nix nor Tvix/Snix performs any of these analyses today; this is the largest
*pure-evaluator* speedup available to us (the largest speedup overall is the
incremental cache of [incremental evaluation cache](12-incremental-evaluation-cache.md),
which is orthogonal and stacks on top).

## 2. The execution model these analyses target

Before describing the analyses, fix the runtime objects they manipulate. The
full model lives in [value representation](05-value-representation.md) and
[execution tiers and Cranelift](08-execution-tiers-and-cranelift.md); the
relevant invariants here are:

- **Compilation is per-expression, not per-activation.** We compile each syntactic
  expression once (bounded: tens of thousands of expressions across the AOS
  package set), never once per thunk activation (which would be billions). The
  output of an analysis is therefore *attached to an expression node* and amortized
  across all its dynamic instances.

- **A thunk is `(code_ptr, captured_env, state)`.** `state` is one of
  `Suspended`, `Blackhole`, `Forced(value)`. Forcing checks `state`; if
  `Suspended`, it calls `code_ptr(runtime, captured_env)`, transitioning through
  `Blackhole` (so a self-referential force is detected as infinite recursion)
  and ending at `Forced(value)`, which caches the result.

- **A lambda is `(code_ptr, captured_env)`.**

- **Values are tagged (16-byte first cut, NaN-boxed later) and immutable.**
  Immutability is the property every analysis below leans on: a value, once
  `Forced`, never changes, so any fact we prove about it stays true.

The analyses produce, per expression, a small set of *facts* — strictness,
cardinality, escape — that the lowering stage (tree-walk tier and Cranelift
tiers alike) consults to choose between three lowering strategies for any
sub-expression `e` in a binding position:

```text
strategy          when chosen                         cost
---------------   ---------------------------------   --------------------------------
THUNK   (lazy)    e may not be demanded, or is        alloc thunk; force on demand
                  shared and expensive
EAGER   (strict)  e is provably always demanded       evaluate inline, no thunk, no
                                                       force machinery
SCALAR  (inline)  e is eager AND its result does not   keep fields in registers/stack;
                  escape its allocating frame          no heap object at all
```

The rest of this document is, essentially, the specification of *which analysis
licenses which strategy*, and *why Nix lets us go further than the systems we
borrow from*.

## 3. Thunks: the baseline, and the four things wrong with it

### 3.1 The naive thunk

The correctness oracle (tier 0, the tree-walking interpreter) implements thunks
exactly as C++ Nix does, because being a faithful oracle is its entire job. A
binding `x = e` in environment `ρ` becomes a heap thunk capturing `(⟦e⟧, ρ)`.
Demanding `x` runs `force`:

```rust
/// Forces `thunk` to weak head normal form (WHNF), memoizing the result.
///
/// # Panics
///
/// Does not panic; infinite recursion is reported as a Nix evaluation error
/// when a `Blackhole` thunk is re-entered.
fn force(rt: &Runtime, thunk: &Thunk) -> Value {
    match thunk.state.load() {
        State::Forced(v) => v,                 // fast path: already WHNF
        State::Blackhole => rt.infinite_recursion_error(thunk),
        State::Suspended => {
            thunk.state.store(State::Blackhole);
            let v = (thunk.code)(rt, thunk.env); // re-enter compiled/interpreted body
            thunk.state.store(State::Forced(v));
            v
        }
    }
}
```

This is the semantics every other tier must match bit-for-bit. The optimizations
below never change *what* `force` would compute; they change whether a thunk is
ever built in the first place, and whether the `force` call site can be proven
to hit the fast path (or be deleted).

### 3.2 The four costs, named

| Cost | Description | The analysis that removes it |
|------|-------------|------------------------------|
| **Allocation** | every thunk is a heap object the GC must trace | strictness (eager lowering) + escape analysis (scalar replacement) |
| **Blackhole/update bookkeeping** | the `Blackhole` write and the `Forced` write exist only to support *sharing* and *cycle detection* | cardinality (single-entry / call-by-name thunks) |
| **Force dispatch** | each demand is a state test + possible indirect call | pointer tagging (§7, and [value representation](05-value-representation.md)) — turns "already WHNF?" into a tag bit test |
| **Re-forcing the strict** | building then immediately forcing | strictness + worker-wrapper (§4) |

### 3.3 Why pointer tagging matters here, briefly

[value representation](05-value-representation.md) owns the value layout, but one
point belongs in the laziness story because it changes the *force fast path*.
GHC's runtime, on top of its **spineless tagless G-machine**, uses *dynamic
pointer tagging* (Marlow, Yakushev & Peyton Jones, ICFP '07): the spare low bits
of a heap pointer record whether the pointed-to closure is *already evaluated*
and, for a constructor, *which* constructor. The payoff: forcing an
already-evaluated value is a **tag-bit test on a register**, not a memory load of
`state` followed by a branch, and certainly not an indirect call. In `aos-nix`,
the dominant dynamic case — "this thunk was already forced; give me the value" —
becomes a single masked compare. We tag WHNF-ness and small-constructor identity
into the value's spare bits in the same spirit. This is a constant
factor, but it multiplies every force in the program, and it is the difference
between laziness costing a predicted, correctly-speculated branch and costing a
cache miss.

## 4. Strictness / demand analysis and the worker-wrapper transform

### 4.1 What strictness analysis proves

**Strictness analysis** answers, for a binding or a function parameter: *is this
guaranteed to be evaluated whenever the surrounding expression is evaluated?* If
`f` is strict in its argument `x` — i.e. `f ⊥ = ⊥`, forcing `f`'s result forces
`x` — then passing `x` as a thunk is pointless: we can evaluate it before the
call and pass the WHNF value directly. GHC has exploited strictness this way
since its early releases; its modern incarnation is the **Demand Analyser**,
which computes, on the Core
IR, both strictness ("evaluated at least once") and the usage/cardinality
information of §5 ("evaluated at most once / not at all") in a single
backward fixpoint pass. The canonical reference is Sergey, Vytiniotis, Peyton
Jones et al., *Theory and Practice of Demand Analysis in Haskell* (JFP draft,
Microsoft Research), which is the design we are tracking.

In Nix, the demand structure is dominated by a handful of *provably strict
contexts*, and crucially these are the hot ones:

- **Arithmetic and comparison primops** (`+`, `-`, `<`, `==` on numbers) are
  strict in both operands.
- **`if c then t else e`** is strict in `c`.
- **`builtins.derivationStrict`** — the name is not a coincidence — forces every
  attribute of the derivation argument, in deterministic order. *Every binding
  that flows into a derivation attrset is strict.* In the AOS package set, that
  is the overwhelming majority of all bindings that matter for `.drv`
  production.
- **`foldl'`, `genList`'s generator at each index, `length`, `string`
  interpolation `"${e}"`** (strict in `e`, which must reduce to a stringable
  value), `builtins.concatStringsSep`, attribute-path selection.
- **`with`/`inherit` bodies and `let` bodies** propagate demand to the bindings
  the body actually forces.

The analysis is a standard backward demand-propagation fixpoint over the
[IR](04-frontend-parser-and-ir.md): start from the strict primops and
`derivationStrict` as demand sources, propagate demand transducers through each
syntactic form, iterate to a fixed point over the (finite, whole-program) call
graph. Because we have the *entire* expression closure in memory after parsing
(§8), this is a closed-world analysis with no separate-compilation
approximation — see §8 for why that is the decisive advantage over GHC.

### 4.2 The worker-wrapper transform

Strictness information is *exploited* by the **worker/wrapper transformation**
(GHC's `-fworker-wrapper`). Conceptually, a function `f` is split into:

- a **worker** `$wf` that takes its strict arguments **already evaluated and
  unboxed**, with absent (provably-unused) arguments dropped entirely; and
- a thin **wrapper** `f` that has the original lazy calling convention, forces
  the strict arguments, and tail-calls the worker. The wrapper is marked
  always-inline, so at every call site it disappears and the caller calls the
  worker directly with values it already has in registers.

GHC's own documentation describes the transform precisely: it "exploits
strictness and absence information by unboxing strict arguments and replacing
absent fields by dummy values in a wrapper function that will inline in all
relevant scenarios and thus expose a specialised, unboxed calling convention of
the worker function." Recent GHC additionally threads a *Boxity Analysis* to
decide when a parameter genuinely needs to stay boxed.

In `aos-nix` terms, applied to Nix's most important shape — a function returning
an attrset that is immediately consumed strictly:

```text
Source (Nix):
    mkDerivation = { pname, version, ... }@args:
      derivationStrict (args // {
        name = "${pname}-${version}";
        builder = ...;
      });

Analysis: derivationStrict forces every attr. Therefore `name` is strict,
therefore `pname` and `version` are strict (string interpolation is strict in
its parts), therefore the corresponding bindings need no thunk.

Lowered (worker-wrapper, schematic):
    $w_mkDerivation(pname_val: Value /*WHNF*/, version_val: Value /*WHNF*/, ...):
        let name_val = string_concat(pname_val, "-", version_val);  // eager, no thunk
        ... build derivation attrset in registers ...
    mkDerivation(args):                         // wrapper, always inlined
        let pname_val   = force(select(args, pname));
        let version_val = force(select(args, version));
        $w_mkDerivation(pname_val, version_val, ...)
```

The wrapper's `force` calls are emitted at the *call site* after inlining, where
the caller frequently already holds the WHNF values (because *it* was lowered
eagerly), so the forces collapse to no-ops the tag-test fast path resolves
statically. The net effect for the strict core of a derivation is: **zero thunks
allocated, zero force machinery, straight-line code that builds the derivation
attrset directly.**

### 4.3 Soundness: where Nix lets us be more aggressive, and where it does not

The one place strictness analysis can change observable behavior is *evaluating
something that the lazy program would never have evaluated* — turning a
non-terminating or error-raising thunk into an actual divergence/error. GHC is
careful here: it only forces eagerly where it has *proven* the value is demanded,
because Haskell's `⊥` (bottom: non-termination or `error`) is observable. **Nix
has the same hazard** — `throw`, `abort`, `assert false`, and infinite recursion
are all observable, and a derivation that diverges lazily but is never demanded
must *stay* undemanded. We therefore adopt GHC's discipline exactly: **eager
lowering is licensed only by a positive proof of strictness**, never by
heuristic. An unproven binding stays a thunk. This is what keeps `.drv` output
byte-identical: we never force an expression C++ Nix would have left unforced,
and we never *fail* to force one C++ Nix would have forced. Strictness analysis
is a *performance* transform that is observationally invisible by construction.

The compatibility gate of [compatibility constraints](02-compatibility-constraints.md)
makes this non-negotiable: the differential harness diffs `.drv` bytes against
`nix-instantiate` across the whole AOS closure. A strictness bug that forced a
should-be-lazy `throw` would surface as an evaluation error where C++ Nix
produced a derivation — a hard, immediate test failure, not a silent divergence.
That is the desired failure mode: loud and caught.

## 5. Cardinality / usage analysis (0 / 1 / many)

Strictness asks "*at least once?*". **Usage (cardinality) analysis** asks "*at
most once?*" and "*not at all?*". GHC computes both together in its demand
analyser; the usage component answers, per the GHC documentation, "how many
times a binding is accessed during a single evaluation" and "how many times the
body of a lambda is called relative to its enclosing expression." The three
buckets and what each licenses:

| Cardinality | Meaning | Optimization licensed |
|-------------|---------|-----------------------|
| **0 (absent)** | binding/argument is never demanded on any path | **dead-binding elimination**: emit no code, drop the argument (worker takes a dummy / nothing) |
| **1 (used-once)** | demanded at most once per evaluation | **single-entry thunk**: no `Blackhole` write, no `Forced` update, no memoization slot — or downgrade to **call-by-name** (re-evaluate freely; it's pure) |
| **many** | may be demanded more than once | full memoizing **update-thunk** (the §3 baseline) |

### 5.1 Single-entry thunks: deleting the update machinery

The `Blackhole`→`Forced` update protocol in §3.1 exists for exactly two reasons:
(1) **sharing** — so a value demanded twice is computed once; and (2) **cycle
detection** — so `x = x` is a detected infinite recursion rather than a hang. If
cardinality proves a thunk is entered **at most once**, reason (1) evaporates:
there is no second demand to share with. GHC exploits this directly — its usage
analysis lets it, in its own words, "use call-by-name instead of call-by-need,
effectively turning thunks into non-memoised functions" for used-at-most-once
bindings. A single-entry thunk needs no update slot and no `Forced` write-back;
in the call-by-name downgrade it needs no heap cell at all, because re-evaluation
is free in a pure language.

The Nix-specific multiplier: an enormous fraction of Nix thunks are
*intermediate* — the `name` string, the `args // { ... }` overlay, the
per-element thunk inside a `map f xs` — and are demanded exactly once by the very
next strict operation. These are textbook used-once bindings. C++ Nix pays the
full update-thunk price for every one of them; `aos-nix` pays nothing beyond the
computation itself.

### 5.2 Absence: dead-binding elimination

Cardinality-0 bindings are simply deleted. In Nix this is common where a large
`let` or a `rec { ... }` attrset defines helpers, only some of which a given
consumer path forces. Absence analysis lets the worker (§4.2) take a dummy in the
absent slot and the binding's code never be emitted. GHC's worker-wrapper does
precisely this — "replacing absent fields by dummy values." The subtlety, again,
is `⊥`: a binding whose *only* effect is to diverge must not be deleted if some
path forces it; absence is a "never demanded on *any* path" property, so deleting
it is observationally sound. We compute it as the dual of the demand fixpoint.

### 5.3 Soundness note specific to cardinality

The dangerous direction is *under*-counting cardinality — treating a
demanded-twice thunk as used-once would compute a side-effecting-looking value
twice. But Nix is pure: recomputation is observationally identical to reuse
(modulo `throw`/`abort`, which are *deterministic* — they throw the same thing
every time). So even a *wrong* "used-once" classification cannot change the
result value; it can only change performance (recomputing something we could
have shared). This makes the call-by-name downgrade strictly safe in a way it is
*not* in an impure language. We still compute cardinality precisely to avoid the
performance pathology of recomputing an expensive shared thunk, but the
correctness floor is purity. This is a recurring theme: **purity converts
analyses that are merely-an-optimization-if-correct into
correct-even-if-imprecise.**

## 6. Full laziness / let-floating

### 6.1 The transform

**Full laziness** (a.k.a. **let-floating outward**) hoists a let-binding *out of
an enclosing lambda* when the binding does not depend on the lambda's parameter,
so that the bound expression is computed **once**, when the lambda is created,
rather than **once per call**. GHC implements this from the classic Peyton Jones,
Partain & Santos paper *Let-floating: moving bindings to give faster programs*
(ICFP '96). GHC's user guide describes the pass as floating "let-bindings outside
enclosing lambdas, in the hope they will thereby be computed less often," and
also documents the complementary **float-inward** direction, which sinks a
binding toward its use so a branch that never runs never allocates it.

The canonical Nix shape this attacks:

```text
Source (Nix):
    map (x: let prefix = "${pkgs.hello}/bin/"; in "${prefix}${x}") names

Inside the lambda, `prefix` does not mention `x`. Naively, every call to the
mapped lambda rebuilds the `prefix` thunk and re-forces it.

After let-floating outward:
    let prefix = "${pkgs.hello}/bin/";          # computed once
    in map (x: "${prefix}${x}") names           # lambda body just concatenates
```

A `prefix` that interpolates a store path (forcing a whole sub-derivation) being
recomputed for every element of `names` is the difference between O(1) and O(n)
traversals of the derivation graph (the `.drv` output DAG).
`genList (i: let table = expensiveConstant; in ...)`
is the same story.

### 6.2 The float-inward direction

Float-inward sinks a binding to the smallest scope dominating its uses. In Nix
this matters for `if`/`else` and for attrset fields gated behind conditions: a
binding only used in the `then` branch should not be built when the `else` branch
is taken. GHC notes float-inward "may avoid unnecessary allocation if the branch
the let is now on is never executed," and that it exposes more local information
to later passes. We run both directions, float-inward before the strictness
fixpoint (to tighten demand scopes) and float-outward after (to hoist proven
loop-invariants).

### 6.3 The residency caveat — and why it is smaller for us

Full laziness is not free lunch. GHC's documentation is explicit that it
"increases sharing, which can lead to increased memory residency": a value
hoisted out of a lambda and shared across all calls *stays alive* as long as the
lambda does, even if any single call would have let it die immediately. For a
long-running Haskell program this can be a space leak, and the residency hazard
is one reason GHC does not float every eligible binding outward.

For `aos-nix` the calculus is different in two ways that both favor floating more
aggressively:

1. **Tier A is a one-shot batch.** As [memory management and GC](06-memory-management-and-gc.md)
   specifies, the CLI evaluation path uses a bump-arena that is **never freed**
   until process exit. Residency of a hoisted constant is irrelevant when the
   whole heap is dropped at the end anyway; the classic space-leak hazard of
   full laziness simply does not apply to a `nix-instantiate`-shaped job. We can
   float without the residency anxiety GHC must carry.

2. **Hash-consing absorbs duplicate hoists.** Even where floating creates a
   shared binding, the [value representation](05-value-representation.md)
   hash-consing layer means structurally-equal hoisted values were going to be
   interned to one allocation regardless. Floating and maximal sharing reinforce
   each other.

In daemon mode (tier B, generational GC) the residency caveat returns, and we
apply GHC's mitigation: bound the *size/cost* of what we float (don't hoist a
binding that builds an unbounded data structure out of a short-lived loop). This
is an open tuning question (§10) rather than a correctness one — floating never
changes results in a pure language; it only trades time for space.

## 7. Escape analysis and scalar replacement

### 7.1 The transform, from HotSpot

Strictness + cardinality delete *unnecessary* thunks. **Escape analysis** attacks
the thunks and attrsets that genuinely *are* built and used, but whose lifetime
is provably confined to the frame that built them. If an object **does not
escape** — no reference to it outlives the activation that created it, and no
reference reaches another thread or the heap-resident result — then it need not
be heap-allocated at all.

HotSpot's C2 compiler is the reference implementation, and a precise one: as
Shipilëv's *JVM Anatomy Quark #18* documents, HotSpot does **not** do true stack
allocation; it does **Scalar Replacement of Aggregates (SRA)**. SRA *decomposes
the object entirely*, replacing each field access with a synthetic local
variable; those locals are then handled by the register allocator, which spills
to stack slots only under register pressure. The object "never exists as a
coherent data structure on the stack or the heap — it effectively ceases to exist
as an object at the machine code level." That is exactly the model `aos-nix`
adopts: a non-escaping attrset becomes a bag of SSA values in Cranelift, never a
heap attrset.

```text
Source (Nix):
    let pair = { a = f x; b = g x; }; in pair.a + pair.b

`pair` never escapes the let. Escape analysis proves no reference to it leaves
this expression.

After scalar replacement (schematic CLIF-level):
    v_a = call f(x)        ; was pair.a, now an SSA value
    v_b = call g(x)        ; was pair.b
    v_r = iadd v_a, v_b    ; pair.a + pair.b, no attrset ever allocated
```

The attrset, its hidden-class pointer, its key array, its value array — none of
it is built. `.a` and `.b` become reads of `v_a`/`v_b`, resolved at compile time
(no shape check, no inline cache, no `select` runtime call; cf.
[attribute sets, hidden classes, and inline caches](09-attribute-sets-hidden-classes-and-inline-caches.md)).

### 7.2 Why this is *more* effective in Nix than in Java

HotSpot's escape analysis is famously conservative and fragile in practice — the
*Object Allocation Tax* literature notes that EA "both helps and misleads," and
that one heap-storing call or one virtual call that the JIT cannot devirtualize
poisons it. The reasons EA is hard in Java are precisely the reasons it is
*easy* in Nix:

| Java hazard | Why it breaks EA | Why Nix is immune |
|-------------|------------------|-------------------|
| **Mutation / identity** | an object's identity (`==`, synchronization, identity hash) can leak; a field can be reassigned to point elsewhere | Nix values are **immutable**; there is no identity beyond structural equality, no reassignment, no synchronization |
| **Virtual dispatch** | a method call may stash `this` somewhere unknown | Nix has no methods; primop targets are statically known builtins |
| **Reflection / JNI / finalizers** | opaque escape routes the analysis must assume the worst about | Nix has none of these |
| **Separate compilation** | callee bodies may be unavailable | the whole program is in memory (§8) |
| **Exceptions carrying references** | a thrown object escapes | `throw`/`abort` carry a *string*, not a reference to the analyzed aggregate |

Immutability is the decisive one. In Java, "this object does not escape" must
also rule out *aliasing through mutation*; in Nix, an immutable value has no
hidden channels — if no syntactic reference to it survives the frame, it cannot
be observed outside the frame, full stop. This makes Nix escape analysis closer
to a *syntactic reachability* check than to the heavyweight points-to analysis
HotSpot needs. We get HotSpot's payoff with far less of HotSpot's fragility.

### 7.3 What "escape" means precisely, and the interaction with hash-consing

An aggregate **escapes** the frame `F` that allocates it if any of:

- it is returned from `F` (becomes part of `F`'s WHNF result), or
- it is stored into another heap object that escapes (e.g. captured into a thunk
  or lambda environment that outlives `F`), or
- it is passed to a primop/function that is not transparent to escape (we
  maintain a table of escape signatures for the ~120 builtins of
  [primops and runtime ABI](10-primops-and-runtime-abi.md): `length`, `+`,
  comparison, `attrNames` of a then-discarded set, etc. do **not** cause escape;
  `derivationStrict`, list/attrset *construction that flows to the result* do).

There is a deliberate interaction with [value representation](05-value-representation.md)'s
hash-consing: a value we are about to **intern** has, by definition, escaped into
the global intern table and the incremental cache. So scalar replacement applies
to the *transient* aggregates *between* interned values, and interning is the
boundary at which an aggregate is forced to materialize. Concretely: the `pair`
in §7.1 is scalar-replaced and never interned; the final derivation attrset
*does* materialize and *is* interned, because it escapes into the `.drv` and the
cache. The analysis must therefore treat "flows into a to-be-interned result" as
an escape, which it does via the "returned from `F`" clause.

### 7.4 Supporting transforms: unboxed multi-returns and join points

Two GHC/HotSpot supporting transforms make scalar replacement pay off:

- **Unboxed multi-return / unboxed tuples.** When a worker (§4.2) produces
  several scalar values that the caller immediately consumes (the decomposed
  fields of a scalar-replaced aggregate), we return them in multiple registers
  rather than boxing them into a tuple object. Cranelift's calling-convention
  support for multiple return values (and out-params for the overflow) is the
  mechanism; see [execution tiers and Cranelift](08-execution-tiers-and-cranelift.md).

- **Join points.** A *join point* is GHC's name for a code block that several
  control-flow paths jump to (e.g. the continuation after an `if`), compiled as a
  local label/jump rather than a heap-allocated continuation closure. They let
  scalar-replaced values survive across `if`/`else` and `let` without being boxed
  to cross the merge. In CLIF these are simply block parameters on the merge
  block — Cranelift's SSA block arguments *are* join points.

## 7.5 The IR-to-IR simplifier pipeline: iterating to a fixpoint (GHC Core-to-Core)

The analyses of §§4–7 are not run once, in isolation. They are **passes in one
IR-to-IR optimizer that runs them iteratively to a fixpoint**, exactly as GHC's
Core-to-Core pipeline runs its *simplifier* interleaved with demand analysis,
float-out, specialization, and CSE across several phases. This is **pre-JIT IR
simplification** (the simplifier, GHC Core-to-Core — not graph reduction, which in
this RFC names only the lazy *evaluation* technique of §3): it is pure IR-to-IR
transformation, *independent of the execution tier*, so it improves the IR the
tier-0 tree-walk oracle interprets **and** the IR Cranelift later compiles
([execution tiers](08-execution-tiers-and-cranelift.md)) — it pays off before a
single line of JIT exists. In the unified-demand-graph framing
([architecture overview](03-architecture-overview.md) §3.4) the optimizer is just a
pure (effect-class) **compile-node**, a graph node memoized by input-IR hash, so
optimization results are cached across runs like everything else.

### 7.5.1 The simplifier (the workhorse), iterated to a fixpoint

Beyond the demand/cardinality/float/escape passes already described, the simplifier
performs the *pure local reductions* that each expose further reductions — which is
why it must iterate:

- **Inlining + beta-reduction.** Inline small or used-once lambdas and `let`
  bindings. Nix is higher-order and saturated with tiny `lib` functions; inlining
  them removes call overhead *and* exposes constant folding, case-of-known, and
  strictness at the call site. GHC-style heuristics (size threshold; used-once
  always-inline from the cardinality analysis of §5).
- **Constant folding.** Evaluate total, constant subexpressions at compile time:
  `1 + 2 → 3`, `"a" + "b" → "ab"`, `builtins.length [ 1 2 3 ] → 3`.
- **Case-of-known / select-of-known.** `{ a = 1; }.a → 1`; `if true then x else y →
  x`; attribute selection on a statically-known attrset literal folds to the field.
  (This is GHC's case-of-known-constructor, specialized to Nix attrsets and `if`.)
- **Dead-binding elimination** (from §5.2 absence analysis), **common-subexpression
  elimination**, and **eta-reduction/expansion**. CSE is *safe and desirable* here
  precisely because values are immutable and we already maximally share via
  hash-consing ([05](05-value-representation.md)) — GHC must be cautious about CSE
  changing sharing/laziness; we are not.
- **let-floating in and out** (§6) — floated as part of the same loop, not a
  separate phase, so a hoist exposes an inline and vice-versa.

These interleave with the analyses because each enables the others: inlining
exposes strictness (§4); strictness enables worker/wrapper and unboxing; floating
exposes constant folding; specialization (a `map f` with statically-known `f`)
exposes more inlining. We run the simplifier in phases — gentle early passes, more
aggressive later — to a fixpoint or a capped iteration count, exactly GHC's
strategy.

### 7.5.2 Rewrite rules: list fusion is the high-value Nix-specific one

The pipeline supports **algebraic rewrite RULES** — semantics-preserving rewrites
applied during simplification. The standout for Nix is **list fusion**, because
`lib` chains `map`/`filter`/`concatMap` constantly, allocating intermediate lists:

```text
   map f (map g xs)        →  map (\x: f (g x)) xs      -- one traversal, no temp list
   length (map f xs)       →  length xs                 -- f never runs
   concatMap f [ x ]       →  f x
   filter p (filter q xs)  →  filter (\x: q x && p x) xs
```

This is the same win GHC gets from foldr/build (and stream) fusion, applied to
Nix's list builtins — eliminating intermediate-list allocation that neither C++ Nix
nor Tvix removes.

### 7.5.3 The soundness rule (the same effect/error discipline as everywhere)

Every reduction must be **observably transparent** with respect to Nix semantics —
the differential gate ([differential testing](15-differential-testing-and-benchmarking.md))
catches any reduction that changes a `.drv` byte. Two sharp edges, both instances
of the effect/error-quarantine rule that governs speculation
([04](04-frontend-parser-and-ir.md) §9.6) and the unified graph
([03](03-architecture-overview.md) §3.4):

- **Never fold a *failing* subexpression eagerly.** `1 / 0`, `throw "x"`, `abort` —
  if the original is lazy and un-demanded, constant-folding it must not fire the
  error at compile time. Folding is restricted to **total** operations; a folded
  error is stashed and re-raised only if the value is genuinely demanded.
- **Strictness must be *proven*, never speculative.** Worker/wrapper may evaluate a
  binding eagerly only where §4 *proves* it is always forced. Making a lazy binding
  strict where it was not observably strict would change termination/error behavior
  and the `.drv` — forbidden (§4.3).

### 7.5.4 Phasing

The *core simplifier* (inline, beta, constant-fold, case-of-known, DCE, CSE, eta)
and its interleaving with the §§4–7 analyses are committed — they are cheap,
tier-independent, and help even the oracle. The *aggressiveness* — inlining size
thresholds, how many fixpoint iterations, which rewrite RULES (especially fusion)
to enable — is **measure-gated**: over-inlining bloats IR and over-eager fusion can
change sharing, so each is tuned against the harness and the
`NIX_SHOW_STATS`-style counters ([15](15-differential-testing-and-benchmarking.md)),
never assumed. See the [decision register](19-decision-register.md).

## 8. The whole-program advantage: why this works better in Nix than anywhere

Every analysis above is, in the general functional-language setting,
*approximate* — GHC must conservatively assume the worst about anything it cannot
see, because Haskell is compiled module-by-module with separate compilation, and
demand/usage/escape facts cannot always cross a module boundary precisely. GHC's
own passes are correspondingly conservative — it does not float every eligible
binding (the residency tradeoff of §6.3), and its analyses back off at module
boundaries. HotSpot's escape analysis is
limited by what the JIT can see at compile time and by devirtualization. These
are not failures of engineering; they are consequences of the *open-world*
setting those compilers operate in.

`aos-nix` operates in a **closed world**:

1. **The whole program is present.** An `aos build` or `nix-instantiate`
   evaluation starts from a root expression and `import`s its way to a *finite,
   fully-known* closure of `.nix` files. After the parse/scope phase
   ([frontend, parser, and IR](04-frontend-parser-and-ir.md)) the entire IR is in
   memory. There is no separate compilation, no FFI, no dynamic code loading, no
   `dlopen`. Every callee body is visible.

2. **There is no mutation and no identity.** Immutability ([value
   representation](05-value-representation.md)) removes the aliasing and
   escape-through-mutation hazards that bound HotSpot's EA, and removes the
   recomputation-changes-results hazard that bounds GHC's strictness aggression.

3. **There are no side effects, no I/O ordering, no threads-with-shared-mutable-state
   in the language.** The only "effects" are `throw`/`abort`/`assert` (pure,
   deterministic, value-carrying) and `import`/`readFile`/`derivationStrict`
   (which we model as pure functions of their content-hashed inputs;
   cf. [incremental evaluation cache](12-incremental-evaluation-cache.md)).

The consequence is a *qualitative* one, not merely quantitative: **analyses that
must be conservative approximations in GHC and HotSpot become exact in
`aos-nix`.** A demand fixpoint over the closed AOS call graph computes *the*
strictness of every binding, not a safe under-approximation. An escape check over
fully-visible callee bodies computes *the* escape set, not a worst-case
over-approximation. We harvest GHC's and HotSpot's *techniques* while escaping
their *fundamental limitations*, because Nix's purity and whole-program batch
nature remove the very things that forced those compilers to approximate.

This is the concrete content of the RFC's *synthesis thesis* ([architecture
overview](03-architecture-overview.md)) for the laziness layer: the techniques
are borrowed; the *totality and soundness* are a gift of the Nix semantics.

### 8.1 Cost and staging of the analyses

These are whole-program fixpoint analyses, which sounds expensive. Two facts keep
them affordable:

- **The program is bounded.** Tens of thousands of expressions, not billions of
  activations. A backward demand fixpoint over the AOS IR is milliseconds-to-low-seconds,
  and it is *itself* cached content-addressed by file hash (§9 /
  [incremental evaluation cache](12-incremental-evaluation-cache.md)) so it runs
  once per package-set version, not once per `aos` invocation.

- **They are optional and layered.** The build order
  ([roadmap and risks](17-roadmap-and-risks.md)) puts the parser + scope +
  tree-walk oracle + differential harness **first**, with *no* analyses — that
  yields the baseline parity proof and the eval-time number. Strictness and
  escape analysis land next (roadmap item 3) because they delete most allocations
  *even in the tree-walk tier*, before any Cranelift work. Each analysis is a
  pure function from IR to per-node facts; the lowering tiers consult facts if
  present and fall back to the conservative THUNK strategy if absent. Missing,
  skipped, failed, or conservative facts therefore degrade to *slower*, never to
  *wrong*. Incorrect positive facts can change behavior, so every fact producer
  remains byte-gated by the `.drv` differential harness.

## 9. Where the analysis facts live, and how they are cached

Each analysis annotates the [arena AST / IR](04-frontend-parser-and-ir.md) with a
compact per-node fact record:

```rust
/// Per-expression analysis facts attached to an IR node.
///
/// All fields default to the conservative choice so an absent or partial
/// analysis is always sound: `Unknown` strictness forces nothing eagerly,
/// `Many` cardinality keeps the full update thunk, `Escapes` keeps the heap
/// allocation. Skipped or failed analysis can only make code slower; incorrect
/// positive facts are semantic changes and must be caught by the differential
/// gate.
#[derive(Clone, Copy)]
struct ExprFacts {
    /// `Strict` licenses EAGER lowering; `Unknown` keeps THUNK.
    strictness: Strictness,   // Strict | Unknown
    /// Drives single-entry vs update thunk, and dead-binding elimination.
    cardinality: Cardinality, // Absent | Once | Many
    /// `NoEscape` licenses SCALAR replacement; `Escapes` keeps the allocation.
    escape: Escape,           // NoEscape | Escapes
}
```

Because the facts are a pure function of the (content-hashed) IR, they are cached
in the same content-addressed store as parse/compile artifacts: the AOS package
set is parsed once, analyzed once, and the facts are reused across every
evaluation and across CI machines via the Attic-backed cache described in
[incremental evaluation cache](12-incremental-evaluation-cache.md). The lowering
tiers ([execution tiers and Cranelift](08-execution-tiers-and-cranelift.md))
read `ExprFacts` to pick THUNK / EAGER / SCALAR per node.

## 10. Open questions and research-grade edges

The analyses in §§4–7 range from "standard, port it" (strictness, worker-wrapper)
to "research-grade for Nix specifically." Marked honestly:

1. **Cardinality precision under higher-order Nix.** Nix is higher-order and
   liberally uses `map`/`foldl'`/library combinators. GHC's call-arity and demand
   analyses interact subtly here (see *Demand Analysis vs. Call Arity*, HIW
   2017); getting precise used-once facts through `builtins.map` and through
   user-defined recursion schemes is the part most likely to start
   over-conservative. **Open:** how much cardinality precision is worth chasing
   before the incremental cache ([incremental evaluation cache](12-incremental-evaluation-cache.md))
   subsumes the win.

2. **Float-outward residency policy in daemon mode (§6.3).** The size/cost bound
   on what to hoist is a tuning parameter with no obviously-correct setting;
   needs measurement against real daemon workloads, which do not yet exist for
   `aos-nix`.

3. **Escape signatures for the builtin surface (§7.3).** Hand-authoring escape
   transparency for ~120 primops is error-prone; a binding that wrongly claims
   escape-transparency could, in principle, scalar-replace an aggregate that
   actually escapes and corrupt a result. **Mitigation:** the differential `.drv`
   gate ([differential testing and benchmarking](15-differential-testing-and-benchmarking.md))
   catches any such corruption as a byte diff; default-off until green
   ([integration with AOS](14-integration-with-aos.md)). Still, this table wants
   property-test fuzzing, not just the closure diff.

4. **Interaction with parallel forcing.** [parallel evaluation](13-parallel-evaluation.md)
   mutates thunks via CAS. Single-entry thunks (§5.1) that skip the `Blackhole`
   write must be re-examined under parallelism: the blackhole is *also* how a
   second thread detects an in-progress force. A used-once thunk that is *actually*
   only entered once is fine; one mis-classified as used-once under a parallel
   schedule that does enter it twice could race. **Decision (closed): the
   blackhole-skipping call-by-name downgrade is restricted to thunks the escape
   analysis proves are *frame-local*** (never published to a shared slot, so no
   second thread can reach them). Any thunk that escapes to a shared slot keeps
   the full `Suspended → Blackhole → Forced` CAS protocol regardless of
   cardinality. This makes single-entry optimization sound under work-stealing
   forcing ([13](13-parallel-evaluation.md)) without a sequential-tier carve-out,
   and it reuses a fact escape analysis already computes.

5. **Measure-first ordering.** Per [motivation and goals](01-motivation-and-goals.md)
   and the roadmap, none of this is justified until the baseline harness confirms
   *eval* (not build) is the bottleneck and `NIX_SHOW_STATS` confirms thunk
   allocation/GC is where the time goes. The analyses are predicated on that
   measurement holding; if the incremental cache alone closes the build-time gap
   (roadmap item 1), several of these become lower priority.

## 11. Summary

Laziness, implemented as C++ Nix implements it, is the bulk of cold-eval cost:
allocate a thunk, trace it, force it, update it — usually all four for a value
demanded exactly once a nanosecond later. `aos-nix` makes laziness nearly free by
porting the static analyses GHC and HotSpot use to *avoid* the work entirely, and
exploits Nix's purity, immutability, and whole-program closure to run those
analyses *exactly* where GHC and HotSpot can only approximate:

- **Strictness/demand + worker-wrapper** (GHC) → provably-demanded bindings
  compile eagerly with zero thunk allocation; derivation cores become
  straight-line code.
- **Cardinality 0/1/many** (GHC usage analysis) → dead bindings deleted,
  used-once bindings become single-entry / call-by-name with no update
  machinery.
- **Full laziness / let-floating** (GHC, ICFP '96) → loop-invariant thunks built
  inside `map`/`genList` are hoisted and computed once; the residency hazard that
  constrains GHC is absent in our one-shot arena.
- **Escape analysis + scalar replacement** (HotSpot C2 SRA) → non-escaping
  attrsets and thunks dissolve into registers, with none of the
  mutation/dispatch/reflection fragility that bounds HotSpot, because Nix values
  are immutable and the whole program is visible.

Every transform is licensed only by positive proof, defaults to the conservative
thunk on uncertainty, and is validated against byte-identical `.drv` output by
the differential gate of [compatibility constraints](02-compatibility-constraints.md).
The analyses make laziness cheap; the [incremental cache](12-incremental-evaluation-cache.md)
makes it unnecessary; together they are how `aos-nix` intends to beat C++ Nix on
the AOS closure without ever diverging from it by a single byte.

## Implementation checklist

Per-feature tracker for the whole-program analyses (strictness/demand + worker-wrapper, cardinality, full-laziness, escape analysis + scalar replacement) and the demand/usage fact infrastructure; master roll-up: [implementation checklist (all phases)](22-implementation-checklist-all-phases.md). Per the unlimited-budget mandate, every item here is in scope — including research-grade ones — built in dependency order and gated by the differential harness, never cut for scope.

This doc owns the **analyses**; the IR-to-IR *reductions* they license (inlining, beta, constant folding, case-/select-of-known, DCE, CSE, eta, let-floating, rewrite RULES / list fusion) are the simplifier, catalogued pass-by-pass in the [optimization pass catalog](26-optimization-pass-catalog.md) (`C-21`/`S-20`). Every analysis defaults to the conservative choice, so a bug degrades to *slower*, never *wrong* (§9); the gate is the differential `.drv` harness plus `NIX_SHOW_STATS`-style thunk-count deltas.

### Fact infrastructure (§9)

- [x] `ExprFacts { strictness, cardinality, escape }` per-IR-node record, all fields defaulting to the conservative choice (`Unknown`/`Many`/`Escapes`) (§9) — **P4**, `S-9`; annotations over the one IR ([25](25-intermediate-representation.md)), consumed by the oracle before any JIT exists.
- [x] Current fact-table precursor: `ratchet-core::ir` now exposes
      `ExprFacts`, `Strictness`, `Cardinality`, `Escape`, and an `IrFacts`
      table attached to every `Ir`; lowering, parse-cache hydration, and
      manual IR fixtures initialize one conservative `Unknown`/`Many`/`Escapes`
      record per arena node, import IR remapping preserves the fact table it
      receives, and parse-artifact validation rejects fact-table/node-count
      mismatches. Parse-cache entries may also carry an optional `facts.bin`
      sidecar that overlays facts when present and fingerprint-matched, and
      falls back to conservative facts when absent, malformed, or stale. This is
      only the default-safe annotation substrate; whole-program fixpoints,
      IR-hash content-addressed fact persistence, and actual JIT CLIF/storage
      consumers remain open.
- [x] Current fact-refresh precursor: `ratchet-core::ir::annotate_ir` resets a
      lowered `Ir` to conservative facts, runs the current strictness,
      cardinality, and escape producers in a fixed order, returns a combined
      report, and leaves conservative facts behind if any producer rejects
      malformed IR. This is not yet the memoized closed-world fixpoint driver.
- [ ] Facts cached content-addressed by IR hash in the same CA store as parse/compile artifacts (analyzed once per package-set version, reused across runs/CI) (§9, §8.1) — **P4**, ties to `S-14`/`S-15`.
- [x] Current persistent fact-sidecar transport precursor:
      parse-artifact bundles now carry an optional fifth `facts.bin` section
      after the mandatory frontend artifacts, and hydration writes that sidecar
      only when it validates against the bundled lowered-IR fingerprint and node
      count. Four-section bundles remain factless, and malformed or mismatched
      fact sections remove stale local sidecars and fall back to conservative
      facts. This lets existing persistent parse/file artifact blobs transport
      analyzed facts, but it is not an independent IR-hash fact artifact or
      analyzed-once cross-source fact index.
- [x] Current refreshed fact-sidecar writer precursor:
      `ParseCacheEntry::write_fact_sidecar` updates an existing entry's
      `facts.bin` after analysis only when the supplied analyzed IR fingerprints
      to the stored `ir.bin`/`symbols.bin` lowered artifact and its fact-table
      length matches the stored node count. Mismatched IRs, malformed stored
      artifacts, wrong-length fact tables, and write failures are reported
      instead of silently committing stale facts. This is an explicit
      parse-cache sidecar update path, not the independent IR-hash fact artifact
      store, closed-world fixpoint cache, or analyzed-once cross-source fact
      index.
- [x] Current explicit fact-refresh adapter precursor:
      `CachedParse::refresh_and_store_facts` now runs `annotate_ir` over a
      loaded or freshly parsed module, leaves refreshed facts in the in-memory
      `Ir`, and persists them through the validated `facts.bin` sidecar writer.
      It reports analysis failures separately from cache write failures, and a
      failed sidecar write does not discard the refreshed in-memory facts. This
      is an opt-in API for callers that already chose to analyze a parse result,
      not automatic analysis scheduling, whole-program fixpoint orchestration,
      independent IR-hash fact persistence, or an analyzed-once cross-source
      fact index.
- [x] Current analyzed parse-cache load precursor:
      `ParseCache::load_or_parse_analyzed_bytes` returns a `CachedAnalyzedParse`
      by loading or parsing source bytes, refreshing the returned module's
      in-memory facts, and best-effort writing the validated `facts.bin`
      sidecar. The result reports whether fact storage succeeded, while parse
      and analysis failures remain explicit errors. This is a caller-driven
      analyzed-load helper; it is not broad automatic analysis scheduling for
      every evaluator surface, whole-program fixpoint scheduling, independent
      IR-hash fact persistence, or an analyzed-once cross-source fact index.
- [x] Current configured-import analysis refresh precursor:
      ordinary unscoped filesystem imports with a configured parse cache now
      best-effort refresh facts on loaded or freshly parsed `CachedParse`
      results before IR remapping/evaluation and before persistent
      parse-artifact materialization. The tree-walk oracle can therefore
      consume current strictness/cardinality/escape facts for eligible imports,
      and validated `facts.bin` sidecars are written when possible. Scoped
      imports, text-store imports, and uncached imports stay conservative.
      Analysis failures leave existing/conservative facts, while sidecar or
      persistent write failures remain advisory and may still leave refreshed
      in-memory facts for the current evaluation. This is configured import
      integration for the current local analysis pipeline, not whole-program
      fixpoint scheduling, independent IR-hash fact persistence, or an
      analyzed-once cross-source fact index.
- [x] Current native root analysis refresh precursor:
      `NixNative::lower_native_source_bytes` now best-effort refreshes facts on
      configured parse-cache hits and miss/fallback parses before returning root
      IR to raw expression, raw instantiation, or file-backed instantiation
      entry points. Parse-keyed raw roots and file-keyed native source roots
      attempt to write validated `facts.bin` sidecars and re-materialize
      persistent parse/file artifacts when a persistent root is configured.
      Uncached native lowering stays conservative; analysis failures leave
      existing/conservative facts, while sidecar or persistent write failures
      remain advisory and may still leave refreshed in-memory facts for the
      current evaluation. This is native root integration for the current local
      analysis pipeline, not imported-module scheduling beyond the configured
      import path, whole-program fixpoint scheduling, independent IR-hash fact
      persistence, or an analyzed-once cross-source fact index.
- [x] Current cross-module call-summary and eager-assembly bridge (P4 Chunk E):
      `IR_ANALYSIS_VERSION = 7` persists sparse per-lambda argument/formal
      demand and escape summaries plus per-node structural-totality proofs.
      Formal-set summaries describe demanded attribute values with exact-key or
      all-except-key domains, following static literals, right-biased `//`
      chains, conditionals, aliases, and static `builtins.removeAttrs` while
      declining recursive, dynamic, cyclic, or otherwise unknown provenance.
      Imported symbols and cached sidecars remap and validate the summaries
      before use. At a statically shaped call, the tree-walk evaluator matches
      the caller's actual attribute bindings to the callee summary and installs
      a temporary assembly plan: proven-demanded structurally-total values can
      be evaluated without a thunk, while demanded-before-effect or
      once/no-escape cases use their narrower licensed forms. Pattern failures,
      non-total values, unknown update operands, aggregate escape, and missing
      or malformed facts fail closed to ordinary lazy allocation. The same
      static provenance seeds derivation-boundary values through `//` with exact
      RHS shadowing. Adversarial trace/error tests, fact-sidecar round trips and
      corruption rejection, cache miss-to-hit remapping, the representative
      byte-parity matrix, and the upstream language suite are green. A noisy
      local three-sample `bench.wide-eval` A/B against pristine pre-Chunk-E HEAD
      measured median native wall 1.391 -> 1.373 s cold and 1.338 -> 1.306 s
      warm, while peak arena mapping fell 71.5 -> 67.5 MiB; the absolute times
      are load-contaminated, so this landing claims the allocation reduction and
      no regression rather than a stable throughput win. This closes the
      scheduled Chunk-E transport/consumer slice, not the memoized closed-world
      fixpoint, IR rewrite, worker generation, or independent IR-hash fact
      index.

### Strictness / demand analysis + worker-wrapper (§4)

- [ ] Backward demand-propagation fixpoint over the IR, seeded from strict primops / `if`-condition / `derivationStrict` / interpolation / `foldl'` etc., iterated to a fixed point over the closed AOS call graph (§4.1) — **P4**, `S-9`.
- [ ] Worker/wrapper transform: split into an unboxed-strict-args worker + an always-inline lazy-convention wrapper that forces strict args and tail-calls the worker (§4.2) — **P4**, `S-9`; reductions in [26](26-optimization-pass-catalog.md).
- [ ] Soundness discipline: eager lowering licensed only by *proven* strictness, never heuristic; an unproven binding stays a thunk (§4.3) — **P4**; harness byte-green is the hard gate (a forced should-be-lazy `throw` is a loud test failure).
- [x] Current strictness-analysis precursor: `ratchet-core::analysis::strictness`
      adds a conservative demanded-node worklist seeded at the IR root. It
      annotates only child positions the tree-walk evaluator unconditionally
      demands to WHNF: strict unary/binary/ternary builtin arguments where the
      runtime semantics really demand them, `if`/assert conditions,
      interpolation children, dynamic attrset keys, leading dynamic select/hasAttr
      path segments, strict binary operands, thunk bodies, and direct literal
      lambda arguments whose simple formal is unconditionally demanded by the
      body, plus direct formal-set lambda arguments after the formal symbols and
      frame-slot shape validate because pattern matching must force the argument
      to attrs. It deliberately leaves lazy list elements, attr values, skipped
      higher-order callbacks, `foldl'`'s empty-list initial accumulator, assert
      bodies, selected branches, option-dependent `traceVerbose` messages, and
      shadowed-frame lambda arguments conservative. `ratchet-oracle` covers the
      producer/consumer path by annotating `(x: x + 1) (1 + 2)` and `({}: 1) {}`
      and observing the argument `ThunkAlloc` elided with `thunks_elided == 1`,
      while annotated foldl-empty and unreached dynamic attr-path regressions stay
      lazy.
- [x] Current worker-wrapper planning precursor:
      `ratchet-core::analysis::worker_wrapper` reports direct literal lambda
      calls where a wrapper could force a proven-strict lazy argument before a
      stricter worker call. It admits simple-formal patterns and validated
      formal-set patterns only when replayed strictness proves the argument is
      demanded, so forged strict facts over frame-slot mismatches remain
      retained. The planner rejects fact-table/node-count mismatches before it
      consumes imported strictness facts, so stale proof records outside the
      arena cannot license a split. This is still a plan surface only; it does
      not rewrite IR, generate workers, unbox fields, or solve the
      closed-call-graph fixpoint.
- [x] Current lowering-policy precursor: `ExprFacts::binding_lowering`
      encodes the THUNK/EAGER/SCALAR decision lattice so conservative or
      escape-only facts still choose THUNK, `Eager` requires proven strictness,
      and `Scalar` requires both proven strictness and proven no-escape.
      `ExprFacts::thunk_sharing` similarly keeps normal update/blackhole
      machinery unless cardinality and frame-locality proofs license a
      single-entry thunk, or a non-contradicted absence proof licenses
      omission. This records the policy API; actual JIT CLIF/storage consumers
      remain open.
- [x] Current JIT fact-plan precursor:
      `ratchet-jit::lower::jit_tier1_thunk_fact_plan` validates that a requested
      node is a well-formed `ThunkAlloc` with an existing non-self body and a
      fact table whose length matches the arena node count, then produces an
      address-free
      `JitTier1ThunkFactPlan` carrying the source `ExprFacts`,
      `BindingLowering`, `ThunkSharing`, and a collapsed
      `JitTier1ThunkFactDecision`. Conservative facts still choose ordinary
      updating thunk storage, non-absent strict facts choose eager WHNF or
      scalar eligibility, `Once + NoEscape` lazy facts choose a single-entry
      thunk, non-contradicted absence chooses omission, and `Absent + Strict`
      contradictions fail closed to ordinary updating thunk storage. This is a
      checked policy bridge for future tier-1 lowering only; it does not emit
      CLIF for thunk storage, call runtime helpers, register symbols, or execute
      native code.
- [x] Current tree-walk lowering consumer: the oracle's `ThunkAlloc` path reads
      each node's `ExprFacts::binding_lowering`, keeps conservative/unknown
      facts lazy, evaluates proven-strict `Eager` and `Scalar` facts directly to
      WHNF outside order-sensitive binding assembly, and records elisions in
      `EvalStats::thunks_elided`. During `let`, attrset, and formal-set default
      population, even strict facts keep thunks so forward references,
      dynamic-key errors, and duplicate-key validation cannot observe reordered
      value evaluation; lazy `SingleEntry` facts may still choose direct-force
      storage there because allocation stays lazy and preserves frame shape.
      Scalar replacement is intentionally represented as eager WHNF in the
      tree-walk oracle until the optimized tiers have stack/register storage.
      Covered by tests proving conservative facts still allocate suspended
      thunks, strict facts elide safe list-element thunks, analyzer-produced
      direct-body `let` proofs create single-entry storage, inherited select
      bindings stay lazy during attrset assembly, and frame-initialization facts
      stay lazy.

### Cardinality / usage analysis 0/1/many (§5)

- [ ] Usage component of the demand fixpoint computing absent / used-once / many per binding (§5) — **P4**, `S-9`.
- [x] Current cardinality-analysis precursor: `ratchet-core::analysis::cardinality`
      annotates simple same-frame `let` binding value nodes as `Absent` or
      `Once` when syntactic slot use can be counted without crossing another
      frame-producing node. Multi-use bindings, nested lambdas, nested lets,
      formal patterns, and recursive attrsets stay at conservative `Many`.
      This only produces facts for later passes; it does not yet lower
      single-entry thunks, remove absent bindings, or run the whole-program
      usage fixpoint.
- [x] Current branch-sensitive cardinality precursor:
      local usage counting now treats `if` branches as mutually exclusive for
      same-frame slots: the condition is counted unconditionally, then the
      branch contribution is the maximum of the then/else branch counts rather
      than their sum. This lets `let x = ...; in if c then x else x` prove
      `Once`, while condition-plus-branch uses and nested frame-producing
      branches still stay conservative at `Many`. This is still local syntactic
      cardinality only; it does not add path-sensitive demand facts,
      recursion/higher-order precision, or the whole-program usage fixpoint.
- [x] Current demanded-binding cardinality precursor:
      local usage counting now seeds a `let` frame from the body, then counts a
      binding value only after that binding's slot becomes reachable from the
      body or another already-reachable binding value. Each demanded binding
      value is counted once, matching the current shared-thunk model, so dead
      sibling bindings no longer make their dependencies appear live while
      transitive demanded aliases still refine to `Once`. Demanded values that
      cross nested frame producers still reset the whole frame to conservative
      `Many`; this is not the whole-program usage fixpoint.
- [ ] Single-entry thunks: drop the `Blackhole`/`Forced` update machinery (or downgrade to call-by-name) for used-at-most-once bindings (§5.1) — **P4**; the blackhole-skip restricted to escape-proven *frame-local* thunks so it is sound under parallel forcing (§10 item 4, `C-8`); ties to [13](13-parallel-evaluation.md) **P3.5**.
- [x] Current frame-local single-entry preflight:
      `ratchet-core::analysis::thunk_sharing` names the safety predicate for
      this reduction. `frame_local_single_entry_thunk_downgrade` accepts only
      well-formed `ThunkAlloc` nodes and returns `SingleEntry` only when the
      fact table proves both `Cardinality::Once` and `Escape::NoEscape`; absent
      thunks produce `Omit`, and every missing proof keeps update/blackhole
      machinery. This is a proof API only; the single-entry representation,
      call-by-name lowering, dead-binding elimination, and stronger
      cardinality/escape analyses remain open.
- [x] Current direct-body `let` thunk frame-local proof:
      `annotate_escape` now marks a lazy `let` binding thunk `NoEscape` only
      when the enclosing `let` body is exactly that binding's same-frame local
      slot, the binding value is a well-formed `ThunkAlloc`, every binding key
      in the frame is static, no sibling binding value captures the slot, and
      the thunk allocation has exactly one direct IR reference.
      Combined with the current local cardinality producer, `annotate_ir` feeds
      the `Once + NoEscape` proof into `frame_local_single_entry_thunk_downgrade`
      for the narrow `let x = ...; in x` shape. List publication,
      sibling-binding capture, nested frame producers, self-referential thunk
      bodies, higher-order uses, raw/shared thunk aliases, and the whole-program
      demand/escape fixpoint remain conservative.
- [ ] Absence → dead-binding elimination via the dual of the demand fixpoint (worker takes a dummy, code never emitted) (§5.2) — **P4**, `S-9`; reduction in [26](26-optimization-pass-catalog.md).
- [x] Current tree-walk dead-binding consumer:
      `ratchet-oracle` now consumes successful `dead_binding_elimination_plan`
      results for loaded IR modules that already carry analyzed facts. The
      tree-walk oracle leaves admitted absent thunk-valued `let` bindings in
      their dummy frame slots and skips the binding thunk allocation while
      preserving conservative result/trace observables and falling back to
      normal lazy allocation on planner failure. The planner rejects
      fact-table/node-count mismatches before it consumes imported cardinality
      facts, so short or overlong fact tables cannot license omission.
      Configured parse-cache imports may carry best-effort refreshed facts;
      uncached, scoped, and text-store imports lowered without annotation keep
      conservative facts. This is a tree-walk `let` consumer only; IR rewriting, frame compaction, worker dummy arguments,
      attrset/formal-argument absence, stronger cardinality, and the
      whole-program demand fixpoint remain open.
- [ ] Cardinality precision under higher-order Nix (`map`/`foldl'`/recursion schemes), pushed as far as it pays before the incremental cache subsumes the win (§5.3, §10 item 1) — **P4/P8**, `M-15` (measure-gated precision, IN SCOPE — chased, not cut).

### Full laziness / let-floating (§6)

- [ ] Float-outward: hoist a let-binding out of an enclosing lambda when it does not depend on the parameter, so a loop-invariant is computed once (§6.1) — **P8**, `S-9`; `analysis/full_laziness.rs`, benchmark-gated.
- [x] Current full-laziness precursor: `ratchet-core::analysis::full_laziness`
      reports only closed, pure static-key `let` binding values nested under simple
      identifier lambdas. The root lazy binding thunk is allowed only when its
      forced body is closed and pure; any local/upvalue reference, nested thunk
      allocation, dynamic-scope probe, primop, nested frame producer, formal-set
      pattern, dynamic `let` key, recursive attrset, or effectful node stays conservative. The
      report includes the owning `let`, binding index, binding key, and binding
      value. This is candidate discovery only; it performs no float-out/float-in
      rewrite and does not yet move mutually-dependent groups.
- [ ] Float-inward: sink a binding to the smallest scope dominating its uses (branch-gated allocation avoidance), run before the strictness fixpoint (§6.2) — **P8**.
- [ ] Residency policy: float aggressively in Tier A (one-shot arena, no space-leak hazard); in daemon mode bound the size/cost of what is floated (§6.3) — **P8**, `R-6` (daemon residency tuning, research-grade, IN SCOPE).

### Escape analysis + scalar replacement (§7)

- [ ] Escape analysis as a syntactic-reachability check over the closed program (returned-from-frame / stored-into-escaping-object / passed-to-non-transparent-primop) (§7.1, §7.3) — **P4**, `S-9`; depends on precise capture sets ([04](04-frontend-parser-and-ir.md) §6.4).
- [x] Current escape-analysis precursor: `ratchet-core::analysis::escape`
      owns the current escape fact approximation and marks only allocation-free
      immediate scalar literals (`int`, `float`, `bool`, `null`) as `NoEscape`.
      Every other node is reset to conservative `Escapes`, and malformed
      kind/payload pairs are rejected. This does not yet prove non-escaping
      attrsets, lists, thunks, or primop results, and it does not perform scalar
      replacement.
- [x] Current direct-body lazy-thunk escape precursor:
      `annotate_escape` now also proves frame-locality for static lazy `let`
      thunks whose only admitted use is the direct `let` body local slot and
      whose frame has only static keys and no sibling binding value capture of
      that slot, with no extra direct IR aliases of the thunk allocation. This
      gives the C-8 single-entry preflight one analyzer-produced lazy-thunk proof
      while keeping list publication, sibling captures, nested frame producers,
      dynamic keys, raw/shared thunk aliases, and general closure escape
      conservative.
- [ ] Scalar Replacement of Aggregates: decompose a non-escaping attrset/list/thunk into SSA values (Cranelift block params as join points; unboxed multi-returns) — no heap object at all (§7.1, §7.4) — **P4** facts / **P6–P7** CLIF realization ([08](08-execution-tiers-and-cranelift.md)); reduction in [26](26-optimization-pass-catalog.md).
- [ ] Escape-signature table for the ~120-primop surface, with the to-be-interned boundary treated as an escape (§7.3) — **P4**, `R-9`; property-test fuzzing (not just the closure diff), default-off until green.
- [x] Current semantic escape-signature fuzz expansion:
      `ratchet-oracle` now fuzzes tree-walk payload values for randomized
      immediate-scalar predicate, collection, string, version, and list-search
      primop inputs while asserting each generated root still belongs to the
      direct immediate-scalar signature surface. This expands the semantic
      harness beyond tag-only samples, but C++-oracle comparison, exhaustive
      input generation for every builtin, and aggregate/result-forwarding
      escape proofs remain open.
- [x] Current conservative semantic escape-signature expansion:
      `ratchet-oracle` now also samples conservative direct builtin signatures
      that return heap values, compute inline scalar results, or forward operand
      values, including type/string codecs, JSON/XML/TOML conversion, attr/list
      transforms, regex split, hash/string helpers, conservative scalar results
      such as numeric `add`, and scalar forwarding through `head`, `getAttr`,
      `seq`, and `elemAt`.
      Each sample must lower to the requested root
      direct `PrimOp`, remain outside the immediate-scalar allowlist, and return
      the expected heap or inline tag. This expands negative semantic coverage
      for the escape table, but still does not exhaustively generate valid
      inputs for every conservative builtin, compare against the C++ oracle for
      each sample, or prove aggregate/result-forwarding escape behavior.

### Whole-program closed-world enablers (§8)

- [ ] Closed-world fixpoint infrastructure exploiting the fully-known import closure, immutability, and effect-freedom to compute *exact* (not approximate) demand/escape facts (§8) — **P4**, `S-9`; the qualitative advantage over GHC/HotSpot.
- [ ] Interaction with parallel forcing re-examined for single-entry thunks under work-stealing schedules (§10 item 4) — **P3.5/P4**, `C-8` (closed); `loom`/Miri audit `R-4`.

## References

External claims in this document were verified against the following sources.

- GHC User's Guide, *Optimisation (code improvement)* — worker/wrapper
  (`-fworker-wrapper`), full laziness / let-floating, float-inward, and the
  residency caveat: https://downloads.haskell.org/ghc/9.12.1/docs/users_guide/using-optimisation.html
- Sergey, Vytiniotis, Peyton Jones et al., *Theory and Practice of Demand
  Analysis in Haskell* (JFP draft, Microsoft Research) — combined
  strictness + usage/cardinality demand analysis, call-by-name for used-once
  bindings, absence:
  https://www.microsoft.com/en-us/research/wp-content/uploads/2017/03/demand-jfp-draft.pdf
- *Demand Analysis vs. Call Arity*, Haskell Implementors' Workshop (HIW 2017,
  ICFP 2017) — interaction of demand and arity analysis (cardinality precision
  open question):
  https://icfp17.sigplan.org/details/hiw-2017/14/Demand-Analysis-vs-Call-Arity
- Wikipedia, *Strictness analysis* — background and definition:
  https://en.wikipedia.org/wiki/Strictness_analysis
- Marlow, Yakushev & Peyton Jones, *Faster laziness using dynamic pointer
  tagging* (ICFP 2007) — encoding evaluatedness and constructor tags in heap
  pointer low bits (the §3.3 force fast path):
  https://simonmar.github.io/bib/papers/ptr-tagging.pdf
- Aleksey Shipilëv, *JVM Anatomy Quark #18: Scalar Replacement* — HotSpot does
  Scalar Replacement of Aggregates (SRA), not true stack allocation; the object
  ceases to exist at the machine-code level:
  https://shipilev.net/jvm/anatomy-quarks/18-scalar-replacement/
- OpenJDK, *HotSpot Escape Analysis and Scalar Replacement Status* (C. Lucas):
  https://cr.openjdk.org/~cslucas/escape-analysis/EscapeAnalysis.html
- *The Object Allocation Tax: ... the JIT's Escape Analysis Both Helps and
  Misleads You*, Java Code Geeks (EA fragility in practice):
  https://www.javacodegeeks.com/2026/04/the-object-allocation-tax-why-your-java-service-is-40-gc-and-how-the-jits-escape-analysis-both-helps-and-misleads-you.html
- *Announcing Snix* and *Component Overview* — Snix (Tvix fork, 2025);
  `snix-eval` is a bytecode-VM evaluator, `nix-compat` provides shared Nix
  compatibility functionality; project defers optimization until
  nixpkgs-correct: https://snix.dev/blog/announcing-snix/ and
  https://snix.dev/docs/components/overview/
- TVL, *Tvix: We are rewriting Nix* (lineage / prior art):
  https://tvl.fyi/blog/rewriting-nix

Foundational paper referenced from the GHC documentation (not independently
fetched here, cited as the named source for the let-floating transform): Peyton
Jones, Partain & Santos, *Let-floating: moving bindings to give faster programs*,
ICFP 1996.
