# RFC-0007 - Glossary

This document is the **canonical lexicon** for the RFC-0007 set on `aos-nix`, the
Rust Nix evaluator for ANDYL OS. Each entry gives a precise definition *in the
context of aos-nix* and, where a term is treated in depth elsewhere, a pointer to
the owning document. Where the prose elsewhere in the set drifts, **these
definitions govern**; the [design-language and prior-art map](#design-language-and-prior-art-map)
at the end is the implementor's Rosetta stone — "if you've seen X in system Y,
that is what this is."

A standing terminology contract disciplines a handful of words that would
otherwise float:

- **"the demand graph"** always means the one demand-driven incremental
  memoization graph (Adapton DCG / Salsa query graph); its units are **graph
  nodes** (a *demand-graph node*). **"graph reduction"** is a lazy *evaluation*
  technique only; the **"derivation graph"** / **".drv closure"** is Nix's output
  DAG. The bare word "graph" is never used for any of these — it is always
  qualified.
- **"node"** is always qualified: *AST node*, *IR node*, or *graph node*.
- **CAS** means **compare-and-swap only**. The content-addressed value store is
  *the CA store* (a.k.a. *the value store*) — **never** "CAS." The two collide
  on three letters and on nothing else; see *CA store* and *CAS*.

Five invariants recur throughout and frame nearly every definition below:

1. **Eval, not build.** aos-nix replaces only the path from `.nix` source to a
   `.drv` derivation graph; real Nix still *builds* the resulting `.drv`. See
   [motivation and goals](01-motivation-and-goals.md).
2. **Byte-identical to C++ Nix.** The output is a bug-for-bug contract: identical
   `.drv` files and store paths, SHA-256 derivation hashing, exact string
   contexts. See [compatibility constraints](02-compatibility-constraints.md).
3. **Differential-harness-gated.** aos-nix is default-OFF until the `.drv`-diff
   harness is byte-green on the full AOS closure; `NixCli` is a permanent
   fallback. See [differential testing and benchmarking](15-differential-testing-and-benchmarking.md).
4. **Cranelift backend.** All compiled tiers use Cranelift, not LLVM/WASM. See
   [execution tiers and Cranelift](08-execution-tiers-and-cranelift.md).
5. **Split hashing.** xxh3 in-process, blake3 durable/shared, SHA-256 *only* for
   Nix-observed `.drv`/store hashes — no internal hash ever leaks into a
   Nix-observed hash. See [incremental evaluation cache](12-incremental-evaluation-cache.md).

A standing theme — the *synthesis thesis* of [architecture overview](03-architecture-overview.md)
— is that Nix's **purity and value immutability** convert techniques that are
*partial or unsound* in their source runtimes (GHC, HotSpot, V8, Salsa) into ones
that are *total and sound* here.

---

## A

**Adapton** — A research framework for *demand-driven* incremental computation
(Hammer et al., PLDI 2014) built around a *demanded computation graph (DCG)* — one
concrete instance of **the demand graph** — with a separation between inner
computations and outer observers. One of the named sources for aos-nix's
incremental cache; change propagation runs only for results an observer actually
demands. See [incremental evaluation cache](12-incremental-evaluation-cache.md).

**AOS_NIX_NATIVE** — The environment-variable gate that selects the native
`aos-nix` evaluator (`NixNative`) over the subprocess `NixCli` fallback. It stays
**unset (off) by default** until the differential `.drv`-diff harness is
byte-green on the full AOS package set. See [architecture overview](03-architecture-overview.md)
and [integration with AOS](14-integration-with-aos.md).

**ATerm** — The textual serialization format Nix uses on disk for `.drv` files.
aos-nix produces ATerm via the `nix-compat` crate, byte-identically to C++ Nix;
its serialization, attr ordering, and string-context encoding are a compatibility
firewall, not an optimization target. See [derivation and store compatibility](11-derivation-and-store-compatibility.md).

---

## B

**Baseline JIT (tier 1)** — The Cranelift compilation tier that removes
interpreter-dispatch overhead with *fast compile and no speculation*: every value
access, `select`, arithmetic op, and `force` is fully general and calls a runtime
symbol. The analogue of HotSpot's C1. See [execution tiers and Cranelift](08-execution-tiers-and-cranelift.md).

**Blackholing / blackhole** — The thunk state denoting "being forced *on the
current stack*." In the **serial** model (`Suspended → Blackhole → Forced`) it is
the middle state; re-entering a blackholed thunk is Nix's infinite-recursion
detection (`error: infinite recursion encountered`). In the **parallel** superset
(`Suspended → Pending → Awaited → Forced/Failed`), `Blackhole` is split off from
inter-thread blocking: `Pending`/`Awaited` mean "*another* thread is forcing"
(block or work-steal), while `Blackhole` keeps its precise meaning — "the *same*
thread re-entered a thunk it is already forcing," the genuine cyclic error. One
model; the serial chain is its uncontended subset. See
[value representation](05-value-representation.md),
[parallel evaluation](13-parallel-evaluation.md), and
[laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md).

**blake3** — The cryptographic, SIMD/tree hash used for *durable, content-addressed*
eval-cache keys and value-hashes shared across CI machines. Chosen over SHA-256
for speed and over xxh3 for collision-resistance: a collision in a *shared* cache
could corrupt results, so the cross-machine layer must be cryptographic. Never
appears in `.drv` output. See [incremental evaluation cache](12-incremental-evaluation-cache.md).

**Bump arena** — The Tier A allocator for one-shot CLI eval: a bump-pointer heap
that is **never freed** until process exit. It is the fastest possible allocator
and correct for a batch job that drops its whole heap at exit; it also lets
compiled code hold raw interior pointers freely (no collector to invalidate
them). See [memory management and GC](06-memory-management-and-gc.md).

**Bytecode VM vs. tree-walking** — Two interpreter strategies. A *tree-walking*
interpreter (aos-nix tier 0, and C++ Nix) walks the AST/IR directly; a *bytecode
VM* (Snix/Tvix's `snix-eval`) compiles to a bytecode that a dispatch loop
executes. aos-nix uses a tree-walk oracle at tier 0 and Cranelift-compiled native
code above it, rather than a bytecode VM. See [execution tiers and Cranelift](08-execution-tiers-and-cranelift.md).

---

## C

**Call-by-need / lazy evaluation** — The evaluation strategy of Nix (and GHC):
every binding, list element, and attribute value is a suspended computation
evaluated *at most once* and *only when demanded*. "Call-by-need" adds memoization
(sharing) to "call-by-name"; cardinality analysis can downgrade a provably
used-once binding from call-by-need to call-by-name because re-evaluation is free
in a pure language. See [laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md).

**Cardinality analysis** — The whole-program *usage* analysis (the "at most once?"
/ "not at all?" half of GHC's demand analyser) that classifies each binding as
**0 (absent)**, **1 (used-once)**, or **many**. Absent bindings are dead-code
eliminated; used-once thunks drop their blackhole/update machinery (single-entry
thunk or call-by-name downgrade); many-use thunks keep the full memoizing update
thunk. See [laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md).

**CA store / value store** — The `mmap`'d, on-disk, content-addressed arena of
hash-consed values that backs the incremental eval cache (`values/`, `files/`).
Entries are keyed by **blake3** of their content, so eviction needs no write-back
(the hash *is* the address) and the store doubles as the evaluator's
**out-of-core** swap-to-disk valve. **Always write "the CA store" or "the value
store," never "CAS"** — `CAS` is compare-and-swap (see *CAS*), and some sibling
prose still abbreviates the store as "CAS"; that usage is non-canonical and reads
as the store here. See [memory management and GC](06-memory-management-and-gc.md)
§3.4 and [incremental evaluation cache](12-incremental-evaluation-cache.md).

**CAS (compare-and-swap)** — The lock-free atomic primitive (read-modify-write
conditioned on an expected prior value) used for the thunk state word so a
parallel forcer can claim a `Suspended` thunk without a lock. **In this RFC `CAS`
means compare-and-swap and nothing else** — the content-addressed value store is
*the CA store*, never "CAS" (the abbreviations collide on three letters and
share no meaning). See [parallel evaluation](13-parallel-evaluation.md).

**Content-addressed (CA)** — Of a derivation or a cache entry: named by a hash of
its *content* rather than its inputs. CA derivations enable build-layer early
cutoff (a rebuild whose output content is unchanged stops propagating). The eval
cache's persistent stores (`values/`, `files/`) are content-addressed by blake3
(*the CA store*). Contrast *input-addressed*. See [derivation and store compatibility](11-derivation-and-store-compatibility.md)
and [incremental evaluation cache](12-incremental-evaluation-cache.md).

**Copy-and-patch** — An ultra-low-warmup compilation technique that stitches
pre-compiled machine-code "stencils," patching in constants and addresses, for
microsecond compile times (CPython 3.13's JIT, OOPSLA 2021). Noted as a *deferred,
measurement-gated* alternative to the Cranelift baseline for tier 1 if tier-1
compile time (not code quality) proves a bottleneck. See [execution tiers and Cranelift](08-execution-tiers-and-cranelift.md).

**Core IR** — The generic, language-agnostic lazy-functional IR housed in
`ratchet-core`: the GHC-Core analog (lazy lambda calculus — Int/Float/Bool/Null/Str,
de-Bruijn vars, Lambda/Apply, Let, If, BinOp, List, ThunkAlloc, data-constructor +
projection, the `PrimOp` escape hatch) that carries *no* Nix knowledge. It is the
"generic IR" worth factoring — one layer **above** *CLIF* (the lower-level,
von-Neumann, LLVM-analog SSA the Core lowers *to*) and the substrate every dialect
plugs into. Distinct from the Nix-specific *IR* taxonomy (which adds the dialect
nodes); the Core is its language-agnostic subset. See
[generalization and language dialects](28-generalization-and-language-dialects.md)
and [the intermediate representation](25-intermediate-representation.md).

**Cranelift** — The pure-Rust code generator (born in Wasmtime; also
`rustc_codegen_cranelift`) chosen as the JIT backend for tiers 1 and 2. Picked for
~10x-faster compilation than LLVM (warmup-friendly), hermetic pure-Rust builds,
`JITBuilder::symbol` host-symbol resolution matching the runtime ABI, and user
stack maps for a precise external GC. See [execution tiers and Cranelift](08-execution-tiers-and-cranelift.md).

**CLIF** — Cranelift IR, the SSA intermediate representation each IR node lowers
to. Its block parameters serve as *join points* for scalar-replaced values.
Worked lowering sketches in [execution tiers and Cranelift](08-execution-tiers-and-cranelift.md).

---

## D

**de Bruijn index** — A static slot index assigned to each variable reference by
the scope-resolution pass, replacing named-variable lookup with a flat indexed
environment (a vector of value pointers, not a chain of named maps). This makes
environment access constant-time and environment hashing cheap. See [frontend, parser and IR](04-frontend-parser-and-ir.md)
and [architecture overview](03-architecture-overview.md).

**Demand / strictness analysis** — See *Strictness / demand analysis*.

**Demand graph (the)** — The single demand-driven incremental memoization graph
that *is* the evaluator: a content-addressed, suspendable dataflow graph whose
**graph nodes** are units of deferred work (lex, parse, resolve, analyze, compile,
force) keyed on `H(expression ⊕ environment)` and carrying a value-hash that drives
early cutoff. A node is created only when demanded, and change propagates only
along edges an observer demands. The unified-demand-graph thesis — *parser,
compiler, and forcer are one model* — makes the front-end a first-class citizen of
this graph rather than a serial prelude. **Always "the demand graph," never the
bare "graph"; its units are "graph nodes," never bare "nodes."** Distinct from
*graph reduction* (a lazy-evaluation technique) and the *derivation graph* (Nix's
`.drv` output DAG). See [architecture overview](03-architecture-overview.md) §3.4
and [incremental evaluation cache](12-incremental-evaluation-cache.md).

**Demand-graph node** — One unit of the demand graph: a memoized,
content-addressed, suspendable computation tagged with an *effect class* (pure vs.
effectful) and a granularity tier (durable query node vs. fine in-memory thunk).
The same node *model* covers lexing, parsing, analysis, compilation, and forcing.
Qualify always — a *graph node* is not an *AST node* or an *IR node*. See
[architecture overview](03-architecture-overview.md) §3.4.

**Demand-driven / incremental computation** — The model in which evaluation is the
incremental maintenance of **the demand graph**: a graph node is created only when
forced, and change propagates only along edges an observer demands. Graph nodes are
keyed on `H(expression ⊕ environment)` and carry a value-hash that drives early
cutoff. See [incremental evaluation cache](12-incremental-evaluation-cache.md).

**Dialect** — A language plugged into the `ratchet` engine on top of the *Core
IR*. A dialect supplies, at registration time: its **syntax** (a per-language
front-end crate), its **extra ops** beyond Core (reached through the indexed
`PrimOp` escape hatch, never new Core variants), its **effect-lattice members**
(what is speculable and the opaque effect key — see *effect lattice*), its
**primop table** (the builtin identities and their per-argument strictness), and
its **rewrite rules** (dialect-specific simplifier RULES, e.g. Nix list fusion).
It is a registration-time seam (monomorphized, never `dyn` on the force path),
not a build-time dependency of the engine. **Nix is the first (and, in RFC-0007,
the only) dialect**; Haskell and TLA+ are recorded only to validate the boundary.
See [generalization and language dialects](28-generalization-and-language-dialects.md).

**Deoptimization / uncommon trap** — HotSpot's mechanism (and term) for abandoning
a speculative tier-2 native frame when a guard fails, *reconstructing* the abstract
evaluation state from deopt metadata, and resuming in the tier-0 oracle.
Deoptimization keeps speculation correct without being sound-by-proof; in aos-nix
it is dramatically simpler than in HotSpot because Nix is effect-free — there are
no partially-performed side effects to roll back. See [execution tiers and Cranelift](08-execution-tiers-and-cranelift.md).

**Derivation / `.drv`** — The unit of build description Nix emits: a node in the
build graph specifying a builder, arguments, environment, inputs, and outputs,
serialized as an ATerm `.drv` file with SHA-256-hashed output paths. Producing
`.drv` files byte-identical to C++ Nix is aos-nix's entire output contract. See
[derivation and store compatibility](11-derivation-and-store-compatibility.md).

**Derivation graph / `.drv` closure** — Nix's **output** DAG: the directed acyclic
graph of `.drv` derivations and their store-path inputs that aos-nix *emits* and
real Nix then *builds*. This is what "the path from `.nix` source to a derivation
graph" (invariant 1) refers to. It is **not** the demand graph (the internal
incremental engine) and **not** *graph reduction* (a lazy-evaluation technique);
keep the three distinct whenever "graph" appears. See
[derivation and store compatibility](11-derivation-and-store-compatibility.md).

**derivationStrict** — The builtin (`builtins.derivationStrict`) that
*forces every attribute* of a derivation argument in deterministic attr order,
builds a `nix-compat` `Derivation`, serializes ATerm, and hashes output paths with
SHA-256. The name is not a coincidence: it is the dominant strict context, so
nearly every binding flowing into a derivation is provably strict. The
compatibility firewall (L1) of the stack. See [derivation and store compatibility](11-derivation-and-store-compatibility.md).

---

## E

**Effect class** — The per-node property that splits demand-graph nodes into
**pure** (lex, parse, resolve, analyze, compile, and *most* thunks — freely
memoized, speculated, re-run, parallelized) and **effectful** (`derivationStrict`
writes a `.drv`; `import`/`readFile` read the filesystem; **IFD** triggers a build).
Effectful nodes are a constrained subclass: at-most-once execution, **no
speculation**, their effects keyed into the cache as explicit inputs. The scheduler
reads a per-node effect tag; *speculation and re-execution are sound only for pure
nodes.* The general form of the speculative-parse error-quarantine rule. See
[architecture overview](03-architecture-overview.md) §3.4 and
[laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md).

**Effect lattice** — The *open, dialect-supplied* replacement for the closed
`enum EffectClass { Pure, Effectful }` (decision `S-23`). Rather than a fixed enum
the engine interprets, the effect class becomes an engine trait — `is_speculable()
-> bool` plus `effect_key() -> EffectKey` — and the dialect supplies the concrete
members (for Nix: `import`, IFD, `readFile`, `derivationStrict`). `ratchet-cache`
gates speculation and re-execution on the per-node effect tag *without
interpreting* it; this is the one generalization that crosses into an UNSAFE
engine crate. See [generalization and language dialects](28-generalization-and-language-dialects.md)
§5 and *Effect class* (the Nix-populated instance of this lattice).

**Error quarantine** — The soundness rule that a *speculative* parse/compile (or
any ahead-of-demand work on a pure node) **may never surface an error**. In Nix,
a syntax error in a file fires *only when that file is actually imported* (errors
are lazy). A speculative failure is therefore **stashed against the node, not
raised**, and re-raised only if and when evaluation genuinely demands that file —
reproducing exactly the error C++ Nix would have produced at that point. Whether a
file was speculated or parsed on demand must be **unobservable**. This is the same
discipline as CPU speculative execution and the *effect class* gate; it is what
keeps speculation from leaking into bug-for-bug `.drv` parity. See
[frontend, parser and IR](04-frontend-parser-and-ir.md) §9.6.

**Early cutoff** — The single feature that makes incremental evaluation
*systemic*: when a reconsidered node recomputes to a value-hash *equal* to its
previous one, change propagation **stops** — consumers are not dirtied. Editing a
comment in a widely-imported file recomputes almost nothing. This is Salsa's
red-green algorithm and *Build Systems à la Carte*'s verifying-trace cutoff; it is
the biggest systemic lever in the whole RFC. See [incremental evaluation cache](12-incremental-evaluation-cache.md).

**Escape analysis** — The whole-program analysis that proves an aggregate (attrset,
list, thunk) never outlives the frame that built it, licensing *scalar
replacement*. Borrowed from HotSpot's C2, but *more* effective in Nix because
immutability removes the aliasing/identity/virtual-dispatch hazards that make it
fragile in Java, reducing it to near-syntactic reachability. An aggregate that
flows into a to-be-interned result counts as escaping. See [laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md).

---

## F

**Fiber** — A **stackful coroutine** (green thread) the runtime parks and resumes
to suspend an eval node blocked on I/O — an IFD waiting on a build, an eval-time
fetcher — so its CPU worker is freed to run other graph nodes. Fibers give M:N
green-threading: many fibers multiplexed over the rayon worker threads, with a
single fiber scheduler shared across node kinds. They exist because rayon
(CPU work-stealing) and the tokio reactor (I/O) cannot transparently co-schedule;
a stackful fiber can yield across that boundary where an `async fn` cannot. Same-
thread reentry is detected by recording the owning thread/fiber id on a claimed
thunk. See [parallel evaluation](13-parallel-evaluation.md) §5.5.

**Force / forcing** — The operation that drives a value to weak head normal form,
evaluating its thunk if necessary. The runtime heartbeat: check state; if `Forced`
return the cached slot (a single tag test on the hot path), if `Blackhole` raise
infinite recursion, if `Suspended` transition through `Blackhole`, run the body,
cache, and mark `Forced`. Exposed to compiled code as the `aos_force` runtime
symbol — the hottest call. See [value representation](05-value-representation.md)
and [laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md).

**Full-laziness / let-floating** — The GHC transform (Peyton Jones, Partain &
Santos, ICFP '96) that *floats* a let-binding outward, out of an enclosing lambda
it does not depend on, so a loop-invariant subexpression (e.g. a store-path
interpolation inside a `map`) is computed **once** rather than per call. The
complementary *float-inward* sinks a binding toward its uses. The GHC residency
caveat (hoisting can leak space) largely vanishes in aos-nix's never-free CLI
arena. See [laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md).

**Fusion** — See *Rewrite RULES / fusion* and *Simplifier (the)*.

---

## G

**Generational GC** — A precise generational *copying* collector for long-lived
daemon mode (Tier B), exploiting the extreme form the generational hypothesis
takes here (intermediate thunks die almost immediately). It moves objects, so JIT
code must cooperate via read/write barriers and precise stack maps. Contrast the
Tier A bump arena. See [memory management and GC](06-memory-management-and-gc.md).

**Graph node** — See *Demand-graph node*. A *graph node* is a unit of the demand
graph; it is **not** an *AST node* or an *IR node* — qualify always.

**Graph reduction** — A name for **lazy evaluation as a rewriting technique** —
repeatedly reducing a graph of shared subexpressions to normal form, the classic
implementation of call-by-need (GHC's STG is its industrial form). In this RFC the
phrase is reserved for that *evaluation* sense only. It is **not** the demand graph
(the incremental engine) and **not** the derivation graph (Nix's `.drv` output
DAG). See *Call-by-need / lazy evaluation* and [value representation](05-value-representation.md).

---

## H

**HAMT** — Hash array mapped trie, the fallback representation for large or
override-heavy attribute sets (small/stable attrsets use a flat shape-indexed array
instead). See [value representation](05-value-representation.md) and [attribute sets, hidden classes and inline caches](09-attribute-sets-hidden-classes-and-inline-caches.md).

**Hash-consing / maximal sharing** — Interning immutable values so structurally
equal values collapse to a *single* allocation, consulting a global cons-table
(keyed by xxh3, with structural equality as tiebreak) at construction time. It buys
heap deduplication (store-path strings, `meta`/`stdenv` recur constantly), O(1)
structural equality via pointer equality, and a precomputed value-hash stored in
the object header that powers the incremental cache's early cutoff. **Total in
Nix** because values never mutate — niche elsewhere, global here. See [value representation](05-value-representation.md).

**Hidden class / shape / map** — The V8-derived structure (a.k.a. *shape* or *map*)
that an attribute set's header references: the sorted/insertion-ordered key set
shared by all attrsets with the same keys in the same order, so `attrs.field`
becomes a shape-check plus a constant-offset load. aos-nix's shape carries a
*deterministic ordering invariant* V8 does not need, because attr iteration order
is observable and feeds `derivationStrict`. See [attribute sets, hidden classes and inline caches](09-attribute-sets-hidden-classes-and-inline-caches.md).

---

## I

**IFD (import-from-derivation)** — The Nix pattern where evaluation `import`s (or
`readFile`s) a path that is *itself a derivation output*, so forcing that thunk
**forces a build to run mid-evaluation** and blocks eval until the `.drv` is built.
IFD is the canonical *effectful* demand-graph node: at-most-once, **no
speculation**, build-keyed into the cache; it is the chief reason an eval node may
**block on I/O for seconds**, which is what the *fiber* scheduler and the tokio I/O
reactor exist to absorb. See [primops and runtime ABI](10-primops-and-runtime-abi.md)
and [parallel evaluation](13-parallel-evaluation.md).

**Inline cache (IC)** — A per-access-site cache mapping observed *shape → field
offset*, walking the states **uninitialized → monomorphic → polymorphic →
megamorphic** as it sees shapes. *Monomorphic* (one shape) is the fast case tier 2
specializes into a guarded constant-offset load; *polymorphic* caches a small fixed
set; *megamorphic* falls back to a generic lookup. Exposed as `aos_select_ic`.
Borrowed from V8/HotSpot; sound here because immutable values never change shape.
See [attribute sets, hidden classes and inline caches](09-attribute-sets-hidden-classes-and-inline-caches.md).

**Intermediate representation (IR)** — The single arena-allocated representation
all tiers share: a closed `NodeKind` taxonomy (an *IR node* is one node of it),
scope-resolved to de-Bruijn `(depth, slot)` form, carrying a per-node *effect
class*. The tier-0 oracle interprets it, Cranelift compiles it, and the simplifier
rewrites it ("one IR for all tiers"). Distinct from *CLIF* (Cranelift's own SSA IR,
which IR nodes lower *into* at tier 1/2). Specified in
[the intermediate representation](25-intermediate-representation.md); the passes
that rewrite it are catalogued in
[the optimization pass catalog](26-optimization-pass-catalog.md).

**Input-addressed (IA)** — Of a derivation: its output store path is computed from
a hash of its *inputs* (the ATerm of the derivation), the default Nix scheme.
Contrast *content-addressed (CA)*. aos-nix must reproduce IA output-path hashing
(SHA-256) byte-identically. See [derivation and store compatibility](11-derivation-and-store-compatibility.md).

---

## J

**JIT tier / baseline / optimizing** — The compiled execution tiers above the
tier-0 oracle: tier 1 is the Cranelift **baseline** (fast compile, no speculation,
removes interpreter overhead) and tier 2 is the Cranelift **optimizing** tier
(profile-guided shape/type speculation, strictness baking, scalar replacement,
inlining, guarded by deopt and OSR). Promotion is profile/counter-driven, HotSpot
style. See [execution tiers and Cranelift](08-execution-tiers-and-cranelift.md).

---

## L

**Lazy / call-by-need evaluation** — See *Call-by-need / lazy evaluation*.

---

## M

**Maximal sharing** — See *Hash-consing / maximal sharing*.

**Megamorphic** — See *Inline cache*.

**Memoization** — Caching a computation's result keyed on its inputs so a repeat is
a lookup, not a recompute. The incremental cache memoizes thunk and derivation
results keyed on `H(expression ⊕ environment)`; hash-consing memoizes value
construction. Sound across runs in Nix because evaluation is *referentially
transparent* (a pure function of source plus captured environment). See [incremental evaluation cache](12-incremental-evaluation-cache.md).

**Monomorphic / polymorphic** — See *Inline cache*.

---

## N

**NaN-boxing** — The 8-byte value-encoding optimization that hides a 3-bit tag plus
a ~48-bit payload inside the unused bit patterns of a quiet IEEE-754 NaN, storing
real doubles verbatim. The *measured optimization*, not the baseline: a NaN-box
payload cannot hold a full `i64` (LuaJIT's 52-bit cautionary tale), and Nix `int`
*is* a first-class 64-bit integer, so large ints must be boxed. Favored only inside
homogeneous nursery containers, gated on a measured win. See [value representation](05-value-representation.md).

**NixEval trait** — The Rust trait abstracting the evaluator behind the `aos` CLI:
`instantiate(file, attr) -> DrvPath`, `eval_expr`, etc. Two implementors:
`NixCli` (subprocess `nix-instantiate`, the **permanent** fallback) and
`NixNative` (aos-nix, gated by `AOS_NIX_NATIVE`). See [architecture overview](03-architecture-overview.md)
and [integration with AOS](14-integration-with-aos.md).

**nix-compat** — The crate (from the Snix project, pinned to a git rev) that
provides faithful, already-tested implementations of Nix's on-disk formats —
`Derivation`, ATerm serialization, output-path hashing, store-path parsing.
aos-nix depends on it precisely to inherit `.drv`/store-path parity rather than
re-deriving these formats. Its API is unstable; expect to carry local patches and
upstream fixes. See [derivation and store compatibility](11-derivation-and-store-compatibility.md).

---

## O

**On-stack replacement (OSR)** — HotSpot's technique for *entering* compiled code
in the middle of a long-running activation that began in a lower tier, rather than
waiting for the next call — the dual of deoptimization. In Nix it targets the
dynamic equivalents of hot loops (a deep `foldl'`, a long `genList`, a recursive
`fix`). An advanced measured variant, not a phase-1 requirement. See
[execution tiers and Cranelift](08-execution-tiers-and-cranelift.md).

**Oracle (tier-0 tree-walk)** — The simplest faithful interpreter of Nix semantics,
written in *safe* Rust, walking the arena IR directly. It is the permanent
**correctness reference** (the differential tie-breaker), runs cold/run-once code,
is debuggable, and is the `miri`/sanitizer-checked safe island. Tiers 1/2 must
agree with it bit-for-bit; deopt targets it. See [execution tiers and Cranelift](08-execution-tiers-and-cranelift.md).

**Out-of-core / spill** — The capability, unavailable to C++ Nix's BDW-GC heap, of
letting cold values live *on disk* instead of in RAM: a cold hash-consed value is
dropped from the in-RAM arena, leaving only its content hash, and is rematerialized
on the next access by reading it back from the `mmap`'d **CA store**. Because the
store is content-addressed and immutable, eviction is **write-back-free** (the hash
*is* the address) and the OS page cache does the paging. This converts the
peak-memory bound from "live set must fit in RAM" to "resident working set must fit
in RAM, with the cold tail spilled." Distinct from register/safepoint *spill slots*
in compiled code; this entry is the heap sense. See
[memory management and GC](06-memory-management-and-gc.md) §3.4.

---

## P

**Pointer tagging** — Encoding small state in the spare low bits of an 8-byte-aligned
heap pointer (alignment ≥ 8 leaves the low 3 bits free). aos-nix's chief use is the
thunk **FORCED** bit (bit 0): a re-force of an already-forced thunk becomes a tag
test on a register, skipping the state load and indirect call — GHC's dynamic
pointer tagging. Optionally encodes small-list/small-attrs constructor info.
Sounder than in GHC because a forced Nix value never reverts. See [value representation](05-value-representation.md).

**Precise vs. conservative GC** — A *precise* collector knows the exact type of
every root and heap field (from the value tag), so it can move objects and never
falsely retains garbage; a *conservative* collector (Boehm, used by C++ Nix) treats
any pointer-like stack word as a root, causing false retention and dominating C++
Nix's cost. Replacing Boehm with a precise collector is a named win of the project.
See [memory management and GC](06-memory-management-and-gc.md).

**Primop / builtin** — A Nix `builtins.*` function (~120 total) implemented as a
Rust function and registered as a Cranelift runtime symbol (`nix.builtin.<name>`).
Primops are indistinguishable from lambdas to user code, carry escape signatures
for the analysis, and some (arithmetic, comparison, `derivationStrict`) are
provably strict demand sources. See [primops and runtime ABI](10-primops-and-runtime-abi.md).

---

## R

**ratchet** — The **language-agnostic evaluation engine** factored out of the
aos-nix substrate: the unified demand graph, the *Core IR*, the execution tiers,
the GC, and the value representation — everything that carries no Nix knowledge.
Nix is the first (and, in RFC-0007, only) *dialect* of it. The engine crates are
`ratchet-prefixed` and potentially extractable as standalone crates
(`ratchet-core`, `ratchet-value`, `ratchet-gc`, `ratchet-jit`, `ratchet-cache`,
`ratchet-parallel`, `ratchet-oracle`, `ratchet-dialect`); the Nix band stays
`aos-nix-*`. The template is MLIR (one IR infrastructure, many dialects,
progressive lowering), plus demand-graph memoization MLIR lacks. Adopting it is a
naming/layering decision (`S-22`) that does not change what aos-nix delivers — a
byte-identical Nix evaluator. See
[generalization and language dialects](28-generalization-and-language-dialects.md).

**Region inference** — A static analysis (an advanced measured variant) that assigns
allocations to lexical *regions* freed wholesale when the region exits, reducing
GC pressure for daemon mode by bounding object lifetimes statically. The committed
subset is the *lexical/escape* pass; full effect-based region inference (Tofte–
Talpin) is built and selected in the advanced stack. See
[memory management and GC](06-memory-management-and-gc.md).

**Rewrite RULES / fusion** — The **algebraic, semantics-preserving rewrites** the
simplifier applies during simplification (GHC's `RULES`). The high-value
Nix-specific one is **list fusion**: collapsing `map`/`filter`/`concatMap` chains
that `lib` builds constantly so they traverse once with no intermediate-list
allocation (`map f (map g xs) → map (f∘g) xs`; `length (map f xs) → length xs`).
The same win as GHC's foldr/build (and stream) fusion, here applied to Nix's list
builtins — allocation neither C++ Nix nor Snix removes. Which RULES are enabled is
*measure-gated* (over-eager fusion can pessimize). This is the **simplifier**'s
rewrite machinery, **not** *graph reduction*. See
[laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md) §7.5.2.

---

## S

**Salsa** — The Rust incremental-computation framework (the engine behind
rust-analyzer's durable incrementality) whose *red-green* algorithm and query graph
aos-nix's incremental cache adopts: backward invalidation floods until it reaches a
query whose result is unchanged. One of the named P0 sources. See [incremental evaluation cache](12-incremental-evaluation-cache.md).

**Scalar replacement** — The HotSpot C2 transform (Scalar Replacement of Aggregates)
that *decomposes* a non-escaping aggregate into individual SSA values, so the object
never exists as a coherent structure on heap or stack — its field accesses become
reads of CLIF SSA values. Licensed by escape analysis; far more applicable in Nix
than Java because immutable values rarely escape. See [laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md).

**Shape** — See *Hidden class / shape / map*.

**Simplifier (the)** — aos-nix's **IR-to-IR optimizer**, the direct analogue of
GHC's **Core-to-Core simplifier**, iterated to a fixpoint and interleaved with the
whole-program analyses. It performs the *pure local reductions* that each expose
the next: inlining + beta-reduction, constant folding, **case-of-known** /
select-of-known (`{ a = 1; }.a → 1`), dead-binding elimination, CSE (safe here
because values are immutable and already maximally shared), eta-reduction, and
let-floating — plus algebraic **rewrite RULES** (*fusion*). Run in phases (gentle
early, aggressive late). Always "the simplifier," **never** "graph reduction" (a
distinct, evaluation-time concept). See
[laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md) §7.5.

**SHA-256** — The hash Nix's on-disk format mandates for `.drv` and store-path
hashing. In aos-nix it is used **only** at the `derivationStrict` boundary,
computed from the ATerm serialization of *values* — never for internal sharing or
caching, and no internal (xxh3/blake3) hash may ever leak into it. Non-negotiable
for compatibility. See [derivation and store compatibility](11-derivation-and-store-compatibility.md).

**Snix / Tvix** — The peer Rust Nix evaluator project (Snix is the 2025 fork/rename
of Tvix). `snix-eval` is a bytecode-VM evaluator that defers optimization until
nixpkgs-correct; it has no hash-consing, no strictness analysis, and no
`.drv`-parity guarantee. aos-nix reuses its `nix-compat` crate and its conformance
test approach while differing in execution model. See [prior art and references](16-prior-art-and-references.md).

**Speculative parsing / compilation** — Doing front-end work (parse, less eagerly
pre-compile) on **idle workers ahead of the demand** that will force it, prefetching
along *statically-known* import edges (a literal `import ./foo.nix` is a static edge
readable from the AST) so the IR is warm in the cache when the thunk forces. Sound
*only* for **pure** nodes and *only* under **error quarantine** (a speculative
failure is stashed, never raised, until genuine demand re-raises it). Bounded (idle
cores only, capped depth) and **measure-gated** in its aggressiveness. The front-end
analogue of CPU speculative execution. See
[frontend, parser and IR](04-frontend-parser-and-ir.md) §9.6.

**Spill** — See *Out-of-core / spill* (heap sense). In compiled code, "spill" also
names the ordinary register-allocator move of a value to a stack slot at a
safepoint; context disambiguates.

**String context** — The set of store-path dependencies a Nix string carries.
Interpolating a derivation into a string records the dependency; when
`derivationStrict` reads the string, the context becomes an input edge. String
operations union contexts; `unsafeDiscardStringContext`/`getContext`/
`addDrvOutputDependencies` manipulate them. **Must match C++ Nix exactly** or the
derivation gets different inputs and a different store path. Represented as an
interned COW bitset of store-path ids, included in the string's cons key. See [value representation](05-value-representation.md).

**Store path** — A `/nix/store/<hash>-<name>` path naming a derivation or its
output, with the hash computed (SHA-256) input- or content-addressed. Producing
store paths byte-identical to C++ Nix is half the output contract; any divergence
is a total cache miss. See [derivation and store compatibility](11-derivation-and-store-compatibility.md).

**Strictness / demand analysis** — The GHC-derived whole-program analysis that proves
a binding is *always* evaluated when its context is ("evaluated at least once"),
licensing **eager** lowering with zero thunk allocation. Computed as a backward
demand fixpoint from strict primops and `derivationStrict`. *Exact* in aos-nix (not
a conservative approximation) because the whole program is a closed batch. Eager
lowering is licensed only by positive proof, never heuristic, so it can never force
a should-be-lazy `throw`. See [laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md).

**Symbol interning** — Mapping each attribute name (and store-path id) to a small
`u32` so attr keys, shapes, and string contexts compare and hash as integers rather
than strings. A prerequisite for cheap hidden classes and context bitsets. See [value representation](05-value-representation.md)
and [attribute sets, hidden classes and inline caches](09-attribute-sets-hidden-classes-and-inline-caches.md).

---

## T

**Tagged value** — The first-cut (and tree-walk-oracle) value encoding: a 16-byte
tagged union of an 8-byte tag/discriminant word and an 8-byte payload, with every
`i64`, `f64`, and pointer inline. Chosen over an 8-byte NaN-box as the baseline
because Nix's first-class `i64` cannot fit a NaN-box payload. The tag travels *with*
the value in a register pair, so compiled code learns a value's type without a heap
load. See [value representation](05-value-representation.md).

**Thunk** — The runtime embodiment of laziness: a heap object `(code_ptr,
captured_env, state)` representing a suspended computation that, when forced,
produces a WHNF value. **Not** a user-visible Nix type (`typeOf` never returns
`"thunk"`). The state machine is monotonic and idempotent. **One model, two
subsets:** serial `Suspended → Blackhole → Forced`; parallel superset
`Suspended → Pending → Awaited → Forced/Failed` (claimed via a `CAS` on the state
word — *compare-and-swap*, not the CA store), with `Blackhole` retained for
same-thread cycle detection. Strictness/cardinality analysis can shrink or *delete*
the thunk entirely (eager lowering, single-entry, dead-code elimination). See
[value representation](05-value-representation.md),
[parallel evaluation](13-parallel-evaluation.md), and
[laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md).

**Tree-walking** — See *Bytecode VM vs. tree-walking* and *Oracle*.

---

## U

**Uncommon trap** — See *Deoptimization / uncommon trap*.

**Usage analysis** — See *Cardinality analysis*.

---

## W

**WHNF (weak head normal form)** — The form a value reaches when its *outermost*
constructor is known — an int is an int, a list is a list even if its elements are
still thunks. Forcing drives a value to WHNF and no further (Nix is *weak head*
lazy, like GHC). The hot path of any lazy evaluator is re-forcing an already-WHNF
value; making "is this WHNF?" a single register tag test (tagged value) or pointer
bit test (FORCED tag) is the core of cheap laziness. See [value representation](05-value-representation.md).

**Work-stealing** — The scheduling discipline of aos-nix's parallel forcing pool:
each worker owns a **Chase-Lev** lock-free deque, pushing/popping its own end and
*stealing* from the opposite end of a victim's deque when idle. It is the structure
underlying **rayon** and most modern task runtimes, and the same load-balancing GHC
uses for sparks — so a thread that would block on a thunk claimed by another worker
(`Pending`/`Awaited`) can instead steal unrelated work and stay busy. Here
work-stealing is the **CPU** concern (rayon); eval-time blocking **I/O** is the
tokio reactor's (see *Fiber*). See [parallel evaluation](13-parallel-evaluation.md)
§4.2 and §5.5.

**Worker-wrapper** — GHC's transform that exploits strictness/absence information by
splitting a function into a **worker** (`$wf`, taking strict arguments already
evaluated/unboxed, with absent arguments dropped) and a thin always-inlined
**wrapper** (the original lazy convention, forcing the strict args and tail-calling
the worker). For a derivation core this yields zero thunks and straight-line code.
See [laziness and whole-program analyses](07-laziness-and-whole-program-analyses.md).

---

## X

**xxh3 / xxHash** — The fastest non-cryptographic hash (multi-GB/s), used for
*in-process* cons-table keys and hot value/cache-key probes. Non-cryptographic is
fine here because collisions are caught by the table's structural-equality fallback
(a collision risks only a recompute, never a wrong answer). Never durable, never
shared across machines (that is blake3's job), never in `.drv` output. See [value representation](05-value-representation.md)
and [incremental evaluation cache](12-incremental-evaluation-cache.md).

---

## Design-language and prior-art map

aos-nix is a *synthesis* of techniques proven in other systems, made sound here by
Nix's purity and value immutability. This table is the implementor's Rosetta stone:
each row pins an aos-nix concept to its **canonical term** and the **origin system
or paper an implementor should study** — *if you've seen X in system Y, that is what
this is.* The middle column is the lexicon entry that governs; the right column is
where to learn the technique in its native habitat (read the origin, then the owning
RFC section for how aos-nix adapts it).

| aos-nix concept | Canonical term (lexicon entry) | Origin to study — system / paper |
|---|---|---|
| The incremental engine *is* the evaluator | **the demand graph** / *demand-graph node* | Salsa & rust-analyzer (red-green query graph); Adapton DCG (Hammer et al., PLDI 2014); *Build Systems à la Carte* (Mokhov et al., ICFP 2018) |
| One graph for parse + compile + force | **unified demand graph** | Salsa (lex/parse/name-res/type-infer all queries in one graph) |
| Unchanged recompute halts propagation | **early cutoff** | Adapton; Skip language (early cutoff by construction); Salsa red-green; *Build Systems à la Carte* verifying traces |
| IR-to-IR fixpoint optimizer | **the simplifier** | GHC **Core-to-Core** simplifier (Peyton Jones & Santos, "A transformation-based optimiser for Haskell") |
| Algebraic rewrites; collapse list pipelines | **rewrite RULES / fusion** | GHC `RULES`; foldr/build & stream fusion (Gill–Launchbury–Peyton Jones; Coutts–Leshchinsky–Stewart) |
| Prove "always forced" → eager, no thunk | **strictness / demand analysis**; **worker-wrapper**; **cardinality analysis**; **full-laziness** | GHC demand analyser, worker/wrapper split, let-floating (Peyton Jones, Partain & Santos, ICFP '96) |
| Attrset layout shared by key-shape | **hidden class / shape / map** | V8 hidden classes (a.k.a. shapes/maps); Self maps |
| Per-site `shape → offset` cache | **inline cache** (mono/poly/megamorphic) | V8 / Self / SpiderMonkey inline caches |
| Cheap incremental key for attrs | **HAMT**; **symbol interning** | Bagwell HAMT; symbol/atom interning |
| Tier-up + speculate + bail out | **tiered JIT**; **deoptimization / uncommon trap**; **on-stack replacement (OSR)** | HotSpot (C1/C2, uncommon traps, OSR) |
| 8-byte value encoding + tag-in-NaN | **NaN-boxing** / **tagged value**; tracing context | LuaJIT (NaN-boxing; trace-based JIT) |
| State in spare pointer bits; closure entry | **pointer tagging**; **graph reduction** | GHC dynamic pointer tagging; the **STG** machine (Spineless Tagless G-machine) |
| Move-collect short-lived thunks; exact roots | **generational GC**; **precise vs. conservative GC** | GHC generational copying GC; HotSpot generational GC (vs. Boehm conservative GC, C++ Nix) |
| Lexical-lifetime allocation, freed wholesale | **region inference** | Tofte–Talpin region inference (region-based memory management) |
| Lock-free deque load balancing | **work-stealing** | Chase–Lev deque; **rayon** (its industrial Rust form) |
| Suspend an I/O-blocked node, free the worker | **fiber** (stackful coroutine, M:N) | stackful coroutines / green threads; tokio reactor for the I/O side |
| Fast warmup native backend | **Cranelift**; **CLIF** | Cranelift in **Wasmtime**; `rustc_codegen_cranelift` |
| Collapse equal values to one allocation | **hash-consing / maximal sharing** | classic hash-consing; ATerm maximal sharing (van den Brand et al.) |
| Name cache/store entries by content hash | **content-addressed (CA)** / **the CA store** | Git object store; Attic / `snix-castore` (and contrast **CAS** = compare-and-swap) |
| Inherit Nix on-disk formats verbatim | **nix-compat**; **ATerm**; **derivation / `.drv`** | Nix (`.drv`/ATerm/store paths); **Snix**'s `nix-compat` crate (depended upon, pinned) |

For the long-form treatment of each lineage — what aos-nix keeps, drops, and why
purity makes a partial technique total — see [prior art and references](16-prior-art-and-references.md).
