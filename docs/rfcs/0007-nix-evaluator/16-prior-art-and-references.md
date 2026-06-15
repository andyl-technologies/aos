# RFC-0007 - Prior art and references

This document is the citation-backed survey beneath the rest of RFC-0007. The
[architecture overview](03-architecture-overview.md) makes a single load-bearing
claim — that a fast Nix evaluator is the *disciplined assembly of known-good
techniques*, not a research program — and the credibility of that claim rests
entirely on the techniques being real, mature, and applicable. This document is
where each borrowed idea is named, traced to the production system or paper it
comes from, reduced to a one-line *what we take*, and pinned to a verified source
URL.

It is organized as a catalogue. Each entry answers three questions: **what is
the system or result, what specifically does aos-nix take from it, and where is
the evidence.** The synthesis thesis is argued elsewhere; here we only establish
that the parts exist and behave as the rest of the RFC assumes. Where a claim
could not be verified to a specific number or date, it is stated qualitatively
and flagged as such — the rule for this document is *no fabricated citation, no
invented figure*.

Read this alongside the four documents whose technique choices it substantiates:
the [architecture overview](03-architecture-overview.md) (the synthesis map),
[execution tiers and Cranelift](08-execution-tiers-and-cranelift.md) (the JIT
ancestry), [incremental evaluation cache](12-incremental-evaluation-cache.md)
(the P0 lineage), and the [laziness analyses](07-laziness-and-whole-program-analyses.md).

> **Framing invariant.** aos-nix is an *eval-only* evaluator: it replaces the
> path from `.nix` source to a `.drv` graph and must emit **byte-identical**
> `.drv` files and store paths to C++ Nix (SHA-256, differential-harness-gated;
> see [compatibility constraints](02-compatibility-constraints.md)). The
> baseline it must *beat* is **C++ Nix**, which is genuinely fast — not Haskell,
> not a toy. The backend is **Cranelift**, not LLVM or WASM. The biggest single
> systemic win is the **incremental early-cutoff cache**, not any constant-factor
> JIT improvement. Every entry below is selected against those invariants.

---

## 1. The Nix-implementation landscape: what already exists

Before mining other language runtimes, we situate aos-nix against the other Nix
implementations. Three matter: the C++ reference (the baseline to beat), the
Rust reimplementation lineage Tvix -> Snix (whose `nix-compat` we depend on and
whose architecture we both learn from and deliberately diverge from), and hnix
(the cautionary data point).

### 1.1 C++ Nix — the fast reference baseline to *beat*

C++ Nix (`NixOS/nix`) is the reference implementation and the thing the
[acceptance gate](02-compatibility-constraints.md) diffs against. It is a
**tree-walking AST interpreter**: after parsing, a `bindVars()` pass resolves
variable references to environment positions via a `StaticEnv`, then evaluation
directly traverses the AST.

> **What we take.** The semantics we must reproduce bit-for-bit, *and* the cost
> structure we must beat. Specifically we adopt the parts of its design that the
> compatibility contract makes mandatory and treat the rest as the performance
> target:
>
> - **Symbol interning.** Identifiers are interned to integer symbols; attribute
>   sets are keyed and compared on those symbols. aos-nix interns identically
>   (see [value representation](05-value-representation.md)).
> - **Sorted `Bindings`.** Attribute sets store bindings in a sorted-by-symbol
>   layout, which is *why* iteration order is deterministic and observable — a
>   property the [hidden-class model](09-attribute-sets-hidden-classes-and-inline-caches.md)
>   must preserve to keep `derivationStrict` byte-identical.
> - **String contexts.** Strings carry a *context* set (the store paths a string
>   depends on); context propagation is part of the `.drv` contract
>   ([derivation and store compatibility](11-derivation-and-store-compatibility.md)).
> - **Static scope resolution (`bindVars`/`StaticEnv`).** The pre-evaluation
>   binding pass that aos-nix mirrors as static slot indices
>   ([frontend, parser and IR](04-frontend-parser-and-ir.md)).
> - **The flake evaluation cache.** Nix's flake mode already caches evaluation
>   results in a per-user SQLite database keyed on a fingerprint of the flake
>   closure plus the attribute path; a warm `nix shell nixpkgs#firefox` drops
>   from ~0.39s to ~0.03s. This is *prior art for caching eval outputs* — but it
>   is coarse (whole-attribute, flake-scoped, local-only) and lacks early
>   cutoff. aos-nix's [incremental cache](12-incremental-evaluation-cache.md)
>   is the fine-grained, cross-machine generalization.
> - **CA derivations.** Content-addressed derivations bring *build-layer* early
>   cutoff to Nix (stop a rebuild when the output content is provably unchanged).
>   This is the build-graph mirror of our eval-graph early cutoff and shares the
>   content-addressed discipline.

The dominant *cost* we attack is the **Boehm conservative garbage collector**.
C++ Nix's evaluation memory (values, environments, strings) is allocated through
Boehm GC; its imprecision (any stack word that *looks* like a pointer is treated
as a root) both retains garbage and is a dominant runtime cost. Replacing Boehm
with a precise collector ([memory management and GC](06-memory-management-and-gc.md))
is one of the named wins of the whole project.

| C++ Nix feature | aos-nix relationship | Document |
|-----------------|----------------------|----------|
| Symbol interning | adopted (mandatory for attr identity) | [05](05-value-representation.md) |
| Sorted `Bindings`, observable order | adopted + shape-modeled | [09](09-attribute-sets-hidden-classes-and-inline-caches.md) |
| String contexts | adopted (drv contract) | [11](11-derivation-and-store-compatibility.md) |
| `bindVars`/`StaticEnv` scope resolution | adopted as slot indices | [04](04-frontend-parser-and-ir.md) |
| Flake SQLite eval cache | superseded by fine-grained CA value store | [12](12-incremental-evaluation-cache.md) |
| CA derivations early cutoff | mirrored at eval layer | [12](12-incremental-evaluation-cache.md) |
| Boehm conservative GC | **replaced** by precise GC | [06](06-memory-management-and-gc.md) |
| Tree-walking interpreter | matched by tier-0 oracle, beaten by JIT | [08](08-execution-tiers-and-cranelift.md) |

Sources: Nix evaluation engine, `bindVars`/`StaticEnv`, Boehm GC allocation —
<https://deepwiki.com/NixOS/nix/2.1-evaluation-engine>; Boehm-GC build option /
dependence — <https://github.com/NixOS/nix/issues/6250>; string-context indirection
and interning discussion — <https://git.snix.dev/snix/snix/issues/122>; flake eval
cache (SQLite, fingerprint, 0.39s->0.03s) — <https://www.tweag.io/blog/2020-06-25-eval-cache/>;
CA derivations early cutoff — <https://wiki.nixos.org/wiki/Ca-derivations> and
RFC 0062 <https://github.com/NixOS/rfcs/blob/master/rfcs/0062-content-addressed-paths.md>.

### 1.2 Tvix -> Snix — the Rust reimplementation we depend on and diverge from

Tvix is a from-scratch Rust reimplementation of Nix that originated in the TVL
(`tvl.fyi`) monorepo. Unlike C++ Nix's tree-walk, **Tvix compiles the parsed Nix
AST to a compact, Nix-specific bytecode and executes it on a custom abstract
machine (a bytecode VM)**, performing in-depth scope analysis at compile time so
identifier access is efficient and some errors surface before runtime.

In **March 2025** the project was forked and renamed **Snix**, moving to
dedicated infrastructure (`snix.dev`, `git.snix.dev`) after differing priorities
within Tvix development; the Snix launch was announced **2025-03-16**. The Rust
crate set is the same lineage: `snix-eval` (the evaluator / bytecode VM),
`snix-castore` (content-addressed store, not Nix-specific), `snix-store`,
`snix-glue` (store/builder-interacting builtins, keeping `snix-eval` simple),
`snix-cli`, `snix-serde`, and — critically for us — **`nix-compat`**, a library
exposing Nix data types, formats, and protocols (store paths, NAR, ATerm
derivations, hashing).

> **What we take.**
>
> - **`nix-compat` as the L1 compatibility firewall.** We depend on `nix-compat`
>   (pinned to a git rev) for ATerm `.drv` serialization, store-path hashing, and
>   the other on-disk/wire formats, precisely so we inherit a faithful,
>   already-tested implementation rather than re-deriving the byte formats. Its
>   APIs are explicitly *unstable* — Snix's CLI and crate APIs are works in
>   progress — so we expect to carry local patches and upstream fixes (see the
>   pin-and-upstream policy in [11](11-derivation-and-store-compatibility.md)).
> - **The conformance-suite practice.** Snix reuses the C++ Nix language test
>   suite to validate evaluation; aos-nix does the same alongside its
>   differential `.drv` harness ([differential testing](15-differential-testing-and-benchmarking.md)).
> - **Confirmation that a Rust Nix evaluator is viable and adoptable.** devenv
>   announced (2024-10-22, with a NixCon 2024 talk) that it was switching its Nix
>   implementation to tvix-eval, motivated by C++ Nix's monolithic,
>   non-library-shaped C FFI and memory-safety concerns — the same library-shaped,
>   memory-safe motivation aos-nix shares. (devenv later tracked Snix evaluation
>   as the project renamed.)

> **Where we diverge — and why this is not "just rewrite Tvix".**
>
> - **Architecture: bytecode VM vs. tiered tree-walk + JIT.** Snix executes a
>   bytecode VM. aos-nix uses a tree-walk *oracle* (tier 0) plus a Cranelift
>   JIT (tiers 1-2) — a different point in the design space chosen for the
>   expression-vs-activation ratio ([08](08-execution-tiers-and-cranelift.md)).
> - **Performance posture is explicitly deferred in Tvix/Snix.** Early Tvix
>   microbenchmarks against C++ Nix (on the subset of features then ready) were
>   reported as roughly an **order of magnitude faster** — but the project
>   **disclaims any real-world relevance**: those benchmarks are "in no way
>   indicative of real-life performance for things like nixpkgs," and Tvix
>   deliberately **avoids fine-grained optimization until it evaluates all of
>   nixpkgs correctly** (correctness-first). aos-nix takes the opposite-ordered
>   bet only *after* parity: it is measure-first and parity-gated, and treats the
>   incremental cache (not raw interpreter speed) as the dominant lever.
> - **No `.drv`-parity guarantee from Snix.** Snix does not promise byte-identical
>   `.drv`/store-path output to C++ Nix as a hard, harness-enforced gate. For
>   aos-nix that parity *is* the acceptance gate ([02](02-compatibility-constraints.md)).
>   This is the single most important divergence: we cannot adopt any Snix design
>   choice that trades away `.drv` byte-identity.

| Snix component | aos-nix use |
|----------------|-------------|
| `nix-compat` | **depended upon** (pinned rev) for ATerm/NAR/store-path/hashing |
| C++ Nix language test suite (reused by Snix) | **reused** as conformance suite |
| `snix-eval` bytecode VM | **studied, not adopted** (we tier a tree-walk + JIT) |
| `snix-castore`/`snix-store` | informs the content-addressed eval cache shape |
| correctness-first, optimization-deferred posture | **inverted post-parity** (measure-first) |

Sources: Snix announcement and rename (2025-03-16, differing priorities) —
<https://snix.dev/blog/announcing-snix/>; component overview (`nix-compat`,
`snix-castore`, `snix-store`, `snix-glue`, `snix-cli`, `snix-serde`) —
<https://snix.dev/docs/components/overview/>; Snix repo description (modern Rust
re-implementation) — <https://git.snix.dev/snix/snix>; Tvix bytecode VM /
scope analysis / "order of magnitude faster but not indicative of nixpkgs" /
"avoiding fine-grained optimization until correct" — tvix/eval README
<https://code.tvl.fyi/about/tvix/eval/README.md?id=be32ab1eb2b60bf028c32954d1a6a5d09c6d2f9c>;
devenv switch to Tvix (2024-10-22, motivations) —
<https://devenv.sh/blog/2024/10/22/devenv-is-switching-its-nix-implementation-to-tvix/>
and discourse <https://discourse.nixos.org/t/devenv-is-switching-nix-implementation-to-tvix/54753>;
devenv tracking Snix evaluation — <https://github.com/cachix/devenv/issues/1548>;
`nix-compat` API instability — issue tracker at <https://git.snix.dev/snix/snix>.

### 1.3 hnix — the cautionary data point

hnix is a Haskell implementation of the Nix language, designed primarily so
Haskell authors can build *tooling* around Nix, and as a result it leans heavily
on abstraction (customizable behavior at many points). That abstraction has a
performance cost: reported figures show hnix **parsing** `all-packages.nix` in
~6.9s versus C Nix's ~0.36s, and an **evaluation** taking ~1.125s versus
`nix-instantiate`'s ~0.089s on the same expression — roughly an order of
magnitude slower on both axes.

> **What we take.** A *negative* lesson, restated in [03 §1.2](03-architecture-overview.md):
> **language choice is not the performance lever.** hnix is written in Haskell —
> the canonical "fast lazy functional" language — and is nonetheless markedly
> *slower* than C++ Nix. This is the direct refutation of "rewrite it in
> $FAST_LANGUAGE and it gets fast." The lever is the *technique stack*
> (laziness made cheap, shapes, precise GC, tiered codegen, caching), not the
> host language. hnix is the evidence that we must beat C++ Nix on technique, and
> may not assume a Rust (or Haskell) rewrite wins by default.

Sources: hnix parse/eval performance figures —
<https://github.com/haskell-nix/hnix/issues/200> and
<https://github.com/haskell-nix/hnix/issues/16>; hnix design (tooling-oriented,
abstraction-heavy) — <https://github.com/haskell-nix/hnix/wiki/Design-of-the-HNix-code-base>;
package — <https://hackage.haskell.org/package/hnix>.

---

## 2. Laziness made cheap — GHC (P1)

Nix is lazy. A naive evaluator allocates a heap thunk for every unforced
subexpression and pays update/blackhole machinery on each force. GHC spent
decades making laziness nearly free, and *neither C++ Nix nor Snix applies those
whole-program analyses*. This is the P1 prior-art source.

### 2.1 The Spineless Tagless G-machine (STG)

GHC's execution model is the **Spineless Tagless G-machine**. It is "spineless"
(the graph is a set of small interlinked heap objects, not one monolithic
structure), "tagless" (all heap values — unevaluated thunks, functions, and
already-evaluated values — are represented uniformly as closures entered through
a code pointer), and graph-reducing (a heap object may be overwritten by a
simpler equivalent once computed, e.g. `1+1` becomes `2`).

> **What we take.**
>
> - **The uniform closure / thunk representation and the entered-via-code-pointer
>   model.** aos-nix's thunk is `(code_ptr, captured_env, state)` and forcing
>   *enters* `code_ptr` — directly the STG closure-entry idea, specialized to a
>   monotonic `Suspended -> Blackhole -> Forced` state machine
>   ([03 §3.2](03-architecture-overview.md), [08 §1.2](08-execution-tiers-and-cranelift.md)).
> - **The black hole.** STG's self-reference detector becomes our `Blackhole`
>   state; Nix programs rely on the *infinite-recursion* error, which the harness
>   diffs, so it is mandatory, not optional.
> - **Pointer tagging.** GHC encodes evaluatedness / small-constructor info in the
>   spare low bits of a pointer, so testing whether a value is already in WHNF is
>   a bit test rather than a memory load plus indirect jump. aos-nix uses the same
>   trick so the `Forced` arm of `force` degenerates to a tag check
>   ([value representation](05-value-representation.md)).

Sources: STG version 2.5 (the definitive paper) —
<https://www.microsoft.com/en-us/research/wp-content/uploads/1992/04/spineless-tagless-gmachine.pdf>;
spineless/tagless/graph-reducing exposition and pointer-tagging (spare low bits)
— <https://jozefg.bitbucket.io/posts/2014-10-28-stg.html> and
<https://www.arbertrary.dev/stgm-presentation/stgm-deck.html>.

### 2.2 Demand / strictness analysis + worker-wrapper

GHC's **demand analyser** determines what demand a function places on its
arguments. If an argument is scrutinised on every code path, the function is
*strict* in it, and GHC may use call-by-value and pass the argument **unboxed**.
The results drive the **worker-wrapper transformation**, which splits each
function into a *wrapper* (ordinary calling convention, an impedance matcher) and
a *worker* (a specialised, often-unboxed calling convention) — and the
worker-wrapper transform is precisely how unboxing is implemented.

Demand analysis also subsumes **usage / cardinality analysis**: strictness is
"evaluated at least once"; usage asks "evaluated at most once" (a single-entry
thunk needs no memoisation/update machinery — call-by-name suffices) or "at most
zero times" (an *absent* binding generates no code at all, replaced by a dummy at
the call site). A modern refinement (boxity analysis) tracks whether a parameter
must stay boxed to avoid reboxing.

> **What we take** (detailed in [laziness analyses](07-laziness-and-whole-program-analyses.md)):
>
> - **Strictness/demand -> eager compilation.** Bindings provably always-forced
>   compile eagerly with zero thunk allocation, via a worker-wrapper-style split
>   that tier 2 can inline ([08 §2.3](08-execution-tiers-and-cranelift.md)).
> - **Cardinality 0/1/many.** Used-at-most-once bindings skip blackhole/update
>   machinery; used-zero bindings are dead-code-eliminated. This *also* sharpens
>   the [incremental cache](12-incremental-evaluation-cache.md) by narrowing the
>   free-variable set that environment hashing must cover.
> - **The purity upgrade.** GHC's demand analysis is bounded by separate
>   compilation (cross-module demand is conservative). Nix evaluation is a
>   *whole-program batch*: the entire expression closure is visible at once, so
>   the analysis is total over the batch ([03 §1.1](03-architecture-overview.md)).

Sources: *Theory and Practice of Demand Analysis in Haskell* (Sergey,
Vytiniotis, Peyton Jones, et al.) —
<https://www.microsoft.com/en-us/research/wp-content/uploads/2017/03/demand-jfp-draft.pdf>;
GHC user's guide optimisation flags (strictness, worker-wrapper) —
<https://downloads.haskell.org/ghc/9.12.1/docs/users_guide/using-optimisation.html>;
usage/cardinality and absence analysis exposition —
<https://fixpt.de/blog/2018-12-30-strictness-analysis-part-2.html>.

### 2.3 GHC's runtime: generational GC and full laziness

GHC pairs the STG model with a **generational copying collector** (most objects
die young; a small nursery is collected frequently) and the **full-laziness /
let-floating** transform (hoist a constant subexpression out of a lambda so a
thunk built inside a loop is computed once, not per iteration).

> **What we take.** The generational hypothesis, which holds in an *extreme* form
> for Nix (intermediate thunks built during forcing die almost immediately) and
> motivates the daemon-mode **precise generational copying collector**
> ([06](06-memory-management-and-gc.md)); and full-laziness / let-floating as a
> P1 follow-up ([07](07-laziness-and-whole-program-analyses.md)). GHC sparks
> (its parallelism primitive) inform [parallel forcing](13-parallel-evaluation.md).

Source: STG paper and GHC optimisation guide as above; the generational
collector and full-laziness are standard GHC features documented in the user's
guide <https://downloads.haskell.org/ghc/9.12.1/docs/users_guide/using-optimisation.html>.

---

## 3. Tiered compilation, deopt, and precise GC — HotSpot / the JVM (P3, P4)

The JVM's HotSpot VM is the canonical tiered-JIT-with-deoptimization system and
the direct ancestor of aos-nix's execution-tier model and its precise-GC ambition.

### 3.1 Tiered compilation and on-stack replacement

HotSpot runs methods first in an **interpreter**, profiles them, and promotes hot
methods through compiled tiers (the C1 "client" and C2 "server" compilers),
with **on-stack replacement (OSR)** to enter compiled code in the middle of a
long-running loop rather than waiting for the next call.

> **What we take.** The whole tier model ([08](08-execution-tiers-and-cranelift.md)):
> tier 0 (tree-walk oracle = interpreter), tier 1 (Cranelift baseline = C1-like,
> fast compile, no speculation), tier 2 (Cranelift optimized = C2-like,
> speculative). We collapse C1/C2 onto one backend (Cranelift) at two
> optimization levels. OSR is adopted as a *measured follow-up* for the dynamic
> equivalents of hot loops (deep `foldl'`, long `genList`, iterated `fix`).

Source: "How Tiered Compilation works in OpenJDK" (interpreter -> C1 -> C2, OSR,
`osr_bci`) — <https://devblogs.microsoft.com/java/how-tiered-compilation-works-in-openjdk/>;
introductory C2 internals — <https://eme64.github.io/blog/2024/12/24/Intro-to-C2-Part01.html>.

### 3.2 Deoptimization and uncommon traps

HotSpot speculates and *guards*: it can stop executing a method's machine code
and transfer control back to the interpreter — **deoptimization** — at a
**deoptimization point known as an uncommon trap**, recovering program state and
resuming in bytecode when an optimistic assumption is proven wrong.

> **What we take.** The "assume, guard, fall back" discipline is the backbone of
> tier 2 ([08 §3](08-execution-tiers-and-cranelift.md)): each speculation pairs a
> guard with an uncommon-trap edge that reconstructs the abstract state and
> **resumes in the tier-0 oracle**. **Purity sharpens this dramatically**: in Nix
> there are no side effects partially performed before the trap, so deopt is pure
> state reconstruction with *no rollback* — the entire class of HotSpot
> deopt-around-partial-stores bugs does not exist here.

Source: deoptimization / uncommon trap definition — Kotzmann & Mössenböck,
"Escape Analysis in the Context of Dynamic Compilation and Deoptimization"
<https://dl.acm.org/doi/10.1145/1064979.1064996>; OpenJDK `deoptimization.cpp` —
<https://github.com/openjdk/jdk/blob/master/src/hotspot/share/runtime/deoptimization.cpp>;
overview — <https://www.w3computing.com/articles/jvm-jit-compiler-deep-dive-c1-c2-tiered-compilation/>.

### 3.3 Escape analysis + scalar replacement (and reallocation on deopt)

HotSpot's C2 performs **escape analysis**: an object that cannot be observed by
another method or thread does not *escape*, which licenses **scalar replacement**
(keep its fields in registers/stack slots instead of heap-allocating it), stack
allocation, and synchronization elision. Crucially, because the interpreter does
not know about scalar replacement, the **deoptimization framework was extended to
reallocate (and relock) objects on demand** when execution falls back.

> **What we take.** Escape-analyzed scalar replacement of non-escaping
> attrsets/thunks in tier 2 ([07](07-laziness-and-whole-program-analyses.md),
> [08 §2.3](08-execution-tiers-and-cranelift.md)), *and* the matching
> **materialization-on-deopt** obligation: if tier 2 eliminated an allocation,
> the deopt path must rebuild the real heap object before re-entering tier 0
> ([08 §3.2](08-execution-tiers-and-cranelift.md), flagged as the subtlest tier-2
> item, with a conservative "don't scalar-replace across a deopt point" initial
> policy). **Purity again helps**: Nix values are immutable and identity-free, so
> far more objects provably don't escape than in Java, where mutable aliasing and
> reflection defeat the analysis.

Source: Kotzmann & Mössenböck, escape analysis in dynamic compilation and
deoptimization, with on-demand reallocation/relocking —
<https://dl.acm.org/doi/10.1145/1064979.1064996>; HotSpot EA/SR status —
<https://cr.openjdk.org/~cslucas/escape-analysis/EscapeAnalysis.html>;
escape analysis overview — <https://en.wikipedia.org/wiki/Escape_analysis>.

### 3.4 Low-pause collectors: G1, ZGC, Shenandoah

The modern JVM collectors are the reference for low-pause, moving, region-based
GC. **G1** is region-based with configurable pause targets. **Shenandoah**
performs fully concurrent compaction (historically via Brooks pointers), keeping
pauses in the sub-10ms range even on very large heaps. **ZGC** uses **colored
pointers** (state embedded in pointer bits) plus load barriers to guarantee
sub-10ms pauses largely independent of heap size.

> **What we take.** The design vocabulary for daemon-mode GC
> ([06](06-memory-management-and-gc.md), [13](13-parallel-evaluation.md)):
> region-based collection (G1), and colored-pointer + load-barrier concurrent
> collection (ZGC/Shenandoah) as the model for a future low-pause daemon
> collector. This is explicitly the **hardest open coupling** in the design —
> concurrent moving GC interacting with the monotonic thunk-update protocol and
> JIT-emitted load barriers — and is *out of scope for the first cut*, which uses
> a single-threaded precise generational collector (daemon) or a never-free
> bump arena (CLI). The CLI path sidesteps GC entirely.

Source: G1 vs ZGC vs Shenandoah comparison (regions, Brooks pointers, colored
pointers, sub-10ms pauses) —
<https://www.javacodegeeks.com/2025/08/java-gc-performance-g1-vs-zgc-vs-shenandoah.html>;
Java performance overview — <https://javapro.io/2025/04/07/hitchhikers-guide-to-java-performance/>.

---

## 4. Shapes, inline caches, and value boxing — V8 and LuaJIT (P2)

The attribute set is the single hottest data structure in nixpkgs-scale
evaluation, and its access pattern is structurally identical to JavaScript object
property access. V8 and LuaJIT are the P2 sources.

### 4.1 V8 — hidden classes (maps) and inline caches

V8 gives objects with the same keys in the same order a shared **hidden class**
(internally a **Map**), an object-shape descriptor. Property access is optimized
by **inline caches** at each access site, which progress through states as they
observe shapes: **uninitialized -> monomorphic -> polymorphic -> megamorphic**.
Monomorphic (one shape seen) checks the cached hidden class and loads at a
remembered offset — extremely fast; polymorphic caches a small set (typically up
to 4); **megamorphic** (more than four shapes) abandons site-level optimization.

> **What we take** ([attribute sets, hidden classes and inline caches](09-attribute-sets-hidden-classes-and-inline-caches.md)):
> the hidden-class model for attrsets (same keys/order -> shared shape), so
> `attrs.field` becomes a shape-check plus a constant-offset load, and the
> per-site inline cache with the same monomorphic/polymorphic/megamorphic state
> machine. **The Nix twist**: iteration order is *observable* and must match C++
> Nix byte-for-byte (it feeds `derivationStrict`), so our shape model carries a
> deterministic ordering invariant V8 does not need — shape transitions must
> preserve sorted/insertion order. **Purity sharpens it**: V8 must defend hidden
> classes against runtime mutation (properties added later); Nix values are
> immutable, so a value's shape is fixed for its lifetime and a tier-2 shape
> guard can only fail across *different* values, never via mutation.

Source: V8 "Maps (Hidden Classes)" docs — <https://v8.dev/docs/hidden-classes>;
IC states (monomorphic/polymorphic/megamorphic, >4 = megamorphic) —
<https://braineanear.medium.com/the-v8-engine-series-iii-inline-caching-unlocking-javascript-performance-51cf09a64cc3>
and <https://medium.com/@yashschandra/hidden-v8-optimizations-hidden-classes-and-inline-caching-736a09c2e9eb>.

### 4.2 LuaJIT — NaN-boxing and the tracing JIT

LuaJIT pairs an assembler interpreter with a **tracing JIT** (it discovers hot
*traces* of execution, not hot methods, and compiles them to native code via an
SSA IR). Its value representation uses **NaN-boxing**: all values are packed into
a 64-bit double, with non-double values encoded inside the bit patterns NaN
leaves unused.

> **What we take.** NaN-boxing as the *candidate* compact value representation
> ([value representation](05-value-representation.md)). It is taken with an
> explicit caveat: **Nix integers are `i64` and do not fit a NaN-box payload**
> (which has room for a pointer, not a full 64-bit int), forcing a boxed-int
> fallback. The first cut is therefore a **16-byte tagged value**; whether
> NaN-boxing's register-passing win survives the boxed-int tax is an **open,
> measured** question ([05](05-value-representation.md), [08 §10](08-execution-tiers-and-cranelift.md)).
> We do **not** adopt LuaJIT's *tracing* model — aos-nix is a method-style
> (per-expression) JIT, matching the bounded-expression/unbounded-activation
> ratio ([08 §1](08-execution-tiers-and-cranelift.md)).

Source: LuaJIT tracing JIT and SSA IR — <https://luajit.org/luajit.html> and
<https://en.wikipedia.org/wiki/LuaJIT>; NaN-boxing usage (SpiderMonkey, LuaJIT,
others) — <https://arxiv.org/pdf/2411.16544> ("Float Self-Tagging") and
<https://en.wikipedia.org/wiki/LuaJIT>.

### 4.3 PyPy — meta-tracing (noted, not adopted)

PyPy, written in RPython, generates a **meta-tracing JIT**: rather than tracing
the user program directly, it traces the *interpreter* executing the user
program, so one JIT framework serves many guest languages, naturally capturing
latent type feedback.

> **What we take.** A *noted alternative*, not adopted. Meta-tracing is the most
> general way to get a JIT "for free" from an interpreter, and is worth knowing as
> the road not taken: aos-nix instead hand-builds a method JIT over Cranelift
> because (a) we have exactly one guest language, (b) the expression/activation
> ratio favors method compilation, and (c) tracing would complicate the
> byte-identical-`.drv` determinism contract. It is recorded here for
> completeness as a known point in the JIT design space.

Source: Bolz et al., "Tracing the Meta-Level: PyPy's Tracing JIT Compiler"
(ICOOOLPS 2009) — <https://dl.acm.org/doi/pdf/10.1145/1565824.1565827>; RPython
meta-JIT docs — <https://rpython.readthedocs.io/en/latest/jit/pyjitpl5.html>;
PyPy on meta-tracing's success — <https://pypy.org/posts/2025/01/musings-tracing.html>.

---

## 5. Incremental computation — the P0 lineage (Salsa, Adapton, Skip, à la Carte)

P0 (the incremental early-cutoff cache) is the single biggest systemic lever in
the RFC ([12](12-incremental-evaluation-cache.md)). Its prior art is the
incremental-computation literature, which spends most of its complexity budget
*tracking mutable inputs* — complexity Nix's purity lets us discard.

### 5.1 Salsa / the red-green algorithm (rust-analyzer, rustc)

Salsa is the incremental-recomputation engine behind rust-analyzer; its core
**"red-green" algorithm** (inherited from rustc's query system, which is where
the name comes from) floods invalidation backward from changed inputs and **stops
at the first query whose recomputed result is unchanged — early cutoff**. The
*durable incrementality* refinement notes that in a mostly-no-op edit, Salsa need
only walk the query graph and bump version numbers, executing no queries; inputs
carry a *durability* describing how likely they are to change.

> **What we take** ([incremental cache §4](12-incremental-evaluation-cache.md)):
> the red-green change-propagation algorithm and **early cutoff as the central
> mechanism** — recompute a node, compare its new value-hash against the old, and
> *halt propagation when unchanged*. Editing a comment in a widely-imported file
> recomputes almost nothing. **Early cutoff is even more powerful in Nix than in
> an editor**: `.drv` output is a function of *values*, not source text, so
> reformatting or comment edits hit cutoff at depth 0. The must-be-byte-identical
> requirement also means the canonical value the cutoff hashes is *already on the
> critical path*.

Source: Salsa "red-green algorithm" — <https://salsa-rs.github.io/salsa/reference/algorithm.html>;
Salsa overview — <https://salsa-rs.github.io/salsa/overview.html>; durable
incrementality (no-op builds bump versions only) —
<https://rust-analyzer.github.io/blog/2023/07/24/durable-incrementality.html>;
rustc query origin of red-green — <https://rustc-dev-guide.rust-lang.org/queries/salsa.html>.

### 5.2 Adapton — demand-driven incremental computation (PLDI 2014)

Adapton (Hammer, Khoo, Hicks, Foster, PLDI 2014) formalizes **demand-driven**
incremental computation via a **demanded computation graph (DCG)** and an explicit
separation between **inner incremental computations** and **outer observers**:
programs recompute only what observers actually demand, letting inner
computations be reused liberally.

> **What we take** ([incremental cache §2-3](12-incremental-evaluation-cache.md)):
> the DCG abstraction (we model evaluation as a dependency graph of cached
> computations, built lazily) and the inner/outer-observer separation — a node is
> created **only when forced**, and change propagation runs only for results the
> top-level `derivationStrict` we are instantiating actually demands. This is what
> keeps the cache demand-driven rather than a bulk pre-pass.

Source: Adapton paper (DCG, inner/outer separation, demand-driven) —
<https://dl.acm.org/doi/10.1145/2666356.2594324> and project page
<http://matthewhammer.org/adapton/>; Rust port — <https://docs.rs/adapton>.

### 5.3 Skip — sound memoization via side-effect tracking

Skip is a programming language whose defining feature is **precise tracking of
side effects**; when its type system can prove the absence of side effects at a
function boundary, the runtime safely memoizes that computation with **reactive
invalidation** (cached values are invalidated automatically when underlying data
changes).

> **What we take.** A *conceptual confirmation*, not code. Skip demonstrates that
> sound memoization across a function boundary *requires* proving side-effect
> freedom — and went as far as building a whole type system to do it. **Nix hands
> us that proof for free** (purity + immutability + reified filesystem reads), so
> the machinery Skip spends a type system on, we get from the language semantics
> ([12 §1.1](12-incremental-evaluation-cache.md)). Skip is the clearest statement
> of *why* the purity waiver is the enabling condition for our cache.

Source: Skip side-effect tracking enabling memoization with reactive invalidation
— <https://skiplang.com/blog/2017/01/04/how-memoization-works.html> and
<https://github.com/SkipLabs/skip>.

### 5.4 Build Systems à la Carte — the trace taxonomy

Mokhov, Mitchell & Peyton Jones's *Build Systems à la Carte* gives the precise
vocabulary for *what kind of trace* a build/eval system keeps: **verifying**
traces (store hashes of deps + result; support early cutoff by comparing result
hashes), **constructive** traces (store the resulting value; early cutoff limited
to one level), and **deep constructive** traces (full transitive closure; no
early cutoff except at `n` levels). The key result: deep constructive traces
*cannot* support early cutoff except at `n` levels.

> **What we take** ([incremental cache §2.1, §6](12-incremental-evaluation-cache.md)):
> the trace taxonomy as the design framework. We keep **verifying traces** for
> freshness decisions (compare value-hashes, propagate only on change — the
> early-cutoff path) and use **constructive storage** (the `n=1` special case)
> only as the content-addressed value store that lets us *reconstruct* a value
> deemed fresh without recomputing it. We deliberately **avoid deep constructive
> traces**, which would force a choice between early cutoff and shallow rebuilds.

Source: *Build Systems à la Carte* (ICFP 2018) —
<https://www.microsoft.com/en-us/research/wp-content/uploads/2018/03/build-systems.pdf>;
*Theory and Practice* journal version —
<https://ndmitchell.com/downloads/paper-build_systems_a_la_carte_theory_and_practice-21_apr_2020.pdf>.

### 5.5 Attic — content-addressed persistence for the eval cache

AOS already runs an Attic binary cache that shares *build outputs* across CI
machines via content-addressed global deduplication (NARs and chunks) and a
multi-level GC.

> **What we take** ([incremental cache §6](12-incremental-evaluation-cache.md)):
> the persistence shape. We extend Attic's content-addressed sharing from *build
> outputs* to *eval outputs* — a content-addressed value store keyed by blake3,
> with global deduplication (hash-consing dedups in memory; the on-disk key *is*
> the value-hash, so it dedups on disk for free), self-certifying cross-machine
> sharing, and layered GC mirroring Attic's. The eval cache lives in its own
> `andyl-os` Attic namespace, isolated from the build-output cache.

Source: Attic (content-addressed dedup, three-level GC) —
<https://docs.attic.rs/> and <https://github.com/zhaofengli/attic>.

---

## 6. Codegen backend — Cranelift, and the copy-and-patch alternative (P4)

The backend choice is a first-class architectural commitment, fully argued in
[execution tiers and Cranelift §5](08-execution-tiers-and-cranelift.md) and
summarized here against its sources.

### 6.1 Cranelift — the chosen backend

Cranelift is a pure-Rust code generator developed for **Wasmtime**, used both as
Wasmtime's baseline Wasm compiler and as an alternative rustc backend
(`rustc_codegen_cranelift`). Its design explicitly trades a few percent of
steady-state code quality for **roughly an order-of-magnitude faster compilation
than LLVM**. `cranelift-jit` provides `JITBuilder`/`JITModule`, where
**`JITBuilder::symbol` registers host functions** that the JIT uses to resolve
names "declared, but not defined, in the module being compiled" — exactly the
runtime-symbol mechanism our ABI (`aos_force`, `aos_alloc_*`, `aos_prim_*`)
needs. Cranelift also supplies **user stack maps** for an *external* precise
collector to find GC roots in compiled frames (it ships the safepoint/stack-map
infrastructure but **not** a collector).

> **What we take.** Cranelift as *the* backend for both compiled tiers, chosen
> for (1) fast warmup (the project exists to *reduce* eval latency; a backend that
> spends it in the compiler defeats the purpose), (2) pure-Rust hermeticity (no
> C++ LLVM toolchain, fitting AOS's build-from-source ethos), (3) the
> `JITBuilder::symbol` host-symbol story that the runtime ABI is built around, and
> (4) user-stack-map support for the precise GC. The user-stack-maps API is
> relatively new, so we pin a Cranelift revision and expect churn
> ([08 §6, §10](08-execution-tiers-and-cranelift.md)).
>
> **Why not LLVM**: superior peak codegen but ~10x slower compilation — backwards
> for a warmup-sensitive JIT — and a heavy C++ build. Retained only as an
> *optional AOT cache tier* for a stable hot core. **Why not WASM**: buys
> sandboxing/portability we don't need, adds a host-boundary cost on every
> runtime-symbol call, and fights the custom precise GC.

Source: Cranelift overview / design — <https://cranelift.dev/>; Cranelift-vs-LLVM
trade-off — <https://github.com/bytecodealliance/wasmtime/blob/main/cranelift/docs/compare-llvm.md>;
`JITBuilder` host-symbol resolution — <https://docs.rs/cranelift-jit/latest/cranelift_jit/struct.JITBuilder.html>;
`rustc_codegen_cranelift` JIT — <https://github.com/rust-lang/rust/blob/main/compiler/rustc_codegen_cranelift/src/driver/jit.rs>;
user stack maps (frontend obligation, external collector) —
<https://fitzgen.com/2024/09/10/new-stack-maps-for-wasmtime.html> and
<https://bytecodealliance.org/articles/new-stack-maps-for-wasmtime>.

### 6.2 Copy-and-patch compilation — the deferred tier-1 alternative

**Copy-and-patch** (Xu & Kjolstad, OOPSLA 2021) stitches together pre-compiled
machine-code **stencils**, patching in runtime constants and addresses, to
produce native code with *microsecond-class* compile times — far faster even than
Cranelift's baseline. It is the technique behind the **CPython 3.13 experimental
JIT** (PEP 744): LLVM compiles each Tier-2 micro-op handler into a stencil *at
CPython build time*, the stencils are baked into the binary, and the runtime
copies and patches them; the assembly step is so fast that CPython "spends more
time allocating memory for the code buffer than filling it," trading optimization
depth for compile speed.

> **What we take.** A *noted, deferred* tier-1 alternative
> ([08 §5.4](08-execution-tiers-and-cranelift.md)). For a tier-1 whose only job is
> "remove interpreter overhead with the least possible compile cost,"
> copy-and-patch may be a *better* fit than Cranelift baseline — and is the hedge
> against the open question (Q1) that the one-shot CLI workload is the worst case
> for any JIT warmup. It is **research-grade, not committed**: adopting it means
> authoring/maintaining an arch-specific stencil library (a fresh source of
> `unsafe`), worth it only if profiling shows tier-1 *compile time* (not code
> quality) is a measured bottleneck. Starting with one backend (Cranelift) for
> both tiers means one lowering, one ABI, one stack-map plumbing.

Source: Copy-and-Patch Compilation (Xu & Kjolstad, OOPSLA 2021) —
<https://arxiv.org/pdf/2011.13127> and ACM DOI
<https://dl.acm.org/doi/abs/10.1145/3485513>; CPython 3.13 copy-and-patch JIT —
PEP 744 <https://peps.python.org/pep-0744/>; copy-and-patch overview —
<https://en.wikipedia.org/wiki/Copy-and-patch>.

---

## 7. Parallel evaluation — Determinate Systems (and GHC sparks)

aos-nix's parallel-forcing design ([parallel evaluation](13-parallel-evaluation.md))
draws on two sources: GHC's spark model (already cited in §2.3) for the
monotonic-claim discipline, and Determinate Systems' production parallel Nix
evaluator for proof that the workload parallelizes.

**Determinate Nix** shipped **parallel evaluation** to users (in Determinate Nix
3.11.1), reporting real-world evaluation times "cut in half or more" — one cited
figure is **23.70s -> 5.77s on 12 threads, a 4.1x speedup** — gated by an
`eval-cores` setting (ramped from a default of 2 up to unlimited) and exposing a
`builtins.parallel` builtin for explicit in-expression parallelism.

> **What we take.** Confirmation that **Nix evaluation parallelizes in practice**
> and the engineering pattern for it. aos-nix makes the only mutable runtime
> state — the thunk-update protocol — monotonic and idempotent. The serial
> oracle's `Suspended -> Blackhole -> Forced` state machine becomes, under
> parallelism, the superset `Suspended -> Pending -> Awaited -> Forced/Failed`
> ([13 §3.1](13-parallel-evaluation.md)): a thread claims a thunk with a
> compare-and-swap (CAS) of `Suspended -> Pending`, a losing thread work-steals
> elsewhere, and same-thread re-entry remains the genuine `Blackhole` cycle error
> ([03 §3.2](03-architecture-overview.md), [13](13-parallel-evaluation.md)). This
> is the GHC spark model and the same monotonic-claim discipline Determinate
> Systems' parallel evaluator validates at production scale.

The scheduler underneath that claim discipline is a **Chase-Lev work-stealing
deque** (Chase & Lev, SPAA 2005) — the lock-free deque that underlies Rayon and
crossbeam, and the structure GHC uses to load-balance sparks. aos-nix's L1
work-stealing pool ([13 §4.2](13-parallel-evaluation.md)) is built directly on
it: each worker owns a deque, pushes/pops LIFO, and idle peers steal FIFO from
the oldest end. The fiber I/O layer's region-confinement of non-escaping thunks
([13 §5.4](13-parallel-evaluation.md)) in turn rests on **Tofte-Talpin region
inference** (Tofte & Talpin, 1994), the prior art behind aos-nix's
escape-analysis-driven nursery confinement.

Source: "Parallel evaluation comes to Determinate Nix" (3.11.1, eval-cores,
`builtins.parallel`) — <https://determinate.systems/blog/changelog-determinate-nix-3111/>;
"Parallel Nix evaluation" (23.70s -> 5.77s, 12 threads, 4.1x) —
<https://determinate.systems/blog/parallel-nix-eval/>; Chase & Lev, "Dynamic
Circular Work-Stealing Deque" (SPAA 2005; basis for Rayon/crossbeam) —
<https://www.dre.vanderbilt.edu/~schmidt/PDF/work-stealing-dequeue.pdf>;
Tofte & Talpin, "Implementation of the Typed Call-by-Value Lambda-Calculus using
a Stack of Regions" (POPL 1994; region inference) —
<https://dl.acm.org/doi/10.1145/174675.177855>.

---

## 8. The borrowed-technique matrix

The table below is the document in one view: each technique, its source system, a
verified citation anchor, and the aos-nix document that cashes it out. It is the
concrete face of the [synthesis thesis](03-architecture-overview.md) — every row
is a *borrowed* technique with a named ancestor, and the novelty is the
assembly, plus the fact that Nix's purity upgrades each from "partial and
guarded" to "total and sound."

| Technique | Source system | aos-nix document | Purity upgrade |
|-----------|---------------|------------------|----------------|
| Closure/thunk model, black hole, pointer tagging | GHC STG | [05](05-value-representation.md), [08](08-execution-tiers-and-cranelift.md) | n/a (already sound in GHC; absent in C++ Nix/Snix) |
| Strictness/demand + worker-wrapper, cardinality | GHC | [07](07-laziness-and-whole-program-analyses.md) | Whole-program batch: analysis total, not cross-module-conservative |
| Full-laziness / let-floating, generational GC | GHC | [06](06-memory-management-and-gc.md), [07](07-laziness-and-whole-program-analyses.md) | Extreme generational hypothesis (thunks die instantly) |
| Tiered compilation, OSR | HotSpot | [08](08-execution-tiers-and-cranelift.md) | Bounded expression count makes tiering cheap |
| Deoptimization / uncommon traps | HotSpot | [08](08-execution-tiers-and-cranelift.md) | No effects to roll back: deopt is pure state reconstruction |
| Escape analysis + scalar replacement (+ realloc on deopt) | HotSpot | [07](07-laziness-and-whole-program-analyses.md), [08](08-execution-tiers-and-cranelift.md) | Immutable, identity-free values: far more provably don't escape |
| G1/ZGC/Shenandoah region+colored-pointer GC | JVM | [06](06-memory-management-and-gc.md), [13](13-parallel-evaluation.md) | (hardest open coupling; first cut sidesteps) |
| Hidden classes (maps) + inline caches | V8 | [09](09-attribute-sets-hidden-classes-and-inline-caches.md) | Shapes never mutate: a value's shape is fixed for its lifetime |
| NaN-boxing value rep | LuaJIT | [05](05-value-representation.md) | i64 doesn't fit; boxed-int fallback (open, measured) |
| Meta-tracing JIT | PyPy | (noted, not adopted) | n/a |
| Red-green early cutoff | Salsa / rustc / rust-analyzer | [12](12-incremental-evaluation-cache.md) | `.drv` is a function of values, not text: cutoff at depth 0 |
| Demanded computation graph, inner/outer observers | Adapton | [12](12-incremental-evaluation-cache.md) | Demand-driven node creation; only what observers demand |
| Sound memoization via side-effect proof | Skip | [12](12-incremental-evaluation-cache.md) | Purity gives the proof for free (no type system needed) |
| Verifying vs constructive trace taxonomy | Build Systems à la Carte | [12](12-incremental-evaluation-cache.md) | Verifying traces + constructive store, no deep traces |
| Content-addressed dedup persistence | Attic | [12](12-incremental-evaluation-cache.md) | Hash-consing dedups on disk for free |
| Pure-Rust JIT, host symbols, user stack maps | Cranelift / Wasmtime | [08](08-execution-tiers-and-cranelift.md) | Trusted in-process code: no sandbox tax |
| Copy-and-patch stencils | Xu & Kjolstad / CPython 3.13 | [08](08-execution-tiers-and-cranelift.md) | (deferred tier-1 hedge for CLI warmup) |
| Monotonic-claim parallel forcing | GHC sparks / Determinate Nix | [13](13-parallel-evaluation.md) | Only mutable state is monotonic thunk update |
| Work-stealing deque (lock-free) | Chase-Lev / Rayon / crossbeam | [13](13-parallel-evaluation.md) | CPU-bound forcing fork-joins; pure values share no mutable state |
| Region inference / escape-confined nurseries | Tofte-Talpin | [07](07-laziness-and-whole-program-analyses.md), [13](13-parallel-evaluation.md) | Immutable values: most thunks provably never escape their derivation |
| Symbol interning, sorted bindings, string contexts, CA derivations | C++ Nix | [05](05-value-representation.md), [09](09-attribute-sets-hidden-classes-and-inline-caches.md), [11](11-derivation-and-store-compatibility.md), [12](12-incremental-evaluation-cache.md) | baseline to reproduce/beat |
| `nix-compat` formats, conformance suite | Snix (ex-Tvix) | [11](11-derivation-and-store-compatibility.md), [15](15-differential-testing-and-benchmarking.md) | dependency; `.drv` parity is *our* added gate |

---

## 9. What is *not* prior art here (deliberate non-borrowings)

To be honest about scope, a few techniques are *adjacent* but explicitly **not**
adopted, recorded so future readers do not mistake omission for oversight:

- **Tracing JITs (LuaJIT/PyPy trace selection).** We use a *method* (per-expression)
  JIT, not trace selection, because the bounded-expression/unbounded-activation
  ratio ([08 §1](08-execution-tiers-and-cranelift.md)) favors method compilation
  and tracing complicates the determinism contract. LuaJIT's *NaN-boxing* is
  borrowed; its *tracing* is not.
- **WASM as an execution target.** Rejected for sandbox/boundary cost against the
  custom GC ([08 §5.3](08-execution-tiers-and-cranelift.md)).
- **LLVM as the JIT backend.** Rejected for warmup; retained only as an optional
  AOT cache tier ([08 §5.2](08-execution-tiers-and-cranelift.md)).
- **Snix's bytecode VM.** Studied; not adopted (we tier a tree-walk oracle + JIT).
- **Deep constructive traces.** Rejected because they kill early cutoff
  ([12 §2.1](12-incremental-evaluation-cache.md)).
- **The flake-level SQLite eval cache as-is.** Too coarse and local; superseded by
  the fine-grained content-addressed cross-machine cache.

---

## 10. Summary

Every load-bearing technique in RFC-0007 has a named, verifiable ancestor:

- **The Nix landscape** sets the frame — **C++ Nix** is the fast baseline to beat
  (Boehm GC its chief cost; symbol interning, sorted bindings, string contexts,
  flake cache, CA derivations its adopted parts); **Tvix -> Snix** (renamed
  2025-03-16) gives us `nix-compat` and a conformance practice but inverts our
  performance posture and does not guarantee `.drv` parity; **hnix** proves
  language choice alone is not the lever.
- **GHC** supplies laziness made cheap (STG closures, black holes, pointer
  tagging, demand/strictness + worker-wrapper, cardinality, full-laziness,
  generational GC).
- **HotSpot/JVM** supplies tiered compilation, deopt/uncommon traps, escape
  analysis + scalar replacement with realloc-on-deopt, and the G1/ZGC/Shenandoah
  GC vocabulary.
- **V8** supplies hidden classes + inline caches; **LuaJIT** supplies NaN-boxing
  (with the i64 caveat); **PyPy** is noted, not adopted.
- **Salsa/Adapton/Skip/Build Systems à la Carte/Attic** supply the P0 incremental
  cache: red-green early cutoff, the demanded computation graph, sound memoization
  via the purity waiver, the verifying/constructive trace taxonomy, and
  content-addressed cross-machine persistence.
- **Cranelift/Wasmtime** supplies the pure-Rust JIT, host symbols, and user stack
  maps; **copy-and-patch** is the deferred CLI-warmup hedge; **Determinate
  Systems** and **GHC sparks** validate parallel forcing.

The recurring theme — argued in [03](03-architecture-overview.md) and
[08 §9](08-execution-tiers-and-cranelift.md) and visible in the matrix's right
column — is that each technique was invented to be defended against mutation,
dynamic loading, or side effects, and **Nix's purity, immutability, and
whole-program batch nature waive that defensive tax**, upgrading each borrowed
technique from partial-and-guarded to total-and-sound. The contribution of
aos-nix is the disciplined assembly, subject always to the byte-identical `.drv`
acceptance gate.

---

## References

Nix implementations:

- C++ Nix evaluation engine, `bindVars`/`StaticEnv`, Boehm GC —
  <https://deepwiki.com/NixOS/nix/2.1-evaluation-engine>;
  Boehm dependence — <https://github.com/NixOS/nix/issues/6250>
- String-context interning/indirection — <https://git.snix.dev/snix/snix/issues/122>
- Flake evaluation cache (SQLite, fingerprint, ~0.39s->0.03s) —
  <https://www.tweag.io/blog/2020-06-25-eval-cache/>
- CA derivations / early cutoff — <https://wiki.nixos.org/wiki/Ca-derivations>;
  RFC 0062 — <https://github.com/NixOS/rfcs/blob/master/rfcs/0062-content-addressed-paths.md>
- Snix announcement / rename (2025-03-16) — <https://snix.dev/blog/announcing-snix/>
- Snix component overview (`nix-compat`, `snix-eval`, `snix-castore`, `snix-store`,
  `snix-glue`, `snix-cli`, `snix-serde`) — <https://snix.dev/docs/components/overview/>
- Snix repository — <https://git.snix.dev/snix/snix>
- Tvix eval README (bytecode VM, scope analysis, "order of magnitude faster but
  not indicative of nixpkgs", "avoiding fine-grained optimization until correct")
  — <https://code.tvl.fyi/about/tvix/eval/README.md?id=be32ab1eb2b60bf028c32954d1a6a5d09c6d2f9c>
- devenv switch to Tvix (2024-10-22, motivations) —
  <https://devenv.sh/blog/2024/10/22/devenv-is-switching-its-nix-implementation-to-tvix/>;
  discourse — <https://discourse.nixos.org/t/devenv-is-switching-nix-implementation-to-tvix/54753>;
  Snix evaluation tracking — <https://github.com/cachix/devenv/issues/1548>
- hnix performance (parse ~6.9s vs ~0.36s; eval ~1.125s vs ~0.089s) —
  <https://github.com/haskell-nix/hnix/issues/200>,
  <https://github.com/haskell-nix/hnix/issues/16>;
  design — <https://github.com/haskell-nix/hnix/wiki/Design-of-the-HNix-code-base>

GHC / STG:

- The Spineless Tagless G-machine (v2.5) —
  <https://www.microsoft.com/en-us/research/wp-content/uploads/1992/04/spineless-tagless-gmachine.pdf>
- STG exposition + pointer tagging — <https://jozefg.bitbucket.io/posts/2014-10-28-stg.html>,
  <https://www.arbertrary.dev/stgm-presentation/stgm-deck.html>
- Theory and Practice of Demand Analysis in Haskell —
  <https://www.microsoft.com/en-us/research/wp-content/uploads/2017/03/demand-jfp-draft.pdf>
- GHC optimisation (strictness, worker-wrapper, full-laziness, generational GC) —
  <https://downloads.haskell.org/ghc/9.12.1/docs/users_guide/using-optimisation.html>
- Usage/cardinality/absence analysis — <https://fixpt.de/blog/2018-12-30-strictness-analysis-part-2.html>

HotSpot / JVM:

- Tiered compilation, OSR — <https://devblogs.microsoft.com/java/how-tiered-compilation-works-in-openjdk/>
- C2 internals intro — <https://eme64.github.io/blog/2024/12/24/Intro-to-C2-Part01.html>
- Escape analysis in dynamic compilation and deoptimization (uncommon trap,
  realloc/relock on deopt; Kotzmann & Mössenböck) —
  <https://dl.acm.org/doi/10.1145/1064979.1064996>
- HotSpot escape-analysis/scalar-replacement status —
  <https://cr.openjdk.org/~cslucas/escape-analysis/EscapeAnalysis.html>;
  overview — <https://en.wikipedia.org/wiki/Escape_analysis>
- OpenJDK `deoptimization.cpp` —
  <https://github.com/openjdk/jdk/blob/master/src/hotspot/share/runtime/deoptimization.cpp>;
  JIT deep dive — <https://www.w3computing.com/articles/jvm-jit-compiler-deep-dive-c1-c2-tiered-compilation/>
- G1 vs ZGC vs Shenandoah (regions, Brooks/colored pointers, sub-10ms) —
  <https://www.javacodegeeks.com/2025/08/java-gc-performance-g1-vs-zgc-vs-shenandoah.html>

V8 / LuaJIT / PyPy:

- V8 Maps (Hidden Classes) — <https://v8.dev/docs/hidden-classes>
- V8 inline-cache states (mono/poly/megamorphic, >4 = megamorphic) —
  <https://braineanear.medium.com/the-v8-engine-series-iii-inline-caching-unlocking-javascript-performance-51cf09a64cc3>,
  <https://medium.com/@yashschandra/hidden-v8-optimizations-hidden-classes-and-inline-caching-736a09c2e9eb>
- LuaJIT (tracing JIT, SSA IR) — <https://luajit.org/luajit.html>,
  <https://en.wikipedia.org/wiki/LuaJIT>
- NaN-boxing usage — <https://arxiv.org/pdf/2411.16544>
- PyPy meta-tracing — <https://dl.acm.org/doi/pdf/10.1145/1565824.1565827>;
  RPython meta-JIT — <https://rpython.readthedocs.io/en/latest/jit/pyjitpl5.html>;
  PyPy on tracing — <https://pypy.org/posts/2025/01/musings-tracing.html>

Incremental computation:

- Salsa red-green algorithm — <https://salsa-rs.github.io/salsa/reference/algorithm.html>;
  overview — <https://salsa-rs.github.io/salsa/overview.html>;
  durable incrementality — <https://rust-analyzer.github.io/blog/2023/07/24/durable-incrementality.html>;
  rustc query origin — <https://rustc-dev-guide.rust-lang.org/queries/salsa.html>
- Adapton (PLDI 2014, DCG, inner/outer observers) —
  <https://dl.acm.org/doi/10.1145/2666356.2594324>;
  project — <http://matthewhammer.org/adapton/>; Rust port — <https://docs.rs/adapton>
- Skip (side-effect tracking, reactive memoization) —
  <https://skiplang.com/blog/2017/01/04/how-memoization-works.html>,
  <https://github.com/SkipLabs/skip>
- Build Systems à la Carte (trace taxonomy, early cutoff) —
  <https://www.microsoft.com/en-us/research/wp-content/uploads/2018/03/build-systems.pdf>,
  <https://ndmitchell.com/downloads/paper-build_systems_a_la_carte_theory_and_practice-21_apr_2020.pdf>
- Attic (content-addressed dedup, three-level GC) — <https://docs.attic.rs/>,
  <https://github.com/zhaofengli/attic>

Codegen backend:

- Cranelift — <https://cranelift.dev/>; vs LLVM —
  <https://github.com/bytecodealliance/wasmtime/blob/main/cranelift/docs/compare-llvm.md>
- `JITBuilder` host symbols — <https://docs.rs/cranelift-jit/latest/cranelift_jit/struct.JITBuilder.html>;
  `rustc_codegen_cranelift` — <https://github.com/rust-lang/rust/blob/main/compiler/rustc_codegen_cranelift/src/driver/jit.rs>
- User stack maps — <https://fitzgen.com/2024/09/10/new-stack-maps-for-wasmtime.html>,
  <https://bytecodealliance.org/articles/new-stack-maps-for-wasmtime>
- Copy-and-Patch Compilation (Xu & Kjolstad, OOPSLA 2021) —
  <https://arxiv.org/pdf/2011.13127>, <https://dl.acm.org/doi/abs/10.1145/3485513>;
  CPython 3.13 JIT (PEP 744) — <https://peps.python.org/pep-0744/>;
  overview — <https://en.wikipedia.org/wiki/Copy-and-patch>

Parallel evaluation:

- Determinate Nix parallel evaluation (3.11.1, eval-cores, `builtins.parallel`) —
  <https://determinate.systems/blog/changelog-determinate-nix-3111/>;
  4.1x / 23.70s->5.77s — <https://determinate.systems/blog/parallel-nix-eval/>
