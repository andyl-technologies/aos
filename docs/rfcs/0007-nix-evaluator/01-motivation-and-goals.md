# RFC-0007 - Motivation and Goals

This document opens the RFC-0007 design set for **aos-nix**, a from-scratch,
state-of-the-art Nix language evaluator written in Rust and shipped as a new
crate (`crates/aos-nix`) inside the ANDYL OS (AOS) monorepo. It establishes
*why* the project exists, what it is and is not allowed to do, the
**measure-first gate** that must be cleared before a single line of optimizing
compiler is written, and the concrete success criteria by which the whole
effort will be judged.

The remaining documents in the set develop the architecture in depth: the
[compatibility constraints](02-compatibility-constraints.md) that bound every
design choice, the [architecture overview](03-architecture-overview.md) and its
synthesis thesis, the [frontend](04-frontend-parser-and-ir.md),
[value representation](05-value-representation.md),
[memory management](06-memory-management-and-gc.md),
[laziness analyses](07-laziness-and-whole-program-analyses.md),
[execution tiers](08-execution-tiers-and-cranelift.md),
[attribute sets](09-attribute-sets-hidden-classes-and-inline-caches.md),
[primops/runtime ABI](10-primops-and-runtime-abi.md),
[derivation/store compatibility](11-derivation-and-store-compatibility.md),
the [incremental evaluation cache](12-incremental-evaluation-cache.md),
[parallel evaluation](13-parallel-evaluation.md),
[AOS integration](14-integration-with-aos.md),
[differential testing and benchmarking](15-differential-testing-and-benchmarking.md),
[prior art](16-prior-art-and-references.md),
[roadmap and risks](17-roadmap-and-risks.md), and the
[glossary](18-glossary.md).

This document deliberately makes *no* status claim — the maturity header lives
only in the set's `README.md`. What follows is the argument for the work.

---

## 1. The problem: evaluation is a recurring tax on every build

AOS is a hermetic, from-source Linux distribution. Unlike a binary distro, AOS
rebuilds its entire toolchain — the source bootstrap chain, the GCC ladder, the
Rust and Java and Bazel bootstraps — from primitive seeds. Every one of those
packages is expressed as Nix. Before anything is *built*, the Nix expression
tree describing the package set must be *evaluated*: parsed, lazily reduced, and
lowered into a graph of `.drv` derivation files that the builder consumes.

Today the `aos` CLI does not evaluate Nix itself. It shells out to the upstream
C++ Nix binaries — `nix-instantiate`, `nix-build`, `nix-store` — through the
`NixCli` adapter in `crates/aos-core/src/nix/store.rs`. That adapter is correct
and battle-tested, and it will remain a permanent fallback (see
[integration](14-integration-with-aos.md)). But the *evaluation* it drives is a
repeated, build-time bottleneck:

- Evaluation happens on **every** CI run, every developer `aos build`, every
  `aos show`, every `aos graph`. It is not amortized the way a single
  expensive build of GCC is amortized across a cache hit.
- The AOS package set is large and deeply interconnected. Evaluating the
  toplevel of a system variant forces a substantial fraction of the entire
  expression tree, re-parsing and re-reducing the same library functions,
  the same `stdenv`, the same `mkDerivation` machinery, on every invocation.
- C++ Nix evaluation is single-threaded, allocates aggressively, and leans on a
  **Boehm conservative garbage collector** whose scanning cost dominates
  large-closure evaluation. None of that work is reused between runs: cold
  start re-parses, re-evaluates, and re-hashes from scratch.

Crucially, evaluation and building are **distinct phases**. A `.drv` is a pure
function of the expression tree; *realising* that `.drv` (running the compiler,
linking, packaging) is a separate, heavyweight phase. aos-nix attacks **only**
the eval path:

```text
  .nix source ──► [ EVALUATION ]  ──►  .drv graph  ──► [ BUILD ] ──► store outputs
   (aos-nix's scope)  ▲                                  ▲
                      │                                  │
            this RFC replaces this stage      real Nix still does this
```

Real Nix still *builds* the `.drv` that aos-nix emits. We are not touching the
build daemon, the sandbox, the substituter, or NAR/narinfo handling beyond what
is needed to emit byte-identical derivations. This is precisely why the
**measure-first gate** in §5 is mandatory: we must *prove* eval is the
bottleneck on real AOS workloads before optimizing it, because optimizing the
wrong phase is wasted engineering.

### 1.1 Why this is worth a from-scratch evaluator

A reasonable objection: why not profile C++ Nix and patch its hot paths, or
adopt an existing Rust evaluator? Three reasons, developed across this set:

1. **The biggest win is systemic, not constant-factor.** The single largest
   real-world speedup available is *not evaluating at all* — a persistent,
   content-addressed, early-cutoff **incremental evaluation cache** (see
   [incremental cache](12-incremental-evaluation-cache.md)). Editing a comment,
   or a leaf package far from the toolchain, should recompute almost nothing.
   This is sound *only* because Nix is pure, and it is architecturally
   incompatible with C++ Nix's design. It may, on its own, solve the build-time
   problem regardless of raw interpreter speed.

2. **Nix's purity turns partial optimizations into total ones.** Techniques
   that are unsound or merely opportunistic in Java, JavaScript, or Python —
   escape analysis, scalar replacement, hash-consing, aggressive memoization,
   parallel evaluation — become *total and sound* on an immutable, pure,
   whole-program, batch language. We can be more aggressive than V8 or HotSpot
   *because* the language gives us guarantees they do not have. This is the
   central [synthesis thesis](03-architecture-overview.md).

3. **No existing Rust evaluator meets our hard constraint.** Tvix (now forked
   and renamed **Snix** in March 2025) is the most advanced effort, a Rust
   bytecode-VM implementation with early microbenchmarks reported around
   ~10× over C++ Nix — but the project itself *disclaims real-world relevance*
   for those numbers, defers optimization until it is nixpkgs-correct, ships an
   explicitly unstable CLI, and offers **no `.drv`-parity guarantee**. hnix
   (Haskell) is a cautionary data point: notably *slow*, a reminder that
   "Haskell speed" is not automatic. None of these can be dropped into AOS,
   where a single divergent `.drv` is catastrophic (§2). We do, however, plan
   to *reuse* Snix's `nix-compat` crate for ATerm/store-path/NAR formats and
   its language conformance approach (see
   [derivation compatibility](11-derivation-and-store-compatibility.md) and
   [prior art](16-prior-art-and-references.md)).

---

## 2. The hard constraint: bug-for-bug derivation compatibility

Everything in this RFC is subordinate to one non-negotiable invariant:

> **aos-nix MUST produce byte-identical `.drv` files and byte-identical store
> paths to C++ Nix, for the entire AOS package set.**

This is not a nicety; it is an existential constraint specific to a from-source
distro. The store path of every derivation is an *input hash*: a SHA-256 digest
computed over the derivation's complete description — its ATerm-serialized form,
its inputs, its environment, transitively its dependencies' output paths. The
hashing pipeline is fixed by Nix's on-disk format:

```text
  Derivation ──► ATerm serialization ──► SHA-256 ──► XOR-fold to 160 bits
                                                  ──► Nix base-32 encode
                                                  ──► 32-char store-path hash
```

The consequence of any divergence is severe and immediate:

```text
  aos-nix emits a .drv that differs by ONE byte
        │
        ▼
  different ATerm  ──►  different SHA-256  ──►  different store path
        │
        ▼
  the build cache (Attic / binary cache) sees an UNKNOWN path
        │
        ▼
  TOTAL cache miss  ──►  rebuild from source
        │
        ▼
  in AOS: rebuild the GCC ladder / Rust bootstrap / Java chain
          (hours-to-days of compute; catastrophic)
```

In a binary distro a divergent hash is a wasted download. In AOS it triggers a
from-source rebuild of the bootstrap toolchain. **Bug-for-bug compatibility is
therefore the gate, not an aspiration.** Concretely this means:

- **SHA-256 for all Nix-observed hashes.** Derivation hashing and store-path
  computation use SHA-256 as mandated by the Nix on-disk format. This is
  non-negotiable and is *separate* from aos-nix's internal hashing policy,
  which uses xxh3 for hot in-process hashing and blake3 for the durable cache
  (see [incremental cache](12-incremental-evaluation-cache.md)). SHA-256 is
  used *only* where Nix observes it.
- **String contexts must match exactly.** The propagation of store-path
  references through string operations — the dependency provenance that
  `derivationStrict` reads back — must be identical, or the input set of a
  derivation diverges. See
  [derivation compatibility](11-derivation-and-store-compatibility.md).
- **Deterministic attribute iteration order.** Attrset key ordering is
  observable (it determines the order of environment variables written into the
  `.drv`), so the [attrset representation](09-attribute-sets-hidden-classes-and-inline-caches.md)
  must reproduce Nix's ordering exactly.
- **Bug-for-bug, not spec-for-spec.** Where C++ Nix has an observable quirk, we
  reproduce the *quirk*, not an idealized semantics. "Compatible" means "emits
  what `nix-instantiate` emits," full stop.

The **acceptance gate** that enforces this is a differential harness that diffs
aos-nix's `.drv` output against `nix-instantiate` across the whole AOS package
set; it is specified in [compatibility constraints](02-compatibility-constraints.md)
and [differential testing](15-differential-testing-and-benchmarking.md), and
restated as a success criterion in §6.

---

## 3. Goals

The goals below are ordered by priority. The ordering matters: it is the same
ordering that drives the ranked roadmap in [roadmap](17-roadmap-and-risks.md),
and it reflects the belief that the *systemic* wins dwarf the constant-factor
ones.

### G1 — Byte-identical `.drv` and store-path parity (correctness floor)

The non-negotiable. aos-nix must be a drop-in replacement for the
eval-to-`.drv` path such that, for every package and system variant in AOS, the
emitted derivation graph is byte-identical to C++ Nix's. This is the floor
beneath every other goal; a faster-but-divergent evaluator is worthless here.

### G2 — Eliminate redundant evaluation across runs (the order-of-magnitude win)

Model evaluation as a demand-driven incremental computation graph in the
tradition of **Salsa** (rust-analyzer), **Adapton**, **Skip**, and *Build
Systems à la Carte*. Memoize each thunk/derivation result keyed on a hash of
its expression plus captured environment, persist that memo
content-addressed across runs, and apply **early cutoff**: when a recomputed
node's value-hash equals its prior value-hash, stop propagation. A comment edit
recomputes nearly nothing. This is the single biggest expected real-world win,
it is largely independent of raw interpreter speed, and it is *sound only
because Nix is pure*. It extends AOS's existing Attic cache from build outputs
to **eval outputs**, shared across CI machines.

### G3 — Make laziness nearly free (delete allocation, not just speed it up)

Apply whole-program GHC-style analyses that C++ Nix and Tvix/Snix do *not*
perform: **strictness/demand analysis** with the **worker-wrapper transform**
so always-forced bindings compile *eagerly* with zero thunk allocation;
**cardinality/usage analysis** (0/1/many) so single-entry thunks shed their
blackhole/update machinery and dead bindings are eliminated; **full-laziness /
let-floating** so thunks built inside `map`/`genList` loops are computed once;
and HotSpot-style **escape analysis + scalar replacement** so short-lived
non-escaping attrsets and thunks are kept in registers/stack rather than
heap-allocated. Nix's purity makes these *far* more effective than on Java. See
[laziness analyses](07-laziness-and-whole-program-analyses.md).

### G4 — A best-in-class allocator and GC, replacing Boehm

All allocation flows through runtime symbols (`aos_alloc_*`) so the GC strategy
can swap without touching JIT-emitted code. For the one-shot CLI case, a
**bump-pointer arena that never frees** and is dropped wholesale at process
exit — the fastest possible allocator for a batch job. For the long-lived
daemon case, a **precise generational copying collector** with a
cache-resident nursery (the generational hypothesis is extreme here:
intermediate thunks die instantly), *precise* rather than Boehm-conservative to
eliminate false retention, with concurrent low-pause collection
(ZGC/Shenandoah-style colored pointers + load barriers) reserved for daemon
mode. This directly replaces what is C++ Nix's dominant runtime cost. See
[memory management](06-memory-management-and-gc.md).

### G5 — Fast attribute-set access and updates

Attrsets are the hottest data structure in Nix. Borrow **V8 hidden classes /
shapes** with transition trees so attrsets reaching a program point share a
shape and access becomes a shape-check plus a constant-offset load; add
**polymorphic inline caches** on `select` sites; and represent the `//` update
operator as a shape transition + flat-array copy for small sets, falling back
to a **HAMT / persistent immutable map** with structural sharing for
large/override-heavy sets. Intern symbols to `u32`. See
[attribute sets](09-attribute-sets-hidden-classes-and-inline-caches.md).

### G6 — Tiered execution that beats C++ Nix on raw eval, with a correctness oracle

Adopt the **HotSpot tiered-compilation** model: a tier-0 tree-walking
interpreter that is the correctness *oracle* (and the path for cold, run-once
thunks and for debuggability); a tier-1 **Cranelift baseline JIT** for hot
thunks; a tier-2 Cranelift optimized tier with speculation, deoptimization
(uncommon traps), and on-stack replacement; with profile-guided promotion.
Cranelift is chosen for fast compile/warmup and its pure-Rust, hermetic-friendly
nature (see §4 and [execution tiers](08-execution-tiers-and-cranelift.md)).

### G7 — Sound parallel evaluation

A pure language makes parallel evaluation *sound*, but the thunk graph is shared
mutable state (forcing mutates a thunk). The low-risk first cut evaluates
independent top-level derivations on a work-stealing pool, each with its own
nursery, sharing only immutable parsed-IR / symbol / hash-cons tables. The
aggressive version uses **lock-free CAS thunks** (claim-to-force, work-steal or
help on blackhole) in the spirit of GHC's spark model and Determinate Systems'
parallel Nix eval. See [parallel evaluation](13-parallel-evaluation.md).

### G8 — Clean, gated integration with a permanent fallback

Introduce a `NixEval` trait in `aos-core`; keep `NixCli` (subprocess) as a
**permanent** fallback and ship `NixNative` (aos-nix) behind an `AOS_NIX_NATIVE`
gate, **default OFF** until the differential harness is green on the full
closure. See [integration](14-integration-with-aos.md).

---

## 4. Non-goals

Equally important is what aos-nix will **not** do. Scoping discipline is the
primary defense against the project's largest risk — that the full SOTA design
is research-grade and unbounded (see [roadmap](17-roadmap-and-risks.md)).

### N1 — We do not replace the builder

aos-nix evaluates expressions to `.drv` files and store paths. It does **not**
realise derivations, run build sandboxes, substitute from binary caches, or
manage NAR/narinfo beyond emitting byte-identical derivations. Real Nix builds
the `.drv` aos-nix produces. Eval and build are distinct phases; we attack only
eval.

### N2 — We do not change Nix's on-disk formats or hashing

ATerm `.drv` serialization, store-path layout, SHA-256 derivation hashing, and
string-context semantics are *fixed* by the requirement to match C++ Nix. We
implement them faithfully; we do not improve, modernize, or "fix" them. Our own
faster hashes (xxh3, blake3) are internal-only and never observed by Nix.

### N3 — We are not a general-purpose, spec-pure Nix

We target **bug-for-bug** compatibility with C++ Nix as deployed, on the subset
of the language and primops that the AOS package set exercises. We are not
chasing a clean-room reimplementation of an idealized Nix semantics, nor every
obscure corner of the language unused by AOS. The conformance suite (reused from
C++ Nix, as Tvix/Snix does) sets the breadth bar; the AOS package set sets the
acceptance bar.

### N4 — We do not default-on until parity is proven

aos-nix ships disabled. There is no flag day. The native path is opt-in
(`AOS_NIX_NATIVE=1`) until the differential harness is byte-green across the
full AOS closure, and `NixCli` remains a permanent escape hatch even afterward.

### N5 — We do not adopt LLVM, WASM, or a conservative GC

These are explicitly rejected backends/strategies (§4 below and
[execution tiers](08-execution-tiers-and-cranelift.md)): LLVM's compile latency
is wrong for a JIT; WASM buys sandboxing/portability we do not need and fights
our custom GC; Boehm conservative GC is the cost we are *removing*. LLVM may
return *only* as an optional AOT cache tier for a small, stable hot core.

### N6 — We do not chase microbenchmark glory

We are not optimizing for synthetic eval microbenchmarks. The metric is
wall-clock eval time on real AOS workloads, gated on `.drv` parity. We treat
Tvix/Snix's ~10× microbenchmark figure as suggestive but, per the Snix
project's own disclaimer, not predictive of real-world performance.

### Backend selection, stated as a non-goal boundary

The canonical decision, recorded here and justified in
[execution tiers](08-execution-tiers-and-cranelift.md):

| Backend | Verdict | Rationale |
|---|---|---|
| **Cranelift** | **Chosen** | Pure-Rust JIT; codegen ~an order of magnitude faster to *compile* than LLVM (Wasmtime's own measurements), at a modest runtime cost (~a few % vs TurboFan; ~14% vs LLVM). Fast warmup fits a per-expression-compiled, tiered evaluator and AOS's hermetic ethos. |
| LLVM | Rejected (mostly) | Superior steady-state codegen but far slower to compile — wrong tradeoff for a JIT whose thunks are compiled on demand. Permitted *only* as an optional AOT cache tier for a stable hot core. |
| WASM | Rejected | Sandboxing/portability we don't need; adds a host-boundary cost and fights the custom precise GC. |
| Copy-and-patch | Noted alternative | An ultra-low-warmup option worth measuring against Cranelift baseline if warmup ever dominates. |

---

## 5. The measure-first gate

> **No optimizing-compiler work begins until we have *measured* that evaluation
> — not building, not I/O — is the dominant cost on representative AOS
> workloads.**

This gate exists because the entire premise of aos-nix ("eval is a bottleneck")
is an empirical claim, and the cost of being wrong is enormous: building a
tiered JIT and a precise GC to accelerate a phase that turns out to be 5% of
wall-clock is a catastrophic misallocation. The synthesis thesis is only worth
pursuing if the measurement supports it.

### 5.1 What we measure, and how

The gate is cleared by a measurement protocol, not a vibe:

1. **Phase attribution on real workloads.** Time `nix-instantiate` (pure eval)
   separately from `nix-build` (eval + realise) across a representative slice of
   AOS: a full system-variant toplevel, the toolchain closure, and a spread of
   leaf packages. Establish what fraction of end-to-end wall-clock is *eval*.
2. **`NIX_SHOW_STATS`.** C++ Nix's built-in instrumentation reports thunks
   forced, function calls, GC time, allocation counts, and symbol-table sizes.
   This both quantifies the eval cost *and* tells us *where* it goes — thunk
   churn vs. GC vs. attrset access — directly informing which of G2–G6 pays
   off first.
3. **Cold vs. warm.** Measure first-run (cold parse + eval) against
   re-evaluation of the same closure. A large cold/warm gap is direct evidence
   for the G2 incremental-cache thesis; a small gap with high `NIX_SHOW_STATS`
   GC time points instead at G4.

### 5.2 Gate outcomes

```text
   measure eval share of wall-clock on AOS workloads
                 │
        ┌────────┴─────────┐
        │                  │
   eval dominant       eval minor
        │                  │
   PROCEED with        STOP / re-scope:
   the ranked          the bottleneck is build or I/O;
   roadmap (G2 first)  an evaluator does not help
```

The gate is not a one-time ceremony. Per-commit benchmarking (Windtunnel-style)
and the `NIX_SHOW_STATS`/`AOS_NIX`-stats counters keep the measurement live, so
that *each* optimization in the roadmap is justified by a measured delta before
it lands, not by belief that it "should" be faster. The corollary mantra,
carried throughout the set: **the fastest evaluator is the one that does not
evaluate** — which is why G2 (the incremental cache) leads the roadmap even
though it is "less interesting" than a JIT.

### 5.3 Build order implied by the gate

Because the gate demands a baseline number and a parity proof *before* any
optimizing compiler, **phase 1 is fixed**: build the recursive-descent parser,
scope resolution, the tree-walk oracle, and the differential `.drv` harness
*first*. That phase simultaneously (a) yields the baseline eval-time number the
gate needs, and (b) proves byte-identical parity is achievable on the AOS
constructs that matter — *before* a single Cranelift instruction is emitted.
The full ordering is in [roadmap](17-roadmap-and-risks.md).

---

## 6. Success criteria

aos-nix is successful when, and only when, all of the following hold. They are
written to be falsifiable.

### C1 — Parity (the gate, hard)

The differential harness diffs aos-nix's emitted `.drv` files against
`nix-instantiate` across the **entire** AOS package set and reports
**byte-identical** derivations and store paths, with zero divergences. String
contexts and attribute iteration order match exactly. This is a *binary*
criterion: anything short of zero divergence fails C1, because any single
divergence can trigger a from-source toolchain rebuild. See
[compatibility constraints](02-compatibility-constraints.md).

### C2 — Conformance

aos-nix passes the C++ Nix language conformance test suite (reused as Tvix/Snix
does) for the language subset and primops AOS exercises, with documented,
intentional exclusions for unused corners only.

### C3 — Real-world eval speedup

On representative AOS workloads (full system-variant toplevel; toolchain
closure; leaf-package spread), measured wall-clock **eval** time is materially
faster than C++ Nix, with the bulk of the win attributable to the G2 incremental
early-cutoff cache on warm runs and to G3/G4/G5/G6 on cold runs. The number is
reported via the per-commit benchmark harness, not asserted. We explicitly do
*not* commit to a specific multiple up front; the measure-first discipline
(§5) sets the target from the baseline.

### C4 — Early-cutoff effectiveness

A semantically-irrelevant edit (a comment change; a whitespace change; a change
to a leaf package far from the toolchain) recomputes a *small, bounded* fraction
of the closure and emits an unchanged `.drv` for everything downstream of the
unchanged value-hash. This is the direct test of G2 and the incremental cache's
early-cutoff property.

### C5 — Safe integration

`NixNative` is selectable behind `AOS_NIX_NATIVE=1`, `NixCli` remains a working
permanent fallback, and the default path is unchanged until C1 is green on the
full closure. The `unsafe` surface (NaN-boxing, JIT fn-ptr calls, raw heap) is
confined and `// SAFETY`-commented, with miri/sanitizer CI kept green on the
safe tree-walk oracle — the justified exception to AOS's "avoid `unsafe` at all
costs" rule (see [integration](14-integration-with-aos.md)).

### C6 — Measurement-justified evolution

Every optimization that lands is accompanied by a measured delta on the
benchmark harness. No optimization ships on faith. This is the success
criterion for the *process*, and it is what keeps the research-grade scope
bounded.

### Success-criteria summary

| ID | Criterion | Type | Owning document |
|----|-----------|------|-----------------|
| C1 | Byte-identical `.drv` / store paths across all of AOS | Binary gate | [02](02-compatibility-constraints.md), [15](15-differential-testing-and-benchmarking.md) |
| C2 | Passes C++ Nix conformance suite (AOS subset) | Pass/fail | [15](15-differential-testing-and-benchmarking.md) |
| C3 | Materially faster real-world eval wall-clock | Measured | [15](15-differential-testing-and-benchmarking.md) |
| C4 | Bounded recomputation on irrelevant edits | Measured | [12](12-incremental-evaluation-cache.md) |
| C5 | Gated, fallback-safe, confined `unsafe` | Structural | [14](14-integration-with-aos.md) |
| C6 | Each optimization justified by a measured delta | Process | [15](15-differential-testing-and-benchmarking.md) |

---

## 7. Open questions

Marked explicitly so the design record does not overstate certainty.

- **Does G2 alone clear the goal?** It is plausible that the incremental
  early-cutoff cache solves the AOS build-time problem on its own, making the
  tiered JIT (G6) a measured-but-deferred follow-up. The measure-first data from
  phase 1 should settle this. *Open until measured.*
- **What is the real cold-eval ceiling on AOS?** We do not yet have the baseline
  `nix-instantiate` + `NIX_SHOW_STATS` numbers for the AOS closure that the gate
  (§5) demands. Until phase 1 produces them, C3's target multiple is undefined
  by design.
- **How stable is `nix-compat`?** We depend on Snix's `nix-compat` crate for
  ATerm/store-path/NAR formats, pinned to a git rev. Its API is pre-1.0; we
  expect to track it closely and contribute fixes upstream. *Risk, tracked in
  [roadmap](17-roadmap-and-risks.md).*
- **Long tail of `.drv` divergence.** C1 is binary, but reaching it may surface
  a long tail of subtle quirks (float formatting, error-message-as-value edge
  cases, `__structuredAttrs`, context-propagation corners). The harness must be
  run on the *full* closure, repeatedly, before default-on. *Open until the
  harness is byte-green.*
- **NaN-boxing vs. tagged values.** Nix ints are `i64` and do not fit a
  NaN-box payload; the first cut uses a 16-byte tagged value, with NaN-boxing
  as a *measured* optimization rather than a baseline assumption (see
  [value representation](05-value-representation.md)). Whether NaN-boxing pays
  off net of its complexity is open until measured.

---

## References

External claims in this document were verified against the following sources.

- Snix (the March 2025 fork/rename of Tvix) and `tvix-eval`'s bytecode-VM
  architecture and stated scope:
  - Announcing Snix — https://snix.dev/blog/announcing-snix/
  - Snix project repository — https://git.snix.dev/snix/snix
  - `tvix_eval` crate docs — https://docs.tvix.dev/rust/tvix_eval/index.html
  - Tvix project site — https://tvix.dev/
  - devenv switching its Nix implementation to Tvix (Oct 2024) —
    https://devenv.sh/blog/2024/10/22/devenv-is-switching-its-nix-implementation-to-tvix/
- Cranelift's compile-speed-vs-LLVM tradeoff and JIT use in Wasmtime:
  - Cranelift README — https://github.com/bytecodealliance/wasmtime/blob/main/cranelift/README.md
  - Cranelift vs. LLVM comparison — https://github.com/bytecodealliance/wasmtime/blob/main/cranelift/docs/compare-llvm.md
  - Cranelift project site — https://cranelift.dev/
- GHC strictness/demand analysis, usage (cardinality) analysis, and the
  worker-wrapper transform:
  - GHC User's Guide, "Optimisation (code improvement)" —
    https://downloads.haskell.org/ghc/9.12.1/docs/html/users_guide/using-optimisation.html
- Nix derivation hashing (ATerm → SHA-256 → 160-bit truncation → base-32) and
  input-addressed store paths:
  - Nix Reference Manual, "Store Derivation and Deriving Path" —
    https://nix.dev/manual/nix/2.34/store/derivation/
  - "What's in a Nix store path" — https://fzakaria.com/2025/03/28/what-s-in-a-nix-store-path
