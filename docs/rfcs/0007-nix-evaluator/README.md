# RFC-0007: aos-nix - a state-of-the-art Nix evaluator in Rust

- **Status:** Proposed (design only - no implementation in this PR)
- **Date:** 2026-06-15
- **Audience:** anyone working on `crates/aos-nix` (proposed), on the
  `NixEval` seam in `crates/aos-core/src/nix/`, or on AOS build/eval
  performance more broadly.

## Problem

Nix **evaluation** - parsing `.nix` files and lazily reducing the
expression tree into a `.drv` derivation graph - is a repeated,
on-the-critical-path cost in AOS builds and CI. It is a distinct phase
from **building** (realising a `.drv` into store paths by running
compilers): a faster evaluator attacks only the former. Today the `aos`
CLI shells out to `nix-instantiate` / `nix-build` / `nix-store` via
`NixCli` (`crates/aos-core/src/nix/store.rs`); every eval pays C++ Nix's
tree-walking interpreter and Boehm conservative GC, with no cross-run
memoization of evaluation results.

This RFC designs **aos-nix**, a from-scratch Nix language evaluator in
Rust that replaces the **eval** path only (`eval -> .drv`); real Nix
continues to **build** the resulting `.drv`. The hard constraint that
dominates every decision: aos-nix must produce **byte-identical `.drv`
files and store paths** as C++ Nix (SHA-256, exact string-context
semantics). Any divergence yields a different store path, a total cache
miss, and a rebuild of the from-source toolchain - catastrophic in this
repo. Compatibility is therefore gated by a **differential harness** that
diffs aos-nix output against `nix-instantiate` across the whole AOS
package set.

The design thesis: a fast Nix evaluator is a fast implementation of a
lazy, dynamically-typed, garbage-collected functional language *plus* an
incremental recomputation layer - and Nix's purity, value immutability,
and whole-program batch nature make techniques that are partial or
unsound elsewhere (GHC strictness analysis, V8 hidden classes, HotSpot
escape analysis, Salsa/Adapton early-cutoff memoization) become total and
sound here.

## Goals

- A Rust evaluator that is **bug-for-bug compatible** with C++ Nix on
  `.drv` and store-path output, proven by a differential harness.
- Substantially faster cold evaluation than C++ Nix, and near-free
  **re-evaluation** of an unchanged package set via a persistent,
  early-cutoff incremental cache.
- A safe, debuggable **tree-walk oracle** tier alongside a **Cranelift**
  JIT, with profile-guided promotion and deoptimization.
- A clean integration seam (`trait NixEval`) so the native evaluator is
  opt-in and the existing subprocess path remains a permanent fallback.
- A measure-first discipline: confirm eval (not build) is the bottleneck,
  and quantify every optimization against the harness and benchmarks.

## Non-goals

- **Replacing the Nix builder.** aos-nix emits `.drv`; realisation stays
  with Nix (and AOS's existing store/cache tooling, RFC-0005).
- **General nixpkgs compatibility.** The target corpus is AOS's own
  package set; nixpkgs-scale coverage is explicitly out of scope.
- **Defaulting on before parity is proven.** `AOS_NIX_NATIVE` stays off
  until the differential harness is green on the full closure.
- **A stable public API or a new CLI surface** beyond the `NixEval` seam
  and diagnostic subcommands.

## Document index

| Doc | Topic |
| --- | --- |
| [01](01-motivation-and-goals.md) | Why eval is a build-time bottleneck; eval vs build; measure-first; goals, non-goals, and success criteria |
| [02](02-compatibility-constraints.md) | Bug-for-bug `.drv`/store-path parity, string contexts, SHA-256, and the differential acceptance gate |
| [03](03-architecture-overview.md) | The layered stack, the four hard problems, the purity synthesis thesis, and the execution-tier model |
| [04](04-frontend-parser-and-ir.md) | Lexer, recursive-descent parser, compact arena AST, scope resolution to slot indices, and parse caching |
| [05](05-value-representation.md) | Tagged / NaN-boxed values, GHC-style pointer tagging for WHNF, and hash-consing / maximal sharing |
| [06](06-memory-management-and-gc.md) | Bump-arena one-shot heap, precise generational GC, region inference, and allocation via runtime symbols |
| [07](07-laziness-and-whole-program-analyses.md) | Thunks; strictness/demand + worker-wrapper, cardinality, full-laziness, escape analysis + scalar replacement |
| [08](08-execution-tiers-and-cranelift.md) | Tree-walk oracle, Cranelift baseline/optimized tiers, deopt, OSR, the runtime ABI, and why Cranelift over LLVM/WASM |
| [09](09-attribute-sets-hidden-classes-and-inline-caches.md) | Hidden classes/shapes, polymorphic inline caches, HAMT for `//`, symbol interning, iteration-order compat |
| [10](10-primops-and-runtime-abi.md) | The ~120 builtins, the runtime symbol table, `import` caching, perfect hashing, and the uniform call ABI |
| [11](11-derivation-and-store-compatibility.md) | `derivationStrict`, ATerm serialization, `nix-compat`, IA/CA output hashing, string contexts, RFC-0005 tie-in |
| [12](12-incremental-evaluation-cache.md) | Demand-driven memoization with early cutoff, content-addressed persistence, Attic integration, hashing policy |
| [13](13-parallel-evaluation.md) | Lock-free CAS thunks, work-stealing forcing, coarse top-level parallelism, and the parallel-GC interaction |
| [14](14-integration-with-aos.md) | The `NixEval` trait, the aos-core seam, `AOS_NIX_NATIVE` gating, `NixCli` fallback, and the `unsafe` policy |
| [15](15-differential-testing-and-benchmarking.md) | The `.drv`-diff harness, conformance-suite reuse, `NIX_SHOW_STATS`, per-commit benchmarking, measure-first |
| [16](16-prior-art-and-references.md) | Tvix/Snix, C++ Nix, hnix, GHC, HotSpot, V8/LuaJIT/PyPy, Salsa/Adapton/Skip, Cranelift - with citations |
| [17](17-roadmap-and-risks.md) | The phased build order, the ranked 90% subset, the risk register, and open questions |
| [18](18-glossary.md) | Terms: WHNF, thunk, hidden class, inline cache, early cutoff, hash-consing, ATerm, deopt, and more |
| [19](19-decision-register.md) | Consolidated decision register: every settled, closed, measure-gated, and research-grade decision, with its resolution or gating measurement |
| [20](20-nix-language-conformance.md) | Nix *language* conformance checklist: every syntax/semantic/edge-case rule to reproduce for parity (operators, attrsets, fixpoints, scoping, strings/contexts, coercions) |
| [21](21-builtins-conformance.md) | Builtins conformance catalog: every `builtins.*` primop with signature, parity notes, edge cases, and the impure-builtin cache-keying table |
| [22](22-implementation-checklist-all-phases.md) | Implementation checklist across all phases (P1–P8 + P3.5), with deliverables, conformance gates, decisions closed, and exit criteria |

## Decision log

The table below is the top-level summary. The **exhaustive register** — every
settled, review-closed, measure-gated, and research-grade decision, each with its
resolution or the exact measurement that will settle it — is
[19 - decision register](19-decision-register.md). It is the single source of
truth an implementer should work from; nothing measure-gated or research-grade
blocks Phase 1.

| Decision | Rationale |
| --- | --- |
| **Eval-only scope** (`eval -> .drv`); Nix still builds | The bottleneck and the tractable surface is evaluation; realisation stays with proven tooling. See [01](01-motivation-and-goals.md). |
| **Byte-identical `.drv` / store paths; SHA-256** | Any divergence = cache miss = toolchain rebuild. Non-negotiable, harness-gated. See [02](02-compatibility-constraints.md). |
| **Cranelift** as the JIT backend (not LLVM, not WASM) | Pure-Rust, fast compile/warmup, fits the hermetic ethos; LLVM is an optional AOT tier only; WASM fights the custom GC. See [08](08-execution-tiers-and-cranelift.md). |
| **Tree-walk oracle + tiered JIT** | The tree-walker is the correctness oracle, the cold/run-once path, and the debuggable baseline; Cranelift handles hot thunks. See [03](03-architecture-overview.md), [08](08-execution-tiers-and-cranelift.md). |
| **Compile per-expression once**, not per thunk-activation | Bounds the compile units to the static program; thunks are `(code, env, state)` instances. See [03](03-architecture-overview.md). |
| **Bump-arena "never free" -> precise generational GC** | One-shot eval drops the whole arena at exit (fastest allocator); a daemon swaps in a precise moving collector behind the alloc symbols. Replaces Boehm. See [06](06-memory-management-and-gc.md). |
| **Hash-consing / maximal sharing** | Immutable values make structural interning sound: heap dedup, O(1) equality, trivial cache keys. See [05](05-value-representation.md). |
| **Whole-program laziness analyses** (strictness, escape, full-laziness) | Delete the majority of thunk and attrset allocations before they happen; sound because Nix is pure. See [07](07-laziness-and-whole-program-analyses.md). |
| **Hidden classes + inline caches for attrsets** | Attribute access is the hottest op; shapes turn it into a guard + constant-offset load. See [09](09-attribute-sets-hidden-classes-and-inline-caches.md). |
| **Incremental early-cutoff eval cache** is the headline win | The fastest evaluator is one that does not evaluate; unchanged inputs recompute almost nothing. Often bigger than any constant factor. See [12](12-incremental-evaluation-cache.md). |
| **Hashing split:** xxh3 / blake3 / SHA-256 | xxh3 in-process; blake3 for the durable/shared cache (collision-safe); SHA-256 *only* for Nix-observed `.drv`/store hashes. See [12](12-incremental-evaluation-cache.md). |
| **`NixEval` trait + `AOS_NIX_NATIVE` gate** | Native eval is opt-in; `NixCli` subprocess remains a permanent fallback; default off until parity proven. See [14](14-integration-with-aos.md). |
| **`unsafe` is the justified exception here** | NaN-boxing, JIT fn-ptr calls, and a raw heap require it; mitigated with SAFETY comments and miri/sanitizer CI on the safe tier. See [14](14-integration-with-aos.md). |
| **Measure-first** | Confirm eval, not build, is the bottleneck before optimizing; quantify against the harness. See [15](15-differential-testing-and-benchmarking.md). |
| **Content-addressed derivations are first-class** | CA is in the first acceptance gate (not deferred); AOS's store model is content-addressed (RFC-0005). See [11](11-derivation-and-store-compatibility.md), [19](19-decision-register.md) C-11. |
| **Parallel graph evaluation is promoted early** | Lock-free CAS thunks + work-stealing forcing as an early phase (P3.5), not a rank-5 tail; sequential oracle stays ground truth, `loom`/Miri-gated. Concurrent *moving* GC stays deferred. See [13](13-parallel-evaluation.md), [19](19-decision-register.md) C-12. |

## Roadmap

Build order (full detail in [17](17-roadmap-and-risks.md)):

1. **Phase 1 - oracle + gate.** Parser, scope resolution, a tree-walk
   interpreter (the correctness oracle), and the differential `.drv`-diff
   harness. This yields the baseline eval-time number *and* proves parity
   is achievable on AOS's hand-rolled `mkDerivation` / `ccWrapper` /
   `evalModules` constructs - before any Cranelift work.

Then the ranked **90% subset**, in order:

2. **Incremental early-cutoff cache + hash-consing** - the biggest
   real-world win, largely independent of interpreter speed; may solve
   the build-time problem on its own.
3. **Bump-arena one-shot heap + precise generational GC.**
4. **Strictness + escape analysis** - deletes most allocations; helps
   even the tree-walk tier.
5. **Hidden classes + inline caches, then Cranelift tiering + deopt.**

Everything else (pointer tagging, full-laziness, region inference,
parallel forcing, concurrent GC) is a measured, profile-driven follow-up.

> An RFC is a design record, not living documentation. Once aos-nix
> ships, this body is frozen and only the status header above is
> maintained; canonical docs elsewhere in `docs/` will describe how the
> evaluator works in the tree.
