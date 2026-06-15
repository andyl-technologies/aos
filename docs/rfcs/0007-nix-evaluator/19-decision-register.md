# RFC-0007 - Decision register

This is the **single source of truth for every design decision** in the RFC-0007
set: what is settled, what was closed during review, what is deliberately left to
measurement, and what is explicitly deferred as research-grade. It exists so an
implementer never has to reconstruct the decision state by reading sixteen
scattered "Open questions" sections — every fork is here, with its resolution or
its gating condition and a pointer to the owning document.

## How to read this

Each row carries a **status**:

| Status | Meaning | Implementer action |
| --- | --- | --- |
| **Settled** | Decided as a baseline architectural choice in the design docs. | Build it as written. |
| **Closed** | Was an open question; **resolved during the review pass** (recorded both here and in the owning doc). | Build the recorded resolution. |
| **Measure-gated** | A *default* is specified; whether to change it is decided by the differential harness / profiler, not by design. | Build the default; revisit only if the named measurement says so. |
| **Research-grade** | Deferred; outside the ranked "90% subset". A default (often "don't build it yet") is given. | Do not build in the first cuts; the default holds. |

The crucial property: **nothing that is Measure-gated or Research-grade blocks
Phase 1.** Phase 1 ([roadmap](17-roadmap-and-risks.md) §6) touches only Settled
and Closed decisions. Measurement-dependent and research-grade items are, by
construction, downstream of the baseline the gate produces.

---

## 1. Settled baseline decisions

The load-bearing architectural calls, already made in the design and mirrored in
the [README decision log](README.md#decision-log).

| ID | Decision | Resolution | Owner |
| --- | --- | --- | --- |
| S-1 | Scope | Eval-only (`eval -> .drv`); real Nix still builds. | [01](01-motivation-and-goals.md) |
| S-2 | Compatibility bar | Byte-identical `.drv` + store paths vs C++ Nix; SHA-256; harness-gated; default-off until green. | [02](02-compatibility-constraints.md) |
| S-3 | JIT backend | Cranelift (pure-Rust). LLVM is an optional AOT tier only; WASM rejected. | [08](08-execution-tiers-and-cranelift.md) |
| S-4 | Execution model | Compile per-expression once; thunks are `(code, env, state)` instances. | [08](08-execution-tiers-and-cranelift.md) |
| S-5 | Tiering | Permanent tree-walk oracle → Cranelift baseline → optimized + deopt/OSR. | [03](03-architecture-overview.md), [08](08-execution-tiers-and-cranelift.md) |
| S-6 | Value layout | 16-byte tagged `Value`, i64/f64 inline; pointer-tag `FORCED` shortcut. | [05](05-value-representation.md) |
| S-7 | Sharing | Hash-consing / maximal sharing of immutable values (O(1) equality, cheap cache keys). | [05](05-value-representation.md) |
| S-8 | Heap | Bump-arena "never free" (Tier A) → precise generational GC (Tier B); alloc via runtime symbols; replaces Boehm. | [06](06-memory-management-and-gc.md) |
| S-9 | Laziness | Whole-program strictness/demand + worker-wrapper, cardinality, full-laziness, escape analysis + scalar replacement. | [07](07-laziness-and-whole-program-analyses.md) |
| S-10 | Attrsets | Hidden classes + polymorphic inline caches + HAMT for `//`; `u32` symbol interning; deterministic iteration order. | [09](09-attribute-sets-hidden-classes-and-inline-caches.md) |
| S-11 | Frontend | Hand-written recursive-descent + Pratt → compact arena AST; de Bruijn slots; content-addressed parse cache. | [04](04-frontend-parser-and-ir.md) |
| S-12 | Primops | ~120 builtins as plain Rust, registered as JIT symbols; uniform `extern "C"` ABI; `import` cached by realpath + content hash. | [10](10-primops-and-runtime-abi.md) |
| S-13 | Derivation path | `derivationStrict` → `nix-compat` `Derivation` → ATerm → SHA-256 output paths; never reimplement `compressHash`. | [11](11-derivation-and-store-compatibility.md) |
| S-14 | Incremental cache | Demand-driven memoization with early cutoff; the headline systemic win; sound because Nix is pure. | [12](12-incremental-evaluation-cache.md) |
| S-15 | Hashing split | xxh3 in-process; blake3 durable/shared cache; SHA-256 *only* for Nix-observed hashes. | [12](12-incremental-evaluation-cache.md) |
| S-16 | Integration | `trait NixEval` seam; `AOS_NIX_NATIVE` gate; `NixCli` permanent fallback; staged rollout. | [14](14-integration-with-aos.md) |
| S-17 | `unsafe` policy | Justified exception (NaN-box/JIT/raw heap); `// SAFETY:` comments; miri/sanitizer CI on the safe tree-walk tier. | [14](14-integration-with-aos.md) |
| S-18 | Process discipline | Measure-first: confirm eval (not build) is the bottleneck before optimizing. | [01](01-motivation-and-goals.md), [15](15-differential-testing-and-benchmarking.md) |

---

## 2. Decisions closed during the review pass

These were open questions in the first draft; each is now **resolved** here and
in the owning doc, so an implementer of the relevant component has the call made.

| ID | Was open | Decision | Owner |
| --- | --- | --- | --- |
| C-1 | Cache-key free-variable combiner | **Ordered, length-prefixed combiner**, hashed once — never bare XOR (XOR is order/multiplicity-blind and would cause false cache hits = a correctness bug). | [12](12-incremental-evaluation-cache.md) §3.2 |
| C-2 | Is the strictness FV set precise enough, or is a dedicated minimization pass needed? | **Baseline reuses the strictness/escape FV set**; a dedicated dependency-minimization pass is a *measure-gated* follow-up (imprecision is a perf bug, never correctness). | [12](12-incremental-evaluation-cache.md) §8.1 |
| C-3 | Cache transport: through `NixEval` or beside it? | **Beside the trait.** Push/pull rides the existing Attic content-addressed path; `NixEval` stays minimal and transport-agnostic. | [14](14-integration-with-aos.md) §12 |
| C-4 | `eval_expr` JSON-rendering parity | **A dedicated `--eval --json` differential check**, owned by doc 15, required green before Phase C. | [14](14-integration-with-aos.md) §12, [15](15-differential-testing-and-benchmarking.md) |
| C-5 | `nix-compat` / Cranelift revision churn | **Pin exact git revs (`Cargo.lock`); vendor only patched modules; gate every bump on the full `.drv` harness.** Breakage becomes a maintenance event, never a silent correctness event. | [14](14-integration-with-aos.md) §12 |
| C-6 | First acceptance-gate scope: IA-only or include CA? | **Input-addressed only** for the first green gate (CA is the IA-dominated set's thin tail); CA parity is designed-in but deferred to synthesized CA fixtures. | [02](02-compatibility-constraints.md) §8, [11](11-derivation-and-store-compatibility.md) §5.4 |
| C-7 | Permanent `rnix → arena IR` shim, or hand-roll only? | **Hand-roll exclusively;** rnix is a test-only differential oracle. No second production frontend to keep in parity. | [04](04-frontend-parser-and-ir.md) §12 |
| C-8 | Are single-entry (blackhole-skipping) thunks sound under parallel forcing? | **Yes, when restricted to escape-analysis-proven *frame-local* thunks.** Escaped thunks keep the full CAS protocol regardless of cardinality. No sequential-tier carve-out needed. | [07](07-laziness-and-whole-program-analyses.md) §10 |
| C-9 | Which Nix version / `NIX_SHOW_STATS` schema to baseline against? | **Pin the single C++ Nix version AOS builds with** (same rev as the `nix-compat` pin); parse stats defensively; bumps are deliberate + harness-gated. | [15](15-differential-testing-and-benchmarking.md) §9 |
| C-10 | Daemon vs per-invocation process | **Per-invocation first** (Tier-A arena). A persistent eval daemon is a measure-gated follow-up; the `NixEval` seam is unchanged by that later flip. | [14](14-integration-with-aos.md) §12 |

---

## 3. Measure-gated decisions

A default is specified and buildable today; the differential harness or profiler
decides whether to change it. **None of these block Phase 1** — most are
*downstream* of the baseline numbers Phase 1 produces.

| ID | Question | Default (build this) | Decided by | Owner |
| --- | --- | --- | --- | --- |
| M-1 | Does the incremental cache alone clear the build-time goal? | Build cache + arena + oracle first; treat the JIT as deferred. | Phase 1/2 baseline vs warm numbers. | [01](01-motivation-and-goals.md), [17](17-roadmap-and-risks.md) |
| M-2 | What is the real cold-eval ceiling on AOS? | (No default — Phase 1 *produces* it.) | Phase 1 `nix-instantiate` + `NIX_SHOW_STATS`. | [01](01-motivation-and-goals.md) |
| M-3 | What fraction of CI eval is cold vs warm? | Assume re-eval-dominated; validate. | Instrumented CI traces. | [12](12-incremental-evaluation-cache.md) §8.1 |
| M-4 | Does NaN-boxing pay off net of the i64-box tax? | 16-byte tagged value (no NaN-boxing). | Register-passing benchmark. | [05](05-value-representation.md) §12 |
| M-5 | Does the Cranelift JIT pay for itself in one-shot CLI mode? | Tree-walk + cache; JIT reserved for where it profiles well; copy-and-patch is the hedge. | Warmup-vs-one-shot benchmark. | [08](08-execution-tiers-and-cranelift.md) §10 |
| M-6 | Is OSR worth its complexity? | No OSR in the first JIT cut. | Profile for long single activations. | [08](08-execution-tiers-and-cranelift.md) §10 |
| M-7 | Scalar-replace across deopt points? | No (conservative: never across a deopt point). | Harness once tiering is real. | [08](08-execution-tiers-and-cranelift.md) §10 |
| M-8 | Copy-and-patch vs Cranelift for tier 1? | Cranelift baseline. | Tier-1 compile-time profile. | [08](08-execution-tiers-and-cranelift.md) §5.4 |
| M-9 | Inline the hottest primops into Cranelift IR? | Symbol-call only. | Per-primop benchmark. | [10](10-primops-and-runtime-abi.md) §9 |
| M-10 | Speculate on monomorphic dynamic `builtins.${name}`? | PHF slow path. | Site-frequency profile. | [10](10-primops-and-runtime-abi.md) §9 |
| M-11 | Cache memoization granularity (which nodes). | Start coarse (derivations + heavy library nodes), measure. | AOS traces (hit/overhead). | [12](12-incremental-evaluation-cache.md) §8.2 |
| M-12 | Cons-table sizing under daemon GC. | Hash-cons strings/symbols/derivation-env values; widen only if cheap. | Tier-B scavenge cost. | [05](05-value-representation.md) §12 |
| M-13 | Context bitset vs sorted-smallvec crossover. | COW interned bitset. | Context-cardinality distribution. | [05](05-value-representation.md) §12 |
| M-14 | Region inference vs just the generational GC. | Arena + generational GC first; lexical/escape region pass only where profiles show medium-lived allocation. | Allocation-lifetime profile. | [06](06-memory-management-and-gc.md) §5.2 |
| M-15 | How much cardinality precision to chase. | Standard strictness/worker-wrapper; stop where the cache subsumes the win. | Spurious-recompute + thunk-count stats. | [07](07-laziness-and-whole-program-analyses.md) §10 |
| M-16 | Trivia-suppressing lexer mode for pure eval. | Single lexer with trivia retained. | Hot-path lexer profile. | [04](04-frontend-parser-and-ir.md) §12 |
| M-17 | L1 coarse pool vs L2 intra-derivation parallel forcing. | L1 only first. | Tail-latency / load-imbalance profile. | [13](13-parallel-evaluation.md) §8 |
| M-18 | Cross-nursery shared-value touch cost. | (Assume low; measure under Tier B.) | Multi-worker sharing profile. | [13](13-parallel-evaluation.md) §8 |
| M-19 | Regression-detector noise band + runner pinning. | Use self-hosted-runner determinism; tune a band. | CI timing variance. | [15](15-differential-testing-and-benchmarking.md) §9 |
| M-20 | `__structuredAttrs` JSON byte-parity. | Trust `nix-compat`; verify. | Harness on structured-attrs packages. | [11](11-derivation-and-store-compatibility.md) §12 |
| M-21 | Second-version conformance canary. | Single pinned Nix version only. | Forward-compat need. | [15](15-differential-testing-and-benchmarking.md) §9 |

---

## 4. Research-grade / deferred decisions

Outside the 90% subset. The default is "do not build yet"; the baseline holds.

| ID | Item | Default / stance | Owner |
| --- | --- | --- | --- |
| R-1 | Concurrent moving GC (ZGC/Shenandoah-style) × monotonic thunk mutation. | Daemon-only; single-threaded precise-generational first cut sidesteps it. | [03](03-architecture-overview.md), [13](13-parallel-evaluation.md) |
| R-2 | Tier-2-emitted GC load barriers. | Out of scope for the first JIT; Stage B0 stop-the-world is the shipping answer. | [08](08-execution-tiers-and-cranelift.md), [13](13-parallel-evaluation.md) |
| R-3 | WHNF tag bits vs colored-pointer bits co-design. | Unsolved; may force a wider value. Deferred to daemon GC work. | [13](13-parallel-evaluation.md) §8 |
| R-4 | Load-barrier-on-CAS formal verification (weak memory). | Required before L2 ships; `loom`/Miri on the safe oracle. | [13](13-parallel-evaluation.md) §8 |
| R-5 | Full effect-based region inference. | Flagged research item, not a committed deliverable; the lexical/escape pass is the committed subset. | [06](06-memory-management-and-gc.md) §5.2 |
| R-6 | Daemon float-outward residency policy. | Tuning parameter; no daemon workload exists yet. | [07](07-laziness-and-whole-program-analyses.md) §10 |
| R-7 | Tier-2-only fused "super-node" IR. | Deferred; the "one IR for all tiers" invariant holds until tiering is measured. | [04](04-frontend-parser-and-ir.md) §12 |
| R-8 | Frontend `with`-shape speculation hooks. | Leave entirely to runtime inline caches for now. | [04](04-frontend-parser-and-ir.md) §12, [09](09-attribute-sets-hidden-classes-and-inline-caches.md) |
| R-9 | Escape signatures for the ~120-primop surface. | Hand-authored + **property-test fuzzing** (not just the closure diff), since a wrong escape-transparency claim could corrupt a result; default-off until green. | [07](07-laziness-and-whole-program-analyses.md) §10 |
| R-10 | Impure-primop dependency edges into the cache. | `readFile`/`readDir`/`getEnv`/etc. keyed as explicit content-hash inputs; `currentTime` not cached. Edge-exactness is research-grade. | [10](10-primops-and-runtime-abi.md), [12](12-incremental-evaluation-cache.md) |
| R-11 | Output-placeholder scheme stability across Nix versions. | Track the *specific* pinned `nix-instantiate`; harness runs against exactly it. | [11](11-derivation-and-store-compatibility.md) §12 |
| R-12 | Rare context primops (`addDrvOutputDependencies`, `unsafeDiscardOutputDependency`, `appendContext`). | Reproduced from C++ source; coverage thin → flagged for the conformance suite. | [11](11-derivation-and-store-compatibility.md) §12 |
| R-13 | Differential-fuzzer reduction quality. | `cargo fuzz` minimization first; a Nix-aware reducer only if needed. | [15](15-differential-testing-and-benchmarking.md) §9 |
| R-14 | Cache persistence on-disk schema stability. | Versioned schema; treat as evolvable, not a contract. | [12](12-incremental-evaluation-cache.md) §8.4 |

---

## 5. Process decisions (not design forks)

A few items are neither settled design nor measurable defaults — they are
*activities* the implementation must perform:

- **Error-text parity enumeration.** The first gate scopes to error-*class*
  parity. The AOS packages that assert on error *text* must be enumerated and
  decided per-case before those packages flip to native. Shared between
  [02](02-compatibility-constraints.md) §8 and [15](15-differential-testing-and-benchmarking.md) §9.
- **Diagnostic-message parity depth.** Treated as a soft, best-effort gate
  ([04](04-frontend-parser-and-ir.md) §12); `.drv` parity never depends on it.

---

## 6. Summary

- **18 Settled + 10 Closed decisions** mean Phase 1 — and the rank-1 cache — are
  buildable from this RFC with no unstated design calls.
- **21 Measure-gated** items each carry a buildable default; the harness and
  profiler (not a meeting) decide whether to move off it.
- **14 Research-grade** items are explicitly deferred with a holding default.
- The through-line: this RFC does not pretend every micro-decision is pre-made;
  it pretends *nothing*. Each fork is either decided, or has a default plus the
  exact measurement that will decide it. That is what makes the design
  record honest and the implementation path unambiguous.

See the [roadmap](17-roadmap-and-risks.md) for the order in which these land, and
the [README decision log](README.md#decision-log) for the top-level summary.
