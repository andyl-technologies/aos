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
| **Research-grade** | Committed high-risk work whose implementation policy is selected by measurement and correctness gates. | Build the variants after their prerequisites; keep the measured winner or policy. |

The crucial property: **nothing that is Measure-gated or Research-grade blocks
Phase 1.** Phase 1 ([roadmap](17-roadmap-and-risks.md) §6) touches only Settled
and Closed decisions. Measurement-dependent and research-grade items are, by
construction, downstream of the baseline the gate produces.

> **Budget mandate (see [roadmap](17-roadmap-and-risks.md) §0).** This is an
> unlimited-budget, non-time-bounded build of the absolute fastest evaluator, so
> the two soft statuses are re-read accordingly: **Measure-gated** no longer
> means "defer until proven worth it" — it means **build the competing variants,
> measure, and keep the winner** (e.g. NaN-box vs. tagged value, fiber I/O
> turn-on, inlining thresholds), never shipping a regression. **Research-grade**
> items are **in scope**, not dropped — they remain hard/uncertain but are
> committed deliverables (concurrent moving GC, full region inference, the LLVM
> AOT tier-3). What is *unchanged*: the **Settled** and **Closed** rows, and
> every correctness gate (differential harness, `loom` audit, conformance) —
> those are absolute regardless of budget.

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
| S-17 | `unsafe` policy | A standing, scoped waiver of AOS's "avoid `unsafe` at all costs" rule for this crate, for performance: NaN-box/tagged values, JIT fn-ptr calls, raw heap/GC, stackful fibers, lock-free CAS concurrency, and `mmap`/out-of-core — a surface the unlimited-budget mandate enlarges. Fenced into an audited core (`#![deny(unsafe_op_in_unsafe_fn)]`, `// SAFETY:` on every block) behind a `#![forbid(unsafe_code)]` oracle; gated by miri/ASan/UBSan/`loom`/TSan/fuzz + two-maintainer review; `.unwrap()`/`.expect()` ban still applies. | [14](14-integration-with-aos.md) §10 |
| S-18 | Process discipline | Measure-first: confirm eval (not build) is the bottleneck before optimizing. | [01](01-motivation-and-goals.md), [15](15-differential-testing-and-benchmarking.md) |
| S-19 | IR contract | A single arena IR with a `NodeKind` taxonomy, scope-resolved de-Bruijn form, per-node effect-class annotation, and the "one **Core** IR for all tiers" rule (oracle interprets, Cranelift compiles, simplifier rewrites). The generic **Core** is `ratchet-core`; Nix-specific nodes (`DerivationStrict`, `with`) are a **dialect extension** reached through the indexed escape hatch, not new Core variants ([28](28-generalization-and-language-dialects.md)). | [25](25-intermediate-representation.md), [28](28-generalization-and-language-dialects.md) |
| S-20 | Optimization pass catalog | The simplifier (C-21) specified pass-by-pass over the IR (S-19): matched `NodeKind`s, the before→after rewrite, effect-class/totality/proven-fact preconditions, fixpoint phase order, and committed-vs-measure-gated status. | [26](26-optimization-pass-catalog.md) |
| S-21 | Engineering standards | A workspace of focused crates with a crate-level safe/unsafe fence; `thiserror` errors (`anyhow` only at the binary boundary); `tracing`-only structured logging (no raw stdout/stderr from libraries); docs.rs-quality docs; traits for swappable seams but never `Box<dyn>` on the force hot path; layered tests (unit + differential + conformance + proptest + fuzz + loom + miri + criterion) with a ≥90% core coverage floor; debugging hooks; PR-level commit messages. File-size and dir-tree conventions for 100k+ LOC. The engine crates lose the `aos-nix-` prefix and become `ratchet-value`/`-gc`/`-jit`/`-cache`/`-parallel` (UNSAFE) + `ratchet-core`/`-oracle`/`-dialect` (SAFE); `aos-nix-ir` splits into generic `ratchet-core` plus the SAFE `aos-nix-dialect` ([28](28-generalization-and-language-dialects.md) §3). | [27](27-engineering-standards.md), [28](28-generalization-and-language-dialects.md) |
| S-22 | Core + dialect architecture (`ratchet`), Nix-only delivery | Adopt the MLIR-style Core/dialect factoring and the `ratchet-*` topology: the substrate (demand graph, Core IR, tiers, GC) is a language-agnostic engine `ratchet`; Nix is the first *dialect* that plugs into it. Deliver Nix and only Nix in RFC-0007. Generality is adopted only where free or nearly free (naming, crate boundaries); no second frontend, no abstraction that taxes the byte-identity gate. | [28](28-generalization-and-language-dialects.md) §8 |
| S-23 | Open, dialect-supplied effect lattice | The effect class is an engine trait (`is_speculable` + `effect_key`), not a closed `enum { Pure, Effectful }`; the dialect supplies the members (`import`/IFD/`readFile`/`derivationStrict`). This is the one generalization that touches an UNSAFE engine crate (`ratchet-cache`), which gates speculation/re-execution on the per-node effect tag but never interprets it. | [28](28-generalization-and-language-dialects.md) §5, §8 |

---

## 2. Decisions closed during the review pass

These were open questions in the first draft; each is now **resolved** here and
in the owning doc, so an implementer of the relevant component has the call made.

| ID | Was open | Decision | Owner |
| --- | --- | --- | --- |
| C-1 | Cache-key free-variable combiner | **Ordered, length-prefixed combiner**, hashed once — never bare XOR (XOR is order/multiplicity-blind and would cause false cache hits = a correctness bug). | [12](12-incremental-evaluation-cache.md) §3.2 |
| C-2 | Is the strictness FV set precise enough, or is a dedicated minimization pass needed? | **Baseline reuses the strictness/escape FV set**; a dedicated dependency-minimization pass is a *measure-gated* follow-up (imprecision is a perf bug, never correctness). | [12](12-incremental-evaluation-cache.md) §8.1 |
| C-3 | Cache transport: through `NixEval` or beside it? | **Beside the trait.** Push/pull rides the existing Attic content-addressed path; `NixEval` stays minimal and transport-agnostic. | [14](14-integration-with-aos.md) §13 |
| C-4 | `eval_expr` JSON-rendering parity | **A dedicated `--eval --json` differential check**, owned by doc 15, required green before Phase C. | [14](14-integration-with-aos.md) §13, [15](15-differential-testing-and-benchmarking.md) |
| C-5 | `nix-compat` / Cranelift revision churn | **Pin exact git revs (`Cargo.lock`); vendor only patched modules; gate every bump on the full `.drv` harness.** Breakage becomes a maintenance event, never a silent correctness event. | [14](14-integration-with-aos.md) §13 |
| C-6 | First acceptance-gate scope: IA-only or include CA? | **Both input-addressed AND content-addressed from the first gate** (superseded — see C-11). AOS's store model is content-addressed (RFC-0005), so CA parity is on the critical path, not a tail. | [02](02-compatibility-constraints.md) §8, [11](11-derivation-and-store-compatibility.md) §5.4 |
| C-11 | Content-addressed derivations: deferred or first-class? | **First-class from the start.** `derivationStrict` handles floating + fixed CA outputs in Phase 1; the gate covers CA; coverage comes from CA fixtures + the AOS RFC-0005 realisation graph. Parity targets the *pinned* Nix's CA (ATerm) encoding, which is an experimental/"not yet stable" surface — hence the exact-rev pin (C-5/C-9). | [11](11-derivation-and-store-compatibility.md) §5.4, [02](02-compatibility-constraints.md) §8 |
| C-12 | Parallel thunk-graph evaluation: rank-5 follow-up or first-class? | **First-class, promoted early.** The lock-free compare-and-swap (CAS) thunk protocol is atomic from Phase 1; the L1 work-stealing pool + L2 thunk-graph forcing ([13](13-parallel-evaluation.md)) land as an early phase (P3.5), not P8. Non-negotiable guardrails: the **sequential** tree-walk oracle stays the correctness ground truth, and the parallel tier ships only after the `loom`/Miri memory-ordering audit (R-4, now committed-early) is green. Concurrent *moving* GC (R-1/R-2) stays separate and deferred — one-shot mode uses per-worker bump nurseries + never-free, which sidesteps it. | [13](13-parallel-evaluation.md) |
| C-13 | Durable-cache storage engine | **Two engines by data nature:** a custom mmap'd append-only **packfile** for the immutable content-addressed `values/`/`files/` blobs (zero-copy reads, append-only, GC-by-repack), and **`heed`/LMDB** for `nodes/` metadata + the hash→offset index (zero-copy MVCC reads for parallel workers, single batched writer, tiny hermetic C lib). SQLite (proven in C++ Nix but not zero-copy) and pure-Rust redb noted as alternatives. The cache is *advisory* (a lost entry → recompute, never a wrong `.drv`), so LMDB runs with relaxed sync (NOSYNC/MAPASYNC) — crash-safety without crash-durability. | [12](12-incremental-evaluation-cache.md) §6.5 |
| C-14 | When does a memoized result get written to disk? | **A two-tier threshold.** A node may be cheaply memoized in RAM but is materialized to the durable packfile **only when** `eval_cost(node) > hash + serialize + IO` **and** it is likely re-demanded across runs. Trivial nodes never persist; `derivationStrict`/`import`/large-library nodes always do. | [12](12-incremental-evaluation-cache.md) §3.4 |
| C-15 | Thunk dedupe strategy | **Three layers, and we do *not* hash unforced thunks.** Compile-time thunk sharing (full-laziness/CSE, [07](07-laziness-and-whole-program-analyses.md)); runtime coarse xxh3 memoization (the cache, at §3.3 granularity); post-force value hash-consing ([05](05-value-representation.md)). Hashing an unforced thunk is unsound (forcing-to-hash destroys laziness and can diverge), so thunk identity keys on expression identity + value-hashes of *already-forced* free vars. | [12](12-incremental-evaluation-cache.md) §3.5 |
| C-16 | Concurrency runtime: rayon, tokio, async, fibers | **rayon (crossbeam Chase-Lev)** for CPU graph forcing (L1+L2); **tokio reactor** on its own threads for genuinely-blocking eval-time I/O (IFD, network fetchers); **stackful fibers** (green threads) so an I/O-blocked node parks and frees its worker (M:N, Go-style) **without async-coloring the recursive `force`**. Full async-coloring is documented but **rejected** (Box::pin-per-frame tax on the hot path). There is no built-in rayon↔tokio co-scheduler; fibers are how we get M:N I/O multiplexing. Local fast reads stay synchronous; never block a compute worker on I/O. | [13](13-parallel-evaluation.md) §5.5 |
| C-17 | Out-of-core memory / OS cooperation | **The mmap'd value store is the spill-to-disk vanilla Nix lacks.** Cold hash-consed values evict to the CA store and rematerialize on demand; the OS pages them in/out; eviction is write-back-free (the blake3 hash is the address). Plus deliberate `madvise` (`DONTNEED`/`PAGEOUT`/`COLD`) and huge pages for the nursery, and one configurable memory budget driving (under→never-free, near→spill+madvise, over→install collector). Hash-consing already makes the live set strictly smaller than C++ Nix's. | [06](06-memory-management-and-gc.md), [12](12-incremental-evaluation-cache.md) §6.6 |
| C-18 | Cutover gate to `AOS_NIX_NATIVE=on` | **A single falsifiable bar:** 100% full-closure byte parity (incl. the toolchain ladder) + conformance green + a fixed budget of differential-fuzz CPU-hours at zero new divergences + a fixed shadow-mode window at zero divergence across real CI evals + benchmark premise met + `NixCli` fallback retained permanently. Thresholds are tunable; the *shape* is the commitment. | [15](15-differential-testing-and-benchmarking.md) §8.1 |
| C-19 | Front-end as deferred graph nodes | **Parse and compile are lazy, parallel, speculative graph nodes**, not a serial prelude: parse on `import` demand, native-compile on heat; independent files parse/compile in parallel on the rayon pool; idle workers speculatively prefetch along statically-known import edges. Speculation is **side-effect-free and error-quarantined** (a speculative parse error is stashed, raised only if the file is genuinely imported). | [04](04-frontend-parser-and-ir.md) §9.6 |
| C-20 | One unified demand graph | **Lex/parse/resolve/analyze/compile/force are all node kinds in one demand-driven incremental dataflow graph** (the Salsa model). Memoization, parallelism, suspend/resume, speculation, diagnostics, and persistence are properties of the graph engine, inherited by every kind. Two seams keep it honest: an **effect class** (pure nodes freely memoized/speculated/re-run; effectful nodes — `derivationStrict`/`import`/IFD — at-most-once, no speculation) and a **two-tier granularity** (coarse durable query nodes vs fine ephemeral thunk forcing). | [03](03-architecture-overview.md) §3.4 |
| C-21 | Pre-JIT IR-to-IR optimizer | **A GHC Core-to-Core simplifier run iteratively to a fixpoint**, interleaved with the §§4–7 analyses: inlining/beta, constant folding, case-/select-of-known, DCE, CSE, eta, let-floating, plus rewrite **RULES (list fusion)**. Tier-independent (helps the oracle and the JIT), a memoized compile-node. Sound by the same effect/error discipline (never fold a failing/effectful subexpr eagerly; strictness must be proven, not speculative). | [07](07-laziness-and-whole-program-analyses.md) §7.5 |
| C-22 | Flakes | **Full flake-layer evaluation is out of scope.** aos-nix targets non-flake evaluation of the AOS package set and `systems/`; `flake.nix` schema validation, input graph/lock-file resolution, registries, and the flake eval cache are outside the evaluator-core completion claim. Selected flake-adjacent builtin subsets and scoped errors are tracked separately in [21](21-builtins-conformance.md). | [23](23-scope-platform-and-modes.md) |
| C-23 | Restricted / pure-eval + allowed-paths | **In scope, matching the pinned Nix's semantics:** `--pure-eval` disables impure builtins; `restrict-eval`/allowed-paths/allowed-uris mediate eval-time `readFile`/`import`/fetchers. Ties to the I/O boundary ([13](13-parallel-evaluation.md) §5.5) and impure-read cache keying ([12](12-incremental-evaluation-cache.md)). | [23](23-scope-platform-and-modes.md) |
| C-24 | Multi-arch portability | **Value-rep (NaN-box/tagged + pointer tags) assumes 64-bit, 8-byte-aligned, canonical pointers — holds on x86-64 and aarch64; 32-bit unsupported.** Critical invariant: host arch affects eval *speed* (codegen), never eval *output* — the same `.drv` must be produced cross-host for a given `currentSystem`, confirmed by the harness; `currentSystem` reports the target, while `builtins.system` stays absent in the pinned builtin surface. | [23](23-scope-platform-and-modes.md) |
| C-25 | `nixVersion`/`langVersion` | **Spoof to the exact pinned C++ Nix version** (parity requirement, not cosmetic): version-gated nixpkgs/AOS code (`lib.versionAtLeast builtins.nixVersion …`) must take identical branches, or the `.drv` diverges. | [23](23-scope-platform-and-modes.md) |
| C-26 | Error-reporting library | **miette** — a diagnostic *framework* (codes, severity, help, multi-span labels, `thiserror` integration, fancy renderer; pure-Rust). ariadne (render-only) considered, kept as a future renderer swap. Presentation (miette) is separate from parity: error-**class** parity is hard, error-**text** parity best-effort. | [24](24-observability-and-diagnostics.md) |
| C-27 | IFD eval→build handoff | **aos-nix evaluates only; an IFD demand realises the build through the AOS build path** (`NixCli::realise` / `aos build`), never aos-nix itself. The IFD-blocked **fiber parks** while the build runs (tokio-driven subprocess), freeing its worker; the result is keyed on the built output's content address (early cutoff). IFD semantics pinned to C++ Nix for parity. | [14](14-integration-with-aos.md) §9 |
| C-28 | Operating-system support | **Both Linux and macOS (Darwin), like vanilla Nix** — the support matrix is `{x86_64, aarch64} × {linux, darwin}`. Portable by default; OS-specific optimizations sit behind `#[cfg]` build gates with correct fallbacks (Linux `madvise(PAGEOUT/COLD)`/THP; macOS Apple-Silicon JIT `MAP_JIT` + W^X toggling). The host OS affects eval *speed*, never *output*; the harness runs on both. | [23](23-scope-platform-and-modes.md) §3.5, [08](08-execution-tiers-and-cranelift.md) §5.1, [06](06-memory-management-and-gc.md) §3.5 |
| C-7 | Permanent `rnix → arena IR` shim, or hand-roll only? | **Hand-roll exclusively;** rnix is a test-only differential oracle. No second production frontend to keep in parity. | [04](04-frontend-parser-and-ir.md) §12 |
| C-8 | Are single-entry (blackhole-skipping) thunks sound under parallel forcing? | **Yes, when restricted to escape-analysis-proven *frame-local* thunks.** Escaped thunks keep the full CAS protocol regardless of cardinality. No sequential-tier carve-out needed. | [07](07-laziness-and-whole-program-analyses.md) §10 |
| C-9 | Which Nix version / `NIX_SHOW_STATS` schema to baseline against? | **Pin the single C++ Nix version AOS builds with** (same rev as the `nix-compat` pin); parse stats defensively; bumps are deliberate + harness-gated. | [15](15-differential-testing-and-benchmarking.md) §9 |
| C-10 | Daemon vs per-invocation process | **Per-invocation first** (Tier-A arena). A persistent eval daemon is a measure-gated follow-up; the `NixEval` seam is unchanged by that later flip. | [14](14-integration-with-aos.md) §13 |

---

## 3. Measure-gated decisions

A default is specified and buildable today; the differential harness or profiler
decides whether to change it. **None of these block Phase 1** — most are
*downstream* of the baseline numbers Phase 1 produces.

| ID | Question | Default (build this) | Decided by | Owner |
| --- | --- | --- | --- | --- |
| M-1 | Does the incremental cache alone clear the build-time goal? | Build cache + arena + oracle first; treat the JIT as deferred. | P1.5 opening data recorded in [phase1-baseline-characterization.md](phase1-baseline-characterization.md); final answer waits for P2 cache measurements. | [01](01-motivation-and-goals.md), [17](17-roadmap-and-risks.md) |
| M-2 | What is the real cold-eval ceiling on AOS? | P1 representative baseline recorded; use it as the initial target. | Resolved for the committed representative slice in [phase1-baseline-characterization.md](phase1-baseline-characterization.md). | [01](01-motivation-and-goals.md) |
| M-3 | What fraction of CI eval is cold vs warm? | Assume re-eval-dominated; validate. | First P1.5 cold/warm read recorded; real CI distribution still requires instrumented CI traces. | [12](12-incremental-evaluation-cache.md) §8.1 |
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
| M-17 | L2 intra-derivation parallel forcing depth. | Build the parallel pool by default (C-12); L1 coarse + L2 graph forcing are committed. The remaining *measure-gated* knob is how aggressively L2 forces *within* one giant derivation before the overhead outweighs the tail-latency win. | Tail-latency / load-imbalance profile. | [13](13-parallel-evaluation.md) §8 |
| M-18 | Cross-nursery shared-value touch cost. | (Assume low; measure under Tier B.) | Multi-worker sharing profile. | [13](13-parallel-evaluation.md) §8 |
| M-19 | Regression-detector noise band + runner pinning. | Use self-hosted-runner determinism; tune a band. | CI timing variance. | [15](15-differential-testing-and-benchmarking.md) §9 |
| M-20 | `__structuredAttrs` JSON byte-parity. | Trust `nix-compat`; verify. | Harness on structured-attrs packages. | [11](11-derivation-and-store-compatibility.md) §12 |
| M-21 | Second-version conformance canary. | Single pinned Nix version only. | Forward-compat need. | [15](15-differential-testing-and-benchmarking.md) §9 |
| M-22 | When to enable fiber-based eval-time I/O suspension (C-16). | Build sync core + rayon + tokio reactor first; turn on fiber suspension only when eval-time *blocking* I/O concurrency justifies it. Local reads stay synchronous regardless. | Eval-time IFD/fetch concurrency profile. | [13](13-parallel-evaluation.md) §5.5 |
| M-23 | Speculative parse/compile prefetch aggressiveness (C-19). | Lazy + parallel parse/compile committed; speculative prefetch depth (how far down static import edges; pre-parse only vs pre-compile) tuned to avoid wasted cores. | Mis-speculation rate vs idle-core availability. | [04](04-frontend-parser-and-ir.md) §9.6 |
| M-24 | Simplifier aggressiveness (C-21). | Core simplifier + analyses committed; inlining size thresholds, fixpoint iteration count, and which rewrite RULES/fusion to enable are tuned (over-inlining bloats IR; over-eager fusion can change sharing). | IR-size + `NIX_SHOW_STATS` counters vs harness. | [07](07-laziness-and-whole-program-analyses.md) §7.5 |

---

## 4. Research-grade committed decisions

In scope under the budget mandate. The first safe baseline still lands before
these variants, but the variants are built and selected by measurement rather
than descoped by default.

| ID | Item | Default / stance | Owner |
| --- | --- | --- | --- |
| R-1 | Concurrent moving GC (ZGC/Shenandoah-style) × monotonic thunk mutation. | Daemon-only; single-threaded precise-generational first cut sidesteps it. | [03](03-architecture-overview.md), [13](13-parallel-evaluation.md) |
| R-2 | Tier-2-emitted GC load barriers. | Stage B0 stop-the-world is the first shipping answer; tier-2 load barriers are built with the concurrent moving-GC variant. | [08](08-execution-tiers-and-cranelift.md), [13](13-parallel-evaluation.md) |
| R-3 | WHNF tag bits vs colored-pointer bits co-design. | Unsolved; build the daemon-GC variants and widen the value if the measured policy requires it. | [13](13-parallel-evaluation.md) §8 |
| R-4 | Memory-ordering audit of the parallel thunk protocol (weak memory). | **Promoted to a committed, early gate** (C-12): the acquire/release CAS discipline must pass a `loom`/Miri audit *before the parallel tier is trusted* — it is the safety gate on shipping parallel thunk-graph evaluation, not a deferred nicety. (The harder *load-barrier* proof for a concurrent moving collector remains research-grade with R-1/R-2.) | [13](13-parallel-evaluation.md) §8 |
| R-5 | Full effect-based region inference. | Committed advanced deliverable; lexical/escape regions land first, then the full effect-based variant is built and benchmarked in P8. | [06](06-memory-management-and-gc.md) §5.2 |
| R-6 | Daemon float-outward residency policy. | Tuning parameter; no daemon workload exists yet. | [07](07-laziness-and-whole-program-analyses.md) §10 |
| R-7 | Tier-2-only fused "super-node" IR. | The "one IR for all tiers" invariant holds for the first tiers; build a fused-IR variant only after tiering data justifies it. | [04](04-frontend-parser-and-ir.md) §12 |
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

- **21 Settled + 28 Closed decisions** mean Phase 1 — and the rank-1 cache — are
  buildable from this RFC with no unstated design calls. (C-11/C-12 promote
  content-addressed derivations and parallel thunk-graph evaluation to first-class,
  early scope; C-13–C-18 settle the cache storage engine, materialization
  threshold, dedupe strategy, concurrency runtime — rayon + tokio + fibers — the
  out-of-core memory story, and the cutover gate; C-19–C-21 settle the front-end
  as deferred graph nodes, the single unified demand graph, and the pre-JIT
  GHC-style simplifier; C-22–C-27 settle flakes-out, restricted/pure-eval,
  multi-arch, version spoofing, the error library, and the IFD handoff.)
- **24 Measure-gated** items each carry a buildable default; the harness and
  profiler (not a meeting) decide whether to move off it.
- **14 Research-grade** items are committed advanced work with measurement- or
  proof-selected implementation policy.
- The through-line: this RFC does not pretend every micro-decision is pre-made;
  it pretends *nothing*. Each fork is either decided, or has a default plus the
  exact measurement that will decide it. That is what makes the design
  record honest and the implementation path unambiguous.

See the [roadmap](17-roadmap-and-risks.md) for the order in which these land, and
the [README decision log](README.md#decision-log) for the top-level summary.
