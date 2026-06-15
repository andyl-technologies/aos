# RFC-0007 - Implementation checklist (all phases)

This is the single tickable master checklist for the whole `aos-nix` build,
spanning every phase from the Phase-1 foundation through the research-grade
tail. It is the *superset* across all phases; Phase 1 already has a detailed,
ordered checklist in the [roadmap](17-roadmap-and-risks.md) §6, and this
document references that section rather than re-typing it verbatim. Every other
phase is expanded here in the same shape so an implementer can track the whole
project from one page.

It is bound to three upstream documents and must not contradict them:

- the [roadmap](17-roadmap-and-risks.md) — the phase table (P1–P8), the ranked
  90% subset (ranks 0–5), the risk register, and the Phase-1 checklist;
- the [decision register](19-decision-register.md) — every Settled / Closed /
  Measure-gated / Research-grade decision, by ID (`S-*`, `C-*`, `M-*`, `R-*`);
- the [AOS integration](14-integration-with-aos.md) — the `NixEval` seam and the
  `AOS_NIX_NATIVE` staged rollout (Phases A → E: Off → Shadow → On-`eval_expr`
  → On-`instantiate` → verify-sampling-reduced).

The conformance surface it turns green is owned by two sibling documents:

- [Nix language conformance](20-nix-language-conformance.md) — the language
  surface (syntax, scoping, operators, coercions, error semantics);
- [builtins conformance](21-builtins-conformance.md) — the ~120-primop surface
  ([10](10-primops-and-runtime-abi.md)), pure and impure.

Per RFC discipline this document makes no status claim; the maturity header
lives only in the set's `README.md`.

---

## How to use this checklist

- **The ordering insight is the whole point.** Byte-for-byte parity on the
  language ([20](20-nix-language-conformance.md)) and builtins
  ([21](21-builtins-conformance.md)) surfaces is achieved in **Phase 1**, under
  the slow tree-walk oracle, and then held **invariant** through every
  optimization phase that follows. Performance is layered on top of an
  already-correct evaluator; the differential `.drv`-diff harness
  ([15](15-differential-testing-and-benchmarking.md)) is the regression guard
  that catches any parity loss. **Optimizations never trade away correctness.**
  Every phase after P1 carries the same conformance line: *"hold parity; harness
  stays byte-green."*
- **Each phase section gives**: a one-line GOAL; `- [ ]` deliverables (concrete
  modules under `crates/aos-nix/`); `- [ ]` conformance items (referencing
  [20](20-nix-language-conformance.md) / [21](21-builtins-conformance.md)); the
  decision-register IDs the phase **closes** or **measures**; falsifiable EXIT
  CRITERIA; and the rollout gate it unlocks.
- **Two schedules run in parallel.** The P-phases add *speed* (capability); the
  rollout Phases A–E from [14](14-integration-with-aos.md) §7.1 add *trust*. The
  rollout column tracks the trust schedule. `AOS_NIX_NATIVE` stays **default-Off**
  across both until the harness is byte-green on the full closure
  ([17](17-roadmap-and-risks.md) R1).
- **Tick a box only when its evidence exists** — a green harness run, a recorded
  benchmark delta, a `miri`/sanitizer-clean CI job. Falsifiable, not aspirational.
- **A phase does not begin until its predecessor's exit criterion holds** (the
  gate dependencies in [17](17-roadmap-and-risks.md) §3). The one hard kill gate
  is **P1.5** (measure-first): if eval is not the bottleneck, the project
  **stops or re-scopes** ([01](01-motivation-and-goals.md) §5.2).

### The invariants, restated (do not violate)

- **Eval-only**: `eval -> .drv`; real Nix still builds (`S-1`).
- **Byte-identical** `.drv` + store paths vs C++ Nix; SHA-256; harness-gated;
  default-off until green (`S-2`).
- **`NixCli` permanent fallback** — flippable by one env var, never removed
  (`S-16`, [14](14-integration-with-aos.md) §4.1).
- **Cranelift backend, tree-walk oracle is the permanent correctness reference**
  (`S-3`, `S-5`) — the fast path is never the final arbiter of a store path.
- **The incremental early-cutoff cache is the biggest expected win** (`S-14`),
  built *first* among the optimizations and possibly sufficient alone (`M-1`).
- **Measure-first** (`S-18`): no optimizing-compiler work until P1 data proves
  eval is the dominant cost.

---

## Master progress table

| Phase | Goal | Rollout gate unlocked | Status |
|-------|------|-----------------------|--------|
| **P1** | Frontend + scope + tree-walk oracle + `.drv` harness; **full language + builtins parity achieved, IA *and* CA derivations** (C-11); thunk state atomic from day 1 (C-12) | Phase A (default Off, harness in CI); Phase B (Shadow) once enough of the closure is byte-green | ☐ |
| **P1.5** | Measure-first decision (kill/continue gate) | — (decides whether P2–P8 happen at all) | ☐ |
| **P2** | Incremental early-cutoff cache + hash-consing (rank 1) | Phase B (Shadow) hardened; Phase C (On for `eval_expr`) becomes reachable | ☐ |
| **P3** | Bump-arena heap + precise generational GC (rank 2) | (parity held; trust schedule continues) | ☐ |
| **P3.5** | **Parallel graph evaluation** (C-12): L1 work-stealing pool + L2 lock-free CAS thunks; `loom`/Miri audit green | (parity held; multi-core speedup; oracle stays ground truth) | ☐ |
| **P4** | Strictness + escape analysis (rank 3) | Phase C (On for `eval_expr`) | ☐ |
| **P5** | Hidden classes + PIC (rank 4a) | (parity held; Phase C in effect) | ☐ |
| **P6** | Cranelift baseline JIT, tier 1 (rank 4b) | Phase D (On for `instantiate`, verify-sampling kept) becomes reachable | ☐ |
| **P7** | Cranelift optimized + deopt + OSR, tier 2 (rank 4c) | Phase D hardened across all tiers | ☐ |
| **P8** | Measured follow-ups (rank 5): pointer tagging, full-laziness, region inference, concurrent *moving* GC | Phase E (verify sampling reduced; `NixCli` retained) | ☐ |

Legend: ☐ not started · ◐ in progress · ☑ exit criterion met.

---

## Phase 1 — Frontend + scope + tree-walk oracle + differential harness (rank 0)

**GOAL.** Build the cheapest faithful Nix evaluator — parser, scope resolution,
tree-walk oracle — and the differential `.drv`-diff harness, and with them
achieve **full byte-for-byte language and builtins parity** on the AOS closure,
plus the baseline cold-eval number. This is the parity that all later phases
hold invariant.

> The complete, *ordered* Phase-1 implementer checklist lives in
> [roadmap](17-roadmap-and-risks.md) §6 ("Phase 1 — implementer checklist") and
> is **not duplicated** here. The boxes below are the section-level rollup of
> that list; tick them as the §6 sub-items complete.

**Deliverables (rollup of [17](17-roadmap-and-risks.md) §6).**

- [ ] Crate skeleton: `crates/aos-nix/` in the workspace; pinned `nix-compat`
      git rev (`C-5`); `lib.rs` `//!` overview to the AOS doc standard.
- [ ] `NixEval` seam wired in `aos-core` ([14](14-integration-with-aos.md) §3):
      trait defined, `NixCli` as first impl, stub `NixNative` behind
      `AOS_NIX_NATIVE` (default off).
- [ ] Frontend: `syntax/lexer.rs`, `syntax/ast.rs` (compact arena AST, `u32`
      NodeIds), `syntax/parser.rs` (recursive-descent + Pratt; rnix is
      test-only, `C-7`), `compile/scope.rs` (de Bruijn `(depth, slot)`),
      `cache/parse.rs` (blake3 content-addressed parse cache).
- [ ] Value + heap subset: `value.rs` (16-byte tagged `Value`, **no NaN-boxing**,
      `S-6`/`M-4`), `heap/arena.rs` (bump-arena Tier A, allocate-never-free,
      all alloc behind `aos_alloc_*`), `attrs.rs` (sorted-vec + binary-search,
      `u32`-interned symbols, deterministic iteration order).
- [ ] Tree-walk oracle: `eval/tree_walk.rs` (call-by-need; thunks
      `Suspended → Blackhole → Forced`; `with`/`rec`/`let`/`if`/operators) — the
      permanent correctness oracle ([08](08-execution-tiers-and-cranelift.md) §2.1).
- [ ] `runtime/builtins/` — the primop surface ([10](10-primops-and-runtime-abi.md))
      as plain Rust, interned-symbol dispatch; `import` cached by realpath +
      content hash (`S-12`).
- [ ] Compatibility core: `store/derivation.rs` (`derivationStrict` →
      `nix-compat` `Derivation` → ATerm → SHA-256 output paths; never reimplement
      `compressHash`; **IA *and* CA** derivations from the start — floating +
      fixed CA outputs, `C-11`/`S-13`) and `store/context.rs` (string
      contexts as interned COW bitsets).
- [ ] The gate: `aos nix-diff` (and/or a Rust test) asserting **byte-identical
      `.drv`** from `NixNative` vs `nix-instantiate` over the full AOS package
      set ([15](15-differential-testing-and-benchmarking.md)); baseline capture
      of `nix-instantiate` wall-clock + `NIX_SHOW_STATS`; differential parser
      tests vs the rnix oracle; seed the `cargo fuzz` differential fuzzer.

**Conformance — FULL parity is a Phase-1 requirement.**

- [ ] **All of the language surface in [20](20-nix-language-conformance.md)
      diffs green under the tree-walk oracle**: lexical/grammar forms, scoping
      (`let`/`rec`/`with`/inherit), operators and precedence, type coercions and
      string interpolation, `assert`/`throw`/`abort` and error *class* parity
      ([15](15-differential-testing-and-benchmarking.md) §3.3), attr-ordering
      and float-formatting corners.
- [ ] **All pure builtins in [21](21-builtins-conformance.md) diff green** under
      the oracle (string/list/attr/arithmetic/`derivationStrict`/`import`/
      `toJSON`/`fromJSON`/path ops), with impure builtins
      (`readFile`/`readDir`/`getEnv`) producing identical `.drv` inputs on the
      tested closure.
- [ ] **Parity is achieved here, under the slow oracle, before any optimization
      exists.** This conformance checklist is satisfied in Phase 1 and then held
      *invariant* by every later phase; the differential harness
      ([15](15-differential-testing-and-benchmarking.md)) is the standing
      regression guard.

**Decisions closed/measured.**

- [ ] Closes (builds as written): `S-1`, `S-2`, `S-3` (no JIT yet, backend
      chosen), `S-6`, `S-11`, `S-12`, `S-13`, `S-16`, `C-6` (IA-only), `C-7`
      (hand-rolled frontend), `C-9` (pinned Nix version), `M-4` default
      (16-byte tagged value, no NaN-box).
- [ ] Produces the inputs for: `M-2` (cold-eval ceiling — Phase 1 *produces*
      it), `Q-B` baseline that sets C3's target.

**EXIT CRITERIA (falsifiable).** The `.drv`-diff harness is **byte-green on the
full AOS closure** under the tree-walk oracle (zero divergence on
`mkDerivation`/`ccWrapper`/`evalModules` and the whole package set); baseline
eval-time and `NIX_SHOW_STATS` numbers are recorded; `AOS_NIX_NATIVE` still
defaults off ([17](17-roadmap-and-risks.md) §6, P1 exit).

**Rollout gate unlocked.** **Phase A** (default Off, harness in CI, PRs blocked
on regressions). **Phase B** (Shadow mode in CI) may begin as soon as the oracle
is byte-green on enough of the closure to be worth diffing against real CI
traffic ([14](14-integration-with-aos.md) §7.1; [17](17-roadmap-and-risks.md)
§3) — it does not wait for any later phase.

---

## Phase 1.5 — Measure-first decision (the kill/continue gate)

**GOAL.** Decide, from P1 data alone, whether *evaluation* (not build, not I/O)
is the dominant repeated cost on representative AOS workloads — and therefore
whether the optimization phases happen at all.

**Deliverables.**

- [ ] A documented determination from the P1 baseline (`nix-instantiate`
      wall-clock + `NIX_SHOW_STATS` vs build/I/O time) that eval is or is not the
      bottleneck ([01](01-motivation-and-goals.md) §5.1–5.2).
- [ ] If eval is **not** dominant → record the STOP/re-scope decision; the
      cheap, independently-useful P1 artifacts (oracle + harness) remain valuable
      for validating `NixCli` itself ([17](17-roadmap-and-risks.md) R6).

**Conformance.** No new surface; parity from P1 holds.

**Decisions closed/measured.**

- [ ] Measures `M-1` opening data (does the cache plausibly clear the goal?),
      `M-3` (cold vs warm fraction, first read).
- [ ] Resolves `Q-B`; informs `Q-A`/`Q-C`.

**EXIT CRITERIA (falsifiable).** A written determination exists, grounded in P1
numbers, stating eval is the dominant AOS cost (continue) or is not (stop /
re-scope). This is the only phase whose exit can cancel the project.

**Rollout gate unlocked.** None directly — it *gates whether P2–P8 are built*.
The trust schedule (Phases A/B) continues independently.

---

## Phase 2 — Incremental early-cutoff cache + hash-consing (rank 1)

**GOAL.** Add the headline systemic win: a demand-driven incremental computation
graph that memoizes thunk and `derivationStrict` results keyed on
`H(expr ⊕ env)` with **early cutoff**, plus hash-consing as its enabling
substrate. Pays off even on the rank-0 oracle; may clear the build-time goal
alone (`M-1`/`Q-A`).

**Deliverables.**

- [ ] `cache/dcg.rs` — the demand-driven incremental computation graph (Salsa /
      Adapton / *Build Systems à la Carte* model): nodes, demand edges,
      change-propagation, early cutoff ([12](12-incremental-evaluation-cache.md) §1).
- [ ] `cache/key.rs` — the cache key combiner: an **ordered, length-prefixed**
      free-variable combiner hashed once, **never bare XOR** (`C-1`).
- [ ] `cache/cutoff.rs` — early-cutoff: stop propagation when a recomputed
      value-hash equals its prior value-hash.
- [ ] `value/hashcons.rs` — hash-consing / maximal sharing of immutable values
      (O(1) equality; turns value-hashing into a field load — `S-7`).
- [ ] `cache/hashing.rs` — the hashing split: xxh3 in-process, blake3
      durable/shared, SHA-256 *only* for Nix-observed hashes (`S-15`).
- [ ] `cache/persist.rs` — versioned on-disk `nodes/values/files` schema with a
      schema-version field and discard-on-mismatch (`R-14`); transport stays
      **beside** `NixEval`, on the Attic content-addressed path (`C-3`).
- [ ] Impure-input edges: `readFile`/`readDir`/`getEnv` keyed as explicit
      content-hash inputs; `currentTime` not cached (`R-10`).
- [ ] `AOS_NIX_CACHE=0` bypass for minimal-reproducer parity checks; periodic
      cold re-validation job in CI ([12](12-incremental-evaluation-cache.md) §8.3).

**Conformance (hold parity).**

- [ ] Harness stays byte-green: `AOS_NIX_CACHE=0` and cached runs agree
      byte-for-byte over the full closure ([20](20-nix-language-conformance.md) +
      [21](21-builtins-conformance.md) surface unchanged).
- [ ] The **leak invariant** holds: internal xxh3/blake3 hashes never appear in
      any Nix-observed hash ([12](12-incremental-evaluation-cache.md) §5.2).
- [ ] A semantically-irrelevant edit (comment/whitespace/leaf-package) leaves
      downstream `.drv` bytes unchanged (C4, [01](01-motivation-and-goals.md) §6).

**Decisions closed/measured.**

- [ ] Closes: `S-7`, `S-14`, `S-15`, `C-1`, `C-2` (reuse strictness FV set as
      baseline), `C-3` (cache beside the trait), `R-14` (versioned schema).
- [ ] Measures: `M-1` (cache alone clears the goal? — `Q-A`), `M-3`, `M-11`
      (memoization granularity — start coarse), `Q-C`, `Q-D` (FV-narrowing
      precision), `Q-H` (persistence/cross-machine stability).

**EXIT CRITERIA (falsifiable).** A semantically-irrelevant edit recomputes a
*bounded, small* fraction of the closure and emits unchanged `.drv` downstream;
`AOS_NIX_CACHE=0` and cached runs are byte-identical on the harness across the
full closure ([17](17-roadmap-and-risks.md) §3, P2). The warm-vs-cold delta is
recorded so `M-1`/`Q-A` can be answered.

**Rollout gate unlocked.** Hardens **Phase B** (Shadow). With the cache stable
and the harness byte-green warm and cold, **Phase C** (On for `eval_expr`)
becomes reachable once the dedicated `--eval --json` check is green (`C-4`,
gated in P4's metadata path).

---

## Phase 3 — Bump-arena heap + precise generational GC (rank 2)

**GOAL.** Replace C++ Nix's dominant runtime cost (the Boehm conservative
collector): a never-free bump arena for one-shot CLI, a precise generational
copying collector for the daemon case. Attacks the cost the cache cannot avoid
and helps the oracle directly.

**Deliverables.**

- [ ] `heap/arena.rs` — Tier A bump-pointer arena finalized: allocate, never
      free, drop wholesale at process exit (the per-invocation default, `C-10`).
- [ ] `heap/gc.rs` — Tier B precise generational copying collector with a
      cache-resident nursery; precise (not conservative) so Boehm-style false
      retention is eliminated ([06](06-memory-management-and-gc.md)).
- [ ] `runtime/alloc.rs` — all allocation routes through `aos_alloc_*` runtime
      symbols so the GC strategy swaps without touching callers (and, later, the
      JIT) ([03](03-architecture-overview.md) §4.5; `S-8`).
- [ ] `heap/roots.rs` — precise root enumeration / stack maps for the collector.
- [ ] `#![forbid(unsafe_code)]` preserved on the oracle/frontend/glue;
      `#![deny(unsafe_op_in_unsafe_fn)]` + `// SAFETY:` per block in `heap/`;
      `cargo fuzz` target on the GC (`S-17`, [14](14-integration-with-aos.md) §9.3).

**Conformance (hold parity).**

- [ ] Harness stays byte-green under both Tier A and Tier B
      ([20](20-nix-language-conformance.md) + [21](21-builtins-conformance.md)
      unchanged — GC is invisible to `.drv` bytes).
- [ ] Precise GC passes `miri` / ASan / UBSan on the safe tree.

**Decisions closed/measured.**

- [ ] Closes: `S-8` (Tier A + Tier B), `C-10` (per-invocation first).
- [ ] Measures: `M-12` (cons-table sizing under daemon GC), `M-14` (region
      inference vs generational GC — generational first), `Q-G` (daemon vs
      per-invocation — deferred).

**EXIT CRITERIA (falsifiable).** One-shot CLI eval allocates through
`aos_alloc_*`, frees nothing, drops at exit; measured allocation/GC time on the
oracle is materially below the P1 Boehm baseline; the precise GC passes
`miri`/ASan on the safe tree ([17](17-roadmap-and-risks.md) §3, P3).

**Rollout gate unlocked.** None new (parity held; Phase B/C trust schedule
continues). The arena is part of the *expected CLI win* together with the cache
([17](17-roadmap-and-risks.md) R8).

---

## Phase 3.5 — Parallel graph evaluation (C-12)

**GOAL.** Use all cores. Promoted from the rank-5 tail to a committed early phase
per decision C-12: a work-stealing pool evaluates independent top-level
derivations concurrently (L1), and threads force the shared lazy thunk graph in
parallel via a lock-free CAS protocol (L2) — without ever producing a result
that differs from the sequential oracle. Placed after P3 because per-worker
nurseries build on the bump arena.

**Deliverables.**

- [ ] `eval/parallel.rs` — the L1 **work-stealing scheduler** (Chase-Lev deques)
      over independent top-level derivations, each worker with its own nursery
      ([13](13-parallel-evaluation.md) §4).
- [ ] `eval/thunk_cas.rs` — the L2 **lock-free CAS thunk protocol**
      (`Suspended → Pending → Awaited → Forced/Failed`); claim-by-CAS, with
      work-stealing or parking on a claimed thunk ([13](13-parallel-evaluation.md) §3).
      The thunk word is already atomic from P1, so this adds a scheduler, not a
      representation change.
- [ ] Per-worker bump nurseries + a concurrent (or per-worker-then-merged)
      hash-cons table; never-free in CLI mode sidesteps any moving-collector race
      ([13](13-parallel-evaluation.md) §5).
- [ ] Single-entry-thunk downgrade restricted to escape-analysis-proven
      *frame-local* thunks (C-8), so the blackhole-skip is sound under parallel
      schedules.

**Conformance (hold parity).**

- [ ] The parallel evaluator is **differentially identical to the sequential
      oracle** across the full closure — output determinism under nondeterministic
      scheduling ([13](13-parallel-evaluation.md) §4.4); the
      [20](20-nix-language-conformance.md)/[21](21-builtins-conformance.md)
      surface stays byte-green.
- [ ] **`loom`/Miri memory-ordering audit (R-4) is green** before the parallel
      tier is trusted. *No data races, ever.*

**Decisions closed/measured.**

- [ ] Closes `C-12` (parallel graph eval is first-class) and the early half of
      `R-4` (the CAS memory-ordering audit, now a committed gate); uses `C-8`.
- [ ] Measures `M-17` (how aggressively L2 forces *within* one giant derivation)
      and `M-18` (cross-nursery shared-value touch cost).

**EXIT CRITERIA (falsifiable).** Differential identity vs the sequential oracle
on the full closure under many-thread scheduling; `loom`/Miri audit green; a
recorded multi-core speedup over the serial baseline; harness byte-green.

**Rollout gate unlocked.** None new (parity held); the speedup feeds the *expected
CLI win* alongside the cache and arena.

---

## Phase 4 — Strictness + escape analysis (rank 3)

**GOAL.** Whole-program GHC-style analyses that *delete* allocation rather than
speed it up: strictness/demand + worker-wrapper (eager, thunk-free strict
bindings), cardinality (shed blackhole/update machinery, drop dead bindings),
escape analysis + scalar replacement (keep short-lived non-escaping values off
the heap). Annotates the IR — helps the oracle before any JIT exists.

**Deliverables.**

- [ ] `analysis/strictness.rs` — whole-program strictness/demand analysis +
      worker-wrapper transform ([07](07-laziness-and-whole-program-analyses.md)).
- [ ] `analysis/cardinality.rs` — single-entry thunk detection (blackhole-skip
      only for escape-proven *frame-local* thunks, `C-8`) + dead-binding removal.
- [ ] `analysis/escape.rs` — escape analysis + scalar replacement for
      non-escaping attrsets/thunks.
- [ ] `ir/annotate.rs` — IR annotations consumed by the tree-walk oracle (and
      later the JIT), and the strictness FV set reused by the cache key (`C-2`).
- [ ] Soundness harness: property-test fuzzing of escape signatures for the
      ~120-primop surface (a wrong escape-transparency claim could corrupt a
      result — `R-9`).
- [ ] `--eval --json` differential check green (`C-4`) — required before the
      `eval_expr` flip.

**Conformance (hold parity).**

- [ ] Harness stays byte-green; analysis is **sound** — no eager forcing of a
      binding the oracle leaves unforced; no observable change to
      [20](20-nix-language-conformance.md) / [21](21-builtins-conformance.md).
- [ ] `--eval --json` value-rendering parity green (float formatting, attr
      ordering, string-context) — gates Phase C ([14](14-integration-with-aos.md)
      §12, `C-4`).

**Decisions closed/measured.**

- [ ] Closes: `S-9` (the committed analyses subset), `C-2`, `C-8`, `C-4`, `R-9`
      (escape-signature property fuzzing, default-off until green).
- [ ] Measures: `M-15` (how much cardinality precision to chase — stop where the
      cache subsumes the win), `Q-D` (FV precision feeding the cache key).

**EXIT CRITERIA (falsifiable).** Annotated IR compiles provably-strict bindings
eagerly with a **measured drop in thunk-allocation count** vs the P1
`NIX_SHOW_STATS`; the harness stays byte-green; no binding the oracle leaves
unforced is eagerly forced ([17](17-roadmap-and-risks.md) §3, P4).

**Rollout gate unlocked.** **Phase C** (default On for `eval_expr` only — the
low-blast-radius metadata path) once the `--eval --json` check is green. A wrong
metadata string is visible and harmless; a wrong `.drv` is invisible and
catastrophic, so `eval_expr` flips before `instantiate`
([14](14-integration-with-aos.md) §7.1).

---

## Phase 5 — Hidden classes + polymorphic inline caches (rank 4a)

**GOAL.** Make attrset access — the hottest operation in any nixpkgs-scale eval —
a shape-check plus a constant-offset load, via hidden classes (shapes) and
polymorphic inline caches. Still no codegen; the oracle gains the fast path.

**Deliverables.**

- [ ] `attrs/shape.rs` — hidden classes (shapes): shape transitions, shape
      table, monomorphic/polymorphic shape sites
      ([09](09-attribute-sets-hidden-classes-and-inline-caches.md)).
- [ ] `attrs/pic.rs` — polymorphic inline caches at `select` sites
      (shape-check → constant-offset load; megamorphic fallback).
- [ ] `attrs/hamt.rs` — HAMT for `//` update merges; `u32` symbol interning
      preserved (`S-10`).
- [ ] Deterministic iteration order preserved across shape transitions
      (the ordering invariant of [09](09-attribute-sets-hidden-classes-and-inline-caches.md)).

**Conformance (hold parity).**

- [ ] `select` resolves via shape-check + offset load with a PIC, and **attr
      iteration order remains byte-identical to C++ Nix** — the single most
      parity-sensitive property of this phase ([21](21-builtins-conformance.md)
      ordering-dependent builtins like `attrNames`/`mapAttrs` unchanged).
- [ ] Harness byte-green over the full closure.

**Decisions closed/measured.**

- [ ] Closes: `S-10` (hidden classes + PIC + HAMT + interning).
- [ ] Measures: `R-8` (frontend `with`-shape speculation left entirely to
      runtime inline caches for now).

**EXIT CRITERIA (falsifiable).** `select` sites resolve via shape-check +
constant-offset load with a working PIC; attr iteration order is byte-identical
to C++ Nix; harness byte-green ([17](17-roadmap-and-risks.md) §3, P5).

**Rollout gate unlocked.** None new (parity held; Phase C in effect). This is
the last phase before the speculative machinery; it makes the residue the cache
cannot elide cheap to walk.

---

## Phase 6 — Cranelift baseline JIT, tier 1 (rank 4b)

**GOAL.** Compile hot thunks per-expression once via Cranelift (tier 1). The
first speculation-free codegen tier; the tree-walk oracle remains the deopt
target and correctness backstop. Reserved for where it profiles well (daemon /
hot loops), not the dominant one-shot case (`M-5`/`R8`).

**Deliverables.**

- [ ] `jit/cranelift.rs` — `JITBuilder`/`JITModule` setup, external-symbol
      registration for the `aos_alloc_*` and primop ABI
      ([08](08-execution-tiers-and-cranelift.md)).
- [ ] `jit/lower.rs` — lower the annotated IR to Cranelift IR; compile
      per-expression once; thunks are `(code, env, state)` instances (`S-4`).
- [ ] `jit/abi.rs` — uniform `extern "C"` runtime ABI; primops called by symbol
      ([10](10-primops-and-runtime-abi.md); `M-9` default symbol-call only).
- [ ] `jit/tier.rs` — tier-up policy (hot-thunk detection) into tier 1.
- [ ] `unsafe` discipline: `jit/` under `#![deny(unsafe_op_in_unsafe_fn)]`,
      `// SAFETY:` per block, two-maintainer review, ASan/UBSan CI; the
      `transmute` of code pointers is the documented innate-unsafe call (`S-17`).
- [ ] Copy-and-patch hedge kept measurable if Cranelift warmup proves too high
      (`M-8`).

**Conformance (hold parity).**

- [ ] **Tier-1 output is differentially identical to the tier-0 oracle** across
      the closure — every JIT-compiled thunk produces the same value the oracle
      does ([20](20-nix-language-conformance.md) + [21](21-builtins-conformance.md)
      held invariant; the oracle is the tie-breaker, [17](17-roadmap-and-risks.md) R2).
- [ ] Harness byte-green with the JIT enabled.

**Decisions closed/measured.**

- [ ] Closes: `S-4` (compile-once execution model), `S-3` codegen (Cranelift
      baseline realized), `S-5` baseline tier.
- [ ] Measures: `M-5` (does the JIT pay off in one-shot CLI? — `Q-F`), `M-8`
      (copy-and-patch vs Cranelift), `M-9` (inline hottest primops?).

**EXIT CRITERIA (falsifiable).** Hot thunks compile per-expression once via
Cranelift; tier-1 output is differentially identical to the tier-0 oracle across
the closure; warmup cost is **measured against the one-shot CLI workload** (the
JIT's worst case) ([17](17-roadmap-and-risks.md) §3, P6; R8).

**Rollout gate unlocked.** **Phase D** (default On for `instantiate`, with
`AOS_NIX_NATIVE_VERIFY` sampling kept) becomes *reachable* — but only after the
full-closure harness is byte-green under the JIT-enabled native path
([14](14-integration-with-aos.md) §7.1).

---

## Phase 7 — Cranelift optimized + deopt + OSR, tier 2 (rank 4c)

**GOAL.** The speculative optimized tier: speculation guarded by uncommon traps,
deoptimization back to the oracle at any safepoint, and on-stack replacement.
Every deopt path must land in semantics identical to the oracle — *no observable
`.drv` difference, ever*.

**Deliverables.**

- [ ] `jit/opt.rs` — tier-2 optimized compilation with type/shape speculation.
- [ ] `jit/deopt.rs` — uncommon traps + deoptimization; user stack maps; the
      slow path is always a correct continuation of the fast path
      ([08](08-execution-tiers-and-cranelift.md); [14](14-integration-with-aos.md) §8).
- [ ] `jit/osr.rs` — on-stack replacement to enter hot loops mid-execution
      (gated on `M-6`).
- [ ] Speculation guards: scalar-replacement *not* carried across deopt points
      in the first cut (`M-7`).
- [ ] `loom`/`miri` verification scaffolding for any barrier/CAS interactions
      that tier-2 introduces (kept minimal until daemon GC, `R-4`).

**Conformance (hold parity).**

- [ ] **Every deopt path lands in semantics identical to the oracle** — a
      deopt-triggered re-execution produces byte-identical `.drv`
      ([20](20-nix-language-conformance.md) + [21](21-builtins-conformance.md)
      held under speculation).
- [ ] Harness byte-green **under all tiers** simultaneously (oracle, tier 1,
      tier 2 with deopt/OSR exercised).

**Decisions closed/measured.**

- [ ] Closes: `S-5` full tiering (optimized + deopt/OSR).
- [ ] Measures: `M-6` (is OSR worth it?), `M-7` (scalar-replace across deopt? —
      no, conservatively).

**EXIT CRITERIA (falsifiable).** Speculation is guarded by uncommon traps; every
deopt path is semantics-identical to the oracle (no observable `.drv`
difference, ever); OSR enters hot loops mid-execution; the harness is byte-green
under all tiers ([17](17-roadmap-and-risks.md) §3, P7).

**Rollout gate unlocked.** Hardens **Phase D** across all tiers. With the full
closure byte-green under every tier and Shadow/verify-sampling silent on real
traffic for a long window, `AOS_NIX_NATIVE` may default **On** for `instantiate`
([14](14-integration-with-aos.md) §7; the long-tail risk R1 governs the calendar).

---

## Phase 8 — Measured follow-ups (rank 5)

**GOAL.** The explicitly-uncertain tail. Each item ships **only** on a recorded
benchmark delta against AOS traces; any that fails to show a delta is dropped,
not shipped (C6). None is on the critical path.

**Deliverables (each independently gated on a measured delta).**

- [ ] `value/tag.rs` — pointer tagging for WHNF-test fast paths
      ([05](05-value-representation.md)); NaN-boxing remains open because Nix
      `i64` ints do not fit a NaN-box payload (`M-4`/`Q-E`).
- [ ] `analysis/full_laziness.rs` — full-laziness / let-floating
      ([07](07-laziness-and-whole-program-analyses.md); daemon residency policy
      `R-6`).
- [ ] `heap/region.rs` — lexical/escape region inference *only* where profiles
      show medium-lived allocation (`M-14`); full effect-based region inference
      stays research-grade (`R-5`).
- [ ] `heap/concurrent_gc.rs` — concurrent/moving GC for daemon mode
      (ZGC/Shenandoah-style colored pointers + load barriers), **daemon-only**,
      sidestepped by the bump arena in CLI mode (`R-1`/`R-2`/`R-3`/`R-4`; the
      deepest unsolved coupling, [17](17-roadmap-and-risks.md) R9).

**Conformance (hold parity).**

- [ ] Harness stays byte-green for **each** follow-up independently
      ([20](20-nix-language-conformance.md) + [21](21-builtins-conformance.md)
      invariant); a follow-up that cannot stay byte-green is dropped.
- [ ] Concurrent-GC × thunk-mutation interactions verified under `loom`/`miri`
      before shipping (`R-4`), daemon-mode only.

**Decisions closed/measured.**

- [ ] Measures: `M-4`/`Q-E` (NaN-box pays off?), `M-13` (context bitset vs
      smallvec crossover), `M-14`/`R-5` (region inference), `M-17`/`M-18`
      (parallel-forcing granularity / shared-value touch cost), `Q-G` (daemon
      model).
- [ ] Research-grade tail held under their defaults until measured:
      `R-1`/`R-2`/`R-3`/`R-4` (concurrent moving GC), `R-6` (daemon float-out),
      `R-7` (super-node IR — deferred).

**EXIT CRITERIA (falsifiable).** Each of pointer tagging / NaN-box /
full-laziness / region inference / concurrent *moving* GC lands *only*
with a recorded benchmark delta (C6); any that fails to show a delta is dropped,
not shipped; the harness stays byte-green throughout
([17](17-roadmap-and-risks.md) §3, P8). (Parallel *forcing* is no longer in this
tail — it is the committed P3.5 below/above; only the concurrent *moving
collector* remains here.)

**Rollout gate unlocked.** **Phase E** (verify-sampling reduced; `NixCli`
retained as the permanent fallback). Even at default-on, `AOS_NIX_NATIVE_VERIFY`
sampling stays as a residual canary and `AOS_NIX_NATIVE=0` remains the one-line
kill switch ([14](14-integration-with-aos.md) §7.2, §10).

---

## The parity invariant, drawn once

```text
   PHASE 1  ── achieve byte-for-byte parity (docs 20 + 21) under the
              SLOW tree-walk oracle.  Harness byte-green on full closure.
                         │
                         ▼   parity is now an INVARIANT
   P2 cache / P3 heap / P4 analyses / P5 shapes / P6 jit-1 / P7 jit-2 / P8 tail
        each phase changes ONLY performance; the harness (doc 15) re-proves
        parity after every change. A phase that cannot stay byte-green is
        reverted, not shipped.
                         │
                         ▼
   trust gradient (least → most trusted), doc 14 §9.2:
     unsafe JIT tiers  <  safe tree-walk oracle  <  NixCli (C++ Nix)
```

Optimizations are layered on top of an already-correct evaluator. The fast path
is never the final arbiter of a store path; a wrong `.drv` is catastrophic and a
slow `.drv` is merely slow ([17](17-roadmap-and-risks.md) §4.1).

---

## Definition of done (whole RFC)

The RFC-0007 implementation is **done** when all of the following hold
simultaneously:

- [ ] **Harness byte-green on the full closure.** The differential `.drv`-diff
      harness ([15](15-differential-testing-and-benchmarking.md)) is byte-green
      across the *entire* AOS package set — every `.drv` and store path identical
      to the pinned C++ Nix, identical error/no-error outcomes — and stays green
      in CI, under all execution tiers (oracle, tier 1, tier 2 with
      deopt/OSR exercised). The full [20](20-nix-language-conformance.md) and
      [21](21-builtins-conformance.md) surfaces are green and held invariant.
- [ ] **A measured win.** A recorded benchmark delta on representative AOS
      workloads shows native eval is materially faster than the `nix-instantiate`
      baseline from P1 — with the expected CLI win attributed to cache + arena
      (and analyses), per the measure-first discipline (`S-18`,
      [15](15-differential-testing-and-benchmarking.md) §6). Every shipped
      optimization carries its own measured delta; un-delivering ones were
      dropped, not shipped.
- [ ] **`AOS_NIX_NATIVE` default-On with `NixCli` fallback retained.**
      `AOS_NIX_NATIVE` defaults **On** for `instantiate` (Phase D/E) only after
      the closure has been byte-green and Shadow/verify-sampling silent on real
      traffic for a long window; `NixCli` remains the permanent oracle and
      one-env-var fallback (`AOS_NIX_NATIVE=0`), never removed; a residual
      `AOS_NIX_NATIVE_VERIFY` canary remains ([14](14-integration-with-aos.md)
      §7.1, §10; `S-16`).

If P1.5 determined eval is *not* the bottleneck, "done" is instead the recorded
STOP/re-scope decision plus the independently-useful P1 artifacts (the oracle
and the `.drv`-diff harness) — and phases P2–P8 are never built
([01](01-motivation-and-goals.md) §5.2, [17](17-roadmap-and-risks.md) R6).

---

## References

This checklist is a derived view; the authoritative argument for each item lives
in the document it cites.

- The phase table, ranked subset, Phase-1 checklist, and risk register:
  [roadmap and risks](17-roadmap-and-risks.md).
- Every decision ID (`S-*`/`C-*`/`M-*`/`R-*`) and its status:
  [decision register](19-decision-register.md).
- The `NixEval` seam, `AOS_NIX_NATIVE` modes, the Off → Shadow → On rollout
  Phases A–E, and the `unsafe` policy: [integration with AOS](14-integration-with-aos.md).
- The differential `.drv`-diff harness and per-commit benchmarking that gate
  every phase: [differential testing and benchmarking](15-differential-testing-and-benchmarking.md).
- The conformance surface held invariant from Phase 1 on:
  [Nix language conformance](20-nix-language-conformance.md) and
  [builtins conformance](21-builtins-conformance.md).
