# RFC-0007 - Implementation checklist (all phases)

This is the single tickable master checklist for the whole `aos-nix` build,
spanning every phase from the Phase-1 foundation through the research-grade
tail. It is the *superset* across all phases; Phase 1 already has a detailed,
ordered checklist in the [roadmap](17-roadmap-and-risks.md) §6, and this
document references that section rather than re-typing it verbatim. Every other
phase is expanded here in the same shape so an implementer can track the whole
project from one page.

It is bound to three upstream documents and must not contradict them:

- the [roadmap](17-roadmap-and-risks.md) — the budget mandate (§0), the phase
  table (P1–P8), the ranked build sequence (ranks 0–5, no longer a scope cut),
  the risk register, and the Phase-1 checklist;
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

## Budget mandate (read first)

This checklist is governed by the **unlimited-budget, non-time-bounded** mandate
in the [roadmap](17-roadmap-and-risks.md) §0: the goal is the *absolute fastest
and most efficient* Nix evaluator achievable, not a schedule-bounded fix for AOS
build time. That reframes how every box below is read:

- **The full technique stack is committed — there is no "90% subset."** The
  ranked build sequence is retained below only as a *build sequence*. The research-grade
  (`R-*`) tail in the [decision register](19-decision-register.md) — the **LLVM
  AOT tier-3** (peak throughput beyond the Cranelift JIT), a **concurrent moving
  GC**, and **full effect-based region inference** — is **in scope**, a committed
  deliverable, not "ship only if measured."
- **The P-phases are a build *order*, not a scope boundary.** Their sequence is
  dictated by dependency, correctness, and risk; with unlimited people the
  independent workstreams (frontend, cache, heap/GC, analyses, shapes, JIT tiers,
  AOT, parallelism) proceed **in parallel**. A box does not have to wait on an
  unrelated phase — only on its true predecessor (the gate dependencies in
  [17](17-roadmap-and-risks.md) §3 and the per-doc checklists).
- **"Measure-first" means *build-the-variants-and-select-the-winner*, not
  stop/descope.** The `M-*` register items (NaN-box vs. tagged value, fiber I/O
  turn-on, inlining thresholds, fusion aggressiveness, tier policies) are
  **build-and-select** decisions: implement the alternatives, benchmark, keep the
  winner — and **never ship a regression**. A measured finding does not cancel a
  deliverable; it chooses among implementations of it.
- **The correctness gates remain absolute — no amount of budget waives them.**
  The differential `.drv`-diff harness (byte parity), the `loom`/Miri
  memory-ordering audit (no data races), and the conformance suite
  ([20](20-nix-language-conformance.md)/[21](21-builtins-conformance.md)) gate
  **every** feature, always. Oracle-first, atomic-thunks-from-day-1, and
  parity-before-trust are *correctness sequencing*, not economics, and they stay.

The implementation is tracked **feature-by-feature**: every topic doc now carries
its own `## Implementation checklist`, and this document is the **roll-up**. See
the [per-doc checklist index](#per-doc-checklist-index) below.

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
- **A phase does not begin until its true predecessor artifact exists**
  (the gate dependencies in [17](17-roadmap-and-risks.md) §3) — but under the
  budget mandate the workstreams otherwise run in **parallel**, not strictly
  serial. For P1.5, the predecessor artifact is the P1 baseline data, not the
  later granular conformance cleanups. **P1.5 is no longer a kill gate.** Under
  the unlimited-budget mandate it is **baseline characterization**: we still
  measure where eval time goes, but a finding that eval is a minor fraction of
  build time does **not** stop the project — the goal is the fastest evaluator
  regardless ([17](17-roadmap-and-risks.md) §0; recast in the P1.5 section
  below).

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
- **Measure-first**, reinterpreted under the budget mandate (`S-18`,
  [17](17-roadmap-and-risks.md) §0): not "build only if proven worth it" but
  **build the competing variants, measure, keep the winner** — and never ship a
  regression. P1 data orders and parallelizes the work; it does not gate whether
  the optimization stack is built.

---

## Master progress table

| Phase | Goal | Rollout gate unlocked | Status |
|-------|------|-----------------------|--------|
| **P1** | Frontend + scope + tree-walk oracle + `.drv` harness; **full language + builtins parity achieved, IA *and* CA derivations** (C-11); thunk state atomic from day 1 (C-12) | Phase A (default Off, harness in CI); Phase B (Shadow) once enough of the closure is byte-green | ☐ |
| **P1b** | Re-layer the monolith into `ratchet` engine + Nix dialect (S-22); open effect lattice (S-23); behaviorally inert, harness byte-green | (no new rollout gate; parity held) | ☑ |
| **P1.5** | **Baseline characterization** (measure-first, *not* a kill gate): record where eval time goes; P2–P8 are built regardless | — (informs ordering/parallelism; does **not** decide whether P2–P8 happen) | ☑ |
| **P2** | Incremental early-cutoff cache + hash-consing (rank 1) | Phase B (Shadow) hardened; Phase C (On for `eval_expr`) becomes reachable | ☐ |
| **P3** | Bump-arena heap + precise generational GC (rank 2) | (parity held; trust schedule continues) | ☐ |
| **P3.5** | **Parallel graph evaluation** (C-12): L1 work-stealing pool + L2 lock-free CAS thunks; `loom`/Miri audit green | (parity held; multi-core speedup; oracle stays ground truth) | ☐ |
| **P4** | Strictness + escape analysis (rank 3) | Phase C (On for `eval_expr`) | ☐ |
| **P5** | Hidden classes + PIC (rank 4a) | (parity held; Phase C in effect) | ☐ |
| **P6** | Cranelift baseline JIT, tier 1 (rank 4b) | Phase D (On for `instantiate`, verify-sampling kept) becomes reachable | ☐ |
| **P7** | Cranelift optimized + deopt + OSR, tier 2 (rank 4c) | Phase D hardened across all tiers | ☐ |
| **P7.5** | **LLVM AOT tier-3** (committed): peak throughput beyond the Cranelift JIT for ahead-of-time / daemon-resident hot code; oracle remains correctness backstop | (parity held; tier-3 differentially identical to the oracle) | ☐ |
| **P8** | **Committed advanced stack** (formerly "measured follow-ups"): pointer tagging, full-laziness, **concurrent *moving* GC**, **full effect-based region inference** — all in scope, each carrying its own measured delta; build-the-variants-and-keep-the-winner | Phase E (verify sampling reduced; `NixCli` retained) | ☐ |

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

- [x] Crate skeleton: `crates/aos-nix/` in the workspace; pinned `nix-compat`
      git rev (`C-5`); `lib.rs` `//!` overview to the AOS doc standard.
      → re-layered in Phase 1b ([28](28-generalization-and-language-dialects.md) §10):
      the single-crate `aos-nix` layout splits into the `ratchet-*` engine +
      the `aos-nix-*` dialect band.
- [x] `NixEval` seam wired in `aos-core` ([14](14-integration-with-aos.md) §3):
      trait defined, `NixCli` as first impl, stub `NixNative` behind
      `AOS_NIX_NATIVE` (default off).
- [x] Frontend: `syntax/lexer`, `syntax/ast` compact arena AST with `u32`
      `NodeId`s and child slices, `syntax/parser` recursive-descent + Pratt
      parser (rnix remains test-only, `C-7`), `compile/scope` rewriting
      expression identifiers to `LocalVar { slot }`,
      `UpvalVar { depth, slot }`, `WithVar`, or `GlobalVar`, and
      `cache::parse` blake3 content-addressed parse cache over source bytes,
      schema version, and parser flags.
- [x] Value + heap subset: `value.rs` (16-byte tagged `Value`, **no NaN-boxing**,
      `S-6`/`M-4`), `heap/arena.rs` (bump-arena Tier A, allocate-never-free,
      all alloc behind `aos_alloc_*`), `attrs.rs` (sorted-vec + binary-search,
      `u32`-interned symbols, deterministic iteration order).
- [x] Tree-walk oracle core: `eval/tree_walk` current sequential call-by-need
      evaluator with serial `Suspended → Blackhole → Forced` thunks, forcing,
      closures, `with`, `rec`, `let`, `if`, and operators — the permanent
      sequential correctness oracle ([08](08-execution-tiers-and-cranelift.md)
      §2.1). The P3.5 parallel thunk protocol, full conformance, and full
      `.drv` parity gates remain separate open rows.
- [x] `runtime/builtins/` declaration/registry/dispatch substrate: generated
      builtin inventory, sorted registry, compile-time lookup table, direct and
      first-class call metadata, interned-`Symbol` lookup into generated
      dispatch, and ordinary filesystem `import` result/parse caching
      (`S-12`), excluding `scopedImport` and text-store parse-cache paths. Full
      primop semantics remain tracked by [10](10-primops-and-runtime-abi.md)'s
      open full-surface row and the conformance gates.
- [x] Compatibility core semantics: current tree-walk `derivationStrict`
      populates `nix_compat::derivation::Derivation`, emits explicit ATerm
      bytes, uses local SHA-256 fingerprint construction plus
      `nix_compat::store_path` for `compress_hash`/final store-path validation,
      supports input-addressed, fixed-output, floating CA, and impure output
      modes, materializes `.drv` bytes safely, and consumes sorted immutable
      string contexts for input partitioning.
- [x] Compatibility hardening: `nix-compat` pinned (snix git rev in
      `crates/Cargo.toml`); type-enforced three-hash split done (the
      `DerivationHashModulo` newtype distinguishing hash-modulo from raw ATerm and
      output digests); string context made copy-on-write (`Arc<[ContextElement]>`,
      O(1) clone) — the further interned-pool/bitset layer remains a documented
      perf follow-up, no correctness impact; full transitive
      `.drv`/drv-path/output-path parity proven by the byte-green full-closure
      gate; RFC-0005 deriving-path roots resolved (`drv!output`) and CA graph gates
      covered by the floating/fixed/structured content-addressed derivation tests.
      → re-layered in Phase 1b ([28](28-generalization-and-language-dialects.md) §10):
      the context bitset + union-on-concat semantics move out of `ratchet-value`
      into `aos-nix-dialect`.
- [x] Gate tooling/scaffolds: `diff_closure` plus `aos nix-diff` path, byte, and
      structural modes, closure traversal, root-vs-contaminated localization,
      direct node reruns, `--all`/`--systems`/toolchain/lang-corpus enumeration,
      binary corpus failure semantics, `NixCli::instantiate_with_stats`,
      `aos nix-diff --oracle-stats`, `aos nix-bench` with byte-parity guard
      before recording, `cargo-fuzz` `internal_diff_raw`/`parity_json` seeds,
      the configured C++ Nix lang corpus runner, and `proptest` invariant
      coverage are in place.
- [x] Full acceptance gate: **byte-identical `.drv` output from `NixNative` vs
      pinned C++ `nix-instantiate` (2.24.12) over the full AOS closure is DONE**
      (`aos nix-diff --all`: 0 divergences / 0 eval-failures across all 546
      packages), and the representative eval-time + `NIX_SHOW_STATS` baseline is
      committed (`docs/rfcs/0007-nix-evaluator/phase1-baseline.jsonl`).
- [ ] Standing harness robustness remains: rnix parser acceptance differential
      coverage is now present in `aos-nix-syntax`'s test-only
      `parser_acceptance_matches_rnix_oracle_on_p1_syntax_corpus` plus
      automatically enumerated local language fixtures, source-seed fuzz
      corpora, and the real workspace `.nix` source tree (package/module/system
      files); `aos nix-fuzz-corpus` now populates ignored parity-fuzzer source
      seeds from the full §2.7 package/toolchain/system corpus and configured
      generated conformance corpus. The configured pinned C++ oracle recursion
      semantics check now runs on a fixed 32 MiB worker stack, so recursive
      fixed-point regressions report as semantic test failures instead of
      aborting the `ratchet-oracle cpp_nix` harness process. Full parity-fuzzer
      budget/quiescence remains.
      This is a standing-harness robustness item, not the falsifiable byte-green
      gate, which is met.

**Conformance — FULL parity is a Phase-1 requirement.**

- [x] **All of the language surface in [20](20-nix-language-conformance.md)
      diffs green under the tree-walk oracle**: lexical/grammar forms, scoping
      (`let`/`rec`/`with`/inherit), operators and precedence, type coercions and
      string interpolation, `assert`/`throw`/`abort` and error *class* parity
      ([15](15-differential-testing-and-benchmarking.md) §3.3), attr-ordering
      and float-formatting corners.
      → The full 546-package closure (mkDerivation/ccWrapper/evalModules + every
      package expression) diffs byte-green, exercising this surface in practice.
      The configured pinned C++ Nix `2.24.12` `tests/functional/lang` corpus now
      runs through the tree-walk conformance gate with `208 passed, 1 skipped, 0
      failed`; the runner uses Nix-dialect lowering for raw/XML/strict paths,
      pins the configured target system as an evaluator option, and models
      dynamic `with`, search path, autoarg, XML, and postprocess cases. The
      representative error-class parity gate in [15](15-differential-testing-and-benchmarking.md)
      §3.3 covers type/throw/assert/abort classification separately from the
      upstream corpus's pass/fail outcome check.
- [x] **All pure builtins in [21](21-builtins-conformance.md) diff green** under
      the oracle (string/list/attr/arithmetic/`derivationStrict`/`import`/
      `toJSON`/`fromJSON`/path ops), with impure builtins
      (`readFile`/`readDir`/`getEnv`) producing identical `.drv` inputs on the
      tested closure.
      → Impure-builtin `.drv`-input parity on the closure is DONE (the readFile
      string-context fix). The configured pinned C++ Nix `2.24.12` oracle suite
      (`ratchet-oracle cpp_nix`) now passes with `43 passed, 31 ignored, 0
      failed`, covering the pinned builtin surface, identity constants,
      type/control/attrset/numeric/order/string/path/context/list/hash/JSON/XML/
      TOML/search-path/import/derivation semantics, trace/warn behavior, and
      generated core JSON expressions. The still-open full `fetchTree`/`getFlake`
      flake-protocol rows in [21](21-builtins-conformance.md) remain explicitly
      scoped outside this pure-builtin Phase-1 rollup.
- [x] **Parity is achieved here, under the slow oracle, before any optimization
      exists.** Demonstrated: the `.drv` differential harness is byte-green on the
      full AOS closure with no JIT/optimization tier present. This is then held
      *invariant* by every later phase; the differential harness
      ([15](15-differential-testing-and-benchmarking.md)) is the standing
      regression guard.

**Decisions closed/measured.**

- [x] Closes (builds as written): `S-1`, `S-2`, `S-3` (no JIT yet, backend
      chosen), `S-6`, `S-11`, `S-12`, `S-13`, `S-16`, `C-6` (IA-only), `C-7`
      (hand-rolled frontend), `C-9` (pinned Nix version), `M-4` default
      (16-byte tagged value, no NaN-box).
- [x] Produces the inputs for: `M-2` (cold-eval ceiling — Phase 1 *produces*
      it), `Q-B` baseline that sets C3's target. (Recorded in
      `phase1-baseline.jsonl` via `aos nix-measure`.)

**EXIT CRITERIA (falsifiable) — MET (2026-06-24).** The `.drv`-diff harness is
**byte-green on the full AOS closure** under the tree-walk oracle (zero
divergence across all 546 packages incl. `mkDerivation`/`ccWrapper`/`evalModules`,
vs pinned C++ Nix 2.24.12); baseline eval-time and `NIX_SHOW_STATS` numbers are
recorded (`phase1-baseline.jsonl`); `AOS_NIX_NATIVE` still defaults off (tested)
([17](17-roadmap-and-risks.md) §6, P1 exit).

**Rollout gate unlocked.** **Phase A** (default Off, harness in CI, PRs blocked
on regressions). **Phase B** (Shadow mode in CI) may begin as soon as the oracle
is byte-green on enough of the closure to be worth diffing against real CI
traffic ([14](14-integration-with-aos.md) §7.1; [17](17-roadmap-and-risks.md)
§3) — it does not wait for any later phase.

---

## Phase 1b — Re-layering into ratchet + the Nix dialect

**GOAL.** Split the single monolithic `aos-nix` crate into the language-agnostic
`ratchet` engine + the Nix dialect — the MLIR-style Core/dialect factoring of
[28](28-generalization-and-language-dialects.md) (decisions `S-22`/`S-23`). This
pass is **behaviorally inert**: it changes no `.drv` output, and the differential
harness stays byte-green on the same fixtures as before the split. It **enters**
once the parser → Core IR → oracle skeleton compiles and the first fixtures are
byte-green; it **overlaps** the tail of Phase 1 and the P1.5 characterization;
and it **must complete before Phase 2**, because P2 builds `ratchet-cache` and
the open effect lattice (`S-23`), which should be *born* in the new Core/dialect
model rather than retrofitted onto the monolith. The crate boundaries it draws
match [28](28-generalization-and-language-dialects.md) §3 /
[27](27-engineering-standards.md) §1.1; the full per-feature checklist lives in
[28](28-generalization-and-language-dialects.md) §10.

**Deliverables (from [28](28-generalization-and-language-dialects.md) §10).**

- [x] **Crate split with `ratchet` naming.** Break the `aos-nix` monolith into
      `ratchet-core` (Core IR, from `compile/ir.rs` + `compile/scope.rs`),
      `ratchet-oracle` (from `eval/`), `ratchet-value`
      (from `value.rs`/`list.rs`/`attrs.rs`/`heap/`), `ratchet-dialect` (new), and
      the Nix band (`aos-nix` umbrella, `aos-nix-syntax` from `syntax/`,
      `aos-nix-dialect` new, `aos-nix-compat` from the store glue,
      `aos-nix-harness`). Reserve but do not create `ratchet-gc` (P3),
      `ratchet-cache` (P2), `ratchet-jit` (P6), `ratchet-parallel` (P3.5).
- [x] **Core/dialect IR split.** Generic `IrKind` stays in `ratchet-core`;
      `DerivationStrict` and `WithVar` are Nix-owned dialect ops behind the
      `PrimOp` escape hatch (`IrData::DialectNode` /
      `IrData::DialectScopeVar` with Nix op keys), and the resolver's
      "unresolved name" path lowers only through a dialect hook.
- [x] **`EffectClass` → open trait (`S-23`).** Replace the closed
      `enum EffectClass { Pure, Effectful }` with a `ratchet-core` trait
      (`is_speculable` + `effect_key`); the Nix dialect supplies the members
      (`import`/IFD/`readFile`/`derivationStrict`); delete the hardcoded
      `effect_for(DerivationStrict) => Effectful`.
- [x] **String-context extraction.** `ratchet-value` keeps the generic tagged
      value + hash-consing; the context bitset + union-on-concat semantics move to
      `aos-nix-dialect`, with the engine's cons-key hashing taking a
      dialect-supplied discriminator so identical-bytes / different-context strings
      still do not collapse.
- [x] **`ratchet-dialect` trait definition.** The registration-time interface
      (extra ops, effect members, primop table, rewrite rules, lowering hooks);
      monomorphized, never `dyn` on the force path.
- [x] **Habit guard (carries through the rest of P1).** No new Nix-specific
      `IrKind` variants — every new builtin routes through `PrimOp`; keep
      string-context confined to the dialect.

**Conformance (hold parity).** The refactor is behaviorally inert; the
[20](20-nix-language-conformance.md)/[21](21-builtins-conformance.md) surface is
untouched and stays byte-green.

**Decisions closed/measured.**

- [x] Closes: `S-22` (Core + dialect / `ratchet` topology, Nix-only delivery),
      `S-23` (open, dialect-supplied effect lattice).

**EXIT CRITERIA (falsifiable) — MET (2026-06-24).** The `.drv`-diff harness is
byte-green on the **same fixtures as before the split** (behaviorally inert);
the crate boundaries match [28](28-generalization-and-language-dialects.md) §3 /
[27](27-engineering-standards.md) §1.1; complete before Phase 2 begins. Evidence:
`cargo test --manifest-path crates/Cargo.toml -p aos-nix-harness --features native-eval`.

**Rollout gate unlocked.** None (no new rollout gate; parity held — the trust
schedule continues unchanged).

---

## Phase 1.5 — Baseline characterization (measure-first, not a kill gate)

**GOAL.** Characterize, from P1 data, *where eval time goes* on representative
AOS workloads — which constructs, which phases of evaluation, cold vs. warm — so
the optimization workstreams are ordered and parallelized by evidence. Under the
[budget mandate](17-roadmap-and-risks.md) §0 this is **characterization, not a
kill/continue gate**: a finding that eval is a minor fraction of build time does
**not** stop or re-scope the project. The goal is the fastest evaluator
regardless, and P2–P8 are built either way.

**Deliverables.**

- [x] A documented **characterization** from the P1 baseline (`nix-instantiate`
      wall-clock + `NIX_SHOW_STATS` vs build/I/O time): the eval-time breakdown,
      the hottest constructs, and the cold/warm split
      ([01](01-motivation-and-goals.md) §5.1–5.2). Recorded in
      [phase1-baseline-characterization.md](phase1-baseline-characterization.md)
      from the committed `phase1-baseline.jsonl` artifact.
- [x] The breakdown is used to **prioritize and parallelize** the workstreams
      (which of cache / heap / analyses / shapes / JIT / AOT to staff first), not
      to gate whether they happen. Even if eval is a small fraction, the cheap P1
      artifacts (oracle + harness) also keep validating `NixCli` itself
      ([17](17-roadmap-and-risks.md) R6). The recorded order keeps P2 first,
      prepares P3/P4 in parallel once P2 interfaces settle, starts P5 with
      profiling hooks, and leaves JIT/AOT tiers behind the cache/heap/analysis
      data.

**Conformance.** No new surface; parity from P1 holds.

**Decisions closed/measured.**

- [x] Measures `M-1` opening data (how much does the cache plausibly buy?),
      `M-3` (cold vs warm fraction, first read).
- [x] Resolves `Q-B` for the committed representative P1 slice; informs
      `Q-A`/`Q-C` and the staffing order of P2–P8.

**EXIT CRITERIA (falsifiable) — MET (2026-06-24).** A written eval-time
**characterization** exists, grounded in P1 numbers, breaking down where time is
spent and feeding the workstream ordering:
[phase1-baseline-characterization.md](phase1-baseline-characterization.md). No
exit of this phase can cancel the project — under the budget mandate the
optimization stack is committed regardless of the breakdown.

**Rollout gate unlocked.** None directly — it *informs the ordering and
parallelism of P2–P8*, which are built unconditionally. The trust schedule
(Phases A/B) continues independently.

---

## Phase 2 — Incremental early-cutoff cache + hash-consing (rank 1)

**GOAL.** Add the headline systemic win: a demand-driven incremental computation
graph that memoizes thunk and `derivationStrict` results keyed on
`H(expr ⊕ env)` with **early cutoff**, plus hash-consing as its enabling
substrate. Pays off even on the rank-0 oracle; may clear the build-time goal
alone (`M-1`/`Q-A`).

**Deliverables.**

- [x] Current `cache/dcg.rs` in-memory demand-graph substrate: nodes keyed by
      opaque `DemandCacheKey`, deterministic dependency/dependent edges,
      clean/dirty freshness, and local `EarlyCutoff` reconsideration that newly
      dirties direct dependents only when a recomputed `ValueHash` changes or no
      prior hash exists.
- [x] Current demand-graph dirty-frontier scheduling substrate:
      `DemandGraph::dirty_nodes` exposes dirty nodes in deterministic node
      order, and `DemandGraph::ready_dirty_nodes` exposes only dirty nodes with
      no dirty transitive dependencies, so a future evaluator scheduler can
      recompute a frontier without bypassing early cutoff through dirty
      intermediates. This is a graph-side scheduling view only; automatic
      evaluator recomputation, dynamic dependency tracing, SCC-aware cycle
      handling, parallel scheduling, persistence, and cached/uncached harness
      proof remain open (`S-14`/`C-20`).
- [x] Current dirty-frontier blocker diagnostic substrate:
      `DemandGraph::dirty_frontier` returns a `DirtyFrontier` snapshot with
      ready dirty nodes and `BlockedDirtyNode` entries whose blocker lists name
      dirty upstream nodes in deterministic node order; dependency cycles that
      keep a dirty node reachable from itself report that self edge as a
      blocker instead of making a stalled frontier look empty. This is a
      graph-side diagnostic only; SCC-specific errors, evaluator scheduling
      integration, dynamic dependency tracing, persistence, and cached/uncached
      harness proof remain open (`S-14`/`C-20`).
- [x] Current graph-only ready-dirty recomputation loop substrate:
      `DemandGraph::recompute_ready_dirty_nodes` repeatedly snapshots the dirty
      frontier, calls a caller-supplied recompute callback for each ready dirty
      node's new `ValueHash` in deterministic node order, applies
      `reconsider_node` for early cutoff and dependent dirtying, and returns the
      ordered reconsiderations plus the final frontier. The loop cleans stable
      nodes, propagates changed hashes until the frontier is empty, and stops
      with a blocked frontier for dirty cycles or other dirty upstream blockers.
      This is graph-side scheduling only; evaluator node lifecycle integration,
      dynamic dependency capture, canonical value hashing, impure-input leaf
      integration, persistence, parallel/SCC-aware scheduling, and
      cached/uncached `.drv` harness proof remain open (`S-14`/`C-20`).
- [x] Current EvalCache dirty-frontier adapter:
      `EvalCache::dirty_frontier` exposes the graph-side `DirtyFrontier`
      snapshot through caller-owned evaluator cache state, and
      `EvalCacheRuntime::dirty_frontier` reports `None` when cache observation
      is disabled or the same read-only snapshot when enabled. This is a
      read-only adapter only; evaluator-owned recomputation, node lifecycle
      integration, dynamic dependency tracing, persistence, and cached/uncached
      harness proof remain open (`S-14`/`C-20`).
- [x] Current EvalCache ready-dirty recomputation adapter:
      `EvalCache::recompute_ready_dirty_nodes` and
      `EvalCacheRuntime::recompute_ready_dirty_nodes` expose the graph
      ready-dirty loop through caller-owned evaluator cache state, while
      disabled runtimes return `None` without invoking the recompute callback.
      This is an explicit cache-state adapter only; evaluator-owned node
      recomputation, dynamic dependency capture, canonical value hashing beyond
      caller-supplied `ValueHash` results, impure-input leaf integration,
      persistence, and cached/uncached `.drv` parity proof remain open
      (`S-14`/`C-20`).
- [x] Current dynamic dependency replacement substrate:
      `DemandGraph::replace_dependencies` validates a caller-supplied node and
      replacement dependency set before atomically swapping the node's whole
      forward dependency set and reverse dependent edges, and the explicit
      impure-trace adapters use it only for nodes whose dependencies are
      represented by the latest explicit trace, replacing those edges on
      cacheable recomputes and clearing them on incomplete or uncacheable
      recomputes. This is explicit graph/runtime edge maintenance only; typed
      dependency groups, automatic evaluator-owned dynamic dependency capture,
      separate inner/outer observers, evaluator-integrated ready-dirty
      recomputation, persistence, and cached/uncached `.drv` parity proof remain
      open (`S-14`/`C-20`).
- [ ] Full demand-driven incremental graph remains: create nodes on actual
      force/eval demand, capture dependencies dynamically Adapton-style,
      separate inner/outer observers, connect the ready-dirty recomputation loop
      to evaluator demand, integrate impure-input leaves and persistence, and prove
      cached/uncached `.drv` parity.
- [x] Current `force_memoized` claimed-thunk boundary: tree-walk `force_value`
      delegates newly claimed thunk forcing to `force_memoized_claimed_thunk`,
      which builds a force-cache subject only after demand reaches the thunk,
      routes policy-admitted subjects through the shared in-memory/durable
      force-cache path before evaluating the thunk body, publishes cache hits
      into the thunk cell, and observes successful WHNF results after admitted
      uncached body evaluation.
      Allocating a source-backed lazy attr thunk leaves the shared `EvalCache`
      empty until the thunk is actually forced and admitted. This is the current
      claimed-thunk inline payload boundary only; full demand-node lifecycle,
      dynamic dependency capture, canonical free-variable production, general
      memo lookup, persistent graph integration, and cached/uncached `.drv`
      harness proof remain open (`S-14`). The gate covers
      `source_backed_force_cache_creates_expression_node_only_on_force` plus
      source-backed force-cache hit/update tests.
- [x] Current `cache/key.rs` standalone combiner substrate: `CacheExprIdentity`
      plus opaque `DemandCacheKey` compute one order-sensitive hot xxh3 probe
      and one BLAKE3 confirmation digest over domain/version prefixes,
      expression identity bytes, and caller-supplied free-variable value hashes
      encoded as length-prefixed chunks. This checks the C-1 combiner rule only,
      not canonical free-variable set/order production, real durable value-hash
      production, or differential harness coverage.
- [x] Current expression-node allocation/keying substrate:
      `DemandGraph::get_or_insert_expression_node` and
      `EvalCache::get_or_insert_expression_node` centralize graph insertion for
      a caller-supplied `CacheExprIdentity`, ordered free-variable value hashes,
      and optional node value hash; existing nodes keep their first value hash.
      This is explicit allocation/keying only; canonical free-variable
      discovery/order from strictness/escape analysis, real durable value-hash
      production, `force_memoized`, automatic evaluator expression-node
      lifecycle, persistence, currentTime taint propagation, and cached/uncached
      harness proof remain open (`C-1`/`C-2`/`S-14`).
- [x] Current closed source-backed force-demand observation substrate:
      `EvalCache::observe_inline_expression_payload` and
      `EvalCacheRuntime::observe_inline_expression_payload` insert/reconsider
      expression nodes from caller-supplied identities, and tree-walk
      `force_value` now observes successful, closed, source-backed
      `EvalThunkKind::Node` forces whose entire body subtree is both speculable
      and in a conservative self-contained IR-kind whitelist, and whose WHNF
      result is either an inline scalar, a Nix string payload with or without
      context, a Nix path payload with or without context, a replayable Nix list
      whose existing spine elements are non-thunk replayable payloads or
      suspended closed literal thunks with replayable static payloads, or a
      replayable Nix attrset that preserves source-order metadata and
      root-or-own-module binding source positions when present and whose existing
      bindings are non-thunk replayable payloads or suspended closed literal
      thunks with replayable static payloads. Position-bearing observations are
      admitted only when every retained binding position belongs to the forced
      expression's own module, and admitted payloads carry that module's
      source-identity hash as replay provenance. The
      precursor expression identity uses a domain-separated hash of source name,
      source bytes, module path-literal base, evaluator-option salt, and the
      lowered node source span, then pairs that expression-positioned artifact
      hash with the IR node id, so identical file bytes under different
      relative-path bases or node spans do not share one observed node.
      `NixNative` passes its caller-owned cache runtime into
      tree-walk evaluation, so repeated closed source-backed evaluations reuse
      the same demand node and apply the existing value-hash early-cutoff
      decision. This is
      observation/reconsideration only: source-less raw eval outside the
      lowered-IR-backed node-thunk subset, captured dynamic/scoped-global
      thunks, ambient/synthetic builtin values outside the admitted constant subset,
      search-path/global/builtin/primop/application/dialect nodes pending
      explicit option and impure-input keys, synthetic apply/select
      thunks, canonical free-variable hashes, general memo lookup,
      remaining suspended non-literal/non-replayable captured thunk-cell free
      variables, arbitrary lazy-element list and lazy-binding attrset payloads,
      multi-module or non-own-module
      binding-position persistence and module-source remapping, and other
      composite value hashing, persistence, and cached/uncached harness proof remain open
      (`S-14`/`S-15`). The gate includes positioned attrset force-cache hit,
      imported own-module positioned attrset replay/remap, stale unprovenanced
      positioned payload miss/clear, and
      `unsafeGetAttrPos` provenance canaries.
- [x] Current pure closed force-cache hit substrate: `EvalCache` keeps per-node
      scalar/string/path/replayable-list/replayable-attrset payload records beside demand-graph value
      hashes, `EvalCacheRuntime::lookup_inline_expression_payload` returns a
      memoized payload only for clean nodes whose payload hash still matches the
      graph, and tree-walk `force_value` consults this shared cache before
      evaluating a policy-admitted newly claimed closed source-backed thunk whose
      entire body subtree is both speculable and in the conservative
      self-contained IR-kind whitelist. Hits publish immediate scalars directly and rehydrate
      context-free string bytes, context-bearing string bytes plus context, path bytes with or without context, replayable Nix lists, or replayable Nix attrsets with source-order metadata and root-or-own-module binding source positions into the evaluator-local heap before finishing
      the thunk cell, remapping retained own-module attr positions to the
      current body module on replay only when the payload carries matching
      module-source provenance; closed literal lazy list elements and attrset bindings
      rehydrate as strict static replayable payload values, so thunk identity
      and laziness from the cold run are not preserved across the cached
      payload. Disabled runtimes, unknown nodes, dirty nodes, missing payloads,
      stale payloads, unprovenanced positioned payloads, and incompatible,
      multi-module, or non-own positioned
      payloads are misses. This is a scalar/string/path/replayable-list/replayable-attrset
      pure/local hit path only: source-less raw eval outside the
      lowered-IR-backed node-thunk subset, captured dynamic/scoped-global
      thunks, ambient/synthetic builtin values outside the admitted constant subset,
      search-path/global/builtin/primop/application/dialect nodes pending
      explicit option and impure-input keys, synthetic apply/select
      thunks, canonical free-variable hashes, remaining suspended
      non-literal/non-replayable captured thunk-cell free variables, arbitrary
      non-literal lazy-element lists and lazy-binding attrsets, broader
      multi-module/non-own
      binding-position module-source remapping, and other composite payloads,
      transitive dirty scheduling, persistence, `derivationStrict` SHA-256
      short-circuiting, and cached/uncached harness proof remain open
      (`S-14`/`S-15`). The gate includes `cache::runtime` lookup tests,
      source-backed force-cache hit/skip tests, positioned attrset
      hit/provenance canaries, imported own-module positioned attrset replay/remap
      canary, stale unprovenanced positioned payload miss/clear canary, and
      closed-literal lazy composite hit canaries.
- [x] Current force-time inline impure-edge substrate: tree-walk force slices the
      impure-input trace observed while a closed source-backed thunk body
      evaluates, and
      `EvalCache::observe_inline_expression_payload_with_impure_inputs` stores
      a scalar/string/path/replayable-list/replayable-attrset payload only when that slice is complete and
      cacheable, wiring the expression node to the observed input leaves at the
      same time.
      The observation whitelist admits the existing pure subset plus cacheable
      input primops (`import`, `getEnv`, `hashFile`, `pathExists`, `readDir`,
      `readFile`, `readFileType`) with safe children such as path literals, so
      stable `pathExists`, ordinary filesystem `hashFile`, and canonical
      plain-file filesystem-import thunks reached without symlinked path
      components now create expression/input edges while `currentTime`,
      symlinked import routes, search-path literals, and application-like forms
      outside the selected first-class cacheable impure call subset still create
      no payload.
      Trace-backed payload records are tagged as requiring revalidation and are
      misses through the existing public lookup API; incomplete or uncacheable
      trace observations invalidate any existing payload for the same
      key. Lookup remains restricted to the pure/speculable subset until the
      cache retains typed input identities and revalidates them before a hit.
      This is edge wiring and payload storage only; source-less raw eval
      outside the lowered-IR-backed node-thunk subset, captured
      dynamic/scoped-global thunks,
      ambient builtin values outside the admitted constant subset,
      search-path/global/builtin/
      application/dialect nodes beyond the traceable primop subset, canonical
      free-variable hashes, typed input-identity retention, force-time input
      revalidation, remaining suspended non-literal/non-replayable captured
      thunk-cell free variables, arbitrary lazy-element lists, lazy-binding
      attrsets, and other composite payloads, transitive dirty scheduling,
      persistence, `derivationStrict` SHA-256 short-circuiting, and
      cached/uncached harness proof remain open (`R-10`/`S-14`).
- [x] Current force-time inline impure revalidation substrate: trace-backed
      inline payload records now retain the cacheable input fingerprints from
      their force-time trace, and
      `EvalCache::lookup_inline_expression_payload_with_impure_inputs`
      revalidates those typed identities through an `ImpureInputRevalidator`
      before returning a scalar, string, path, replayable-list, or replayable-attrset payload for
      tree-walk rehydration. Changed, unavailable, uncacheable, or
      identity-mismatched fresh inputs invalidate the payload and miss. Tree-walk
      supplies a conservative options-backed revalidator for `import`, `getEnv`,
      `hashFile`, `pathExists`, `readFile`, `readDir`, and `readFileType`, so
      stable source-backed `getEnv`, `hashFile`, `pathExists`, `readFile`-,
      `readDir`-, and `readFileType`-backed thunks, plus canonical plain-file
      filesystem-import-backed thunks reached without symlinked path components,
      can hit after replaying their input probes, including import-cache hits
      that replay the originally observed nested input trace and generated
      `readDir` attrsets canonicalized to a deterministic source order. Changed
      environment values, directory listings, file types, read/hash bytes, import
      source bytes, deleted paths, unavailable paths, or symlinked import routes
      force recomputation through the normal evaluator path. Revalidated cache
      hits append their fresh fingerprints back into the
      active evaluator trace so enclosing forced thunks cannot be observed as
      pure by losing nested dependencies.
      `readFile` revalidation is guarded by the option-salted expression
      identity for store-dir-dependent string context, and the older public pure
      lookup remains immediate-value-only. This is in-memory scalar/string/path/replayable-list/replayable-attrset
      effectful reuse only; source-less raw eval outside the
      lowered-IR-backed node-thunk subset, captured dynamic/scoped-global
      thunks, ambient builtin values outside the admitted constant subset,
      search-path/global/builtin/application/dialect nodes beyond the
      traceable primop subset, canonical free-variable hashes, persistent
      input-identity retention, remaining suspended non-literal/non-replayable
      captured thunk-cell free variables, arbitrary lazy-element lists,
      lazy-binding attrsets, and other composite payloads, transitive dirty
      scheduling, persistent graph/value cache integration, `derivationStrict`
      SHA-256 short-circuiting, and cached/uncached harness proof remain open
      (`R-10`/`S-14`).
- [x] Current force-cache evaluator option identity salt: force expression
      identities now hash the module's `store_dir`, `home_dir`, configured
      `current_system`, configured `current_time`, and `eval_mode` alongside
      source name or lowered-IR fingerprint, path-literal base, lowered node
      source span, and IR node id.
      This prevents the current admitted force-cache path from sharing inline
      payloads across evaluator configurations that can change path/context,
      ambient builtin constants, impurity-policy behavior, or expression source
      position. It is deliberately conservative and may miss across option/span
      changes that do not affect a
      specific expression; full cache-key integration, canonical free-variable
      hashes, fine-grained option dependency tracking, persistent keys, and
      cached/uncached harness proof remain open (`C-1`/`C-2`/`R-10`).
- [x] Current ambient and synthetic builtin constant force-cache substrate: tree-walk admits
      only symbol-checked `BuiltinAttr` constants for force-cache
      lookup/observation: immediate true/false/null, `currentSystem`,
      `storeDir`, `nixVersion`, and `langVersion`; `currentTime` is
      observation-only and remains uncacheable through its existing impure
      trace. Matching configured `currentSystem` and `storeDir` thunks can now
      hit as context-free string payloads, while changed `currentSystem` or
      `storeDir` options miss through the expanded option identity salt.
      Reified `builtins` attrset entries for those constants are now delayed
      synthetic builtin-attr thunks, so constructing the attrset does not force
      `currentTime`, and runtime selections such as
      `let b = builtins; in b.currentSystem` use synthetic identities keyed by
      module identity, force-site `IrId` and lowered source span, builtin
      symbol, and execution tag. The observation-only `currentTime`
      canaries assert that ordinary forcing leaves persistent force metadata
      and trace sidecars empty, while seeded stale durable node-thunk and
      synthetic builtin-attr `currentTime` payloads are cleared and tombstoned
      without recording demand. This
      deliberately skips the recursive `builtins` attrset, `nixPath`,
      derivation, first-class primops, synthetic apply/select thunks,
      broader persistence, and cached/uncached harness proof. The gate covers
      source-backed and source-less ambient and synthetic currentSystem
      hit/miss, synthetic storeDir hit/miss/symbol-separation, synthetic
      force-site span separation, synthetic immediate constants, reified currentTime laziness, stale synthetic
      currentTime runtime payload invalidation, observation-only currentTime
      sidecar-empty and stale-durable tombstone canaries, and source-backed/source-less
      currentTime uncacheable-trace force-cache tests (`C-1`/`C-2`/`R-10`).
- [x] Current source-less lowered-IR force-cache identity substrate:
      `cache::parse::lowered_ir_fingerprint` hashes the stable `ir.bin` and
      `symbols.bin` artifact encodings under the parse-cache schema version,
      and tree-walk uses that digest when a module has no source provenance
      before applying the same path-literal-base, `store_dir`, `home_dir`,
      configured `current_system`, configured `current_time`, and `eval_mode`
      salts plus lowered node and synthetic force-site source spans. This lets
      caller-owned in-memory cache runtimes share conservative source-less
      lowered-IR node-thunk and admitted synthetic builtin-attr payloads without
      requiring source bytes, while still separating equal-shaped IR whose symbol
      tables, path bases, evaluator options, node spans, or synthetic force-site
      spans differ. It is a
      source-independent identity substrate only; broader source-less raw eval
      surfaces, synthetic apply/select thunks, remaining composite payloads, persistence,
      fine-grained option dependency tracking, and cached/uncached harness proof
      remain open. The gate covers lowered-IR fingerprint tests plus
      source-less hit/miss, source/source-less domain separation,
      path/store/home/current-system/eval-mode salt, readFile revalidation,
      captured-free-variable tests, and source-less synthetic builtin constant
      hit tests (`C-1`/`C-2`/`S-14`).
- [x] Current inline/string/path/replayable-composite captured-free-variable
      force-cache key substrate: tree-walk now builds one force-cache subject for
      each source-backed or lowered-IR-backed node thunk, including ordered
      durable hashes for referenced captured lexical slots when every captured
      slot value is either an inline scalar supported by
      `ValueHash::from_inline_value`, a Nix string with or without context, a
      Nix path with or without context, a replayable Nix list, a replayable Nix
      attrset whose source-order metadata and binding positions are preserved
      when present, a
      fulfilled thunk cell whose cached value is one of those replayable values,
      or a suspended closed literal thunk whose static payload is one of those
      replayable values.
      Strings and paths are hashed in one durable force-capture domain with typed
      string/path tags; contextual values append canonical context element tags
      and length-prefixed path/output bytes. Replayable list/attrset captures
      hash the current replayable payload value hash under the same
      force-capture domain with a composite tag; positioned composites
      additionally salt the captured hash with the cache identity of every
      module referenced by retained binding positions. Lookup and observation feed
      those hashes into the existing ordered/length-prefixed demand-key
      combiner, so repeated captured inline/string/path/replayable-composite
      thunks hit only when their free-variable value hashes match and miss when
      those captured values differ or their referenced position-source
      identities differ. This deliberately skips dynamic `with`
      scopes, scoped-import globals, arbitrary non-literal lazy-element lists,
      arbitrary non-literal lazy-binding attrsets,
      position-bearing attrsets whose retained module ids cannot be resolved to
      loaded module identities, lambdas, primops,
      suspended non-literal/non-replayable thunk-cell captures including computed
      values not already forced in the captured slot, captured bodies with nested lexical-frame introducers, apply/select
      thunks, full strictness/escape free-variable analysis, remaining
      heap/composite value hashes, persistence, and cached/uncached harness
      proof. The gate covers captured inline/string/path/list and empty-attrset
      hit/miss tests, lowered lambda-argument coverage, cross-type string/path
      hash separation, materialized context-bearing string/path capture hash
      tests, preforced computed string thunk-cell capture tests, fulfilled
      replayable-attrset thunk-cell hash tests, direct suspended thunk-cell skip tests, caller-level
      suspended computed capture subject-skip canary, dynamic `with`/scoped-import
      global subject-skip canaries, lambda/recursive-attrset nested
      lexical-frame subject-skip canaries, captured lambda/primop value
      subject-skip canaries, synthetic apply/apply2/select thunk subject-skip
      canaries, captured root/imported positioned attrset source-salted
      admission and hit/miss canaries, source-order attrset admission canaries, captured closed-literal lazy-element list and
      lazy-binding attrset admission canaries, captured computed lazy-element list
      and lazy-binding attrset subject-skip canaries, and representative captured unsupported free-variable skips
      (`C-1`/`C-2`).
- [x] Current node-span force-cache identity precursor: source-backed and
      source-less node-thunk expression identities now fold the lowered node's
      source span into the durable expression-identity hash before pairing that
      hash with the existing `IrId` discriminator, and synthetic builtin-attr
      identities fold the lowered force-site span into their force-site
      `IrId`/symbol/execution identity. This moves the current
      identity shape toward the RFC `source content hash + IR node position` key
      while preserving the existing source-byte/lowered-IR fingerprint,
      path-literal-base, evaluator-option salt, synthetic builtin
      symbol/execution behavior, and ordered free-variable hash behavior. Full cache-key integration still
      requires canonical strictness/escape free-variable sets, real durable value
      hashes for all admitted values, persistent key compatibility decisions,
      and the cached/uncached false-hit harness. The gate covers a force-cache
      identity and shared-runtime no-hit regression for same source bytes and
      same `IrId` under changed node or synthetic force-site spans (`C-1`/`C-2`).
- [ ] Full cache-key integration remains: feed source content + IR node position
      from the evaluator into demand-graph expression nodes, reuse the
      strictness/escape free-variable set for canonical slot ordering, feed real
      durable value hashes, and run the differential false-hit gate (`C-1`/`C-2`).
- [x] Current memoization-granularity policy substrate: `cache::policy` defines
      `MemoizationSubject` defaults for the always/conditional/never classes and
      `MemoizationClass::decide` admits conditional work only when both
      used-many and cheap-value-hash signals are present. `MemoizationDemand`
      records same-run demand counts with saturating increments, marks a
      computation used-many on the second observed demand, and feeds that signal
      into the existing admission decision when the caller supplies
      value-hash cost information. This is policy vocabulary only; evaluator
      subject selection beyond the current force-cache thunk bridge,
      cardinality-analysis signal bridges, measured value-hash cost sampling,
      persistence/materialization policy refinement, and measured AOS tuning remain open
      (`M-11`).
- [x] Current force-cache memoization demand signal bridge: enabled
      `EvalCacheRuntime` records same-run `MemoizationDemand` by the same
      expression identity plus ordered free-variable hashes used for force-cache
      payload keys, returns the current `MemoizationSubject` default admission
      decision, and exposes read-only demand telemetry without allocating
      demand-graph expression nodes. Tree-walk claimed-thunk forcing now reports
      `MemoizationSubject::Thunk` demand with the current cheap-value-hash signal
      before force-cache admission, while disabled runtimes remain no-ops. This
      is the same-run signal bridge only; cardinality-analysis signals, measured
      value-hash cost sampling, broader evaluator subject selection, and AOS
      tuning remain open
      (`M-11`). The gate covers `cache::runtime` memoization-demand tests plus
      the source-backed force-cache demand bridge test.
- [x] Current force-cache memoization policy stats precursor: `EvalStats` and
      the `aos_nix::eval::stats` tracing event report
      `force_cache_memoization_admits`, `force_cache_memoization_bypasses`, and
      derived `force_cache_memoization_demands` from the runtime
      demand/admission bridge. These counters expose the policy decision stream;
      the counters themselves do not choose subjects, sample costs, or tune
      thresholds. Cardinality analysis, measured value-hash cost sampling,
      broader evaluator subject selection, and AOS tuning remain open
      (`M-11`). The gate covers stats trace tests plus the source-backed demand
      bridge stats test.
- [x] Current force-cache memoization admission gate: tree-walk consumes the
      force-cache `MemoizationDecision` before lookup/observation. `Bypass`
      forces the thunk normally and records persistent current demand, but skips
      in-memory and durable lookup, impure-trace slicing for force payloads,
      payload observation, value materialization, and force-cache hit/miss
      accounting. `Admit` preserves the existing lookup, revalidation,
      observation, materialization, and hit/miss paths. Tree-walk treats
      captured-free-variable node thunks, synthetic builtin-attr constants, and
      closed replayable composite literal node thunks as selected subjects that
      admit on first demand; ordinary node thunks remain conditional.
      Conditional thunk subjects admit on the second cheap same-run demand or on
      the first demand of a later run when persistent node metadata shows prior-run demand;
      missing subjects, disabled runtimes, lock errors, and demand-recording
      errors fail open to the old direct-evaluation path. This is a coarse thunk
      admission gate only; cardinality analysis, measured value-hash cost
      sampling, non-thunk evaluator subject selection, full `force_memoized`
      demand-node lifecycle, and AOS tuning remain open (`M-11`/`S-14`). The
      gate covers first-demand bypass/admit/hit force-cache tests plus
      persistent force-cache surface canaries.
- [x] Current force-cache hit/overhead stats precursor: `EvalStats` reports
      force-cache-specific hits, misses, and probes separately from aggregate
      evaluator cache hits/misses, and the stats tracing event emits
      `force_cache_hits`, `force_cache_misses`, and `force_cache_probes`.
      The aggregate `cache_hits`/`cache_misses` fields retain their existing
      broad meaning by combining force-cache counts with import parse-cache and
      find-file cache counts. This is coarse telemetry only; it does not select
      memoization subjects, sample value-hash costs, attribute wall-clock
      overhead to individual nodes, or tune policy thresholds from AOS workloads
      (`M-11`). The gate covers stats trace tests plus source-backed
      force-cache hit/miss tests.
- [x] Current `cache/cutoff.rs` standalone decision primitive: typed
      `ValueHash` plus `EarlyCutoff::decide(previous, recomputed)` returns
      `CutOff` only when a prior value hash exists and equals the recomputed
      value hash; missing or changed prior hashes return `Propagate`.
- [x] Current inline scalar/string/path/replayable-list/replayable-attrset value-hash substrate:
      `ValueHash::from_inline_value` hashes validated inline WHNF
      `int`/`bool`/`null`/`float` payloads in the durable BLAKE3 domain
      `aos-nix-inline-value-hash-v1`; floats are hashed by raw IEEE bits, so
      this may over-propagate relative to future Nix numeric canonicalization
      but cannot cut off distinct bit patterns. `ValueHash` also hashes
      context-free string bytes, context-bearing string bytes plus canonical
      context elements, path bytes with or without canonical context elements,
      empty lists, replayable list payloads whose element payloads are length-framed,
      replayable attrset payloads whose binding names and value payloads are
      length-framed in separate durable BLAKE3 domains, and
      position-bearing attrset payload records whose binding position-presence
      tags, module ids, and source spans participate in the hash; source-provenanced
      positioned result payloads additionally include the retained module
      source-identity hash in the persistent value preimage; attrset
      hashing uses raw-byte-sorted binding order for canonical attrsets and
      distinct source-order tags when construction order is observable.
      Arbitrary non-literal lazy-element list and lazy-binding attrset cacheability, multi-module/non-own-module position-bearing attrset replay, functions/thunks cacheability
      policy, generic hash-cons value fields, `force_memoized` integration, and
      harness proof remain open (`S-14`/`S-15`). The gate includes positioned
      attrset payload lookup/hash/root-position persistence coverage,
      own-module imported positioned attrset replay/remap coverage, stale
      unprovenanced positioned payload miss/clear coverage, and
      source-salted positioned captured attrset hash coverage.
- [x] Current inline-value early-cutoff adapter:
      `DemandGraph::reconsider_inline_value_node` and
      `EvalCache::reconsider_inline_value_node` hash a recomputed inline scalar
      before applying ordinary node reconsideration; unsupported heap values
      fail before mutating node state. This is an inline adapter only;
      heap/composite canonical hashing, functions/thunks policy, real evaluator
      value-hash production, `force_memoized`, evaluator node lifecycle,
      automatic `NixNative` use, persistence, and harness proof remain open
      (`S-14`/`S-15`).
- [x] Current derivation ATerm value-hash precursor:
      `ValueHash::from_derivation_aterm_bytes` hashes recorded `.drv` ATerm
      bytes in a separate durable BLAKE3 value-hash domain and can drive
      `EarlyCutoff` equality for repeated derivationStrict surfaces while
      staying out of Nix-observed SHA-256 path and `.drv` hashing. This is a
      comparison-key precursor only; evaluator-owned derivationStrict demand
      nodes, dependency capture, SHA-256 short-circuiting, persistence, and
      cached/uncached `.drv` parity proof remain open (`S-14`/`S-15`).
- [x] Current derivation ATerm cache observation adapter:
      `DemandGraph::reconsider_derivation_aterm_node`,
      `EvalCache::observe_derivation_aterm_expression`, and
      `EvalCacheRuntime::observe_derivation_aterm_expression` expose
      caller-owned early-cutoff observation over recorded `.drv` ATerm bytes,
      with disabled runtimes returning `None` without mutating cache state.
      This is an explicit cache API only; evaluator-owned derivationStrict
      demand-node lifecycle, expression identity/free-variable production,
      dependency capture, SHA-256 short-circuiting, persistence, and
      cached/uncached `.drv` parity proof remain open (`S-14`/`S-15`).
- [x] Current derivation ATerm path lookup substrate:
      crate-private `EvalCache::observe_derivation_aterm_expression_path`,
      `EvalCacheRuntime::observe_derivation_aterm_expression_path`, and
      `lookup_derivation_aterm_path` store caller-supplied `.drv` path bytes
      beside a derivation ATerm value hash and bind the graph node to the full
      ATerm/path side-payload hash. Lookups return path bytes only for clean
      nodes whose side record still matches the caller's ATerm bytes and whose
      current graph hash still matches the recorded ATerm/path payload. Dirty,
      changed, missing-key, missing-record, and disabled-runtime cases are
      misses. This cache-side in-memory storage/lookup substrate is now
      consumed by the later tree-walk cached `.drv` path reuse precursor for
      eligible derivations; runtime-level generic side-record persistence,
      dependency capture beyond hashable lexical captures, full SHA-256
      store-path short-circuiting, and full
      cached/uncached `.drv` parity proof remain open (`S-14`/`S-15`).
- [x] Current derivationStrict ATerm evaluator observation substrate:
      tree-walk `derivationStrict` observes recorded `.drv` ATerm bytes into
      the enabled `EvalCacheRuntime` after normal output path and `.drv` path
      computation, using a derivation-specific expression identity salted by
      module identity, source span, and hashable captured lexical free
      variables. Disabled runtimes, `with`/scoped-global environments, and
      unsupported captured values skip observation; repeated unchanged
      derivation ATerm/path payloads increment early-cutoff stats without
      counting cache hits or misses. This explicit observation path feeds the
      in-memory and persistent final-path precursors only: evaluator-owned
      recomputation scheduling, dynamic dependency capture beyond hashable
      lexical captures, full SHA-256 short-circuiting, and full
      cached/uncached `.drv` parity proof remain open (`S-14`/`S-15`).
- [x] Current derivationStrict ATerm path-record writeback substrate:
      tree-walk `derivationStrict` writes the already-computed absolute `.drv`
      path bytes into the derivation ATerm cache side record through
      `EvalCacheRuntime::observe_derivation_aterm_expression_path`, after
      normal Nix-observed path computation has completed, when eval-cache
      observation is enabled and derivation ATerm subject capture, runtime
      locking, and serialization succeed. The later cached `.drv` path reuse
      precursor now consults this side record for eligible static, floating-CA,
      and impure derivations, but deferred-placeholder `.drv` paths and the
      initial derivation modulo hash still use normal construction. Dependency
      capture beyond hashable lexical captures, full SHA-256 store-path
      short-circuiting, and full
      cached/uncached `.drv` parity proof remain open (`S-14`/`S-15`).
- [x] Current derivationStrict cached `.drv` path reuse precursor:
      tree-walk `derivationStrict` recomputes final ATerm bytes for static,
      floating-CA, and impure derivations, probes the clean derivation ATerm
      path side record, validates that cached absolute path against the
      current configured store directory and expected `${name}.drv` basename,
      and reuses it instead of rebuilding the final `.drv` text path when the
      record matches. The reuse increments `derivation_aterm_path_reuses`,
      drives `derivation_text_path_calculations` to zero for matching clean
      root reuse tests, and
      leaves aggregate `cache_hits`/`cache_misses` and force-cache hit/miss
      accounting unchanged; misses, stale records, disabled runtimes,
      unsupported captured values, invalid cached paths, configured-store
      mismatches, and wrong derivation names fall back to normal path
      construction. Initial derivation modulo hashing, static-output misses,
      deferred-placeholder derivations, dependency capture beyond hashable
      lexical captures, full
      derivationStrict-node SHA-256/store-path early cutoff, and
      full cached/uncached `.drv` parity proof remain open (`S-14`/`S-15`).
- [x] Current persistent derivationStrict `.drv` path side-record precursor:
      tree-walk `derivationStrict` materializes exact final ATerm/path side
      payloads into the persistent `values/` pack keyed from the same
      derivation expression identity and hashable lexical free-variable value
      hashes as the in-memory side record. Fresh runtimes can load the payload,
      verify that the blob hash equals the recorded side-payload value hash,
      require the persisted ATerm bytes to match the freshly recomputed ATerm,
      and reuse the final `.drv` path through the same store-dir/name
      validation as in-memory hits before seeding the runtime side record. This
      skips only the final `.drv` text-path calculation for exact ATerm
      matches; final ATerm serialization, initial derivation modulo hashing,
      deferred-placeholder derivations, dynamic
      dependency capture beyond hashable lexical captures, full
      derivationStrict-node SHA-256/store-path early cutoff, and full
      cached/uncached `.drv` parity proof remain open. Gates: persistent
      derivation ATerm path payload round-trip, fresh-runtime path-reuse, and
      stale-ATerm mismatch plus invalid-path fallback tests (`S-14`/`S-15`).
- [x] Current static derivation output-path reuse precursor:
      tree-walk `derivationStrict` records a clean crate-private side payload
      for static derivations keyed by a separate input-hash-substituted
      pre-output ATerm identity, containing resolved output store paths plus
      the final derivation hash modulo. The demand-graph value hash for this
      side record binds the pre-output ATerm, output path payload, and final
      modulo hash, so changed payload observations propagate even when the
      pre-output ATerm key is unchanged. Later unchanged static derivations
      probe that record before calculating the derivation-modulo hash, validate
      that every cached output belongs to the
      current output set, is inside the configured store, and has the expected
      output basename, then restore output paths and skip the input-addressed
      output path computation plus both static-output modulo hash calculations.
      Reuse increments `static_derivation_output_path_reuses` but does not count
      as a generic force-cache hit; disabled runtimes, unsupported captured
      values, stale/dirty/changed records, invalid payloads, and output-set
      mismatches fall back to normal construction. Final ATerm serialization,
      deferred-placeholder derivations, dynamic dependency capture beyond
      hashable lexical captures, and full cached/uncached `.drv` parity proof
      remain open (`S-14`/`S-15`).
- [x] Current persistent static derivation output-path side-record precursor:
      tree-walk `derivationStrict` materializes exact pre-output ATerm/static
      output side payloads into the persistent `values/` pack keyed from the
      static-output derivation expression identity and hashable lexical
      free-variable value hashes. Fresh runtimes can load the payload, verify
      that the blob hash equals the recorded side-payload value hash, require
      the persisted pre-output ATerm bytes to match the freshly recomputed
      pre-output ATerm, and reuse output paths only after the existing
      output-set, configured-store, output-basename, and duplicate-output
      validation succeeds. This skips the static-output derivation hash/modulo
      work for exact pre-output matches; final ATerm serialization, final
      `.drv` path construction when no final-path side record exists,
      deferred-placeholder derivations, dynamic dependency capture beyond
      hashable lexical captures, full derivationStrict-node SHA-256/store-path
      early cutoff, and full cached/uncached `.drv` parity proof remain open.
      Gates: persistent static-output payload round-trip, fresh-runtime reuse,
      stale-pre-output mismatch fallback, and invalid-output-path fallback
      tests (`S-14`/`S-15`).
- [x] Current cached derivationStrict `.drv` surface parity canary:
      tree-walk tests compare cache-off, cache-on first-observation, and
      cache-on path-reuse runs for root static, floating-CA, and impure
      derivations, a static input-closure graph, a deferred-placeholder
      downstream graph, plus fresh-runtime persistent exact-ATerm final-path
      and exact-pre-output static-output hits, requiring identical recorded
      `.drv` paths and ATerm bytes across those runs. The static root case
      proves one static-output-path reuse before final `.drv` path reuse, zero
      derivation hash-boundary calculations, and zero final `.drv` text-path
      calculations on the clean reuse run. The static/floating-CA/impure root
      cases prove final `.drv` path reuse skips final text-path calculation,
      and the static
      input-closure case proves two eligible input derivations reuse static
      output paths and final `.drv` paths while reducing derivation hash and
      text-path work without changing the downstream closure surface; the
      persistent floating-CA case proves a fresh runtime can skip the final
      text-path calculation without static-output reuse, and the persistent
      static case proves a fresh runtime can skip static-output hash work and
      final text-path work together. This is selected in-memory and exact
      persistent reuse parity only; full-closure cached/uncached parity,
      dynamic dependency capture beyond hashable lexical captures, broader
      modulo-hash shortcuts, and full derivationStrict-node SHA-256/store-path
      early cutoff remain open
      (`S-14`/`S-15`).
- [x] Current forced-payload early-cutoff stats substrate:
      trace-backed force-cache payload observation now reports its value-hash
      `Reconsideration`, first trace-backed insertion uses no synthetic prior
      hash, and tree-walk increments `EvalStats::early_cutoffs` when a
      recomputed pure or trace-backed force-cache payload returns `CutOff`.
      This is telemetry for the current explicit force-cache observation path
      only; evaluator-owned recomputation scheduling, transitive red/green
      propagation, canonical hashes for all values, persistence-aware cutoff
      accounting, and cached/uncached `.drv` parity proof remain open
      (`S-14`/`M-11`).
- [ ] Full Salsa/red-green early cutoff remains: recompute demand-graph nodes,
      produce canonical value hashes, compare old/new hashes, stop propagation
      through dependents on no-change, and prove cached/uncached `.drv` parity.
- [x] Current value-consing precursor outside future `value/hashcons.rs`: the P1
      evaluator heap already conses heap strings and path values in separate
      evaluator-local tables using `NixString::structural_hash_xxh3()` plus
      equality confirmation, preserving context-sensitive identity so identical
      bytes with different contexts do not collapse. This is limited string/path
      consing, not generic immutable-value hash-consing, composite value maximal
      sharing, O(1) equality for all values, durable value hashes, or field-load
      value-hash support.
- [ ] `value/hashcons.rs` — full hash-consing / maximal sharing of immutable
      values: generic post-force interning for composite values, O(1) equality,
      cached value hashes that make value-hashing a field load, and integration
      with the demand graph/early cutoff (`S-7`).
- [x] Current hash-routing and typed-domain precursor in `cache/hashing.rs`:
      evaluator-local string/path cons tables use xxh3 structural hashes with
      equality confirmation and are typed as `HotXxh3Hash`; durable frontend
      parse-cache keys use BLAKE3 over source bytes plus schema/flags, with
      file memo keys pairing canonical realpath and BLAKE3(file bytes), and are
      typed as `DurableBlake3Hash`; Nix-observed `.drv`/store-path surfaces use
      SHA-256 and hash/fetch builtins use their requested Nix hash APIs rather
      than evaluator-local xxh3/BLAKE3 digests. This is the current substrate
      only, not the full P2 cache hashing layer (`S-15`).
- [x] Current Nix-observed hash leak canary:
      `internal_cache_hash_canaries_do_not_reach_drv_surfaces` evaluates a
      static derivation through configured parse/persist cache roots with
      eval-cache observation enabled while importing a real temporary file and
      materializing an effectful forced `builtins.pathExists ./marker` payload.
      It computes the actual current parse-cache BLAKE3 keys for the root and
      imported sources, the `ParseFileKey` content hash for the imported file,
      the persisted force-cache node metadata keys, materialized value hashes,
      node-trace value hashes plus input identity and observation hashes, and the
      evaluator-local xxh3 structural hash for the derivation name string, then
      checks both recorded
      `.drv` ATerm bytes and the `.drv` store path for absence of those
      internal digest renderings, Nix-base32 encodings, and raw digest bytes.
      It also asserts the configured import parse-cache entry, persistent
      file-artifact mapping, persistent force value, and effectful force trace
      occurred. This is a selected current-substrate regression canary, not the
      full type-enforced P2 leak-invariant harness (`S-15`).
- [x] Current imported-derivation cache-surface parity canary:
      `configured_import_cache_preserves_drv_surfaces` evaluates the same
      imported-file derivation with import caching disabled, with configured
      parse/persist roots on a miss/write path, and with a later persistent-hit
      path, then requires identical `.drv` paths and ATerm bytes across all
      three runs. It also scans those surfaces for the imported file
      parse-cache and file-content BLAKE3 renderings in hex, raw bytes, and Nix
      base32. This is selected current-substrate coverage only, not the full
      cached/uncached closure parity gate (`S-15`).
- [x] Current hash-builtin cache-surface canaries:
      `configured_import_cache_preserves_hash_builtin_surface` evaluates
      `builtins.hashString "sha256" (import file)` with import caching disabled,
      with configured parse/persist roots on a miss/write path, and with a later
      persistent-hit path, then requires identical SHA-256 hash-string output
      across all three runs and scans that output for the selected internal
      parse/import/file-content BLAKE3 and hot xxh3 canaries.
      `configured_cache_preserves_guarded_hash_file_surface` evaluates
      `builtins.hashFile "sha256" ./payload.txt` behind a forced
      `builtins.pathExists ./marker` guard with eval-cache disabled, with
      configured persistent force-cache demand/writeback on cold and
      materializing paths, and with a fresh-runtime persistent force-cache hit
      for the guarded hashFile trace,
      then requires identical SHA-256 file-hash output across all runs and scans
      that output for synthetic root parse-cache-key and payload-content BLAKE3
      sentinels, actual guard/hashFile persistent force-cache trace/value
      canaries, and hot xxh3 canaries. These sample selected
      `hashString`/`hashFile` output surfaces only; they do not prove the full
      hash/fetch builtin leak-invariant gate (`S-15`).
- [ ] Remaining full P2 cache hashing split: demand-graph xxh3 keys, BLAKE3
      durable/shared value and file CA keys, full type-enforced leak-invariant
      boundaries, and CI/harness proof that internal xxh3/BLAKE3 digests cannot
      reach Nix-observed store-path or `.drv` SHA-256 inputs (`S-15`).
- [x] Current `cache/persist.rs` layout/schema substrate: creates an
      evaluator-cache root with versioned `nodes/`, `values/`, `files/`, and
      `schema.toml` metadata carrying a stable format marker plus schema
      version; `ratchet-cache::schema::CacheSchema` owns the TOML
      read/parse/validation and temp-file replacement write primitive, and
      `ratchet-cache::owned_paths::OwnedPaths` owns root/payload directory
      creation plus schema-mismatch payload discard while `ratchet-oracle`
      preserves the discard policy and `PersistError` surface. Matching schemas
      preserve payloads, well-formed version mismatch discards only owned
      payload paths without following symlinks, and malformed or wrong-format
      metadata errors without deleting payloads. This is layout/versioning plus
      schema/owned-path migration only; node/value/file serialization, mmap
      packfiles, LMDB/redb metadata, Attic transport, GC, and full harness proof
      remain open (`R-14`).
- [x] Current content-addressed blob key/packfile path substrate:
      `PersistLayout` fixes store-specific append-only packfile paths under
      `values/` and `files/`, while `PersistBlobStore`/`PersistBlobKey` produce
      stable domain-separated `DurableBlake3Hash` keys for the future
      hash-to-offset index. This is addressing only; serialization, mmap
      packfile format, append/read, offset indexing, GC/repack, and harness
      proof remain open (`C-13`/`R-14`).
- [x] Current immutable blob packfile codec substrate:
      `PersistBlobPackHeader` validates fixed magic/version/header-length bytes,
      and `PersistBlobRecordHeader` encodes each record's `DurableBlake3Hash`
      plus payload length as stable little-endian metadata. This is format
      metadata only; file creation, append/read, mmap, payload verification,
      offset-index writes, GC/repack, and harness proof remain open (`C-13`).
- [x] Current buffered blob pack append/read substrate: `PersistBlobPack`
      initializes headers without replacing corrupt non-empty files, appends
      only payloads matching the caller's `DurableBlake3Hash`, returns record
      offsets plus lengths, and reads payloads back with record and payload hash
      verification. This is ordinary `std::fs` IO only; mmap zero-copy reads,
      LMDB/redb index integration, batched writing, crash-durability policy,
      GC/repack, Attic transport, and harness proof remain open (`C-13`).
- [x] Current `ratchet-cache` unsafe crate and mmap primitive:
      `ratchet-cache` now exists as the RFC engine-band unsafe crate with
      `#![deny(unsafe_op_in_unsafe_fn)]`, and `store::ReadOnlyMmap` wraps Unix
      read-only `mmap` behind an explicitly unsafe constructor, documented file
      immutability contract, and `// SAFETY:` comments for every unsafe block.
      `ratchet-oracle` remains `#![forbid(unsafe_code)]` and does not call this
      primitive yet. This is the unsafe fence and raw mapping substrate only;
      safe cache-root lease protocol, LMDB/redb metadata, mmap-backed indexed
      hits, out-of-core value rematerialization, cross-process writer
      coordination, and harness proof remain open (`C-13`/`R-14`).
- [x] Current `ratchet-cache` mmap blob-pack payload reader:
      `blob_pack::MappedBlobPack` validates the current pack header and record
      format from a `ReadOnlyMmap`, checks lookup hash/length and payload
      bounds, rehashes mapped payload bytes with BLAKE3, and returns
      `MappedBlobPayload<'_>` as a borrowed zero-copy slice. Unit coverage
      includes generated packs plus a frozen literal `AOS-NIX-BLOBPACK`
      empty-payload fixture that pins magic/version/header-length, record hash,
      and little-endian payload length bytes. This covers the current
      compatibility format inside the unsafe engine crate only; construction
      remains `unsafe`, and safe cache-root leases, `ratchet-oracle`
      integration, append writing, LMDB/redb offset indexes, automatic
      mmap-backed indexed hits, out-of-core rematerialization, cross-process
      writer coordination, and harness proof remain open
      (`C-13`/`R-14`).
- [x] Current lease-shaped mmap blob-pack API:
      `blob_pack::BlobPackReadLease` is an unsafe-to-implement trait whose
      `covers_file` contract states that a file is immutable for the borrowed
      lease lifetime, and `MappedBlobPack::map_file_with_lease` returns
      `LeasedMappedBlobPack<'lease>` so mapped payload borrows cannot outlive
      that lease. Tests cover accepted leases and rejected non-covering leases.
      A compile-fail rustdoc canary proves a leased mapping cannot escape a
      stack lease as `'static`.
      This is a type-boundary substrate only; production cache-root lease
      implementation, same-root lock migration into `ratchet-cache`,
      cross-process/durable filesystem leases, `ratchet-oracle` integration,
      automatic mmap-backed indexed hits, append-writer migration, LMDB/redb
      offset indexes, out-of-core rematerialization, and harness proof remain
      open (`C-13`/`R-14`).
- [x] Current oracle-writer/mapped-reader compatibility canary:
      `aos-nix-harness` has an integration test that writes blob-pack records
      through the existing safe `ratchet-oracle::cache::PersistBlobPack`
      buffered writer, maps the resulting file through
      `ratchet-cache::blob_pack::MappedBlobPack`, and verifies the borrowed
      mapped payload slices match the original bytes. The unsafe mmap call
      stays in harness test code rather than the safe oracle crate. This is
      format compatibility coverage only; production mmap-read integration,
      safe cache-root leases, mmap-backed indexed hits,
      LMDB/redb offset indexes, out-of-core rematerialization, cross-process
      writer coordination, and harness proof remain open (`C-13`/`R-14`).
- [x] Current `ratchet-cache` blob-pack tail-trim primitive:
      `blob_pack::BlobPackAppender::trim_tail` validates the current pack
      header, rejects offsets before the fixed header or beyond the current
      file length, truncates only the requested suffix, and returns the removed
      byte count. Unit coverage proves tail-record reclamation, no-op trims,
      invalid offset rejection, past-end rejection, and corrupt-header
      preservation, and `PersistBlobPack::trim_tail` now delegates to this
      primitive while preserving the existing oracle error surface. This is an
      uncoordinated engine-side truncation primitive only; cache-root writer
      locks in `ratchet-cache`, cross-process/durable coordination, crash
      transactions with sidecar indexes, automatic GC policy, LMDB/redb offset
      indexes, mmap-backed indexed hits, and full harness proof remain open
      (`C-13`/`R-14`).
- [x] Current hash-to-offset index value codec substrate: `PersistBlobKey`
      supplies domain-separated index keys, and `PersistBlobLocation` round-trips
      record offset plus payload length as stable little-endian index metadata.
      This is codec-only; LMDB/redb environments, tables, transactions, index
      writes/reads, mmap pointer reads, GC/repack, and harness proof remain open
      (`C-13`).
- [x] Current hash-to-offset index entry codec:
      `PersistBlobIndexEntry` binds a decoded `PersistBlobKey` to its
      `PersistBlobLocation` in one stable fixed-width record, preserving
      short-prefix and malformed embedded-key validation through the existing
      codecs. This is codec-only; LMDB/redb environments, tables, transactions,
      index writes/reads, mmap pointer reads, GC/repack, and harness proof remain
      open (`C-13`).
- [x] Current fixed-record blob index file substrate:
      `PersistBlobIndex` opens/creates a sidecar index file, appends fixed-width
      `PersistBlobIndexEntry` records, rejects truncated record tails on open,
      and linearly scans records to return the newest matching hash-to-offset
      location. This is a simple durable sidecar only; LMDB/redb MVCC tables,
      transactions, writer batching/locking, automatic integration with
      low-level `PersistCache::append_blob`/`read_blob`, mmap pointer reads,
      GC/repack, and harness proof remain open (`C-13`).
- [x] Current file-artifact mapping codec substrate:
      `PersistFileArtifactKey` derives a stable `files/` index key from
      canonical realpath bytes, source content hash, and the
      schema/flag-sensitive `ParseCacheKey`, while
      `PersistFileArtifactIndexValue` encodes a `files/` blob key plus pack
      location. This is codec-only; durable index engines, parse-artifact pack
      payloads, lookup/write integration, mmap reads, GC/repack, Attic
      transport, and harness proof remain open (`C-13`/`R-10`).
- [x] Current file-artifact index key decoder:
      `PersistFileArtifactKey::decode_index_bytes` round-trips the 33-byte
      tagged file-artifact mapping key, accepts longer index-key prefixes
      consistently with other fixed codecs, and rejects short or wrong-tag keys
      through `PersistPackFormatError`. This is codec-only; durable index
      engines, lookup/write integration, parse-artifact payload validation,
      mmap reads, GC/repack, Attic transport, and harness proof remain open
      (`C-13`).
- [x] Current file-artifact index entry codec:
      `PersistFileArtifactIndexEntry` binds a decoded file-artifact mapping key
      to its `files/` blob index value in one stable fixed-width record,
      preserving malformed embedded key/value validation through the existing
      codecs. This is codec-only; durable index engines, lookup/write
      integration, parse-artifact payload validation, mmap reads, GC/repack,
      Attic transport, and harness proof remain open (`C-13`).
- [x] Current fixed-record file-artifact index file substrate:
      `PersistFileArtifactIndex` opens/creates the
      `nodes/file-artifacts.index` sidecar, appends fixed-width
      `PersistFileArtifactIndexEntry` records, rejects truncated record tails on
      open, and linearly scans records to return the newest file-artifact
      mapping value; `PersistCache::open` initializes/exposes it and
      `record_file_artifact`/`lookup_file_artifact` wrap explicit writes and
      lookups. This is a simple durable sidecar only; LMDB/redb MVCC tables,
      transactions, automatic materialization writes, parse-cache hit
      integration, mmap reads, cross-process writer coordination, GC/repack,
      Attic transport, and harness proof remain open (`C-13`/`R-10`).
- [x] Current `ratchet-cache` fixed-record artifact-index substrate:
      `artifact_index::ArtifactIndexKey`, `ArtifactIndexValue`,
      `ArtifactIndexEntry`, and `ArtifactIndex` provide the generic engine-band
      33-byte key plus 49-byte value record layout and
      append/newest/physical-scan/compact/replacement file operations for the
      current frontend artifact sidecars, including `nodes/file-artifacts.index`
      and `nodes/parse-artifacts.index`. The engine can also return every
      physical entry so typed adapters can validate stale records before
      applying newest-wins semantics. This is a fixed-record sidecar primitive
      only; LMDB/redb tables, writer batching, mmap reads, cross-process
      coordination, GC/repack integration, Attic transport, and full
      storage-engine harness proof remain open (`C-13`/`R-14`).
- [x] Current oracle file/parse artifact sidecar migration:
      `PersistFileArtifactIndex` and `PersistParseArtifactIndex` now wrap
      `ratchet-cache::artifact_index::ArtifactIndex` for open, append, physical
      scans, newest-entry scans, and compaction rewrites while routing every
      engine record back through the typed file/parse artifact codecs. Invalid
      namespace tags, malformed embedded blob-store values, and stale malformed
      records therefore still fail through the existing artifact index errors.
      Cross-crate compatibility tests prove both writer directions and invalid
      generic engine records. This is the append-only sidecar migration only;
      oracle still owns same-root locks, cache policy, blob payload validation,
      and parse/file materialization semantics, while LMDB/redb tables, writer
      batching, mmap reads, GC/repack engine migration, Attic transport, and
      cross-process coordination remain open (`C-13`/`R-14`).
- [x] Current parse-artifact bundle payload codec: `ParseArtifactBundle` frames
      the current `resolved.bin`/`ir.bin`/`symbols.bin`/`meta.toml` artifact
      bytes as one versioned little-endian payload, and
      `ParseCacheEntry::read_artifact_bundle` reads complete entries into that
      bundle. This is payload-format substrate only; automatic file-artifact
      materialization, automatic parse-cache integration, cache-hit selection,
      mmap reads, and harness proof remain open (`C-13`).
- [x] Current explicit parse-cache hit reader:
      `ParseCache::load_cached_bytes` computes the normal source-content key,
      returns `Ok(None)` for missing/incomplete entries, and decodes complete
      `resolved.bin`/`ir.bin`/`symbols.bin` artifacts into `CachedParse` without
      parsing. `load_or_parse_bytes` reuses this helper while preserving
      fallback-to-parse behavior for corrupt entries. This is explicit parse
      cache hit reading only; durable file-artifact lookup integration,
      automatic evaluator hit selection, mmap reads, and harness proof remain
      open (`C-13`).
- [x] Current parse metadata decoder substrate:
      `ParseCacheMeta::from_toml` and `ParseArtifactBundle::decode_meta` parse
      bundled `meta.toml` into typed schema/node/symbol counts plus the
      diagnostic source hint, rejecting malformed TOML, missing fields, wrong
      types, and out-of-range integers. This is metadata validation only;
      artifact semantic validation, keyed hydration enforcement, durable index
      lookup, cache-hit integration, and harness proof remain open (`C-13`).
- [x] Current metadata/count/resolved-artifact validated bundle hydration writer:
      `ParseCacheEntry::write_artifact_bundle_validated` uses
      `ParseArtifactBundle::validate_meta` to decode bundled metadata, check
      `schema_version`, decode the bundled `resolved.bin`/`symbols.bin`/
      `ir.bin` artifacts, and cross-check `symbol_count`/`node_count` before
      creating or overwriting entry files, then delegates successful writes to
      the existing metadata-last bundle writer. This is decoder-backed
      artifact-shape and count validation only; full artifact semantic
      validation beyond existing decoders, keyed hydration enforcement, durable
      index lookup, cache-hit integration, and harness proof remain open
      (`C-13`).
- [x] Current parse-artifact bundle hydration adapter:
      `ParseCacheEntry::write_artifact_bundle` writes a raw bundle back into an
      entry, clearing `meta.toml` before payload writes and committing metadata
      last so partial hydration is not treated as complete. This is explicit
      entry hydration only; durable index lookup, automatic file-artifact
      materialization, semantic validation before write, mmap reads, cache-hit
      integration, and harness proof remain open (`C-13`).
- [x] Current cache-level blob pack/index initialization substrate:
      `PersistCache::open` initializes and exposes separate value/file
      `PersistBlobPack` and `PersistBlobIndex` handles after schema validation
      and owned-directory setup, and reports corrupt non-empty packfiles or
      malformed fixed-record indexes instead of replacing them. Automatic index
      updates/lookups from cache append/read calls, node metadata, mmap reads,
      writer batching, GC/repack, Attic transport, and harness proof remain open
      (`C-13`/`R-14`).
- [x] Current key-routed blob IO substrate: `PersistCache::append_blob` and
      `read_blob` route a `PersistBlobKey` to the value or file pack, preserving
      namespace separation for identical payload hashes while reusing pack-level
      hash and record verification; `append_blob` holds the selected store's
      same-process same-root blob write lock before appending. Automatic
      durable index lookup/update from these raw helpers, node metadata, mmap
      reads, writer batching, GC/repack, Attic transport, and harness proof
      remain open (`C-13`/`R-14`).
- [x] Current explicit indexed blob IO helpers:
      `PersistCache::append_blob_indexed` appends through the key-routed pack
      while holding the selected store's same-process same-root blob-store write
      lock and records the returned location in the selected `PersistBlobIndex`,
      while `lookup_blob_location`/`read_blob_indexed` scan the sidecar index
      and read/verify the indexed pack record, returning `None` for misses.
      This is explicit non-transactional sidecar integration only; automatic
      low-level append/read indexing, node metadata linkage, mmap reads, writer
      batching, cross-process locking, GC/repack, Attic transport, and harness
      proof remain open (`C-13`/`R-14`).
- [x] Current explicit blob-pack tail-GC helper:
      `PersistCache::trim_blob_pack_tail` snapshots the selected store's latest
      live roots (`values/` blob index entries, or `files/`
      blob/file-artifact/parse-artifact index entries plus same-process pending
      file/parse artifact roots) while holding the selected store's
      same-process same-root blob lock plus the file/parse mapping locks for
      `files/` trims, verifies each referenced pack record, and truncates only
      unindexed bytes after the highest live record through
      `ratchet-cache::blob_pack::BlobPackAppender::trim_tail`, returning
      `PersistBlobPackTrim` byte/count stats. This is tail-only maintenance for
      unindexed trailing records; applied full-pack repack is covered by the
      explicit helpers below, while cross-process/raw-writer coordination,
      automatic GC policy, mmap reads, Attic transport, and harness proof
      remain open (`C-13`/`R-14`).
- [x] Current read-only blob-pack liveness plan:
      `PersistCache::plan_blob_pack_liveness` snapshots and verifies the same
      latest live roots used by tail trimming plus same-process pending
      file/parse artifact roots, scans the selected pack, and classifies
      verified physical records as rooted or sidecar-unrooted with byte counts
      for current tail-trim candidates. This is diagnostic planning only, not
      the final RFC GC root model: node metadata reachability is covered by the
      value reachability plan below, applied pack rewriting is covered by the
      explicit repack helpers below, and automatic GC policy,
      cross-process/raw-writer coordination, mmap reads, Attic transport, and
      harness proof remain open
      (`C-13`/`R-14`).
- [x] Current read-only blob-pack repack plan:
      `PersistCache::plan_blob_pack_repack` builds the selected store's
      liveness plan, preserves verified live records in current pack order,
      assigns their contiguous locations in a fresh compacted pack, and reports
      omitted unrooted records plus before/after byte counts. This is
      relocation planning only; applying `files/` plans with pending artifact
      roots, automatic GC policy, cross-process/raw-writer coordination, mmap
      reads, Attic transport, and harness proof remain open
      (`C-13`/`R-14`).
- [x] Current read-only node value-root plan:
      `PersistCache::plan_node_value_roots` snapshots latest node metadata,
      resolves materialized value hashes through the `values/` blob index, and
      verifies resolved value-pack records while reporting metadata links whose
      value hash is missing from the blob index. This is diagnostic
      node-to-value reachability only; retention windows, metadata pruning,
      pack rewriting/deletion, live-record relocation, automatic GC policy,
      cross-process/raw-writer coordination, mmap reads, Attic transport, and
      harness proof remain open (`C-13`/`R-14`).
- [x] Current read-only value-pack reachability plan:
      `PersistCache::plan_value_blob_reachability` snapshots latest node
      metadata and `values/` blob-index entries, verifies node-rooted records,
      scans the value pack, and classifies physical records as node-rooted,
      indexed-without-node-root, or absent from latest index roots while
      reporting missing node metadata links. This is diagnostic classification
      only; retention windows, metadata pruning, sidecar repair, pack
      rewriting/deletion, live-record relocation, automatic GC policy,
      cross-process/raw-writer coordination, mmap reads, Attic transport, and
      harness proof remain open (`C-13`/`R-14`).
- [x] Current read-only file-pack reachability plan:
      `PersistCache::plan_file_blob_reachability` snapshots latest
      file-artifact, parse-artifact, `files/` blob-index, and same-process
      pending artifact roots, verifies captured roots, scans the file pack, and
      classifies physical records as file-artifact-rooted,
      parse-artifact-rooted, pending-artifact-rooted, indexed-without-artifact,
      or absent from all captured roots. This is diagnostic classification
      only; retention windows, sidecar repair, pack rewriting/deletion,
      live-record relocation, automatic GC policy, cross-process/raw-writer
      coordination, mmap reads, Attic transport, and harness proof remain open
      (`C-13`/`R-14`).
- [x] Current `ratchet-cache` staged file-replacement primitive:
      `ratchet-cache::file_replace::FileReplacementSet` owns ordered staged
      file replacement with stale-backup removal, target-to-backup moves,
      staged-file installation, best-effort staged/backup cleanup, and backup
      restoration after ordinary filesystem failures. The value-pack repack
      swap now delegates to this primitive while preserving the existing
      `PersistValueBlobPackRepackError` pack/index surface. This is a swap
      choreography primitive only; file-pack four-sidecar swap migration,
      crash transactionality, durable filesystem locks/CAS, cross-process/raw
      writers, and automatic GC policy remain open (`C-13`/`R-14`).
- [x] Current explicit value-pack repack helper:
      `PersistCache::repack_value_blob_pack` holds the same-root `values/`
      store lock, plans live-record relocation, stages a compacted value pack
      plus replacement value blob-index sidecar, and swaps both into place via
      `ratchet-cache::file_replace::FileReplacementSet` with best-effort
      rollback for ordinary filesystem errors. It preserves latest indexed
      value roots and omits unrooted value records. This is
      caller-driven advisory maintenance only; crash transactionality, node
      metadata pruning, automatic GC policy, cross-process/raw-writer
      coordination, mmap reads, Attic transport, and harness proof remain open
      (`C-13`/`R-14`).
- [x] Current explicit file-pack repack helper:
      `PersistCache::repack_file_blob_pack` holds the same-root `files/` store,
      file-artifact, and parse-artifact locks, rejects same-process pending
      artifact roots, stages a compacted file pack plus relocated file blob,
      file-artifact, and parse-artifact sidecars, and swaps them into place
      with best-effort rollback for ordinary filesystem errors. This is
      caller-driven advisory maintenance only; crash transactionality,
      automatic GC policy, cross-process/raw-writer coordination, mmap reads,
      Attic transport, and harness proof remain open
      (`C-13`/`R-14`/`R-10`).
- [x] Current explicit all-blob-pack repack helper:
      `PersistCache::repack_blob_packs` runs value-pack repack and then
      file-pack repack, returning both applied plans and total reclaimed blob
      bytes. It is sequential and non-transactional: a committed value-pack
      rewrite can remain if a later file-pack repack fails. It does not compact
      unrelated sidecars, rebuild blob indexes from physical pack scans before
      planning, coordinate with cross-process/raw writers, or apply automatic
      GC policy (`C-13`/`R-14`).
- [x] Current blob-pack integrity scan primitive:
      `PersistBlobPack::records` scans a pack in record order, validates every
      record header and payload hash, rejects truncated or corrupt tails instead
      of returning partial metadata, and returns `PersistBlobPackRecord`
      hash/location entries for maintenance callers. This is read-only buffered
      scan metadata only; live-root selection, repack/relocation writing,
      concurrent writer coordination, automatic GC policy, mmap reads, Attic
      transport, and harness proof remain open (`C-13`/`R-14`).
- [x] Current store-typed blob-pack index-entry scan adapter:
      `PersistCache::blob_pack_index_entries` routes a verified pack scan
      through the selected `values/` or `files/` store and maps every physical
      record, including stale duplicates and unindexed tails, to the matching
      `PersistBlobIndexEntry` key/location shape without writing the sidecar.
      This is read-only repair/repack input only; index rebuild, live-root
      selection, repack/relocation writing, concurrent writer coordination,
      automatic GC policy, mmap reads, Attic transport, and harness proof remain
      open (`C-13`/`R-14`).
- [x] Current newest physical blob-pack index-entry scan adapter:
      `PersistCache::latest_blob_pack_index_entries` collapses the verified
      physical pack scan to newest-record-wins `PersistBlobIndexEntry`
      candidates per content hash in stable encoded-key order, matching sidecar
      latest-entry encoded-key ordering while still including unindexed physical
      records. This is read-only index-rebuild input only; index rewrite,
      live-root selection, repack/relocation writing, concurrent writer
      coordination, automatic GC policy, mmap reads, Attic transport, and
      harness proof remain open (`C-13`/`R-14`).
- [x] Current read-only blob-index rebuild plan:
      `PersistCache::plan_blob_index_rebuild` compares the selected sidecar's
      newest lookup entries with the verified newest physical records in the
      matching blob pack, returning the exact entries a future rebuild would
      write plus missing, stale, and dangling lookup differences. Older
      append-only sidecar history is ignored once newest lookups match, and
      corrupt packs fail the plan rather than producing partial repair
      metadata. This is diagnostic rebuild input only; index rewrite, physical
      sidecar canonicalization, live-root selection, pack trimming,
      repack/relocation writing, concurrent writer coordination, automatic GC
      policy, mmap reads, Attic transport, and harness proof remain open
      (`C-13`/`R-14`).
- [x] Current explicit blob-index rebuild helper:
      `PersistCache::rebuild_blob_index_from_pack` builds the verified rebuild
      plan for one store while holding that store's same-process same-root
      blob-index write lock, then replaces only that store's hash-to-offset
      sidecar with the plan's newest physical pack entries, indexing previously
      unindexed newest records, repairing stale locations, dropping dangling
      entries, and canonicalizing duplicate sidecar history. This is
      caller-driven single-sidecar repair only; live-root selection, blob-pack
      trimming, full repack/relocation, cross-process/raw-writer coordination,
      automatic GC/repair policy, mmap reads, Attic transport, and harness
      proof remain open (`C-13`/`R-14`).
- [x] Current explicit all-blob-index rebuild helper:
      `PersistCache::rebuild_blob_indexes_from_packs` rebuilds the `values/`
      and then `files/` hash-to-offset sidecars from verified pack scans and
      returns both applied plans, sharing each selected store's same-process
      same-root blob-index write lock for its rebuild step. This is sequential
      and non-transactional: a committed value-index rebuild remains in place
      if the later file-index rebuild fails. It does not rebuild file-artifact,
      parse-artifact, or node sidecars, select live roots, trim or repack blobs,
      coordinate cross-process/raw writers, or implement automatic repair/GC
      policy; mmap reads, Attic transport, and harness proof remain open
      (`C-13`/`R-14`).
- [x] Current idempotent indexed blob materialization substrate:
      `PersistCache::ensure_blob_indexed` reuses an existing sidecar location
      only after the pointed pack record verifies for the requested
      `PersistBlobKey` and payload bytes, appending a fresh record and newer
      index entry for missing or stale locations, including stale pointers to
      another valid pack record; indexed value payload, file-artifact, and
      parse-artifact materializers use this path so duplicate materialization
      does not grow `values/` or `files/` packs. This is same-process duplicate
      suppression only; cross-process locking/CAS, automatic compaction,
      GC/repack, mmap reads, LMDB/redb indexes, and harness proof remain open
      (`C-13`/`R-14`).
- [x] Current clone-local indexed materialization single-flight precursor:
      cloned `PersistCache` handles now share per-store in-process mutexes
      around the `ensure_blob_indexed` lookup/read/append/index critical
      section, so simultaneous same-key materialization through clones of one
      opened cache collapses the initially-missing case to one fresh verified
      pack record and newest sidecar entry for the selected `values/` or
      `files/` store. This does not compact older append-only sidecar history
      for stale or previously duplicated entries. Multi-process writers,
      durable filesystem locks/CAS, automatic compaction, GC/repack, mmap
      reads, LMDB/redb indexes, and loom/harness proof remain open
      (`C-13`/`R-4`/`R-14`).
- [x] Current same-process same-root indexed materialization single-flight
      precursor: independently opened `PersistCache` handles in one process now
      store canonicalized layout paths and acquire their per-store blob
      materialization mutexes from a process-local weak registry keyed by the
      canonical persistent cache root, so simultaneous same-key materialization
      through separate opens of the same root shares the same
      `ensure_blob_indexed` critical section. The initially-missing case
      collapses to one fresh verified pack record and newest sidecar entry for
      the selected store, public `append_blob` and `append_blob_indexed` use the
      same lock for cache-level non-idempotent appends, a poisoned same-root
      lock is reported before any cache-level raw append or indexed
      append/index write, and an opened symlink-root handle keeps writing the
      canonical target it opened even if the symlink is retargeted.
      Different roots, multi-process writers, two-machine misses, durable
      filesystem locks/CAS, automatic compaction, GC/repack, mmap reads,
      LMDB/redb indexes, and loom/harness proof remain open
      (`C-13`/`R-4`/`R-14`).
- [x] Current same-process same-root blob-store maintenance lock precursor:
      cache-level blob-index compaction, blob-index rebuild, blob-pack tail
      trim, and value/file blob-pack repack share the same per-store root-lock
      registry entries as indexed materialization, so maintenance rewrites for
      one live canonical cache root serialize with cache-level indexed or raw
      blob writes for the selected `values/` or `files/` store. File-pack tail
      trim and file-pack repack also share the file-artifact and parse-artifact
      mapping locks while they snapshot or relocate those live roots. Poisoned
      live same-root locks are reported before compaction, rebuild, trim, or
      repack writes sidecars, truncates, or replaces a pack. Raw lower-level
      `PersistBlobIndex`/`PersistBlobPack` users, different roots,
      multi-process writers, two-machine races, durable filesystem locks/CAS,
      LMDB/redb indexes, automatic GC policy, and loom/harness proof remain
      open (`C-13`/`R-4`/`R-14`).
- [x] Current same-process same-root open-initialization lock precursor:
      `PersistCache::open` now creates the caller-supplied root, canonicalizes
      it, acquires a process-local same-root open mutex from the shared weak
      root-lock registry, and only then performs schema validation/rewrites plus
      pack/index initialization through the canonical layout. If a panic
      poisons a live same-root open lock while another cache handle or waiter
      keeps that root's lock object alive, later same-root opens report the
      poison before touching schema or sidecars; first-open/no-survivor sticky
      poison remains intentionally outside the weak-registry guarantee. This is
      same-process initialization serialization only; raw lower-level sidecar
      helpers, different roots, multi-process writers, two-machine misses,
      durable filesystem locks/CAS, automatic repair/GC policy, LMDB/redb
      transactions, and loom/harness proof remain open (`C-13`/`R-4`/`R-14`).
- [x] Current same-process same-root node-metadata writer lock precursor:
      independently opened `PersistCache` handles in one process acquire their
      node-metadata write mutex from the same process-local weak root-lock
      registry, so raw metadata appends, typed reuse/value-hash
      read-modify-appends, current-demand increments, run-boundary advancement,
      and metadata compaction serialize for a live canonical cache root.
      Concurrent same-root demand records keep every current-run increment, and
      a poisoned live metadata lock is reported before any sidecar write. Raw
      lower-level `PersistNodeMetadataIndex` users, different roots,
      multi-process writers, two-machine races, durable filesystem locks/CAS,
      LMDB/redb node tables, automatic GC/repack, and loom/harness proof remain
      open (`C-13`/`R-4`/`S-14`).
- [x] Current same-process same-root node-trace writer lock precursor:
      independently opened `PersistCache` handles in one process acquire their
      node-trace write mutex from the same process-local weak root-lock
      registry, so trace appends and trace-log compaction serialize for a live
      canonical cache root. Concurrent same-root trace appends keep every
      complete record readable, and a poisoned live trace lock is reported
      before any log write. Raw lower-level `PersistNodeTraceLog` users,
      different roots, multi-process writers, two-machine races, durable
      filesystem locks/CAS, LMDB/redb node tables, transactionality with
      metadata/value blobs, automatic GC/repack, and loom/harness proof remain
      open (`C-13`/`R-4`/`S-14`).
- [x] Current same-process same-root artifact-mapping writer lock precursor:
      independently opened `PersistCache` handles in one process acquire
      file-artifact and parse-artifact mapping write mutexes from the same
      process-local weak root-lock registry, so cache-level mapping appends and
      mapping compaction serialize for a live canonical cache root. Concurrent
      same-root appends keep every complete mapping record readable, and
      poisoned live mapping locks are reported before any sidecar write. Raw
      lower-level `PersistFileArtifactIndex`/`PersistParseArtifactIndex` users,
      different roots, multi-process writers, two-machine races, durable
      filesystem locks/CAS, LMDB/redb indexes, automatic GC/repack, and
      loom/harness proof remain open (`C-13`/`R-4`/`R-10`).
- [x] Current explicit fixed-record sidecar compaction substrate:
      `PersistBlobIndex`, `PersistFileArtifactIndex`, and
      `PersistParseArtifactIndex` now expose `latest_entries` and
      `compact_latest_entries`, scanning append-only fixed-record indexes into
      deterministic newest-entry-per-key order and rewriting through a
      truncated temporary file plus rename. `PersistCache::compact_blob_index`,
      `compact_file_artifact_index`, and `compact_parse_artifact_index` expose
      those operations through the opened cache root. Blob-index compaction
      keeps the repaired newest same-key pointer after stale indexed
      materialization repair while leaving old pack bytes untouched and shares
      same-process same-root store locks; file/parse artifact compaction shares
      same-process same-root mapping locks. This is caller-driven maintenance
      only; automatic compaction/GC policy, cross-process/raw-writer
      coordination, LMDB/redb indexes, pack GC/repack, mmap reads, Attic
      transport, and harness proof remain open
      (`C-13`/`R-14`).
- [ ] Full P2 persistence remains: custom mmap packfile for immutable
      `values`/`files`, LMDB/redb mutable `nodes` metadata and indexes,
      serialized node/value/file records, Attic transport, GC/repack, and
      cached/uncached harness proof (`C-13`/`R-14`); transport stays **beside**
      `NixEval`, on the Attic content-addressed path (`C-3`).
- [x] Current materialization-threshold policy substrate: `cache::policy`
      defines caller-supplied `MaterializationCosts` and
      `MaterializationSignals`, computes `write_cost = hash + serialize + IO`
      with saturation, and returns `Materialize` only when
      `eval_cost > write_cost` and the caller-supplied reuse signal predicts
      cross-run reuse. This is a pure threshold decision only; persistent
      reuse-metadata bridges and deterministic evaluator cost observations are
      covered below, while RAM-tier promotion, automatic value writes outside
      the current force-cache bridge, GC/repack, and AOS tuning remain open
      (`C-14`).
- [x] Current materialization reuse-counter signal substrate:
      `MaterializationReuse` carries prior-run and current-run demand counters,
      saturates current-run increments, and converts prior-run demand into the
      existing `MaterializationSignals` cross-run reuse bit. This is policy
      vocabulary only; persistent storage and force-cache demand accounting are
      covered by later rows, while cost measurement, packfile writes, and AOS
      tuning remain open (`C-14`).
- [x] Current materialization reuse run-boundary substrate:
      `MaterializationReuse::advance_run` carries current-run demand into
      prior-run history with saturation and clears current-run observations, so
      same-run demand only becomes a cross-run reuse signal for later runs. This
      is policy vocabulary only; persistent sidecar adapters are covered by
      later rows, while automatic process-boundary update, cost measurement,
      packfile writes, and AOS tuning remain open (`C-14`).
- [x] Current materialization reuse metadata codec:
      `MaterializationReuse::encode_persist_metadata`/`decode_persist_metadata`
      define a stable 16-byte little-endian payload for previous-run and
      current-run demand counters, with short-prefix validation through
      `PersistPackFormatError`. This is codec-only; node metadata index,
      force-cache demand accounting, automatic process-boundary update, cost
      measurement, and AOS tuning remain open (`C-14`).
- [x] Current demand-node metadata codec substrate:
      `PersistNodeMetadataKey` derives stable persistent BLAKE3 keys for
      expression nodes from `CacheExprIdentity` plus ordered free-variable value
      hashes, and for impure-input leaves from their typed input identity hash,
      in domains separate from hot `DemandCacheKey`; `PersistNodeMetadataIndexValue`
      wraps materialization reuse counters plus an optional materialized
      cached-expression `ValueHash` with canonical absent/present encoding, and
      `PersistNodeMetadataIndexEntry` frames key/value records. This is
      codec-only; fixed-record index storage, force-cache demand accounting,
      and cache-level node-value link helpers are covered by following rows,
      while LMDB/redb node tables, process-boundary updates, and AOS tuning
      remain open (`C-13`/`C-14`/`S-14`).
- [x] Current demand-node metadata index substrate:
      `PersistLayout::node_metadata_index_path` adds `nodes/metadata.index`,
      `PersistNodeMetadataIndex` appends fixed-width metadata records and
      resolves lookups with newest-record-wins semantics, and
      `PersistCache::record_node_metadata`/`lookup_node_metadata` expose the
      sidecar through the opened persistent cache root. This is a simple
      fixed-record sidecar only; typed counter update helpers and force-cache
      demand accounting are covered by following rows, while LMDB/redb node
      tables, process-boundary updates, mmap reads, GC/repack, and AOS tuning
      remain open (`C-13`/`C-14`/`S-14`).
- [x] Current `ratchet-cache` fixed-record node-metadata substrate:
      `node_metadata::NodeMetadataKey`, `NodeMetadataValue`,
      `NodeMetadataEntry`, and `NodeMetadataIndex` provide the generic
      engine-band record layout and append/newest/compact/replacement file
      operations for the current `nodes/metadata.index` sidecar without
      interpreting oracle-specific metadata semantics. The engine can also
      return every physical entry so typed adapters can validate stale records
      before applying newest-wins semantics. This is a fixed-record sidecar
      primitive only; LMDB/redb tables, writer batching, mmap reads,
      cross-process coordination, and full storage-engine harness proof remain
      open (`C-13`/`R-14`).
- [x] Current oracle node-metadata sidecar migration:
      `PersistNodeMetadataIndex` now wraps
      `ratchet-cache::node_metadata::NodeMetadataIndex` for open, append,
      physical scans, newest-entry scans, and compaction rewrites while routing
      every engine record back through the oracle key/value codecs. Invalid
      namespace tags, malformed optional value-hash fields, and stale malformed
      records therefore still fail through `PersistNodeMetadataIndexError`.
      Cross-crate compatibility tests prove both writer directions and invalid
      generic engine records. This is the append-only sidecar migration only;
      oracle still owns same-root locks, node-trace/value transactionality, and
      cache policy, while LMDB/redb tables, writer batching, mmap reads, GC
      policy, and cross-process coordination remain open (`C-13`/`R-14`).
- [x] Current `ratchet-cache` variable-length node-trace log substrate:
      `node_trace_log::NodeTraceLogKey`, `NodeTraceLogValueHash`,
      `NodeTraceLogEntry`, and `NodeTraceLog` provide the generic engine-band
      record layout and append/newest/physical-scan/compact/replacement file
      operations for the current `nodes/traces.log` sidecar without
      interpreting oracle-specific trace payload semantics. The engine keeps
      payloads opaque, rejects truncated record headers and payloads, and
      returns newest entries in stable key order. This is an engine-side
      sidecar primitive now consumed by oracle trace storage; LMDB/redb tables,
      writer batching, mmap reads, node-metadata/value transactionality,
      cross-process coordination, and full storage-engine harness proof remain
      open (`C-13`/`R-14`).
- [x] Current oracle node-trace log migration:
      `PersistNodeTraceLog` now wraps
      `ratchet-cache::node_trace_log::NodeTraceLog` for open, append, physical
      scans, newest-entry scans, and compaction rewrites while routing every
      engine record back through the oracle key and payload codecs. Invalid
      namespace tags, malformed payload bytes, and stale malformed records
      therefore still fail through `PersistNodeTraceLogError`. Cross-crate
      compatibility tests prove both writer directions and invalid generic
      engine records. This is the append-only sidecar migration only; oracle
      still owns same-root locks, node-metadata/value transactionality, and
      cache policy, while LMDB/redb tables, writer batching, mmap reads, GC
      policy, and cross-process coordination remain open (`C-13`/`R-14`).
- [x] Current explicit node reuse counter update adapter:
      `PersistCache::record_node_materialization_reuse` and
      `lookup_node_materialization_reuse` expose typed materialization reuse
      counters over the raw metadata index, and
      `record_node_current_demand` reads the newest counters, starts from empty
      counters on a miss, appends a saturated current-demand increment, and
      returns the recorded value. Reuse updates preserve any existing
      materialized cached-expression value-hash link in the same metadata
      record, and same-process same-root writers share the metadata write lock
      for the read-modify-append critical section. This is caller-driven and
      append-only; evaluator call-site integration is covered by the
      force-cache accounting and public run-boundary rows below, while
      cross-process writer coordination, LMDB/redb node tables, compaction/GC,
      and AOS tuning remain open (`C-13`/`C-14`/`S-14`).
- [x] Current explicit node reuse run-boundary adapter:
      `PersistCache::advance_node_materialization_reuse_run` looks up the
      newest counters for one node key, returns `None` without writing on a
      miss, and otherwise appends `MaterializationReuse::advance_run` so
      current-run observations become prior-run reuse signal for later runs
      while preserving any materialized value-hash link. This is caller-driven
      and append-only, with same-process same-root writers serialized by the
      metadata write lock; Drop/panic/error-path process-boundary orchestration,
      cross-process writer coordination, LMDB/redb node tables, compaction/GC,
      and AOS tuning remain open (`C-13`/`C-14`/`S-14`).
- [x] Current explicit node reuse sidecar advancement:
      `PersistNodeMetadataIndex::latest_entries` scans the fixed-record
      metadata sidecar into deterministic newest-entry-per-key order, and
      `PersistCache::advance_all_node_materialization_reuse_runs` appends
      changed `MaterializationReuse::advance_run` records for all known node
      keys while preserving materialized value-hash links and skipping no-op
      counters. This is caller-driven and append-only, with same-process
      same-root writers serialized by the metadata write lock;
      Drop/panic/error-path process-boundary orchestration, cross-process
      writer coordination, LMDB/redb node tables, automatic compaction/GC
      policy, and AOS tuning remain open
      (`C-13`/`C-14`/`S-14`).
- [x] Current public evaluator reuse run-boundary advancement:
      successful public tree-walk free-function evaluation exits (`eval_whnf*`,
      `eval_instantiation_attr_path*`, `eval_raw_bytes*`, and
      `eval_number_raw_bytes_with_options`) call
      `advance_all_node_materialization_reuse_runs` when eval-cache
      observation is enabled and the evaluator already opened the persistent
      cache root. This advances current-run force-cache demand into prior-run
      materialization history without creating a persistent cache for
      evaluations that never touched it. This is public free-function
      entry-point orchestration only; low-level `TreeWalk::eval_root`/`eval_node`
      advancement, Drop/panic/error-path advancement, cross-process writer
      locking, LMDB/redb node tables, automatic compaction/GC policy, and AOS
      tuning remain open (`C-13`/`C-14`/`S-14`).
- [x] Current explicit node metadata sidecar compaction:
      `PersistNodeMetadataIndex::compact_latest_entries` rewrites
      `nodes/metadata.index` through a temporary file and rename so only the
      newest record for each node metadata key remains in stable key order,
      including any materialized value-hash link, and
      `PersistCache::compact_node_metadata` exposes that operation through the
      opened cache root. This is caller-driven, with same-process same-root
      writers serialized by the metadata write lock; automatic
      process-boundary orchestration, cross-process writer coordination,
      LMDB/redb node tables, automatic compaction/GC policy, and AOS tuning
      remain open (`C-13`/`C-14`/`S-14`).
- [x] Current force-cache persistent demand accounting:
      tree-walk `force_value` derives `PersistNodeMetadataKey` from the same
      lookup-safe `ForceCacheSubject` identity and ordered free-variable hashes
      used by the in-memory force-cache key, lazily opens the configured
      persistent cache root when `eval_cache_enabled` is on, and best-effort
      appends `record_node_current_demand` for successful cold forces and
      in-memory force-cache hits. Observation-only uncacheable subjects such as
      `currentTime` have no metadata identity and are not counted. This is
      current-run demand accounting only; public successful run-boundary
      advancement is covered above, while Drop/panic/error-path advancement,
      cross-process writer coordination, durable cached-payload hit selection,
      LMDB/redb node tables, automatic compaction/GC policy, and AOS tuning
      remain open (`C-13`/`C-14`/`S-14`).
- [x] Current node-reuse materialization decision adapter:
      `PersistCache::node_materialization_signals` and
      `node_materialization_decision` read the newest persisted
      `MaterializationReuse` counters for a demand-node key, treat misses as
      empty counters, combine prior-run reuse with caller-supplied
      `MaterializationCosts`, and return the same `MaterializationDecision`
      accepted by the existing blob/file/parse materializers. Current-run-only
      demand does not predict cross-run reuse until an explicit run-boundary
      advance has moved it into prior history. This is decision plumbing only;
      public successful run-boundary advancement and threshold-driven evaluator
      writeback are covered by separate rows, while Drop/panic/error-path
      advancement, cost measurement, LMDB/redb node tables, automatic
      compaction/GC policy, and AOS tuning remain open (`C-13`/`C-14`).
- [x] Current explicit materialization-to-pack adapter:
      `PersistCache::materialize_blob` consumes a caller-supplied
      `MaterializationDecision`, skips without hashing/writing on
      `KeepInMemory`, and appends through the key-routed blob pack on
      `Materialize`. Cost measurement, reuse metadata, evaluator value
      serialization, automatic durable index updates, mmap reads, GC/repack, and
      AOS tuning remain open (`C-14`).
- [x] Current materialized blob index-entry accessor:
      `PersistMaterialization::index_entry` returns the complete
      `PersistBlobIndexEntry` only when a blob was materialized, binding the
      caller-supplied blob key and pack location the future durable index would
      store. This is accessor-only; durable index writes/reads, evaluator value
      serialization, lookup paths, mmap reads, GC/repack, and AOS tuning remain
      open (`C-13`/`C-14`).
- [x] Current threshold-to-pack signal adapter:
      `PersistCache::materialize_blob_with_signals` evaluates caller-supplied
      `MaterializationSignals` at the persistence boundary, preserves the
      skip-without-hash/write behavior when the threshold fails, and delegates
      passing signals to the key-routed blob pack append path. This is
      adapter-only; cost measurement, reuse metadata production, evaluator
      value serialization, automatic durable index updates, mmap reads,
      GC/repack, and AOS tuning remain open (`C-14`).
- [x] Current explicit indexed materialization adapters:
      `PersistCache::materialize_blob_indexed` and
      `materialize_blob_indexed_with_signals` preserve skip-without-hash/write
      behavior, and on `Materialize` ensure the blob is present through
      `ensure_blob_indexed`, reusing verified sidecar locations or
      appending/indexing fresh records as needed. This is
      explicit non-transactional indexed materialization only; cost measurement,
      reuse metadata production, typed evaluator payload handling, automatic raw
      materialization indexing, mmap reads, GC/repack, and AOS tuning remain
      open (`C-13`/`C-14`).
- [x] Current cached-expression value payload persistence adapter:
      `CachedExpressionValue::encode_persistent_payload` and
      `decode_persistent_payload` round-trip the current replayable force-cache
      payload set (inline scalars, context-free strings, context-bearing
      strings, path payloads with or without context, replayable lists, and
      replayable attrsets including source-order-tagged, position-bearing, and
      source-provenanced position-bearing attrsets) as the canonical BLAKE3 preimage used by
      `ValueHash`, so hashing the encoded bytes yields the payload's durable
      value-hash digest. `CachedExpressionValue::persistent_payload_len`
      reports the exact canonical byte length, including source-provenance
      envelopes, without allocating the encoded bytes. The decoder rejects
      malformed and non-canonical string-context payloads, malformed/truncated
      nested list element payloads, malformed attr-position tags,
      source-provenance envelopes without retained positions, positionless
      positioned-attrset tags, and
      malformed/non-canonical attrset binding payloads including duplicate source-order binding names. `PersistCache::materialize_cached_expression_value_indexed`,
      `materialize_cached_expression_value_indexed_with_signals`, and
      `load_cached_expression_value_indexed` write and read those payloads
      through the indexed `values/` pack by value hash, and loads rehash the
      decoded payload before returning it while preserving
      skip-without-hash/encode/write behavior when the materialization threshold
      fails. This is an explicit cache-level payload bridge only; evaluator
      durable hit selection, lazy-element list or lazy-binding attrset values, mmap
      reads, full AOS cost calibration, GC/repack, and cached/uncached harness proof
      remain open (`C-13`/`C-14`/`S-14`).
- [x] Current cached-expression node-value metadata linkage adapter:
      `PersistCache::record_node_materialized_value_hash`,
      `clear_node_materialized_value_hash`, and
      `lookup_node_materialized_value_hash` preserve materialization reuse
      counters while linking or unlinking a demand-node metadata key from the
      newest materialized cached-expression `ValueHash`;
      `materialize_cached_expression_node_value_indexed`,
      `materialize_cached_expression_node_value_indexed_with_signals`, and
      `load_cached_expression_node_value_indexed` combine that link with the
      indexed `values/` payload helpers. Skips do not hash, encode, write, or
      record metadata, and node-key loads return `None` for missing metadata,
      reuse-only metadata, cleared metadata, or missing value blobs. This is
      explicit cache-level linkage only; evaluator durable hit selection,
      node/value transactionality, lazy-element list or lazy-binding attrset values, mmap
      reads, cost measurement, GC/repack, and cached/uncached harness proof
      remain open (`C-13`/`C-14`/`S-14`).
- [x] Current threshold-driven force-cache persistent value writeback:
      tree-walk `force_value` now materializes replayable forced-expression
      payloads through `PersistCache::node_materialization_signals` and
      `materialize_cached_expression_node_value_indexed_with_signals` after the
      in-memory force-cache observation accepts a node payload. The evaluator
      supplies unit costs from
      `TreeWalkOptions::force_cache_materialization_costs`; persisted prior-run
      demand supplies the cross-run reuse bit, so cold same-run demand records
      metadata but skips durable value and trace writes until a
      run-boundary advance makes that demand prior history. Pure complete
      observations materialize only after successful expression-node
      reconsideration and a positive threshold decision; impure observations do
      the same only when the trace is cacheable and returns an expression node.
      Rejected impure observations and unsupported recomputed payloads clear any
      existing durable node-value link after the in-memory force-cache has
      rejected the observation or had an opportunity to invalidate any runtime
      payload; observation-only uncacheable subjects such as `currentTime` can
      clear a stale durable record through their observation identity without
      using that identity for demand, hit selection, or writeback, and missing
      durable records remain a no-op. The writeback lazily opens the configured persistent cache root,
      skips disabled runtimes, unavailable persistent roots, negative threshold
      decisions, and advisory write errors. This is threshold-driven force
      payload writeback/clear only; evaluator-wide durable hit selection,
      full AOS cost calibration, lazy-element list or lazy-binding attrset values, mmap
      reads, GC/repack, and cached/uncached harness proof
      remain open. The gate covers force-cache persistent-demand/value
      writeback, threshold skip/materialize, stale-clear, and observation-only
      currentTime stale-durable tombstone tests (`C-13`/`C-14`/`S-14`).
- [x] Current deterministic force-cache materialization cost observations:
      `MaterializationCostObservation` converts observed evaluator work units
      and canonical persistent payload byte lengths into `MaterializationCosts`
      by scaling caller-supplied unit costs. Payload bytes are rounded to KiB
      cost units with a one-unit floor, and zero observed force work also uses a
      one-unit floor for manual observations. `CachedExpressionValue::persistent_payload_len`
      supplies the measured write-floor bytes without hashing or allocating the
      encoded payload. Tree-walk cold thunk forces and cacheable first-class
      impure primop calls pass the observed `thunks_forced` delta into
      persistent writeback; observations with non-empty impure traces also use
      the payload KiB units as a deterministic eval-work floor for non-thunk
      I/O work. Large replayable
      payload canaries prove that one-work-unit manual observations stay
      RAM-only when measured write cost dominates, that higher observed work
      crosses the same threshold, and that a production large `readFile` with
      prior demand durably materializes its value and verifying trace. This is
      deterministic in-evaluator cost collection only; wall-clock sampling, AOS
      trace calibration, RAM-tier promotion, mmap reads, GC/repack, and
      cached/uncached harness proof remain open (`C-14`).
- [x] Current node verifying-trace payload codec:
      `PersistNodeTracePayload` frames complete cacheable impure-input traces
      as versioned little-endian bytes with a magic header, typed input
      kind/mode tags including binary-safe `hashFile`, raw identity subjects,
      and observed-result hashes, plus a schema-version-5 tombstone marker for
      explicitly invalidating older trace records.
      `CacheableInputFingerprint::from_observation_hash` reconstructs the
      persisted fingerprints without re-reading the host. The standalone
      payload decoder preserves trace order, accepts version-1 trace
      payload bytes for direct decoding, rejects version-1 tombstone sentinels,
      rejects uncacheable `currentTime`, impossible kind/mode pairs, malformed
      tags, truncated payloads, and trailing bytes, and exposes stable payload
      constants for node-trace sidecars. This is payload-format compatibility
      only, not a non-destructive schema-4 cache-root migration. This is
      payload-format substrate only; cache-level sidecar storage is covered
      below, while evaluator durable hit selection, revalidation, currentTime
      taint propagation through persisted dependents, mmap reads, GC/repack,
      and cached/uncached harness proof remain open
      (`C-13`/`R-10`/`S-14`).
- [x] Current value-associated node verifying-trace sidecar substrate:
      `PersistLayout::node_trace_log_path` adds `nodes/traces.log`;
      `PersistNodeTraceLog` appends variable-length records keyed by
      `PersistNodeMetadataKey` and carrying the materialized `ValueHash` plus
      `PersistNodeTracePayload`, validates existing log records on open, and
      returns the newest record for a node key through linear lookup.
      `PersistCache::record_node_trace`, `record_node_trace_tombstone`, and
      `lookup_node_trace` expose the sidecar through the opened cache root.
      Same-process same-root cache-level appends share the trace write lock.
      This schema-version-5 log is a simple append-only substrate only;
      LMDB/redb node tables, transactionality with node metadata or value
      blobs, automatic evaluator writeback beyond the force-cache bridge below,
      durable hit selection, revalidation, currentTime taint propagation through
      persisted dependents, cross-process writer coordination, automatic
      compaction/GC policy, mmap reads, and cached/uncached harness proof remain open
      (`C-13`/`R-10`/`S-14`).
- [x] Current explicit node trace-log compaction substrate:
      `PersistNodeTraceLog::latest_entries` scans the append-only
      `nodes/traces.log` into the newest trace entry per node key, preserving
      tombstones when they are newest; `compact_latest_entries` rewrites those
      newest entries in stable key order through a temporary log and rename;
      and `PersistCache::compact_node_traces` exposes the operation at cache
      level. This is an explicit caller-driven maintenance primitive with
      same-process same-root writers serialized by the trace write lock;
      automatic compaction/GC policy, LMDB/redb node table, transactionality
      with metadata/value blobs, cross-process writer coordination, mmap reads,
      and cached/uncached harness proof remain open (`C-13`/`R-10`/`S-14`).
- [x] Current explicit all-sidecar compaction adapter:
      `PersistCache::compact_sidecars` runs the current value/file blob-index,
      file-artifact, parse-artifact, node-metadata, and node-trace compaction
      primitives in a deterministic order and returns `PersistCompaction`
      counts for the newest entries retained by each sidecar, with
      `PersistCompactionError` preserving the failing sidecar type. This is a
      caller-driven maintenance helper only; it is sequential rather than
      transactional, requires callers to serialize cross-process and raw
      lower-level sidecar writes that bypass the current same-root locks, does
      not rewrite blob packs or drop unreferenced blobs, and still leaves
      automatic compaction/GC policy, cross-process writer coordination,
      LMDB/redb indexes, pack GC/repack, mmap reads, Attic transport, and
      cached/uncached harness proof open
      (`C-13`/`R-10`/`R-14`/`S-14`). The gate is the
      all-sidecar compaction cache test.
- [x] Current explicit storage maintenance sweep:
      `PersistCache::compact_storage` runs all current sidecar compaction,
      rebuilds value/file blob-index sidecars from verified pack scans, and
      then trims value/file blob-pack tails, returning
      `PersistStorageMaintenance` with sidecar counts, applied blob-index
      rebuild plans, and per-pack trim stats while
      `PersistStorageMaintenanceError` preserves the failing phase. Failure
      coverage pins the non-transactional boundaries: sidecar compaction
      remains committed when value-pack scan/rebuild fails, rebuilt blob
      indexes remain committed when a later file-artifact root verification
      fails during file-pack trimming, and previously unindexed physical tail
      records become indexed roots before trimming. This is sequential
      caller-driven maintenance only; automatic compaction/GC policy,
      transactionality across sidecar/rebuild/pack phases, cross-process/raw
      pack or sidecar writer coordination, LMDB/redb indexes, mmap reads,
      Attic transport, and cached/uncached harness proof remain open, and it
      does not run the explicit full-pack repack helpers
      (`C-13`/`R-10`/`R-14`/`S-14`). The gate is the storage maintenance cache
      tests.
- [x] Current explicit storage repack sweep:
      `PersistCache::repack_storage` compacts all current append-only
      sidecars, then runs `repack_blob_packs` against the current live roots,
      returning `PersistStorageRepack` with sidecar counts and applied
      value/file repack plans. Unlike `compact_storage`, it does not rebuild
      blob indexes from physical pack scans before planning, so unindexed pack
      records stay unrooted and can be omitted by the repack. Failure coverage
      pins the non-transactional boundaries where sidecar compaction remains
      committed if file-pack repack fails and value-pack repack may already be
      committed before that failure. This is sequential caller-driven
      maintenance only; automatic compaction/GC policy, transactionality across
      sidecar/repack phases, cross-process/raw pack or sidecar writer
      coordination, LMDB/redb indexes, mmap reads, Attic transport, and
      cached/uncached harness proof remain open
      (`C-13`/`R-10`/`R-14`/`S-14`). The gate is the storage repack cache tests.
- [x] Current force-cache persistent trace writeback:
      after tree-walk `force_value` gets an accepted forced-expression
      observation and successfully materializes its value payload, it appends a
      value-associated `PersistNodeTracePayload` through
      `PersistCache::record_node_trace` using the same expression metadata key
      that links the materialized payload plus the payload's `ValueHash`.
      Trace-write failure clears the just-linked durable value metadata so a
      value is not left live without a persisted trace; pure observations write
      a zero-input trace payload, while cacheable impure observations write
      their observed trace segment. Rejected or unsupported observations clear
      the durable value link and append a trace tombstone so older
      value-associated trace log records cannot become live again through a
      later same-hash relink. The sidecar is still non-transactional. This is
      trace writeback/tombstoning only; evaluator durable hit selection,
      revalidation, transactionality with value materialization, currentTime
      taint propagation through persisted dependents, automatic compaction/GC,
      mmap reads, and cached/uncached harness proof remain open
      (`C-13`/`R-10`/`S-14`).
- [x] Current value-associated trace revalidation load adapter:
      `PersistCache::load_cached_expression_node_value_with_trace_revalidation`
      reads the newest node metadata value link and newest trace record,
      returns a miss when either is missing, their `ValueHash` values differ,
      or the newest trace is a tombstone, revalidates each persisted cacheable
      impure input through caller-supplied `ImpureInputRevalidator`, and loads
      the indexed `values/` payload only after every fresh identity and
      observation hash still matches. This is cache-level durable-hit substrate
      only: no evaluator hit selection, in-memory demand-graph insertion, dirty
      propagation, transactionality with value materialization, currentTime
      taint propagation through persisted dependents, automatic compaction/GC,
      mmap reads, and cached/uncached harness proof remain open
      (`C-13`/`R-10`/`S-14`).
- [x] Current force-cache durable hit selection:
      tree-walk forced-expression lookup now tries the trace-verified
      persistent node-value load after an in-memory force-cache miss; pure
      values hit through the same path by using a zero-input trace record
      rather than trace absence. Selected saturated first-class cacheable
      impure calls share this path through a force-cache subject keyed by
      apply-node identity, builtin name, and argument value hashes: unary
      `import`, `pathExists`, `readDir`, `readFile`, `readFileType`, and
      `getEnv`, plus full-arity first-class `hashFile`. Hits
      rehydrate replayable payloads into the
      current evaluator heap, preserving source-order attrset metadata and
      root-or-own-module binding source positions when the durable payload carries those attrset
      tags, remapping single-module retained attr positions to the current body
      module only when the payload's source-provenance hash matches the current
      body module source, seed the caller-owned in-memory runtime with the
      payload and any revalidated input edges, record fresh revalidated impure
      inputs into the enclosing evaluation trace when present, record
      current-run persistent demand, and count the result as a cache hit.
      Missing/stale/tombstoned traces, value-hash mismatches, unavailable
      persistent roots, persistent read errors, stale impure observations,
      missing value blobs, unsupported payload rehydration, unprovenanced stale
      positioned payloads, and incompatible, multi-module, or non-own positioned
      payloads all fall back to ordinary forcing and clear stale
      durable payload links. This is replayable forced-expression hit selection only:
      no dirty propagation beyond revalidation miss fallback, partially applied
      `hashFile` payload caching, lazy-element list or lazy-binding attrset
      values, broader multi-module/non-own binding-position module-source
      remapping, transactionality with value materialization, currentTime taint
      propagation through persisted dependents, automatic compaction/GC, mmap
      reads, and cached/uncached harness proof remain open
      (`C-13`/`R-10`/`S-14`).
- [x] Current persistent force-value `.drv` surface parity canary:
      `persistent_force_cache_hit_preserves_drv_surfaces` evaluates the same
      derivation attr path with eval cache disabled, with configured persistent
      force-cache demand/writeback on the cold and materializing paths, and
      with a fresh-runtime persistent forced-value hit for a replayed
      `builtins.currentSystem` payload. It requires identical `.drv` paths and
      ATerm bytes across all runs and requires the final run to report a
      force-cache hit. It also scans those derivation surfaces for the
      persisted force-cache node/value/trace hashes in hex, raw bytes, and Nix
      base32. This samples the current replayable forced-value hit path inside
      a derivation input surface; full cached-vs-uncached closure parity, the
      full leak invariant, derivationStrict-node SHA-256 early cutoff, lazy
      replay payloads, mmap reads, GC/repack, and future value-memoization
      safety net remain open (`S-14`).
- [x] Current effectful persistent force-value `.drv` surface parity canary:
      `persistent_effectful_force_cache_hit_preserves_drv_surfaces` evaluates
      the same derivation attr path with eval cache disabled, with configured
      persistent force-cache demand/writeback on cold and materializing paths,
      and with a fresh-runtime trace-verified persistent forced-value hit for a
      replayed `builtins.pathExists ./marker` branch inside `args`. It requires
      identical `.drv` paths and ATerm bytes across all runs, requires the
      final run to report a force-cache hit and load the expected force-cache
      metadata key, requires the materializing run to persist the exact
      path-exists trace, and requires persistent-hit
      revalidation to replay the path-exists fingerprint into the enclosing
      impure-input trace. It also scans those derivation surfaces for the
      exercised path-exists trace identity/observation hashes plus persisted
      force-cache node/value/trace hashes in hex, raw bytes, and Nix base32.
      This samples the current effectful replayable forced-value hit path
      inside a derivation input surface; full cached-vs-uncached closure
      parity, the full leak invariant, derivationStrict-node SHA-256 early
      cutoff, lazy replay payloads, stale-input miss surfaces, mmap reads,
      GC/repack, and future value-memoization safety net remain open (`S-14`).
- [x] Current first-class `import` persistent force-value `.drv` surface canary:
      `persistent_first_class_import_force_cache_hit_and_stale_miss_preserve_drv_surfaces`
      evaluates a derivation attr path whose `args` depend on first-class
      `let b = builtins; in b.import ./imported.nix`, first through
      cache-disabled and materializing same-source runs, then through a
      fresh-runtime persistent hit, and finally after mutating the imported
      source. It requires same-source cached runs to match cache-disabled
      `.drv` path, ATerm bytes, and import fingerprint, requires the
      persistent-hit run to report a force-cache hit and load the expected
      force-cache metadata key, requires the changed-source persistent run to
      miss and recompute the changed import fingerprint, requires materializing
      and changed-source persistent runs to persist live trace records for the
      exact import traces under the same force-cache metadata key with
      different materialized value hashes, requires same-runtime and
      fresh-runtime post-recompute changed-source runs to hit without
      force-cache misses and requires the fresh-runtime run to load the changed
      force-cache metadata key, and requires the changed `.drv` path and ATerm
      bytes to match a cache-disabled changed-source surface while differing
      from the original surface. This samples first-class `import` durable hit
      selection and stale-input fallback inside one derivation input; dirty
      propagation beyond direct revalidation fallback, full cached-vs-uncached
      closure parity, the full leak invariant, derivationStrict-node SHA-256
      early cutoff, lazy replay payloads, mmap reads, GC/repack, and future
      value-memoization safety net remain open (`R-10`/`S-14`).
- [x] Current filesystem impure-leaf persistent force-value `.drv` surface
      parity canaries:
      `persistent_read_file_force_cache_hit_preserves_drv_surfaces`,
      `persistent_read_dir_force_cache_hit_preserves_drv_surfaces`, and
      `persistent_read_file_type_force_cache_hit_preserves_drv_surfaces`
      evaluate derivation attr paths with eval cache disabled, with configured
      persistent force-cache demand/writeback on cold and materializing paths,
      and with fresh-runtime trace-verified persistent forced-value hits for
      `builtins.readFile`, `builtins.readDir`, and `builtins.readFileType`
      values used inside derivation `args`. They require identical `.drv` paths
      and ATerm bytes across all runs, require final runs to report force-cache
      hits and load the expected force-cache metadata keys, require
      materializing runs to persist the exact filesystem traces, and require
      persistent-hit revalidation to replay the matching filesystem
      fingerprints into the enclosing impure-input trace. They also
      scan those derivation surfaces for the exercised trace
      identity/observation hashes plus persisted force-cache node/value/trace
      hashes in hex, raw bytes, and Nix base32. This samples the current
      replayable filesystem impure-leaf hit paths inside derivation input
      surfaces; it does not cover full cached-vs-uncached closure parity, the
      full leak invariant, derivationStrict-node SHA-256 early cutoff,
      stale-input miss surfaces beyond the canaries below, lazy replay payloads,
      mmap reads, GC/repack, or future value-memoization safety net
      (`R-10`/`S-14`).
- [x] Current stale filesystem impure-leaf persistent force-value `.drv`
      surface canaries:
      `persistent_read_file_force_cache_stale_miss_preserves_drv_surfaces`,
      `persistent_read_dir_force_cache_stale_miss_preserves_drv_surfaces`, and
      `persistent_read_file_type_force_cache_stale_miss_preserves_drv_surfaces`
      materialize trace-verified `builtins.readFile ./input.txt`,
      `builtins.readDir ./dir`, and `builtins.readFileType ./target`
      forced-value payloads inside derivation `args`, mutate the backing
      filesystem input, then evaluate through the same persistent cache root.
      They require stale persistent observations not to reuse old filesystem
      payloads, require baseline materialization to persist the exact
      filesystem traces, require recomputation to replay and persist the changed
      filesystem fingerprints under the same force-cache metadata keys with
      different materialized value hashes, require same-runtime and
      fresh-runtime post-recompute changed-input runs to hit without
      force-cache misses and require the fresh-runtime runs to load the changed
      force-cache metadata keys, and require the resulting `.drv` paths and
      ATerm bytes to match cache-off changed-input runs while differing from
      the original materialized surfaces. They also scan original/materialized/
      changed/stale/post-recompute surfaces for the exercised trace
      identity/observation hashes plus persisted force-cache node/value/trace
      hashes in hex, raw bytes, and Nix base32. This samples stale filesystem
      leaf fallback inside derivation input surfaces; it does not cover full
      cached-vs-uncached closure parity, the full leak invariant,
      derivationStrict-node SHA-256 early cutoff, dirty propagation beyond
      fallback, lazy replay payloads, mmap reads, GC/repack, or future
      value-memoization safety net (`R-10`/`S-14`).
- [x] Current `getEnv` configured-environment persistent force-value `.drv`
      surface canary:
      `persistent_get_env_force_cache_hit_and_stale_miss_preserve_drv_surfaces`
      evaluates a derivation attr path whose `args` depend on first-class
      `let b = builtins; in b.getEnv "AOS_FORCE_CACHE_DRV_TEST"` with eval
      cache disabled, with configured persistent force-cache demand/writeback on
      cold and materializing paths, with a fresh-runtime trace-verified
      persistent forced-value hit for the same configured environment, and
      finally with the configured environment changed through the same
      persistent root. It requires same-env cached runs to match the
      cache-disabled `.drv` path, ATerm bytes, and `getEnv` fingerprint,
      requires the persistent-hit run to report a force-cache hit and load the
      expected force-cache metadata key, requires the changed-env persistent run
      to miss and recompute the changed `getEnv` fingerprint, requires
      materializing and changed-env persistent runs to persist exact `getEnv`
      traces under the same force-cache metadata key with different materialized
      value hashes, requires same-runtime and fresh-runtime changed-env
      post-recompute runs to hit without force-cache misses and requires the
      fresh-runtime run to load the changed force-cache metadata key, and
      requires the changed `.drv` path and ATerm bytes to match a cache-disabled
      changed-env surface while differing from the original surface. It also
      scans original/materialized/hit/changed/stale/post-recompute derivation
      surfaces for the exercised `getEnv` trace identity/observation hashes plus
      persisted force-cache node/value/trace hashes in hex, raw bytes, and Nix
      base32. This samples persistent `getEnv` hit selection and stale-input
      fallback inside one derivation input; it does not prove dirty propagation
      beyond direct revalidation fallback, full cached-vs-uncached closure
      parity, the full leak invariant, derivationStrict-node SHA-256 early
      cutoff, lazy replay payloads, mmap reads, GC/repack, or future
      value-memoization safety net (`R-10`/`S-14`).
- [x] Current stale effectful persistent force-value `.drv` surface parity
      canary: `persistent_effectful_force_cache_stale_miss_preserves_drv_surfaces`
      materializes a trace-verified `builtins.pathExists ./marker`
      forced-value payload inside derivation `args`, removes the marker, then
      evaluates through the same persistent cache root. It requires the stale
      persistent observation not to reuse the old marker-present payload,
      requires materializing and stale-miss runs to persist exact path-exists
      traces under the same force-cache metadata key with different materialized
      value hashes, requires recomputation to replay the new path-exists
      fingerprint, requires same-runtime and fresh-runtime marker-missing
      post-recompute runs to hit without force-cache misses and requires the
      fresh-runtime run to load the changed force-cache metadata key, and
      requires the resulting `.drv` path and ATerm bytes to match a cache-off
      marker-missing run while differing from the marker-present materialized
      surface. It also scans original/materialized/missing/stale/post-recompute
      surfaces for the exercised path-exists trace identity/observation hashes
      plus persisted force-cache node/value/trace hashes in hex, raw bytes, and
      Nix base32. This samples the current stale-input fallback inside a
      derivation input surface; full cached-vs-uncached closure parity, the
      full leak invariant, derivationStrict-node SHA-256 early cutoff, dirty
      propagation beyond fallback, lazy replay payloads, mmap reads, GC/repack,
      and future value-memoization safety net remain open (`S-14`).
- [x] Current uncacheable `currentTime` `.drv` surface canary:
      `persistent_current_time_force_cache_no_replay_preserves_drv_surfaces`
      evaluates a derivation attr path whose `args` depend on
      `builtins.currentTime` through a forced string conversion, requires
      same-time configured cached runs to match cache-disabled `.drv` path and
      ATerm bytes without reporting force-cache hits or misses, then changes
      the configured current time and requires the cached run to match the
      changed cache-disabled surface instead of replaying the older one, again
      without force-cache hits or misses. Each run records the uncacheable
      currentTime trace, and the canary asserts that persistent force metadata
      and trace sidecars remain empty. The adjacent
      `source_backed_current_time_tombstones_stale_persistent_payload` and
      `observation_only_current_time_tombstones_stale_persistent_payload`
      canaries seed stale durable payloads under the source-backed node-thunk
      and synthetic builtin-attr currentTime observation identities and require
      uncacheable forcing to clear the value link, tombstone the trace, and
      leave seeded reuse counters unchanged.
      This samples currentTime inside one derivation input surface plus one
      stale durable force-value boundary; general currentTime taint propagation through
      persisted dependents, full cached-vs-uncached closure parity,
      derivationStrict-node SHA-256 early cutoff, mmap reads, GC/repack, and
      future value-memoization safety net remain open
      (`S-14`/`R-10`).
- [x] Current explicit file-artifact materialization adapter:
      `PersistCache::materialize_file_artifact` derives the file-artifact
      mapping key from a caller-supplied `ParseFileKey`/`ParseCacheKey`, skips
      without payload hashing or writing on `KeepInMemory`, and on
      `Materialize` appends the payload to the `files/` pack and returns the
      typed index value a future durable index would store. Parse-artifact
      payload format, automatic parse-cache integration, durable index updates,
      lookup, mmap reads, GC/repack, and harness proof remain open
      (`C-13`/`C-14`).
- [x] Current explicit indexed file-artifact materialization adapters:
      `PersistCache::materialize_file_artifact_indexed` and
      `materialize_file_artifact_indexed_with_signals` preserve
      skip-without-hash/write behavior, and on `Materialize` ensure the payload
      is present through `ensure_blob_indexed` before recording the
      realpath/content/parse mapping through `record_file_artifact`. Successful
      indexed materialization records the file-artifact mapping sidecar entry
      and either reuses or records the `files/` blob hash-to-offset sidecar
      entry. This is explicit non-transactional indexed materialization only;
      automatic parse-cache integration, durable hit selection, mmap reads,
      GC/repack, and harness proof remain open (`C-13`/`C-14`/`R-10`).
- [x] Current materialized file-artifact index-entry accessor:
      `PersistFileArtifactMaterialization::index_entry` returns the complete
      `PersistFileArtifactIndexEntry` only when an artifact was materialized,
      binding the mapping key and blob lookup value the future durable index
      would store. This is accessor-only; durable index writes/reads,
      parse-cache integration, lookup, mmap reads, GC/repack, and harness proof
      remain open (`C-13`).
- [x] Current explicit parse-entry materialization adapter:
      `PersistCache::materialize_parse_artifact_entry` consumes a caller-supplied
      `ParseFileKey`/`ParseCacheKey` plus source `ParseCacheEntry`, skips without
      reading or encoding the entry on `KeepInMemory`, and on `Materialize`
      bundles the existing parse artifacts and appends that payload through the
      file-artifact materialization adapter. Automatic parse-cache integration,
      durable index updates, lookup, source/key equality proof, mmap reads,
      GC/repack, and harness proof remain open (`C-13`/`C-14`).
- [x] Current explicit indexed parse-entry materialization adapter:
      `PersistCache::materialize_parse_artifact_entry_indexed` consumes the
      same caller-supplied `ParseFileKey`/`ParseCacheKey` plus source
      `ParseCacheEntry`, preserves skip-without-read/encode behavior, and on
      `Materialize` bundles the existing parse artifacts before delegating to
      indexed file-artifact materialization so the `files/` blob is reused or
      freshly indexed and the file-artifact mapping entry is recorded. This is
      explicit non-transactional indexed materialization only; automatic
      parse-cache integration, durable hit selection, source/key equality proof,
      mmap reads, GC/repack, and harness proof remain open (`C-13`/`C-14`).
- [x] Current file/parse threshold signal adapters:
      `PersistCache::materialize_file_artifact_with_signals`,
      `materialize_file_artifact_indexed_with_signals`,
      `materialize_parse_artifact_entry_with_signals`, and
      `materialize_parse_artifact_entry_indexed_with_signals` evaluate
      caller-supplied `MaterializationSignals` before delegating to the existing
      decision-based adapters, preserving skip-without-payload-read/write
      behavior when the threshold fails. Automatic parse-cache integration,
      durable hit selection, source/key equality proof, mmap reads, GC/repack,
      and harness proof remain open (`C-13`/`C-14`).
- [x] Current explicit file-artifact read adapter:
      `PersistCache::read_file_artifact` consumes a typed
      `PersistFileArtifactIndexValue` and reads/verifies the referenced payload
      through the `files/` pack. This is a typed buffered read helper only;
      parse-artifact payload decoding, automatic cache-hit selection, mmap
      reads, GC/repack, and harness proof remain open (`C-13`).
- [x] Current explicit file-artifact bundle hydration adapter:
      `PersistCache::hydrate_file_artifact_bundle` reads a typed `files/`
      artifact value, decodes the `ParseArtifactBundle` payload, validates
      bundled metadata/schema/counts and `resolved.bin`/`symbols.bin`/`ir.bin`
      decoder shape through `ParseArtifactBundle::validate_meta`, and writes it
      into a caller-supplied `ParseCacheEntry` only after validation succeeds.
      This is explicit validated hydration only; automatic cache-hit selection,
      source/key equality proof, mmap reads, full artifact semantic validation
      beyond existing decoders, GC/repack, and harness proof remain open
      (`C-13`).
- [x] Current keyed file-artifact bundle hydration adapter:
      `PersistCache::hydrate_file_artifact_bundle_for_key` derives the expected
      `PersistFileArtifactKey` from the requested `ParseFileKey`/`ParseCacheKey`,
      rejects mismatches before reading the `files/` pack, and otherwise
      delegates to validated bundle hydration. This is explicit keyed hydration
      only; automatic cache-hit selection, full artifact semantic validation
      beyond existing decoders, mmap reads, GC/repack, and harness proof remain open
      (`C-13`).
- [x] Current indexed file-artifact bundle hydration adapter:
      `PersistCache::hydrate_file_artifact_bundle_from_entry` consumes a
      complete `PersistFileArtifactIndexEntry`, verifies its key against the
      requested `ParseFileKey`/`ParseCacheKey`, and delegates matching entries
      to validated bundle hydration. This is explicit entry-shaped hydration
      only; automatic cache-hit selection, full artifact
      semantic validation beyond existing decoders, mmap reads, GC/repack, and
      harness proof remain open
      (`C-13`).
- [x] Current indexed file-artifact lookup hydration adapter:
      `PersistCache::hydrate_file_artifact_bundle_from_index` derives the
      file-artifact mapping key from `ParseFileKey`/`ParseCacheKey`, performs
      `lookup_file_artifact`, returns `Ok(None)` on misses, and on hits hydrates
      the validated bundle into a caller-supplied `ParseCacheEntry` while
      returning the matched `PersistFileArtifactIndexEntry`. This is explicit
      cache-level lookup hydration only; automatic parse-cache integration,
      durable hit selection, source/key equality proof, mmap reads, full
      artifact semantic validation beyond existing decoders, GC/repack, and
      harness proof remain open (`C-13`).
- [x] Current source-derived indexed parse-cache hydration adapter:
      `PersistCache::hydrate_parse_cache_entry_from_source_index` derives both
      `ParseFileKey` and `ParseCacheKey` from one caller-supplied realpath/source
      byte pair, uses the normal `ParseCache` entry path for that source, and
      delegates matching durable file-artifact mappings to validated indexed
      hydration. This is explicit source-shaped hydration only; canonical path
      resolution, automatic parse-cache integration, durable hit selection,
      mmap reads, full artifact semantic validation beyond existing decoders,
      GC/repack, and harness proof remain open (`C-13`).
- [x] Current source-derived indexed parse-cache load adapter:
      `PersistCache::load_parse_cache_source_from_index` derives both source
      identities from one caller-supplied canonical realpath/source byte pair,
      hydrates the matching durable file-artifact entry into the normal
      `ParseCache` layout, then returns it through
      `ParseCache::load_cached_bytes` as a `CachedParse` hit. This is explicit
      caller-driven durable hit loading only; canonical path resolution,
      automatic evaluator/import selection, mmap reads, full artifact semantic
      validation beyond existing decoders, GC/repack, and harness proof remain
      open (`C-13`/`R-10`).
- [x] Current file-derived indexed parse-cache hydration adapter:
      `PersistCache::hydrate_parse_cache_entry_from_file_index` canonicalizes a
      requested filesystem path, reads the canonical source bytes, derives the
      same source-shaped identities, and hydrates the normal `ParseCache` entry
      when the durable file-artifact index has a match. This is explicit
      file-shaped hydration only; automatic parse-cache/evaluator integration,
      durable hit selection, mmap reads, full artifact semantic validation
      beyond existing decoders, GC/repack, and harness proof remain open
      (`C-13`).
- [x] Current file-derived indexed parse-cache load adapter:
      `PersistCache::load_parse_cache_file_from_index` canonicalizes and reads a
      requested source file, hydrates the matching durable file-artifact entry
      into the normal `ParseCache` layout, then returns it through
      `ParseCache::load_cached_bytes` as a `CachedParse` hit. This is explicit
      caller-driven durable hit loading only; automatic evaluator/import
      selection, mmap reads, full artifact semantic validation beyond existing
      decoders, GC/repack, and harness proof remain open (`C-13`/`R-10`).
- [x] Current parse-keyed persistent parse-artifact index substrate:
      `PersistLayout::parse_artifact_index_path` adds
      `nodes/parse-artifacts.index`; `PersistParseArtifactKey` encodes the
      `ParseCacheKey` without a realpath; and
      `PersistCache::materialize_parse_cache_entry_indexed`,
      `PersistCache::hydrate_parse_cache_entry_from_parse_index`, and
      `PersistCache::load_parse_cache_bytes_from_index` materialize and hydrate
      caller-supplied source bytes through this parse-artifact index.
      Materialization rejects entries whose normal parse-cache directory key
      does not match the supplied `ParseCacheKey`, and hydration validates
      bundled metadata/schema/counts plus `resolved.bin`/`symbols.bin`/`ir.bin`
      decoder shape before writing the target entry. This is cache API
      substrate only; evaluator integration is covered by the raw native
      expression row below. Source equality proof beyond the parse-cache entry
      directory key, mmap reads, full artifact semantic validation beyond
      existing decoders, GC/repack, and harness proof remain open
      (`C-13`/`C-14`/`R-10`).
- [x] Current ordinary filesystem import durable parse-cache hit selection:
      `TreeWalkOptions::set_persist_cache_root` configures an optional
      persistent cache root, and unscoped filesystem imports with a configured
      `parse_cache_root` now try
      `PersistCache::load_parse_cache_source_from_index` using the same
      canonical realpath/source bytes already recorded for the import input
      fingerprint before falling back to `ParseCache::load_or_parse_bytes` when
      the persistent root is unavailable, misses, or has stale/corrupt indexed
      artifacts. The persistent root opens lazily on the first eligible import;
      scoped imports and text-store imports still bypass this path. This is
      evaluator import hit selection only; mmap reads, full artifact semantic
      validation beyond existing decoders, GC/repack, and harness proof remain open
      (`C-13`/`R-10`).
- [x] Current ordinary filesystem import durable parse-cache writeback:
      unscoped filesystem imports with configured `parse_cache_root` and
      `persist_cache_root` now materialize successfully stored
      `ParseCache::load_or_parse_bytes` results into the persistent
      file-artifact index with `MaterializationDecision::Materialize` after
      durable misses or stale/corrupt durable entries fall back to normal parse
      loading. Writeback opens the persistent root through the same lazy
      advisory path as durable hit selection and ignores persistent write
      failures. This is ordinary import writeback only; file-backed native
      source roots and raw native expressions are covered separately. Mmap
      reads, full artifact semantic validation beyond existing decoders,
      GC/repack, and harness proof remain open (`C-13`/`C-14`/`R-10`).
- [x] Current file-backed native root durable parse-cache integration:
      `NixNative::lower_native_source_bytes` now accepts an optional canonical
      source path from file-backed instantiation roots and, when both
      `parse_cache_root` and `persist_cache_root` are configured, tries
      `PersistCache::load_parse_cache_source_from_index` before ordinary
      `ParseCache::load_or_parse_bytes`, then writes successfully stored
      fallback parses to the persistent file-artifact index. Raw
      `eval_expr`/`instantiate_expr` sources do not synthesize file-artifact
      keys. This is native file-root lookup/writeback only; mmap reads, full
      artifact semantic validation beyond existing decoders, GC/repack, and
      harness proof remain open
      (`C-13`/`C-14`/`R-10`).
- [x] Current file-backed native root cache-off/cached closure parity canary:
      `native_file_instantiation_cache_off_on_and_persistent_hit_preserve_drv_closure`
      evaluates the same two-derivation file-root attr path with native cache
      disabled, with configured parse/persist/eval cache on the miss/write
      path, and with a fresh parse root hydrated from a persistent file-artifact
      hit. It requires the selected root `.drv` path and every recorded
      input/root ATerm byte payload to be identical, records the persistent
      file-index hit, and scans cache-off, cache-on miss, and persistent-hit
      closure paths/ATerm bytes for the exercised file-root parse-cache and
      file-content BLAKE3 renderings (hex, raw bytes, and Nix base32). This
      samples the current native file-instantiation closure surface, not the
      full cached-vs-uncached AOS closure harness, full leak-invariant harness,
      or future value-memoization safety net (`S-14`/`S-15`).
- [x] Current raw native expression durable parse-cache integration:
      `NixNative::lower_native_source_bytes`, when called without a canonical
      source path and with both `parse_cache_root` and `persist_cache_root`
      configured, tries `PersistCache::load_parse_cache_bytes_from_index`
      before ordinary `ParseCache::load_or_parse_bytes`, then writes
      successfully stored fallback parses through
      `PersistCache::materialize_parse_cache_entry_indexed`. Raw
      `eval_expr`/`instantiate_expr` sources use parse-keyed persistent
      artifacts and still do not synthesize file-artifact keys. This is raw
      native expression lookup/writeback only; source equality proof beyond
      the parse-cache entry directory key, mmap reads, full artifact semantic
      validation beyond existing decoders, GC/repack, and harness proof remain
      open
      (`C-13`/`C-14`/`R-10`).
- [x] Current `cache/input.rs` impure-input fingerprint substrate: typed
      identities and deterministic durable observation hashes for
      `import`/`readFile`/`hashFile`/`readDir`/`readFileType`/`pathExists`/
      `getEnv`, plus an explicit uncacheable `currentTime` marker. `hashFile`
      has its own binary-safe read identity and observation domain rather than
      sharing `readFile`'s string-read domain. This is a fingerprinting
      primitive only; tree-walk builtins, demand-graph leaves, allowed-path/IFD/
      fetch interactions, and edge-exactness harness coverage remain open
      (`R-10`).
- [x] Current tree-walk impure-input observation trace: successful ordinary
      filesystem `import`, `readFile`, `hashFile`, `readDir`, `readFileType`,
      `pathExists`, and impure-mode `getEnv` calls append `cache/input.rs`
      fingerprints to `TreeWalk`/`EvalOutcome`; ordinary filesystem `hashFile`
      records a binary-safe `hashFile` input fingerprint for the bytes it
      hashes; selected `currentTime` appends an uncacheable marker. Trace
      construction failures mark the trace incomplete/cache-unusable without
      changing Nix evaluation semantics. This is an evaluator observation
      surface only; demand-graph leaves, dependency wiring, persistence,
      allowed-path/IFD/fetch interactions, and edge-exactness harness coverage
      remain open (`R-10`).
- [x] Current `hashFile` impure-leaf force-cache canary:
      `persistent_hash_file_force_cache_hit_and_stale_miss_preserve_drv_surfaces`
      evaluates a derivation attr path whose `args` include
      first-class `b.hashFile "sha256" ./input.txt`, materializes the first
      binary file payload through configured persistent force-cache writeback,
      verifies a fresh-runtime persistent hit for that `hashFile`-fingerprinted
      payload with no force-cache misses, mutates the hashed file, requires the
      stale run to miss and recompute, then verifies same-runtime and
      fresh-runtime hits for the changed binary payload with no force-cache
      misses while preserving cache-on/cache-off `.drv` path and ATerm parity
      for both file versions.
      This proves selected ordinary filesystem full-arity first-class
      `hashFile` payload trace admission, binary-safe revalidation, and
      stale-payload fallback inside a derivation input surface only; partially
      applied hashFile payload caching, allowed-path/IFD/fetch interactions,
      text-store-only paths, full automatic demand-edge wiring, and
      edge-exactness harness coverage remain open
      (`R-10`/`S-14`).
- [x] Current cache-side impure leaf substrate: domain-separated
      `DemandCacheKey` construction from typed input identities,
      non-canonical `ValueHash` wrapping for observed input results, and
      `DemandGraph::observe_impure_input` insertion/reconsideration for
      cacheable input leaves. This is graph bookkeeping only; wiring
      `EvalOutcome` traces from the evaluator/cache runtime, evaluating-node
      edges, currentTime taint propagation, persistence, allowed-path/IFD/fetch
      interactions, and edge-exactness harness coverage remain open
      (`R-10`/`S-14`).
- [x] Current cache-side impure trace ingestion substrate:
      `DemandGraph::observe_impure_trace` consumes complete cacheable traces
      into input leaf observations, reports incomplete traces as cache-unusable
      before graph mutation, and reports uncacheable inputs such as
      `currentTime` before graph mutation regardless of trace order. This is
      cacheability/leaf ingestion only; wiring `EvalOutcome` traces from the
      evaluator/cache runtime, evaluating-node edges, currentTime taint
      propagation through memoized nodes, persistence, allowed-path/IFD/fetch
      interactions, and edge-exactness harness coverage remain open
      (`R-10`/`S-14`).
- [x] Current EvalOutcome trace-to-cache substrate: `cache::EvalCache` is an
      explicit caller-owned demand-graph wrapper, `ImpureInputTraceSource`
      abstracts evaluator trace providers, and `EvalOutcome` implements that
      trait so completed tree-walk evaluations can be manually observed by the
      cache layer. This is an observation adapter only; demand/evaluating-node
      creation, automatic edges from evaluator-created nodes to input leaves,
      currentTime taint propagation through memoized nodes, persistence,
      allowed-path/IFD/fetch trace coverage, and edge-exactness harness
      coverage remain open (`R-10`/`S-14`).
- [x] Current EvalCache runtime enable/disable substrate:
      `cache::EvalCacheRuntime` models disabled cache observation as a no-op
      and enabled cache observation as delegation to an in-memory `EvalCache`;
      `TreeWalkOptions::eval_cache_enabled` controls whether `NixNative` owns
      an enabled runtime, and enabled native evaluations automatically observe
      their `EvalOutcome` impure traces into that cache. This is automatic leaf
      ingestion only; demand/evaluating-node creation, evaluator-node cache-key
      integration, automatic edges from evaluator-created nodes to input
      leaves, value memoization, currentTime taint propagation through memoized
      nodes, persistence, and edge-exactness harness coverage remain open
      (`R-10`/`S-14`).
- [x] Current graph-side impure input edge substrate:
      `DemandGraph::observe_impure_trace_for_node` wires complete cacheable
      input leaves to a caller-supplied existing node by replacing that node's
      whole dependency set with the latest leaves, so later changed input
      observations dirty that node only for current trace-owned inputs;
      incomplete and uncacheable traces add no leaves and clear prior
      dependencies from that node. This is graph-side edge wiring only for
      nodes whose dependencies are owned by the explicit trace; automatic
      demand/evaluating-node creation, cache-key integration for evaluator
      nodes, mixed dependency scopes, typed edge groups, automatic edges from
      evaluator-created nodes to input leaves, value memoization, currentTime
      taint propagation through memoized nodes, persistence,
      allowed-path/IFD/fetch trace coverage, and edge-exactness harness
      coverage remain open (`R-10`/`S-14`).
- [x] Current EvalCache trace-to-node edge adapter:
      `EvalCache::from_graph` wraps a prebuilt demand graph and
      `EvalCache::observe_impure_inputs_for_node` delegates an
      `ImpureInputTraceSource` to `DemandGraph::observe_impure_trace_for_node`
      for a caller-supplied existing node. This is an explicit adapter only;
      automatic demand/evaluating-node creation, evaluator-node cache-key
      integration, automatic edges from evaluator-created nodes to input
      leaves, value memoization, currentTime taint propagation through memoized
      nodes, persistence, allowed-path/IFD/fetch trace coverage, and
      edge-exactness harness coverage remain open (`R-10`/`S-14`).
- [x] Current explicit expression-trace edge adapter:
      `EvalCache::observe_expression_impure_inputs` and
      `EvalCacheRuntime::observe_expression_impure_inputs` first compute the
      caller-supplied expression key and observe/classify a completed trace,
      skip new expression-node creation for incomplete or uncacheable traces
      while invalidating any existing inline side payload and clearing stale
      dependencies for an existing key, and for complete cacheable traces get
      or insert the expression node before invalidating any prior side payload
      and replacing its input edges. This is
      still explicit caller-driven wiring; automatic evaluator demand-node
      lifecycle, evaluator-produced expression identities/free-variable value
      hashes, value memoization, currentTime taint propagation through memoized
      nodes, persistence, and edge-exactness harness coverage remain open
      (`R-10`/`S-14`).
- [x] Current expression cacheability status substrate:
      `ExpressionTraceObservation::cacheability` exposes a typed memoization
      gate that distinguishes cacheable expression nodes, incomplete traces,
      and uncacheable inputs such as `currentTime`. This is a status surface
      only; evaluator memo lookup, automatic taint propagation through
      already-memoized dependents, persistence, and edge-exactness harness
      coverage remain open (`R-10`/`S-14`).
- [ ] Full impure-input edges remain: `import`/`readFile`/`hashFile`/`readDir`/
      `readFileType`/`pathExists`/`getEnv` keyed as explicit content-hash
      demand-graph inputs; `currentTime` taints dependent memos as uncacheable
      (`R-10`).
- [x] Current precursor: AOS-configured native-cache kill switch. Blank
      `AOS_NIX_CACHE` or `AOS_NIX_CACHE=0` clears
      `NixEvalConfig::native_cache_root`; only a valid absolute root maps to
      `TreeWalkOptions::parse_cache_root = <root>/parse`,
      `TreeWalkOptions::persist_cache_root = <root>/persist`, and
      `TreeWalkOptions::eval_cache_enabled = true`. Native frontend lowering
      and ordinary import parse-cache paths use the durable frontend parse/IR
      artifact cache only when `parse_cache_root` is present, materialize
      file-derived parse artifacts only when `persist_cache_root` is present,
      and `NixNative` keeps `EvalCacheRuntime` disabled when eval-cache
      ingestion is disabled. Forced-expression persistent demand accounting,
      durable hit selection, value payload writeback, verifying-trace
      writeback, and derivation ATerm/static-output side-record durable
      lookup/writeback are gated by `eval_cache_enabled`, so disabled
      eval-cache observation writes no persistent force or derivation side
      metadata even if a test caller configures a persistent root directly;
      the native expression
      disabled-persistent-root canary also proves parse persistence remains
      active while force metadata and trace sidecars stay empty. This covers
      the current parse-cache persistence layer, in-memory impure-trace leaf
      ingestion, replayable forced-expression value/trace cache, and
      derivation side-record persistence, not full demand/evaluating-node
      lifecycle, persistent demand graph, generic value memoization, or
      in-process import result memoization. Gates:
      `eval_config_parses_aos_nix_cache_env_values`,
      `eval_config_maps_native_cache_root_to_cache_options`,
      `native_expression_disabled_persistent_root_leaves_force_sidecars_empty`,
      `disabled_eval_cache_option_skips_persistent_derivation_side_records`,
      native/tree-walk parse-cache tests, and native/force eval-cache disabled
      tests.
      ([12](12-incremental-evaluation-cache.md) §8.3).
- [x] Current native raw-instantiation cache-off/cached closure parity canary:
      `native_instantiation_expr_cache_off_on_and_persistent_hit_preserve_drv_closure`
      evaluates the same two-derivation raw expression with native cache
      disabled, with configured parse/persist/eval cache on the miss/write
      path, and with a fresh parse root hydrated from a persistent raw
      parse-artifact hit. It requires the root `.drv` path and every recorded
      input/root ATerm byte payload to be identical, records the persistent
      parse-index hit, and scans cache-off, cache-on miss, and persistent-hit
      closure paths/ATerm bytes for the exercised raw-wrapper parse-cache
      BLAKE3 renderings (hex, raw bytes, and Nix base32). This samples the
      current native raw-instantiation closure surface, not the full
      cached-vs-uncached AOS closure harness, full leak-invariant harness, or
      future value-memoization safety net
      ([12](12-incremental-evaluation-cache.md) §8.3).
- [x] Current native file-instantiation cache-off/cached closure parity canary:
      `native_file_instantiation_cache_off_on_and_persistent_hit_preserve_drv_closure`
      evaluates the same two-derivation file-root attr path with native cache
      disabled, with configured parse/persist/eval cache on the miss/write
      path, and with a fresh parse root hydrated from a persistent file-artifact
      hit. It requires the selected root `.drv` path and every recorded
      input/root ATerm byte payload to be identical, records the persistent
      file-index hit, and scans cache-off, cache-on miss, and persistent-hit
      closure paths/ATerm bytes for the exercised file-root parse-cache and
      file-content BLAKE3 renderings (hex, raw bytes, and Nix base32). This
      samples the current native file-instantiation closure surface, not the
      full cached-vs-uncached AOS closure harness, full leak-invariant harness,
      or future value-memoization safety net
      ([12](12-incremental-evaluation-cache.md) §8.3).
- [x] Current native semantic-no-op leaf edit closure canary:
      `native_file_instantiation_comment_only_leaf_edit_preserves_drv_closure`
      and `native_file_instantiation_unused_leaf_package_edit_preserves_drv_closure`
      evaluate file-root attr paths whose selected derivations depend on a leaf
      import through an input derivation, seed configured parse/persist cache
      with the first leaf source, rewrite either comments/whitespace or an
      unused derivation package in that leaf, and then require cache-disabled
      and cached runs to keep the two-derivation `.drv` closure byte-identical
      while the changed leaf reparses into the fresh cache root. They also
      scan uncached/cached first and changed closures for the exercised
      first/changed leaf parse-cache and file-content BLAKE3 renderings in
      hex, raw bytes, and Nix base32. This samples one comment/whitespace leaf
      edit and one unused leaf-package edit, not bounded recomputation
      measurement, full AOS closure coverage, the full leak invariant, or
      future value-memoization safety net
      ([12](12-incremental-evaluation-cache.md) §8.3).
- [x] Current native forced-expression sidecar leak canaries:
      `native_instantiation_expr_force_cache_sidecar_hashes_do_not_leak_into_drv_closure`
      and
      `native_file_instantiation_force_cache_sidecar_hashes_do_not_leak_into_drv_closure`
      drive raw-expression and file-root attr-path `NixNative` instantiation
      through cache-off, persistent demand observation, durable forced-value
      materialization, and a fresh-runtime persistent pass for a configured
      `currentSystem` thunk. The final fresh-runtime passes must report
      force-cache hits, and the canary scanner only admits persistent node
      metadata entries whose linked value loads through the cached-expression
      payload decoder. The canaries then scan the resulting `.drv` path and
      ATerm closure surfaces for forced-expression node metadata BLAKE3
      addresses, materialized value BLAKE3 addresses, trace-side BLAKE3
      addresses when present, and a representative context-free `NixString`
      xxh3 hot-hash sentinel. This extends the current native closure safety
      net to forced-expression persistent sidecars on both native source entry
      shapes; it is not the full cache-off AOS closure harness, full
      internal-hash leak invariant, or future value-memoization safety net
      ([12](12-incremental-evaluation-cache.md) §5.2/§8.3).
- [x] Current `AOS_NIX_CACHE=0` native closure bypass canary:
      `aos_nix_cache_zero_bypasses_native_closure_cache_root` configures a
      stale cache-root path that is a plain file, applies the real
      `AOS_NIX_CACHE=0` config path, verifies the mapped native
      `TreeWalkOptions` have no parse/persist cache roots and eval-cache is
      disabled, and then requires native-only instantiation to produce the same
      in-memory `.drv` closure as an explicitly uncached baseline. This samples
      the public env/config kill switch at the native `.drv` closure boundary;
      it is not the full periodic cache-off/cold cached CI harness or future
      value-memoization safety net ([12](12-incremental-evaluation-cache.md)
      §8.3).
- [ ] Full Phase-2 cache-off safety net remains: `AOS_NIX_CACHE=0` must bypass
      future incremental persistence/value memoization, and CI must periodically
      run cold cached-vs-uncached full-closure `.drv` revalidation
      ([12](12-incremental-evaluation-cache.md) §8.3).

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

- [x] Current prerequisite already in place: P1 safe owned-chunk `BumpArena`
      substrate from [06](06-memory-management-and-gc.md) — aligned monotonic
      allocations through entry-point-shaped `aos_alloc_*` Rust helpers,
      never-free typed handles, Rust-owned chunk drop, and arena accounting.
- [ ] Final Tier-A runtime arena remains: `mmap`/`munmap` chunks, thread-local
      per-worker arenas, CLI-wide Tier-A default, and byte-green proof under
      Tier A (the per-invocation default, `C-10`).
- [ ] `heap/gc.rs` — Tier B precise generational copying collector with a
      cache-resident nursery; precise (not conservative) so Boehm-style false
      retention is eliminated ([06](06-memory-management-and-gc.md)).
- [ ] `runtime/alloc.rs` — all allocation routes through `aos_alloc_*` runtime
      symbols so the GC strategy swaps without touching callers (and, later, the
      JIT) ([03](03-architecture-overview.md) §4.5; `S-8`).
- [ ] `heap/roots.rs` — precise root enumeration / stack maps for the collector.
- [x] Current safe-crate prerequisite already in place: the monolithic
      `aos-nix` oracle/frontend/glue crate carries `#![forbid(unsafe_code)]`
      and checks/source scans show no Rust `unsafe` forms in the evaluator
      crate (`S-17`, [14](14-integration-with-aos.md) §10).
- [ ] Future heap/GC unsafe policy and tooling remain: `heap/` or later unsafe
      crates under `#![deny(unsafe_op_in_unsafe_fn)]`, per-block `// SAFETY:`,
      GC fuzz target, and miri/ASan/UBSan/TSan/loom CI as applicable (`S-17`,
      [14](14-integration-with-aos.md) §9.3).

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
- [x] Current shared node-table admission precursor: `SharedDemandGraph`
      wraps the existing in-memory `DemandGraph` behind a same-process mutex,
      exposes `DemandNodeAdmission` from insert-or-get calls, and proves cloned
      concurrent same-key misses converge on one inserted node while preserving
      the winner's value hash. This is the convergence contract only; the final
      lock-free append-only/CAS table, scheduler integration, persistent
      two-machine single-flight, and loom/Miri audit remain open
      ([12](12-incremental-evaluation-cache.md) §8.3,
      [13](13-parallel-evaluation.md) §4.3).
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

## Phase 7.5 — LLVM AOT tier-3 (committed)

**GOAL.** Push **peak throughput beyond the Cranelift JIT**: an ahead-of-time
LLVM compilation tier for the hottest, daemon-resident code, where Cranelift's
fast-warmup baseline/optimized tiers leave throughput on the table. Under the
[budget mandate](17-roadmap-and-risks.md) §0 this is a **committed deliverable**,
not "only if measured" — the measure-first work here is *which* code reaches
tier-3 and how the LLVM and Cranelift backends compare, decided by
build-the-variants-and-keep-the-winner. The tree-walk oracle remains the deopt
target and the permanent correctness backstop; tier-3 never arbitrates a store
path.

**Deliverables.**

- [ ] `aot/llvm.rs` — the LLVM AOT backend: lower the annotated IR
      ([25](25-intermediate-representation.md)) through LLVM, sharing the same
      uniform `extern "C"` runtime ABI and `aos_alloc_*` symbols as the Cranelift
      tiers ([08](08-execution-tiers-and-cranelift.md); [10](10-primops-and-runtime-abi.md)).
- [ ] `aot/tier.rs` — tier-3 promotion policy (very-hot, long-lived code in the
      daemon case); a Cranelift-tier-2 vs LLVM-tier-3 throughput comparison
      recorded as the build-and-select evidence.
- [ ] `aot/cache.rs` — persistence/reuse of AOT-compiled code keyed on the same
      content-addressed identity as the rest of the pipeline (compile once, reuse
      across daemon lifetimes).
- [ ] `unsafe` discipline matching the JIT tiers: `aot/` under
      `#![deny(unsafe_op_in_unsafe_fn)]`, `// SAFETY:` per block, two-maintainer
      review, ASan/UBSan CI (`S-17`).

**Conformance (hold parity).**

- [ ] **Tier-3 (LLVM AOT) output is differentially identical to the tier-0
      oracle** across the closure ([20](20-nix-language-conformance.md) +
      [21](21-builtins-conformance.md) held invariant); deopt from tier-3 lands in
      semantics identical to the oracle.
- [ ] Harness byte-green **under all tiers** simultaneously (oracle, tier 1,
      tier 2, tier 3).

**Decisions closed/measured.**

- [ ] Measures: the LLVM-AOT-vs-Cranelift throughput crossover and which code
      reaches tier-3 (build-and-select; never ship a regression vs tier 2).

**EXIT CRITERIA (falsifiable).** Very-hot daemon-resident code compiles via LLVM
AOT; tier-3 output is differentially identical to the oracle across the closure;
a recorded throughput delta over tier-2 Cranelift on the daemon workload; the
harness is byte-green under all tiers.

**Rollout gate unlocked.** None new (parity held; the trust schedule continues).
Tier-3 deepens the daemon-mode win without changing the trust gradient — the
oracle is still the tie-breaker.

---

## Phase 8 — Committed advanced stack (formerly the rank-5 tail)

**GOAL.** The advanced stack, now **fully committed** under the
[budget mandate](17-roadmap-and-risks.md) §0. These are no longer "ship only if
the delta appears" follow-ups: pointer tagging, full-laziness, **concurrent
*moving* GC**, and **full effect-based region inference** are all **in scope and
built**. "Measure-first" here means *build the competing variants and keep the
winner* — each shipped form carries its own recorded benchmark delta and we
**never ship a regression**, but the deliverable itself is not optional.

**Deliverables (each built; the benchmark selects the implementation, not whether
it ships).**

- [ ] `value/tag.rs` — pointer tagging for WHNF-test fast paths
      ([05](05-value-representation.md)); NaN-boxing remains a *variant to
      evaluate* because Nix `i64` ints do not fit a NaN-box payload — build both
      and select (`M-4`/`Q-E`).
- [ ] `analysis/full_laziness.rs` — full-laziness / let-floating
      ([07](07-laziness-and-whole-program-analyses.md); daemon residency policy
      `R-6`).
- [ ] `heap/region.rs` — region inference: lexical/escape regions, extended to
      **full effect-based region inference** as a committed deliverable (`R-5`)
      rather than a research-grade maybe; profiles (`M-14`) tune *where* regions
      replace generational allocation, not *whether* the analysis is built.
- [ ] `heap/concurrent_gc.rs` — **concurrent *moving* GC** for daemon mode
      (ZGC/Shenandoah-style colored pointers + load barriers), a committed
      deliverable; **daemon-only**, sidestepped by the bump arena in CLI mode
      (`R-1`/`R-2`/`R-3`/`R-4`; the deepest coupling,
      [17](17-roadmap-and-risks.md) R9).

**Conformance (hold parity).**

- [ ] Harness stays byte-green for **each** deliverable independently
      ([20](20-nix-language-conformance.md) + [21](21-builtins-conformance.md)
      invariant); a *variant* that cannot stay byte-green is not selected, but the
      feature is still delivered via the variant that holds parity.
- [ ] Concurrent-GC × thunk-mutation interactions verified under `loom`/`miri`
      before shipping (`R-4`), daemon-mode only — the memory-ordering audit is an
      **absolute** gate, not relaxed by the budget mandate.

**Decisions closed/measured.**

- [ ] Closes (as committed deliverables): `R-1`/`R-2`/`R-3` (concurrent moving
      GC), `R-5` (full effect-based region inference), `R-6` (daemon float-out).
- [ ] Measures (build-and-select among variants): `M-4`/`Q-E` (NaN-box vs.
      tagged value), `M-13` (context bitset vs smallvec crossover), `M-14`
      (region granularity), `M-17`/`M-18` (parallel-forcing granularity /
      shared-value touch cost), `Q-G` (daemon model). `R-7` (super-node IR) stays
      deferred only because it is unspecified, not for budget reasons.

**EXIT CRITERIA (falsifiable).** Pointer tagging, full-laziness, full
effect-based region inference, and the concurrent *moving* GC are all **built and
benchmarked**; each ships in the variant carrying a recorded benchmark delta with
no regression (C6); the `loom`/Miri audit is green for the concurrent collector;
the harness stays byte-green throughout ([17](17-roadmap-and-risks.md) §0, §3).
(Parallel *forcing* is not in this stack — it is the committed P3.5; the
concurrent *moving collector* lives here.)

**Rollout gate unlocked.** **Phase E** (verify-sampling reduced; `NixCli`
retained as the permanent fallback). Even at default-on, `AOS_NIX_NATIVE_VERIFY`
sampling stays as a residual canary and `AOS_NIX_NATIVE=0` remains the one-line
kill switch ([14](14-integration-with-aos.md) §7.2, §10).

---

## Per-doc checklist index

Under the [budget mandate](17-roadmap-and-risks.md) §0 the project is tracked
**feature-by-feature**: every design doc now carries its own
`## Implementation checklist` section, and this all-phases document is the
**roll-up** across them. Each row links the topic doc to its per-feature
checklist (anchor `#implementation-checklist`). The phase sections above remain
the *order* in which these features are built and rolled out; the per-doc
checklists are the *fine-grained* trackers the phases aggregate.

| Doc | Topic | Checklist |
|-----|-------|-----------|
| [04](04-frontend-parser-and-ir.md) | Frontend: lexer, parser, arena AST, scope, IR lowering | [checklist](04-frontend-parser-and-ir.md#implementation-checklist) |
| [05](05-value-representation.md) | Value representation: tagged values, pointer tagging, NaN-box, hash-consing | [checklist](05-value-representation.md#implementation-checklist) |
| [06](06-memory-management-and-gc.md) | Memory: alloc-via-symbols, bump arena, generational + concurrent GC, regions | [checklist](06-memory-management-and-gc.md#implementation-checklist) |
| [07](07-laziness-and-whole-program-analyses.md) | Laziness + whole-program analyses (strictness, cardinality, full-laziness, escape) | [checklist](07-laziness-and-whole-program-analyses.md#implementation-checklist) |
| [08](08-execution-tiers-and-cranelift.md) | Execution tiers: tree-walk oracle, Cranelift JIT, LLVM AOT tier-3 | [checklist](08-execution-tiers-and-cranelift.md#implementation-checklist) |
| [09](09-attribute-sets-hidden-classes-and-inline-caches.md) | Attribute sets: hidden classes, inline caches, HAMT, iteration order | [checklist](09-attribute-sets-hidden-classes-and-inline-caches.md#implementation-checklist) |
| [10](10-primops-and-runtime-abi.md) | Primops + the runtime ABI | [checklist](10-primops-and-runtime-abi.md#implementation-checklist) |
| [11](11-derivation-and-store-compatibility.md) | Derivation + store compatibility (the CA store, ATerm, output paths) | [checklist](11-derivation-and-store-compatibility.md#implementation-checklist) |
| [12](12-incremental-evaluation-cache.md) | Incremental evaluation cache (demand graph, early cutoff, hash-consing) | [checklist](12-incremental-evaluation-cache.md#implementation-checklist) |
| [13](13-parallel-evaluation.md) | Parallel evaluation (work-stealing, fibers, lock-free CAS thunks) | [checklist](13-parallel-evaluation.md#implementation-checklist) |
| [14](14-integration-with-aos.md) | Integration with AOS: `NixEval` seam, gating, fallback, `unsafe` policy | [checklist](14-integration-with-aos.md#implementation-checklist) |
| [15](15-differential-testing-and-benchmarking.md) | Differential testing + benchmarking (the `.drv`-diff harness) | [checklist](15-differential-testing-and-benchmarking.md#implementation-checklist) |
| [23](23-scope-platform-and-modes.md) | Scope, platform, and language modes | [checklist](23-scope-platform-and-modes.md#implementation-checklist) |
| [24](24-observability-and-diagnostics.md) | Observability and diagnostics | [checklist](24-observability-and-diagnostics.md#implementation-checklist) |
| [25](25-intermediate-representation.md) | The intermediate representation (IR) | [checklist](25-intermediate-representation.md#implementation-checklist) |
| [26](26-optimization-pass-catalog.md) | The optimization pass catalog (the simplifier) | [per-pass status](26-optimization-pass-catalog.md) |
| [28](28-generalization-and-language-dialects.md) | Generalization + language dialects (the `ratchet` engine; Core/dialect split; Phase 1b re-layering) | [checklist](28-generalization-and-language-dialects.md#implementation-checklist) |

**Notes.**

- Docs [20](20-nix-language-conformance.md) (language) and
  [21](21-builtins-conformance.md) (builtins) are the **conformance checklists** —
  the parity surface held invariant from Phase 1 on — rather than per-feature
  build trackers; they are not duplicated as rows above.
- Doc [26](26-optimization-pass-catalog.md) carries **per-pass status** (each
  simplifier pass records its own Soundness/Status note) instead of a single
  `## Implementation checklist` section.

---

## The parity invariant, drawn once

```text
   PHASE 1  ── achieve byte-for-byte parity (docs 20 + 21) under the
              SLOW tree-walk oracle.  Harness byte-green on full closure.
                         │
                         ▼   parity is now an INVARIANT
   P2 cache / P3 heap / P3.5 parallel / P4 analyses / P5 shapes /
   P6 jit-1 / P7 jit-2 / P7.5 LLVM-AOT-tier-3 / P8 concurrent-moving-GC + regions
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

- [ ] **The full stack is built and benchmarked.** Under the
      [budget mandate](17-roadmap-and-risks.md) §0, "done" requires the *entire*
      committed technique stack to be implemented and measured — not a 90% subset:
      the incremental early-cutoff cache, the bump arena + precise generational GC,
      the parallel work-stealing/fiber evaluator with lock-free CAS thunks, the
      whole-program analyses, hidden classes + inline caches, the Cranelift JIT
      tiers, the **LLVM AOT tier-3**, the **concurrent *moving* GC**, and **full
      effect-based region inference**. Each carries its own recorded benchmark
      delta (build-the-variants-and-keep-the-winner); no committed deliverable is
      dropped for scope.
- [ ] **Harness byte-green on the full closure, throughout.** The differential
      `.drv`-diff harness ([15](15-differential-testing-and-benchmarking.md)) is
      byte-green across the *entire* AOS package set — every `.drv` and store path
      identical to the pinned C++ Nix, identical error/no-error outcomes — and
      stays green in CI **through every change**, under **all** execution tiers
      (oracle, tier 1, tier 2 with deopt/OSR exercised, tier-3 LLVM AOT). The full
      [20](20-nix-language-conformance.md) and [21](21-builtins-conformance.md)
      surfaces are green and held invariant; the `loom`/Miri audit is green for the
      parallel evaluator and the concurrent collector.
- [ ] **A measured win.** A recorded benchmark delta on representative AOS
      workloads shows native eval is materially faster than the `nix-instantiate`
      baseline from P1, pursued to the *fastest evaluator achievable* rather than a
      sufficiency threshold. Every shipped optimization — through tier-3, the
      concurrent collector, and region inference — carries its own measured delta
      and never ships a regression (`S-18`,
      [15](15-differential-testing-and-benchmarking.md) §6).
- [ ] **`AOS_NIX_NATIVE` default-On with `NixCli` fallback retained.**
      `AOS_NIX_NATIVE` defaults **On** for `instantiate` (Phase D/E) only after
      the closure has been byte-green and Shadow/verify-sampling silent on real
      traffic for a long window; `NixCli` remains the permanent oracle and
      one-env-var fallback (`AOS_NIX_NATIVE=0`), never removed; a residual
      `AOS_NIX_NATIVE_VERIFY` canary remains ([14](14-integration-with-aos.md)
      §7.1, §10; `S-16`).

Under the [budget mandate](17-roadmap-and-risks.md) §0 there is no STOP branch:
P1.5 is **baseline characterization**, not a kill gate, so a finding that eval is
a small fraction of build time does not change the definition of done. The full
stack above is built and benchmarked regardless; the P1.5 breakdown only orders
and parallelizes the workstreams ([01](01-motivation-and-goals.md) §5.2,
[17](17-roadmap-and-risks.md) §0, R6).

---

## References

This checklist is a derived view; the authoritative argument for each item lives
in the document it cites.

- The phase table, ranked build sequence, Phase-1 checklist, and risk register:
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
