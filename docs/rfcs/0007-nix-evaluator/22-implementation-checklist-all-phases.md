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
      direct node reruns, `--smoke` zlib witness,
      `--all`/`--systems`/toolchain/lang-corpus enumeration,
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
- [x] Standing parser/fuzz harness robustness: rnix parser acceptance
      differential coverage is present in `aos-nix-syntax`'s test-only
      `parser_acceptance_matches_rnix_oracle_on_p1_syntax_corpus` plus
      automatically enumerated local language fixtures, source-seed fuzz
      corpora with explicit `internal_diff_raw` and `parity_json` sentinels, and
      the real workspace `.nix` source tree with package, toolchain, module, and
      system sentinels; `aos nix-fuzz-corpus` now populates ignored parity-fuzzer source
      seeds from the full §2.7 package/toolchain/system corpus and configured
      generated conformance corpus. The configured pinned C++ oracle recursion
      semantics check now runs on a fixed 32 MiB worker stack, so recursive
      fixed-point regressions report as semantic test failures instead of
      aborting the `ratchet-oracle cpp_nix` harness process. Covered by
      `parser_acceptance_matches_rnix_oracle_on_p1_syntax_corpus`,
      `parser_acceptance_matches_rnix_oracle_on_local_fixtures_and_fuzz_seeds`,
      `parser_acceptance_matches_rnix_oracle_on_workspace_nix_sources`,
      `nix_fuzz_corpus` command/CLI tests,
      `fuzz_source_seed_uses_string_attr_path_segments`,
      `explicit_toolchain_corpus_names_foundational_roots`,
      `gcc_toolchain_tier_components_name_derivation_roots`,
      `toolchain_attr_expr_absolutizes_and_filters_existing_derivations`,
      `system_attr_expr_absolutizes_relative_file_and_selects_toplevels`,
      `conformance_corpus_generates_eval_okay_derivation_attrs`, and
      `recursive_lambda_eval_fail_uses_stack_safe_max_call_depth`.
      This is a standing-harness robustness item, not the falsifiable byte-green
      gate, which is met.
- [ ] Full parity-fuzzer budget/quiescence and post-change conformance
      revalidation remain: after the last evaluator semantics change, run the
      configured `internal_diff_raw` and `parity_json` fuzz targets for the
      acceptance budget with zero new divergences, and keep the full conformance
      harness green before default-on cutover. This is tracked as a cutover soak
      gate, not as a local unit-test scaffold.

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
- [x] Current grouped dynamic dependency replacement substrate:
      `DemandDependencyGroup` splits graph edge ownership between memo-read and
      impure-input edges, `DemandNode::dependencies()` remains the deterministic
      union used by dirty-frontier scheduling and propagation, and
      `DemandGraph::replace_dependency_group` refreshes one group while
      preserving other groups and maintaining reverse dependent edges from the
      union diff. Whole-set `replace_dependencies` remains as a compatibility
      reset, while graph and runtime impure-trace adapters now replace or clear
      only the impure-input group so later trace refreshes do not erase
      memo-read edges. This is explicit graph/runtime edge ownership only;
      automatic evaluator-owned dynamic dependency capture, separate inner/outer
      active observers, evaluator-integrated ready-dirty recomputation,
      persistent graph serialization, and cached/uncached `.drv` parity proof
      remain open (`S-14`/`C-20`).
- [x] Current force-cache memo-read edge precursor: tree-walk tracks a
      stack of active memo-read expression nodes while policy-admitted
      lookup-identity thunks evaluate, `EvalCache` can return the demand node
      that supplied an in-memory inline payload hit, persistent force-cache hits
      report the runtime node seeded by durable payload rehydration, and
      successful in-memory or persistent force-cache hits under an active parent
      collect the hit child node into the active parent frame. Successful
      admitted thunk child misses also collect the newly evaluated child
      expression node into the enclosing active parent after the child
      completes, and successful admitted first-class cacheable impure primop
      misses collect the accepted primop expression node into the active parent
      frame after the primop payload observation completes.
      Successful parent force completion replaces the parent's `MemoRead`
      group with that per-evaluation child set without disturbing impure-input
      edges; failed parent evaluations leave the previous memo-read group
      unchanged. Runtime dependency replacement and lookup paths for clean
      inline payloads, trace-backed inline payloads, derivation ATerm side
      records, and static-output side records now also miss and purge the side
      payload when the target node has an already-dirty direct or transitive
      `MemoRead` supplier, so a stale supplier cannot be bypassed simply because
      the dependent node has not yet been dirtied.
      Disabled runtimes, inactive parents, and self-edges remain no-ops. This
      covers force-cache child payload hits that already have or
      seed an in-memory runtime node, admitted thunk child misses with runtime
      nodes, and admitted first-class cacheable impure primop misses with runtime
      nodes; it also covers transitive dirty memo-read supplier side-record
      purges. Persistent force-cache trace writeback now attaches every
      committed direct `MemoRead` supplier that needs its own durable proof as a
      durable node metadata key plus pinned supplier value hash, and
      rejects/clears the parent writeback if any committed supplier is neither
      backed by a matching materialized value link plus live verifying trace nor
      a clean live inline supplier with no nested memo-read suppliers and no
      impure-input leaves outside the parent trace's cacheable leaves.
      Trace-backed durable loads recursively revalidate those supplier traces,
      reject uncacheable supplier revalidation such as `currentTime`, and check
      pinned hashes before accepting the parent payload. Durable hits also
      replace the current runtime node's memo-read group from dependency keys
      when every supplier node is already present, and reject/clear the durable
      parent payload when any supplier key is unresolved, any pinned supplier
      hash changed, or any rehydrated supplier is already dirty. Rejected
      rehydration also purges the just-observed runtime payload so the same run
      cannot hit an unproven in-memory side record. General evaluator-owned
      dynamic dependency capture, separate inner/outer observers,
      evaluator-integrated ready-dirty recomputation, full persistent graph serialization, and
      cached/uncached `.drv` parity proof remain open (`S-14`/`C-20`). The gate
      covers
      `eval_cache_payload_hits_return_supplier_node_for_memo_read_edges` and
      `clean_inline_payload_with_dirty_memo_supplier_misses_and_purges_record`,
      `clean_inline_payload_with_transitively_dirty_memo_supplier_misses_and_purges_record`,
      `clean_trace_backed_inline_payload_with_dirty_memo_supplier_misses_and_purges_record`,
      `clean_trace_payload_with_transitively_dirty_memo_supplier_misses_and_purges_record`,
      `clean_derivation_side_records_with_dirty_memo_supplier_miss_and_purge`,
      `clean_derivation_side_records_with_transitively_dirty_memo_supplier_miss_and_purge`,
      `replace_memo_read_dependencies_with_transitive_dirty_supplier_purges_side_records`,
      `source_backed_active_force_cache_hits_record_memo_read_edges`,
      `source_backed_active_force_cache_hits_replace_prior_memo_read_edges`,
      `source_backed_parent_force_without_hits_clears_prior_memo_read_edges`,
      `source_backed_active_force_cache_child_misses_record_memo_read_edges`,
      `effectful_primop_child_misses_record_memo_read_edges`,
      `source_backed_active_persistent_force_cache_hits_record_memo_read_edges`,
      trace-backed `effectful_forced_inline_thunks_hit_from_persistent_cache_after_revalidation`,
      `cache_cached_expression_node_payload_trace_revalidation_checks_memo_read_dependencies`,
      `cache_trace_revalidation_rejects_uncacheable_memo_read_dependency`,
      `cacheable_impure_force_observation_writes_persistent_value_link`,
      `force_observation_with_unproven_memo_supplier_clears_persistent_value_link`,
      `persistent_force_cache_hit_rejects_dirty_supplier_from_trace_dependency_key`,
      `persistent_force_cache_hit_rejects_unresolved_supplier_without_runtime_payload_hit`,
      `source_backed_admitted_force_error_balances_active_force_cache_stack`,
      and `source_backed_admitted_force_error_preserves_prior_memo_read_edges`.
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
      encoded as length-prefixed chunks. Tests pin stability, source/node
      identity changes, order sensitivity, multiplicity, length-prefix
      ambiguity, key-level hash-map separation under matching hot probes, and
      demand-graph separation under matching hot probes. This checks the C-1
      combiner rule and in-process collision-confirmation rule only, not
      canonical free-variable set/order production, real durable value-hash
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
      explicit option and impure-input keys, synthetic apply thunks and
      remaining dynamic/unhashable select thunks, canonical free-variable
      hashes, general memo lookup,
      remaining suspended non-literal/non-replayable captured thunk-cell free
      variables, arbitrary lazy-element list and lazy-binding attrset payloads,
      multi-module or non-own-module
      binding-position persistence and module-source remapping, and other
      composite value hashing, persistence, and cached/uncached harness proof remain open
      (`S-14`/`S-15`). The gate includes positioned attrset force-cache hit,
      imported own-module positioned attrset replay/remap, stale unprovenanced
      positioned payload miss/clear, multi-module stale positioned payload
      miss/clear, and
      `unsafeGetAttrPos` provenance canaries.
- [x] Current pure closed force-cache hit substrate: `EvalCache` keeps per-node
      scalar/string/path/replayable-list/replayable-attrset payload records beside demand-graph value
      hashes, `EvalCacheRuntime::lookup_inline_expression_payload` returns a
      memoized payload only for clean nodes whose payload hash still matches the
      graph and whose memo-read supplier chain is clean, and tree-walk
      `force_value` consults this shared cache before
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
      stale payloads, dirty memo-read supplier chains, unprovenanced positioned
      payloads, and incompatible, multi-module, or non-own positioned
      payloads are misses. This is a scalar/string/path/replayable-list/replayable-attrset
      pure/local hit path only: source-less raw eval outside the
      lowered-IR-backed node-thunk subset, captured dynamic/scoped-global
      thunks, ambient/synthetic builtin values outside the admitted constant subset,
      search-path/global/builtin/primop/application/dialect nodes pending
      explicit option and impure-input keys, synthetic apply thunks and
      remaining dynamic/unhashable select thunks, canonical free-variable
      hashes, remaining suspended
      non-literal/non-replayable captured thunk-cell free variables, arbitrary
      non-literal lazy-element lists and lazy-binding attrsets, broader
      multi-module/non-own
      binding-position module-source remapping, and other composite payloads,
      full transitive dirty scheduling, persistence, `derivationStrict` SHA-256
      short-circuiting, and cached/uncached harness proof remain open
      (`S-14`/`S-15`). The gate includes `cache::runtime` lookup tests,
      source-backed force-cache hit/skip tests, positioned attrset
      hit/provenance canaries, imported own-module positioned attrset replay/remap
      canary, stale unprovenanced and multi-module positioned payload
      miss/clear canaries, and
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
      key, while cacheable trace observations whose payload cannot be recorded
      also dirty the existing node and clear stale impure-input ownership.
      Lookup remains restricted to the pure/speculable subset until the
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
      identities now hash the module's `store_dir`, search-path base, configured
      `nix_path` entries, hidden corepkgs path, `home_dir`, configured
      `current_system`, configured `current_time`, `eval_mode`, and
      ambient-search-path rejection plus unconfigured-impure-builtin rejection
      alongside source name or lowered-IR fingerprint, path-literal base,
      lowered node source span, and IR node id.
      This prevents the current admitted force-cache path from sharing inline
      payloads across evaluator configurations that can change path/context,
      search-path resolution, ambient builtin constants, impurity-policy
      behavior, or expression source position. It is deliberately conservative
      and may miss across option/span changes that do not affect a
      specific expression; full cache-key integration, canonical free-variable
      hashes, fine-grained option dependency tracking, persistent keys, and
      cached/uncached harness proof remain open (`C-1`/`C-2`/`R-10`).
- [x] Current ambient and synthetic builtin constant force-cache substrate: tree-walk admits
      only symbol-checked `BuiltinAttr` constants for force-cache
      lookup/observation: immediate true/false/null, `currentSystem`,
      `storeDir`, `nixVersion`, `langVersion`, and visible `nixPath`;
      `currentTime` is
      observation-only and remains uncacheable through its existing impure
      trace. Matching configured `currentSystem`, `storeDir`, and `nixPath`
      thunks can now hit as context-free string or replayable list payloads,
      while changed `currentSystem`, `storeDir`, or `nixPath` values still miss
      through builtin-specific synthetic identity inputs.
      Reified `builtins` attrset entries for those constants are now delayed
      synthetic builtin-attr thunks, so constructing the attrset does not force
      `currentTime`, and runtime selections such as
      `let b = builtins; in b.currentSystem` use synthetic identities keyed by
      source/lowered-IR identity, force-site `IrId` and lowered source span,
      builtin symbol, execution tag, and only the
      evaluator-option fields observable by that builtin. Thus immediate
      constants ignore evaluator options and path-literal base, version
      constants ignore evaluator options and path-literal base while keying on
      their pinned version/langVersion values,
      `storeDir` keys only on `store_dir`, `currentSystem` keys on
      `current_system` plus pure/non-pure visibility, and `nixPath` keys on
      visible search-path inputs plus ambient-search-path rejection. The
      observation-only `currentTime`
      canaries assert that ordinary forcing leaves persistent force metadata
      and trace sidecars empty, while seeded stale durable node-thunk and
      synthetic builtin-attr `currentTime` payloads are cleared and tombstoned
      without recording demand. This
      deliberately skips the recursive `builtins` attrset, derivation,
      first-class primops, synthetic apply thunks,
      remaining dynamic/unhashable select thunks,
      broader persistence, and cached/uncached harness proof. The gate covers
      source-backed and source-less ambient and synthetic currentSystem
      hit/miss, direct ambient/source-less nixPath hit/miss, synthetic
      currentSystem/storeDir/nixPath/immediate/version unrelated-option hit canaries,
      synthetic pure-hidden nixPath entry sharing, synthetic storeDir
      hit/miss/symbol-separation, synthetic nixPath hit/miss by visible
      search-path inputs, synthetic force-site span separation,
      synthetic immediate
      constants, reified currentTime laziness, stale synthetic
      currentTime runtime payload invalidation, observation-only currentTime
      sidecar-empty and stale-durable tombstone canaries, and source-backed/source-less
      currentTime uncacheable-trace force-cache tests (`C-1`/`C-2`/`R-10`).
- [x] Current first-class `getEnv` force-cache identity narrowing precursor:
      admitted saturated first-class `builtins.getEnv` child-call identities now
      reuse the source/lowered-IR module identity and call-site span, builtin
      symbol, execution tag, and only the pure/non-pure environment visibility
      salt instead of the broad evaluator-option identity and path-literal base.
      The environment variable name remains in the child-call free-variable
      value hash, while the observed environment value remains an impure-input
      trace revalidated before replay; pure mode gets a separate
      hidden-environment identity because pure `getEnv` returns the empty string
      without recording an impure input. This is intentionally limited to
      first-class `getEnv`; filesystem/search-path primops such as `readFile`,
      `pathExists`, `hashFile`, `findFile`, and import still use their existing
      conservative identities until their option and policy dependencies are
      narrowed separately. The gate covers first-class `getEnv`
      unrelated-option hit, changed-environment stale miss, pure-mode
      identity-separation, and persistent child-call hit/stale-miss canaries
      (`C-1`/`C-2`/`R-10`).
- [x] Current source-less lowered-IR force-cache identity substrate:
      `cache::parse::lowered_ir_fingerprint` hashes the stable `ir.bin` and
      `symbols.bin` artifact encodings under the parse-cache schema version,
      and tree-walk uses that digest when a module has no source provenance.
      Source-less node-thunk identities then apply the same path-literal-base,
      `store_dir`, search-path base, configured `nix_path` entries, hidden
      corepkgs path, `home_dir`, configured `current_system`, configured
      `current_time`, `eval_mode`, ambient-search-path rejection, and
      unconfigured-impure-builtin rejection salts plus the lowered node source
      span. Source-less synthetic builtin-attr identities reuse the lowered-IR
      fingerprint and synthetic force-site source span but deliberately omit
      path-literal-base and the broad evaluator-option salt, adding only the
      option fields observable by the selected builtin. This lets caller-owned
      in-memory cache runtimes share conservative source-less lowered-IR
      node-thunk and admitted synthetic builtin-attr payloads without requiring
      source bytes, while still separating equal-shaped IR whose symbol tables,
      node spans, synthetic force-site spans, or relevant evaluator options
      differ. It is a
      source-independent identity substrate only; broader source-less raw eval
      surfaces, synthetic apply thunks, remaining dynamic/unhashable select
      thunk surfaces, remaining composite payloads, persistence,
      fine-grained option dependency tracking, and cached/uncached harness proof
      remain open. The gate covers lowered-IR fingerprint tests plus
      source-less hit/miss, source/source-less domain separation,
      path/store/home/current-system/eval-mode salt, readFile revalidation,
      captured-free-variable tests, and source-less synthetic builtin constant
      hit tests (`C-1`/`C-2`/`S-14`).
- [x] Current inline/string/path/replayable-composite captured-free-variable
      force-cache key substrate: tree-walk now builds one force-cache subject for
      each source-backed or lowered-IR-backed node thunk, including ordered
      `ValueHash` values for referenced captured lexical slots when every captured
      slot value is either an inline scalar supported by
      `ValueHash::from_inline_value`, a Nix string with or without context, a
      Nix path with or without context, a replayable Nix list, a replayable Nix
      attrset whose source-order metadata and binding positions are preserved
      when present, a
      fulfilled thunk cell whose cached value is one of those replayable values,
      a suspended closed literal thunk whose static payload is one of those
      replayable values, or a suspended captured local/upvalue alias thunk whose
      referenced captured payload is one of those replayable values.
      Static synthetic select thunks with static attr paths now use a
      domain-separated select-site/path identity plus the selected path value's
      force-captured hash; selected binding position source-name/span identities
      are folded in when present. Matching selected values hit across unselected
      receiver-sibling edits that do not move a retained selected binding
      position; position-bearing selected bindings intentionally miss when their
      retained source-name/span identity changes. Changed selected values miss,
      changed paths or select sites do not false-hit, and dynamic paths,
      unhashable receivers, or unhashable selected values skip subject
      construction. Captured
      free-variable scans also project simple static selects from captured
      lexical slots to selected-value hashes, falling back to the prior
      whole-slot hash when projection cannot be resolved without adding demand.
      Default-bearing captured static selects now use branch-separated hashes:
      present branches hash the selected path value and ignore the unused
      default, while missing branches hash a missing-branch marker plus the
      default expression's captured free-variable dependencies.
      This lets derivation side-record keys ignore unselected imported attrset
      siblings while preserving positioned-source identity.
      Static `hasAttr` paths over captured lexical slots now use a
      domain-separated key-presence hash when the receiver path can be resolved
      through already materialized attrsets, or through safe suspended capture
      aliases to already materialized attrsets, without forcing binding values.
      This lets `x ? name` force-cache subjects ignore changed lazy binding
      payloads while still missing when key presence changes; unresolved
      computed receivers, dynamic paths, and unresolved nested intermediates fall
      back to the prior whole-slot hash/skip behavior. The current `hasAttr`
      canaries cover force-cache subject/payload behavior; derivation
      side-record-specific reuse remains under the separate side-record gates.
      Strings and paths are hashed in one durable force-capture domain with typed
      string/path tags; contextual values append canonical context element tags
      and length-prefixed path/output bytes. Replayable list/attrset captures
      hash the current replayable payload value hash under the same
      force-capture domain with a composite tag; positioned composites
      additionally salt the captured hash with the cache identity of every
      module referenced by retained binding positions. Lookup and observation feed
      those typed value hashes into the existing ordered/length-prefixed demand-key
      combiner, so repeated captured inline/string/path/replayable-composite
      thunks hit only when their free-variable value hashes match and miss when
      those captured values differ or their referenced position-source
      identities differ. Static-key nested `let` bodies are admitted with
      nested-frame-depth-adjusted free-variable scans, so inner locals/upvalues
      are ignored while outer captured slots remain hashed. This deliberately skips dynamic `with`
      scopes, scoped-import globals, arbitrary non-literal lazy-element lists,
      arbitrary non-literal lazy-binding attrsets except for static `hasAttr`
      key-presence projections,
      position-bearing attrsets whose retained module ids cannot be resolved to
      loaded module identities, lambdas, primops,
      suspended computed/non-replayable thunk-cell captures including computed
      values not already forced in the captured slot, recursive captured alias
      cycles, lambda/formal/recursive-attrset frame introducers and dynamic-key
      nested `let` bodies, apply thunks
      and dynamic-path, unhashable-receiver, or unhashable-selected-value select
      thunks, full
      strictness/escape free-variable analysis, remaining
      composite value hashes, persistence, and cached/uncached harness
      proof. The gate covers captured inline/string/path/list and empty-attrset
      hit/miss tests, repeated captured-slot deduplication, lowered
      lambda-argument coverage, cross-type string/path hash separation,
      materialized context-bearing string/path capture hash tests, preforced
      computed string thunk-cell capture tests, fulfilled
      replayable-attrset thunk-cell hash tests, direct suspended computed and
      recursive alias thunk-cell skip tests, caller-level
      suspended computed capture subject-skip canary, dynamic `with`/scoped-import
      global subject-skip canaries, captured static nested-let outer-capture
      hit/miss and dynamic-key skip canaries, lambda/recursive-attrset nested
      lexical-frame subject-skip canaries, captured lambda/primop value
      subject-skip canaries, synthetic apply/apply2 subject-skip canaries,
      synthetic static-select selected-value/path/site hit/miss,
      unselected-sibling hit, and dynamic-path/unhashable-receiver/
      unhashable-selected-value skip canaries, captured static-select
      projection hit/miss, default present/missing branch, and
      suspended-receiver fallback canaries, captured root/imported
      positioned attrset source-salted
      admission and hit/miss canaries, source-order attrset admission canaries, captured closed-literal lazy-element list and
      lazy-binding attrset admission canaries, captured computed lazy-element list
      and non-presence-projected lazy-binding attrset subject-skip canaries,
      captured static `hasAttr` key-presence hit/miss plus alias, dynamic,
      unresolved, nested skip/no-force canaries,
      direct and first-class
      captured explicit-list `findFile` hit canaries, first-class captured
      unary `getEnv`/`import`/`readDir`/`readFile`/`readFileType` argument hit
      canary, first-class captured `pathExists` and `hashFile` argument hit/miss
      canaries, and representative
      captured unsupported free-variable skips plus
      `native_file_instantiation_unused_leaf_package_edit_preserves_drv_closure`,
      which now requires unselected leaf-package edits to reuse both static
      output side records and both final ATerm paths with zero derivation hash or
      text-path calculations
      (`C-1`/`C-2`).
- [x] Current free-variable value-hash type boundary:
      `DemandCacheKey::for_free_vars`, `PersistNodeMetadataKey::for_expression`,
      `DemandGraph`/`SharedDemandGraph` expression-node helpers,
      `EvalCache`/`EvalCacheRuntime` expression lookup, observation, and
      materialization helpers, derivation side-record helpers,
      `ForceCacheSubject`, tree-walk captured-free-variable hash production,
      and heap `captured_value_hash` memoization now carry free-variable hashes
      as `ValueHash`. Stable hot/persistent key construction unwraps with
      `ValueHash::as_durable_hash()` only at the length-framed byte-combiner
      boundary, while expression/source/input identities and final metadata/blob
      index keys remain raw `DurableBlake3Hash` domains. This closes the current
      free-variable constructor leak; it is not the full canonical value
      serializer, the full strictness/escape free-variable set, persistent graph
      integration, or the cached/uncached false-hit harness. Gates:
      `cargo check --manifest-path crates/Cargo.toml -p ratchet-oracle --tests`, `cache::key`,
      `cache::persist::tests::format_tests::node_metadata_index`, `eval::heap`,
      captured free-variable tests, and derivation side-record cache-path tests
      (`S-15`).
- [x] Current demand-cache key hash boundary:
      `DemandKeyHotHash` marks the in-process xxh3 probe for `DemandCacheKey`,
      and `DemandKeyConfirmationHash` marks the BLAKE3 confirmation digest that
      keeps same-hot-hash collisions distinct. `DemandCacheKey::for_free_vars`
      and `DemandCacheKey::for_impure_input` construct both halves from their
      domain-separated preimages before demand-graph insertion, while the
      raw-parts test helper now accepts only these typed key-hash wrappers.
      This type-enforces the current demand-key hot/confirmation corridor only;
      it does not make demand keys durable addresses, implement the full
      persistent graph, or prove the full internal-hash leak invariant. Gates:
      `cache::key`, `cache::dcg` key-collision tests, and
      `ratchet-oracle`/`aos-nix`/`aos-nix-harness` test-target compile coverage
      (`S-15`).
- [x] Current nested-let free-variable narrowing precursor: the tree-walk
      force-cache free-variable collector now validates nested `let` binding
      keys as static as before, then computes a same-frame reachable binding
      slot set from the nested body and traverses only those binding values when
      constructing ordered free-variable value hashes. If the local scan reaches
      nested frame-producing syntax, recursive attrsets, invalid local slots, or
      child tables it cannot validate, it falls back to the prior
      all-static-binding traversal behavior, which may still reject subject
      construction for unsupported nested nodes. Dynamic nested binding keys
      still reject subject construction. This removes dead nested binding
      captures from the current demand key without changing the key combiner,
      value hashing, or persistence format; it is not the full strictness/escape
      free-variable set fact, broad demand-sensitive traversal for lazy
      attr/list/select/default positions, persistent graph integration, or the
      cached/uncached false-hit harness. Gates:
      `captured_nested_let_body_thunks_skip_dead_binding_free_variables`,
      `captured_nested_let_body_thunks_keep_transitive_live_binding_free_variables`,
      `captured_nested_let_body_thunks_drop_dead_transitive_binding_free_variables`,
      `captured_nested_let_body_thunks_fallback_to_prior_static_binding_traversal`,
      `captured_nested_let_body_thunks_hit_when_only_dead_outer_free_variables_change`,
      existing nested-let capture hit/miss tests, and the dynamic-key
      subject-rejection canary (`C-1`/`C-2`).
- [x] Current node-span force-cache identity precursor: source-backed and
      source-less node-thunk expression identities now fold the lowered node's
      source span into the durable expression-identity hash before pairing that
      hash with the existing `IrId` discriminator, and synthetic builtin-attr
      identities fold the lowered force-site span into their force-site
      `IrId`/symbol/execution identity. This moves the current
      identity shape toward the RFC `source content hash + IR node position` key
      while preserving the existing source-byte/lowered-IR fingerprint,
      path-literal-base and evaluator-option salt for node-thunk identities,
      synthetic builtin symbol/execution behavior, builtin-specific option
      salting, and ordered free-variable value-hash behavior. Full cache-key integration still
      requires canonical strictness/escape free-variable sets, real durable value
      hashes for all admitted values, persistent key compatibility decisions,
      and the cached/uncached false-hit harness. The gate covers source-backed
      same-`IrId` node-span force-cache identity and shared-runtime no-hit
      regressions, source-less fixed-module-hash identity separation plus
      span-mutated lowered-IR shared-runtime no-hit regression, and synthetic
      force-site span changes (`C-1`/`C-2`).
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
- [x] Current dirty pure inline-payload lifecycle precursor:
      reusable dependency-free pure inline payload lookups can now reconsider a
      dirty demand node against the side record's stored payload `ValueHash`,
      return the in-memory hit when the hash cuts off locally, clean the node,
      and let tree-walk account for the in-memory early cutoff without
      re-forcing the thunk body. Dirty pure nodes with dependencies remain
      misses until dependency hash snapshots or scheduler-owned recomputation
      can prove the payload. Pure payload observations also clear only the
      node's `ImpureInput` dependency group when replacing a prior trace-backed
      observation, while preserving `MemoRead` edges, so stale file/env leaves
      no longer dirty a now-pure expression. This is the pure reusable side
      record lifecycle only; evaluator-owned dirty-frontier scheduling, dynamic
      dependency capture for arbitrary computations, heap/composite canonical
      hashing beyond replayable payloads, persistence-wide graph serialization,
      and cached/uncached `.drv` parity proof remain open (`S-14`/`S-15`).
      Gates: dirty dependency-free pure inline payload cutoff runtime test,
      clean changed memo-supplier miss regression, pure-over-trace impure-edge
      clearing tests, trace-backed clean changed memo-supplier miss regression,
      and same-runtime source-backed force-cache early-cutoff integration test.
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
      ATerm/path side-payload hash; the side payload may also carry the
      already-computed `hashDerivationModulo`. Clean byte-return lookups
      return path bytes only for clean nodes whose side record still matches
      the caller's ATerm bytes and whose current graph hash still matches the
      recorded ATerm/path payload. The revalidating hit lookup additionally
      accepts dirty nodes when the current ATerm and recorded side-payload hash
      still match, runs graph reconsideration to clean unchanged nodes, and
      reports that reconsideration to callers; changed dirty records miss and
      remain dirty. Missing-key, missing-record, and disabled-runtime cases are
      misses. Hit variants return the supplying
      demand node for active memo-read observers while the existing wrappers
      keep returning only path bytes, and tree-walk can consume the optional
      modulo hash from the crate-private hit path. This cache-side in-memory
      storage/lookup substrate is now consumed by the later tree-walk cached
      `.drv` path reuse precursor for eligible derivations; runtime-level
      generic side-record persistence, broader dependency capture beyond active
      memo-read side-record hits, full SHA-256 store-path short-circuiting, and
      full cached/uncached `.drv` parity proof remain open (`S-14`/`S-15`). The
      gate includes optional-modulo payload round-trip,
      `eval_cache_derivation_aterm_path_hits_return_supplier_node_for_memo_read_edges`,
      dirty revalidation hit/miss tests, and
      `derivation_strict_revalidates_dirty_aterm_and_static_output_side_records`.
- [x] Current derivationStrict ATerm evaluator observation substrate:
      tree-walk `derivationStrict` observes recorded `.drv` ATerm bytes into
      the enabled `EvalCacheRuntime` after normal output path and `.drv` path
      computation, using a derivation-specific expression identity salted by
      module identity, source span, and hashable captured lexical free
      variables. Eligible direct final ATerm nodes open an active memo-read
      frame before evaluating the derivation argument expression, and
      first-class calls open the frame while processing the already-evaluated
      argument value and forcing derivation fields; successful completion
      replaces that node's `MemoRead` group with child expression nodes read
      during the evaluation and records the final ATerm node into any enclosing
      active frame, while failed derivations leave prior memo-read edges
      unchanged. In-memory and persistent derivation ATerm path hits plus
      static-output side-record hits return or seed runtime nodes so active
      observers can collect those side-record reads when they are actually
      used. Disabled runtimes, `with`/scoped-global environments, and
      unsupported captured values skip observation; repeated unchanged
      derivation ATerm/path payloads increment early-cutoff stats without
      counting cache hits or misses. This explicit observation path feeds the
      in-memory and persistent final-path precursors only: evaluator-owned
      recomputation scheduling, broader dynamic dependency capture beyond these
      active memo-read edges, full SHA-256 short-circuiting, and full
      cached/uncached `.drv` parity proof remain open (`S-14`/`S-15`). The gate
      includes tree-walk derivation ATerm cache-observation tests plus
      `derivation_strict_final_aterm_node_records_argument_memo_read_edges`,
      `derivation_strict_final_aterm_node_records_child_memo_read_edges`,
      `derivation_strict_final_aterm_node_records_static_output_path_hits`, and
      `derivation_strict_errors_preserve_prior_final_aterm_memo_read_edges`.
- [x] Current derivationStrict ATerm path-record writeback substrate:
      tree-walk `derivationStrict` writes the already-computed absolute `.drv`
      path bytes plus the known derivation hash modulo into the derivation ATerm
      cache side record through
      `EvalCacheRuntime::observe_derivation_aterm_expression_path`, after
      normal Nix-observed path computation has completed, when eval-cache
      observation is enabled and derivation ATerm subject capture, runtime
      locking, and serialization succeed. The later cached `.drv` path reuse
      precursor now consults this side record for eligible static, floating-CA,
      and impure derivations; floating-CA exact hits can replay the recorded
      modulo hash only when their input hash set has no deferred suppliers,
      while old/no-hash payloads, deferred-input hits, misses,
      deferred-placeholder `.drv` paths, and output path computation still use
      normal construction as needed. Dependency capture beyond hashable lexical
      captures, full SHA-256 store-path short-circuiting, and full
      cached/uncached `.drv` parity proof remain open (`S-14`/`S-15`).
- [x] Current derivationStrict cached `.drv` path reuse precursor:
      tree-walk `derivationStrict` recomputes final ATerm bytes for static,
      floating-CA, and impure derivations, probes the derivation ATerm path
      side record, validates that cached absolute path against the current
      configured store directory and expected `${name}.drv` basename, and
      reuses it instead of rebuilding the final `.drv` text path when the
      record matches. Floating-CA exact hits that carry a recorded modulo hash
      also skip `hashDerivationModulo` recomputation when the current input
      hash set has no deferred suppliers. Clean matches reuse directly; dirty
      same-value matches revalidate through graph reconsideration and clean the
      node, while the normal post-derivation ATerm observation remains the
      single early-cutoff accounting point for the final node. The reuse increments
      `derivation_aterm_path_reuses`, drives
      `derivation_text_path_calculations` to zero for matching root reuse
      tests, and
      leaves aggregate `cache_hits`/`cache_misses` and force-cache hit/miss
      accounting unchanged; accepted hits report their supplier node to
      enclosing active memo-read observers. Misses, stale or changed records,
      disabled runtimes, unsupported captured values, invalid cached paths,
      configured-store mismatches, wrong derivation names, and old/no-hash
      final-path payloads, and floating-CA hits with deferred inputs fall back
      to normal hash/path construction as needed. Static-output misses,
      deferred-placeholder derivations, broader dynamic
      dependency capture beyond active memo-read side-record hits, full
      derivationStrict-node SHA-256/store-path early cutoff, and
      full cached/uncached `.drv` parity proof remain open (`S-14`/`S-15`).
- [x] Current persistent derivationStrict `.drv` path side-record precursor:
      tree-walk `derivationStrict` materializes exact final ATerm/path side
      payloads, optionally including the known derivation hash modulo, into the
      persistent `values/` pack keyed from the same derivation expression
      identity and hashable lexical free-variable value hashes as the in-memory
      side record. Fresh runtimes can load the payload, verify that the blob
      hash equals the recorded side-payload value hash, require the persisted
      ATerm bytes to match the freshly recomputed ATerm, and reuse the final
      `.drv` path through the same store-dir/name validation as in-memory hits
      before seeding the runtime side record and reporting the seeded node to
      active memo-read observers. For new floating-CA payloads with no deferred
      input suppliers this skips both the final `.drv` text-path calculation
      and modulo-hash recomputation on exact ATerm matches; dirty-supplier
      rehydration rejection falls back to normal path calculation, clears the
      durable side-record link, and does not count an early cutoff. Final
      ATerm serialization, old/no-hash payloads, deferred-input floating-CA
      hash replay, deferred-placeholder derivations, broader dynamic
      dependency capture beyond active memo-read side-record hits, full
      derivationStrict-node SHA-256/store-path early cutoff, and full
      cached/uncached `.drv` parity proof remain open. Gates: persistent
      derivation ATerm path payload round-trip, fresh-runtime path/hash-reuse,
      and stale-ATerm mismatch, dirty-supplier, plus invalid-path fallback
      tests (`S-14`/`S-15`).
- [x] Current derivationStrict final ATerm byte plumbing precursor:
      when eligible static, floating-CA, and impure derivation path calculation
      already has final ATerm bytes for final-path side-record lookup or miss
      handling, tree-walk carries those bytes through
      `DerivationAtermPathCacheResult`, stores them in `KnownDerivation`,
      passes them to post-derivation ATerm side-record observation, and reuses
      them for derivation snapshots instead of serializing the same final ATerm
      again. Deferred-placeholder derivations and paths without precomputed
      final bytes still use the existing `known_derivation_aterm_bytes`
      fallback serialization. This removes duplicate serialization on the
      current eligible `derivationStrict` surfaces only; it does not return
      cached `.drv` paths without evaluating `derivationStrict`, widen
      side-record eligibility, implement SHA-256/store-path early cutoff, or
      prove full cached/uncached `.drv` parity. Gate:
      `derivation_strict_records_precomputed_final_aterm_bytes` plus focused
      derivation observation/path-cache suites (`S-14`/`S-15`).
- [x] Current static derivation output-path reuse precursor:
      tree-walk `derivationStrict` records a crate-private side payload for
      static derivations keyed by a separate input-hash-substituted pre-output
      ATerm identity, containing resolved output store paths plus the final
      derivation hash modulo. The demand-graph value hash for this side record
      binds the pre-output ATerm, output path payload, and final modulo hash,
      so changed payload observations propagate even when the pre-output ATerm
      key is unchanged. Later unchanged static derivations probe that record
      before calculating the derivation-modulo hash, validate that every cached
      output belongs to the
      current output set, is inside the configured store, and has the expected
      output basename, then restore output paths and skip the input-addressed
      output path computation plus both static-output modulo hash calculations.
      Accepted hits report their supplier node to enclosing active memo-read
      observers. Clean matches reuse directly; dirty same-value matches
      revalidate through graph reconsideration, clean the node, and increment
      early-cutoff stats after output-path validation. Reuse increments
      `static_derivation_output_path_reuses` but does not count as a generic
      force-cache hit; disabled runtimes, unsupported captured values, stale or
      changed records, invalid payloads, and output-set mismatches fall back to
      normal construction, and the revalidating lookup itself leaves changed
      dirty records dirty until normal observation updates them. Final ATerm
      serialization, deferred-placeholder derivations, broader dynamic
      dependency capture beyond active memo-read side-record hits, and full
      cached/uncached `.drv` parity proof remain open (`S-14`/`S-15`). The
      gate includes
      `eval_cache_static_output_path_hits_return_supplier_node_for_memo_read_edges`,
      dirty revalidation hit/miss tests, and tree-walk derivation
      path-reuse/hash-calculation tests.
- [x] Current persistent static derivation output-path side-record precursor:
      tree-walk `derivationStrict` materializes exact pre-output ATerm/static
      output side payloads into the persistent `values/` pack keyed from the
      static-output derivation expression identity and hashable lexical
      free-variable value hashes. Fresh runtimes can load the payload, verify
      that the blob hash equals the recorded side-payload value hash, require
      the persisted pre-output ATerm bytes to match the freshly recomputed
      pre-output ATerm, and reuse output paths only after the existing
      output-set, configured-store, output-basename, and duplicate-output
      validation succeeds, seeding the runtime side record and reporting the
      seeded node to active memo-read observers. This skips the static-output
      derivation hash/modulo work for exact pre-output matches;
      dirty-supplier rehydration rejection falls back to normal output hashing,
      clears the durable side-record link, and does not count an early cutoff.
      Final ATerm serialization, final `.drv` path construction when no
      final-path side record exists, deferred-placeholder derivations, broader
      dynamic dependency capture beyond active memo-read side-record hits, full
      derivationStrict-node SHA-256/store-path early cutoff, and full
      cached/uncached `.drv` parity proof remain open. Gates: persistent
      static-output payload round-trip, fresh-runtime reuse, stale-pre-output
      mismatch fallback, dirty-supplier fallback, and invalid-output-path
      fallback tests (`S-14`/`S-15`).
- [x] Current cached derivationStrict `.drv` surface parity canary:
      tree-walk tests compare cache-off, cache-on first-observation, and
      cache-on path-reuse runs for root static, floating-CA, and impure
      derivations, a static input-closure graph, a deferred-placeholder
      downstream graph, plus fresh-runtime persistent exact-ATerm final-path
      and exact-pre-output static-output hits, requiring identical recorded
      `.drv` paths and ATerm bytes across those runs. The static root case
      proves one static-output-path reuse before final `.drv` path reuse, zero
      derivation hash-boundary calculations, and zero final `.drv` text-path
      calculations on the clean reuse run. The no-deferred floating-CA root and
      persistent floating-CA cases prove final `.drv` path reuse can also replay
      the recorded modulo hash and skip hash-boundary calculations without
      static-output reuse. The deferred-input floating-CA case proves final path
      reuse still recomputes the modulo hash. The static/floating-CA/impure root
      cases prove final `.drv` path reuse skips final text-path calculation, and the static
      input-closure case proves two eligible input derivations reuse static
      output paths and final `.drv` paths while reducing derivation hash and
      text-path work without changing the downstream closure surface; the
      persistent static case proves a fresh runtime can skip static-output hash
      work and final text-path work together. This is selected in-memory and exact
      persistent reuse parity only; full-closure cached/uncached parity,
      dynamic dependency capture beyond hashable lexical captures, broader
      modulo-hash shortcuts, and full derivationStrict-node SHA-256/store-path
      early cutoff remain open
      (`S-14`/`S-15`).
- [x] Current native file-closure derivation side-record parity canary:
      `native_file_cache_parity_harness_covers_derivation_side_record_reuse`
      drives a three-derivation static input closure through the public
      `NixNative` file-closure path with eval cache disabled, cache-on
      miss/write, fresh cache-on reuse, fresh persistent-hit reuse, and
      cache-disabled-over-populated-persistent-root legs. It requires
      byte-identical `.drv` closures, proves the miss/write leg performs normal
      derivation hash and final text-path work without side-record reuse, proves
      the fresh cache-on and persistent-hit legs reuse exactly three
      static-output side records and three final ATerm path side records while
      performing zero derivation hash and final text-path calculations, and
      proves the cache-disabled leg reports no side-record reuse while leaving
      the populated persistent root unchanged. Source-edit side-record reuse is
      additionally sampled by the forced semantic-no-op leaf edit canary below.
      This is a public native API canary for the existing exact static
      side-record path only; dynamic dependency capture beyond hashable lexical
      captures, evaluator-owned dirty-frontier scheduling, transitive red/green
      propagation beyond the local dirty canary, broader modulo-hash shortcuts,
      full AOS package-set closure parity, and full derivationStrict-node
      SHA-256/store-path early cutoff remain open (`S-14`/`S-15`).
- [x] Current dirty derivation side-record revalidation canary:
      tree-walk tests dirty both the static-output side-record node and final
      ATerm path side-record node after a successful observation, then
      reevaluate the same derivation and require static-output reuse, final
      `.drv` path reuse, zero derivation hash-boundary calculations, zero
      final text-path calculations, clean graph nodes, unchanged `.drv`
      path/ATerm bytes, and exactly two early cutoffs. This proves local dirty
      same-value side-record revalidation for the selected static derivation
      path only; evaluator-owned dirty-frontier scheduling, transitive
      red/green propagation beyond the two side records, persistence-aware
      dirty revalidation, and full derivationStrict-node SHA-256/store-path
      early cutoff remain open (`S-14`/`S-15`). Gate:
      `derivation_strict_revalidates_dirty_aterm_and_static_output_side_records`.
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
- [x] Current dirty trace-backed force-payload revalidation precursor:
      in-memory force-cache lookup now revalidates trace-backed inline payload
      records even when their expression node is dirty, provided the retained
      impure-input identities and observation hashes still match and the node's
      stored value hash still equals the side payload hash. Same-value dirty
      hits clean the node through `DemandGraph::reconsider_node`, report the
      reconsideration on the payload hit, and tree-walk counts `CutOff` hits in
      `EvalStats::early_cutoffs`; changed, unavailable, or uncacheable inputs
      still invalidate the payload and miss, and dirty direct or transitive
      memo-read suppliers still block reuse. This is local dirty-node
      revalidation for trace-backed forced-expression payloads only;
      evaluator-owned dirty-frontier
      scheduling, transitive red/green propagation, persistence-aware dirty
      revalidation, canonical hashes for all values, and cached/uncached `.drv`
      parity proof remain open (`S-14`/`M-11`). Gates:
      dirty trace-backed inline-payload cache tests and
      `dirty_effectful_force_cache_hit_revalidates_and_counts_early_cutoff`.
- [x] Current persistent-hit force-payload early-cutoff accounting:
      fresh-runtime persistent force-cache hits now preserve the runtime
      payload-observation `Reconsideration` when seeding the in-memory demand
      graph, including pure empty-trace payloads and trace-backed payloads with
      revalidated impure-input leaves. If the durable hit rehydrates a dirty
      same-hash runtime node, tree-walk increments `EvalStats::early_cutoffs`
      just like an in-memory dirty hit; rejected dirty or unresolved supplier
      rehydrations remain misses and keep `early_cutoffs` at zero. This is
      accounting for persistent-hit runtime seeding only; evaluator-owned
      dirty-frontier scheduling, transitive red/green propagation, canonical
      hashes for all values, and cached/uncached `.drv` parity proof remain
      open (`S-14`/`M-11`). Gates:
      `dirty_persistent_pure_force_cache_hit_counts_early_cutoff` and
      `dirty_persistent_effectful_force_cache_hit_counts_early_cutoff`, plus
      persistent force-cache supplier-rejection tests.
- [ ] Full Salsa/red-green early cutoff remains: recompute demand-graph nodes,
      produce canonical value hashes, compare old/new hashes, stop propagation
      through dependents on no-change, and prove cached/uncached `.drv` parity.
- [x] Current value-consing precursor outside future `value/hashcons.rs`: the P1
      evaluator heap already conses heap strings, path values, list spines, and
      shape-aware flat attrsets in separate evaluator-local tables using
      `HotXxh3Hash` structural hashes plus equality confirmation. String/path
      consing preserves context-sensitive identity so identical bytes with
      different contexts do not collapse, list consing compares raw child
      `Value` identities, and attrset consing includes shape id, source/iteration
      order metadata, binding positions, and raw child `Value` identities.
      Lambdas, primops, and thunks remain deliberately uninterned and carry no
      stored structural hash, so closure environments, partial applications, and
      suspended work keep distinct identities. Covered by heap consing tests,
      including `lambdas_primops_and_thunks_are_not_hash_consed`. This
      is current heap-local consing, not generic post-force immutable-value
      hash-consing, maximal sharing across all values, O(1) equality for all
      values, durable value hashes, or field-load value-hash support.
- [x] Current force-capture value-hash field-load precursor: evaluator heap
      records now carry an optional cached `ValueHash` in the force-captured
      value domain, and the force-cache captured-free-variable key path consults
      and populates that field for heap strings, paths, replayable lists, and
      replayable attrsets after the existing canonical payload hash succeeds.
      Hash-consed heap records share the cached field, so repeated captures of
      the same consed value avoid recomputing the captured `ValueHash`.
      This is limited to the current tree-walk heap records and force-cache
      subject keying; it is not generic post-force immutable-value hash-consing,
      O(1) equality, persisted value hashes, demand-graph value-hash production,
      or full field-load value hashing for all values. Gates:
      `hash_consed_heap_records_share_cached_captured_value_hashes` and
      `materialized_capture_hashes_are_cached_on_heap_records`.
- [x] Current `value/hashcons.rs` admission precursor: `HashConsTable`
      exposes a collision-safe `try_get_or_reserve` operation for copyable
      runtime handles, returning either an equality-confirmed existing handle or
      a reserved insertion token; buckets track outstanding reservations so
      multiple unfilled slots for the same key remain capacity-backed, slot
      tokens are bound to their originating table, and callers can cancel vacant
      reservations after allocation failure. The tree-walk evaluator heap now
      routes string, path, list, and attrset consing through per-type
      `Existing`/`Vacant` admission helpers that preserve the old failure-side
      order of payload lookup, record-slot reservation, and then cons-table slot
      reservation, and cancel the vacant slot on later arena/value-construction
      failure while keeping xxh3 bucket lookup, payload equality confirmation,
      context-sensitive string/path identity, raw child-value list equality, and
      shape/position/order-aware attrset equality. Lambdas, primops, and thunks
      remain uninterned. This removes the previous caller-open-coded
      find/reserve result handling for current heap-local consing; it is not
      generic post-force immutable-value hash-consing, O(1) equality for all
      values, persisted value hashes, or demand-graph value-hash integration.
      Gates: `ratchet-value` hashcons admission/reservation tests and evaluator
      heap consing tests.
- [x] Current cached expression value-hash field-load precursor:
      `CachedExpressionValue` stores its canonical `ValueHash` at payload
      construction/decode time, including attr-position source envelopes, and
      in-memory force-cache side records replay values through constructors that
      restore the cached hash field. Demand graph observation and persistent
      materialization paths now read the cached payload hash instead of
      rehashing replayable cached-expression payloads. This covers current
      replayable force-cache payloads only; it is not generic post-force
      immutable-value hash-consing, O(1) equality for all values, persisted heap
      value hashes, or full demand-graph value-hash integration. Gates:
      cached-expression payload encoding tests and inline-payload record replay
      tests.
- [x] Current heap canonical value-hash field precursor: tree-walk heap records
      now carry a separate optional canonical `ValueHash` field, distinct from
      the existing force-capture identity hash field, and successful replayable
      payload extraction for heap strings, paths, lists, and attrsets stores the
      payload's canonical hash on the originating hash-consed heap record. The
      field is available after payload canonicalization, while current
      production use is limited to preserving an existing matching field and
      warning without overwrite on mismatches; it is not yet a demand-graph hash
      source. This is still scoped to current tree-walk heap records and
      replayable force-cache payload extraction; it is not generic post-force
      immutable-value hash-consing, O(1) equality for all values, persisted heap
      value hashes, or demand-graph value-hash production. Gates: evaluator heap
      value-hash cache tests and materialized capture payload-extraction cache
      tests.
- [x] Current heap value-hash insertion-contract precursor:
      `EvalHeap::cache_value_hash` now accepts only the first canonical
      `ValueHash` for a heap record or the same hash again, returning an
      explicit inserted/already-present status and rejecting mismatched hashes
      without mutating the record. Tree-walk payload extraction still
      field-checks before writes and warns without overwrite on mismatch. This
      hardens current-run heap value-hash storage only; it is not generic
      post-force immutable-value hash-consing, persisted heap hashes,
      demand-graph value-hash production, or full O(1) equality. Gates:
      evaluator heap mismatch tests and materialized payload stale-hash
      preservation tests.
- [ ] `value/hashcons.rs` — full hash-consing / maximal sharing of immutable
      values: generic post-force interning for composite values, O(1) equality,
      cached value hashes that make value-hashing a field load, and integration
      with the demand graph/early cutoff (`S-7`).
- [x] Current hash-routing and typed-domain precursor in `cache/hashing.rs`:
      evaluator-local string/path/list/attrset cons tables use xxh3 structural
      hashes with equality confirmation and are typed as `HotXxh3Hash`; durable
      frontend parse-cache keys use BLAKE3 over source bytes plus schema/flags,
      with file memo keys pairing canonical realpath and BLAKE3(file bytes), and
      are typed as `DurableBlake3Hash`; Nix-observed `.drv`/store-path surfaces
      use SHA-256 and hash/fetch builtins use their requested Nix hash APIs
      rather than evaluator-local xxh3/BLAKE3 digests. This is the current substrate
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
- [x] Current hash/fetch/source-path cache-surface canaries:
      `configured_import_cache_preserves_hash_builtin_surface` evaluates
      `builtins.hashString "sha256" (import file)` with import caching disabled,
      with configured parse/persist roots on a miss/write path, and with a later
      persistent-hit path, then mutates the imported source and requires the
      changed source to produce the changed cache-disabled SHA-256 hash-string
      output through a fresh content-addressed miss/write path and a later
      persistent-hit path. It scans all original and changed hashString outputs
      for selected root/import parse-cache BLAKE3, file-content BLAKE3, and hot
      xxh3 canaries.
      `configured_import_cache_preserves_convert_hash_surface` evaluates
      `builtins.convertHash (import file)` over an imported typed hash and
      output format with import caching disabled, with configured parse/persist
      roots on a miss/write path, and with a later persistent-hit path, requires
      identical converted Nix hash-string outputs across all three runs, and
      scans those convertHash outputs for root/import parse-cache BLAKE3,
      imported-file content BLAKE3, imported-hash and decoded-digest BLAKE3,
      and hot xxh3 canaries.
      `configured_cache_preserves_guarded_hash_file_surface` evaluates
      `builtins.hashFile "sha256" ./payload.txt` behind a forced
      `builtins.pathExists ./marker` guard with eval-cache disabled, with
      configured persistent force-cache demand/writeback on cold and
      materializing paths, and with a fresh-runtime persistent force-cache hit
      for the guarded hashFile trace, then mutates the hashed payload and
      requires stale persistent fallback to produce the changed cache-disabled
      SHA-256 file-hash output before a fresh-runtime post-recompute hit. It
      scans both original and changed outputs for synthetic root
      parse-cache-key and payload-content BLAKE3 sentinels, actual
      guard/hashFile persistent force-cache trace/value canaries, and hot xxh3
      canaries. `configured_import_cache_preserves_fetchurl_store_path_surface`
      evaluates `builtins.fetchurl (import file)` over a local `file://`
      fixed-output fetch with import caching disabled, with configured
      parse/persist roots on a miss/write path, and with a later persistent-hit
      path, requires identical returned store-path strings across all three
      runs, and scans those fetchurl surfaces for root/import parse-cache
      BLAKE3, imported-file content BLAKE3, a fetched-payload BLAKE3 sentinel,
      and hot xxh3 canaries.
      `configured_import_cache_preserves_fetch_tarball_store_path_surface`
      evaluates `builtins.fetchTarball (import file)` over a local `file://`
      fixed-output tarball with import caching disabled, with configured
      parse/persist roots on a miss/write path, and with a later persistent-hit
      path, requires identical returned store-path strings across all three
      runs, checks the unpacked tree materializes, and scans those fetchTarball
      surfaces for root/import parse-cache BLAKE3, imported-file content BLAKE3,
      an archive-bytes BLAKE3 sentinel, and hot xxh3 canaries.
      `configured_import_cache_preserves_fetch_git_store_path_surface`
      evaluates `builtins.fetchGit (import file)` over a local fixed-revision
      `file://` git repository with import caching disabled, with configured
      parse/persist roots on a miss/write path, and with a later persistent-hit
      path, requires identical returned store-path strings across all three
      runs, checks the checkout materializes, and scans those fetchGit surfaces
      for root/import parse-cache BLAKE3, imported-file content BLAKE3, a
      worktree-payload BLAKE3 sentinel, and hot xxh3 canaries.
      `configured_import_cache_preserves_fetch_tree_path_store_path_surface`
      evaluates path-form `builtins.fetchTree` over a local tree path imported
      from a file with import caching disabled, with configured parse/persist
      roots on a miss/write path, and with a later persistent-hit path, requires
      identical returned `outPath` strings across all three runs, checks the
      store tree materializes, and scans those fetchTree path surfaces for
      root/import parse-cache BLAKE3, imported-file content BLAKE3,
      tree-payload BLAKE3 sentinels, and hot xxh3 canaries.
      `configured_import_cache_preserves_path_store_path_surface` evaluates
      `builtins.path (import file)` over a local flat fixed-output path with
      import caching disabled, with configured parse/persist roots on a
      miss/write path, and with a later persistent-hit path, requires identical
      returned store-path strings across all three runs, and scans those path
      surfaces for root/import parse-cache BLAKE3, imported-file content BLAKE3,
      a payload BLAKE3 sentinel, and hot xxh3 canaries.
      `configured_import_cache_preserves_find_file_path_store_path_surface`
      evaluates `builtins.path` over a path resolved by `builtins.findFile`
      from imported search-root/prefix/lookup/name files with import caching
      disabled, with configured parse/persist roots on a miss/write path, and
      with a later persistent-hit path, requires identical returned store-path
      strings across all three runs, and scans those findFile-fed path surfaces
      for root/search-root/prefix/lookup/name parse-cache BLAKE3, imported-file
      content BLAKE3, source-tree payload BLAKE3 sentinels, and hot xxh3
      canaries.
      `configured_import_cache_preserves_filter_source_store_path_surface`
      evaluates `builtins.filterSource` over a local tree path imported from a
      file with import caching disabled, with configured parse/persist roots on
      a miss/write path, and with a later persistent-hit path, requires
      identical filtered store-path strings across all three runs, requires that
      surface to differ from the unfiltered `builtins.path` surface, and scans
      those filterSource surfaces for root/import parse-cache BLAKE3,
      imported-file content BLAKE3, included/excluded file-content BLAKE3
      sentinels, and hot xxh3 canaries.
      `configured_import_cache_preserves_to_file_store_path_surface` evaluates
      `builtins.toFile (import nameFile) (import contentsFile)` with import
      caching disabled, with configured parse/persist roots on a miss/write
      path, and with a later persistent-hit path, requires identical text-store
      path strings across all three runs, and scans those toFile surfaces for
      root/name/content parse-cache BLAKE3, imported-file content BLAKE3, a
      toFile body BLAKE3 sentinel, and hot xxh3 canaries. These sample selected
      `hashString`/`convertHash`/`hashFile`/`fetchurl`/`fetchTarball`/
      `fetchGit`/`fetchTree`/`builtins.path`/`findFile`/`filterSource`/`toFile`
      output surfaces only; they do not prove the full hash/fetch/source/text-path
      leak-invariant gate (`S-15`).
- [x] Current derivation modulo SHA-256 type boundary: `cache::hashing` exposes
      `NixSha256Digest` as the typed Nix-observed SHA-256 domain, distinct from
      `HotXxh3Hash` and `DurableBlake3Hash`; `DerivationHashModulo` wraps that
      type behind named constructors/accessors instead of exposing raw
      `[u8; 32]`; and derivation ATerm/static-output side-record APIs carry
      `NixSha256Digest` for replayed `hashDerivationModulo` bytes while keeping
      BLAKE3 `ValueHash` for side-payload cache identity. The persistent
      side-payload format remains byte-compatible, but fresh SHA-256 computation
      and persistent decode are the explicit raw-bytes-to-Nix-SHA crossings,
      while output-path/ATerm serialization extracts bytes through named Nix SHA
      accessors. This type-enforces the current derivation side-record modulo
      path only; other store-path/hash builtin SHA-256 preimages and the full
      differential `.drv` harness remain open (`S-15`).
- [x] Current derivation side-payload value hash boundary:
      `DerivationSidePayloadValueHash` now marks BLAKE3 side-record payload
      hashes for cached final ATerm path payloads and static derivation output
      path payloads. `CachedDerivationOutputPaths::value_hash` and final
      ATerm path payload hashing finalize through this type before
      `ValueHash::from_derivation_side_payload_hash` adapts them into graph
      material, while derivation ATerm input comparison still uses
      `ValueHash::from_derivation_aterm_bytes` and Nix-observed modulo/path
      hashing still uses `NixSha256Digest`. This type-enforces the current
      derivation side-payload BLAKE3 finalization corridor only; generic
      canonical value-hash serialization, persistent graph serialization, and
      the full differential `.drv` harness remain open (`S-15`). Gate:
      `derivation_payload`, derivation side-record runtime tests, derivation
      path-reuse surface tests, and
      `internal_cache_hash_canaries_do_not_reach_drv_surfaces`.
- [x] Current cached-expression payload value hash boundary:
      `CachedExpressionPayloadValueHash` now marks BLAKE3 value hashes for
      canonical `CachedExpressionValue` persistent payload bytes, including
      source-provenance envelopes for positioned attrsets.
      `InlineValuePayload::value_hash_from_persistent_payload`,
      `CachedExpressionValue::value_hash_for_attr_position_source`, and the
      precomputed empty-list/empty-attrset const hashes finalize through this
      type before `ValueHash::from_cached_expression_payload_hash` adapts them
      into graph and value-blob material. This type-enforces current
      cached-expression payload BLAKE3 finalization only; the general canonical
      value serializer, broader value-store hashing, persistent graph
      serialization, and the full differential `.drv` harness remain open
      (`S-15`). Gate: inline-payload encoding tests, cached-expression
      materialization and payload rehydration tests, positioned-payload tests,
      and `ratchet-oracle`/`aos-nix`/`aos-nix-harness` test-target compile
      coverage.
- [x] Current store-path SHA-256 preimage type boundary: derivation, text,
      fixed-output, and source store-path constructors now carry
      `NixSha256Digest` through `build_store_path_from_fingerprint_parts`,
      `store_path_bytes_from_fingerprint_parts`, `fixed_output_path_digest`,
      `flat_source_fixed_output_digest`, `build_ca_path`, and the helper that
      hashes Nix-observed SHA-256 preimages. Raw `[u8; 32]` values still enter
      at existing Nix API edges such as decoded expected hashes and
      `nix_compat` `CAHash` variants, but those
      call sites convert explicitly to `NixSha256Digest` before store-path
      fingerprint construction; mismatch/error surfaces still report the same
      raw digest bytes. This type-enforces selected current store-path
      construction helpers only; hash builtin outputs, every source/fetch
      variant, and the full differential leak-invariant harness remain open
      (`S-15`).
- [x] Current fetch expected-SHA type boundary: decoded `builtins.fetchurl` and
      `builtins.fetchTarball` `sha256` arguments, including empty placeholder
      hashes, now become `NixSha256Digest` at argument parsing; their store-path
      construction helpers require that typed digest, and fetchTarball
      existing-store validation plus fetch mismatch diagnostics unwrap only at
      the Nix validation or error-reporting edge. This type-enforces the
      current fixed `sha256` fetch argument path only; `builtins.path` expected
      hashes, hash builtin outputs/conversions, other source/fetch variants, and
      the full differential leak-invariant harness remain open (`S-15`). Gate:
      fetchurl/fetchTarball store-path surface canaries and fetch hash mismatch
      tests.
- [x] Current `builtins.path` expected-SHA type boundary: decoded
      `builtins.path { sha256 = ...; }` arguments now become `NixSha256Digest`
      before entering the shared source-path store-string helpers; recursive and
      flat source hashing return typed Nix SHA-256 digests, compare through that
      typed boundary for mismatch diagnostics, and continue to typed store-path
      fingerprint construction. This type-enforces the current
      `builtins.path` expected-hash corridor only; hash builtin
      outputs/conversions, other source/fetch variants, and the full
      differential leak-invariant harness remain open (`S-15`). Gate:
      `path_primop_supports_flat_hashing_and_sha256_checks`,
      `source_path_sha_helpers_return_nix_sha256_digests`, and path store-path
      surface canary.
- [x] Current `fetchTree`/`fetchGit` NAR SHA-256 type boundary: decoded
      `builtins.fetchTree` `narHash` locks from attrsets and flake refs now
      become `NixSha256Digest` at argument parsing, and computed recursive NAR
      SHA-256 bytes for `fetchTree` and `fetchGit` are wrapped before
      store-path construction or existing-store validation. SRI `narHash`
      rendering and mismatch diagnostics still unwrap through named SHA-256
      accessors at the Nix-observed output/error boundary. This type-enforces
      the current fetchTree/fetchGit NAR-store corridor only; hash builtin
      outputs/conversions, other source/fetch variants, and the full
      differential leak-invariant harness remain open (`S-15`). Gate:
      fetchTree/fetchGit store-path surface canaries and fetchTree hash
      mismatch tests.
- [x] Current source/fetch payload SHA-256 helper boundary:
      `TreeWalk::source_path_nar_sha256` and
      `TreeWalk::source_path_flat_sha256` now return `NixSha256Digest`
      directly, current fetchTarball/fetchTree/fetchGit source digest callers
      carry that type through expected-hash comparison, SRI narHash rendering,
      store-path construction, existing-store validation, and mismatch
      diagnostics, and `builtins.fetchurl` wraps downloaded payload SHA-256
      bytes with `NixSha256Digest` before expected-hash comparison or
      store-path construction. The raw bytes are still produced at the local
      SHA-256 computation point and unwrapped at Nix-observed diagnostic or
      encoding edges. This tightens the selected current source/fetch SHA
      corridor only; hash builtin outputs/conversions, other non-hash Nix byte
      surfaces, and the full differential leak-invariant harness remain open
      (`S-15`). Gate: `source_path_sha_helpers_return_nix_sha256_digests` plus
      existing fetchurl/source/fetch store-path and mismatch tests.
- [x] Current placeholder/input-hash SHA-256 type boundary:
      `builtins.placeholder`, derivation output placeholders, and deferred
      downstream output placeholders now compute Nix-observed SHA-256 through
      `NixSha256Digest` before slash-prefixed Nix-base32 rendering, and
      derivation input-hash replacement maps now key by `NixSha256Digest`
      until the ATerm writers unwrap through named SHA accessors for lower-hex
      serialization. This type-enforces the selected placeholder and
      derivation input-hash replacement corridor only; other non-hash Nix byte
      surfaces and the full differential leak-invariant harness remain open
      (`S-15`). Gate: `placeholder_primop_matches_cpp_nix_hash_scheme`,
      `derivation_strict_unions_input_hash_replacement_outputs`, and
      exact ATerm byte fixtures
      `derivation_strict_input_hash_replacements_serialize_exact_aterm_order`
      and `floating_ca_input_hash_replacements_serialize_exact_aterm_order`.
- [x] Current hash builtin/conversion Nix digest type boundary:
      `NixHashDigest` carries a `HashStringAlgorithm` with validated digest
      bytes for `hashString`, `hashFile`, and `convertHash` decode/encode
      flows. `decode_convert_hash`, `decode_hash_payload`,
      `decode_sri_hash_payload`, `hash_bytes`, `alloc_hash_digest`, and
      `encode_convert_hash_digest` now traffic in that typed Nix-observed hash
      domain instead of naked digest vectors, while SHA-256-only fetch/path
      callers explicitly extract `NixSha256Digest` before store-path
      construction. This type-enforces the current hash builtin and conversion
      corridor only; other source/fetch variants, non-hash Nix byte surfaces,
      and the full differential leak-invariant harness remain open (`S-15`).
      Gate: `op_types` hash-domain tests plus hashString/hashFile/convertHash
      behavior and cache-surface canaries.
- [x] Current persistent `files/` blob key hash boundary:
      `PersistFileBlobHash` now marks payload addresses stored in the persistent
      `files/` blob pack. Production file/parse artifact materialization computes
      this type from artifact payload bytes, `PersistBlobKey::for_file` requires it,
      and file/parse artifact index values store and return it while decoded
      persisted `files/` blob-key bytes cross through an explicit wrapper. This
      type-enforces the current frontend artifact blob corridor only; full
      cache-value hashing and the full differential leak-invariant harness
      remain open (`S-15`). Gate:
      `format_tests`, `blob_sidecars`, `file_artifact_materialization`,
      `file_artifact_hydration`, `parse_artifact_entry_materialization`,
      `cache_io_tests`, plus `ratchet-oracle` and `aos-nix-harness` test-target
      checks.
- [x] Current parse file-content memo hash boundary:
      `ParseFileContentHash` now marks source bytes read into `ParseFileKey`
      realpath/content memo keys. `ParseFileKey::for_source` computes this type,
      `ParseFileKey::new` requires it, and
      `PersistFileArtifactKey::for_realpath_bytes` consumes it before unwrapping
      only at the stable persisted-index preimage. Existing leak-canary tests
      unwrap with `ParseFileContentHash::as_durable_hash()` only where they scan
      `.drv` surfaces for raw internal BLAKE3 renderings. This type-enforces the
      current parse-file realpath/content memo corridor only; full cache-value
      hashing and the full differential leak-invariant harness remain open
      (`S-15`). Gate:
      `parse_file_content_hash_wraps_source_bytes`, `cache::parse`,
      `format_tests`, and `ratchet-oracle` test-target compile coverage.
- [x] Current lowered-IR artifact fingerprint hash boundary:
      `LoweredIrFingerprint` now marks the stable `ir.bin`/`symbols.bin`
      artifact digest used for source-less module identities and optional
      `facts.bin` sidecar validation. `lowered_ir_fingerprint`,
      `lowered_ir_artifact_fingerprint`, `encode_ir_facts`, and
      `decode_ir_facts` traffic in that type, unwrapping only when framing the
      fact artifact bytes or feeding the source-less module identity hasher.
      This type-enforces the current lowered-IR artifact fingerprint corridor
      only; full cache-value hashing and the full differential leak-invariant
      harness remain open (`S-15`). Gate:
      `lowered_ir` tests and `ratchet-oracle` test-target compile coverage.
- [x] Current parse-cache source key hash boundary:
      `ParseCacheSourceHash` now marks source-byte digests that back
      `ParseCacheKey`. `ParseCacheKey::for_source` computes this typed domain,
      cache-entry path selection uses the explicitly named
      `ParseCacheKey::cache_dir_name`, persistent parse-artifact and
      file-artifact index preimages consume `ParseCacheKey::as_durable_hash()`
      only at disk-format boundaries, and leak-canary tests unwrap through the
      same typed accessor only where they scan `.drv` surfaces for raw internal
      BLAKE3 renderings. This type-enforces the current parse-cache source
      artifact key corridor only; full cache-value hashing and the full
      differential leak-invariant harness remain open (`S-15`). Gate:
      `cache::parse`, `format_tests`, and `ratchet-oracle`/`aos-nix`
      test-target compile coverage.
- [x] Current impure-input observation hash boundary:
      `ImpureInputObservationHash` now marks observed filesystem/environment
      result hashes for cacheable impure inputs. Operation-specific
      `ImpureInputFingerprint` constructors compute this type,
      `CacheableInputFingerprint` stores and returns it, and
      `ValueHash::from_impure_input_observation_hash` requires it before early
      cutoff or demand-graph consumers can treat an observation as a value leaf.
      Persistent node-trace payload encoding unwraps only at the wire-format
      byte boundary, while `CacheableInputFingerprint::from_observation_hash`
      remains the explicit persisted-parts boundary for decoded traces and
      format fixtures. This type-enforces the current observation-hash corridor
      only; the full differential leak-invariant harness remains open (`S-15`).
      Gate:
      `cache::input`, `cache::cutoff`, `cache::dcg::tests::impure_input`,
      `format_tests`, and `ratchet-oracle`/`aos-nix`/`aos-nix-harness`
      test-target compile coverage.
- [x] Current impure-input identity hash boundary:
      `ImpureInputIdentityHash` now marks domain-versioned impure-input
      identity hashes over kind, mode, and subject bytes. `ImpureInputIdentity`
      stores and returns this type, while `DemandCacheKey::for_impure_input`
      and `PersistNodeMetadataKey::for_impure_input` require it before using
      identity bytes in hot-key, confirmation-hash, or persistent metadata-key
      preimages. Synthetic low-level persistence fixtures wrap arbitrary bytes
      through explicit test helpers, and leak-canary scanners unwrap through
      `ImpureInputIdentityHash::as_durable_hash()` only where they scan `.drv`
      surfaces for raw internal BLAKE3 renderings. This type-enforces the
      current impure-input identity corridor only; the full differential
      leak-invariant harness remains open (`S-15`). Gate: `cache::input`,
      `cache::key`, `cache::dcg::tests::impure_input`, `format_tests`,
      `node_metadata`, and `ratchet-oracle`/`aos-nix`/`aos-nix-harness`
      test-target compile coverage.
- [x] Current cache expression source hash boundary:
      `CacheExprSourceHash` now marks the source/artifact component of
      `CacheExprIdentity`. Production tree-walk constructors compute this type
      from domain-separated expression, first-class primop call, derivation,
      synthetic builtin-attr, and synthetic select identity preimages, while
      `CacheExprIdentity::new`
      requires it before demand keys, value-hash confirmation keys, or
      persistent node-metadata keys can consume expression identity source
      bytes. Persistent-key and demand-key preimages unwrap through
      `CacheExprSourceHash::as_durable_hash()` only at those stable byte-format
      boundaries, and synthetic fixtures wrap arbitrary bytes through explicit
      test helpers. This type-enforces the current expression-source identity
      corridor only; positioned payload provenance hashes, remaining generic
      durable hash plumbing, and the full differential leak-invariant harness
      remain open (`S-15`). Gate: `cache::key`, `cache::dcg`,
      `cache::runtime`, `format_tests`, `node_metadata`, and
      `ratchet-oracle`/`aos-nix`/`aos-nix-harness` test-target compile
      coverage.
- [x] Current positioned-payload source provenance hash boundary:
      `AttrPositionSourceHash` now marks the module/source identity attached to
      persistent position-bearing attrset payload envelopes. Tree-walk replay
      preparation wraps the module identity hash only when a payload retains
      binding positions, cached payload records keep that typed provenance
      through in-memory observation and replay, persistent payload decoding
      wraps envelope bytes at the format boundary, and payload value-hash and
      wire encoders unwrap only when framing the stable
      `attrs-position-source-v1` byte preimage. This type-enforces the current
      position-bearing payload replay-provenance corridor only; positioned
      capture value-hash salting, remaining generic durable hash plumbing, and
      the full differential leak-invariant harness remain open (`S-15`). Gate:
      `cache::runtime`, positioned payload force-cache tests, and
      `ratchet-oracle`/`aos-nix`/`aos-nix-harness` test-target compile
      coverage.
- [x] Current positioned-capture source salt hash boundary:
      `ForceCapturePositionSourceHash` now marks the module/source identity
      hashes salted into `FORCE_CAPTURED_VALUE_HASH_DOMAIN_VERSION` for
      position-bearing captured composite payloads. Captured composite hashing
      wraps each retained binding-position module identity before salting the
      force-captured value-hash preimage, and unwraps only when appending the
      stable capture-preimage bytes. This type-enforces the current positioned
      capture salt corridor only; broader capture value-hash typing, remaining
      generic durable hash plumbing, and the full differential leak-invariant
      harness remain open (`S-15`). Gate: `materialized_captures`, captured
      positioned-composite force-cache tests, and
      `ratchet-oracle`/`aos-nix`/`aos-nix-harness` test-target compile
      coverage.
- [x] Current static-select binding position hash boundary:
      `StaticSelectPositionHash` now marks the source-name/module and span
      identity for retained binding positions that participate in static-select
      captured-value projections. Static-select projection construction wraps
      each selected binding position identity before sorting/deduplicating the
      projection set, and unwraps only when appending those identities to the
      stable `static-select` captured-value preimage. This type-enforces the
      current selected-binding position projection corridor only; remaining
      force-captured value-hash finalization, generic durable hash plumbing, and
      the full differential leak-invariant harness remain open (`S-15`). Gate:
      `captured_static_selects_miss_when_selected_binding_position_changes`,
      captured static-select projection tests, captured positioned-composite
      force-cache tests, and `ratchet-oracle`/`aos-nix`/`aos-nix-harness`
      test-target compile coverage.
- [x] Current force-captured value hash boundary:
      `ForceCapturedValueHash` now marks durable digests finalized under
      `FORCE_CAPTURED_VALUE_HASH_DOMAIN_VERSION` before they enter shared
      `ValueHash` key material. Tree-walk string/path/composite
      captured-free-variable hashing, static-select projection and default
      branch hashes, static-has-attr result hashes, replayed payload
      free-variable hashes, and synthetic visible `nixPath` argument hashing
      finalize through this type, while
      `ValueHash::from_force_captured_value_hash` is the only conversion for
      force-captured BLAKE3 digests into demand-key material. This
      type-enforces the current force-cache free-variable fingerprint
      finalization corridor only; canonical value-hash serialization,
      remaining generic durable hash plumbing, and the full differential
      leak-invariant harness remain open (`S-15`). Gate: `captured_scalars`,
      `materialized_captures`, captured static-select / default / has-attr
      force-cache tests, and
      `ratchet-oracle`/`aos-nix`/`aos-nix-harness` test-target compile
      coverage.
- [x] Current demand-cache key hash boundary:
      `DemandKeyHotHash` marks the in-process xxh3 probe for `DemandCacheKey`,
      and `DemandKeyConfirmationHash` marks the BLAKE3 confirmation digest that
      keeps same-hot-hash collisions distinct. `DemandCacheKey::for_free_vars`
      and `DemandCacheKey::for_impure_input` construct both halves from their
      domain-separated preimages before demand-graph insertion, while the
      raw-parts test helper now accepts only these typed key-hash wrappers.
      This type-enforces the current demand-key hot/confirmation corridor only;
      it does not make demand keys durable addresses, implement the full
      persistent graph, or prove the full differential leak-invariant harness.
      Gate: `cache::key`, `cache::dcg` key-collision tests, and
      `ratchet-oracle`/`aos-nix`/`aos-nix-harness` test-target compile coverage
      (`S-15`).
- [x] Current persistent node metadata key hash boundary:
      `PersistNodeMetadataKeyHash` marks BLAKE3 keys for durable demand-node
      metadata and trace sidecar records. `PersistNodeMetadataKey::for_expression`,
      `PersistNodeMetadataKey::for_impure_input`, and
      `PersistNodeMetadataKey::decode_index_bytes` construct or decode the
      typed key hash, while `PersistNodeMetadataKey::hash` preserves the
      existing raw durable-hash inspection accessor and
      `PersistNodeMetadataKey::index_bytes` unwraps at the stable sidecar and
      engine key boundary. This type-enforces current persistent node
      metadata/trace key finalization and decoding only; persisted value-hash
      fields, full graph persistence, LMDB/redb indexes, and the full
      differential leak-invariant harness remain open. Gate: `cache::hashing`,
      node metadata/trace format tests, persistent force-cache
      demand/materialization tests, and
      `ratchet-oracle`/`aos-nix`/`aos-nix-harness` test-target compile coverage
      (`S-15`).
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
- [x] Current blob pack append/validation substrate: `PersistBlobPack`
      initializes headers without replacing corrupt non-empty files, appends
      only payloads matching the caller's `DurableBlake3Hash`, returns record
      offsets plus lengths. Length reads, owned direct payload reads,
      metadata-only payload-window validation, record scans, payload
      verification, payload comparisons, raw lower-level relocation copies, and
      cache-level repack copies now route through the scoped mmap row below.
      This is ordinary `std::fs` append plus mapped validation only;
      LMDB/redb index integration, batched writing, crash-durability policy,
      GC/repack, Attic transport, and harness proof remain open (`C-13`).
- [x] Current `ratchet-cache` unsafe crate and mmap primitive:
      `ratchet-cache` now exists as the RFC engine-band unsafe crate with
      `#![deny(unsafe_op_in_unsafe_fn)]`, and `store::ReadOnlyMmap` wraps Unix
      read-only `mmap` behind an explicitly unsafe constructor, documented file
      immutability contract, and `// SAFETY:` comments for every unsafe block.
      `ratchet-oracle` does not call this primitive directly. This is the
      unsafe fence and raw mapping substrate only; full durable lease protocol,
      LMDB/redb metadata, full mmap
      maintenance/repack paths, out-of-core value rematerialization,
      cross-process writer coordination, and harness proof remain open
      (`C-13`/`R-14`).
- [x] Current `ratchet-cache` mmap blob-pack payload reader:
      `blob_pack::MappedBlobPack` validates the current pack header and record
      format from a `ReadOnlyMmap`, checks lookup hash/length and payload
      bounds, exposes metadata-only `payload_window` validation without hashing
      payload bytes, rehashes mapped payload bytes with BLAKE3 for full
      `payload` reads, and returns `MappedBlobPayload<'_>` as a borrowed
      zero-copy slice. Unit coverage includes generated packs, a
      metadata-window corrupt-payload canary, and a frozen literal
      `AOS-NIX-BLOBPACK` empty-payload fixture that pins magic/version/header-length,
      record hash, and little-endian payload length bytes. This covers the
      current compatibility format inside the unsafe engine crate only;
      construction remains `unsafe`, and safe oracle integration is covered by
      the scoped mmap adapter below. LMDB/redb offset indexes, out-of-core
      rematerialization, cross-process writer coordination, and harness proof
      remain open (`C-13`/`R-14`).
- [x] Current lease-shaped mmap blob-pack API:
      `blob_pack::BlobPackReadLease` is an unsafe-to-implement trait whose
      `covers_file` contract states that a file is immutable for the borrowed
      lease lifetime, and `MappedBlobPack::map_file_with_lease` returns
      `LeasedMappedBlobPack<'lease>` so mapped payload borrows cannot outlive
      that lease. Tests cover accepted leases and rejected non-covering leases.
      A compile-fail rustdoc canary proves a leased mapping cannot escape a
      stack lease as `'static`.
      This is the generic type-boundary substrate; the current advisory-lock
      implementation and scoped oracle adapters are covered below, while
      cross-process/durable filesystem lease hardening, append-writer
      migration, LMDB/redb offset indexes, out-of-core rematerialization, and
      full harness proof remain open (`C-13`/`R-14`).
- [x] Current oracle-writer/mapped-reader compatibility canary:
      `aos-nix-harness` has an integration test that writes blob-pack records
      through the existing safe `ratchet-oracle::cache::PersistBlobPack`
      writer, maps the resulting file through
      `ratchet-cache::blob_pack::MappedBlobPack`, and verifies the borrowed
      mapped payload slices match the original bytes. The unsafe mmap call
      stays in harness test code rather than the safe oracle crate. This is
      format compatibility coverage only; LMDB/redb offset indexes, out-of-core
      rematerialization, cross-process writer coordination, and harness proof
      remain open (`C-13`/`R-14`).
- [x] Current scoped oracle mmap read adapter:
      `ratchet-cache::blob_pack::BlobPackFileReadLease` ties
      `MappedBlobPack::map_file_with_lease` to a shared lock on the pack
      descriptor plus descriptor identity check, while safe `ratchet-cache`
      pack initialization, append, and tail-trim paths acquire the
      corresponding exclusive descriptor lock.
      `ratchet-oracle::cache::PersistBlobPack::len` opens, leases, maps,
      validates the header, and returns the mapped file length through the
      scoped adapter.
      `ratchet-oracle::cache::PersistBlobPack::with_blob` and
      `with_mapped_blob` open, lease, map, verify, and visit payload bytes inside
      a callback so borrowed mmap bytes never escape `ratchet-oracle`'s safe
      API. `PersistBlobPack::read_blob` remains an owned-byte wrapper around
      that lower-level visitor. `PersistBlobPack::payload_window` validates
      metadata-only payload windows through scoped mappings without hashing
      payload bytes. `PersistBlobPack::records` and `with_mapped_records`
      perform verified pack-record metadata scans through scoped mappings, while
      `PersistBlobPack::verify_blob` and `payload_matches` verify payloads
      through scoped mappings and return only owned payload-window metadata or
      booleans.
      `PersistCache::with_blob` and `PersistCache::with_blob_indexed` expose
      public callback-scoped borrowed payload visits through that scoped mapped
      callback, while `PersistCache::read_blob` and
      `PersistCache::read_blob_indexed` remain owned-byte wrappers;
      `PersistCache::with_cached_expression_value_indexed` decodes and rehashes
      cached-expression values through the scoped mapped callback before
      visiting the decoded value after the value-store locks are released, while
      `load_cached_expression_value_indexed` remains an owned decoded-value
      wrapper; `PersistCache::with_cached_expression_node_value_indexed` and
      `with_cached_expression_node_value_with_trace_revalidation` visit decoded
      node-linked cached-expression values and trace-revalidated cached-expression
      values plus memo-read dependency keys after node metadata, trace, mapped
      value payload, and value-store locks are released,
      while their load counterparts remain owned decoded-value wrappers;
      `PersistCache::with_file_artifact_bundle` and
      `PersistCache::with_parse_artifact_bundle` decode and validate
      parse-artifact bundles through the scoped mapped callback before visiting
      the decoded bundle after the files-store locks are released, while raw
      file/parse artifact reads remain owned-byte wrappers;
      direct/keyed/entry-shaped file-artifact hydration, and
      direct/keyed/entry-shaped parse-artifact hydration decode through the same
      path under the existing shared value/files store advisory locks. Indexed
      file/parse artifact lookup hydration also holds the matching
      artifact-mapping advisory lock across sidecar lookup and mapped `files/`
      decode. `PersistCache::with_parse_cache_bytes_from_index`,
      `with_parse_cache_source_from_index`, and
      `with_parse_cache_file_from_index` visit hydrated `CachedParse` hits after
      indexed artifact lookup, scoped mapped hydration, and files/artifact locks
      are released, while their load counterparts remain owned `CachedParse`
      wrappers. Focused cached-expression payload, lower-level blob-pack,
      lower-level blob-index, direct artifact-read, artifact-hydration, and
      indexed parse-cache hit tests require lower-level
      `PersistBlobPack::len`/`records`/`verify_blob`/`payload_matches` plus
      indexed value/file reads, cache-level direct raw `read_blob`/`with_blob`,
      decoded cached-expression value visits, node-linked decoded
      cached-expression value visits, trace-revalidated decoded cached-expression
      value/dependency visits, decoded parse-artifact bundle visits, raw file/parse artifact
      reads, direct/keyed/entry-shaped/indexed artifact hydration, and indexed
      parse-cache hit visits to enter the scoped mapped adapter, hold or release
      the relevant store/artifact advisory locks at the public API boundary, reject
      corrupt value-pack payloads, and fail key mismatches before taking the
      files store lock. Blob-index rebuild, liveness, reachability, and
      repack-planning scan adapters also use scoped mapped metadata scans under
      the selected store advisory lock. Node value-root, value/file
      reachability, liveness-plan, and tail-trim root verification also use
      scoped mapped payload checks under the selected store advisory lock, and
      value/file repack apply copies relocated live records through scoped mapped
      payload checks under that same selected store advisory lock. This
      is scoped cooperating-writer mmap integration
      only; LMDB/redb offset indexes, out-of-core rematerialization,
      cross-machine CAS-grade leases, and
      cached/uncached harness proof remain open
      (`C-13`/`R-14`). Gates include
      `cache_cached_expression_payload_borrowed_load_visits_decoded_value_under_scoped_mapping`,
      `cache_cached_expression_node_payload_borrowed_load_visits_decoded_value_under_scoped_mapping`,
      `cache_cached_expression_node_trace_borrowed_visit_decodes_after_scoped_mapping`,
      `cache_file_artifact_borrowed_bundle_visit_decodes_after_scoped_mapping`,
      `cache_parse_artifact_borrowed_bundle_visit_decodes_after_scoped_mapping`,
      `blob_pack_len_uses_scoped_mapped_pack`,
      `blob_pack_len_rejects_corrupt_header_through_scoped_mapping`,
      `blob_pack_records_scans_verified_records_in_pack_order`,
      `blob_pack_borrowed_read_uses_scoped_mapped_payload`,
      `blob_pack_payload_window_validates_lookup_bounds_without_hashing_payload`,
      `blob_pack_verify_blob_uses_scoped_mapped_payload_without_materializing`,
      `blob_pack_payload_matches_compares_verified_payload_bytes`,
      `cache_parse_index_borrowed_load_visits_cached_parse_after_hydration`,
      `cache_source_index_borrowed_load_visits_cached_parse_after_hydration`,
      `cache_file_index_borrowed_load_visits_cached_parse_after_hydration`,
      `cache_raw_blob_borrowed_read_uses_scoped_mapped_payload`,
      `cache_blob_indexed_borrowed_read_uses_scoped_mapped_payload`,
      `cache_blob_indexed_io_updates_index_and_reads_by_key`,
      `cache_blob_io_is_routed_by_key_store`,
      `cache_cached_expression_payload_load_uses_scoped_mapped_value_pack`,
      `cache_cached_expression_payload_load_acquires_value_store_advisory_lock`,
      `cache_cached_expression_payload_load_rejects_corrupt_mapped_value_blob`,
      `cache_file_artifact_read_uses_scoped_mapped_files_pack`,
      `cache_parse_artifact_read_uses_scoped_mapped_files_pack`,
      `cache_file_artifact_hydrates_parse_entry_from_materialized_bundle`,
      `cache_file_artifact_hydrates_parse_entry_after_key_match`,
      `cache_parse_artifact_hydrates_parse_entry_after_key_match`,
      `cache_file_artifact_hydrates_parse_entry_from_index_entry`, and
      `cache_parse_artifact_hydrates_parse_entry_from_index_entry`.
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
      oracle still owns cache policy, blob payload validation, and parse/file
      materialization semantics, while LMDB/redb tables, writer batching, mmap
      reads, GC/repack engine migration, Attic transport, and cross-process
      coordination remain open (`C-13`/`R-14`).
- [x] Current parse-artifact bundle payload codec: `ParseArtifactBundle` frames
      the current `resolved.bin`/`ir.bin`/`symbols.bin`/`meta.toml` artifact
      bytes as one versioned little-endian payload, and
      `ParseCacheEntry::read_artifact_bundle` reads complete entries into that
      bundle. Optional parse-cache sidecars such as `facts.bin` are cache-local
      and deliberately excluded from the bundle framing. This is payload-format
      substrate only; automatic file-artifact materialization, automatic
      parse-cache integration, cache-hit selection, mmap reads, and harness
      proof remain open (`C-13`).
- [x] Current explicit parse-cache hit reader:
      `ParseCache::load_cached_bytes` computes the normal source-content key,
      returns `Ok(None)` for missing/incomplete entries, and decodes complete
      `resolved.bin`/`ir.bin`/`symbols.bin` artifacts into `CachedParse` without
      parsing, overlaying optional `facts.bin` analysis facts when the sidecar
      is present and matches the lowered-IR artifact fingerprint.
      `load_or_parse_bytes` reuses this helper while preserving fallback-to-parse
      behavior for corrupt entries. This is explicit parse cache hit reading
      only; durable file-artifact lookup integration, automatic evaluator hit
      selection, mmap reads, and harness proof remain open (`C-13`).
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
      entry, clearing `meta.toml` before payload writes, clearing stale
      `facts.bin` because bundles do not carry analysis sidecars, and committing
      metadata last so partial hydration is not treated as complete. This is
      explicit entry hydration only; durable index lookup, automatic
      file-artifact materialization, semantic validation before write, mmap
      reads, cache-hit integration, and harness proof remain open (`C-13`).
- [x] Current cache-level blob pack/index initialization substrate:
      `PersistCache::open` initializes and exposes separate value/file
      `PersistBlobPack` and `PersistBlobIndex` handles after schema validation
      and owned-directory setup, and reports corrupt non-empty packfiles or
      malformed fixed-record indexes instead of replacing them. Automatic index
      updates/lookups from cache append/read calls, node metadata, mmap reads,
      writer batching, GC/repack, Attic transport, and harness proof remain open
      (`C-13`/`R-14`).
- [x] Current key-routed blob IO substrate: `PersistCache::append_blob`,
      `read_blob`, and `with_blob` route a `PersistBlobKey` to the value or file
      pack, preserving namespace separation for identical payload hashes while
      reusing pack-level hash and record verification; `append_blob` holds the
      selected store's advisory file lock and same-process same-root blob write
      lock before appending, `with_blob` holds the selected store's shared
      advisory file lock and same-process same-root blob read lock before
      visiting verified borrowed mapped bytes, and cache-level `read_blob`
      remains an owned-byte wrapper around `with_blob`. Automatic durable index
      lookup/update from these raw helpers, node metadata, writer batching,
      maintenance-writer coordination, CAS policy, Attic transport, and harness
      proof remain open (`C-13`/`R-14`). Gates include
      `cache_blob_io_is_routed_by_key_store` and
      `cache_raw_blob_borrowed_read_uses_scoped_mapped_payload`.
- [x] Current explicit indexed blob IO helpers:
      `PersistCache::append_blob_indexed` appends through the key-routed pack
      while holding the selected store's advisory file lock and same-process
      same-root blob-store write lock and records the returned location in the
      selected `PersistBlobIndex`, while
      `lookup_blob_location`/`with_blob_indexed` scan the sidecar index and
      map/verify/visit the indexed pack record under the selected store's shared
      advisory file lock plus same-process same-root store lock, returning
      `None` for misses; `read_blob_indexed` remains an owned-byte wrapper around
      `with_blob_indexed`. This is explicit non-transactional sidecar integration
      only; automatic low-level append/read indexing, raw lower-level pack/index
      coordination, node metadata linkage, writer batching, CAS policy,
      GC/repack, Attic transport, and harness proof remain open (`C-13`/`R-14`).
      Gates include `cache_blob_indexed_io_updates_index_and_reads_by_key` and
      `cache_blob_indexed_borrowed_read_uses_scoped_mapped_payload`.
- [x] Current explicit blob-pack tail-GC helper:
      `PersistCache::trim_blob_pack_tail` snapshots the selected store's latest
      live roots (`values/` blob index entries, or `files/`
      blob/file-artifact/parse-artifact index entries plus same-process pending
      file/parse artifact roots) while holding the selected store's advisory
      file lock and same-process same-root blob lock plus the file/parse mapping
      locks for `files/` trims, verifies each referenced pack record through
      scoped mapped payload checks under the selected store advisory lock, and
      truncates only unindexed bytes after the highest live record through
      `ratchet-cache::blob_pack::BlobPackAppender::trim_tail`, returning
      `PersistBlobPackTrim` byte/count stats. This is tail-only maintenance for
      unindexed trailing records; applied full-pack repack is covered by the
      explicit helpers below, while raw lower-level pack/sidecar coordination,
      unrelated maintenance-writer coordination, automatic GC policy, Attic
      transport, and harness proof remain open (`C-13`/`R-14`).
- [x] Current read-only blob-pack liveness plan:
      `PersistCache::plan_blob_pack_liveness` snapshots the same latest live
      roots used by tail trimming plus same-process pending file/parse artifact
      roots, verifies those roots through scoped mapped payload checks, scans
      selected pack records through scoped mapped metadata under the selected
      store advisory lock, and classifies verified physical records as rooted or
      sidecar-unrooted with byte counts
      for current tail-trim candidates while holding the same-root store lock.
      For `files`, file/parse artifact sidecar snapshots also hold shared
      mapping advisory locks plus the same-root mapping locks. This is
      diagnostic planning only, not the final RFC GC root model: node metadata
      reachability is covered by the value reachability plan below, applied pack
      rewriting is covered by the explicit repack helpers below, and automatic
      GC policy, raw lower-level writer coordination, Attic transport, and
      harness proof remain open (`C-13`/`R-14`). Gates include
      `cache_blob_pack_liveness_plan_classifies_value_records` and
      `cache_blob_pack_liveness_plan_includes_file_artifact_roots`.
- [x] Current read-only blob-pack repack plan:
      `PersistCache::plan_blob_pack_repack` builds the selected store's scoped
      mapped liveness plan, preserves verified live records in current pack
      order, assigns their contiguous locations in a fresh compacted pack, and
      reports omitted unrooted records plus before/after byte counts. Public
      planning holds the liveness plan's shared advisory read locks while
      inspecting current state. This is relocation planning only; applying
      `files` plans with pending artifact roots, automatic GC policy, raw
      lower-level writer coordination, Attic transport, and harness proof remain
      open (`C-13`/`R-14`). Gates include
      `cache_blob_pack_repack_plan_maps_value_live_records_to_compacted_offsets`.
- [x] Current read-only node value-root plan:
      `PersistCache::plan_node_value_roots` snapshots latest node metadata,
      resolves materialized value hashes through the `values` blob index, and
      verifies resolved value-pack records through scoped mapped payload checks
      while reporting metadata links whose value hash is missing from the blob
      index. The value-index snapshot and mapped value-pack verification run
      under the shared `values` store advisory lock plus same-root store lock;
      the node-metadata snapshot holds the shared
      node-metadata advisory lock plus same-root metadata lock. This is
      diagnostic node-to-value reachability only; retention windows, metadata
      pruning, pack rewriting/deletion, live-record relocation, automatic GC
      policy, raw lower-level writer coordination, Attic transport, and harness
      proof remain open (`C-13`/`R-14`).
- [x] Current read-only value-pack reachability plan:
      `PersistCache::plan_value_blob_reachability` snapshots latest node
      metadata and `values` blob-index entries, verifies latest value-index
      roots through scoped mapped payload checks, scans value pack records through
      scoped mapped metadata under the `values` store advisory lock, and
      classifies physical records as node-rooted, indexed-without-node-root, or
      absent from latest index roots while reporting missing node metadata
      links. The value-index snapshot, mapped root verification, and value-pack
      scan run under the shared `values` store advisory lock plus same-root
      store lock; the node-metadata snapshot holds the shared node-metadata
      advisory lock plus same-root metadata lock only while collecting metadata
      entries. This is diagnostic classification only; retention windows,
      metadata pruning, sidecar repair, pack rewriting/deletion, live-record
      relocation, automatic GC policy, raw lower-level writer coordination,
      Attic transport, and harness proof remain open (`C-13`/`R-14`). Gates include
      `cache_value_blob_reachability_plan_classifies_value_records`.
- [x] Current read-only file-pack reachability plan:
      `PersistCache::plan_file_blob_reachability` snapshots latest
      file-artifact, parse-artifact, `files` blob-index, and same-process
      pending artifact roots, verifies captured roots through scoped mapped
      payload checks, scans file pack records through scoped mapped metadata
      under the `files` store advisory lock, and classifies physical records as
      file-artifact-rooted,
      parse-artifact-rooted, pending-artifact-rooted, indexed-without-artifact,
      or absent from all captured roots while holding the shared `files` store
      advisory lock plus same-root store lock. File/parse artifact sidecar
      snapshots also hold shared mapping advisory locks plus the same-root
      mapping locks. This is diagnostic classification only; retention windows,
      sidecar repair, pack rewriting/deletion, live-record relocation, automatic
      GC policy, raw lower-level writer coordination, Attic transport, and
      harness proof remain open (`C-13`/`R-14`). Gates include
      `cache_file_blob_reachability_plan_classifies_file_records`.
- [x] Current `ratchet-cache` staged file-replacement primitive:
      `ratchet-cache::file_replace::FileReplacementSet` owns ordered staged
      file replacement with stale-backup removal, target-to-backup moves,
      staged-file installation, best-effort staged/backup cleanup, and backup
      restoration after ordinary filesystem failures. The value-pack repack
      and file-pack repack swaps now delegate to this primitive while preserving
      the existing `PersistValueBlobPackRepackError` and
      `PersistFileBlobPackRepackError` role-specific surfaces. This is a swap
      choreography primitive only; oracle cache-level repack wrappers provide
      current per-store and artifact-mapping advisory locking, while crash
      transactionality, durable filesystem locks/CAS, raw lower-level writers,
      cross-process pending artifact publication during file repack, and
      automatic GC policy remain open (`C-13`/`R-14`).
- [x] Current `ratchet-cache` staged repack sidecar writer:
      `ratchet-cache::blob_index::BlobIndex::write_entries_to` and
      `ratchet-cache::artifact_index::ArtifactIndex::write_entries_to` replace
      stale staged sidecar files and write exact caller-supplied entry sets for
      value/file blob-index and file/parse-artifact repack sidecars before the
      later multi-file swap. Oracle repack staging now routes through these
      typed helpers while preserving the existing `Persist*IndexError` surfaces.
      This is sidecar staging only; oracle repack wrappers provide current
      per-store and artifact-mapping advisory locking and scoped mapped
      live-root planning, while durable transaction policy across staged
      sidecars and packs, raw lower-level writers, cross-process pending
      artifact publication during file repack, and automatic GC policy remain open
      (`C-13`/`R-14`).
- [x] Current explicit value-pack repack helper:
      `PersistCache::repack_value_blob_pack` holds the selected store's
      advisory file lock and same-root `values/` store lock, plans live-record
      relocation through the scoped mapped liveness scan, stages a compacted
      value pack by copying each relocated live record through scoped mapped
      payload verification plus replacement value blob-index sidecar, and swaps
      both into place via
      `ratchet-cache::file_replace::FileReplacementSet` with best-effort
      rollback for ordinary filesystem errors. It preserves latest indexed
      value roots, omits unrooted value records, and has direct stale-location
      canaries proving pre-repack value offsets no longer verify after
      relocation while rewritten indexes load the relocated payloads. This is
      caller-driven
      maintenance only; crash transactionality, node metadata pruning, automatic
      GC policy, raw lower-level writer coordination, unrelated sidecar
      coordination, Attic transport, and harness proof remain open
      (`C-13`/`R-14`).
- [x] Current explicit file-pack repack helper:
      `PersistCache::repack_file_blob_pack` holds the selected store's advisory
      file lock, the file/parse artifact advisory locks, and the same-root
      `files/` store, file-artifact, and parse-artifact locks, rejects
      same-process pending artifact roots, plans live-record relocation through
      the scoped mapped liveness scan, stages a compacted file pack by copying
      each relocated live record through scoped mapped payload verification plus
      relocated file blob, file-artifact, and parse-artifact sidecars, and swaps
      them into place via
      `ratchet-cache::file_replace::FileReplacementSet` with best-effort
      rollback for ordinary filesystem errors. It has direct stale-location
      canaries proving pre-repack file-artifact, parse-artifact, and indexed
      file-blob offsets no longer verify after relocation while rewritten
      sidecars load the relocated payloads. This is caller-driven
      maintenance only; crash transactionality, automatic GC policy, raw
      lower-level writer coordination, cross-process pending artifact
      publication, Attic transport, and harness proof remain open
      (`C-13`/`R-14`/`R-10`).
- [x] Current explicit all-blob-pack repack helper:
      `PersistCache::repack_blob_packs` runs value-pack repack and then
      file-pack repack, returning both applied plans and total reclaimed blob
      bytes; each pack repack holds that store's advisory file lock for its
      rewrite, and file-pack repack also holds the artifact-mapping advisory
      locks. It is sequential and non-transactional: a committed value-pack
      rewrite can remain if a later file-pack repack fails. It does not compact
      unrelated sidecars, rebuild blob indexes from physical pack scans before
      planning, coordinate raw lower-level pack/index users or cross-process
      pending artifact publication, or apply automatic GC policy
      (`C-13`/`R-14`).
- [x] Current blob-pack integrity scan primitive:
      `PersistBlobPack::records` scans a pack in record order through a scoped
      memory map, validates every record header and mapped payload hash, rejects
      truncated or corrupt tails instead of returning partial metadata, and
      returns `PersistBlobPackRecord` hash/location entries for maintenance
      callers. `with_mapped_records` performs the same verified metadata scan
      while a caller-owned advisory read lease is held, without letting payload
      bytes escape. This is read-only scan metadata only; live-root selection,
      repack/relocation writing, automatic GC policy, Attic transport, and
      harness proof remain open (`C-13`/`R-14`).
- [x] Current store-typed blob-pack index-entry scan adapter:
      `PersistCache::blob_pack_index_entries` routes a scoped mapped verified
      pack scan through the selected `values/` or `files/` store under that
      store's advisory read lock, and maps every physical record, including
      stale duplicates and unindexed tails, to the matching
      `PersistBlobIndexEntry` key/location shape without writing the sidecar.
      This is read-only repair/repack input only; live-root selection,
      repack/relocation writing, unrelated maintenance-writer coordination,
      automatic GC policy, Attic transport, and harness proof remain open
      (`C-13`/`R-14`). Gates include
      `cache_blob_pack_index_entries_are_store_typed` and
      `cache_blob_pack_index_entries_acquires_advisory_store_lock_before_same_process_lock`.
- [x] Current newest physical blob-pack index-entry scan adapter:
      `PersistCache::latest_blob_pack_index_entries` collapses the scoped
      mapped physical pack scan to newest-record-wins `PersistBlobIndexEntry`
      candidates per content hash in stable encoded-key order, matching sidecar
      latest-entry encoded-key ordering while still including unindexed physical
      records. This is read-only index-rebuild input only; live-root selection,
      repack/relocation writing, unrelated maintenance-writer coordination,
      automatic GC policy, Attic transport, and harness proof remain open
      (`C-13`/`R-14`). Gates include
      `cache_latest_blob_pack_index_entries_compacts_physical_duplicates` and
      `cache_latest_blob_pack_index_entries_acquires_advisory_store_lock_before_same_process_lock`.
- [x] Current read-only blob-index rebuild plan:
      `PersistCache::plan_blob_index_rebuild` compares the selected sidecar's
      newest lookup entries with the scoped mapped newest physical records in
      the matching blob pack while holding the selected store's advisory read
      lock, returning the exact entries a future rebuild would write plus
      missing, stale, and dangling lookup differences. Older append-only
      sidecar history is ignored once newest lookups match, and corrupt packs
      fail the plan rather than producing partial repair metadata. This is
      diagnostic rebuild input only; physical sidecar canonicalization,
      live-root selection, pack trimming, repack/relocation writing, unrelated
      maintenance-writer coordination, automatic GC policy, Attic transport,
      and harness proof remain open (`C-13`/`R-14`). Gates include
      `cache_blob_index_rebuild_plan_reports_missing_stale_and_dangling_entries`
      and
      `cache_blob_index_rebuild_plan_acquires_advisory_store_lock_before_same_process_lock`.
- [x] Current explicit blob-index rebuild helper:
      `PersistCache::rebuild_blob_index_from_pack` builds the verified rebuild
      plan for one store while holding that store's advisory file lock and
      same-process same-root blob-index write lock, then replaces only that
      store's hash-to-offset sidecar with the plan's newest physical pack
      entries, indexing previously unindexed newest records, repairing stale
      locations, dropping dangling entries, and canonicalizing duplicate sidecar
      history. This is caller-driven single-sidecar repair only; live-root
      selection, blob-pack trimming, full repack/relocation, raw lower-level
      sidecar coordination, unrelated maintenance-writer coordination,
      automatic GC/repair policy, Attic transport, and harness proof remain
      open (`C-13`/`R-14`).
- [x] Current explicit all-blob-index rebuild helper:
      `PersistCache::rebuild_blob_indexes_from_packs` rebuilds the `values/`
      and then `files/` hash-to-offset sidecars from verified pack scans and
      returns both applied plans, sharing each selected store's advisory file
      lock and same-process same-root blob-index write lock for its rebuild step.
      This is sequential and non-transactional: a committed value-index rebuild
      remains in place if the later file-index rebuild fails. It does not rebuild
      file-artifact, parse-artifact, or node sidecars, select live roots, trim or
      repack blobs, coordinate raw lower-level sidecar users or unrelated
      maintenance writers, or implement automatic repair/GC policy; mmap reads,
      Attic transport, and harness proof remain open (`C-13`/`R-14`).
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
- [x] Current same-process plus advisory blob-store access lock precursor:
      independently opened `PersistCache` handles in one process now store
      canonicalized layout paths and acquire their per-store blob mutexes through
      `ratchet-cache::root_locks::CacheRootLocks`, whose process-local weak
      registry is keyed by the canonical persistent cache root. Cache-level blob
      writes, blob-index rewrites, blob-pack tail trims, and blob-pack repacks
      (`append_blob`, `ensure_blob_indexed`, `append_blob_indexed`,
      `compact_blob_index`, `rebuild_blob_index_from_pack`,
      `trim_blob_pack_tail`, `repack_value_blob_pack`,
      `repack_file_blob_pack`, and callers such as raw or indexed
      materialization) first acquire an exclusive
      `ratchet-cache::file_lock::AdvisoryFileLock` at `.locks/values.lock` or
      `.locks/files.lock`, then acquire the same-process store mutex while they
      write the pack and/or blob-index sidecar, truncate the pack tail, or stage
      and swap a compacted pack.
      Cache-level raw/indexed blob reads, direct artifact reads/hydration, and
      read-only pack planners (`read_blob`, `read_blob_indexed`,
      `read_file_artifact`, `read_parse_artifact`,
      `hydrate_file_artifact_bundle`, `hydrate_parse_artifact_bundle`,
      `plan_blob_pack_liveness`, `plan_blob_pack_repack`,
      `plan_node_value_roots`, `plan_value_blob_reachability`, and
      `plan_file_blob_reachability`) first acquire a shared advisory lock for
      the selected store, then acquire the same-process store mutex while they
      read sidecar locations and verify or scan pack records; indexed artifact
      hydration reads first acquire shared `files` store and artifact-mapping
      advisory locks, then acquire the same-process store and mapping mutexes
      while they read the sidecar mapping and verify the referenced `files` pack
      record. Cooperating readers can share advisory locks but serialize against
      cache-level writers and maintenance.
      Simultaneous same-key materialization through separate opens of the same
      root shares the same `ensure_blob_indexed` critical section, and
      cooperating cross-process cache-level blob readers, planners, artifact
      hydration readers, writers, tail trims, and pack repacks share the same
      advisory files. The initially-missing indexed case collapses to one fresh verified
      pack record and newest sidecar entry for the selected store, poisoned
      same-root locks are mapped back into the existing oracle error surface
      before any cache-level raw append, raw read, indexed append/index write,
      indexed read, direct or indexed artifact hydration read,
      liveness/reachability plan, blob-index compaction/rebuild, blob-pack tail
      trim, or blob-pack repack, and an opened symlink-root handle keeps writing
      the canonical target it opened even if the symlink is retargeted.
      Raw/lower-level `PersistBlobPack`/`PersistBlobIndex` users,
      cross-process pending artifact publication during file maintenance,
      different roots, two-machine misses, full filesystem-lock/CAS policy,
      automatic compaction, GC/repack, mmap reads, LMDB/redb indexes, and
      loom/harness proof remain open (`C-13`/`R-4`/`R-14`).
- [x] Current same-process same-root blob-store maintenance lock precursor:
      cache-level value/file blob-pack repack shares the same
      `ratchet-cache::root_locks` per-store slots as indexed materialization, so
      maintenance rewrites for one live canonical cache root serialize with
      cache-level indexed or raw blob writes for the selected `values/` or
      `files/` store inside one process. Blob-index compaction/rebuild,
      blob-pack tail trim, and value/file blob-pack repack additionally use the
      per-store advisory file lock as covered above. File-pack tail trim and
      file-pack repack also share the file-artifact and parse-artifact advisory
      locks plus mapping slots while they snapshot or relocate those live roots;
      oracle keeps the pending file-root map in a canonical-root weak registry
      because those roots are semantic liveness, not generic lock substrate.
      Poisoned live same-root locks are reported before compaction, rebuild,
      trim, or repack writes sidecars, truncates, or replaces a pack. Raw
      lower-level `PersistBlobIndex`/`PersistBlobPack` users, cross-process
      pending artifact publication, different roots, two-machine races, full
      filesystem-lock/CAS policy, LMDB/redb indexes, automatic GC policy, and
      loom/harness proof remain open (`C-13`/`R-4`/`R-14`).
- [x] Current same-process plus advisory open-initialization lock precursor:
      `PersistCache::open` now creates the caller-supplied root, canonicalizes
      it through `ratchet-cache::root_locks`, acquires an exclusive
      `ratchet-cache::file_lock::AdvisoryFileLock` at `.locks/open.lock`, then
      acquires that root's process-local open slot before schema
      validation/rewrites plus pack/index initialization through the canonical
      layout. If a panic
      poisons a live same-root open lock while another cache handle or waiter
      keeps that root's lock object alive, later same-root opens report the
      poison before touching schema or sidecars; first-open/no-survivor sticky
      poison remains intentionally outside the weak-registry guarantee. This is
      open-initialization serialization only; raw lower-level sidecar helpers,
      pack/index writers, different roots, two-machine misses, full
      filesystem-lock/CAS policy, automatic repair/GC policy, LMDB/redb
      transactions, and loom/harness proof remain open (`C-13`/`R-4`/`R-14`).
- [x] Current same-process plus advisory node-metadata access lock precursor:
      independently opened `PersistCache` handles in one process acquire
      `ratchet-cache::file_lock::AdvisoryFileLock` at
      `.locks/node-metadata.lock` before acquiring their node-metadata mutex
      from `ratchet-cache::root_locks`, so read-only reachability metadata
      snapshots hold shared advisory locks, while raw metadata appends, typed
      reuse/value-hash read-modify-appends, current-demand increments,
      run-boundary advancement, and metadata compaction hold exclusive advisory
      locks for a live canonical cache root. Concurrent same-root demand records
      keep every current-run increment, poisoned live metadata locks are reported
      before any sidecar write or reachability metadata snapshot, and
      cooperating cross-process cache-level metadata snapshot readers and
      writers share the same advisory file. Cache-level metadata lookups that
      can be followed by value-store reads intentionally remain outside this
      reader lock to preserve the existing metadata-first load order.
      Raw lower-level `PersistNodeMetadataIndex` users, different roots,
      two-machine races, full CAS-grade coordination, LMDB/redb node tables,
      automatic GC/repack, and loom/harness proof remain open
      (`C-13`/`R-4`/`S-14`).
- [x] Current same-process plus advisory node-trace access lock precursor:
      independently opened `PersistCache` handles in one process acquire
      `ratchet-cache::file_lock::AdvisoryFileLock` at
      `.locks/node-traces.lock` before acquiring their node-trace mutex from
      `ratchet-cache::root_locks`, so cache-level trace lookups hold shared
      advisory locks while scanning the append-only log, and trace appends,
      tombstones, and trace-log compaction hold exclusive advisory locks for a
      live canonical cache root. Concurrent same-root trace appends keep every
      complete record readable, poisoned live trace locks are reported before
      any trace lookup or log write, and cooperating cross-process cache-level
      trace readers and writers share the same advisory file. Trace lookups
      release the advisory read lock before any later revalidation or
      value-store read in trace-backed node-value loads. Raw lower-level
      `PersistNodeTraceLog` users, different roots, two-machine races, full
      CAS-grade coordination, LMDB/redb node tables, transactionality with
      metadata/value blobs, automatic GC/repack, and loom/harness proof remain
      open (`C-13`/`R-4`/`S-14`).
- [x] Current same-process plus advisory artifact-mapping access lock precursor:
      independently opened `PersistCache` handles in one process acquire
      `ratchet-cache::file_lock::AdvisoryFileLock`s at
      `.locks/file-artifacts.lock` and `.locks/parse-artifacts.lock` before
      acquiring file-artifact and parse-artifact mapping mutexes from
      `ratchet-cache::root_locks`, so cache-level mapping appends, raw mapping
      lookups, liveness/reachability sidecar snapshots, mapping compaction,
      indexed hydration reads, and file-pack tail trim/repack mapping phases
      serialize for a live canonical cache root. Mapping writers and maintenance
      phases hold exclusive mapping advisory locks; raw file-artifact and
      parse-artifact mapping lookups plus liveness/reachability sidecar snapshots
      hold shared mapping advisory locks before the same-root locks while they
      read the sidecar; indexed hydration reads additionally hold the shared
      `files` store advisory and same-root file-store lock while they perform the
      referenced `files/` pack read. Concurrent same-root appends keep every
      complete mapping record readable, poisoned live mapping locks are reported
      before any sidecar write, mapping lookup, liveness/reachability snapshot,
      or indexed hydration read, and cooperating cross-process cache-level
      mapping readers and writers share the same advisory files. Raw lower-level
      `PersistFileArtifactIndex`/`PersistParseArtifactIndex` users, different
      roots, cross-process pending artifact publication, two-machine races,
      durable filesystem locks/CAS, LMDB/redb indexes, automatic GC/repack, and
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
      the selected store's advisory file lock plus same-process same-root store
      lock; file/parse artifact compaction shares artifact-mapping advisory
      locks plus same-process same-root mapping locks. This is caller-driven
      maintenance only; automatic compaction/GC policy, raw lower-level sidecar
      coordination, cross-process pending artifact publication, LMDB/redb
      indexes, pack GC/repack, mmap reads, Attic transport, and harness proof
      remain open (`C-13`/`R-14`).
- [x] Current `ratchet-cache` advisory file-lock substrate:
      `file_lock::AdvisoryFileLock` creates a caller-supplied lock file and
      parent directories, acquires blocking or nonblocking Unix `flock`
      shared/exclusive locks, and releases the advisory lock when dropped. Unit
      coverage proves lock-file creation, shared/shared compatibility,
      shared/exclusive and exclusive/exclusive nonblocking rejection, and
      drop-time release; oracle root open now uses it for `.locks/open.lock`,
      cache-level raw/indexed blob reads, direct/indexed artifact hydration
      reads, read-only liveness/reachability planners, raw/indexed blob writes
      plus blob-index compaction/rebuild, blob-pack tail trim, and blob-pack
      repack use it for
      `.locks/values.lock` and `.locks/files.lock`, and cache-level file/parse
      artifact raw mapping lookups, liveness/reachability sidecar snapshots,
      mapping writes, indexed artifact hydration reads, and file-pack maintenance
      phases use `.locks/file-artifacts.lock` and `.locks/parse-artifacts.lock`,
      cache-level reachability metadata snapshots, metadata writes, and metadata
      compaction use `.locks/node-metadata.lock`, and cache-level node trace
      lookups, writes, and compaction use `.locks/node-traces.lock`. This is
      filesystem-lock substrate plus open-initialization and selected
      cache-level blob-store reads/writes/planning/maintenance plus
      mapping/metadata/trace reads/writes/maintenance only:
      raw/lower-level pack/index/sidecar writers, cross-process pending
      artifact publication, mmap read leases, CAS protocols, mandatory locking,
      raw-writer enforcement, two-machine races, and loom/harness proof remain
      open (`R-4`/`R-14`).
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
      fixed-record sidecar only; typed counter update helpers, force-cache
      demand accounting, and advisory lock coverage are covered by following
      rows, while raw lower-level sidecar coordination, LMDB/redb node tables,
      process-boundary updates, mmap reads, GC/repack, and AOS tuning remain open
      (`C-13`/`C-14`/`S-14`).
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
      oracle still owns node-trace/value transactionality and cache policy,
      while LMDB/redb tables, writer batching, mmap reads, GC policy, and
      cross-process coordination remain open (`C-13`/`R-14`).
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
      still owns node-metadata/value transactionality and cache policy, while
      LMDB/redb tables, writer batching, mmap reads, GC policy, and
      cross-process coordination remain open (`C-13`/`R-14`).
- [x] Current explicit node reuse counter update adapter:
      `PersistCache::record_node_materialization_reuse` and
      `lookup_node_materialization_reuse` expose typed materialization reuse
      counters over the raw metadata index, and
      `record_node_current_demand` reads the newest counters, starts from empty
      counters on a miss, appends a saturated current-demand increment, and
      returns the recorded value. Reuse updates preserve any existing
      materialized cached-expression value-hash link in the same metadata
      record, and cache-level writers acquire `.locks/node-metadata.lock`
      before the same-root metadata write lock for the read-modify-append
      critical section. This is caller-driven and append-only; evaluator
      call-site integration is covered by the force-cache accounting and public
      run-boundary rows below, while raw lower-level sidecar users, different
      cache roots, full two-machine/CAS-grade coordination, LMDB/redb node
      tables, compaction/GC policy, and AOS tuning remain open
      (`C-13`/`C-14`/`S-14`).
- [x] Current explicit node reuse run-boundary adapter:
      `PersistCache::advance_node_materialization_reuse_run` looks up the
      newest counters for one node key, returns `None` without writing on a
      miss, and otherwise appends `MaterializationReuse::advance_run` so
      current-run observations become prior-run reuse signal for later runs
      while preserving any materialized value-hash link. This is caller-driven
      and append-only, with cache-level writers serialized by
      `.locks/node-metadata.lock` plus the same-root metadata write lock;
      Drop/panic/error-path process-boundary orchestration, raw lower-level
      sidecar users, different cache roots, full two-machine/CAS-grade
      coordination, LMDB/redb node tables, compaction/GC policy, and AOS tuning
      remain open (`C-13`/`C-14`/`S-14`).
- [x] Current explicit node reuse sidecar advancement:
      `PersistNodeMetadataIndex::latest_entries` scans the fixed-record
      metadata sidecar into deterministic newest-entry-per-key order, and
      `PersistCache::advance_all_node_materialization_reuse_runs` appends
      changed `MaterializationReuse::advance_run` records for all known node
      keys while preserving materialized value-hash links and skipping no-op
      counters. This is caller-driven and append-only, with cache-level writers
      serialized by `.locks/node-metadata.lock` plus the same-root metadata
      write lock; Drop/panic/error-path process-boundary orchestration, raw
      lower-level sidecar users, different cache roots,
      full two-machine/CAS-grade coordination, LMDB/redb node tables, automatic
      compaction/GC policy, and AOS tuning remain open
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
      advancement, Drop/panic/error-path advancement, raw lower-level sidecar
      coordination, full two-machine/CAS-grade coordination, LMDB/redb node
      tables, automatic compaction/GC policy, and AOS tuning remain open
      (`C-13`/`C-14`/`S-14`).
- [x] Current explicit node metadata sidecar compaction:
      `PersistNodeMetadataIndex::compact_latest_entries` rewrites
      `nodes/metadata.index` through a temporary file and rename so only the
      newest record for each node metadata key remains in stable key order,
      including any materialized value-hash link, and
      `PersistCache::compact_node_metadata` exposes that operation through the
      opened cache root. This is caller-driven, with cache-level writers
      serialized by the node-metadata advisory lock plus same-process same-root
      metadata write lock; automatic process-boundary orchestration, raw
      lower-level sidecar coordination, LMDB/redb node tables, automatic
      compaction/GC policy, and AOS tuning remain open (`C-13`/`C-14`/`S-14`).
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
      raw lower-level sidecar coordination, full two-machine/CAS-grade
      coordination, durable cached-payload hit selection, LMDB/redb node tables,
      automatic compaction/GC policy, and AOS tuning remain open
      (`C-13`/`C-14`/`S-14`).
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
      through the indexed `values/` pack by value hash, while
      `with_cached_expression_value_indexed` exposes a callback-scoped decoded
      value visit after the scoped mapped payload has been decoded and rehashed.
      Focused coverage proves scoped mapped-adapter use, advisory-lock blocking,
      corrupt payload rejection, decoded-value visits, and preservation of
      skip-without-hash/encode/write behavior when the materialization threshold
      fails. This is an explicit cache-level payload bridge only; evaluator
      durable hit selection, lazy-element list or lazy-binding attrset values,
      full AOS cost calibration, GC/repack, and cached/uncached harness proof
      remain open (`C-13`/`C-14`/`S-14`). Gates include
      `cache_cached_expression_payload_borrowed_load_visits_decoded_value_under_scoped_mapping`,
      `cache_cached_expression_payload_load_uses_scoped_mapped_value_pack`,
      `cache_cached_expression_payload_load_acquires_value_store_advisory_lock`
      and `cache_cached_expression_payload_load_rejects_corrupt_mapped_value_blob`.
- [x] Current cached-expression node-value metadata linkage adapter:
      `PersistCache::record_node_materialized_value_hash`,
      `clear_node_materialized_value_hash`, and
      `lookup_node_materialized_value_hash` preserve materialization reuse
      counters while linking or unlinking a demand-node metadata key from the
      newest materialized cached-expression `ValueHash`;
      `materialize_cached_expression_node_value_indexed`,
      `materialize_cached_expression_node_value_indexed_with_signals`, and
      `load_cached_expression_node_value_indexed` combine that link with the
      indexed `values/` payload helpers, while
      `with_cached_expression_node_value_indexed` exposes a callback-scoped
      decoded value visit after metadata and value-pack locks are released.
      Skips do not hash, encode, write, or record metadata, and node-key
      loads/visits return `None` for missing metadata, reuse-only metadata,
      cleared metadata, or missing value blobs. This is
      explicit cache-level linkage only; evaluator durable hit selection,
      node/value transactionality, lazy-element list or lazy-binding attrset
      values, cost measurement, GC/repack, and cached/uncached harness proof
      remain open (`C-13`/`C-14`/`S-14`). Gates include
      `cache_cached_expression_node_payload_borrowed_load_visits_decoded_value_under_scoped_mapping`
      and the existing node-value linkage tests.
- [x] Current threshold-driven force-cache persistent value writeback:
      tree-walk `force_value` now materializes replayable forced-expression
      payloads through `PersistCache::node_materialization_signals` and
      `materialize_cached_expression_node_value_indexed` after the
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
- [x] Current force-cache materialization decision telemetry:
      tree-walk `EvalStats` mirrors force-cache materialization threshold
      decisions as `force_cache_materialization_materializes`,
      `force_cache_materialization_keeps_in_memory`, and derived
      `force_cache_materialization_decisions` counters, and emits them in the
      existing `aos_nix::eval::stats` trace event. The threshold-driven
      force-cache writeback path increments these counters after
      `PersistCache::node_materialization_signals` returns a policy decision
      and before optional value hashing/writing, so profitable and unprofitable
      persistent writeback observations are visible without conflating advisory
      write failures with policy choices. This is evaluator telemetry only; AOS
      trace calibration, RAM-tier promotion, mmap reads, GC/repack, and
      cached/uncached harness proof remain open. Gates cover eval stats trace
      tests plus force-cache persistent threshold skip/materialize tests
      (`C-14`).
- [x] Current node verifying-trace payload codec:
      `PersistNodeTracePayload` frames complete cacheable impure-input traces
      as versioned little-endian bytes with a magic header, typed input
      kind/mode tags including binary-safe `hashFile` and version-3 `findFile`
      candidate path-existence mode, raw identity subjects, observed-result
      hashes, version-4 sorted/deduplicated memo-read dependency
      `PersistNodeMetadataKey` records, and version-5 dependency records with
      pinned optional supplier value hashes, plus a header-only tombstone marker
      for explicitly invalidating older trace records.
      `CacheableInputFingerprint::from_observation_hash` reconstructs the
      persisted fingerprints without re-reading the host. The standalone
      payload decoder preserves trace order, decodes older version-1 through
      version-3 payloads with an empty dependency list, keeps tombstones
      dependency-free, rejects version-1 tombstone sentinels,
      rejects uncacheable `currentTime`, impossible kind/mode pairs, malformed
      tags, future mode tags in older payload versions, malformed dependency
      keys, truncated payloads, and trailing bytes, and exposes stable payload
      constants for node-trace sidecars. This is payload-format compatibility
      only, not a non-destructive schema-6 cache-root migration. This is a
      durable `dep-keys[]` carrier substrate only; cache-level sidecar storage
      is covered below, while evaluator memo-read dependency recording,
      persistent graph rehydration/revalidation, durable hit selection,
      currentTime taint propagation through persisted dependents, mmap reads,
      GC/repack, and cached/uncached harness proof remain open
      (`C-13`/`R-10`/`S-14`).
- [x] Current value-associated node verifying-trace sidecar substrate:
      `PersistLayout::node_trace_log_path` adds `nodes/traces.log`;
      `PersistNodeTraceLog` appends variable-length records keyed by
      `PersistNodeMetadataKey` and carrying the materialized `ValueHash` plus
      `PersistNodeTracePayload`, validates existing log records on open, and
      returns the newest record for a node key through linear lookup.
      `PersistCache::record_node_trace`, `record_node_trace_tombstone`, and
      `lookup_node_trace` expose the sidecar through the opened cache root.
      Cache-level trace appends and tombstones acquire exclusive
      `.locks/node-traces.lock` before the same-root trace write lock, and
      cache-level trace lookups acquire shared `.locks/node-traces.lock` before
      the same-root trace read lock. Record/lookup paths preserve version-5
      memo-read dependency records. This schema-version-8 log is a simple
      append-only substrate only; LMDB/redb node tables, transactionality with
      node metadata or value blobs, automatic evaluator writeback beyond the
      force-cache bridge below, runtime memo-read dependency recording,
      persistent graph rehydration/revalidation, durable hit selection, raw
      lower-level sidecar coordination, full two-machine/CAS-grade coordination,
      currentTime taint propagation through persisted dependents, automatic
      compaction/GC policy, mmap reads, and cached/uncached harness proof remain
      open (`C-13`/`R-10`/`S-14`).
- [x] Current explicit node trace-log compaction substrate:
      `PersistNodeTraceLog::latest_entries` scans the append-only
      `nodes/traces.log` into the newest trace entry per node key, preserving
      tombstones when they are newest; `compact_latest_entries` rewrites those
      newest entries in stable key order through a temporary log and rename
      while preserving any version-5 memo-read dependency records; and
      `PersistCache::compact_node_traces` exposes the operation at cache level.
      This is an explicit caller-driven maintenance primitive with cache-level
      writers serialized by `.locks/node-traces.lock` plus the same-root trace
      write lock; automatic compaction/GC policy, LMDB/redb node table,
      transactionality with metadata/value blobs, runtime memo-read dependency
      recording, persistent graph rehydration/revalidation, raw lower-level
      sidecar coordination, full two-machine/CAS-grade coordination, mmap
      reads, and cached/uncached harness proof remain open
      (`C-13`/`R-10`/`S-14`).
- [x] Current explicit all-sidecar compaction adapter:
      `PersistCache::compact_sidecars` runs the current value/file blob-index,
      file-artifact, parse-artifact, node-metadata, and node-trace compaction
      primitives in a deterministic order and returns `PersistCompaction`
      counts for the newest entries retained by each sidecar, with
      `PersistCompactionError` preserving the failing sidecar type. This is a
      caller-driven maintenance helper only; it is sequential rather than
      transactional, gives advisory coordination to the value/file blob-index,
      file/parse artifact, node-metadata, and node-trace compaction phases,
      requires callers to serialize raw lower-level sidecar writes, does not
      rewrite blob packs or drop unreferenced blobs, and still leaves automatic
      compaction/GC policy, LMDB/redb indexes, pack GC/repack, mmap reads, Attic
      transport, and cached/uncached harness proof open
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
      caller-driven maintenance only; it does not run the explicit full-pack
      repack helpers, gives advisory coordination to blob-index
      compaction/rebuild, file/parse artifact compaction, node-metadata
      compaction, node-trace compaction, and blob-pack tail-trim phases, and
      automatic compaction/GC policy, transactionality across
      sidecar/rebuild/pack phases, raw lower-level pack or sidecar coordination,
      cross-process pending artifact publication, LMDB/redb indexes, mmap
      reads, Attic transport, and cached/uncached harness proof remain open
      (`C-13`/`R-10`/`R-14`/`S-14`). The gate is the storage maintenance cache
      tests.
- [x] Current explicit storage repack sweep:
      `PersistCache::repack_storage` compacts all current append-only
      sidecars, then runs `repack_blob_packs` against the current live roots,
      returning `PersistStorageRepack` with sidecar counts and applied
      value/file repack plans; sidecar compaction phases use their advisory
      locks, the blob-pack repack phases use each selected store's advisory
      file lock, and file-pack repack also uses file/parse artifact advisory
      locks. Unlike `compact_storage`, it does not rebuild blob indexes from
      physical pack scans before planning, so unindexed pack records stay
      unrooted and can be omitted by the repack. Failure coverage pins the
      non-transactional boundaries where sidecar compaction remains
      committed if file-pack repack fails and value-pack repack may already be
      committed before that failure, while the underlying pack-helper tests pin
      stale pre-repack direct-location rejection after relocation. This is
      sequential caller-driven
      maintenance only; automatic compaction/GC policy, transactionality across
      sidecar/repack phases, raw lower-level pack or sidecar writer
      coordination, cross-process pending artifact publication, LMDB/redb
      indexes, mmap reads, Attic transport, and cached/uncached harness proof
      remain open
      (`C-13`/`R-10`/`R-14`/`S-14`). The gate is the storage repack cache tests.
- [x] Current automatic storage maintenance policy precursor:
      `PersistStorageMaintenancePolicy`,
      `PersistCache::plan_storage_maintenance`, and
      `PersistCache::maintain_storage` choose among the current explicit
      helpers without adding a new storage engine. Planning first compares both
      blob indexes to verified physical pack records, then computes value/file
      repack plans. Automatic execution always repairs indexes through
      `compact_storage` before considering byte reclamation, so recoverable
      unindexed newest records are indexed rather than deleted by an eager
      repack. Repair-clean plans that meet the policy threshold run a fresh
      `compact_storage` sweep before `repack_storage`; below-threshold plans
      return a skipped outcome with the diagnostic plan. This is conservative
      policy plumbing over current sidecars and pack helpers only; background
      scheduling, retention windows, a single transaction across repair/repack
      phases, a cache-level raw writer quiescence protocol beyond the explicit
      helper locks, raw lower-level writer coordination, cross-process pending
      artifact publication, LMDB/redb indexes, Attic transport, and
      cached/uncached harness proof remain open (`C-13`/`R-14`). The gate is
      the automatic storage maintenance cache tests.
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
      observation hash still matches; `with_cached_expression_node_value_with_trace_revalidation`
      exposes the same validated hit through a callback-scoped decoded value and
      memo-read dependency visit after metadata, trace, and value-pack locks are
      released. The trace lookup itself runs under the
      shared node-trace advisory lock and releases it before revalidation or
      value payload loading. This is cache-level durable-hit substrate only: no
      evaluator hit selection, in-memory demand-graph insertion, dirty
      propagation, transactionality with value materialization, currentTime
      taint propagation through persisted dependents, automatic compaction/GC,
      and cached/uncached harness proof remain open
      (`C-13`/`R-10`/`S-14`). Gates include
      `cache_cached_expression_node_trace_borrowed_visit_decodes_after_scoped_mapping`
      and the existing trace-verified node-value load tests.
- [x] Current force-cache durable hit selection:
      tree-walk forced-expression lookup now tries the trace-verified
      persistent node-value load after an in-memory force-cache miss; pure
      values hit through the same path by using a zero-input trace record
      rather than trace absence. Selected saturated first-class cacheable
      impure calls share this path through a force-cache subject keyed by
      apply-node identity, builtin name, and argument value hashes: unary
      `import`, `pathExists`, `readDir`, `readFile`, `readFileType`, and
      `getEnv`, including selected immutable text-store `readFile`, plus
      full-arity, named-partial, and immutable text-store `hashFile`. Hits
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
      no dirty propagation beyond revalidation miss fallback, lazy-element list
      or lazy-binding attrset values, broader multi-module/non-own binding-position module-source
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
      `persistent_context_read_file_force_cache_hit_preserves_drv_surfaces`,
      `persistent_read_dir_force_cache_hit_preserves_drv_surfaces`, and
      `persistent_read_file_type_force_cache_hit_preserves_drv_surfaces`
      evaluate derivation attr paths with eval cache disabled, with configured
      persistent force-cache demand/writeback on cold and materializing paths,
      and with fresh-runtime trace-verified persistent forced-value hits for
      context-free `builtins.readFile`, `builtins.readDir`, and
      `builtins.readFileType` values used inside derivation `args`, plus a
      context-bearing `builtins.readFile` payload that must add the referenced
      store path as a decoded derivation input source. They require identical
      `.drv` paths and ATerm bytes across all runs, require final runs to report
      force-cache hits and load the expected force-cache metadata keys, require
      materializing runs to persist the exact filesystem traces, and require
      persistent-hit revalidation to replay the matching filesystem fingerprints
      into the enclosing impure-input trace. The adjacent
      `persistent_text_store_read_file_force_cache_hit_preserves_drv_surfaces`
      forces an immutable `builtins.toFile` payload before reading it through
      `readFile`, then requires the zero-input persistent trace to materialize
      and replay without leaking force-cache hashes into the `.drv` path or
      ATerm. These canaries also scan those derivation surfaces for the
      exercised trace
      identity/observation hashes plus persisted force-cache node/value/trace
      hashes in hex, raw bytes, and Nix base32. This samples the current
      replayable filesystem impure-leaf, including context-bearing `readFile`
      payloads, and selected immutable text-store `readFile` hit paths inside
      derivation input
      surfaces; it does not cover full cached-vs-uncached closure parity, the
      full leak invariant, derivationStrict-node SHA-256 early cutoff,
      stale-input miss surfaces beyond the canaries below, lazy replay payloads,
      broader lazy text-store call shapes, mmap reads, GC/repack, or future
      value-memoization safety net
      (`R-10`/`S-14`).
- [x] Current stale filesystem impure-leaf persistent force-value `.drv`
      surface canaries:
      `persistent_read_file_force_cache_stale_miss_preserves_drv_surfaces`,
      `persistent_context_read_file_force_cache_stale_miss_preserves_drv_surfaces`,
      `persistent_read_dir_force_cache_stale_miss_preserves_drv_surfaces`, and
      `persistent_read_file_type_force_cache_stale_miss_preserves_drv_surfaces`
      materialize trace-verified context-free `builtins.readFile ./input.txt`,
      `builtins.readDir ./dir`, and `builtins.readFileType ./target`
      forced-value payloads inside derivation `args`, plus a context-bearing
      `builtins.readFile ./input.txt` payload, mutate the backing filesystem
      input, then evaluate through the same persistent cache root. The
      context-bearing `readFile` stale canary also requires the old and changed
      store-path contexts to appear as decoded derivation input sources before
      and after mutation. They require stale persistent observations not to
      reuse old filesystem payloads, require baseline materialization to persist
      the exact filesystem traces, require recomputation to replay and persist
      the changed filesystem fingerprints under the same force-cache metadata
      keys with different materialized value hashes, require same-runtime and
      fresh-runtime post-recompute changed-input runs to hit without
      force-cache misses and require the fresh-runtime runs to load the changed
      force-cache metadata keys, and require the resulting `.drv` paths and
      ATerm bytes to match cache-off changed-input runs while differing from
      the original materialized surfaces. They also scan original/materialized/
      changed/stale/post-recompute surfaces for the exercised trace
      identity/observation hashes plus persisted force-cache node/value/trace
      hashes in hex, raw bytes, and Nix base32. This samples stale filesystem
      leaf fallback inside derivation input surfaces, including context-bearing
      `readFile` context replacement; it does not cover full cached-vs-uncached
      closure parity, the full leak invariant, derivationStrict-node SHA-256
      early cutoff, dirty propagation beyond fallback, lazy replay payloads,
      mmap reads, GC/repack, or future value-memoization safety net
      (`R-10`/`S-14`).
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
- [x] Current text-store `import` trace and no-replay `.drv` surface canary:
      `to_file_text_store_import_records_complete_empty_trace` requires a pure
      `import (builtins.toFile ...)` to expose a complete zero-input impure
      trace, while
      `to_file_text_store_import_with_current_time_records_uncacheable_trace`
      requires imported `builtins.currentTime` source to keep the trace
      complete with the uncacheable currentTime fingerprint.
      Text-store imports intentionally mark the force-cache trace incomplete,
      so persistent forced-expression replay cannot skip imported-source side
      effects such as nested `toFile` text-store insertion.
      `first_class_text_store_import_does_not_replay_without_text_store_effects`
      exercises that first-class shape with a pre-forced outer text-store
      import whose imported source creates an inner text-store Nix file, then
      requires second and third fresh persistent-cache runs to produce the same
      returned path and to have that path present in each fresh evaluator's text
      store.
      `persistent_text_store_import_force_cache_no_replay_preserves_drv_surfaces`
      evaluates a derivation attr path whose `args` depend on
      `import (builtins.toFile "force-cache-text-store-import-payload.nix"
      "...")`, first with eval cache disabled and then through a configured
      persistent cache root. It requires cached runs to match the
      cache-disabled `.drv` path and ATerm bytes, requires each run to expose
      the complete zero-input text-store import trace, requires no force-cache
      hits or misses, and asserts that no live persistent force-cache trace is
      written for this computed `toFile` import shape.
      This guards the current text-store import no-replay contract inside
      direct and first-class surfaces; implementing replay for text-store
      imports still needs a design that preserves or rehydrates imported-source
      text-store effects, and broader lazy text-store call shapes, full
      cached-vs-uncached closure parity, derivationStrict-node SHA-256 early
      cutoff, mmap reads, GC/repack, and future value-memoization safety net
      remain open (`R-10`/`S-14`).
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
      and trace sidecars remain empty. The same canary now also requires
      derivation ATerm path and static-output side-record reuse counters to stay
      at zero while `.drv` hash and text-path calculations still run. The adjacent
      `current_time_derivation_taints_in_memory_side_record_nodes` canary uses a
      shared runtime to require uncacheable derivation traces to remove both
      in-memory derivation side-record maps, leave their nodes dirty, and
      recompute instead of reusing those side records on a second same-time run.
      Its persistent-root companion
      `current_time_derivation_skips_persistent_side_record_nodes` requires the
      final ATerm and static-output side-record keys to have no live
      materialized value links and requires a fresh runtime to recompute instead
      of reusing persistent side records.
      The adjacent
      `source_backed_current_time_tombstones_stale_persistent_payload` and
      `observation_only_current_time_tombstones_stale_persistent_payload`
      canaries seed stale durable payloads under the source-backed node-thunk
      and synthetic builtin-attr currentTime observation identities and require
      uncacheable forcing to clear the value link, tombstone the trace, and
      leave seeded reuse counters unchanged.
      This samples currentTime inside one derivation input surface, the
      derivationStrict uncacheable-trace side-record invalidation path, the
      observation-only active memo-read bridge, and one stale durable force-value
      boundary; general currentTime taint propagation through persisted
      dependents, full cached-vs-uncached closure parity,
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
- [x] Current explicit file/parse artifact read adapter:
      `PersistCache::read_file_artifact` and `read_parse_artifact` consume typed
      artifact index values and read/verify the referenced payload through the
      scoped mapped `files/` pack adapter under the shared `files` store
      advisory lock plus same-root file-store lock, cloning owned bytes before
      returning to callers so borrowed mmap slices cannot escape the safe API.
      This is a typed raw artifact read helper only; decoded bundle visitors are
      covered by the hydration row below, while automatic cache-hit selection,
      GC/repack, and harness proof remain open (`C-13`).
- [x] Current explicit file-artifact bundle hydration adapter:
      `PersistCache::hydrate_file_artifact_bundle` reads a typed `files/`
      artifact value through the scoped mapped files-pack adapter under the
      shared `files` store advisory lock plus same-root file-store lock, decodes
      the `ParseArtifactBundle` payload, validates bundled metadata/schema/counts
      and `resolved.bin`/`symbols.bin`/`ir.bin` decoder shape through
      `ParseArtifactBundle::validate_meta`, and writes it into a caller-supplied
      `ParseCacheEntry` only after validation succeeds.
      `PersistCache::with_file_artifact_bundle` and
      `with_parse_artifact_bundle` expose direct decoded and validated bundle
      visits after the scoped mapped files-pack read has released its locks. This
      is explicit validated hydration and direct bundle visitation only; automatic
      cache-hit selection, source/key equality proof, full artifact semantic
      validation beyond existing decoders, GC/repack, and harness proof remain
      open (`C-13`).
- [x] Current keyed file-artifact bundle hydration adapter:
      `PersistCache::hydrate_file_artifact_bundle_for_key` derives the expected
      `PersistFileArtifactKey` from the requested `ParseFileKey`/`ParseCacheKey`,
      rejects mismatches before reading the `files/` pack, and otherwise
      delegates to scoped mapped validated bundle hydration. This is explicit
      keyed hydration only; automatic cache-hit selection, full artifact
      semantic validation beyond existing decoders, GC/repack, and harness proof remain open
      (`C-13`).
- [x] Current indexed file-artifact bundle hydration adapter:
      `PersistCache::hydrate_file_artifact_bundle_from_entry` consumes a
      complete `PersistFileArtifactIndexEntry`, verifies its key against the
      requested `ParseFileKey`/`ParseCacheKey`, and delegates matching entries
      to scoped mapped validated bundle hydration. This is explicit entry-shaped
      hydration only; automatic cache-hit selection, full artifact semantic
      validation beyond existing decoders, GC/repack, and harness proof remain open
      (`C-13`).
- [x] Current indexed file-artifact lookup hydration adapter:
      `PersistCache::hydrate_file_artifact_bundle_from_index` derives the
      file-artifact mapping key from `ParseFileKey`/`ParseCacheKey`, performs
      `lookup_file_artifact`, returns `Ok(None)` on misses, and on hits hydrates
      the validated bundle into a caller-supplied `ParseCacheEntry` while
      returning the matched `PersistFileArtifactIndexEntry`. The lookup and
      scoped mapped `files` pack decode run under shared `files` store and
      file-artifact mapping advisory locks plus the same-root locks, so
      cooperating writers and maintenance cannot expose a split sidecar/pack
      view. This is explicit cache-level lookup hydration only; automatic
      parse-cache integration, durable hit selection, source/key equality
      proof, full artifact semantic validation beyond existing decoders,
      GC/repack, and harness proof remain open (`C-13`).
- [x] Current source-derived indexed parse-cache hydration adapter:
      `PersistCache::hydrate_parse_cache_entry_from_source_index` derives both
      `ParseFileKey` and `ParseCacheKey` from one caller-supplied realpath/source
      byte pair, uses the normal `ParseCache` entry path for that source, and
      delegates matching durable file-artifact mappings to validated indexed
      hydration. This is explicit source-shaped hydration only; canonical path
      resolution, automatic parse-cache integration, durable hit selection, full
      artifact semantic validation beyond existing decoders, GC/repack, and
      harness proof remain open (`C-13`).
- [x] Current source-derived indexed parse-cache load adapter:
      `PersistCache::load_parse_cache_source_from_index` derives both source
      identities from one caller-supplied canonical realpath/source byte pair,
      hydrates the matching durable file-artifact entry into the normal
      `ParseCache` layout, then returns it through
      `ParseCache::load_cached_bytes` as a `CachedParse` hit;
      `PersistCache::with_parse_cache_source_from_index` visits that hydrated
      hit after indexed artifact lookup, scoped mapped hydration, and
      files/file-artifact locks are released. This is explicit caller-driven
      durable hit loading only; canonical path resolution, automatic
      evaluator/import selection, full artifact semantic validation beyond
      existing decoders, GC/repack, and harness proof remain open
      (`C-13`/`R-10`). Gate:
      `cache_source_index_borrowed_load_visits_cached_parse_after_hydration`.
- [x] Current file-derived indexed parse-cache hydration adapter:
      `PersistCache::hydrate_parse_cache_entry_from_file_index` canonicalizes a
      requested filesystem path, reads the canonical source bytes, derives the
      same source-shaped identities, and hydrates the normal `ParseCache` entry
      when the durable file-artifact index has a match. This is explicit
      file-shaped hydration only; automatic parse-cache/evaluator integration,
      durable hit selection, full artifact semantic validation beyond existing
      decoders, GC/repack, and harness proof remain open (`C-13`).
- [x] Current file-derived indexed parse-cache load adapter:
      `PersistCache::load_parse_cache_file_from_index` canonicalizes and reads a
      requested source file, hydrates the matching durable file-artifact entry
      into the normal `ParseCache` layout, then returns it through
      `ParseCache::load_cached_bytes` as a `CachedParse` hit;
      `PersistCache::with_parse_cache_file_from_index` visits that hydrated hit
      after indexed artifact lookup, scoped mapped hydration, and
      files/file-artifact locks are released. This is explicit caller-driven
      durable hit loading only; automatic evaluator/import selection, full
      artifact semantic validation beyond existing decoders, GC/repack, and
      harness proof remain open (`C-13`/`R-10`). Gate:
      `cache_file_index_borrowed_load_visits_cached_parse_after_hydration`.
- [x] Current parse-keyed persistent parse-artifact index substrate:
      `PersistLayout::parse_artifact_index_path` adds
      `nodes/parse-artifacts.index`; `PersistParseArtifactKey` encodes the
      `ParseCacheKey` without a realpath; and
      `PersistCache::materialize_parse_cache_entry_indexed`,
      `PersistCache::hydrate_parse_cache_entry_from_parse_index`, and
      `PersistCache::load_parse_cache_bytes_from_index` materialize and hydrate
      caller-supplied source bytes through this parse-artifact index;
      `PersistCache::with_parse_cache_bytes_from_index` visits hydrated
      parse-keyed hits after indexed artifact lookup, scoped mapped hydration,
      and files/parse-artifact locks are released.
      Materialization rejects entries whose normal parse-cache directory key
      does not match the supplied `ParseCacheKey`, and hydration validates
      bundled metadata/schema/counts plus `resolved.bin`/`symbols.bin`/`ir.bin`
      decoder shape before writing the target entry. The parse-artifact lookup
      and scoped mapped `files` pack decode run under shared `files` store and
      parse-artifact mapping advisory locks plus the same-root locks. This is cache API
      substrate only; evaluator integration is covered by the raw native
      expression row below. Source equality proof beyond the parse-cache entry
      directory key, full artifact semantic validation beyond existing decoders,
      GC/repack, and harness proof remain open (`C-13`/`C-14`/`R-10`). Gate:
      `cache_parse_index_borrowed_load_visits_cached_parse_after_hydration`.
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
      evaluator import hit selection only; borrowed-hit integration in the
      evaluator import path, full artifact semantic validation beyond existing
      decoders, GC/repack, and harness proof remain open (`C-13`/`R-10`).
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
      keys. This is native file-root lookup/writeback only; borrowed-hit
      integration in native lowering, full artifact semantic validation beyond
      existing decoders, GC/repack, and harness proof remain open
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
      the parse-cache entry directory key, borrowed-hit integration in native
      lowering, full artifact semantic validation beyond existing decoders,
      GC/repack, and harness proof remain open
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
      for both file versions. The adjacent
      `persistent_partial_hash_file_force_cache_hit_and_stale_miss_preserve_drv_surfaces`
      stores `b.hashFile "sha256"` in a binding and applies that named partial
      later, requiring the same hit, stale-miss, and post-recompute surfaces.
      The adjacent
      `persistent_text_store_hash_file_force_cache_hit_preserves_drv_surfaces`
      forces an immutable `builtins.toFile` payload before hashing it through
      `hashFile`, then requires the zero-input persistent trace to materialize
      and replay without leaking force-cache hashes into the `.drv` path or
      ATerm. This proves selected ordinary filesystem full-arity and
      named-partial first-class `hashFile` payload trace admission, binary-safe
      revalidation, stale-payload fallback, and immutable text-store `hashFile`
      zero-input trace replay inside derivation input surfaces only;
      allowed-path/IFD/fetch interactions, text-store import paths, broader
      lazy text-store call shapes, full automatic demand-edge wiring, and
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
      `ImpureInput` dependency group with the latest leaves, so later changed
      input observations dirty that node only for current trace-owned inputs
      while preserving memo-read dependencies; incomplete and uncacheable traces
      add no leaves, mark the node plus its transitive `MemoRead` dependent
      closure dirty, and clear only prior impure-input dependencies from that
      node. This is graph-side edge wiring only for explicit caller-supplied
      nodes; automatic demand/evaluating-node creation, cache-key integration
      for evaluator nodes, active observer capture of nested memo reads,
      automatic edges from evaluator-created nodes to input leaves, value
      memoization, full currentTime taint propagation through memoized nodes,
      persistence, allowed-path/IFD/fetch trace coverage, and edge-exactness
      harness coverage remain open (`R-10`/`S-14`).
- [x] Current EvalCache trace-to-node edge adapter:
      `EvalCache::from_graph` wraps a prebuilt demand graph and
      `EvalCache::observe_impure_inputs_for_node` delegates an
      `ImpureInputTraceSource` to `DemandGraph::observe_impure_trace_for_node`
      for a caller-supplied existing node, removing side payload records for
      that node and its transitive memo-read dependent closure when the observed
      trace is incomplete or uncacheable. This is an explicit
      adapter only; automatic demand/evaluating-node creation,
      evaluator-node cache-key integration, automatic edges from
      evaluator-created nodes to input leaves, value memoization, full
      currentTime taint propagation through memoized nodes, persistence,
      allowed-path/IFD/fetch trace coverage, and
      edge-exactness harness coverage remain open (`R-10`/`S-14`).
- [x] Current explicit expression-trace edge adapter:
      `EvalCache::observe_expression_impure_inputs` and
      `EvalCacheRuntime::observe_expression_impure_inputs` first compute the
      caller-supplied expression key and observe/classify a completed trace,
      skip new expression-node creation for incomplete or uncacheable traces
      while invalidating any existing node and side inline payload and clearing
      stale impure-input dependencies for an existing key, and for complete
      cacheable traces get or insert the expression node before invalidating any
      prior side payload and replacing its impure-input edge group. This is still
      explicit caller-driven wiring; automatic evaluator demand-node lifecycle,
      evaluator-produced expression identities/free-variable value hashes,
      active observer capture of nested memo reads, value memoization,
      full currentTime taint propagation through memoized nodes, persistence, and
      edge-exactness harness coverage remain open (`R-10`/`S-14`).
- [x] Current expression cacheability status substrate:
      `ExpressionTraceObservation::cacheability` exposes a typed memoization
      gate that distinguishes cacheable expression nodes, incomplete traces,
      and uncacheable inputs such as `currentTime`. This is a status surface
      only; evaluator memo lookup, automatic taint propagation through
      already-memoized dependents, persistence, and edge-exactness harness
      coverage remain open (`R-10`/`S-14`).
- [x] Current uncacheable/incomplete trace invalidation propagation precursor:
      `DemandGraph::invalidate_node` marks a node dirty without requiring a
      replacement value hash and dirties the transitive dependent closure
      reached through `MemoRead` groups. Runtime expression-trace,
      trace-to-node, and trace-backed inline-payload invalidation paths use it
      when an existing expression observes an incomplete or uncacheable trace
      such as `currentTime`, while clearing only the `ImpureInput` dependency
      group and preserving `MemoRead` edges. Runtime invalidation also purges
      inline, derivation ATerm path, and static-output side records for the
      invalidated node plus that memo-read dependent closure. Replacing a
      node's `MemoRead` group now also checks the newly attached suppliers and
      immediately taints/purges the dependent if any supplier is already dirty,
      which covers side records observed before an active evaluator frame is
      closed. Derivation active-frame closure mirrors that dirty-supplier taint
      to the persistent final ATerm/static-output side-record metadata
      (`derivation_frame_close_dirty_supplier_clears_persistent_side_records`).
      Runtime side-payload observations also refuse to leave a reusable
      side record on a node whose memo-read suppliers are already dirty.
      DerivationStrict uncacheable-trace invalidation also clears persistent
      final ATerm/static-output materialized-value links for the current
      side-record subjects, and enabled-runtime dirty-supplier rejections do not
      report accepted side-payload observations to persistence or persistent-hit
      replay (`persistent_force_cache_hit_rejects_dirty_runtime_supplier`,
      `persistent_derivation_aterm_path_hit_rejects_dirty_runtime_supplier`,
      `persistent_static_derivation_output_paths_hit_rejects_dirty_runtime_supplier`).
      This remains transitive memo-read taint only; automatic evaluator node lifecycle
      integration, persistence, full currentTime taint propagation through
      future durable dependents, and edge-exactness harness coverage remain
      open (`R-10`/`S-14`).
- [x] Current force-cache impure-edge exactness canaries:
      `impure_input_builtins_record_exact_force_cache_graph_edges` forces one
      source-backed attr thunk each for ordinary filesystem `readFile`,
      `hashFile`, `readDir`, `readFileType`, `pathExists`, and impure-mode
      `getEnv` plus a two-leaf `pathExists (readFile ./target)` trace;
      `nested_multi_input_builtins_record_exact_force_cache_graph_edges` covers
      a composed three-leaf `readFile`-fed `pathExists` plus a second
      `pathExists` trace;
      `nested_multi_input_payload_hits_persistent_cache_and_records_exact_edges`
      verifies that the same composed trace persists under the attr-thunk
      metadata key and rehydrates into a fresh runtime graph with the exact
      replayed leaves; and
      `import_backed_inline_thunks_record_exact_force_cache_graph_edges` covers
      canonical plain-file `import`;
      `find_file_forced_inline_thunks_revalidate_candidate_edges_before_hits`
      covers a direct explicit-list `findFile` miss-then-hit candidate trace;
      and `find_file_first_class_nix_path_records_exact_force_cache_graph_edges`
      covers the admitted first-class `findFile builtins.nixPath` child-call key
      with the same miss-then-hit `FindFileCandidate` leaves; and
      `find_file_first_class_explicit_list_records_exact_force_cache_graph_edges`
      covers the admitted first-class explicit-list child-call key with the same
      miss-then-hit leaves; and
      `composed_search_path_literal_equality_records_exact_force_cache_graph_edges`
      covers a composed `<...> == <...>` thunk with distinct
      `FindFileCandidate` leaves. They require the
      evaluator trace to match the expected typed fingerprint(s) and the enabled
      runtime graph to contain exactly one impure-edge owner, which must be the
      node for that thunk's or admitted child call's force-cache
      impure-observation key, whose `ImpureInput` dependency group points to the
      leaf or leaves keyed by those fingerprints, with reverse dependent edges
      on the leaves. This is a focused force-cache edge harness for the
      currently admitted ordinary filesystem/import/direct explicit-list
      `findFile`/first-class `findFile builtins.nixPath`/first-class
      explicit-list `findFile`/cacheable search-path literal subset; it does
      not cover broader search-path fetch interactions, broad persistent graph
      replay, or `currentTime` taint propagation
      (`R-10`/`S-14`).
- [ ] Full impure-input edges remain: `import`/`readFile`/`hashFile`/`readDir`/
      `readFileType`/`pathExists`/`getEnv` keyed as explicit content-hash
      demand-graph inputs; `currentTime` taints dependent memos as uncacheable
      (`R-10`).
- [x] Current precursor: durable import input revalidation. Forced-expression
      cache canaries now prove an `import`-backed thunk survives a fresh runtime
      through persistent value and verifying-trace lookup when the imported file
      bytes are unchanged, and misses/recomputes through a fresh runtime when
      those imported bytes change. This is scoped to the forced-expression
      value/trace replay path for import fingerprints, not full dynamic
      dependency capture, import-result memoization persistence, the persistent
      demand graph, or currentTime taint propagation (`R-10`/`S-14`).
- [x] Current precursor: durable pathExists input revalidation.
      Forced-expression cache canaries now prove a `pathExists` boolean payload
      survives a fresh runtime through persistent value and verifying-trace
      lookup when path existence is unchanged, and misses/recomputes through a
      fresh runtime when that existence bit changes. This is scoped to
      forced-expression value/trace replay for pathExists fingerprints, not
      full dynamic dependency capture, persistent demand graph, generic value
      memoization, or currentTime taint propagation (`R-10`/`S-14`).
- [x] Current precursor: durable readFile input revalidation. Forced-expression
      cache canaries now prove a `readFile` string payload survives a fresh
      runtime through persistent value and verifying-trace lookup when file
      bytes are unchanged, and misses/recomputes through a fresh runtime when
      those bytes change. This is scoped to forced-expression value/trace replay
      for readFile fingerprints, not full dynamic dependency capture,
      persistent demand graph, generic value memoization, or currentTime taint
      propagation (`R-10`/`S-14`).
- [x] Current precursor: durable hashFile input revalidation.
      Forced-expression cache canaries now prove a binary-safe `hashFile`
      string payload survives a fresh runtime through persistent value and
      verifying-trace lookup when hashed file bytes are unchanged, and
      misses/recomputes through a fresh runtime when those bytes change. This
      is scoped to forced-expression value/trace replay for hashFile
      fingerprints, not full dynamic dependency capture, persistent demand
      graph, generic value memoization, or currentTime taint propagation
      (`R-10`/`S-14`).
- [x] Current precursor: durable metadata-style input revalidation. Forced
      expression cache canaries now prove `getEnv`, `readDir`, and
      `readFileType` payloads survive a fresh runtime through persistent value
      and verifying-trace lookup when their observed inputs are unchanged, and
      miss/recompute through a fresh runtime when the environment value,
      directory entries, or file type changes. This extends the existing
      in-memory force-cache edge tests and the durable `pathExists`/`readFile`/
      `hashFile` canaries, but remains scoped to forced-expression value
      replay and verifying traces, not the full persistent demand graph,
      automatic evaluator-node lifecycle, currentTime taint propagation, or
      generic value memoization (`R-10`/`S-14`).
- [x] Current precursor: currentTime forced-expression no-replay. Fresh-runtime
      forced-expression canaries now prove `builtins.currentTime` records an
      uncacheable trace, forces normally through configured persistent cache
      roots for repeated same-time and changed-time runs, reports no
      force-cache hits or misses, and records no persistent force metadata
      entries or trace records. A dependent forced-expression canary also seeds
      stale durable payload metadata for `builtins.currentTime + 1` and proves
      the dependent recomputes, preserves the uncacheable trace, clears the
      stale value link, and tombstones the stale trace without recording demand.
      An unsupported-payload canary seeds stale runtime and durable payload
      metadata under a `currentTime` observation-only identity, returns a
      too-deep nested list that cannot be serialized as a force-cache payload,
      and proves the stale runtime payload is invalidated while the stale
      persistent value link is cleared and its trace tombstoned.
      This is scoped to direct, force-dependent, and unsupported-payload
      currentTime expression boundaries, not full currentTime taint propagation through
      already-memoized dependents or the persistent demand graph
      (`R-10`/`S-14`).
- [x] Current precursor: force-cache option identity includes access policy.
      Forced-expression identities now salt normalized allowed filesystem roots
      and allowed URI prefixes alongside search-path base, configured `nix_path`,
      corepkgs, store/home/system/time/eval-mode, and ambient-search-path
      rejection, intentionally making existing module-hash-derived derivation
      side records cold under the new v3 salt. Focused option-identity tests
      prove allowed path and URI changes allocate distinct demand nodes, and
      `search_path_literal_thunks_do_not_replay_across_allowed_path_policy`
      and
      `composed_search_path_literal_thunks_do_not_replay_across_allowed_path_policy`
      prove restricted-mode direct and composed `<...>` payloads rehydrate in a
      same-policy fresh runtime but are not replayed when the same search path
      is denied. First-class `findFile builtins.nixPath` and closed/replayable
      explicit-list `findFile` child-call policy canaries now prove same-policy
      fresh-runtime replay and denied-policy miss/error behavior for those
      admitted child-call slices. This is scoped to force-cache identity,
      direct/composed search-path policy replay, and the admitted first-class `findFile`
      child-call slices, not fetch interactions or the persistent demand graph
      (`R-10`/`S-14`).
- [x] Current precursor: composed search-path literal force-cache admission.
      Source-backed forced thunks whose body contains ambient `<...>` literals
      or lexical `__nixPath` literals reached through hashable local/upvalue
      captures now admit those `SearchPath` nodes under otherwise force-cache
      safe composed expressions. The focused equality canaries prove
      `<pkg/subdir> == <pkg/subdir>` hits in memory and from persistent cache
      after replaying both `FindFileCandidate` probes, misses when configured
      `nix_path` changes, records exact graph impure-input edges for distinct
      composed candidates, does not replay across restricted allowed-path
      policy changes, reuses matching captured lexical search-path values, and
      leaves computed/unhashable lexical search-path payloads unadmitted. This
      is scoped to direct/composed cacheable-origin search-path literals, not
      arbitrary `SearchPath` payload materialization, first-class/curried
      `findFile` outside the admitted child-call slices, fetch interactions,
      broad persistent graph replay, or the full search-path edge-exactness
      harness (`R-10`/`S-14`).
- [x] Current precursor: first-class `findFile builtins.nixPath` child-call
      admission. Saturated first-class `findFile` calls whose first argument is
      the suspended synthetic `builtins.nixPath` attr now hash that argument
      from the configured `nix_path`, admit after the normal
      first-class demand gate, replay candidate traces on in-memory and
      fresh-runtime persistent child-call hits, and miss when the configured
      `nix_path` changes. This is scoped to the `builtins.nixPath` child-call
      replay slice only; the enclosing thunk still evaluates unless separately
      admitted, and fetch interactions and broad search-path edge-exactness
      remain open (`R-10`/`S-14`).
- [x] Current precursor: first-class explicit-list `findFile` child-call
      admission. Saturated first-class `findFile` calls whose first argument is
      a replayable explicit search-path list, including captured local/upvalue
      alias entries, now fall back from the synthetic `builtins.nixPath` hash path
      to the normal replayable argument payload hash, replay candidate traces on
      in-memory and fresh-runtime persistent child-call hits, and miss when the
      path-literal base/search-path payload identity changes. The exact-edge canary
      `find_file_first_class_explicit_list_records_exact_force_cache_graph_edges`
      proves the admitted child-call key owns the observed miss-then-hit
      `FindFileCandidate` leaves. The persistent-hit canary also verifies the
      trace-log metadata key belongs to that child call and the fresh runtime
      graph owns the revalidated candidate edge. This is scoped to replayable
      explicit-list child-call replay only; the enclosing thunk still evaluates
      unless separately admitted, computed or otherwise non-replayable captured
      explicit-list entries remain outside child-call key admission, and fetch
      interactions, broad persistent graph replay, and broad search-path
      edge-exactness remain open (`R-10`/`S-14`).
- [x] Current precursor: first-class cacheable impure primop captured-argument
      alias admission. Saturated first-class `import`, `getEnv`, `hashFile`,
      `pathExists`, `readDir`, `readFile`, and `readFileType` child calls now
      admit one suspended captured local/upvalue alias in a path/string argument
      position when the aliased target is a closed target thunk, fulfilled or
      not, that hashes through the existing closed literal/replayable payload
      path or a direct already materialized context-free string/path value. This
      covers captured-name `getEnv`, captured-path `pathExists`, and captured
      algorithm/path `hashFile` in-memory
      demand/materialize/replay behavior, plus stale trace miss/recompute for
      changed paths, while still skipping alias chains, dynamic `with` scopes,
      scoped globals, fulfilled text-store outputs, computed/non-replayable
      targets, and text-store replay shapes outside the cacheable trace
      contract. The gate is
      `first_class_unary_import_and_file_builtins_with_captured_args_hit_child_calls`,
      `first_class_path_exists_with_captured_path_hits_child_call`,
      `first_class_hash_file_with_captured_algorithm_and_path_hits_child_call`,
      and the existing persistent text-store `readFile`/`hashFile` canaries.
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
      active while force metadata and trace sidecars stay empty. The public
      `AOS_NIX_CACHE=0` closure canaries cover stale-file and populated-root
      cache paths for raw-expression and file-backed native closures, proving
      the env/config kill switch maps those configured roots to no native cache
      roots, preserves `.drv` closure bytes against explicitly uncached
      baselines, and leaves seeded cache-root regular-file paths and bytes
      unchanged. This covers
      the current parse-cache persistence layer, in-memory impure-trace leaf
      ingestion, replayable forced-expression value/trace cache, and
      derivation side-record persistence, not full demand/evaluating-node
      lifecycle, persistent demand graph, generic value memoization, or
      in-process import result memoization, syscall-level no-read proof, or
      cache metadata/symlink/directory-only state. Gates:
      `eval_config_parses_aos_nix_cache_env_values`,
      `eval_config_maps_native_cache_root_to_cache_options`,
      `aos_nix_cache_zero_bypasses_native_closure_cache_root`,
      `aos_nix_cache_zero_bypasses_file_backed_native_closure_cache_root`,
      `aos_nix_cache_zero_bypasses_populated_native_closure_cache_root`,
      `aos_nix_cache_zero_bypasses_populated_file_backed_native_closure_cache_root`,
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
      input/root ATerm byte payload to be identical, requires the cache-off leg
      to report zero aggregate evaluator cache hit/miss counters, zero
      force-cache hit/miss counters, zero force-cache memoization-decision
      counters, zero force-cache materialization threshold-decision counters,
      zero early cutoffs, and zero derivation final-path/static-output
      side-record reuse, records the persistent parse-index hit, and scans
      cache-off, cache-on miss, and persistent-hit closure paths/ATerm bytes
      for the exercised raw-wrapper parse-cache BLAKE3 renderings (hex, raw
      bytes, and Nix base32). This samples the
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
      input/root ATerm byte payload to be identical, requires the cache-off leg
      to report zero aggregate evaluator cache hit/miss counters, zero
      force-cache hit/miss counters, zero force-cache memoization-decision
      counters, zero force-cache materialization threshold-decision counters,
      zero early cutoffs, and zero derivation final-path/static-output
      side-record reuse, records the persistent file-index hit, and scans
      cache-off, cache-on miss, and persistent-hit closure paths/ATerm bytes
      for the exercised file-root parse-cache and file-content BLAKE3 renderings
      (hex, raw bytes, and Nix base32). This
      samples the current native file-instantiation closure surface, not the
      full cached-vs-uncached AOS closure harness, full leak-invariant harness,
      or future value-memoization safety net
      ([12](12-incremental-evaluation-cache.md) §8.3).
- [x] Current reusable native file-closure cache-parity harness and empty-fold
      update regression witness:
      `native_file_closure_cache_parity` drives one file-root attr selection
      through native cache disabled, cache-on miss/write, a second cache-on
      pass, a fresh parse-root persistent-hit pass, and a disabled-eval-cache
      pass over the populated persistent root, requiring byte-identical `.drv`
      closures while checking disabled-cache force sidecars and persistent files
      remain unchanged. The shared harness also requires both cache-off and
      disabled-eval-cache legs to report zero aggregate evaluator cache hit/miss
      counters, zero force-cache hit/miss counters, zero force-cache
      memoization-decision counters, zero force-cache materialization
      threshold-decision counters, zero early cutoffs, and zero derivation
      final-path/static-output side-record reuse,
      so telemetry cannot quietly imply incremental-cache activity on cache-off
      paths.
      `native_file_cache_parity_harness_covers_empty_foldl_update_regression`
      applies that harness to a `pkgs.zlib`-style file where
      `subdirPackages = builtins.foldl' ... {} []` flows into
      `filePackages // subdirPackages`, so strict attr-update consumers must
      force the lazy empty-fold accumulator before type-checking. The witness
      also scans all cache-off/cache-on-second/persistent-hit/disabled
      closure surfaces for the exercised file-root parse-cache and file-content
      BLAKE3 renderings. This is a focused reusable harness and regression
      canary for native file closures, not full persistent demand-graph replay,
      full AOS package-set coverage, syscall-level cache-off no-read proof, or
      the full cached-vs-uncached CI safety net
      ([12](12-incremental-evaluation-cache.md) §8.3).
- [x] Current reusable native file-closure filesystem-input parity witness:
      `native_file_cache_parity_harness_covers_filesystem_impure_inputs` reuses
      `native_file_closure_cache_parity` on a direct file-root package that
      imports `./dep.nix` and forces `builtins.readFile`, `builtins.hashFile`,
      `builtins.readDir` through `attrNames`, `builtins.readFileType`, and
      `builtins.pathExists` into derivation arguments. The witness requires
      byte-identical `.drv` closures across disabled cache, cache-on miss/write,
      second cache-on pass, persistent source-artifact hit, and
      disabled-eval-cache over the populated persistent root; it positively
      checks the root ATerm contains the imported suffix, readFile payload,
      hashFile digest, readFileType/pathExists results, and readDir entry names;
      it also proves both the root and imported file parse artifacts are written
      locally and durably, requires aggregate cache miss/hit accounting that
      covers imported parse-cache miss/hit activity on the cache-miss and
      persistent-hit legs, and scans all closure surfaces for root/imported
      parse-cache, root/imported file-content, and filesystem impure-input
      identity/observation BLAKE3 renderings.
      `native_file_cache_parity_harness_covers_stale_source_path_input` seeds a
      derivation whose only variable argument is an unfixed local flat
      `builtins.path` source, mutates the source file, then requires stale
      cached and post-recompute persistent runs to hydrate the unchanged file
      root from the durable source artifact, match the changed uncached closure,
      differ from the original closure, keep the root `.drv` path changed by the
      source store path, and scan root parse/file-content/source-payload
      canaries out of all closure surfaces.
      `native_file_cache_parity_harness_covers_filtered_source_path_inputs`
      drives a recursive `builtins.filterSource` tree into derivation arguments,
      mutates an excluded file and requires cache-off/cache-on closures to stay
      byte-identical to the original, then mutates the included file and requires
      cache-on persistent runs with durable file-root parse hits to match the
      changed uncached closure, differ from the original closure, and scan root
      parse/file-content plus included/excluded payload canaries out of all
      closure surfaces.
      `native_file_cache_parity_harness_covers_stale_filesystem_impure_inputs`
      seeds the same native file-closure persistent root with `readFile` and
      `hashFile` payloads, mutates the payload file, then requires stale cached
      and post-recompute persistent runs to match the changed uncached closure,
      differ from the original closure, and contain only the changed payload and
      digest; it also requires stale force-cache miss activity, replacement of
      the original `readFile`/`hashFile` trace value hashes under the same
      metadata keys, post-recompute force-cache hits with no misses, and scans
      original/changed impure-input plus persistent sidecar hashes.
      `native_file_cache_parity_harness_covers_stale_metadata_impure_inputs`
      performs the same closure-level stale-cache check for `readDir`,
      `readFileType`, and `pathExists`: it mutates a directory entry, turns a
      regular file into a directory, removes a probed path, then requires stale
      cached and post-recompute persistent runs to match the changed uncached
      closure, replace the same force-cache metadata keys with changed value
      hashes, load the keys for the changed metadata observations after
      recomputation, and keep all impure-input and persistent sidecar hashes out
      of `.drv` surfaces.
      `native_file_cache_parity_harness_covers_configured_search_path_input`
      drives a caller-configured `nix_path` entry through native
      file-root instantiation, resolves a direct `<pkg/source>` lookup into a
      `builtins.path` derivation argument, requires byte-identical closures
      across the same five harness legs while allowing ordinary per-evaluator
      search-path lookup-cache stats on disabled legs, scans closure surfaces for
      search-path candidate identity, persistent force sidecar,
      root parse/file-content, and source-payload canaries, and leaves
      unconfigured native instantiation plus raw expression instantiation on the
      existing ambient-search-path fallback path.
      `native_file_cache_parity_harness_covers_current_system_option_salt` seeds
      a persistent direct-file closure under `builtins.currentSystem =
      x86_64-linux`, reruns the same attr path under `aarch64-linux`, and
      requires cached output to match the changed uncached closure, miss rather
      than replay the original payload, later hit the changed `currentSystem`
      value-hash metadata entry, and keep persistent sidecar hashes plus both
      `currentSystem` hot hashes out of `.drv` surfaces.
      This broadens the reusable direct-file cache-parity harness across
      filesystem-sensitive forced inputs, source-path stale-content
      recomputation, filtered recursive source output parity, filesystem stale
      content/metadata/existence recomputation, configured search-path closure
      parity, and ambient currentSystem option-sensitive reuse; it is not full
      impure-input demand-graph integration, full AOS package-set coverage,
      syscall-level cache-off no-read proof, or the full cached-vs-uncached CI
      safety net
      ([12](12-incremental-evaluation-cache.md) §6.3/§8.3).
- [x] Current reusable native file-closure ambient-input parity witness:
      `native_file_cache_parity_harness_covers_get_env_impure_input` seeds a
      persistent direct-file closure with configured `builtins.getEnv`, mutates
      the configured environment value, and requires stale cached output to
      match the changed uncached closure, replace the same getEnv force-cache
      metadata key with a changed value hash, later hit the changed key, and
      keep the original/changed getEnv trace hashes plus persistent sidecar
      hashes out of `.drv` surfaces.
      `native_file_cache_parity_harness_covers_absent_empty_and_pure_get_env`
      seeds an absent getEnv read, requires configured empty getEnv to preserve
      the same empty-string closure while missing stale absent input and
      recording the explicit-empty trace, mutates it to a present value, requires
      stale cached output to recompute to the present closure, and then runs pure
      mode with that value configured to prove pure cached output still matches
      the empty-string closure rather than replaying the impure value.
      `native_file_cache_parity_harness_covers_current_time_configured_input`
      drives configured `builtins.currentTime` through the same file-closure
      boundary and requires a changed timestamp cached run to match the changed
      uncached closure rather than the original while scanning persistent
      sidecar hashes and currentTime hot hashes out of `.drv` surfaces.
      This extends the direct-file cache-parity harness to ambient impure
      inputs; it is not itself a currentTime uncacheability/tombstone proof,
      full currentTime taint propagation through future durable dependents,
      full impure-input demand-graph integration, full AOS package-set coverage,
      syscall-level cache-off no-read proof, or the full cached-vs-uncached CI
      safety net
      ([12](12-incremental-evaluation-cache.md) §6.3/§8.3).
- [x] Current persistent value-blob key hash boundary:
      `PersistBlobKey::for_value` now requires `ValueHash`, so indexed
      cached-expression materialization/load, node-value linking,
      reachability planning, and derivation side-record value-blob reads/writes
      keep semantic value hashes typed until the blob-index byte boundary. Raw
      `DurableBlake3Hash` remains available for value-blob keys only through
      explicit low-level `PersistBlobKey::new(PersistBlobStore::Values, ...)`,
      `PersistBlobPackRecord::key(PersistBlobStore::Values)`, and
      `decode_index_bytes` disk-format/pack-scan paths, used by generic raw
      blob IO/materialization/layout tests, pack/index format tests, and
      corrupt/wrong-store fixtures. This closes the current
      semantic constructor leak for `values/` blobs; it is not the full constructive
      value store, the full value-hash serializer, or the full internal-hash
      leak invariant. Gate: `cargo check --manifest-path crates/Cargo.toml -p ratchet-oracle --tests`,
      `cargo check --manifest-path crates/Cargo.toml -p aos-nix-harness --tests`, `blob_index`,
      `cached_expression_materialization`, `blob_reachability`,
      `value_blob_repack` ([12](12-incremental-evaluation-cache.md) §5.2/§8.3).
- [x] Current persistent `files/` blob key hash boundary:
      `PersistFileBlobHash` now marks payload addresses stored in the persistent
      `files/` blob pack. Production file/parse artifact materialization computes
      this type from artifact payload bytes, `PersistBlobKey::for_file` requires it,
      and file/parse artifact index values store and return it while decoded
      persisted `files/` blob-key bytes cross through an explicit wrapper. The
      public cross-crate compatibility tests use typed `ValueHash` and
      `PersistFileBlobHash` constructors instead of the generic raw blob-key
      constructor. This closes the current semantic constructor leak for
      frontend artifact blobs; full cache-value hashing and the full
      internal-hash leak invariant remain open. Gate: `cargo check --manifest-path crates/Cargo.toml -p ratchet-oracle --tests`,
      `cargo check --manifest-path crates/Cargo.toml -p aos-nix-harness --tests`,
      `format_tests`, `blob_sidecars`, `file_artifact_materialization`,
      `file_artifact_hydration`, `parse_artifact_entry_materialization`,
      `cache_io_tests` ([12](12-incremental-evaluation-cache.md) §5.2/§8.3).
- [x] Current parse file-content memo hash boundary:
      `ParseFileContentHash` now marks source bytes read into `ParseFileKey`
      realpath/content memo keys. `ParseFileKey::for_source` computes this type,
      `ParseFileKey::new` requires it, and
      `PersistFileArtifactKey::for_realpath_bytes` consumes it before unwrapping
      only at the stable persisted-index preimage. Existing leak-canary tests
      unwrap with `ParseFileContentHash::as_durable_hash()` only where they scan
      `.drv` surfaces for raw internal BLAKE3 renderings. This type-enforces the
      current parse-file realpath/content memo corridor only; full cache-value
      hashing and the full internal-hash leak invariant remain open. Gate:
      `parse_file_content_hash_wraps_source_bytes`, `cache::parse`,
      `format_tests`, and `ratchet-oracle` test-target compile coverage
      ([12](12-incremental-evaluation-cache.md) §5.2/§8.3).
- [x] Current lowered-IR artifact fingerprint hash boundary:
      `LoweredIrFingerprint` now marks the stable `ir.bin`/`symbols.bin`
      artifact digest used for source-less module identities and optional
      `facts.bin` sidecar validation. `lowered_ir_fingerprint`,
      `lowered_ir_artifact_fingerprint`, `encode_ir_facts`, and
      `decode_ir_facts` traffic in that type, unwrapping only when framing the
      fact artifact bytes or feeding the source-less module identity hasher.
      This type-enforces the current lowered-IR artifact fingerprint corridor
      only; full cache-value hashing and the full internal-hash leak invariant
      remain open. Gate: `lowered_ir` tests and
      `ratchet-oracle` test-target compile coverage
      ([12](12-incremental-evaluation-cache.md) §5.2/§8.3).
- [x] Current parse-cache source key hash boundary:
      `ParseCacheSourceHash` now marks source-byte digests that back
      `ParseCacheKey`. `ParseCacheKey::for_source` computes this typed domain,
      cache-entry path selection uses the explicitly named
      `ParseCacheKey::cache_dir_name`, persistent parse-artifact and
      file-artifact index preimages consume `ParseCacheKey::as_durable_hash()`
      only at disk-format boundaries, and leak-canary tests unwrap through the
      same typed accessor only where they scan `.drv` surfaces for raw internal
      BLAKE3 renderings. This type-enforces the current parse-cache source
      artifact key corridor only; full cache-value hashing and the full
      internal-hash leak invariant remain open. Gate:
      `cache::parse`, `format_tests`, and `ratchet-oracle`/`aos-nix`
      test-target compile coverage
      ([12](12-incremental-evaluation-cache.md) §5.2/§8.3).
- [x] Current impure-input observation hash boundary:
      `ImpureInputObservationHash` now marks observed filesystem/environment
      result hashes for cacheable impure inputs. Operation-specific
      `ImpureInputFingerprint` constructors compute this type,
      `CacheableInputFingerprint` stores and returns it, and
      `ValueHash::from_impure_input_observation_hash` requires it before early
      cutoff or demand-graph consumers can treat an observation as a value leaf.
      Persistent node-trace payload encoding unwraps only at the wire-format
      byte boundary, while `CacheableInputFingerprint::from_observation_hash`
      remains the explicit persisted-parts boundary for decoded traces and
      format fixtures. This type-enforces the current observation-hash corridor
      only; the full internal-hash leak invariant remains open. Gate:
      `cache::input`, `cache::cutoff`,
      `cache::dcg::tests::impure_input`, `format_tests`, and
      `ratchet-oracle`/`aos-nix`/`aos-nix-harness` test-target compile coverage
      ([12](12-incremental-evaluation-cache.md) §5.2/§8.3).
- [x] Current impure-input identity hash boundary:
      `ImpureInputIdentityHash` now marks domain-versioned impure-input
      identity hashes over kind, mode, and subject bytes. `ImpureInputIdentity`
      stores and returns this type, while `DemandCacheKey::for_impure_input`
      and `PersistNodeMetadataKey::for_impure_input` require it before using
      identity bytes in hot-key, confirmation-hash, or persistent metadata-key
      preimages. Synthetic low-level persistence fixtures wrap arbitrary bytes
      through explicit test helpers, and leak-canary scanners unwrap through
      `ImpureInputIdentityHash::as_durable_hash()` only where they scan `.drv`
      surfaces for raw internal BLAKE3 renderings. This type-enforces the
      current impure-input identity corridor only; the full internal-hash leak
      invariant remains open. Gate: `cache::input`, `cache::key`,
      `cache::dcg::tests::impure_input`, `format_tests`, `node_metadata`, and
      `ratchet-oracle`/`aos-nix`/`aos-nix-harness` test-target compile coverage
      ([12](12-incremental-evaluation-cache.md) §5.2/§8.3).
- [x] Current cache expression source hash boundary:
      `CacheExprSourceHash` now marks the source/artifact component of
      `CacheExprIdentity`. Production tree-walk constructors compute this type
      from domain-separated expression, first-class primop call, derivation,
      synthetic builtin-attr, and synthetic select identity preimages, while
      `CacheExprIdentity::new`
      requires it before demand keys, value-hash confirmation keys, or
      persistent node-metadata keys can consume expression identity source
      bytes. Persistent-key and demand-key preimages unwrap through
      `CacheExprSourceHash::as_durable_hash()` only at those stable byte-format
      boundaries, and synthetic fixtures wrap arbitrary bytes through explicit
      test helpers. This type-enforces the current expression-source identity
      corridor only; positioned payload provenance hashes, remaining generic
      durable hash plumbing, and the full internal-hash leak invariant remain
      open. Gate: `cache::key`, `cache::dcg`, `cache::runtime`, `format_tests`,
      `node_metadata`, and `ratchet-oracle`/`aos-nix`/`aos-nix-harness`
      test-target compile coverage
      ([12](12-incremental-evaluation-cache.md) §5.2/§8.3).
- [x] Current positioned-payload source provenance hash boundary:
      `AttrPositionSourceHash` now marks the module/source identity attached to
      persistent position-bearing attrset payload envelopes. Tree-walk replay
      preparation wraps the module identity hash only when a payload retains
      binding positions, cached payload records keep that typed provenance
      through in-memory observation and replay, persistent payload decoding
      wraps envelope bytes at the format boundary, and payload value-hash and
      wire encoders unwrap only when framing the stable
      `attrs-position-source-v1` byte preimage. This type-enforces the current
      position-bearing payload replay-provenance corridor only; positioned
      capture value-hash salting, remaining generic durable hash plumbing, and
      the full internal-hash leak invariant remain open. Gate:
      `cache::runtime`, positioned payload force-cache tests, and
      `ratchet-oracle`/`aos-nix`/`aos-nix-harness` test-target compile coverage
      ([12](12-incremental-evaluation-cache.md) §5.2/§8.3).
- [x] Current positioned-capture source salt hash boundary:
      `ForceCapturePositionSourceHash` now marks the module/source identity
      hashes salted into `FORCE_CAPTURED_VALUE_HASH_DOMAIN_VERSION` for
      position-bearing captured composite payloads. Captured composite hashing
      wraps each retained binding-position module identity before salting the
      force-captured value-hash preimage, and unwraps only when appending the
      stable capture-preimage bytes. This type-enforces the current positioned
      capture salt corridor only; broader capture value-hash typing, remaining
      generic durable hash plumbing, and the full internal-hash leak invariant
      remain open. Gate: `materialized_captures`, captured
      positioned-composite force-cache tests, and
      `ratchet-oracle`/`aos-nix`/`aos-nix-harness` test-target compile coverage
      ([12](12-incremental-evaluation-cache.md) §5.2/§8.3).
- [x] Current static-select binding position hash boundary:
      `StaticSelectPositionHash` now marks the source-name/module and span
      identity for retained binding positions that participate in static-select
      captured-value projections. Static-select projection construction wraps
      each selected binding position identity before sorting/deduplicating the
      projection set, and unwraps only when appending those identities to the
      stable `static-select` captured-value preimage. This type-enforces the
      current selected-binding position projection corridor only; remaining
      force-captured value-hash finalization, generic durable hash plumbing, and
      the full internal-hash leak invariant remain open. Gate:
      `captured_static_selects_miss_when_selected_binding_position_changes`,
      captured static-select projection tests, captured positioned-composite
      force-cache tests, and `ratchet-oracle`/`aos-nix`/`aos-nix-harness`
      test-target compile coverage
      ([12](12-incremental-evaluation-cache.md) §5.2/§8.3).
- [x] Current force-captured value hash boundary:
      `ForceCapturedValueHash` now marks durable digests finalized under
      `FORCE_CAPTURED_VALUE_HASH_DOMAIN_VERSION` before they enter shared
      `ValueHash` key material. Tree-walk string/path/composite
      captured-free-variable hashing, static-select projection and default
      branch hashes, static-has-attr result hashes, replayed payload
      free-variable hashes, and synthetic visible `nixPath` argument hashing
      finalize through this type, while
      `ValueHash::from_force_captured_value_hash` is the only conversion for
      force-captured BLAKE3 digests into demand-key material. This
      type-enforces the current force-cache free-variable fingerprint
      finalization corridor only; canonical value-hash serialization,
      remaining generic durable hash plumbing, and the full internal-hash leak
      invariant remain open. Gate: `captured_scalars`,
      `materialized_captures`, captured static-select / default / has-attr
      force-cache tests, and
      `ratchet-oracle`/`aos-nix`/`aos-nix-harness` test-target compile
      coverage
      ([12](12-incremental-evaluation-cache.md) §5.2/§8.3).
- [x] Current derivation side-payload value hash boundary:
      `DerivationSidePayloadValueHash` now marks BLAKE3 side-record payload
      hashes for cached final ATerm path payloads and static derivation output
      path payloads. `CachedDerivationOutputPaths::value_hash` and final
      ATerm path payload hashing finalize through this type before
      `ValueHash::from_derivation_side_payload_hash` adapts them into graph
      material, while derivation ATerm input comparison still uses
      `ValueHash::from_derivation_aterm_bytes` and Nix-observed modulo/path
      hashing still uses `NixSha256Digest`. This type-enforces the current
      derivation side-payload BLAKE3 finalization corridor only; generic
      canonical value-hash serialization, persistent graph serialization, and
      the full internal-hash leak invariant remain open. Gate:
      `derivation_payload`, derivation side-record runtime tests, derivation
      path-reuse surface tests, and
      `internal_cache_hash_canaries_do_not_reach_drv_surfaces`
      ([12](12-incremental-evaluation-cache.md) §5.2/§4.3).
- [x] Current cached-expression payload value hash boundary:
      `CachedExpressionPayloadValueHash` now marks BLAKE3 value hashes for
      canonical `CachedExpressionValue` persistent payload bytes, including
      source-provenance envelopes for positioned attrsets.
      `InlineValuePayload::value_hash_from_persistent_payload`,
      `CachedExpressionValue::value_hash_for_attr_position_source`, and the
      precomputed empty-list/empty-attrset const hashes finalize through this
      type before `ValueHash::from_cached_expression_payload_hash` adapts them
      into graph and value-blob material. This type-enforces current
      cached-expression payload BLAKE3 finalization only; the general canonical
      value serializer, broader value-store hashing, persistent graph
      serialization, and the full internal-hash leak invariant remain open.
      Gate: inline-payload encoding tests, cached-expression materialization
      and payload rehydration tests, positioned-payload tests, and
      `ratchet-oracle`/`aos-nix`/`aos-nix-harness` test-target compile coverage
      ([12](12-incremental-evaluation-cache.md) §5.2).
- [x] Current demand-cache key hash boundary:
      `DemandKeyHotHash` marks the in-process xxh3 probe for `DemandCacheKey`,
      and `DemandKeyConfirmationHash` marks the BLAKE3 confirmation digest that
      keeps same-hot-hash collisions distinct. `DemandCacheKey::for_free_vars`
      and `DemandCacheKey::for_impure_input` construct both halves from their
      domain-separated preimages before demand-graph insertion, while the
      raw-parts test helper now accepts only these typed key-hash wrappers.
      This type-enforces the current demand-key hot/confirmation corridor only;
      it does not make demand keys durable addresses, implement the full
      persistent graph, or prove the full internal-hash leak invariant. Gate:
      `cache::key`, `cache::dcg` key-collision tests, and
      `ratchet-oracle`/`aos-nix`/`aos-nix-harness` test-target compile coverage
      ([12](12-incremental-evaluation-cache.md) §3.2/§5.2).
- [x] Current persistent node metadata key hash boundary:
      `PersistNodeMetadataKeyHash` marks BLAKE3 keys for durable demand-node
      metadata and trace sidecar records. `PersistNodeMetadataKey::for_expression`,
      `PersistNodeMetadataKey::for_impure_input`, and
      `PersistNodeMetadataKey::decode_index_bytes` construct or decode the
      typed key hash, while `PersistNodeMetadataKey::hash` preserves the
      existing raw durable-hash inspection accessor and
      `PersistNodeMetadataKey::index_bytes` unwraps at the stable sidecar and
      engine key boundary. This type-enforces current persistent node
      metadata/trace key finalization and decoding only; persisted value-hash
      fields, full graph persistence, LMDB/redb indexes, and the full
      internal-hash leak-invariant harness remain open. Gate: `cache::hashing`,
      node metadata/trace format tests, persistent force-cache
      demand/materialization tests, and
      `ratchet-oracle`/`aos-nix`/`aos-nix-harness` test-target compile coverage
      ([12](12-incremental-evaluation-cache.md) §3.4/§5.2/§6.5).
- [x] Current native semantic-no-op source edit closure canaries:
      `native_instantiation_expr_comment_only_edit_preserves_drv_closure`,
      `native_file_instantiation_comment_only_leaf_edit_preserves_drv_closure`,
      `native_file_instantiation_comment_only_forced_leaf_edit_preserves_drv_closure`,
      and `native_file_instantiation_unused_leaf_package_edit_preserves_drv_closure`
      evaluate a raw expression root with inline input derivations plus
      file-root attr paths whose selected derivations depend on a leaf import
      through an input derivation. They seed configured parse/persist cache with
      the first source, rewrite either raw-root comments/whitespace, leaf
      comments/whitespace, or an unused derivation package in that leaf, and
      then require cache-disabled and cached runs to keep the two-derivation
      `.drv` closure byte-identical while the changed source reparses into the
      fresh cache root. The raw-expression variant proves the changed source
      misses the first raw parse artifact and then hydrates the changed raw
      parse artifact through a fresh parse root. The forced-leaf variant
      additionally materializes a `currentSystem` force payload under the first
      source, decodes that indexed persistent payload back to the expected
      context-free string, then runs the comment-only changed source through
      cached miss and later persistent-hit paths while scanning the
      byte-identical closure surfaces for the observed forced-payload sidecar
      hashes and the `currentSystem` hot xxh3 sentinel. Because reusable
      derivation side records may satisfy the later closure request before the
      leaf `currentSystem` value is demanded again, the fresh-hit legs assert
      that demanded persistent force-cache hit keys are reported and decodable
      rather than requiring that specific `currentSystem` key to be hit. That
      forced-leaf path also proves the same-source materialization/fresh-hit
      legs and the changed-source cached miss/fresh-hit legs reuse both
      static-output side records and final ATerm path side records for the two
      derivations, and perform zero derivation hash and final text-path
      calculations. The ordinary comment-only leaf changed-source cached leg
      also requires the same two side-record reuses and zero derivation
      hash/text-path work, while the unused leaf-package edit pins the current
      partial dirty frontier with one static-output side-record reuse, one final
      ATerm path side-record reuse, two derivation-hash calculations, and one
      final text-path calculation before producing the same closure bytes. The
      canaries scan uncached/cached first and changed closures for the exercised
      first/changed raw-wrapper parse-cache BLAKE3, leaf parse-cache BLAKE3, and
      file-content BLAKE3 renderings in hex, raw bytes, and Nix base32. This
      samples one raw-root comment/whitespace edit, one ordinary
      comment/whitespace leaf edit, one forced comment/whitespace leaf edit, and
      one unused leaf-package edit plus selected derivation side-record shortcut
      counters, not full bounded recomputation measurement, full AOS closure
      coverage, the full leak invariant, or future value-memoization safety net
      ([12](12-incremental-evaluation-cache.md) §8.3).
- [x] Current native forced-expression sidecar leak/bypass canaries:
      `native_instantiation_expr_force_cache_sidecar_hashes_do_not_leak_into_drv_closure`
      and
      `native_file_instantiation_force_cache_sidecar_hashes_do_not_leak_into_drv_closure`
      drive raw-expression and file-root attr-path `NixNative` instantiation
      through cache-off, persistent demand observation, durable forced-value
      materialization, and a fresh-runtime persistent pass for a configured
      `currentSystem` thunk. The cache-off leak legs require zero aggregate
      evaluator cache hit/miss counters, zero force-cache hit/miss counters,
      zero force-cache memoization-decision counters, zero force-cache
      materialization threshold-decision counters, zero early cutoffs, and zero
      derivation final-path/static-output side-record reuse. The final
      fresh-runtime passes must report force-cache hits, and the canary scanner
      only admits persistent node metadata entries whose linked value loads
      through the cached-expression payload decoder. The canaries then scan the
      resulting `.drv` path and ATerm closure surfaces for forced-expression node
      metadata BLAKE3 addresses, materialized value BLAKE3 addresses, trace-side
      BLAKE3 addresses when present, and a representative context-free
      `NixString` xxh3 hot-hash sentinel.
      `native_instantiation_expr_disabled_cache_bypasses_persistent_force_sidecar_effects`
      and
      `native_file_instantiation_disabled_cache_bypasses_persistent_force_sidecar_effects`
      seed real persistent forced-expression payloads, then rerun the same
      raw-expression and file-root closures with eval-cache disabled and the
      same persistent root configured, requiring byte-identical closure output,
      the same zero incremental-cache stats contract, unchanged latest logical
      node metadata and trace entries, and no sidecar hash leak into the
      disabled closures. The raw-expression canary additionally requires byte-identical
      persistent cache file contents; the file-root canary requires
      byte-identical force-cache node/value sidecar contents while leaving
      file-root parse artifact persistence to the separate frontend cache
      gates. This
      extends the current native closure safety net to forced-expression
      persistent sidecars and populated-root disabled-cache side-effect
      bypasses on both native source entry shapes; it is not syscall-level
      no-read instrumentation, the full cache-off AOS closure harness, full
      internal-hash leak invariant, or future value-memoization safety net
      ([12](12-incremental-evaluation-cache.md) §5.2/§8.3).
- [x] Current `AOS_NIX_CACHE=0` native eval/closure bypass canaries:
      `aos_nix_cache_zero_bypasses_native_closure_cache_root` configures a
      stale cache-root path that is a plain file, applies the real
      `AOS_NIX_CACHE=0` config path, verifies the mapped native
      `TreeWalkOptions` have no parse/persist cache roots and eval-cache is
      disabled, and then requires native-only instantiation to produce the same
      in-memory `.drv` closure as an explicitly uncached baseline. The
      file-backed companion canary drives the same public config path through
      `NativeOnlyEval::instantiate_closure` with a real source file and `-A`
      selector, again proving that the disabled stale cache-root file is not
      touched and that the resulting closure bytes match the uncached baseline.
      `aos_nix_cache_zero_bypasses_populated_native_closure_cache_root` and
      `aos_nix_cache_zero_bypasses_populated_file_backed_native_closure_cache_root`
      first seed real cache roots through cache-enabled raw-expression and
      file-backed native-only instantiation until a loadable persistent
      forced-expression payload exists, snapshot the populated cache-root file
      contents, then apply the real `AOS_NIX_CACHE=0` config path and require
      no native cache roots, byte-identical `.drv` closures, and unchanged
      populated cache-root regular-file paths and bytes.
      `aos_nix_cache_zero_bypasses_populated_native_eval_expr_cache_root`
      performs the same public config-path check for strict-JSON `eval_expr`:
      it seeds a populated cache root with an attr-selected string thunk until
      loadable persistent force-cache payloads exist, then requires
      `AOS_NIX_CACHE=0` to preserve the uncached JSON output and leave the
      populated cache-root regular-file paths and bytes unchanged.
      `aos_nix_cache_zero_leaves_non_file_cache_roots_untouched` additionally
      drives the same public config path over directory-only cache roots,
      cache-root symlinks, and stale metadata-shaped cache directories, requiring
      byte-identical native closures and unchanged directory, symlink, target,
      and metadata-shaped tree snapshots.
      `aos_nix_cache_zero_ignores_inaccessible_cache_root` places a configured
      cache root behind a non-searchable parent and requires the cache-off path
      to produce baseline closure bytes with zero cache stats while preserving
      the inaccessible cache-root tree after access is restored. All disabled
      `AOS_NIX_CACHE=0`
      eval/closure legs now also require zero aggregate evaluator cache hit/miss
      counters, zero force-cache hit/miss counters, zero force-cache
      memoization-decision counters, zero force-cache materialization
      threshold-decision counters, zero early cutoffs, and zero derivation
      final-path/static-output side-record reuse.
      This samples the public env/config kill switch at the strict-JSON
      `eval_expr`, raw-expression `.drv`, and file-backed native `.drv` closure
      boundaries; it is not the full periodic
      cache-off/cold cached CI harness, syscall-level no-read proof, complete
      cache metadata/symlink/directory/inaccessible-state proof, or future
      value-memoization safety net
      ([12](12-incremental-evaluation-cache.md) §8.3).
- [x] Current `nix-diff` cache-validation command precursor:
      `aos nix-diff --cache-validation` evaluates each selected attr once
      through each side of the existing differential closure harness, then
      compares the recorded results as a three-way cold safety matrix: C++ Nix
      oracle versus native cache-off, C++ Nix oracle versus native cold-cache,
      and native cache-off versus native cold-cache. The mode works with
      `--attr`, `--smoke`, `--all`, and `--systems`, creates an empty per-attr
      native cache root for the cold-cache leg, clears `native_cache_root` for
      the cache-off leg, rejects direct `.drv` pair mode and `--oracle-stats`,
      renders machine-readable JSON with per-comparison roots/divergences,
      top-level/per-attr comparison-failure counts, and per-attr cold roots in
      accepted byte-mode full-closure fixtures, removes successful cold roots,
      retains failing cold roots, and reports a reproduction command carrying
      `--cache-validation` on failures. This is a runnable command-level
      validation hook only; the local
      `just cache-validation-smoke` recipe runs the `--smoke` zlib witness via
      `nix run . -- nix-diff --smoke --cache-validation --mode=byte -- default.nix`;
      scheduled CI wiring, full AOS package-set closure coverage on Linux,
      syscall-level cache-off no-read proof, and full future value-memoization
      safety remain open. Gates:
      `nix_diff_parses_cache_validation`,
      `nix_diff_parses_cache_validation_smoke_hook_command`,
      `smoke_corpus_selects_zlib_witness`,
      `nix_diff_cache_validation_rejects_incompatible_modes`,
      `cache_validation_attr_report_compares_oracle_cache_off_and_cold_cache`,
      `cache_validation_json_renders_full_closure_matrix_failures`,
      `cache_validation_json_counts_failed_comparisons_without_divergences`,
      `cache_validation_reproduction_args_insert_flag_before_file_separator`,
      and
      `cache_validation_full_closure_cleanup_removes_only_successful_cold_roots`
      ([12](12-incremental-evaluation-cache.md) §8.3).
- [x] Current cache-validation Linux check-graph precursor:
      `pkgs.aos` integration checks now expose
      `checks.integration.aos-cache-validation-smoke` (and flake checks expose
      it as `integration-aos-cache-validation-smoke`). The check provisions a
      throwaway local Nix store/state/log tree and native cache root under
      `$TMPDIR`, initializes that store with AOS-built `nix-store --init`, and
      runs the installed AOS-built CLI wrapper as
      `aos --eval-system=<check-system> nix-diff --smoke --cache-validation --mode=byte -- <repo>/default.nix`.
      This wires the zlib witness into the Linux check graph only; scheduled CI
      execution, full AOS package-set closure coverage on Linux, syscall-level
      cache-off no-read proof, and full future value-memoization safety remain
      open. Gate: `checks.integration.aos-cache-validation-smoke` / flake
      `integration-aos-cache-validation-smoke`
      ([12](12-incremental-evaluation-cache.md) §8.3).
- [x] Current cache-validation full-closure matrix unit witness:
      `cache_validation_attr_report` is covered in `DiffMode::Byte` and
      `DiffMode::Structural` with in-memory `.drv` closures for all three matrix
      sides, proving the cache-validation command path can consume full closure
      bytes without falling back to path-only instantiation in either accepted
      full-closure mode. The witnesses also inject cold-cache-only byte drift
      plus structural-mode byte-and-field drift under an unchanged root path and
      require both oracle-vs-cold-cache and cache-off-vs-cold-cache matrix
      comparisons to fail while oracle-vs-cache-off remains clean. This is
      also pinned so path-only evaluators are rejected in byte and structural
      cache-validation modes instead of silently degrading to root path
      comparison. This is local unit coverage of the full-closure safety-net
      path only; scheduled CI wiring, full AOS package-set closure coverage on
      Linux, syscall-level cache-off no-read proof, and future
      value-memoization safety remain open.
      Gates:
      `cache_validation_byte_mode_uses_in_memory_closures_without_path_fallback`,
      `cache_validation_byte_mode_detects_cold_closure_byte_drift`,
      `cache_validation_structural_mode_uses_in_memory_closures_without_path_fallback`,
      `cache_validation_structural_mode_detects_cold_closure_structural_drift`,
      and `cache_validation_full_closure_modes_reject_path_only_evaluators`
      ([12](12-incremental-evaluation-cache.md) §8.3).
- [x] Current cache-validation full-closure mode guard:
      `aos nix-diff --cache-validation` rejects `--mode=path` before probing
      for `nix-instantiate` or selecting native side evaluators, and accepts
      only `--mode=byte` or `--mode=structural`. The lower-level comparison
      helpers still support path mode for direct unit fixtures, but the
      user-facing cache-validation safety-net command cannot be accidentally run
      as a root-path-only check. This pins command-mode policy only; scheduled
      CI wiring, full AOS package-set closure coverage on Linux, syscall-level
      cache-off no-read proof, and future value-memoization safety remain open.
      Gates: `cache_validation_rejects_path_mode` and
      `cache_validation_path_mode_rejects_before_nix_probe`
      ([12](12-incremental-evaluation-cache.md) §8.3).
- [x] Current cache-validation side-config planning unit witness:
      cache-validation side construction routes through explicit cache-off and
      cold-cache config helpers. Unit coverage proves the cache-off side clears
      only `native_cache_root`, the cold-cache side sets only the per-attribute
      absolute cache root, the caller config is left unchanged, and eval mode,
      store directories, allowlists, `NIX_PATH`, `HOME`, working directory,
      current system, and trace verbosity are preserved. This pins the local
      root-selection contract only; native evaluator selection, runtime
      syscall/no-read proof, full AOS package-set closure coverage, CI
      scheduling, and future value-memoization bypass proof remain open. Gate:
      `cache_validation_side_configs_only_change_native_cache_root`
      ([12](12-incremental-evaluation-cache.md) §8.3).
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

- [x] P1 arena-shape prerequisite already in place: `BumpArena` established
      aligned monotonic allocations through entry-point-shaped `aos_alloc_*`
      Rust helpers, never-free typed handles, geometric/dedicated chunk growth,
      and arena accounting before the P3 mmap backend replaced the concrete
      chunk storage.
- [ ] Final Tier-A runtime arena remains: `mmap`/`munmap` chunks, thread-local
      per-worker arenas, CLI-wide Tier-A default, and byte-green proof under
      Tier A (the per-invocation default, `C-10`).
- [x] Current Tier-A mmap/thread-local precursor: `ratchet-value::heap::BumpArena`
      uses anonymous `mmap` chunks and `munmap` drop, records both logical
      reserved bytes and page-rounded mapped bytes, and exposes
      `ThreadLocalBumpArena` for per-worker never-free arenas. Full Tier-A
      closure proof and benchmark evidence remain open in the row above.
- [ ] `heap/gc.rs` — Tier B precise generational copying collector with a
      cache-resident nursery; precise (not conservative) so Boehm-style false
      retention is eliminated ([06](06-memory-management-and-gc.md)).
- [x] Current minor-GC frontier precursor:
      `ratchet-value::heap::gc::MinorGcPlan` builds the initial young-object
      frontier for a future Tier-B minor collection from precise roots plus a
      caller-supplied remembered-set snapshot whose targets must refer to
      current nursery objects. It filters inline, old, and permanent roots out
      of the young frontier, deduplicates young roots and remembered targets in
      discovery order, validates that every live young seed has unique nursery
      age metadata, and applies an age-based copy-to-next-nursery vs
      promote-to-old policy. This is a survivor frontier and promotion plan
      only; relocation/writeback, nursery semispace storage, old-generation
      collection, GC-stress mode, and byte-green Tier-B harness execution remain
      open in the full collector row above.
- [x] Current remembered-set epoch-validation precursor:
      `ratchet-value::heap::gc::RememberedSetEpoch` and
      `RememberedSetSnapshot` attach explicit collection epoch metadata to the
      deduplicated old/permanent-to-young edge set, and
      `MinorGcPlan::from_roots_and_remembered` rejects snapshots whose epoch
      differs from the requested minor-collection epoch before using remembered
      targets. Unit tests cover epoch propagation through `RememberedSet`,
      matching-epoch planning, and mismatch rejection. This validates metadata
      only; complete remembered-set construction by the real card table and
      collector remains open.
- [x] Current minor-GC field-expansion precursor:
      `ratchet-value::heap::gc::NurseryObjectFields` and
      `MinorGcPlan::from_roots_remembered_and_fields` expand the young survivor
      frontier through caller-supplied precise nursery fields, recursively
      adding young fields while filtering inline, old, and permanent fields.
      The expansion deduplicates shared children and cycles in discovery order,
      validates unique field metadata for every reached young object, and then
      applies the same age-based promotion policy. Unit tests cover transitive
      expansion, non-young field filtering, cycle/deduplication behavior,
      post-expansion promotion, and missing/duplicate field metadata rejection.
      This remains a planning surface only; object copying, forwarding-pointer
      updates, relocation writeback, semispace allocation, mutable oracle
      root/field slot integration, and collector invocation remain open.
- [x] Current minor-GC destination-allocation planning precursor:
      `ratchet-value::heap::gc::NurseryObjectLayout` and
      `MinorGcDestinationAllocationPlan::from_minor_gc_plan` validate
      caller-supplied object size/alignment metadata for a survivor plan and
      split destination storage requirements by copy-to-nursery vs promote-to-old
      action. Allocations keep survivor-frontier order, require one layout per
      live survivor with no stale entries, reject duplicate layouts, zero sizes,
      invalid alignments, and byte-total overflow, and report nursery, old, and
      aggregate byte requirements. Unit tests cover copy/promote byte splitting,
      ordering, layout validation failures, per-generation overflow, and
      aggregate overflow. This remains allocation planning only; destination
      address allocation, object copying, forwarding pointers, root/field
      writeback, and semispace management remain open.
- [x] Current minor-GC destination-placement planning precursor:
      `ratchet-value::heap::gc::MinorGcDestinationPlacementPlan` converts a
      destination-allocation plan into aligned byte offsets inside future nursery
      and old-generation destination spaces. It keeps survivor-frontier order
      while advancing nursery and old offset streams independently, includes
      alignment padding in reserved-byte totals, and rejects invalid alignment
      metadata plus per-generation or aggregate reserved-byte overflow. Unit
      tests cover nursery/old offset separation, padding, retained survivor
      identity, invalid alignment defense, per-generation reserved-byte
      overflow, and aggregate reserved-byte overflow. This remains offset
      metadata only; reserving pages, choosing base addresses, allocating
      destination objects, copying bytes, forwarding pointers, and semispace
      management remain open.
- [x] Current minor-GC relocation-destination materialization precursor:
      `ratchet-value::heap::gc::MinorGcDestinationBases` and
      `MinorGcRelocationDestinationPlan::from_placement_plan` combine checked
      placement offsets with caller-supplied nursery and old-generation base
      addresses to materialize relocation destination metadata. Copied survivors
      use the nursery base, promoted survivors use the old-generation base,
      address arithmetic is overflow-checked, materialized addresses reuse
      `GcHeapAddress` low-tag validation, object alignment is rechecked after
      base addition, and the table is validated by the existing relocation-map
      rules. The constructor also requires the placement plan to match the
      survivor plan's count, source order, and copy/promote actions. Unit tests
      cover base-plus-offset materialization, copy/promote generation
      preservation through the relocation map, address overflow rejection,
      invalid low-tag address rejection, base-induced alignment mismatch, and
      mismatched placement-plan rejection. This remains metadata only; reserving
      or choosing pages, allocating destination objects, copying bytes,
      forwarding pointers, root/field writeback, and semispace management remain
      open.
- [x] Current minor-GC relocation-map precursor:
      `ratchet-value::heap::gc::MinorGcRelocationDestination` and
      `MinorGcRelocationPlan::from_minor_gc_plan` validate collector-supplied
      destination metadata for a survivor plan. Relocations keep survivor
      frontier order, preserve copy-vs-promote actions, require one destination
      per live survivor source, reject stale non-survivor sources, and reject
      duplicate destination addresses or any destination that still points into
      the live from-space survivor set. Unit tests cover ordering/action
      preservation plus missing, duplicate-source, duplicate-destination,
      stale-source, and from-space destination rejection. This is still only map
      construction; destination allocation, object copying, forwarding pointers,
      root/field writeback, and semispace management remain open.
- [x] Current minor-GC object-copy scheduling precursor:
      `ratchet-value::heap::gc::MinorGcObjectCopyPlan::from_relocation_plan`
      combines a validated relocation map with caller-supplied nursery layout
      metadata to schedule copy/promote byte ranges in relocation order. Each
      copy records source, destination, copy-vs-promote action, destination
      generation, relocated value metadata, object size, and destination
      alignment. The constructor requires exactly one valid layout per relocated
      source, rejects missing, duplicate, invalid, or stale layout metadata, and
      verifies relocation destinations satisfy the source object's required
      alignment even when callers build relocation maps directly. Unit tests
      cover copy/promote scheduling, relocation-order preservation, relocated
      value generation, layout-validation failure modes, and direct-relocation
      destination-alignment rejection. This constructor remains scheduling
      metadata only; reading or writing real heap object bytes, reserving
      semispace pages, forwarding pointers, root/field writeback, and
      remembered-set mutation remain open.
- [x] Current minor-GC object-byte copy-buffer precursor:
      `MinorGcObjectByteCopyBuffer` and
      `MinorGcObjectCopyPlan::copy_into_buffers` apply an object-copy schedule
      to caller-owned byte slices after checking buffer count, source and
      destination address order, and exact source/destination byte lengths. The
      helper validates the full buffer list before copying any bytes, so count,
      address, or length failures leave all destinations unchanged. Unit tests
      cover copied-young and promoted-old byte copies plus count, source,
      destination, source-length, destination-length, and no-partial-write
      failures. This remains a byte-slice application surface only; destination
      object allocation, real heap storage reads, semispace page reservation,
      forwarding pointers, root/field writeback, and remembered-set mutation
      remain open.
- [x] Current minor-GC owned destination-storage precursor:
      `ratchet-value::heap::gc::MinorGcOwnedDestinationStorage` allocates
      caller-owned next-nursery and old-generation byte buffers from a validated
      `MinorGcDestinationPlacementPlan`, chooses aligned interior bases for each
      generation, exposes those bases through `MinorGcDestinationBases`, and can
      materialize the matching relocation-destination plan. `copy_from_sources`
      accepts source bytes in object-copy order, first verifies that the object
      copy plan exactly matches the storage's placement plan, then validates
      source count, source order, exact byte lengths, destination range bounds,
      and same-generation range overlap before mutating storage. Successful
      copies report copied/promoted counts plus per-generation payload bytes.
      Unit tests cover aligned base materialization, nursery/old payload copying
      with padding preservation, empty placement plans, copy-plan length/
      destination/size mismatch rejection, and source count/source/length
      mismatch rejection with no partial writes. This reserves owned byte
      storage for a planned collection, but still does not allocate live object
      headers, read source bytes from real heap objects, swap nursery semispaces,
      install forwarding pointers, mutate roots/fields, own the card table, or
      rescan old fields.
- [x] Current minor-GC forwarding-pointer planning precursor:
      `ratchet-value::heap::gc::MinorGcForwardingPointerPlan::from_object_copy_plan`
      turns the object-copy schedule into deterministic forwarding-pointer
      metadata in copy order. Each pointer records the from-space source,
      relocated destination address, copy-vs-promote action, destination
      generation, and forwarded heap value that a later collector step would
      install in the source object's forwarding slot. Unit tests cover
      copied-young, promoted-old, forwarded-value generation, and empty
      schedules. This remains header-installation metadata only; object-header
      mutation, object-byte copying, root/field writeback, semispace management,
      and remembered-set mutation remain open.
- [x] Current minor-GC forwarding-slot installation precursor:
      `MinorGcForwardingSlot` and
      `MinorGcForwardingPointerPlan::install_into_slots` apply a validated
      forwarding plan to caller-owned forwarding-slot buffers after checking
      slot count, source order, and empty-slot state. The helper validates the
      full buffer before writing any forwarded value, so count, source, or
      occupied-slot failures leave slots unchanged. Unit tests cover copied-young
      and promoted-old forwarded values plus length, source, occupied-slot, and
      no-partial-write failures. This remains a slot-buffer application surface
      only; real object-header integration, object-byte copying, root/field
      writeback, semispace management, and remembered-set mutation remain open.
- [x] Current minor-GC reference-rewrite precursor:
      `ratchet-value::heap::gc::MinorGcReferenceRewritePlan` turns a
      caller-supplied root/field reference sequence and a validated relocation
      map into deterministic slot rewrite metadata. It ignores inline, old, and
      permanent references, maps copied survivors to young destination values,
      maps promoted survivors to old destination values, keeps duplicate young
      references as separate slot rewrites, and rejects any young reference not
      present in the relocation map. `apply_to_references` can apply the plan to
      a caller-owned slot buffer after validating every planned slot still
      contains the expected young from-space reference; validation failures leave
      the buffer unchanged. Unit tests cover copied/promoted generation mapping,
      duplicate-slot preservation, non-young filtering, missing relocation
      rejection, successful slot-buffer rewrite, stale-slot rejection,
      out-of-bounds rejection, and no-partial-write behavior. Live evaluator
      root/object-field integration, forwarding pointers, remembered sets, and
      semispace management remain open.
- [x] Current minor-GC remembered-set refresh precursor:
      `ratchet-value::heap::gc::MinorGcRememberedSetRefreshPlan` classifies a
      remembered-set snapshot against a validated relocation map. It retains
      copied nursery survivors as rewritten old/permanent-to-young edges, drops
      promoted targets because they are no longer young, and drops stale/dead
      targets that have no relocation. Unit tests cover snapshot-order
      decisions, retained copied edges from distinct sources, promoted-target
      drops, stale/dead drops, retained-edge iteration, and empty snapshots.
      This remains metadata only; mutating the remembered set, advancing epochs,
      rescanning old fields, copying objects, and semispace management remain
      open.
- [x] Current minor-GC remembered-set epoch-rebuild precursor:
      `ratchet-value::heap::gc::RememberedSetEpoch::checked_next` and
      `MinorGcRememberedSetRefreshPlan::rebuild_remembered_set` construct a
      next-epoch remembered set from the refresh plan's retained copied-young
      edges. The helper preserves retained-edge order through the existing
      deduplicating `RememberedSet`, advances the epoch exactly once, and
      rejects epoch overflow. Unit tests cover non-empty rebuilds, empty
      rebuilds, retained-edge filtering, and overflow rejection. This still does
      not mutate the source snapshot, own card-table construction, rescan old
      fields, or invoke the collector.
- [x] Current dirty old-field rescan precursor:
      `ratchet-value::heap::gc::MinorGcOldObjectFields` and
      `MinorGcOldFieldRescanPlan::from_dirty_cards` rescan caller-supplied
      precise old/permanent object fields whose source card is dirty, filter
      non-young field values and clean/young source objects, classify copied
      young targets as retained remembered edges at their relocated nursery
      destination, and drop promoted or dead young targets. The rescan plan
      preserves object/field order and exposes retained edges for remembered-set
      rebuilds. `MinorGcRememberedSetRefreshPlan::rebuild_remembered_set_with_old_field_rescan`
      merges retained snapshot edges with dirty-card rescan edges through the
      same deduplicating remembered-set insertion path while advancing the epoch
      once. Unit tests cover copied, promoted, dead, clean-card,
      permanent-source, and young-source cases plus deduplication between refresh
      and rescan edges. This remains caller-owned metadata; discovering old
      objects from card pages, owning dirty-card scanning state, mutating old
      fields, publishing the remembered set into evaluator state, and collector
      dispatch remain open.
- [x] Current minor-GC commit-plan old-field-rescan precursor:
      `MinorGcCommitPlan::from_parts_with_old_field_rescan` validates dirty
      old/permanent field rescan decisions against the same object-copy schedule
      used by forwarding, reference-rewrite, and remembered-set refresh
      validation before precomputing the next remembered set with retained rescan
      edges included. Publication still validates the caller-owned source
      remembered-set epoch and snapshot edges, while the published next epoch may
      include deduplicated dirty-card rescan edges. Unit tests cover duplicate
      refresh/rescan retention, new dirty-source retention, promoted/dead rescan
      drops, and stale relocation-map rejection through a dedicated
      old-field-rescan mismatch error. This remains commit metadata only; live
      old-field mutation, card-table ownership, evaluator-state dirty-card
      clearing, and collector dispatch remain open.
- [x] Current minor-GC commit-plan precursor:
      `ratchet-value::heap::gc::MinorGcCommitPlan::from_parts` composes the
      validated object-copy schedule, forwarding-pointer plan, reference-rewrite
      plan, and remembered-set refresh into a single ordered commit metadata
      object. It verifies the forwarding plan, reference rewrites, and
      remembered-set refresh decisions are exact projections of the object-copy
      schedule and precomputes the rebuilt next-epoch remembered set, surfacing
      cross-plan mismatches, epoch overflow, or retained-edge storage failures
      before a future mutating collector step begins. Unit tests cover valid
      composition, next remembered-set publication, forwarding count/order
      mismatches, rewrite source/replacement mismatches, retained/drop-promoted/
      drop-dead refresh mismatches, and remembered-set epoch overflow. This
      remains preflight metadata only; byte copying, forwarding-pointer
      installation, live root/field slot mutation, and semispace management
      remain open.
- [x] Current minor-GC remembered-set publication precursor:
      `MinorGcCommitPlan::publish_next_remembered_set` consumes a validated
      commit plan after checking the caller-owned remembered set still matches
      the refresh source epoch and edge sequence, then moves the precomputed
      next-epoch set into place without a post-preflight allocation. Unit tests
      cover successful publication, next-epoch edge replacement, epoch
      mismatch, same-epoch length drift, same-length edge drift, and no partial
      mutation of stale caller-owned sets. This remains only the remembered-set
      publication boundary; object-byte copying,
      forwarding-pointer installation, live root/field slot mutation, card-table
      ownership, and semispace management remain open.
- [x] Current minor-GC commit-buffer application precursor:
      `MinorGcCommitBuffers` and `MinorGcCommitPlan::apply_to_buffers` apply a
      validated commit plan to caller-owned byte-copy buffers, forwarding slots,
      reference slots, and remembered-set state. The helper validates every
      supplied buffer before mutation, then performs the ordered commit steps:
      copy object bytes, install forwarding values, rewrite references, and
      publish the next remembered set, and clear an optional caller-owned
      card-table buffer after publication succeeds. The report-returning variant
      includes the dirty-card clearing count. Unit tests cover successful
      cross-buffer application, dirty-card clearing, and a late remembered-set
      mismatch that leaves byte destinations, forwarding slots, references,
      remembered-set state, and dirty cards unchanged. This remains a
      caller-buffer application surface only; destination object allocation,
      binding buffers to real heap storage or object headers, live card-table
      ownership, old-field rescanning, and semispace management remain open.
- [ ] `runtime/alloc.rs` — all allocation routes through `aos_alloc_*` runtime
      symbols so the GC strategy swaps without touching callers (and, later, the
      JIT) ([03](03-architecture-overview.md) §4.5; `S-8`).
- [x] Current `runtime/alloc.rs` allocation-dispatch precursor:
      `ratchet-oracle::runtime::alloc::RuntimeAllocator` installs the Tier-A
      runtime allocation strategy for the tree-walk oracle; `EvalHeap` no longer
      owns `BumpArena` directly and every typed heap allocation routes through
      centralized `aos_alloc_*`-shaped methods. The actual exported
      `unsafe extern "C"`/JIT-symbol ABI and multi-strategy GC swapping remain
      open in the row above.
- [x] Current allocation-symbol binding precursor:
      `RuntimeAllocationEntryPoint` now carries the frozen `aos_alloc_*` symbol
      name for every centralized runtime allocation route and supports reverse
      lookup from symbol name back to the safe Rust entry point. Tests prove the
      runtime allocation inventory exactly matches `ratchet-core`'s
      `RuntimeHelperRole::Allocation` table and rejects non-allocation symbols.
      This is symbol inventory and dispatch metadata only; no unsafe C exports,
      Cranelift symbol registration, or Tier-B collector body swap is
      implemented here.
- [x] Current runtime symbol-manifest precursor:
      `ratchet-core::runtime_abi::runtime_symbol_manifest()` builds the
      deterministic, lexicographically sorted symbol table that future
      `JITBuilder::symbol` setup can consume before attaching executable
      addresses. The manifest combines every `aos_*` helper and every declared
      `nix.builtin.*` builtin, validates duplicate final symbol names, and tags
      helper entries by `RuntimeHelperRole` while tagging builtin entries
      separately. Tests cover full helper/builtin coverage, sorted uniqueness,
      duplicate rejection, and representative helper/builtin lookups. This is
      registration metadata only; exported wrappers, Cranelift module
      construction, address binding, compiled-artifact relinking, and native
      trap transfer remain open.
- [x] Current runtime symbol binding-manifest precursor:
      `ratchet-oracle::runtime::helpers::runtime_symbol_binding_manifest()`
      consumes the full `ratchet-core` runtime symbol manifest and preserves its
      deterministic order while classifying each symbol as a currently bound
      allocation, call-control, attrset-access, environment-access, forcing, or write-barrier helper, an
      unbound future helper role, or a builtin. Tests cross-check order parity
      with the core manifest, exact safe-helper coverage including `aos_apply`,
      `aos_has_attr`, `aos_select_ic`, `aos_update`, `aos_env_get`, `aos_blackhole_check`, and both forcing helpers.
      Representative unbound helpers include error helpers and builtin
      classification. This is binding-status metadata only; it attaches
      no function pointers, exports no native wrappers, registers no Cranelift
      symbols, and leaves builtin and error helper addresses
      unbound.
- [x] Current runtime symbol registration-preflight precursor:
      `ratchet-oracle::runtime::helpers::runtime_symbol_registration_preflight()`
      converts the binding manifest into a deterministic readiness report for
      future native registration: current allocation, call-control,
      attrset-access, environment-access, forcing, and write-barrier helper bindings stay in runtime-manifest order, and every
      missing helper or builtin binding is reported in stable symbol order. The
      stricter
      `runtime_symbol_registration_plan()` currently returns an incomplete
      registration error until all helper and builtin executable bindings exist.
      Tests cover helper readiness, sorted missing bindings, representative
      error-helper gaps, a builtin gap, and the incomplete-plan failure.
      This is a registration preflight only; it attaches no executable
      addresses, exports no wrappers, and performs no Cranelift registration.
- [x] Current runtime symbol ABI-signature preflight precursor:
      `runtime::helpers::runtime_symbol_abi_signature_preflight()` combines safe
      helper binding metadata with core-owned helper `RuntimeCallSignature`
      metadata and `ratchet-core` builtin call-shape metadata in stable runtime
      symbol order. It attaches allocation, call-control, attrset-access,
      environment-access, forcing, and write-barrier helper signatures only when
      the corresponding core helper signature exists, plus callable builtin
      `RuntimeCallSignature` metadata, while
      leaving unbound helper roles and value-only builtin symbols in the
      missing-binding report. Tests prove helper parity with the safe
      registration preflight, core signature coverage for every currently bound
      helper, builtin parity with the builtin call preflight, exact binding/gap
      projection order, representative callable builtin metadata, and current
      helper/value-only gaps. This is signature metadata only: no executable
      addresses, exported wrappers, `JITBuilder::symbol`
      registrations, Cranelift lowering, native trap transfer, or compiled
      artifact relinking is implemented.
- [x] Current runtime symbol ABI-signature plan precursor:
      `runtime::helpers::runtime_symbol_abi_signature_plan()` is the checked
      completeness gate over the ABI-signature preflight. It returns a
      `RuntimeSymbolAbiSignaturePlan` only once every runtime symbol has
      signature metadata and currently returns an incomplete-plan error carrying
      the full preflight while helper/value-only gaps remain. Tests pin the
      missing count, representative helper and value-only builtin gaps,
      preserved callable builtin metadata, and a synthetic complete conversion
      path. This is metadata gating only: no executable addresses, exported
      wrappers, `JITBuilder::symbol` registrations, Cranelift lowering, native
      trap transfer, or compiled artifact relinking is implemented.
- [x] Current runtime symbol native-target candidate preflight precursor:
      `runtime::helpers::runtime_symbol_native_target_candidate_preflight()`
      consumes the ABI-signature preflight, then combines helper Rust-callable
      availability with the signature-covered helper/builtin set into a
      target-readiness report. It records allocation, call-control,
      attrset-access, environment-access, forcing, and write-barrier helpers as address-free symbol/role
      wrapper-generation candidates and reports ABI-signature gaps, value-only builtins, and
      callable builtins without wrapper bodies as gaps carrying
      builtin-wrapper blockers: missing wrapper body, runtime/env ABI decoding,
      native `Value` argument materialization, evaluator call-frame binding,
      active argument root registration, builtin dispatch binding,
      argument-forcing contract preservation, trap transfer, and native `Value`
      return materialization. Tests prove exact projection order from
      ABI-signature metadata, helper-callable parity, representative
      helper/value-only gaps, all callable builtin wrapper gaps and blockers,
      and no current helper-callable gaps. This is readiness metadata only: no
      executable addresses, exported wrappers, `JITBuilder::symbol`
      registrations, Cranelift lowering, native trap transfer, or compiled
      artifact relinking is implemented.
- [x] Current runtime symbol native-target candidate plan precursor:
      `runtime::helpers::runtime_symbol_native_target_candidate_plan()` is the
      checked completeness gate over the address-free candidate preflight. It
      returns a `RuntimeSymbolNativeTargetCandidatePlan` only when every runtime
      symbol is a symbol/role candidate and currently returns an incomplete-plan
      error carrying the full preflight while helper and builtin gaps remain.
      Tests pin the missing count, representative address-free helper
      candidates, representative helper/builtin gaps, and a synthetic complete
      conversion path. This is symbol/role metadata gating only: no executable
      addresses, exported wrappers, `JITBuilder::symbol` registrations,
      Cranelift lowering, native trap transfer, or compiled artifact relinking is
      implemented.
- [x] Current runtime symbol Rust-callable preflight precursor:
      `runtime::helpers::runtime_symbol_rust_callable_preflight()` consumes the
      same stable runtime symbol manifest, preserves its order, and attaches
      process-local Rust-callable helper metadata for the currently covered
      allocation, call-control, attrset-access, environment-access, forcing, and write-barrier helper symbols
      while reporting unbound helper and builtin symbols as gaps. Tests prove
      helper-callable order matches the helper-family callable inventory,
      callable helper symbols line up with the safe registration preflight, and
      missing symbols remain identical to the existing incomplete registration
      report. This is Rust-callable readiness
      metadata only: the addresses are not exported C ABI targets, not final
      `JITBuilder::symbol` registrations, and not a complete runtime-symbol
      registration plan.
- [x] Current `aos-nix` JIT address-candidate bridge:
      `aos_nix::jit::nix_jit_runtime_symbol_address_candidate_preflight()`
      composes oracle Rust-callable helper metadata with `ratchet-jit`
      runtime-symbol address candidates. It projects process-local callable
      helper addresses for currently covered allocation, call-control,
      attrset-access, environment-access, forcing, and write-barrier helpers into `JitRuntimeSymbolAddressCandidate` values while
      carrying oracle missing bindings for unbound helpers and builtins. The
      bridge now exposes helper-role filtered candidate views, including the
      allocation-helper manifest-order subset. Tests pin allocation,
      call-control, attrset-access, environment-access, forcing, and write-barrier role filtering,
      feed only the allocation-filtered subset through JIT registration, and still cover
      registered env-slot tier-1 promotion for `aos_env_get`. This is safe
      integration preflight plumbing only: it does not export C ABI wrappers,
      make addresses serializable or relinkable, cast finalized code pointers,
      dereference registered addresses, call native code, or complete
      runtime-symbol registration.
- [x] Current `aos-nix` runtime-symbol registration preflight bridge:
      `aos_nix::jit::nix_jit_runtime_symbol_registration_preflight()`
      builds the oracle-derived address-candidate preflight, carries the oracle
      native-export preflight, and immediately feeds the address candidates
      through `ratchet-jit` runtime-symbol registration readiness. The returned
      report owns those handoff inputs and separately reports that the current
      candidates still have Rust-callable rather than exported-wrapper address
      provenance. Tests prove allocation-helper, `aos_apply`, `aos_env_get`,
      `aos_force`/`aos_force_deep`, and `aos_gc_write_barrier`
      binding/address parity, preserve the current
      unbound helper and builtin missing-native-address registration gaps, and
      prove registered helper addresses still retain missing exported-wrapper
      blockers plus Rust-callable provenance gaps. This is safe integration preflight
      metadata only: it does not call
      `JITBuilder::symbol`, export C ABI wrappers, finalize code, dereference
      helper addresses, call native code, or complete runtime-symbol
      registration.
- [x] Current `aos-nix` runtime-symbol registration plan gate:
      `aos_nix::jit::nix_jit_runtime_symbol_registration_plan()` derives
      oracle address candidates, carries oracle native-export readiness, and
      requires the JIT registration preflight, native-export preflight, and
      exported-address provenance gate to be complete before returning a complete
      plan. The current implementation returns a typed incomplete error carrying
      the owned Nix preflight while unbound helper/builtin address gaps,
      exported-wrapper blockers, and Rust-callable address-provenance gaps
      remain. `aos_apply`, `aos_force`, and `aos_force_deep` now have
      Rust-callable address candidates but still carry family-specific
      native-export and provenance blockers. This is
      strict metadata gating only: it
      does not call
      `JITBuilder::symbol`, export C ABI wrappers, finalize code, dereference
      helper addresses, call native code, or complete runtime-symbol
      registration.
- [x] Current `aos-nix` registered tier-1 promotion bridge:
      `aos_nix::jit::nix_jit_registered_tier1_promotion_preflight_for_ir_root()`
      derives oracle helper address candidates and drives the registered-symbol
      Cranelift tier-1 promotion preflight from the top-level integration crate.
      Candidate projection runs only after policy requests tier 1. Tests cover
      cold no-lowering/no-candidate behavior, candidate failure after a
      promotion decision, and threshold env-slot promotion using the
      oracle-derived `aos_env_get` candidate. This keeps
      `ratchet-jit` free of an oracle dependency while giving `aos-nix` a single
      safe promotion handoff. It does not mutate evaluator heap thunks, perform
      atomic thunk-state CAS, cast or call finalized code pointers, dereference
      registered addresses, call native code, or complete runtime-symbol
      registration.
- [x] Current `aos-nix` force-aware registered tier-1 promotion bridge:
      `aos_nix::jit::nix_jit_force_aware_registered_tier1_promotion_preflight_for_ir_root()`
      derives oracle helper address candidates and drives the force-aware
      Cranelift promotion preflight from the top-level integration crate.
      Candidate projection still runs only after policy requests tier 1, so
      cold roots record an invocation and remain in tier 0 without requiring
      helper-address metadata. Literal roots still promote with no artifact
      runtime imports. Hot local environment-slot roots lower through the forced
      env-slot artifact importing `aos_env_get` and `aos_force`; the current
      oracle candidates include both helpers, but `aos_force` still has no
      exported native wrapper, so the bridge reports the registered-module
      finalization guard before tier-slot pointer installation. This keeps the force-aware bridge safe:
      it does not mutate evaluator heap thunks, perform atomic thunk-state CAS,
      cast or call code pointers, dereference registered addresses, call native
      code, or complete runtime-symbol registration.
- [x] Current `aos-nix` registered tier-1 install-plan handoff:
      `aos_nix::jit::nix_jit_registered_tier1_install_plan_for_ir_root()`
      wraps the registered promotion preflight in a safe handoff object that
      owns the updated tier slot and, for promoted roots, the encapsulated
      Cranelift module backing the opaque tier-1 code pointer. Tests cover cold
      slot preservation, promoted pointer metadata, registered `aos_env_get`
      visibility, and module ownership. This creates the future evaluator thunk
      install boundary but still does not mutate heap thunks, perform atomic
      thunk-state CAS, cast or call code pointers, dereference registered
      addresses, call native code, or complete full/native runtime-symbol
      registration for unrelated stable symbols.
- [x] Current `aos-nix` force-aware registered tier-1 install-plan handoff:
      `aos_nix::jit::nix_jit_force_aware_registered_tier1_install_plan_for_ir_root()`
      wraps the force-aware registered promotion preflight in the same safe
      handoff object used by the existing registered path. Tests cover cold slot
      preservation before candidate projection, literal pointer/module-owner
      readiness, and the current hot env-slot `aos_force` registered-module
      finalization guard before pointer installation. This creates the future
      force-aware evaluator thunk install boundary but still does not mutate heap
      thunks, perform atomic thunk-state CAS, cast or call code pointers,
      dereference registered addresses, call native code, or complete
      runtime-symbol registration.
- [x] Current `aos-nix` evaluator-thunk install readiness preflight:
      `aos_nix::jit::nix_jit_registered_tier1_thunk_install_readiness_for_ir_root()`
      wraps the registered install plan in a read-only report against a target
      evaluator thunk. The report distinguishes missing tier-1 code, missing
      module ownership, non-node thunks, module-qualified IR-root mismatches,
      and non-suspended thunk states from the future publication gaps: heap
      tier-slot storage, atomic thunk-state publish, and native thunk-entry
      dispatch. Tests cover cold no-code reports, a promoted suspended-node
      thunk, non-node rejection, IR-root mismatch, same-IR-id module mismatch,
      missing module ownership for an already-installed slot, and forced-thunk
      rejection. This is safe readiness plumbing only: it does not mutate heap
      thunks, perform atomic thunk-state CAS, cast or call code pointers,
      dereference registered addresses, call native code, or complete
      full/native runtime-symbol registration.
- [x] Current `aos-nix` force-aware evaluator-thunk install readiness preflight:
      `aos_nix::jit::nix_jit_force_aware_registered_tier1_thunk_install_readiness_for_ir_root()`
      wraps the force-aware registered install plan in the same read-only report
      against a target evaluator thunk. Tests cover cold no-code reports,
      literal roots reaching the existing future publication gaps, and hot
      env-slot roots preserving the `aos_force` finalization guard before
      pointer installation or evaluator publication. This is safe readiness
      plumbing only: it does not mutate heap thunks, perform atomic thunk-state
      CAS, cast or call code pointers, dereference registered addresses, call
      native code, or complete runtime-symbol registration.
- [x] Current `aos-nix` tier-1 conformance-readiness preflight:
      `aos_nix::jit::nix_jit_tier1_conformance_readiness_for_ir_root()`
      aggregates the top-level runtime-symbol registration bridge and one
      evaluator-thunk install-readiness report into the blocker set for enabling
      the differential harness with tier 1 active. It reports JIT
      runtime-symbol registration gaps, native-export gaps, Rust-callable
      address-provenance gaps, and per-thunk install gaps without running native
      code. Tests cover a hot env-slot root that reaches opaque tier-1
      code-pointer metadata but remains blocked by runtime/export/provenance
      and evaluator publication gaps, plus a cold no-compile root. This remains
      a harness-facing gate report only: it does not run the harness, mutate
      evaluator heap thunks, perform atomic thunk-state CAS, cast or call code
      pointers, dereference registered helper addresses, call native code, or
      prove tier-1 output parity.
- [x] Current `aos-nix` force-aware tier-1 conformance-readiness preflight:
      `aos_nix::jit::nix_jit_force_aware_tier1_conformance_readiness_for_ir_root()`
      aggregates the top-level runtime-symbol registration bridge and one
      force-aware evaluator-thunk install-readiness report. Tests cover literal
      roots reaching the existing runtime-symbol and future-publish blockers,
      cold roots preserving the no-code gap, and hot env-slot roots surfacing the
      `aos_force` finalization guard before pointer installation or evaluator
      publication. This is a harness gate only: it does not mutate heap
      thunks, perform atomic thunk-state CAS, cast or call code pointers,
      dereference registered addresses, call native code, or complete
      runtime-symbol registration.
- [x] Current allocation ABI-signature precursor:
      `RuntimeAllocationAbiSignature` records success-path helper signature
      metadata for each `aos_alloc_*` entry point: a leading runtime context
      parameter, entry-specific native payload parameters (`code_ptr`/`env`,
      `shape`/`slots`, `head`/`tail`, lengths, raw size/align/tag), and a typed
      allocation pointer result kind. Tests assert the signature table remains
      ordered with `RuntimeAllocationEntryPoint`, matches the `ratchet-core`
      allocation helper symbol inventory, and pins the parameter/result shape for
      every helper. The signature descriptor also resolves from a frozen symbol
      name so future registration code can consume the same inventory. This is
      metadata only; actual exported `unsafe extern "C"` functions, the
      executable trap-transfer wrappers, Cranelift symbol registration, native
      startup binding, every-tier/primop routing, and Tier-B collector body
      swapping remain open.
- [x] Current allocation-vtable precursor:
      internal `RuntimeAllocationVTable` dispatch is selected from the installed
      `RuntimeAllocator` backend and carries typed safe Rust function pointers for
      every frozen `aos_alloc_*` route. The existing public allocator entry
      points now dispatch through that table before reaching the Tier-A
      `BumpArena` bodies, and tests assert both default/configured allocator
      construction and direct crate-internal vtable calls preserve the expected
      safepoint entry points. This is internal safe Rust startup dispatch only; no
      unsafe C exports, native trap transfer, Cranelift symbol registration,
      Tier-B table, or compiled-artifact relinking is implemented here.
- [x] Current allocation-request dispatch precursor:
      `RuntimeAllocationRequest` now captures the safe storage-reservation
      payload for each frozen `aos_alloc_*` entry point, exposes its entry-point
      and symbol mapping, and gives `RuntimeAllocator::allocate` a single typed
      request wall over the installed `RuntimeAllocationVTable`. The existing
      public `aos_alloc_*` methods route through that request wall, preserving
      Tier-A safepoint accounting while making future native wrappers consume
      the same request-to-entry-point contract. Tests cover manifest-order
      request dispatch, symbol mapping, expected heap-object kinds, and
      safepoint entry-point recording. This is still safe Rust dispatch only; no
      unsafe C exports, semantic ABI payload initialization, Cranelift symbol
      registration, Tier-B table, or compiled-artifact relinking is implemented
      here.
- [x] Current allocation-safepoint request-preservation precursor:
      allocation safepoints, GC-stress collector-poll requests, and high-water
      memory-budget decisions now retain the full `RuntimeAllocationRequest` and
      derive the legacy entry-point accessor from that payload. This preserves
      request details that are lossy in post-allocation object metadata, such as
      raw allocation alignment, while keeping existing entry-point consumers
      stable. Tests cover request preservation through typed dispatch,
      collector-poll requests, permanent-shared polls, sequence-saturation
      polls, and budget decisions. This remains metadata only; no collector is
      invoked, no native wrapper receives the payload, and Tier-B routing is
      still open.
- [x] Current allocation Rust-callable address precursor:
      `runtime::alloc::runtime_allocation_rust_callable_bindings()` now attaches
      a process-local Rust storage-wrapper function address to every frozen
      `aos_alloc_*` entry point in manifest order, separately from the frozen
      native ABI signature. The callable wrappers dispatch back through
      `RuntimeAllocator`, so registration metadata can name the selected
      allocator strategy boundary rather than the Tier-A bump-arena bodies
      directly. Tests prove entry-point/signature order parity, exact
      entry-point-to-wrapper pointer mapping, non-null callable addresses, and
      full request preservation through each wrapper (`attrs`, `cons`, `lambda`,
      `list`, `raw`, `string`, and `thunk`). This is still not the exported C
      ABI: these Rust addresses are not callable through
      `RuntimeAllocationAbiSignature`, and no `unsafe extern "C"` symbols,
      semantic payload initialization for `code_ptr`/`env` or `head`/`tail`,
      trap transfer, Cranelift registration, Tier-B table, or compiled-artifact
      relinking is implemented here.
- [x] Current write-barrier symbol/signature precursor:
      `ratchet-core::runtime_abi` now reserves the single
      `RuntimeHelperRole::WriteBarrier` helper symbol, `aos_gc_write_barrier`,
      alongside the allocation helper inventory. `ratchet-oracle::runtime::barrier`
      mirrors that symbol as `RuntimeWriteBarrierEntryPoint` and pins its
      machine-level signature: runtime context, source thunk pointer whose
      forced-result slot is being updated, and published `Value`, returning
      unit. Tests prove the oracle write-barrier
      inventory exactly matches the core helper role, round-trips from symbol
      text, and rejects non-barrier helpers. This is ABI metadata only; it does
      not export the `unsafe extern "C"` function, register Cranelift symbols,
      or wire compiled code to the heap-backed thunk-resolve barrier.
- [x] Current write-barrier vtable precursor:
      internal `RuntimeWriteBarrierVTable` dispatch is selected from the
      configured `GenerationalGcTier` and carries the frozen
      `aos_gc_write_barrier` entry-point/signature inventory plus a safe Rust
      function pointer for thunk-result publication. The one-shot table returns
      a disabled `ThunkResolveBarrier`, while the daemon-generational table
      creates the heap-backed `EvalHeapThunkResolveBarrier` and can attach a
      caller-owned card table. Tree-walk thunk publication now enters this
      runtime dispatch wall before calling `ForceGuard::finish_with_barrier`,
      and tests cover tier selection, the disabled route, the daemon
      heap-adapter route with and without a card table, and end-to-end
      remembered-edge/card-mark behavior. This is internal safe Rust dispatch
      only; it does not export the `unsafe extern "C"` function, register
      Cranelift symbols, mutate object generations, or install the Tier-B
      collector table.
- [x] Current write-barrier Rust-callable address precursor:
      `runtime::barrier::runtime_write_barrier_rust_callable_bindings()` now
      attaches a process-local Rust thunk-resolution barrier-constructor address
      to `aos_gc_write_barrier`, separately from the frozen native ABI
      signature. The callable wrapper dispatches through the selected
      `RuntimeWriteBarrierVTable`, preserving the one-shot and daemon
      generational routes. Tests prove entry-point/signature order parity, exact
      entry-point-to-wrapper pointer mapping, non-null callable addresses, and
      wrapper dispatch through both vtable routes. This is still not the
      exported C ABI: the Rust address is not callable through
      `RuntimeWriteBarrierAbiSignature`, and no `unsafe extern "C"` symbol,
      runtime-context extraction, native thunk/value decoding, trap transfer,
      Cranelift registration, object-generation mutation, or Tier-B collector
      installation is implemented here.
- [x] Current runtime-helper binding-manifest precursor:
      `ratchet-oracle::runtime::helpers` now combines the allocation,
      call-control, attrset-access, environment-access, forcing, and
      write-barrier helper families into one safe
      `RuntimeHelperBinding` inventory. Each binding carries the frozen helper
      symbol, core helper role, family-specific ABI signature, and failure
      convention, and resolves back from symbol text. The current allocation,
      call-control, attrset-access, environment-access, forcing, and
      write-barrier helpers are pinned as
      `TrapToEvaluator`: they return only on success and future native wrappers
      must transfer failures to evaluator trap/error machinery instead of
      returning null pointers or sentinels. Tests prove the manifest exactly
      covers the currently bound `RuntimeHelperRole::Allocation`,
      `RuntimeHelperRole::CallControl`, `RuntimeHelperRole::AttrsetAccess`,
      `RuntimeHelperRole::EnvironmentAccess`,
      `RuntimeHelperRole::ForcingControl`, and `RuntimeHelperRole::WriteBarrier`
      symbols from `ratchet-core`, preserves
      the allocation/call-control/attrset-access/environment-access/forcing/write-barrier ABI
      inventories, pins the
      helper failure convention by symbol, and rejects helper roles that still
      have no safe runtime binding. This is a registration manifest only; it
      does not export `unsafe extern "C"` functions, implement trap transfer,
      register Cranelift symbols, or add bindings for error
      helpers.
- [x] Current runtime-helper Rust-callable preflight precursor:
      `runtime::helpers::runtime_helper_rust_callable_bindings()` lifts the
      allocation, call-control, attrset-access, environment-access, forcing, and
      write-barrier Rust-callable
      storage-wrapper addresses into the helper-family layer, while
      `runtime_helper_rust_callable_preflight()` reports whether any currently
      bound helper family still lacks such a callable. The preflight is now
      complete for the currently bound allocation, call-control, attrset-access,
      environment-access, forcing, and write-barrier helper set. Tests prove
      family inventory parity, safe-helper
      metadata round trips, exact callable coverage, and the empty
      missing-binding report. This is still helper-family Rust metadata only: no
      exported C ABI symbols, Cranelift registration, unbound
      error helpers, builtin addresses, or complete
      runtime-symbol registration plan is implemented.
- [x] Current allocation-safepoint metadata precursor:
      `runtime::alloc` now records an `AllocationSafepoint` at every
      centralized worker `aos_alloc_*` route and every permanent-shared
      allocation route, including allocator tier, entry-point name, object kind,
      allocation sizes, and post-allocation arena accounting. Tests pin exactly
      one safepoint for `thunk`, `lambda`, `attrs`, `cons`, `list`, `string`,
      and `raw` worker allocations plus permanent `attrs`, `list`, and
      `string` allocations. This remains metadata only; collector invocation,
      live-root construction, GC-stress execution, and exported C ABI symbols
      remain open.
- [x] Current allocation native-export readiness gate:
      `runtime::alloc::runtime_allocation_native_export_preflight()` records the
      exact blockers that keep each frozen `aos_alloc_*` helper from being an
      exported native ABI symbol: missing `unsafe extern "C"` wrapper,
      runtime-context ABI decoding, evaluator trap transfer, typed pointer
      return materialization, and the extra semantic-payload initialization gap
      for `aos_alloc_cons`, `aos_alloc_lambda`, and `aos_alloc_thunk`.
      `runtime::helpers::runtime_symbol_native_export_preflight()` lifts that
      into full runtime-symbol order, preserving earlier helper/builtin
      candidate gaps and converting current address-free helper candidates into
      explicit missing exported-wrapper gaps. The strict
      `runtime_symbol_native_export_plan()` still rejects as incomplete. This is
      safe readiness metadata only: no C ABI function is exported, no Rust
      callable is treated as ABI-callable, no `JITBuilder::symbol` registration
      occurs, and no native trap transfer or semantic object initialization is
      implemented.
- [x] Current environment-access native-export readiness gate:
      `runtime::env::runtime_env_access_native_export_preflight()` records the
      exact blockers that keep `aos_env_get` from being an exported native ABI
      symbol: missing `unsafe extern "C"` wrapper, native environment-pointer
      and frame-layout binding, `EvalFrame` borrow-conflict preservation,
      slot-index decoding, evaluator trap transfer, and by-value `Value` return
      materialization. The aggregate
      `runtime::helpers::runtime_symbol_native_export_preflight()` now preserves
      allocation-specific blockers for `aos_alloc_*`,
      environment-access-specific blockers for `aos_env_get`,
      write-barrier-specific blockers for `aos_gc_write_barrier`, and earlier
      helper/builtin candidate gaps in full runtime-symbol order. This remains
      safe readiness metadata only: no C ABI function is exported, no Rust
      callable is treated as ABI-callable, no `JITBuilder::symbol` registration
      occurs, and no native trap transfer, frame-layout/borrow binding, or `Value` ABI
      return path is implemented.
- [x] Current write-barrier native-export readiness gate:
      `runtime::barrier::runtime_write_barrier_native_export_preflight()`
      records the exact blockers that keep `aos_gc_write_barrier` from being an
      exported native ABI symbol: missing `unsafe extern "C"` wrapper,
      runtime-context ABI decoding, runtime GC-state extraction for the
      heap/remembered set/card table, native source-thunk/value decoding,
      evaluator trap transfer, and dispatch into the safe before-publish barrier
      path. The aggregate
      `runtime::helpers::runtime_symbol_native_export_preflight()` now preserves
      allocation-specific blockers for `aos_alloc_*`,
      environment-access-specific blockers for `aos_env_get`,
      write-barrier-specific blockers for `aos_gc_write_barrier`, and earlier
      helper/builtin candidate gaps in full runtime-symbol order. This remains
      safe readiness metadata only: no C ABI function is exported, no Rust
      callable is treated as ABI-callable, no `JITBuilder::symbol` registration
      occurs, and no native trap transfer or thunk/value decoding is implemented.
- [x] Current allocation collector-poll request precursor:
      `AllocationSafepoint::collector_poll` and
      `AllocationSafepointState::last_safepoint_collector_poll` expose a typed
      `AllocationCollectorPoll` when GC-stress policy marks the most recent
      allocation safepoint for collection. The request carries safepoint
      sequence, allocator tier, `aos_alloc_*` entry point, poll reason, and
      post-allocation arena accounting. Tests cover disabled safepoints, worker
      and permanent-shared GC-stress requests, and sequence saturation. This is
      a collector dispatch request only; live-root construction, collector
      invocation, relocation, and byte-green GC-stress execution remain open.
- [x] Current allocation-poll precise-scan snapshot precursor:
      `EvalHeap::scan_collector_poll_roots` pairs an allocation collector-poll
      request with a validated `AllocationCollectorPollScan` built from an
      explicit caller-supplied `EvalRootSet`. The snapshot retains the original
      poll metadata and the `PreciseHeapScan` graph that future collector
      dispatch will consume. Tests cover a real GC-stress allocation poll,
      precise traversal of the reachable object graph, and preservation of the
      triggering `aos_alloc_*` entry point. It does not automatically derive
      tree-walk roots from the poll, invoke a collector, expose mutable
      relocation slots, or update references. The tree-walk safepoint bridge
      below now supplies evaluator roots and transient value-stack roots for
      callers that already captured the exact poll to scan.
- [x] Current allocation-poll minor-GC planning bridge precursor:
      `EvalHeap::plan_collector_poll_minor_gc` converts an
      `AllocationCollectorPollScan` plus a remembered-set snapshot into the
      existing `MinorGcPlan` survivor frontier. The bridge classifies current
      oracle worker records as young and permanent-shared records as permanent,
      rejects stale copied graph snapshots when object edges, heap record count,
      or allocator safepoint state changes, generates nursery age and precise
      field metadata from the typed side table, validates remembered-set edges
      against current oracle generations, and fails closed when any current
      permanent-to-young edge is missing from the supplied remembered set. Unit
      tests cover worker-root survivor expansion, permanent-to-worker
      remembered-edge rejection inside and outside the explicit root graph,
      remembered-edge success, stale thunk-state snapshots, and heap-growth
      staleness. It still does not automatically derive tree-walk roots from an
      allocation poll, retain mutable root/field relocation slots, copy objects,
      install forwarding pointers, mutate references, or run GC-stress
      collection.
- [x] Current allocation-poll card-table validation precursor:
      `GcCardTableSnapshot` exposes the dirty-card view produced by daemon
      thunk-resolution write barriers, and
      `EvalHeap::plan_collector_poll_minor_gc_with_card_table` verifies every
      remembered-edge source is covered by a dirty source card before deriving
      the minor-GC survivor frontier. `EvalOutcome` uses that stricter planner
      for GC-stress boundary plans, so the recorded daemon card table
      participates in the dry-run collector path. Tests cover low-level snapshot
      coverage, direct and boundary-level missing dirty-card rejection,
      dirty-card success, and the existing boundary remembered-edge dry-run.
      This remains validation metadata only; card-table clearing against the
      live daemon table, object-generation mutation, and Tier-B collector
      installation remain open.
- [x] Current allocation-poll dirty old-field rescan bridge precursor:
      card-table-aware `AllocationCollectorPollMinorGcPlan`s now capture an
      owned dirty-card snapshot plus current old/permanent field metadata.
      `EvalHeap::plan_collector_poll_minor_gc_with_card_table` still fails
      closed for unremembered permanent-to-young edges whose source card is not
      dirty, while dirty unremembered fields seed the survivor frontier and
      receive heap-backed dirty-old-field reference slots for later rewrite
      metadata.
      `AllocationCollectorPollMinorGcPlan::commit_plan` then builds a
      `MinorGcOldFieldRescanPlan` from the captured card/field metadata and
      composes it through `MinorGcCommitPlan::from_parts_with_old_field_rescan`,
      so the precomputed next remembered set can include deduplicated dirty-card
      rescan edges while publication still validates only the source remembered
      snapshot. Unit tests cover dirty remembered-edge success, dirty
      unremembered survivor expansion for copied and promoted targets,
      dirty-old-field rewrite/writeback metadata, old-field metadata capture,
      and rescan publication of unremembered targets. This remains a planning
      bridge only; live root/field mutation, semispace ownership, and collector
      dispatch remain open; live card-table and remembered-set bridges are
      covered below.
- [x] Current allocation-poll card-table commit-buffer precursor:
      boundary commit preflights now carry an owned fallible clone of the
      daemon-wide card-table snapshot, and
      `AllocationCollectorPollMinorGcCommitBuffers::with_card_table` threads that
      buffer through to the lower-level commit application. The owned dry-run
      clears dirty cards only after object-byte copies, forwarding slots,
      reference rewrites, and remembered-set publication validate and apply.
      Worker and permanent-shared boundary applications each receive their own
      daemon-wide clone, and the dry-run summary aggregates their dirty-card
      clearing counts alongside the per-owned application reports.
      Tests cover low-level dirty-card clearing, no-partial-clear on stale commit
      buffers, boundary remembered-edge dry-run clearing of the owned card
      table, and sibling boundary preflights clearing independent daemon-wide
      copies. This remains an owned-buffer dry-run for object bytes, forwarding
      slots, reference storage, and remembered-set publication; outcome-owned
      live card-table clearing is covered by the next row, while evaluator/daemon
      collector installation remains open.
- [x] Current boundary live-card-table clearing bridge:
      `EvalOutcome::gc_stress_boundary_minor_gc_commit_dry_run_with_live_card_table`
      derives the same boundary commit dry run and clears the outcome-owned
      daemon card table only after every recorded allocator tier has validated
      and applied its owned synthetic commit buffers. The returned report keeps
      duplicated owned dry-run card clears separate from the single live
      outcome-card-table clear, and failed planning or commit validation leaves
      the live table unchanged. Tests cover remembered-edge and dirty old-field
      boundary successes, multi-card live clears, empty-boundary no-clear
      behavior, and a missing-dirty-card failure that preserves the original live
      dirty-card marker. This is still not a full live collector commit: live
      root/field mutation, live heap-object byte binding, real object-header
      forwarding metadata, object-generation mutation, semispace ownership, and
      Tier-B dispatch remain open.
- [x] Current boundary live remembered-set publication bridge:
      `EvalOutcome::gc_stress_boundary_minor_gc_commit_dry_run_with_live_remembered_set`
      derives the same boundary commit dry run, leaves empty outcomes unchanged,
      and for non-empty outcomes publishes a next-epoch remembered set into
      outcome-owned state before clearing the outcome-owned daemon card table.
      Sibling worker/permanent applications are merged by unioning their
      validated next remembered-set edges at the shared next epoch, after first
      verifying that sibling survivor forwarding slots form a coherent merged
      relocation map: overlapping sources must agree and distinct sources must
      not collide on one destination, and destination addresses must be disjoint
      from the merged source set. The returned report records whether
      publication happened and how many live dirty cards were cleared. Unit tests
      cover single-tier worker and permanent-shared publication with live-card
      clearing, multi-tier merge publication with observed raw relocation-map
      coherence and live-card clearing, and empty-boundary no-mutation behavior.
      This is still not a full live collector commit: live root/field mutation,
      live heap-object byte binding, real object-header forwarding metadata,
      object-generation mutation, semispace ownership, and Tier-B dispatch
      remain open.
- [x] Current boundary live forwarding-slot bridge:
      `EvalOutcome::gc_stress_boundary_minor_gc_commit_dry_run_with_live_forwarding_slots`
      derives the same owned boundary commit dry run, merges sibling
      worker/permanent forwarding applications through the same raw
      relocation-map coherence checks used by live remembered-set publication,
      and installs the deduplicated forwarding values into evaluator heap
      side-table cells only after every dry-run and live-slot validation
      succeeds. Empty/no-survivor boundaries leave forwarding cells unchanged,
      and occupied live forwarding cells reject repeat installation without
      partial mutation. Unit tests cover copied-young, promoted-old, multi-tier
      overlapping-source merge, repeat-install rejection/no-mutation, and
      empty-boundary no-op behavior. This is still not a full live collector
      commit: live root/field mutation, live heap-object byte binding, real ABI
      object-header forwarding writes, object-generation mutation, semispace
      ownership, remembered-source field mutation, and Tier-B dispatch remain
      open.
- [x] Current boundary live destination-byte side-table bridge:
      `EvalOutcome::gc_stress_boundary_minor_gc_commit_dry_run_with_live_destination_storage`
      derives the same owned boundary commit dry run, verifies sibling
      worker/permanent applications through the shared raw relocation-map
      coherence checks, deduplicates overlapping object-copy snapshots that
      agree, and installs per-destination object payload bytes into an
      outcome-owned side table only after dry-run and merge validation succeeds.
      Empty/no-survivor boundaries leave the side table unchanged, and repeat
      installs reject without partial mutation. Unit tests cover copied-young,
      promoted-old, multi-tier overlapping-source merge, repeat-install
      rejection/no-mutation, and empty-boundary no-op behavior. This is still
      not a full live collector commit: installed bytes are not bound to live
      heap-object bodies or semispace pages, and live root/field mutation, real
      ABI object-header forwarding writes, object-generation mutation,
      remembered-source field mutation, and Tier-B dispatch remain open.
- [x] Current boundary live reference-writeback side-table bridge:
      `EvalOutcome::gc_stress_boundary_minor_gc_commit_dry_run_with_live_reference_writebacks`
      derives the same owned boundary commit dry run, validates sibling survivor
      relocations through the shared raw relocation-map coherence checks, clones
      the already validated root and heap-field writeback buffers, and installs
      those rewritten slot snapshots into outcome-owned metadata only after
      dry-run validation succeeds. Empty/no-writeback boundaries leave the side
      table unchanged, and repeat installs reject without partial mutation. Unit
      tests cover root writebacks, dirty old-field heap writebacks,
      no-writeback no-ops, partition preservation, repeat-install rejection, and
      unchanged live card-table state. This is still not a full live collector commit: the slots are not
      bound to live evaluator roots or heap object fields, and live root/field
      mutation, real ABI object-header forwarding writes, object-generation
      mutation, remembered-source field mutation, and Tier-B dispatch remain
      open.
- [x] Current allocation-poll reference-slot precursor:
      `AllocationCollectorPollMinorGcPlan` carries a deterministic, labeled
      reference-slot sequence for the future rewrite step: explicit roots from
      the poll scan, remembered-edge source fields in snapshot order, and
      dirty old/permanent fields from the card-table-aware rescan, and precise
      `HeapEdgeSource`-labeled fields of planned young survivors in survivor
      order. Remembered edges are expanded through current concrete source
      fields, so duplicate source fields produce distinct rewrite slots and
      stale remembered entries with no current field are rejected. Dirty
      old/permanent fields seed the card-table-aware survivor frontier after the
      remembered-set frontier and receive their own heap-field-backed slots. The
      `reference_rewrite_plan` helper delegates that sequence to
      `MinorGcReferenceRewritePlan` once a relocation map exists, preserving
      slot indices so tests can link rewrites back to copied roots, remembered
      source fields, dirty old/permanent fields, and survivor fields. Unit tests
      cover root and nursery-field rewrites, remembered-edge rewrites, duplicate
      remembered source fields, dirty-card unremembered survivor edges, mixed
      remembered/dirty frontier ordering, clean unremembered source-card
      rejection, and stale remembered-edge rejection. This remains copied slot
      metadata only;
      mutable evaluator roots, object-field writeback, remembered-source field
      mutation, and live runtime-state application remain open.
- [x] Current allocation-poll destination-planning bridge precursor:
      `AllocationCollectorPollMinorGcPlan::relocation_destination_plan`
      composes the poll survivor frontier with caller-supplied nursery layouts
      and caller-chosen nursery/old destination bases to build the existing
      lower-level destination allocation, aligned placement, and materialized
      relocation-destination plans. The wrapper preserves all three
      intermediate plans so tests can assert copied-young and promoted-old
      allocation/reserved-byte accounting before commit metadata is built.
      `EvalHeap::plan_collector_poll_minor_gc_relocation_destinations` derives
      survivor layouts from allocator-recorded heap side-table size/alignment
      metadata and rejects heap record or allocation-safepoint changes after
      planning before materializing destinations. This remains destination
      metadata only; semispace page reservation, base selection, object storage
      allocation, buffer binding to real heap objects, and generation-space
      management remain open.
- [x] Current allocation-poll commit-plan bridge precursor:
      `AllocationCollectorPollMinorGcPlan::commit_plan` owns the remembered-set
      snapshot used by the poll plan and composes the existing lower-level
      object-copy, forwarding-pointer, reference-rewrite, and remembered-set
      refresh subplans into a `MinorGcCommitPlan` from the materialized
      allocation-poll destination wrapper. It validates the wrapper's placement
      count, survivor source order, and copy/promote actions against the poll
      plan's own survivor frontier, rebuilds the relocation map against that
      frontier, and derives object-copy sizes from the validated placement plan.
      The bridge preserves the poll plan's
      labeled reference slots beside the commit metadata, so tests can connect
      lower-level rewrites back to copied roots, remembered source fields, dirty
      old/permanent fields, and survivor fields. Unit tests cover empty
      remembered-set commit metadata, retained copied-young remembered edges, and
      rejection of a destination plan built for a different poll survivor
      frontier or promotion policy. This remains metadata only; destination
      storage allocation, binding byte buffers
      to real objects, forwarding-slot installation, live root/object-field
      mutation, remembered-source field mutation, remembered-set publication, and
      semispace management remain open.
- [x] Current allocation-poll commit-buffer bridge precursor:
      `AllocationCollectorPollMinorGcCommitPlan::apply_to_buffers` and
      `AllocationCollectorPollMinorGcCommitBuffers` expose a caller-buffer
      application boundary at the allocation-poll layer. The bridge verifies
      that caller-owned reference values still match every copied poll reference
      label/value before delegating object-byte copies, forwarding-slot
      installation, reference rewrites, and remembered-set publication to the
      already validated lower-level `MinorGcCommitPlan`. `EvalHeap` can derive a
      live reference buffer for heap-field-backed slots by re-reading
      remembered-source, dirty old/permanent, and nursery-field labels from the
      side table while rejecting copied root slots, and can derive heap-field
      writeback metadata from lower-level rewrites by revalidating each
      remembered-source, dirty old/permanent, or nursery field's label, copied
      value, and lower-level rewrite source before returning the planned
      replacement. Remembered and dirty old/permanent fields write back through
      their existing source object, while nursery fields name the relocated
      destination object that would receive the rewritten field. Root rewrites are
      skipped by that heap-field writeback view because their mutable storage
      remains external to `EvalHeap`;
      `AllocationCollectorPollMinorGcCommitPlan::root_writeback_plan` exposes
      those root-backed rewrites as metadata with the same slot-to-rewrite source
      validation, and `EvalHeap::collector_poll_minor_gc_reference_writeback_plan`
      returns the root and heap-field writeback partitions together.
      The allocation-poll commit wrapper now carries the heap record and
      allocation-safepoint snapshot used by heap-backed buffer derivation.
      `EvalHeap::collector_poll_minor_gc_object_byte_copy_plan` rejects stale
      commit snapshots, validates planned copy sources against current young
      worker-domain heap records, and returns source/destination/size/alignment/action
      requests for a future storage owner.
      `AllocationCollectorPollMinorGcCommitPlan::forwarding_slot_buffer` derives
      empty caller-owned forwarding slots in lower-level forwarding-pointer order.
      `EvalHeap::collector_poll_minor_gc_reference_buffer` merges caller-supplied
      current root values with live heap-field reads into one full
      reference-slot-order buffer for later caller-owned commit application. Unit
      tests cover successful empty-remembered-set application, retained
      copied-young remembered-edge publication, object-byte-copy request
      derivation for copied and promoted survivors, post-commit allocation
      rejection, stale source-layout rejection, heap-field and full
      reference-buffer derivation, root writeback derivation, combined mixed
      root/heap writeback partitioning, forwarding-slot buffer derivation for
      copied and promoted survivors, heap-field writeback derivation for copied
      and promoted nursery owners, root-slot rejection/empty root-only heap-field
      writebacks, stale field-label rejection, stale same-label field-value
      rejection, root-value count/source/value rejection, incomplete or mismatched
      reference-buffer rejection before lower-level mutation, and lower-level
      stale-buffer error mapping without partial mutation. This remains a
      caller-buffer/writeback-metadata surface only;
      destination storage allocation, binding raw byte slices to live heap objects
      or object headers, tree-walk root/object-field mutation, remembered-source
      field mutation, and semispace management remain open.
- [x] Current GC-stress boundary reference-writeback application precursor:
      `EvalGcStressBoundaryMinorGcCommitPreflight::apply_reference_writebacks_to_owned_slots`
      copies the boundary preflight's owned root and heap-field writeback slots,
      validates them with the combined
      `AllocationCollectorPollReferenceWritebackPlan`, applies replacements into
      those owned buffers, and returns a per-tier report with the rewritten
      buffers. `EvalGcStressBoundaryMinorGcCommitPreflights` applies the same
      operation across worker and permanent-shared preflights while preserving
      the tier partition. Tests cover worker-root rewrites, mixed root plus
      heap-field rewrites, permanent-shared empty rewrites, and empty reports when
      GC stress is disabled. This remains boundary-owned buffer application only;
      live tree-walk root/heap-field binding, object-byte copying, forwarding-slot
      installation, remembered-set publication, remembered-source field mutation,
      and semispace management remain open.
- [x] Current GC-stress boundary commit-buffer application precursor:
      `EvalGcStressBoundaryMinorGcCommitPreflight::apply_commit_to_owned_buffers`
      rebuilds the paired commit metadata, allocates boundary-owned synthetic
      object byte buffers from the preflight's copy requests, clones forwarding
      slots and reference buffers, clones the remembered-set snapshot, and
      copies the same synthetic source bytes into fresh
      `MinorGcOwnedDestinationStorage` sized by the paired placement plan before
      applying the lower-level `AllocationCollectorPollMinorGcCommitPlan` into
      the remaining owned buffers. The returned per-tier report includes
      object-copy, promotion, forwarding, reference-rewrite, and remembered-set
      publication counts plus the mutated owned buffers and destination-storage
      byte snapshots. The aggregate
      `EvalGcStressBoundaryMinorGcCommitPreflights::apply_commits_to_owned_buffers`
      preserves worker/permanent-shared partitioning. Tests cover worker
      owned-buffer commits, mixed root plus heap-field commit applications,
      retained remembered-edge publication into the owned remembered-set buffer,
      copied and promoted destination-storage bytes, permanent-shared empty
      commits, and empty reports when GC stress is disabled. Remembered-set
      source buffers are copied fallibly through the existing
      `RememberedSet::record` path. This remains boundary-owned buffer/storage
      application only; binding raw bytes to live heap objects, installing real
      object-header forwarding slots, mutating live tree-walk roots or heap
      fields, mutating remembered source fields, publishing the evaluator-owned
      remembered set, and semispace swapping/management remain open.
- [x] Current GC-stress boundary commit dry-run precursor:
      `EvalGcStressBoundaryMinorGcCommitPreflights::apply_owned_commit_dry_run`
      consumes the boundary preflight bundle, applies owned reference-writeback
      buffers, owned synthetic commit buffers, and owned destination-storage
      byte placement from the same metadata, and returns
      `EvalGcStressBoundaryMinorGcCommitDryRun` with the preflights, writeback
      applications, and commit applications preserved together.
      `EvalOutcome::gc_stress_boundary_minor_gc_commit_dry_run` drives the full
      boundary pipeline from the recorded GC-stress scans in one checked call,
      and `EvalGcStressBoundaryMinorGcCommitDryRun::summary` aggregates per-tier
      dry-run counts for copies, promotions, forwarding installs, reference
      rewrites, root/heap-field writebacks, remembered-set publication,
      dirty-card clearing, and object-payload byte totals from the preserved
      preflight metadata.
      Tests cover the worker dry-run path, including copy, promotion,
      forwarding, reference-rewrite, owned-buffer byte equality,
      destination-storage byte placement, and summary counts/bytes;
      permanent-shared empty dry-run partitioning; mixed root/heap-field summary
      aggregation; dirty old-field rescan publication/writeback at the boundary;
      plus the stress-disabled empty path. This remains an owned dry-run
      telemetry surface only; live heap-object byte binding, real
      object-header forwarding installation, live tree-walk root/heap-field
      mutation, remembered-source field mutation, evaluator remembered-set
      publication, and semispace management remain open.
- [x] Current GC-stress safepoint-poll precursor:
      `runtime::alloc::GcStressPolicy` classifies centralized worker and
      permanent-shared allocation safepoints under disabled, every-safepoint, or
      every-N-safepoints stress policies, and `AllocationSafepoint` records the
      poll reason for later collector dispatch. `EvalHeap::set_gc_stress_policy`
      installs one policy across both worker and permanent allocation domains.
      Periodic policies use the allocator lifetime safepoint sequence, and
      enabled stress policies poll when that sequence saturates. Tests pin
      zero-period rejection, default-disabled behavior, every-safepoint polling,
      lifetime-sequence periodic polling, saturation polling, permanent-shared
      polling, and heap-level installation across both domains. This is
      poll-intent metadata only. `TreeWalkOptions` can now install the policy on
      the evaluator heap, and tree-walk tests cover worker-domain lambda
      allocation and permanent-shared string allocation poll reasons. Building
      the live root set for an observed poll that is still current for its
      allocator tier is now possible through the tree-walk collector-poll scan
      bridge below. Owned tree-walk outcomes now record
      `EvalGcStressBoundaryScans` at successful evaluation boundaries: current
      worker and permanent-shared polls are scanned separately with the produced
      value published as transient value-stack slot 0, and tests cover lambda,
      string, and attr-path outcomes under every-safepoint stress.
      `EvalOutcome::gc_stress_boundary_minor_gc_plans` can convert those
      recorded scans into caller-owned `AllocationCollectorPollMinorGcPlan`
      metadata using the outcome's remembered-set snapshot and a caller-supplied
      promotion policy; tests cover worker young-survivor planning,
      permanent-root/no-survivor planning, and empty reports when stress is
      disabled. Invoking the collector, actually collecting at every safepoint,
      and exported C ABI symbols remain open.
- [x] Current permanent-shared allocation closure:
      `runtime::alloc::PermanentSharedAllocator` exposes a permanent domain
      with accounting separate from the Tier-A worker allocator, and `EvalHeap`
      owns both domains. Hash-consed reusable values — strings, paths, list
      spines, and flat attrsets — allocate through permanent shared storage and
      record that placement in the typed side table; thunks, lambdas, and
      primop wrappers remain worker-domain allocations. Tests pin split
      accounting, domain-marked records, unchanged cons-table reuse, and the
      current collector-poll contract that hash-consed roots are permanent
      minor-GC roots rather than survivor-frontier objects. They also preserve
      the cross-domain caveat that permanent list/attr containers may hold
      worker-domain child handles visible to precise root scanning.
      `RuntimeAllocator::reset_to_empty` now drops worker chunks without touching
      permanent shared storage, and `EvalHeap::reset_worker_allocator_if_idle`
      rejects that reset while worker-domain records are live. The real daemon
      lifetime model, exported ABI, and Tier-B collector integration remain
      open under the broader heap/GC rows.
- [x] Current high-water budget policy precursor:
      `ratchet-value::heap::budget` provides the single configurable-budget
      classifier for memory pressure: below the derived soft limit it keeps Tier
      A, near/above the budget it asks for cold/dead-page reclaim when that can
      bring projected residency under the hard budget, and it asks for Tier B
      only when known cheap reclaim is insufficient.
      `runtime::alloc::AllocationSafepoint` can now classify that policy from
      post-allocation mapped arena bytes plus caller-supplied dead-page and
      cold-hash-cons reclaim estimates, returning an
      `AllocationMemoryBudgetDecision` for later runtime dispatch. `EvalHeap`
      also exposes whole-heap classification over the saturating sum of worker
      and permanent mapped arena bytes, preserving both domain accounting
      snapshots in `EvalHeapMemoryBudgetDecision`.
      `EvalHeap::respond_to_memory_budget_with_unused_tail_advice` now executes
      the implemented cheap reclaim path by deriving dead arena bytes from
      supported page-advisable worker/permanent tails, applying dead-page advice
      for `SpillCold` and before `RequestTierB`, and reporting when advice is
      still insufficient without crediting cold hash-cons reclaim. Tests cover
      zero-budget rejection, headroom derivation, spill-before-collector
      ordering, saturating reclaim accounting, safepoint-level
      Continue/Spill/Tier-B classification, whole-heap worker/permanent
      aggregation, the three current action paths, and the sub-page/unsupported
      advice-capacity guard. The `aos --max-rss` / `AOS_NIX_MAX_RSS` knob now
      flows through `NixEvalConfig` into native-eval `TreeWalkOptions` as a
      validated `HeapMemoryBudget`, and `TreeWalk` installs that budget on
      `EvalHeap`. Successful typed heap allocations now poll the configured
      budget automatically, dispatch the implemented unused-tail advice response,
      and retain the latest action for tests and later daemon policy;
      `EvalOutcome` snapshots that final action through `memory_budget_action()`
      so root and attr-path callers can observe the safety-valve decision
      without reaching into heap internals. When callers configure both a heap
      budget and the post-evaluation cheap-advice idle threshold, `EvalOutcome`
      also snapshots the cold-aware planning telemetry through
      `cheap_memory_budget_plan()`. Hash-cons hits skip the poll because no heap
      allocation occurred. Linux and Darwin budget polls now sample process RSS
      from `/proc/self/statm` or Mach `MACH_TASK_BASIC_INFO` through
      `ProcessResidentMemorySample`, falling back to arena-mapped bytes on
      unsupported or unreadable platforms; tests pin the Linux parser, the
      Darwin live-source path, the fallback mode, the resident-source metadata
      carried by budget decisions, and outcome-level budget-action reporting.
      Daemon policy, live RSS backends beyond Linux/Darwin, CA-store spill,
      allocation-time automatic hash-consed pageout policy, and collector
      installation remain open under the full memory-management rows. `EvalHeap`
      also tracks per-record access epochs and exposes cold hash-consed
      logical-byte estimates for opt-in budget classification.
      `plan_memory_budget_with_cheap_memory_advice` now combines those cold
      estimates with supported unused-tail capacity and, when the classifier
      asks for reclaim, records dead-tail advice plus hash-consed
      `MADV_PAGEOUT` advice for telemetry, while the automatic
      allocation-safepoint budget action and `memory_budget_action()` still
      credit zero cold reclaim until CA-store spill/rematerialization exists.
- [x] Current cold hash-cons candidate precursor:
      `EvalHeap` stamps typed heap records with a monotonic access epoch at
      allocation time, refreshes successful reusable-value reads and hash-cons
      hits, and estimates cold permanent-shared hash-consed bytes by idle epoch
      threshold. The opt-in budget classifier can carry that estimate as
      `cold_hash_consed_bytes` for future spill planning, and the opt-in
      cold-aware plan applies the current non-destructive pageout advice hook
      alongside unused-tail advice as telemetry when that classifier asks for
      reclaim. This is still not CA-store spill and not proof of resident-byte
      reclaim: it installs no CA-store handle, evicts or rematerializes no
      value, and does not change automatic memory-budget actions.
- [x] Current `madvise` portability closure:
      `ratchet-value::heap::advice` provides an advisory-memory API over
      `MemoryAdviceRange` and the dead/free/cold/evict/huge heap hints, with
      non-empty raw-range construction kept at an explicit unsafe heap boundary.
      Linux trims requests to full pages wholly contained by the supplied range
      before lowering to `madvise`; non-Linux targets return an unsupported
      outcome without touching memory; empty or sub-page ranges are a no-op; OS
      rejection remains an advisory outcome rather than a correctness failure.
      `BumpArena::advise_unused_tail` now exposes a safe arena-owned integration
      point that advises only bytes at or above each chunk's bump cursor, reports
      outcome counts in `ArenaMemoryAdviceReport`, preserves arena accounting,
      and leaves advised tails available for later allocations. `RuntimeAllocator`,
      `PermanentSharedAllocator`, and `EvalHeap` now expose safe unused-tail
      advice reports for worker and permanent domains without deciding when
      policy should invoke them. Tests cover range metadata, zero-length no-op
      behavior, typed helper dispatch, non-Linux unsupported behavior, Linux
      full-page trimming, a Linux anonymous-`mmap` `MADV_DONTNEED` call, Linux
      flag mapping, non-empty sub-page helper dispatch, empty arenas, complete
      unused-tail pages, unchanged accounting, post-advice allocation reuse,
      runtime allocator forwarding, and whole-heap worker/permanent
      aggregation. Integrating the shim with
      CA-store spill, region-pop/dead-page selection, full budget-triggered
      dispatch, and collector-installation policy remains open under the full
      memory-management rows.
- [x] Current cold hash-consed page-advice precursor:
      `ratchet-value::heap::advise_cold_heap_object_allocation` and
      `advise_evict_heap_object_allocation` provide safe, non-destructive typed
      heap-object wrappers for `MemoryAdviceKind::Cold` and
      `MemoryAdviceKind::Evict`, keeping raw destructive range construction
      inside the heap crate's unsafe boundary.
      `EvalHeap::advise_cold_hash_consed_values(min_idle_epochs)` and
      `EvalHeap::advise_evict_hash_consed_values(min_idle_epochs)` apply those
      hints to permanent-shared structurally hash-consed records selected by
      the idle-epoch coldness predicate and report record counts, requested
      logical bytes, and advisory outcomes through
      `EvalHeapColdHashConsedAdviceReport`. Tests pin cold-record selection,
      cold and evict advisory outcome accounting, non-destructive coldness
      preservation, and hot-record exclusion after a value read. This is not
      budget-triggered, installs no CA-store handle, and rematerializes no
      value.
- [x] Current cheap-advice aggregation precursor:
      `EvalHeap::advise_cheap_memory_ranges(min_idle_epochs)` runs the two
      implemented page-advice passes together: dead advice for unused worker and
      permanent arena tails, and cold advice for idle permanent hash-consed
      records. `EvalHeapCheapMemoryAdviceReport` returns both underlying
      reports without turning cold hints into reclaim accounting. This is an
      integration hook only; automatic budget dispatch still credits zero cold
      reclaim, does not issue automatic `MADV_PAGEOUT`, does not request Tier B
      from this helper, and does not spill or rematerialize CA-store values.
- [x] Current tree-walk opt-in cheap-advice policy precursor:
      `TreeWalkOptions` now carries an optional post-evaluation idle-epoch
      threshold for cheap heap advice. When configured, root and attr-path
      `EvalOutcome`s carry post-result advice telemetry after the evaluator has
      produced the value, derivation snapshot, and stats snapshot. Without a
      heap budget, or when the combined budget/advice plan stays below the soft
      limit, the outcome reports `EvalHeap::advise_cheap_memory_ranges` and its
      `MADV_COLD` hash-consed hint. With both a heap budget and the idle
      threshold configured, the cold-aware budget plan reports hash-consed
      `MADV_PAGEOUT` advice when reclaim is planned. This is opt-in outcome
      telemetry only: allocation-time budget polling, force-cache identity,
      output values, `.drv` materialization, cold-reclaim accounting, and
      CA-store spill/rematerialization remain unchanged.
- [x] Current arena region-pop primitive precursor:
      `ratchet-value::heap::arena` now exposes `ArenaRegionMark` and
      `BumpArena::pop_region_to_mark` for proof-gated lexical subregion
      reclamation. The primitive rewinds the retained chunk to the marker,
      drops later chunks, restores the saved next-chunk growth state, and
      reports released used bytes, unmapped bytes, and the dead-advice outcome
      for the newly-dead retained-chunk range. Linux lowers that advice to
      `MADV_DONTNEED`; non-Linux and sub-page ranges remain advisory skip
      outcomes.
- [x] Current tree-walk region-pop admission precursor:
      `EvalHeap::worker_region_mark` and
      `EvalHeap::pop_worker_region_if_disconnected` connect manually admitted
      worker-region markers to typed side-table invalidation. The gate rejects
      non-worker suffix records, retained precise edges into the suffix, and
      foreign or allocator-reset-stale markers; preserves nested LIFO markers
      across inner pops; confines the unsafe value-layer arena rewind to the
      runtime allocator after typed validation; restores worker allocation-safepoint accounting to
      the marker; and truncates typed records. Reclaimed handles fail as unknown
      immediately after truncation, while later bump reuse may assign the same
      address to a new record. Collector-poll scans and minor-GC plan metadata
      capture the heap region owner/epoch so region pops stale old snapshots
      even after safepoint rollback and address reuse. Tests cover disconnected
      suffix reclamation, permanent suffix rejection, retained-thunk
      cached-result rejection, foreign-marker rejection, reset-stale marker
      rejection, nested LIFO reclamation, collector-poll scan staleness under
      address reuse, epoch-overflow owner rotation, and safepoint rollback.
      `EvalHeap::pop_worker_region_if_plan_permits` now connects the
      conservative `RegionPlan` policy to this manual admission boundary:
      non-pop plans retire the marker without reclaiming heap records, and
      lexical no-escape plans route through the same typed validation before
      reclaiming a suffix.
      Automatic tree-walk allocation placement and IR escape-analysis wiring
      remain open.
- [ ] `heap/roots.rs` — precise root enumeration / stack maps for the collector.
- [x] Current `heap/roots.rs` tree-walk graph precursor:
      `ratchet-oracle::eval::heap::roots` defines explicit root descriptors for
      value-stack slots, active and suspended tree-walk lexical/dynamic scopes,
      force continuations, primop arguments, import-cache entries, permanent
      interned/hash-cons roots, and future stack-map slots supplied by tests or
      later safepoint builders; `EvalHeap` can build stable sorted interned root
      sets and scan reachable typed records from a caller-supplied explicit root
      set. The scan validates tag/side-table agreement before address
      deduplication, ignores inline and external-runtime non-roots, grows scan
      side tables with the reachable graph rather than total heap size, emits
      shape-qualified attr edges, list edges, lambda/thunk captured-env edges,
      primop-arg edges, and state-sensitive suspended/blackholed/forced thunk
      edges. This is a copied-value graph report, not relocation-writeback
      slots; the moving Tier-B collector, full relocation-slot root contract,
      and Cranelift stack-map wiring remain open in the row above and in
      [08](08-execution-tiers-and-cranelift.md).
- [x] Current `heap/roots.rs` collector-poll minor-GC bridge precursor:
      `EvalHeap::plan_collector_poll_minor_gc` validates that a copied
      collector-poll heap graph still matches current typed heap records, maps
      worker-domain records to young-generation metadata, maps permanent-shared
      records to permanent metadata, and calls
      `MinorGcPlan::from_roots_remembered_and_fields` with generated nursery
      age and field tables. The bridge rejects copied graph snapshots after
      heap growth or allocator-safepoint changes, rejects remembered-set edges
      that no longer describe permanent-to-young references, and rejects current
      permanent-to-young graph edges that were not remembered. This connects
      precise root scanning to minor-GC survivor planning, but it is still not a
      mutating collector: mutable relocation slots, root/field writeback,
      object copying, forwarding pointers, card-table ownership, and JIT
      stack-map integration remain open.
- [x] Current `heap/roots.rs` reference-slot bridge precursor:
      `AllocationCollectorPollReferenceSlot` labels the copied references that
      would need relocation after a minor collection: root slots, concrete
      remembered old/permanent source fields, and `HeapEdgeSource`-labeled fields
      of planned nursery survivors. Remembered edges are expanded into the current
      source fields they describe, including duplicate fields to the same target,
      and stale remembered entries with no matching source field are rejected. The
      slot sequence feeds `MinorGcReferenceRewritePlan` with stable indices, but
      does not yet own or mutate the underlying evaluator storage. Real
      relocation slots for tree-walk roots, copied object fields, remembered
      old/permanent fields, and later JIT stack-map entries remain open.
- [x] Current `heap/roots.rs` stack-map root-writeback metadata precursor:
      `AllocationCollectorPollRootWritebackPlan::stack_map_writebacks` exposes
      the compiled-frame `EvalRootSource::StackMap` subset of root writebacks in
      reference-rewrite order, and `stack_map_writeback_count` reports that
      partition for future JIT stack-map storage owners. Tests drive stack and
      register stack-map roots through collector-poll scanning, minor-GC
      planning, root-writeback metadata, and caller-owned slot application while
      preserving a value-stack root in the same plan. This is metadata only;
      live compiled-frame mutation, Cranelift stack-map emission/consumption,
      and a JIT safepoint writer remain open.
- [x] Current `heap/roots.rs` destination-planning bridge precursor:
      `AllocationCollectorPollMinorGcPlan::relocation_destination_plan` derives
      destination allocation requirements, aligned placements, and materialized
      relocation destinations from the copied poll survivor plan and
      caller-provided layouts/bases. `EvalHeap` also exposes a heap-record-backed
      bridge that derives survivor layouts from recorded allocation size/alignment
      metadata and rejects post-plan heap allocation before destination
      materialization. This connects precise-root minor-GC planning to
      lower-level destination metadata, but still does not allocate or bind live
      destination storage.
- [x] Current `heap/roots.rs` commit-plan bridge precursor:
      `AllocationCollectorPollMinorGcPlan::commit_plan` stores the remembered-set
      snapshot captured during allocation-poll planning and composes it with the
      allocation-poll destination wrapper to produce `MinorGcCommitPlan`
      metadata after validating the wrapper's placement count, survivor order,
      and copy/promote actions against the poll plan. The wrapper keeps the copied
      `AllocationCollectorPollReferenceSlot` labels next to the lower-level
      commit plan, but still does not provide mutable tree-walk roots, copied
      object-field slots, old/permanent field mutation, or stack-map writeback
      slots.
- [x] Current `heap/roots.rs` commit-buffer bridge precursor:
      `AllocationCollectorPollMinorGcCommitPlan::apply_to_buffers` checks that
      caller-owned reference values still match copied
      `AllocationCollectorPollReferenceSlot` label values, then applies the
      validated lower-level commit plan to caller-owned byte-copy buffers,
      forwarding slots, reference values, and remembered-set state.
      `AllocationCollectorPollMinorGcCommitPlan::apply_to_buffers_with_report`
      performs the same validation and buffer commit while returning the
      lower-level `MinorGcCommitReport` for committed copy, promotion,
      forwarding, reference-rewrite, and remembered-set publication counts.
      The commit wrapper carries the heap record and allocation-safepoint
      snapshot from the poll plan, and
      `EvalHeap::collector_poll_minor_gc_object_byte_copy_plan` rejects stale
      snapshots before binding the lower-level object-copy schedule back to
      current young worker-domain heap records, revalidating their recorded
      size/alignment, and returning copy requests for the future
      semispace/storage owner rather than raw byte slices.
      `AllocationCollectorPollObjectByteCopyPlan` now exposes copy-to-nursery
      and promote-to-old request views plus per-generation object-payload byte
      totals, while destination-space sizing continues to come from the
      placement plan's reserved-byte totals so alignment padding stays explicit.
      `EvalHeap::collector_poll_minor_gc_heap_field_reference_buffer` can bind
      remembered-source, dirty old/permanent, and nursery-field slots back to
      current side-table fields for the reference buffer while rejecting copied
      root slots, and
      `AllocationCollectorPollMinorGcCommitPlan::root_writeback_plan` filters
      lower-level rewrites to root-backed slots with slot-to-rewrite source
      validation. `AllocationCollectorPollRootWritebackPlan::apply_to_slots`
      validates caller-owned root writeback slot count, source labels, and
      expected values before rewriting the supplied slot buffer and reporting the
      rewrite count; it still leaves live tree-walk/JIT root storage binding to
      the safepoint owner.
      `EvalHeap::collector_poll_minor_gc_heap_field_writeback_plan` filters
      lower-level rewrites to heap-field-backed slots, revalidates their current
      labels/values plus slot-to-rewrite source binding, and returns the
      writeback object plus replacement value that a future mutating field writer
      would store. `AllocationCollectorPollHeapFieldWritebackPlan::apply_to_slots`
      validates caller-owned heap-field writeback slot count, validation/writeback
      objects, field labels, and expected values before rewriting the supplied
      field-slot buffer and reporting the rewrite count; it still leaves live
      object-field mutation and semispace storage ownership to the collector.
      `EvalHeap::collector_poll_minor_gc_reference_writeback_plan`
      returns both partitions together for callers that need complete reference
      writeback metadata, and
      `AllocationCollectorPollReferenceWritebackPlan::apply_to_slots` validates
      both caller-owned root and heap-field slot partitions before rewriting
      either partition, so a stale heap-field slot cannot partially rewrite root
      slots. `EvalHeap::collector_poll_minor_gc_reference_buffer`
      merges external root
      values with live heap-field reads into one caller-owned reference buffer.
      This connects the roots bridge to commit-buffer preflight/application tests,
      but still does not provide live heap-object byte slices, semispace
      destination storage, tree-walk root writeback, live object-field mutation,
      old/permanent field mutation in evaluator-owned objects, or JIT stack-map
      writeback slots.
- [x] Current tree-walk safepoint root-set builder precursor:
      `TreeWalk::safepoint_root_set` and `TreeWalk::safepoint_heap_scan` build
      precise roots from explicit evaluator state: active lexical frame slots,
      active dynamic `with` scopes, scoped-import globals,
      caller env/with/scoped-global stacks suspended by nested evaluation,
      active force continuations, first-class primop arguments, ready import
      cache values, and permanent interned/hash-cons roots.
      `TreeWalk::safepoint_root_set_with_value_stack` adds caller-supplied
      transient value-stack roots for Rust locals or allocation return values
      that are live at a safepoint but not yet stored in evaluator state
      (skipping inline non-root values), and
      `TreeWalk::safepoint_collector_poll_scan` pairs a supplied, still-current
      `AllocationCollectorPoll` with those tree-walk roots through the existing
      heap collector-poll scan, rejecting polls that are no longer current for
      their allocator tier. `TreeWalk::gc_stress_boundary_scans` runs that scan
      at successful owned evaluation boundaries for each current worker and
      permanent-shared poll, exposing `EvalGcStressBoundaryScans` on
      `EvalOutcome` with the produced WHNF value rooted as transient value-stack
      slot 0. `EvalOutcome::gc_stress_boundary_minor_gc_plans` then delegates
      those stored scans to `EvalHeap::plan_collector_poll_minor_gc` with the
      outcome remembered-set snapshot and a caller-supplied promotion policy,
      preserving the result as caller-owned planning metadata.
      `EvalOutcome::gc_stress_boundary_minor_gc_relocation_destinations` carries
      those boundary plans one step further by deriving current heap-record
      layouts and materializing caller-supplied nursery/old destination bases;
      `EvalOutcome::gc_stress_boundary_minor_gc_relocation_plans` retains each
      boundary survivor plan next to its destinations so callers can derive
      matching commit metadata from the paired report.
      `EvalOutcome::gc_stress_boundary_minor_gc_commit_preflights` then
      validates and extracts owned object byte-copy requests, empty forwarding
      slot buffers, copied reference buffers, and root/heap-field reference
      writeback metadata plus caller-owned writeback slot buffers from those
      paired plans. Boundary preflights can now apply those reference writebacks
      to owned slot-buffer copies and can apply the complete lower-level commit
      to boundary-owned synthetic byte, forwarding-slot, reference, and
      remembered-set buffers. Boundary preflights expose per-generation
      object-payload byte totals, and the dry-run summary reports those totals
      alongside rewritten root/heap-field counts and lower-level commit counts.
      `EvalOutcome::gc_stress_boundary_minor_gc_commit_dry_run_with_live_card_table`
      then gates a single outcome-owned card-table clear on the same successful
      owned dry-run validation;
      `EvalOutcome::gc_stress_boundary_minor_gc_commit_dry_run_with_live_remembered_set`
      publishes an outcome-owned remembered set after the same dry run, merging
      sibling worker/permanent next sets when both tiers produced applications;
      `EvalOutcome::gc_stress_boundary_minor_gc_commit_dry_run_with_live_forwarding_slots`
      installs evaluator-owned side-table forwarding values after the same dry
      run; and
      `EvalOutcome::gc_stress_boundary_minor_gc_commit_dry_run_with_live_destination_storage`
      installs deduplicated outcome-owned destination-byte snapshots from the
      same validated commit applications. These helpers still do not bind those
      bytes to live heap-object bodies, live root/field storage, real ABI
      object-header forwarding storage, object-generation metadata, or semispace
      storage, and they do not commit those live mutations.
      The force,
      lambda-call, import-evaluation, nested
      numeric-equality, and saturated first-class primop paths
      register/unregister active or suspended safepoint frames, including
      error-path cleanup, and
      `eval::tree_walk::tests::safepoint_roots` covers stable root labels,
      suspended-env roots, import-cache roots, interned-root inclusion, heap
      scanning, GC-stress collector-poll scanning with an explicit transient
      root, minor-GC planning from that scan, boundary scans for worker,
      permanent-shared, and attr-path outcomes, boundary minor-GC planning for
      worker, permanent-shared, and stress-disabled outcomes, boundary
      relocation-destination planning for worker, permanent-shared, and
      stress-disabled outcomes, boundary paired relocation/commit-metadata
      planning for worker, permanent-shared, and stress-disabled outcomes,
      boundary commit-preflight reports for worker, permanent-shared, and
      stress-disabled outcomes, boundary owned reference-writeback, synthetic
      commit-buffer application, single-call owned commit dry-run,
      outcome-owned live card-table clearing after successful dry-run
      validation, single-tier and multi-tier live remembered-set publication,
      live side-table forwarding installation, stale same-domain poll
      rejection, recursive-force cleanup, and
      first-class primop error cleanup. This remains a root-set
      precursor: arbitrary Rust locals still need explicit value-stack
      registration, and mutable relocation slots, collector invocation, and JIT
      stack maps remain open in the full precise-root row above.
- [x] Current thunk-resolve write-barrier precursor:
      `ratchet-value::heap::gc` classifies the single generational write
      barrier for `Blackhole -> Forced(value)`, records only
      old/permanent-to-young edges in a deduplicating remembered set, and leaves
      one-shot arena mode disabled. `ratchet-oracle::eval::thunk::ForceGuard`
      now exposes `finish_with_barrier`, while the default `ForceGuard::finish`
      uses the disabled barrier; tests pin that custom barriers run while the
      thunk is still blackholed and can reject publication without leaving a
      forced result. `EvalHeap::thunk_resolve_write_barrier` now builds a
      heap-backed adapter that validates the source thunk against the side table,
      classifies the forced value's current generation (including inline and
      external values), delegates remembered-edge insertion and optional
      dirty-card marking to the lower-level barrier helper, and implements the
      `ThunkResolveBarrier` hook for `ForceGuard::finish_with_barrier`. Unit
      tests cover remembered-edge insertion and card marking for a
      permanent-to-young publication, inline/external no-op classification,
      non-thunk source rejection, and the current caller-owned invariant that
      the adapter must be paired with the matching force guard.
      `TreeWalkOptions` can now select the thunk-resolution barrier tier;
      tree-walk forcing publishes newly evaluated and force-cache replayed thunk
      results through the heap-backed barrier when daemon mode is selected, and
      exposes the tree-walk-owned `RememberedSet` and `GcCardTable` on
      `TreeWalk`/`EvalOutcome`. Required old/permanent-to-young edges and source
      cards are recorded there; replayed permanent-shared payloads remain no-op
      barrier writes. The tree-walk publish path now enters the
      `runtime::barrier` vtable first, selecting the one-shot disabled adapter
      or daemon heap-backed adapter from the configured tier. Mutable generation
      updates and Tier-B collector integration remain open under `heap/gc.rs`.
- [x] Current unsafe-policy precursor: the oracle/frontend/glue layer keeps
      `unsafe_code` denied by default, with the current exception limited to the
      typed region-pop handoff into `BumpArena::pop_region_to_mark` after
      `EvalHeap` side-table validation. Broader heap/GC unsafe code still
      belongs behind explicit unsafe fences, documented `// SAFETY:` comments,
      and dedicated tooling (`S-17`, [14](14-integration-with-aos.md) §10).
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
- [x] Current safe L1 scheduler precursor:
      `ratchet-oracle::eval::parallel` exposes deterministic top-level task
      seeding and a standard-library work-stealing executor for independent
      roots. Tasks are seeded round-robin across worker-owned deques, workers pop
      local work from the LIFO end, idle workers steal older peer work from the
      FIFO end, and result collation is sorted by stable task index rather than
      completion order. The execution report carries per-worker local-pop,
      steal, and completion counters plus per-task initial/completing worker
      metadata. Unit tests pin round-robin placement, stable result ordering,
      exactly-once task completion, empty task sets, and worker-panic reporting.
      This is a safe scheduler/readiness layer only: it is not the final
      lock-free Chase-Lev deque, does not evaluate Nix derivations, does not
      allocate per-worker nurseries, does not integrate with shared thunk CAS,
      and does not satisfy the full L1 deliverable above.
- [ ] `eval/thunk_cas.rs` — the L2 **lock-free CAS thunk protocol**
      (`Suspended → Pending → Awaited → Forced/Failed`); claim-by-CAS, with
      work-stealing or parking on a claimed thunk ([13](13-parallel-evaluation.md) §3).
      The thunk word is already atomic from P1, so this adds a scheduler, not a
      representation change.
- [x] Current L2 CAS state-word precursor:
      `ratchet-oracle::eval::thunk_cas` defines the owner-tagged atomic word
      encoding for `Suspended`, `Pending(worker)`, `Awaited(worker)`,
      `Forced`, and `Failed`; exposes acquire state loads, single-winner
      `Suspended -> Pending(worker)` claim CAS, same-worker cycle
      classification, foreign pending/awaited classification, non-parking
      foreign `Pending -> Awaited` marking, and guarded release publication to
      `Forced` or `Failed`. Active claim guards are deliberately not `Send`,
      and dropping one publishes `Failed` so safe unwinding cannot strand a
      thunk in a claimed state. Unit tests pin encoding round-trips,
      exactly-one concurrent claimant, self-cycle versus foreign contention,
      awaited publication metadata, failed terminal behavior, drop-to-failed
      unwinding, acquire/release payload visibility, and wrong-owner publish
      rejection. This is the state-word/protocol precursor only: it does not
      replace the serial tree-walk thunk cell, does not store forced values or
      captured errors, does not install waiter lists or wakeups, does not
      perform work stealing or parking, and does not satisfy the loom/Miri/TSan
      gate.
- [x] Current safe waiter/wakeup precursor:
      `ratchet-oracle::eval::thunk_wait` wraps the CAS state word with a
      standard-library mutex and condition variable so foreign workers can mark
      a thunk `Awaited`, register under the waiter mutex, check the terminal
      predicate before sleeping, and wake after the owner publishes `Forced` or
      `Failed`. The owner stores the terminal state first, then takes the same
      waiter mutex before notifying, which models the no-lost-wakeup ordering
      required by [13](13-parallel-evaluation.md) §3.6. Claim guards remain
      worker-affine and compile-fail doctests in this slice check that they are
      not `Send`; dropping a wait-cell claim publishes `Failed` and broadcasts
      to waiters.
      Unit tests cover forced publish wakeup, drop-to-failed wakeup, self-cycle
      classification, already terminal no-wait behavior, and
      waiter/notification counters. This is a blocking correctness precursor
      only: it does not drain local work, steal peer work before parking, store
      values/errors, implement the final lock-free waiter list, integrate with
      the evaluator scheduler, or satisfy the loom/Miri/TSan gate.
- [x] Current wait-or-steal ordering precursor:
      `ParallelThunkWaitCell::claim_or_run_ready_then_wait` accepts a
      caller-supplied ready-work hook and, on a foreign-owned thunk, rechecks the
      thunk after each reported local task or stolen peer task before registering
      a waiter and entering the blocking wait-cell path. Its contention report
      records local work runs, stolen work runs, and whether a waiter was
      registered. Unit tests prove that terminal publication observed while
      ready work runs avoids waiter registration, that terminal publication
      between an idle report and waiter marking is reported as no registration,
      and that multiple reported local/stolen work items run before an idle hook
      registers and wakes through the safe waiter path. This is an
      ordering/readiness layer only: the hook is not the final Chase-Lev/rayon
      scheduler, cannot prove the caller exhausted real worker deques or peer
      steals, does not hold a scheduler park token, and still uses the blocking
      wait-cell precursor rather than a lock-free waiter list.
- [x] Current parallel thunk terminal-payload precursor:
      `ParallelThunkPayloadCell` layers typed terminal payload storage over the
      safe CAS/wait-cell protocol. The claim owner stores either a forced payload
      or captured failure before publishing the terminal state, so foreign waiters
      wake through the existing no-lost-wakeup path and then clone the matching
      payload for re-raise or value replay. Dropping an active payload guard
      publishes a configured failure payload before the underlying wait guard
      releases `Failed`, preserving the no-stranded-claim invariant with a
      concrete error. Tests cover forced payload wake/replay, failed payload
      wake/replay, drop-to-failed payload publication, wait-or-steal payload
      return with contention counters, and replay for later claim attempts. This
      is still a safe payload precursor only: it does not replace the serial
      tree-walk thunk cell, store evaluator-native `Value`/`TreeWalkError`
      payloads, install the final lock-free waiter list, wire scheduler parking,
      or satisfy the loom/Miri/TSan audit.
- [x] Current semantic WHNF tag-test precursor:
      `ratchet-oracle::eval::whnf_tag` defines the active-ABI fast-path
      boundary for force entry. `classify_whnf_tag_fast_path` returns every
      non-`Thunk` `ValueTag` as already-WHNF by inspection, and
      `checked_whnf_tag_fast_path` resolves only thunk-tag misses through
      `EvalHeap::get_thunk` before the caller enters the thunk protocol. The
      serial tree-walk `force_value` now uses this classifier at its force-entry
      boundary, and unit tests pin that inline scalars and heap WHNF tags return
      without heap lookup, thunk tags miss, foreign thunk pointers are rejected
      only on the slow path, and an already forced serial thunk still misses in
      the current 16-byte representation. This is the semantic tag-compare
      precursor only: it is not the future low-bit pointer-tag `FORCED`
      shortcut, does not skip the thunk cell for already forced thunk values,
      does not integrate with the parallel scheduler/CAS wait path, and does
      not satisfy the loom/Miri/TSan gate.
- [x] Current shared node-table admission precursor: `SharedDemandGraph`
      wraps the existing in-memory `DemandGraph` behind a same-process mutex,
      exposes `DemandNodeAdmission` from insert-or-get calls, and proves cloned
      concurrent same-key misses converge on one inserted node while preserving
      the winner's value hash. This is the convergence contract only; the final
      lock-free append-only/CAS table, scheduler integration, persistent
      two-machine single-flight, and loom/Miri audit remain open
      ([12](12-incremental-evaluation-cache.md) §8.3,
      [13](13-parallel-evaluation.md) §4.3).
- [x] Current shared symbol-interner admission precursor:
      `aos-nix-syntax::SharedSymbolTable` wraps the current dense `SymbolTable`
      behind a same-process mutex and reports whether each intern call inserted
      or reused an existing symbol. Tests prove same-key concurrent misses
      converge on one dense id with one inserted admission, existing-table
      wrapping preserves ids, snapshots expose a consistent dense-table clone,
      and poisoned locks fail before interning or snapshotting. Distinct new
      symbols racing for insertion still receive dense ids in mutex-acquisition
      order. This is the same-process convergence contract only: it is not the
      final lock-free append-only interner, does not provide global cross-process
      ids, does not replace parser-local symbol ownership, and does not satisfy
      the loom/Miri/TSan audit.
- [x] Current parallel output-collation precursor:
      `ratchet-oracle::eval::parallel_output` normalizes worker-emitted output
      fragments into stable task order, merges `StringContext`s through their
      canonical set union, sorts unique `.drv` outputs by path, computes
      content-only SHA-256 digests from `.drv` bytes, deduplicates identical
      repeated `.drv` emissions, and rejects duplicate task fragments or
      same-path conflicting bytes. This is the output collation contract only:
      it is not the final thread-count differential `.drv` harness, does not
      execute the parallel scheduler, does not materialize derivations, and does
      not audit live attrset iteration under nondeterminism.
- [ ] Per-worker bump nurseries + a concurrent (or per-worker-then-merged)
      hash-cons table; never-free in CLI mode sidesteps any moving-collector race
      ([13](13-parallel-evaluation.md) §5).
- [x] Current per-worker nursery/hash-cons merge precursor:
      `ratchet-oracle::eval::parallel_heap` records the deterministic heap-state
      contract needed before the evaluator owns real per-worker heaps.
      `parallel_worker_nursery_plan` maps top-level tasks to stable
      initial worker-local nurseries, and `merge_parallel_hash_cons_candidates`
      merges worker-local hash-cons emissions in `(worker_id, local_index)` order
      while using equality checks to distinguish reuse from same-hash
      collisions.
      Tests prove stable nursery assignment, retained idle-worker nurseries,
      completion-order-independent canonical winners, equality-confirmed
      same-hash duplicate reuse, collision-safe distinct admissions,
      independent admission for equal values with mismatched hashes, duplicate
      worker-local slot rejection, and empty merges. This is the deterministic
      per-worker-then-merged contract only: it does not allocate through
      per-worker `EvalHeap` instances, publish into the live cons tables, replace
      the current hash-cons implementation with a concurrent/lock-free table,
      integrate with the scheduler, rely on never-free CLI mode, or satisfy the
      loom/Miri/TSan gate.
- [x] Current stolen-task nursery ownership precursor:
      `parallel_task_nursery_ownership_plan` combines the deterministic
      top-level nursery seed plan with observed task completion workers, then
      records that allocation ownership follows the executing worker's nursery
      rather than the task's initial queue owner. Completion records are sorted
      by stable task index so the ownership report is independent of scheduler
      completion order. Tests cover stolen versus local ownership counts,
      completion-order independence, empty completed sets, unknown task/worker
      rejection, and duplicate task-completion rejection. This is an
      allocation-ownership planning precursor only: it
      does not allocate through live worker-local `EvalHeap` instances, migrate
      existing objects between nurseries, execute the scheduler, distinguish
      fail-fast cancellation from missing completions, publish into hash-cons
      tables, or satisfy the loom/Miri/TSan gate.
- [x] Current scheduler-to-nursery ownership bridge:
      `parallel_task_nursery_ownership_from_top_level_report` derives the
      allocation-ownership plan from the safe L1 scheduler report, requiring the
      report and nursery seed plan to agree on worker count, task count, and each
      task's initial worker before assigning the allocation nursery from the
      worker that actually completed the task. Tests cover successful ownership
      derivation from `execute_parallel_top_level`, worker-count mismatch
      rejection, task-count mismatch rejection, and internally malformed
      incomplete-report rejection. This is the scheduler report bridge only: it
      does not embed ownership records into the scheduler report type, allocate
      through live worker-local `EvalHeap` instances, expose a public
      partial-report constructor, distinguish cancellation from completions,
      publish into hash-cons tables, or satisfy the loom/Miri/TSan gate.
- [x] Current fallible scheduler-to-nursery ownership bridge:
      `parallel_task_nursery_ownership_from_fallible_top_level_report` derives
      allocation ownership for completed root outcomes from the fallible L1
      scheduler report while permitting fail-fast cancellation to leave queued
      roots with no ownership record. The bridge validates worker count, task
      count, completed-outcome vector length, and completed-plus-skipped
      accounting before assigning allocation nurseries from each completing
      worker. Tests cover complete collect-all fallible reports, cancelled
      fail-fast reports, worker-count mismatch rejection, and internally
      malformed completed-outcome count rejection, under-accounted report
      rejection, and skipped-without-cancellation rejection. This is the
      fallible report bridge only: it does not embed ownership records into the
      fallible report, allocate through live worker-local `EvalHeap` instances,
      attach cancellation causes to missing ownership records, interrupt
      in-flight work, publish into hash-cons tables, or satisfy the
      loom/Miri/TSan gate.
- [ ] Single-entry-thunk downgrade restricted to escape-analysis-proven
      *frame-local* thunks (C-8), so the blackhole-skip is sound under parallel
      schedules.
- [x] Current frame-local single-entry thunk downgrade preflight:
      `ratchet-core::analysis::thunk_sharing` exposes
      `frame_local_single_entry_thunk_downgrade`, which validates that a target
      node is a well-formed `ThunkAlloc` and returns `SingleEntry` only for
      `ExprFacts` with `Once` cardinality plus `NoEscape` frame-locality. Missing
      proofs keep ordinary update/blackhole state with an explicit reason, while
      non-contradicted `Absent` thunks return `Omit` rather than a blackhole-skip
      downgrade. Tests cover the admitted proof, escaping once-used thunks,
      frame-local many-entry thunks, absent thunks, strict absent conflicts,
      non-thunk rejection, malformed thunk payload rejection, and dangling thunk
      body rejection. This is the named safety predicate only: it does not
      change tree-walk allocation, install a single-entry representation,
      implement call-by-name lowering, improve cardinality/escape precision, or
      close the loom/Miri/TSan audit.
- [x] Current tree-walk thunk allocation planning precursor:
      `ratchet-oracle::eval::thunk_lowering` consumes the C-8
      `frame_local_single_entry_thunk_downgrade` proof at the tree-walk
      allocation boundary and returns an explicit plan: ordinary update slot,
      single-entry lazy storage, omitted absent binding, or strict WHNF elision.
      The plan preserves the existing order-sensitive binding-assembly guard by
      forcing ordinary update slots while frames are populated before consulting
      analysis facts, lets strictness elision take precedence over lazy
      single-entry storage when no thunk is allocated, and treats contradictory
      absent-plus-strict facts conservatively as an update slot. Tests cover lazy
      frame-local single-entry admission, strict elision precedence,
      order-sensitive update fallback with present and missing facts,
      escaping-thunk update fallback, absent omission, and absent-strict conflict
      rejection of elision. This is still a planning precursor only: it does not
      install a single-entry runtime representation, change `ThunkCell`,
      implement call-by-name lowering, remove absent bindings from frame layout,
      improve analysis precision, or close the loom/Miri/TSan audit.
- [x] Current fallible L1 root execution precursor:
      `ratchet-oracle::eval::parallel_failure` adds a safe fallible top-level
      executor for independent roots. Root-local failures are stored as per-task
      outcomes, outcomes are sorted by stable task index before reporting,
      `canonical_error` selects the lowest-index observed failure, and
      fail-fast mode sets a shared cancellation flag that workers observe before
      probing queues for more top-level work; workers already past that check may
      still start another task. Tests cover collect-all error collation, stable
      success ordering, cooperative cancellation before later task-boundary
      checks, canonical selection over observed multi-worker failures, no
      cancellation in collect-all mode, worker accounting, empty task sets, worker
      panic reporting, and stable policy display. This is an L1
      root-failure/cancellation contract only: it does not store per-thunk
      `Failed` payloads, re-raise stored thunk errors to waiters, wire GC-poll
      safepoints, interrupt in-flight work, evaluate Nix derivations, or satisfy
      the loom/Miri/TSan audit.

**Conformance (hold parity).**

- [ ] The parallel evaluator is **differentially identical to the sequential
      oracle** across the full closure — output determinism under nondeterministic
      scheduling ([13](13-parallel-evaluation.md) §4.4); the
      [20](20-nix-language-conformance.md)/[21](21-builtins-conformance.md)
      surface stays byte-green.
- [x] Current scheduler-backed thread-count output differential precursor:
      `ratchet-oracle::eval::compare_parallel_output_across_worker_counts`
      executes cloned top-level output tasks through the safe L1 scheduler at
      multiple worker counts, stamps each task-local output with the
      scheduler-observed task index and completing worker, collates fragments
      with the canonical `parallel_output` rules, and rejects any worker count
      whose canonical output differs from the baseline. Tests cover stable
      collation across 1/2/4 worker runs, missing worker-count rejection,
      scheduler-run collation conflict reporting, and detected divergence from
      stateful output. This is a thread-count output harness precursor only: it
      does not evaluate Nix derivations, materialize live `.drv` outputs, compare
      against the sequential tree-walk oracle, run the full closure, audit live
      attrset iteration under nondeterminism, or satisfy the loom/Miri/TSan
      gate.
- [ ] **`loom`/Miri memory-ordering audit (R-4) is green** before the parallel
      tier is trusted. *No data races, ever.*
- [x] Current CAS memory-ordering audit precursor:
      `ratchet-oracle::eval::validate_parallel_thunk_memory_ordering` exposes a
      machine-checkable manifest for the safe L2 CAS state-word precursor and
      the state-word implementation now uses the same named ordering constants.
      The manifest pins acquire state loads, acquire-release claim CAS success,
      acquire claim CAS failure, acquire-release awaited-marker CAS success,
      acquire awaited-marker CAS failure, release terminal publication success,
      and acquire terminal publication failure. Tests validate every audited
      role, keep rationale text present, and continue to cover payload visibility
      through the release-publish/acquire-load pairing. This is a CAS ordering
      contract precursor only: it does not run loom, Miri, TSan, or ASan, model
      all interleavings, replace the blocking wait-cell precursor with a
      lock-free waiter list, verify scheduler park-token interactions, or
      certify the parallel tier for production.

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
- [x] Current `analysis/strictness.rs` precursor: `ratchet-core` exposes an
      initial conservative strictness fact producer that walks demanded IR nodes
      from the root and marks only guaranteed-WHNF child positions as
      `Strict`. It uses runtime builtin semantics rather than coarse direct
      lowering metadata, so higher-order callbacks skipped by empty inputs,
      `sort` comparators, and `foldl'` initial accumulators remain lazy unless a
      later proof demands them; option-dependent `traceVerbose` messages also
      remain conservative. Direct literal lambda applications can mark an
      argument `ThunkAlloc` strict when a simple formal is unconditionally
      demanded by the lambda body, and the tree-walk oracle verifies this
      produced fact elides the argument thunk while preserving foldl-empty and
      unreached dynamic attr-path laziness. This does not close the whole-program
      closed-call-graph fixpoint or worker/wrapper transform.
- [ ] `analysis/cardinality.rs` — single-entry thunk detection (blackhole-skip
      only for escape-proven *frame-local* thunks, `C-8`) + dead-binding removal.
- [x] Current `analysis/cardinality.rs` precursor: `ratchet-core` exposes a
      local cardinality fact producer for simple `let` frames. It counts
      same-frame slot references in binding values and the body, marks binding
      value nodes `Absent` or `Once` only when the count is complete, and leaves
      multi-use or nested-frame cases at conservative `Many`. This provides the
      initial fact producer for usage analysis; it does not yet implement
      single-entry thunk lowering, call-by-name downgrades, dead-binding
      elimination, escape-proven frame-locality integration, or the whole-program
      demand fixpoint.
- [x] Current dead-binding elimination planning precursor:
      `ratchet-core::analysis::dead_binding` consumes cardinality facts and
      returns a conservative plan for `let` bindings whose value code can be
      omitted while retaining a dummy frame slot. The planner admits only
      static-key bindings with `Cardinality::Absent` and non-strict facts,
      retains used bindings, retains contradictory absent-plus-strict bindings,
      and retains dynamic-key bindings so key evaluation is not skipped. Tests
      cover absent binding admission, many-use retention, absent-strict
      retention, dynamic-key retention, missing value-fact rejection, and
      malformed `let` payload rejection. This is a planning precursor only: it
      does not rewrite IR, compact frame layouts, emit worker dummy arguments,
      remove code in the tree-walk oracle, handle attrset or formal-argument
      absence, improve cardinality precision, or run the whole-program demand
      fixpoint.
- [ ] `analysis/escape.rs` — escape analysis + scalar replacement for
      non-escaping attrsets/thunks.
- [x] Current `analysis/escape.rs` precursor: `ratchet-core` exposes a
      conservative escape fact producer that marks only allocation-free immediate
      scalar literals (`int`, `float`, `bool`, `null`) as `NoEscape` and resets
      all other nodes to `Escapes`. It validates node kind/payload shapes so
      malformed IR cannot silently retain stale `NoEscape` facts. Aggregate
      escape analysis, the full primop escape surface, scalar replacement, and
      frame-local thunk integration remain open.
- [x] Current scalar replacement planning precursor:
      `ratchet-core::analysis::scalar_replacement` consumes strictness and
      escape facts and returns the immediate scalar nodes whose current facts
      license non-heap representation. The planner admits only `int`, `float`,
      `bool`, and `null` nodes with both `Strict` and `NoEscape`, retains scalar
      nodes with missing proofs, retains non-scalar `Strict + NoEscape` facts as
      unsupported by this precursor, and rejects missing facts or malformed
      scalar payloads. This is a planning precursor only: optimized storage
      lowering, aggregate scalar replacement, the full primop escape surface,
      and frame-local thunk/attrset escape integration remain open.
- [x] Current primop escape-signature precursor:
      `ratchet-core::analysis::escape_signature` classifies only direct primops
      whose result is guaranteed to be an immediate scalar, and `annotate_escape`
      now marks those primop result nodes `NoEscape` after validating their
      symbol and child-slice side tables. Overloaded `add`, result-forwarding
      operations such as `seq`/`trace`, aggregate/string builders, unknown
      builtins, and effectful import/fetch/filesystem boundaries remain
      conservative. This does not yet propagate primop result facts through
      wrapping thunks, infer aggregate escape, or provide the property-test
      harness for the full builtin surface.
- [ ] `ir/annotate.rs` — IR annotations consumed by the tree-walk oracle (and
      later the JIT), and the strictness FV set reused by the cache key (`C-2`).
- [x] Current `ir/annotate.rs` precursor: `ratchet-core::ir::annotate_ir`
      refreshes the current fact table from a conservative baseline, runs the
      strictness, cardinality, and escape fact producers, returns a combined
      report, and leaves conservative facts behind on producer errors. The
      tree-walk oracle already consumes the fact table carried by `Ir` for
      thunk elision, exposes region-plan classification from those facts, and
      records source-thunk allocation-site region-plan sampling in `EvalStats`,
      but cache-key reuse, closed-world fixpoints, allocation-site placement,
      and JIT consumers remain open.
- [x] Current IR-fact substrate precursor: `ratchet-core::ir` exposes the
      conservative `ExprFacts` lattice (`Unknown` strictness, `Many`
      cardinality, `Escapes` allocation behavior) plus an `IrFacts` table
      attached to every lowered `Ir`; lowering, parse-cache hydration, and
      manual IR fixtures initialize one conservative record per node, import IR
      remapping preserves the fact table it receives, and parse-artifact
      validation rejects fact-table/node-count mismatches. Parse-cache entry
      reads now optionally overlay a validated `facts.bin` sidecar only when it
      matches the lowered-IR artifact fingerprint, and fall back to conservative
      facts when the sidecar is absent, malformed, or stale.
      This does not close `ir/annotate.rs`: analysis passes, IR-hash
      content-addressed persistent fact artifacts, strictness FV sets, and
      JIT lowering consumers remain open.
- [ ] Soundness harness: property-test fuzzing of escape signatures for the
      ~120-primop surface (a wrong escape-transparency claim could corrupt a
      result — `R-9`).
- [x] Current lowering-policy precursor: `ExprFacts::binding_lowering`
      encodes THUNK/EAGER/SCALAR selection with THUNK as the conservative
      default, `Eager` gated by proven strictness, and `Scalar` gated by both
      proven strictness and proven no-escape. `ExprFacts::thunk_sharing` keeps
      normal update/blackhole machinery unless cardinality plus no-escape
      proofs license single-entry thunks, or a non-contradicted absence proof
      licenses omission. This is the policy API; JIT consumers and the analysis
      passes remain open.
- [x] Current tree-walk lowering consumer: `eval_thunk_alloc` now consumes
      `ExprFacts::binding_lowering` for thunk-allocation nodes. Conservative
      facts still allocate suspended thunks; `Eager` and `Scalar` facts evaluate
      the body directly to WHNF and increment `thunks_elided` except while
      `let`, attrset, or formal-set default bindings are being assembled. Those
      order-sensitive paths keep all binding thunks lazy to avoid reading
      uninitialized forward-reference slots or reordering value errors ahead of
      dynamic-key and duplicate-key validation. The tree-walk oracle treats
      `Scalar` as eager WHNF until optimized tiers add non-heap storage. Gate:
      `attrs_2` tests cover conservative thunk preservation, safe strict/eager
      fact elision, inherited-select assembly preservation, dynamic-key error
      ordering, and frame-initialization preservation.
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
- [x] Current `attrs/shape.rs` precursor: `ratchet-value` exposes the safe
      `AttrShape` descriptor with symbol-sorted key vector, binary-search slot
      lookup, construction-order permutation, rank-sorted raw-byte
      lexicographic iteration permutation, shape-local inverse lexicographic
      rank table, and an in-process xxh3 key-vector fingerprint. Global/shared
      shape interning, PIC integration, HAMT dispatch, and runtime fast paths
      remain open.
- [x] Current shape-transition precursor: `AttrShape` can locally plan key
      insertions. Existing keys return the current symbol-sorted slot; new keys
      append to construction order and produce a child descriptor with updated
      source/lexicographic permutations. The local descriptor API itself has no
      parent-edge cache; the process-local table precursor below owns cached
      edges and pointer-identity handles.
- [x] Current shape-table precursor: `ratchet-value` exposes a process-local
      `ShapeTable` rooted at the empty shape, pointer-identity `ShapeHandle`s,
      fingerprint-filtered descriptor interning, and parent-record transition
      edge caching. Global/shared table behavior, lock-free reads, runtime attr
      allocation, select-site use, and `.drv` effects remain open.
- [x] Current shaped-instance precursor: `ratchet-value` exposes `ShapedAttrs`,
      a safe `{ ShapeHandle, values_by_symbol }` flat instance that validates
      value counts, stores values in the shape's symbol-slot order, and
      iterates through the shape's source/lexicographic permutations. Source
      positions, evaluator heap allocation, active `FlatAttrs` replacement,
      select-site/runtime use, and `.drv` effects remain open.
- [x] Current static-shape-plan precursor: `ratchet-value` exposes
      `StaticShapePlan`, which resolves static literal construction-order keys
      through the process-local transition tree once, stores the final
      `ShapeHandle`, and records source-slot to symbol-slot placement for
      filling shaped value arrays. IR lowering, evaluator attr allocation,
      active `FlatAttrs` replacement, and `.drv` effects remain open.
- [x] Current shaped hash-consing precursor: `ratchet-value` exposes
      `ShapedAttrConsTable`, which buckets `ShapedAttrs` by an in-process
      shaped fingerprint and reuses only candidates confirmed by the same
      interned shape pointer plus raw `Value` equality. It returns
      `Arc<ShapedAttrs>` handles; evaluator heap allocation, active `FlatAttrs`
      replacement, select-site/runtime use, and `.drv` effects remain open.
- [ ] `attrs/pic.rs` — polymorphic inline caches at `select` sites
      (shape-check → constant-offset load; megamorphic fallback).
- [x] Current `attrs/pic.rs` precursor: `ratchet-value` exposes the safe
      inline-cache state-machine contract with opaque process-local shape ids,
      shape-to-slot entries, default polymorphic cap `N = 4`, and checked
      `Uninitialized → Monomorphic → Polymorphic → Megamorphic` transitions.
      Runtime select execution, shape guards, slow resolver dispatch, tree-walk
      ICs, and deopt edges remain open.
- [x] Current shaped-select fast-path precursor: `ratchet-value` exposes
      `ShapedSelectCache`, which guards one static key on `ShapedAttrs` by
      interned shape pointer, loads cached symbol slots on hits, resolves misses
      through the shape descriptor, and widens through the PIC state machine.
      Tree-walk `Select`, final runtime `select_slow`, HAMT-valued selection,
      and `.drv` effects remain open.
- [x] Current `select_slow` precursor: `ratchet-value` exposes
      `attrs::select`, a representation-dispatching slow lookup over `FlatAttrs`,
      `HamtAttrs`, and `ShapedAttrs`. Flat uses binary search, HAMT uses trie
      lookup, and shaped attrs resolve a shape slot before loading the value
      array. Tree-walk `Select`, the PIC miss path, runtime attr representation,
      and `.drv` effects remain open.
- [x] Current shaped update precursor: `ratchet-value` exposes
      `ShapedUpdatePlan`, which computes a small shaped `//` result shape
      through the transition tree and instantiates a shaped value array with the
      current shallow update order: left source-order bindings keep their
      slots, right values overwrite shared keys, and right-only bindings append
      in right source order. Active `//` evaluator integration, HAMT policy use,
      and `.drv` effects remain open.
- [ ] `attrs/hamt.rs` — HAMT for `//` update merges; `u32` symbol interning
      preserved (`S-10`).
- [x] Current `attrs/hamt.rs` precursor: `ratchet-value` exposes a safe
      immutable bitmap-indexed attr map keyed by dense `Symbol` ids, with
      persistent insert/replace, checked duplicate/unknown-key handling, and a
      cached rank-sorted raw-byte lexicographic ordered view. The active `//`
      evaluator path, HAMT-valued selection, final measured CHAMP layout, and
      observable `.drv` effects remain open.
- [x] Current HAMT update-merge precursor: `ratchet-value` exposes
      `HamtAttrs::update_from_flat` and `HamtAttrs::update_from_hamt`, which
      apply right-biased `//` merges through persistent insert/replace
      operations, preserve old roots, report inserted/replaced counts, and
      rebuild the cached raw-byte lexicographic ordered view once for the merged
      result. Active `//` evaluator wiring, representation-policy dispatch,
      final CHAMP tuning, and `.drv` effects remain open.
- [x] Current `attrs/repr.rs` precursor: `ratchet-value` exposes a safe
      `Flat`/`Hamt` representation-policy classifier for static literals,
      dynamic constructions, and `//` merge results. Static literals are
      threshold-exempt and stay flat because their shape is known; existing HAMT
      left operands, large results, and deep override chains prefer HAMT; HAMT
      decisions require an ordered-view memo. HAMT nodes, `//` integration,
      `FlatAttrs` changes, and observable order changes remain open.
- [x] Current update-dispatch precursor: `ratchet-value` exposes
      `AttrSetReprValue`, a safe `FlatAttrs`/`HamtAttrs` wrapper with
      `update_from_flat_right` policy dispatch. Small flat-left merges copy into
      a new flat attrset preserving left slots plus right-only append order;
      HAMT-classified merges convert flat left operands as needed and call the
      persistent HAMT merge helper. The precursor assumes `self`, `right`, and
      `symbols` share one symbol universe. Active evaluator `//` wiring, HAMT
      right source-order semantics, measured threshold calibration, and `.drv`
      differential proof remain open.
- [x] Current HAMT select-policy precursor: `ratchet-value` exposes
      `HamtSelectCache`, which binds one static select key and models the two
      RFC policy choices for HAMT-valued selections: cache a distinguished HAMT
      entry that keeps using keyed HAMT lookup, or fold the site into the
      megamorphic path. The HAMT attrset and select key must share one symbol
      universe. `select_slow`, `ShapedSelectCache`, native PIC lowering, and
      active evaluator selection remain open.
- [ ] Deterministic iteration order preserved across shape transitions
      (the ordering invariant of [09](09-attribute-sets-hidden-classes-and-inline-caches.md)).
- [x] Current in-process order-parity precursor: `ratchet-value` exposes
      `attrs::order`, which collects and validates observable raw-byte
      lexicographic key vectors for `FlatAttrs`, `HamtAttrs`, `ShapedAttrs`, and
      `AttrSetReprValue`, compares representations against each other under the
      same symbol universe, rejects unresolved symbols, and tests adversarial
      symbol allocation order (`b`, `a\xff`, `a`, `a\0`). C++ Nix differential
      checking, `derivationStrict` consumption, and `.drv` byte parity remain
      open.
- [x] Current cached ordering-rank precursor: `aos-nix-syntax::SymbolTable`
      maintains process-local current raw-byte lexicographic ranks; current
      flat attrsets, shapes, and HAMTs sort ordered views through that rank
      snapshot; and shapes expose a shape-local inverse rank table over
      symbol-sorted slots. Global/shared symbol ranks, runtime shape/HAMT use,
      `derivationStrict` shape-order consumption, and full order-parity harness
      proof remain open.
- [x] Current native derivationStrict quoted/non-ASCII ordering canary:
      `native_instantiation_expr_orders_quoted_non_ascii_derivation_env_attrs`
      instantiates a static derivation whose environment mixes ordinary keys
      with a quoted `é` key and asserts the emitted root ATerm environment
      tuples appear in raw-byte lexicographic order (`aardvark`, `builder`,
      `name`, `out`, `system`, `zz`, then `é`). The env-gated
      `configured_cpp_nix_native_drv_closure_bytes_match_cli` oracle test
      includes the same shape and, when `AOS_NIX_ORACLE` is configured, compares
      the native `.drv` root path and recorded ATerm bytes against C++ Nix
      materialization. This is a focused current flat/native derivationStrict
      canary only; global/shared symbol ranks, future shaped/HAMT evaluator
      representations, active cached-order consumption by those representations,
      full conformance 20-21, and full AOS closure ordering parity remain open
      (`S-13`).
- [x] Current attrset telemetry precursor: `ratchet-value::attrs::telemetry`
      exposes in-process, byte-neutral counters/snapshots for shape census,
      generic/shaped/HAMT select-cache terminal-state histograms and lookup
      paths, `//` operand-size, result-length-upper-bound, and
      override-chain-depth distributions, HAMT merge insert/replace totals, and
      order-parity outcomes. The active tree-walk evaluator now records `//`
      update-merge samples with syntactic update-chain depth through this
      telemetry surface and exposes them via `EvalOutcome::attr_telemetry`; this
      does not replace runtime
      shape/PIC/HAMT instrumentation, full package-set measurements, C++
      `NIX_SHOW_STATS` comparison, or `.drv` differential proof.

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
- [x] Current constant-thunk CLIF body precursor:
      `ratchet-jit::lower::lower_constant_thunk_body()` builds and verifies a
      Cranelift `Function` for a compiled thunk body returning one constant
      runtime `Value`. It consumes the frozen thunk signature, appends entry
      block parameters for `rt` and `env`, emits two `iconst.i64` instructions
      for the `ratchet-value` tag/payload words, and returns those two ABI
      words. Tests pin signature parity, entry-block parameter shape,
      int/bool/null constants, and verifier acceptance. This is a lowerer smoke
      test only: no generic IR traversal, force/runtime calls, `JITModule`,
      executable buffer, finalized function pointer, symbol registration, or
      native call is implemented.
- [x] Current literal-IR CLIF root precursor:
      `ratchet-jit::lower::lower_constant_ir_thunk_body()` accepts actual Core
      IR arena roots for `Int`, `Float`, `Bool`, and `Null` literals, converts
      them to the current `ratchet-value` representation, and reuses the
      constant-thunk CLIF body path. It rejects missing roots, unsupported root
      kinds, and mismatched kind/payload pairs. Tests cover supported literals
      and those rejection paths. This remains bounded constant lowering: no
      generic child traversal, environment access, forcing, runtime-symbol calls,
      branches, applications, `JITModule`, executable buffer, finalized function
      pointer, symbol registration, or native call is implemented.
- [x] Current whole-IR literal CLIF entrypoint precursor:
      `ratchet-jit::lower::lower_constant_ir_root_thunk_body()` takes a lowered
      Core `Ir` artifact and lowers its root through the same literal-only CLIF
      path. Tests cover parsed/resolved/lowered literal source artifacts,
      nonzero artifact roots, and malformed artifacts with missing root ids. The
      crate root re-exports the literal IR lowering functions; this is still
      verified CLIF function construction only, with no `JITModule`, executable
      buffer, symbol registration, or native call.
- [x] Current direct-`ThunkAlloc` literal CLIF precursor:
      `ratchet-jit::lower::lower_constant_ir_thunk_body()` unwraps one direct
      `IrKind::ThunkAlloc` / `IrData::Node` wrapper and lowers its literal body
      through the constant path. Tests cover raw direct literal thunk allocation,
      missing thunk body ids, unsupported thunk body kinds, and malformed thunk
      payload data. This is the first bounded child traversal only:
      the literal path emits no helper calls, and nested/generic traversal,
      executable/native runtime calls, forcing, branches, applications,
      `JITModule`, executable buffer, symbol registration, and native calls
      remain unimplemented.
- [x] Current local env-slot CLIF precursor:
      `ratchet-jit::lower::lower_env_get_ir_thunk_body()` lowers a direct
      `IrKind::LocalVar` root, plus one direct `ThunkAlloc` wrapper around a
      local variable, into verified non-executable CLIF. The generated body
      imports `aos_env_get` through deterministic user-external CLIF metadata,
      passes the compiled thunk `env` parameter and an `i32` slot constant, and
      returns the helper's two runtime `Value` words. Tests pin helper
      namespace/index metadata, imported signature parity with `ratchet-core`,
      call operands/results, artifact metadata, and malformed/unsupported IR
      rejection paths. This is the first emitted runtime-helper call in the
      lowerer, but still no `JITModule`, real symbol relocation, native helper
      address, executable buffer, raw pointer call, upvalue frame traversal,
      force/select/app lowering, or generic IR traversal is implemented.
- [x] Current forced env-slot CLIF precursor:
      `ratchet-jit::lower::lower_forced_env_get_ir_thunk_body()` lowers the
      same bounded local-slot shapes as the env-get precursor, then emits an
      `aos_force(rt, value)` helper call over the loaded two-word runtime
      `Value`. The generated body imports both `aos_env_get` and `aos_force`
      through deterministic user-external CLIF metadata, passes the compiled
      thunk `rt` parameter into the force call, and returns the forced
      two-word `Value`. Module-readiness metadata now resolves the `aos_force`
      artifact import alongside `aos_env_get`, and the existing registered
      artifact-definition path can rewrite both helper imports with synthetic
      candidates. Tests pin helper namespace/index metadata, imported signature
      parity, call ordering and operands, direct `ThunkAlloc` artifact metadata,
      readiness import resolution, registered definition of the forced artifact,
      the missing-`aos_force` candidate guard, and the explicit registered
      finalization rejection for forced artifacts. The new lowerer entrypoints
      remain verified non-executable CLIF construction; registered Cranelift
      coverage stops at the existing definition-only `JITModule` preflight with
      synthetic candidates. Forced artifacts are not eligible for the registered
      finalization preflight yet, so no executable pointer exposure, real
      exported wrapper address, raw pointer call, select/app lowering, or
      generic IR traversal is implemented.
- [x] Current deterministic IR-root CLIF naming precursor:
      `ratchet-jit::lower::clif_name_for_ir_root()` reserves a Cranelift
      user-function namespace for verified CLIF functions lowered from Core IR
      roots and uses the raw `IrId` as the function index. Tests pin default
      constant-body naming, reserved namespace/index mapping, direct
      `ThunkAlloc` root naming, and nonzero whole-artifact root naming. This is
      non-executable naming metadata only: no `JITModule`, symbol declaration,
      relocation, executable address, compiled artifact cache, or native call is
      implemented.
- [x] Current non-executable CLIF artifact precursor:
      `ratchet-jit::artifact::JitClifArtifact` carries verified Cranelift
      `Function` values together with tier, thunk-body kind, and source identity
      metadata. The lowerer now exposes artifact-returning variants for
      standalone constant smoke bodies, literal IR roots, local env-slot roots,
      direct `ThunkAlloc` wrappers, and whole-IR root entrypoints. Tests pin
      tier-1/kind/source metadata, default smoke-body naming, direct
      `ThunkAlloc` root source ids, nonzero whole-artifact roots, env-slot
      artifact source ids, and extraction of the contained CLIF function. This
      is address-free CLIF metadata only: no `JITModule`, executable buffer,
      function pointer,
      symbol registration, compiled artifact cache, persistence format, or
      native call is implemented.
- [ ] `jit/abi.rs` — uniform `extern "C"` runtime ABI; primops called by symbol
      ([10](10-primops-and-runtime-abi.md); `M-9` default symbol-call only).
- [x] Current uniform runtime-call ABI metadata precursor:
      `ratchet-core::runtime_abi` now owns safe `RuntimeCallSignature`
      descriptors for compiled thunk bodies, compiled lambda bodies, builtin
      primop wrappers, and the core-owned allocation, attrset has-attr/select-IC/update,
      call-control apply, deoptimization, environment-access, error-control
      throw, force/deep-force, and write-barrier helper shapes. The
      descriptors pin the shared `extern "C"` convention,
      runtime/environment parameter prefix, positional `Value` arguments, helper
      pointer/scalar parameters including symbol and inline-cache site ids,
      deopt-record pointers, error pointers, pointer, `Value`, unit, or
      divergent helper returns, and
      the 16-byte/two-register `Value` layout. Tests cover
      thunk/lambda shapes, primop arity descriptors, unsupported-arity rejection,
      parity with the builtin declaration inventory, and representative helper
      signatures. This is metadata only: no `unsafe extern "C"` type aliases,
      exported wrappers, raw-pointer call boundaries, Cranelift lowering, or
      `JITBuilder::symbol` registration are implemented here.
- [x] Current builtin runtime-call preflight precursor:
      `ratchet-core::runtime_abi::runtime_builtin_call_manifest()` keeps the
      `nix.builtin.*` call-shape inventory in stable runtime-symbol order and
      classifies each builtin as callable primop-wrapper metadata, value-only
      builtin metadata, or an unsupported future arity. The corresponding
      preflight attaches frozen `RuntimeCallSignature` metadata for callable
      builtin symbols and reports value-only symbols (`true`, `false`, `null`,
      `builtins`, and other configured values) as gaps. Tests pin order parity
      with the runtime symbol manifest, representative callable arities,
      value-only gaps, and unsupported-arity handling. This remains metadata
      only: no builtin `unsafe extern "C"` wrappers, executable addresses,
      raw-pointer dispatch, Cranelift lowering, or `JITBuilder::symbol`
      registration are implemented here.
- [x] Current stable-symbol naming precursor: `ratchet-core::runtime_abi`
      freezes the safe metadata names that later `jit/abi.rs` and
      `jit/cranelift.rs` will register: `nix.builtin.<visible-name>` for every
      declared builtin plus typed `aos_*` helper-symbol declarations. It
      validates builtin names before rendering string-keyed symbol names, but
      does not export unsafe ABI functions or register a Cranelift symbol
      table.
- [x] Current `ratchet-jit` crate-boundary precursor:
      `ratchet-jit` is now a workspace crate with
      `#![deny(unsafe_op_in_unsafe_fn)]`, crate-level docs for the future unsafe
      execution-tier boundary, and a safe `abi` module. `abi` mirrors
      the frozen thunk, lambda, primop, and core-owned helper
      `RuntimeCallSignature` metadata from `ratchet-core`, while runtime-symbol
      candidate gates remain in
      `ratchet-oracle` until a lower shared metadata layer exists. Tests prove ABI
      metadata parity and callable-kind coverage. This adds no oracle dependency,
      exported wrappers, raw function-pointer calls, executable addresses, or
      `JITBuilder::symbol` registration.
- [x] Current Cranelift crate-version pin precursor:
      `ratchet-jit::cranelift::jit_cranelift_dependency_pin()` records the exact
      `cranelift-codegen`, `cranelift-jit`, `cranelift-module`, and
      `cranelift-native` crate versions used by the safe CLIF and JIT-module
      setup slices, and tests assert that the active linked crate versions still
      match the pin. This is a crate-version guard only: it does not add
      executable buffers, runtime-symbol address registration, or the later
      user-stack-map git-revision policy.
- [x] Current `ratchet-jit` CLIF-signature ABI precursor:
      `ratchet-jit::abi::clif_signature_for_runtime_call()` lowers the frozen
      `RuntimeCallSignature` metadata into Cranelift `Signature` values for the
      uniform runtime ABI. It maps `rt`, `env`, code pointers, object pointers,
      and `usize` to host-pointer-sized CLIF slots, maps fixed `u32`-sized fields
      to `i32`, expands every runtime `Value` argument or return to two `i64`
      ABI slots, and emits no return slots for unit helpers. Tests cover thunk
      and lambda signatures, primop arities 0-3, representative allocation,
      attrset has-attr/select-IC/update, call-control apply, deoptimization, environment-access,
      error-control throw, force, and write-barrier helper
      signatures, and the layout guard. This signature adapter remains metadata
      only: it does not construct a `JITModule`, register symbols, lower a CLIF
      body, allocate an executable buffer, cross a
      raw pointer call boundary, or export a native wrapper.
- [x] Current artifact runtime-import readiness precursor:
      `ratchet-jit::module::JitModuleReadinessPreflight` inspects each verified
      CLIF artifact's imported external functions and resolves known AOS
      runtime-helper user-external names back to stable runtime symbols.
      Env-slot artifacts report one required `aos_env_get` import, validate that
      import's CLIF signature against the runtime-symbol declaration preflight,
      and surface explicit import gaps for unknown external names, missing
      declarations, missing import signatures, or signature mismatches. Constant
      artifacts report no artifact-specific imports. Tests pin empty imports for
      constants, the resolved env-get import namespace/index, declaration
      parity, malformed-import gap handling, and synthetic complete-plan
      preservation. This is address-free dependency metadata only: no
      `JITBuilder::symbol`, native address binding, relocation, finalization, or
      call into the helper occurs here.
- [x] Current `ratchet-jit` runtime-symbol inventory precursor:
      `ratchet-jit::symbols::jit_runtime_symbol_inventory()` mirrors the
      address-free `ratchet-core` runtime symbol manifest inside the JIT crate
      without depending on `ratchet-oracle`. It preserves core manifest order,
      exposes symbol-presence and kind lookups, and tests pin exact manifest
      parity, representative helper/builtin kinds, sorted order, and mixed
      helper/builtin coverage. This remains symbol metadata only: no candidate
      readiness, executable addresses, Cranelift lowering, exported wrappers, or
      `JITBuilder::symbol` registration is implemented.
- [x] Current JIT symbol-declaration preflight precursor:
      `ratchet-jit::symbols::jit_runtime_symbol_declaration_preflight()` joins
      the stable runtime symbol manifest with callable builtin ABI metadata and
      core-owned allocation, attrset has-attr/select-IC/update, call-control apply,
      deoptimization, environment-access, error-control throw, write-barrier,
      blackhole-check and force/deep-force helper ABI metadata, then lowers those
      runtime signatures to CLIF `Signature` declarations. `aos_env_get` is frozen as
      `(env, slot) -> Value` and lowers to a host-pointer environment parameter,
      an `i32` slot parameter, and two `i64` return slots;
      `aos_force`/`aos_force_deep` are frozen as `(rt, Value) -> Value`;
      `aos_blackhole_check` is frozen as `(rt, Value) -> Unit`;
      `aos_apply` is frozen as `(rt, Value function, Value arg) -> Value`;
      `aos_has_attr`/`aos_select_ic` are frozen as
      `(rt, Value attrs, SymbolId, InlineCacheSiteId) -> Value`; `aos_update`
      is frozen as `(rt, Value left, Value right) -> Value`; `aos_deopt`
      is frozen as `(rt, DeoptRecordPointer) -> Value`; `aos_throw` is frozen
      as `(rt, ErrorPointer) -> !`.
      Unshaped helpers (`aos_try_begin` and `aos_try_end`)
      and value-only builtins
      remain explicit declaration gaps. Tests pin a representative callable
      builtin declaration, allocation, attrset-access, call-control,
      deoptimization, environment-access, error-control,
      write-barrier, and forcing-helper declarations, the current unshaped
      try-helper gaps, value-only builtin gaps, and exact declaration parity with callable
      builtins plus core-owned helpers.
      This is declaration metadata only: no environment layout, runtime helper
      address, `JITModule`, `JITBuilder::symbol`, executable address, exported
      wrapper, relocation, or native call is implemented.
- [x] Current JIT symbol-registration preflight precursor:
      `ratchet-jit::symbols::jit_runtime_symbol_registration_preflight()`
      consumes the CLIF declaration preflight and joins it with explicit
      native-address candidate metadata. The default safe scaffold installs no
      address table, so currently every declaration reports a missing native
      address while declaration gaps remain preserved in stable runtime-symbol
      order. Tests pin missing-address gaps for callable builtins and
      core-owned helpers, declaration-gap preservation, synthetic candidate
      binding order for allocation and environment-access helpers plus callable
      builtins, kind-mismatch handling, duplicate-candidate rejection, and
      unknown-candidate rejection, plus the incomplete-plan gate. This is
      registration-readiness metadata only: it does not call `JITBuilder::symbol`,
      expose raw function pointers, dereference native addresses, export
      wrappers, finalize code, or call native code.
- [x] Current Cranelift `JITBuilder::symbol` registration precursor:
      `ratchet-jit::cranelift::jit_cranelift_symbol_registration_preflight_with_candidates()`
      consumes explicit native-address candidates, calls `JITBuilder::symbol`
      for every symbol that has both CLIF declaration metadata and address
      metadata, and seals the configured builder inside an encapsulated
      `JITModule`. Missing declarations, missing addresses, kind mismatches,
      duplicates, and unknown candidates stay as registration gaps or errors.
      Tests pin the default no-address state, synthetic registered-symbol order
      for allocation and environment-access helpers plus callable builtins,
      representative declaration gaps, unknown-candidate error propagation, and
      encapsulated-module ownership. This does not install real exported wrappers,
      dereference or call registered addresses, declare imports, define CLIF
      functions, finalize executable memory, or expose code
      pointers.
- [x] Current JIT module-readiness precursor:
      `ratchet-jit::module::jit_module_readiness_preflight_for_artifact()`
      composes a verified CLIF artifact with the address-free JIT runtime-symbol
      declaration preflight and exposes the artifact metadata, callable builtin
      declarations, core-owned allocation, attrset has-attr/select-IC/update, deoptimization,
      environment-access, error-control throw, write-barrier, call-control
      apply, blackhole-check, and force/deep-force helper declarations, and stable
      runtime-symbol gaps as one future module-setup handoff. The checked
      `jit_module_readiness_plan_for_artifact()` gate currently returns an
      incomplete-symbol error while unshaped helpers (`aos_try_begin` and `aos_try_end`) and
      value-only builtin declaration gaps remain.
      Tests pin artifact metadata, callable builtin/helper declaration
      visibility, representative helper gaps, the
      current incomplete-plan error, deterministic IR-root function-name copying,
      and a synthetic complete conversion. This readiness API remains metadata
      only: it does not construct a `JITModule`, allocate an executable buffer,
      attach a symbol address, emit a relocation, or call `JITBuilder::symbol`.
- [x] Current safe `JITModule` declaration precursor:
      `ratchet-jit::cranelift::jit_cranelift_module_declaration_preflight_for_artifact()`
      builds a real Cranelift `JITModule` through a fallible native-ISA builder
      and declares every currently shape-known callable builtin plus
      core-owned allocation, attrset has-attr/select-IC/update, call-control apply,
      deoptimization, environment-access, error-control throw, write-barrier,
      blackhole-check, and force/deep-force helper runtime symbol as a
      `Linkage::Import` function. The stricter
      `jit_cranelift_module_setup_for_artifact()` remains gated by the
      module-readiness plan and currently returns an incomplete-symbol error
      while unshaped helpers (`aos_try_begin` and `aos_try_end`) and value-only builtin
      gaps remain. Tests pin the expanded Cranelift crate-version set,
      imported callable builtin/helper declarations, representative helper gaps,
      and the strict setup rejection.
      This is real safe module construction and import declaration only: no
      runtime symbol address is registered, no `JITBuilder::symbol` call is made,
      no CLIF body is defined in the module, no executable memory is finalized,
      and no native code pointer is produced or called.
- [x] Current Cranelift artifact-definition precursor:
      `ratchet-jit::cranelift::jit_cranelift_artifact_definition_preflight_for_artifact()`
      consumes one verified CLIF artifact, declares a deterministic exported
      module symbol for the artifact body, and passes that body through
      Cranelift's `JITModule::define_function` API while preserving callable
      builtin/helper imports and the current unshaped-helper/value-only builtin
      declaration gaps, while rejecting call-bearing artifacts with a structured
      runtime-import registration error. Tests pin constant-smoke and
      Core-IR-root module symbol names, exported linkage, imported callable
      builtin/helper visibility, representative helper gaps, env-slot
      runtime-import rejection, and encapsulated-module ownership. This compiles
      into a private `JITModule` and does allocate JIT code memory through
      Cranelift on successful definition, but it still does not register runtime
      symbol addresses, call `JITBuilder::symbol`, finalize definitions, expose a
      code pointer, call native code, lower generic IR, or emit runtime calls.
- [x] Current registered-symbol artifact-definition precursor:
      `ratchet-jit::cranelift::jit_cranelift_registered_artifact_definition_preflight_with_candidates()`
      composes explicit native-address candidates with the artifact definition
      path. It calls `JITBuilder::symbol` for declaration-matched candidates,
      declares runtime imports in the same module, rewrites artifact runtime
      helper imports such as `aos_env_get` from AOS user-external names to
      Cranelift module-local `FuncId` names, and defines the artifact body. Tests
      pin env-slot artifact definition with a synthetic `aos_env_get` candidate,
      missing-candidate rejection for artifact imports, constant artifact
      definition while unrelated registration gaps remain, exported linkage,
      registered/imported symbol visibility, representative registration gaps,
      and encapsulated-module ownership. This is still definition-only: it does
      not use real exported wrappers, dereference or call registered addresses,
      finalize executable memory, expose a code pointer, install tier metadata,
      or call native code.
- [x] Current registered-symbol artifact-finalization precursor:
      `ratchet-jit::cranelift::jit_cranelift_registered_artifact_finalization_preflight_with_candidates()`
      composes explicit native-address candidates with the registered artifact
      definition path, calls `JITModule::finalize_definitions`, and returns a
      non-null opaque code pointer for the finalized artifact body. Tests pin
      env-slot finalization with a synthetic relocation target for `aos_env_get`,
      missing-candidate and wrong-kind candidate rejection for artifact imports,
      unresolved-import readiness preservation, code-pointer metadata,
      registered/imported symbol visibility, representative registration gaps,
      and encapsulated-module ownership. This finalizes executable memory for
      registered call-bearing artifacts, but still does not use real exported
      wrappers, directly dereference or call registered addresses, cast or call
      the finalized code pointer, install tier metadata, mutate evaluator thunk
      state, or complete runtime-symbol registration for unrelated stable
      symbols.
- [x] Current Cranelift artifact-finalization precursor:
      `ratchet-jit::cranelift::jit_cranelift_artifact_finalization_preflight_for_artifact()`
      takes one verified CLIF artifact through the same import declaration and
      artifact definition path, calls `JITModule::finalize_definitions`, and
      returns a non-null opaque finalized code pointer for the exported artifact
      body. Tests pin constant-smoke and Core-IR-root symbol names, exported
      linkage, non-null code-pointer metadata, callable builtin imports,
      representative helper gaps, encapsulated-module ownership, and conversion
      into the slot-compatible `JitCompiledCodePointer` metadata wrapper, and
      structured rejection for env-slot artifacts with runtime imports. This
      finalizes executable memory for non-call-bearing artifacts but still does
      not install the pointer into evaluator thunk state, cast the code pointer
      to a function type, call native code, lower generic IR, emit runtime calls,
      or complete runtime-symbol registration. This unregistered API still
      rejects call-bearing artifacts; those artifacts must use a registered
      finalization path, and full native-call integration still requires real
      exported wrappers plus matching address registration for every emitted
      runtime call.
- [x] Current owned Cranelift tier-1 slot preflight:
      `ratchet-jit::cranelift::jit_cranelift_tier1_slot_preflight_for_artifact()`
      composes artifact finalization with a fresh `JitTieredCodeSlot`, installs
      the finalized artifact's opaque `JitCompiledCodePointer` into that slot,
      and keeps the `JITModule` owner in the same returned preflight value. Tests
      pin constant-smoke and Core-IR-root slot installation, slot/current-tier
      state, pointer equality with the finalized artifact, incomplete runtime
      symbol readiness, runtime-import rejection, and module ownership. This
      unregistered path is still metadata assembly only: it does not publish into
      evaluator heap thunk state, perform atomic thunk-state CAS, cast or call
      the code pointer, lower generic IR, emit runtime calls, or complete
      runtime-symbol registration.
- [x] Current registered-symbol tier-1 slot preflight:
      `ratchet-jit::cranelift::jit_cranelift_registered_tier1_slot_preflight_with_candidates()`
      composes registered-symbol artifact finalization with a fresh
      `JitTieredCodeSlot`, installs the finalized artifact's opaque
      `JitCompiledCodePointer`, and keeps the `JITModule` owner beside the slot
      metadata. Tests pin env-slot installation with a synthetic relocation
      target for `aos_env_get`, constant artifact installation while unrelated
      registration gaps remain, missing-candidate rejection, slot/current-tier
      state, pointer equality, registered/imported symbol visibility, artifact
      runtime-import metadata, and module ownership. This remains metadata
      assembly only: it does not publish into evaluator heap thunk state, perform
      atomic thunk-state CAS, directly dereference or call registered addresses,
      cast or call the code pointer, lower generic IR, or complete
      runtime-symbol registration for unrelated stable symbols.
- [x] Current promotion-gated tier-1 compile/install preflight:
      `ratchet-jit::cranelift::jit_cranelift_tier1_promotion_preflight_for_ir_root()`
      records one invocation on an existing `JitTieredCodeSlot`, applies
      `TierUpPolicy`, and only when the policy requests tier-1 promotion lowers a
      currently-supported literal IR root, finalizes it, installs the opaque
      pointer metadata into the updated slot, and keeps the `JITModule` owner in
      the promoted result. Tests pin cold no-compile behavior for unsupported
      roots, threshold and multi-use promotion, installed-slot no-repeat
      compilation, deferred lowering errors, slot counter preservation on success
      and promoted errors, pointer equality, and module ownership. This is still
      unregistered safe preflight assembly only: no evaluator heap thunk is
      mutated, no atomic thunk-state CAS runs, no native code pointer is cast or
      called, and runtime-call lowering remains rejected by this path.
- [x] Current registered-symbol promotion-gated tier-1 compile/install preflight:
      `ratchet-jit::cranelift::jit_cranelift_registered_tier1_promotion_preflight_for_ir_root_with_candidates()`
      records one invocation on an existing `JitTieredCodeSlot`, applies
      `TierUpPolicy`, and only when policy requests tier-1 promotion lowers a
      currently-supported literal or local env-slot IR root, finalizes it through
      the registered-symbol path, installs the opaque pointer metadata into the
      updated slot, and keeps the `JITModule` owner in the promoted result. Tests
      pin cold no-compile behavior for unsupported roots, env-slot threshold
      promotion with a synthetic relocation target for `aos_env_get`, wrapped
      env-slot and wrapped literal roots, literal multi-use promotion without
      runtime candidates, promoted missing-candidate failure with slot counter
      preservation, deferred lowering errors, pointer equality,
      registered/imported symbol metadata, and module ownership. This is still
      safe preflight assembly only: no evaluator heap thunk is mutated, no atomic
      thunk-state CAS runs, registered addresses are not directly dereferenced or
      called, no native code pointer is cast or called, and generic runtime-call
      lowering beyond the env-slot precursor remains open.
- [x] Current force-aware registered promotion precursor:
      `ratchet-jit::cranelift::jit_cranelift_force_aware_registered_tier1_promotion_preflight_for_ir_root_with_candidates()`
      records one invocation with the same tier-up policy, preserves the
      existing literal-root promotion path, and lowers local env-slot roots
      through the forced env-slot CLIF artifact. Hot local-slot roots therefore
      require both `aos_env_get` and `aos_force` candidates, then stop at the
      explicit `aos_force` registered-finalization guard before any pointer is
      installed. Tests pin cold unsupported-root no-lowering behavior, literal
      multi-use promotion without runtime candidates, and hot env-slot
      force-call promotion rejection with the invocation-updated slot preserved.
      This is a policy/lowering handoff only: no evaluator heap thunk is
      mutated, no atomic thunk-state CAS runs, no forced artifact is finalized,
      no native code pointer is cast or called, and no `aos_force` wrapper is
      exported or invoked.
- [x] Current compiled-tier safepoint policy precursor:
      `ratchet-jit::safepoints::jit_safepoint_policy()` records that compiled
      tier 1 and tier 2 code must emit safepoints and user stack maps
      unconditionally, and that the required safepoint placements are allocation
      sites and `aos_force` calls. Tests pin the policy for both compiled tiers
      and the exact placement set. This remains policy metadata only: no
      Cranelift user-stack-map emission, live-reference annotation, collector
      root consumption, executable buffer, `JITModule`, or symbol registration is
      implemented.
- [ ] `jit/tier.rs` — tier-up policy (hot-thunk detection) into tier 1.
- [x] Current `ratchet-jit` tier-up policy precursor:
      `ratchet-jit::tier::TierUpPolicy` names the tier-0 to tier-1 hotness
      decision as safe policy metadata: a low default invocation threshold plus
      optional accepted multi-use evidence from profiling or cardinality
      analysis. `TierUpCounter` saturates invocation observations,
      `TierUpObservation` carries invocation, demand, and current-tier evidence,
      and `TierUpDecision` reports stay/promote decisions with target tier and
      reason bits. Tests pin threshold promotion, eager multi-use promotion,
      absent/once cardinality staying cold, disabled eager promotion, combined
      reasons, zero-threshold measurement tuning, counter saturation, and
      already-tier-1 no-repeat promotion. This does not store counters beside
      thunks, mutate thunk state or code pointers, lower Cranelift IR, compile
      native code, install OSR, or run tier-1 code.
- [x] Current tiered code-slot precursor:
      `ratchet-jit::tier::JitTieredCodeSlot` stores a saturating
      `TierUpCounter` beside optional opaque `JitCompiledCodePointer` metadata,
      records invocations through `TierUpPolicy`, and installs tier-1 code
      metadata once after a future compile. Tests pin cold default state,
      threshold and multi-use promotion decisions, duplicate-install rejection,
      and already-installed tier-1 no-repeat promotion. This is safe slot
      metadata only: no evaluator heap thunk is rewritten, no atomic thunk-state
      CAS is implemented, no Cranelift lowering/finalization is triggered, and no
      code pointer is cast or called.
- [ ] `unsafe` discipline: `jit/` under `#![deny(unsafe_op_in_unsafe_fn)]`,
      `// SAFETY:` per block, two-maintainer review, ASan/UBSan CI; the
      `transmute` of code pointers is the documented innate-unsafe call (`S-17`).
- [x] Current `ratchet-jit` unsafe-discipline precursor:
      `ratchet-jit::safety::jit_unsafe_discipline()` records the JIT crate's
      unsafe-boundary manifest: `#![deny(unsafe_op_in_unsafe_fn)]`, local
      `// SAFETY:` invariant comments, second-reviewer requirement, sanitizer-CI
      requirement, and the innately unsafe code-pointer-transmute call boundary.
      Tests assert the manifest, prove the crate root declares the lint, and scan
      current JIT sources for real `unsafe`/`extern`/`transmute` code tokens
      outside line comments and ordinary strings. This is a precursor only: no
      unsafe JIT blocks, exported wrappers, executable code calls, CI jobs, or
      review automation are implemented here.
- [ ] Copy-and-patch hedge kept measurable if Cranelift warmup proves too high
      (`M-8`).
- [x] Current copy-and-patch measurement hedge precursor:
      `ratchet-jit::warmup::CopyAndPatchHedgeGate` keeps the deferred
      copy-and-patch alternative measurable without adding a stencil backend. It
      records a Cranelift compile-share threshold, an optional measured
      copy-and-patch compile-time comparison, and a required speedup threshold
      before `CopyAndPatchHedgeDecision::ConsiderCopyAndPatch` can favor the
      stencil backend. Tests pin compile-share accounting, low-share Cranelift
      retention, high-share measurement requests, insufficient and sufficient
      speedup decisions, zero-cost speedup handling, and custom thresholds. This
      is measurement policy only: no stencil generation, backend switch,
      executable patching, benchmark harness, or Cranelift lowering is
      implemented.

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
- [x] Current `value/tag.rs` precursor: `ratchet-value` exposes safe checked
      low-bit heap address tag helpers, reserves the low three bits of
      8-byte-aligned heap pointers, and names the thunk `FORCED` shortcut bit.
      Raw decoded words do not prove pointer provenance or liveness; the active
      `Value` representation and force path are unchanged.
- [x] Current `value/nanbox.rs` precursor: `ratchet-value` exposes the safe
      NaN-box layout contract for the measured value-size variant. It reserves a
      negative quiet-NaN prefix, three tag bits, and a 48-bit payload; normalizes
      colliding float NaNs away from boxed patterns; validates
      heap-address/immediate/small-int payloads; and reports heap-address
      payloads for future precise-GC scanning without reconstructing provenance.
      The active 16-byte `Value` ABI is unchanged.
- [x] Current `value/small.rs` precursor: `ratchet-value` exposes the safe
      small-constructor layout contract. Zero-, one-, and two-slot lists or
      attrsets classify as inline candidates; larger constructors stay
      heap-backed. Checked inline payload helpers preserve list values and attr
      entries without forcing, reject duplicate inline attr keys, and treat
      unused slots as null padding. The active `NixList`/`FlatAttrs`
      representations and observable iteration behavior are unchanged.
- [ ] `analysis/full_laziness.rs` — full-laziness / let-floating
      ([07](07-laziness-and-whole-program-analyses.md); daemon residency policy
      `R-6`).
- [x] Current `analysis/full_laziness.rs` precursor: `ratchet-core` reports
      closed, pure static-key `let` binding values nested under simple identifier lambdas
      as future float-out candidates. It allows the root lazy binding thunk only
      when its forced body is closed and pure, rejects any local/upvalue
      reference, nested thunk allocation, dynamic-scope probe, primop, nested
      frame producer, formal-set pattern, dynamic `let` key, recursive attrset, or effectful node,
      preserves binding index/key context in the report, and performs no rewrite.
      General float-out, float-in, mutually-dependent groups, and daemon
      residency policy remain open.
- [ ] `heap/region.rs` — region inference: lexical/escape regions, extended to
      **full effect-based region inference** as a committed deliverable (`R-5`)
      rather than a research-grade maybe; profiles (`M-14`) tune *where* regions
      replace generational allocation, not *whether* the analysis is built.
- [x] Current `heap/region.rs` precursor: `ratchet-value` exposes the
      conservative region-placement policy for later IR/effect analysis. Private
      allocation sites require positive no-escape, no-latent-force,
      speculable-effect, and bounded-lexical-lifetime proofs before selecting a
      pop-safe lexical subregion; permanent shared values bypass region pop; all
      missing proofs fall back to the active root arena or daemon GC heap.
- [x] Current tree-walk region-plan adapter precursor:
      `TreeWalk::allocation_region_facts` and
      `TreeWalk::region_plan_for_allocation` translate current-module
      `ExprFacts` plus each IR node's `EffectClass` into
      `AllocationRegionFacts` and the existing conservative `RegionPlan`
      decision. Missing node/fact records fail closed to conservative placement,
      hash-consed source value shapes (string/URI/interpolation forms,
      path/search-path forms, lists, and attrsets) are marked permanent shared
      so they bypass lexical region placement, private non-thunk nodes require
      `Strict + NoEscape + speculable` facts to become lexical-subregion
      candidates, and thunk allocations remain conservative until a distinct
      no-latent-force proof exists. Successful source `ThunkAlloc` allocations
      now record the conservative `RegionPlan` outcome in `EvalStats`
      source-thunk region-plan counters, making source-thunk allocation sampling
      observable without changing heap placement. This is a classification
      bridge for future allocation-site placement; it does not allocate into
      subregions, pop automatically, or strengthen the current escape pass.
- [x] Current arena region-pop primitive precursor: `BumpArena` can capture a
      lexical subregion marker and, behind an explicit caller proof, pop back to
      it by rewinding the retained chunk, unmapping later chunks, restoring the
      arena growth state, and advising the newly-dead retained range as dead.
      Linux lowers that hint to `MADV_DONTNEED`; unsupported and sub-page ranges
      remain advisory outcomes. The primitive is covered by same-chunk
      rewind/reuse, whole-chunk release, growth restoration, and invalid-marker
      tests.
- [x] Current tree-walk region-pop admission precursor: `EvalHeap` can capture
      worker-region markers and reclaim a manually admitted suffix only after
      proving all suffix records are worker-owned, retained precise heap edges
      do not target them, and the marker belongs to the current heap/worker
      allocator lifetime. Successful pops call the caller-validated arena
      rewind only after typed validation, roll worker allocation-safepoint state
      back to the marker, truncate typed records, advance the collector snapshot
      epoch, and make reclaimed handles fail as unknown until a later bump reuse
      assigns the address to a new record. Nested LIFO markers remain valid
      across inner pops. Source thunk allocations now record the conservative
      `RegionPlan` decision as telemetry, and
      `pop_worker_region_if_plan_permits` routes that existing decision into
      the manual typed admission boundary. Actual region allocation remains
      disconnected from automatic IR allocation-site placement and
      escape-analysis proofs.
- [ ] `heap/concurrent_gc.rs` — **concurrent *moving* GC** for daemon mode
      (ZGC/Shenandoah-style colored pointers + load barriers), a committed
      deliverable; **daemon-only**, sidestepped by the bump arena in CLI mode
      (`R-1`/`R-2`/`R-3`/`R-4`; the deepest coupling,
      [17](17-roadmap-and-risks.md) R9).
- [x] Current `heap/concurrent_gc.rs` precursor: `ratchet-value` exposes the
      safe daemon-only barrier-address/load-barrier decision contract.
      Already-uncolored aligned address bits with collector-supplied `Current`
      color take the fast path, stale colors route to relocation/marking repair,
      one-shot arena mode disables concurrent barriers, and no high-bit colored
      pointer decoding, object movement, dereference, allocation, or bump-arena
      behavior changes are implemented yet.

**Conformance (hold parity).**

- [ ] Harness stays byte-green for **each** deliverable independently
      ([20](20-nix-language-conformance.md) + [21](21-builtins-conformance.md)
      invariant); a *variant* that cannot stay byte-green is not selected, but the
      feature is still delivered via the variant that holds parity.
- [ ] Concurrent-GC × thunk-mutation interactions verified under `loom`/`miri`
      before shipping (`R-4`), daemon-mode only — the memory-ordering audit is an
      **absolute** gate, not relaxed by the budget mandate.
- [x] Current thunk-mutation barrier precursor: `ratchet-value` classifies the
      load-barrier ordering required before thunk claim/publish mutations.
      Daemon-mode current addresses proceed after the load-barrier fast path,
      stale colors require relocation/marking repair first, and one-shot arena
      mode disables the barrier. The real CAS integration and `loom`/Miri proof
      remain open.

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
