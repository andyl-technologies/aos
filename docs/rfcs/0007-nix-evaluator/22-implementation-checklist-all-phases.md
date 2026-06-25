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
- [ ] Full demand-driven incremental graph remains: create nodes on actual
      force/eval demand, capture dependencies dynamically Adapton-style,
      separate inner/outer observers, schedule transitive
      propagation/recomputation, integrate impure-input leaves and persistence, and
      prove cached/uncached `.drv` parity.
- [x] Current `cache/key.rs` standalone combiner substrate: `CacheExprIdentity`
      plus opaque `DemandCacheKey` compute one order-sensitive xxh3 key over a
      domain/version prefix, expression identity bytes, and caller-supplied
      free-variable value hashes encoded as length-prefixed chunks. This checks
      the C-1 combiner rule only, not demand-graph integration, canonical
      free-variable set/order production, real durable value-hash production, or
      false-hit harness coverage.
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
      `EvalCache::observe_inline_expression_result` and
      `EvalCacheRuntime::observe_inline_expression_result` insert/reconsider
      expression nodes from caller-supplied identities, and tree-walk
      `force_value` now observes successful, closed, source-backed
      `EvalThunkKind::Node` forces whose entire body subtree is both speculable
      and in a conservative self-contained IR-kind whitelist, and whose WHNF
      result is an inline scalar. The precursor expression identity uses a
      domain-separated hash of source name, source bytes, and module
      path-literal base plus the IR node id, so identical file bytes under
      different relative-path bases do not share one observed node. `NixNative`
      passes its caller-owned cache runtime into tree-walk evaluation, so
      repeated closed source-backed evaluations reuse the same demand node and
      apply the existing inline-value early-cutoff decision. This is
      observation/reconsideration only: source-less raw eval, captured
      lexical/dynamic/scoped-global thunks, ambient builtin constants,
      search-path/path/global/builtin/primop/application/dialect nodes pending
      explicit option and impure-input keys, synthetic apply/select/builtin-attr
      thunks, canonical free-variable hashes, general memo lookup,
      heap/composite value hashing, persistence, and cached/uncached harness
      proof remain open (`S-14`/`S-15`).
- [x] Current pure closed inline force-cache hit substrate: `EvalCache` keeps
      per-node inline scalar payload records beside demand-graph value hashes,
      `EvalCacheRuntime::lookup_inline_expression_result` returns a memoized
      value only for clean nodes whose payload hash still matches the graph, and
      tree-walk `force_value` consults this shared cache before evaluating a
      newly claimed closed source-backed thunk whose entire body subtree is
      both speculable and in the conservative self-contained IR-kind whitelist.
      Hits publish the scalar into the evaluator-local thunk cell and update
      cache-hit stats; disabled runtimes, unknown nodes, dirty nodes, missing
      payloads, and stale payloads are misses. This is a scalar/pure/local hit
      path only: source-less raw eval, captured lexical/dynamic/scoped-global
      thunks, ambient builtin constants,
      search-path/path/global/builtin/primop/application/dialect nodes pending
      explicit option and impure-input keys, synthetic apply/select/builtin-attr
      thunks, canonical free-variable hashes, heap/composite payloads,
      transitive dirty scheduling, persistence, `derivationStrict` SHA-256
      short-circuiting, and cached/uncached harness proof remain open
      (`S-14`/`S-15`).
- [x] Current force-time inline impure-edge substrate: tree-walk force slices the
      impure-input trace observed while a closed source-backed thunk body
      evaluates, and
      `EvalCache::observe_inline_expression_result_with_impure_inputs` stores
      an inline scalar payload only when that slice is complete and cacheable,
      wiring the expression node to the observed input leaves at the same time.
      The observation whitelist admits the existing pure subset plus cacheable
      input primops (`getEnv`, `pathExists`, `readDir`, `readFile`,
      `readFileType`) with safe children such as path literals, so stable
      `pathExists` thunks now create expression/input edges while `currentTime`,
      search-path literals, and application-like forms still create no payload.
      Trace-backed payload records are tagged as requiring revalidation and are
      misses through the existing public lookup API; incomplete or uncacheable
      trace observations invalidate any existing inline payload for the same
      key. Lookup remains restricted to the pure/speculable subset until the
      cache retains typed input identities and revalidates them before a hit.
      This is edge wiring and payload storage only; effectful memo reuse,
      source-less raw eval, captured lexical/dynamic/scoped-global thunks,
      ambient builtin constants, search-path/path/global/builtin/
      application/dialect nodes beyond the traceable primop subset, canonical
      free-variable hashes, typed input-identity retention, force-time input
      revalidation, heap/composite payloads, transitive dirty scheduling,
      persistence, `derivationStrict` SHA-256 short-circuiting, and
      cached/uncached harness proof remain open (`R-10`/`S-14`).
- [x] Current force-time inline impure revalidation substrate: trace-backed
      inline payload records now retain the cacheable input fingerprints from
      their force-time trace, and
      `EvalCache::lookup_inline_expression_result_with_impure_inputs`
      revalidates those typed identities through an `ImpureInputRevalidator`
      before returning a scalar payload. Changed, unavailable, uncacheable, or
      identity-mismatched fresh inputs invalidate the payload and miss. Tree-walk
      supplies a conservative options-backed revalidator for `getEnv`,
      `pathExists`, `readDir`, and `readFileType`, so stable source-backed
      `pathExists` thunks can hit after replaying their input probe, while
      deleted or changed paths force recomputation through the normal evaluator
      path. Revalidated cache hits append their fresh fingerprints back into the
      active evaluator trace so enclosing forced thunks cannot be observed as
      pure by losing nested dependencies. `readFile`-backed payloads remain
      misses until revalidation identities include store-dir-dependent string
      context, and the older public pure lookup remains pure-only. This is
      in-memory scalar effectful reuse only; source-less raw eval, captured
      lexical/dynamic/scoped-global thunks, ambient builtin constants,
      search-path/path/global/builtin/application/dialect nodes beyond the
      traceable primop subset, canonical free-variable hashes, persistent
      input-identity retention, heap/composite payloads, transitive dirty
      scheduling, persistent graph/value cache integration, `derivationStrict`
      SHA-256 short-circuiting, and cached/uncached harness proof remain open
      (`R-10`/`S-14`).
- [x] Current force-cache evaluator option identity salt: source-backed force
      expression identities now hash the module's `store_dir`, `home_dir`, and
      `eval_mode` alongside source name, source bytes, path-literal base, and
      IR node id. This prevents the current advisory force cache from sharing
      inline payloads across evaluator configurations that can change
      path/context or impurity-policy behavior. It is deliberately conservative
      and may miss across option changes that do not affect a specific
      expression; full cache-key integration, canonical free-variable hashes,
      fine-grained option dependency tracking, persistent keys, and
      cached/uncached harness proof remain open (`C-1`/`C-2`/`R-10`).
- [x] Current inline captured-free-variable force-cache key substrate: tree-walk
      now builds one force-cache subject for each source-backed node thunk,
      including ordered durable hashes for referenced captured lexical slots
      when every captured slot value is already an inline scalar supported by
      `ValueHash::from_inline_value`. Lookup and observation feed those hashes
      into the existing ordered/length-prefixed demand-key combiner, so repeated
      captured inline thunks hit only when their free-variable value hashes match
      and miss when those captured values differ. This deliberately skips dynamic
      `with` scopes, scoped-import globals, captured
      heap/string/path/list/attrs/lambda/primop/thunk values, captured bodies
      with nested lexical-frame introducers, source-less/apply/select/builtin-attr
      thunks, full strictness/escape free-variable analysis, heap/composite value
      hashes, persistence, and cached/uncached harness proof. The gate covers
      captured inline hit/miss tests, lowered lambda-argument coverage, and
      representative captured unsupported free-variable skips (`C-1`/`C-2`).
- [ ] Full cache-key integration remains: feed source content + IR node position
      from the evaluator into demand-graph expression nodes, reuse the
      strictness/escape free-variable set for canonical slot ordering, feed real
      durable value hashes, and run the differential false-hit gate (`C-1`/`C-2`).
- [x] Current memoization-granularity policy substrate: `cache::policy` defines
      `MemoizationSubject` defaults for the always/conditional/never classes and
      `MemoizationClass::decide` admits conditional work only when both
      used-many and cheap-value-hash signals are present. This is policy
      vocabulary only; evaluator subject selection, demand/cardinality signal
      production, hit/overhead tracing, `force_memoized` use,
      persistence/materialization decisions, and measured AOS tuning remain open
      (`M-11`).
- [x] Current `cache/cutoff.rs` standalone decision primitive: typed
      `ValueHash` plus `EarlyCutoff::decide(previous, recomputed)` returns
      `CutOff` only when a prior value hash exists and equals the recomputed
      value hash; missing or changed prior hashes return `Propagate`.
- [x] Current inline scalar value-hash substrate:
      `ValueHash::from_inline_value` hashes validated inline WHNF
      `int`/`bool`/`null`/`float` payloads in the durable BLAKE3 domain
      `aos-nix-inline-value-hash-v1`; floats are hashed by raw IEEE bits, so
      this may over-propagate relative to future Nix numeric canonicalization
      but cannot cut off distinct bit patterns. Heap-backed values,
      strings/paths/lists/attrs canonical serialization, functions/thunks
      cacheability policy, generic hash-cons value fields, `force_memoized`
      integration, persistence, and harness proof remain open (`S-14`/`S-15`).
- [x] Current inline-value early-cutoff adapter:
      `DemandGraph::reconsider_inline_value_node` and
      `EvalCache::reconsider_inline_value_node` hash a recomputed inline scalar
      before applying ordinary node reconsideration; unsupported heap values
      fail before mutating node state. This is an inline adapter only;
      heap/composite canonical hashing, functions/thunks policy, real evaluator
      value-hash production, `force_memoized`, evaluator node lifecycle,
      automatic `NixNative` use, persistence, and harness proof remain open
      (`S-14`/`S-15`).
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
- [ ] Remaining full P2 cache hashing split: demand-graph xxh3 keys, BLAKE3
      durable/shared value and file CA keys, full type-enforced leak-invariant
      boundaries, and CI/harness proof that internal xxh3/BLAKE3 digests cannot
      reach Nix-observed store-path or `.drv` SHA-256 inputs (`S-15`).
- [x] Current `cache/persist.rs` layout/schema substrate: creates an
      evaluator-cache root with versioned `nodes/`, `values/`, `files/`, and
      `schema.toml` metadata carrying a stable format marker plus schema
      version; matching schemas preserve payloads, well-formed version mismatch
      discards only owned payload paths, and malformed/wrong-format metadata
      errors without deleting payloads.
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
      integration, mmap reads, writer batching/locking, GC/repack, Attic
      transport, and harness proof remain open (`C-13`/`R-10`).
- [x] Current parse-artifact bundle payload codec: `ParseArtifactBundle` frames
      the current `resolved.bin`/`ir.bin`/`symbols.bin`/`meta.toml` artifact
      bytes as one versioned little-endian payload, and
      `ParseCacheEntry::read_artifact_bundle` reads complete entries into that
      bundle. This is payload-format substrate only; automatic file-artifact
      materialization, durable index updates, lookup, bundle-to-entry hydration,
      mmap reads, and harness proof remain open (`C-13`).
- [x] Current parse metadata decoder substrate:
      `ParseCacheMeta::from_toml` and `ParseArtifactBundle::decode_meta` parse
      bundled `meta.toml` into typed schema/node/symbol counts plus the
      diagnostic source hint, rejecting malformed TOML, missing fields, wrong
      types, and out-of-range integers. This is metadata validation only;
      artifact semantic validation, keyed hydration enforcement, durable index
      lookup, cache-hit integration, and harness proof remain open (`C-13`).
- [x] Current metadata/count-validated bundle hydration writer:
      `ParseCacheEntry::write_artifact_bundle_validated` uses
      `ParseArtifactBundle::validate_meta` to decode bundled metadata, check
      `schema_version`, decode the bundled symbols/IR artifacts, and cross-check
      `symbol_count`/`node_count` before creating or overwriting entry files,
      then delegates successful writes to the existing metadata-last bundle
      writer. This is metadata and artifact-count validation only; full artifact
      semantic validation beyond existing decoders, keyed hydration enforcement,
      durable index lookup, cache-hit integration, and harness proof remain open
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
      hash and record verification. Automatic durable index lookup/update from
      these raw helpers, node metadata, mmap reads, writer batching, GC/repack,
      Attic transport, and harness proof remain open (`C-13`/`R-14`).
- [x] Current explicit indexed blob IO helpers:
      `PersistCache::append_blob_indexed` appends through the key-routed pack and
      records the returned location in the selected `PersistBlobIndex`, while
      `lookup_blob_location`/`read_blob_indexed` scan the sidecar index and
      read/verify the indexed pack record, returning `None` for misses. This is
      explicit non-transactional sidecar integration only; automatic low-level
      append/read indexing, file-artifact/materialization index updates, node
      metadata linkage, mmap reads, writer batching/locking, GC/repack, Attic
      transport, and harness proof remain open (`C-13`/`R-14`).
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
      cross-run reuse. This is a pure threshold decision only; cost measurement,
      reuse metadata, RAM-tier promotion, packfile writes, persistence
      integration, GC/repack, and AOS tuning remain open (`C-14`).
- [x] Current materialization reuse-counter signal substrate:
      `MaterializationReuse` carries prior-run and current-run demand counters,
      saturates current-run increments, and converts prior-run demand into the
      existing `MaterializationSignals` cross-run reuse bit. This is policy
      vocabulary only; durable counter storage, evaluator demand accounting,
      cost measurement, packfile writes, and AOS tuning remain open (`C-14`).
- [x] Current materialization reuse run-boundary substrate:
      `MaterializationReuse::advance_run` carries current-run demand into
      prior-run history with saturation and clears current-run observations, so
      same-run demand only becomes a cross-run reuse signal for later runs. This
      is policy vocabulary only; durable counter storage, automatic
      process-boundary update, evaluator demand accounting, cost measurement,
      packfile writes, and AOS tuning remain open (`C-14`).
- [x] Current materialization reuse metadata codec:
      `MaterializationReuse::encode_persist_metadata`/`decode_persist_metadata`
      define a stable 16-byte little-endian payload for previous-run and
      current-run demand counters, with short-prefix validation through
      `PersistPackFormatError`. This is codec-only; node metadata index,
      durable counter storage, automatic process-boundary update, evaluator
      demand accounting, cost measurement, and AOS tuning remain open (`C-14`).
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
      behavior, and on `Materialize` append through `append_blob_indexed` so
      successful materialization records a sidecar hash-to-offset entry. This is
      explicit non-transactional indexed materialization only; cost measurement,
      reuse metadata production, evaluator value serialization, automatic raw
      materialization indexing, file-artifact/materialization index updates,
      mmap reads, GC/repack, and AOS tuning remain open (`C-13`/`C-14`).
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
      skip-without-hash/write behavior, and on `Materialize` append the payload
      through `append_blob_indexed` before recording the realpath/content/parse
      mapping through `record_file_artifact`. Successful indexed
      materialization records both the `files/` blob hash-to-offset sidecar
      entry and the file-artifact mapping sidecar entry. This is explicit
      non-transactional indexed materialization only; automatic parse-cache
      integration, parse-entry indexed materialization, durable hit selection,
      mmap reads, GC/repack, and harness proof remain open
      (`C-13`/`C-14`/`R-10`).
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
- [x] Current file/parse threshold signal adapters:
      `PersistCache::materialize_file_artifact_with_signals` and
      `materialize_parse_artifact_entry_with_signals` evaluate caller-supplied
      `MaterializationSignals` before delegating to the existing decision-based
      adapters, preserving skip-without-payload-read/write behavior when the
      threshold fails. Automatic parse-cache integration, durable index updates,
      lookup, source/key equality proof, mmap reads, GC/repack, and harness
      proof remain open (`C-13`/`C-14`).
- [x] Current explicit file-artifact read adapter:
      `PersistCache::read_file_artifact` consumes a typed
      `PersistFileArtifactIndexValue` and reads/verifies the referenced payload
      through the `files/` pack. This is a typed buffered read helper only;
      durable index lookup, parse-artifact payload decoding, mmap reads, cache
      hit integration, GC/repack, and harness proof remain open (`C-13`).
- [x] Current explicit file-artifact bundle hydration adapter:
      `PersistCache::hydrate_file_artifact_bundle` reads a typed `files/`
      artifact value, decodes the `ParseArtifactBundle` payload, validates
      bundled metadata/schema/counts through `ParseArtifactBundle::validate_meta`,
      and writes it into a caller-supplied `ParseCacheEntry` only after
      validation succeeds. This is explicit validated hydration only; durable
      index lookup, automatic cache-hit selection, source/key equality proof,
      mmap reads, full artifact semantic validation beyond existing decoders,
      GC/repack, and harness proof remain open (`C-13`).
- [x] Current keyed file-artifact bundle hydration adapter:
      `PersistCache::hydrate_file_artifact_bundle_for_key` derives the expected
      `PersistFileArtifactKey` from the requested `ParseFileKey`/`ParseCacheKey`,
      rejects mismatches before reading the `files/` pack, and otherwise
      delegates to validated bundle hydration. This is explicit keyed hydration
      only; durable index lookup, automatic cache-hit selection, full artifact
      semantic validation beyond existing decoders, mmap reads, GC/repack, and
      harness proof remain open
      (`C-13`).
- [x] Current indexed file-artifact bundle hydration adapter:
      `PersistCache::hydrate_file_artifact_bundle_from_entry` consumes a
      complete `PersistFileArtifactIndexEntry`, verifies its key against the
      requested `ParseFileKey`/`ParseCacheKey`, and delegates matching entries
      to validated bundle hydration. This is explicit entry-shaped hydration
      only; durable index lookup, automatic cache-hit selection, full artifact
      semantic validation beyond existing decoders, mmap reads, GC/repack, and
      harness proof remain open
      (`C-13`).
- [x] Current `cache/input.rs` impure-input fingerprint substrate: typed
      identities and deterministic durable observation hashes for
      `import`/`readFile`/`readDir`/`readFileType`/`pathExists`/`getEnv`, plus
      an explicit uncacheable `currentTime` marker. This is a fingerprinting
      primitive only; tree-walk builtins, demand-graph leaves,
      allowed-path/IFD/fetch interactions, and edge-exactness harness coverage
      remain open (`R-10`).
- [x] Current tree-walk impure-input observation trace: successful ordinary
      filesystem `import`, `readFile`, `readDir`, `readFileType`,
      `pathExists`, and impure-mode `getEnv` calls append `cache/input.rs`
      fingerprints to `TreeWalk`/`EvalOutcome`; selected `currentTime` appends
      an uncacheable marker. Trace construction failures mark the trace
      incomplete/cache-unusable without changing Nix evaluation semantics. This
      is an evaluator observation surface only; demand-graph leaves,
      dependency wiring, persistence, allowed-path/IFD/fetch interactions, and
      edge-exactness harness coverage remain open (`R-10`).
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
      input leaves to a caller-supplied existing node, so later changed input
      observations dirty that node through ordinary dependency propagation;
      incomplete and uncacheable traces add no leaves or edges. This is
      graph-side edge wiring only; automatic demand/evaluating-node creation,
      cache-key integration for evaluator nodes, automatic edges from
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
      `EvalCacheRuntime::observe_expression_impure_inputs` first
      observe/classify a completed trace, skip expression-node creation for
      incomplete or uncacheable traces, and for complete cacheable traces get
      or insert a caller-supplied expression node before wiring input leaves to
      it. This is
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
- [ ] Full impure-input edges remain: `import`/`readFile`/`readDir`/
      `readFileType`/`pathExists`/`getEnv` keyed as explicit content-hash
      demand-graph inputs; `currentTime` taints dependent memos as uncacheable
      (`R-10`).
- [x] Current precursor: AOS-configured native-cache kill switch. Blank
      `AOS_NIX_CACHE` or `AOS_NIX_CACHE=0` clears
      `NixEvalConfig::native_cache_root`; only a valid absolute root maps to
      `TreeWalkOptions::parse_cache_root = <root>/parse` and
      `TreeWalkOptions::eval_cache_enabled = true`. Native frontend lowering
      and ordinary import parse-cache paths use the durable frontend parse/IR
      artifact cache only when `parse_cache_root` is present, and `NixNative`
      keeps `EvalCacheRuntime` disabled when eval-cache ingestion is disabled.
      This covers only the current parse-cache persistence layer and in-memory
      impure-trace leaf ingestion, not value memoization,
      demand/evaluating-node lifecycle, persistent demand graph/value cache, or
      in-process import result memo ([12](12-incremental-evaluation-cache.md)
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
