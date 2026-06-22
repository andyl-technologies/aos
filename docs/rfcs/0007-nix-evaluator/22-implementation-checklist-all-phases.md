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
  table (P1–P8), the ranked subset (ranks 0–5, now a *build sequence* not a scope
  cut), the risk register, and the Phase-1 checklist;
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
  ranked subset is retained below only as a *build sequence*. The research-grade
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
- **A phase does not begin until its true predecessor's exit criterion holds**
  (the gate dependencies in [17](17-roadmap-and-risks.md) §3) — but under the
  budget mandate the workstreams otherwise run in **parallel**, not strictly
  serial. **P1.5 is no longer a kill gate.** Under the unlimited-budget mandate
  it is **baseline characterization**: we still measure where eval time goes, but
  a finding that eval is a minor fraction of build time does **not** stop the
  project — the goal is the fastest evaluator regardless
  ([17](17-roadmap-and-risks.md) §0; recast in the P1.5 section below).

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
| **P1b** | Re-layer the monolith into `ratchet` engine + Nix dialect (S-22); open effect lattice (S-23); behaviorally inert, harness byte-green | (no new rollout gate; parity held) | ☐ |
| **P1.5** | **Baseline characterization** (measure-first, *not* a kill gate): record where eval time goes; P2–P8 are built regardless | — (informs ordering/parallelism; does **not** decide whether P2–P8 happen) | ☐ |
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
- [ ] Compatibility hardening still open: `nix-compat` pin/adapter,
      type-enforced three-hash split, interned COW string-context
      representation, full transitive `.drv`/drv-path/output-path parity, and
      RFC-0005 deriving-path/CA graph gates.
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
- [ ] Full acceptance gate still open: byte-identical `.drv` output from
      `NixNative` vs pinned C++ `nix-instantiate` over the full AOS closure,
      committed full-closure wall-clock + `NIX_SHOW_STATS` baseline, rnix parser
      differential oracle unless superseded by a later RFC/doc decision,
      automatic fuzz-corpus population, full parity-fuzzer budget/quiescence, and
      full conformance diff-green.

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

- [ ] **Crate split with `ratchet` naming.** Break the `aos-nix` monolith into
      `ratchet-core` (Core IR, from `compile/ir.rs` + `compile/scope.rs`),
      `ratchet-oracle` (from `eval/`), `ratchet-value`
      (from `value.rs`/`list.rs`/`attrs.rs`/`heap/`), `ratchet-dialect` (new), and
      the Nix band (`aos-nix` umbrella, `aos-nix-syntax` from `syntax/`,
      `aos-nix-dialect` new, `aos-nix-compat` from the store glue,
      `aos-nix-harness`). Reserve but do not create `ratchet-gc` (P3),
      `ratchet-cache` (P2), `ratchet-jit` (P6), `ratchet-parallel` (P3.5).
- [ ] **Core/dialect IR split.** Generic `IrKind` stays in `ratchet-core`; move
      `DerivationStrict` and `WithVar` behind the dialect escape hatch, reusing the
      existing `PrimOp(symbol, args)` indirection; the resolver's "unresolved
      name" path becomes a dialect hook (Nix emits `WithVar`; other dialects
      error).
- [ ] **`EffectClass` → open trait (`S-23`).** Replace the closed
      `enum EffectClass { Pure, Effectful }` with a `ratchet-core` trait
      (`is_speculable` + `effect_key`); the Nix dialect supplies the members
      (`import`/IFD/`readFile`/`derivationStrict`); delete the hardcoded
      `effect_for(DerivationStrict) => Effectful`.
- [ ] **String-context extraction.** `ratchet-value` keeps the generic tagged
      value + hash-consing; the context bitset + union-on-concat semantics move to
      `aos-nix-dialect`, with the engine's cons-key hashing taking a
      dialect-supplied discriminator so identical-bytes / different-context strings
      still do not collapse.
- [ ] **`ratchet-dialect` trait definition.** The registration-time interface
      (extra ops, effect members, primop table, rewrite rules, lowering hooks);
      monomorphized, never `dyn` on the force path.
- [ ] **Habit guard (carries through the rest of P1).** No new Nix-specific
      `IrKind` variants — every new builtin routes through `PrimOp`; keep
      string-context confined to the dialect.

**Conformance (hold parity).** The refactor is behaviorally inert; the
[20](20-nix-language-conformance.md)/[21](21-builtins-conformance.md) surface is
untouched and stays byte-green.

**Decisions closed/measured.**

- [ ] Closes: `S-22` (Core + dialect / `ratchet` topology, Nix-only delivery),
      `S-23` (open, dialect-supplied effect lattice).

**EXIT CRITERIA (falsifiable).** The `.drv`-diff harness is byte-green on the
**same fixtures as before the split** (behaviorally inert); the crate boundaries
match [28](28-generalization-and-language-dialects.md) §3 /
[27](27-engineering-standards.md) §1.1; complete before Phase 2 begins.

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

- [ ] A documented **characterization** from the P1 baseline (`nix-instantiate`
      wall-clock + `NIX_SHOW_STATS` vs build/I/O time): the eval-time breakdown,
      the hottest constructs, and the cold/warm split
      ([01](01-motivation-and-goals.md) §5.1–5.2).
- [ ] The breakdown is used to **prioritize and parallelize** the workstreams
      (which of cache / heap / analyses / shapes / JIT / AOT to staff first), not
      to gate whether they happen. Even if eval is a small fraction, the cheap P1
      artifacts (oracle + harness) also keep validating `NixCli` itself
      ([17](17-roadmap-and-risks.md) R6).

**Conformance.** No new surface; parity from P1 holds.

**Decisions closed/measured.**

- [ ] Measures `M-1` opening data (how much does the cache plausibly buy?),
      `M-3` (cold vs warm fraction, first read).
- [ ] Resolves `Q-B`; informs `Q-A`/`Q-C` and the staffing order of P2–P8.

**EXIT CRITERIA (falsifiable).** A written eval-time **characterization** exists,
grounded in P1 numbers, breaking down where time is spent and feeding the
workstream ordering. No exit of this phase can cancel the project — under the
budget mandate the optimization stack is committed regardless of the breakdown.

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

- [ ] `cache/dcg.rs` — the demand-driven incremental computation graph (Salsa /
      Adapton / *Build Systems à la Carte* model): nodes, demand edges,
      change-propagation, early cutoff ([12](12-incremental-evaluation-cache.md) §1).
- [ ] `cache/key.rs` — the cache key combiner: an **ordered, length-prefixed**
      free-variable combiner hashed once, **never bare XOR** (`C-1`).
- [ ] `cache/cutoff.rs` — early-cutoff: stop propagation when a recomputed
      value-hash equals its prior value-hash.
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
- [ ] `cache/persist.rs` — versioned on-disk `nodes/values/files` schema with a
      schema-version field and discard-on-mismatch (`R-14`); transport stays
      **beside** `NixEval`, on the Attic content-addressed path (`C-3`).
- [ ] Impure-input edges: `readFile`/`readDir`/`getEnv` keyed as explicit
      content-hash inputs; `currentTime` not cached (`R-10`).
- [x] Current precursor: AOS-configured parse-cache kill switch. Blank
      `AOS_NIX_CACHE` or `AOS_NIX_CACHE=0` clears
      `NixEvalConfig::native_cache_root`; only a valid absolute root maps to
      `TreeWalkOptions::parse_cache_root = <root>/parse`; native frontend
      lowering and ordinary import parse-cache paths use the durable frontend
      parse/IR artifact cache only when `parse_cache_root` is present. This
      covers only the current parse-cache persistence layer, not the future
      demand-graph/value memoization cache or in-process import result memo
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
