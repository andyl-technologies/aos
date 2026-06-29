# RFC-0007 - Roadmap and risks

This document is the delivery plan and the risk ledger for aos-nix. Every other
document in the set argues for a *technique*; this one fixes the *order* in
which those techniques are built and names the things that can go wrong. It is
deliberately the most conservative document in the RFC, because the ambition
described elsewhere — a tiered Cranelift JIT, a precise generational collector,
whole-program strictness analysis, a cross-machine incremental cache — is
research-grade in aggregate, and the single most effective defense against
research-grade scope is a ranked build sequence where each step is
independently shippable and independently valuable.

Read this after the [motivation and goals](01-motivation-and-goals.md) (which
establishes the measure-first discipline and the success criteria the roadmap is
built to satisfy), the [architecture overview](03-architecture-overview.md) (whose §6
previews the ranked build sequence this document expands), and the
[AOS integration](14-integration-with-aos.md) doc (whose phased flip — Off,
Shadow, On-for-`eval_expr`, On-for-`instantiate` — is the rollout half of this
roadmap). The [incremental cache](12-incremental-evaluation-cache.md) and
[differential testing](15-differential-testing-and-benchmarking.md) docs own the
two pieces of phase 1 that the whole plan pivots on: the early-cutoff cache and
the `.drv`-diff harness.

Per RFC discipline this document makes no status claim. It describes the
intended order of construction and the risks attending it; the maturity header
lives only in the set's `README.md`.

---

## 0. Budget and scope mandate (unlimited budget)

This is an **unlimited-budget, non-time-bounded** implementation whose goal is
the **absolute fastest and most efficient** Nix evaluator achievable — not a
pragmatic, schedule-bounded fix for AOS build time. That mandate changes what
the rest of this document means, and it is important to separate *what relaxes*
from *what does not*.

**What the budget mandate relaxes — the economic gates:**

- **The full technique stack is committed.** There is no "90% subset" scope cut.
  The research-grade (`R-*`) tail in the [decision register](19-decision-register.md)
  — concurrent moving GC, full effect-based region inference, an **LLVM AOT
  tier-3** for peak throughput beyond the Cranelift JIT, and the rest — is **in
  scope**, not deferred.
- **The ranked subset (§2) is a *build sequence*, not a scope boundary.** Its
  order is dictated by dependency, correctness, and risk; with unlimited people
  the independent workstreams proceed in parallel.
- **`P1.5` is no longer a kill/re-scope gate** (§3). It becomes *baseline
  characterization*: we still measure where eval time goes, but a finding that
  eval is a small fraction of build time does not stop the project — the goal is
  the fastest evaluator regardless.
- **"Measure-first" is reinterpreted, not discarded.** It changes from "build
  only if proven worth it" to **"build the competing variants, measure, keep the
  winner."** The `M-*` register items (NaN-box vs. tagged value, fiber I/O
  turn-on, inlining thresholds, fusion aggressiveness) become *build-and-select*
  decisions: we implement the alternatives and let the benchmark choose — and we
  **never ship a regression**.

**What the budget mandate does *not* relax — the correctness gates (absolute):**

- The differential `.drv`-diff harness (byte parity) gates every feature, always.
- The `loom`/Miri memory-ordering audit (no data races) gates the parallel tier.
- The conformance suite ([20](20-nix-language-conformance.md)/[21](21-builtins-conformance.md))
  gates language/builtins parity.
- **Oracle-first, atomic-thunks-from-day-1, parity-before-trust** stay — these
  are *correctness sequencing*, not economics, and no amount of budget waives
  them.

The implementation is tracked feature-by-feature: each topic doc carries its own
`## Implementation checklist`, and the master roll-up is
[the all-phases checklist](22-implementation-checklist-all-phases.md).

---

## 1. The two invariants that fix the build order

The roadmap is not free to schedule work however it likes. Two invariants,
established upstream and restated here because they *determine* phase 1,
constrain the entire plan:

1. **Measure before you optimize.** The
   [measure-first characterization](01-motivation-and-goals.md) requires a
   baseline before optimization work is ordered: measure *evaluation* separately
   from building and I/O, then use the counter breakdown to decide which
   workstreams get staff first. Under the budget mandate in §0, the measurement
   no longer cancels the later phases; producing it is still a deliverable, and
   it cannot be produced without a working evaluator to measure and a
   `nix-instantiate` baseline to measure against.

2. **Prove parity before you trust speed.** The
   [acceptance gate](03-architecture-overview.md) §5 makes the differential
   `.drv`-diff harness the binary criterion for correctness (C1 in
   [01](01-motivation-and-goals.md) §6). A faster-but-divergent evaluator is
   worthless here, because a single divergent store path triggers a from-source
   toolchain rebuild ([11](11-derivation-and-store-compatibility.md)). Parity
   must be *demonstrated*, on the AOS constructs that matter, before any
   speculation-bearing tier exists to muddy the attribution of a divergence.

Both invariants point at the same conclusion, and it is the load-bearing
scheduling decision of the whole project:

> **Phase 1 is fixed: parser + scope resolution + tree-walk interpreter (the
> correctness oracle) + the differential `.drv`-diff harness, built FIRST,
> before a single line of Cranelift.** That phase simultaneously (a) yields the
> baseline eval-time number the measure-first characterization demands, and (b) proves
> byte-identical `.drv` parity is achievable on AOS's hand-rolled
> `mkDerivation`, `ccWrapper`, and `evalModules` constructs — the constructs
> that actually appear in the AOS package set — *before* we invest in making
> evaluation fast.

The tree-walk oracle is the cheapest possible faithful Nix implementation
([03](03-architecture-overview.md) §4.1): no codegen, no speculation, nothing to
get subtly wrong. It is the thing we can write quickly, validate exhaustively
under `miri` ([14](14-integration-with-aos.md) §9), and trust by construction.
It is also slow — and that is fine, because phase 1's job is not speed. Its job
is to answer two empirical questions that the rest of the roadmap is
contingent on:

- *Where does eval actually cost us?* If the measure-first data says eval is a
  minor fraction of long first builds, that changes priority and validation
  targets rather than cancelling the roadmap. The oracle plus the harness is the
  instrument that settles this for each workload class.
- *Is byte-identical parity achievable on AOS at all?* If the oracle cannot be
  made to match `nix-instantiate` on the AOS closure even with unlimited time,
  no amount of JIT engineering rescues the project. Phase 1 de-risks the
  existential question first.

This is why the oracle is not "phase 0 throwaway." It is the permanent
correctness reference the JIT tiers are forever validated against
([03](03-architecture-overview.md) §4.1,
[14](14-integration-with-aos.md) §9.2), and it is the `miri`/sanitizer host that
keeps the safe tree to analyze ([14](14-integration-with-aos.md) §9.3). It is
built first because everything downstream depends on it, not despite that.

---

## 2. The ranked build sequence

The architecture overview ([03](03-architecture-overview.md) §6) introduces the
*ranked build sequence*: the order in which the technique stack is delivered so the
biggest real-world wins land first and each rank is independently valuable even
if later ranks slip. This section is the authoritative expansion. The ordering
encodes a thesis — **the systemic win (not evaluating at all) dwarfs the
constant-factor wins (evaluating faster)** — so the incremental cache leads,
even though it is "less interesting" than a JIT, and Cranelift comes late, after
the foundation it optimizes is proven and well-understood.

The ranks, in build order:

### Rank 0 — Foundation: parser, scope resolution, tree-walk oracle, harness

The fixed phase 1 of §1. Recursive-descent parser into a compact arena AST
([04](04-frontend-parser-and-ir.md)); scope resolution to static slot indices
(de Bruijn-style); the tier-0 tree-walking interpreter
([03](03-architecture-overview.md) §4.1); and the differential `.drv`-diff
harness ([15](15-differential-testing-and-benchmarking.md)) wired through the
`NixEval` trait ([14](14-integration-with-aos.md) §3) so the oracle and
`NixCli` are diffed automatically. The `nix-compat` crate
([11](11-derivation-and-store-compatibility.md)) provides ATerm serialization,
SHA-256 store-path computation, and the `.drv` writer, so rank 0 is an
*orchestration* of a faithful store backend, not a from-scratch ATerm writer.

**Output of rank 0:** the baseline eval-time number, a parity proof on AOS
constructs, and a green-or-not-green harness signal. Everything after this is
gated on that signal.

### Rank 1 — Incremental early-cutoff cache + hash-consing

The largest expected real-world win, and the first optimization built, because
it is *largely independent of interpreter speed* — it sits above the evaluator
as a memoization and change-propagation layer and pays off even on the rank-0
tree-walk oracle ([12](12-incremental-evaluation-cache.md) §1). It models
evaluation as a demand-driven incremental computation graph (Salsa, Adapton,
*Build Systems à la Carte*), memoizes thunk and `derivationStrict` results keyed
on `H(expr ⊕ env)`, and applies **early cutoff**: when a recomputed value-hash
equals its prior value-hash, propagation stops. Hash-consing/maximal sharing
([05](05-value-representation.md)) is its enabling substrate — it turns
value-hashing from a tree-walk into a field load, which is what makes the
environment-hashing in the cache key cheap ([12](12-incremental-evaluation-cache.md) §3.2).

This rank may, on its own, solve the AOS build-time problem
([01](01-motivation-and-goals.md) §7, [12](12-incremental-evaluation-cache.md)
§1), making everything below it a measured-but-deferred follow-up. That is the
single most important uncertainty in the roadmap (§5, Q-A), and it is why this
rank leads: if it clears the goal, we learn that before building a JIT.

### Rank 2 — Bump-arena one-shot heap + precise generational GC

Replaces what is C++ Nix's dominant runtime cost: the Boehm conservative
collector ([06](06-memory-management-and-gc.md)). For the one-shot CLI case (the
dominant AOS workload), a **bump-pointer arena that never frees** and is dropped
wholesale at process exit — the fastest possible allocator for a batch job. For
the long-lived daemon case, a **precise generational copying collector** with a
cache-resident nursery, precise rather than conservative so Boehm-style false
retention is eliminated. All allocation routes through runtime symbols
(`aos_alloc_*`) so the GC strategy swaps without touching the (eventual)
JIT-emitted code ([03](03-architecture-overview.md) §4.5). This rank attacks the
cost of the work the cache cannot avoid and *also helps the tree-walk oracle*,
so it pays off before any JIT exists.

### Rank 3 — Strictness + escape analysis

Whole-program GHC-style analyses ([07](07-laziness-and-whole-program-analyses.md))
that *delete allocation rather than speed it up*: **strictness/demand analysis**
with the worker-wrapper transform compiles always-forced bindings eagerly with
zero thunk allocation; **cardinality analysis** sheds blackhole/update machinery
from single-entry thunks and eliminates dead bindings; **escape analysis +
scalar replacement** keeps short-lived non-escaping attrsets and thunks off the
heap. Crucially, these analyses *annotate the IR* and help even the tree-walk
oracle (fewer thunks to allocate and force), so — like ranks 1 and 2 — rank 3
delivers value before a JIT exists. Nix's purity makes these analyses far more
effective than they are on Java or JavaScript
([03](03-architecture-overview.md) §1.1).

### Rank 4 — Hidden classes + PIC, then Cranelift tiering + deopt

Only here, with the foundation, cache, heap, and analyses proven, do we build
the speculative machinery. First **hidden classes (shapes) + polymorphic inline
caches** ([09](09-attribute-sets-hidden-classes-and-inline-caches.md)) so
attrset access becomes a shape-check plus a constant-offset load — attrsets being
the hottest data structure in any nixpkgs-scale eval. Then the **Cranelift
tiers** ([08](08-execution-tiers-and-cranelift.md)): a tier-1 baseline JIT for
hot thunks, a tier-2 optimized tier with speculation, **deoptimization**
(uncommon traps), and on-stack replacement. Cranelift, not LLVM or WASM
([01](01-motivation-and-goals.md) §4, [08](08-execution-tiers-and-cranelift.md));
the tier-0 oracle remains the deopt target and the correctness backstop. This
rank is a constant-factor optimization on the *residue* the cache cannot elide —
which is why it comes after the cache, not before.

### Rank 5 — Advanced stack, build-and-select

Everything whose payoff is uncertain enough that it ships behind a measured
policy: **pointer tagging** for WHNF-test fast paths
([05](05-value-representation.md)), **NaN-boxing** as a comparator to the tagged
baseline ([01](01-motivation-and-goals.md) §7,
[05](05-value-representation.md)), **full-laziness / let-floating**
([07](07-laziness-and-whole-program-analyses.md)), **region inference**, and
**concurrent/moving GC** for daemon mode (ZGC/Shenandoah-style colored pointers
+ load barriers — [06](06-memory-management-and-gc.md)). Under the budget
mandate these variants are in scope: build the competing implementations,
measure them against AOS traces, and keep the winner or best policy (C6 in
[01](01-motivation-and-goals.md) §6).

> **Promoted out of rank 5 (decision C-11/C-12).** **Content-addressed
> derivations** and **parallel thunk-graph evaluation** are no longer deferred
> follow-ups — they are first-class. CA is built into the Phase-1 compatibility
> core (it is on AOS's critical path via RFC-0005); parallel thunk-graph evaluation
> (lock-free CAS thunks + work-stealing forcing, [13](13-parallel-evaluation.md))
> is its own early phase (P3.5 below). Two guardrails make "right away" safe
> rather than reckless: the **sequential** tree-walk oracle remains the
> correctness ground truth that the parallel tier is diffed against, and the
> parallel tier ships only after a `loom`/Miri memory-ordering audit (R-4,
> now a committed gate). Note that *concurrent moving GC* stays in rank 5 — it is
> a distinct problem from parallel forcing, and one-shot mode sidesteps it with
> per-worker bump nurseries + never-free.

### The ranked build sequence, summarized

```text
  RANK  DELIVERABLE                                   PROBLEM    INDEPENDENT VALUE
  ────  ──────────────────────────────────────────   ───────    ─────────────────────────
   0    parser + scope + tree-walk oracle + harness   founda-    baseline eval # + parity
                                                      tion       proof + go/no-go signal
   1    incremental early-cutoff cache + hash-cons     P0        may solve build-time ALONE;
                                                                 helps the oracle directly
   2    bump-arena heap + precise generational GC      P3        kills the Boehm tax;
                                                                 helps the oracle directly
   3    strictness + escape analysis                   P1        deletes allocations;
                                                                 helps the oracle directly
   4    hidden classes + PIC, then Cranelift tiering   P2, P4    constant-factor on the
        + deopt                                                  residue the cache can't elide
  3.5   parallel thunk-graph evaluation (CAS thunks    ‖         first-class (C-12); uses all
        + work-stealing forcing)                                 cores; oracle stays ground truth
   5    pointer tagging, NaN-box, full-laziness,       P1/P3/P4  advanced stack; build
        region inference, concurrent moving GC         + ‖       variants and keep winner
```
```text
  NOTE  content-addressed derivations (C-11) are built into P1's compat core,
        not a later phase — AOS's store model is content-addressed (RFC-0005).
```

The shape of the table is the argument: ranks 1–3 each carry independent value
*and* help the tree-walk oracle, so they are de-risked optimizations that pay off
before the first Cranelift instruction. Rank 4 (the JIT) is deferred precisely
because by then we are optimizing a well-understood residue against a stable
oracle, not chasing a moving target. Rank 5 is the explicitly-uncertain advanced
tail: build the variants, measure them, and keep the winning policy.

---

## 3. The phase table

The ranks above describe *what* is built in *what order*. The phases below add
*scope*, *exit criteria*, and *rough effort* — the operational schedule. Effort
is given in coarse t-shirt sizes (S/M/L/XL) rather than calendar time, because
the calendar depends on staffing and on how much of rank 1 alone clears the
goal. Each phase's exit criterion is a *falsifiable* condition; a phase is not
"done" until its exit criterion is observably met, and later phases must not
begin until their predecessors' exits hold (the gate dependencies are explicit
in the last column).

| Phase | Scope (rank) | Exit criterion (falsifiable) | Effort | Gated on |
|-------|--------------|------------------------------|--------|----------|
| **P1** | Frontend + tree-walk oracle + `.drv` harness (rank 0); compat core covers **both IA and CA derivations** (C-11); thunk state machine **atomic from day 1** to admit parallelism later (C-12) | Harness runs the *full* AOS closure under the oracle vs `NixCli`; baseline eval-time and `NIX_SHOW_STATS` numbers recorded; parity demonstrated on `mkDerivation`/`ccWrapper`/`evalModules` constructs **and on CA-derivation fixtures + the RFC-0005 graph** (zero divergence on the tested subset). | **L** | — |
| **P1b** | Re-layer the P1 monolith into the `ratchet` engine + Nix dialect (Core/dialect IR split, open effect lattice, crate split) — behaviorally inert. See [28](28-generalization-and-language-dialects.md) §10. | Differential `.drv` harness byte-green on the same fixtures as before the split; crate boundaries match [27](27-engineering-standards.md) §1.1 / [28](28-generalization-and-language-dialects.md) §3. | **M** | P1 skeleton byte-green |
| **P1.5** | Baseline characterization | Documented characterization, from P1 data, of where eval time goes: eval vs build/I/O, hottest counters, and cold vs warm. The result orders and parallelizes P2-P8; it does **not** cancel later phases under the budget mandate (§0). | **S** | P1 baseline artifact |
| **P2** | Incremental cache + hash-consing (rank 1) | A semantically-irrelevant edit (comment/whitespace/leaf-package) recomputes a *bounded, small* fraction of the closure and emits unchanged `.drv` downstream (C4 in [01](01-motivation-and-goals.md) §6); `AOS_NIX_CACHE=0` and cached runs agree byte-for-byte on the harness. | **L** | P1.5 |
| **P3** | Bump-arena + precise generational GC (rank 2) | One-shot CLI eval allocates through `aos_alloc_*`, frees nothing, drops at exit; measured allocation/GC time on the oracle is materially below the Boehm baseline from P1; precise GC passes `miri`/ASan on the safe tree. | **M** | P2 |
| **P3.5** | Parallel thunk-graph evaluation (rank 3.5, C-12): L1 work-stealing pool + L2 lock-free CAS thunk forcing ([13](13-parallel-evaluation.md)) | The parallel evaluator is differentially identical to the **sequential** oracle across the full closure (output determinism under nondeterministic scheduling); the `loom`/Miri memory-ordering audit (R-4) is green; measured multi-core speedup over the serial baseline on the AOS closure. **No data races, ever.** | **L** | P3 |
| **P4** | Strictness + escape analysis (rank 3) | Annotated IR compiles provably-strict bindings eagerly (measured drop in thunk-allocation count vs P1 `NIX_SHOW_STATS`); harness stays byte-green; analysis is sound (no eager forcing of a binding the oracle leaves unforced); single-entry-thunk downgrade restricted to frame-local thunks (C-8), keeping it sound under P3.5 parallelism. | **M** | P3 |
| **P5** | Hidden classes + PIC (rank 4a) | `select` sites resolve via shape-check + constant-offset load with a polymorphic inline cache; attr iteration order remains byte-identical to C++ Nix (the ordering invariant of [09](09-attribute-sets-hidden-classes-and-inline-caches.md)); harness byte-green. | **M** | P4 |
| **P6** | Cranelift baseline JIT (rank 4b, tier 1) | Hot thunks compile per-expression once via Cranelift; tier-1 output is differentially identical to the tier-0 oracle across the closure; warmup cost measured against one-shot CLI workload. | **L** | P5 |
| **P7** | Cranelift optimized + deopt + OSR (rank 4c, tier 2) | Speculation guarded by uncommon traps; every deopt path lands in semantics identical to the oracle (no observable `.drv` difference, ever); OSR enters hot loops mid-execution; harness byte-green under all tiers. | **XL** | P6 |
| **P8** | Advanced stack (rank 5): pointer tagging, full-laziness, concurrent *moving* GC, and full effect-based region inference | Each advanced variant lands behind the same byte-parity and benchmark evidence discipline (C6); under the budget mandate the variants are built and benchmarked, then the winner or best policy is selected. (Parallel *forcing* is no longer here — it is P3.5; only the concurrent *moving collector* remains in this tail.) | **XL** | P7 |

A few properties of the table are deliberate and worth stating:

- **P1b overlaps P1's tail and precedes P2.** The re-layering into the `ratchet`
  engine + the Nix dialect ([28](28-generalization-and-language-dialects.md) §10)
  is behaviorally inert — it changes no `.drv` output and the harness stays
  byte-green — so it does not block P1 feature work; it *enters* once the parser →
  Core IR → oracle skeleton compiles and the first fixtures are byte-green and
  runs alongside the remainder of P1 and the P1.5 characterization. It **must
  complete before P2**, because P2 builds `ratchet-cache` and the open effect
  lattice (`S-23`), which should be born in the new Core/dialect model rather than
  retrofitted onto the monolith.
- **P1.5 is a real measurement checkpoint, not a formality.** It sits
  immediately after the first phase so the workload profile is known before the
  expensive phases are staffed. Under the budget mandate (§0), its exit cannot
  cancel the project; it orders and parallelizes the committed optimization
  stack. The measure-first discipline ([01](01-motivation-and-goals.md) §5) is
  encoded here.
- **The rollout phases (Off → Shadow → On) run in parallel with P2–P8, not
  after them.** The phased flip from [14](14-integration-with-aos.md) §7.1 —
  Phase A (default Off, harness in CI), Phase B (Shadow mode), Phase C (On for
  `eval_expr`), Phase D (On for `instantiate`), Phase E (verify-sampling
  reduced) — is the *trust* schedule layered over the *capability* schedule
  here. Shadow mode (Phase B) can begin as soon as P1's oracle is byte-green on
  enough of the closure to be worth diffing against real CI traffic; it does not
  wait for the JIT. The two schedules are orthogonal: P-phases add *speed*, the
  integration phases add *trust*, and `AOS_NIX_NATIVE` stays default-Off across
  both until C1 is green on the full closure.
- **Effort is back-loaded into the JIT (P6–P8).** This is intentional and
  matches the ranking: the cheap, high-value, low-risk work (the cache, the
  arena, the analyses) front-loads measurable wins, and the expensive,
  speculative, `unsafe`-heavy work is deferred until the cheaper work has either
  cleared the goal or precisely characterized the residue that the JIT must
  attack.

---

## 4. Risk register

The risks below are the ones that can sink the project or silently corrupt its
output. Each is rated for **impact** (how bad if it happens) and **likelihood**
(how probable), and paired with the **mitigation** already designed into the
architecture. The register is ordered by the product of the two — the long tail
of `.drv` divergence is first because it is both high-impact and high-likelihood
and is named the dominant risk throughout the set
([01](01-motivation-and-goals.md) §7, [03](03-architecture-overview.md) §7,
[14](14-integration-with-aos.md) §7.2).

| # | Risk | Impact | Likelihood | Mitigation |
|---|------|--------|------------|------------|
| **R1** | **Long tail of `.drv` divergence.** Parity (C1) is binary, but reaching it surfaces a long tail of subtle quirks — float formatting, error-as-value edge cases, `__structuredAttrs`, string-context propagation corners, attr-ordering edge cases — that pass the harness on tested packages but diverge on a rarely-evaluated one and silently force a toolchain rebuild. | **Catastrophic** (from-source rebuild of the GCC ladder / Rust / Java chains) | **High** | **Never default-on until the harness is byte-green on the *full* closure** ([14](14-integration-with-aos.md) §7). Defense-in-depth: default `Off`; `Shadow` mode diffs every real CI eval; `AOS_NIX_NATIVE_VERIFY` sampling as a residual canary even after default-on; **`NixCli` permanent fallback** flippable by one env var. The tree-walk oracle localizes each divergence as *semantics* vs *codegen* before it can reach the store. |
| **R2** | **JIT debuggability.** Speculative, deoptimizing, on-stack-replaced Cranelift code is hard to step through; a divergence introduced in tier 1/2 is hard to attribute and bisect. | **High** (slows the long-tail fix in R1) | **Medium** | The **tier-0 tree-walk oracle is the tie-breaker by construction** ([03](03-architecture-overview.md) §4.1): the harness runs against the oracle *first* to localize whether a divergence is a semantics bug (oracle wrong) or a codegen bug (JIT-only). Every deopt path must land in semantics identical to the oracle ([03](03-architecture-overview.md) §5.3), so the slow path is always a correct continuation of the fast path. The oracle is the trivially-traceable reference the JIT is diffed against. |
| **R3** | **Large `unsafe` surface.** NaN-boxing/tagged values, JIT fn-ptr calls, and the raw-heap/GC are irreducibly `unsafe` ([14](14-integration-with-aos.md) §9) — memory-safety or UB bugs there could corrupt a value and, downstream, a `.drv`, violating AOS's "avoid `unsafe` at all costs" rule. | **High** (UB → wrong output or crash) | **Medium** | **Fence the `unsafe` into a small, audited core.** The oracle/frontend/`nix-compat`-glue/harness are `#![forbid(unsafe_code)]` and kept `miri`/sanitizer-clean; the unsafe modules use `#![deny(unsafe_op_in_unsafe_fn)]` with a `// SAFETY:` comment per block, two-maintainer review, ASan/UBSan CI, and `cargo fuzz` on value-decode/GC/ATerm ([14](14-integration-with-aos.md) §9.3). The safe oracle gives `miri` a complete program to analyze; the `unsafe` tiers are differential-tested against it and are never the *final* arbiter of a store path. |
| **R4** | **Research-grade scope.** The full SOTA design (tiered JIT + precise/concurrent GC + whole-program analyses + cross-machine cache) is unbounded; attempting it all at once risks never shipping anything. | **High** (project stalls, delivers nothing) | **Medium-High** | **The ranked build sequence (§2), correctness gates (§3), and P1.5 characterization.** Each rank is independently shippable behind `AOS_NIX_NATIVE` and individually valuable; ranks 1–3 pay off *on the oracle* before any JIT exists; the P1.5 data orders the work rather than cancelling it. Non-goals ([01](01-motivation-and-goals.md) §4) bound the language/primop surface to what AOS exercises. |
| **R5** | **`nix-compat` / Snix API instability.** `NixNative` depends on Snix's `nix-compat` crate (pinned git rev) for ATerm/store-path/NAR formats on the parity-critical path; its API is explicitly pre-1.0 and has already moved (Tvix → Snix rename, March 2025; Derivation/ATerm sliced out and reparsed). | **Medium** (maintenance churn on the critical path; *not* a correctness risk — output is still diffed) | **High** | **Pin a specific git rev**, carry local patches, and **expect to contribute fixes upstream** ([14](14-integration-with-aos.md) §13). A breaking change is a *maintenance* cost, not a correctness one: any regression it introduces is caught by the differential gate before it can reach the store. The leverage of reusing a faithful, battle-tested store backend outweighs the churn. |
| **R6** | **Measure-first shows eval is workload-dependent.** P1 data can show eval is a minor fraction of long first builds while still dominating no-op, already-built, or repeated eval workloads. | **Medium** (wrong workstream priority) | **Low-Medium** | **P1.5 is the explicit characterization point** ([01](01-motivation-and-goals.md) §5.2). Under the budget mandate it does not kill/re-scope the project; it prevents a false global claim and feeds the P2-P8 staffing order. The oracle + harness remain independently useful artifacts and continue validating `NixCli` itself. |
| **R7** | **Incremental cache under-tracks a dependency.** An implementation bug that fails to reify a read as a graph edge (e.g. an `import`/`readFile` not hashed as an input) lets a stale value survive a change it should have invalidated. | **High** (stale `.drv` → wrong build) | **Medium** | The **leak invariant** ([12](12-incremental-evaluation-cache.md) §5.2) keeps internal hashes out of Nix-observed hashes; the **differential harness** catches any mis-cached value that altered a `.drv`; **`AOS_NIX_CACHE=0`** gives a minimal reproducer when cached and uncached runs disagree; **periodic cold re-validation** in CI catches latent under-tracking ([12](12-incremental-evaluation-cache.md) §8.3); and the **permanent `NixCli` fallback** is the ultimate reference. A cache miss only ever costs a recompute, never a wrong answer. |
| **R8** | **One-shot CLI is the worst case for a JIT.** The dominant AOS workload is one-shot `aos build`, which gives the JIT no time to amortize warmup; tier 1/2 may never pay for themselves in CLI mode. | **Medium** (wasted JIT effort in the dominant mode) | **Medium** | The win in CLI mode is expected to come from **P0 (cache) + P3 (arena) + tier-0 improvements**, with the JIT reserved for daemon mode ([03](03-architecture-overview.md) §7 Q1). **Copy-and-patch** ([01](01-motivation-and-goals.md) §4, [08](08-execution-tiers-and-cranelift.md)) is the ultra-low-warmup hedge to measure if Cranelift's baseline warmup proves too high. Crucially, the JIT (rank 4) is deferred *behind* the cache and arena precisely so this risk is characterized before it is incurred. |
| **R9** | **Concurrent/moving GC × thunk mutation.** The interaction of a concurrent moving collector with the monotonic thunk-update protocol and JIT-emitted read/write barriers is the deepest unsolved coupling in the design ([03](03-architecture-overview.md) §7 Q3). | **High** (subtle GC/JIT bugs) | **Low** (daemon-only) | **Daemon-mode only**; the dominant one-shot CLI mode sidesteps it entirely via the **never-free bump arena** ([06](06-memory-management-and-gc.md)). It is explicitly **rank 5** advanced-stack work, not on the one-shot critical path, and the `aos_alloc_*` runtime-symbol discipline ([03](03-architecture-overview.md) §4.5) localizes the coupling to the allocator implementation rather than spreading it through JIT-emitted code. |
| **R10** | **Cache overhead can exceed its savings on a slow interpreter (interpreter speed is a prerequisite of the cache, not an independent axis).** Rank 1 (§2) is justified on the premise that the early-cutoff cache is "largely independent of interpreter speed" and "pays off even on the rank-0 tree-walk oracle." Early P2 measurement (2026-06-28, HEAD `d8c988cb`, oracle nix-2.28.6, via `aos nix-diff` on `pkgs.zlib`) contradicts both: enabling the cache *raised* cold eval from **6.5 s** (`AOS_NIX_CACHE=0`) to **11.8 s**, and successive warm runs degraded **monotonically** — 45.7 → 52.7 → 65.9 → 78.6 s — at stable on-disk size, i.e. the persistent force-cache replay/validation grows per run rather than amortizing. The tree-walk itself is ~**100×** slower than C++ Nix (0.068 s eval), so the cache's hashing/replay cost dominates instead of being hidden; and its cheap-hashing premise rests on hash-consing + a compact value representation (the Rank 1 substrate / Rank 5 pointer-tagging) that are not yet built. | **Medium** (mis-ordered workstream — the *lead* optimization is currently net-negative; **not** a correctness risk: `AOS_NIX_CACHE=0` is faster and the differential gate still guards every `.drv`) | **High** (observed) | **Treat interpreter speed as a prerequisite of the cache.** (1) Fix the per-run degradation — an apparently unbounded replay/validation loop in the force-cache read path — as a correctness-class defect, not a tuning task. (2) Gate further cache investment on a **fast-baseline milestone**: the tree-walk oracle within a small constant factor of C++ Nix on the eval-only path with the cache **off**, made a falsifiable gate analogous to byte-green (R1). (3) Consider pulling the value-representation + bump-arena work (Rank 2) and hash-consing/pointer-tagging (Rank 5) **partly forward**, since Rank 1's cheap-hashing premise depends on them — then re-validate the "independent of interpreter speed" claim against that substrate. Note C++ Nix is itself a tree-walk interpreter with *no* JIT, so the ~100× catch-up is a **pre-JIT** exercise (Ranks 2-3); the JIT (Rank 4) is about *exceeding* C++ Nix, not reaching it. The permanent `AOS_NIX_CACHE=0` and `NixCli` fallbacks keep this a sequencing issue, never a correctness one. |

### 4.1 The asymmetry that orders the register

Every mitigation above resolves to the same structural insight, which is why the
register reads as variations on one theme: **the cost of a wrong `.drv` is
catastrophic and the cost of a slow `.drv` is merely slow, so every risk is
mitigated by keeping a *correct, trusted, slower* path permanently available and
never letting the fast path be the final arbiter.** The trust gradient
([14](14-integration-with-aos.md) §9.2) — unsafe JIT tiers < safe tree-walk
oracle < `NixCli` (C++ Nix) — is the spine of the whole risk posture. R1, R2,
R3, R6, R7 all terminate in "fall back to the oracle, and ultimately to
`NixCli`." The roadmap is paranoid by construction because the failure mode is
asymmetric and brutal.

---

## 5. Open questions

These are explicitly *not settled* and are flagged as measurement-dependent or
research-grade. They are the questions whose answers reshape the roadmap, kept
here so the design record does not overstate certainty.

- **Q-A — Does rank 1 (the incremental cache) alone clear the goal?** It is
  plausible the early-cutoff cache solves the AOS build-time problem on its own,
  reducing the JIT (rank 4) and the rank-5 tail to measured-but-deferred
  follow-ups ([01](01-motivation-and-goals.md) §7,
  [12](12-incremental-evaluation-cache.md) §1). The P1/P2 measure-first data
  should settle it. *This is the single most consequential ordering question in
  the roadmap; if the answer is yes, later tiers still exist under the budget
  mandate but no longer carry the same short-workload urgency.* **Open until P2
  cache measurements exist.** **Update (2026-06-28): the first P2 cache
  measurements now exist and are net-negative — with the cache enabled, eval is
  *slower*, and successive warm runs degrade monotonically (R10). The leading
  hypothesis (rank 1 alone clears the goal) is therefore not supported by the
  initial data: on the current tree-walk, the cache amplifies a ~100×-slow base
  rather than eliding it. Q-A stays open, but its resolution is now gated on the
  interpreter-speed prerequisites (Ranks 2-3) and a fix for the per-run replay
  degradation — i.e. the cache must be re-measured on a *fast* baseline before
  its standalone payoff can be judged.**

- **Q-B — What is the real cold-eval ceiling on AOS?** The committed P1
  baseline gives the representative `nix-instantiate` + `NIX_SHOW_STATS`
  numbers that the measure-first characterization needs
  ([01](01-motivation-and-goals.md) §5.1). C3's target is now anchored by a
  measurement instead of a guess. **Resolved for the committed representative P1
  slice on 2026-06-24**:
  [phase1-baseline-characterization.md](phase1-baseline-characterization.md).
  The larger CI workload distribution remains Q-C.

- **Q-C — What fraction of AOS CI eval time is cold vs warm?** The cache's entire
  value is in re-evaluation; if AOS CI is dominated by cold first-runs on fresh
  machines, rank 1's payoff shrinks ([12](12-incremental-evaluation-cache.md)
  §8.1). We believe the AOS workflow is re-evaluation-dominated but have not
  quantified it. **Open until measured.**

- **Q-D — Is free-variable narrowing precise enough for cheap environment
  hashing?** The cache key mixes in the value-hashes of an expression's free
  variables; if the strictness pass's FV set is imprecise, thunks rekey on
  irrelevant slot changes and recompute spuriously (a performance bug, never a
  correctness bug — [12](12-incremental-evaluation-cache.md) §8.1). Whether the
  existing strictness analysis suffices or a dedicated dependency-minimization
  pass is needed is open.

- **Q-E — Does NaN-boxing pay off net of its complexity?** Nix ints are `i64` and
  do not fit a NaN-box payload, forcing a boxed-int fallback; the rank-0 cut uses
  a 16-byte tagged value, with NaN-boxing a *measured* rank-5 optimization, not a
  baseline ([01](01-motivation-and-goals.md) §7,
  [05](05-value-representation.md)). Whether the register-passing win survives
  the boxed-int tax is open.

- **Q-F — Does the Cranelift JIT ever pay for itself in one-shot CLI mode?** Tied
  to R8: the dominant workload is the worst case for any JIT. Resolution is
  measurement-gated; copy-and-patch is the hedge ([08](08-execution-tiers-and-cranelift.md)).
  **Open until P6 measures warmup against the one-shot workload.**

- **Q-G — Daemon or per-invocation process?** The roadmap assumes the
  per-invocation `aos` process model (bump arena, drop at exit). A persistent
  eval daemon would amortize JIT warmup and share the incremental cache across
  invocations, but flips the GC to the generational/concurrent tier (rank 5,
  R9) and may require a `NixEval` lifecycle (`shutdown`/`flush`)
  ([14](14-integration-with-aos.md) §13). Deferred until the per-process numbers
  justify it.

- **Q-H — Persistence-format and cross-machine-cache stability.** The on-disk
  `nodes/values/files` schema ([12](12-incremental-evaluation-cache.md) §6) is a
  data contract needing a schema-version field and a discard-on-mismatch policy;
  the single-flight protocol for the *persistent* store across machines (not just
  threads) is unspecified ([12](12-incremental-evaluation-cache.md) §8.4). Whether
  cache push/pull is plumbed through `NixEval` or sits beside it (as the
  build-output cache does) leans toward beside-it to keep the trait minimal
  ([14](14-integration-with-aos.md) §13). **Open.**

- **Q-I — How large is the R1 long tail, actually?** The defense-in-depth around
  `.drv` divergence is sound, but the *size* of the tail — how many obscure
  quirks must be reproduced bug-for-bug before the full closure is byte-green —
  is unknown until the harness runs the full closure repeatedly under Shadow
  mode against real CI traffic ([14](14-integration-with-aos.md) §7.2). This is
  the open question that ultimately governs the calendar to default-on. **Open
  until the harness is byte-green on the full closure.**

---

## 6. Phase 1 — implementer checklist

Phase 1 has zero unsettled design decisions (every choice it touches is recorded
in the [decision register](19-decision-register.md)); it is buildable end-to-end
from this RFC. It produces the two things that gate everything after it: the
baseline cold-eval number and the proof that `.drv` parity is achievable on the
AOS package set. Build it in this order.

**Crate skeleton (`crates/aos-nix/`).**

- [x] Add `aos-nix` to the workspace (`crates/Cargo.toml` members) with pinned
      `nix-compat` (git rev) and the `xxhash-rust`/`blake3`/`sha2` deps. No
      Cranelift dependency yet — Phase 1 is tree-walk only.
      → re-layered in Phase 1b ([28](28-generalization-and-language-dialects.md) §10):
      the single-crate `aos-nix` layout is split into the `ratchet-*` engine +
      the `aos-nix-*` dialect band.
- [x] `lib.rs` `//!` crate overview + module map, to the AOS Rust doc standard.
- [x] Wire the `NixEval` trait in `aos-core` ([14](14-integration-with-aos.md)):
      define the trait, keep `NixCli` as its first impl, add a stub `NixNative`
      behind `AOS_NIX_NATIVE` (off by default).

**Frontend ([04](04-frontend-parser-and-ir.md)).**

- [x] `syntax/lexer.rs` — hand-written lexer; tokens are `Copy` (span + 1-byte
      kind). Trivia retained.
- [x] `syntax/ast.rs` — compact arena AST, `u32` NodeIds, fixed-stride nodes.
- [x] `syntax/parser.rs` — recursive-descent + Pratt for operators; **no rnix in
      the production path** (rnix is a test-only oracle).
- [x] `compile/scope.rs` — name resolution to de Bruijn `(depth, slot)` indices.
- [x] `cache/parse.rs` — content-addressed (blake3) parse-artifact cache so the
      package set parses once.

**Value + heap (Phase-1 subset, [05](05-value-representation.md)/[06](06-memory-management-and-gc.md)).**

- [x] `value.rs` — the 16-byte tagged `Value` (i64/f64 inline; heap forms behind
      `NonNull`). **No NaN-boxing** (measure-gated, [05](05-value-representation.md) §12).
- [x] `heap/arena.rs` — bump-arena Tier A (allocate, never free, drop at exit),
      with all allocation behind `aos_alloc_*`-shaped entry points so the GC tier
      can swap in later without touching callers. **No GC in Phase 1.**
- [x] `attrs.rs` — sorted-vec + binary-search attrsets with `u32`-interned
      symbols; deterministic iteration order. Hidden classes are Phase-4.

**Tree-walk oracle ([08](08-execution-tiers-and-cranelift.md) §2.1).**

- [x] `eval/tree_walk.rs` — the current sequential call-by-need interpreter:
      thunks (`Suspended → Blackhole → Forced`), forcing, closures, `with`,
      `rec`, `let`, `if`, and operators. This is the permanent **sequential**
      correctness oracle. Implemented by the safe tree-walk evaluator over
      lowered IR, `ThunkCell`/`ForceGuard`, environment-capturing thunk
      allocation, and the core-form evaluator modules. Covered by the
      `eval::thunk` tests and tree-walk tests for lazy attr/list values,
      recursive attrsets, `let`/`with` scoping, lambda application, control
      flow, operators, thunk memoization, blackhole detection, and error
      unwinding.
- [ ] P3.5 parallel thunk protocol over the same semantic lifecycle: the P1
      state word is already atomic, but the parallel superset
      `Suspended → Pending → Awaited → Forced/Failed`, waiter wakeups,
      same-thread `Blackhole` distinction, thread-safe result publication, and
      `loom`/Miri/TSan proof remain owned by
      [13](13-parallel-evaluation.md). P1 itself stays single-threaded.
- [ ] Conformance: the full [language surface](20-nix-language-conformance.md)
      and [pure builtins](21-builtins-conformance.md) must diff-green under this
      oracle. **Parity is a Phase-1 requirement, then held invariant** through
      every later optimization (see [all-phases checklist](22-implementation-checklist-all-phases.md)).
- [x] `runtime/builtins/` declaration/registry/dispatch substrate: the
      `define_builtins!` inventory, sorted `BuiltinRegistry`, compile-time
      `BuiltinLookupTable`, direct/first-class arity, effect, availability, and
      native-fallback metadata, plus generated `select`/`apply_direct`/`apply`
      dispatch after interned `Symbol` lookup resolves to a declaration.
      Ordinary filesystem `import` uses a canonical-realpath result cache plus
      a durable parse/compile cache keyed by source blake3, schema version, and
      parser flags; `scopedImport` and text-store imports intentionally bypass
      the durable parse cache. Full primop semantics remain tracked by the open
      [10](10-primops-and-runtime-abi.md) full-surface row and conformance gate.

**Compatibility core ([11](11-derivation-and-store-compatibility.md)).**

- [x] Current tree-walk `derivationStrict` compatibility core: collect the
      string env in deterministic attr order, populate
      `nix_compat::derivation::Derivation`, emit explicit local ATerm bytes,
      construct local SHA-256 fingerprints for text-path and
      hash-derivation-modulo inputs, use `nix_compat::store_path` for
      `compress_hash`/final store-path validation, and materialize `.drv` bytes
      safely. Input-addressed, fixed-output, floating CA, and impure derivation
      output modes are implemented in the tree-walk builder.
- [ ] Compatibility hardening still open: pin/vendor `nix-compat` behind an
      adapter, type-enforce the three-hash split, and add the full transitive
      `.drv`/drv-path/output-path parity gate with CA fixtures plus the
      [RFC-0005](../0005-ca-trust-map.md) graph ([02](02-compatibility-constraints.md)
      §8, [11](11-derivation-and-store-compatibility.md) §5.4).
- [x] Current string-context semantic core: context element kinds, sorted and
      deduplicated immutable contexts, union through string ops, reflection and
      discard/update primops, and `derivationStrict` input partitioning.
- [ ] Future string-context representation: interned COW bitsets/sorted sets
      and deriving-path intern ids.
      → re-layered in Phase 1b ([28](28-generalization-and-language-dialects.md) §10):
      the context bitset + union-on-concat semantics move out of `ratchet-value`
      into `aos-nix-dialect`.

**The gate ([15](15-differential-testing-and-benchmarking.md)) — the deliverable.**

- [x] Current `.drv` diff harness core/tooling: `diff_closure` and
      `aos nix-diff` compare path, byte, and structural modes; traverse
      input-derivation closures; classify root vs. contaminated divergences;
      emit direct node reruns through file-backed pairs or closure bundles; build
      `--all` package, `--systems` toplevel, explicit toolchain, and optional
      lang-conformance corpora; and fail corpus runs with binary all-or-nothing
      semantics.
- [x] Full `.drv` acceptance gate: the harness is byte-green from `NixNative` vs
      the pinned C++ `nix-instantiate` over the full AOS closure and must block
      regressions through the default-off, shadow, and default-on rollout gates.
- [x] Baseline/stat capture tooling: `NixCli::instantiate_with_stats`,
      `aos nix-diff --oracle-stats`, `aos nix-bench`, benchmark corpus discovery,
      stats aggregation, and the byte-parity guard before recording are in place.
- [x] Recorded baseline: capture and commit representative AOS
      `nix-instantiate` wall-clock + `NIX_SHOW_STATS` (thunks, fn calls, gc) in
      `phase1-baseline.jsonl`; the P1.5 characterization in
      [phase1-baseline-characterization.md](phase1-baseline-characterization.md)
      sets the initial C3 target and answers Q-B for the committed slice.
- [x] Current fuzz/conformance scaffolds: `cargo-fuzz` targets and seed corpora
      for `internal_diff_raw` and `parity_json`, source-seed passthrough,
      structure-aware valid-expression generation, the configured C++ Nix lang
      corpus runner, and `proptest` invariant coverage are in place.
- [x] Current parser/fuzz hardening scaffold: the rnix parser acceptance
      differential oracle runs as `aos-nix-syntax`'s test-only
      `parser_acceptance_matches_rnix_oracle_on_p1_syntax_corpus` plus
      automatically enumerated local language fixtures, source-seed fuzz
      corpora with explicit `internal_diff_raw` and `parity_json` sentinels, and
      the real workspace `.nix` source tree with package, toolchain, module, and
      system sentinels; `aos nix-fuzz-corpus` now populates ignored parity-fuzzer source
      seeds from the full §2.7 package/toolchain/system corpus and configured
      generated conformance corpus. Covered by the parser rnix-acceptance tests,
      `nix_fuzz_corpus` command/CLI tests, and the `nix_diff` corpus rendering
      tests for package/system/toolchain/conformance roots.
- [ ] Full parity-fuzzer budget/quiescence and full conformance diff-green
      remain acceptance gates: after the last evaluator-affecting change, run
      the configured fuzz budget to zero new divergences and keep the full
      conformance harness green before any default-on cutover.

**Phase-1 exit criteria.** The `.drv`-diff harness is byte-green on the full AOS
closure under the tree-walk oracle; the baseline eval-time and `NIX_SHOW_STATS`
numbers are recorded; `AOS_NIX_NATIVE` still defaults off. Only then do the
ranked items (cache, arena/GC, analyses, JIT) begin — in the order of §2.

### Phase 1b — re-layering into ratchet + the Nix dialect

The implementation starts as a single monolithic `aos-nix` crate. Phase 1b is a
**behaviorally inert** structural pass that splits it into the language-agnostic
`ratchet` engine + the Nix dialect — the MLIR-style Core/dialect factoring of
[28](28-generalization-and-language-dialects.md) (decisions `S-22`/`S-23`). It
changes no `.drv` output: the differential harness stays byte-green on the same
fixtures as before the split. **Entry:** once the parser → Core IR → oracle
skeleton compiles and the first fixtures are byte-green. **Overlap:** it runs
alongside the remainder of P1 and the P1.5 characterization; agents continuing P1
fold its boundaries in as they go, rewriting already-done modules to fit.
**Ordering:** it **must complete before P2**, because P2 builds `ratchet-cache`
and the open effect lattice and those should be *born* in the new model, not
retrofitted. The checklist (condensed from [28](28-generalization-and-language-dialects.md) §10):

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
      `PrimOp` escape hatch (`IrData::DialectNode` / `IrData::DialectScopeVar`
      with Nix op keys), and the resolver's "unresolved name" path lowers only
      through a dialect hook.
- [x] **`EffectClass` → open trait (`S-23`).** Replace the closed
      `enum EffectClass { Pure, Effectful }` with a `ratchet-core` trait
      (`is_speculable` + `effect_key`); the Nix dialect supplies the members
      (`import`/IFD/`readFile`/`derivationStrict`). Delete the hardcoded
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

**Phase-1b exit criterion.** The `.drv`-diff harness is byte-green on the same
fixtures as before the split (the refactor is behaviorally inert), and the crate
boundaries match [28](28-generalization-and-language-dialects.md) §3 /
[27](27-engineering-standards.md) §1.1.

---

## 7. Summary

The roadmap is fixed at its head and ranked through its body. Phase 1 — parser,
scope resolution, the tree-walk correctness oracle, and the differential
`.drv`-diff harness — is built first and non-negotiably, because it is the only
way to produce both the baseline eval-time number the measure-first
characterization needs and the parity proof on AOS's
`mkDerivation`/`ccWrapper`/`evalModules` constructs that the acceptance gate
demands, *before* any optimizing compiler exists. P1.5 characterizes where eval
time goes and orders the committed optimization stack. After that, the ranked
sequence delivers the biggest systemic win first — the incremental early-cutoff
cache, which may solve the build-time problem on its own and pays off even on
the oracle — then the arena/precise GC, then the strictness/escape analyses
(all three of which help the tree-walk tier before any JIT exists), then hidden
classes + PIC and the Cranelift tiers, and finally the advanced tail of pointer
tagging, NaN-boxing, full-laziness, region inference, and concurrent moving GC.
The risk register is a single theme stated nine ways: a wrong
`.drv` is catastrophic and a slow `.drv` is merely slow, so the fast path is
never the final arbiter — the tree-walk oracle and the permanent `NixCli`
fallback are always there to catch it, and `AOS_NIX_NATIVE` stays default-Off
until the harness is byte-green on the full closure. The fastest evaluator is
the one that does not evaluate; the safest rollout is the one that can be undone
with a single environment variable.

---

## References

This document synthesizes the roadmap and risk posture from the rest of the
RFC-0007 set; the external claims it leans on are sourced in the documents it
cites.

- Measure-first gate, success criteria, backend selection, and the long-tail /
  `nix-compat` open questions: [motivation and goals](01-motivation-and-goals.md).
- The ranked build sequence, the tier model, the acceptance gate as an architectural
  force, and the per-rank prior-art mapping:
  [architecture overview](03-architecture-overview.md).
- Early cutoff, the verifying/constructive trace model, hashing policy, and the
  cache's own failure modes and open questions:
  [incremental evaluation cache](12-incremental-evaluation-cache.md).
- The `NixEval` seam, the Off/Shadow/On phased flip, the failure/fallback model,
  and the `unsafe` policy and tooling discipline:
  [integration with AOS](14-integration-with-aos.md).
- The differential `.drv`-diff harness and per-commit benchmarking that gate
  every phase: [differential testing and benchmarking](15-differential-testing-and-benchmarking.md).
- The prior-art lineage (Salsa/Adapton, GHC, HotSpot, V8, Cranelift, Snix) the
  ranks draw from: [prior art and references](16-prior-art-and-references.md).
