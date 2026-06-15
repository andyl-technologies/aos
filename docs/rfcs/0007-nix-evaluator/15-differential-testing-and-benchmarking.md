# RFC-0007 - Differential testing and benchmarking

This document specifies how aos-nix *proves* it is correct and *demonstrates*
it is fast. Those are two distinct obligations with two distinct harnesses, and
this document treats them in priority order — correctness first, because a
faster-but-divergent evaluator is worthless in a from-source distribution (see
[motivation and goals](01-motivation-and-goals.md) and
[compatibility constraints](02-compatibility-constraints.md)).

The centerpiece is the **differential `.drv`-diff harness**: it runs aos-nix and
`nix-instantiate` across the *entire* AOS package set and asserts byte-identical
`.drv` files and store paths. That harness is not a test among tests — it is the
**acceptance gate** that governs whether aos-nix may ever be turned on (see the
gating mechanism in [integration with AOS](14-integration-with-aos.md)). Around
it sit three supporting pillars: reuse of the C++ Nix language **conformance
suite** (as Tvix/Snix does), `NIX_SHOW_STATS`-style **eval statistics** that
quantify *where* eval time goes, and **per-commit benchmarking** that catches
regressions before they land. All of it is subordinate to the **measure-first
principle**: we do not optimize a phase until we have measured that it is the
bottleneck.

This document is deliberately concrete. It specifies what to diff, how to bisect
a divergence down from "one byte off in `glibc.drv`" to "`inputDrvs` entry 17,"
how the harness is wired (as a Rust test *and* an `aos` subcommand sharing the
`NixEval` trait), and how the gate result feeds the staged `AOS_NIX_NATIVE`
rollout.

---

## 1. Two obligations, two harnesses

It is worth stating the split sharply, because conflating correctness testing
and performance testing is the classic way both get done badly.

```text
   ┌──────────────────────────────┐      ┌──────────────────────────────┐
   │  CORRECTNESS  (the gate)     │      │  PERFORMANCE  (the budget)   │
   │                              │      │                              │
   │  differential .drv-diff       │      │  per-commit benchmark suite  │
   │  vs nix-instantiate           │      │  (Windtunnel-style)          │
   │  + conformance test suite     │      │  + NIX_SHOW_STATS counters   │
   │                              │      │                              │
   │  result: BINARY (pass/fail)  │      │  result: a number + a trend  │
   │  blocks default-on rollout   │      │  blocks regressions          │
   └──────────────────────────────┘      └──────────────────────────────┘
            must be GREEN                       must not REGRESS
       before AOS_NIX_NATIVE=on            before a perf PR may land
```

The two never substitute for each other:

- A correctness pass with no speedup means the project failed its premise (an
  evaluator nobody turns on because it is no faster) but harmed nothing.
- A performance win with a single divergence is **catastrophic** — it can
  trigger a from-source rebuild of the GCC ladder (see
  [compatibility constraints](02-compatibility-constraints.md) §3). The
  correctness gate therefore has *absolute priority* and *veto power* over the
  performance work.

This priority ordering is why the correctness harness is specified first and in
the most detail.

---

## 2. The differential `.drv`-diff harness (the acceptance gate)

The acceptance gate is defined informally in
[compatibility constraints](02-compatibility-constraints.md) §7. This section
makes it operational: the algorithm, the closure walk, the three diff modes, the
bisection workflow, and the dual incarnation as a test and a subcommand.

### 2.1 What it proves

For every `(file, attr)` the AOS package set can produce, the harness asserts
that aos-nix and C++ Nix emit the byte-identical derivation **closure**:

```text
   for each (file, attr) in AOS package set:
       drv_ref = NixCli.instantiate(file, attr)        # C++ Nix — the oracle
       drv_aos = NixNative.instantiate(file, attr)      # aos-nix — the candidate

       assert path(drv_aos)  == path(drv_ref)           # store-path equality
       assert bytes(drv_aos) == bytes(drv_ref)          # ATerm byte equality

       for each input in closure(drv_ref):              # WALK THE WHOLE CLOSURE
           assert path/bytes equal for input            # down to the leaves

       assert errored(drv_aos) == errored(drv_ref)      # error/no-error parity

   GATE PASSES  iff  every node in every closure matches AND
                     every input that errors under one evaluator errors
                     under the other.
```

Three properties of this definition are load-bearing:

1. **It is closure-complete.** The harness does not stop at the top-level
   `.drv`; it recurses over `inputDrvs` to the leaves. A divergence deep in the
   DAG (in `glibc`, in a `gcc4_4` bootstrap stage) is the *expensive* one
   because the store graph is Merkle-structured — a single wrong byte low in the
   graph fans out to everything above it (see
   [compatibility constraints](02-compatibility-constraints.md) §3). Passing on
   `hello` proves essentially nothing; the gate is the full closure including
   the foundational toolchain derivations.

2. **It diffs `.drv` *bytes*, not eval output.** This is the only check that
   catches string-context divergence. A context bug (dropping a store-path
   reference across `builtins.substring`, say) is *invisible* in a string's
   printed value but silently removes an input from a downstream `.drv`,
   changing its hash (see
   [compatibility constraints](02-compatibility-constraints.md) §5.3). Diffing
   the serialized ATerm is the single pass that catches context divergence,
   attribute-ordering divergence, ATerm-quoting divergence, and FOD-hash
   divergence together.

3. **It checks error parity.** If aos-nix throws where C++ Nix succeeds — or
   succeeds where C++ Nix throws — that is a gate failure exactly like a byte
   mismatch. This guards the `EvalError`-vs-`Unsupported` distinction the
   integration relies on (see [integration with AOS](14-integration-with-aos.md)
   §6): the fallback logic is only sound if the two evaluators agree on *which
   inputs error*.

### 2.2 Why the gate is binary and all-or-nothing

There is no "98% passing" state in which aos-nix becomes the default. Because
the cost of one foundational divergence is a full distribution rebuild, the gate
is **all-or-nothing for the default-on decision**. This is the concrete
mechanism behind success criterion **C1** in
[motivation and goals](01-motivation-and-goals.md): byte-identical `.drv` and
store paths across all of AOS, zero divergences, as a *binary* criterion.

A partial pass is still *useful* — it tells us how far we are and which packages
remain — but it never unlocks `AOS_NIX_NATIVE=on` by default. During
development, aos-nix is used opportunistically and continuously double-checked
against `NixCli` via shadow mode (§2.6); it is *trusted* by default only when
the gate is green end-to-end.

### 2.3 The three diff modes

A raw `cmp` of two `.drv` files answers "do they differ?" but not "where?" The
harness offers three modes, escalating from fast triage to root-cause:

| Mode | Compares | Cost | Use |
|---|---|---|---|
| **Path diff** | the printed store path(s) | cheapest | first-signal triage; "does anything differ at all?" |
| **Byte diff** | `cmp` of `.drv` ATerm bytes | cheap | the authoritative gate check |
| **Structural diff** | parsed ATerm, field by field | parse cost | root-causes a byte mismatch |

The **structural diff** is the workhorse for debugging. On a byte mismatch it
parses both `.drv` files using `nix-compat`'s ATerm *parser* (the same crate
that writes them; see
[derivation and store compatibility](11-derivation-and-store-compatibility.md))
and reports the first differing field. This turns an opaque "one byte off
somewhere in `glibc.drv`" into an actionable "`inputDrvs` entry 17 differs:
ref=`/nix/store/aaa…-foo.drv` vs `/nix/store/bbb…-foo.drv`."

The structural diff also *disambiguates the bug class* by where the difference
lands:

```text
   structural diff result        ─────►  likely root cause
   ───────────────────────               ───────────────────
   fields identical, bytes differ        SERIALIZATION: ATerm quoting/escaping
                                         or field ordering (a nix-compat-glue or
                                         attr-order bug)

   `env` block order differs             ATTR ITERATION ORDER: symbol-collation
                                         mismatch (see doc 09)

   `inputDrvs` / `inputSrcs` differ      EVALUATION or STRING CONTEXT: a wrong
                                         dependency was discovered (see doc 02 §5)

   `outputs` hash differs                OUTPUT-PATH COMPUTATION: masked-ATerm /
                                         FOD recipe mismatch (see doc 11)

   a field present on one side only      a primop emitted (or failed to emit) an
                                         env entry / arg (see doc 10)
```

This mapping is what makes the *long tail* of divergence (the dominant risk in
[roadmap and risks](17-roadmap-and-risks.md)) tractable to chase: each new
divergence class is localized to one owning subsystem rather than searched for
across the whole evaluator.

### 2.4 Bisecting a divergence

When the closure-complete gate reports N divergent nodes, they are almost never
independent — they fan out from a *root* divergence low in the DAG. The harness
exploits the Merkle structure to find that root cheaply:

```text
   1. Collect the set D of all divergent .drv nodes across the closure.

   2. Order D topologically (inputDrvs is a DAG).

   3. The ROOT divergences are the nodes in D with NO divergent input —
      i.e. all of their inputDrvs matched, yet they themselves differ.
      Everything else in D is downstream contamination: it differs ONLY
      because one of its inputs got a different store path.

   4. Fix root divergences first; re-run; the contaminated set collapses.
```

Concretely: if `glibc.drv` diverges and 4,000 packages downstream also diverge,
the harness reports `glibc` as the single root and the other 4,000 as
*contaminated* (their own evaluation may be perfectly correct — they inherited a
wrong input path). The engineer fixes one bug, not 4,001. This is the diffing
analogue of the Merkle fan-out that makes divergence catastrophic: the same
structure that makes one wrong byte expensive also makes it *findable*.

The harness emits, per root divergence, a **self-contained reproduction**: the
`(file, attr)`, both `.drv` paths, the structural-diff field localization, and
the minimal input set — enough to re-run that one node without re-evaluating the
closure (mirroring the divergence reports described in
[integration with AOS](14-integration-with-aos.md) §10).

### 2.5 Harness incarnations: a Rust test and an `aos` subcommand

The harness exists in two forms over **one** implementation, because it serves
two audiences. Both are thin consumers of the `NixEval` trait from `aos-core`
(see [integration with AOS](14-integration-with-aos.md) §3) — holding *both* a
`NixCli` box and a `NixNative` box and comparing their outputs. The trait is
what makes the harness trivial: it is just a third consumer of the same seam.

**(a) As a Rust integration test** (`crates/aos-nix/tests/drv_diff.rs`), run in
CI on every PR. It is parameterized over a corpus of `(file, attr)` pairs
(§2.7) and fails the build on any divergence. This is the form that *gates
merges*.

**(b) As an `aos` subcommand** (`aos nix-diff`), for interactive debugging and
ad-hoc closure sweeps. A developer chasing a divergence runs it directly,
selects a mode, and gets the structural localization without recompiling the
test binary.

```rust
/// Differential `.drv` comparison between two [`NixEval`] implementations.
///
/// Instantiates `attr` of `file` under both the reference evaluator
/// (`oracle`, normally [`NixCli`]) and the candidate (`cand`, normally
/// `NixNative`), then walks the resulting derivation closures and reports
/// every node whose store path or ATerm bytes differ, plus any
/// error/no-error mismatch.
///
/// # Errors
///
/// Returns an error if either evaluator fails to *run* (a process or I/O
/// failure) — note that this is distinct from an *evaluation* error, which
/// is captured as a value and compared for parity rather than propagated.
///
/// # Examples
///
/// ```no_run
/// # use std::path::Path;
/// # use aos_nix_harness::{diff_closure, DiffMode, DiffReport};
/// # fn run(oracle: &dyn aos_core::NixEval, cand: &dyn aos_core::NixEval)
/// #     -> anyhow::Result<()> {
/// let report: DiffReport = diff_closure(
///     oracle,
///     cand,
///     Path::new("default.nix"),
///     "glibc",
///     DiffMode::Structural,
/// )?;
/// assert!(report.is_match(), "{}", report.localize());
/// # Ok(())
/// # }
/// ```
pub fn diff_closure(
    oracle: &dyn NixEval,
    cand: &dyn NixEval,
    file: &Path,
    attr: &str,
    mode: DiffMode,
) -> Result<DiffReport> {
    // 1. instantiate under both evaluators
    // 2. walk inputDrvs of the oracle closure breadth-first
    // 3. compare path + bytes (+ structural fields in Structural mode)
    // 4. classify each divergence as ROOT or CONTAMINATED (§2.4)
    // ...
}

/// The granularity at which two `.drv` closures are compared.
pub enum DiffMode {
    /// Compare only the top-level printed store path(s). Fastest triage.
    Path,
    /// Compare the full ATerm bytes of every node. The authoritative gate.
    Byte,
    /// Parse both ATerms and compare field by field to localize a mismatch.
    Structural,
}
```

The Rust test form is what enforces success criterion **C1**; the subcommand is
what makes C1 *reachable* by a human chasing the long tail.

### 2.6 Shadow mode is the gate run against real traffic

Beyond the corpus-driven CI test, the **shadow mode** described in
[integration with AOS](14-integration-with-aos.md) §5.1 turns the *entire CI
fleet* into an always-on extension of this harness. In shadow mode every real
`aos build` / `aos test` runs both evaluators, returns the `NixCli` answer
(authoritative), and diffs the `NixNative` answer in the background. Divergences
are reported but never reach the store.

This matters for the gate because the static corpus (§2.7) can only test what we
thought to enumerate; shadow mode tests *what AOS actually evaluates*, including
packages that only appear under a specific system configuration. The two are
complementary:

```text
   corpus test (CI)     — deterministic, enumerated, gates merges
   shadow mode (CI)     — real traffic, catches the configurations the
                          corpus missed; zero risk (native output discarded)
```

### 2.7 The corpus: what the gate actually iterates

The gate's `(file, attr)` corpus is generated from the AOS package set itself,
not hand-maintained:

- **All packages.** Every attribute reachable from the package set's
  `default.nix` — enumerated the way `aos graph` / `aos show` already walk it
  (the same machinery in `aos-core` that drives `aos build`).
- **All system-variant toplevels.** Each `systems/` variant's
  `system.build.toplevel`, which forces a substantial fraction of the entire
  expression tree (the realistic worst case for both correctness and
  performance).
- **The toolchain closure explicitly.** The source-bootstrap chain and the GCC
  ladder (`gcc3_4` → `gcc14`), the Rust bootstrap (mrustc → rustc), the JDK
  8→25 chain, the Bazel and LLVM trees — the long, expensive, foundational
  closures whose divergence is the most expensive possible event.
- **A conformance corpus** (§3), independent of the AOS package set, pinning
  pure-language semantics.

Because the corpus is *derived* from the package set, it grows automatically as
AOS gains packages — a new package is in the gate the moment it is in the tree.

---

## 3. Reusing the C++ Nix language conformance suite

The `.drv`-diff gate proves output parity on *what AOS evaluates*. It does not,
by construction, exercise language corners the AOS packages happen not to use.
For those, aos-nix reuses the **C++ Nix language test suite**, exactly as
Tvix/Snix does.

### 3.1 Why reuse rather than invent

Nix has no specification; the reference implementation *is* the spec, quirks
included (see [compatibility constraints](02-compatibility-constraints.md) §1.3).
A clean-room conformance suite written from an idealized reading of the language
would, by definition, fail to pin the bug-for-bug behaviors we must reproduce.
Reusing C++ Nix's own `tests/functional/lang/` corpus means our conformance bar
*is* the reference implementation's behavior, not an interpretation of it.

This is precisely the path Tvix/Snix took: they reimplemented the test-discovery
logic of C++ Nix's `lang.sh`, with skip logic that reacts to the C++ Nix version
under test, and run the corpus against multiple C++ Nix versions to verify
behavior as they implement newer features.

### 3.2 The four test categories

The C++ Nix language corpus (as Tvix/Snix consume it) splits into four kinds,
which aos-nix's runner reproduces:

| Category | Meaning | aos-nix assertion |
|---|---|---|
| `eval-okay-*` | evaluates successfully to a known value | aos-nix produces the byte-identical expected output |
| `eval-fail-*` | must fail to evaluate (no expected output) | aos-nix also fails (error *class* parity; see §3.3) |
| `parse-okay-*` | parses successfully (no eval) | aos-nix's parser accepts it |
| `parse-fail-*` | must fail to parse | aos-nix's parser rejects it |

The `eval-okay` cases compare the *rendered value* (the `--eval` output),
complementing the `.drv`-diff gate which compares the *derivation*. The
`parse-*` cases pin the [frontend](04-frontend-parser-and-ir.md) independent of
evaluation, catching grammar regressions before they can produce a wrong value.

### 3.3 Error parity: class, not (yet) bytes

For `eval-fail` and `parse-fail` cases, aos-nix must fail — but full byte-parity
of error *messages* is a non-goal for the first gate (error text is not a Merkle
input; it never affects a store path). What is in scope is **error-class
parity**: a type error stays a type error, a `throw` stays a `throw`, an
assertion failure stays an assertion failure. This is the same line drawn in
[compatibility constraints](02-compatibility-constraints.md) §8 (open question
4) and the basis for the `EvalError`-vs-`Unsupported` fallback distinction in
[integration with AOS](14-integration-with-aos.md) §6. The conformance runner
asserts class parity; the AOS packages that additionally assert on error *text*
are enumerated and handled per-case.

### 3.4 Documented, intentional exclusions

Per non-goal **N3** in [motivation and goals](01-motivation-and-goals.md),
aos-nix targets the language subset and primops the AOS package set exercises.
Conformance cases for corners AOS never touches may be explicitly excluded — but
each exclusion is *documented and intentional* (an entry in a `skip` list with a
reason), never a silent omission. This satisfies success criterion **C2**:
passes the conformance suite for the AOS subset, with documented exclusions for
unused corners only.

```text
   conformance suite ── guards the LANGUAGE  (operators, builtins, coercions,
                                              parse/eval errors)
   .drv-diff gate    ── guards the OUTPUT    (byte-identical derivations on the
                                              real AOS closure)
                       complementary, not redundant
```

---

## 4. Eval statistics: measuring *where* the time goes

The measure-first principle requires more than a wall-clock number; it requires
knowing *which* of the ranked optimizations (G2–G6 in
[motivation and goals](01-motivation-and-goals.md)) will pay off. C++ Nix's
built-in `NIX_SHOW_STATS` instrumentation supplies the baseline breakdown, and
aos-nix mirrors it with its own counters so the two are directly comparable.

### 4.1 `NIX_SHOW_STATS` as the baseline instrument

C++ Nix exposes evaluation statistics through two environment variables:

- **`NIX_SHOW_STATS=1`** — print evaluation statistics at the end of a run
  (number of values allocated, thunks, function calls, and related counters).
- **`NIX_SHOW_STATS_PATH=<file>`** — write those statistics as **JSON** to a
  file instead of stderr, so they are machine-parsable (queryable with `jq`).

A representative invocation, as documented on the NixOS wiki:

```sh
NIX_SHOW_STATS=1 NIX_SHOW_STATS_PATH=stats.json \
  nix-instantiate --eval some-expr.nix
jq .nrThunks stats.json     # e.g. => 29
```

The JSON exposes the counters that map directly onto aos-nix's design levers.
The exact field set varies by Nix version, but the load-bearing ones are:

| `NIX_SHOW_STATS` signal | What it quantifies | Which aos-nix lever it justifies |
|---|---|---|
| `nrThunks` / values allocated | thunk + value churn | G3 (laziness analyses), G4 (allocator/GC) |
| thunks avoided | how often laziness was *un*needed | G3 strictness/worker-wrapper (eager-where-safe) |
| function calls / primop calls | call overhead | G6 (tiered execution / Cranelift) |
| attribute lookups / sets | attrset access pressure | G5 (hidden classes + inline caches) |
| GC time / bytes | collector cost | G4 (precise GC replacing Boehm) |
| symbol-table size | interning pressure | G5 (`u32` symbol interning) |

This is exactly the phase-attribution data the measure-first gate in
[motivation and goals](01-motivation-and-goals.md) §5 demands: a large
`nrThunks` with high GC time argues for G4; a small cold/warm gap with high
attribute-lookup counts argues for G5; a large cold/warm gap argues for the G2
incremental cache. The optimization ordering is *driven by these numbers*, not
chosen up front.

### 4.2 aos-nix's mirrored counters

aos-nix maintains its own statistics, deliberately **named to parallel
`NIX_SHOW_STATS`** so a before/after comparison is a field-by-field diff rather
than a translation exercise. They surface through `aos`'s stats output and the
`tracing` counters described in
[integration with AOS](14-integration-with-aos.md) §10 (native successes,
fallbacks, shadow divergences). The aos-nix counters additionally expose what
C++ Nix cannot, because those mechanisms do not exist in C++ Nix:

| aos-nix counter | Reports | Tied to |
|---|---|---|
| `thunks_forced` / `thunks_allocated` | direct analogue of `nrThunks` | G3 |
| `thunks_elided` | thunks removed by strictness/worker-wrapper | G3 (the *delta* vs C++ Nix) |
| `inline_cache_hits` / `misses` | `select`-site shape-check outcomes | G5 |
| `shape_transitions` | hidden-class transition-tree growth | G5 |
| `gc_bytes` / `gc_pause_us` | precise-GC cost (or arena high-water) | G4 |
| `tier_promotions` | tree-walk → Cranelift baseline → optimized | G6 |
| `deopts` | uncommon-trap fallbacks to the oracle | G6 |
| `cache_hits` / `early_cutoffs` | incremental-cache reuse + early-cutoff | G2 |

The `early_cutoffs` counter is the direct instrument for success criterion
**C4** (bounded recomputation on irrelevant edits): a comment-only edit that
recomputes a small, bounded fraction of the closure shows up as a high
`early_cutoffs` ratio and an unchanged downstream `.drv` (see
[incremental evaluation cache](12-incremental-evaluation-cache.md)).

### 4.3 What the statistics are *not*

Statistics quantify *where* eval time goes; they never substitute for the
wall-clock benchmark (§5) and they never override the correctness gate (§2). A
PR that improves `inline_cache_hits` but regresses wall-clock is not a win; a PR
that improves any counter but diverges on the `.drv` gate is rejected outright.
Counters are *diagnostic*, the benchmark is the *budget*, and the gate is the
*veto*.

---

## 5. Per-commit benchmarking (catching regressions)

Correctness is binary and gated; performance is a continuously-defended budget.
The Nix evaluator's history is a cautionary tale here: it is extremely
performance-sensitive, yet for years its eval performance was never tracked,
so regressions accumulated silently. There is a longstanding NixOS request for
continuous eval benchmarks with a dashboard over git history precisely because
of this. aos-nix does not repeat that mistake.

### 5.1 Windtunnel-style per-commit tracking

aos-nix runs a **per-commit benchmark suite** in the spirit of Windtunnel
(`windtunnel.ci`) and `github-action-benchmark`: every commit (or at least every
PR) re-runs a fixed set of eval benchmarks, records the timings keyed by commit,
and **fails or warns on a statistically significant regression** against the
baseline. The result is a trend line over git history, so a slowdown is caught
at the commit that introduced it rather than discovered months later.

```text
   commit ──► run benchmark corpus ──► timings.json (keyed by commit sha)
                                            │
                                            ▼
                              compare against rolling baseline
                                            │
                    ┌───────────────────────┼───────────────────────┐
                    ▼                       ▼                        ▼
            within noise band        improvement              REGRESSION
            (record, continue)    (record new baseline)   (warn / block PR,
                                                            annotate with the
                                                            NIX_SHOW_STATS delta)
```

When a regression fires, the report includes the **statistics delta** (§4): not
just "120ms → 145ms" but "`thunks_allocated` +18%, `gc_pause_us` +40%" — which
points at the cause (here, an allocation regression) rather than leaving the
engineer to profile from scratch.

### 5.2 The benchmark corpus

The benchmark corpus mirrors the workloads named in success criterion **C3** and
the measure-first protocol (§5 of
[motivation and goals](01-motivation-and-goals.md)):

| Benchmark | Why |
|---|---|
| Full system-variant toplevel eval | the realistic worst case; forces most of the tree |
| Toolchain closure eval (GCC ladder, Rust/JDK bootstrap) | the deepest, most-shared closures |
| Leaf-package spread | the common interactive case (`aos show`, `aos build pkg`) |
| **Cold vs. warm** of each of the above | isolates the G2 incremental-cache win from raw interpreter speed |
| Microbenchmarks (attrset access, `map`/`genList`, deep recursion) | localizes G5/G3/G6 deltas — *diagnostic only* |

The **cold/warm split** is the most important axis. Cold eval (fresh parse +
evaluate, empty incremental cache) measures raw interpreter throughput and
stresses G3/G4/G5/G6. Warm eval (re-evaluating with a populated cache) measures
the G2 early-cutoff win, which the project believes is the single largest
real-world speedup. A large cold/warm gap is *direct evidence* for the
incremental-cache thesis (see
[incremental evaluation cache](12-incremental-evaluation-cache.md)); the
benchmark is how we keep that gap honest.

### 5.3 The metric is real-world eval wall-clock, gated on parity

Per non-goal **N6** in [motivation and goals](01-motivation-and-goals.md),
aos-nix does **not** optimize for synthetic microbenchmark glory. The
microbenchmarks in the corpus are *diagnostic* — they attribute a regression to
a subsystem — but the *budget* is wall-clock eval time on the real AOS
workloads. And every benchmark run is gated on the `.drv` parity check: a
benchmark result from a divergent evaluator is meaningless, so the benchmark
harness asserts parity (in shadow style) before recording a timing. We will not
report a speedup we cannot also prove correct.

We deliberately do **not** commit to a target multiple up front (the Tvix/Snix
~10× microbenchmark figure is treated as suggestive, not predictive — the Snix
project itself disclaims its real-world relevance). The measure-first baseline
(§6) sets the target from the actual `nix-instantiate` numbers on the AOS
closure.

---

## 6. The measure-first principle in practice

The measure-first gate (defined in [motivation and goals](01-motivation-and-goals.md)
§5) is not a one-time ceremony. This document is where it is *operationalized*
into a standing discipline.

### 6.1 The opening measurement (phase 1 deliverable)

Before any optimizing-compiler work, phase 1 produces the baseline the gate
demands:

```text
   1. Phase-attribute wall-clock on representative AOS workloads:
         time nix-instantiate  (pure EVAL)
         time nix-build        (EVAL + REALISE)
      => what fraction of end-to-end wall-clock is EVAL?

   2. Run NIX_SHOW_STATS / NIX_SHOW_STATS_PATH on those same workloads:
         where does eval time go? (thunks vs GC vs attr access vs calls)

   3. Measure COLD vs WARM:
         a large cold/warm gap  => evidence for G2 (incremental cache)
         high GC time           => evidence for G4 (precise GC)
         high attr-lookup count => evidence for G5 (hidden classes)

   GATE:  eval dominant?  ─ yes ─► proceed with the ranked roadmap (G2 first)
                          └ no  ─► STOP / re-scope: the bottleneck is build
                                   or I/O; an evaluator does not help
```

This is also the phase that builds the tree-walk oracle and the `.drv`-diff
harness *first* — so that the baseline number (which the gate needs) and the
parity proof (which C1 needs) both exist before a single Cranelift instruction
is emitted. The build order is fixed by the gate (see
[motivation and goals](01-motivation-and-goals.md) §5.3 and the roadmap in
[roadmap and risks](17-roadmap-and-risks.md)).

### 6.2 The standing rule: every optimization carries a measured delta

Success criterion **C6** is a *process* criterion: every optimization that lands
is accompanied by a measured delta on the benchmark harness (§5), with the
`NIX_SHOW_STATS`-style counter breakdown (§4) showing *why* it helped. No
optimization ships on faith.

```text
   a perf PR is admissible iff:
     (1) the .drv-diff gate stays GREEN          (correctness, §2 — veto)
     (2) the per-commit benchmark shows a
         wall-clock improvement on a real workload (budget, §5)
     (3) the counter breakdown explains the win   (diagnosis, §4)
   missing any of the three => the PR does not land as a perf win
```

The corollary mantra, carried throughout the set: **the fastest evaluator is the
one that does not evaluate** — which is why G2 (the incremental cache) leads the
roadmap despite being "less interesting" than a JIT, and why the cold/warm
benchmark split (§5.2) is the most-watched number.

---

## 7. The tree-walk oracle as an internal differential check

The differential harness of §2 checks aos-nix against the *external* oracle
(C++ Nix via `NixCli`). aos-nix also maintains an **internal** differential
check that catches bugs *before* they reach the `.drv` boundary: the tier-0
tree-walking interpreter is the **correctness oracle** for the optimized tiers
(see [execution tiers](08-execution-tiers-and-cranelift.md)).

```text
   trust gradient (least → most trusted):
     Cranelift optimized tier  <  tree-walk oracle  <  NixCli (C++ Nix)
              └── checked against ──┘      └── checked against ──┘
                  (internal differential)      (.drv-diff gate, §2)
```

In test and fuzz configurations, any thunk's optimized-tier result is checked
against the tree-walk oracle's result. This has three benefits:

1. **It localizes JIT/analysis bugs.** A divergence here means a Cranelift-tier
   or whole-program-analysis bug, distinct from a serialization or
   string-context bug — caught before it can perturb a `.drv`.
2. **It gives a debuggable reference.** When the optimized tier diverges, the
   oracle's result is the known-good value to diff against, in-process, without
   reaching for C++ Nix.
3. **It is the `miri`/sanitizer-clean program.** The oracle is 100% safe Rust
   (`#![forbid(unsafe_code)]`; see
   [integration with AOS](14-integration-with-aos.md) §9), so the conformance
   suite (§3) runs under `miri` against the *oracle* tier — giving the
   sanitizers a complete, exercisable program even though they cannot follow
   JIT-emitted machine code.

The oracle and the external gate compose into defense in depth: the unsafe
optimized tiers are validated against the safe oracle, which is validated against
C++ Nix. The unsafe surface is never the final arbiter of a store path — the
`.drv`-diff gate is.

### 7.1 Fuzzing the differential

Beyond the enumerated corpus, aos-nix fuzzes the differential: a generator emits
random (but valid) Nix expressions, both the optimized tier and the oracle
evaluate them, and any disagreement is a bug. The same generator feeds the
`cargo fuzz` targets named in
[integration with AOS](14-integration-with-aos.md) §9.3 (value decode, GC, ATerm
round-trip). Fuzzing is how we attack the long tail that the enumerated corpus
and even shadow mode cannot reach — expressions AOS does not yet contain but the
language permits.

---

## 8. How it all gates the `AOS_NIX_NATIVE` rollout

The harnesses in this document are the *evidence* the staged rollout in
[integration with AOS](14-integration-with-aos.md) §7 consumes. The mapping is
direct:

```text
   Phase A  default Off, .drv-diff harness + conformance in CI
            (PRs blocked on any divergence or conformance regression)   ◄─ §2, §3
   Phase B  default Off, SHADOW mode on in CI
            (every real eval diffed against C++ Nix; zero risk)         ◄─ §2.6
   Phase C  default On for eval_expr only (low blast radius)
            (gated on the rendered-value conformance corpus)            ◄─ §3.2
   Phase D  default On for instantiate, VERIFY sampling kept
            (the .drv-diff gate is green on the full closure)           ◄─ §2.1
   Phase E  verify sampling reduced; NixCli retained as permanent fallback
            (per-commit benchmark guards against regressions forever)   ◄─ §5
```

Each phase is unlocked by a harness result, never by belief:

- **A → B** requires the corpus `.drv`-diff gate (§2) and conformance suite (§3)
  green in CI.
- **B → C** requires shadow mode (§2.6) silently correct on real traffic for a
  sustained window — `eval_expr` first because a wrong metadata string is
  visible and harmless, where a wrong `.drv` is invisible and catastrophic (the
  blast-radius asymmetry from
  [integration with AOS](14-integration-with-aos.md) §3.2).
- **C → D** requires the full-closure `.drv`-diff gate (§2.1) byte-green,
  including the toolchain closure.
- **D → E** requires the residual `AOS_NIX_NATIVE_VERIFY` sampling (a production
  canary) to find zero divergences over a long window.

And throughout, the per-commit benchmark (§5) runs independently: it does not
gate *correctness* rollout, but it gates *perf regressions* — a commit that
keeps the gate green but slows eval is blocked just as firmly, because a native
evaluator that is correct but slower than C++ Nix has failed its premise.

---

## 9. Open questions

Flagged so the design record does not overstate certainty.

1. **`NIX_SHOW_STATS` field stability across Nix versions.** The exact JSON
   field set (`nrThunks`, function-call counts, GC fields) varies by C++ Nix
   release, and the format has been the subject of "make it machine-parsable"
   work upstream. **Decision (closed): pin the single C++ Nix version AOS builds
   with as the one baseline reference** — both the `.drv`/store oracle and the
   `NIX_SHOW_STATS` schema — and parse stats defensively (tolerate added fields,
   match known fields by name, fail loudly only on a *renamed* field the harness
   reads). The pinned Nix version is the same rev the `nix-compat` pin must match
   ([14](14-integration-with-aos.md) §12); bumping it is a deliberate,
   harness-gated event, not an ambient float. A second-version forward-compat
   canary is an optional later add, not part of the first gate.

2. **Statistical significance threshold for regressions.** Per-commit eval
   timings are noisy on shared CI runners. The regression detector needs a noise
   band (and ideally the self-hosted-runner determinism from the AOS CI infra)
   so it neither cries wolf nor misses a real 3% creep. *Open: the band width
   and the runner-pinning strategy.*

3. **Conformance-suite version skew.** Tvix/Snix run the corpus against multiple
   C++ Nix versions with version-reactive skip logic. aos-nix targets the single
   C++ Nix version AOS builds against, which simplifies skip logic but means we
   inherit *that version's* quirks specifically. *Open: whether to also run
   against a second version as a forward-compatibility canary.*

4. **Error-text parity for the AOS packages that assert on it.** §3.3 scopes the
   first gate to error-*class* parity, but some AOS expressions assert on error
   *text*. These must be enumerated and decided per-case before the packages
   that contain them can flip to native. *Open: the enumeration (shared with
   [compatibility constraints](02-compatibility-constraints.md) §8 Q4).*

5. **Fuzzer reduction quality.** When the differential fuzzer (§7.1) finds a
   disagreement, the minimal reproducing expression must be small enough to
   debug. Whether `cargo fuzz`'s built-in minimization suffices for Nix
   expressions, or we need a Nix-aware reducer, is unsettled. *Open until the
   fuzzer is producing real findings.*

---

## 10. Summary

aos-nix carries two independent obligations, proven by two independent harnesses.

**Correctness — the acceptance gate.** The differential `.drv`-diff harness runs
aos-nix against `nix-instantiate` across the *entire* AOS package-set closure and
asserts byte-identical `.drv` files, store paths, string contexts, and
error/no-error outcomes — walking `inputDrvs` to the leaves because a divergence
deep in the Merkle-structured store graph is the catastrophic one. It is
**binary and all-or-nothing**: anything short of zero divergence keeps
`AOS_NIX_NATIVE` default-off (success criterion C1). Three diff modes
(path/byte/structural) plus root-vs-contaminated classification turn "one byte
off in `glibc.drv`" into a localized, bisected, reproducible finding. The
C++ Nix language **conformance suite** (reused as Tvix/Snix does, in its four
`eval-okay`/`eval-fail`/`parse-okay`/`parse-fail` categories) guards the
*language*; the `.drv`-diff gate guards the *output*; the tree-walk **oracle**
and a differential **fuzzer** catch optimized-tier bugs before they reach the
`.drv` boundary.

**Performance — the defended budget.** `NIX_SHOW_STATS`/`NIX_SHOW_STATS_PATH`
supply the baseline phase-attribution that the **measure-first** gate demands,
and aos-nix mirrors those counters (plus its own `early_cutoffs`,
`inline_cache_hits`, `tier_promotions`, `deopts`) so every optimization's win is
*explained*, not merely observed. **Per-commit, Windtunnel-style benchmarking**
keeps the wall-clock budget on real AOS workloads — with the cold/warm split as
the most-watched number (it isolates the G2 incremental-cache win) — and blocks
regressions before they land. No optimization ships on faith: a perf PR is
admissible only if the `.drv`-diff gate stays green (veto), the benchmark shows
a real-workload wall-clock improvement (budget), and the counter breakdown
explains it (diagnosis). The fastest evaluator is the one that does not evaluate
— so the harnesses are built to *prove* that claim, package by package, before
aos-nix is ever trusted by default.

---

## References

External claims in this document were verified against the following sources.

- `NIX_SHOW_STATS` / `NIX_SHOW_STATS_PATH` behavior (print eval statistics; JSON
  output; `nrThunks` and related counters; `jq`-queryable):
  - NixOS Wiki — Nix Evaluation Performance —
    <https://wiki.nixos.org/wiki/Nix_Evaluation_Performance>
  - Nix Reference Manual — Common Environment Variables —
    <https://nix.dev/manual/nix/2.34/command-ref/env-common.html>
  - NixOS/nix #1858 — "Make Nix eval stats more easily machine-parsable" —
    <https://github.com/NixOS/nix/issues/1858>
- Tvix/Snix reuse of the C++ Nix language test suite (four test categories,
  version-reactive skip logic, verification against multiple C++ Nix versions):
  - Tvix `eval` README (lang-test categories and discovery) —
    <https://code.tvl.fyi/about/tvix/eval/README.md>
  - "test(tvix): nix-planned test verification using C++ Nix 2.3 and 2.11" —
    <https://code.tvl.fyi/commit/tvix/verify-lang-tests>
  - NixOS/nix #10320 — "Upstream language tests from Tvix" —
    <https://github.com/NixOS/nix/issues/10320>
  - Announcing Snix (Tvix → Snix rename, March 2025) —
    <https://snix.dev/blog/announcing-snix/>
- Continuous / per-commit benchmarking to catch eval regressions (Windtunnel;
  the longstanding lack of Nix eval benchmark tracking):
  - Windtunnel — <https://windtunnel.ci/>
  - NixOS/nix #4897 — "Continuous benchmarks" —
    <https://github.com/NixOS/nix/issues/4897>
  - Nix Reference Manual — Benchmarking —
    <https://nix.dev/manual/nix/2.32/development/benchmarking.html>
  - `benchmark-action/github-action-benchmark` —
    <https://github.com/benchmark-action/github-action-benchmark>
- Nix derivation `.drv` / ATerm format and store-path hashing (the bytes the
  gate diffs), and `nix-compat`'s ATerm parser/writer:
  - Nix Reference Manual — Derivation "ATerm" file format —
    <https://nix.dev/manual/nix/2.33/protocols/derivation-aterm>
  - `nix-compat::derivation` Rust docs —
    <https://docs.tvix.dev/rust/nix_compat/derivation/struct.Derivation.html>
- `nix-instantiate` (the oracle the gate diffs against) and `--eval` semantics:
  - Nix Reference Manual — `nix-instantiate` —
    <https://nix.dev/manual/nix/2.34/command-ref/nix-instantiate>
