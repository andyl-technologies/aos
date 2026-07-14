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
[integration with AOS](14-integration-with-aos.md) §11).

### 2.5 Harness incarnations: a Rust test and an `aos` subcommand

The harness exists in two forms over **one** implementation, because it serves
two audiences. Both are thin consumers of the `NixEval` trait from `aos-core`
(see [integration with AOS](14-integration-with-aos.md) §3) — holding *both* a
`NixCli` box and a `NixNative` box and comparing their outputs. The trait is
what makes the harness trivial: it is just a third consumer of the same seam.

**(a) As a Rust integration test** (`crates/aos-core/tests/drv_diff.rs`), run by
the hermetic `pkgs.aos` test phase with `--features aos-core/native-eval` and
therefore surfaced through flake `checks.aos`. The current test exercises a
representative `(file, attr)` fixture through every diff mode and a real
root-mutation localization case; the auto-derived corpus remains tracked in
§2.7. This is the form that *gates merges* when the flake check set is enforced.

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
  `aos nix-diff --all` now overlays a filtered explicit toolchain attr list on
  top of the auto-discovered `pkgs.*` derivations, covering the exposed
  `stdenv`/source-bootstrap roots plus the Rust, OpenJDK, Bazel, LLVM, Go,
  Python, CMake, Meson, and Ninja toolchain packages. The GCC ladder is exposed
  as `stdenv.toolchainTiers`, and the corpus selector expands each tier's
  derivation components dynamically so new tiers become runnable roots when
  they are added to the ladder.
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
The runner lives in `crates/aos-nix/tests/lang_conformance.rs`: it discovers the
upstream `lang.sh` filename categories, parses `.flags`, honors `.exp-disabled`,
applies version-reactive skips against pinned C++ Nix `2.24.12`, models the
`lang.sh` environment (`HOME`, `TEST_VAR`, default `NIX_PATH`, `/pwd`
normalization), pins the configured target system as an evaluator option, applies
the pinned digit-normalizing `.postprocess` shape without executing fixture
shell, supports raw `eval-okay` output, XML `eval-okay` output, and parse-mode
resolution checks. Raw/XML/strict evaluation paths lower through the Nix dialect
so dynamic `with` lookups exercise the tree-walk evaluator instead of the
language-agnostic core lowerer. The local fixture corpus runs by default. Setting
`AOS_NIX_LANG_TESTS` to an unpacked
`tests/functional/lang/` directory turns on the full pinned corpus gate,
including `lang.sh`'s special non-eval `bad-drvPath` case; as of this
checkpoint, pinned Nix `2.24.12` reports `208 passed, 1 skipped, 0 failed`; the
remaining skip is upstream `.exp-disabled`, with no local
`LANG_CASE_EXCLUSIONS` entries.

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

This is exactly the phase-attribution data the measure-first characterization in
[motivation and goals](01-motivation-and-goals.md) §5 demands: a large
`nrThunks` with high GC time argues for G4; a small cold/warm gap with high
attribute-lookup counts argues for G5; a large cold/warm gap argues for the G2
incremental cache. The optimization ordering is *driven by these numbers*, not
chosen up front.

### 4.2 aos-nix's mirrored counters

aos-nix maintains its own statistics, deliberately **named to parallel
`NIX_SHOW_STATS`** so a before/after comparison is a field-by-field diff rather
than a translation exercise. They surface through `EvalOutcome` /
`TreeWalk::stats()` snapshots for native-evaluator callers and through the
`tracing` counters described in
[integration with AOS](14-integration-with-aos.md) §11 (native successes,
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

### 5.4 The canonical scoreboard (every campaign reports the same two numbers)

The program-level goals are **10x C++ performance** and **half of C++'s RSS**.
To keep progress comparable across every RFC-0007 campaign — memory ladder, JIT
tiers, parallel eval, persist-write batching — each campaign landing reports the
**same two numbers**, defined once here. Both come from `aos nix-bench --json`
(fields already emitted; no schema change), in the standard config (default
cache-less, `AOS_NIX_JIT=1`, quiet machine, interleaved A/B, median over ≥3
samples), using the **paired-cycle** cold/warm semantics (§5.2, schema v4). Use
`native_summary.median_seconds` (not the mean) for the native leg — it is robust
to the host-load spikes that skew the mean on a contended machine.

1. **Cold-latency geomean — the 10x number.** Over the canonical **17-attr
   suite** (9 leaf: `pkgs.{zlib,xz,bzip2,openssl,curl,sqlite,jq,socat,git}` + 8
   toolchain: `stdenv.{stdenv,bash,coreutils}`, `pkgs.{gcc,glibc,binutils,rust,openjdk}`),
   the geometric mean of the per-attr **cold** `native/oracle` medians:
   ```text
   cold_geomean = geomean over 17 attrs of
       ( median(native_summary.median_seconds)[cold]
         / median(summary.mean_seconds)[cold] )
   ```
   **Goal: cold_geomean ≤ 0.10** (10x faster than C++). Honest v4 baseline
   (2026-07-12): **0.515** (~1.9x). Report the warm geomean alongside for
   context; the cold geomean is the headline.
2. **Wide-eval memory ratio — the 0.5x number.** On `-A bench.wide`, native
   post-run RSS over the C++ oracle child peak, **cold and warm** separately:
   ```text
   mem_ratio(temp) = median(native_summary.memory.rss_after_bytes_max)[temp]
                     / median(summary.child_peak_rss_bytes_max)[temp]
   ```
   **Goal: mem_ratio ≤ 0.50** cold and warm. Also report the raw MiB and
   the native arena peak (`arena_peak_live_mapped_bytes_max`) so a regression is
   attributable to arena vs non-arena traffic. Measure on **Linux** so the
   `MIMALLOC_PURGE_DELAY` reclaim (a no-op under darwin `MADV_FREE`) is reflected.

   **Achieved (2026-07-12, builder-hil1-87eb5b00, HEAD 223fd30f, byte-parity
   green).** With mimalloc's default deferred purge the native process retains
   ~136-139 MiB (0.70-0.72x of the C++ `nix-instantiate` child, which peaks at
   ~184 MiB here — not the ~77 MiB earlier placeholder; the denominator is the
   builder's measured child peak). Setting `MIMALLOC_PURGE_DELAY=0` (now the
   Linux default in the `aos` wrapper) returns those pages at once:
   **cold 37.7 MiB = 0.205x, warm 34.8 MiB = 0.189x** — both under the ≤0.50
   goal and under the ≤38 MiB wide-eval target, for ~5% native wall cost
   (0.346 -> 0.362 s cold; against being ~30x faster than C++ on this eval).

   The win is not wide-eval-specific: the same `MIMALLOC_PURGE_DELAY=0` A/B over
   the **17-attr leaf/toolchain suite** moves the median per-package native RSS
   from ~71 MiB (0.91x of the C++ child) to **~30.4 MiB (0.44x median, per-attr
   0.36-0.52x)** — so the 0.5x memory goal holds on **both** wide and
   per-package scopes. The measured native-time cost of the flag on the leaf
   suite is ~+5% median (per-attr noise -20%..+15%, no outlier regression),
   i.e. a `cold_geomean` of ~0.54 vs the ~0.515 baseline; the authoritative
   clean-oracle `cold_geomean`-under-purge0 is captured with the PGO baseline
   run (§31 substrate work), since the leaf A/B's oracle leg was contended.

**Flagship warm number — the durable-cache repeat-instantiate win.** The two
scoreboard numbers above are the *default cache-less* config. The persist-write
campaign's headline is the **`AOS_NIX_CACHE`-enabled warm repeat**, answered from
the durable root-cutoff record without re-deriving the closure. Measured on the
Linux builder (builder-hil1-87eb5b00, HEAD c36b5189d, native `nix-bench`, median
of 3, byte-parity green):

```text
zlib, AOS_NIX_CACHE set:  cold 312 ms  /  warm 6.6 ms
  warm vs cache-less cold (63.9 ms):  ~10x faster
  warm vs C++ nix-instantiate (~185 ms):  ~28x faster
```

This is the number a repeat `aos` eval on a warm durable cache actually pays, and
the strongest single stat in the campaign. It gates the **default-cache-root
product decision**: warm is decisively worth a default cache root; the open item
is the first-eval **cold** cache-populate tax, now **283 ms ≈ 4.3x cache-less**
(§3.2(b) write-behind cut it from 312 ms / 4.9x; syscalls dropped write −35% /
flock −46%, but the remaining cold cost is eval work + thread-coordination, not
I/O — see `design-notes/persist-write-batching-plan.md` §18.1), down from the
~13x-class before the persist-storm campaign. The whole-system-toplevel view is
the same story writ large: cold-populate ~16.4 s, **warm 20 ms (~820x)** via the
root-cutoff record. **The full decision package** — trajectory, memory, and the
coupled default-on ruling (both write-behind and the durable cache stay
default-off until the cold tax reaches the ≤1.2x gate; write-behind rides with
the cache whenever it is opt-in enabled) — lives in
`design-notes/persist-write-batching-plan.md` §17–§18.

**Scoreboard line every landing pastes into its report/commit body:**
```text
scoreboard: cold_geomean=<x> (goal <=0.10; v4 baseline 0.515)
            wide_mem_ratio cold=<x> warm=<x> (goal <=0.50; native <MiB> vs C++ <MiB>)
```
The exact wide-eval command:
```text
env AOS_NIX_ORACLE=.../nix-instantiate AOS_NIX_NATIVE=1 AOS_NIX_JIT=1 \
    crates/target/release/aos --eval-system x86_64-linux nix-bench \
    --file ./default.nix -A bench.wide --samples 5 --no-record
```

### 5.5 The real-workload row — full system toplevel (the campaign finding)

The 17-attr suite is a package/leaf workload; the **real** deliverable is a full
system config's `system.build.toplevel`, whose evaluation is dominated by the
module-system fixpoint (`lib.evalModules`). Measured on builder-hil1-87eb5b00
(idle, `MIMALLOC_PURGE_DELAY=0`), IFD deps realized once via the oracle
(realization excluded from eval timings), native (HEAD 5c5a9c57) vs pinned C++
Nix 2.24.12, both `--option system x86_64-linux`:

| attr | native cold | C++ cold | ratio | native warm (root-cutoff) | native RSS | C++ RSS | mem ratio | parity |
|------|------------:|---------:|------:|--------------------------:|-----------:|--------:|----------:|:------:|
| `systems.server.build.toplevel` | 2.66s | ~0.53s | **4.9x slower** | **0.039s** | 28.6 MiB | 1044 MiB | **0.027x** | byte |
| `systems.edge.build.toplevel`   | 2.38s | ~0.50s | **4.8x slower** | **0.033s** | 30.1 MiB |  956 MiB | **0.031x** | byte |

**Reading it.** Native is **~4.8-4.9x slower cold** on the real workload — the
opposite sign from the leaf suite (native ~2x *faster*), because the
module-system fixpoint is the JIT-gap shape class (cf. `bench.compute.lambda-interp`
8.9x). But native uses **~35x less memory** (0.03x of C++'s ~1 GiB), and on
**warm repeats** the durable root-cutoff makes native **~14x faster** (~35-40 ms
vs C++ ~0.5s — C++'s eval cache does not help `nix-instantiate`, so its cold and
warm are both ~0.5s). Byte-parity is green on both. Caveat: the cache-enabled
**cold-populate** leg costs ~28-33s (a per-derivation persist write-amp storm,
measured pre-write-behind and under load) — that is cache I/O, not eval, and is
the target of the §3.2(b) write-behind work.

**Cold attribution** (`AOS_NIX_EVAL_STATS`, server, load-insensitive counts): the
2.6s is lambda-application + environment-frame churn — **3.18M function calls,
3.45M env-frame allocations (61 MB of frame slots), 8.6M thunk-state `Arc`
clones** — with the JIT tiers **idle** (zero promotions/dispatches on this shape),
memo cold, and the front-end only ~5-15% (~128 ms warm / ~377 ms cold-first).
Frame pooling is dead: an independent probe found **0 of 7,160** env frames
recyclable at pop (every frame is thunk-retained under Tier-A). The lever is
therefore reducing/reclaiming that retention, not pooling.

**Literal-apply beta-reduction is NEUTRAL here** (measured, `AOS_NIX_SIMPLIFY=1`
vs off at HEAD 31ee38a67, interleaved x3, parity stays byte-green): server 2.98s
vs 2.96s, edge 2.45s vs 2.46-2.81s (the off spread is variance). `Apply(lambda-
literal, arg)` frame-reuse does not fire on the module system, whose applications
are overwhelmingly of **variable-bound** lambdas (`evalModules` mapping module
functions), which the literal form does not catch. The attribution still points
at application/env-frame cost; the levers that reach it are general (not
literal-only) beta/inlining, env-release-on-force (memory), and getting the JIT
to fire on this shape — not literal-apply beta.

**Thunk-state Arc churn is also NEUTRAL on this wall (I1/I2 follow-up,
2026-07-14).** The lazy-Arc thunk record (I1, `cd6bdfa7a`; serial
`thunk_state_arc_clones` −93 %) and its K=4 side-map extension (I2,
`df0bf4b23`; parallel −61 %) eliminated the attribution table's "8.6M
thunk-state Arc clones" line item at the counter level with byte-identical
behavior — but an interleaved pre/post A/B on `systems.server.build.toplevel`
(same source, same protocol, x3 rounds, fresh cache per cold) measures cold
wall **neutral** (pre 17.37s vs post 17.43s medians on a shared builder;
warm identical). The churn was real and is gone, but it was never
wall-dominant on this shape: an Arc clone is an uncontended atomic increment,
and 8.6M of them is tens of milliseconds, not seconds. Consequences: (a) the
counter deltas remain the correct *regression guards* (reintroduced churn is
still waste), but no remaining wall claim rests on I1/I2; (b) the same
suspicion now applies to the frame-allocation line item — **measure the
per-frame cost before building I3 (frame-alloc fast path) / I4
(env-release)**, since 3.45M allocations may likewise be a counters-large,
wall-small item. The load-bearing levers for this shape remain JIT coverage
of the module-fixpoint shape class and the heap-image prelude snapshot
(doc 31 §1).

### 5.6 The carrier matrix — one-word variant vs baseline (S5 gate, 2026-07-12)

First full both-carrier comparison at one HEAD (Linux builder, quiet,
5-sample medians, `AOS_NIX_NATIVE=1 AOS_NIX_JIT=1`, pinned 2.24.12 oracle),
after S4b made the JIT fully live on the one-word carrier (546/546
full-corpus byte-green on both carriers). Ruling: **NO-GO for carrier
promotion** (cutover plan §S4b/S5 status). Key rows (variant/baseline time
ratio; peak RSS variant vs baseline):

| leg | var/base cold | var RSS | base RSS | note |
|---|---|---|---|---|
| pkgs.zlib / openssl | 1.06x | 93 MiB | 95 MiB | residual carrier tax, unattributed |
| bench.wide-eval | 1.075x | 208 MiB | 228 MiB | the memory win holds |
| compute.tak | **0.87x** | 41 MiB | 41 MiB | variant faster |
| compute.fib | 1.07x | 41 MiB | 41 MiB | tier-2 native on both |
| compute.sum-fold | **290x** | 1543 MiB | 41 MiB | DISQUALIFYING — wide-int cliff |
| compute.qsort | 1.26x | 1543 MiB | 486 MiB | same cliff (LCG intermediates) |
| compute.string-builder | 1.11x | — | — | ~7.4% of it is the B1 FlatBytes lookup |

The `sum-fold` cliff attribution and the fix plan live in the cutover plan
§S4b status block and `design-notes/decoded-core-tier2-spec.md` (task #30):
the wide operator literal `2654435761` declined lowering → the tier-2 fold
blacklisted (0 promoted / 0 dispatched / 7 blacklisted) → the interpreted
fold boxed every wide intermediate (3M thunks / 6M values / 876 MB heap;
hash-consing cannot help distinct accumulator streams). Wide literals and
loop intermediates never materialize as runtime values and therefore need
no inline word — the decoded-core emitters remove both the decline and the
boxing for natively-run bodies.

**RE-RUN (2026-07-13, after decoded-core #30 + the decode-accessor inline
pass #31 + the incremental HAMT insert): CLEAN SWEEP.** Cold var/base
medians: sum-fold **0.948x** (was 290x; qsort RSS 412 vs 484 MiB), qsort
0.985x, tak 0.908x, string-builder 0.978x, lambda-interp 0.983x, packages
1.007-1.013x, wide 1.017x at 208 vs 220 MiB; the attr-fixpoint cold
outlier re-measures 0.91x at 8 samples. The variant wins or ties every leg
within noise while holding the memory advantage — the S5 kill-date
criterion's performance clause is met (promotion ruling pending the fuzz
matrix + the full-corpus re-anchor; see the cutover plan §S4b/S5).

**Strict-JSON fuzz-parity matrix (2026-07-13, the S5 conformance-breadth
leg): CLEAN SWEEP — this closed the ruling to GO.** The `parity_json` fuzz
corpus is the package-derived adversarial seed set (`aos nix-fuzz-corpus
--clean` → 549 generated `# aos-nix-fuzz-source` seeds, each an
`import default.nix` + `getAttr pkgs.<x>` full-package eval defaulting to
`system = "x86_64-linux"`; the pinned nix lang corpus was not local so the
count is package-only, short of the ~648 with `AOS_NIX_LANG_TESTS`). It is
replayed as a strict-JSON differential vs the pinned 2.24.12 oracle through
the CLI gate `aos nix-diff --eval-json --eval-json-corpus
fuzz/corpus/parity_json/generated` (the same path as
`checks.integration.aos-eval-json-corpus-smoke`), NOT the ASAN fuzz binary —
a full `pkgs.edk2` eval exceeds libfuzzer's 2048 MiB default RSS under ASAN
(2127 MiB; a memory ceiling, not a divergence — raise with
`-rss_limit_mb=8192`), and IFD only resolves on Linux, so the matrix runs on
the builder. Crucially the harness must select the execution tier: the fuzz
target's `native_options_from_source_config` (and the CLI's
`NixEvalConfig`→`TreeWalkOptions` map, `aos-core/src/nix/eval.rs`) apply
`AOS_NIX_JIT`/`AOS_NIX_PARALLEL`/`AOS_NIX_GC` to the native evaluator — without
that the sweep silently runs serial + no-JIT and would miss the one-word
carrier's JIT-path code (stack maps, decoded-core emitters, deopt), a nominal
gate rather than a real one.

| carrier | leg | corpus | vs pinned 2.24.12 oracle |
|---|---|---|---|
| one-word variant | serial (no JIT) | 549 generated | **549/549 matched**, exit 0 |
| one-word variant | JIT (`AOS_NIX_JIT=1`) | 549 generated | **549/549 matched**, exit 0 |

Baseline legs were omitted as redundant: the darwin language-seed replay
already established variant/baseline outcome-identity (4/5 byte-matched,
`derivation.seed` failing identically on both carriers with the
carrier-independent "native evaluator does not yet support effectful
expression evaluation" limitation), so variant-vs-oracle is the authoritative
gate. Both legs matched byte-for-byte at HEAD `ef1dce36b`; the flip to
`candidate_c_value` as the shipped carrier landed at `5c22a8bab`. Ruling:
**GO for carrier promotion** (cutover plan §5).

---

## 6. The measure-first principle in practice

The measure-first characterization (defined in
[motivation and goals](01-motivation-and-goals.md) §5) is not a one-time
ceremony. This document is where it is *operationalized* into a standing
discipline.

### 6.1 The opening measurement (phase 1 deliverable)

Before optimization work is ordered, phase 1 produces the baseline the
characterization needs:

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

   CHARACTERIZE:
      eval-dominated short/repeated workloads => prioritize G2/G3/G4 first
      build/I/O-dominated long realizations   => avoid false global claims;
                                                validate repeated/no-op eval wins
```

This is also the phase that builds the tree-walk oracle and the `.drv`-diff
harness *first* — so that the baseline number (which the characterization
needs) and the parity proof (which C1 needs) both exist before a single
Cranelift instruction is emitted. The build order is fixed by the
characterization (see
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

### 7.1 The internal differential fuzzer (optimized tier vs the oracle)

Beyond the enumerated corpus, aos-nix fuzzes the **internal** differential: a
generator emits random (but valid) Nix expressions, both the optimized tier and
the tree-walk oracle evaluate them, and any disagreement is a bug. The same
generator feeds the `cargo fuzz` targets named in
[integration with AOS](14-integration-with-aos.md) §9.3 (value decode, GC, ATerm
round-trip). The oracle here is *internal* (tier-0 tree-walk), so this fuzzer's
findings are by construction JIT-tier or whole-program-analysis bugs — the same
class §7's trust gradient localizes — never serialization or string-context
bugs, which only the §2 gate's external oracle can surface. Fuzzing is how we
attack the long tail that the enumerated corpus and even shadow mode cannot reach
— expressions AOS does not yet contain but the language permits.

### 7.2 The parity fuzzer (aos-nix vs C++ Nix)

The §7.1 fuzzer cannot catch a bug that is present in *both* aos-nix tiers — if
the optimized tier and the oracle agree with each other but both diverge from
C++ Nix, the internal differential is silent. The high-value fuzzer therefore
uses C++ Nix itself as the oracle: a **differential parity fuzzer** of aos-nix
against `nix-instantiate`. It is the fuzzing analogue of the §2 `.drv`-diff gate
— same external oracle, same byte-equality assertion — but driven by *generated*
expressions rather than the AOS corpus, so it explores language constructs AOS
happens never to write.

```text
   internal differential (§7.1)  ──  optimized tier   vs  tree-walk oracle
                                     (finds JIT / analysis bugs)

   PARITY fuzzer        (§7.2)  ──  aos-nix (whole)   vs  C++ nix-instantiate
                                     (finds bugs SHARED by both aos-nix tiers:
                                      serialization, context, ordering, FOD hash)

   the two oracles are different on purpose — neither subsumes the other.
```

Four properties make the parity fuzzer find real bugs instead of burning CPU on
inputs C++ Nix and aos-nix both reject at the parser:

- **Structure-aware generation.** The fuzzer does *not* feed pseudorandom bytes
  (which a Nix parser rejects almost immediately, exploring nothing). Instead an
  `Arbitrary`-derived (or grammar-based) generator emits *valid* Nix ASTs —
  attrsets, `rec`, `let`/`with`, fixpoints, function patterns (`@`-binds,
  defaults, ellipses), string interpolation and the **string contexts** it
  produces, and the full operator set (`//`, `++`, `?`, `==`, arithmetic). The
  generator works through the `arbitrary` crate's `Unstructured` wrapper, the
  thin layer the rust-fuzz ecosystem uses to turn a fuzzer's raw byte buffer
  into a typed, well-formed value — so coverage feedback still drives generation
  while every emitted expression is syntactically legal. Emitting valid ASTs is
  what lets the fuzzer go *deep* (into evaluation and `.drv` emission) rather
  than *shallow* (bouncing off the parser).
- **Coverage-guided.** The fuzzer is run under `cargo-fuzz`/libFuzzer (LLVM's
  coverage-guided engine, the rust-fuzz default) — and optionally AFL++ via
  `afl.rs` — so it preferentially mutates toward inputs that reach *new
  evaluator code paths* (a primop branch, a coercion edge, an attrset
  hidden-class transition) rather than re-treading covered ground. Coverage is
  measured over the aos-nix evaluator, so "new coverage" means "a corner of the
  evaluator the AOS corpus never forced."
- **Seeded by the real corpus.** The seed corpus is the §2.7 derived corpus —
  the nixpkgs-shaped AOS package-set expressions plus the conformance corpus
  (§3). Mutation starts from real, idiomatic Nix and walks outward, so the
  fuzzer spends its budget near the language as actually written rather than in
  the pathological-but-irrelevant fringe.
- **Automatic test-case reduction.** Any divergence is reduced to a *minimal*
  reproducer before it reaches a human: libFuzzer's built-in minimization
  (`-minimize_crash`) or AFL++'s `afl-tmin` shrinks the failing expression to the
  smallest input that still diverges. Whether byte-level minimization suffices or
  a Nix-aware (AST-level) reducer is needed is decision **R-13** in
  [decision register](19-decision-register.md) and open question 5 below — the
  AST generator already gives us the structure a smarter reducer would exploit.

A parity-fuzzer divergence feeds the *same* structural-diff localization (§2.3)
and root-vs-contaminated bisection (§2.4) as a corpus divergence: it is a `.drv`
byte mismatch like any other, just discovered by a generator instead of the
package set.

### 7.3 Property-based tests for the slippery invariants

Fuzzing finds *divergences*; property-based tests pin *invariants* — the
properties that must hold of aos-nix's output regardless of the generated input,
several of which are too subtle to catch by eyeballing a `.drv` diff. These run
under `proptest` (Strategy-based generation with automatic shrinking; chosen over
`quickcheck` for its per-value strategies and stronger shrinking, which matter
when a counterexample is a whole Nix expression). Each invariant below is stated
as a property checked across `proptest`-generated inputs:

| Invariant | Property (holds for all generated inputs) |
|---|---|
| **String-context propagation** | for any expression `e` and any context-preserving operation `op` (`substring`, `++`, interpolation, `replaceStrings`), `context(op(e)) == context_cpp(op(e))` — the store-path reference set carried by the string matches C++ Nix exactly (the [doc 02 §5.3](02-compatibility-constraints.md) bug class the `.drv` gate exists to catch) |
| **Attribute collation / iteration order** | for any set of attribute names, aos-nix's iteration order (which fixes `env`-block and `builtins.attrNames` order) equals C++ Nix's symbol collation — the [doc 09](09-attribute-sets-hidden-classes-and-inline-caches.md) ordering the structural diff blames on `env`-block mismatches |
| **Hash determinism** | for any derivation expression, two independent aos-nix evaluations produce byte-identical store paths and `.drv` bytes (no map-iteration or allocation-address nondeterminism leaks into output) |
| **Derivation-env ordering** | for any `derivation` arg attrset, the emitted ATerm `env` entries are ordered identically to C++ Nix — a stronger, derivation-specific case of the collation property, since `env` order is a Merkle input (see [doc 11](11-derivation-and-store-compatibility.md)) |
| **`//` update semantics** | for any two attrsets `a`, `b`, `a // b` has exactly `b`'s value on shared keys, `a`'s elsewhere, the union of keys, and the correct merged context — right-bias and key-union as C++ Nix defines them |
| **`++` concat semantics** | for any two lists, `xs ++ ys` preserves order, length (`len xs + len ys`), and element identity/context with no thunk-forcing side effect the spec does not require |

The property tests run against the tree-walk oracle (the `miri`-clean program of
§7, so the properties are checkable under sanitizers) and, where the property
references C++ Nix behavior, against `nix-instantiate` as in §7.2. They occupy
the rung between the enumerated conformance suite (§3, fixed inputs) and the
parity fuzzer (§7.2, unbounded inputs): *bounded* generation aimed at *named*
invariants, with shrinking that hands back a minimal counterexample for free.

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

### 8.1 The cutover gate: one falsifiable bar for flipping default-on

The phase mapping above describes the *staging*; this subsection names the
single, **falsifiable** bar that must hold before `AOS_NIX_NATIVE` flips from
default-*off* to default-*on*. It is the operational form of success criterion
**C1** and the decision in [integration with AOS](14-integration-with-aos.md) §7:
a checklist whose every item is a measurable harness result, not a judgment call.
The cutover is permitted **iff all** of the following are simultaneously true:

- [ ] **Full-closure byte parity.** 100% of the §2.7 auto-derived corpus is
      `.drv`-byte-green against C++ Nix on the **full closure** — every package,
      every `systems/` toplevel, and the entire toolchain ladder (source
      bootstrap, `gcc3_4`→`gcc14`, mrustc→rustc, JDK 8→25, Bazel, LLVM). Zero
      divergent root nodes (§2.4). This is C1 stated as a number: not "98%," but
      every node in every closure.
- [x] **Conformance runner checkpoint recorded.** The `lang_conformance` runner
      reuses the C++ Nix language suite (§3) in all four categories
      (`eval-okay`/`eval-fail`/`parse-okay`/`parse-fail`), runs a local fixture
      covering those categories by default, and, when `AOS_NIX_LANG_TESTS` is set
      to the pinned corpus, checks the exact Nix `2.24.12` case-name snapshot and
      allowed skip set. The recorded configured checkpoint is `208 passed`,
      `1 skipped`, `0 failed`; the remaining skip is upstream `.exp-disabled`,
      with no local `LANG_CASE_EXCLUSIONS` entries (§3.4, criterion **C2**
      support).
- [ ] **Cutover-time conformance green remains.** At the default-on decision
      point, CI/gating must run the configured C++ Nix language suite for the AOS
      subset and require every supported case green with only documented,
      intentional skips; no silent omissions against the pinned case snapshot
      (§3.4, criterion **C2**).
- [x] **Fuzz/property substrate wired.** The internal differential oracle and
      `fuzz/internal_diff_raw` scaffold, the `fuzz/parity_json` scaffold with
      checked-in source seeds, generated §2.7 source-corpus population via
      `aos nix-fuzz-corpus`, C++ comparison conditional on `AOS_NIX_ORACLE`, and
      bounded `proptest` invariant tests are wired for the P1 tree-walk layer
      (§7.1-§7.3). Optimized-tier fuzzing remains dormant until P6/P7 tiers
      implement real `InternalDiffTier` candidates.
- [ ] **Fuzzing quiescence remains.** After the last evaluator-affecting change,
      accumulate the required parity-fuzzer CPU budget against C++ Nix with zero
      new divergences, keep the internal differential fuzzer active for any
      optimized tiers that exist, and keep property tests green before default-on
      (§7.1-§7.3). "Zero new divergences" resets the clock on any evaluator
      change — a late fix re-arms the fuzzing budget.
- [x] **Shadow-mode implementation substrate wired.** `AOS_NIX_NATIVE=shadow`
      selects `ShadowEval`; `NixCli` remains authoritative, the same file/raw
      expression is evaluated through `NixNative`, `.drv` closures or strict JSON
      values are compared, and match/divergence/incomplete counters are recorded
      without returning native output or materializing it into the store on the
      shadow path (§2.6; [14 §5.1](14-integration-with-aos.md#51-why-shadow-mode-is-the-rollout-workhorse)).
- [ ] **Shadow-mode soak remains.** Run shadow mode for at least **4 weeks**
      across at least **10,000** real CI/fleet evaluations with **zero**
      divergences reported before rollout credit/default-on progression; real
      traffic, not the enumerated corpus (§2.6, §8.1).
- [x] **Benchmark/measurement substrate wired.** `aos nix-bench` records
      parity-gated cold samples over the P1 real-workload corpus plus diagnostic
      microbenchmarks, with `NIX_SHOW_STATS` deltas, commit-keyed history,
      regression blocking, and perf-win admissibility tooling; `aos nix-measure`
      records eval/build phase attribution plus cold/warm samples for the
      non-diagnostic real-workload measure-first characterization (§5, §6.1).
      This supports the benchmark premise but does not establish a speed win.
- [ ] **Benchmark premise result remains.** Before default-on, run the
      representative real AOS workload benchmark gate and show aos-nix at or below
      C++ Nix wall-clock with green `.drv` parity and explanatory counters; a
      correct-but-slower evaluator does not cut over (§5, §8.1).
- [x] **Fallback/verify substrate wired.** `NixCli` implements `NixEval` and
      remains the default/off-mode evaluator; native `On` mode owns a `NixCli`
      fallback through `NativeFallbackEval` for `Unsupported`/`Internal` native
      errors while semantic `EvalError` surfaces; native-control env vars are
      stripped from C++ Nix subprocesses; and `AOS_NIX_NATIVE_VERIFY` can compare
      native file/expression results against `NixCli` while recording
      match/divergence/incomplete counters ([14 §4-§7](14-integration-with-aos.md#the-nixeval-trait-and-nixcli-fallback-24)).
      This keeps the fallback path wired today but does not prove post-cutover
      permanence.
- [ ] **Post-cutover fallback-retention result remains.** After the default
      flips, keep `NixCli` as an exercised runtime escape hatch and oracle, keep
      `AOS_NIX_NATIVE_VERIFY` sampling/canary coverage enabled per the D→E
      rollout, and verify the fallback path has not been removed or bit-rotted.
      The cutover flips the *default*; it never deletes the escape hatch.

The thresholds are deliberately illustrative — 1,000 CPU-hours, 4 weeks, 10,000
evals are tunable knobs the team sets against observed flakiness and fleet size.
**The commitment is the *shape* of the gate, not the specific numbers:** byte
parity on the full closure, conformance, a fuzzing budget at zero divergence, a
shadow-mode soak at zero divergence, the performance premise, and a permanent
fallback — every one a falsifiable harness result. Any single unchecked box keeps
the default off. There is no override and no "ship it anyway," for the same
reason the gate is binary (§2.2): one foundational divergence is a full
from-source distribution rebuild (see
[compatibility constraints](02-compatibility-constraints.md) §3).

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
   ([14](14-integration-with-aos.md) §13); bumping it is a deliberate,
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

5. **Fuzzer reduction quality.** When the differential fuzzers (§7.1, §7.2) find a
   disagreement, the minimal reproducing expression must be small enough to
   debug. Whether libFuzzer's `-minimize_crash` / AFL++'s `afl-tmin` byte-level
   minimization suffices for Nix expressions, or we need a Nix-aware (AST-level)
   reducer, is decision **R-13** in [decision register](19-decision-register.md)
   and remains unsettled. *Open until the fuzzers are producing real findings.*

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
and an **internal differential fuzzer** catch optimized-tier bugs before they
reach the `.drv` boundary, while a **parity fuzzer** (structure-aware,
coverage-guided, corpus-seeded, auto-reducing) and **property tests** over the
slippery invariants (string context, attr collation, hash determinism, `//`/`++`
semantics) catch the bugs *both* aos-nix tiers share by diffing against C++ Nix
on generated inputs. All of it converges on **one falsifiable cutover gate**
(§8.1): full-closure byte parity, conformance green, a fuzzing budget at zero
divergence, a shadow-mode soak at zero divergence, the performance premise met,
and `NixCli` retained as a permanent fallback — every box a harness result, any
single unchecked box keeping `AOS_NIX_NATIVE` default-off.

**Performance — the defended budget.** `NIX_SHOW_STATS`/`NIX_SHOW_STATS_PATH`
supply the baseline phase-attribution that the **measure-first** discipline demands,
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

## Implementation checklist

Per-feature tracker for differential testing and benchmarking (the `.drv`-diff acceptance gate, conformance-suite reuse, the internal/parity fuzzers and property tests, eval statistics, per-commit benchmarking, and the cutover gate); master roll-up: [implementation checklist (all phases)](22-implementation-checklist-all-phases.md). Per the unlimited-budget mandate, every item here is in scope — including research-grade ones — built in dependency order and gated by the differential harness, never cut for scope.

This document *is* the gate. The differential `.drv`-diff harness is a **P1** deliverable built *before* a single Cranelift instruction is emitted, and it is the standing regression guard that holds parity invariant through every optimization phase — the absolute correctness gate the whole RFC is subordinate to (§1, §6.1).

### The differential `.drv`-diff harness — the acceptance gate (§2)

- [x] `diff_closure(oracle, cand, file, attr, mode)` over the `NixEval` trait, closure-complete (walks `inputDrvs` to the leaves), asserting store-path + ATerm-byte equality *and* error/no-error parity per node (§2.1) — **P1**, `S-2`/`C-18`; the harness is a third consumer of the `NixEval` seam ([14](14-integration-with-aos.md) §3).
- [x] `DiffMode::{Path, Byte, Structural}` — Path for triage, Byte as the authoritative gate, Structural parsing both ATerms via `nix-compat` to localize the first differing field and disambiguate the bug class (§2.3) — **P1**, `S-13`.
- [x] Root-vs-contaminated bisection: topologically order the divergent set, report nodes with no divergent input as the roots, collapse the contaminated rest; per-root self-contained reproduction (§2.4): `DrvDiffReport` classifies root versus contaminated divergence nodes, `aos nix-diff` renders both classes, and human/JSON reports carry the Nix file, attr, mode, eval policy/system/allowlist flags, copyable full-comparison reproduction command, exact root oracle/candidate pair, and pair-local byte/structural/input-output diff context. File-backed root pairs carry a direct `aos nix-diff --oracle-drv ... --candidate-drv ...` node-level rerun command; in-memory native/C++ closure bytes are persisted as JSON closure bundles, and root reports include `--oracle-drv-bundle`/`--candidate-drv-bundle` sidecars so the direct node rerun can traverse the exact logical closure without requiring those `.drv` files to exist on disk. Covered by `byte_mode_bundles_in_memory_root_artifacts_for_direct_reruns`, direct pair CLI bundle parsing, and bundle-backed JSON reproduction tests — **P1**, `C-18`.
- [x] Two incarnations over one implementation: the Rust integration test (`crates/aos-core/tests/drv_diff.rs`) runs through the hermetic `pkgs.aos`/flake `checks.aos` path with `cargoTestFlags = "--workspace --features aos-core/native-eval"`, and the `aos nix-diff` subcommand provides interactive localization over the same `diff_closure` implementation (§2.5) — **P1**, `S-2`.
- [x] The auto-derived corpus from the AOS package set: all packages, all `systems/` toplevels, the toolchain closure explicitly (source bootstrap, `gcc3_4→gcc14`, mrustc→rustc, JDK 8→25, Bazel, LLVM), plus the conformance corpus — grows automatically as AOS gains packages (§2.7). `aos nix-diff --smoke` runs the cheap `pkgs.zlib` witness through the same corpus reporting path for per-commit parity checks, while `aos nix-diff --all` auto-enumerates top-level `pkgs.*` derivations, overlays `EXPLICIT_TOOLCHAIN_CORPUS_ATTRS`, dynamically expands `stdenv.toolchainTiers.<tier>.<component>` roots for the GCC ladder, and, when `AOS_NIX_LANG_TESTS` points at an unpacked C++ Nix `tests/functional/lang/` directory, synthesizes a temporary `conformance.*` derivation attrset from supported, non-excluded `eval-okay` cases so the `.drv` byte gate also forces the configured language corpus through the normal `NixEval` seam. Each generated report carries its persistent temp file path for exact `aos nix-diff --attr=conformance.<case> -- <corpus.nix>` reproduction; unsupported command-line-only flags and `lang.sh` environment-sensitive cases remain covered by the dedicated conformance runner rather than silently translated. `--systems` enumerates every `systems.<name>.build.toplevel`; `--smoke` remains only a fast witness, not the acceptance gate — **P1**, `S-2`.
- [x] The binary all-or-nothing gate semantics: `aos nix-diff --all`/`--systems` aggregates every attr report through `corpus_failure`, and any failed attr or divergence returns a failing `NixDiffReportedFailure`/JSON `"matched": false`; there is no "98% passing" unlock for default-on (§2.2) — **P1**, `C-18`/`S-2`.
- [x] Budgeted full generated eval-json corpus in the Linux check graph: `aos nix-diff --eval-json --time-budget <SECONDS>` bounds a corpus replay by wall clock (deterministic seed order, no in-flight abort, skipped counts reported in human/JSON output, divergences in the compared prefix still fail), `aos nix-fuzz-corpus --exclude <ATTR>` (exact attr or dot-prefix) skips eval-time-IFD attrs a sandboxed store cannot realize, and `checks.integration.aos-eval-json-corpus-full` regenerates the automatic package/toolchain/system corpus from the sandboxed repo source plus the pinned-`2.24.12` conformance seed set (unpacked from `pkgs.nix.src`) and replays it against a throwaway sandbox-local store under a 900 s budget; `checks.integration.aos-drv-parity-representative` runs the `.drv` byte gate over the fixed zlib/openssl/coreutils/bash witness set with the same pattern. The three native divergences found by the first full run (hardening `concatStringsSep` thunk forcing, `builtins.match` POSIX-ERE bracket-backslash semantics, and `fromTOML` `5e22` float rendering) were fixed in `bd80675ea`; their temporary `TODO(RFC-0007)` exclusions were removed, leaving only explicit eval-time-IFD exclusions that neither evaluator can realize in the sandbox. `C-4` stays open until the full generated check is green in scheduled Linux CI — **P1+**, `C-4` groundwork, `S-2`.

### Conformance-suite reuse (§3)

- [x] Reuse the C++ Nix `tests/functional/lang/` corpus as Tvix/Snix does: reimplement `lang.sh` discovery + version-reactive skip logic, in all four categories `eval-okay`/`eval-fail`/`parse-okay`/`parse-fail` (§3.1, §3.2). `crates/aos-nix/tests/lang_conformance.rs` discovers the upstream category prefixes, parses `.flags`, honors `.exp-disabled`, applies a skip-rule table against pinned C++ Nix `2.24.12`, runs the configured `AOS_NIX_LANG_TESTS` full pinned corpus gate including `lang.sh`'s special non-eval `bad-drvPath` case, accepts duplicate strict-eval flags already covered by the runner (`--eval`, `--strict`) plus eval-fail trace-display flags when strict eval remains explicit (`--show-trace`, `--no-show-trace`), applies `--max-call-depth` to `TreeWalkOptions`, models eval-okay `-I` search-path flags plus `lang.sh`'s default `NIX_PATH=lang/dir3:lang/dir4`, supplies the hidden C++ Nix `corepkgs` lookup used by `<nix/fetchurl.nix>` without reflecting it through `builtins.nixPath`, honors lexical `__nixPath` overrides for angle-bracket imports, sets `HOME=/fake-home` and `TEST_VAR=foo`, pins evaluator `currentSystem=x86_64-linux`, lowers raw/XML/strict case paths through the Nix dialect, supports `--extra-experimental-features parse-toml-timestamps` via gated `fromTOML` timestamp decoding, supports the pinned `--arg`/`--argstr`/`-A` autoargs fixture shape, models the pinned digit-normalizing `.postprocess` script without executing fixture shell, supports XML expected-output cases, normalizes output paths the same way as `lang.sh`, and precisely skips unsupported capability-changing flags. The evaluator now grows segmented stacks behind every tree-walk node (256 KiB red zone, 2 MiB segments), so the known non-terminating recursive-lambda fixture keeps the production default `max-call-depth = 10000` and returns the evaluator error without a harness-only stack or reduced cap. Raw rendering also preserves logical non-empty attrset identity instead of treating structurally hash-consed peers as aliases; empty attrsets remain repeat-untracked like C++ Nix. The pinned `2.24.12` corpus gates at `208 passed, 1 skipped, 0 failed`; the remaining skip is upstream `.exp-disabled`, with no local `LANG_CASE_EXCLUSIONS` entries — **P1**, criterion **C2**; owned jointly with [20](20-nix-language-conformance.md)/[21](21-builtins-conformance.md).
- [x] Error-**class** parity (type stays type, `throw` stays `throw`, assert stays assert): `cpp_nix_error_classes_match_tree_walk` is a pinned-oracle/configured conformance gate for representative parse-fail, type-error, `throw`, assert, and `abort` failures, while error-**text** parity remains a non-goal for the first gate (§3.3, §3.4) — **P1**; the basis for the `EvalError`-vs-`Unsupported` fallback ([14](14-integration-with-aos.md) §6). Full upstream `tests/functional/lang` reuse remains tracked by the preceding corpus row.

### The tree-walk oracle and the fuzzers (§7)

- [x] Tree-walk oracle as the **internal** differential check: every optimized-tier thunk result diffed against the tier-0 oracle in test/fuzz configs; the oracle is `#![forbid(unsafe_code)]` and remains the miri-clean target for the conformance suite (§7). The P1 scaffold is `aos_nix::eval::internal_diff`: optimized tiers implement `InternalDiffTier`, `compare_raw_with_oracle` evaluates the same IR through the safe tree-walk oracle and the candidate tier, and returns a hard `InternalDiffError::Divergence` on byte mismatch. Unit tests exercise a matching fake tier and a divergent fake tier; there are no optimized tiers yet, so the hook is dormant until P6/P7 tiers wire their thunk/result paths into it — oracle **P1**, optimized-tier activation once tiers exist (**P6**/**P7**), `S-5`/`S-17`.
- [x] Internal differential fuzzer entry-point scaffold: `fuzz/internal_diff_raw` reuses the valid-expression generator and source-seed passthrough, lowers each case to IR, and runs `compare_raw_with_oracle` against a tree-walk mirror candidate. This keeps the `cargo fuzz` target, corpus loading, parse/resolve/lower handoff, and oracle-side raw rendering live before optimized tiers exist — scaffold **P1**, optimized-tier activation remains the following **P6**+ row.
- [ ] Internal differential fuzzer optimized-tier activation: random valid Nix expressions, optimized tier vs the oracle — by construction finds JIT/analysis bugs, never serialization/context bugs (§7.1) — **P6**+, feeds the `cargo fuzz` targets ([14](14-integration-with-aos.md) §9.3). Optimized P6/P7 tiers replace the scaffold mirror with their `InternalDiffTier` implementation before this row can be checked.
- [x] Parity fuzzer **P1 scaffold** (aos-nix whole vs `nix-instantiate`): structure-aware `Arbitrary`/grammar-based valid-AST generation, coverage-guided under `cargo-fuzz`/libFuzzer, source-seed passthrough for the §2.7 package/conformance corpus, automatic generated source-seed population from that corpus, and libFuzzer reduction for failures (§7.2). The scaffold lives in `fuzz/`: `parity_json` decodes either source-seed inputs (`# aos-nix-fuzz-source`) or generated valid JSON-producing ASTs through `arbitrary`, evaluates them with `NixNative::eval_expr`, and compares to pinned C++ `nix-instantiate --eval --strict --json` when `AOS_NIX_ORACLE` is configured. The checked-in seed corpus covers JSON attr/list output, attr update, reflected string context, and `derivationStrict`; `aos nix-fuzz-corpus --clean` writes ignored `fuzz/corpus/parity_json/generated/generated-*.seed` files from the same package/toolchain/system attr enumeration used by `aos nix-diff --all --systems`, while repeatable `--attr <ATTR>` renders explicit package/conformance-shaped source seeds for focused generated-corpus checks without enumerating the full package set. Generated seeds pin source imports to the effective eval system (`x86_64-linux` by default, or `--eval-system`) and record the generated seed's effective eval mode/system/restricted allowlist policy in `# aos-nix-fuzz-config ...` comments that the fuzzer applies to both native and C++ oracle evaluation; automatic conformance corpus generation still copies the configured generated conformance corpus to `generated-conformance-corpus.nix` beside those seeds when `AOS_NIX_LANG_TESTS` is set. `fuzz/Cargo.lock` pins the fuzz-only dependency set. Full fuzz-budget quiescence remains the separate acceptance criterion above (§8.1) — exercised through every later phase, `R-13`.
- [x] Property-based tests (`proptest`) for the slippery invariants: string-context propagation, attribute collation/iteration order, hash determinism, derivation-env ordering, `//` update and `++` concat semantics — bounded generation at named invariants with free shrinking (§7.3). `crates/aos-nix/src/eval/tree_walk/tests/properties.rs` covers context-free and context-bearing string propagation (`++`, interpolation, `substring`, `replaceStrings`), `builtins.attrNames` ordering, deterministic `builtins.hashString`, deterministic derivation ATerm bytes, raw ATerm derivation-env key order, RHS-biased attr update including context preservation, and list concat order/context identity against the tree-walk oracle; `generated_core_json_expressions_match_configured_cpp_nix` samples the generated attr/list/hash/context/derivation expressions against pinned `nix-instantiate` when `AOS_NIX_ORACLE` is configured — **P1**+.

### Eval statistics: where the time goes (§4)

- [x] `NIX_SHOW_STATS` / `NIX_SHOW_STATS_PATH` baseline capture (JSON, `jq`-queryable) on representative AOS workloads, parsed defensively against the single pinned Nix version (§4.1): `NixCli::instantiate_with_stats` sets `NIX_SHOW_STATS=1` plus a temporary `NIX_SHOW_STATS_PATH`, captures elapsed wall time, returns the raw stats JSON, prefers the stats file while falling back to stderr/stdout JSON extraction, accepts added fields by preserving the object and recognizing known stats keys, and fails loudly on missing/multiple stats objects. `aos nix-diff --oracle-stats` exposes the capture path for single attrs plus `--all`/`--systems`, JSON reports carry raw stats and elapsed time, and corpus reports aggregate captured count plus elapsed total/average. Covered by stats-file preference/fallback/parser rejection tests, non-UTF-8 stderr-with-file handling, single-report JSON tests, and corpus aggregation tests; this does not by itself complete the separate P1.5 characterization or aos-nix mirrored-counter rows — **P1**, `C-9`; the phase-attribution data the measure-first discipline consumes.
- [x] aos-nix mirrored counters named to parallel `NIX_SHOW_STATS` (`thunks_forced`/`allocated`/`elided`, `inline_cache_hits`/`misses`, `shape_transitions`, `gc_bytes`/`gc_pause_us`, `tier_promotions`, `deopts`, `cache_hits`/`early_cutoffs`, `force_cache_hits`/`misses`/`probes`, `force_cache_memoization_admits`/`bypasses`/`demands`, `heap_tier_b_admission_*`), surfaced through `tracing` (§4.2): `EvalStats` is returned on every owned tree-walk `EvalOutcome`, `TreeWalk::stats()` exposes live snapshots, and successful public evaluation paths emit the same field names through the `aos_nix::eval::stats` tracing target. The current P1 oracle increments thunk allocation/force/reuse counters, force-cache hit/miss/probe counters, force-cache memoization policy decision counters, shape-transition counters for uncached process-local shape-table edges observed while projecting flat attr allocations, parse-cache and `findFile` cache hit/miss counters, and heap chunk/reserved/used bytes from the bump arena; post-evaluation outcome/native stats also mirror heap Tier-B admission report counters when the metadata admission bridge runs. Later subsystem counters remain schema-stable zeroes until their subsystem lands (`early_cutoffs` **P2**, additional shape counters **P5**, tier counters **P6/P7**), so downstream diagnostics can diff the same field set from day one; `early_cutoffs` is the direct instrument for criterion **C4** ([24](24-observability-and-diagnostics.md) §7). Covered by `eval_outcome_reports_mirrored_stats`, `eval_stats_are_emitted_through_tracing`, the attrset thunks tests for nonzero active shape-transition counts, native Tier-B admission stats tests, and the full `aos-nix` crate test/source-size gates.

### Per-commit benchmarking — the defended budget (§5)

- [x] Windtunnel-style per-commit benchmark suite: re-run fixed eval benchmarks, record timings keyed by commit sha, warn/block on a statistically-significant regression annotated with the `NIX_SHOW_STATS` delta (§5.1) — **P1** scaffold, runs every later phase, `M-19` (noise band + runner pinning). `aos nix-bench` runs the fixed scaffold corpus (`pkgs.zlib` until the corpus row below expands it), captures per-sample wall time and raw `NIX_SHOW_STATS` via `NixCli::instantiate_with_stats`, appends JSONL records keyed by `git rev-parse HEAD` under ignored `.aos-benchmarks/nix-eval.jsonl` unless `--no-record` is set, compares against the previous matching commit with a configurable noise band plus z-score significance check, annotates wall-clock movement with numeric stats deltas, and turns regressions into a CI-blocking exit via `--fail-on-regression`. The full real-workload corpus and mandatory `.drv` parity gate remain the next two unchecked rows.
- [x] The benchmark corpus cold **P1** slice: full system-variant toplevel eval, toolchain-closure eval, leaf-package spread, and diagnostic microbenchmarks (§5.2). The default `aos nix-bench` base corpus now discovers every `systems.<name>.build.toplevel`, overlays the same explicit bootstrap/Rust/JDK/Bazel/LLVM toolchain roots used by `aos nix-diff --all`, dynamically expands `stdenv.toolchainTiers.<tier>.<component>` derivation roots, filters leaf-package spread attrs down to attrs that exist and are derivations, and writes a deterministic ignored diagnostic corpus covering attrset access, `map`/`genList`, and deep recursion. Every recorded benchmark carries `category`, `temperature`, file/attr, per-record eval context fingerprint, samples, summaries, and raw `NIX_SHOW_STATS`; explicit `--attr` remains the focused workload-selection override, with cold/warm record pairing described below.
- [x] The benchmark corpus warm split: the **cold-vs-warm split** of each workload that isolates the G2 incremental-cache win — the most-watched number — is now a first-class `aos nix-bench` record axis. The benchmark corpus expands every selected workload, including explicit `--attr` runs, into paired `category:cold:<attr>` and `category:warm:<attr>` specs; warm specs perform one unrecorded priming pass before capturing recorded samples, and history comparison keys include `temperature`. `--changed-tree` additionally runs a parity-guarded 8-group/96-leaf warm fixture through unchanged, unused/forced/root/shared comments, import-edge, one/scattered/shared value mutations, reporting immediate and settled C++/aos timings plus admission/materialization/cutoff counters. The 2026-07-10 three-sample `b6926d80d`→`0c80cf41c` A/B reduced settled aos wall time by 23-43% across all nine scenarios and unchanged forced work from 196,854 thunks to 150; the final aos/C++ settled ratios were 1.41-3.04 on this local noisy host. This adds the stable warm-cache setup/labels and mutation-locality evidence required for P2 benchmarking; CI wiring and the broader cutover gate remain separate rows.
- [x] Honest cold/warm via paired cycles (schema v4). The pre-v4 "cold" leg was not cold: one native evaluator instance was reused across every spec and sample (the parity gate ran first and warmed it), so after the run's first eval every "cold" sample was in-process warm and cold means were roughly `(1 cold + N-1 warm)/N`. `aos nix-bench` now measures each attribute as one temperature-neutral spec run through `N` paired cycles: each cycle builds a **fresh** evaluator whose durable caches (parse cache, eval persist cache, root-cutoff records) point at a fresh temp dir, times the first `instantiate()` as the **cold** sample, then times a second `instantiate()` on the now-warm instance as the **warm** sample, and drops the instance and its temp caches — so cross-spec/cross-sample contamination is structurally impossible while in-run caching within a single eval stays legal. The parity gate runs on its own long-lived instance, never a cycle instance, so it cannot pre-warm the first cycle's cold sample. The C++ oracle has no in-process warm state (a fresh `nix-instantiate` subprocess per call), so it is sampled once per attribute and its summary is shared as the denominator for both records; the warm ratio is therefore `warm_native / cold_oracle`. The `with_warm_split` corpus expansion and the warm priming pass are removed (one spec per attr; the driver emits both records). Because this redefines **both** temperatures, every record carries a `temperature_semantics` marker (`paired-cycle-cold-v2` / `paired-cycle-warm-v2`; pre-v4 records default to `in-process-<temperature>-v1`) that the history comparison key requires to match, so a v4 true-cold number is never silently compared against a pre-v4 fake-cold baseline. The native summary also gains `median_seconds`, robust to the host-load spikes that skew the mean on a contended machine. Each cycle honors the base config's cache posture exactly, so cold measures what a real first eval pays -- no more, no less. In the **production default** (no `AOS_NIX_CACHE`), `native_cache_root` is `None`, so the durable persist/eval-cache write-through and root-cutoff are off: the cycle adds no cache dir (a fresh instance is already cold), cold is a true cache-less first eval, and warm is the same instance's in-memory second eval (a modest, honest speedup). Adding a temp cache dir here would have made cold pay per-force durable writes a stock cold eval never pays -- write amplification, not eval cost, and the reason the first v4 re-baseline was corrected. When `AOS_NIX_CACHE` **is** set, the cycle redirects the durable cache to a fresh temp dir so cold starts empty (paying the genuine first-eval write cost) and warm is answered from the cache the cold run just populated, *including* the root-cutoff record. **Cold is always the eval-performance signal** (a cold regression is an interpreter/eval slowdown); **warm is the real-world repeat-instantiate signal** whose cache path depends on the config -- in-memory-only by default, cutoff/replay when a durable cache is configured. The two legs are read separately, and parity is proven once per attr on a full-eval instance, so a root-cutoff-answered warm sample (which returns the stored root without re-deriving the closure) never weakens it. History restarts on the honest v4 semantics, so early-run cold numbers legitimately look slower than pre-v4 records, whose "cold" was in-process warm.
- **The standard 17-attr benchmark suite** (the headline geomean suite [31](31-substrate-optimizations.md) cites): **9 leaf packages** — `pkgs.zlib`, `pkgs.xz`, `pkgs.bzip2`, `pkgs.openssl`, `pkgs.curl`, `pkgs.sqlite`, `pkgs.jq`, `pkgs.socat`, `pkgs.git` — plus **8 toolchain roots** — `stdenv.stdenv`, `stdenv.bash`, `stdenv.coreutils`, `pkgs.gcc`, `pkgs.glibc`, `pkgs.binutils`, `pkgs.rust`, `pkgs.openjdk`. Run it as `aos nix-bench -A <each> --samples 3` (the paired-cycle driver emits the cold and warm record for each). The `bench.compute.*` micro suite (`fib`, `tak`, `sum-fold`, `qsort`, `string-builder`, `attr-fixpoint`, `lambda-interp`, `hash-loop`, `all-any`) is an optional compute-coverage add-on, not part of the headline suite. This is the canonical list; cross-day comparison tables should use it so the `native/oracle` geomean is like-for-like.
- [x] Every benchmark run gated on the `.drv` parity check (shadow-style) before recording a timing — a number from a divergent evaluator is meaningless; no target multiple committed up front, baseline sets the target (§5.3) — **P1**, `S-18`/`S-2`. `aos nix-bench` now selects the raw native diff candidate with the same eval config as the timed oracle run, defaults ambient eval to explicit impure eval like `aos nix-diff`, runs byte-mode `diff_closure` for each benchmark spec before any `NIX_SHOW_STATS` sample is captured, fails without recording history on divergence, stores the successful parity proof (`mode = "byte"`, candidate name, roots, divergence counts) in each benchmark record, and only compares regressions against prior records with matching successful parity mode/candidate.

### The measure-first principle and the cutover gate (§6, §8)

- [x] Opening measurement tooling for the **P1.5** characterization (§6.1) — phase-attribute wall-clock (`nix-instantiate` vs `nix-build`), `NIX_SHOW_STATS` breakdown, and cold-vs-warm capture with a recorded action field. `aos nix-measure` reuses the real-workload portion of the benchmark corpus, captures cold and warm `nix-instantiate` samples with raw `NIX_SHOW_STATS`, times `nix-build --no-out-link` for the same workload, records eval/build fraction plus warm delta under ignored `.aos-benchmarks/nix-measure.jsonl`, emits an aggregate decision against `--min-eval-fraction` (default 0.50), can turn stop into a failing local policy check with `--fail-on-stop`, and excludes diagnostic fake-builder microbenchmarks from build-phase measurement — **P1.5** tooling, `S-18`/`M-1`/`M-2`/`M-3`.
- [x] The opening measurement baseline result: run the **P1.5** characterization on representative real workloads and record the actual eval/build/cold/warm breakdown. The committed record is `phase1-baseline.jsonl`; the written characterization is [phase1-baseline-characterization.md](phase1-baseline-characterization.md). Under the unlimited-budget mandate this result orders and parallelizes P2-P8; it does not decide whether those phases exist.
- [x] Perf-PR admissibility gate tooling for the standing rule (§6.2): `aos nix-bench --require-perf-win` turns the benchmark report into a hard admission check that requires green byte `.drv` parity, no significant regressions, at least one non-diagnostic workload with a thresholded wall-clock improvement, and a non-empty `NIX_SHOW_STATS` delta breakdown for the improving workload before the run can be treated as a perf win. The JSON report carries the same `admissibility` decision block for CI consumption — every phase, criterion **C6** tooling.
- [ ] The standing perf-PR admissibility rule wired into the repository CI runner: CI must invoke the perf-win gate on representative real workloads, and a missing green `.drv` gate (veto), real-workload wall-clock improvement (budget), or counter breakdown explaining the win (diagnosis) means the PR does not land as a perf win (§6.2) — every phase, criterion **C6**. This remains unchecked until the actual CI entry point exists in this repository and runs the gate, not just the local policy tooling.
- [ ] The single falsifiable cutover gate (§8.1) — full-closure byte parity (zero divergent roots, incl. the toolchain ladder), conformance green with documented exclusions, a fuzzing budget at zero new divergence (clock resets on any evaluator change), a shadow-mode soak at zero divergence, the benchmark premise met, and `NixCli` retained permanently — every box a harness result, any one unchecked keeps the default off (§8, §8.1) — `C-18`; unlocks rollout **Phase D** default-on for `instantiate`.

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
- Coverage-guided + structure-aware fuzzing in Rust (the §7.2 parity fuzzer:
  `cargo-fuzz`/libFuzzer, the `arbitrary` crate's `Unstructured`, AFL++/`afl.rs`,
  and crash minimization via `-minimize_crash` / `afl-tmin`):
  - Rust Fuzz Book — Structure-Aware Fuzzing —
    <https://rust-fuzz.github.io/book/cargo-fuzz/structure-aware-fuzzing.html>
  - "Announcing Better Support for Fuzzing with Structured Inputs in Rust"
    (the `arbitrary` + `Unstructured` design) —
    <https://fitzgen.com/2020/01/16/better-support-for-fuzzing-structured-inputs-in-rust.html>
  - `arbitrary` crate — <https://docs.rs/arbitrary/>
  - `cargo-fuzz` — <https://github.com/rust-fuzz/cargo-fuzz>
  - AFL++ — Fuzzing in Depth (corpus/test-case minimization, `afl-tmin`) —
    <https://aflplus.plus/docs/fuzzing_in_depth/>
- Property-based testing in Rust (the §7.3 invariant tests):
  - `proptest` crate (Strategy-based generation + shrinking) —
    <https://docs.rs/proptest/>
  - `proptest` vs `quickcheck` (per-value strategies, shrinking) —
    <https://altsysrq.github.io/rustdoc/proptest/0.8.7/proptest/>
