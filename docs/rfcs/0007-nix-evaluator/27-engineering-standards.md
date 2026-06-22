# RFC-0007 - Engineering standards and code quality

> Part of the RFC-0007 aos-nix documentation set. This document is the
> *implementor's manual*: the non-negotiable standards a contributor MUST follow
> when writing aos-nix code. Where the rest of the set says *what* to build, this
> document says *how to build it well* — crate layout, file size, documentation,
> error handling, logging, abstraction boundaries, performance discipline, test
> coverage, debugging affordances, and commit hygiene. It is a spec, not a survey:
> every rule here is binding.
>
> It binds directly to the workspace `CLAUDE.md` "Rust code style" and "Rust
> documentation standard" sections (docs.rs quality, `//!` crate/module headers,
> `///` on every public item, `# Errors`/`# Panics`, the fence-tagging gotcha, no
> clap container docs, avoid `unsafe`/no `unwrap`/`expect`) and *narrows* them for
> a crate set that the unlimited-budget mandate
> ([roadmap and risks](17-roadmap-and-risks.md) §0) expects to grow to hundreds of
> thousands of lines. Read it alongside
> [integration with AOS](14-integration-with-aos.md) §10 (the safe/unsafe fence
> this document makes *crate-level*),
> [observability and diagnostics](24-observability-and-diagnostics.md) (the miette
> and `tracing` decisions §5 and §3 enforce), and
> [differential testing and benchmarking](15-differential-testing-and-benchmarking.md)
> (the test surfaces, counters, and benchmark gate §7 and §8 demand).

## 1. Crate and directory structure

aos-nix is **not one giant crate.** It is a **workspace of focused crates**, and
that split is load-bearing for two independent reasons.

First, **the safe/unsafe fence is crate-level.** The `#![forbid(unsafe_code)]` /
`#![deny(unsafe_op_in_unsafe_fn)]` boundary that
[integration with AOS](14-integration-with-aos.md) §10 draws *through* aos-nix is
implemented here as a boundary *between crates*, not between modules inside one
crate. A crate either forbids `unsafe` entirely or it permits it under the
per-block `// SAFETY:` discipline. A reviewer reads one crate-root attribute and
knows which regime applies to every line in that crate — there is no
file-by-file ambiguity. This is what makes the tree-walk oracle a genuinely
`miri`-clean, sanitizer-clean island (it is its own crate) rather than a
hopefully-clean subtree of a crate that also contains the JIT.

Second, **it wins compile time at 100k+ LOC.** A monolithic crate recompiles
wholesale on every edit; a workspace of focused crates recompiles only the
touched crate and its dependents, and the safe crates (which dominate line count)
never pay for the Cranelift/codegen dependencies of the unsafe crates.

### 1.1 The crate split

SAFE crates carry `#![forbid(unsafe_code)]`. UNSAFE crates carry
`#![deny(unsafe_op_in_unsafe_fn)]` and the standing `unsafe` waiver of
[14](14-integration-with-aos.md) §10.

The crate set splits into three *bands* ([28](28-generalization-and-language-dialects.md) §3):
the language-agnostic ENGINE (the UNSAFE core), the language-agnostic CORE IR +
DIALECT INFRASTRUCTURE, and the NIX dialect. The `ratchet-*` crates carry no Nix
knowledge — they are the substrate, potentially extractable; the `aos-nix-*`
crates are the Nix dialect plus AOS integration. The band boundary coincides with
the safe/unsafe fence ([28](28-generalization-and-language-dialects.md) §3–§5).

```text
   ratchet/ + aos-nix/               workspace root (Cargo.toml [workspace])
   │
   │  ── ENGINE band (language-agnostic; the UNSAFE core) ──
   │
   ├── ratchet-value/     UNSAFE    tagged/NaN-boxed value repr, hash-consing
   │   ├── repr/                      (05) — bit-twiddling under // SAFETY:,
   │   ├── cons/                      #![deny(unsafe_op_..)]; the Nix
   │   └── ...                        string-context discriminator is dialect-supplied
   │
   ├── ratchet-gc/        UNSAFE    bump arena + precise copying collector,
   │   ├── arena/                     stack maps, write barriers (06)
   │   └── collector/
   │
   ├── ratchet-jit/       UNSAFE    Cranelift tier-1/tier-2 codegen, the
   │   ├── lower/                     runtime ABI, fn-ptr transmute+call (08)
   │   ├── runtime_abi/
   │   └── deopt/
   │
   ├── ratchet-cache/     UNSAFE    incremental demand-graph cache + the CA
   │   ├── demand/                    (value) store: mmap, zero-copy reads,
   │   ├── store/                     madvise, out-of-core spill (12); gates on
   │   └── castore/                   the open effect lattice (S-23), never interprets it
   │
   ├── ratchet-parallel/  UNSAFE    fibers (stack switch), Chase-Lev deques,
   │   ├── fiber/                     the lock-free CAS thunk protocol (13)
   │   ├── deque/
   │   └── thunk/
   │
   │  ── CORE IR + DIALECT INFRASTRUCTURE band (language-agnostic) ──
   │
   ├── ratchet-core/        SAFE    the generic Core IR: NodeKind taxonomy,
   │   ├── node/                      de-Bruijn resolution, the simplifier
   │   ├── resolve/                   *framework* + pass catalog (25, 26) — pure
   │   ├── simplify/                  IR-to-IR, #![forbid(unsafe_code)]
   │   └── serialize/                 IR cache wire format (owns a disk format)
   │
   ├── ratchet-dialect/     SAFE    the trait a language plugs into (28 §5):
   │   └── ...                        extra ops, effect members, primop table,
   │                                  rewrite rules, lowering hooks — registration
   │                                  -time, never `dyn` on the force path
   │
   ├── ratchet-oracle/      SAFE    the generic Core tree-walk interpreter —
   │   └── walk/                      the correctness reference (08, 15 §7); the
   │                                  miri/sanitizer-clean trusted core
   │
   │  ── NIX dialect band (a per-language band; repeats per future language) ──
   │
   ├── aos-nix-syntax/      SAFE    Nix lexer, parser, arena AST, source spans
   │   ├── lex/                       (04 frontend) — pure, #![forbid(unsafe_code)]
   │   ├── parse/
   │   └── ast/
   │
   ├── aos-nix-dialect/     SAFE    the Nix dialect: derivationStrict, `with`
   │   ├── builtins/                  lowering, the builtin table + per-primop
   │   ├── context/                   strictness, string-context semantics, Nix
   │   └── rules/                     effects, Nix rewrite RULES (list fusion)
   │
   ├── aos-nix-compat/      SAFE    glue to the pinned `nix-compat` crate:
   │   └── drv/                       Derivation build, ATerm, store-path
   │                                  hashing (11) — orchestration only, no
   │                                  reimplementation, #![forbid(unsafe_code)]
   │
   ├── aos-nix-harness/     SAFE    the differential .drv-diff harness, the
   │   ├── diff/                      conformance runner, fuzz/proptest drivers
   │   ├── conformance/               (15) — #![forbid(unsafe_code)]
   │   └── bench/
   │
   └── aos-nix/                     UMBRELLA crate — the public `Evaluator`
       └── src/lib.rs                 facade NixNative shims over (14 §4.2); wires
                                      the Nix dialect onto ratchet; re-exports the
                                      API, owns no algorithms — //! overview + map
```

`ratchet-core` owns the generic Core IR + the simplifier framework;
`aos-nix-dialect` owns the Nix-specific concepts — `DerivationStrict`, `with`,
the builtin table, string-context semantics, and the Nix rewrite rules.

The dependency direction is one-way: the SAFE frontend/core crates
(`aos-nix-syntax` → `ratchet-core` → `ratchet-oracle`) sit below the UNSAFE
engine crates, the umbrella crate sits on top, and `aos-nix-compat` and
`aos-nix-harness` are leaves the harness and the `NixNative` shim consume. The
dialect crates are SAFE leaves that *parameterize* the engine — never a build-time
dependency of it. No UNSAFE crate is a build-time dependency of the oracle or the
harness — that is what keeps the trusted core analyzable. The `ratchet-*` crates
carry no Nix knowledge whatsoever ([28](28-generalization-and-language-dialects.md) §3–§5).

This three-band topology is the *target* of the **Phase 1b** re-layering
([17](17-roadmap-and-risks.md) §6, [28](28-generalization-and-language-dialects.md) §10);
today's code is still a single `aos-nix` monolith, and the split below is what
Phase 1b carves it into.

### 1.2 The module-directory convention

Within a crate, **each subsystem is a module directory with a `mod.rs`**, never a
single sprawling `.rs` file. The `mod.rs` carries the subsystem's `//!` header
(§3) and re-exports its public surface; the focused submodules beside it own one
concern each. The crate root (`lib.rs`) carries the crate-level `//!` overview and
the crate-root safety attribute (`#![forbid(unsafe_code)]` or
`#![deny(unsafe_op_in_unsafe_fn)]`), and nothing else of substance — it is a map,
not an implementation.

## 2. File size limits

Long files are unreviewable and slow the incremental compiler. The limits:

| Bound | Lines | Action |
|---|---|---|
| Soft target | ~400-500 | the size a file should normally land at |
| Hard cap | ~800-1000 | exceeding it means **split into a `mod/` directory** |

One type or one concern per file wherever reasonable: the `Thunk` state machine,
the inline-cache state walk, a single simplifier pass, one primop family. When a
file approaches the hard cap, it is promoted from `foo.rs` to `foo/mod.rs` plus
focused children — the same module-directory convention as §1.2, applied
reactively.

The rationale is navigability, review, and compile-at-scale, not aesthetics. A
reviewer should be able to hold one file's concern in their head; the compiler
should recompile a small unit when one concern changes. These are soft *targets*
with judgment at the margin — a cohesive 550-line match arm is better than two
contrived 275-line halves — but the hard cap is a real ceiling, not a suggestion.

## 3. Code documentation

aos-nix is held to the workspace docs.rs-quality bar
([CLAUDE.md](../../../CLAUDE.md) "Rust documentation standard") with **no
exceptions for being a low-level evaluator** — a NaN-boxing routine is as
user-facing porcelain as a CLI flag. The binding rules:

- **Crate overview.** Every `lib.rs` carries a `//!` overview: what the crate
  does and a map of its modules and how they fit together.
- **Module header.** Every module file (`mod.rs` and every submodule) carries a
  `//!` header naming what the module owns and its key concepts.
- **Wire/disk-format modules show the format.** Any module that owns an on-disk or
  wire format renders that format in a *fenced example block* in its `//!` header.
  In aos-nix this is at least: the **ATerm** serialization
  (`aos-nix-compat::drv`), the **IR serialization** wire format
  (`ratchet-core::serialize`), the **CA store** / value-store packfile layout
  (`ratchet-cache::store`/`castore`), and **narinfo** wherever it appears. The
  format example is a data contract; it is the first thing a maintainer reads.
- **Every public item gets `///`.** A one-sentence, third-person summary line,
  then detail paragraphs only where behavior is non-obvious. Frequency: *every*
  public item. Scope: *all* public API is user-facing porcelain.
- **`# Errors` on every public fn returning `Result`,** describing the conditions
  that produce each error. **`# Panics`** wherever a panic is reachable (and in
  aos-nix, reachable panics should be vanishingly rare — see §4).
- **Document public struct fields.** Schema and config structs are data
  contracts; their field docs matter most. A public field whose meaning is not
  self-evident is undocumented at its peril.
- **`// SAFETY:` on every `unsafe` block.** In the UNSAFE crates,
  `#![deny(unsafe_op_in_unsafe_fn)]` forces every `unsafe` operation to be an
  explicit, individually-commented block stating the invariant it relies on and
  why it holds. This is the documentation counterpart of the §1 fence.

### 3.1 The fence-tagging rule is a build gate, not a style nit

**Tag every fenced code block** in rustdoc: `` ```text ``, `` ```rust ``,
`` ```no_run ``, `` ```ignore ``, `` ```toml ``. An *untagged* fence becomes a
doctest that the hermetic `pkgs.aos`-style build compiles and runs — so an
untagged format example or ASCII diagram is a **build failure**, not a cosmetic
lapse. Prefer `no_run` for runnable examples that touch the store or codegen;
prefer `text` for format dumps and diagrams. Add a runnable `# Examples` block
only when it compiles against the public API alone.

### 3.2 The clap caveat

Doc comments on `#[derive(Parser/Subcommand/Args)]` containers and their fields
become `--help` output. Do **not** add container `///` docs (document the
surrounding module instead); treat field doc edits as user-facing CLI changes and
keep them short, imperative, and accurate. This applies to the `aos nix-diff`
subcommand ([15](15-differential-testing-and-benchmarking.md) §2.5) and any
debugging flags §9 introduces.

## 4. Error handling

aos-nix models errors as *typed values*, never as stringly-typed escapes, and the
error type is itself a parity surface.

- **Library crates use `thiserror`.** Every library crate models its failure modes
  as a typed enum with `#[derive(thiserror::Error)]`. The core enums are real, not
  illustrative:

  ```rust,ignore
  /// An error raised while evaluating a Nix expression.
  ///
  /// The variant *is* the error class — the parity-relevant axis that the
  /// conformance and `.drv`-diff gates check (15 §3.3, 24 §3). Renaming or
  /// merging a variant such that a former `TypeError` surfaces as a `Throw`
  /// is a parity event; adding a `help` string to its `Diagnostic` impl is
  /// not.
  #[derive(Debug, thiserror::Error, miette::Diagnostic)]
  pub enum EvalError {
      #[error("expected {expected}, got {got}")]
      TypeError { expected: ValueKind, got: ValueKind, span: Span },
      #[error("attribute `{name}` missing")]
      MissingAttr { name: Symbol, span: Span },
      #[error("infinite recursion encountered")]
      InfiniteRecursion { span: Span },
      #[error("{message}")]
      Throw { message: String, span: Span },
      #[error("assertion failed")]
      AssertionFailed { span: Span },
      // ...
  }
  ```

  `ParseError` carries the source span of the first error
  ([24](24-observability-and-diagnostics.md) §4.3); `StoreError`,
  `CacheError`, and the rest follow the same pattern.

- **`anyhow` only at the binary/CLI boundary.** `anyhow::Result` is permitted
  *only* in the `aos`/`aos-core` integration layer (the `NixEval` impls, the CLI
  glue) where errors are about to be rendered and exit. It MUST NOT appear in the
  eval core: a `thiserror` enum that loses its variant to `anyhow::Error` has
  thrown away the class the parity gate reads. (The one sanctioned bridge is
  `NativeEvalError::Internal { message }` at the seam — [14](14-integration-with-aos.md) §6.1 — which exists precisely to corral
  "an aos-nix bug happened" at the boundary.)

- **Propagate with `?`. No `.unwrap()`/`.expect()` in production.** The workspace
  ban applies to aos-nix unchanged; the `unsafe` waiver of
  [14](14-integration-with-aos.md) §10 is about memory/codegen primitives and
  grants nothing for error handling. Tests and examples may `unwrap` where a panic
  is the intended signal.

- **Errors carry source spans** (`Span = (u32, u32)` byte offsets, [04](04-frontend-parser-and-ir.md) §3.1) so miette can render them against the
  original `.nix` ([24](24-observability-and-diagnostics.md) §4), and they must be
  **error-class-compatible with C++ Nix** ([15](15-differential-testing-and-benchmarking.md) §3.3). Error handling here is
  therefore *both* a quality concern *and* a parity concern: the enum is the place
  the two meet.

## 5. Structured logging

Internal diagnostics use the **`tracing` crate exclusively**
([24](24-observability-and-diagnostics.md) §7): spans with structured fields, with
target conventions like `aos_nix::eval`, `aos_nix::gc`, `aos_nix::jit`,
`aos_nix::cache`. Spans nest, fields are typed, and everything is `RUST_LOG`-
filterable and aggregatable.

The anti-pattern this section forbids is blunt: **no `println!`, no `eprintln!`,
no raw stdout/stderr writes anywhere in a library crate.** A diagnostic that
escapes through a raw print is unfilterable, untestable, and — worse for a
parity-gated tool — risks contaminating the user-facing stream. Library code that
"just wants to print something" is a bug; it wants a `tracing` event.

There is exactly **one** sanctioned user-facing stdout/stderr surface, and it is
*deliberate Nix-compatible output owned by the binary boundary* and by
[24](24-observability-and-diagnostics.md): `builtins.trace`/`traceVerbose` print
to stderr with C++ Nix semantics (and are pointedly *not* routed through
`tracing`, which would filter them away — [24](24-observability-and-diagnostics.md) §7.2), and the final evaluation result
is rendered at the binary. Nothing else writes to those streams.

`tracing` also carries the `NIX_SHOW_STATS`-style counters
([15](15-differential-testing-and-benchmarking.md) §4.2) — `thunks_forced`,
`inline_cache_hits`, `shape_transitions`, `tier_promotions`, `deopts`,
`cache_hits`, `early_cutoffs` — and the seam counters (native successes,
fallbacks, shadow divergences). Because these are `tracing` fields rather than ad
hoc prints, the before/after comparison against C++ Nix is a field-by-field diff.

## 6. Trait abstractions

Use traits **liberally for swappable subsystem boundaries, but never on the hot
path.** The distinction is the whole rule and must be applied consciously.

**Traits for boundaries and swappability.** Where a subsystem has more than one
real implementation we intend to swap between, a trait is the right seam:

| Trait | Swaps between | Owning doc |
|---|---|---|
| `NixEval` | `NixCli` ↔ `NixNative` ↔ `ShadowEval` | [14](14-integration-with-aos.md) §3 |
| an allocator/GC trait | bump arena ↔ generational ↔ concurrent moving | [06](06-memory-management-and-gc.md) |
| `StorageEngine` | packfile ↔ LMDB/heed ↔ redb | [12](12-incremental-evaluation-cache.md) |
| a tier/executor trait | oracle ↔ tier-1 baseline ↔ tier-2 optimizing | [08](08-execution-tiers-and-cranelift.md) |
| primop registration | the `aos_prim_<name>` registry | [10](10-primops-and-runtime-abi.md) |
| the hashing policy | xxh3 (in-process) ↔ blake3 (durable) ↔ SHA-256 (Nix) | [18](18-glossary.md) invariant 5 |

These seams are entered rarely relative to the work they gate (one `NixEval`
dispatch per top-level instantiate dwarfs a store write; the GC trait is consulted
at allocation-arena granularity, not per value), so a vtable indirection there is
free.

**Monomorphized concrete code for the hot path.** The forcing/value inner loop —
`force`, the WHNF tag test, `select` against a hidden class, arithmetic — uses
*concrete types and generics/monomorphization*, **never `Box<dyn>` dynamic
dispatch.** A virtual call in the inner force loop defeats the entire performance
goal: it blocks inlining, poisons the branch predictor, and cannot be specialized
by the tier-2 JIT. State this explicitly in code review: *if a trait object would
be called once per forced thunk, it is wrong.* Where polymorphism is genuinely
needed on a warm path, reach for a generic (`fn force<E: Executor>`) that
monomorphizes, an enum dispatch, or a Cranelift runtime symbol — not a `dyn`.

## 7. Performance considerations

The hot path is held to a standing performance discipline, because aos-nix's
*premise* is that it is faster than C++ Nix ([15](15-differential-testing-and-benchmarking.md) §8.1).

- **Avoid heap allocation, dynamic dispatch, and bounds checks on the hot path**
  where they are provable to be redundant. The value, attrset, and IR layouts
  ([05](05-value-representation.md), [09](09-attribute-sets-hidden-classes-and-inline-caches.md),
  [25](25-intermediate-representation.md)) are already designed data-oriented for
  this; respect that design rather than wrapping it.
- **`get_unchecked` only with a `// SAFETY:`** that names the invariant proving
  the index in-bounds, and only where profiling shows the bounds check matters.
  An unchecked index "because it's probably fine" is rejected; an unchecked index
  with a proof from the resolver's slot allocation ([04](04-frontend-parser-and-ir.md) §6) and a benchmark delta is fine.
- **`#[inline]` judiciously** — on the genuinely hot, small functions (`force`'s
  fast path, the tag test), not reflexively on everything.
- **Document perf-critical invariants** in the code: the comment that explains
  *why* a layout is shaped the way it is, or why a branch is ordered the way it
  is, is part of the contract.

**Every perf-affecting change carries a measured delta.** This is criterion **C6**
([15](15-differential-testing-and-benchmarking.md) §6.2) made an engineering
standard: a perf change ships with (a) a `criterion` microbenchmark localizing the
win and (b) movement on the per-commit benchmark ([15](15-differential-testing-and-benchmarking.md) §5), with the
`NIX_SHOW_STATS`-style counter breakdown explaining *why* it helped. **No
regressions** — the per-commit benchmark is a *gate*: a commit that keeps the
`.drv` gate green but slows real-workload eval is blocked just as firmly as a
divergent one. No optimization ships on faith.

## 8. Test coverage

Testing is layered, and the layer a piece of code belongs to is determined by what
it owns.

- **Unit tests per module** — the local invariants, beside the code.
- **The differential `.drv` harness + the conformance suite** ([15](15-differential-testing-and-benchmarking.md), [20](20-nix-language-conformance.md),
  [21](21-builtins-conformance.md)) as the **acceptance** layer — the external
  parity gate, not a test among tests.
- **`proptest` property tests** for the slippery invariants — string-context
  propagation, attr collation, hash determinism, `//`/`++` semantics
  ([15](15-differential-testing-and-benchmarking.md) §7.3).
- **`cargo-fuzz` targets** — value decode, GC, ATerm round-trip, and the
  structure-aware parity fuzzer ([15](15-differential-testing-and-benchmarking.md) §7.1, §7.2).
- **`loom` tests** for the concurrency primitives — the CAS thunk protocol and the
  work-stealing deques ([13](13-parallel-evaluation.md), `R-4`).
- **`miri`** on the safe oracle — the `#![forbid(unsafe_code)]` crate is the
  complete, exercisable program `miri` analyzes ([14](14-integration-with-aos.md) §10.3).
- **`criterion` benches** — microbenchmarks that localize a regression to a
  subsystem (diagnostic, not the budget — [15](15-differential-testing-and-benchmarking.md) §5.3).

### 8.1 Coverage targets by trust tier

| Surface | Target | Why |
|---|---|---|
| safe oracle (`ratchet-oracle`) + compat core (`aos-nix-compat`) | near-100% line coverage | correctness-critical: the oracle *is* the internal reference and the compat glue owns `.drv` bytes |
| the unsafe core (`value`, `gc`, `jit`, `cache`, `parallel`) | exhaustive unit + fuzz + sanitizer | UB has no second chance; coverage alone is insufficient, so fuzz and ASan/UBSan/TSan join it |
| every builtin | a conformance test | [21](21-builtins-conformance.md) — no primop ships untested |
| every optimization pass | a before/after IR test + a `.drv`-parity differential test | [26](26-optimization-pass-catalog.md) — a rewrite is sound only if the IR transforms as specified *and* the `.drv` is unchanged |

### 8.2 CI floors

CI enforces, as merge-blocking gates: a **coverage floor** on the core crates
(e.g. ≥90%), plus **`miri`** (on the oracle), **`loom`** (on the CAS protocol and
deques), **TSan** and **ASan** (on the parallel and unsafe-core binaries), and the
**differential harness** ([15](15-differential-testing-and-benchmarking.md) §2)
green on the corpus. None of these is optional; a red gate blocks the merge.

## 9. Debugging hooks

A divergence is only as fixable as it is debuggable, so aos-nix ships a standing
introspection toolset. Each hook is named with the failure it diagnoses.

| Hook | Diagnoses |
|---|---|
| `--dump-ast` / `--dump-ir` | a frontend bug: the parse or resolution diverged *before* evaluation, so the wrong tree was even handed to the tiers ([04](04-frontend-parser-and-ir.md), [25](25-intermediate-representation.md)) |
| `tracing` force-trace at debug level | a forcing-order or laziness bug: *which* thunk forced *when*, and what it produced ([24](24-observability-and-diagnostics.md) §7) |
| `AOS_NIX_CACHE=0` (cache-off) | a stale/incorrect incremental-cache result: re-run with the demand-graph cache disabled to isolate cache poisoning from an eval bug ([12](12-incremental-evaluation-cache.md)) |
| `--show-trace` eval-stack | a "where did this error come from" question: the logical eval/force-context chain, reconstructed from the evaluator's own stack ([24](24-observability-and-diagnostics.md) §5) |
| structural `.drv` diff + bisection | a `.drv` byte divergence: the first differing ATerm field, plus root-vs-contaminated classification to find the *one* root bug among thousands of contaminated nodes ([15](15-differential-testing-and-benchmarking.md) §2.3, §2.4) |
| in-process oracle-vs-JIT differential | a JIT/analysis bug specifically: the optimized tier's result diffed against the tier-0 oracle, localizing the bug *before* it reaches the `.drv` boundary ([15](15-differential-testing-and-benchmarking.md) §7) |
| the fuzzer minimizer (`R-13`) | an unreadable fuzzer finding: shrink the diverging expression to a minimal reproducer before it reaches a human ([15](15-differential-testing-and-benchmarking.md) §7.2) |
| deopt logging | an over-eager speculation: which guard failed and which tier-2 frame bailed back to the oracle ([08](08-execution-tiers-and-cranelift.md)) |
| `--single-tier` / force-tier-0 | "is this a tier bug or a semantics bug?": pin execution to the tree-walk oracle and see whether the divergence survives — if it does, the bug is in the safe core, not the JIT |

These are not afterthoughts bolted on when a bug appears; they are part of the
deliverable for each subsystem, so the subsystem is debuggable the day it lands.

## 10. Commit message hygiene

Every commit is a PR-level document. One logical change per commit, with a body
that a future maintainer (or a bisect) can read on its own.

- **Subject: conventional `area: summary`** — e.g. `jit: bake monomorphic select
  offset into tier-2 codegen`.
- **Body explains WHAT and WHY** — not a restatement of the diff, but the reason
  the change exists and the approach taken.
- **Cite the RFC sections it implements** by relative path (e.g. "implements
  [08](08-execution-tiers-and-cranelift.md) §4, [26](26-optimization-pass-catalog.md)
  pass S-of-known").
- **Name the decision IDs it closes or measures** (`S-`/`C-`/`M-`/`R-` from
  [19](19-decision-register.md)) — e.g. "closes `S-13`, measures `M-19`".
- **Name the conformance items it turns green** ([20](20-nix-language-conformance.md)/[21](21-builtins-conformance.md)).
- **Record benchmark deltas** — the wall-clock movement and the `NIX_SHOW_STATS`
  counter breakdown (§7), so a regression bisect lands on a commit that already
  explains its own performance.
- **Record the differential-harness status** — green on the corpus, or the
  specific nodes still divergent.

A commit that lands a perf change with no benchmark delta in its body, or a
feature with no conformance/harness line, is incomplete regardless of whether the
code compiles. This mirrors how this RFC's own commits are written: the message
*is* the design record for that change.

## Definition of "done" for a feature

A box in any per-doc implementation checklist is **done** only when *all* of the
following hold. The implementor applies this to every item.

- [ ] **Code** lives in the correct crate for its safety tier (§1), within the
      file-size limits (§2), with traits at boundaries and concrete code on the
      hot path (§6).
- [ ] **Docs** meet the docs.rs bar (§3): `//!` headers, `///` on every public
      item, `# Errors`/`# Panics`, documented public fields, format examples in
      fenced+tagged blocks, `// SAFETY:` on every `unsafe` block.
- [ ] **Errors** are typed (`thiserror`), span-carrying, class-compatible with
      C++ Nix, with no `unwrap`/`expect`/`anyhow` in the core (§4).
- [ ] **Tests** at the right layer (§8): unit + (conformance for a builtin /
      before-after IR + `.drv`-parity for an optimization pass) + proptest/fuzz/
      loom/miri where the surface demands, above the coverage floor.
- [ ] **Bench** for any perf-affecting change: a `criterion` microbench and a
      green per-commit benchmark with the counter breakdown explaining the win,
      **no regression** (§7).
- [ ] **Harness-green**: the differential `.drv`-diff harness stays byte-green on
      the corpus ([15](15-differential-testing-and-benchmarking.md) §2) — the
      veto that overrides everything above.
- [ ] **Reviewed**: a second maintainer reviewed the change, and *every new
      `unsafe` block* specifically ([14](14-integration-with-aos.md) §10.3).
- [ ] **Commit** documents WHAT/WHY, the RFC sections, the decision IDs, the
      conformance items, the benchmark delta, and the harness status (§10).

Anything short of all eight keeps the box unchecked. The riskier the engine below
the `NixEval` seam, the less slack any one of these standards is permitted.
