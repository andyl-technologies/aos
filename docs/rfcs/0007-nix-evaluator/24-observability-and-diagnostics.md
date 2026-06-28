# RFC-0007 - Observability and diagnostics

> Part of the RFC-0007 aos-nix documentation set. This document specifies how
> aos-nix *surfaces* what it is doing — to a human reading an error, to a
> developer at a REPL, and to the maintainer profiling a run. It covers error
> reporting (the library choice and, critically, the boundary between how an
> error is *rendered* and which error *fires*), source-span-driven diagnostics,
> `--show-trace` parity, the native-backed REPL, and internal `tracing`
> instrumentation.
>
> Read this alongside [frontend: parser and IR](04-frontend-parser-and-ir.md)
> (the arena AST carries the source spans every diagnostic points into),
> [differential testing and benchmarking](15-differential-testing-and-benchmarking.md)
> §3.3 (error-class vs error-text parity — the line this document is built
> around), [parallel evaluation](13-parallel-evaluation.md) §5.5 (the fiber model
> that makes the eval stack logical rather than native),
> [incremental evaluation cache](12-incremental-evaluation-cache.md) (the cache
> that backs the REPL), and [integration with AOS](14-integration-with-aos.md)
> (where the `tracing` counters and the `AOS_NIX_NATIVE` flag live).

## 1. Scope and the one distinction that governs everything

Observability in aos-nix has three audiences and one hard rule.

- **The end user** sees *diagnostics*: a parse or evaluation error rendered
  against their `.nix` source, ideally pointing at the exact bytes that are
  wrong.
- **The developer** uses the *REPL*: an interactive evaluator for poking at
  expressions, loading files, and inspecting bindings.
- **The maintainer** consumes *instrumentation*: spans, counters, and logs that
  explain where eval time and allocations went.

The hard rule, stated once and reinforced throughout: **presentation is not
parity.** How aos-nix *renders* an error — colors, underlines, help text, the
diagnostic framework it uses — is a free choice with no bearing on the
`.drv`-diff gate. *Which* error fires, and *of what class*, is a hard
compatibility requirement (cross-ref
[differential testing and benchmarking](15-differential-testing-and-benchmarking.md)
§3.3). Everything in this document is downstream of that split: §2 picks the
rendering framework, §3 makes the split explicit and load-bearing, and the rest
build on it.

This document is therefore deliberately *not* a parity document for error text.
Error-text parity is best-effort, soft-gated, and enumerated per-case where AOS
packages assert on it (see
[compatibility constraints](02-compatibility-constraints.md) §8 Q4 and
[15](15-differential-testing-and-benchmarking.md) §9 open question 4). Error-
*class* parity is non-negotiable and is owned by the conformance and `.drv`-diff
harnesses, not by anything here.

## 2. Decision: miette is the error-reporting framework

> **Decision (D-OBS-1): use [`miette`](https://docs.rs/miette/) as the
> diagnostic *framework* for all user-facing parse and evaluation errors.
> [`ariadne`](https://docs.rs/ariadne/) was considered and explicitly not
> chosen; it is retained as a possible future *renderer* swap.**

### 2.1 Why a framework, not just a renderer

aos-nix's error *types* are real Rust types — `ParseError`, `EvalError`,
`TypeError`, and friends — and they already carry source spans (`Span = (u32,
u32)` byte offsets, see [frontend](04-frontend-parser-and-ir.md) §3.1) threaded
from the arena AST. What we need from an error library is not just pretty output;
it is a *trait-based framework* that lets those types declare their own
diagnostic metadata — an error code, a severity, contextual `help`, an
explanatory `url`, and one or more labeled spans into the original source — and
then renders them consistently.

`miette` is exactly that framework. It is built around the `Diagnostic` trait,
which extends `std::error::Error` with provided methods for `code`, `severity`,
`help`, `url`, `source_code`, `labels`, `related`, and `diagnostic_source`
([docs.rs/miette `Diagnostic`](https://docs.rs/miette/latest/miette/trait.Diagnostic.html)).
It integrates smoothly with `thiserror` via a derive macro (`#[derive(Diagnostic,
Error)]` with `#[diagnostic(code(...))]` and `#[label(...)]` attributes), but
does not *require* it — the trait can be hand-implemented exactly like
`std::error::Error`. It ships a built-in, rustc-style "fancy" renderer that draws
labeled spans, underlines, multi-line labels, related errors, and help/URL
footers, and it is pure Rust with no system dependencies — important for our
hermetic, from-source build (see the build principles in `CLAUDE.md`).

### 2.2 Why not ariadne

`ariadne` is a *beautiful renderer* — arguably prettier than miette's default —
with strong inline/multi-line label layout, overlap heuristics, and configurable
underlines ([docs.rs/ariadne](https://docs.rs/ariadne/),
[github.com/zesterer/ariadne](https://github.com/zesterer/ariadne)). But it is
*only* a renderer: it provides no error-*type* framework. It is the sister
project of the `chumsky` parser and is typically paired with it — you bring your
own error type and feed ariadne a `Report` you assemble by hand. That is the
wrong shape for us. Our parse and eval errors are first-class types that must
carry diagnostic metadata as part of their definition, be propagated with `?`,
and be matched on for *class* (the parity-relevant property). A framework whose
trait the error types *implement* is the right tool; a render-only crate would
leave us hand-rolling the framework miette already provides.

### 2.3 The decision is reversible at the render boundary

Because miette cleanly separates the `Diagnostic` *data* (codes, spans, help)
from its *renderer* (the `ReportHandler`), and because ariadne is render-only,
swapping the *rendering* layer later — to ariadne, or to a bespoke renderer that
mimics C++ Nix's exact output format byte-for-byte — is a localized change behind
the report-printing seam. The error *types* and their spans do not change. We
therefore commit to miette as the framework now and keep ariadne on the table as
a future renderer, with no architectural lock-in.

| Concern | miette (chosen) | ariadne (considered) |
|---|---|---|
| `Diagnostic`-trait error framework | yes (`code`, `severity`, `help`, `url`, `labels`, `related`) | no — renderer only |
| `thiserror` derive integration | yes (optional) | n/a (no error type) |
| Built-in fancy renderer | yes (rustc-style) | yes (arguably nicer) |
| Multi-span / related labels | yes | yes |
| Pure-Rust, hermetic-friendly | yes | yes |
| Role in aos-nix | error *types* + default rendering | possible future *renderer* swap |

## 3. The critical separation: presentation versus parity

This section exists to make the §1 rule impossible to miss, because it is the
single most consequential thing about diagnostics in a parity-gated evaluator.

```text
  ┌─────────────────────────────┐        ┌─────────────────────────────┐
  │  PRESENTATION  (miette)     │        │  PARITY  (the gate)         │
  │                             │        │                             │
  │  HOW an error is rendered:  │        │  WHICH error fires, and of  │
  │  code, color, labels, help, │        │  WHAT CLASS:                │
  │  url, span underlines       │        │  TypeError stays TypeError, │
  │                             │        │  throw stays throw,         │
  │  free choice — no .drv      │        │  assert stays assert        │
  │  impact whatsoever          │        │                             │
  │                             │        │  HARD requirement — owned   │
  │  error-TEXT parity:         │        │  by conformance + .drv gate │
  │  best-effort, soft-gated    │        │  (doc 15 §3.3)              │
  └─────────────────────────────┘        └─────────────────────────────┘
        miette governs THIS                  miette governs NONE of THIS
```

- **miette governs HOW, never WHICH.** miette decides whether a type error is
  shown with a red underline and a `help:` footer. It has *zero* say in whether
  a given expression *is* a type error. The classification logic lives in the
  evaluator and is validated against C++ Nix; the renderer is downstream and
  inert with respect to parity.

- **Error-CLASS parity is a hard requirement.** Per
  [15](15-differential-testing-and-benchmarking.md) §3.3, every `eval-fail` /
  `parse-fail` conformance case asserts that aos-nix fails *in the same class*:
  a type error stays a type error, a `throw` stays a `throw`, an assertion
  failure stays an assertion failure, an undefined-variable error stays an
  undefined-variable error. This is also what the `EvalError`-vs-`Unsupported`
  fallback distinction in [integration with AOS](14-integration-with-aos.md) §6
  relies on: the staged rollout is only sound if the two evaluators *agree on
  which inputs error and of what kind*.

- **Error-TEXT parity is best-effort.** Error message *bytes* are not a Merkle
  input — they never affect a store path — so byte-identical message text is a
  *soft* goal, pursued for developer trust and for the handful of AOS
  expressions that assert on error text (enumerated and handled per-case, per
  [15](15-differential-testing-and-benchmarking.md) §3.3 and §9 Q4). aos-nix
  aims to make its miette-rendered messages *recognizable and informative*, and
  where cheap, *close* to C++ Nix's wording — but it does not subordinate good
  diagnostics to byte-matching a C++ string.

The practical consequence for implementers: an `EvalError` enum variant encodes
the *class* (the parity-relevant axis); its miette `Diagnostic` impl encodes the
*presentation* (the free axis). Adding a `help` string or recoloring a label is
never a parity event. Renaming or merging a variant such that a former
`TypeError` now surfaces as a `throw` *is* a parity event and is caught by the
conformance suite.

| Axis | Owned by | Gate | Changeable freely? |
|---|---|---|---|
| Error class (type/throw/assert/undefined-var/...) | evaluator logic | conformance + `.drv`-diff (hard) | **no** |
| Error/no-error outcome | evaluator logic | `.drv`-diff (hard) | **no** |
| Error text (message bytes) | `Diagnostic` impl | soft, per-case enumerated | mostly yes |
| Rendering (color, labels, help, url, code) | miette renderer | none | **yes** |

## 4. Spans: diagnostics that point into the original `.nix`

The frontend ([04](04-frontend-parser-and-ir.md)) was designed so that every
AST/IR node records the `Span` of the tokens it was built from — `(u32, u32)`
byte offsets into the source, described in [04](04-frontend-parser-and-ir.md)
§3.2 as "the universal diagnostic currency." Diagnostics are the payoff for that
discipline.

### 4.1 From span to label

Every parse and eval error carries the span(s) relevant to it. Mapping a span to
a miette label is mechanical:

- The original source bytes are held as a miette `SourceCode` (typically
  `NamedSource`, carrying the file path hint so the rendered frame shows
  `pkgs/foo/default.nix:12:5`).
- Each error span becomes a `LabeledSpan` — a byte range plus a short label
  string ("expected `;`", "this has type `int`", "`with` expression here").
- Errors with *two* relevant locations (a redefinition vs. its original, a type
  mismatch between operands, a `let` binding vs. its conflicting sibling) emit
  *multiple* labels — miette renders all of them against the same source, which
  is strictly more informative than C++ Nix's single-caret style.

```text
  error[aos_nix::eval::type_error]: cannot coerce an integer to a string
     ╭─[ pkgs/foo/default.nix:12:9 ]
  12 │   name = 42 + "-foo";
     ·          ─┬   ───┬──
     ·           │      ╰── ... while concatenating this string
     ·           ╰──────── this operand has type `int`
     ╰────
   help: `+` concatenates strings/paths or adds numbers; operands must match
```

The byte ranges above come straight from the arena node spans; the label text
and `help` are the `Diagnostic` impl's contribution. The *rendering* is miette;
the *fact that this is a type error* is the evaluator and is parity-checked.

### 4.2 Spans survive the cache and the tiers

Because spans are plain `(u32, u32)` integers stored inline in the arena, they
serialize into the content-addressed parse cache ([04](04-frontend-parser-and-ir.md)
§9) with the rest of the IR and survive `mmap`-reload with zero fixup. A
diagnostic produced from cache-loaded IR points at the same bytes as one produced
from a fresh parse. Likewise, because all execution tiers consume the *same* IR
([04](04-frontend-parser-and-ir.md) §5), an error raised by the tier-0 oracle,
the tier-1 baseline, or a tier-2 deopt all reference the same span — there is no
"the JIT lost the line number" failure mode.

### 4.3 Parse errors stop early; spans are still exact

The evaluator's parser is allowed to stop at the first error
([04](04-frontend-parser-and-ir.md) §4.5) rather than recover LSP-style, because
an unparseable file is an evaluation error in Nix anyway. The first error's span
is still byte-exact, so the miette diagnostic is precise even though no recovery
is attempted. (A future LSP-oriented mode could lower from rnix for recovery;
that is out of scope here and tracked in
[roadmap and risks](17-roadmap-and-risks.md).)

## 5. `--show-trace` parity: structural, not textual

C++ Nix, given `--show-trace`, prints an *evaluation stack trace* on error: a
cascade of "while evaluating ..." frames (the attribute, the function call, the
list element, the `with` body) leading from the top-level expression down to the
point of failure ([NixOS/nix #7553](https://github.com/NixOS/nix/issues/7553),
[#7552](https://github.com/NixOS/nix/issues/7552)). Without `--show-trace` the
trace is summarized or omitted; with it, the full context chain is shown. This is
a heavily-used debugging affordance and aos-nix must provide an equivalent.

### 5.1 Decision: reconstruct from the logical eval stack

> **Decision (D-OBS-2): aos-nix reconstructs the `--show-trace` frame chain from
> a maintained eval-context / force stack, not from the OS call stack. The goal
> is STRUCTURAL parity — the same frames in the same order; full TEXT parity of
> each frame is best-effort.**

The evaluator already maintains, for its own correctness, a notion of the current
evaluation context: which thunk is being forced, which attribute path is being
selected, which function is being applied, which `with` is in scope. aos-nix
threads an explicit *trace frame* onto this context as it forces values — an
`addErrorContext`-equivalent — so that when an error is raised, the chain of
enclosing frames is available to attach to the diagnostic (as miette `related`
diagnostics or as an appended trace section).

Crucially, **this stack is logical, not native.** Under the fiber model
([parallel evaluation](13-parallel-evaluation.md) §5.5), forcing is not a chain
of OS stack frames — work is suspended and resumed across fibers, and the OS
stack is shared and re-used. The trace must therefore be reconstructed from the
*evaluator's own* force/eval-context stack (the logical chain of "what is being
evaluated because what"), which is exactly the chain C++ Nix prints. Reading the
native backtrace would be both wrong (it reflects fiber scheduling, not Nix
evaluation order) and useless after a tier-2 JIT frame. The logical stack is the
source of truth.

### 5.2 What "structural parity" buys and what it does not

| Property | Target | Why |
|---|---|---|
| Same frames present | yes (structural) | a missing/extra "while evaluating the attribute ..." frame is a real divergence in debugging context |
| Same frame order | yes (structural) | the chain must read inner-cause-last like C++ Nix |
| Same frame *wording* | best-effort | message text is not a Merkle input; soft-gated like all error text (§3) |
| Same file:line:col per frame | yes (from spans, §4) | the spans are exact, so locations match even when wording differs |

Structural parity means a developer who knows how to read a C++ Nix trace reads
an aos-nix trace the same way: same number of "while evaluating" steps, same
order, same source locations. The per-frame *English* may differ slightly, and
that is acceptable under the §3 split. Where an AOS test or expression asserts on
trace *text*, it joins the enumerated error-text-parity set
([15](15-differential-testing-and-benchmarking.md) §9 Q4).

### 5.3 Cost and gating

Maintaining the trace frame on every force has a cost, so — mirroring C++ Nix —
the *full* context chain is assembled only when tracing is requested
(`--show-trace` or the aos-nix equivalent), while a *summarized* trace is the
default. The eval-context stack itself is maintained regardless (the evaluator
needs it), but materializing rich frame strings is deferred to the error path,
which is cold. Whether to keep frame strings always or build them lazily on the
error path is an instrumentation-cost question measured under the
measure-first discipline ([15](15-differential-testing-and-benchmarking.md) §4),
not assumed.

## 6. The REPL: a native-backed interactive evaluator

`aos repl` (the existing subcommand, see `CLAUDE.md`) opens an interactive Nix
REPL with the AOS package set loaded. When `AOS_NIX_NATIVE` selects the native
evaluator, that REPL can be backed by aos-nix instead of shelling out to C++
Nix.

### 6.1 Decision: the REPL is a dev tool, parity is best-effort

> **Decision (D-OBS-3): the native evaluator may back `aos repl`. The REPL is a
> developer tool, not a `.drv` producer; behavior parity with C++ Nix's `nix
> repl` is best-effort, NOT gated.**

The acceptance gate ([15](15-differential-testing-and-benchmarking.md) §2) is
about byte-identical *derivations*. A REPL does not instantiate derivations as
its primary job — it evaluates expressions interactively and prints values. A
divergence in, say, how `:t` phrases a type is not a `.drv` divergence and does
not block `AOS_NIX_NATIVE`. The REPL is held to the same *value-rendering*
expectations as the `eval-okay` conformance corpus (a printed value should match,
since that is plain evaluation), but the REPL *meta-commands* and ergonomics are
aos-nix's own and need only be *useful*, not byte-identical to C++ Nix.

### 6.2 REPL capabilities

aos-nix's REPL reproduces the load-bearing subset of C++ Nix's `nix repl`
meta-commands ([nix repl manual](https://nix.dev/manual/nix/2.32/command-ref/new-cli/nix3-repl.html)):

| Command | Behavior | Notes |
|---|---|---|
| `:load <file>` (`:l`) | parse + evaluate a file, bind its attrs into REPL scope | mirrors C++ Nix `:l`; uses the parse cache (§6.3) |
| `:reload` (`:r`) | re-parse + re-evaluate loaded files | early-cutoff makes this cheap (§6.3) |
| `:t <expr>` | print the *type/description* of an evaluated expression | value-render parity (soft) |
| `:p <expr>` | evaluate and print recursively (force deeply) | as C++ Nix `:p` |
| `:b <expr>` | build a derivation (delegates to the realisation path) | derivation output *is* gate-relevant |
| `:q` | quit | — |
| `:scope <expr>` | inspect resolver frames and variable coordinates for an expression in the current REPL context | from the resolver's scope frames ([04](04-frontend-parser-and-ir.md) §6) |

Binding inspection is a natural fit for aos-nix specifically because the resolver
already computes, at every program point, exactly which names are in scope and
their `(depth, slot)` coordinates ([04](04-frontend-parser-and-ir.md) §6.2). The
REPL surfaces that scope metadata directly through `:scope`; it does not
re-derive it.

### 6.3 The REPL is incremental and cache-assisted

The REPL is the most natural beneficiary of the incremental machinery
([incremental evaluation cache](12-incremental-evaluation-cache.md)): an
interactive session re-evaluates overlapping expressions constantly, and `:reload`
after editing one file should recompute only what changed.

- `:load` and imports hit the content-addressed parse cache
  ([04](04-frontend-parser-and-ir.md) §9): unchanged files are not re-parsed.
- `:reload` after a comment-only or localized edit triggers *early cutoff*
  ([12](12-incremental-evaluation-cache.md)): only the bounded set of
  expressions whose *value* changed is recomputed. The `early_cutoffs` counter
  (§7, and [15](15-differential-testing-and-benchmarking.md) §4.2) makes this
  visible — a near-instant `:reload` is the interactive face of success
  criterion C4.

This is where "the fastest evaluator is the one that does not evaluate"
([15](15-differential-testing-and-benchmarking.md) §6.2) is felt directly by a
human: an interactive `:reload` that is sub-perceptible because the cache
absorbed the edit.

## 7. Internal instrumentation: the `tracing` crate

Distinct from *user-facing diagnostics* (§2–§5) is *internal instrumentation* —
the spans, events, and counters the maintainer uses to understand a run. These
serve different audiences and use different machinery.

### 7.1 Decision: `tracing` for internal spans and events

> **Decision (D-OBS-4): use the [`tracing`](https://docs.rs/tracing/) crate
> (already an AOS workspace dependency) for all internal instrumentation —
> evaluation spans, primop entry/exit, cache hit/miss events, tier promotions,
> deopts. This is orthogonal to miette: `tracing` is for *us*, miette is for the
> *user*.**

`tracing` is the Tokio-project framework for structured, event-based diagnostic
instrumentation; a *span* has a beginning and end and may nest, and events and
spans carry typed fields, not just text
([docs.rs/tracing](https://docs.rs/tracing/),
[tokio.rs tracing](https://tokio.rs/tokio/topics/tracing)). It does not require
the tokio runtime. It is already used across the AOS workspace, so aos-nix
reuses it rather than introducing a second logging stack.

Concretely, `tracing` carries the aos-nix statistics counters described in
[15](15-differential-testing-and-benchmarking.md) §4.2 and the success/fallback/
shadow-divergence counters in [integration with AOS](14-integration-with-aos.md)
§10:

| Surface | Mechanism | Cross-ref |
|---|---|---|
| `thunks_forced` / `thunks_allocated` / `thunks_elided` | counters on force/alloc spans | [15](15-differential-testing-and-benchmarking.md) §4.2 (G3) |
| `inline_cache_hits` / `misses`, `shape_transitions` | events at `select` sites | [15](15-differential-testing-and-benchmarking.md) §4.2 (G5) |
| `tier_promotions`, `deopts` | events at tier boundaries | [15](15-differential-testing-and-benchmarking.md) §4.2 (G6) |
| `cache_hits` / `early_cutoffs` | events in the incremental cache | [12](12-incremental-evaluation-cache.md), [15](15-differential-testing-and-benchmarking.md) §4.2 (G2) |
| native successes / fallbacks / shadow divergences | events at the `NixEval` seam | [14](14-integration-with-aos.md) §11 |

Because these are `tracing` fields rather than ad-hoc prints, they are filterable
(`RUST_LOG`-style), aggregatable, and exportable without touching the evaluator —
and they are *named to parallel* `NIX_SHOW_STATS` so the before/after comparison
against C++ Nix is a field-by-field diff
([15](15-differential-testing-and-benchmarking.md) §4.2).

### 7.2 `builtins.trace` / `traceVerbose` are user-facing, not `tracing`

There is a deliberate and important asymmetry: the Nix *language* builtins
`builtins.trace` and `builtins.traceVerbose` are **not** routed through the
`tracing` crate. They are user-observable language features with C++ Nix
semantics that must be reproduced:

- `builtins.trace e1 e2` evaluates `e1`, prints its representation to **stderr**
  unconditionally, and returns `e2`
  ([nix builtins](https://nix.dev/manual/nix/2.18/language/builtins),
  [noogle builtins.trace](https://noogle.dev/f/builtins/trace)).
- `builtins.traceVerbose e1 e2` does the same but prints **only** when
  `--trace-verbose` is enabled
  ([noogle builtins.traceVerbose](https://noogle.dev/f/builtins/traceVerbose)).

These map to **user-facing stderr output that matches C++ Nix**, gated on the
same `--trace-verbose` flag for `traceVerbose`. They are a behavior of the
evaluated program, observable by the program's author, and live on the
error-text-parity axis (§3): best-effort byte parity, hard *behavioral* parity
(it must print, to stderr, and return the second argument). Routing them through
the internal `tracing` subscriber would both filter them away under `RUST_LOG`
settings and change *what the user sees* — both wrong. The two systems stay
separate:

```text
  builtins.trace / traceVerbose ──► stderr  (user-facing, C++ Nix-compatible)
  tracing spans / events        ──► subscriber (maintainer-facing, RUST_LOG-filtered)
```

## 8. Decision summary

| ID | Decision | Parity-gated? |
|---|---|---|
| D-OBS-1 | `miette` is the diagnostic *framework*; `ariadne` considered, kept as future renderer | no (presentation) |
| D-OBS-2 | `--show-trace` reconstructed from the *logical* eval/force stack; structural parity, text best-effort | structural: target; text: soft |
| D-OBS-3 | Native evaluator may back `aos repl`; dev tool, parity best-effort | no (not a `.drv` producer) |
| D-OBS-4 | `tracing` crate for internal instrumentation; orthogonal to miette | no (maintainer-facing) |
| (rule) | `builtins.trace`/`traceVerbose` → user stderr matching C++ Nix, *not* `tracing` | behavioral: hard; text: soft |
| (rule) | Error-CLASS parity hard (doc 15 §3.3); error-TEXT parity best-effort | class: hard |

## 9. Open questions

1. **Frame-string materialization cost.** Whether `--show-trace` frames are kept
   as strings always or built lazily on the cold error path (§5.3) is a
   measure-first question, settled by the instrumentation overhead numbers from
   [15](15-differential-testing-and-benchmarking.md) §4, not assumed here.
2. **C++-Nix-exact renderer.** Whether to add a render mode that mimics C++ Nix's
   error output byte-for-byte (for the enumerated error-text-parity packages, §3)
   — implemented as a miette `ReportHandler` or by swapping to ariadne (§2.3) —
   versus handling those packages purely per-case. Cross-cuts
   [15](15-differential-testing-and-benchmarking.md) §9 Q4.
3. **REPL debugger.** C++ Nix has a `--debugger` that breaks into bindings on
   `throw`/`trace`. Whether aos-nix's REPL grows an equivalent (its logical
   eval-context stack, §5.1, and scope frames, §6.2, are the substrate it would
   need) is deferred until the REPL is in real use.
4. **Remaining span fidelity through desugaring.** The current P1 attr-path,
   `inherit`, and indented-string rewrite surfaces are covered below; ordinary
   string interpolation and later tier/deopt trace reconstruction still need
   canaries proving that synthesized nodes carry spans pointing at *sensible*
   original bytes.

## Implementation checklist

Per-feature tracker for observability and diagnostics (the miette error framework, span-driven diagnostics, `--show-trace` parity, the native-backed REPL, internal `tracing` instrumentation, and the `builtins.trace` split); master roll-up: [implementation checklist (all phases)](22-implementation-checklist-all-phases.md). Per the unlimited-budget mandate, every item here is in scope — including research-grade ones — built in dependency order and gated by the differential harness, never cut for scope.

The governing rule binds every item: **presentation is not parity.** How an error is *rendered* is a free choice with no `.drv` impact; *which* error fires and *of what class* is owned by the conformance and `.drv`-diff harnesses ([15](15-differential-testing-and-benchmarking.md) §3.3), not by anything here. These items are mostly **P1** instrumentation (spans, error types, REPL, `tracing`) that surface the work the optimization phases do.

### Error reporting: miette as the diagnostic framework (§2)

- [x] Current `miette` diagnostic substrate and native-evaluator routing:
      `aos_nix::diagnostic` wraps `LexError`, `ParseError`, `ScopeError`,
      `IrError`, and `TreeWalkError` in `SourceDiagnostic` with `NamedSource`,
      stable `aos_nix::...` diagnostic codes, severity, help, diagnostic help
      URLs, single- and multi-span `LabeledSpan`s, and a `render_fancy_report`
      seam over miette's built-in graphical renderer; `miette` is pinned in
      `crates/Cargo.lock`, and the native evaluator renders source-backed
      reports for raw-expression parser/resolver/lowering/tree-walk failures,
      file-backed root failures, and imported frontend/tree-walk failures when
      the source text is renderable and every span fits the selected source
      while preserving unsupported/fallback taxonomy. Duplicate-attribute parse
      errors label both definitions, binary operand type errors can label both
      operands, and `addErrorContext` logical contexts render as source-mapped
      evaluation-context labels (§2.1–§2.3) — **P1**, `C-26`/`D-OBS-1`; gate
      today: focused diagnostic and native-error tests.
- [ ] Broader diagnostic adoption remains: route every remaining
      CLI/user-facing parse/eval surface through the wrapper, keep full
      summarized/full `--show-trace` parity open, and finish any
      C++-Nix-exact renderer, REPL, or debugger integration once those surfaces
      are in real use (§2.1–§2.3, §5, §6, §9 open questions 2-3) — **P1**,
      `C-26`/`D-OBS-1`/`D-OBS-2`/`D-OBS-3`.

### The presentation-vs-parity separation (§3)

- [x] Encode error **class** in concrete `*ErrorKind` variants (the parity-relevant axis, hard-gated by conformance plus `.drv` error/no-error parity) and error **presentation** in the `Diagnostic` impl (the free axis): AOS keeps lexical, parse, resolver, lowering, and tree-walk evaluator classes in `LexErrorKind`, `ParseErrorKind`, `ScopeErrorKind`, `IrErrorKind`, and `TreeWalkErrorKind` (`TreeWalkErrorKind::Type` is the concrete type-error class), while only `SourceDiagnostic<E>` implements miette `Diagnostic` and owns codes/help/source labels. Diagnostic regression tests assert the wrapper preserves the original typed error and plain display while the rendered report carries the presentation code/help, and `cpp_nix_error_classes_match_tree_walk` gates representative parse/type/throw/assert/abort classes against the pinned C++ Nix oracle; adding a `help` or recoloring a label is not a parity event, while representative class regressions are caught by the conformance gate (§3) — **P1**, `C-26`; error-text parity stays best-effort, soft-gated, per-case enumerated.

### Spans: diagnostics into the original `.nix` (§4)

- [x] Current source-backed span labels: `SourceDiagnostic` maps
      parser/lexer/resolver/lowering/tree-walk `Span = (u32,u32)` values to
      miette `LabeledSpan`s against `NamedSource`; duplicate-attribute parse
      errors and operand type errors emit multiple labels; tree-walk errors
      carry module `EvalErrorSource` provenance plus context/label spans; and
      imported frontend/tree-walk failures preserve source bytes so native
      diagnostics can render against the imported file rather than the root
      when the selected source is renderable and every span fits it (§4.1,
      §4.2) — **P1**; gate today: focused diagnostic/native source tests.
- [ ] Zero-fixup span survival remains: spans must survive the durable
      content-addressed parse cache and every future execution tier so a
      cache-loaded or JIT/deopt-raised error points at the same original bytes
      without per-tier fixup (§4.1, §4.2) — **P1/P6/P7**, depends on the
      arena-AST spans of [04](04-frontend-parser-and-ir.md) §3.1 and the
      future tier/deopt paths.
- [x] Current fail-fast parser diagnostic core: parsing returns one
      `ParseError`, has no recovery/accumulation API, carries a byte `Span`,
      and reports the first error encountered by the fail-fast parser; focused
      tests assert the first significant token after skipped trivia is reported
      at the exact source byte (§4.3) — **P1** core; gate today: parser
      diagnostic tests.
- [x] Span fidelity through desugaring: synthesized/desugared nodes from
      attr-path nesting, `inherit`, and indented-string de-indentation preserve
      sensible original byte spans for diagnostics. Parser canaries assert
      duplicate attribute diagnostics created through attr-path normalization
      and inherit expansion label the original conflicting binding slices,
      including the precise nested `b = ...;` span when an explicit
      `{ b = ...; }` conflicts with `a.b`; a separate indented-string canary
      asserts de-indentation preserves the interpolation node's original
      `${...}` source span for downstream diagnostics. This covers the current
      P1 attr-path, inherit, and indented-string rewrite surfaces; future
      ordinary string interpolation coverage, tier/deopt trace reconstruction,
      and diagnostic reconstruction remain tracked by the zero-fixup
      span-survival and full `--show-trace` rows
      (§4.3, open question 4) — **P1** fit-and-finish.

### `--show-trace` parity: structural, not textual (§5)

- [x] Current logical eval-context substrate: `TreeWalkError` retains
      `addErrorContext`-equivalent `EvalErrorContext` messages with source
      spans/sources in outer-to-inner order, independent of OS stack frames, and
      the miette surface renders matching contexts as `while evaluating: ...`
      evaluation-context labels (§5.1) — **P1** logical stack substrate,
      `D-OBS-2`; gate today: focused `addErrorContext`/diagnostic/native source
      tests.
- [ ] Full `--show-trace` reconstruction remains: assemble summarized/full
      trace frame chains from the evaluator's logical eval/force-context stack,
      add any C++-Nix-required implicit frames beyond current `addErrorContext`
      contexts, and validate the result under the future fiber scheduler where
      the native stack reflects scheduling rather than Nix evaluation order
      (§5.1) — **P1** logical stack, validated against the fiber model
      ([13](13-parallel-evaluation.md) §5.5, **P3.5**); `D-OBS-2`.
- [ ] Target structural parity (same frames, same order, same file:line:col from spans); frame *wording* best-effort; assemble the full chain only when tracing is requested, summarized by default, with lazy-vs-eager frame-string materialization a measure-first question (§5.2, §5.3, open question 1) — **P1**, `D-OBS-2`; text parity soft-gated like all error text (§3).

### The native-backed REPL (§6)

- [x] Back `aos repl` with the native evaluator when `AOS_NIX_NATIVE` selects it: `NixRunner::repl` now delegates to external `nix repl` only for the `nix-cli` evaluator; native/shadow selections run an in-process AOS REPL backed by the selected `NixEval`, validate the initially loaded `default.nix` before claiming it is loaded, evaluate ordinary input/`:p` through strict JSON rendering, support `:t`, validate `:load`/`:reload`, and implement `:b` by instantiating then realising through `NixCli::realise`. The `aos repl` banner names the selected evaluator; scripted unit tests cover selected-evaluator routing, load-validation failure preserving the prior scope, type/eval/build command flow, and native-feature CLI smoke tests with `AOS_NIX_NATIVE=1 --features native-eval --impure-eval` exercise the real binary. This remains a dev tool, parity best-effort, not a `.drv` producer gate (§6.1) — **P1**+, `D-OBS-3`.
- [x] Reproduce the load-bearing `nix repl` meta-commands (`:load`/`:l`, `:reload`/`:r`, `:t`, `:p`, `:b`, `:q`) plus `:scope <expr>` binding/scope inspection from the resolver's `(depth, slot)` scope frames. `NixRunner`'s native REPL command parser now exposes `:scope`, renders frame slot counts/captures plus local/upvalue/with/global references for the REPL-wrapped expression, and keeps the command behind the existing `native-eval` feature boundary. Scripted tests cover load/reload/type/eval/build/quit flow, load-validation failure preserving the prior scope, and `native_repl_scope_command_reports_resolver_coordinates` asserts the lambda capture frame and concrete `x` upvalue / `y` local coordinates (§6.2) — **P1**+; `:b` derivation output *is* gate-relevant.
- [ ] Make the REPL incremental/cache-assisted: `:load` and imports hit the content-addressed parse cache, `:reload` after a localized edit triggers early cutoff (the interactive face of criterion **C4**, instrumented by `early_cutoffs`) (§6.3) — **P2** (depends on the incremental cache, [12](12-incremental-evaluation-cache.md)).

### Internal instrumentation: the `tracing` crate (§7)

- [x] Current `aos-core` `NixEval` seam instrumentation uses `tracing`
      orthogonally to miette: `NixRunner` logs evaluator name plus file/attr
      context for top-level eval/instantiate operations; `aos-core` exposes
      grouped native success/fallback/shadow/verify counters; observer paths
      record native success counts, fallback evaluator pair/reason/count,
      shadow outcomes, verify outcomes, and `.drv` divergence events with
      operation plus file/attr/drv context when available (§7.1) — `D-OBS-4`;
      gate today: `aos-core` eval/runner instrumentation tests, including the
      `native-eval` feature-gated counter and divergence-context tests.
- [x] Current `aos-nix` stats schema/substrate: `EvalStats` exposes the stable
      observability counter schema, owned tree-walk outcomes and
      `TreeWalk::stats()` snapshots carry it, successful public evaluation paths
      emit stable field names on the `aos_nix::eval::stats` tracing target, and
      the P1 tree-walk currently increments implemented thunk
      allocation/force/reuse, cache hit/miss, force-cache policy decision, and
      heap/arena-derived fields while future subsystem fields remain
      schema-stable zeroes until those subsystems land (§7.1;
      [15](15-differential-testing-and-benchmarking.md)
      §4.2) — `D-OBS-4`; gate: stats outcome/tracing tests plus the
      `aos-nix` check.
- [ ] Full all-internal and `aos-nix` subsystem instrumentation remains: wire
      real early-cutoff, inline-cache, shape-transition, tier-promotion, deopt,
      GC, and any other cache/shape/tier counters as those subsystems land;
      align fields with `NIX_SHOW_STATS` where relevant; and promote divergence
      events into the full self-contained report surface (§7.1) — counters land
      as each subsystem does (cache **P2**, shapes **P5**, tiers **P6/P7**);
      `D-OBS-4` ([15](15-differential-testing-and-benchmarking.md) §4.2).
- [x] Current `builtins.trace` / `builtins.traceVerbose` user-facing output
      path stays out of internal `tracing`: tree-walk emits `trace: ...` to
      its stderr sink, records `EvalTraceOutput`, and returns the second
      argument; `traceVerbose` is gated by native
      `TreeWalkOptions::trace_verbose`; `aos-core` maps trace-verbose config to
      native options and C++ `--option trace-verbose true`; and public eval
      commands stream successful eval stderr so plain `builtins.trace` output is
      visible (§7.2) — **P1**, builtins surface
      ([21](21-builtins-conformance.md)); gate today: trace/tree-walk/aos-core
      runner tests, including configured local oracle coverage.
- [ ] Pinned exact stderr parity remains: run the pinned C++ Nix 2.24.12 oracle
      check for byte-exact `builtins.trace` / `builtins.traceVerbose` stderr
      formatting; configured/local oracle tests are coverage, not this
      acceptance gate (§7.2) — **P1**, builtins surface
      ([21](21-builtins-conformance.md)).

### Open questions (research-grade, in scope)

- [ ] A C++-Nix-exact renderer (a miette `ReportHandler` or an ariadne swap) for the enumerated error-text-parity packages; a REPL `--debugger` equivalent built on the logical eval-context stack + scope frames (§9 open questions 2, 3) — deferred research/fit-and-finish, in scope under the unlimited-budget mandate, built only once the REPL/error surfaces are in real use.

## References

External claims in this document were verified against the following sources.

- **miette** (the `Diagnostic` trait: `code`/`severity`/`help`/`url`/
  `labels`/`related`/`source_code`; `thiserror` derive integration; built-in
  fancy renderer; pure Rust):
  - `miette` crate docs — <https://docs.rs/miette/>
  - `Diagnostic` trait reference —
    <https://docs.rs/miette/latest/miette/trait.Diagnostic.html>
  - `miette` README (derive usage, `#[diagnostic(code(...))]`, `#[label(...)]`) —
    <https://github.com/zkat/miette/blob/main/README.md>
  - `miette` on lib.rs — <https://lib.rs/crates/miette>
- **ariadne** (render-only diagnostics crate; sister project of `chumsky`;
  inline/multi-line labels and overlap heuristics; no error-type framework):
  - `ariadne` crate docs — <https://docs.rs/ariadne/>
  - `ariadne` repository (sister of chumsky; renderer features) —
    <https://github.com/zesterer/ariadne>
- **`nix --show-trace`** (evaluation stack trace; "while evaluating ..." context
  frames; summarized vs. full trace):
  - NixOS/nix #7553 — "Show `addErrorContext` traces by default" —
    <https://github.com/NixOS/nix/issues/7553>
  - NixOS/nix #7552 — "Customizable summarized stack traces" —
    <https://github.com/NixOS/nix/issues/7552>
  - NixOS/nix #2458 — `if` / `--show-trace` context attachment —
    <https://github.com/NixOS/nix/issues/2458>
- **`nix repl`** (`:l`/`:load`, `:r`/`:reload`, `:t`, `:p`, `:b`, `:q`;
  binding/scope inspection):
  - Nix Reference Manual — `nix repl` —
    <https://nix.dev/manual/nix/2.32/command-ref/new-cli/nix3-repl.html>
- **`builtins.trace` / `builtins.traceVerbose`** (print to stderr; `traceVerbose`
  gated on `--trace-verbose`; return the second argument):
  - Nix Reference Manual — Built-in Functions —
    <https://nix.dev/manual/nix/2.18/language/builtins>
  - noogle — `builtins.trace` — <https://noogle.dev/f/builtins/trace>
  - noogle — `builtins.traceVerbose` —
    <https://noogle.dev/f/builtins/traceVerbose>
- **`tracing`** (structured, span-based instrumentation; spans have begin/end and
  nest; typed fields; Tokio-maintained, runtime-agnostic):
  - `tracing` crate docs — <https://docs.rs/tracing/>
  - Tokio — Getting started with Tracing —
    <https://tokio.rs/tokio/topics/tracing>
