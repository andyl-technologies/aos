# RFC-0007 - Integration with AOS: the `NixEval` seam, gating, fallback, and the `unsafe` policy

This document specifies how `aos-nix` plugs into the existing ANDYL OS (AOS)
toolchain without taking on the risk that a from-scratch evaluator naturally
carries. The thesis of the whole RFC-0007 set is that `aos-nix` can be *fast*
(see [architecture overview](03-architecture-overview.md)) while remaining
*bug-for-bug compatible* with C++ Nix on the only output that matters — the
`.drv` graph and the store paths derived from it (see
[compatibility constraints](02-compatibility-constraints.md)). This document is
about the *fourth* leg of that stool: **safe rollout**. A new evaluator that is
correct in the lab but defaulted-on before the differential harness is green
would be a catastrophe for this repository specifically, because a single
divergent store path triggers a full from-source toolchain rebuild (see
[derivation and store compatibility](11-derivation-and-store-compatibility.md)).

The integration design is therefore conservative by construction:

1. A narrow Rust trait, `NixEval`, expresses the *only* operation we are
   replacing — `eval -> .drv` — and nothing else.
2. Two implementations sit behind it: `NixCli` (the existing subprocess
   wrapper, kept forever as the oracle and the fallback) and `NixNative`
   (`aos-nix`).
3. A single environment switch, `AOS_NIX_NATIVE`, selects the implementation,
   defaulting **off**.
4. The `unsafe` surface of `aos-nix` is fenced into a small, audited core, and
   AOS's normal "avoid `unsafe` at all costs" rule (see the workspace
   `CLAUDE.md`) is explicitly, narrowly waived for this crate with a documented
   discipline.

The remainder of this document treats each in turn, then covers the failure
model, observability, the build-vs-eval boundary, and open questions.

---

## 1. What we are (and are not) replacing

It is worth restating the scope sharply, because the integration seam is
designed around it. Nix has two distinct phases:

```text
   .nix files                                          build sandbox
   ┌──────────┐    EVALUATION          BUILD          ┌───────────┐
   │ default  │ ───────────────►  .drv ──────────────►│ /nix/store│
   │   .nix   │  (parse + lazily   graph  (run builder │   output  │
   └──────────┘   evaluate to a           in sandbox)  └───────────┘
                  derivation graph)
                  ▲                       ▲
                  │                       │
            aos-nix REPLACES        real Nix STILL OWNS
            ONLY this arrow         this arrow (unchanged)
```

`aos-nix` replaces only the left arrow: turning `default.nix` plus an attribute
path into a `.drv` file (and its transitive `.drv` closure) on disk. The
realisation of that `.drv` into a `/nix/store` output — running the builder in
the sandbox, hashing the NAR, signing, substitution — is **still performed by
real Nix** (`nix-store --realise`, `nix-build`'s build half). We are not writing
a builder, a sandbox, a NAR hasher for build outputs, or a substituter.

This boundary is what makes the integration tractable and the risk bounded.
Eval is pure, deterministic, and produces a small, exactly-checkable artifact
(the `.drv`). Build is the messy, privileged, I/O-heavy part — and we keep using
the battle-tested implementation for it. Section 8 returns to why this split is
load-bearing for the rollout strategy.

The "measure-first" gate from
[motivation and goals](01-motivation-and-goals.md) applies here too: we only
took on this work because instrumentation (`nix-instantiate` wall-clock,
`NIX_SHOW_STATS` thunk/GC/function-call counters) showed that *evaluation*, not
build, is the repeated bottleneck in AOS CI. See
[differential testing and benchmarking](15-differential-testing-and-benchmarking.md)
for that measurement methodology.

---

## 2. The current seam: `NixCli` in `aos-core`

Today the `aos` CLI shells out to the classic Nix tools through two wrappers in
`crates/aos-core/src/nix/`:

- `NixRunner` (`runner.rs`) — a project-rooted wrapper that finds
  `default.nix`, runs `nix-build` / `nix-instantiate`, manages GC roots, opens a
  repl. This is the high-level entry used by `aos build` and `aos test`.
- `NixCli` (`store.rs`) — a thinner, path-explicit wrapper around
  `nix-instantiate`, `nix-build`, and `nix-store` for instantiation,
  realisation, closure queries, and NAR dump/export/import.

The relevant existing signatures (verbatim from the worktree) are:

```rust
// crates/aos-core/src/nix/store.rs
impl NixCli {
    /// Instantiates an attribute from a Nix file, returning the `.drv` path.
    /// Runs `nix-instantiate -f <file> -A <attr>`.
    pub fn instantiate(&self, file: &Path, attr: &str) -> Result<PathBuf> { /* ... */ }

    /// Instantiates a raw expression, returning the `.drv` path.
    pub fn instantiate_expr(&self, expr: &str) -> Result<PathBuf> { /* ... */ }

    /// Builds an attribute (eval + realise), returning the output path.
    pub fn build(&self, file: &Path, attr: &str) -> Result<PathBuf> { /* ... */ }

    /// Realises a `.drv` into its output path. (BUILD phase — never replaced.)
    pub fn realise(&self, drv: &str) -> Result<String> { /* ... */ }
}
```

Every subprocess inherits the `AOS_ROOT`-derived environment from
`aos_nix_env()` so it targets the AOS store layout. Two observations drive the
integration design:

1. **`instantiate` and `instantiate_expr` are exactly the eval boundary.** They
   take a file/expr + attr and return a `.drv` path. That is precisely the
   `eval -> .drv` arrow. `realise` is the build boundary and is out of scope.
2. **`build` is a *composition*: `instantiate` then `realise`.** Once eval is
   abstracted behind a trait, `build` becomes "native-eval to a `.drv`, then
   hand that `.drv` to real Nix's `realise`." The native path only ever touches
   the first half.

This is the seam we formalize.

---

## 3. The `NixEval` trait

We introduce a trait in `aos-core` that names the eval boundary and nothing
more. The deliberate narrowness is the point: the smaller the surface, the
smaller the parity obligation, and the easier the fallback.

```rust
//! The evaluation seam: turning Nix source into a `.drv` graph.
//!
//! [`NixEval`] abstracts the *evaluation* phase of Nix — parsing `.nix`
//! files and lazily reducing the expression tree to a derivation graph
//! written as `.drv` files in the store. It deliberately does **not**
//! cover the *build* phase (realising a `.drv` into a `/nix/store`
//! output); that remains the exclusive job of real Nix via
//! [`NixCli::realise`].
//!
//! Two implementations exist:
//!
//! - [`NixCli`] — shells out to `nix-instantiate`; the correctness
//!   oracle and the permanent fallback.
//! - `NixNative` — the in-process `aos-nix` evaluator (feature-gated;
//!   see the `aos-nix` crate).
//!
//! Selection is governed by the `AOS_NIX_NATIVE` environment variable
//! and the [`select_evaluator`] factory, which defaults to [`NixCli`].

use std::path::{Path, PathBuf};
use anyhow::Result;

/// An evaluator that reduces Nix source to a derivation (`.drv`) path.
///
/// Implementations MUST produce byte-identical `.drv` files and store
/// paths to C++ Nix for every input AOS evaluates; see
/// [RFC-0007 compatibility constraints]. A divergent `.drv` is a
/// correctness bug, not a performance trade-off, because it changes the
/// output store path and forces a full rebuild.
pub trait NixEval {
    /// Evaluates attribute `attr` of the Nix file at `file`, writing the
    /// resulting derivation closure to the store and returning the path
    /// of the top-level `.drv`.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be parsed, evaluation throws
    /// (Nix `throw`/`abort`/type errors), or the `.drv` cannot be
    /// written to the store.
    fn instantiate(&self, file: &Path, attr: &str) -> Result<PathBuf>;

    /// Evaluates a raw expression to a derivation, returning its `.drv`
    /// path. Mirrors `nix-instantiate -E <expr>`.
    ///
    /// # Errors
    ///
    /// As [`NixEval::instantiate`], plus parse errors in `expr`.
    fn instantiate_expr(&self, expr: &str) -> Result<PathBuf>;

    /// Evaluates `expr` and renders the resulting value as a string,
    /// matching `nix-instantiate --eval --strict --json` semantics for
    /// the value kinds AOS uses (strings, ints, bools, lists, attrsets).
    ///
    /// This is the non-derivation eval path used by `aos`'s metadata
    /// queries (package versions, descriptions, system attributes).
    ///
    /// # Errors
    ///
    /// Returns an error on parse failure, evaluation failure, or a value
    /// that cannot be rendered in the requested form.
    fn eval_expr(&self, expr: &str) -> Result<String>;

    /// A human-readable name for diagnostics and logging
    /// (`"nix-cli"` or `"aos-nix"`).
    fn name(&self) -> &'static str;
}
```

Three design decisions in this trait deserve justification.

### 3.1 The trait returns a `.drv` path, not an in-memory value graph

We could have exposed `eval(expr) -> Value` and built `.drv` materialization on
top. We deliberately do not, at the `aos-core` boundary, because:

- The *contract* AOS cares about is the on-disk `.drv` and its store path. A
  trait that returns a `PathBuf` lets the differential harness diff the exact
  bytes (see [§7](#7-the-acceptance-gate-binds-the-seam)). A trait returning an
  in-process `Value` would force the harness to compare a representation that
  C++ Nix never exposes, weakening the parity check.
- It keeps the `aos-core` dependency graph clean. `aos-core` must *not* depend
  on the heavy `aos-nix` umbrella crate — which transitively pulls in the
  `ratchet-*` engine crates (Cranelift via `ratchet-jit`, the GC `ratchet-gc`,
  the `unsafe` core; see
  [generalization and language dialects](28-generalization-and-language-dialects.md)
  §3) — in its default build. The trait lives in `aos-core`; the `NixNative`
  impl lives in `aos-nix` and is wired in only when the feature/flag is enabled.
  `aos-core` thus stays lightweight and `miri`-clean (see
  [§10](#10-the-unsafe-policy)).

### 3.2 `eval_expr` is included but is the *easier* half

`eval_expr` covers the non-derivation queries (`aos show`, version/description
extraction) that `NixRunner::eval_str` / `eval_json` perform today. It is in the
trait because it is on the same eval hot path and benefits from the same
incremental cache (see
[incremental evaluation cache](12-incremental-evaluation-cache.md)). Its parity
bar is *lower* than `instantiate`'s: a wrong version string is a visible bug, but
it does not silently poison the store and cascade into rebuilds. We can therefore
enable `eval_expr` natively somewhat earlier than `instantiate` if we choose,
though the default rollout keeps them gated together for simplicity.

### 3.3 The trait is object-safe and cheaply boxed

All methods take `&self` and return owned/`Result` values; the trait is
object-safe so call sites hold a `Box<dyn NixEval>` chosen once at startup. The
per-call dynamic dispatch cost is irrelevant next to even a single store write,
and it lets the *same* `aos build` code path run under either implementation
with no `#[cfg]` sprinkled through the business logic.

---

## 4. Two implementations behind one trait

### 4.1 `NixCli` — the permanent oracle and fallback

`NixCli` already exists; we implement `NixEval` for it by delegating to its
present subprocess methods (and adding the `eval_expr` arm that wraps
`nix-instantiate --eval --strict --json`). Critically, **`NixCli` is never
removed.** It is three things at once:

- the **default** (`AOS_NIX_NATIVE` unset);
- the **oracle** the differential harness diffs against
  ([differential testing](15-differential-testing-and-benchmarking.md));
- the **runtime fallback** for any input `aos-nix` cannot yet handle (see
  [§6](#6-failure-model-and-fallback)).

This mirrors how a production JIT keeps its interpreter forever (see
[execution tiers](08-execution-tiers-and-cranelift.md)): HotSpot never deletes
its bytecode interpreter; V8 keeps Ignition; LuaJIT keeps its interpreter as
tier 0. The subprocess oracle is `aos-nix`'s tier `-1` — slower than the
tree-walker, but maximally trustworthy because it *is* C++ Nix.

### 4.2 `NixNative` — `aos-nix`

`NixNative` is a thin `aos-core`-facing shim over the `aos-nix` umbrella crate's
public API (the umbrella wires the Nix dialect onto the `ratchet` engine; see
[generalization and language dialects](28-generalization-and-language-dialects.md)
§3). It owns the long-lived evaluator context (interned symbol table, parsed-IR
cache, hash-cons tables in `ratchet-value`, incremental cache handle) so that across many
`instantiate` calls within one `aos` invocation the parse/compile artifacts and
the early-cutoff cache persist (see
[frontend](04-frontend-parser-and-ir.md) and
[incremental cache](12-incremental-evaluation-cache.md)). Sketch:

```rust
/// In-process `aos-nix` evaluator implementing [`NixEval`].
///
/// Holds the evaluator's long-lived, immutable-after-construction
/// tables (interned symbols, parsed IR cache, hash-cons pool) plus a
/// handle to the persistent incremental cache, so repeated
/// instantiations within one process reuse all of it.
pub struct NixNative {
    eval: aos_nix::Evaluator,        // owns IR cache, symbol table, GC arena
    cache: aos_nix::IncrementalCache, // content-addressed early-cutoff cache
}

impl NixEval for NixNative {
    fn instantiate(&self, file: &Path, attr: &str) -> Result<PathBuf> {
        // 1. Parse+resolve `file` (cached by content hash).
        // 2. Force the attr to WHNF; force `derivationStrict` deeply.
        // 3. Serialize via nix-compat -> ATerm -> SHA-256 store path.
        // 4. Write the .drv closure to the store; return top .drv path.
        self.eval.instantiate_to_drv(file, attr, &self.cache)
    }
    fn instantiate_expr(&self, expr: &str) -> Result<PathBuf> { /* ... */ }
    fn eval_expr(&self, expr: &str) -> Result<String> { /* ... */ }
    fn name(&self) -> &'static str { "aos-nix" }
}
```

Note where the SHA-256, ATerm, and store-path logic live: in `nix-compat` (the
Snix/Tvix crate, pinned to a git rev), reused rather than reimplemented. This is
the single most important correctness lever in the whole project — the `.drv`
serialization and store-path hashing are *exactly* the bytes C++ Nix produces
because they come from the same battle-tested formulae. See
[derivation and store compatibility](11-derivation-and-store-compatibility.md)
for the full treatment; here we only note that `NixNative` is a thin orchestration
layer over that crate, not a from-scratch ATerm writer.

---

## 5. Gating: `AOS_NIX_NATIVE` and the selection factory

A single environment variable selects the implementation, read once at process
start by a factory:

```rust
/// Selects the active evaluator from the environment.
///
/// Returns [`NixNative`] when `AOS_NIX_NATIVE` is set to a truthy value
/// (`1`, `true`, `yes`) **and** the `aos-nix` evaluator is compiled in;
/// otherwise returns the [`NixCli`] subprocess evaluator. Defaults to
/// [`NixCli`] — the native path is opt-in until the differential harness
/// is green across the full AOS closure.
///
/// # Errors
///
/// Returns an error only if a requested native evaluator fails to
/// initialize (e.g. the store directory is unwritable). An *unset* or
/// *false* variable never errors.
pub fn select_evaluator(verbose: u8) -> Result<Box<dyn NixEval>> {
    match nix_native_mode() {
        NativeMode::Off => Ok(Box::new(NixCli::new(verbose))),
        #[cfg(feature = "native-eval")]
        NativeMode::On => Ok(Box::new(NixNative::new(verbose)?)),
        #[cfg(feature = "native-eval")]
        NativeMode::Shadow => Ok(Box::new(ShadowEval::new(verbose)?)),
        #[cfg(not(feature = "native-eval"))]
        NativeMode::On | NativeMode::Shadow => {
            // Flag requested native eval but the crate wasn't compiled in.
            // Warn and fall back rather than fail a build.
            tracing::warn!(
                "AOS_NIX_NATIVE set but aos-nix not compiled in; using nix-cli"
            );
            Ok(Box::new(NixCli::new(verbose)))
        }
    }
}
```

The variable has **three** recognized states, not two, because a binary on/off
switch is too blunt for a rollout this risky:

| `AOS_NIX_NATIVE` | Mode      | Behavior                                                                 |
|------------------|-----------|--------------------------------------------------------------------------|
| unset / `0` / `false` | `Off`     | `NixCli` only. The default. Zero behavioral change.                      |
| `1` / `true`     | `On`      | `NixNative` is authoritative; `NixCli` is the per-input fallback (§6).    |
| `shadow`         | `Shadow`  | Run **both**; `NixCli` result is authoritative, `NixNative` is diffed and reported but never returned. |

### 5.1 Why `shadow` mode is the rollout workhorse

`Shadow` is the bridge between "green in the harness" and "trusted in
production." In shadow mode every `instantiate` runs `NixCli` (authoritative,
returned to the caller) *and* `NixNative`, then compares the two `.drv`
closures byte-for-byte. Divergences are logged with full context but **never
affect the build** — the caller always gets the C++ Nix answer.

```text
                       ┌─────────────► NixCli  ──► .drv_A  (RETURNED)
   instantiate(f,a) ───┤
                       └─────────────► NixNative ─► .drv_B  (diffed, dropped)
                                                      │
                              .drv_A == .drv_B ? ─────┘
                                  │ no
                                  ▼
                        emit divergence report
                        (inputs, attr, byte diff)
```

This is the same idea as a "dark launch" or a differential-testing canary: we
get production-traffic coverage of `aos-nix` (every real AOS eval in CI flows
through it) with *zero* risk of a divergent store path reaching the store,
because shadow's native output is computed and discarded. It turns the entire
CI fleet into an always-on extension of the differential harness
([§7](#7-the-acceptance-gate-binds-the-seam)) without betting the cache on it.

Determinate Systems used an analogous "compute it, compare it, but don't trust
it yet" discipline when rolling out parallel Nix evaluation; the lesson — never
flip the authoritative path until the shadow path has been silently correct on
real workloads for a long window — is one we adopt directly. See
[parallel evaluation](13-parallel-evaluation.md).

### 5.2 Granularity: the flag is process-global, scoped per-invocation

`AOS_NIX_NATIVE` is read once per `aos` process. We do **not** support
per-package native/CLI selection within one invocation, because mixing
evaluators within a single derivation closure would make divergence attribution
ambiguous (which evaluator produced the diverging input `.drv`?). A whole `aos
build foo` either evaluates natively or via the CLI. The fallback in
[§6](#6-failure-model-and-fallback) operates at the *top-level instantiate*
granularity, not mid-closure.

### 5.3 Interaction with the Nix flag surface

`AOS_NIX_NATIVE` is an AOS-private variable; it never leaks into the Nix
subprocesses (`aos_nix_env()` does not forward it). When `NixNative` shells out
to real Nix for the *build* half (`realise`), that subprocess is unaware native
eval ever happened — it just receives a `.drv` path. This is only safe because
the `.drv` is byte-identical; a divergent `.drv` would be indistinguishable to
the builder from a legitimate one, which is exactly why parity is non-negotiable
and why the default stays `Off`.

---

## 6. Failure model and fallback

`NixNative` failures are sorted into retryable native gaps, semantic Nix
failures, and internal native bugs; the integration treats those categories very
differently.

### 6.1 Capability failures — fall back transparently

In its early phases `aos-nix` will not implement the entire Nix language and
builtin surface (see [primops and runtime ABI](10-primops-and-runtime-abi.md)
and [roadmap](17-roadmap-and-risks.md)). When it hits a construct it does not yet
support — an unimplemented builtin, an exotic syntax form, a primop edge case —
it returns a *typed* "unsupported" error rather than a wrong answer:

```rust
/// Why a native evaluation could not complete.
pub enum NativeEvalError {
    /// A language/builtin feature aos-nix does not yet implement. The
    /// caller MAY transparently retry with [`NixCli`].
    Unsupported { feature: String, span: Option<SrcSpan> },
    /// A genuine evaluation error (type error, `throw`, assertion).
    /// Both evaluators would fail; do NOT fall back — surface it.
    EvalError { message: String },
    /// An internal invariant was violated (a bug in aos-nix). Fall back
    /// AND emit a loud diagnostic for the bug tracker.
    Internal { message: String },
}
```

The current adapter boundary preserves semantic failures as user-facing message
text. A structured `NixThrow` payload is future hardening, not part of the
checked P1 seam contract.

In `On` mode, the `instantiate` wrapper catches `Unsupported` (and, more
defensively, `Internal`) and **transparently re-runs the whole top-level
instantiation through `NixCli`**. The user gets a correct `.drv`; the only cost
is that this one invocation lost the native speedup. A counter is incremented so
fallbacks are visible in metrics, not silent.

```text
   On mode:
   instantiate(f,a) ─► NixNative ─┬─ Ok(drv) ───────────────► return drv
                                  │
                                  ├─ Unsupported / Internal ─► NixCli(f,a) ─► drv
                                  │      (count++, log)            (fallback)
                                  │
                                  └─ EvalError ──────────────► return error
                                         (do NOT fall back: real Nix
                                          would also reject this input)
```

The distinction between `Unsupported` and `EvalError` is essential. If `aos-nix`
correctly reproduces a Nix *type error* or `throw`, falling back to `NixCli`
would just reproduce the same error more slowly — and worse, could *mask* a case
where `aos-nix` threw when real Nix would have succeeded. So only `Unsupported`
and `Internal` trigger fallback; `EvalError` is surfaced as-is, and the
differential harness independently verifies that `aos-nix` and `NixCli` agree on
*which inputs error* (a thrown-error mismatch is a harness failure just like a
`.drv` byte mismatch).

### 6.2 Divergence failures — must never reach production

A *divergence* — `aos-nix` produces a `.drv` that differs from C++ Nix's — is
the one failure the runtime cannot self-correct, because by definition the
native evaluator believes it succeeded. There is no in-process signal. This is
precisely why:

- the default is `Off`,
- `Shadow` mode exists to surface divergences against real traffic without
  trusting the native result, and
- the **acceptance gate** ([§7](#7-the-acceptance-gate-binds-the-seam)) blocks
  `On`-by-default until divergence is provably zero across the closure.

In `On` mode we additionally support an optional *belt-and-suspenders*
`AOS_NIX_NATIVE_VERIFY=1` that, for a sampled fraction of top-level
instantiations, re-runs `NixCli` and diffs — a production canary that can be
left on in CI at a low sample rate even after default-on, catching any
long-tail divergence (see [§7.2](#72-the-long-tail-risk)).

---

## 7. The acceptance gate binds the seam

The integration is governed by one hard rule:

> `AOS_NIX_NATIVE` defaults to `On` **only after** the differential `.drv`-diff
> harness is green across the *entire* AOS package closure, and stays green in
> CI.

The harness (specified in
[differential testing and benchmarking](15-differential-testing-and-benchmarking.md))
instantiates every attribute in the AOS package set with both `NixCli` and
`NixNative` and asserts byte-identical `.drv` closures *and* identical
error/no-error outcomes. It is the same `NixEval` trait that makes this trivial
to wire: the harness is just a third consumer that holds *both* boxes and
compares.

### 7.1 Phased flip

The flip is staged, not a single switch:

```text
   Phase A  default Off, harness in CI (PRs blocked on regressions)
   Phase B  default Off, Shadow mode on in CI (real-traffic divergence watch)
   Phase C  default On for `eval_expr` only (low-blast-radius metadata path)
   Phase D  default On for `instantiate`, AOS_NIX_NATIVE_VERIFY sampling kept
   Phase E  verify sampling reduced; NixCli retained as permanent fallback
```

`eval_expr` flips before `instantiate` (Phase C before D) precisely because of
the blast-radius asymmetry from [§3.2](#32-eval_expr-is-included-but-is-the-easier-half):
a wrong metadata string is visible and harmless; a wrong `.drv` is invisible and
catastrophic.

### 7.2 The long-tail risk

The dominant risk in this whole RFC is a *long tail* of `.drv` divergence: the
harness is green on everything we tested, but some rarely-evaluated package, or
some construct that only appears under a specific system configuration, diverges
in the field and silently forces a toolchain rebuild. The integration mitigates
this with four independent layers, none of which is sufficient alone:

1. **Default `Off`** — nothing happens until someone opts in.
2. **`Shadow` mode in CI** — every real eval is diffed before we trust native.
3. **`AOS_NIX_NATIVE_VERIFY` sampling** — a residual canary even after default-on.
4. **Permanent `NixCli` fallback** — flipping back is one env var, no code change.

The cost of being wrong is asymmetric and brutal (a full from-source rebuild),
so the rollout is deliberately paranoid. This is the single place in RFC-0007
where we accept "slower but certainly correct" over "faster but maybe wrong"
without hesitation.

---

## 8. Why the eval/build split makes the rollout safe

The eval-only scope ([§1](#1-what-we-are-and-are-not-replacing)) is not just a
scoping convenience; it is what makes the fallback *cheap and total*.

Because `aos-nix` only ever produces a `.drv` and hands it to real Nix to build,
falling back is a pure function of inputs: re-running `nix-instantiate` on the
same file+attr yields the same `.drv` C++ Nix always would. There is no
partially-mutated state, no half-built output, no sandbox to clean up. The
native and fallback paths converge on the exact same downstream artifact. A
fallback in `On` mode is therefore *observably indistinguishable* from never
having tried native eval at all, except slower.

Contrast this with a hypothetical native *builder*: a fallback mid-build would
have to reconcile partial store state, and the trust surface would explode. By
confining `aos-nix` to the pure, idempotent, exactly-checkable eval phase, the
integration keeps "try native, fall back to CLI" a safe, stateless retry. This
is the same reasoning that lets a speculative JIT deoptimize back to the
interpreter at any safepoint (see
[execution tiers](08-execution-tiers-and-cranelift.md)): the slow path is always
a correct, side-effect-compatible continuation of the fast path. Here, `NixCli`
*is* the deopt target for the whole evaluator.

---

## 9. Import-from-derivation (IFD) and the eval->build handoff

The eval/build split of [§1](#1-what-we-are-and-are-not-replacing) draws a clean
line: `aos-nix` evaluates to a `.drv`, real Nix builds. **Import-from-derivation
(IFD) is the one place that line is crossed *during evaluation itself*.** It is
worth its own section precisely because it couples the two phases the rest of
this RFC works to keep separate.

### 9.1 What IFD is

IFD occurs when evaluation forces a value whose production requires a derivation
to be **built first** — most often passing a store path that is itself a build
output to a filesystem-reading builtin (`import`, `readFile`, `readDir`,
`pathExists`) so that evaluation cannot proceed until that output physically
exists. Quoting the Nix manual: "Passing an expression `expr` that evaluates to
a store path to any built-in function which reads from the filesystem
constitutes Import From Derivation (IFD)," and "When the store path needs to be
accessed, evaluation will be paused, the corresponding store object realised,
and then evaluation resumed." That pause is the defining property: IFD is the
single point where eval blocks on the *builder* rather than on more eval.

This is also why IFD is the canonical example of "genuinely blocking eval-time
I/O" — the work the fiber model of [parallel evaluation](13-parallel-evaluation.md)
§5.5 exists to absorb. Every other eval-time read in a from-source distro is a
fast local syscall; IFD is the one that can block for *seconds to minutes* while
a builder runs.

### 9.2 The handoff: aos-nix detects, AOS builds, eval resumes

`aos-nix` never builds anything itself — it only evaluates (see
[§1](#1-what-we-are-and-are-not-replacing)). The IFD handoff is therefore an
explicit hand-back to the AOS build path:

```text
   aos-nix eval ──force store-path-reading builtin
        │
        ├─ detect IFD demand: this value needs derivation D BUILT
        │
        ▼
   realise D via the AOS build path  ── NOT aos-nix:
        nix-store --realise  /  the `aos build` orchestrator
        (NixCli::realise — the SAME build half §1 never replaces)
        │
        ▼  D's output now exists in the store
   re-enter evaluation: read the built output's contents,
   resume forcing where eval paused
```

Concretely: when the native evaluator forces a thunk that demands a not-yet-built
output, it computes and writes that output's `.drv` (still pure eval), then
**realises it through `NixCli::realise` / the `aos build` orchestrator** — the
exact build boundary [§1](#1-what-we-are-and-are-not-replacing) and the
[`NixEval`](#3-the-nixeval-trait) trait keep out of `aos-nix`. Eval blocks on
that realisation, then resumes with the built output's bytes re-entering the
evaluation as an ordinary value. The native evaluator is still doing *only* the
eval arrow; the build arrow is delegated whole, mid-eval.

### 9.3 Integration with the fiber model

An IFD demand is exactly the blocking point the fiber runtime
([parallel evaluation](13-parallel-evaluation.md) §5.5) is designed for. Rather
than pinning an OS thread on `block_on(realise(D))` and starving the work-stealing
pool, the **IFD-blocked fiber parks** — its whole synchronous recursive force
stack is saved on the fiber stack — and its worker work-steals other ready eval
nodes. The realisation runs as a subprocess driven via the tokio reactor; on
build completion the fiber is rescheduled onto some worker and resumes. This
unifies "waiting on a build" with "waiting on a peer's claimed thunk"
([13](13-parallel-evaluation.md) §3.3) under one scheduler: both park-or-steal,
neither spins, neither blocks a compute worker. IFD is the headline justification
for the fiber layer existing at all — a from-source distro that minimizes IFD
mostly needs the synchronous core, and the fiber layer's turn-on is measure-gated
on real IFD/fetch concurrency ([13](13-parallel-evaluation.md) §5.5.5).

### 9.4 Incremental cache and IFD

An IFD result is keyed on the **content address of the built output**, not on the
expression that triggered it: the bytes that re-enter evaluation are exactly the
NAR contents of a realised store path. The incremental cache
([incremental evaluation cache](12-incremental-evaluation-cache.md)) therefore
stores the IFD node under that content hash, so a repeat evaluation whose IFD
input realises to the same output **hits early cutoff** — the downstream eval is
not re-forced, and, where the output is already in the store, the build is not
re-run. IFD's cost (a blocking build mid-eval) is thus paid once and memoized
like any other node, which matters because IFD is otherwise the most expensive
single thing eval can do.

### 9.5 Parity: IFD semantics must match C++ Nix exactly

IFD is *behaviorally* part of evaluation: *when* a build is triggered, *which*
output re-enters eval, and *what* its contents drive next are all observable in
the resulting `.drv` graph. If `aos-nix` triggers an IFD build at a different
point, or reads a different output, or orders the realisation differently in a
way that changes what eval sees, the downstream `.drv` diverges — the one
failure this whole integration is built to prevent ([§6.2](#62-divergence-failures-must-never-reach-production)).
So IFD semantics are pinned to the C++ Nix oracle like everything else: the
differential harness ([differential testing and benchmarking](15-differential-testing-and-benchmarking.md))
must agree on IFD-bearing inputs, and `Shadow` mode ([§5.1](#51-why-shadow-mode-is-the-rollout-workhorse))
diffs them against real traffic.

IFD is widely *discouraged* in nixpkgs — the manual notes it forces realisation
to interleave with evaluation, defeating the "evaluate fully, then build the whole
plan" model and serializing builds the evaluator can only discover one path at a
time. AOS minimizes IFD for the same reasons. But "discouraged" is not "absent":
wherever AOS actually uses IFD, `aos-nix` **MUST support it** with byte-identical
semantics, because a missing or divergent IFD is indistinguishable downstream from
any other parity break. Where `aos-nix` cannot yet reproduce a given IFD form, it
returns the typed `Unsupported` error and falls back to `NixCli`
([§6.1](#61-capability-failures-fall-back-transparently)) — never a wrong answer.

---

## 10. The `unsafe` policy

AOS's workspace rule (`CLAUDE.md`) is blunt: **"Avoid `unsafe` at all costs.
Use it only for an explicit, justified performance need, and document the
invariants with a `// SAFETY:` comment."** The `aos-nix` evaluator is the one
part of the monorepo that needs a *standing, scoped waiver* of the "at all costs"
framing — concretely, the waiver now applies to the `ratchet-*` UNSAFE engine
crates (`ratchet-value`, `ratchet-gc`, `ratchet-jit`, `ratchet-cache`,
`ratchet-parallel`; see
[generalization and language dialects](28-generalization-and-language-dialects.md)
§3), where these mechanisms live, while the Nix-band `aos-nix-*` dialect/frontend
crates stay safe — because several of its core mechanisms are irreducibly
`unsafe` — and the
unlimited-budget mandate ([roadmap](17-roadmap-and-risks.md) §0), which commits
the full performance stack rather than a subset, *enlarges* that surface, so the
waiver is accompanied by commensurately heavier verification (below). The
`unsafe` mechanisms:

1. **NaN-boxed / tagged values** (see [value representation](05-value-representation.md)).
   The optimized value layout reinterprets bit patterns and reads payloads
   through tagged pointers. Decoding a tag and dereferencing the payload is
   `unsafe` because the type system cannot prove the tag matches the payload.
2. **JIT function-pointer calls** (see [execution tiers](08-execution-tiers-and-cranelift.md)).
   Cranelift emits machine code into an executable buffer; calling it means
   `transmute`-ing a raw code pointer to an `extern "C" fn(...)` of the runtime
   ABI and invoking it. Rust cannot verify that the emitted code matches the
   declared signature or calling convention — the community consensus is that
   such calls are *innately* unsafe and there is no way to make the compiler
   check the convention.
3. **Raw heap / GC** (see [memory management and GC](06-memory-management-and-gc.md)).
   The bump arena and the precise copying collector manage raw memory, rewrite
   pointers during a move, and reinterpret object headers — none of which fits
   the borrow checker.
4. **Stackful fibers** (see [parallel evaluation](13-parallel-evaluation.md) §5.5).
   The green-thread runtime that parks an I/O-blocked eval node switches stacks,
   which is `unsafe` by construction (the `corosensei`/`may`-style stack-switch
   primitive). Confined to the fiber scheduler module.
5. **Lock-free concurrency** (see [parallel evaluation](13-parallel-evaluation.md)).
   The compare-and-swap (CAS) thunk protocol and the work-stealing deques use
   atomics and shared mutation that the borrow checker cannot express. This is
   the surface the `loom`/Miri audit (§3.6 there, register `R-4`) exists to
   verify.
6. **`mmap` and out-of-core paths** (see
   [memory management and GC](06-memory-management-and-gc.md) and
   [the incremental cache](12-incremental-evaluation-cache.md)).
   The `mmap`'d CA store, the zero-copy reads into mapped pages, and the
   `madvise` hints are raw-syscall, raw-pointer operations.

These are not gratuitous; they are the mechanisms by which `aos-nix` beats C++
Nix at all — and under the unlimited-budget mandate the *full* set (including the
LLVM AOT tier-3 and the concurrent moving collector) is built, so the surface is
larger than a typical crate's, not smaller. The policy that fences it is what
makes the standing waiver responsible.

### 10.1 The fence: a small, audited `unsafe` core

```text
   ┌──────────────────────────────────────────────────────────┐
   │  aos-nix                                                   │
   │                                                            │
   │  ┌────────────────────┐   safe, #![forbid(unsafe_code)]    │
   │  │  tree-walk oracle   │   tier 0 interpreter, frontend,    │
   │  │  + frontend + IR    │   nix-compat glue, harness         │
   │  └────────────────────┘   (miri-clean, sanitizer-clean)    │
   │            │ trait calls                                    │
   │            ▼                                                │
   │  ┌────────────────────┐   #![deny(unsafe_op_in_unsafe_fn)] │
   │  │  unsafe core:       │   every `unsafe` block carries a   │
   │  │  value-repr, jit,   │   // SAFETY: comment; reviewed by   │
   │  │  gc, runtime-abi    │   a second maintainer; fuzzed       │
   │  └────────────────────┘                                    │
   └──────────────────────────────────────────────────────────┘
```

Concretely:

- The **tree-walk oracle, parser, IR, `nix-compat` glue, and the differential
  harness** are written in 100% safe Rust and carry `#![forbid(unsafe_code)]`.
  This is the *correctness* implementation of the evaluator (it is the in-process
  oracle the JIT tiers are validated against), and it must remain analyzable by
  `miri` and the address/UB sanitizers. CI runs the conformance suite under
  `miri` against this tree (see [§10.3](#103-tooling-discipline)).
- The **`unsafe` mechanisms** (value bit-twiddling, JIT calls, GC) are isolated
  into dedicated modules. Those modules use `#![deny(unsafe_op_in_unsafe_fn)]`
  so that even inside an `unsafe fn` every `unsafe` operation is an explicit,
  individually-commented block. Each block carries a `// SAFETY:` comment
  stating the invariant it relies on and why it holds.
- **No `.unwrap()`/`.expect()` in production paths** still applies to `aos-nix`
  exactly as everywhere else in the workspace; the `unsafe` waiver is *only*
  about memory/codegen primitives, not about error handling.

### 10.2 Why the oracle being safe matters for the *waiver*

The reason we can responsibly run `unsafe` JIT code in a build tool is that we
never have to *trust* it for correctness — only for speed. Every native result
is, in principle, checkable against the safe tree-walk oracle and ultimately
against `NixCli`. The `unsafe` tiers are an *optimization* of an answer the safe
tiers can independently produce:

```text
   trust gradient (least → most trusted):
     unsafe JIT tiers  <  safe tree-walk oracle  <  NixCli (C++ Nix)
            └─ validated against ──┘     └─ validated against ──┘
```

This is the same defense-in-depth that lets HotSpot ship a wildly `unsafe`
optimizing JIT inside a memory-safe-by-reputation platform: the interpreter is
the trusted core and the JIT must match it or be discarded via deopt. In
`aos-nix` the chain extends one further link to the subprocess oracle. So the
`unsafe` surface, while real, is never the *final* arbiter of a store path — the
differential gate ([§7](#7-the-acceptance-gate-binds-the-seam)) is.

### 10.3 Tooling discipline

The standing discipline that accompanies the waiver:

| Control                              | Applies to                  | Purpose                                              |
|--------------------------------------|-----------------------------|------------------------------------------------------|
| `#![forbid(unsafe_code)]`            | oracle, frontend, harness   | guarantee the trusted core has zero `unsafe`         |
| `#![deny(unsafe_op_in_unsafe_fn)]`   | value-repr, jit, gc modules | force per-operation `// SAFETY:` justification       |
| `cargo miri` on the conformance suite| safe oracle tree            | catch UB in the path that doesn't need real codegen  |
| ASan/UBSan CI job                    | full crate                  | catch heap/UB bugs in the `unsafe` core              |
| `cargo fuzz` targets                 | value decode, GC, ATerm     | stress the bit-level and pointer-rewriting code      |
| `loom` model checker                 | CAS thunk protocol, deques  | exhaustively permute atomics interleavings (`R-4`)   |
| ThreadSanitizer (TSan) CI job        | the parallel binary         | catch races the lock-free + fiber paths can hide     |
| two-maintainer review of `unsafe`    | every new `unsafe` block    | no `unsafe` lands without a second set of eyes        |

`miri` cannot execute JIT-compiled machine code or the raw-syscall paths, which
is exactly why the architecture keeps a *fully functional* safe tree-walk
evaluator that produces the same `.drv`: it gives `miri` and the sanitizers a
complete, exercisable program to analyze. The `unsafe` tiers are then differential-
tested against that safe program.

---

## 11. Observability and operator controls

Because this is a risky swap behind a flag, the integration is instrumented so an
operator can always answer "which evaluator produced this, and did they agree?"

- **`name()` in logs.** Every top-level instantiation logs which `NixEval`
  implementation ran (and whether a fallback occurred), via `tracing`.
- **Counters.** Native successes, native fallbacks (by `NativeEvalError`
  variant), shadow divergences, and verify-sample mismatches are counted and
  exposed in `aos`'s stats output, mirroring the spirit of `NIX_SHOW_STATS`
  (thunks forced, GC bytes, function calls) so eval performance and correctness
  are both visible. See
  [differential testing and benchmarking](15-differential-testing-and-benchmarking.md).
- **Divergence reports.** On any shadow/verify mismatch, `aos-nix` writes a
  self-contained report: the file+attr, the two `.drv` paths, and a byte-level
  diff of the ATerm, enough to reproduce and bisect without rerunning the whole
  closure.
- **`AOS_NIX_NATIVE` is the kill switch.** Reverting to fully-trusted C++ Nix
  eval is `AOS_NIX_NATIVE=0` (or unset) — a one-line operator action, no
  rebuild, no redeploy. This is the property that makes default-on tolerable:
  the blast radius of an undiscovered divergence is bounded by how fast we can
  unset one variable.

---

## 12. Summary of the contract

```text
   ┌──────────────────────────────────────────────────────────────────┐
   │ aos build / aos test / aos show                                   │
   │            │                                                      │
   │            ▼   select_evaluator(AOS_NIX_NATIVE)                    │
   │     ┌─────────────────────────────┐                               │
   │     │      dyn NixEval             │                               │
   │     │  instantiate / eval_expr     │   <- the ONLY replaced seam   │
   │     └─────────────────────────────┘                               │
   │        │                  │                                        │
   │   NixCli (default,    NixNative (aos-nix, opt-in)                  │
   │   oracle, fallback)       │  on Unsupported/Internal ─► NixCli     │
   │        │                  ▼                                        │
   │        └────────────►  .drv path  ◄── byte-identical (gated)       │
   │                           │                                        │
   │                           ▼  NixCli::realise  (BUILD, never native)│
   │                       /nix/store output                            │
   └──────────────────────────────────────────────────────────────────┘
```

The integration is intentionally the least clever part of RFC-0007. All the
ambition lives below the `NixEval` trait — the GC, the tiers, the incremental
cache, the hidden classes. At the seam itself we want *boredom*: a narrow trait,
a default-off flag, a shadow mode, a transparent fallback, an `unsafe` core fenced
behind a safe oracle, and one env var to undo everything. The riskier the engine,
the more conservative the harness around it must be.

---

## 13. Open questions

- **Long-lived daemon vs per-invocation process.** **Decision (closed):
  per-invocation first.** The first cut is the per-invocation `aos` process
  model, where the GC is the bump-arena Tier A (allocate, never free, drop at
  exit; see [memory and GC](06-memory-management-and-gc.md)). A persistent eval
  daemon (amortizing warmup, sharing the in-memory cache across invocations) is
  a **measure-gated** follow-up justified only by the per-process numbers; the
  `NixEval` seam is unchanged by that flip, but the implementation would move to
  the generational/concurrent GC tier and the trait would gain an explicit
  lifecycle (`shutdown`/`flush`). Not built until the data demands it.
- **Sharing the incremental cache across machines.** **Decision (closed): beside
  the trait, not through it.** The early-cutoff cache
  ([incremental cache](12-incremental-evaluation-cache.md)) is content-addressed
  and rides AOS's existing Attic infrastructure exactly as the build-output
  cache does today. `NixEval` stays minimal and transport-agnostic: the
  evaluator reads/writes the local cache store, and replication (push/pull) is
  an out-of-band concern beside the trait, not a set of trait methods.
- **`eval_expr` value-rendering parity.** **Decision (closed): a dedicated
  `--eval --json` differential check, owned by
  [differential testing](15-differential-testing-and-benchmarking.md), required
  green before Phase C.** Matching `nix-instantiate --eval --json` formatting
  exactly (float formatting, attr ordering in JSON, string-context handling) is
  a distinct surface from the `.drv` harness and gets its own small gate; it is
  low blast radius but blocks the metadata path's flip to native.
- **`nix-compat` / Cranelift revision pinning.** **Decision (closed): pin exact
  git revisions, vendor only patched modules, gate bumps in CI.** `NixNative`
  depends on the Snix `nix-compat` crate (ATerm/store-path/hash logic) and on
  Cranelift (whose user-stack-maps API is new); both are pre-1.0 and move
  (Tvix → Snix rename, March 2025). The policy: pin both to specific revs
  recorded in `Cargo.lock`; carry local patches as a small vendored overlay
  rather than forking wholesale; and treat a rev bump as a change that must pass
  the full differential `.drv` harness before it lands. A breaking change
  upstream is then a *maintenance* event on the parity-critical path, never a
  silent *correctness* event — the gate still diffs every byte.

---

## Implementation checklist

Per-feature tracker for AOS integration (the `NixEval` seam, the `AOS_NIX_NATIVE` gating and staged rollout, the failure/fallback model, the IFD eval→build handoff, and the `unsafe`-core fence); master roll-up: [implementation checklist (all phases)](22-implementation-checklist-all-phases.md). Per the unlimited-budget mandate, every item here is in scope — including research-grade ones — built in dependency order and gated by the differential harness, never cut for scope.

The seam itself is the *least clever* part of the RFC and is **P1** scope (`S-16`): a narrow trait, a default-off flag, a transparent fallback, a fenced `unsafe` core. The riskier the engine below it, the more conservative this harness around it must be. Every flip from Off → Shadow → On is unlocked by a differential-harness result ([15](15-differential-testing-and-benchmarking.md)), never by belief.

### The `NixEval` trait and `NixCli` fallback (§2–§4)

- [x] `NixEval` trait in `aos-core` (`instantiate`, `instantiate_expr`, `eval_expr`, `name`) — object-safe, returns a `.drv` `PathBuf` (not an in-memory value graph) so the harness diffs exact bytes; `aos-core` never depends on the heavy `aos-nix` crate in its default build (§3, §3.1, §3.3) — **P1**, `S-16`.
- [x] `impl NixEval for NixCli` by delegating to the existing subprocess wrappers, adding the `eval_expr` arm wrapping `nix-instantiate --eval --strict --json`; `NixCli` is the **permanent** default + oracle + runtime fallback, never removed (§4.1) — **P1**, `S-16`; the tier `-1` of the trust gradient.
- [x] `NixNative` shim over the `aos-nix` public API, reused across `instantiate` calls (§4.2). The P1 handle owns verbosity, tree-walk options, parse-cache configuration, and the optional IFD realizer; exposes file-backed and raw-expression instantiation plus in-memory `NativeDrvClosure` output; materializes closures only after the native derivation builder has produced ATerm bytes and store paths through the pinned `nix-compat` derivation/store-path APIs; and remains the single `aos-core` integration handle behind the `native-eval` feature. Later hash-cons table and incremental-cache handles attach to this same shim as those phases land — `NixNative` stub **P1**, real impl grows across **P1–P7**; `S-13`/`C-5`.

### Gating: `AOS_NIX_NATIVE` and the selection factory (§5)

- [x] `select_evaluator` factory reading `AOS_NIX_NATIVE` once at process start; three states `Off`/`On`/`Shadow`, defaulting `Off`; `native-eval` feature-gate with warn-and-fall-back when the flag requests native but the crate is not compiled in (§5) — **P1**, `S-16`/`S-2`.
- [x] `Shadow` mode implementation: `ShadowEval` runs `NixCli` first and returns its authoritative result, then evaluates the same file/raw expression through `NixNative`, compares `.drv` closures byte-for-byte or strict JSON values, records match/divergence/incomplete counters, and never materializes native output into the store on the shadow path (§5.1) — **P2-hardened** implementation, rollout **Phase B** ([15](15-differential-testing-and-benchmarking.md) §2.6).
- [ ] Shadow-mode fleet activation and soak: CI/fleet jobs must run the shadow evaluator broadly enough to satisfy the four-week zero-divergence gate before rollout credit is claimed (§5.1; [15](15-differential-testing-and-benchmarking.md) §8.1).
- [x] Process-global, per-invocation granularity (no mid-closure evaluator mixing); `AOS_NIX_NATIVE` never forwarded into Nix subprocesses (`aos_nix_env()`) so the build half is unaware native eval happened (§5.2, §5.3) — **P1**, `S-16`.

### Failure model and fallback (§6)

- [x] `NativeEvalError` taxonomy — `Unsupported { feature, span: Option<SrcSpan> }` (transparent `NixCli` retry, preserving a span where the native frontend has one), message-only `EvalError { message }` (semantic native evaluation failures surface as-is and do **not** fall back), `Internal { message }` (fall back + `tracing::warn!` diagnostic) — with per-reason fallback counters so retries are visible, not silent (§6.1) — **P1**, `S-16`; the `Unsupported`-vs-`EvalError` split is what the harness error-parity check guards, while structured thrown payloads remain future hardening beyond the current adapter boundary.
- [x] Divergence handling: there is no in-process signal, so it is defended by the four layers — default `Off`, `Shadow`, `AOS_NIX_NATIVE_VERIFY` canary verification, and permanent `NixCli` fallback. `aos_nix_env()` strips native-mode variables from Nix subprocesses, shadow/verify divergences are counted and traced rather than self-corrected, and authoritative native `On` verifies closures before materialization only when `AOS_NIX_NATIVE_VERIFY` is enabled while falling back only for the documented `Unsupported`/`Internal` classes (§6.2, §7.2) — rollout **Phases A–E**, `C-18`.

### The acceptance gate and staged flip (§7)

- [ ] The hard rule wired into CI: `AOS_NIX_NATIVE` defaults `On` **only after** the differential `.drv`-diff harness is byte-green across the *entire* AOS closure and stays green (§7) — `C-18`; the falsifiable cutover gate is owned by [15](15-differential-testing-and-benchmarking.md) §8.1.
- [ ] The phased flip A→E (Off+harness → Shadow → On-`eval_expr` → On-`instantiate`+verify-sampling → verify-reduced+permanent-fallback); `eval_expr` flips before `instantiate` for blast-radius asymmetry (§7.1) — rollout schedule, `S-16`/`C-4`.

### IFD and the eval→build handoff (§9)

- [x] IFD detection during forcing of a store-path-reading builtin; hand-back to the AOS build path (`NixCli::realise`), never aos-nix itself; re-enter eval with the built output's bytes (§9.1, §9.2). `TreeWalk` validates derivation string context before filesystem reads, materializes native-known `.drv` inputs before invoking an `IfdRealizer`, reports unsupported IFD when no realizer is configured, and `aos-core` wires `NixNative` to a realizer that calls the permanent `NixCli` fallback's `nix-store --realise`; failures stay fallback-eligible instead of being misclassified as semantic eval errors — **P1** semantics, `C-27`/`S-1`.
- [ ] IFD-blocked **fiber parks** (its whole synchronous force stack saved) while the realisation runs as a tokio-driven subprocess, unifying "waiting on a build" with "waiting on a peer's claimed thunk" under one scheduler (§9.3) — **P3.5**, `C-16`/`C-27` ([13](13-parallel-evaluation.md) §5.5).
- [ ] IFD result keyed on the **content address of the built output** for incremental-cache early cutoff; IFD semantics pinned byte-identical to C++ Nix (when/which/what), with `Unsupported` fallback where a form is not yet reproduced (§9.4, §9.5) — **P2** caching, `C-27`/`R-10`; gated by the differential harness on IFD-bearing inputs.

### The `unsafe` policy and tooling discipline (§10)

- [ ] Standing, scoped waiver of the workspace "avoid `unsafe` at all costs" rule for the `ratchet-*` UNSAFE engine crates only (the Nix-band `aos-nix-*` crates stay safe; see [28](28-generalization-and-language-dialects.md) §3), covering the six irreducibly-`unsafe` mechanisms (tagged values, JIT fn-ptr calls, raw heap/GC, stackful fibers, lock-free CAS, `mmap`/out-of-core) — *enlarged* by the unlimited-budget mandate, hence heavier verification (§10, §10.0) — `S-17`; this checklist only **references** the §10 policy, it does not restate it.
- [x] Current Phase-1 safe-crate fence: the monolithic `aos-nix`
      frontend/tree-walk/native-glue crate carries `#![forbid(unsafe_code)]`,
      checks under that fence, and source scans find no Rust `unsafe` forms in
      the evaluator crate; remaining `unsafe*` spellings there are Nix builtin
      names or docs/comments (§10.1, §10.2) — **historical P1** discipline,
      `S-17`; this predates the `ratchet-*` split and is not a claim about the
      current `ratchet-oracle` crate.
- [ ] **Discovered oracle unsafe-fence drift:** `ratchet-oracle` still presents
      itself as the safe reference implementation and denies unsafe by default,
      but local allowances now contain a stable-arena thunk dereference, a
      trusted atomic-value decode, and x86-64/AArch64 native stack-pointer
      reads. Close by either moving these primitives behind a separately
      reviewed unsafe substrate API and restoring a source-scan-clean oracle,
      or formally reclassifying the crate and extending the unsafe manifest,
      Miri/sanitizer gates, and two-maintainer review rule to every allowance.
      The closeout must enumerate all real unsafe tokens and prove that no
      unmanifested exception bypasses the crate-level lint (§10.1-§10.3).
- [ ] Final safe/unsafe workspace fence remains: split safe
      oracle/frontend/compat/harness crates with `#![forbid(unsafe_code)]`,
      future unsafe value-repr/JIT/GC/runtime-ABI crates with
      `#![deny(unsafe_op_in_unsafe_fn)]` and per-block `// SAFETY:`, and wire
      the miri/sanitizer clean trust-core CI (§10.1, §10.2) — discipline held
      every later phase, `S-17`.
- [x] Current `ratchet-jit` unsafe-discipline precursor:
      `ratchet-jit::safety::jit_unsafe_discipline()` records the JIT crate's
      unsafe-boundary manifest: `#![deny(unsafe_op_in_unsafe_fn)]`, local
      `// SAFETY:` invariant comments, second-reviewer requirement, sanitizer-CI
      requirement, and the innately unsafe code-pointer-transmute call boundary.
      Tests assert the manifest, prove the crate root declares the lint, and scan
      current JIT sources for real `unsafe`/`extern`/`transmute` code tokens
      outside line comments and ordinary strings. This keeps today's JIT crate
      metadata-only; actual unsafe JIT blocks, CI jobs, and review automation
      remain open.
- [ ] Tooling discipline as standing CI controls: `cargo miri` on the conformance suite, ASan/UBSan, `cargo fuzz` (value decode / GC / ATerm), `loom` (CAS protocol, deques — `R-4`), ThreadSanitizer (parallel binary), two-maintainer review of every new `unsafe` block; `.unwrap()`/`.expect()` ban still applies (§10.3) — **P1**→**P8** as each mechanism lands, `S-17`.

### Observability and operator controls (§11)

- [x] Current AOS integration seam instrumentation: top-level `eval_expr`/`instantiate` seam operations log the selected evaluator name, fallback warnings record native/fallback evaluator names plus fallback reason/count, `AOS_NIX_NATIVE=0`/unset selects CLI/off mode and native-control env vars are stripped from child Nix subprocesses, and grouped native success/fallback/shadow/verify counters plus shadow/verify divergence events carry operation and optional file/attr context (§11) — **P1** seam instrumentation, `S-16`; gate: `aos-core` native instrumentation tests.
- [ ] Full operator report surface remains: promote shadow/verify events into self-contained divergence reports with file+attr, both `.drv` paths, and ATerm byte diffs; wire later all-internal/`aos-nix` subsystem counters as those subsystems land, mirroring `NIX_SHOW_STATS` where applicable (§11) — **P1+** observability/reporting, `S-16` ([24](24-observability-and-diagnostics.md), [15](15-differential-testing-and-benchmarking.md) §4).

### Open questions, decided (§13)

- [x] §13 decision record is closed for the current seam: per-invocation-first evaluation, cache transport beside the `NixEval` trait, a dedicated `eval_expr --eval --json` parity gate recorded as required before Phase C, and exact revision pinning for the currently present external evaluator-format dependency (`nix-compat`) are documented and reflected in the P1 seam/pinning substrate (§13) — decisions closed; gate: docs plus `NixEval`/`eval_expr` seam tests and workspace dependency pin audit.
- [x] Current Cranelift dependency-pinning precursor:
      `ratchet-jit` now depends only on `cranelift-codegen` and
      `target-lexicon` for CLIF signature metadata, with the resolved
      Cranelift-facing versions pinned exactly in the workspace manifest and
      `crates/Cargo.lock`. No `cranelift-jit`, executable memory manager, symbol
      registration, native wrapper, or emitted-code call boundary is present yet.
- [ ] §13 follow-through remains: implement or deliberately defer the persistent eval daemon based on measurement, build the Attic-backed eval-cache transport beside the trait, run the dedicated `eval_expr --eval --json` parity gate before Phase C, and enforce `nix-compat`/Cranelift bump gates with the full harness (§13) — build as recorded; gate: implementation, CI wiring, and full harness bump enforcement.

## References

- Cranelift JIT — `JITBuilder`/`JITModule`, external symbol registration via
  `symbol`/`symbol_lookup_fn`, libcall name resolution:
  <https://docs.rs/cranelift-jit/latest/cranelift_jit/struct.JITModule.html>,
  <https://docs.wasmtime.dev/api/cranelift_jit/struct.JITBuilder.html>,
  <https://github.com/bytecodealliance/cranelift-jit-demo>
- rustc Cranelift backend JIT driver (real-world `symbol_lookup_fn` usage):
  <https://github.com/rust-lang/rust/blob/main/compiler/rustc_codegen_cranelift/src/driver/jit.rs>
- GHC strictness/demand and worker-wrapper (eager forcing, call-by-name for
  used-at-most-once, absent-argument elimination):
  <https://downloads.haskell.org/ghc/latest/docs/users_guide/using-optimisation.html>
- Tvix/Snix `nix-compat` — `Derivation`, ATerm serialization/parser, store-path
  (`build_text_path`) computation:
  <https://docs.tvix.dev/rust/nix_compat/derivation/struct.Derivation.html>,
  <https://tvix.dev/>, <https://tvl.fyi/blog/tvix-update-february-24>
- Snix as a Rust Nix reimplementation usable as a library:
  <https://jngb.lt/posts/snixperiment/>
- Nix store derivation / deriving-path reference (ATerm canonical encoding,
  store-path derivation):
  <https://nix.dev/manual/nix/2.34/store/derivation/>
- Nix *Import From Derivation (IFD)* reference — definition ("an expression that
  evaluates to a store path passed to a built-in that reads the filesystem"),
  the pause/realise/resume rule ("evaluation will be paused, the corresponding
  store object realised, and then evaluation resumed"), and why it is
  discouraged (serializes realisation against the sequential evaluator):
  <https://nix.dev/manual/nix/2.34/language/import-from-derivation>,
  <https://jade.fyi/blog/nix-evaluation-blocking/>
- Rust `unsafe` for JIT function pointers — `transmute` of code pointers,
  innate unsafety of calling JIT-produced fn pointers, no way to enforce calling
  convention; `// SAFETY:` comment convention:
  <https://doc.rust-lang.org/std/mem/fn.transmute.html>,
  <https://doc.rust-lang.org/book/ch20-01-unsafe-rust.html>,
  <https://make-a-demo-tool-in-rust.github.io/1-3-jit.html>
