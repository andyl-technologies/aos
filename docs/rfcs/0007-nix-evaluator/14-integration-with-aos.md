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
  on the heavy `aos-nix` crate (Cranelift, the GC, the `unsafe` core) in its
  default build. The trait lives in `aos-core`; the `NixNative` impl lives in
  `aos-nix` and is wired in only when the feature/flag is enabled. `aos-core`
  thus stays lightweight and `miri`-clean (see [§9](#9-the-unsafe-policy)).

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

`NixNative` is a thin `aos-core`-facing shim over the `aos-nix` crate's public
API. It owns the long-lived evaluator context (interned symbol table, parsed-IR
cache, hash-cons tables, incremental cache handle) so that across many
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

`NixNative` can fail in two qualitatively different ways, and the integration
treats them very differently.

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
    EvalError(NixThrow),
    /// An internal invariant was violated (a bug in aos-nix). Fall back
    /// AND emit a loud diagnostic for the bug tracker.
    Internal(anyhow::Error),
}
```

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

## 9. The `unsafe` policy

AOS's workspace rule (`CLAUDE.md`) is blunt: **"Avoid `unsafe` at all costs.
Use it only for an explicit, justified performance need, and document the
invariants with a `// SAFETY:` comment."** `aos-nix` is the one crate in the
monorepo that needs a *standing, scoped waiver* of the "at all costs" framing,
because three of its core mechanisms are irreducibly `unsafe`:

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

These are not gratuitous; they are the mechanisms by which `aos-nix` beats C++
Nix at all. The policy that fences them is what makes the waiver responsible.

### 9.1 The fence: a small, audited `unsafe` core

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
  `miri` against this tree (see [§9.3](#93-tooling-discipline)).
- The **`unsafe` mechanisms** (value bit-twiddling, JIT calls, GC) are isolated
  into dedicated modules. Those modules use `#![deny(unsafe_op_in_unsafe_fn)]`
  so that even inside an `unsafe fn` every `unsafe` operation is an explicit,
  individually-commented block. Each block carries a `// SAFETY:` comment
  stating the invariant it relies on and why it holds.
- **No `.unwrap()`/`.expect()` in production paths** still applies to `aos-nix`
  exactly as everywhere else in the workspace; the `unsafe` waiver is *only*
  about memory/codegen primitives, not about error handling.

### 9.2 Why the oracle being safe matters for the *waiver*

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

### 9.3 Tooling discipline

The standing discipline that accompanies the waiver:

| Control                              | Applies to                  | Purpose                                              |
|--------------------------------------|-----------------------------|------------------------------------------------------|
| `#![forbid(unsafe_code)]`            | oracle, frontend, harness   | guarantee the trusted core has zero `unsafe`         |
| `#![deny(unsafe_op_in_unsafe_fn)]`   | value-repr, jit, gc modules | force per-operation `// SAFETY:` justification       |
| `cargo miri` on the conformance suite| safe oracle tree            | catch UB in the path that doesn't need real codegen  |
| ASan/UBSan CI job                    | full crate                  | catch heap/UB bugs in the `unsafe` core              |
| `cargo fuzz` targets                 | value decode, GC, ATerm     | stress the bit-level and pointer-rewriting code      |
| two-maintainer review of `unsafe`    | every new `unsafe` block    | no `unsafe` lands without a second set of eyes        |

`miri` cannot execute JIT-compiled machine code or the raw-syscall paths, which
is exactly why the architecture keeps a *fully functional* safe tree-walk
evaluator that produces the same `.drv`: it gives `miri` and the sanitizers a
complete, exercisable program to analyze. The `unsafe` tiers are then differential-
tested against that safe program.

---

## 10. Observability and operator controls

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

## 11. Summary of the contract

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

## 12. Open questions

- **Long-lived daemon vs per-invocation process.** This document assumes the
  per-invocation `aos` process model, where the GC is the bump-arena Tier A
  (allocate, never free, drop at exit; see
  [memory and GC](06-memory-management-and-gc.md)). If we later run `aos-nix` as
  a persistent eval daemon to amortize warmup and share the incremental cache
  across invocations, the `NixEval` seam is unchanged but the implementation
  flips to the generational/concurrent GC tier, and the trait may need an
  explicit lifecycle (`shutdown`/`flush`). Deferred until the per-process numbers
  justify a daemon.
- **Sharing the incremental cache across machines through the trait.** The
  early-cutoff cache ([incremental cache](12-incremental-evaluation-cache.md)) is
  content-addressed and intended to ride AOS's existing Attic infrastructure.
  Whether cache push/pull is plumbed through `NixEval` or sits beside it (as the
  build-output cache does today) is unresolved; leaning toward beside-it to keep
  the trait minimal.
- **`eval_expr` value-rendering parity.** Matching `nix-instantiate --eval
  --json` formatting exactly (float formatting, attr ordering in JSON, context
  string handling) for the metadata path needs its own small differential check
  distinct from the `.drv` harness. Low blast radius, but it must be green before
  Phase C.
- **`nix-compat` API churn.** `NixNative` depends on the Snix/Tvix `nix-compat`
  crate pinned to a git rev for ATerm/store-path/hash logic. The crate's public
  API is explicitly pre-1.0 and has moved (Tvix → Snix rename, March 2025;
  Derivation/ATerm sliced out and reparsed since). We pin a rev and expect to
  carry local patches / contribute fixes upstream; a breaking change there is a
  maintenance risk on the parity-critical path, not a correctness risk (the
  output is still diffed by the gate).

---

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
- Rust `unsafe` for JIT function pointers — `transmute` of code pointers,
  innate unsafety of calling JIT-produced fn pointers, no way to enforce calling
  convention; `// SAFETY:` comment convention:
  <https://doc.rust-lang.org/std/mem/fn.transmute.html>,
  <https://doc.rust-lang.org/book/ch20-01-unsafe-rust.html>,
  <https://make-a-demo-tool-in-rust.github.io/1-3-jit.html>
