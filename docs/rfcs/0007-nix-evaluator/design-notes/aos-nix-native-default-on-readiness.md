# AOS_NIX_NATIVE default-on readiness assessment (report-only)

> Evidence for the `AOS_NIX_NATIVE` default-on flip decision (RFC-0007
> definition-of-done gate). This is a **report**, not a decision: the flip is
> the lead's call and is likely user-surfaced. Written 2026-07-13, HEAD around
> `258b9ed30`, after the S5 carrier promotion GO (`5c22a8bab`). Read-only
> inventory — no code was changed to produce it.

## 0. TL;DR verdict — READY-WITH-FALLBACK

The native evaluator can be flipped default-on with **low risk**, because
default-on does not mean "native or bust": it means "native, then transparently
retry the whole operation on the C++ Nix CLI for anything native cannot handle."
That per-operation fallback (`NativeFallbackEval`, `aos-core/src/nix/eval.rs:2235`)
plus the standing parity evidence (546/546 `.drv`, 549/549×2 strict-JSON) covers
the realistic surface. The two things that keep this from an unconditional
"ready" are (1) a small set of "unsupported" conditions that are **not**
fallback-eligible (they hard-fail as authoritative `EvalError`), and (2) the
standing CI/flake gates do **not** currently run under `AOS_NIX_NATIVE=on`, so a
native regression would not be caught in CI today. Both are addressable
pre-flip; see §4.

---

## 1. Semantics inventory — what `AOS_NIX_NATIVE` is and what default-on means

### 1.1 The env var and its modes

`AOS_NIX_NATIVE` selects the evaluator, parsed in `aos-core/src/nix/eval.rs`
(`NativeMode`, `:1989-2018`; `native_mode_from_env`, `:2020-2033`):

| value | mode | behavior |
|---|---|---|
| unset / `0` / `false` / `no` / `off` / `""` | **Off** (today's default) | C++ Nix CLI only (`NixCli`) |
| `1` / `true` / `yes` / `on` | **On** | native authoritative, with per-operation C++ fallback |
| `shadow` | **Shadow** | run native beside C++, **return the C++ result** (a measurement mode) |
| unknown | Off + `tracing::warn!` | safe default |

`select_evaluator_with_config` (`:2150-2170`) maps the mode to a `Box<dyn
NixEval>`: Off → `NixCli`; On → `NativeFallbackEval`; Shadow → `ShadowEval`. Two
guardrails: (a) native-eval is a compile feature — without `native-eval`, On/Shadow
fall back to `NixCli`; (b) On/Shadow under an **ambient** Nix eval policy
(`NixEvalMode::Ambient`, e.g. `<nixpkgs>`-style ambient search paths) warn and use
`NixCli` (`:2157-2162`).

A companion `AOS_NIX_NATIVE_VERIFY` (`:2035-2127`) is the rollout canary: `off` /
`always` / a fractional sample rate (`0.05`, `5%`). It re-runs the C++ oracle on
a sampled fraction of native operations and compares (see §1.4).

### 1.2 What "default-on" concretely means

Every `aos` subcommand that needs a `NixRunner` (`crates/aos/src/main.rs:15-17`)
routes evaluation through `select_evaluator_with_config`
(`aos-core/src/nix/runner.rs:82`), so default-on flips the evaluator for:

`build`, `system`, `show`, `graph`, `lint`, `test`, `repl`, `gc`,
`why-depends`, `describe`, `prefetch`, `fmt`, `doc`.

Subcommands that do **not** construct a `NixRunner` are unaffected: `serve`,
`token`, `cache`, `package`/`apm`/`apr`, `completions`, and the `--remote` modes
(they use `NixCli` or their own infra directly). Concretely, flipping the
default means `aos build <pkg>` / `aos system build` / `aos show` would
instantiate through the from-scratch Rust evaluator (with the C++ safety net
below) instead of shelling straight to C++ Nix.

### 1.3 The off-switch story post-flip

The escape hatch is preserved and explicit: `AOS_NIX_NATIVE=off` (or `0` /
`false` / `no`) forces the C++ CLI evaluator for any invocation, and the
CLI/wrapper strips these vars before spawning real-Nix subprocesses
(`aos-core/src/nix/env.rs:93-135`, `eval.rs:1169-1170`) so a fallback subprocess
never re-enters native. Flipping "default-on" is a one-line change to the
*default* `NativeMode` when the var is unset; users retain a per-invocation
opt-out.

### 1.4 The verify canary (the post-flip safety net)

When `AOS_NIX_NATIVE_VERIFY` selects `Always` or the sampled Nth operation
(`native_verify_should_run`, `:2117-2127`), the fallback wrapper re-runs the C++
oracle and compares outputs. On mismatch it records
`NativeVerifyOutcome::Divergence`, logs `tracing::error!`, and **returns `Err`**
(`verify_native_eval_expr` `:2907-2946`; the `.drv`-closure verifiers
`:2720-2806`). So a native-vs-C++ divergence under the canary is a **loud, hard
failure with a metrics counter**, not a silent wrong answer — this is exactly
the residual-verification rollout mechanism doc 14 §6.2/§7.2 anticipated.

---

## 2. Gap inventory — the native evaluator's unsupported surface (the critical piece)

### 2.1 The taxonomy — only two of three error classes fall back

The one public error type is `NativeEvalError` (`crates/aos-nix/src/error.rs:28-82`):

| variant | Display | falls back to C++? |
|---|---|---|
| `Unsupported { feature, span }` | `native Nix evaluator does not yet support {feature}` | **YES** (`NativeCliFallbackReason::Unsupported`) |
| `Internal { message }` | `native Nix evaluator internal failure: {message}` | **YES** (`Internal`) |
| `EvalError { message }` | `native Nix evaluation failed: {message}` | **NO — authoritative** |

The fallback decision (`native_cli_fallback_reason`, `eval.rs:3044-3048`) downcasts
to `NativeEvalError` and retries the **whole operation** on C++ only for
`Unsupported`/`Internal`. The gate that classifies a tree-walk failure as
fallback-eligible `Unsupported` vs authoritative `EvalError` is
`tree_walk_unsupported_feature` (`crates/aos-nix/src/native/error.rs:501-533`):
only the listed `TreeWalkErrorKind` variants become `Unsupported`.

**Readiness rule of thumb:** a construct native "doesn't support" is *safe* iff it
maps to `Unsupported`/`Internal` (transparent C++ fallback). The risk is confined
to constructs that map to `EvalError` **and** that C++ Nix would have evaluated
successfully.

### 2.2 Fallback-eligible (safe — transparent per-operation C++ retry)

- **Frontend catch-all** (the safety net): any parse / scope-resolve / IR-lower
  failure becomes `Unsupported` (`native/error.rs:100-124`), so any syntactic or
  scoping construct the native frontend can't handle defers to C++ rather than
  producing a wrong answer.
- **Language constructs**: unsupported lambda parameter patterns, dynamic/unsupported
  `let` binding keys, unsupported source-path coercions, unsupported tree-walk
  primop symbols, unsupported `builtins.<attr>`, unsupported structural equality
  between two runtime types, function/attrs type-mismatch shapes, ambient search
  path (`<nixpkgs>`), search-path lookup miss, non-ASCII path/attr segments
  (`native/error.rs:503-533`, `source.rs:149-153`).
- **CLI/runtime-sensitive builtins — deliberately fall back** (rejected in the
  `ensure_native_json_subset` preflight, `native/fallback.rs:13-234`): `derivation`,
  `import`, `scopedImport`, `derivationStrict`, `currentSystem`, `currentTime`,
  `storeDir`, `nixPath`, `path`, `pathExists`, `filterSource`, `readDir`,
  `readFile`, `readFileType`, `toFile`, `findFile`, `fetchGit`, `fetchMercurial`,
  `fetchTarball`, `fetchTree`, `fetchurl`, `trace`, `warn`, plus any effectful
  strict builtin.
- **Flakes**: `getFlake` → feature `"flakes"` fallback (`builtins/types.rs:350,393`).
  Flake evaluation is not native.
- **Effectful expressions / IFD**:
  - Effectful-expression preflight rejects any non-speculable node →
    `Unsupported { feature: "effectful expression evaluation" }`
    (`native/fallback.rs:32-36`) — the `derivation.seed` limitation seen in the
    fuzz matrix.
  - IFD without a realizer → `UnsupportedImportFromDerivation` (fallback-eligible,
    `error_kind.rs:963`, `native/error.rs:509`). **But** under native mode the CLI
    wires a **C++-backed IFD realizer** (`eval.rs:3051-3063`,
    `native_with_ifd_realizer`) that shells to `nix` to build IFD deps — so IFD
    resolves rather than always deferring.
- **Unknown builtins**: any name outside the 117-name registry
  (`ratchet-core/src/builtins/declarations.rs`, `lookup_builtin` returns `None`)
  → `UnsupportedBuiltinAttr`/`UnsupportedPrimOp` fallback. Notably **`fetchClosure`
  is not in the registry** (would fall back).

### 2.3 NOT fallback-eligible (authoritative `EvalError`, hard-fail) — the real risks

These carry "unsupported" wording but map to `EvalError`, so the operation
**fails** rather than retrying C++. Each is only a problem where native rejects
but C++ would succeed:

- **`UnsupportedDialectOp`** — `unsupported tree-walk dialect operation {op:?}`
  (`error_kind.rs:1368`, raised `eval_apply.rs:239`). An unimplemented
  aos-nix-dialect op hard-errors. Highest-attention item since it's an internal
  op, not a user construct.
- **Per-argument fetch/source/flake attribute rejections**:
  `UnsupportedSourcePathAttr`, `UnsupportedFetchUrlAttr`, `UnsupportedFetchGitAttr`,
  `UnsupportedFetchMercurialAttr`, `UnsupportedFetchTarballAttr`,
  `UnsupportedFetchTreeAttr`, `UnsupportedFlakeRefAttr` (`error_kind.rs:386-722`).
- **Fixed-output derivations**: `non-sha256 recursive fixed output references are
  unsupported`, `flat fixed output references are unsupported`
  (`derivation_build.rs:438,454`).
- **Fetch/flake scheme + entry-type limits**: unsupported URL/flake/forge schemes,
  unsupported tarball/git-worktree entry types (`fetch_tree_forge.rs:344,635`,
  `fetch_git_tree.rs:93,187,408,508`, `fetch_tree_access.rs:207,697,935`,
  `eval_import/fetch_tarball.rs:162`, `flake_git.rs:144`). (Contrast the
  fallback-eligible `UnsupportedFetchTreeFeature`, `error_kind.rs:632`.)
- **Regex** (`builtins.match`/`split`): unsupported POSIX ERE escape / empty
  alternative / lazy quantifier / group (`eval_regex.rs:404-451`).
- **JSON/TOML**: `JsonNumberUnsupported` (`eval_codec.rs:352`), unsupported TOML
  kind (`error_kind.rs:1119`).

**Why the standing parity gates make these low-risk:** the 546/546 full-corpus
`.drv` parity is exactly `aos nix-diff --all --systems` over the AOS package set
plus every system toplevel; the 549/549×2 strict-JSON matrix is the
package-derived fuzz corpus. Both are byte-green on the native carrier, which
means **none of the EvalError-mapped constructs above are actually reached by the
AOS package set / systems / corpus** (if any were, native would have EvalError-ed
where C++ succeeded and the gates would be red). The exposure is therefore a
*future* AOS package introducing one of these constructs — caught by the verify
canary (§1.4), not silently mis-built.

### 2.4 Two structural caveats

- **Fallback is Result-based, so it does not catch panics.** A `panic!` in the
  native path aborts rather than deferring to C++. No `todo!`/`unimplemented!`/
  `unreachable!` was found in the Nix-feature paths, and the `parity_json` fuzz
  corpus with its `arbitrary` generator is purpose-built to find panics/divergence
  and is clean — so the language-surface panic risk is well-exercised, but it is
  a real (if small) residual vs. the graceful-error surface.
- **JIT gaps are not part of this surface.** Unmet JIT-tiering conditions
  (`jit/conformance.rs`, `runtime_symbols/candidates.rs`) fall back to the
  tree-walk interpreter (tier-0), not to C++ Nix, and do not change results.

---

## 3. Gate list — what covers a default-on world, and what does not

### 3.1 Gates that DO validate native-vs-C++ (and are green)

| gate | scope | wired | status |
|---|---|---|---|
| Full-corpus `.drv` parity (`aos nix-diff --all --systems`) | every AOS package + every system toplevel | **manual** (builder) | 546/546 byte-green (both carriers, #28) |
| Strict-JSON fuzz matrix (`aos nix-diff --eval-json --eval-json-corpus`) | 549 package-derived seeds, serial + JIT | **manual** (builder) | 549/549×2, S5 evidence (doc 15 §5.6) |
| System toplevel byte-parity | `systems.server.build.toplevel` | **manual** | byte-green (task #27) |
| `checks.integration.aos-eval-json-corpus-smoke` | the 5 checked-in language seeds | **CI (flake)** | green |

The first three — the ones that actually exercise the breadth of `aos
build`/`system`/`show`'s eval surface on the native carrier — are **manual
builder runs**, not flake checks.

### 3.2 Gates that do NOT currently run native (the coverage gap)

`grep` finds **no `AOS_NIX_NATIVE` in `flake.nix` / `default.nix` / the checks
tree**. The standing flake gates — `checks.eval`, `checks.vm.*`, `checks.fleet.*`
(`flake.nix:159-168`) — evaluate/build under the **default (C++)** evaluator.
They validate the AOS *system*, not the native evaluator, and would **not** catch
a native-eval regression today. Only the 5-seed `aos-eval-json-corpus-smoke` runs
native parity in CI.

So a default-on world has an asymmetry: the deepest native validation (546/546,
549/549) is real but off-CI, while the on-CI gates run C++. This is the single
most actionable pre-flip item.

---

## 4. Risk verdict and recommendation — READY-WITH-FALLBACK

**Verdict: ready-with-fallback.** The architecture is built for a safe default-on:
per-operation transparent C++ fallback on the entire `Unsupported`/`Internal`
surface (which includes every effectful/CLI-sensitive/flake/IFD/unknown-builtin
construct and every parse/resolve/lower failure), a C++-backed IFD realizer so
IFD still builds, and a divergence-detecting verify canary that turns any
native-vs-C++ mismatch into a loud hard error. The 546/546 `.drv` + 549/549×2
JSON parity prove the AOS repo's own `build`/`system`/`show` eval surface is
byte-identical on native, so the realistic "breaks `aos build` post-flip" failure
mode is not present on the current package set.

**Why not unconditionally "ready":**
1. A real `EvalError` hard-fail surface exists (§2.3) that does *not* fall back.
   It is empty on today's corpus but is a latent trap for a future package using
   an exotic fetch/flake scheme, a non-sha256 fixed output, an unusual regex, or
   an unimplemented dialect op.
2. CI does not run native (§3.2) — the deep parity is manual, so a regression
   would not gate a merge.
3. Result-based fallback does not catch panics (§2.4).

**Recommended pre-flip actions (for the flip owner):**
- **Wire native parity into CI.** Either add a flake check that runs the
  full-corpus `.drv` parity (or at least a representative subset + the toplevels)
  under `AOS_NIX_NATIVE=on`, or run `checks.eval` a second time under
  `AOS_NIX_NATIVE=on`, so a native regression is a red merge.
- **Turn on the verify canary in CI/fleet post-flip.** Set
  `AOS_NIX_NATIVE_VERIFY` to a sampling rate (doc 14 §6.2's rollout canary) so any
  production divergence hard-errors with a counter rather than shipping a wrong
  `.drv`. It is the single cheapest guard against the §2.3 latent surface.
- **Consider promoting the highest-risk `EvalError` conditions to `Unsupported`**
  so they fall back instead of hard-failing — `UnsupportedDialectOp` in particular
  (an internal op reaching a user build is a hard stop with no recovery). This is
  the one code change that would move the verdict toward unconditional "ready";
  it is out of scope for this report but flagged as the highest-leverage follow-up.
- **Document the `AOS_NIX_NATIVE=off` escape hatch** wherever the default flip is
  user-surfaced, so operators have a one-flag rollback.

The flip is defensible today behind the fallback + the canary; the CI-native gate
and the canary-in-CI are the two items that convert "defensible" into "safe by
construction."
