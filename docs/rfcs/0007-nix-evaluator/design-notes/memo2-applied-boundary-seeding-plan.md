# MEMO-2 — applied-package boundary seeding (design + measurement plan)

Status: **DESIGN — measurement-first, not yet approved for build-out.**
Owner: p2-attrs (Dylan-approved, task #13). Reviewed-by: (pending team-lead).

This is a design-notes entry in the manner of the other `design-notes/*-plan.md`
specs. It extends the record framework of
[29-tiered-content-keyed-memoization.md](../29-tiered-content-keyed-memoization.md)
with a **new record kind** — the applied-package boundary — and specifies the
**economics measurement that must run and clear a bar before any replay table is
built**, per doc 29 §8's measure-gating discipline and the MEMO-1 negative
(§10.1).

Nothing here weakens the byte-parity contract of
[02](../02-compatibility-constraints.md): the boundary store is advisory, every
hit is revalidated against its impure slice and options identity, and it ships
behind a default-off knob with a CHECK mode (doc 29 §7.1).

---

## 1. The problem: the warm path is all-or-nothing

The durable warm path (root cutoff, doc 29 §1.2 row 2) answers a whole
`instantiate(file, attr)` from one `RootInstantiationRecord` in 7.8–28 ms —
11–820× faster than a cold eval (~2.6 s toplevel). But it fires **only on an
exact root-fingerprint hit**: `root_record_key`
(`aos-nix/src/native/root_cutoff.rs:64`) folds the entry file's content bytes
into the key, so editing *any* file the eval reaches changes the root
fingerprint and the eval falls **all the way to full cold**. There is no
middle gear.

The heap-snapshot campaign's exit verdict named the follow-on precisely: the
import/parse cache seeds **files**, not **applications**. Re-parsing is already
cheap (the parse cache ate the 39–85% front-end share). What a partial-warm eval
still pays in full is the **module fixpoint and every package application** —
`pkgs.<name>` is recomputed for all ~N packages even when an edit touched one
leaf and 99% of the set is byte-identical to the previous eval.

The lever: **seed a durable record at the package-application boundary** so a
partial-warm eval replays the unchanged package applications from cache and
evaluates only the packages the edit transitively reaches.

## 2. What the boundary *is* (design question 1)

In the AOS package set every `pkgs.<name>` is one lambda application at the
`callPackage` seam:

```text
pkgs/default.nix:331  callPackage = path: overrides:
  let fn   = import path;                                   # the package file's root lambda
      auto = builtins.intersectAttrs (builtins.functionArgs fn)
               (self // { inherit mkDerivation fetchurl; }); # deps drawn from the fixpoint
  in fn (auto // overrides);                                # <-- default.nix:340: THE boundary application
```

`discoverPackages` (`pkgs/default.nix:354`) applies this to every `*.nix`
(`value = callPackage (dir + "/${name}") {}`, `default.nix:380`). A package file
is `{ mkDerivation, fetchurl, <deps...> }: mkDerivation { ... }`
(canonical `pkgs/tools/jq.nix`). **The boundary is the `fn (auto // overrides)`
application** — one lambda-apply per package whose argument attrset is the
intersected dependency set from the fixpoint `self`.

**Boundary record key** (an instance of the doc 29 §3 `memo_key`):

- **code component** — `CacheExprIdentity` of the *applied lambda's def-site*:
  `(LoweredIrFingerprint(package file), body IrId)`. This is exactly what
  `cache_expression_identity_for_node`
  (`eval_core/force_identity/identity.rs:59`) already produces, and what the
  Tier-2 dispatch keys on per def-site (`try_tier2_lambda_apply`,
  `tier2_apply.rs:508`: the `(EvalModuleId, IrId)` pair). The applied lambda is
  in hand at the apply site as an `EvalLambda` (`eval_primop_apply.rs:330`,
  `lambda.module()` / `lambda.body()`).
- **argument component** — ordered, length-prefixed durable `ValueHash`es of the
  argument attrset (`auto // overrides`), i.e. the package's dependency values,
  via `DemandCacheKey::for_free_vars` (`cache/key.rs:110`) exactly as MEMO-1
  keys free vars (`eval_core/memo.rs:324`). This is the piece that carries
  transitive invalidation (§4).
- **validity context** — `TreeWalkOptions::result_affecting_fingerprint()`
  (store dir, nix_path/search paths, corepkgs, home, eval mode, pinned
  currentTime), folded exactly as root cutoff folds it (`root_cutoff.rs:92`).
- **impure slice** — the `[CacheableInputFingerprint]` observed *beneath* this
  application (its file `Import`/`ReadFile`, any `ReadDir`), captured with the
  existing cursor/epoch window (`eval_impure_inputs.rs:6` `impure_input_trace_cursor`
  → `:36` `force_cache_impure_input_trace_segment`), which is already how MEMO-1
  slices a subtree (`memo.rs:156` takes the cursor, `memo.rs:746` reads it back).

Every one of these mechanisms already exists; the boundary record is an
**assembly of shipped parts at a new granularity**, not new cryptography.

## 3. Payload representation (design question 2 — the crux)

A package value is an attrset full of thunks and closures — **ineligible for
L2/L3** by doc 29 §6 (unforced thunks, lambdas capture arbitrary graphs). So the
payload cannot be "the package attrset." The decisive question the lead posed:
**what does a downstream eval actually FORCE from an unchanged package?**

For `.drv` production the toplevel demands the package's **derivation**:
`drvPath`, `outPath`, the output set, and the derivation ATerm. Doc 29 §6 is
explicit that this projection is legal to serialize at a demanded boundary:
"a `.drv` closure is fully demanded by definition — root cutoff already exploits
this," and drv attrsets / string+path closures are exactly the *eligible* class.
`ValueHash::from_derivation_aterm_bytes` (`cache/cutoff.rs:206`) already gives a
durable hash of that projection.

**Proposed payload: the forced derivation projection of the package**, encoded
like a scoped `RootClosure` (doc 29 §2.2) — the drv path(s) + output paths +
canonical derivation bytes — rather than the whole attrset. This keeps the
payload closure-free and L2/L3-eligible while covering the `.drv`-relevant
demand.

**The open risk this creates** (must be answered by the measurement, §7): a
package attrset also exposes non-drv attributes a downstream expression may
select — `pkg.override`, `pkg.dev`/`pkg.lib` sub-outputs, `passthru`, `meta`.
Two sound dispositions:

1. **Projection-only, select-outside-projection is a miss.** Record only the drv
   projection; if the downstream forces an attr outside it, the boundary misses
   and that package re-evaluates (correctness preserved, some hit mass lost).
   Simplest and safe; the measurement tells us how much mass survives.
2. **Full-forced eligible attrset.** Record the whole applied attrset *iff* it
   classifies eligible (all entries transitively forced + closure-free) by the
   §6 eligibility walk. Packages carrying closures in `passthru` (e.g.
   `.override`, function-valued fields) fall back to disposition 1's miss for
   those selects. Wider coverage, larger payloads, more classification cost.

Recommendation: **start at disposition 1** (drv projection), because the
toplevel `.drv` gate is the target workload and the projection is provably
eligible; treat full-attrset seeding as a measured widening if the projection's
hit mass is real but capped by non-drv selects. This mirrors MEMO-1's "decline
admission first, widen on measurement" stance (doc 29 §3.2).

## 4. Invalidation (design question 3) — content-addressed and *automatic*

There is no dependency-graph walk and no mtime (doc 29 §7.4). Invalidation falls
out of the two key components:

- **Edit a package's own file** → new `LoweredIrFingerprint` for that file
  (the parse cache is keyed on content hash since `ab7289106`) → the code
  component changes → that package's boundary key **is simply never constructed
  again** → it re-evaluates.
- **Edit a dependency** → the dependency's own boundary record misses and it
  re-evaluates to a **new `ValueHash`** → that new hash appears in the
  **argument component** of every package that captures it → those packages'
  boundary keys change too → they re-evaluate.

This is the elegant property: **transitive invalidation is a byproduct of
keying on argument value hashes** — no explicit reverse-dependency index. The
per-file content hashes give per-file identity; the argument value hashes give
reachability, exactly as the lead framed it.

**Replay is bottom-up and recursive.** To probe package A's boundary we need
A's argument hashes, which are B's, C's… `ValueHash`es. Those come from
*replaying B's/C's boundary records* (a hash + slice-revalidate, not a full
package eval) — the same recursion the fixpoint already performs, but each
node is a cache probe instead of a `mkDerivation` evaluation. A package whose
whole transitive dependency cone is unchanged replays in O(cone size × probe
cost) instead of O(cone size × package-eval cost). **The realizable win is
exactly the ratio of those two costs times the fraction of the set left
unchanged by an edit** — which §7 measures before we build anything.

## 5. Admission (design question 4) — coarse boundaries only

The MEMO-1 negative (doc 29 §10.1) is the governing lesson: at fine
granularity "the repeated work was too cheap to repay keying and replay"
(+25–31% regression). MEMO-2 must admit **only** boundaries whose recompute
cost dwarfs a probe. Two gates:

1. **Structural: only package-application boundaries.** There is no `callPackage`
   marker at the apply site (Explore item 5). Recognize the boundary by the
   applied lambda's def-site being a **package-file root lambda** — an import
   boundary whose module is a discovered package file. Candidate mechanisms
   (to be chosen during build-out, not now): mark file-root lambdas at
   parse-artifact time (the same "admission flag on the lowered node" shape doc
   29 §8 rule 1 prescribes and MEMO-1 already uses, `memo.rs` def-site
   decisions), or gate on the applied module being an import-root with an
   estimated body cost over floor. The apply choke point is
   `clone_env_frames` (`eval_core/module_env.rs:560`) /
   `eval_primop_apply.rs:350`.
2. **Economic: estimated recompute ≥ floor.** A static cost estimate on the
   package body (the `est_recompute` field, doc 29 §2.1/§5.7) must clear
   `AOS_NIX_MEMO_MIN_COST`. Package `mkDerivation` bodies are large and
   phase-bearing — comfortably coarse — but the floor must exist so a trivial
   package file (a bare alias) is not seeded.

**Never probe the bare force/apply path** (doc 29 §8 rule 1): admission is a
per-def-site decision marked once, so non-package applications (the 14.58M
`clone_env_frames` installs the env-flatten histogram measured, 89% empty) pay
**zero**. This is the structural guarantee that MEMO-2 does not re-create the
JIT hook tax.

## 6. Correctness (design question 5)

- **CHECK mode.** Extend `AOS_NIX_MEMO_CHECK` to the boundary tier: every hit
  is shadowed by a real application eval and compared — drv projection by
  canonical bytes, exactly as `verify_root_cutoff_closure`
  (`root_cutoff.rs:341`) shadows a root hit. This is the first-class development
  gate for the two novel surfaces (slice attribution and argument-key admission).
- **Slice revalidation.** A hit revalidates its `[CacheableInputFingerprint]`
  slice through the existing seam `revalidate_cacheable_input_trace`
  (`eval_impure_inputs.rs:103`); all-or-nothing, incomplete-latches
  (`impure_input_trace_complete`), conflicting-observation refusal
  (`canonicalize_cacheable_input_trace`, `:137`). Inherited verbatim from the
  root-cutoff contract.
- **Parity supremacy.** The x4 package byte gate (and Linux full-corpus `.drv`
  gate) must be green with the boundary store off, on, CHECK-on, and in
  parallel mode before any default flip (doc 29 §7.2). A boundary tier that
  wins benchmarks and loses parity does not exist.
- **Format versioning.** New domain constant + format version for the boundary
  record kind (doc 29 §3.4/§7.4); old records miss safely on a bump.

## 7. The measurement-first increment (deliverable b) — build THIS first

Per doc 29 §8 and the MEMO-1 exit ramp, **no replay table is built until a
counting run says the ceiling clears the tax with margin.** The first increment
is an economics probe, cloning the apply-count-probe pattern
(`eval/env/apply_probe.rs`, commit `0a44b0f22`): a sibling probe module with
process statics, a `note_*` at the apply choke point gated on
`eval_stats_dump()`, and an `emit_*` greppable stderr JSON line hooked into
`emit_stats_trace` (`eval_stats.rs:179`).

> **Extraction-channel gotcha (load-bearing, cost hours to relearn):**
> bench-visible counters must go out the `AOS_NIX_EVAL_STATS=1` **eprintln**
> path (`emit_stats_trace` → `emit_env_apply_histogram_report`, stderr), **not**
> the `aos_nix::eval::stats` tracing target and **not** the nix-bench JSON
> (which carries no eval stats). The campaign counters are stranded on the
> unrouted tracing target; do not add the boundary counter there.

The probe must answer four numbers. The **first is a gating precondition** that
can kill or redirect the design more cheaply than the economics can, so it is
measured first:

0. **Argument-hash availability — the decline rate under MEMO-1 rules.** The
   boundary key needs ordered durable `ValueHash`es of the whole argument set,
   but a durable `ValueHash` exists **only for forced, non-closure values**
   (`cache/cutoff.rs`; MEMO-1 explicitly declines thunk-capturing envs, doc 29
   §3.2 thunk rule). At boundary-record time a package's argument set
   (`auto // overrides`) almost certainly still holds **unforced thunks** — deps
   the package never demanded. We **cannot force them to hash them**: forcing to
   hash perturbs force order and breaks byte-parity, the supreme gate. So per
   MEMO-1's unhashable-memo precedent, any boundary whose argument set contains
   an unforced member must **decline admission**. Therefore the probe measures,
   per boundary application at result-record time, the fraction of the argument
   set that is **forced-and-hashable vs unforced**, and reports the resulting
   **decline rate** across boundaries. If most package argument sets contain an
   unforced member, the decline rate approaches 100% and the whole design caps
   out **regardless of the economics** — this number gates everything below.
   (Outs if the decline rate is high are in §8; they are not built now, but the
   probe's per-member forced/unforced breakdown is exactly what sizes them.)

1. **How many package-boundary applications does one cold toplevel perform?**
   Count applications whose applied-lambda def-site is a package-file root
   (§5 gate 1), keyed by `(module, body)` `CacheExprIdentity`. Report distinct
   boundaries and total applications (a package applied once vs many).
2. **What fraction of cold wall do they own?** Accumulate wall time *under* each
   boundary application (enter/exit timestamps around the `fn (auto//overrides)`
   apply), so we know the recompute cost per boundary and the summed
   package-application share of the 2.6 s cold eval. This is the numerator of
   the replay win; if package applications are a small slice of a flat long
   tail (the wave-1 profile warned the residual cold is "flat, no dominator"),
   the ceiling is low and we stop here — counters-only, MEMO-1-style.
3. **The partial-warm stability fraction.** For a one-file edit, how many
   boundary *keys* stay stable (would hit) vs change (must re-eval)? Because
   invalidation is content-addressed (§4), this is computable without a second
   full eval: record each boundary's `(code component, argument-hash component)`
   in eval N, then in a "perturb one leaf package" pass recompute which boundary
   keys change under that leaf's new fingerprint by propagating the argument-hash
   change through the captured-dependency edges. The realizable win ≈
   (share from #2) × (stable fraction from #3) × (1 − probe/recompute cost
   ratio). If editing one leaf leaves 99% of boundaries stable, the lever is
   large; if the dependency cone fans out so an edit perturbs most keys, it is
   small.

**Kill criterion (explicit, per MEMO-1):** the design proceeds only if **both**
(a) the decline rate (#0) leaves a workable admissible fraction *and*
(b) `admissible-boundary-count × mean-recompute × stable-fraction` clears the
probe+key+revalidate tax with margin. A high decline rate (#0) alone is a
redirect signal (toward the §8 lazy-safe-identity outs) even if the economics
look good; failing (b) ships **counters-only** with a recorded negative result
and the effort returns to the durable-unification / L2 levers — exactly the doc
29 §10.1 exit ramp. We measure before we build.

**Scope of the first increment (what I'll actually write after review):**
probe module + statics + `note_pkg_boundary_apply()` at the apply choke point
(gated on `eval_stats_dump()`, `CacheExprIdentity`-keyed) + per-boundary
**forced/unforced argument-member tally (#0)** + wall accumulation (#2) +
`emit_pkg_boundary_report()` on the stderr stats path + an e2e wiring test
(mirroring `tests/options/part_11.rs:824`). No record store, no replay, no key
persistence. One commit, both feature configs green, ≤1000-line files, no new
unsafe, local-only.

## 8. Risks and open questions

- **Argument-hash availability — the design-capping risk (measured first, §7
  #0).** The boundary key wants durable `ValueHash`es of the argument set, but
  those exist only for **forced, non-closure** values, and a package's argument
  set almost certainly still holds **unforced thunks** (deps it never demanded)
  at record time. Forcing them to hash them perturbs force order and breaks
  byte-parity, so those boundaries must **decline** under MEMO-1 rules — and if
  most argument sets contain an unforced member, the decline rate approaches
  100% and the design caps out *regardless of the economics numbers*. This is
  why §7 measures the decline rate before anything else. **Outs (to evaluate
  later, not built now):**
  1. **Key on argument *thunk identity*, not value.** An unforced thunk is
     itself `(code_id, env)` — a lazy-safe identity that changes when its source
     or captured environment changes, derivable **without forcing** (doc 29 §3.2
     records exactly this Adapton-style extension as a measured follow-up). It is
     sound for invalidation-by-content (two thunks with equal recursive identity
     denote the same computation in the same world) but weaker: it misses the
     case where two *different* thunks would force to the *same* value. Cost:
     key derivation recurses through the captured-environment graph.
  2. **Hybrid.** Value hash when the argument member is already forced, thunk
     identity when not — the widest admission, and the natural target if #0 says
     the pure-value decline rate is high but the forced fraction is non-trivial.
  The probe's per-member forced/unforced tally (§7 #0) is exactly what sizes
  which out, if any, is worth building.
- **Ceiling may be low.** The wave-1 residual-cold profile is a flat long tail
  with no dominator; package applications may not own enough wall to repay
  replay. This is precisely why increment #1 is measurement, not code. (Primary
  economic risk; mitigated by the kill criterion.)
- **Argument-hash cost.** Keying a boundary hashes its whole dependency argument
  set. Large dep attrsets hashed once but hit rarely could be blake3-dominated
  (doc 29 §11 headline risk). The hash-once cold side table
  (`heap/record_table.rs` cold value hash) amortizes it; the measurement must
  decompose key time (doc 29 §8 rule 3). The parallel durable-cache
  blake3→xxh128 experiment (measuring now) directly changes this note's cost
  basis: if xxh128 lands as the durable record hash, boundary keying inherits
  the cheaper hash and the argument-hash tax in the kill criterion drops
  accordingly — fold the measured result in before pricing the record store.
- **Non-drv selects cap the projection.** §3 disposition 1 loses mass whenever
  downstream forces `.override`/sub-outputs/`passthru`. Measurement #2 should
  also record *what attrs* the toplevel forces off a package to size this.
- **Recursive replay ordering under parallelism.** Bottom-up boundary replay
  must respect the same publication discipline as MEMO-1's L1
  (payload Release-publish happens-before table insert; doc 29 §7.5).
- **Slice attribution for a whole package subtree** is larger than MEMO-1's
  per-node slice; CHECK mode (doc 29 §7.1) is the backstop and must be green
  before any default flip.

## 9. Phasing

1. **M2-measure (this increment, after review):** the economics probe above.
   Deliverable is *numbers* and a go/no-go on the record store.
2. **M2-record (only if #1 clears the bar):** boundary record kind in the doc 29
   envelope (drv-projection payload), admission flags on package-file-root
   def-sites, L0/L1 in-process store, CHECK mode, parity gate.
3. **M2-durable:** L2 persistence of boundary records under the shared indexed
   `files/` pack + the root-cutoff-style hit/store/revalidate path; cross-eval
   partial-warm demonstration on a one-file-edit corpus.
4. **M2-widen (measured):** full-forced eligible attrset payload; non-drv-select
   coverage — each gated on its own measurement.

Steps 2–4 are **not** authorized by this doc; they are the map the measurement
either opens or closes.
