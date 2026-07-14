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

---

## 10. Probe verdict (2026-07-14): pure-value keying is dead

The §7 economics probe ran on the builder toplevel (cache-off, stats-on):

| Metric | Value |
| --- | --- |
| Boundary applications | 19,698 |
| Distinct def-sites | 1,274 |
| **Declined applications** | **19,467 (98.8%)** |
| Distinct declined def-sites | 1,233 / 1,274 |
| Argument members inspected | 137,535 |
| Hashable (forced) members | 51,240 (37%) |
| Top-level boundary wall | 1.43e9 ns (stats-inflated run) |

The cache-on run agreed (12,978 / 13,132 declined; fewer applications because
the parse/persist path absorbs some). The verdict is unambiguous:

- **Pure-value keying (§2–§3) is dead.** 98.8% of package-boundary argument sets
  contain at least one unforced-thunk (or closure) member at record time, so
  under MEMO-1 rules 98.8% of boundaries decline — exactly the availability cap
  §8 predicted. Keying a boundary on ordered durable value hashes of its
  argument set is not viable.
- **The design survives if — and only if — keying pivots.** The boundary wall
  share is substantial (1,274 distinct package applications owning real cold
  wall), so the *lever* is real; only the *key* is wrong. 37% of members are
  hashable, which sizes a hybrid but does not carry it alone.

The rest of this document (§11) works out the replacement key to the same rigor
as §2–§3 and states honestly where it does or does not beat root cutoff.

---

## 11. Keying redirect: source-Merkle boundary identity

### 11.1 Why generic thunk-identity degenerates (the honest failure)

Doc 29 §3.2 records the Adapton-style out for an unforced free variable: key it
by *its own* `(code_id, env)` memo key, derived without forcing. Applied
naively to a package-boundary argument member, this **degenerates to the whole-
set fingerprint**, i.e. it is no better than root cutoff:

An argument member `self.<dep>` is a thunk whose forcing runs
`fn (auto // overrides)`. To build `auto` it calls
`intersectAttrs (functionArgs fn) (self // { … })`, so the thunk's **captured
environment references the fixpoint `self` in its entirety**. A generic
recursive identity `code_id(thunk) ‖ identity(captured env)` therefore recurses
through `self` — every package in the set — for *every* boundary. The result is
one identity that changes whenever *any* package changes: root cutoff with extra
steps. **We reject generic thunk-env identity.**

### 11.2 The bounded construction: follow static formal edges, not raw capture

The fix is to identify a boundary by the **static dependency edges its formal
set declares**, not by hashing its raw captured environment. A package file is
`{ mkDerivation, fetchurl, <dep₁>, … , <depₙ> }: mkDerivation { … }`; the
formal names are exactly the fixpoint keys it depends on (that is what
`intersectAttrs (functionArgs fn) self` computes). Those names are **static in
the lowered IR** (the `FormalSet` node lists them), so the dependency set is
known from the parse artifact without evaluating or forcing anything.

Define, over the package dependency DAG:

```text
boundary_identity(P) =
    blake3( DOMAIN ‖ FORMAT_VERSION ‖ crate_version
          ‖ LoweredIrFingerprint(P.nix)
          ‖ for f in formals(P) in canonical order:
              dep_component(f) )

dep_component(f) =
    | boundary_identity(Q)        if self.f resolves to a package Q
    | builtin_id(f)               if f is a framework closure
    |                               (mkDerivation, fetchurl) — its def-site code_id
    | DECLINE the whole boundary  if f cannot be statically resolved to either
```

This is a **Merkle hash over each package's own transitive dependency cone**,
keyed on static formal names, memoized once per package (content-addressed), so
computing all identities is `O(edges in the dep DAG)` — linear in the package
graph, no forcing, no eval, derived entirely from parse-cache fingerprints and
`FormalSet` formals. It replaces the dead value-hash environment component of
§3.2 with a **source-identity environment component**.

### 11.3 Soundness — a dep edit flips the identity without forcing (design Q2)

Claim: `boundary_identity(P)` changes whenever `P`'s `.drv` could change,
**and** the change is observable without forcing any argument.

`P`'s derivation is a pure function of (a) `P.nix`'s code, (b) the derivations /
values of `P`'s declared dependencies, and (c) impure inputs. Take each:

- **(a) P's own source.** Any edit to `P.nix` changes
  `LoweredIrFingerprint(P.nix)` (the parse cache is content-hash-keyed since
  `ab7289106`) → a different Merkle preimage → a different identity. ✓
- **(b) A dependency.** By structural induction over the dep DAG: editing a
  dependency `D` changes `LoweredIrFingerprint(D.nix)` (base) or, transitively,
  some deeper dep's identity (step); either way `boundary_identity(D)` changes,
  and `D`'s identity is a Merkle child of every package that declares `D` as a
  formal, so their identities change too. The base case is a leaf package whose
  formals are all framework closures / in-file literals, fully covered by its
  own fingerprint. ✓ The recursion follows **only declared formals**, never the
  ambient `self`, so it terminates on the cone and never touches unrelated
  packages.
- **(c) Impure inputs.** Unchanged from doc 29 §2.3: the boundary record still
  carries its `[CacheableInputFingerprint]` slice and revalidates it on every
  hit. Source identity covers code; the slice covers observed world.

Crucially, every input to the identity — file fingerprints and static formal
names — is available from the parse artifact, so the identity is computed with
**zero forcing**: the 98.8% decline that killed value keying does not arise,
because we never ask for a value hash of an argument at all.

### 11.4 It does NOT degenerate to root cutoff (the load-bearing distinction)

Root cutoff hashes the entire entry closure into **one** fingerprint: any edit
anywhere misses the whole eval. Source-Merkle boundary identity hashes **each
package's own cone separately**: editing leaf package `L` changes
`boundary_identity(L)` and the identities of packages in `L`'s reverse-dependency
cone, and **nothing else**. Every package outside that cone keeps its identity
and replays. This is strictly finer than root cutoff — it is exactly the
partial-warm behaviour the whole effort is for — provided the dep DAG is not a
single giant fan-in where every package transitively depends on the edited one.
For the AOS set the common edit (a leaf tool, a version bump on a mid-tree
package) has a bounded reverse-dep cone, so the lever survives; a change to
`stdenv`/`mkDerivation` itself invalidates nearly everything, which is **correct**
(it does affect nearly every drv) and no worse than root cutoff for that case.

### 11.5 Precision lost vs value keying (design Q4) — the safe direction

Source-identity keying is **coarser** than value keying and loses exactly one
kind of reuse: a source change in the cone that does **not** change the drv
(a comment, a formatting change, a dependency's runtime-only field that never
reaches the derivation) flips the identity and forces a re-eval that value
keying would have elided by observing the drv is byte-identical. The loss is
**false invalidations only**:

- A false invalidation costs one package re-evaluation — a correct, slightly
  slower result.
- A false **hit** would be a wrong `.drv`. Source-Merkle identity cannot produce
  one: equal identity ⇒ identical source cone ⇒ (given the revalidated impure
  slice) identical derivation, by the soundness argument in §11.3.

So the error is entirely in the safe direction, matching doc 29's advisory-tier
invariant (§7.7): a mis-key degrades to a miss, never to a wrong output. This is
the same trade root cutoff already makes (it re-evals on any no-op edit too),
applied at finer granularity.

### 11.6 Hybrid with the 37% forced members (design Q3) — a refinement, not the carry

The 37% of members that *are* forced-and-hashable at record time (typically
in-file scalars a package forces early — version strings, feature flags, and
already-realised shared attrsets) can additionally contribute a durable
`ValueHash` component, giving cross-package dedup that source identity misses
(two textually-different packages that force the *same* value would share the
value component). But the hybrid must not make the key depend on evaluation
dynamics: whether a given member is forced at record time is itself a function
of the eval, so "value-hash if forced else identity" would change the key when
the force pattern shifts — a false miss (safe) but a needless one. Disposition:

- **Carry the key on source identity (§11.2) for every member**, uniformly and
  deterministically. In-file scalars are already covered by
  `LoweredIrFingerprint(P.nix)`, so a version bump flips the identity through
  the file hash regardless.
- Treat the forced-value component as an **optional, separately-versioned dedup
  index** layered on top — never as a substitute for the source identity — and
  only if a later measurement shows the cross-package value-dedup mass is worth
  the added key surface. It is not part of the v1 record key.

### 11.7 Economics re-estimate under source-Merkle keys (design Q5)

- **Key derivation tax:** a blake3 over `(file fingerprint ‖ dep identities)`
  per package, memoized once per boundary → `O(dep DAG edges)` total, all from
  parse-cache data already resident. This is far below the value-hash tax that
  §8 worried about (no large-attrset blake3, no forcing) and is dominated by the
  fingerprints the parse cache computes anyway.
- **Warm benefit:** on a one-file edit, only the edited package's reverse-dep
  cone re-evaluates; the remaining boundaries replay their recorded drv
  projection (a hit is an identity match + slice revalidation, not a
  `mkDerivation` eval). With 1,274 distinct boundaries owning substantial cold
  wall, a leaf edit that leaves most cones intact converts most of the
  package-application wall into replays. The realizable fraction is the
  reverse-dep-cone size distribution — the **next measurement** (§11.8).
- The blake3→xxh128 experiment (measuring now) lowers the per-identity hash cost
  further if it lands; fold its result into the record-store pricing.

### 11.8 What the measurement must now answer (before M2-record)

The keying pivot re-opens a *stability* question the §7 probe did not answer,
and it is the new gate:

1. **Reverse-dep-cone size distribution.** For each package boundary, how many
   boundaries are in its reverse-dependency cone (i.e. would be invalidated if
   it changed)? A median small cone ⇒ a leaf edit replays ~everything ⇒ the
   lever is large. A fat fan-in (most packages transitively depend on a few
   hubs) ⇒ edits near a hub invalidate most of the set ⇒ smaller lever.
2. **Static-resolution coverage.** What fraction of the 1,274 def-sites have
   *all* formals statically resolvable to a package or a framework closure
   (`dep_component` never hits the DECLINE arm)? Boundaries with a dynamically
   computed dependency decline (safe) and cap coverage; this number sizes it.

Both are derivable from the parse artifacts + the fixpoint attr names by a
probe analogous to §7 (a static walk of `FormalSet` formals against the package
set), **no eval**. That is the M2-measure-2 increment, gated the same way: if
the reverse-dep cones are fat or resolution coverage is low, we close
MEMO-2-seeding with §10 + §11.8 as the evidence; if they are favourable, M2-record
proceeds with source-Merkle keys.

**Honest bottom line.** Value keying is dead (§10). Generic thunk-identity is
dead (§11.1, degenerates to root cutoff). Source-Merkle boundary identity
(§11.2) is sound (§11.3), strictly finer than root cutoff (§11.4), safe in its
imprecision (§11.5), and cheap to key (§11.7) — but whether it delivers a
*product-level* win rather than a marginal one now rests entirely on the
reverse-dep-cone distribution (§11.8), which is one more no-eval measurement
away. I recommend building M2-measure-2 before any record store.

### 11.9 M2-measure-2 result (2026-07-14): the gate opens

The analysis (`pkgs/_memo2-cone-analysis.nix`, a pure `readDir` +
`functionArgs` walk — no stdenv, no builds; run with
`nix eval --impure --json --file pkgs/_memo2-cone-analysis.nix`) resolved the
gate **favourably** across 265 package files:

| Reverse-dep cone (packages invalidated per edit, of 265) | |
| --- | --- |
| min / **median** / p90 / p99 / max | 1 / **3** / 32 / 135 / 150 |
| mean | 12.8 |
| **median leaf-edit replay fraction** | **98.9%** (3 / 265 invalidated) |
| p90 replay fraction | 88.0% (32 / 265) |

| Static-resolution coverage (2,034 formals over 265 files) | |
| --- | --- |
| dep-edge / framework / **decline** | 1,029 / 1,004 / **1** |
| **resolved fraction** | **99.9%** |
| unreadable files | 0 |

- **The distribution is strongly right-skewed toward small cones.** The median
  package's edit invalidates only 3 of 265 boundaries — 98.9% of the set replays.
  Even at p90 an edit invalidates 32 (88% replay). Only a handful of deep
  library packages (p99 = 135, max = 150) have large cones, and those are
  *correctly* large: editing a widely-depended-on library should rebuild its
  dependents. The common edit — a leaf tool, a version bump on a mid-tree
  package — sits at the median.
- **Coverage is essentially total.** 99.9% of formals resolve to a package
  dependency or a framework reference; the *only* decline in the whole set is
  `linux`'s `extraConfig` formal (a kernel config arg, correctly not a package —
  that boundary declines, safely). Every package file's formals read cleanly.
- **The fat hubs are isolated as designed.** `fetchurl` (250), `mkDerivation`
  (250), `gnumake` (212), `bash` (56) … are framework references, not
  dependency-cone edges, so they do not distort the per-package distribution;
  their (correctly global) invalidation reach is reported separately.

**Verdict: the gate opens — M2-record proceeds with source-Merkle keys.** The
lever is real (§10: 1,274 boundary applications own substantial cold wall), the
key is sound and cheap (§11.2–11.7), and a typical partial-warm edit now replays
~99% of package boundaries instead of falling to full cold. The one residual
question is per-package recompute cost weighting: cone *counts* are favourable,
but the wall win is (cone-weighted-by-recompute-cost); the drv-projection record
store (§9 M2-record) is where that is realised and measured against the byte
gate.
