# MEMO-2 M2-record — applied-package boundary record store (spec)

Status: **SPEC — design-first, not yet approved for code.**
Owner: p2-attrs (task #13). Reviewed-by: (pending team-lead).

This spec follows the approved keying redirect
([memo2-applied-boundary-seeding-plan.md](memo2-applied-boundary-seeding-plan.md)
§11) and the M2-measure-2 verdict (§11.9: median reverse-dep cone 3/265, 98.9%
replay, 99.9% static-resolution coverage — the gate opened). It specifies the
**boundary record store**: how a package boundary is recorded, keyed by
source-Merkle identity, and replayed on a partial-warm eval so unchanged package
applications skip evaluation. It is an instance of the doc 29
([29-tiered-content-keyed-memoization.md](../29-tiered-content-keyed-memoization.md))
record framework at a new granularity.

Everything here is advisory and byte-parity-subordinate (doc 29 §7.2): a boundary
replay must produce the byte-identical `.drv`, every hit revalidates its impure
slice, a miss falls through to evaluation, and a kill switch disables the tier.

---

## 0. The one honest coupling, stated up front

The source-Merkle key (§2) is **not** a drop-in of doc 29 §3.2's generic
environment component, and it is **not** derivable by generic recursive
thunk-identity keying — §11.1 proved that degenerates to root cutoff, and a
`self`-token shortcut would be *unsound* (it would miss source edits). A sound,
non-degenerate boundary identity **must** resolve each dependency to its
**source file** and hash file contents transitively. That resolution
(`formal name → dependency package → its .nix file`) is exactly the AOS
`callPackage`/`discoverPackages` convention: formal names are fixpoint keys are
package files (`intersectAttrs (functionArgs fn) self`).

So M2-record is deliberately **AOS-package-set-aware**: the boundary-identity
map is a static analysis of the package set's dependency structure (§2.2), the
same computation M2-measure-2 already runs, extended to hash. This is a feature
of the *warm-coverage* goal, not a general Nix memo — and it is flag-gated and
scoped so anything outside the recognised shape declines safely (§4). Naming
this coupling is the point of §0; the rest of the spec builds on it.

---

## 1. The record kind (doc 29 envelope)

A **`BoundaryClosure`** payload kind joins `Value` / `RootClosure` /
`FrontEndArtifact` / `CompiledBody` (doc 29 §2.2). One record per package
boundary:

```text
MemoRecord (kind = BoundaryClosure)
├── key               : BoundaryIdentity            (§2 — source-Merkle, durable blake3)
├── payload
│   └── drv projection : { drvPath, outPaths (by output name), derivation ATerm bytes }
│                         — the fully-demanded, closure-free `.drv` projection of
│                         the applied package (doc 29 §6 eligible: a .drv closure
│                         is demanded by definition; ValueHash::from_derivation_aterm_bytes
│                         already hashes it)
├── impure_slice       : [CacheableInputFingerprint]  (doc 29 §2.3, canonicalized)
├── validity
│   ├── options_identity : TreeWalkOptions::result_affecting_fingerprint()
│   └── format_version   : BOUNDARY_RECORD_FORMAT_VERSION + crate version
└── stats (est_recompute, entry_bytes, hits) — tiering inputs
```

**Why the drv projection and not the attrset** (§11 / doc 29 §6): a package
value is an attrset full of thunks/closures — ineligible for durable tiers. The
derivation projection (drvPath + output paths + ATerm) is fully demanded at the
boundary and closure-free, so it round-trips the canonical codec. A downstream
select outside the projection (`.override`, sub-outputs, `passthru`) is a
**clean miss** for that access → that package re-evaluates (§4); the projection
covers the `.drv`-production workload that is the target.

`v1` payload is projection-only. The full-forced-eligible-attrset payload
(doc 29 §6 eligibility walk) stays a measured widening (M2-widen), not v1.

---

## 2. Source-Merkle key derivation

### 2.1 Definition (restating §11.2 as the record key)

```text
BoundaryIdentity(P) =
  blake3( DOMAIN
        ‖ BOUNDARY_KEY_FORMAT_VERSION ‖ crate_version
        ‖ LoweredIrFingerprint(P.nix)
        ‖ for f in formals(P) in canonical (sorted) order:
            dep_component(f)
        ‖ frameworkIdentity                         # global; see §2.4 (soundness)
        ‖ options_identity )                        # validity context folded in, per root cutoff

dep_component(f) =
  | BoundaryIdentity(Q)     if formal f resolves to package Q (Q.nix exists)
  | builtin_id(f)           if f is a framework reference (mkDerivation, fetchurl,
  |                           stdenv pass-throughs …) — a per-name SALT only, to
  |                           distinguish *which* framework a formal names. It does
  |                           NOT carry framework-edit invalidation; frameworkIdentity
  |                           (§2.4) does, folded once into every key.
  | override_source_id(f)   if f is a shared-source override arg (linuxSource, …) —
  |                           the fixed-output fetch identity (its output hash)
  | ⟂ DECLINE the boundary  otherwise (e.g. linux `extraConfig`, a dynamic arg)
```

`LoweredIrFingerprint` is the per-file post-remap blake3 the parse cache already
persists (doc 29 §3.1; `cache/parse/mod.rs`). The key is a Merkle over the
package's own dependency cone — `O(edges)`, cycle-safe, memoized once per
package — plus the global `frameworkIdentity` that §2.4 proves is required.

### 2.2 Where the Merkle memo lives and when it invalidates

The boundary-identity map is a **derived artifact of the package-set source**,
computed by the same static walk as M2-measure-2 (`pkgs/_memo2-cone-analysis.nix`
logic, in Rust, extended to hash): enumerate `name → file` (the
`discoverPackages` naming), read each file's `LoweredIrFingerprint` + static
`FormalSet` formals from the parse cache, resolve formals to `dep_component`s,
and fold the Merkle bottom-up (topological over the dep DAG; cycles broken by
`genericClosure`-style fixed point).

- **Residency:** an in-memory `name → BoundaryIdentity` map for the eval, built
  lazily+memoized on first boundary demand (or eagerly at eval start when the
  tier is on). Durably, it persists as a **`BoundaryIdentityMap` artifact** keyed
  on the *set* of contributing file fingerprints (a Merkle root over all package
  files), so it is itself a doc 29 record — reusable across evals whose package
  sources are unchanged.
- **Invalidation is content miss (doc 29 §7.4):** edit `P.nix` → new
  `LoweredIrFingerprint(P.nix)` → new `BoundaryIdentity(P)` → and, because it is
  a Merkle child of every package that declares `P` as a formal, new identities
  up `P`'s reverse-dep cone. No reverse-dep index, no invalidation walk: the old
  identities are simply never reconstructed. The `BoundaryIdentityMap` artifact
  whose fingerprint-set changed is likewise never reconstructed and becomes reaper
  garbage.

**Seam:** the map builder consumes parse artifacts only (fingerprints + formals)
— **no eval, no forcing** — exactly like M2-measure-2. It is the AOS-aware piece
of §0; it is seeded from the package-set root (the `pkgs` directory /
`discoverPackages` entry) passed in as configuration, not sniffed from arbitrary
evaluation.

### 2.3 The 37% forced members and the hybrid (design §11.6)

Not in the v1 key. In-file scalars (version strings, flags) are already covered
by `LoweredIrFingerprint(P.nix)`. The forced-value dedup index is an optional,
separately-versioned layer (M2-widen), never a substitute for the source
identity, and only if a later measurement shows cross-package value-dedup mass.

### 2.4 Framework-source soundness — VERIFIED, and why the slice does not cover it

The review flagged the exact silent-wrong-drv class we refuse: a boundary's key
components for framework formals (`mkDerivation`, `fetchurl`, stdenv
pass-throughs) are static per-name salts, so a **stdenv/mkDerivation source edit
does not change them**. That is sound *only if* the framework source edit is
caught elsewhere — either the boundary's revalidated impure slice covers those
`.nix` reads, or a framework fingerprint is in the key. I verified the slice does
**not** cover them, so the key must:

**Verification (against `pkgs/default.nix`).** The framework functions are
constructed **once, at the top of `pkgs/default.nix`'s `let`**, and captured in
`self`:
`mkDerivation = args: rawMkDerivation (…)` where `rawMkDerivation = stdenv.mkDerivation`;
`fetchurl = lib.fetchurl`; `bootstrapTools = stdenv.cc`; and `stdenv` / `lib`
arrive as the `{ lib, stdenv }` arguments (built *outside* `pkgs`). Calling
`mkDerivation {…}` per package **invokes a captured closure — it imports no
framework `.nix` file.** Therefore, during a package boundary's evaluation, the
impure trace captures **no** framework source `Import`/`ReadFile` beneath the
boundary. Worse than "not captured": any framework code imported *lazily* lands
in whichever boundary happens to force it first, so even a stray framework read
is **mis-attributed** to one boundary's slice and absent from all the others.
Either way the slice cannot carry framework-edit invalidation.

**Consequence (the required fix).** Per the review's fallback, fold a global
**`frameworkIdentity`** into every boundary key (§2.1). It is a source Merkle
over the framework closure — the `.nix` sources of `lib/`, `stdenv/`, and
`pkgs/build-support/` (the `mkDerivation`/`fetchurl`/`lib`/nuke-references/
trivial-builder implementations and the toolchain the stdenv arg is built from,
including `stdenv/bootstrap-tools.nix`). Any edit there changes
`frameworkIdentity` → **every** boundary key changes → the whole set
invalidates. That is the *correct* behaviour: a stdenv/mkDerivation change alters
nearly every drv, so a global invalidation is right, and it is no worse than root
cutoff for that (rare) case. `frameworkIdentity` is computed once per eval and
folded into every key, so its cost is a single Merkle, not per-boundary.

**Soundness statement (for §5's parity argument).** A boundary key now covers:
(a) `P`'s own source (`LoweredIrFingerprint(P.nix)`); (b) `P`'s dependency cone
(recursive `dep_component`); (c) the framework source, globally
(`frameworkIdentity`); (d) `P`'s observed impure world (the revalidated
`impure_slice`); (e) resolution config (`options_identity`). A package's drv is a
pure function of exactly (a)–(e), so equal key + revalidated slice ⇒ identical
drv. No framework read rides on an unverified slice-coverage assumption — (c)
carries it explicitly.

**Over-approximation note.** `frameworkIdentity` as a source hash is conservative
(some `lib/` edits do not change any drv, yet flip every key — a false
invalidation, the safe direction). A tighter identity would be `stdenv`'s own
`drvPath`, but that requires a bounded `stdenv` evaluation rather than a pure
source read; deferred as an M2-widen refinement (fewer false invalidations, at
the cost of a small eval in the key builder). v1 stays pure-source and
conservative.

---

## 3. Admission (structural, parse-artifact time, zero probe off-boundary)

Per doc 29 §8 rule 1 (never probe the bare force/apply path): admission is a
**per-def-site decision marked once**, so non-boundary applications (the 14.58M
`clone_env_frames` installs, 89% empty) pay **zero**.

- **Boundary flag on the lowered node.** At parse-artifact time, mark a package
  file's root lambda def-site as a boundary candidate. A def-site is a boundary
  iff (a) its module is a discovered package file (present in the seeded
  `name → file` map), and (b) its root expression is the file's top-level
  `FormalSet` lambda. Both are static properties of the parse artifact; the flag
  rides the artifact like the compiled-body admission flag (`memo.rs`
  `MemoDefSiteDecision`).
- **Cost floor.** `est_recompute ≥ AOS_NIX_MEMO_MIN_COST` (doc 29 §5.7) — a
  package `mkDerivation` body is comfortably coarse, but a bare alias package
  should not seed. The estimate is a static parse fact.
- **Resolution gate.** If any formal hits `dep_component`'s DECLINE arm (§2.1),
  the boundary declines admission (safe): it is keyed only when its whole formal
  set statically resolves. M2-measure-2 says this costs one boundary in the set
  (linux/extraConfig).

At the apply choke point (`eval_primop_apply.rs`, the same seam the M2-measure-1
probe hooks), a non-flagged application does a single already-loaded bool check
and proceeds — no key derivation, no probe.

---

## 4. Replay path (bottom-up, projection-miss = clean fall-through)

Replay is attempted **before** evaluating a flagged boundary application:

1. **Derive / look up `BoundaryIdentity(P)`** from the map (§2.2). Bottom-up by
   construction: `P`'s identity already incorporates its deps' identities, so
   the probe order follows the dep DAG — a package is probed with a key that is
   only valid if its whole source cone is unchanged.
2. **Probe** the boundary record store (L0 → L1 → durable, §6) for that identity
   + matching `options_identity` + `format_version`.
3. **On hit:** revalidate the `impure_slice`
   (`revalidate_cacheable_input_trace`, `eval_impure_inputs.rs:103` — all-or-
   nothing, incomplete-latches, conflict-refusal). If it revalidates, **install
   the recorded drv projection as the boundary's result without evaluating the
   package body.** The downstream fixpoint continues against the projected drv.
4. **On any miss** — no record, options/format mismatch, slice revalidation
   failure, **or a downstream select outside the drv projection** — **fall
   through to the normal package evaluation.** A miss is *never* an error and
   *never* observable in output; it is exactly the eval that would have run
   without the tier. On the post-eval path, record the boundary (§1) if admitted.

**Select-outside-projection handling.** The installed boundary result is a drv
projection, not the full package attrset. A select of a projection field
(`drvPath`, `outPath`, an output) is served from the record; a select of any
other attr (`.dev`, `.override`, `passthru.*`) must **demote to a full
evaluation** of that package — the record cannot answer it. v1: on the first
non-projection select against a replayed boundary, drop the projection and
evaluate the package body (correctness over hit-rate). M2-measure-2's target is
the `.drv` gate, where the toplevel forces `drvPath`/`outPath`; the widening to
full-attrset payloads (M2-widen) is what raises non-drv-select coverage.

---

## 5. CHECK mode and the parity story (byte-gate supremacy)

- **Parity is almost definitional here, but state it:** a boundary hit installs
  a recorded `.drv` projection in place of evaluating the package. Byte parity
  holds iff that projection is byte-identical to what evaluation would produce.
  It is, *because* (a) the source-Merkle identity matches only when the whole
  source cone AND the framework source (`frameworkIdentity`, §2.4) are
  byte-identical, (b) the impure slice revalidates the observed world, and (c)
  the payload IS the canonical derivation bytes — there is no re-derivation step
  that could drift. Equal identity + revalidated slice ⇒ identical drv, by the
  §2.4 soundness statement (a)–(e). This is the §11.5 argument at record
  granularity: false invalidations only, never a false hit. Note in particular
  that a framework/stdenv edit flips `frameworkIdentity` and invalidates every
  boundary — the class the review flagged is closed by the key, not by an
  assumed slice coverage.
- **CHECK mode.** Extend `AOS_NIX_MEMO_CHECK` to the boundary tier: every hit is
  shadowed by a real package evaluation and the drv projections compared
  byte-for-byte, exactly as `verify_root_cutoff_closure` (`root_cutoff.rs:341`)
  shadows a root hit. CHECK is the first-class development gate for the two novel
  surfaces — the source-Merkle map builder and the slice attribution for a whole
  package subtree.
- **The gate that ships nothing until green:** the x4 package byte gate (and, on
  Linux, the full-corpus `.drv` gate) must pass with the boundary tier off, on,
  CHECK-on, and in parallel mode, before any default flip (doc 29 §7.2).

---

## 6. Phasing

1. **M2-record-L0/L1 (this spec's build target, after review):**
   - the `BoundaryIdentityMap` static builder (Rust port of M2-measure-2 +
     hashing), seeded from the package-set root;
   - the boundary admission flag at parse-artifact time;
   - the `BoundaryClosure` record kind + drv-projection payload codec;
   - L0 (per-worker) + L1 (shared, parallel) in-process record store;
   - the replay path (§4) and select-outside-projection demotion;
   - `AOS_NIX_MEMO_CHECK` boundary tier + parity gate;
   - **default-off** behind `AOS_NIX_BOUNDARY_MEMO`.
2. **M2-durable (phased after L0/L1 is byte-green):** persist `BoundaryClosure`
   records and the `BoundaryIdentityMap` artifact under the shared indexed
   `files/` pack with the root-cutoff-style hit/store/revalidate path and the
   demotion engine; the cross-eval partial-warm demonstration (§7) lives here.
3. **M2-widen (measured):** full-forced eligible attrset payload; non-drv-select
   coverage — each gated on its own measurement.

L0/L1 first keeps the correctness surface (map, admission, replay, CHECK) in one
process before durable serialization is added, matching the MEMO-1 phasing
(doc 29 §10.1).

---

## 7. Measurement — the acceptance gate is a partial-warm demo

Cone *counts* are favourable (§11.9), but the honest residual is that the wall
win is **cone-weighted-by-recompute-cost**. The acceptance gate is therefore a
**measured one-file-edit partial-warm demonstration**, not a counter:

1. Cold eval the toplevel with the boundary tier on; record all boundaries.
2. Edit a **median-cone leaf package** (cone ≈ 3, per §11.9 — e.g. a leaf tool),
   changing its source such that its `.drv` changes.
3. Re-eval the toplevel. **Acceptance:**
   - ~99% of the 265 boundaries replay from records (only the edited leaf's
     reverse-dep cone re-evaluates) — measured by boundary hit/miss counters;
   - the second eval lands **near warm speed** (materially below the ~2.6 s cold,
     toward the root-cutoff 7.8–28 ms floor for the replayed fraction) — measured
     wall on the builder;
   - **byte-green**: the produced `.drv` is byte-identical to a from-cold eval of
     the edited tree (the differential gate), tier on/off/CHECK-on.
4. A hub-edit control (edit a high-cone library): confirm it correctly
   invalidates its large cone (few replays) and stays byte-green — proving the
   invalidation is neither too coarse nor unsound.

If the median-leaf demo does not land near warm speed (e.g. the replayed
boundaries' recompute cost is a small fraction of cold wall after all), we close
MEMO-2-seeding with §10/§11.9/§7 as evidence and the tier ships default-off as a
measured negative — the same exit ramp as MEMO-1 (doc 29 §10.1). Favourable ⇒
M2-durable proceeds.

---

## 8. Risks

- **The AOS-convention coupling (§0), the headline risk.** The key builder
  assumes formal names = fixpoint keys = package files. Packages that break it
  (dynamic deps, non-file fixpoint members) decline safely (§3 resolution gate) —
  a coverage cap, not a correctness risk (§11.9 measured it at one boundary). But
  it means the tier is package-set-shaped, not a general Nix memo; it must be
  scoped and flag-gated so a non-package-set eval never engages it.
- **Select-outside-projection demotion churn (§4).** If the toplevel forces
  non-drv attrs off many packages, v1's demote-to-eval erodes the hit rate; the
  §7 demo measures this, and M2-widen addresses it.
- **Slice attribution for a whole package subtree** is larger than MEMO-1's
  per-node slice; CHECK mode (§5) is the backstop and must be green before any
  default flip.
- **Map-build cost** is `O(edges)` over parse artifacts, memoized and persisted;
  it must not dominate the cold path when the tier is on — the §7 cold-leg wall
  measures it. The blake3→xxh128 experiment lowers the per-identity hash cost if
  it lands.

---

## 9. Open questions for review

1. **Map builder home:** a standalone `BoundaryIdentityMap` module consuming the
   parse cache, seeded with the package-set root path — or fold it into the
   existing root-cutoff/native path that already knows the entry file? I lean
   standalone (testable in isolation, reusable by a future `aos` introspection
   command), seeded via `TreeWalkOptions`.
2. **Select-outside-projection:** v1 demote-to-eval (simplest, correct) vs.
   recording a richer eligible projection up front. I recommend demote-to-eval
   for v1 and let the §7 demo size whether M2-widen is worth it.
3. **Identity granularity for framework refs — RESOLVED (review, §2.4).** My
   original "per-name constant is enough" was **wrong** and is retracted: the
   impure slice does **not** cover framework source reads (verified against
   `pkgs/default.nix` — framework functions are captured once at top-level, not
   re-imported per boundary, and lazy reads mis-attribute to one boundary). So a
   static per-name id would silently miss a stdenv/mkDerivation edit — the exact
   wrong-drv class we refuse. Fixed by folding a global `frameworkIdentity`
   (source Merkle over `lib/` + `stdenv/` + `pkgs/build-support/`) into every
   boundary key; `builtin_id(f)` is now only a per-name salt to distinguish which
   framework a formal names. Open sub-question kept for M2-widen: tighten
   `frameworkIdentity` from a pure source hash to `stdenv`'s `drvPath` (fewer
   false invalidations, at the cost of a bounded stdenv eval in the key builder).
