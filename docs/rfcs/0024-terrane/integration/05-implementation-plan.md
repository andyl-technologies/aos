# 05 — Implementation plan

This is the plan AOS works through to adopt Terrane. It is the ordering
authority: it arranges tasks into a serial **trunk** of milestones and a set
of **branch** worklines that fork from named milestones, names the gate
that must be green to leave each milestone or merge each branch, and records
which specification files' `MUST` requirements each covers. The
specification itself carries no checklists (spec `00-conventions.md` §Task
plans); this file is where tasks live.

## The MVP

The MVP serves three consumers at once, because all three are the same
system seen through different surfaces:

1. the RFC-0021 sandbox view service
   ([`01-sandbox-runtime.md`](01-sandbox-runtime.md));
2. shared Nix and Bazel build caches
   ([`07-ci-caches.md`](07-ci-caches.md));
3. GitHub Actions caches for GCP-hosted spot-VM CI runners
   ([`07-ci-caches.md`](07-ci-caches.md)).

The MVP is the trunk through milestone T6: one warehouse over a `file://`
root or a GCS or S3-compatible bucket, N hosts, nested sandboxes, and the
three protocol surfaces those consumers need. Everything else is a branch.

Testing is local only: Nix checks, the AOS-built Garage as the
S3-compatible stand-in, and VM tests on the AOS kernel. Probes against
cloud buckets are run by hand and their results recorded in
[`06-decision-register.md`](06-decision-register.md); no gate depends on
network access.

## How to use this plan

- Task IDs are area-scoped and stable, `T-<AREA>-<n>`, where `<AREA>` is a
  specification prefix (spec `00-conventions.md` §Area prefixes) or one of
  the integration prefixes `SBX`, `HUB`, `PKG`, `CRU`, `CI`. Re-sequencing a
  task never renumbers it. When an earlier task was narrowed to trunk scope,
  its deferred remainder is a new task with the next number in the same
  area, and the narrowed task says so.
- Every task lists the requirement IDs it satisfies and the gate or check
  that proves it. A task is done when its check is green in
  `checks.terrane.*` ([`03-packaging.md`](03-packaging.md) PKG-7).
- **Trunk.** Milestones T0 through T6 are serial. Each leaves a deployable,
  gate-green system and freezes something the branches depend on. A
  milestone is done when all its tasks are checked and its exit gates are
  green; the next milestone does not start before that. T4 and T5 share no
  dependency and MAY be worked concurrently, but merge in that order.
- **Branches.** A branch forks from the milestone it names, keeps every
  trunk gate green throughout, and merges as one reviewed change that adds
  its gates to the registry and its requirement ranges to the conformance
  claim (PLAN-3). A branch depends on another branch only where this plan
  says so.
- **Freezes.** After T1, no branch changes an identity, encoding, bucket
  key, or store trait; branches add registry entries only (properties,
  attributes, surfaces, gate names, reserved names). After T2, the surface
  interface and exposure record are frozen. After T3, the wire protocol and
  token format are frozen. A change to a frozen item goes through trunk as
  its own milestone revision.
- **Trunk gates are the branch floor.** A branch that reddens any trunk
  gate does not merge.
- **[PLAN-1]** Every `MUST` in every specification file named by a
  milestone or branch MUST be satisfied by at least one task before this
  RFC's status moves to Implemented. The coverage section at the end lists
  the mapping and MUST show no uncovered file.
- **[PLAN-3]** The MVP conformance claim (spec TEST-17) MUST be published
  at T6 and MUST list exactly the requirement ranges the trunk satisfies,
  the specification files it leaves partial, and the branch that completes
  each partial file. Every branch merge MUST extend the claim. The RFC's
  status moves to "Implemented (MVP)" at T6 and to "Implemented" only when
  PLAN-1 holds for every file.

```text
trunk:  T0 ── T1 ── T2 ── T3 ── T4 ── T5 ── T6
        │     │     │     │     │     │     │
        │     │     │     │     │     │     └─ B-ops
        │     │     │     │     │     └─ B-consistency
        │     │     │     │     └─ B-surfaces-more ─ B-hub-edge
        │     │     │     ├─ B-auth                  (also needs B-derive)
        │     │     │     ├─ B-topology
        │     │     │     └─ B-bandwidth
        │     │     └─ B-storage
        │     ├─ B-derive
        │     ├─ B-redundancy
        │     └─ B-jobs (also needs B-derive)
        └─ freezes crate layering

T0 foundations · T1 local repository · T2 host tier · T3 wire and buckets
T4 CI caches · T5 sandboxes · T6 hardened MVP
```

## Trunk

### T0 — Foundations

**Status:** Complete (2026-09-29).

Freezes: crate layering and the `no_std` boundary.

Exit gates: `checks.terrane.gates.crate-graph`,
`checks.terrane.gates.core-no-std`, `checks.terrane.package` building an
empty `terrane` binary.

- [x] **T-PKG-1** Add `terrane-core` to the workspace with `#![no_std]`,
  workspace lints, and the AOS Rust documentation standard. — satisfies
  PKG-1, PKG-2, CRATE-1, CRATE-30, CRATE-34 to CRATE-36;
  `checks.terrane.gates.crate-graph`.
- [x] **T-PKG-2** `pkgs/tools/terrane.nix`, workspace vendor hashes,
  nextest in the `aos` package check phase, `aos-dev` targets. — satisfies
  PKG-3 to PKG-5, PKG-11; `checks.terrane.package`.
- [x] **T-CRATE-2** The `terrane`, `terrane-fs`, and `terrane-cli` crates as
  workspace members with the dependency direction rules enforced, the
  `terrane` binary with role selection and configuration loading, and the
  gate harness that maps `gate:` names to `checks.terrane.gates.*`. —
  satisfies CRATE-2, CRATE-4, CRATE-5, CRATE-10 to CRATE-12, CRATE-15,
  CRATE-16, PKG-7; `checks.terrane.gates.crate-graph`,
  `checks.terrane.gates.role-selection`,
  `checks.terrane.gates.registry-complete`.
- [x] **T-RISK-3** Prolly boundary variance: generate trees of 10^4 to 10^7
  entries, measure node-size distribution under TREE-21 to TREE-24, and
  confirm the size-scaled boundary probability holds the distribution within
  spec limits. — satisfies RISK-5, TREE-22, TREE-24;
  `checks.terrane.gates.tree-node-distribution`.

### T1 — Local repository

**Status:** In progress. Latest combined candidate `bddcd674cd72` retains
the reviewed source-discovery tree, qualified with 625 passing core tests
and zero skips. Both mandatory formatters pass. Its default and keep-going
current-trunk aggregates both exit 1; the latter reports twelve failed gate
dependencies, listed under T-DRV-2. Its observed native feature suite records
362 passing and 43 failing tests out of 405; later profiles remain unqualified.
Repeatable I/P/G maintenance is in progress on the shared checked prerequisites.
No formal task merge, task checkbox, milestone exit or freeze advances.

The reviewed owned-association candidate `28e8a7b6e5b9`
passes all 605 core tests with zero skips (Nextest run
`256a9f8c-e8dd-4b19-b284-69a3a4c4478b`), strict all-target core Clippy and
rustdoc. The final increment adds only the public callback panic contract;
strict rustdoc and both required formatters pass again. Parent combined
candidate `b7da6543b94d` passes both formatters and the actual
`property-resolution`, `prov-selector-presets` and `core-no-std` gates,
including all three newly mandatory association cases. Its complete golden
gate passes all 19 owning suites and the 30-section inventory. Its aggregate
finishes with `--keep-going` and exits 1: ten dependencies fail, including
physical-exclusion admission and portable bucket reopen returning
`Unsupported`, missing required native disclosure cases, and the feature
matrix's first profile (370 pass, 23 fail out of 393; later profiles unqualified).
These results precede the newly mandatory executable recorded-fold case.
The prior combined candidate `93c8cf0f90b2` passes its five recorded evaluator
gates and complete golden gate (19 owning suites and 30-section inventory).
The core evaluator binds independently supplied recorded interpretation to
checked view/root evidence and actual recipe rebinding; the new owned table
retains caller configuration without authenticating its justification.
Reviewed recorded-fold candidate `7f859c34bf33` passes all 606 core tests with
zero skips, strict Clippy/rustdoc, its augmented merge gate, selector and no-std
gates, and both formatters. Parent combined candidate `eaa190b4577b` passes
both formatters and its actual merge, selector and no-std gates, plus the
complete golden gate (19 owning suites and 30-section inventory). Its aggregate
exits 1 at `store-idempotent-put`: physical-exclusion admission returns
`Unsupported`. These results precede the new native interpretation cases.
The core case qualifies original-view binding through
exclusion preprocessing and fresh recipe replay; all incoming deltas are
excluded, so it does not newly qualify conflict-policy winner selection or
changed-domain preprocessing. Native historical sourcing and full native fold
propagation remain unqualified. Reviewed native-read candidate `a557f6080593`
installs independently supplied immutable view/root interpretations, retains
the selection in each snapshot, and uses it for path resolution and all three
immutable-read evaluator sites. Parent combined candidate `e6485b457f8b`
passes the actual property, selector and no-std gates, both formatters and the
complete golden gate (19 owning suites, 30-section inventory). Its aggregate
exits 1 in `prov-commit-verify`: three required native disclosure cases remain
missing or unqualified. The original native Nextest run records 356 passing,
41 failing and two timed-out tests out of 399, with zero skips; strict native
Clippy remains red on unowned dead code. Original authoring-root validation
still uses current property semantics before recorded snapshot selection, so
protected historical reads remain unqualified. No formal task merge, checkbox,
milestone exit or freeze follows.

Reviewed native merge-input candidate `b2be541dd49d` retains all three checked
view/original-root pairs through selection, occurrence resolution and side
evaluation before fold preprocessing. Its four actual task gates pass; the
merge gate executes all 34 mandatory selectors. Build, strict rustdoc and both
formatters pass. The original full native run remains red: 357 pass, 43 fail
and two time out out of 402, with zero skips. Strict native Clippy remains red
on unowned dead code. The final increment corrects two test-helper comments
only, and strict rustdoc and both formatters pass again. The candidate remains
isolated; protected native historical checks, core checked-scope/evaluator
consistency and combined qualification remain pending. Earlier aggregate
results precede the newly required core scope cases, so no task or milestone
advances.

Reviewed core scope candidate `7494ef6afdd5` now retains the owned interpretation
through actual authenticated scope verification and requires modern evaluators
to match it. All 609 core tests pass with zero skips (Nextest run
`13cc2767-c4b0-42e2-9c57-91e400280ff5`), along with strict Clippy/rustdoc,
both formatters and four actual task gates. A final enum rustdoc summary changes
no behavior and passes strict rustdoc and both formatters again. Combined
candidate `8db47fdf2822` passes both formatters and all five assigned task gates.
Its aggregate completes all 19 mandatory golden owning suites and their 30
reviewed sections, then exits with failure at `store-idempotent-put`:
`physical_exclusion_overrides_live_rows_during_fresh_admission` returns
`StoreFailure { kind: Unsupported, source: None }`. This default aggregate run
does not inventory all failures. It predates the new adapter retention cases
below and cannot qualify them. Native historical sourcing and complete T1
remain open.

Reviewed adapter candidate `f3099e857c60` preserves the exact immutable
interpretation mode/table through three existing verifier reconstructions.
Its three actual task gates, focused tests, all-target build, strict rustdoc
and both formatters pass. The original full native run records 372 passing,
31 failing and two timed-out tests out of 405, with zero skips; strict native
Clippy remains red on unowned dead code. Combined candidate `9a4a4f733813`
passes both formatters, all five assigned task gates and the complete golden
inventory (19 mandatory owning suites, 30 reviewed sections). Its default
aggregate fails at three missing or unqualified native disclosure cases.
The keep-going aggregate also exits 1, reporting 11 failed gate dependencies:
`prov-disclosure-boundary`, `prov-commit-verify`, `store-idempotent-put`,
`index-generation-manifest`, `ref-epoch-fencing`, `ref-advance-ordering`,
`bucket-file-layout`, `role-selection`, `dom-reference-order`,
`dom-dedup-scope` and `feature-matrix`. The Terrane package's own tests fail;
`role-selection` is blocked by that package. Store/index physical-exclusion
and portable-copy cases return `Unsupported`; the ref cases report expiry
and elapsed deadline failures. The feature-matrix native phase records 369
passing and 33 failing cases. These original outcomes do not establish their
causes. Both aggregate runs predate the new ordinary historical-calculation
and core certified-verification cases below, so they cannot qualify them.
No task or milestone advances.

The preceding combined candidate `1ee291d3a655` includes the reviewed optional
runtime fixture correction `3eb44b68daea`. Both mandatory formatters and seven
actual gates pass: `runtime-agnostic`, `bundle-verify`, `property-resolution`,
`prov-commit-signature`, `prov-selector-presets`, `algebra-merge` and
`core-no-std`. Its complete golden gate passes all 19 owning suites and the
30-section inventory. Both original aggregate commands finish and exit 1;
the keep-going inventory identifies 12 failed gate dependencies:
`bucket-file-layout`, `dom-dedup-scope`, `dom-reference-order`,
`feature-matrix`, `index-generation-manifest`, `prov-commit-verify`,
`prov-disclosure-boundary`, `ref-advance-ordering`, `ref-epoch-fencing`,
`role-selection`, `store-idempotent-put` and `tree-history-independence`.
The strengthened Tree gate refuses the first absent batched-edit selector.
Three required native disclosure cases remain unqualified; backend admission
and portable reopen still return `Unsupported`, and ref tests retain their
expiry/deadline failures. The feature matrix's native Tokio profile records
376 passing and 29 failing tests out of 405; later profiles are unqualified.
The optional-Tokio compilation error is absent from this inventory. These
outcomes do not establish the causes of the remaining runtime failures.
The candidate stays isolated; no formal task merge, checkbox, milestone exit
or freeze follows.

The latest combined candidate `8fd890b79f34` includes the reviewed batched
Tree editor `2d4bb984124f`. All 622 core tests pass with zero skips (Nextest
run `5d07bd77-5ffe-4945-ac72-5acbf3841c00`), together with the core build,
strict all-target core Clippy/rustdoc and both mandatory formatters. Nine
actual gates pass: `tree-history-independence`, `tree-boundaries`,
`runtime-agnostic`, `bundle-verify`, `property-resolution`,
`prov-commit-signature`, `prov-selector-presets`, `algebra-merge` and
`core-no-std`. The complete golden gate passes all 19 mandatory owning suites
and the 30-section inventory. Both original aggregate commands finish and
exit 1; the default aggregate stops at the three missing or unqualified native
disclosure cases in `prov-commit-verify`. The keep-going inventory identifies
11 failed gate dependencies: `bucket-file-layout`, `dom-dedup-scope`,
`dom-reference-order`, `feature-matrix`, `index-generation-manifest`,
`prov-commit-verify`, `prov-disclosure-boundary`, `ref-advance-ordering`,
`ref-epoch-fencing`, `role-selection` and `store-idempotent-put`.
The strengthened Tree history gate now passes all six batched-edit cases.
Backend admission and portable reopen still return `Unsupported`; the ref
cases retain expiry/deadline failures. The feature matrix's native Tokio
profile records 376 passing and 29 failing tests out of 405, with no ignored
or filtered tests; later profiles remain unqualified. These results do not
establish the causes of the runtime failures. Source discovery and complete
index maintenance remain subsequent prerequisites. No formal task merge,
checkbox, milestone exit or freeze follows; the candidates stay isolated.

Deployable as: a local tool that initializes a store under a `file://`
root, commits a directory, forks and merges branches, and checks a commit
out to a directory through the `sdk` surface.

Freezes: every identity domain, encoding, bucket key, and the store traits.

Exit gates: `checks.terrane.gates.golden-vectors`,
`checks.terrane.gates.core-fuzz`, `checks.terrane.gates.bucket-file-cas`,
`checks.terrane.gates.gc-grace-window`,
`checks.terrane.gates.algebra-merge`,
`checks.terrane.gates.derivation-memo`,
`checks.terrane.gates.index-tree-maintenance`, store conformance on `file://`.

- [x] **T-OBJ-1** Identity domains, descriptors, and the `terrane-v1`
  identity profile; second-identity-profile registration hook. — satisfies
  OBJ-1 to OBJ-4, OBJ-6 to OBJ-10; `checks.terrane.gates.identity-idempotence`,
  `checks.terrane.gates.descriptor-strict`.
  The descriptor now exposes the normative four-field canonical byte codec,
  with configured-profile bounds checked on borrowed input before allocating
  its owned fields. Five exact codec cases supplement the existing descriptor
  model test: published bytes, every registered domain and integer boundary,
  noncanonical/unknown fields, oversized headers and a different
  configured profile. The actual six-case `descriptor-strict` gate and
  `core-no-std` pass. All 458 core tests, strict all-target core Clippy and
  rustdoc pass; no existing identity, descriptor bytes or store trait changes.
- [ ] **T-CDC-1** FastCDC chunker with the seeded gear table, codec bytes,
  dictionary identities, canonical object manifests, and receiver-side
  validation. Content-class dictionary selection is completed jointly with
  T-DRV-1. D-81 corrects the registry to retain the stored profile seed;
  all existing zero-seed golden values remain unchanged. Conformance is
  reopened after read-only review confirms the native reader and disclosure
  preloader reject dictionaries stored with a compressed codec. CDC-8 requires
  acceptance of every registered codec for every chunk; CDC-9 treats dictionaries
  as ordinary standalone final chunks. A bounded, identity-verified dictionary
  reader and truthful decoded lengths remain required. No raw-only exception
  exists in the normative specification; existing raw dictionary fixtures do
  not qualify this case. No encoding or identity change is needed. The shared
  `chunk-codec` gate now requires two exact guarded-reader cases for all
  registered dictionary codecs and complete dependency validation before
  exposing plaintext; their implementation remains on its task branch.
  Shared test-only native fixtures are crate-visible so those cases can reuse
  actual protected initialization, publication and live ACL changes. The
  existing immutable-read/live-policy test and mandatory formatting pass;
  strict native Clippy still reports unused incomplete T1 implementations.
  The dictionary-reader candidate now passes the actual `chunk-codec` check,
  including both exact guarded cases: every registered stored dictionary codec,
  nested dependencies, malformed/cyclic/unavailable evidence, top-envelope
  limits before dependency reads and actual current ACL revocation. The
  `chunk-bomb-cap` check also passes. The reviewed helper returns genuine
  dependency-first envelopes with verified plaintext lengths as ordinary data.
  Native preload consumption and complete joint qualification remain required;
  the reader stays on its task branch and T-CDC-1 remains open.
  Both actual codec checks also pass on the isolated joint candidate with the
  reviewed reader merged. Native preload consumption remains on its workline;
  these joint codec results do not advance task completion.
  — satisfies
  OBJ-11 to OBJ-18, CDC-1 to CDC-20;
  `checks.terrane.gates.object-identity-from-manifest`,
  `checks.terrane.gates.cdc-boundaries`,
  `checks.terrane.gates.chunk-codec`, `checks.terrane.gates.chunk-bomb-cap`,
  `checks.terrane.gates.zstd-concat`.
- [x] **T-TREE-1** Deterministic CBOR encoder and decoder with limits before
  allocation; node and entry encoding; entry types including `tree`,
  `whiteout`, and `conflict`; reserved types rejected. Full conflict bases
  use iterative codecs and value operations up to the encoded byte limit;
  the separate graft-depth limit does not restrict them. — satisfies TREE-1
  to TREE-8, TREE-11 to TREE-13, TREE-17, TREE-18, TREE-25 to TREE-34;
  `checks.terrane.gates.canonical-cbor`,
  `checks.terrane.gates.tree-well-formed`.
- [x] **T-TREE-2** Prolly-tree builder with content-defined boundaries and
  history independence, balanced levels, and exact child summaries. —
  satisfies TREE-19 to TREE-24;
  `checks.terrane.gates.tree-boundaries`,
  `checks.terrane.gates.tree-history-independence`.
- [ ] **T-ALG-1** `graft`, `split`, `flatten`, `overlay`, `diff`. The 17-path
  reviewed algebra source is adopted without changing manifests, lockfiles,
  identities or shared native interfaces. All 435 combined core tests, strict
  all-target Clippy, strict rustdoc and mandatory repository formatting pass.
  Actual hermetic graft and diff gates pass their 25 and five exact cases,
  including large-target sharing and independent overlay point-update parity.
  Native repository prerequisites are now integrated. The full trunk aggregate
  remains red on the backend retirement compatibility assertion in
  `index-generation-manifest`; task-branch merge qualification remains pending.
  — satisfies
  ALG-1 to ALG-14; `checks.terrane.gates.algebra-graft`,
  `checks.terrane.gates.algebra-diff`.
- [ ] **T-ALG-2** Three-cursor `merge` with conflict values and the
  `prefer-ours`, `prefer-theirs`, `prefer-trusted`, `keep-conflict`, and
  `error` policies; fast-forward; fork and fold; recipes for `merge` and
  `overlay` composites. Native delta parity is completed with T-FUSE-3
  when the overlay-upper importer exists. Narrowed to trunk scope: `filter`, `map`, set
  operations, and the remaining recipe kinds are T-ALG-3 on B-derive.
  D-79's checked cold-fork lineage and genuine zero-TreeNode-I/O qualification
  remain joint with ref publication and source-preserving collection. Actual
  hermetic merge and acyclic gates pass 27 and seven exact cases. Decoded recipe
  evidence cannot execute trust-sensitive policies without freshly verified
  signed views; fold replay retains resolved source ownership. The four pure
  gates cover all 60 algebra tests. `algebra-fork` remains registered and fails
  explicitly as pending; pure commit-binding tests do not qualify native cold
  forks. Complete native fork, fold and publication checks remain incomplete.
  Private Unix module registrations now separate the forthcoming current-policy
  and native lineage factories. Their native build and mandatory formatting
  pass; they add no cold-fork behavior or authority. Read-only review confirms
  both preparation and final publication must qualify retained lineage without
  TreeNode I/O; optimizing preparation alone cannot satisfy ALG-32.
  The modern commit format audit confirms an ALG-36 codec gap: generic recipe
  validation accepts graft and merge values that omit required operation-specific
  fields. Independently assembled complete Commit inputs demonstrate acceptance
  of `{1: "graft", 2: []}` and `{1: "merge", 2: [], 3: {}}`. The registered
  schemas already require two graft inputs and complete arguments, and three
  merge inputs plus policy arguments. This is an implementation correction,
  with no specification or wire change. The shared `algebra-merge` gate now also
  requires two exact commit-level cases for valid registered/other encodings and
  malformed operation-specific argument refusal. They remain pending on a
  separate task branch; prior standalone recipe results do not qualify this path.
  The actual augmented gate fails on the absent first new exact target (zero
  tests); mandatory formatting passes. The requirement remains open.
  D-107 registers additive provenance context version three under ALG-38,
  binding explicit recorded property interpretation to each immutable view's
  original root and complete vocabularies before fold preprocessing. Versions
  one and two retain their existing bytes and do not supply a missing
  historical association. The merge gate now requires an exact pure
  complete-context/recipe-key case; its implementation and independent
  publication remain pending. Runtime evaluator binding remains required.
  A separate `integration.recorded-context-reference-models` auxiliary reserves
  independent complete version-three fields, malformed input refusal and
  enclosing recipe/configuration/preimage witnesses in three exact groups.
  It fails explicitly while the primitive generator, owning templates and
  reviewed normative publication are absent. No runtime association or task
  completion follows from this pure format prerequisite.
  The reviewed codec candidate now passes parent combined qualification: all
  597 core tests with zero skips (run
  `c4309cc9-1fb6-4640-a839-6d28436ff83f`), strict core Clippy/rustdoc, both
  mandatory formatters and the actual selector, merge, no-std and property
  checks. Its full current-trunk aggregate still exits 1 at the legacy-state
  compatibility assertion in `index-generation-manifest`; no task merges or
  checkbox advancement follow. D-107's reviewed independent witnesses now
  publish 113 complete wires (21 contexts, 22 recipes and 70 format negatives),
  preserving all previous golden bytes. The complete golden gate additionally
  requires their owning suite and a 30-section inventory. The published-input
  auxiliary now passes all three exact owning groups and strict Clippy; its
  output matches the entire normative reference byte-for-byte. The parent
  combined complete golden gate also passes all 19 mandatory owning suites.
  Full current-trunk qualification and task merges remain pending; neither
  these format results nor the ordinary claims establish runtime conformance.
  Fresh historical association, prefix-preserving policy evaluation and native
  propagation remain required.
  The selector gate additionally requires three exact core recorded-evaluation
  cases: verified original-view/configuration binding, one retained
  interpretation across every graft prefix, and refusal of absent or
  inconsistent explicit association. The isolated workline must use separately
  supplied caller configuration and existing verified views; decoded context
  claims and current defaults cannot supply the association. These cases and
  native propagation remain pending, with no task or freeze advancement.
  The merge gate additionally requires executable version-three fold replay:
  freshly checked signed inputs must retain their independently supplied
  original view/root interpretations after exclusions change the incoming
  physical root, then rebind the decoded complete recipe. Missing or changed
  original associations and inconsistent replay inputs must refuse. Reviewed
  candidate `7f859c34bf33` passes the exact owning case, all 606 core tests,
  strict Clippy/rustdoc, three actual task gates and both formatters. It uses
  fresh production signature verification and independently modeled complete
  contexts, recipe bytes, preimage and key. Both restoration and removal change
  the incoming root; missing or changed original associations, interpretations,
  legacy contexts and inconsistent replay evidence refuse actual binding.
  Every incoming delta is excluded, so this case qualifies preprocessing and
  binding replay, without newly qualifying conflict-policy winner selection,
  graft traversal or changed-domain preprocessing. Parent combined task checks
  and formatters pass; its aggregate exits 1 at physical-exclusion admission.
  Native historical sourcing and full native propagation remain open.
  A read-only native merge audit finds the checked base view is available in
  both callers but lost at the physical-evidence-only recomputation boundary.
  The next prerequisite retains all three existing checked view/original-root
  inputs, selects one independently supplied interpretation for each before
  domain resolution, and carries the original side selections through both
  evaluators and fold preprocessing. Three exact native helper cases are now
  mandatory in `algebra-merge`: complete input selection, occurrence-specific
  fences with ambiguous-domain refusal, and original-context fold replay.
  Reviewed isolated candidate `b2be541dd49d` now implements this retention.
  Its actual merge gate executes all 34 exact selectors, including the three
  new native helpers; property resolution, selector presets and no-std also
  pass. Build, strict rustdoc and both formatters pass. The final correction
  preserves evaluator error sources, followed by two factual test-helper
  comment fixes with strict rustdoc and formatting rechecked. The original
  full native run records 357 passing, 43 failing and two timed-out cases out
  of 402; strict native Clippy remains red on unowned dead code. Genuine core
  histories qualify the ordinary interpretation helper; they cannot
  manufacture native protected inputs or qualify original-history/admission
  checks. All incoming deltas are excluded in its fold witness, so trusted
  winner selection, graft fold and changed-domain preprocessing remain
  unqualified. Combined candidate `8db47fdf2822` passes both formatters, all five
  assigned task gates and the complete golden inventory. Its default aggregate
  stops at the unsupported physical-exclusion case in `store-idempotent-put`,
  without inventorying all failures, and predates the new adapter retention
  cases. No task or milestone advances.
  — satisfies ALG-15 to ALG-21, ALG-28 to ALG-39;
  `checks.terrane.gates.algebra-merge`, `checks.terrane.gates.algebra-fork`.
- [ ] **T-PROP-1** Property resolution, types, boundary properties,
  completeness, commit-time requirement checks, and strict attribute-name
  validation. Boundary validation compares AUTH-22's implied verbs and
  preserves inherited administrator rights under AUTH-25 before applying
  PROP-16's ancestor-administration exception. The shared trust-property
  validator also rejects unregistered
  `attr-by` names, matching the provenance selector parser. This task provides
  pure resolution and validation. Actual
  commit admission and graft checks are joint with T-REF-2 and T-CRATE-1;
  trust and flatten policy with T-PROV-1 and T-ALG-2; placement, domains,
  retention, and durability with the corresponding store, domain, GC,
  redundancy, and topology tasks; attribute production with T-DRV-1 and
  T-DRV-2. Host realizers enforce hints and wipe policy. Backfill execution
  belongs to T-JOB-1; this task reports gaps without starting jobs.
  D-101 reopens completion for the new owner-local `index-roots` binding.
  Its pure validation is joint with T-DRV-3; actual verified index admission
  remains joint with T-DRV-2. Previous property behavior stays qualified,
  but does not qualify PROP-29. D-102 fixes immutable recorded property
  vocabularies under PROP-30; its pure compatibility check is joint with
  T-DRV-3 before combined requalification. Reviewing the actual resolver
  exposes a remaining PROP-4/PROP-30 gap: compiled later names currently
  receive validation or behavior under historical recorded revisions.
  The shared resolution gate now also requires three exact cases for inert
  later names, revision-specific defaults and graft placement, and refusal
  of unknown revisions or unregistered extensions. Their pure resolver
  implementation is pending on an isolated task branch; codec vocabulary
  checks alone do not qualify this behavior or native caller propagation.
  The actual augmented gate rejects zero selected tests for its first new
  resolver case after all preceding property and carrier cases pass. Shared
  registry completeness and both mandatory formatters pass. This is a
  prerequisite, not resolver qualification or a task merge.
  The reviewed pure resolver candidate now takes an explicit validated
  recorded-revision context. Trusted later names receive canonical-only
  preservation and remain outside effective policy, including spellings
  recognized by compiled newer validators. Independent tests bind the exact
  33/34/35-name behavioral vocabularies, 33/34 namespace defaults, owner-local
  bindings and revision-specific placement while preserving inheritance,
  domain, wipe and depth rules. Parent qualification of the unpublished
  combined source passes all 589 core tests with zero skipped (Nextest run
  `a0f75e14-c11a-48ba-aa24-f064a500d656`), core/native builds, strict core
  Clippy/rustdoc, all three property gates, `core-no-std`, both pure
  index/registry checks and both mandatory formatters. Its actual current
  aggregate exits 1 through the newly mandatory index witness suite's missing
  fixtures. Historical core/native callers still need recorded-context
  propagation; the previous native disclosure failures are not qualified by
  this run. No candidate task merges onto the trunk or advances a checkbox.
  A read-only caller audit identifies missing explicit semantic-context
  inputs in root snapshots, trust/side-attribute domain extraction and native
  source interpretation. Existing tree/history containers do not retain a
  recorded property revision or trusted preservation vocabulary; current
  defaults do not establish that association. The local initialization
  example is a current-semantics test, not a production historical reader.
  Snapshot enumeration also requires every compiled namespace default, which
  would reject valid revision-1 policy after a resolver-only substitution.
  The property gate now requires four exact pure snapshot/authoring cases:
  recorded defaults and inert names, full/parent graft-path consistency,
  untrusted-name/placement refusal and an explicit-context unsigned plan.
  Their implementation must carry the selected interpretation through every
  layer and enumerate only its namespace vocabulary while retaining raw data.
  This prerequisite does not recover an unstated root revision or qualify
  native configuration associations, current checks or complete propagation.
  Implementation and combined qualification remain pending; T-PROP-1 stays
  open and no task or milestone advances.
  Shared registry completeness and both mandatory formatters pass for this
  inventory prerequisite; those checks do not qualify the missing cases.
  The reviewed snapshot candidate now carries that explicit recorded context
  through full enumeration, selected paths, ancestor-prefix resolution and
  unsigned planning. Its first-parent regression uses ordinary immutable
  Commit records through the same private read-only branch as the public
  history wrapper; it checks both change sides, first-parent selection,
  missing-parent refusal and unchanged ownership rules without manufacturing
  verified history. All four changed snapshot error contracts are documented.
  Parent qualification of the unpublished combined source passes all 593 core
  tests with zero skips (Nextest run `fecdd45b-9727-4309-aa8e-8d219e0d36fe`),
  strict core Clippy/rustdoc, both mandatory formatters, property resolution
  including all four exact snapshot cases, and the complete golden gate.
  Its actual current-trunk aggregate exits 1 in `prov-disclosure-boundary`:
  the required native key-window/current-revocation, safe-index current-producer
  and whiteout/public-baseline cases are absent. These pure results do not
  qualify that native boundary or historical view/context associations.
  T-PROP-1, formal task merges and T1 remain open.
  The recorded-context audit also identifies ALG-38's exclusive version-one/two
  rule as an obstacle to complete immutable memo configuration. D-107 resolves
  that specification gap with an explicitly associated version-three tuple.
  The selector gate now requires three exact pure field/legacy-byte, fixed
  revision/vocabulary and selected-evidence relationship cases. Their codecs,
  independent publication and complete caller association remain pending;
  decoded claims cannot establish a trusted registration or current authority.
  A native caller audit finds five legacy trust constructor calls without a
  retained per-view property revision/preservation source. The next ordinary
  data prerequisite is an immutable caller-supplied view/original-root table:
  it must own validated fixed interpretations, distinguish independently
  configured views even when roots coincide, reject conflicting duplicate
  views, and refuse absent views or root mismatches. Three exact association
  cases are now mandatory in `property-resolution`; reviewed candidate
  `28e8a7b6e5b9` passes them and all 605 core tests. Parent combined
  qualification also passes the actual property, selector and no-std gates,
  complete golden gate and both formatters. The full aggregate exits 1 with
  ten failed dependencies. The table itself cannot authenticate its
  caller's justification, recover historical configuration, or grant authority.
  Native installation, snapshot propagation and live-policy separation remain
  subsequent obligations, with no task checkbox or freeze advancement.
  The next immutable-read prerequisite installs the caller's owned table in a
  deliberate legacy or recorded Guard mode, selects against the actually
  checked view/root and retains that selection in its snapshot. Guard path
  resolution and both repository read evaluators must use that one retained
  interpretation. Explicit missing mappings and cross-mode or conflicting
  snapshot configurations must refuse, including snapshots from another Guard.
  Three exact native configuration/fence/checked-evaluator cases are mandatory
  in `property-resolution`. Their implementation remains isolated; ordinary
  configuration tests cannot qualify native historical verification, live ACL
  changes, merge propagation or original-policy admission. Those integrations
  remain separate requirements before T-PROP-1 or T-PROV-1 can complete.
  Reviewed candidate `a557f6080593` now installs and retains that explicit
  configuration. All three exact native cases pass the owning gate; they use
  independently supplied ordinary configuration and a genuinely signed,
  verified empty history for complete evaluator-byte comparisons. Parent
  combined qualification passes property resolution, selector presets, no-std,
  complete golden vectors and both formatters, but the current aggregate exits
  1 in `prov-commit-verify` on three missing or unqualified disclosure cases.
  Native full-suite and strict Clippy results remain failures. The original
  authoring-root resolver still runs current semantics before snapshot
  selection; these helper cases do not qualify protected historical reads or
  original-context propagation. A subsequent read-only audit also finds
  current-semantic original-scope calculations and a held-read adapter that
  drops explicit configuration. These remain separate propagation gaps; the
  task remains open.
  A core audit finds completed scope annotations do not retain interpretation,
  and evaluator construction checks completion without matching that input.
  The next pure prerequisite parameterizes the existing authenticated scope
  calculation, retains a mode-distinct owned interpretation, rejects conflicting
  revalidation/history unions and matches evaluator construction to that scope.
  The existing single enclosing prior/candidate comparison contract remains
  unchanged; prior views are independently verified under their own selections.
  Three exact signed-history cases are now mandatory across property resolution,
  commit signatures and selector presets. Reviewed isolated candidate
  `7494ef6afdd5` passes all 609 core tests, strict Clippy/rustdoc, both formatters
  and all four assigned gates. The tests use actual signed, reverified histories
  and independently modeled complete contexts, recipe wire and memo preimage/key.
  A copied-tree control retains only the main canonical witness and a genuinely
  verified contextless legacy parent, proving the selected modern scope avoids
  an unnecessary walk of its absent graft child. Mode/revision/name conflicts
  refuse repeated verification and both history-union orders before mutation;
  compatible bootstrap evidence remains enrichable. Combined candidate
  `8db47fdf2822` passes both formatters, all five assigned task gates and the
  complete golden inventory. Its default aggregate fails at the unsupported
  physical-exclusion case in `store-idempotent-put`; it does not inventory all
  failures and predates the adapter retention cases below. These pure checks
  cannot replace protected native historical qualification.
  A read-only adapter audit identifies three verifier reconstructions that
  discard the installed read-interpretation mode/table. The next bounded
  prerequisite clones ordinary configuration through one shared private
  construction helper used by those three existing adapters. Legacy remains
  deliberate; explicit current revision and empty refusal-only tables must
  remain explicit. Three exact native helper cases are mandatory in property
  resolution: complete mode retention, per-view fence/refusal checks, and raw
  local/graft semantics under the retained revision. Their implementation is
  reviewed in isolated candidate `f3099e857c60`. Its three actual gates,
  focused tests, build, strict rustdoc and formats pass; the original full
  native suite and strict Clippy remain red. These ordinary tests invoke the
  actual construction seam without
  replacing protected-state copying, original verification, setup clocks or
  held-backend controls. The separate lifecycle adapter and historical sources
  remain unqualified. Combined candidate `8db47fdf2822` predates these cases;
  no task checkbox, milestone exit or freeze follows.
  A subsequent read-only audit finds historical signature root witnessing and
  ordinary Finish still calculate current semantics before immutable-read
  selection. The next coupled prerequisite selects the installed exact
  view/original-root interpretation before calculating ordinary historical
  occurrence witnesses and dispatches the existing authenticated core scope
  verifier under that selection. One candidate enclosing interpretation
  governs candidate/prior comparison; each independently traversed parent or
  source selects its own justified entry. Current authoring and every protected
  original-association, token, signature, epoch and bootstrap check stay
  mandatory. Three exact historical witness/dispatch cases are now required
  in property resolution. Reviewed isolated candidate `042eaf27c63e` passes
  all three focused cases, all-target build, strict rustdoc, both required
  formatters and four actual scoped gates. Complete occurrence controls now
  distinguish two domains at the same physical root and independently model
  each comparison input's canonical private default. The original full native
  run records 362 passing, 43 failing and three timed-out tests out of 408,
  with zero skips; strict native Clippy remains red on untouched code after
  the two owned fixture lints were corrected. The diagnostic verification gate
  still refuses three missing native disclosure cases. Ordinary helper
  evidence cannot qualify protected native historical inputs, certified cuts
  or independent registration sourcing. Combined candidate `9a4a4f733813`
  predates these cases. No task or milestone advances.
  A separate core audit finds certified destination enumeration, retained-record
  enumeration and dependency/final scope verification still use current
  semantics. An additive recorded candidate must retain one immutable
  caller-justified table, select each actual view/signed-root pair throughout
  those calculations and match imported completed modern scopes before
  consumption. Actual certificate bindings, public retention closure,
  independent attribute producers, private cut rules and original authority
  remain mandatory. Three exact pure-core cases are now required by selector
  presets and the disclosure boundary gate, whose 19 native obligations remain
  unchanged. The reviewed isolated candidate `f4c0e2a9c46c` passes all 612 core
  tests with zero skips, strict all-target Clippy and rustdoc, both required
  formatters and the actual selector, signature and no-std gates. Its complete
  context, recipe and memo witnesses include fresh finished-history rebind;
  active raw placement is checked before compatibility projection. The native
  boundary still fails after the three core cases pass. Its property gate
  predates the separate historical helpers and fails on their absent selector.
  These scoped results do not qualify the combined trunk. Recorded certificate
  issuance, protected native propagation and historical registration sourcing stay
  separate unqualified requirements; combined candidate `9a4a4f733813`
  predates these cases as well.
  Combined candidate `09eef8b223e5` now includes both reviewed prerequisites.
  Both mandatory formatters and the actual property, signature, selector,
  merge and no-std gates pass. The default aggregate and its complete
  keep-going inventory both exit 1; the latter identifies 34 failed gate
  dependencies. Default and runtime-independent test profiles expose two
  unconditional Tokio test attributes in the historical family, although Tokio
  is optional. The owning property profile enables Tokio and passes all three
  cases. A focused feature-portability correction is required before joint
  qualification can proceed; scoped success did not cover those profiles.
  Backend compatibility, native disclosure qualification and the other actual
  failed dependencies remain open. No task merges, checkboxes or milestone
  exits follow this failed combined run.
  Reviewed correction `3eb44b68daea` registers the asynchronous historical
  fixture family only when its optional Tokio feature exists, preserving
  synchronous fixtures and all production behavior. Default and no-default
  test-target compilation, the three exact historical cases, strict rustdoc,
  mandatory formatting and the actual property, runtime and bundle gates pass.
  Its feature matrix passes both core profiles and native no-default; native
  Tokio records 382 passing and 23 failing tests out of 405, including all
  three historical cases passing. Later profiles remain unqualified and strict
  native Clippy remains red on untouched diagnostics. Combined candidate
  `1ee291d3a655` now qualifies the optional-runtime correction with seven
  targeted gates passing, but its complete aggregate still fails as recorded
  in the milestone status. Protected historical sourcing and native disclosure
  qualification remain open.
  — satisfies TREE-14,
  PROP-1 to PROP-30;
  `checks.terrane.gates.property-resolution`,
  `checks.terrane.gates.property-required-attrs`,
  `checks.terrane.gates.property-domain-reference`.
- [x] **T-REF-1** Commit and ref record types, merge base, ancestry, ref
  name grammar. Repository enforcement of tag immutability, ref transitions,
  and commit provenance is completed jointly with T-REF-2; merge/fold parent
  order and composite recipes are completed jointly with T-ALG-2.
  D-46's typed, canonical entry-origin receipts are included in this format
  task; construction and authenticated root/path evidence remain joint with
  T-PROV-1 and T-REF-2. D-75's signed original-context codec and pure
  original-scope verification are included; actual affected-root witnesses,
  current ACL checks and native retention remain joint with T-REF-2. —
  satisfies OBJ-21, OBJ-22, REF-1 to REF-11, REF-24 to REF-26;
  `checks.terrane.gates.ref-names`.
- [ ] **T-DRV-1** Derived attribute records and classification (`hash.*`,
  `class.magic`), stored per object. Index trees, derivations, and memos
  belong to T-DRV-2 in this milestone under AD-11. The nine reviewed pure paths
  now implement stream hashes, bounded classification, canonical records and
  producer evidence requiring complete carrying-view and producer contexts.
  They match the task candidate without dependency or vendor changes. All
  375 combined trunk core tests, strict Clippy/rustdoc and mandatory formatting
  pass. All eleven native derived-data paths are now reviewed and integrated,
  including verified manifest-order plaintext reads, exact signed record
  retention, authoritative catalog reopening, and durable quarantine.
  The native fixture binds actual stored plaintext and reopens produced signed
  attributes; recomputation alone leaves producer provenance untrusted.
  The attribute gate requires complete producer-context tests and unavailable
  evidence retention checks. After reviewed SDK integration, the actual
  `derived-attr-record` gate passes all 21 core and 22 native tests, including
  its exact required producer-context and unavailable-evidence selectors.
  Both mandatory formatting commands, the native library build, and strict
  native rustdoc pass. Strict native Clippy remains red on 20 production and
  two test diagnostics for unused integration paths; warnings are not hidden.
  The aggregate fails the backend retirement compatibility assertion in
  `index-generation-manifest`. Object-reachability collection under DRV-3 and
  joint T-JOB-1 backfill under DRV-11 remain incomplete; a passing attribute
  gate does not qualify those operations.
  — satisfies DRV-1 to DRV-10, DRV-28 (DRV-11 withdrawn);
  `checks.terrane.gates.derived-attr-record`.
- [ ] **T-DRV-2** Derivations, the common memo form, index trees with
  same-commit incremental maintenance with source discovery, expanded changes
  and canonical resynchronization accounting, `verify_index`, `rebuild_index`,
  attribute-value lookup and SHA-256 index continuity. AD-11 moves this
  unchanged task ID from B-derive into T1 because native safe index
  materialization and the later mandatory cache/sandbox consumers need it.
  Implement memoization and verification for the recipe kinds available in
  T1; T-ALG-3 and T-RULE-1 extend the same mechanism for their later kinds.
  D-100 replaces the withdrawn DRV-18 filtered-output bound with DRV-24's
  explicit candidate, occurrence and current-check accounting. D-101 now
  registers the acyclic owner/index binding and executable recipe profile;
  their pure codecs belong to T-DRV-3. D-104 now registers the hierarchical
  occurrence/gap carrier; its pure codecs and typed non-graft reachability
  remain pre-freeze prerequisites. An invented
  property or optional derived ref cannot substitute for the owner binding.
  Positive native safe-index materialization,
  independent current attribute-producer checks and genuine divergent-index
  refusal/rebuild remain required. Neither this ordering correction nor
  passing opaque-index codecs completes the task. D-103 withdraws DRV-14's
  hard bound and replaces it explicitly with DRV-29. Source discovery,
  canonical boundary work, changed-graft descent, batched reuse, full
  verification/rebuild and the positive native case remain mandatory;
  no implementation is qualified by this correction. — satisfies DRV-12,
  DRV-15 to DRV-17, DRV-19 to DRV-30, TREE-35, PROP-31
  (DRV-13/14/18 withdrawn);
  `checks.terrane.gates.derivation-memo`,
  `checks.terrane.gates.index-tree-maintenance`.
  D-100/AD-11's actual `registry-complete` derivation and both mandatory
  formatting commands pass. The registry still exposes all 292 stable gates;
  its index row now names DRV-24 explicitly. The index implementation checks
  remain pending and fail when requested. No task checkbox or milestone
  status is advanced by this correction.
  D-103's actual `registry-complete` check and both mandatory formatters pass;
  all 292 gate names remain stable. Requested `index-tree-maintenance` and
  `derivation-memo` checks both exit 1 explicitly as pending, with the former
  naming the new DRV-29 contract. Real canonical-boundary witnesses, independent
  input/data/route counters and measured resynchronization work remain required.
  This records a pre-freeze specification correction, not implementation
  qualification or task completion.
  The shared pure evaluation module and exact
  `checks.terrane.integration.index-evaluation` inventory are registered
  before parallel implementation work. The scaffold compiles under
  `core-no-std`, and both mandatory formatters pass. The requested evaluation
  check exits 1 on zero selected tests, confirming that declarations alone
  cannot qualify construction or relationship verification. This is an
  implementation prerequisite; same-commit incremental maintenance, typed
  runtime loading/current checks and the native safe-index case remain open.
  The reviewed pure evaluation candidate constructs canonical hierarchical
  I/P/G data over an explicitly supplied ordinary namespace graph and checks
  its exact immutable relationships without invoking construction again.
  Independent models cover repeated grafts, present/missing occurrences of
  one object, zero candidates with gaps, long local-hop sequences, divergent
  rows/routes/gaps and internal child summaries. Unsupported conflicts and
  overlay sources refuse explicitly. Parent qualification passes all 585
  core tests with zero skipped (Nextest run
  `9814a24b-18e1-4e20-b1cb-7caebebecdc9`), core/native builds, strict core
  Clippy/rustdoc and the three exact `integration.index-evaluation` cases.
  Public counters describe traversal events, excluding total encoding,
  hashing and canonical rebuilding cost. This qualifies an immutable-data
  foundation only; runtime loading, indexed discovery, current policy and
  independent producer checks, incremental maintenance and native safe-index
  materialization remain required. No task checkbox advances.
  A source audit finds sparse Tree edits still restart canonical rechunking
  once per point, repeating overlapping suffix work; existing counters record
  events without encoded or hashed byte totals and boundary-region attribution.
  The next pure prerequisite batches affected streams at every level, retains
  compatible intervening subtrees and measures actual physical work separately
  from validation. The shared `tree-history-independence` gate now requires
  three exact cases for overlapping edits, distant reuse with atomic validation,
  and independently checked boundary-work accounting. Missing cases fail
  explicitly. This strengthens a canonical editing prerequisite; index source
  discovery, logical deltas, I/P/G updates, same-commit maintenance and native
  qualification remain separate T-DRV-2 obligations.
  Review of the isolated batched editor requires two stronger executable
  proofs: a changed canonical child reference invalidating a real internal
  content cut, and exhaustive attribution of completion/new-level/root-property
  work as well as recovered regions. A separate source review identifies
  quadratic frontier bookkeeping: each disjoint adopted target rescans prior
  spans, even with no sparse edits, and covered targets restart node searches.
  Monotone ordered frontiers with exact identity checks and measured growth
  bounds are required before accepting this prerequisite. Existing baseline
  test success does not qualify these missing proofs or the complexity bound;
  the candidate remains isolated and T-DRV-2 remains open.
  The owning `tree-history-independence` gate now also requires three exact
  selectors for changed internal content-cut divergence, complete completion
  phase attribution, and bounded adoption-frontier work. All six batch
  selectors must execute nonzero tests. This preserves the existing gate and
  requirement IDs and does not qualify the pending implementation.
  Reviewed isolated editor candidate `2d4bb984124f` now closes these proof and
  complexity gaps. All 501 core tests pass with zero skips (Nextest run
  `c72de151-5836-4383-8637-170434049cad`), along with build, strict all-target
  Clippy/rustdoc, both mandatory formatters and its three actual gates. The
  history gate executes all six exact selectors. The final delta adds only
  scoped-helper rustdoc and passes strict docs, both formatters and all three
  gates again. Combined candidate `8fd890b79f34` passes all 622 core tests,
  strict core Clippy/rustdoc, both mandatory formatters and nine actual gates,
  including all six strengthened Tree selectors. Its full current-trunk
  aggregate exits 1 with 11 failed gate dependencies, listed in T1's status.
  No formal task merge or complete index-maintenance claim follows.
  The following pure prerequisite compares old/new immutable source frontiers,
  skips equal subtrees and expands changed, added and removed graft populations
  with distinct local-hop occurrences. It must report independently checked
  logical input/data changes and actual discovery work, keeping preparation and
  validation separate. Three exact source-discovery groups are now required by
  `checks.terrane.integration.index-evaluation`; absent selectors fail explicitly.
  The normative `index-tree-maintenance` and `derivation-memo` gates remain
  pending. Discovery alone cannot qualify I/P/G updates, complete route deltas,
  same-commit maintenance, current lookup or the full T-DRV-2 bound.
  Reviewed isolated source-discovery candidate `deeb44f07844` now passes
  all 625 core tests with zero skips (Nextest run
  `6c24d43e-bf4b-4c10-821f-d25cca554e86`), build, strict all-target
  Clippy/rustdoc, both mandatory formatters and its actual index-evaluation
  and no-std checks. The evaluation check executes all six exact evaluation
  and source-discovery selectors once each. Independent complete models
  preserve distinct local graft hops, actual tagged content references and
  missing-value states. Measured connected regions retain their first cut;
  recovered and tail intervals contain every exclusively owned physical
  event, including repeated reads and closing work. Preparation and newly
  enabled enumeration remain separately reported. Combined candidate
  `bddcd674cd72` has the identical entire Git tree. Its default full
  current-trunk aggregate exits 1 at `commit-order` with an `Expired`
  result. The original keep-going inventory also exits 1, with twelve failed
  dependencies: `bucket-file-layout`, `commit-order`, `dom-dedup-scope`,
  `dom-reference-order`, `feature-matrix`, `index-generation-manifest`,
  `prov-commit-verify`, `prov-disclosure-boundary`, `ref-advance-ordering`,
  `ref-epoch-fencing`, `role-selection` and `store-idempotent-put`.
  All 609 monitored files remain unchanged throughout the combined run.
  No task checkbox or T1 freeze advances.
  The next shared prerequisite reserves the ordinary repeatable maintenance
  module and adds five exact evaluation-check groups for complete I/P/G
  models and logical deltas, successive updates with stable storage and
  bounded maps, batched all-level boundary work, genuine refusals, and
  separate initialization/rebuild/validation/export costs. Missing groups
  fail explicitly. This strengthened check is not qualified by the earlier
  six-group source-discovery result. The already-vendored no-std arena
  dependency is qualified through the actual no-std gate, core build,
  strict all-target Clippy/rustdoc and both mandatory formatters. Local
  staging reuses the complete existing package archives with the exact
  changed lockfile; every locked external package and source stays unchanged.
  Its recomputed vendor hash is updated at all seven workspace hash sites.
  The actual registry check still proves 292 stable unique gates. These
  shared declarations qualify no maintenance algorithm; complete I/P/G
  and native behavior remain required.
- [ ] **T-DRV-3** Pure index format prerequisites: canonical owner-local
  `index-roots` value/binding validation, closed executable index-recipe
  codec, value-plus-object opaque keys and D-104's contextual primary/gap/route
  carriers and structural property placement. Preserve generic retained recipe
  validity and all existing identities. D-101 registers these formats before
  T1's freeze; this task implements ordinary data without giving it current
  authority. Root/occurrence loading, producer verification, incremental
  maintenance, complete coverage and native dispatch remain T-DRV-2.
  Publish independently assembled format witnesses jointly with T-TEST-1.
  The shared golden gate now additionally requires the index owning suite,
  with seven exact codec/relationship groups and independent reproduction.
  Missing fixtures fail explicitly. Its complete fields, positive immutable
  identities/descriptors, retained historical context and scope-specific
  rejection witnesses remain pending; the previous 17-suite result does not
  qualify this new mandatory consumer or publish the missing index corpus.
  The requested `integration.index-reference-models` check exits 1 explicitly
  on its missing owning fixtures. Shared registry completeness and both
  mandatory formatters pass; no format or task is qualified by the scaffold.
  A separate independent finite field-model audit reproduces all four complete
  owner/primary/route/gap relationships and refuses all 32 scoped contextual
  controls. Repeated grafts retain their distinct occurrences, one object
  retains present and missing routes, zero candidates retain gaps, and 17
  local hops retain a 4,355-byte composed occurrence without creating an
  oversized local key. This supplements the primitive byte/identity audit;
  it does not qualify owning codecs, large canonical boundaries, current
  policy, authority or the still-unpublished normative index corpus.
  D-106 publishes the additive index field corpus and corrects TEST-1's
  distinction between malformed format inputs and explicit contextual
  controls. All 176 named wires have complete independent field or raw
  assembly models: 104 positive and 72 negative. The 88 immutable positives
  include 86 Nodes, one complete historical Commit and one actual Chunk;
  seven detached recipe keys remain lookup data without content descriptors.
  Independent parent and read-only review audits reproduce those identities,
  descriptors and expanded entries, verify all control source-owner contexts
  and preserve the entire previous 2,624,962-byte reference prefix exactly.
  The reviewed inventory assigns the new section to the mandatory index
  consumer, bringing the reference to 29 sections and 18 owning suites.
  This publishes witnesses without qualifying their owning execution: the
  checked-in generator and seven exact consumer groups remain pending.
  Current policy, producer checks, runtime lookup, incremental maintenance,
  native behavior and the full T1 aggregate remain unqualified. No task
  checkbox or milestone status advances.
  The publication prerequisite passes the actual registry-completeness
  check, source-built 29-section inventory and both mandatory formatters.
  Removing the index owning dependency makes that inventory refuse. The
  requested index reference check exits 1 explicitly on absent fixtures.
  Its current trunk aggregate exits 1 because `core-fuzz` cannot find the
  `format_properties` target on this trunk source; the implementation remains
  on the unpublished qualification branch. This is the observed aggregate
  failure, not a new native or backend result. Owning index reproduction and
  combined qualification remain pending before formal task merges.
  The shared property gate now requires the exact owning-root binding case;
  its absence must fail rather than qualify the new registry entry from old
  property tests. D-104 additionally requires exact role/placement and semantic
  revision cases; unchanged older codec checks alone cannot qualify those
  extensions. — satisfies the format portions of PROP-29 to PROP-31, TREE-35,
  DRV-12, DRV-25, DRV-26, DRV-30, TEST-1 to TEST-3;
  `checks.terrane.integration.index-format`,
  `checks.terrane.integration.property-registry`,
  `checks.terrane.gates.property-resolution`,
  `checks.terrane.gates.core-no-std`.
  D-101's shared prerequisite exposes the module and exact pure check
  inventory before task branches start. The actual `registry-complete`
  and `core-no-std` checks pass, as do both mandatory formatters. The actual
  augmented property gate and index-format check fail on the absent exact
  owner-binding case (zero selected tests), confirming no old suite can
  qualify the new format. Runtime index gates remain explicitly pending.
  D-102's shared pure compatibility prerequisite preserves revision 1's exact
  33 names and published bytes, registers revision 2's exact `index-roots`
  extension, and keeps later names inert through nested and enclosing
  consumed-record decoding. The current trace records the scalar revision
  matching its exact compiled vocabulary; it grants no new authority.
  The final source snapshot passes all 491 core tests with zero skipped
  (Nextest run `9bde4201-6e20-46e2-82a6-d2d5d741bcce`), strict all-target
  core Clippy and strict rustdoc, core and native builds, the four exact
  `integration.property-registry` cases, `registry-complete`, `core-no-std`,
  and both mandatory formatting commands. The actual current-trunk aggregate
  exits 1 on the absent `format_properties` target in `core-fuzz`.
  This qualifies only the pure revision compatibility prerequisite. Runtime
  historical-revision propagation, combined index qualification and format
  witness publication remain incomplete; no task checkbox advances.
  The reviewed index candidate rebased onto D-102 with all ten owned blobs
  unchanged. Its full core suite passes 494/494 with zero skipped (Nextest
  run `bc7f0b6a-0042-4151-a7b8-2c54c90119ee`), including all eight previously
  failing historical registry cases. Strict core Clippy/rustdoc, core and
  native builds, the three exact index-format and four property-registry
  cases, all 16 property-resolution cases, required attributes, domain
  references, registry completeness, `core-no-std` and both formatters pass.
  Its actual aggregate still fails on absent `format_properties`.
  The unpublished combined qualification then runs all 618 owning core
  tests: 614 pass and four fail, with zero skipped (Nextest run
  `bde15c72-4282-4456-8561-39a0b122d410`). The failures expose two generated
  registry models still labeling the moving vocabulary revision 1, missing
  generated `IndexRoots` property coverage, and a published 33-name namespace
  witness incorrectly compared with all 34 current names. Its build, strict
  Clippy/rustdoc and both formatters pass; all 46 temporary inputs are compared
  and restored exactly after every original terminal. The fixture correction
  is isolated before further combined qualification. The index candidate
  remains unmerged into the trunk, with no task or milestone advancement.
  The isolated fixture correction fixes all four combined regressions while
  preserving the published revision-1 vocabulary and old witness bytes. Its
  final full core suite passes 619/619 with zero skipped (Nextest run
  `db738614-9b40-4038-8c7b-9756c6e80e39`), with core build, strict all-target
  core Clippy, strict rustdoc and both formatters passing; all 46 temporary
  inputs are compared and restored exactly after the original terminal.
  The reviewed unpublished joint source retains exactly those Rust and
  namespace-witness bytes after integrating D-103's specification metadata.
  Independent parent qualification passes `core-fuzz`, `canonical-cbor`,
  `namespace-reference-models`, `golden-vectors`, `property-resolution`,
  `integration.index-format`, `integration.property-registry`, `core-no-std`,
  `registry-complete` and both mandatory formatters. The actual aggregate
  exits 1 on
  `bucket::retirement_tests::legacy_state1_without_inventory_blocks_opaque_index_aliases_even_with_empty_key6`
  in `index-generation-manifest`. Runtime index gates, occurrence-carrier
  registration, normative index witness publication and the remaining native
  disclosure cases remain incomplete. These results qualify the corrected
  pure fixtures only; no task merge, checkbox or milestone status advances.
  D-104 registers the hierarchical carrier before the freeze, separating
  structural metadata from all existing value/function/index-selector inputs.
  Property revisions 1/2 and attribute revision 1 retain their immutable
  meanings; the new active carrier requires exact property revision 3 and
  attribute revision 2, with unchanged physical tree revision 1. Independent
  full-diff review accepts the normative correction. Its actual
  `registry-complete` check passes with all 292 gate names stable, and both
  mandatory formatters pass. `index-tree-maintenance` exits 1 explicitly as
  pending with TREE-35, PROP-31 and DRV-30 named. The augmented pure index
  check rejects zero selected owning-binding tests on the trunk; the property
  registry check passes all four historical cases then rejects zero selected
  new semantic-revision cases. The actual trunk aggregate exits 1 through
  the pending `reconciliation-reference-models` dependency of `golden-vectors`.
  Exact carrier/placement and recorded-revision tests are now mandatory in
  shared inventories, including canonical CBOR and property resolution;
  older suites cannot qualify the new contracts. Pure carrier implementation,
  independently published witnesses and complete T-DRV-2 runtime qualification
  remain pending, with no task checkbox or milestone advancement.
  Parent review combines the carrier and recorded-revision candidates only
  in the unpublished qualification branch. Its complete core suite passes
  577/577 with zero skipped (Nextest run
  `d0c7473c-f166-4be7-aeb9-65085eaa10c7`), as do core build, strict all-target
  Clippy/rustdoc, `core-fuzz`, canonical CBOR, namespace reference models,
  property resolution, both pure index/registry inventories, `core-no-std`,
  registry completeness and both mandatory formatters. The actual golden
  and current-trunk aggregates fail
  `reference_publication_control_negatives_require_structural_rejection`:
  the old `registry-revision` witness rejects attribute revision two, now
  registered by D-104. D-105 preserves that wire as positive ordinary data
  and replaces the negative with unregistered revision three. The shared
  inventory requires the new exact owning-codec group before fixture work
  begins; independent regeneration and actual checks remain pending.
  D-105's shared registry check and both mandatory formatters pass. The
  source-built Python inventory validates all 28 sections and their 17 owning
  consumers. The actual `integration.control-reference-models` check exits 1
  explicitly because the owning fixture files are absent from the trunk.
  No candidate merges into the trunk and no task checkbox advances.
  The reviewed D-105 fixture candidate reproduces all 126 published control
  wires: 89 positive and 37 negative. It preserves 124 old wires unchanged,
  retains the former negative bytes exactly as the new positive, and changes
  only the explicitly withdrawn negative interpretation. All seven exact
  owning-codec groups and strict consumer Clippy pass. Its full core run with
  temporary consumer copies passes 592/592 with zero skipped (Nextest run
  `9374aeeb-c5d2-4982-ae42-cde97267dc2e`); those copies and the complete
  reference are compared and removed after all original consumers terminate.
  Parent qualification of the final unpublished joint source passes its
  normal 585-test core suite, core/native builds, strict core Clippy/rustdoc,
  all eleven focused checks and both mandatory formatters. This includes
  the actual complete `golden-vectors` gate with all 17 mandatory owning
  suites, the corrected control group and the new pure evaluation group.
  The actual current-trunk aggregate exits 1 in `prov-disclosure-boundary`,
  explicitly naming the still-unqualified native key-window/revocation,
  safe-index producer/rebuild and whiteout application cases. That is this
  run's observed failure; the prior backend failure is not a new result.
  The worker's separate `checks.rust.aos-test-targets` selection is unavailable
  because the attribute is absent; no replacement check is declared green.
  Normative index witness publication and complete runtime/index maintenance
  remain pending. No candidate task merge, checkbox or milestone advances.
- [x] **T-AUTH-1** Capability token verification (Ed25519, chain, caveats,
  attenuation) in `no_std`. — satisfies AUTH-7 to AUTH-22;
  `checks.terrane.gates.auth-verify-pure`,
  `checks.terrane.gates.auth-attenuation-monotone`.
- [ ] **T-TEST-1** Golden vectors generated by the reference implementation
  and checked into `spec/reference/golden-vectors.md`; fuzz and property
  tests for every format. The public property candidate exposed sixteen
  malformed version-2 trust-context cases accepted by the previous validator.
  Borrowed schema validation now checks exact evidence tuples, digest widths,
  complete paths, canonical values, sorted unique rows and view/domain/name
  relationships. D-86 clarifies genuine unsigned carrying witnesses and
  complete path semantics without changing fields or encoded bytes. Five new
  source regressions pass, including actual version-1/version-2 encoders from
  completed legacy evidence. The 37-case hermetic selector gate, `core-no-std`
  and mandatory formatting pass. Full core Nextest passes all 474 tests;
  strict core Clippy and rustdoc pass;
  the actual aggregate still rejects the absent `format_properties` target.
  The shared `core-fuzz` gate also requires two exact private signature-omission
  properties and three private disclosure/context/side-evidence encoder
  properties. Their implementation and final public corpus qualification remain
  on the task branch. These results do not complete TEST-3.
  D-80 adds independently reproduced D-77/D-78 byte
  witnesses and distinguishes decoder rejection from authority claims.
  Remaining format publication and joint native qualification are incomplete.
  D-84 now publishes 39 independently encoded D-79 witnesses for original
  controls, local/remote imports, trust rows, seeded configuration, policy,
  backend registration, retained heads, selected publication state and
  pointers, raw import/trust/pin digests, and structural lineage/proof claims.
  Two explicit missing-inventory checkpoint/genesis witnesses require decoder
  rejection; their independent wire inputs bypass the rejecting encoders.
  The reference generator `tests/terrane/publication_vectors.py` uses only
  canonical CBOR primitives and the source-built `terrane-core` example
  `reference_blake3` for raw digest bytes. The hermetic
  `checks.terrane.integration.publication-format-vectors` check reproduces
  their complete reference section and runs ten exact tests that encode
  separately constructed models, decode positive published bytes and reject
  the negative inputs. It passes, as do all 449 core tests, strict core Clippy
  and rustdoc. Every prior golden byte remains unchanged. Remaining
  collection/retirement formats and complete corpus/fuzz qualification
  remain required before T1's encoding freeze; `golden-vectors` stays pending.
  The `core-fuzz` harness now requires the pure `format_properties` integration
  target and refuses empty or ignored execution. Its implementation and
  format-by-format coverage review remain pending; registering that harness
  does not qualify TEST-3.
  A separate `checks.terrane.integration.pack-format-vectors` harness requires
  independent reproduction and four exact cases for a two-entry pack, its
  detached index and explicit CRC/reserved-field rejection witnesses. D-85
  publishes those four witnesses with full fields and registered positive
  container identities. The independent primitive little-endian/CRC32C
  generator and all four exact public-model tests pass the actual hermetic
  harness. All 453 core tests, strict all-target core Clippy and rustdoc pass;
  the existing 39 publication witnesses and ten exact cases still pass.
  The publication generator now bounds its own section at the next level-two
  heading, preserving later reference sections when checking or replacing it.
  Every previous golden byte remains unchanged. This qualifies the added
  witnesses, while the remaining complete corpus and fuzz review stay pending.
  Mandatory repository formatting passes. The actual trunk aggregate remains
  red: `core-fuzz` refuses the absent `format_properties` target, which remains
  on its task branch. The historical-bootstrap candidate's aggregate also
  fails `index-generation-manifest`'s legacy-state compatibility assertion.
  Neither failure proves the remaining native disclosure gates green; no
  task or milestone advances.
  An independent collection-record generator now constructs 20 wire models
  from CDDL fields and the registered GC-7 hint rule: lease, roots, mark,
  checkpoint state, tombstone and generation manifest, including five negative
  inputs. Source-built Python passes explicit CBOR/hint oracles and temporary
  reference insertion, preservation, overwrite-refusal and tamper-rejection
  checks. The hermetic `collection-reference-generator` check runs those
  primitive oracles and emits all models using only the AOS Python package.
  Its output is preparation for the remaining reference corpus;
  D-87 now publishes all 20 additive witnesses, preserving every prior byte.
  Six separately constructed Rust model groups compare positive bytes/fields
  and reject the five negative inputs. All six exact groups pass the actual
  hermetic `collection-format-vectors` check, including independent reference
  reproduction. The preceding 474-test core checkpoint and strict Clippy and
  rustdoc pass. The updated full core Nextest run passes all 480 tests with
  no skips; its strict all-target Clippy and rustdoc stages also pass.
  The actual current aggregate still rejects the absent `format_properties`
  target. The complete corpus stays unqualified; no task or milestone advances.
  A further reference review found the unpublished internal-node model and
  complete eleven-domain descriptor coverage required by TEST-2. The independent
  `foundation-reference-generator` check initially emitted eleven descriptors
  and three node models. Further review replaced its preliminary tiny-child
  layout with an independently computed real profile cut and a final tail.
  D-88 publishes the resulting eleven descriptors with complete payloads and
  four node models, reproducing five preserved identities. All previous golden
  bytes remain unchanged. The actual `foundation-format-vectors` hermetic check
  reproduces the complete reference section and passes three exact public-model
  groups: every descriptor, node fields/identities, and the canonical builder's
  root with exact child counts/weights. Strict Clippy for the added test passes,
  as do preservation, section-bound, tamper and duplicate-heading audits and
  mandatory repository formatting. Full core build and Nextest pass on these
  final published inputs: 483 tests, zero skips, run
  `21e3a61d-38c1-4474-ac8e-f63ab17f2191`. Strict all-target core Clippy and
  warnings/missing-docs rustdoc also pass. The actual trunk aggregate still
  rejects the absent `format_properties` target; complete golden/fuzz and native
  qualification remain incomplete. Deferred filter and memo payloads are CDDL
  descriptor inputs; no branch workline starts.
  The independent `retirement-reference-generator` check now emits 34 inert
  wire models for the eleven existing D-82 record schemas: 27 positive field
  models and seven structural rejection inputs. Its actual hermetic run passes
  fixed CBOR oracles, embedded-record digest/revision relationships and bounded
  section reproduction. A separate read-only audit parses every emitted EDN
  model, compares all wire bytes, and verifies preservation, tamper refusal and
  duplicate/missing-heading refusal. Long text and byte literals use EDN
  concatenation so wrapping preserves their values. Normative publication and
  separately constructed Rust codec comparisons remain required; these inert
  fields establish no current authority, completed wait or physical permission.
  The format-property candidate's actual hermetic `core-fuzz` run passes all
  46 public cases and four of its five required private cases. The final private
  side-evidence case fails; inspection identifies an invalid positive fixture
  with an empty shebang argument, which the existing codec correctly rejects.
  Its original focused qualification now confirms four private cases pass and
  that same fixture fails with `InvalidValue`. The task stays unmerged;
  the minimal fixture correction now passes all 46 public cases and five exact
  private selectors in the actual hermetic `core-fuzz` check, preserving an
  explicit empty-argument rejection assertion. The final candidate is now
  rebased onto the D-88 and principal-comparison prerequisites. Its full core
  build, 534-test Nextest run (zero skips,
  `4a750303-88de-4862-9afb-9ecf5f32fb6b`), strict all-target Clippy, strict
  rustdoc and mandatory formatting pass. The actual hermetic `core-fuzz` check
  passes all 46 public cases and five exact private selectors. Its exact
  aggregate still fails: the first required `root_context::bootstrap_fork`
  selector executes zero tests because the original-bootstrap task remains
  separate. No gate selector is weakened; the candidate stays unmerged, and
  complete golden/fuzz and native qualification remain required.
  The independently reviewed original-bootstrap candidate passes all 491 core
  tests with zero skips, strict Clippy/rustdoc and all 20 exact signature-gate
  cases, including its eight copied-root checks. An isolated joint checkout
  combines that candidate with the property candidate. Its actual aggregate
  advances past both core prerequisites and fails `prov-disclosure-boundary`:
  the nineteen required native selectors remain absent from trunk. The native
  task's additional paired/recovery regressions do not substitute for those
  exact contracts. Neither task is merged or advanced.
  A separate `algebra-reference-models` hermetic check prepares seventeen
  independently encoded recipe witnesses: twelve positive models and five
  structural rejections. Four exact public-model groups compare graft/overlay/
  merge bytes, recipe hashes, decoded fields, replacement and ordered policies;
  strict Clippy passes. The inert trust profile supplies no executable authority.
  D-89 now publishes those seventeen additive witnesses, preserving every prior
  byte and identity. The final `algebra-format-vectors` hermetic check reproduces
  the complete section and passes all four exact groups and strict Clippy.
  The original preparation check remains an alias to this stronger published
  check. Full core build, all 487 Nextest tests with zero skips (run
  `194809af-dba4-4274-9768-141cb4fb5883`), strict all-target Clippy and strict
  warnings/missing-docs rustdoc pass on these published wire inputs. Mandatory
  formatting passes. A legacy owning-codec coverage audit
  identifies existing published inputs without complete independent model
  consumers; `legacy-format-vectors` now requires twelve exact public groups
  and one private unverified token-field group. The actual task-branch check
  now passes all thirteen groups and strict all-target Clippy; every D-80 input
  has an independently constructed full model or primitive negative oracle.
  After rebasing onto D-89, its full core suite passes all 551 tests with zero
  skips (run `82022eba-9aa3-4e6f-bcc2-f291228ada36`), build/strict Clippy/rustdoc/
  formatting and `core-fuzz` also pass. Its actual aggregate still refuses the
  missing bootstrap-fork selector. Full review of the eight-file legacy
  addition finds complete positive model comparisons and independent negative
  wires. The updated isolated joint candidate includes both the property and
  bootstrap branches; its actual `prov-commit-signature` passes all twenty
  required exact cases. The combined core build and all 559 Nextest tests pass
  with zero skips (run `20edeff7-dc54-4971-a85c-33caf27556e7`), together with
  strict all-target Clippy and warnings/missing-docs rustdoc. The actual joint
  aggregate fails `prov-commit-verify`, which requires the nineteen native
  disclosure selectors still absent from trunk. Complete native qualification
  remains required. A new `namespace-reference-models` auxiliary harness reserves
  three exact owning-codec groups for independent entry metadata and root
  properties;
  it fails explicitly until the independent generator and model inputs exist.
  The separate `attribute-reference-models` auxiliary likewise reserves three
  exact groups for complete registered value models, record fields and opaque
  signature/preimage formats, and independently reconstructed negative wires.
  Its actual hermetic request fails explicitly while the independent inputs
  are absent; mandatory formatting passes. These reserved checks establish no
  format or runtime conformance.
  The isolated namespace candidate now passes all three exact format groups
  for 69 models (22 entries, six root-property roots, three namespace roots
  and 38 negative wires), strict template Clippy and all 490 core tests with
  zero skips (run `8f025970-31b4-4cbc-8b6b-7b48c109cb69`). Its strict all-target
  Clippy, warnings/missing-docs rustdoc and mandatory formatting pass.
  The assumed future property remains a local extension-preservation test,
  excluded from the reference under CONV-3; all 33 registered properties are
  represented. The attribute candidate likewise passes its actual three-group
  auxiliary check for 19 values, 42 complete records and 49 negative wires,
  strict template Clippy, all 490 core tests, strict all-target Clippy,
  warnings/missing-docs rustdoc and mandatory formatting. Both isolated actual
  aggregates still reject the absent `format_properties` target.
  D-90 publishes these 179 additive field witnesses while preserving every
  preceding reference byte. The two auxiliary harnesses now require independent
  reproduction of the normative corpus and run owning-codec tests against
  that corpus. Their reviewed input branches remain separate; qualification
  against this stronger published check is pending. No full golden or native
  conformance is claimed.
  Qualification against D-90's published whole file now passes both actual
  auxiliary checks and all six exact model groups with strict template Clippy.
  The attribute candidate's published-input build, all 490 core tests, strict
  all-target Clippy, warnings/missing-docs rustdoc and mandatory formatting pass.
  Its actual aggregate still rejects the absent `format_properties` target.
  The namespace candidate's published-input build, all 490 core tests with
  zero skips (run `9c15a5fe-e069-4084-8787-07c9882530ce`), strict all-target
  Clippy, warnings/missing-docs rustdoc and mandatory formatting also pass.
  Its actual aggregate likewise refuses the absent property target. The joint
  candidate's minimal concrete `Sync`-bound correction passes the actual
  `chunk-bomb-cap` check, a genuine non-Send fixture and std/wasm compilation.
  After including that correction, the actual joint aggregate compiles native
  default mode and fails the legacy state-without-inventory compatibility
  assertion in `index-generation-manifest`. Neither that partial aggregate
  execution nor the additional native cases proves the nineteen disclosure
  contracts complete; no task or milestone advances.
  A subsequent source audit identifies missing complete chunk-envelope and
  merged-index-shard reference sections. The reserved
  `container-reference-models` check requires independent primitive assembly
  and three exact owning-codec groups; it fails explicitly until its input
  files exist. Frame decompression and native publication remain separate
  requirements; registration does not qualify them.
  Both published-format auxiliary checks now also pass on the isolated combined
  property/bootstrap/native candidate, including all six exact model groups and
  strict template Clippy. The combined full core build, all 565 Nextest tests
  across nine binaries with zero skips (run
  `c3c4c9eb-d11b-442f-b010-0715ad346caa`), strict all-target Clippy and
  warnings/missing-docs rustdoc pass. Temporary consumers were retained until
  every original stage terminated. This establishes the combined core format
  checkpoint, while the native aggregate and full golden corpus remain red.
  A read-only owning-codec audit confirms TEST-2's enumerated minimum examples
  have published complete consumers. Additional implemented format families
  still need published witnesses or consumers: modern commit/ref projections,
  selector AST and private evidence projections, permanent-retirement records
  and further publication/control alternatives. `LocalGcReconciliation` has a
  registered schema but no located owning codec; it remains an implementation
  gap rather than an assumed branch deferral. Complete golden conformance is
  still unproven, and the registered `golden-vectors` check remains pending.
  The task stays unmerged, and complete golden coverage remains open.
  D-91 publishes 85 additive envelope/shard witnesses: eight envelopes, 38
  shards and 39 independently constructed negative wires. Ordinary envelopes
  use the registered profile maximum; two overhead controls explicitly use a
  local structural oracle. All preceding reference bytes and every prepared
  wire byte/digest remain unchanged. The prepared three-group hermetic check,
  strict template Clippy and mandatory formatting pass. The shared auxiliary
  harness now requires independent reproduction of the normative whole file;
  its reviewed input branch remains separate. Its actual published-input check
  now passes all three exact owning-codec groups and strict template Clippy.
  The actual input-branch aggregate still rejects the absent `format_properties`
  target. This establishes no native codec, index or complete golden conformance;
  no task or milestone advances.
  The isolated joint candidate now includes these published container inputs.
  Its full core build, all 568 Nextest tests across ten binaries with zero skips
  (run `b792ffd6-0906-46e3-b246-ad4c21b10edf`), strict all-target Clippy,
  warnings/missing-docs rustdoc and final mandatory formatting pass. Temporary
  consumers remain present through qualification and final formatting, then are
  removed. Complete golden coverage and native milestone qualification remain
  open; this combined core checkpoint advances no task or milestone.
  A separate `retirement-reference-models` auxiliary harness now reserves seven
  exact owning-codec groups for the existing 34 inert record models: complete
  authorization, preparation, operation, pass, fence and owner fields plus
  independently assembled structural rejections. Its input templates remain
  pending; the check fails explicitly until they exist. Format comparison
  establishes no current authority, completed wait or physical permission;
  normative publication and complete golden qualification remain required.
  D-92 now publishes all 34 inert retirement record witnesses. Full consumer
  review covers independent wire assembly, complete public and nested models,
  structural rejection, truncation, nonminimal headers and eleven decoder size
  limits. The input candidate passes its seven exact auxiliary groups, all 494
  core Nextest tests with zero skips, strict Clippy, warnings/missing-docs rustdoc
  and mandatory formatting. The shared harness now checks the normative whole
  reference and copies that published file into the consumer. Published-input
  qualification remains pending. Its actual candidate aggregate still rejects
  the absent `format_properties` target; no task or milestone advances.
  The rebased reviewed retirement consumer now passes the actual published-input
  auxiliary, including all seven exact groups and strict Clippy. Its copied
  output reference matches the entire normative golden file byte-for-byte.
  The isolated combined core candidate passes its full build, all 575 Nextest
  tests across eleven binaries with zero skips (run
  `fbd1e124-b65a-4894-abdf-96555cc671fa`), strict all-target Clippy,
  warnings/missing-docs rustdoc and both mandatory formatters. All ten temporary
  inputs remained frozen through every original consumer and were removed only
  after terminal qualification. Native aggregate and complete corpus coverage
  remain unqualified; no formal task merge or status advance follows.
  The separate `refs-reference-models` auxiliary reserves four exact groups
  for complete modern commit optional fields/preimages, ref policy and snapshot
  envelope fields/preimages, reflog reason/CAS/predecessor alternatives and
  independently malformed wire inputs. It fails explicitly while its primitive
  generator and model templates are absent. These untrusted format inputs
  establish no signed authority, live ref state or successful publication;
  complete reference publication remains open.
  A separate `evidence-reference-models` auxiliary reserves five exact pure
  groups for complete selector AST models, trust-context versions and presence,
  selected side-evidence tuples, disclosure statement fields/preimages and
  normalized whole-target binding fields/digests. It appends test-only consumers
  to the existing pure encoding seams in its sandbox, without exposing a new
  production interface. It fails explicitly while those input templates,
  generator or pure prerequisites are absent. This registration establishes
  no verification, trust evaluation or native disclosure authority.
  Complete review of the isolated modern-ref inputs covers 147 independent
  models: 33 commits, eight ref records, ten reflogs and 96 malformed wires.
  A corrected graft witness contains the actual canonical Tree target; its
  complete decoded recipe is compared independently. All four auxiliary groups,
  491 core Nextest tests, strict Clippy/rustdoc and mandatory formatting pass.
  Normative publication remains pending the REF-9 reference-text correction.
  Complete review of the isolated private-evidence inputs covers 86 witnesses,
  including 32 negatives: selector arenas, both context versions, nine-field
  side evidence, statement preimages and whole-target normalization. Its five
  exact auxiliary groups, 564 core Nextest tests, strict Clippy/rustdoc and
  mandatory formatting pass. Publication remains pending exact-byte reference
  comparison and its missing, duplicate, split and whitespace controls.
  Encoder-only projections are compared field by field without claiming an
  owning typed decoder. Neither input candidate qualifies the full aggregate.
  D-93 now publishes all 86 reviewed selector/private-evidence witnesses with
  every prior golden byte preserved. The corrected comparator passes its real
  CLI refusal controls and the five-group auxiliary; all emitted models remain
  byte-identical. The shared auxiliary now verifies the normative whole file
  and supplies that published input to every consumer. Qualification against
  that published source remains pending; complete corpus and native gates stay
  open, with no task tick or formal merge.
  The D-93 consumer now passes the actual published-input auxiliary: five exact
  groups, strict template Clippy and mandatory formats. Its entire output
  reference matches the normative golden file; all seven reviewed input blobs
  remain unchanged across the merge-preserving rebase.
  D-94 publishes all 147 complete modern Commit/ref witnesses. Independent
  reproduction preserves every preceding golden byte and all witness wires.
  The REF-9 citation correction passes source-built comparison, four auxiliary
  groups and mandatory formats. The shared harness now checks and consumes
  the normative whole reference. Published-input qualification remains pending.
  The reviewed owning Commit recipe candidate separately passes all 489 core
  tests with zero skips, strict Clippy/rustdoc, actual `algebra-merge` including
  both new schema groups, `ref-names` and mandatory formatting. Full qualification
  follows the shared generic-map normalization-fixture correction; its initial
  invalid-overlay fixture failure remains recorded. The actual isolated aggregate
  still fails the missing `format_properties` target; the candidate stays unmerged.
  A separate `control-reference-models` auxiliary now reserves six exact groups
  for backend binding alternatives, original-control versions, complete nested
  Guard snapshots, portable inventory/genesis fields, publication proof variants
  and independently assembled structural negatives. It fails explicitly until
  its generator and public-model consumers exist. These are ordinary format
  records; no signing, checked authority, backend, native reconciliation or
  collection effects are qualified by this registration.
  The registered local-v1 reconciliation format remains a separate owning-codec
  gap. A dedicated pure module location and `reconciliation-reference-models`
  auxiliary reserve complete-field, independent malformed-wire and decoder-limit
  groups. The check fails explicitly while its codec/model inputs are pending.
  This scope contains ordinary record fields only; current-fence verification,
  physical reconciliation and native effects remain unqualified.
  The D-94 consumer now passes all four exact published-input auxiliary groups,
  strict Clippy and mandatory formatting. Its copied output matches the whole
  normative reference. The combined candidate passes its full core build,
  all 586 Nextest tests with zero skips (run
  `2997fd36-5888-43ba-8967-29f62ca3d258`), strict all-target Clippy,
  warnings/missing-docs rustdoc and both mandatory formatters. All 23 temporary
  inputs remained frozen through every original consumer and were compared
  before their removal or exact source restoration. Native aggregate and
  complete golden coverage remain open; no task or milestone advances.
  Full review of the local-v1 reconciliation candidate covers its exact
  registered five-field codec, borrowed validation before fence-key retention,
  12 complete models, 68 structural negatives and 11 decoder-bound/late-finish
  probes. Its isolated build, all 490 core Nextest tests, strict Clippy/rustdoc,
  three exact auxiliary groups and mandatory formatting pass. The isolated
  aggregate still fails on the missing `format_properties` target. D-95 now
  publishes all 91 reviewed wires while preserving every prior golden byte.
  The shared harness checks and consumes the normative whole reference;
  published-input qualification remains pending. The codec stays on its task
  branch, and no current authority or native physical operation is qualified.
  Full review of the publication/control alternative candidate covers all nine
  input files and 125 witnesses: 88 complete positive records and 37 independent
  malformed wires. Its build, all 493 core Nextest tests with zero skips,
  strict Clippy/rustdoc, six exact auxiliary groups and mandatory formatting pass.
  Every positive also rejects all truncated prefixes, trailing bytes and
  nonminimal container heads. Local original registration remains version 1;
  physical/import unions exercise the actual registered version-2 alternatives.
  Opaque CAPABILITIES bytes establish presence only, without payload validation.
  D-96 publishes the reviewed alternatives and raw embedded relationships while
  preserving all previous golden bytes. The shared harness now checks and
  supplies the entire normative reference; published-input qualification remains
  pending. The isolated aggregate still fails on missing `format_properties`;
  no native authority, task merge or milestone completion is claimed.
  The rebased D-95 codec consumer now passes the actual published-input
  auxiliary: all three exact groups, strict consumer Clippy and both mandatory
  formatters. Its full copied reference equals the normative D-95 revision;
  all three reviewed source blobs remain unchanged across the rebase.
  The clean combined candidate's actual trunk aggregate now terminates on
  `prov-disclosure-boundary`: twelve of the nineteen required native targets
  remain absent or unqualified. The failing aggregate is retained separately
  from the passing 586-test core qualification. No task branch merges or
  milestone exit follows either narrower result.
  The D-96 consumer now passes all six exact published-input auxiliary groups,
  strict consumer Clippy and both mandatory formatters. Its full reference
  output matches the normative whole file; all nine reviewed input blobs remain
  unchanged across the rebase. A separate `lineage-reference-models` auxiliary
  reserves complete ordinary control-pin alternatives, consumed root layers
  and repeated occurrences, view domains/order, complete used-input summaries,
  whole source records and independently malformed wire inputs. It fails
  explicitly while those input templates are absent. These pure formats grant
  no checked lineage, trusted policy, current authority or native permission.
  The combined candidate now includes both reviewed D-95/D-96 owning consumers.
  Its full core build, all 595 Nextest tests with zero skips (run
  `f54485a1-e9f7-48f0-982c-88d8b1e8bdbc`), strict all-target Clippy,
  warnings/missing-docs rustdoc and both mandatory formatters pass. All 34
  temporary inputs were byte-compared after every original stage terminated,
  then removed or restored exactly. Complete golden and native qualification
  remain open; this core result advances no task or milestone.
  Both D-95/D-96 auxiliaries also pass on that clean combined candidate:
  three and six exact owning-codec groups plus strict consumer Clippy. Each
  output reference matches all 994,692 bytes of the normative golden file.
  These combined format results do not qualify the still-incomplete aggregate.
  A published-input closure audit also identifies the original chunk/gear/CDC
  and node-boundary rows, standalone inline entry, and two unsigned token
  preimages as needing explicit normative consumers. A separate
  `prefix-reference-models` auxiliary reserves six exact groups for these
  witnesses and fails explicitly while their templates are absent. Its private
  test imports expose pure encoders and profile parameters only; token keys
  and signatures remain ordinary opaque fields, without signing, verification
  or authority construction. Nonempty outer recipe context and the actual
  `golden-vectors` dependency/coverage inventory also remain open.
  Full review of the six consumed-lineage inputs covers 36 complete positive
  models and 155 independently assembled negative wires. Its isolated build,
  all 493 core Nextest tests with zero skips (run
  `9ed8f506-949a-4cd5-88c3-575668b2932c`), strict Clippy/rustdoc, six exact
  auxiliary groups and mandatory formatting pass. ROOT independently reproduced
  all 191 unique wires and the four embedded Commit digest claims. D-97 publishes
  those reviewed bytes while preserving every previous reference byte; the
  shared harness now requires the normative whole file. Published-input and
  combined qualification remain pending. The isolated aggregate still fails
  on missing `format_properties`; no authority, task or milestone is qualified.
  A separate `recipe-context-reference-models` auxiliary reserves nonempty
  outer domain pairs, complete trust selector/version/configuration/accepted-ID
  and timestamp fields, represented path/fold configuration, and independently
  malformed inputs in four exact groups. It fails while templates are absent.
  All proposed models retain `authenticated = false`, empty executable
  evaluators and no runtime fold filter; this pure format prerequisite creates
  no verified resolution, trust evaluator or native policy permission.
  The D-97 consumer now passes all six exact published-input auxiliary groups,
  strict consumer Clippy and both mandatory formatters with unchanged reviewed
  input blobs. Its complete output matches all 2,571,254 normative bytes.
  The same auxiliary also passes on the combined candidate, with both formats
  passing there. The combined candidate's full core build, all 601 Nextest
  tests with zero skips (run `41bb292d-d0e8-4d97-a572-d62c9ab6fcee`), strict
  all-target Clippy, warnings/missing-docs rustdoc and both mandatory formatters
  now pass. All forty temporary inputs and their owning source/template bytes
  remained frozen through every original terminal; exact comparison preceded
  removal or restoration. No full native or milestone conformance follows.
  `golden-vectors` now requires seventeen owning codec suites and a reviewed
  section-to-consumer inventory, including original-prefix and outer-recipe
  coverage. Missing current-milestone templates fail their owning checks.
  Inventory checks reject missing/duplicate/unassigned sections, changed witness
  counts and missing consumer dependencies; owning suites prove byte/model
  equality. The complete gate remains unqualified while inputs are incomplete.
  Its actual ROOT build now fails on the absent attribute-model template through
  a mandatory owning dependency. That concrete failure replaces the old generic
  pending gate; it does not qualify either the complete corpus or the aggregate.
  The stable gate registry passes after that wiring change. The actual ROOT
  aggregate still fails on the absent `format_properties` integration target.
  On the clean combined candidate, the complete aggregate instead reaches the
  mandatory original-prefix consumer and fails because its templates are not
  yet included. Both original aggregate outcomes are retained; neither the
  first failure nor the passing 601-test core suite qualifies remaining gates.
  Full review of the five outer-recipe consumer inputs covers 13 complete
  positive recipes and 62 independently assembled structural negatives. Its
  isolated build, all 491 Nextest tests with zero skips (run
  `9c556593-25fa-4a84-859d-549bce25b2c0`), strict Clippy/rustdoc, four exact
  auxiliary groups and both mandatory formatters pass. ROOT independently
  reproduces all 75 unique wires and 13 memo identities. D-98 publishes those
  reviewed bytes while preserving every prior reference byte; the shared
  harness now requires the normative whole file and the reviewed inventory
  assigns the new section to its mandatory owning suite. Complete decoded
  models remain unauthenticated, without evaluators or a runtime fold filter.
  Generic canonical configuration retention does not claim registered profile
  execution, verified context binding or fold re-evaluation. Published-input
  and combined qualification remain pending; no task or milestone advances.
  The rebased original-prefix and D-98 consumers now pass their actual
  published-input auxiliaries: six and four exact groups, strict consumer
  Clippy and both mandatory formatters, with all reviewed input blobs unchanged.
  D-98's output matches all 2,623,525 normative bytes. Both inputs are reviewed
  and included on the unpublished combined candidate. Its actual complete
  `golden-vectors` check passes seventeen mandatory suites and all 28 assigned
  sections. Independent closure review nevertheless finds five published
  legacy identity/hash literals observed only as matching fixed constants:
  manifest, commit and attribute identities, the unsigned Commit preimage hash
  and the raw delete-authorization hash. A bounded literal reader and mutation
  controls remain required before that passing gate establishes TEST-1 closure.
  No production or normative byte change is needed for this observation fix.
  The combined candidate's full core build, all 611 Nextest tests with zero
  skips (run `6d54d2e1-c666-432b-af0f-356b96bdb773`), strict all-target Clippy,
  warnings/missing-docs rustdoc and both mandatory formatters pass. All 46
  temporary inputs and owning source/template bytes remained frozen through
  every original terminal; exact comparison preceded removal or restoration.
  Its actual full aggregate still fails the legacy state-1 compatibility case
  in `index-generation-manifest`. That failure and the literal-observation gap
  remain explicit; no formal task merge, checkbox or milestone advances.
  The reviewed legacy correction now reads all five actual published literals
  through bounded, unique-section readers and compares each with its owning
  raw or domain-prefixed digest computation. Thirty-five malformed, missing,
  duplicate or changed-literal controls refuse the input; five surrounding
  section controls remain accepted. Existing model bytes, identities and
  normative reference bytes are unchanged. The exact legacy auxiliary and
  its strict consumer Clippy pass. On the updated combined candidate, the
  actual complete `golden-vectors` gate again passes seventeen mandatory
  owning suites and all 28 reviewed sections, closing those five observation
  gaps. All 611 core Nextest tests pass with zero skips (run
  `fb739c3a-d26a-40f9-a679-9d55beb3b2f3`), alongside the all-target build,
  strict all-target Clippy, warnings/missing-docs rustdoc and both mandatory
  formatters. All 46 temporary inputs and owning bytes remain frozen through
  every original terminal and are compared before exact restoration/removal.
  The actual full aggregate still fails the legacy state-1 compatibility
  assertion in `index-generation-manifest`; T1 and formal task merges remain
  open despite this stronger golden evidence.
  The D-106 index inputs now pass full source review and their actual combined
  published-input check: seven exact Rust groups compare independently
  assembled complete models, 176 wires and the finite occurrence/carrier
  relationships. Positive owner bindings use independently initialized fields
  through the existing value construction interface before testing their
  wrapper encoder; decoded wrapper output does not define the expected model.
  The recipe section checker accepts exactly one separator LF before a later
  level-two heading and still refuses extra framing or changed witness bytes.
  On the unpublished joint candidate, the actual complete `golden-vectors`
  gate passes all 18 mandatory owning suites and all 29 reviewed sections.
  The index output matches all 3,141,999 published bytes, and both mandatory
  formatters pass. This closes the immediate corpus-input failure; complete
  current-trunk and native qualification remain required before task merges,
  checkbox advancement or T1's encoding freeze.
  — satisfies TEST-1 to TEST-4, CRATE-3;
  `checks.terrane.gates.golden-vectors`, `checks.terrane.gates.core-fuzz`.
- [x] **T-STORE-1** The `ContentStore`, `RefStore`, and `Store` traits,
  capability types, error taxonomy, `HttpClient`, `Clock`, and `LocalFs`
  traits, and compatible runtime features. Concrete operation semantics are
  T-BKT-1; routed authority forwarding is T-STORE-2. — satisfies STORE-30,
  STORE-32, CRATE-6 to CRATE-8, CRATE-29;
  `checks.terrane.gates.feature-matrix`,
  `checks.terrane.gates.store-error-taxonomy`,
  `checks.terrane.gates.store-trait-split`,
  `checks.terrane.gates.runtime-agnostic`.
- [x] **T-PACK-1** Pack writer and reader, per-pack index objects, trailer
  recovery, meta packs, tree-order emission. Durable backend publication and
  ref-advance ordering are completed jointly with T-BKT-1 and T-REF-2.
  — satisfies PACK-1 to PACK-16;
  `checks.terrane.gates.pack-header`,
  `checks.terrane.gates.pack-self-describing`,
  `checks.terrane.gates.pack-single-writer`.
- [x] **T-PACK-2** Merged index shards by generation, tombstones, rebuild
  from per-pack indexes, and bundles. D-71 distinguishes GC-retired placements
  from sticky identity quarantine; newer fallback and rebuild preserve
  quarantine, while a fresh verified placement may supersede GC retirement.
  Narrowed to trunk scope: filters are
  T-PACK-3 on B-bandwidth. Authoritative generation-manifest publication
  is completed jointly with T-BKT-1. — satisfies PACK-17 to PACK-20, PACK-24 to
  PACK-28; `checks.terrane.gates.index-shard-generations`,
  `checks.terrane.gates.index-rebuild`,
  `checks.terrane.gates.bundle-verify`.
- [x] **T-BKT-1** `bucket` backend over `file://`: key layout, mutability
  classes, atomic writes, filesystem CAS, generation manifests, startup
  probe. D-77's version-2 ref and migrated-log leaves preserve nested ref names;
  version-1 compatibility is read-only and qualified migration may be refused.
  Actual nested-name collisions, migrated-log coexistence, independent reopen,
  whole-record CAS and cancellation are qualified by the local backend gates.
  Private identity proofs borrow a live single or paired exclusion and its
  existing source/destination role; they cannot independently grant repository
  authority. Same-bucket publication retains one actual namespace lock across
  source checks and durable CAS, with independent writer exclusion, cancellation
  and durable reopen qualified by the local backend checks.
  Protected deletion-intent key classification grants no ordinary-write authority;
  physical deletion and current-root fencing remain joint work with T-GC-1.
  D-79's selected publication chain, protected external control and retained
  absent-name history require joint T-REF-2/T-GC-1 integration; existing local
  backend qualification does not claim those new contracts complete.
  Narrowed to trunk scope: S3-compatible and GCS backends are
  T-BKT-2 and T-BKT-3 at T3. The backend implements OBJ-5's idempotent
  writes and verified reads; T-HOST-1 completes its cache-admission rule.
  — satisfies OBJ-5 jointly with T-HOST-1, STORE-1 to STORE-9, STORE-11
  to STORE-13, STORE-33, BKT-1 to BKT-4, BKT-6 to
  BKT-8, BKT-13, BKT-14, BKT-16, BKT-17;
  `checks.terrane.gates.store-idempotent-put`,
  `checks.terrane.gates.store-verify-on-put`,
  `checks.terrane.gates.store-verify-on-get`,
  `checks.terrane.gates.store-ranged-get`,
  `checks.terrane.gates.store-has-batched`,
  `checks.terrane.gates.store-ref-cas`,
  `checks.terrane.gates.store-ref-log-append-once`,
  `checks.terrane.gates.store-capability-probe`,
  `checks.terrane.gates.store-list-not-authoritative`,
  `checks.terrane.gates.store-validates-uploads`,
  `checks.terrane.gates.bucket-key-registry`,
  `checks.terrane.gates.bucket-file-layout`,
  `checks.terrane.gates.bucket-file-atomic-write`,
  `checks.terrane.gates.bucket-file-cas`.
- [ ] **T-REF-2** Ref advance protocol (packs, indexes, log, CAS), epochs,
  single-writer default, tags, reflog, rollback, watch, and commit-set entry
  provenance. Durable disclosure certificate verification and publication are
  incomplete: the shared receipt codec accepts the registered raw shape, but
  unchecked certificates cannot replace verified history. These checks are
  joint with T-PROV-1 and T-DOM-1; they remain unqualified until destination-only
  reopen, private erasure and current-authority race checks pass. Affected-root
  admission and historical context coverage under D-75 remain incomplete;
  ordinary entry paths cannot become permission boundaries. D-76's original
  ACL administration, retained bootstrap evidence and actual-ancestor
  delegation checks remain joint with these admission gates. D-79's exact
  selected publication, complete Guard inputs and absent-name recreation
  history remain pending implementation and actual competing-writer checks.
  The shared CAPABILITIES key-11 codec and explicit protected-operator
  configuration are present. Legacy handles refuse registered markers;
  checked activation, selected reads and transitions remain joint work.
  Canonical reflogs distinguish an absent current CAS expectation from a
  retained committed predecessor without resetting its sequence or epoch;
  native selection of that retained history remains joint work.
  The portable history, snapshot and pointer payload keys have registered
  mutability; protected publication control remains outside ordinary key I/O.
  The shared private handoff includes a final operation check after staging.
  Existing-only coordination and complete profile access support genuine
  read-only startup verification. Actual producer integration, submitted-effect
  retention and full crash/copy qualification remain incomplete.
  A read-only timing audit of the combined source-discovery candidate
  `bddcd674cd` preserves the original aggregate failures. The side-attribute
  test returned `Expired`; its 53.20-second total does not establish the final
  attempt's elapsed time or load causation. The fixture's 30-second bound uses
  native monotonic time, which Tokio timer pause does not freeze. The observed
  cancellation barrier failure precedes cancellation; Unsupported results
  remain distinct implementation failures. Per-attempt timing evidence and
  genuine unchanged-bound qualification remain required. All 12 current
  aggregate failures remain unresolved.
  Optional native binding hooks now retain the exact injected clock and actual
  duplicated exclusion without stronger generic clock or lock bounds. Native
  and supported non-Send builds qualify the shared seam; private factories,
  final consumed-control fencing and complete effect routing remain pending.
  The combined retained-effect and held-read candidate passes 37 selected
  native regressions and all 64 supported non-Send tests. Actual descriptor
  rebinding, queued expiry and cancellation checks preserve the original
  exclusions through physical completion. The private factory namespace and
  producer-owned effect-context handoff are present. Reviewed directory repair
  compares the captured name and opened descriptor before exact 0700 repair,
  rechecks other consumed inputs and the unchanged clock, and refuses unreadable
  owner-masked creation before protected handoff. The actual guard producer
  retains successful current requests and complete consumed control receipts;
  the joint closed-consumer candidate refuses a consumed registration replaced
  after Guard-installation staging and preserves the selected slot through
  independent reopen. A genuine ordinary branch dispatch also preserves its
  exact chained predecessor and whole old head; intervening pack/index Raw
  preparation slots are verified separately, and the rejected target stays
  absent. The combined content and D-82 candidate builds with the reviewed
  pure retirement and collector prerequisites. Its latest joint run includes
  all 33 ref selectors and 22 backend cases: 46 pass and nine fail. The two
  raw burn-association checks and retained content/quarantine checks pass,
  as do directory-failure/abandoned-candidate outcomes, queued native
  cancellation and all four complete parent-batch regressions. The Guard rejection
  witness checks its exact predecessor and absent target before reopening;
  reopening separately selects only a distinct canonical Raw capability update.
  The canonical retirement-association fixture and actual retained log fault
  correction pass their separate four-case qualification. Remaining failures
  in the broader run are cancellation arrival and multiwriter duration under
  unchanged bounds, Pack/Index fault hooks and the registration hook selecting
  an earlier preparatory Raw slot, and five positive copy/GC-retirement cases
  that still return Unsupported. Reviewed test-only retargeting selects the
  actual retained content rename and staged Guard/Candidate transaction while
  preserving whole predecessor, head and absent-target assertions; its native
  qualification passes all three targeted native regressions. The fresh
  per-operation held-content candidate preserves physical CAPABILITIES and
  MANIFEST namespace checks and passes six native parity, ancestry, incarnation,
  integrity and intervening-publication cases. The committed coordination
  creation-mode correction also passes with those six cases under umask 000.
  Its broader 33-selector run passes 32 cases, including the unchanged
  30-second multiwriter case; cancellation arrival still fails under that
  grouped load. The same cancellation case passes once as the isolated exact
  selector used by the hermetic gate, with its original 2-second limit and
  primitive/barrier assertions unchanged. These are scoped process results,
  not a complete Nix gate pass. Mandatory formatting and the supported non-Send
  std/surface-sdk build pass; inherited unfinished-production warnings remain.
  The later copied-burn/index-policy and three-walk control candidate builds
  and passes all 14 focused cases. Its subsequent grouped ref run passes
  31 of 33 selectors, with cancellation arrival and multiwriter expiry failing
  at the original 2-second and 30-second bounds. No deadline or assertion has
  changed. The policy fixtures verify unselected catalog data and detached
  aliases; they do not qualify selected copied-retirement authority.
  Shared existing-open prerequisites now require an existing-only final
  catalog exclusion and a descriptor-bound native range probe. The generic
  native range reader also uses a nofollow descriptor and preserves ordinary
  hardlinks. All five focused native range/metadata/lock cases pass on the
  released shared source. Exact gate membership now includes the three
  descriptor-range cases, four ordered control-walk cases and four index-policy
  cases. Actual Active-open integration and complete native qualification
  remain pending; fresh and Pending activation remain separate work.
  The five-file existing-Active candidate has completed source review and
  genuine task rebase onto the shared hooks. It classifies exact registration
  under the existing exclusion, retains its actual descriptor before repair,
  dispatches fixed present-key create-new and descriptor-bound range probes,
  and refuses an eligible successor with a stale whole CAPABILITIES preimage
  before staging. The assembled native library builds, and a focused native
  process passes all eight startup cases and all 13 collector lease cases.
  Cancellation separately checks the actual independently opened coordination
  descriptor remains kernel-locked after the waiter is aborted. The probe gate
  requires all eight exact startup selectors. These scoped results do not
  qualify the full task; they precede the separate fresh/Pending qualification.
  The verify-on-get, ranged-get and file-CAS gates now require the appropriate
  exact held-content selectors and reject missing tests. Complete effect routing
  remains pending.
  Ordered ancestry and record-parent batching preserve all
  metadata observations, duplicate reads, exact payload reads and initial/final
  fences. The CAS gate
  now requires their actual cardinality, error-priority and ancestry regressions;
  the hermetic registry gate qualifies all 292 registered specification names,
  including the four ref gates. This registry result does not qualify their
  implementations. The declared workspace vendor output now builds with its
  exact lockfile hash. Previously submitted hermetic snapshot builds pass all
  27 file-CAS selectors, all seven atomic-write/directory selectors and the
  formats-without-std gate. Those snapshots precede the expanded current gate
  set and qualify only their recorded source. Complete current gate builds
  still require remaining producer/GC source integration; trunk formatting
  also awaits those missing source modules. A fixed optional protected-record
  read recipe now keeps all ordered parent observations, policy checks before
  body reads and same-descriptor leaf checks in one native worker. Unsupported
  bindings and fault-intercepting wrappers retain the original scalar path.
  The reviewed consumer preserves the complete scalar path on `None` and
  propagates hook errors without retrying. Shared native/scalar predicates
  preserve owner, mode and single-link checks. One focused native process passes
  all six binding fixtures, seven complete-transcript/fallback/final-fence
  fixtures and 14 prior record/control/content cases. Native and supported
  non-Send library builds and both mandatory formatting commands pass on that
  candidate. Exact gates now require the six binding and seven consumer cases;
  hermetic qualification passes all 44 exact `bucket-file-cas` cases and all
  10 exact `bucket-probe` cases on the reviewed joint candidate. The capability
  gate passes 24 exact cases on a separate reviewed checkpoint, including five
  opened-directory retention cases. Queued and running cancellation preserve
  the actual directory descriptors and independently acquired kernel exclusion
  through physical completion and durability; replacement and unsafe policy
  refuse writes. A shared opaque initialization interface now fixes configured
  inputs before the first root mutation and reserves fresh receipts for genuine
  native creators. Its private programs remain beneath the retained publication
  frame and native executor; unavailable bindings refuse without root creation.
  The shared default external control naming is unchanged. A separate frozen
  initializer candidate passes 22 actual cases: nine creator/probe cases,
  five Pending recovery cases and the eight unchanged Active-open cases.
  Actual successful create-new supplies freshness; durable staged snapshot,
  transaction and portable pointer precede handoff. Existing Pending restart
  reuses its exact operation, and same-byte replacement of an original staged
  inode refuses activation. Queued and running cancellation retain actual
  opened descriptors and kernel exclusion through worker acknowledgment.
  An effective-UID mismatch refuses before any root/control creation. The
  supported non-Send build, strict rustdoc and mandatory formatting pass on
  that candidate. The shared outcome now boxes its opaque receipt, and the
  reviewed test-only assertion corrections pass formatting and strict rustdoc.
  Strict Clippy still fails on shared diagnostics; no lint is suppressed.
  The capability gate now requires all 14 new exact cases, raising its floor
  from 24 to 38. Actual Nix qualification passes all 38 exact cases on the
  frozen initializer graph. Three native fault/read fixtures now forward the
  actual initialization binding without changing their interception or
  assertions. On that graph, the corrected file CAS gate passes all 44 exact
  cases and the probe gate passes all 10. Complete source integration and
  whole-task qualification remain pending.
  The reviewed shared selected-observation and fixed publication engine now
  replace their trunk declarations. The private frame captures exact selected
  reads and actual exclusions; immutable staging precedes the sole consecutive
  create-once slot, and portable projection precedes logical caches. Existing
  collector observation and checkpoint anchors remain intact. All five adopted
  files pass source formatting and match the qualified candidate except for
  those preserved anchors. Seven shared children now implement sealed checked
  transitions, protected control reads, registered-profile input, portable
  projection, exact read receipts, consecutive chain resolution and raw
  successor validation. Their complete source review checks held identity,
  whole preimages, absent-name history, opaque Notes and unchanged burn ownership;
  all seven match both qualified bucket and collector graphs and pass scoped
  source formatting. The 17 reviewed activation and publication-test paths
  now also match the frozen bucket graph exactly. The native creator, retained
  activation and same-registration Pending recovery consume the original
  opened-directory and coordination receipts; their tests keep actual lock,
  incarnation, ancestry, fault and complete-transcript assertions. Scoped AOS
  source formatting passes. A current trunk native build stops at the missing
  collector observation body before qualification, so these source adoptions
  do not claim native gates or a task merge. Complete native graph integration
  and the full trunk gate set remain pending.
  Eight reviewed lower-backend paths now connect layout admission, existing-only
  exclusion, retained holders, selected refs/logs, catalog and content operations
  to that engine. All eight match the frozen bucket and reference graphs and
  pass scoped AOS source formatting. They preserve per-read physical namespace
  checks, detached-index exclusion and represented permanent-burn completeness;
  the older collector snapshot lacks those later backend corrections. The actual
  trunk native build then reported 27 diagnostics, down from the lease adoption's
  64, with real Guard types and consumers still absent. This source integration
  does not qualify the full task; Guard/reference integration precedes current
  runtime gates. Nine reviewed backend fixture paths now match the frozen
  bucket graph and preserve actual initialization, retained effects, fault
  interception, whole selected records and absent-name predecessor assertions.
  Capability and manifest cache recovery uses selected history; legacy unknown
  authority remains refused. The mandatory repository formatting sequence
  passes; these fixtures still require the complete Guard graph to execute.
  The declared opened-directory retention test module is restored exactly
  from its reviewed source. It preserves actual descriptor, ancestry, kernel
  exclusion and queued/running cancellation assertions. The exact mandatory
  Rust-check and all-format sequence now passes on the trunk; native execution
  of these fixtures still requires the complete Guard/reference source graph.
  The previous trunk aggregate stopped in `bundle-verify` compilation,
  before test execution, with 30 diagnostics. Missing Guard, domain and
  protected installation APIs include the collector fixture's namespace and
  registration types; remaining inference diagnostics are retained separately.
  After native domain and backend-fixture adoption and the pure provenance/
  derived closure, the aggregate stopped in package compilation with 27 missing
  Guard/consumer and resulting inference diagnostics. Nineteen fully reviewed
  Guard paths now retain actual current requests, complete protected controls,
  original bootstrap associations and the injected clock through publication.
  They match the frozen reference source while preserving the trunk collection
  hook and shared interfaces. Mandatory repository formatting passes. That
  native build and actual aggregate's `bundle-verify` compilation both stopped on
  29 missing algebra/ref-advance API diagnostics, before runtime tests. After
  reviewed algebra adoption, that native build and actual aggregate's
  package compilation stopped on the same 21 ref-advance and resulting inference
  diagnostics. Native
  admission still explicitly refuses disclosure certificates until their complete
  authenticated publication path exists. No native gate or task merge is qualified.
  Qualification exposed
  an overwrite fixture still targeting the previous rename primitive and three
  fixtures retaining their own namespace receipts while waiting to reacquire.
  The reviewed test-only corrections inject a real write at the current
  create-new primitive and drop the actual owning adapters before reacquisition;
  original assertions and timing bounds remain unchanged. Earlier failed and
  interrupted logs remain separate from the corrected qualifications. The
  narrow FsRef adapter
  forwards only to its actual underlying binding; FaultFs keeps scalar
  interception. A separate original multiwriter selector on the assembled
  joint candidate returns `Expired` at the first joined result with its
  original 30-second request window. A separate opt-in test-only phase trace
  passes that exact case with unchanged assertions: its durable acknowledgments
  arrive 9.18 and 18.77 seconds after the original request origins. The complete
  test takes 36.140 seconds, including setup and final assertions. Initial
  whole `admit_join` calls take about 6.05 seconds each and the losing request's
  whole `admit_rebase` takes 4.22 seconds. The successful trace does not explain
  the earlier failure's unmeasured phase or establish reliable timing. A deeper
  test-only trace passes the same case in 32.851 seconds; it separates fresh
  policy/history/tree verification from synchronous merge and encoding, which
  take milliseconds. The observed acknowledgments arrive 8.67 and 17.19 seconds
  after the unchanged original origins. A later original untraced multiwriter
  process passes in 40.700 seconds including setup and final assertions.
  The grouped 33-selector run passes 32 cases and fails the unchanged
  two-second cancellation-barrier arrival. Subsequent actual Nix qualification
  passes all four reference gates on that same frozen source: 16 exact ordering
  cases, five epoch-fencing cases, three watch cases and 12 commit-order cases.
  Each gate runs individual exact test processes with the original bounds.
  These passes preserve the grouped-run failure as separate evidence and do
  not establish reliable timing. Both native reference adapters now forward
  the initializer to their actual binding; scalar fault interception and
  deadlines remain unchanged. Three fresh-reference cases and mandatory
  formatting pass on that frozen forwarding candidate. All four actual Nix
  gates pass again with the same 16/5/3/12 exact selectors on that separate
  candidate. Joint source qualification remains pending.
  No deadline change or speedup is claimed.
  Seventeen fully reviewed ref-advance source paths are now adopted on the
  trunk. Sixteen of the 18 total reference paths, including the existing phase
  tracer, match the frozen candidate exactly. The two intentional corrections
  enforce D-83/REF-3: opaque Notes cannot acquire branch sessions or receive
  commit-pointer policy advances. Their regression checks refusal before token
  validation and preserves the actual selected publication stamp; it is added
  to the ordering gate as an individual exact selector. Shared manifests,
  lockfiles, Guard, backend and selected-effect interfaces remain unchanged.
  The actual native production build and strict rustdoc now pass. Mandatory
  repository formatting passes. Reviewed SDK and native derived prerequisites
  are now integrated. All four actual reference gates pass on that combined
  snapshot: 17 ordering, five epoch-fencing, three watch and 12 commit-order
  exact selectors. Full native Nextest executes 359 tests: 352 pass and seven
  fail, with no skipped tests or timeouts. Six failures are shared backend
  compatibility/import cases; the cancellation waiter still exceeds its
  unchanged 30-second bound under concurrency despite passing in isolation.
  The absent-history fixture now drops its retained adapter before reacquiring
  exclusion; its exact unchanged history assertions pass in 0.557 seconds.
  The full current-gate aggregate fails the retirement compatibility assertion
  in `index-generation-manifest`. Strict all-target Clippy remains red on 20
  production and two test diagnostics; warnings are not suppressed.
  `prov-commit-verify` and `prov-disclosure-boundary` now execute native
  discovery and fail explicitly for the 19 missing required boundary cases.
  Durable certificates, original foreign authority,
  and complete publication qualification remain incomplete; these focused
  passes do not qualify the task or milestone exit.
  The shared final-effect context now carries independently owned protected
  control receipts. Its executor duplicates every owner's descriptors and
  captures exact ancestors, directories, locks and records under that owner's
  protection; the primary receipt must remain the destination's. Existing
  producers still provide one receipt. This prerequisite does not qualify the
  paired disclosure producer. The actual ordering gate compiles and passes
  five selected cases before cancellation fails at the unchanged two-second
  barrier-arrival limit; the final publication barrier is not reached within
  that limit. The case exits after 5.60 seconds, rather than demonstrating a
  cancellation-release failure. The full aggregate again fails the known
  retirement assertion in `index-generation-manifest`. Mandatory formatting
  passes; source receipts and the complete disclosure path remain unqualified.
  Original-control revalidation now reuses its existing ordered ancestor
  batch, retaining every fresh path result and the separate fresh directory
  and lock checks. Independent source review, the native build and eight
  focused original/consumed regressions pass. The ninth focused development
  case still misses cancellation's unchanged two-second arrival limit. The
  actual hermetic ordering gate passes all 17 exact selectors, including that
  cancellation case with unchanged assertions. The full aggregate remains red
  on the 19 unqualified disclosure cases; isolated optimized execution does
  not establish reliable timing or complete task qualification. Both mandatory
  formatting commands pass.
  — satisfies
  TREE-16, REF-12 to REF-23, REF-27 to REF-31, PROV-26 to PROV-31, DOM-24;
  `checks.terrane.gates.prov-commit-verify`,
  `checks.terrane.gates.prov-disclosure-boundary`,
  `checks.terrane.gates.ref-advance-ordering`,
  `checks.terrane.gates.ref-epoch-fencing`, `checks.terrane.gates.ref-watch`.
- [ ] **T-GC-1** Mark-and-sweep collector: roots, mark, grace, two-phase
  sweep, singleton lease, resumability, retention values `gc`, `lease`,
  `ttl`, `forever`, and ordinary reflog duration/count selection. D-78
  registers physical creation journals and recoverable deletion intent;
  the reviewed pure journal, marking, proof-context, checkpoint, retention and
  grace-window bodies now replace their trunk declarations. All 27 adopted
  paths, including 16 independent hexadecimal witnesses, match the qualified
  collector graph byte-for-byte; their source formatting passes. The base
  publication codecs are now integrated, including complete checkpoint coverage
  of represented catalog changes. D-79 original, Guard and consumed-lineage
  evidence codecs and D-82 permanent ownership, copied-retirement and recurring
  reconciliation formats are integrated. All 31 adopted evidence/retirement
  paths match the reviewed collector graph byte-for-byte. The actual trunk core
  passes all 299 tests, no-default compilation, strict Clippy and rustdoc,
  complete core formatting and the hermetic `formats-no-std` and
  `canonical-cbor` gates. The latter executes all 14 evidence fixtures, 27
  collector cases, 21 retirement cases and four decoding regressions in actual
  test processes bounded to 256 MiB. Qualification on the complete native trunk
  remains pending.
  The 11 reviewed native checkpoint paths now replace their trunk declarations:
  complete selected observations, metadata-only historical Guard adaptation,
  actual consumed controls, retained fixed checkpoint effects and resumable
  marking. All 11 match both frozen collector checkpoints byte-for-byte and
  pass scoped AOS source formatting; the existing private producer and executor
  namespace anchors are preserved. This adoption grants no sweep or deletion
  authority. Native lease, lower backend and reference/Guard prerequisites
  still need integration before the current trunk can qualify these paths.
  The shared canonical collector lease preserves whole-value proposal and
  fencing checks. Actual selected lease authority remains joint native work;
  native integration, actual crash/timer/restore qualification and complete
  current-root/publication fencing remain pending. Physical intent alone
  cannot qualify deletion.
  D-79 defines complete current fences, selected lease/configuration changes
  and source-lineage preservation; their native implementation and actual
  effect/recovery qualification remain incomplete. D-82 registers permanent
  burns, destination retirement barriers for ordinary copies, and recurring
  physical-residue reconciliation. Selected permanent control record formats
  preserve their represented whole authorization and ownership associations.
  Their canonical byte and allocation witnesses pass the actual trunk Nix gate;
  they do not establish native ownership or deletion permission.
  Ref rows check canonical registered
  names, unsigned order and whole current records before storage; Notes retain
  their opaque bytes. Private factories, local copied-retirement effects and
  provider qualification remain pending. Decoded records grant no physical
  collection authority.
  The separate pure collector prerequisite preserves the version-one root,
  mark, state and local journal models. Its complete source review checks
  traversal-context ordering, cutoff dominance, reconstructed mark hints and
  immutable operation associations against GC-3 to GC-7, GC-28 to GC-30
  and the registered CDDL. All 16 local-v1 fixtures match the normative hex
  byte for byte. The candidate passes 299 core tests. A second qualification
  runs the canonical gate's 27 exact selectors in 27 separate 256 MiB test
  processes; each runs one test and exits successfully. Strict Clippy and
  rustdoc, a no-default-feature core build and mandatory formatting also pass
  with the exact reviewed publication/retirement prerequisites temporarily
  present and byte-verified before removal. Complete native trunk source
  integration and runtime Nix qualification remain pending. No decoded checkpoint,
  elapsed bound or physical intent grants native collection authority.
  A separate shared opaque lease carrier and anchored producer/executor hooks
  now distinguish selected lease publication from ordinary Raw writes and
  collection permission. Its dedicated producer must verify the actual
  current Guard, whole selected lease, exact injected clock and genuinely
  consumed protected controls; submitted effects retain their real exclusions
  through durability. These declarations grant no authority and remain
  unqualified until the producer, fixed consumer and positive native singleton
  lease tests are integrated.
  A separate private mark-checkpoint handoff and five runtime hooks retain
  the complete checked roots, raw canonical digests, whole selected root/state
  preimages, actual physical read receipts and each independently configured
  control owner. Only the genuine descendant producer can construct the
  handoff. The fixed consumer must derive canonical cycle/shard/revision paths
  and refresh its retained live clock and poisoned-session check before staging,
  slot dispatch and acknowledgment. These declarations grant no sweep,
  deletion or availability-loss authority. A separate native checkpoint candidate
  passes nine exact tests: selected roots and immutable mark progress, restart
  through completed marking, stale-renewal refusal and permanent session poison,
  incomplete-frontier refusal, canceled checkpoint retention, count-zero
  metadata witnesses without old chunks, queued expiry before acknowledgment,
  two finite replay checks and real takeover into a different marking cycle.
  GC-7's optional final leaves are omitted to avoid colliding with immutable
  revision directories; completed selected revision pointers remain unchanged.
  Non-Send and no-default library builds, strict rustdoc and mandatory formatting
  pass on that candidate. Reviewed replay validation derives finite containment
  from persisted traversal instead of imposing a global step ceiling. The
  checkpoint cancellation witness independently observes actual kernel lock
  contention. Resume requires the original marking epoch; actual takeover
  refuses old checkpoints and completes a new cycle without changing the old
  selected state or immutable mark bytes. Strict Clippy still reports unfinished
  shared diagnostics. The actual singleton-lease Nix gate passes 19 exact cases
  on the frozen reviewed collector graph: 13 native lease cases, five runner
  fencing and progress cases, and one independent non-Send Rc case. Native
  source integration and full collector gates remain pending; foreign ownership,
  disclosure, grace, sweep, restore and deletion are incomplete.
  D-83 reconciles opaque advisory Notes with commit-bearing GC roots while
  preserving their whole selected values in current fences. Two actual Notes
  regressions pass: opaque and RefRecord-shaped Notes stay outside commit
  roots, Derived refs remain roots, and a changed selected Note invalidates
  stale whole-inventory publication. Completed resume independently reopens
  the FileBucket, Guard and retention verifier and preserves the original
  selected Notes. Both collector fixture bindings now invoke genuine native
  initialization; the non-Send Rc case passes independently, and the native
  collector run passes all 24 selected cases. The unchanged singleton-lease
  Nix gate again passes all 19 exact cases on this initializer-compatible graph.
  Strict rustdoc, non-Send compilation and mandatory formatting pass; strict
  Clippy remains blocked by shared diagnostics. Full collector qualification
  and source integration remain pending.
  An unrepaired observation hook retains the actual writable holder role and
  fresh complete chain checks so live-other-holder, stale lease or Guard
  rejection can precede every cache effect. A separately anchored test clock
  retains its exact injected state for queued-expiry and continuity witnesses;
  production clock constructors remain private. The initial selected lease
  candidate passes 11 of 12 actual Tokio cases and the independent Rc
  acquire/renew/takeover/reopen case. Its failing existing-open case identifies
  coordination creation in the old activation path. After the reviewed
  retained Active-open route and genuine read-observation helper are integrated,
  a separate task worktree rebased onto the shared trunk passes all 13 actual
  native lease cases, including missing-coordination and the final clock check.
  Both mandatory formatting commands pass there. Full review of
  the nine owned source files checks the genuine producer, exact whole lease
  and preserved successor, consumed registration controls, retained clock and
  cancellation durability. A final retained clock check before receipt
  acknowledgment has been added. Its separate actual regression fails before
  the correction and passes afterward: the lease remains selected, but the
  expired clock prevents a success receipt. The corrected independent Rc case
  passes in its actual test process, and both mandatory formatting commands
  exit successfully. Earlier rustdoc and no-default-feature compilation pass;
  strict Clippy remains blocked by 22 inherited
  unfinished-production diagnostics. Native source integration, runner-wide
  lease fencing and complete gate qualification remain pending.
  The nine reviewed native lease paths now match the frozen qualified collector
  graph on the trunk and pass scoped AOS source formatting. The genuine lease
  producer and fixed executor retain the actual clock, namespace and consumed
  registration controls; final selection acknowledgment refreshes that same
  clock. Native and Rc fixtures forward initialization to their actual binding.
  Source parity preserves the existing private producer, executor and clock
  anchors. This adoption does not claim a current trunk lease gate pass; lower
  backend and reference/Guard integration still precede runtime qualification.
  That lease-only adoption reached type checking and failed on 64 diagnostics,
  including the absent lower-backend artifact/retained-holder APIs and actual
  Guard types. No stub, weaker receipt or lint suppression replaces those
  remaining implementations.
  Narrowed
  to trunk scope: compaction is T-GC-2 on
  B-jobs. — satisfies GC-1, GC-3 to GC-7, GC-9 to GC-17, GC-22 to GC-24,
  GC-28 to GC-30; `checks.terrane.gates.gc-roots-complete`,
  `checks.terrane.gates.gc-mark-reachability`,
  `checks.terrane.gates.gc-grace-window`,
  `checks.terrane.gates.gc-two-phase-delete`,
  `checks.terrane.gates.gc-singleton-lease`.
- [ ] **T-PROV-1** Commit signing and verification, entry provenance,
  selector language and trust presets. Historical signatures, authenticated
  tree evidence, and entry and attribute origins are verified in the pure
  core. Current-ACL commit guarding and durable disclosure certificate
  verification/publication are joint with T-REF-2 and T-DOM-1; merge admission
  with T-ALG-2; wire and command error translation with their runtime tasks.
  A shared `VerifiedHistory::append_verified` prerequisite now preserves
  completed disclosure boundaries, original root/bootstrap scopes and selected
  side records across history unions. Both public inputs must have completed
  contexts; private disclosure candidates may import only completed dependency
  histories. Provisional inputs, differing original authentication evidence,
  incompatible profile limits, tree interpretations and retained associations
  fail without changing the receiver. Eleven new exact regressions pass,
  including genuine signed-record verification with different issuer retirement
  bounds, completed disclosure and selected side-record context preservation.
  All 469 core tests, strict all-target core Clippy and rustdoc pass, together
  with the actual 32-case selector gate and `core-no-std`. The actual aggregate
  remains red at the absent `format_properties` task target; this prerequisite
  does not supply the parked historical-bootstrap selectors or qualify native
  disclosure/collection. On its isolated branch the native producer now passes
  a public-source factory/erasure/reopen test and the first required private-cut
  case: distinct original public author, private current discloser and public
  destination; private sibling/history absence; both upstream namespaces and
  credentials erased; destination-only authorized reopen/read. A second
  required case passes through the public SDK with two independent source
  histories, distinct certificates, manifest plaintext and existing completed
  destination baseline ancestry. Its producer transfers dependencies according
  to the finished candidate and already verified destination history. Seventeen
  required cases and paired recovery remain pending. Full native Nextest runs
  all 368 tests: 360 pass and eight fail, including six existing bucket
  compatibility checks and two configured deadline failures under contention.
  The owned disclosure cases pass in that run; strict native Clippy remains
  red. Strict native rustdoc passes with warnings and missing documentation
  denied. The full native suite and disclosure gate remain unqualified.
  A subsequent isolated worker run passes both unchanged deadline cases and
  three genuine disclosure regressions, including independently initialized
  factories with identical issuer labels. Strict native rustdoc also passes.
  Strict Clippy still fails on seven existing production and two test dead-code
  paths. These focused results do not qualify the failing full native suite;
  the remaining required disclosure cases and paired recovery stay incomplete.
  The isolated cached paired-recovery draft now passes its genuine interrupted
  import/retry regression and all three previous paired cases, with native
  build and mandatory formatting green. Ordinary reopen still refuses the
  selected-versus-installed mismatch. Fresh recovery, unrelated-carrier and
  changed-record refusal, current-permission refusal and the complete required
  disclosure suite remain incomplete. Review also found that paired principal
  comparisons used only their displayed names. The shared `same_principal`
  prerequisite now compares authenticated name and kind while keeping group,
  token and issuer claims independently authorized. Its two exact hermetic
  fixture cases and mandatory formatting pass. Wiring it into the producer and
  genuine kind-mismatch refusals remain required; the native suite and strict
  Clippy are still unqualified.
  The reopened pure PROV-13 correction now propagates content and attribute
  acceptance errors only for predicates requiring that ancestry.
  Introduction-only Any, issuer and eligible Strict selectors keep independent
  source evidence;
  inherited root constraints and nested attribute contexts retain their own
  acceptance requirements. The complete reviewed pure context/disclosure and
  derived-data source closure is adopted. All 375 trunk core tests, strict
  all-target Clippy, strict rustdoc and mandatory repository formatting pass.
  Actual hermetic signature and selector gates pass all 12 and 21 exact cases,
  including missing ancestry, introduction-only and inherited-root regressions.
  Review identified an AUTH-28/PROV-4 gap for unchanged-root forks: graph
  unchangedness skipped the destination's independent original bootstrap
  comparison. The signature gate now requires eight exact historical bootstrap
  regressions; the implementation remains on its task branch and absent
  selectors fail the trunk check. Current admission now compares the actual
  fresh destination's bootstrap before unchanged-source reuse and retains any
  required Admin check for final publication. The actual hermetic `commit-order`
  gate passes all fourteen exact cases, including widening denial and a genuine
  retained fork with source Fork and destination Commit-only token grants.
  Standalone Nextest also passes all three focused bootstrap cases. Native
  compilation and strict rustdoc pass. Strict all-target Clippy fails with
  twenty production and two test diagnostics for unused integration paths;
  those warnings are not suppressed. Current credentials cannot repair
  missing original Admin.
  The reviewed historical-bootstrap candidate implements all eight required
  regressions, passes all 457 core tests, strict core Clippy and rustdoc, and
  the twenty-case hermetic signature gate. Its required actual aggregate
  exits with failure at `index-generation-manifest`: the legacy-state test
  expects `Unsupported`, but receives a different error kind that the test
  does not print. The candidate remains unmerged. That result does not resolve
  retirement compatibility or qualify any of the nineteen native disclosure
  boundary cases; the unmerged historical selectors still fail on trunk.
  Reviewed annotated-tag signing and verification now bind the exact REF-20
  preimage, terminal key, expected tag/commit and source Tag/Admin scope.
  Earlier snapshot-only qualification passed all 303 trunk core tests and its
  12-case hermetic signature gate, including four snapshot cases. Neither pure
  qualification establishes native tag
  publication or current ACL checks. Complete native disclosure/publication and
  collection qualification remain incomplete. Earlier trunk aggregates failed
  the retirement compatibility assertion in `index-generation-manifest`.
  Native disclosure qualification now requires 19 exact end-to-end cases,
  covering protected imports, historical keys, complete boundary validation,
  independent current authority, destination-only reopening and safe special
  entry materialization. Discovery and execution are checked separately;
  missing, empty or ignored selections cannot qualify a gate. The actual
  hermetic `prov-disclosure-boundary` build compiles the native test binary and
  fails because all 19 required cases are absent. The current full aggregate
  exits with failure at `prov-commit-verify` for those missing cases; neither
  this earlier discovery failure nor pure qualification resolves the known
  backend retirement failures. Mandatory Rust and repository formatting pass.
  The isolated protected-import foundation also passes all 16 selected native
  original-authority, consumed-control and retention regressions. It remains
  on its task branch; existing regressions do not qualify the 19 required
  disclosure boundary cases or the unfinished publication producer.
  Its ancestor-first complete-history draft also passes 17 selected native
  regressions; dedicated issuance and paired publication remain closed.
  The isolated dedicated-role factory run passes 18 native regressions,
  including a distinct disclosure key and refusal to repair an erased seed.
  Native publication now derives its consumed snapshot from the actual held
  guard's trust state, preserving complete snapshot equality. Historical
  original authority remains independent of the current physical discloser;
  identical issuer labels across independently initialized repositories now
  have an isolated scoped historical-consumption candidate. Its exact retained
  import-trust pin carries the foreign public key and retirement bound without
  replacing current configured local keys. The complete six-file source review,
  native build, 16 focused regressions and mandatory formatting pass. This is
  preparatory evidence; genuine independent-factory paired publication and the
  19 required boundary cases remain unqualified.
  The current isolated paired-publication candidate now passes six genuine
  native regressions, including interrupted cached-import recovery, unrelated
  pending-carrier and altered retained-trust refusal, valid attenuated current
  scope denials and equal-subject/different-principal-kind refusal. The exact
  run `013dc7c0-97d8-4fab-bf92-bcb0be766673` has six passes and 367 filtered
  cases. Only two of the nineteen required contracts are implemented; the
  remaining seventeen stay open. An additional genuine fresh-factory recovery
  case now passes after dropping the original destination instance: valid
  attenuated source Read and destination Commit denials, changed canonical
  retained-trust refusal, exact paired recovery, source/seed erasure and ordinary
  destination-only reopening/content read. Its run
  `ddb9ddcf-a1b2-4734-80ab-751edcbe560c` passes one case with 373 filtered.
  Independent local initialization exposed source-profile parameters incorrectly
  reused for destination staging. The reviewed correction supplies the actual
  destination profile while preserving its encoded-payload and referenced-chunk
  validation before dedup. The reviewed deferred coordinator remains private;
  ordinary reopening still refuses pending selected configuration mismatches.
  This scoped evidence precedes public entrypoint and strict native qualification.
  These additional regressions do not qualify the absent contracts.
  Complete review of the subsequent native candidate covers dependency-first
  dictionary staging, independently retained graft producers and genuine
  canonical conflict resolution. The dictionary fixture verifies Raw, Zstd
  and nested ZstdDict envelopes, exact encoded transfer and typed current-scope,
  profile and plaintext-length refusals. The replacement-graft correction finds
  the retained matching root before a displaced same-path occurrence. Its four
  focused cases pass together; the genuine conflict-resolution case separately
  passes run `a57c9686-ffa9-4330-a460-be68a97d18c8`. Five of nineteen required
  contracts have isolated passing evidence. The combined qualification source
  remains unpublished; full native gates and the aggregate remain required.
  The combined candidate now passes all five selected native fixtures serially
  (run `bed3d1ff-b2bc-41ff-b05e-6132df0d88b5`), both actual `chunk-codec` and
  `chunk-bomb-cap` gates and mandatory formatting. The original concurrent
  four-case run passed two cases, expired during materialization and timed out
  in one case. Serial qualification preserves all existing lease and test
  deadlines; it does not establish concurrent reliability or qualify the
  fourteen remaining required boundary contracts.
  Subsequent full reviews qualify the limited directory/raw-symlink contract
  and complete sibling/private-attribute/unanchored-parent refusal. Both have
  isolated passing native evidence and mandatory formatting; seven of nineteen
  boundary contracts now have reviewed passing evidence. The first/second-parent
  candidate additionally verifies actual independent source references, exact
  signed input order, uncovered private second-parent attributes, refusal before
  transfer and source-erased destination-only reopening. Its final isolated case
  passes run `c62e1db1-31e9-4ea7-96b1-a1b926824be7`. The same exact case also
  passes on the combined candidate (run
  `bdccdd05-6605-4ed4-b735-9d281b512666`); eight of nineteen boundary contracts
  now have reviewed passing evidence. Full native gates remain required.
  The nested/repeated-root fixture passes homogeneous source and destination
  publication, exact source tuples and private-cut Tree refusal. Review keeps
  case 12 scoped until a discriminating nested effective-domain witness exists.
  PROV-31/PROP-5 permit the current single-domain backend to refuse unsupported
  placement. No specification contradiction or mixed-domain acceptance claim
  follows that limitation. A legal closing graft-override refusal must still
  distinguish actual occurrence-policy resolution under PROP-1/PROP-2 from
  substitution of the configured label; no production policy change is made.
  The complete nested/repeated-root candidate now includes that legal closing
  graft override on a shared physical root. Review verifies independent actual
  path-policy resolution, legal reference ordering and a genuine credential
  permitting both domains. The unsupported-placement refusal precedes head,
  chunk and candidate-root effects, with the homogeneous paired-publication
  control preserved. Its exact combined case passes run
  `b463ba3e-67d9-40bc-853e-43d1216a3c5f`, followed by both mandatory formatters.
  Nine of nineteen boundary contracts now have reviewed passing evidence;
  full native gates and task merge remain open. An initial misspelled filter
  selected zero tests and is retained as a failing observation, not qualification.
  Full review of the copied-attribute producer fixture verifies an actual
  same-content metadata edit with a public producer distinct from its content
  introducer, retained independent original authority, and precise refusal of
  byte-identical attributes from a private producer on an existing public head.
  Its paired stripped-attribute control and source-erased destination reopening
  preserve the earlier public producer. The exact combined case passes run
  `bc4e7509-9f93-4008-805f-a95ec7d547d8`, followed by both mandatory formatters.
  Ten of nineteen boundary contracts now have reviewed passing evidence;
  complete native qualification and formal task merge remain open.
  The public-introducer/ancestry fixture also passes full review: separately
  initialized real group claims and signing keys distinguish public baseline
  and direct selectors from private attestation. An ordinary public descendant
  retains its introducing commit, accepted-by evidence and provenance walk;
  destination-only reopening after source erasure preserves the public boundary.
  Its exact combined case passes run `d7bec2fe-111d-49ba-8bcf-91db322d0c4a`,
  followed by both mandatory formatters. Eleven of nineteen boundary contracts
  now have reviewed passing evidence. Complete native gates remain required.
  Two further original-control fixtures pass full review and combined exact
  execution: independently retained original ref/ACL survives complete source
  erasure and destination-only reopen, while canonical changed import policy
  fails its exact retained binding; actual copied destination binding/trust and
  a different genuine historical key are refused with unchanged whole heads.
  Exact restoration succeeds after each refusal. The ACL negative is a changed
  bound record, not a re-signed originally unauthorized Commit. The combined
  run passes both cases (`adf2a80a-098d-4009-9ba1-2b1692a8d5ab`); both mandatory
  formatters also pass on that source. Thirteen of nineteen boundary contracts
  now have reviewed passing evidence; full native conformance remains open.
  Full review also accepts the raw-kind and domain-scope fixtures. The raw
  tree, whiteout, conflict and index refusals use only candidate-reachable
  uploads, with a genuine file admission control. Canonical overlay/index
  refusal does not qualify positive native whiteout application or index
  rebuilding. Independent real source/destination domain caveats are checked
  before deduplication despite an existing byte-identical destination chunk;
  actual public-to-private reference refusal preserves the authorized paired
  private-to-public control. All fifteen reviewed mandatory boundary contracts
  now pass together on the updated combined source (run
  `32006d9f-b178-45e7-b76d-b9327edfd760`, fifteen selected, 377 unrelated
  tests skipped), with both mandatory formatters passing on the same source.
  Historical rotation, complete current-authority changes, positive whiteout
  application and positive index rebuilding remain mandatory and unqualified.
  The rotation fixture is stopped on an actual prerequisite: configured local
  disclosure roles are selected Guard snapshot inputs, so changing a role's
  interval or replacing its key cannot pass ordinary reopen's exact snapshot
  check. Qualifying the PROV-26/DOM-24 rotation fixture requires genuine bounded
  setup and an authorized selection transition; a changed role file, relabeled
  key or weakened reopen check cannot qualify ordinary rotation. No such bypass
  or task advancement occurs.
  A shared test-only prerequisite now observes an actual retained Candidate
  slot for one physical publication control and ref before native dispatch's
  final checks. It delays the unchanged effect without retaining a mutex or
  adding a production callback. Three exact tests pass (run
  `3f58c8c6-2f7b-4bb9-8745-235b2ccc1bf1`), including genuine slot publication
  and independently retained wall-clock state; the native build and both
  mandatory formatters pass. The initial fixture confused authoring control
  with publication control and failed; its corrected path comes from the
  held backend's checked physical registration. All original commands finish
  before that correction, and all corrected inputs stay frozen through the
  final commands. Strict native Clippy retains the same 21 production and
  two test unused-path diagnostics. The actual trunk aggregate still fails
  missing public core-fuzz inputs. This prerequisite does not qualify the
  complete current-authority contract or advance the task.
  Full review and combined execution now qualify the current-authority case.
  Independently initialized private source and public destination factories
  expire each genuine attenuated token at the actual Candidate slot, retain
  competing authority transitions until release, and require exact Read or
  Commit denial. Fresh valid tokens still succeed at the advanced clock.
  The same-epoch destination change distinguishes a stale whole head from
  valid current-parent provenance; separate current epochs, token scopes and
  canonical-root ACL changes are checked against historical source selection.
  All sixteen reviewed mandatory cases pass together on the clean combined
  candidate (run `497e74ec-4581-4da0-9a40-84a6f9cfc6b0`, sixteen selected,
  380 unrelated tests skipped). Three equivalent prior fixture lint corrections
  preserve their precise refusal assertions and separately pass all three
  owning tests. Strict isolated native Clippy still rejects seven production
  and two test unused-path diagnostics; none are suppressed. Both mandatory
  formatters pass on the combined source. Its actual full aggregate fails
  `property-resolution` because D-101's exact owner-binding case is absent;
  T-DRV-3 implements that prerequisite separately. Earlier backend retirement
  failures remain unresolved. No formal task merge or checkbox advances.
  Historical rotation, positive whiteout application and positive index
  rebuilding remain mandatory and unqualified. Whiteout review identifies
  missing contextual native layer verification and recipe admission: existing
  signed Commit/root and ordered overlay-recipe formats can carry the inputs,
  but raw layer roots cannot replace checked original and current evidence.
  Ordinary tree loading must continue rejecting whiteouts. No new byte field,
  global decoder fallback or substitute positive fixture is introduced.
  — satisfies PROV-1 to PROV-31;
  `checks.terrane.gates.prov-commit-signature`,
  `checks.terrane.gates.prov-selector-presets`,
  `checks.terrane.gates.prov-commit-verify`,
  `checks.terrane.gates.prov-disclosure-boundary`.
- [ ] **T-DOM-1** Domain property semantics, cross-domain reference checks,
  dedup scoping, existence-oracle rules and durable disclosure evidence.
  Special tree, whiteout, conflict and index disclosure remain required;
  file/directory-marker/symlink certificates alone do not qualify DOM-7.
  Eight reviewed native domain paths now supply guarded root/domain bindings,
  independent storage, namespace configuration and administrative request types.
  Their complete source matches the reference candidate; no manifest, lockfile,
  Guard or publication interface changed. Mandatory repository formatting passes.
  The subsequent reviewed Guard source adoption resolves those missing symbols.
  After reviewed ref-advance adoption, the native production build and strict
  rustdoc pass. Reviewed SDK prerequisites now allow native tests to execute;
  full Nextest passes 352 of 359 tests and the aggregate fails the backend
  retirement compatibility assertion in `index-generation-manifest`. Actual
  current-authority disclosure, deletion and domain gates remain incomplete.
  Index disclosure is stopped on a pre-freeze prerequisite gap: DRV-13 requires
  an owner-root property binding from attribute name to index root, but the
  registered `index` property contains only required attribute names. Existing
  opaque-index codecs and explicit `TreeUse::Index` interpretation supply no
  registered binding carrier or native read dispatch. PROP-3/CONV-3 forbid an
  invented property, and optional derived refs cannot replace DRV-23 correctness.
  The DOM-7/PROV-30 native index-rebuild case remains mandatory and unqualified;
  its operational dependency belongs to T-DRV-2. No branch workline is started,
  encoding is not frozen, and no pure-codec result substitutes for that case.
  A read-only ordering audit identified the former cycle: completed T1
  is needed before B-derive, while this positive native case currently requires
  T-DRV-2's rebuilding operation before T1 can exit. PROV-30/DOM-7 forbid index
  certificates and permit safe materialization or authorized full-source
  retention; they do not independently mandate native rebuild availability.
  AD-11 below resolves this task-ordering cycle. Raw index refusal
  and independent current attribute-producer checks remain T1 obligations;
  no branch work, guessed binding carrier or weaker current-policy rule follows.
  A broader ordering audit finds that moving this positive contract to B-derive
  alone would also violate trunk MVP requirements: CI-3 requires the SHA-256
  CAS index at T4, while AD-5/SBX-12 require an index-tree descriptor lookup at
  T5. T-SBX-4's temporary per-object lookup contradicts SBX-12. Index-specific
  prerequisites therefore need a D-n-backed trunk ordering correction that
  preserves same-commit incremental maintenance and DRV-16/17
  verification/rebuild. D-103 explicitly replaces DRV-14's hard bound with
  DRV-29's expanded-change and canonical-resynchronization accounting.
  DRV-13's owner binding and detached recipe association also need an explicit
  acyclic registered format; an index containing its owner's hash would cycle
  with the owner's reference to that index. Finally, SBX-11's media-type and
  length-framed descriptor SHA-256 differs from DRV-6's plaintext SHA-256;
  their lookup keys cannot silently be treated as interchangeable. These are
  unresolved specification/integration prerequisites, not permission to start
  branch work or substitute a weaker gate.
  D-99 corrects DRV-18's existing trigger to use the registered `sha256` hash
  name and `hash.sha256` attribute name in their respective property sets;
  its complexity and authorization obligations are unchanged. This editorial
  namespace correction does not resolve the carrier, ordering or framed
  descriptor prerequisites, and no native index capability is claimed.
  AD-11 now resolves the task-ordering cycle by placing T-DRV-2 in T1 and
  adding both of its gates to the milestone exit set. The positive native
  index case stays mandatory; no B-* workline starts. D-100 explicitly
  replaces the filtered-output cost bound with DRV-24's candidate and
  current-check accounting. Acyclic binding, executable recipe, occurrence
  evidence and the framed descriptor bridge remain unresolved prerequisites.
  — satisfies DOM-1 to DOM-11, DOM-16, DOM-17, DOM-20, DOM-24;
  `checks.terrane.gates.dom-reference-order`,
  `checks.terrane.gates.dom-dedup-scope`.
- [ ] **T-CRATE-1** SDK types and verbs (`Tree`, `View`, `Store`,
  `Repository`, `fork`, `commit`, `merge`, `diff`, `realize`) and the `sdk`
  surface (checkout to a directory). All 21 reviewed native repository and
  surface paths are integrated, including protected local retention, canonical
  directory import, authorized reads and registered SDK checkout. Actual
  factory tests pass genuine legacy refusal, protected bootstrap and reopening
  with a damaged mutable capability cache; non-Send `std,wasm` passes 116 tests.
  Snapshot path authorization reuses only the current tree verified within
  that same call, avoiding a duplicate complete history traversal. Five actual
  regressions pass live ACL revocation, scoped content/hash access, removed
  named roots, ordinary-file boundary refusal and protected bootstrap loss.
  Every entry, file and chunk still receives fresh authorization. The 116
  non-Send tests, strict native rustdoc and mandatory formatting pass; the
  actual trunk aggregate remains red on index-generation retirement.
  Target snapshot construction also retains the complete history verified
  within that same invocation. Eight expanded regressions pass, including
  protected registration, consumed inputs and held expiry/issuer retirement;
  all 116 non-Send tests, strict native rustdoc and mandatory formatting pass.
  This removes a duplicate target-history observation, preserving subsequent
  current-policy and content checks rather than promising identical I/O timing.
  Documented `Chunk`, `Object`, `Ref` and `Root` SDK names now reuse the
  canonical core representations. Strict core Clippy, core/native rustdoc,
  `formats-no-std`, and both mandatory formatting commands pass for this facade.
  An isolated SDK read candidate removes redundant target verification when a
  trusted live policy reference is configured. Its two genuine factory
  regressions pass current ACL revocation and protected original-association
  loss after a prior successful read. Seven existing security regressions also
  pass, including named-root removal, scoped content, actual physical original
  authority and held expiry. The actual feature matrix passes both 439-case
  core runs and 73 portable cases; native execution passes 354 of 361 tests,
  with six known backend failures and the unchanged cancellation failure.
  The full aggregate remains red on the backend retirement assertion. Direct
  complete native qualification builds successfully and passes 355 of 362
  tests, with the same six backend failures and the unchanged cancellation
  arrival failure; no test times out. All 116 non-Send portable tests pass.
  Strict Clippy still rejects the known twenty production and two test dead-code
  diagnostics. The stricter documentation check identifies four undocumented
  public store-error fields; their comments-only correction passes native
  rustdoc with warnings and missing documentation denied, plus both mandatory
  formatting commands. The original-authority fallback now has an isolated
  single-traversal candidate, whose native build and formatting pass; its
  ten focused native regressions pass, including a genuine original-reference
  fallback with unchanged trusted configuration. Its final full native run
  passes 356 of 363 tests with the same seven failures and no timeouts; all
  116 portable tests and strict native rustdoc also pass. Its final Nix feature
  matrix passes both 439-case core runs and 73 portable cases, then fails with
  355 of 362 native passes and the same seven failures. The actual aggregate
  fails `prov-commit-verify` because the 19 required disclosure cases remain
  unqualified; the named repository and surface architecture checks also fail
  explicitly as pending. Both mandatory formatting commands pass.
  This candidate is unmerged and does not qualify the task.
  Pure core view, endpoint, exposure
  and schema vocabulary is integrated as an SDK prerequisite. View parsing
  rejects an explicit empty subtree and normalizes the grammar's optional
  trailing directory separator. All 439 core tests, strict core Clippy and
  rustdoc, `formats-no-std`, and both mandatory formatting commands pass.
  This does not qualify runtime surfaces or complete the exposure configuration.
  The integrated binary still has only its T0 configuration/role launcher.
  The reviewed local command frontend remains on its isolated task branch.
  Its latest unchanged suite passes two tests and times out in the whole
  workflow at 120 seconds: initialization, directory commit, fork, independent
  branch commits, merge and registered merged checkout finish, but fixed-commit
  checkout does not return before the deadline. A prior source snapshot passed
  all three tests in 106.45 seconds. Variable publication timings do not prove
  a regression from the target-history correction; current complete-workflow
  qualification remains open. This branch stays unmerged while aggregate
  qualification is red.
  A subsequent isolated CLI preview on the reviewed SDK read candidate passes
  all three CLI tests in 103.198 seconds with the unchanged 120-second limit.
  It covers the complete separate-process workflow and fixed historical
  checkout. Strict CLI rustdoc and both mandatory formatting commands pass.
  Its actual feature matrix still fails with the same seven native failures,
  strict Clippy rejects inherited unfinished native paths, and the aggregate
  fails on the 19 unqualified disclosure cases. This single workflow pass does
  not establish package, ext4 or complete task qualification; both candidates
  remain unmerged.
  Its fresh feature matrix passes both 439-test core runs and 73 portable
  native tests, then fails with 351 native passes and eight failures, including
  a multiwriter join expiry. The release package builds, but its unchanged
  full suite runs 802 tests: 786 pass, fourteen fail and two time out. Seven
  shared ref operations expire under aggregate load; the CLI workflow and
  descendant-policy regression exceed their unchanged 120-second limits.
  The isolated workflow pass therefore does not establish package qualification.
  Strict native Clippy still fails on twenty production and two test dead-code
  diagnostics; the latest shared correction adds none. The cancellation-only
  native-read fixture candidate remains an unmerged WIP: its latest full run
  passes 353 of 360 tests, with six backend failures and the unchanged
  two-second cancellation-barrier arrival failure. No successful Terrane ext4
  workflow qualification artifact is present;
  the earlier claim of registration does not establish qualification. The scoped
  descendant-only policy diff correction is integrated; its real protected-factory
  regression passes with unchanged scope and admission checks. The actual feature
  matrix still fails on six backend compatibility cases and the cancellation
  waiter; the trunk aggregate fails the index-generation retirement assertion.
  The shared `checks.terrane.integration.local-workflow-ext4` registration now
  exists and an actual request fails explicitly as pending. The concrete
  hermetic ext4 VM workflow is not yet adopted on the trunk;
  registration does not qualify local workflow or store conformance.
  The isolated two-file ext4 workflow candidate is implemented and reviewed.
  Its actual VM check builds the genuine release package, but required package
  tests exit with failure before the rootfs or VM can run. No per-test totals
  were emitted, the VM never boots, and no successful artifact exists. The
  actual aggregate also fails on the 19 unqualified disclosure cases. Syntax
  and both mandatory formatting checks pass; package checks remain enabled.
  Both mandatory formatting commands pass. Complete workflow and package
  qualification remain pending; native I/O
  batching preserves every required observation and fence.
  Local bucket/namespace/Guard/coordinator construction is now factored into a
  private helper for the paired-recovery implementation. Ordinary initialization
  and reopen still call their original strict retention factories; no pending
  repository is returned to ordinary callers. The actual hermetic
  `local-factory-construction` check passes both existing protected bootstrap
  and directory-edit/reopen regressions, with exact nonempty selections.
  Mandatory formatting passes. Its two inherited native dead-code warnings
  remain visible; this targeted check does not establish strict native Clippy
  or complete paired recovery, which remains on its task branch.
  — satisfies CRATE-22 to CRATE-27;
  `checks.terrane.gates.feature-matrix`.

### T2 — Host tier

Deployable as: one machine that holds a local cache of any commit, seals
objects, and exposes them to the `sdk` surface, with the `serve`,
`realize`, `publish`, and `gc` roles as systemd units. No FUSE yet.

Freezes: the surface interface and the exposure record.

Exit gates: `checks.terrane.gates.host-crash-recovery`,
`checks.terrane.gates.host-publish-sequence`,
`checks.terrane.gates.surface-interface`,
`checks.terrane.gates.role-selection`.

- [ ] **T-HOST-1** `disk` tier layout, verify-before-admit, quarantine,
  reassembly modes `never` and `always`, S3-FIFO eviction, pins,
  reservations, exact quotas, wipe modes `none` and `zero`, two-phase
  delete, embedded state scope, crash recovery, circuit breaker toward
  lower tiers. Narrowed to trunk scope: `smart` reassembly and the
  `discard` and `volatile` wipe modes are T-HOST-3 on B-consistency. —
  satisfies OBJ-5 jointly with T-BKT-1, HOST-1 to HOST-5, HOST-11 to
  HOST-25, HOST-27 to HOST-36,
  BKT-15; `checks.terrane.gates.host-layout`,
  `checks.terrane.gates.host-eviction-s3fifo`,
  `checks.terrane.gates.host-verify-before-admit`,
  `checks.terrane.gates.host-crash-recovery`.
- [ ] **T-HOST-2** `publish` role: networkless sealer with fs-verity,
  no-replace publication, adoption on recovery. — satisfies HOST-6 to
  HOST-9, ARCH-8; `checks.terrane.gates.publisher-sole-writer`,
  `checks.terrane.gates.host-publish-sequence`.
- [ ] **T-STORE-3** `shared-dir` backend and per-domain object directories.
  — satisfies STORE-14, DOM-12 to DOM-15, HOST-27;
  `checks.terrane.gates.shared-dir-read-only`,
  `checks.terrane.gates.dom-host-isolation`.
- [ ] **T-SURF-1** Surface interface, exposure records, schema validation,
  TOML configuration, status reporting, in-process registry, ownership and
  timestamp presentation, and privileged xattr filtering. — satisfies
  TREE-9, TREE-10, TREE-15, SURF-1 to SURF-32, CRATE-17, CRATE-28;
  `checks.terrane.gates.surface-interface`,
  `checks.terrane.gates.surface-schema`,
  `checks.terrane.gates.surface-status`.
- [ ] **T-PKG-3** `modules/terrane/` options, unit rendering for the
  `serve`, `realize`, `publish`, and `gc` roles, and the module evaluation
  check. — satisfies PKG-8, PKG-10; `checks.terrane.module-eval`.

### T3 — Wire protocol and buckets

Deployable as: one warehouse and N hosts. A host runs
`routed[disk, remote(warehouse)]`; the warehouse runs `guard(bucket)` over
Garage, an S3-compatible bucket, a GCS bucket, or a `file://` root.

Freezes: the wire protocol and the token format.

Exit gates: `checks.terrane.gates.proto-conformance`,
`checks.terrane.gates.bucket-probe`,
`checks.terrane.gates.auth-single-enforcement`, store conformance on
Garage.

- [ ] **T-PROTO-1** ConnectRPC services from `spec/reference/protocol.md`:
  content, ref, tier; negotiation; `PutPack`; presigned reads; `GetRange`;
  bundles; watch; index deltas; error codes; versioning; presigning in the
  `serve` role. — satisfies PROTO-1 to PROTO-55;
  `checks.terrane.gates.proto-transport`,
  `checks.terrane.gates.proto-negotiate`,
  `checks.terrane.gates.proto-presign`, `checks.terrane.gates.proto-errors`.
- [ ] **T-STORE-2** `routed`, `guard`, `cache`, `remote` combinators and the
  store expression parser and validator. `routed` selects in configured
  order with circuit breakers. Narrowed to trunk scope: cost-sorted
  selection is T-TOPO-2 on B-topology. — satisfies STORE-10, STORE-15 to
  STORE-29, STORE-31; `checks.terrane.gates.routed-read-order`,
  `checks.terrane.gates.routed-write-authority`,
  `checks.terrane.gates.store-expression-validate`,
  `checks.terrane.gates.store-ref-forwarding`.
- [ ] **T-BKT-2** `bucket` backend over the S3-compatible API (reusing
  `aos-net` and `aos-hub-core` signing): conditional writes, multipart
  abort, opaque version tokens, ranged-`GET` probe, tested against the
  AOS-built Garage in a Nix check. — satisfies BKT-5, BKT-9 to BKT-12;
  `checks.terrane.gates.bucket-ref-cas`,
  `checks.terrane.gates.bucket-create-once`,
  `checks.terrane.gates.bucket-etag-opaque`,
  `checks.terrane.gates.bucket-multipart-abort`,
  `checks.terrane.gates.bucket-probe`.
- [ ] **T-BKT-3** `bucket` backend over Google Cloud Storage: V4 signed
  URLs for presigned reads, `x-goog-if-generation-match` preconditions for
  refs and create-once keys, resumable uploads with abort, service-account
  and instance-metadata credentials. Tested locally against a recorded
  fixture; the live probe is manual and recorded in
  [`06-decision-register.md`](06-decision-register.md). — satisfies BKT-5,
  BKT-6, BKT-9 to BKT-12 for the GCS provider row, CI-2;
  `checks.terrane.gates.bucket-probe`,
  `checks.terrane.integration.gcs-fixture`.
- [ ] **T-RISK-1** Conditional-write probe against a `file://` root and the
  AOS-built Garage, recording which report `refs: cas` and which downgrade
  to `single-writer`. Narrowed to trunk scope: probes against R2, S3, GCS,
  and other S3-compatible stores are T-RISK-5, run by hand. — satisfies
  RISK-1, BKT-10, BKT-11, TEST-7;
  `checks.terrane.gates.bucket-probe`.
- [ ] **T-TOPO-1** Locality labels on every store, hop accounting and hop
  limits, circuit breakers, `home` on every root with CAS executed at home,
  and the fixed-order selection rule for local tiers before remote ones.
  Narrowed to trunk scope: cost vectors, peers, residency, warming,
  promisor-style misses, replication, and partition behavior are T-TOPO-2
  on B-topology. — satisfies TOPO-1 to TOPO-3, TOPO-7, TOPO-9 to TOPO-14,
  TOPO-26, TOPO-27; `checks.terrane.gates.topo-labels`,
  `checks.terrane.gates.topo-hops`, `checks.terrane.gates.topo-breaker`,
  `checks.terrane.gates.topo-home`.
- [ ] **T-BW-1** Ancestry and Merkle negotiation, chunk negotiation
  restricted to the tree diff, bounded batched `has`, watch instead of
  polling, whole-pack threshold, bundles of missing nodes only, multiplexed
  control messages. Narrowed to trunk scope: filters, wire deltas,
  dictionaries, peers, and replicate-once are T-BW-2 on B-bandwidth. —
  satisfies BW-1 to BW-4, BW-7 to BW-9, BW-17, BW-20 to BW-22;
  `checks.terrane.gates.bandwidth-negotiate-delta`.
- [ ] **T-AUTH-2** `guard` enforcement, ACL properties, grant evaluation,
  presigned-read minting, host-held tokens, surface commit attenuation,
  expiry and epoch revocation, and two workload issuers: a static-key
  issuer that mints from a file-held signing key, and a GCP
  instance-identity issuer that exchanges a GCE instance identity token for
  a Terrane token bound to the instance and its declared job. Narrowed to
  trunk scope: OIDC device flow, browser session exchange, mTLS, and key
  retirement are T-AUTH-3 on B-auth. — satisfies AUTH-1, AUTH-3, AUTH-5,
  AUTH-6, AUTH-23 to AUTH-37, AUTH-41 to AUTH-43, CI-4, CI-5;
  `checks.terrane.gates.auth-workload-mint`,
  `checks.terrane.gates.auth-acl-intersection`,
  `checks.terrane.gates.auth-single-enforcement`,
  `checks.terrane.gates.auth-surface-commit-scope`,
  `checks.terrane.integration.gcp-instance-issuer`.
- [ ] **T-CONS-1** Writer modes `manual` and `periodic`, durability levels
  `local` and `region`, epoch fencing, reader modes with atomic `follow`
  switch, the consistency table. Narrowed to trunk scope: `sync` mode,
  `zone` and `regions(k)` durability, and `writers=many` are T-CONS-2 on
  B-consistency. — satisfies CONS-4 to CONS-9, CONS-11 to CONS-20, CONS-28
  to CONS-33; `checks.terrane.gates.cons-writer-modes`,
  `checks.terrane.gates.cons-fencing`,
  `checks.terrane.gates.cons-follow-atomic`,
  `checks.terrane.gates.cons-table`.
- [ ] **T-OBS-1** Status surface over the CLI and API (`status`, `tiers`,
  `exposures`), structured logs with trace ids, security-relevant log
  events, reflog blame, and the metric set. Narrowed to trunk scope: hop
  spans, trace propagation across tiers, decision logs, and metrics export
  are T-OBS-2 on B-ops. — satisfies OBS-7 to OBS-11, OBS-13, OBS-14, OBS-16,
  OBS-17; `checks.terrane.gates.obs-status-surface`,
  `checks.terrane.gates.obs-metrics`, `checks.terrane.gates.obs-blame`.
- [ ] **T-TEST-2** Protocol conformance client and server and the security
  suite. Narrowed to trunk scope: tier chaos beyond corrupt and slow
  children is T-TEST-4 at T6 and T-TEST-5 on B-topology. — satisfies
  TEST-6, TEST-13, TEST-14; `checks.terrane.gates.proto-conformance`.

### T4 — CI caches

Deployable as: the shared cache for CI, as described in
[`07-ci-caches.md`](07-ci-caches.md). Stock `nix`, `bazel`, and the GitHub
Actions cache client use it through the three protocol surfaces; spot-VM
runners run `terrane` in the `realize` role with an ephemeral `disk` tier.

Exit gates: `checks.terrane.gates.nix-frame-concat`,
`checks.terrane.gates.reapi-completeness`,
`checks.terrane.integration.ci-fork-fold`, stock `nix`, `bazel`, and the
GitHub Actions cache client exercised end to end in a Nix check.

- [ ] **T-NIX-1** `nix-cache` surface: schema, narinfo, zero-CPU `.nar.zst`
  streaming, store-path lookups, writable uploads, bearer credential
  mapping. Lookups use path-keyed lookup in the canonical root whose entry
  names begin with the store-path hash, as permitted by NIX-9; T-DRV-2's
  indexes are already a trunk prerequisite. T-NIX-2 replaces this lookup
  with a store-path index without making the SHA-256 CAS index optional.
  — satisfies
  NIX-1 to NIX-8, NIX-10 to NIX-13;
  `checks.terrane.gates.nix-frame-concat`,
  `checks.terrane.gates.nix-surface-stream`.
- [ ] **T-REAPI-1** `reapi` surface: `cas/` and `ac/` schema, SHA-256
  addressing through `hash.sha256`, `FindMissingBlobs` from the tree,
  ByteStream, Capabilities, upload validation, writer mode, bearer and
  header credential mapping. — satisfies REAPI-1, REAPI-2, REAPI-4 to
  REAPI-8; `checks.terrane.gates.surface-schema`.
- [ ] **T-REAPI-2** REAPI completeness checking: `GetActionResult` verifies
  every referenced output blob is present before returning, touching the
  blobs it checks so eviction keeps them. — satisfies REAPI-3;
  `checks.terrane.gates.reapi-completeness`.
- [ ] **T-GHA-1** `gha-cache` surface: `<version>/<key>` schema, reserve
  and ranged upload and commit, exact-then-prefix restore by range scan,
  upload deadline, bearer credential mapping through the exposure's issuer.
  — satisfies GHA-1 to GHA-3, GHA-5 to GHA-8;
  `checks.terrane.gates.surface-schema`.
- [ ] **T-CI-1** PR fork and fold policy: the runner-facing view is a
  branch forked from `refs/heads/ci/master` into `refs/heads/ci/pr/<n>` at
  job start, the job's token carries `fork` on master and `commit` on its
  own branch only, and a trusted post-merge job holding `commit` on master
  folds the branch by merge and retires it. — satisfies CI-1, CI-3, CI-6
  to CI-8, GHA-4, spec ALG-32 to ALG-35, AUTH-23;
  `checks.terrane.integration.ci-fork-fold`.
- [ ] **T-CI-2** Credential mapping per surface: the GitHub Actions job
  token and the Bazel and Nix bearer headers are exchanged, through the
  exposure's issuer, for an attenuation of the runner's workload token
  scoped to the job's branch; every mapping is one of the SURF-21 forms and
  is tested for non-widening. — satisfies CI-9, CI-10, spec SURF-20 to
  SURF-23, PROV-25; `checks.terrane.integration.ci-credential-map`.
- [ ] **T-CI-3** Runner role configuration: a `terrane` configuration
  profile for a spot VM with an ephemeral `disk` tier sized from the
  instance, `routed[disk, remote(warehouse)]`, presigned direct reads from
  GCS, `periodic` writer mode with a bounded interval, and warm-from-bucket
  at boot for the view's bundle. — satisfies CI-11 to CI-14, spec CONS-9,
  HOST-35; `checks.terrane.integration.ci-runner-profile`.
- [ ] **T-CI-4** Client configuration and end-to-end check: `nix` with the
  surface as a substituter and post-build upload, `bazel` with
  `--remote_cache` and `--remote_header`, and the GitHub Actions cache
  client pointed at the surface, all exercised against one warehouse in a
  Nix check. — satisfies CI-15 to CI-17;
  `checks.terrane.integration.ci-clients`.

### T5 — Sandboxes

Deployable as: the RFC-0021 sandbox view service
([`01-sandbox-runtime.md`](01-sandbox-runtime.md)). T5 does not depend on
T4 and MAY be worked concurrently with it; it merges after T4.

Exit gates: `checks.terrane.gates.fuse-passthrough`,
`checks.terrane.integration.viewd-role`,
`checks.terrane.gates.perf-nested-zero-dup`, and RFC-0021's existing view
conformance tests passing over Terrane.

- [ ] **T-RISK-4** FUSE passthrough and overlay-over-FUSE exec on the AOS
  6.18 kernel: prove `FUSE_DEV_IOC_BACKING_OPEN` registration through
  `aos-mountd` and that exec of a passthrough-backed binary succeeds. —
  satisfies RISK-10, RISK-11, FUSE-13, FUSE-39;
  `checks.terrane.gates.exec-through-overlay`.
- [ ] **T-FUSE-1** Structural index compiler and mmap reader. — satisfies
  FUSE-7 to FUSE-12; `checks.terrane.gates.fuse-index-roundtrip`.
- [ ] **T-FUSE-2** FUSE worker: passthrough, fallback, inode policy,
  attributes, open path, coalescing, mount options, leases, drain. —
  satisfies FUSE-1 to FUSE-6, FUSE-13 to FUSE-31, FUSE-43 to FUSE-50,
  ARCH-7, ARCH-11; `checks.terrane.gates.fuse-worker-isolation`,
  `checks.terrane.gates.fuse-passthrough`,
  `checks.terrane.gates.fuse-verify-before-serve`.
- [ ] **T-FUSE-3** Writable exposures: overlay upper, quota, commit walk,
  the `.terrane` control directory, `manual` and `periodic` commit.
  Narrowed to trunk scope: `fsync` binding in `sync` mode and redirections
  are T-FUSE-4 on B-consistency. — satisfies FUSE-32 to FUSE-35, FUSE-40
  to FUSE-42, CONS-1 to CONS-3, CONS-10 (the `manual` and `periodic`
  clauses), CONS-13, CONS-24 to CONS-27, CONS-34 to CONS-37, TEST-5;
  `checks.terrane.gates.merge-native-parity`,
  `checks.terrane.gates.fuse-upper-isolation`,
  `checks.terrane.gates.cons-fsync-sticky`,
  `checks.terrane.gates.cons-control`.
- [ ] **T-SBX-1** `terrane serve` as `aos-viewd`, `terrane publish` as the
  publisher, worker units in `aos-view-services.slice`, no privileged
  mounts. — satisfies SBX-1 to SBX-5, PKG-8, PKG-9;
  `checks.terrane.integration.viewd-role`,
  `checks.terrane.integration.publisher-role`,
  `checks.terrane.gates.no-privileged-mounts`.
- [ ] **T-SBX-2** Attachments as exposures; view-mode mapping; durable
  attachment records; `follow` replacement through `aos-mountd`. —
  satisfies SBX-6 to SBX-8; `checks.terrane.integration.view-modes`,
  `checks.terrane.integration.attachment-record`,
  `checks.terrane.integration.follow-replace`.
- [ ] **T-SBX-3** Disclosure-domain mapping and strict placement. —
  satisfies SBX-9, SBX-10; `checks.terrane.integration.domain-map`.
- [ ] **T-SBX-4** `aos-sandbox-v1` identity profile, SHA-256 attributes on
  sandbox roots, portable-tree adapter, `ObjectSource` and
  `ImmutableFetchTransport` implementations. Indexed descriptor resolution
  consumes the completed T-DRV-2 machinery; a per-object record lookup
  does not satisfy the one-index lookup requirement. The exact framed
  descriptor bridge still requires its separate normative correction.
  — satisfies SBX-11 to SBX-17;
  `checks.terrane.integration.identity-profile`,
  `checks.terrane.integration.object-source`,
  `checks.terrane.integration.fetch-transport`.
- [ ] **T-SBX-5** Nix store union views and nested `shared-dir` sandboxes;
  capacity and memory wiring. — satisfies SBX-18 to SBX-21;
  `checks.terrane.integration.nix-union`,
  `checks.terrane.gates.perf-nested-zero-dup`.
- [ ] **T-PKG-4** `fuse-worker` units and the `aos-view-services.slice`
  wiring in `modules/terrane/`. — satisfies PKG-8, PKG-9;
  `checks.terrane.module-eval`.

### T6 — Hardened MVP

Deployable as: the same system as T5, trusted. Ends with the MVP
conformance claim (PLAN-3).

Exit gates: `checks.terrane.gates.host-crash-recovery`,
`checks.terrane.gates.tier-chaos` (corrupt and slow children),
`checks.terrane.gates.perf-methodology`, `checks.terrane.plan-coverage`.

- [ ] **T-TEST-4** Crash recovery of every trunk role at every fsync point;
  chaos with a corrupt child and a slow child; conformance runs on
  `file://`, Garage, and the GCS fixture. — satisfies TEST-8 (the corrupt
  and slow cases), TEST-9; `checks.terrane.gates.host-crash-recovery`,
  `checks.terrane.gates.tier-chaos`.
- [ ] **T-PERF-1** Performance harness with the measurement methodology and
  every `gate:perf-*` check implemented and reported. Narrowed to trunk
  scope: the gates report but do not block; blocking thresholds on
  reference hardware are T-PERF-2 on B-ops. — satisfies PERF-1 to PERF-12,
  TEST-15; `checks.terrane.gates.perf-methodology` and each
  `checks.terrane.gates.perf-*` in reporting mode.
- [ ] **T-TEST-3** The MVP conformance claim for Core, Distribution
  (fixed-order routing), Security (workload issuers), Host, and the `fuse`,
  `sdk`, `nix-cache`, `reapi`, and `gha-cache` surfaces, with the partial
  files and their completing branches listed; the plan-coverage lint. —
  satisfies TEST-16 to TEST-18, PERF-13, PLAN-2, PLAN-3;
  `checks.terrane.gates.registry-complete`,
  `checks.terrane.plan-coverage`.
- [ ] **T-PKG-5** Operator documentation under `docs/`: warehouse and host
  deployment, runner profile, backup and restore of a bucket, GC
  operation, and the status surface. — satisfies PKG-11;
  `checks.terrane.docs`.

## Branches

### B-derive — Additional tree algebra and rulesets

Forks from T1. Merge gates: `checks.terrane.gates.derivation-memo`,
`checks.terrane.gates.index-tree-maintenance`,
`checks.terrane.gates.ruleset-eval-order`.

T-DRV-2 is a T1 trunk task under AD-11. This workline extends its common
memo/evaluation machinery for additional operations and keeps both existing
index gates green; it does not supply an MVP index prerequisite.

- [ ] **T-ALG-3** `filter`, `map`, set operations, and recipes for every
  composite kind. Deferred from T-ALG-2. — satisfies ALG-22 to ALG-27;
  `checks.terrane.gates.algebra-diff`.
- [ ] **T-RULE-1** Ruleset IR, compiler to recipes, evaluator, and portable
  policy encoding. — satisfies RULE-1 to RULE-28;
  `checks.terrane.gates.ruleset-eval-order`,
  `checks.terrane.gates.ruleset-derived-root`,
  `checks.terrane.gates.ruleset-magic-memo`,
  `checks.terrane.gates.ruleset-blessed-targets`.
- [ ] **T-NIX-2** Replace the `nix-cache` surface's store-path map with the
  index tree required by NIX-9. — satisfies NIX-9;
  `checks.terrane.gates.nix-surface-stream`.

### B-redundancy — Replication, striping, block device

Forks from T1. Merge gates:
`checks.terrane.gates.redundancy-striped-reconstruct`,
`checks.terrane.gates.redundancy-quorum-refs`,
`checks.terrane.gates.blockdev-crash-recovery`.

- [ ] **T-RED-1** `replicated` and `striped` combinators, placement, verify
  and repair, scrub and resilver jobs, quorum refs, federation. —
  satisfies RED-1 to RED-33; `checks.terrane.gates.redundancy-replicated-ack`,
  `checks.terrane.gates.redundancy-striped-reconstruct`,
  `checks.terrane.gates.redundancy-quorum-refs`.
- [ ] **T-BLK-1** `blockdev` backend: superblocks, slab log, index region,
  compaction, recovery scan, hybrid with a `disk` tier. — satisfies BLK-1 to
  BLK-19, HOST-37, CRATE-9; `checks.terrane.gates.blockdev-format-roundtrip`,
  `checks.terrane.gates.blockdev-ref-cas`,
  `checks.terrane.gates.blockdev-crash-recovery`.

### B-jobs — Tree jobs, compaction, migrations, imports

Forks from T1 and B-derive. Merge gates: `checks.terrane.gates.job-resume`,
`checks.terrane.gates.mig-store-move`.

- [ ] **T-JOB-1** Tree job primitive: shards, cursors, checkpoints, fold,
  follow, status, cancellation, in-exposure access. — satisfies JOB-1 to
  JOB-33, DRV-11, PROP-25; `checks.terrane.gates.job-ref-lifecycle`,
  `checks.terrane.gates.job-resume`, `checks.terrane.gates.job-fold`,
  `checks.terrane.gates.job-follow`.
- [ ] **T-GC-2** Pack compaction under the utilization threshold, tree-order
  rewrite, index swap, generation rebuild, rate limiting. Deferred from
  T-GC-1. — satisfies GC-18 to GC-21;
  `checks.terrane.gates.gc-two-phase-delete`.
- [ ] **T-MIG-1** Import adapters (Nix binary cache, REAPI, GHA, OCI, git,
  `terrane-compatible`, `aos-portable-tree`), layout and tree-format
  migrations, chunk-parameter migrations, store moves, splits and joins,
  identity-profile coexistence. — satisfies MIG-8 to MIG-33;
  `checks.terrane.gates.mig-layout-merge`,
  `checks.terrane.gates.mig-store-move`,
  `checks.terrane.gates.mig-digest-coexist`.

### B-storage — EROFS, VM, block surface, Crucible

Forks from T2. Merge gates: `checks.terrane.gates.erofs-image-determinism`,
`checks.terrane.gates.block-layout-determinism`,
`checks.terrane.gates.vm-no-duplication`.

- [ ] **T-EROFS-1** Deterministic EROFS image generation, overlay with
  data-only lower and `verity=require`, lazy mode, `follow` replacement. —
  satisfies EROFS-1 to EROFS-15; `checks.terrane.gates.erofs-image-determinism`,
  `checks.terrane.gates.erofs-verity`.
- [ ] **T-VM-1** virtiofs export with DAX, virtio-pmem option, nested
  instances in guests, guest token attenuation. — satisfies VM-1 to VM-18;
  `checks.terrane.gates.vm-export-scope`,
  `checks.terrane.gates.vm-no-duplication`.
- [ ] **T-VBLK-1** Block surface: deterministic layout, extent map, lazy
  block reads over `vhost-user-blk`, `ublk`, or NBD, read-only. —
  satisfies VBLK-1 to VBLK-13; `checks.terrane.gates.block-layout-determinism`.
- [ ] **T-CRU-1** `DagStore` adapter, shared store, content-id indexing,
  closure trees, block surface for scenario disks, license-boundary scan.
  — satisfies CRU-1 to CRU-11; `checks.terrane.integration.crucible-dagstore`,
  `checks.terrane.integration.crucible-block-surface`,
  `checks.terrane.integration.license-boundary`.

### B-auth — Human login, mTLS, revocation

Forks from T3. Merge gates: `checks.terrane.gates.auth-oidc-login`,
`checks.terrane.gates.auth-mtls`, `checks.terrane.gates.auth-token-chain`.

- [ ] **T-AUTH-3** OIDC device flow for humans, browser session exchange,
  mTLS service principals, issuer key retirement, web-surface session
  rules. Deferred from T-AUTH-2. — satisfies AUTH-2, AUTH-4, AUTH-38 to
  AUTH-40, AUTH-44; `checks.terrane.gates.auth-oidc-login`,
  `checks.terrane.gates.auth-mtls`, `checks.terrane.gates.auth-token-chain`.

### B-topology — Cost routing, peers, regions

Forks from T3. Merge gates: `checks.terrane.gates.topo-selection`,
`checks.terrane.gates.topo-residency`,
`checks.terrane.gates.topo-partition`,
`checks.terrane.gates.gc-multiregion`.

- [ ] **T-TOPO-2** Cost vectors with decay and hysteresis, cost-sorted
  selection, peer discovery and serving, residency filters and `Where`,
  warming, promisor-style cross-region misses, `replicate` policies,
  partition behavior, multi-region GC roots and marks. Deferred from
  T-TOPO-1. — satisfies TOPO-4 to TOPO-6, TOPO-8, TOPO-15 to TOPO-25,
  TOPO-28 to TOPO-42, GC-2, GC-8, GC-25 to GC-27, RISK-12;
  `checks.terrane.gates.topo-selection`,
  `checks.terrane.gates.topo-residency`, `checks.terrane.gates.topo-warm`,
  `checks.terrane.gates.topo-promisor`,
  `checks.terrane.gates.topo-replicate`,
  `checks.terrane.gates.topo-partition`,
  `checks.terrane.gates.gc-multiregion`,
  `checks.terrane.gates.routing-stability`.
- [ ] **T-TEST-5** Tier chaos with a partitioned child and stale refs.
  Deferred from T-TEST-2. — satisfies TEST-8 (the partition cases);
  `checks.terrane.gates.tier-chaos`.
- [ ] **T-RISK-5** Conditional-write probes against R2, S3, GCS, and the
  other S3-compatible stores AOS operates, run by hand with results
  recorded. Deferred from T-RISK-1. — satisfies RISK-1, TEST-7;
  recorded in [`06-decision-register.md`](06-decision-register.md).

### B-bandwidth — Filters, deltas, dictionaries

Forks from T3. Merge gates:
`checks.terrane.gates.bandwidth-wire-delta-roundtrip`,
`checks.terrane.gates.index-filter-hint-only`.

- [ ] **T-PACK-3** Filters per merged shard, fetched by generation delta,
  hint-only semantics. Deferred from T-PACK-2. — satisfies PACK-21 to
  PACK-23, RISK-7; `checks.terrane.gates.index-filter`,
  `checks.terrane.gates.index-filter-hint-only`.
- [ ] **T-BW-2** Locally cached remote filters in negotiation, trained
  dictionaries per content class, wire deltas reconstructed and stored
  whole, `shared-dir` zero-byte accounting, zone peers with egress in the
  cost vector, profile-driven prefetch, replicate-once. Deferred from
  T-BW-1. — satisfies BW-5, BW-6, BW-10 to BW-16, BW-18, BW-19;
  `checks.terrane.gates.bandwidth-wire-delta-roundtrip`,
  `checks.terrane.gates.negotiation-bytes`.

### B-surfaces-more — git, oci, browse, api

Forks from T4. Merge gates: `checks.terrane.gates.surface-schema` for each
surface, and a browser exercised end to end against `browse` and `api`.

- [ ] **T-WEB-1** `browse` and `api` surfaces. — satisfies WEB-1 to WEB-7;
  `checks.terrane.gates.surface-schema`.
- [ ] **T-GIT-1** `git` surface (read-only upload-pack over memoized tree
  projections; needs B-derive for the memo). — satisfies GIT-1 to GIT-9;
  `checks.terrane.gates.surface-schema`.
- [ ] **T-OCI-1** `oci` surface. — satisfies OCI-1 to OCI-7;
  `checks.terrane.gates.surface-schema`.

### B-hub-edge — AOS Hub on R2, `terrane-edge`, console

Forks from B-surfaces-more and B-derive. Merge gates:
`checks.terrane.gates.edge-native-interop`,
`checks.terrane.integration.hub-import` against a staging Hub.

- [ ] **T-RISK-2** zstd on `wasm32-unknown-unknown`: decode with a pure-Rust
  decoder, measure CPU per MiB under the Worker budget, and confirm that
  encode is not required at the edge. — satisfies RISK-2, EDGE-17, EDGE-18;
  `checks.terrane.gates.core-no-std`.
- [ ] **T-EDGE-1** `terrane-edge` crate, Worker bindings, R2 `onlyIf`
  backend, edge conformance claim. — satisfies EDGE-1 to EDGE-22, CRATE-13,
  CRATE-14, PKG-6; `checks.terrane.gates.core-no-std`,
  `checks.terrane.gates.edge-native-interop`.
- [ ] **T-HUB-1** Hub token issuer, registry branches with properties from
  Hub configuration, shared bucket, edge role. — satisfies HUB-1 to HUB-5;
  `checks.terrane.integration.hub-issuer`,
  `checks.terrane.integration.hub-registry-branch`,
  `checks.terrane.integration.hub-edge-role`.
- [ ] **T-HUB-2** SHA-256 index continuity and the per-registry import and
  cutover with rollback. — satisfies HUB-6, HUB-7, MIG-1 to MIG-7;
  `checks.terrane.integration.hub-sha256-index`,
  `checks.terrane.integration.hub-import`,
  `checks.terrane.gates.mig-import-idempotent`.
- [ ] **T-HUB-3** Hub surfaces, signing job, console over `api`, OCI
  publication, GC driver, release tags, client compatibility. — satisfies
  HUB-8 to HUB-14; `checks.terrane.integration.hub-signing`,
  `checks.terrane.integration.hub-console-api`,
  `checks.terrane.integration.hub-gc`,
  `checks.terrane.integration.hub-client-compat`.

### B-consistency — `sync` mode, redirections, host modes

Forks from T5. Merge gates: `checks.terrane.gates.cons-sync-fsync`,
`checks.terrane.gates.cons-multiwriter`,
`checks.terrane.gates.host-reassembly-heuristic`.

- [ ] **T-CONS-2** `sync` writer mode, `zone` and `regions(k)` durability,
  `writers=many` with auto-rebase and conflict refs. Deferred from
  T-CONS-1. — satisfies CONS-10 (the `sync` clause), CONS-21 to CONS-23;
  `checks.terrane.gates.cons-sync-fsync`,
  `checks.terrane.gates.cons-multiwriter`.
- [ ] **T-FUSE-4** `fsync` binding to commit in `sync` mode and redirect
  options. Deferred from T-FUSE-3. — satisfies FUSE-36 to FUSE-38;
  `checks.terrane.gates.cons-sync-fsync`.
- [ ] **T-HOST-3** `smart` reassembly heuristic and the `discard` and
  `volatile` wipe modes. Deferred from T-HOST-1. — satisfies HOST-10,
  HOST-26; `checks.terrane.gates.host-reassembly-heuristic`,
  `checks.terrane.gates.host-wipe-on-release`.
- [ ] **T-REAPI-3** `sync` writer mode for `reapi` and `gha-cache`
  exposures once T-CONS-2 lands (REAPI-7, GHA-7 `SHOULD`). — satisfies
  REAPI-7, GHA-7; `checks.terrane.gates.cons-sync-fsync`.

### B-ops — Tracing, metrics export, blocking performance, read audit

Forks from T6. Merge gates: `checks.terrane.gates.obs-trace-propagation`,
`checks.terrane.gates.obs-hop-latency`, every `checks.terrane.gates.perf-*`
in blocking mode.

- [ ] **T-OBS-2** Trace propagation across tiers, hop spans and latency,
  decision logs for rulesets (needs B-derive), page-fault attribution,
  metrics export, stability of metric names. Deferred from T-OBS-1. —
  satisfies OBS-1 to OBS-6, OBS-12, OBS-15;
  `checks.terrane.gates.obs-trace-propagation`,
  `checks.terrane.gates.obs-hop-latency`,
  `checks.terrane.gates.obs-decision-log`.
- [ ] **T-PERF-2** Blocking thresholds for every `gate:perf-*` on the
  reference configuration, published with the conformance claim. Deferred
  from T-PERF-1. — satisfies PERF-11, PERF-13;
  each `checks.terrane.gates.perf-*` in blocking mode.
- [ ] **T-OBS-3** Durable read-audit event and sink, resolving spec `40`
  open question 11. — satisfies the requirement a later specification
  version adds; `checks.terrane.gates.obs-metrics`.

## Coverage

Milestones are `T<n>`; branches are `B-<name>`. A file listed under both a
milestone and a branch is partial at the MVP and completed by the branch;
the MVP conformance claim (PLAN-3) says so explicitly.

| Specification file | Milestone or branch | Tasks |
| --- | --- | --- |
| 01 goals and invariants | T1–T6 | every task; invariants are cross-cutting gates |
| 03 architecture | T0, T2, T3, T5 | T-CRATE-2, T-HOST-2, T-PROTO-1, T-SBX-1, T-FUSE-2 |
| 04 content model | T1 | T-OBJ-1 |
| 05 chunking | T1 | T-CDC-1 |
| 06 tree format | T0, T1 | T-RISK-3, T-TREE-1, T-TREE-2 |
| 07 tree algebra | T1, B-derive | T-ALG-1, T-ALG-2, T-ALG-3 |
| 08 properties | T1 | T-PROP-1 |
| 09 refs and commits | T1 | T-REF-1, T-REF-2 |
| 10 derived data | T1, B-derive, B-jobs | T-DRV-1, T-DRV-2, T-DRV-3, T-JOB-1 |
| 11 store trait | T1, T2, T3 | T-STORE-1, T-STORE-3, T-STORE-2 |
| 12 pack format | T1, B-bandwidth | T-PACK-1, T-PACK-2, T-PACK-3 |
| 13 bucket layout | T1, T2, T3 | T-BKT-1, T-HOST-1, T-BKT-2, T-BKT-3, T-RISK-1 |
| 14 host tier | T2, B-consistency, B-redundancy | T-HOST-1, T-HOST-2, T-HOST-3, T-BLK-1 |
| 15 redundancy | B-redundancy | T-RED-1 |
| 16 block-device backend | B-redundancy | T-BLK-1 |
| 17 garbage collection | T1, B-jobs, B-topology | T-GC-1, T-GC-2, T-TOPO-2 |
| 18 protocol | T3 | T-PROTO-1 |
| 19 tiering and topology | T3, B-topology | T-TOPO-1, T-TOPO-2 |
| 20 consistency | T3, T5, B-consistency | T-CONS-1, T-FUSE-3, T-CONS-2, T-FUSE-4 |
| 21 bandwidth | T3, B-bandwidth | T-BW-1, T-BW-2 |
| 22 authentication | T1, T3, B-auth | T-AUTH-1, T-AUTH-2, T-AUTH-3 |
| 23 provenance | T1 | T-PROV-1 |
| 24 disclosure domains | T1, T2 | T-DOM-1, T-STORE-3 |
| 25 threat model | T3 | T-TEST-2 (mapping only; no `MUST`s of its own beyond residual-risk statements) |
| 26 surfaces | T2 | T-SURF-1 |
| 27 FUSE | T5, B-consistency | T-RISK-4, T-FUSE-1, T-FUSE-2, T-FUSE-3, T-FUSE-4 |
| 28 EROFS and block | B-storage | T-EROFS-1, T-VBLK-1 |
| 29 VM | B-storage | T-VM-1 |
| 30 protocol surfaces | T4, B-derive, B-surfaces-more, B-consistency | T-NIX-1, T-REAPI-1, T-REAPI-2, T-GHA-1, T-NIX-2, T-WEB-1, T-GIT-1, T-OCI-1, T-REAPI-3 |
| 31 rulesets | B-derive | T-RULE-1 |
| 32 tree jobs | B-jobs | T-JOB-1 |
| 33 migrations | B-jobs, B-hub-edge | T-MIG-1, T-HUB-2 |
| 34 observability | T3, B-ops | T-OBS-1, T-OBS-2, T-OBS-3 |
| 35 performance | T6, B-ops | T-PERF-1, T-PERF-2 |
| 36 testing | T1, T3, T6, B-topology | T-TEST-1, T-TEST-2, T-TEST-3, T-TEST-4, T-TEST-5 |
| 37 crates | T0, T1 | T-PKG-1, T-CRATE-2, T-CRATE-1 |
| 38 edge | B-hub-edge | T-RISK-2, T-EDGE-1 |
| 40 risks | T0, T3, T5, B-topology, B-bandwidth, B-hub-edge | T-RISK-3, T-RISK-1, T-RISK-4, T-RISK-5, T-PACK-3, T-RISK-2 |
| integration 01 | T5 | T-SBX-1 to T-SBX-5 |
| integration 02 | B-hub-edge | T-HUB-1 to T-HUB-3 |
| integration 03 | T0, T2, T5, T6 | T-PKG-1 to T-PKG-5 |
| integration 04 | B-storage | T-CRU-1 |
| integration 07 | T3, T4 | T-BKT-3, T-AUTH-2, T-CI-1 to T-CI-4 |

- **[PLAN-2]** A doc lint MUST verify that every requirement ID cited by a
  task exists in the specification or in this directory, and that every
  `MUST` in the files above is cited by at least one task. The lint runs as
  `checks.terrane.plan-coverage` and MUST be green before status changes.
