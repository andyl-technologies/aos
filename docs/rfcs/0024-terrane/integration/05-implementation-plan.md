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

Deployable as: a local tool that initializes a store under a `file://`
root, commits a directory, forks and merges branches, and checks a commit
out to a directory through the `sdk` surface.

Freezes: every identity domain, encoding, bucket key, and the store traits.

Exit gates: `checks.terrane.gates.golden-vectors`,
`checks.terrane.gates.core-fuzz`, `checks.terrane.gates.bucket-file-cas`,
`checks.terrane.gates.gc-grace-window`,
`checks.terrane.gates.algebra-merge`, store conformance on `file://`.

- [x] **T-OBJ-1** Identity domains, descriptors, and the `terrane-v1`
  identity profile; second-identity-profile registration hook. — satisfies
  OBJ-1 to OBJ-4, OBJ-6 to OBJ-10; `checks.terrane.gates.identity-idempotence`,
  `checks.terrane.gates.descriptor-strict`.
- [x] **T-CDC-1** FastCDC chunker with the seeded gear table, codec bytes,
  dictionary identities, canonical object manifests, and receiver-side
  validation. Content-class dictionary selection is completed jointly with
  T-DRV-1. D-81 corrects the registry to retain the stored profile seed;
  all existing zero-seed golden values remain unchanged. — satisfies
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
- [ ] **T-ALG-1** `graft`, `split`, `flatten`, `overlay`, `diff`. — satisfies
  ALG-1 to ALG-14; `checks.terrane.gates.algebra-graft`,
  `checks.terrane.gates.algebra-diff`.
- [ ] **T-ALG-2** Three-cursor `merge` with conflict values and the
  `prefer-ours`, `prefer-theirs`, `prefer-trusted`, `keep-conflict`, and
  `error` policies; fast-forward; fork and fold; recipes for `merge` and
  `overlay` composites. Native delta parity is completed with T-FUSE-3
  when the overlay-upper importer exists. Narrowed to trunk scope: `filter`, `map`, set
  operations, and the remaining recipe kinds are T-ALG-3 on B-derive.
  D-79's checked cold-fork lineage and genuine zero-TreeNode-I/O qualification
  remain joint with ref publication and source-preserving collection. —
  satisfies ALG-15 to ALG-21, ALG-28 to ALG-39;
  `checks.terrane.gates.algebra-merge`, `checks.terrane.gates.algebra-fork`.
- [x] **T-PROP-1** Property resolution, types, boundary properties,
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
  belongs to T-JOB-1; this task reports gaps without starting jobs. —
  satisfies TREE-14, PROP-1 to PROP-28;
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
  `class.magic`), stored per object. Narrowed to trunk scope: index trees,
  derivations, and memos are T-DRV-2 on B-derive. — satisfies DRV-1 to
  DRV-11; `checks.terrane.gates.derived-attr-record`.
- [x] **T-AUTH-1** Capability token verification (Ed25519, chain, caveats,
  attenuation) in `no_std`. — satisfies AUTH-7 to AUTH-22;
  `checks.terrane.gates.auth-verify-pure`,
  `checks.terrane.gates.auth-attenuation-monotone`.
- [ ] **T-TEST-1** Golden vectors generated by the reference implementation
  and checked into `spec/reference/golden-vectors.md`; fuzz and property
  tests for every format. D-80 adds independently reproduced D-77/D-78 byte
  witnesses and distinguishes decoder rejection from authority claims.
  Remaining format publication and joint native qualification are incomplete.
  D-79's newly registered publication/control schemas also need independent
  byte vectors and decoder tests before T1's encoding freeze.
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
  trunk native build now reports 27 diagnostics, down from the lease adoption's
  64, with real Guard types and consumers still absent. This source integration
  does not qualify the full task; backend test closure and Guard/reference
  integration precede current runtime gates.
  The declared opened-directory retention test module is restored exactly
  from its reviewed source. It preserves actual descriptor, ancestry, kernel
  exclusion and queued/running cancellation assertions. The exact mandatory
  Rust-check and all-format sequence now passes on the trunk; native execution
  of these fixtures still requires the complete Guard/reference source graph.
  The actual current trunk aggregate stops in `bundle-verify` compilation,
  before test execution, with 30 diagnostics. Missing Guard, domain and
  protected installation APIs include the collector fixture's namespace and
  registration types; remaining inference diagnostics are retained separately.
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
  gates pass again with the same 16/5/3/12 exact selectors. Integration of the
  owned adapters and joint source qualification remain pending.
  No deadline change or speedup is claimed.
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
  The current native build reaches type checking and fails on 64 diagnostics,
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
  The pure task is reopened for PROV-13: unavailable public ancestry can
  become empty acceptance evidence under negation. The reviewed task correction
  propagates content and attribute acceptance errors; its coupled context and
  derived-data source closure still requires trunk adoption and qualification.
  Reviewed annotated-tag signing and verification now bind the exact REF-20
  preimage, terminal key, expected tag/commit and source Tag/Admin scope.
  All 303 trunk core tests, strict all-target Clippy, strict rustdoc and core
  formatting pass. The expanded hermetic signature gate passes its 12 exact
  selectors, including four snapshot cases. This does not qualify native tag
  publication, current ACL checks or the pending acceptance correction.
  — satisfies PROV-1 to PROV-25;
  `checks.terrane.gates.prov-commit-signature`,
  `checks.terrane.gates.prov-selector-presets`.
- [ ] **T-DOM-1** Domain property semantics, cross-domain reference checks,
  dedup scoping, existence-oracle rules and durable disclosure evidence.
  Special tree, whiteout, conflict and index disclosure remain required;
  file/directory-marker/symlink certificates alone do not qualify DOM-7.
  Eight reviewed native domain paths now supply guarded root/domain bindings,
  independent storage, namespace configuration and administrative request types.
  Their complete source matches the reference candidate; no manifest, lockfile,
  Guard or publication interface changed. Mandatory repository formatting passes.
  The current native production build still stops on 27 missing Guard/consumer
  and resulting inference diagnostics before runtime qualification. Actual
  current-authority disclosure, deletion and domain gates remain incomplete.
  — satisfies DOM-1 to DOM-11, DOM-16, DOM-17, DOM-20, DOM-24;
  `checks.terrane.gates.dom-reference-order`,
  `checks.terrane.gates.dom-dedup-scope`.
- [ ] **T-CRATE-1** SDK types and verbs (`Tree`, `View`, `Store`,
  `Repository`, `fork`, `commit`, `merge`, `diff`, `realize`) and the `sdk`
  surface (checkout to a directory). The mandatory ext4 workflow is registered;
  audit passes, but directory KeepConflict publication still exceeds the
  unchanged writer deadline. Complete workflow and package qualification remain
  pending; native I/O batching preserves every required observation and fence.
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
  mapping. Lookups use a per-root store-path map maintained by the surface
  until index trees land (T-DRV-2); the map is a derivation in all but
  name and is replaced, not migrated. — satisfies NIX-1 to NIX-8, NIX-10 to
  NIX-13; `checks.terrane.gates.nix-frame-concat`,
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
  `ImmutableFetchTransport` implementations. The SHA-256 index tree
  arrives with T-DRV-2; until then lookups use the per-object attribute
  record. — satisfies SBX-11 to SBX-17;
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

### B-derive — Derivations, index trees, rulesets

Forks from T1. Merge gates: `checks.terrane.gates.derivation-memo`,
`checks.terrane.gates.index-tree-maintenance`,
`checks.terrane.gates.ruleset-eval-order`.

- [ ] **T-ALG-3** `filter`, `map`, set operations, and recipes for every
  composite kind. Deferred from T-ALG-2. — satisfies ALG-22 to ALG-27;
  `checks.terrane.gates.algebra-diff`.
- [ ] **T-DRV-2** Derivations, memos, index trees with O(delta) maintenance,
  `verify_index`, lookup by attribute value, SHA-256 index continuity.
  Deferred from T-DRV-1. — satisfies DRV-12 to DRV-23;
  `checks.terrane.gates.derivation-memo`,
  `checks.terrane.gates.index-tree-maintenance`.
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
| 10 derived data | T1, B-derive, B-jobs | T-DRV-1, T-DRV-2, T-JOB-1 |
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
